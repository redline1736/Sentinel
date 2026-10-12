#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <curl/curl.h>
#include <pthread.h>

#include "chrome.h"
#include "../global.h"

/* ============================================================================
 * Internal helpers
 * ============================================================================ */

typedef struct {
    char  *buf;
    size_t len;
    size_t cap;
} resp_buf;

static size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t total = size * nmemb;
    resp_buf *r = (resp_buf *)userdata;

    if (r->len + total + 1 > r->cap) {
        size_t newcap = r->cap ? r->cap * 2 : 4096;
        while (newcap < r->len + total + 1) newcap *= 2;
        char *nb = realloc(r->buf, newcap);
        if (!nb) return 0;
        r->buf = nb;
        r->cap = newcap;
    }
    memcpy(r->buf + r->len, ptr, total);
    r->len += total;
    r->buf[r->len] = '\0';
    return total;
}

static int json_escape(const char *src, char *dst, size_t dstsz) {
    size_t j = 0;
    for (size_t i = 0; src[i]; i++) {
        unsigned char ch = (unsigned char)src[i];
        const char *rep = NULL;
        char tmp[8];
        switch (ch) {
            case '"':  rep = "\\\""; break;
            case '\\': rep = "\\\\"; break;
            case '\n': rep = "\\n";  break;
            case '\r': rep = "\\r";  break;
            case '\t': rep = "\\t";  break;
            case '\b': rep = "\\b";  break;
            case '\f': rep = "\\f";  break;
            default:
                if (ch < 0x20) {
                    snprintf(tmp, sizeof(tmp), "\\u%04x", ch);
                    rep = tmp;
                }
                break;
        }
        if (rep) {
            size_t rl = strlen(rep);
            if (j + rl + 1 > dstsz) return 0;
            memcpy(dst + j, rep, rl);
            j += rl;
        } else {
            if (j + 2 > dstsz) return 0;
            dst[j++] = (char)ch;
        }
    }
    if (j >= dstsz) return 0;
    dst[j] = '\0';
    return 1;
}

static int recv_until_id(chrome *c, int id, const char *needle,
                         int max_frames, int per_frame_usleep)
{
    char idneedle[32];
    snprintf(idneedle, sizeof(idneedle), "\"id\":%d", id);

    for (int i = 0; i < max_frames; i++) {
        const struct curl_ws_frame *meta = NULL;
        char buf[8192];
        size_t n = 0;
        CURLcode rc = curl_ws_recv(c->curl, buf, sizeof(buf) - 1, &n, &meta);

        if (rc == CURLE_AGAIN) {
            usleep(per_frame_usleep);
            continue;
        }
        if (rc != CURLE_OK) return -1;
        if (n == 0) { usleep(per_frame_usleep); continue; }

        buf[n] = '\0';
        if (strstr(buf, idneedle) && (!needle || strstr(buf, needle)))
            return 1;
    }
    return 0;
}

static int ws_send(chrome *c, const char *data) {
    size_t sent = 0;
    size_t total = strlen(data);
    CURLcode rc = curl_ws_send(c->curl, data, total, &sent, 0, CURLWS_TEXT);
    if (rc != CURLE_OK) {
        fprintf(stderr, "[CDP] ws_send failed: %s\n", curl_easy_strerror(rc));
        return -1;
    }
    return 0;
}

/* ============================================================================
 * Port wait / WS discovery
 * ============================================================================ */

int wait_for_port(int port, int timeout_sec) {
    for (int i = 0; i < timeout_sec * 10; i++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return -1;
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family      = AF_INET;
        addr.sin_port        = htons((uint16_t)port);
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
            close(fd);
            return 0;
        }
        close(fd);
        usleep(100000);
    }
    return -1;
}

int discover_ws_url(chrome *c, int port) {
    char url[128];
    snprintf(url, sizeof(url), "http://127.0.0.1:%d/json", port);

    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    resp_buf rb = {0};
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &rb);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK || !rb.buf) {
        fprintf(stderr, "Failed to query /json: %s\n", curl_easy_strerror(res));
        free(rb.buf);
        return -1;
    }

    char *start = strstr(rb.buf, "\"webSocketDebuggerUrl\"");
    if (!start) {
        fprintf(stderr, "No webSocketDebuggerUrl found in /json response\n");
        free(rb.buf);
        return -1;
    }
    start = strchr(start, ':');
    if (!start) { free(rb.buf); return -1; }
    start++;
    while (*start == ' ' || *start == '"') start++;

    char *end = strchr(start, '"');
    if (!end) { free(rb.buf); return -1; }
    *end = '\0';

    snprintf(c->ws_url, MAX_WS_URL, "%s", start);
    printf("[CDP] Discovered WS URL: %s\n", c->ws_url);
    free(rb.buf);
    return 0;
}

/* ============================================================================
 * Instrumentation JS
 *
 * window.__gq_xss is set BEFORE the real function is called, so even if the
 * real alert()/confirm() blocks the JS thread, the marker is already set.
 * ============================================================================ */

static const char *INSTRUMENT_JS =
    "(function(){"
    "['alert','prompt','confirm'].forEach(function(f){"
    "var o=window[f];"
    "window[f]=function(){window.__gq_xss=1;"
    "try{return o.apply(window,arguments)}catch(e){}};"
    "});"
    "window.addEventListener('error',function(){window.__gq_xss=1});"
    "})()";

/* ============================================================================
 * Chrome lifecycle
 * ============================================================================ */

/* Chromium's own startup checks race when several instances are forked
 * simultaneously from a multithreaded parent.  Serialize the launch. */
static pthread_mutex_t g_chrome_launch_lock = PTHREAD_MUTEX_INITIALIZER;

int init_chrome(chrome *c, int port) {
    if (!c) return -1;
    memset(c, 0, sizeof(*c));
    c->port = port;
    c->pid  = -1;

    char profile[128];
    snprintf(profile, sizeof(profile), "/tmp/remote-profile-%d", port);

    /* Nuke the profile dir so a crashed prior run can't leave a stale lock. */
    char rmcmd[256];
    snprintf(rmcmd, sizeof(rmcmd), "rm -rf %s", profile);
    if (system(rmcmd) != 0) {
        /* best-effort */
    }

    char port_opt[64];
    snprintf(port_opt, sizeof(port_opt), "--remote-debugging-port=%d", port);

    pthread_mutex_lock(&g_chrome_launch_lock);

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        pthread_mutex_unlock(&g_chrome_launch_lock);
        return -1;
    }
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            if (devnull > STDERR_FILENO) close(devnull);
        }
        setsid();

        execlp("chromium", "chromium",
               port_opt,
               "--user-data-dir", profile,
               "--remote-allow-origins=*",
               "--headless=new",
               "--disable-gpu",
               "--no-first-run",
               "--no-default-browser-check",
               "--disable-extensions",
               "--disable-dev-shm-usage",
               (char *)NULL);

        execlp("google-chrome", "google-chrome",
               port_opt,
               "--user-data-dir", profile,
               "--remote-allow-origins=*",
               "--headless=new",
               "--disable-gpu",
               "--no-first-run",
               "--no-default-browser-check",
               "--disable-extensions",
               "--disable-dev-shm-usage",
               (char *)NULL);

        execlp("chromium-browser", "chromium-browser",
               port_opt,
               "--user-data-dir", profile,
               "--remote-allow-origins=*",
               "--headless=new",
               "--disable-gpu",
               "--no-first-run",
               "--no-default-browser-check",
               "--disable-extensions",
               "--disable-dev-shm-usage",
               (char *)NULL);

        _exit(127);
    }

    c->pid = pid;

    if (wait_for_port(port, 15) != 0) {
        fprintf(stderr, "Timed out waiting for Chrome on port %d\n", port);
        close_chrome(c);
        pthread_mutex_unlock(&g_chrome_launch_lock);
        return -1;
    }
    printf("[CDP] Chrome ready on port %d (pid %d)\n", port, (int)c->pid);

    /* Stagger so the next launch's Chromium doesn't collide with this
     * instance's internal initialization. */
    usleep(300000);

    pthread_mutex_unlock(&g_chrome_launch_lock);

    if (discover_ws_url(c, port) != 0) {
        close_chrome(c);
        return -1;
    }

    c->curl = curl_easy_init();
    if (!c->curl) { close_chrome(c); return -1; }

    curl_version_info_data *ver = curl_version_info(CURLVERSION_NOW);
    int ws_supported = 0;
#ifdef CURL_VERSION_WEBSOCKETS
    if (ver && (ver->features & CURL_VERSION_WEBSOCKETS)) ws_supported = 1;
#else
    if (ver && ver->version_num >= 0x075600) ws_supported = 1;
#endif

    if (!ws_supported) {
        printf("[CDP] libcurl lacks WebSocket support — detection disabled\n");
        c->use_websocket = 0;
        curl_easy_setopt(c->curl, CURLOPT_TIMEOUT, 5L);
        curl_easy_setopt(c->curl, CURLOPT_CONNECTTIMEOUT, 3L);
        return 0;
    }

    curl_easy_setopt(c->curl, CURLOPT_URL, c->ws_url);
    curl_easy_setopt(c->curl, CURLOPT_CONNECT_ONLY, 2L);
    curl_easy_setopt(c->curl, CURLOPT_NOSIGNAL, 1L);

    CURLcode res = curl_easy_perform(c->curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "WebSocket connect failed: %s\n",
                curl_easy_strerror(res));
        curl_easy_cleanup(c->curl);
        c->curl = NULL;
        close_chrome(c);
        return -1;
    }

    c->use_websocket = 1;
    printf("[CDP] WebSocket connected\n");

    const char *enable_cmd = "{\"id\":1,\"method\":\"Page.enable\"}";
    const char *rt_cmd     = "{\"id\":2,\"method\":\"Runtime.enable\"}";
    if (ws_send(c, enable_cmd) != 0 || ws_send(c, rt_cmd) != 0) {
        close_chrome(c);
        return -1;
    }

    char instr[4096];
    int n = snprintf(instr, sizeof(instr),
        "{\"id\":3,\"method\":\"Page.addScriptToEvaluateOnNewDocument\","
        "\"params\":{\"source\":\"%s\"}}",
        INSTRUMENT_JS);
    if (n < 0 || (size_t)n >= sizeof(instr)) {
        fprintf(stderr, "[CDP] instrumentation command truncated\n");
        close_chrome(c);
        return -1;
    }
    if (ws_send(c, instr) != 0) { close_chrome(c); return -1; }

    for (int id = 1; id <= 3; id++) {
        if (recv_until_id(c, id, NULL, 100, 5000) != 1) {
            fprintf(stderr, "[CDP] timed out awaiting ack id=%d\n", id);
            close_chrome(c);
            return -1;
        }
    }
    printf("[CDP] Page.enable + Runtime.enable + instrumentation acked\n");
    return 0;
}

void close_chrome(chrome *c) {
    if (!c) return;
    if (c->curl) {
        curl_easy_cleanup(c->curl);
        c->curl = NULL;
    }
    if (c->pid > 0) {
        kill(c->pid, SIGTERM);
        for (int i = 0; i < 20; i++) {
            pid_t r = waitpid(c->pid, NULL, WNOHANG);
            if (r == c->pid || (r < 0 && errno == ECHILD)) break;
            usleep(50000);
        }
        if (kill(c->pid, 0) == 0) kill(c->pid, SIGKILL);
        c->pid = -1;
    }
}

/* ============================================================================
 * Navigation & CDP
 * ============================================================================ */

int navigate_to(chrome *c, const char *url) {
    if (!c || !c->curl || !c->use_websocket) return -1;
    if (!url) return -1;

    size_t ulen = strlen(url);
    char *esc = malloc(ulen * 6 + 1);
    if (!esc) return -1;
    if (!json_escape(url, esc, ulen * 6 + 1)) { free(esc); return -1; }

    size_t need = strlen(esc) + 128;
    char *nav_cmd = malloc(need);
    if (!nav_cmd) { free(esc); return -1; }

    int n = snprintf(nav_cmd, need,
        "{\"id\":50,\"method\":\"Page.navigate\",\"params\":{\"url\":\"%s\"}}",
        esc);
    free(esc);
    if (n < 0 || (size_t)n >= need) { free(nav_cmd); return -1; }

    int rc = ws_send(c, nav_cmd);
    free(nav_cmd);
    return rc;
}

int send_cdp(chrome *c, const char *method, const char *params, int id) {
    if (!c || !c->curl || !c->use_websocket) return -1;

    size_t need = strlen(method) + (params ? strlen(params) : 0) + 128;
    char *cmd = malloc(need);
    if (!cmd) return -1;

    int n = snprintf(cmd, need,
        "{\"id\":%d,\"method\":\"%s\",\"params\":%s}",
        id, method, params ? params : "{}");
    if (n < 0 || (size_t)n >= need) { free(cmd); return -1; }

    int rc = ws_send(c, cmd);
    free(cmd);
    return rc;
}

/* ============================================================================
 * Input simulation (kept for API compatibility, not used by detect_xss)
 * ============================================================================ */

int simulate_mouse_move(chrome *c, int x, int y) {
    char params[256];
    snprintf(params, sizeof(params),
        "{\"type\":\"mouseMoved\",\"x\":%d,\"y\":%d,"
        "\"button\":\"none\",\"modifiers\":0,\"pointerType\":\"mouse\"}",
        x, y);
    return send_cdp(c, "Input.dispatchMouseEvent", params, 100);
}

int simulate_click(chrome *c, int x, int y) {
    char press[256], release[256];
    snprintf(press, sizeof(press),
        "{\"type\":\"mousePressed\",\"x\":%d,\"y\":%d,"
        "\"button\":\"left\",\"clickCount\":1,\"modifiers\":0,"
        "\"pointerType\":\"mouse\"}", x, y);
    if (send_cdp(c, "Input.dispatchMouseEvent", press, 101) != 0)
        return -1;

    usleep(20000);

    snprintf(release, sizeof(release),
        "{\"type\":\"mouseReleased\",\"x\":%d,\"y\":%d,"
        "\"button\":\"left\",\"clickCount\":1,\"modifiers\":0,"
        "\"pointerType\":\"mouse\"}", x, y);
    return send_cdp(c, "Input.dispatchMouseEvent", release, 102);
}

/* ============================================================================
 * Dialog detection
 *
 * If a Page.javascriptDialogOpening event is seen, accept it immediately so
 * the JS thread unblocks.  Also drains the ack for handleJavaScriptDialog so
 * it doesn't linger in the WebSocket buffer and confuse the next probe.
 * ============================================================================ */

int handle_dialogs(chrome *c, int max_polls) {
    if (!c || !c->curl || !c->use_websocket) return 1;

    int saw_dialog = 0;

    for (int i = 0; i < max_polls; i++) {
        const struct curl_ws_frame *meta = NULL;
        char buf[8192];
        size_t n = 0;
        CURLcode rc = curl_ws_recv(c->curl, buf, sizeof(buf) - 1, &n, &meta);

        if (rc == CURLE_AGAIN) { usleep(20000); continue; }
        if (rc != CURLE_OK) break;
        if (n == 0) continue;
        buf[n] = '\0';

        if (strstr(buf, "Page.javascriptDialogOpening")) {
            const char *handle_cmd =
                "{\"id\":3,\"method\":\"Page.handleJavaScriptDialog\","
                "\"params\":{\"accept\":true}}";
            ws_send(c, handle_cmd);
            printf("[CDP] XSS DETECTED — dialog accepted\n");
            saw_dialog = 1;

            /* Drain the ack (and anything else queued) so the next
             * Runtime.evaluate probe sees its own response first. */
            for (int j = 0; j < 3; j++) {
                const struct curl_ws_frame *m2 = NULL;
                char b2[2048];
                size_t n2 = 0;
                CURLcode rc2 = curl_ws_recv(c->curl, b2, sizeof(b2) - 1, &n2, &m2);
                if (rc2 != CURLE_OK) break;
                if (n2 == 0) break;
            }
            break;
        }
    }
    return saw_dialog ? 0 : 1;
}

/* ============================================================================
 * Marker probe — must be called AFTER any pending dialog is dismissed.
 * ============================================================================ */

int probe_runtime_marker(chrome *c) {
    if (!c || !c->curl || !c->use_websocket) return 1;

    const char *cmd =
        "{\"id\":77,\"method\":\"Runtime.evaluate\",\"params\":{"
        "\"expression\":\"window.__gq_xss===1\","
        "\"returnByValue\":true}}";

    if (ws_send(c, cmd) != 0) return 1;

    /* 500 frames × 5ms = 2.5s ceiling; returns as soon as the ack arrives. */
    int found = recv_until_id(c, 77, "\"value\":true", 500, 5000);
    return (found == 1) ? 0 : 1;
}

/* ============================================================================
 * Event dispatch — one round trip instead of many mouse moves
 * ============================================================================ */

static int dispatch_events(chrome *c) {
    if (!c || !c->use_websocket) return -1;

    const char *cmd =
        "{\"id\":88,\"method\":\"Runtime.evaluate\",\"params\":{"
        "\"expression\":\"(function(){"
        "var evs=['mouseover','mouseenter','pointerenter','pointerover',"
        "'mousemove','click','mousedown','mouseup','focus','error','load'];"
        "function fire(t){"
        "for(var i=0;i<evs.length;i++){"
        "try{t.dispatchEvent(new MouseEvent(evs[i],{bubbles:true,cancelable:true,view:window}))}catch(e){}"
        "}"
        "}"
        "fire(window);fire(document);"
        "try{fire(document.body)}catch(e){}"
        "var all=document.querySelectorAll('*');"
        "for(var j=0;j<all.length&&j<500;j++){fire(all[j])}"
        "})()\","
        "\"returnByValue\":true}}";

    if (ws_send(c, cmd) != 0) return -1;
    recv_until_id(c, 88, NULL, 100, 5000);
    return 0;
}

/* ============================================================================
 * Interaction detection
 * ============================================================================ */

int detect_payload_event_type(const char *payload) {
    if (!payload) return XSS_INTERACT_NONE;

    if (strstr(payload, "onmousemove")    ||
        strstr(payload, "onmouseover")    ||
        strstr(payload, "onmouseenter")   ||
        strstr(payload, "onpointermove")  ||
        strstr(payload, "onpointerover")  ||
        strstr(payload, "onpointerenter"))
        return XSS_INTERACT_MOUSE;

    if (strstr(payload, "onclick")        ||
        strstr(payload, "ondblclick")     ||
        strstr(payload, "onpointerdown")  ||
        strstr(payload, "onpointerup")    ||
        (strstr(payload, "href=javascript:") && strstr(payload, "<a")) ||
        (strstr(payload, "href=javascript:") && strstr(payload, "<area")))
        return XSS_INTERACT_CLICK;

    return XSS_INTERACT_NONE;
}

/* ============================================================================
 * Combined XSS detection
 *
 * Order matters:
 *   1. Unconditionally send Page.handleJavaScriptDialog{accept:true}.  If a
 *      dialog is blocking the JS thread, this unblocks it.  If nothing is
 *      pending, Chrome replies with an error which we ignore.
 *   2. Read any Page.javascriptDialogOpening frames that were queued before
 *      we sent the accept command.
 *   3. Ask the page for window.__gq_xss.  The JS thread is free now, so
 *      Runtime.evaluate returns immediately instead of queuing behind a
 *      blocked alert()/confirm().
 *   4. For event-driven payloads, dispatch synthetic events, then run the
 *      same dismiss-then-probe sequence again.
 * ============================================================================ */

int detect_xss(chrome *c, int max_polls, int interaction) {
    if (!c || !c->use_websocket) return 1;

    /* Step 1 — unconditionally dismiss any pending dialog. */
    ws_send(c,
        "{\"id\":98,\"method\":\"Page.handleJavaScriptDialog\","
        "\"params\":{\"accept\":true}}");

    /* Give Chrome a moment to unblock the JS thread if a dialog was open. */
    usleep(30000);

    /* Step 2 — read any dialog-opening frames that are queued. */
    if (handle_dialogs(c, max_polls) == 0) return 0;

    /* Step 3 — marker check. */
    if (probe_runtime_marker(c) == 0) return 0;

    /* Step 4 — for event-driven payloads, trigger and retry. */
    if (interaction == XSS_INTERACT_MOUSE || interaction == XSS_INTERACT_CLICK) {
        dispatch_events(c);
        usleep(50000);

        /* Dismiss anything the dispatched events triggered. */
        ws_send(c,
            "{\"id\":98,\"method\":\"Page.handleJavaScriptDialog\","
            "\"params\":{\"accept\":true}}");
        usleep(30000);

        if (handle_dialogs(c, 10) == 0) return 0;
        if (probe_runtime_marker(c) == 0) return 0;
    }

    return 1;
}