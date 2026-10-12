#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <curl/curl.h>

#include "chrome.h"
#include "../global.h"

/* ============================================================================
 * Internal helpers
 * ============================================================================ */

/* growable response accumulator for libcurl callbacks */
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
        if (!nb) return 0;   /* signal error */
        r->buf = nb;
        r->cap = newcap;
    }
    memcpy(r->buf + r->len, ptr, total);
    r->len += total;
    r->buf[r->len] = '\0';
    return total;
}

/* JSON string escaper — writes into dst (may be dst==src for in-place). */
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

/* ----------------------------------------------------------------------------
 * Read WebSocket frames until we find one containing "id":<id> (optionally
 * also containing `needle`).  Drains and discards unrelated events.
 * Returns:
 *   1  -> found
 *   0  -> not found within budget
 *  -1  -> transport error
 * -------------------------------------------------------------------------- */
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

/* Simple synchronous WS send helper. */
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

int init_chrome(chrome *c, int port) {
    if (!c) return -1;
    memset(c, 0, sizeof(*c));
    c->port = port;
    c->pid  = -1;

    /* Fork+exec so we get a real PID for isolated kill. */
    char profile[128];
    snprintf(profile, sizeof(profile), "/tmp/remote-profile-%d", port);

    char port_opt[64];
    snprintf(port_opt, sizeof(port_opt), "--remote-debugging-port=%d", port);

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    }
    if (pid == 0) {
        /* child */
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            if (devnull > STDERR_FILENO) close(devnull);
        }
        setsid();   /* detach from controlling terminal */

        execlp("chromium", "chromium",
               port_opt,
               "--user-data-dir", profile,
               "--remote-allow-origins=*",
               "--headless=new",
               "--disable-gpu",
               "--no-first-run",
               "--no-default-browser-check",
               "--disable-extensions",
               (char *)NULL);

        /* If chromium isn't found, try chrome / google-chrome. */
        execlp("google-chrome", "google-chrome",
               port_opt,
               "--user-data-dir", profile,
               "--remote-allow-origins=*",
               "--headless=new",
               "--disable-gpu",
               "--no-first-run",
               "--no-default-browser-check",
               "--disable-extensions",
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
               (char *)NULL);

        _exit(127);
    }

    /* parent */
    c->pid = pid;

    if (wait_for_port(port, 10) != 0) {
        fprintf(stderr, "Timed out waiting for Chrome on port %d\n", port);
        close_chrome(c);
        return -1;
    }
    printf("[CDP] Chrome ready on port %d (pid %d)\n", port, (int)c->pid);

    if (discover_ws_url(c, port) != 0) {
        close_chrome(c);
        return -1;
    }

    c->curl = curl_easy_init();
    if (!c->curl) { close_chrome(c); return -1; }

    /* Detect WS support. */
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

    /* --- Handshake: Page.enable, Runtime.enable, instrumentation --- */
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

    /* Wait for all three ack IDs. */
    for (int id = 1; id <= 3; id++) {
        if (recv_until_id(c, id, NULL, 100, 50000) != 1) {
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
        /* reap briefly */
        for (int i = 0; i < 20; i++) {
            pid_t r = waitpid(c->pid, NULL, WNOHANG);
            if (r == c->pid || (r < 0 && errno == ECHILD)) break;
            usleep(50000);
        }
        /* escalate if still alive */
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

    /* Escape url for JSON safety. */
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
 * Input simulation
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

    usleep(50000);

    snprintf(release, sizeof(release),
        "{\"type\":\"mouseReleased\",\"x\":%d,\"y\":%d,"
        "\"button\":\"left\",\"clickCount\":1,\"modifiers\":0,"
        "\"pointerType\":\"mouse\"}", x, y);
    return send_cdp(c, "Input.dispatchMouseEvent", release, 102);
}

/* ============================================================================
 * Dialog + marker detection
 * ============================================================================ */

int handle_dialogs(chrome *c, int max_polls) {
    if (!c || !c->curl || !c->use_websocket) return 1;

    for (int i = 0; i < max_polls; i++) {
        const struct curl_ws_frame *meta = NULL;
        char buf[8192];
        size_t n = 0;
        CURLcode rc = curl_ws_recv(c->curl, buf, sizeof(buf) - 1, &n, &meta);

        if (rc == CURLE_AGAIN) { usleep(100000); continue; }
        if (rc != CURLE_OK) break;
        if (n == 0) continue;
        buf[n] = '\0';

        if (strstr(buf, "Page.javascriptDialogOpening")) {
            const char *handle_cmd =
                "{\"id\":3,\"method\":\"Page.handleJavaScriptDialog\","
                "\"params\":{\"accept\":true}}";
            ws_send(c, handle_cmd);
            printf("[CDP] XSS DETECTED — dialog accepted\n");
            return 0;
        }
    }
    return 1;
}

int probe_runtime_marker(chrome *c) {
    if (!c || !c->curl || !c->use_websocket) return 1;

    const char *cmd =
        "{\"id\":77,\"method\":\"Runtime.evaluate\",\"params\":{"
        "\"expression\":\"window.__gq_xss===1\","
        "\"returnByValue\":true}}";

    if (ws_send(c, cmd) != 0) return 1;

    /* Look specifically for our id and a true value; skip other events. */
    int found = recv_until_id(c, 77, "\"value\":true", 200, 30000);
    return (found == 1) ? 0 : 1;
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
 * ============================================================================ */

int detect_xss(chrome *c, int max_polls, int interaction) {
    if (!c || !c->use_websocket) return 1;

    if (interaction == XSS_INTERACT_MOUSE) {
        for (int step = 0; step < 10; step++) {
            simulate_mouse_move(c, step * 100 + 10, 50 + (step % 5) * 30);
            usleep(80000);
            if (handle_dialogs(c, 3) == 0) return 0;
        }
        if (handle_dialogs(c, max_polls) == 0) return 0;
        return probe_runtime_marker(c);
    }

    if (interaction == XSS_INTERACT_CLICK) {
        int positions[][2] = {
            {100, 100}, {200, 150}, {300, 200},
            {50,  50},  {400, 300}, {150, 250}
        };
        for (int i = 0; i < 6; i++) {
            simulate_click(c, positions[i][0], positions[i][1]);
            usleep(100000);
            if (handle_dialogs(c, 3) == 0) return 0;
        }
        if (handle_dialogs(c, max_polls) == 0) return 0;
        return probe_runtime_marker(c);
    }

    if (handle_dialogs(c, max_polls) == 0) return 0;
    return probe_runtime_marker(c);
}