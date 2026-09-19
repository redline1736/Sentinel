#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "chrome.h"

#define MAX_WS_URL 256
#define MAX_CDP_CMD 4096

typedef struct {
    CURL *curl;
    char ws_url[MAX_WS_URL];
    int use_websocket;
} chrome;

chrome c = {0};

/* Static C callback */
static size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t total = size * nmemb;
    char *buf = (char*)userdata;
    size_t current_len = strlen(buf);
    size_t max_len = 4095;

    if (current_len + total > max_len) {
        total = max_len - current_len;
    }
    if (total > 0) {
        memcpy(buf + current_len, ptr, total);
        buf[current_len + total] = '\0';
    }
    return size * nmemb;
}

/* Utility: wait for a TCP port to be open */
int wait_for_port(int port, int timeout_sec) {
    for (int i = 0; i < timeout_sec * 10; i++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return -1;
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            close(fd);
            return 0;
        }
        close(fd);
        usleep(100000);
    }
    return -1;
}

/* Query /json endpoint to get the actual WS URL */
int discover_ws_url(int port) {
    char url[128];
    snprintf(url, sizeof(url), "http://127.0.0.1:%d/json", port);

    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    char response[4096] = {0};
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        fprintf(stderr, "Failed to query /json: %s\n", curl_easy_strerror(res));
        return -1;
    }

    response[4095] = '\0';

    char *start = strstr(response, "\"webSocketDebuggerUrl\"");
    if (!start) {
        fprintf(stderr, "No webSocketDebuggerUrl found in /json response\n");
        return -1;
    }
    start = strchr(start, ':');
    if (!start) return -1;
    start++;
    while (*start == ' ' || *start == '"') start++;

    char *end = strchr(start, '"');
    if (!end) return -1;
    *end = '\0';

    snprintf(c.ws_url, MAX_WS_URL, "%s", start);
    printf("[CDP] Discovered WS URL: %s\n", c.ws_url);
    return 0;
}

/* Send HTTP command to Chrome (kept for API-compat; unused by default) */
static int send_cdp_http(const char *method, const char *params, int id) {
    if (!c.curl) return -1;

    char cmd[MAX_CDP_CMD];
    snprintf(cmd, sizeof(cmd),
             "{\"id\":%d,\"method\":\"%s\",\"params\":%s}", id, method, params);

    char response[4096] = {0};
    char url[256];
    snprintf(url, sizeof(url), "http://127.0.0.1:9222/json/rpc");

    curl_easy_reset(c.curl);
    curl_easy_setopt(c.curl, CURLOPT_URL, url);
    curl_easy_setopt(c.curl, CURLOPT_POSTFIELDS, cmd);
    curl_easy_setopt(c.curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(c.curl, CURLOPT_WRITEDATA, response);
    curl_easy_setopt(c.curl, CURLOPT_TIMEOUT, 5L);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(c.curl, CURLOPT_HTTPHEADER, headers);

    CURLcode res = curl_easy_perform(c.curl);
    curl_slist_free_all(headers);

    if (res != CURLE_OK) {
        fprintf(stderr, "[CDP] send_cdp_http failed: %s\n", curl_easy_strerror(res));
        return -1;
    }
    return 0;
}

/* JS installed on every new document: record XSS firing into window.__gq_xss */
static const char *INSTRUMENT_JS =
    "(function(){"
    "['alert','prompt','confirm'].forEach(function(f){"
    "var o=window[f];"
    "window[f]=function(){window.__gq_xss=1;"
    "try{return o.apply(window,arguments)}catch(e){}};"
    "});"
    "window.addEventListener('error',function(){window.__gq_xss=1});"
    "})()";

/* Initialize Chrome and connect */
int init_chrome(int port) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "chromium --remote-debugging-port=%d "
             "--user-data-dir=/tmp/remote-profile-%d "
             "--remote-allow-origins=* "
             "--headless --disable-gpu --no-first-run "
             "--no-default-browser-check --disable-extensions "
             ">/dev/null 2>&1 &",
             port, port);
    printf("[CDP] Launching: %s\n", cmd);

    if (system(cmd) == -1) {
        fprintf(stderr, "Failed to launch Chrome\n");
        return -1;
    }

    if (wait_for_port(port, 10) != 0) {
        fprintf(stderr, "Timed out waiting for Chrome on port %d\n", port);
        return -1;
    }
    printf("[CDP] Chrome is ready on port %d\n", port);

    if (discover_ws_url(port) != 0) return -1;

    c.curl = curl_easy_init();
    if (!c.curl) return -1;

    c.use_websocket = 0;

    curl_version_info_data *ver = curl_version_info(CURLVERSION_NOW);
    int ws_supported = 0;

#ifdef CURL_VERSION_WEBSOCKETS
    if (ver && (ver->features & CURL_VERSION_WEBSOCKETS)) ws_supported = 1;
#else
    if (ver && ver->version_num >= 0x075600) ws_supported = 1;
#endif

    if (ws_supported) {
        printf("[CDP] WebSocket support detected\n");
        c.use_websocket = 1;

        curl_easy_setopt(c.curl, CURLOPT_URL, c.ws_url);
        curl_easy_setopt(c.curl, CURLOPT_CONNECT_ONLY, 2L);

        CURLcode res = curl_easy_perform(c.curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "WebSocket connection failed: %s, falling back to HTTP\n",
                    curl_easy_strerror(res));
            c.use_websocket = 0;
            curl_easy_cleanup(c.curl);
            c.curl = curl_easy_init();
            if (!c.curl) return -1;
        } else {
            printf("[CDP] WebSocket connected\n");
            size_t sent;

            const char *enable_cmd = "{\"id\":1,\"method\":\"Page.enable\"}";
            curl_ws_send(c.curl, enable_cmd, strlen(enable_cmd), &sent, 0, CURLWS_TEXT);

            const char *rt_cmd = "{\"id\":2,\"method\":\"Runtime.enable\"}";
            curl_ws_send(c.curl, rt_cmd, strlen(rt_cmd), &sent, 0, CURLWS_TEXT);

            /* Install marker hook into every new document. The source string
             * contains no double-quotes so it needs no JSON escaping. */
            char instr[2048];
            snprintf(instr, sizeof(instr),
                     "{\"id\":3,\"method\":\"Page.addScriptToEvaluateOnNewDocument\","
                     "\"params\":{\"source\":\"%s\"}}",
                     INSTRUMENT_JS);
            curl_ws_send(c.curl, instr, strlen(instr), &sent, 0, CURLWS_TEXT);

            printf("[CDP] Page.enable + Runtime.enable + instrumentation sent\n");
            return 0;
        }
    }

    printf("[CDP] Using HTTP fallback\n");
    curl_easy_setopt(c.curl, CURLOPT_TIMEOUT, 5L);
    curl_easy_setopt(c.curl, CURLOPT_CONNECTTIMEOUT, 3L);
    printf("[CDP] HTTP connection established\n");

    return 0;
}

/* Navigate to a URL */
int navigate_to(const char *url) {
    if (!c.curl) {
        fprintf(stderr, "Not connected\n");
        return -1;
    }

    if (c.use_websocket) {
        char nav_cmd[8192];
        snprintf(nav_cmd, sizeof(nav_cmd),
                 "{\"id\":50,\"method\":\"Page.navigate\","
                 "\"params\":{\"url\":\"%s\"}}",
                 url);
        size_t sent;
        curl_ws_send(c.curl, nav_cmd, strlen(nav_cmd), &sent, 0, CURLWS_TEXT);
    } else {
        char params[8192];
        snprintf(params, sizeof(params), "{\"url\":\"%s\"}", url);
        send_cdp_http("Page.navigate", params, 50);
    }
    return 0;
}

/* Send a raw CDP command */
int send_cdp(const char *method, const char *params, int id) {
    if (!c.curl) return -1;

    if (c.use_websocket) {
        char cmd[MAX_CDP_CMD];
        snprintf(cmd, sizeof(cmd),
                 "{\"id\":%d,\"method\":\"%s\",\"params\":%s}", id, method, params);
        size_t sent;
        CURLcode res = curl_ws_send(c.curl, cmd, strlen(cmd), &sent, 0, CURLWS_TEXT);
        if (res != CURLE_OK) {
            fprintf(stderr, "[CDP] send_cdp failed (%s): %s\n",
                    method, curl_easy_strerror(res));
            return -1;
        }
    } else {
        send_cdp_http(method, params, id);
    }
    return 0;
}

/* Simulate mouse movement */
int simulate_mouse_move(int x, int y) {
    char params[256];
    snprintf(params, sizeof(params),
             "{\"type\":\"mouseMoved\",\"x\":%d,\"y\":%d,"
             "\"button\":\"none\",\"modifiers\":0,\"pointerType\":\"mouse\"}",
             x, y);
    return send_cdp("Input.dispatchMouseEvent", params, 100);
}

/* Simulate mouse click */
int simulate_click(int x, int y) {
    char press_params[256];
    snprintf(press_params, sizeof(press_params),
             "{\"type\":\"mousePressed\",\"x\":%d,\"y\":%d,"
             "\"button\":\"left\",\"clickCount\":1,\"modifiers\":0,"
             "\"pointerType\":\"mouse\"}",
             x, y);
    if (send_cdp("Input.dispatchMouseEvent", press_params, 101) != 0)
        return -1;

    usleep(50000);

    char release_params[256];
    snprintf(release_params, sizeof(release_params),
             "{\"type\":\"mouseReleased\",\"x\":%d,\"y\":%d,"
             "\"button\":\"left\",\"clickCount\":1,\"modifiers\":0,"
             "\"pointerType\":\"mouse\"}",
             x, y);
    return send_cdp("Input.dispatchMouseEvent", release_params, 102);
}

/* Poll for dialogs and handle them */
int handle_dialogs(int max_polls) {
    if (!c.curl) return -1;
    if (!c.use_websocket) return 1;

    for (int i = 0; i < max_polls; i++) {
        const struct curl_ws_frame *meta;
        char buf[4096];
        size_t nread;

        CURLcode rc = curl_ws_recv(c.curl, buf, sizeof(buf) - 1, &nread, &meta);
        if (rc == CURLE_AGAIN) {
            usleep(100000);
            continue;
        }
        if (rc != CURLE_OK) break;
        if (nread == 0) continue;

        buf[nread] = '\0';

        if (strstr(buf, "Page.javascriptDialogOpening")) {
            const char *handle_cmd =
                "{\"id\":3,\"method\":\"Page.handleJavaScriptDialog\","
                "\"params\":{\"accept\":true}}";
            size_t sent;
            curl_ws_send(c.curl, handle_cmd, strlen(handle_cmd), &sent, 0, CURLWS_TEXT);
            printf("[CDP] XSS DETECTED — dialog accepted\n");
            return 0;
        }
    }
    return 1;
}

/* Check window.__gq_xss via Runtime.evaluate.
 * Returns 0 if the marker fired, 1 otherwise. */
int probe_runtime_marker(void) {
    if (!c.curl || !c.use_websocket) return 1;

    const char *cmd =
        "{\"id\":77,\"method\":\"Runtime.evaluate\",\"params\":{"
        "\"expression\":\"window.__gq_xss===1\","
        "\"returnByValue\":true}}";

    size_t sent;
    if (curl_ws_send(c.curl, cmd, strlen(cmd), &sent, 0, CURLWS_TEXT) != CURLE_OK)
        return 1;

    for (int i = 0; i < 20; i++) {
        const struct curl_ws_frame *meta;
        char buf[4096];
        size_t n;
        CURLcode rc = curl_ws_recv(c.curl, buf, sizeof(buf) - 1, &n, &meta);
        if (rc == CURLE_AGAIN) { usleep(50000); continue; }
        if (rc != CURLE_OK) break;
        if (n == 0) continue;
        buf[n] = '\0';
        if (strstr(buf, "\"id\":77") && strstr(buf, "\"value\":true"))
            return 0;
    }
    return 1;
}

/* Detect what interaction a payload needs based on its event handler */
int detect_payload_event_type(const char *payload) {
    if (!payload) return XSS_INTERACT_NONE;

    if (strstr(payload, "onmousemove") ||
        strstr(payload, "onmouseover") ||
        strstr(payload, "onmouseenter") ||
        strstr(payload, "onpointermove") ||
        strstr(payload, "onpointerover") ||
        strstr(payload, "onpointerenter"))
        return XSS_INTERACT_MOUSE;

    if (strstr(payload, "onclick") ||
        strstr(payload, "ondblclick") ||
        strstr(payload, "onpointerdown") ||
        strstr(payload, "onpointerup") ||
        (strstr(payload, "href=javascript:") && strstr(payload, "<a")) ||
        (strstr(payload, "href=javascript:") && strstr(payload, "<area")))
        return XSS_INTERACT_CLICK;

    return XSS_INTERACT_NONE;
}

/* Enhanced XSS detection — dialogs OR runtime marker */
int detect_xss(int max_polls, int interaction) {
    if (interaction == XSS_INTERACT_MOUSE) {
        for (int step = 0; step < 10; step++) {
            simulate_mouse_move(step * 100 + 10, 50 + (step % 5) * 30);
            usleep(80000);
            if (handle_dialogs(3) == 0) return 0;
        }
        if (handle_dialogs(max_polls) == 0) return 0;
        return probe_runtime_marker();
    }

    if (interaction == XSS_INTERACT_CLICK) {
        int click_positions[][2] = {
            {100, 100}, {200, 150}, {300, 200},
            {50, 50},   {400, 300}, {150, 250}
        };
        for (int i = 0; i < 6; i++) {
            simulate_click(click_positions[i][0], click_positions[i][1]);
            usleep(100000);
            if (handle_dialogs(3) == 0) return 0;
        }
        if (handle_dialogs(max_polls) == 0) return 0;
        return probe_runtime_marker();
    }

    if (handle_dialogs(max_polls) == 0) return 0;
    return probe_runtime_marker();
}

/* Clean up */
void close_chrome() {
    if (c.curl) {
        curl_easy_cleanup(c.curl);
        c.curl = NULL;
    }
    if (system("pkill -f 'remote-debugging-port' 2>/dev/null") == -1) {
        /* Process may not exist, ignore */
    }
}