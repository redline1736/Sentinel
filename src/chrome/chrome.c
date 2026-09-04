#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "chrome.h"        // FIX: defines XSS_INTERACT_MOUSE/CLICK/NONE

#define MAX_WS_URL 256
#define MAX_CDP_CMD 4096

typedef struct {
    CURL *curl;
    char ws_url[MAX_WS_URL];
} chrome;

chrome c = {0};

/* FIX: static C callback replaces C++ lambda (invalid in C) */
static size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t total = size * nmemb;
    char *buf = (char*)userdata;
    size_t current_len = strlen(buf);
    size_t max_len = 4095; /* Leave room for null terminator */
    
    if (current_len + total > max_len) {
        total = max_len - current_len;
    }
    if (total > 0) {
        memcpy(buf + current_len, ptr, total);
        buf[current_len + total] = '\0';
    }
    return size * nmemb;
}

/* ---------- Utility: wait for a TCP port to be open ---------- */
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
            return 0;  // port is open
        }
        close(fd);
        usleep(100000);  // 100ms
    }
    return -1;  // timeout
}

/* ---------- Query /json endpoint to get the actual WS URL ---------- */
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

    /* Make sure response is null-terminated */
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

/* ---------- Initialize Chrome and connect ---------- */
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
    system(cmd);

    if (wait_for_port(port, 10) != 0) {
        fprintf(stderr, "Timed out waiting for Chrome on port %d\n", port);
        return -1;
    }
    printf("[CDP] Chrome is ready on port %d\n", port);

    if (discover_ws_url(port) != 0) return -1;

    c.curl = curl_easy_init();
    if (!c.curl) return -1;

    curl_easy_setopt(c.curl, CURLOPT_URL, c.ws_url);
    curl_easy_setopt(c.curl, CURLOPT_CONNECT_ONLY, 2L); // WebSocket mode

    CURLcode res = curl_easy_perform(c.curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "WebSocket connection failed: %s\n", curl_easy_strerror(res));
        curl_easy_cleanup(c.curl);
        c.curl = NULL;
        return -1;
    }
    printf("[CDP] WebSocket connected\n");

    // Enable Page domain so we get dialog events
    const char *enable_cmd = "{\"id\":1,\"method\":\"Page.enable\"}";
    size_t sent;
    curl_ws_send(c.curl, enable_cmd, strlen(enable_cmd), &sent, 0, CURLWS_TEXT);
    printf("[CDP] Page.enable sent\n");

    return 0;
}

/* ---------- Navigate to a URL ---------- */
int navigate_to(const char *url) {
    if (!c.curl) {
        fprintf(stderr, "Not connected\n");
        return -1;
    }
    char nav_cmd[1024];
    snprintf(nav_cmd, sizeof(nav_cmd),
             "{\"id\":2,\"method\":\"Page.navigate\","
             "\"params\":{\"url\":\"%s\"}}",
             url);
    size_t sent;
    curl_ws_send(c.curl, nav_cmd, strlen(nav_cmd), &sent, 0, CURLWS_TEXT);
    printf("[CDP] Navigate sent: %s\n", url);
    return 0;
}

/* ---------- Send a raw CDP command ---------- */
int send_cdp(const char *method, const char *params, int id) {
    if (!c.curl) return -1;
    char cmd[MAX_CDP_CMD];
    snprintf(cmd, sizeof(cmd),
             "{\"id\":%d,\"method\":\"%s\",\"params\":%s}", id, method, params);
    size_t sent;
    CURLcode res = curl_ws_send(c.curl, cmd, strlen(cmd), &sent, 0, CURLWS_TEXT);
    if (res != CURLE_OK) {
        fprintf(stderr, "[CDP] send_cdp failed (%s): %s\n", method, curl_easy_strerror(res));
        return -1;
    }
    return 0;
}

/* ---------- Simulate mouse movement via CDP Input.dispatchMouseEvent ---------- */
int simulate_mouse_move(int x, int y) {
    char params[256];
    snprintf(params, sizeof(params),
             "{\"type\":\"mouseMoved\",\"x\":%d,\"y\":%d,"
             "\"button\":\"none\",\"modifiers\":0,\"pointerType\":\"mouse\"}",
             x, y);
    int ret = send_cdp("Input.dispatchMouseEvent", params, 100);
    if (ret == 0)
        printf("[CDP] Mouse moved to (%d, %d)\n", x, y);
    return ret;
}

/* ---------- Simulate mouse click via CDP Input.dispatchMouseEvent ---------- */
int simulate_click(int x, int y) {
    char press_params[256];
    snprintf(press_params, sizeof(press_params),
             "{\"type\":\"mousePressed\",\"x\":%d,\"y\":%d,"
             "\"button\":\"left\",\"clickCount\":1,\"modifiers\":0,"
             "\"pointerType\":\"mouse\"}",
             x, y);
    if (send_cdp("Input.dispatchMouseEvent", press_params, 101) != 0)
        return -1;

    usleep(50000); // 50ms between press and release

    char release_params[256];
    snprintf(release_params, sizeof(release_params),
             "{\"type\":\"mouseReleased\",\"x\":%d,\"y\":%d,"
             "\"button\":\"left\",\"clickCount\":1,\"modifiers\":0,"
             "\"pointerType\":\"mouse\"}",
             x, y);
    int ret = send_cdp("Input.dispatchMouseEvent", release_params, 102);
    if (ret == 0)
        printf("[CDP] Click at (%d, %d)\n", x, y);
    return ret;
}

/* ---------- Poll for dialogs and handle them ---------- */
int handle_dialogs(int max_polls) {
    if (!c.curl) return -1;

    for (int i = 0; i < max_polls; i++) {
        const struct curl_ws_frame *meta;
        char buf[4096];
        size_t nread;

        CURLcode rc = curl_ws_recv(c.curl, buf, sizeof(buf) - 1, &nread, &meta);
        if (rc == CURLE_AGAIN) {
            usleep(100000); // 100ms
            continue;
        }
        if (rc != CURLE_OK) {
            fprintf(stderr, "WebSocket recv error: %s\n", curl_easy_strerror(rc));
            break;
        }
        if (nread == 0) continue;

        buf[nread] = '\0';
        printf("[WS] %s\n", buf);

        if (strstr(buf, "Page.javascriptDialogOpening")) {
            const char *handle_cmd =
                "{\"id\":3,\"method\":\"Page.handleJavaScriptDialog\","
                "\"params\":{\"accept\":true}}";
            size_t sent;
            curl_ws_send(c.curl, handle_cmd, strlen(handle_cmd), &sent, 0, CURLWS_TEXT);
            printf("[CDP] XSS DETECTED — dialog accepted\n");
            return 0;  // XSS confirmed
        }
    }
    return 1;  // No dialog detected
}

/* ---------- Detect what interaction a payload needs based on its event handler ---------- */
int detect_payload_event_type(const char *payload) {
    if (!payload) return XSS_INTERACT_NONE;
    
    /* Event handlers that fire on mouse movement */
    if (strstr(payload, "onmousemove") ||
        strstr(payload, "onmouseover") ||
        strstr(payload, "onmouseenter") ||
        strstr(payload, "onpointermove") ||
        strstr(payload, "onpointerover") ||
        strstr(payload, "onpointerenter"))
        return XSS_INTERACT_MOUSE;

    /* Event handlers that fire on click */
    if (strstr(payload, "onclick") ||
        strstr(payload, "ondblclick") ||
        strstr(payload, "onpointerdown") ||
        strstr(payload, "onpointerup") ||
        (strstr(payload, "href=javascript:") && strstr(payload, "<a")) ||
        (strstr(payload, "href=javascript:") && strstr(payload, "<area")))
        return XSS_INTERACT_CLICK;

    /* Default: onload, onerror, onfocus, onabort, autofocus, etc. fire automatically */
    return XSS_INTERACT_NONE;
}

/* ---------- Enhanced XSS detection: navigate, interact, detect ---------- */
int detect_xss(int max_polls, int interaction) {
    if (interaction == XSS_INTERACT_MOUSE) {
        /* Move mouse across the page — sweep (x,y) to trigger onmousemove/onmouseover */
        for (int step = 0; step < 10; step++) {
            simulate_mouse_move(step * 100 + 10, 50 + (step % 5) * 30);
            usleep(80000); // 80ms between moves

            /* Check for dialog after each move */
            if (handle_dialogs(3) == 0)
                return 0;  /* XSS confirmed */
        }
        /* Final check after all moves */
        return handle_dialogs(max_polls);
    }

    if (interaction == XSS_INTERACT_CLICK) {
        /* Click at several positions across the page */
        int click_positions[][2] = {
            {100, 100}, {200, 150}, {300, 200},
            {50, 50},   {400, 300}, {150, 250}
        };
        for (int i = 0; i < 6; i++) {
            simulate_click(click_positions[i][0], click_positions[i][1]);
            usleep(100000); // 100ms

            if (handle_dialogs(3) == 0)
                return 0;  /* XSS confirmed */
        }
        return handle_dialogs(max_polls);
    }

    /* XSS_INTERACT_NONE — just poll for dialogs (onload, onerror fire automatically) */
    return handle_dialogs(max_polls);
}

/* ---------- Clean up ---------- */
void close_chrome() {
    if (c.curl) {
        curl_easy_cleanup(c.curl);
        c.curl = NULL;
    }
    system("pkill -f 'remote-debugging-port' 2>/dev/null");
}