#ifndef CHROME_H
#define CHROME_H

#include <sys/types.h>
#include <curl/curl.h>

#define MAX_WS_URL   256
#define MAX_CDP_CMD  4096

typedef struct {
    CURL  *curl;
    char   ws_url[MAX_WS_URL];
    int    use_websocket;
    pid_t  pid;          /* Chrome process, for isolated cleanup */
    int    port;
} chrome;

/* XSS interaction types */
#define XSS_INTERACT_NONE   0
#define XSS_INTERACT_MOUSE  1
#define XSS_INTERACT_CLICK  2

/* Function prototypes */
int  init_chrome(chrome *c, int port);
int  wait_for_port(int port, int timeout_sec);
int  discover_ws_url(chrome *c, int port);
int  navigate_to(chrome *c, const char *url);
int  send_cdp(chrome *c, const char *method, const char *params, int id);
int  simulate_mouse_move(chrome *c, int x, int y);
int  simulate_click(chrome *c, int x, int y);
int  handle_dialogs(chrome *c, int max_polls);
int  detect_payload_event_type(const char *payload);
int  detect_xss(chrome *c, int max_polls, int interaction);
int  probe_runtime_marker(chrome *c);   /* 0 if window.__gq_xss===1, else 1 */
void close_chrome(chrome *c);

#endif /* CHROME_H */