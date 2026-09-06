#ifndef CHROME_H
#define CHROME_H

#ifdef __cplusplus
extern "C" {
#endif

/* XSS interaction types */
#define XSS_INTERACT_NONE   0
#define XSS_INTERACT_MOUSE  1
#define XSS_INTERACT_CLICK  2

/* Function prototypes */
int init_chrome(int port);
int wait_for_port(int port, int timeout_sec);
int discover_ws_url(int port);
int navigate_to(const char *url);
int send_cdp(const char *method, const char *params, int id);
int simulate_mouse_move(int x, int y);
int simulate_click(int x, int y);
int handle_dialogs(int max_polls);
int detect_payload_event_type(const char *payload);
int detect_xss(int max_polls, int interaction);
void close_chrome(void);

#ifdef __cplusplus
}
#endif

#endif /* CHROME_H */