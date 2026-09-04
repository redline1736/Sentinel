#ifndef CHROME_H
#define CHROME_H

/* XSS trigger interaction types */
#define XSS_INTERACT_NONE      0   /* Just poll for dialogs (onload, onerror) */
#define XSS_INTERACT_MOUSE     1   /* Simulate mouse movement (onmousemove, onmouseover) */
#define XSS_INTERACT_CLICK     2   /* Simulate click (onclick) */

int wait_for_port(int port, int timeout_sec);
int discover_ws_url(int port);
int init_chrome(int port);
int navigate_to(const char *url);
int handle_dialogs(int max_polls);

/* New XSS-specific CDP functions */
int send_cdp(const char *method, const char *params, int id);
int simulate_mouse_move(int x, int y);
int simulate_click(int x, int y);
int detect_xss(int max_polls, int interaction);

/* Inspect a payload string to determine what interaction it needs */
int detect_payload_event_type(const char *payload);

void close_chrome();

#endif