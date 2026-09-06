#ifndef GQ_H
#define GQ_H
#include "../global.h"
int sql_run(void);
int xss_run(char *url, char *path);
int find_param_reflecting(char *url, char *path);
void xss_reflect(char *url, char *path);
void xss_custom(char *url, char *path);  /* NEW: handles mouse/click/link XSS events */

#endif