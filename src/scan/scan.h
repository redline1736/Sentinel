#ifndef SCAN_H
#define SCAN_H

#include <stdbool.h>

/* Rate-limit tunables (defined in scan.c) */
extern int g_rate;
extern double g_retry_minutes;

/* HTTP request wrapper (implemented in scan.c; honors the active proxy) */
int http_send(const char *url, const char *method, const char *file);
void enumerate_rate(const char *url, const char *method, const char *file);

/* Recon functions */
void subdomain();
void scanning();
void *wpscan(void *arg);  /* thread worker */
void analyze();
void run();

#endif