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
void scanning(char *target_url);
void *wpscan(void *arg);  /* thread worker */
void run(char *url);  /* main pipeline (subdomain + scanning + analysis) */
void analyze();
#endif