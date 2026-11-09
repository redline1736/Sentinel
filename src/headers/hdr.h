#ifndef HDR_H
#define HDR_H

/* Scan security headers on base_url, write findings to <hostdir>/headers.txt */
void header(const char *base_url, const char *hostdir);

#endif /* HDR_H */