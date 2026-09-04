#ifndef GLOBAL_H
#define GLOBAL_H

#include <stdbool.h>

#define G_DOMAIN_MAX 512
#define G_DIR_MAX    1536
#define G_PROXY_MAX  (G_DIR_MAX)

struct global {
    char domain[G_DOMAIN_MAX];
    char dir[G_DIR_MAX];
    bool full;
    bool xss;
    bool deepblue;
    bool urlscan;      /* true: --scan-url mode (skip subdomain, live.txt pre-seeded) */
    bool proxy;        /* true when any proxy path is active */
    bool tor;          /* true specifically for the Tor pool */
    int  proxy_mode;   /* PROXY_NONE / PROXY_TOR / PROXY_CUSTOM / PROXY_ELITE */
    char proxy_list[G_PROXY_MAX]; /* path to user proxy file (PROXY_CUSTOM) */
};



extern struct global g;

#endif