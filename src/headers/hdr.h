#ifndef HDR_H
#define HDR_H

typedef struct {
    char *host;
    char *outdir;
} headers_t;

void header_scan(void *arg);

#endif /* HDR_H */