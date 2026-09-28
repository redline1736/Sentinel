#ifndef HTTP_H
#define HTTP_H

#include <stdbool.h>

typedef struct {
    int code;
    char filename[64];
} request;

int http_send_get(request *r, const char *url);
int http_send_post(request *r, const char *url,
                   bool upload, const char *data,
                   bool is_raw, const char *raw_data);

#endif