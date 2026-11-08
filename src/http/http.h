#ifndef HTTP_H
#define HTTP_H

#include <stddef.h>
#include <stdbool.h>

#define HTTP_HDR_MAX 16384

typedef struct {
    int    code;              /* HTTP status, 0 on transport failure */
    char  *body;              /* NUL-terminated response body (may be binary; len in body_len) */
    size_t body_len;
    char   headers[HTTP_HDR_MAX]; /* raw header block, NUL-terminated */
    char   effective_url[2048];
    char  *filename;          /* auto: "curl_<rand>.txt" the body was mirrored to */
} request;

void curl_http_init(void);
void curl_http_cleanup(void);

/* free a request's dynamic members; safe on zeroed requests */
void request_free(request *r);

/* case-insensitive header lookup out of r->headers; false if absent */
bool http_get_header(const request *r, const char *name,
                     char *out, size_t outsz);

int http_send_get(request *r, const char *url);
int http_send_post(request *r, const char *url,
                   bool upload, const char *data,
                   bool is_raw, const char *raw_data);
int http_send_option(request *r, const char *url);

/* returns 1 on success and fills r; 0 on failure (r is still valid/zeroed) */
#endif /* HTTP_H */