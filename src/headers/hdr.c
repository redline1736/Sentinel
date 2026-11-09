#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "../global.h"
#include "../http/http.h"
#include "hdr.h"

void header(const char *base_url, const char *hostdir) {
    if (!base_url || !hostdir) return;

    char outpath[2048];
    snprintf(outpath, sizeof(outpath), "%s/headers.txt", hostdir);

    request r = {0};
    if (!http_send_get(&r, base_url) || r.code == 0) {
        fprintf(stderr, "[headers] request failed for %s\n", base_url);
        request_free(&r);
        return;
    }
    printf("[headers] %s -> HTTP %d\n", base_url, r.code);

    FILE *out = fopen(outpath, "w");
    if (!out) {
        fprintf(stderr, "[headers] cannot write %s\n", outpath);
        request_free(&r);
        return;
    }

    int has_csp = 0, has_hsts = 0, has_xfo = 0, has_nosniff = 0, has_refpol = 0;

    /* r.headers is a NUL-terminated raw header block, CRLF-separated. */
    const char *line = r.headers;
    while (line && *line) {
        const char *eol = strchr(line, '\n');
        size_t len = eol ? (size_t)(eol - line) : strlen(line);
        if (len >= HTTP_HDR_MAX) len = HTTP_HDR_MAX - 1;

        char buf[HTTP_HDR_MAX];
        memcpy(buf, line, len);
        buf[len] = '\0';

        size_t bl = strlen(buf);
        while (bl && buf[bl - 1] == '\r')
            buf[--bl] = '\0';

        char *colon = strchr(buf, ':');
        if (colon) {
            *colon = '\0';
            char *v = colon + 1;
            while (*v == ' ') v++;

            char name[64];
            snprintf(name, sizeof(name), "%s", buf);
            for (char *p = name; *p; p++)
                *p = (char)tolower((unsigned char)*p);

            if (!strcmp(name, "content-security-policy"))   has_csp = 1;
            if (!strcmp(name, "strict-transport-security")) has_hsts = 1;
            if (!strcmp(name, "x-frame-options") ||
                (!strcmp(name, "content-security-policy") &&
                 strstr(v, "frame-ancestors")))               has_xfo = 1;
            if (!strcmp(name, "x-content-type-options"))    has_nosniff = 1;
            if (!strcmp(name, "referrer-policy"))           has_refpol = 1;

            if (!strcmp(name, "access-control-allow-origin") &&
                !strcmp(v, "*"))
                fprintf(out, "[CORS] Wildcard Access-Control-Allow-Origin on %s\n",
                        base_url);

            if (!strcmp(name, "server") || !strcmp(name, "x-powered-by"))
                fprintf(out, "[INFO] %s: %s (fingerprint exposure)\n", name, v);

            if (!strcmp(name, "set-cookie")) {
                if (!strstr(v, "HttpOnly"))
                    fprintf(out, "[COOKIE] Missing HttpOnly: %.120s\n", v);
                if (!strstr(v, "Secure"))
                    fprintf(out, "[COOKIE] Missing Secure flag: %.120s\n", v);
            }
        }

        line = eol ? eol + 1 : NULL;
    }

    if (!has_csp)     fprintf(out, "[HEADER] Missing Content-Security-Policy\n");
    if (!has_hsts)    fprintf(out, "[HEADER] Missing Strict-Transport-Security\n");
    if (!has_xfo)     fprintf(out, "[HEADER] Missing clickjacking protection\n");
    if (!has_nosniff) fprintf(out, "[HEADER] Missing X-Content-Type-Options\n");
    if (!has_refpol)  fprintf(out, "[HEADER] Missing Referrer-Policy\n");

    fclose(out);
    request_free(&r);

    printf("[headers] findings written to %s\n", outpath);
}