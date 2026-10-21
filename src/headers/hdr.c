#include <curl/curl.h>
#include "../global.h"
#include "../prox/prox.h"
#include "hdr.h"
#include <pthread.h>

static size_t hdr_cb(char *b, size_t s, size_t n, void *ud) {
    FILE *f = (FILE *)ud; fwrite(b, s, n, f); return s * n;
}

/* Checks one http(s) host; writes findings to <outdir>/<host>/headers.txt */
void *header_scan(void *arg) {

    headers_t *hdr_args = (headers_t *)arg;
    const char *host = hdr_args->host;
    const char *outdir = hdr_args->outdir;

    char url[512], outpath[1024];
    snprintf(url, sizeof(url), "https://%s/", host);
    snprintf(outpath, sizeof(outpath), "%s/%s/headers.txt", outdir, host);

    FILE *out = fopen(outpath, "w");
    if (!out) return;

    if (g.proxy) {
        proxy = proxy_get_socks();
        if (!proxy)
            fprintf(stderr, "gq_http_send: no proxy available — sending direct\n");
    }

    CURL *c = curl_easy_init();
    if (!c) { fclose(out); return; }
    FILE *hdr = tmpfile();
    if (proxy) curl_easy_setopt(c, CURLOPT_PROXY, proxy);
    curl_easy_setopt(c, CURLOPT_URL, url);
    curl_easy_setopt(c, CURLOPT_HEADERFUNCTION, hdr_cb);
    curl_easy_setopt(c, CURLOPT_WRITEHEADER, hdr);        /* headers to tmpfile */
    curl_easy_setopt(c, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 20L);
    curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(c, CURLOPT_USERAGENT, "Sentinel-scan/1.0");
    curl_easy_perform(c);

    long code = 0;
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &code);
    curl_easy_cleanup(c);

    rewind(hdr);
    char line[4096];
    int has_csp = 0, has_hsts = 0, has_xfo = 0, has_nosniff = 0, has_refpol = 0;
    while (fgets(line, sizeof(line), hdr)) {
        for (char *p = line; *p; p++) *p = (char)(*p == '\n' || *p == '\r' ? 0 : *p);
        char *colon = strchr(line, ':');
        if (!colon) continue;
        *colon = 0;
        char *v = colon + 1; while (*v == ' ') v++;
        char name[64]; snprintf(name, sizeof(name), "%s", line);
        for (char *p = name; *p; p++) *p = (char)tolower((unsigned char)*p);

        if (!strcmp(name, "content-security-policy")) has_csp = 1;
        if (!strcmp(name, "strict-transport-security")) has_hsts = 1;
        if (!strcmp(name, "x-frame-options") ||
            (!strcmp(name, "content-security-policy") && strstr(v, "frame-ancestors"))) has_xfo = 1;
        if (!strcmp(name, "x-content-type-options")) has_nosniff = 1;
        if (!strcmp(name, "referrer-policy")) has_refpol = 1;
        if (!strcmp(name, "access-control-allow-origin") && !strcmp(v, "*"))
            fprintf(out, "[CORS] Wildcard Access-Control-Allow-Origin on %s\n", host);
        if (!strcmp(name, "server") || !strcmp(name, "x-powered-by"))
            fprintf(out, "[INFO] %s: %s (fingerprint exposure)\n", name, v);
        if (!strcmp(name, "set-cookie") && !strstr(v, "HttpOnly"))
            fprintf(out, "[COOKIE] Missing HttpOnly: %.120s\n", v);
        if (!strcmp(name, "set-cookie") && !strstr(v, "Secure"))
            fprintf(out, "[COOKIE] Missing Secure flag: %.120s\n", v);
    }
    if (!has_csp)     fprintf(out, "[HEADER] Missing Content-Security-Policy\n");
    if (!has_hsts)    fprintf(out, "[HEADER] Missing Strict-Transport-Security\n");
    if (!has_xfo)     fprintf(out, "[HEADER] Missing clickjacking protection\n");
    if (!has_nosniff) fprintf(out, "[HEADER] Missing X-Content-Type-Options\n");
    if (!has_refpol)  fprintf(out, "[HEADER] Missing Referrer-Policy\n");
    (void)code;
    fclose(hdr); fclose(out);
}