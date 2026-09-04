/* _GNU_SOURCE supplied via CFLAGS (-D_GNU_SOURCE) — do not redefine. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>
#include "util.h"
#include "../prox/prox.h"
#include "../global.h"

struct global g;   /* single definition of the global struct */

static size_t write_callback(void *ptr, size_t size, size_t nmemb, void *stream) {
    return fwrite(ptr, size, nmemb, (FILE *)stream);
}

/* libcurl must be global-init'd exactly once across all threads. */
void curl_http_init(void)      { curl_global_init(CURL_GLOBAL_ALL); }
void curl_http_cleanup(void)   { curl_global_cleanup(); }

void run_requests_json(const char *url, const char *method,
                 const char *file, const char *out_path) {
    FILE *fp = fopen(file, "rb");
    if (!fp) {
        fprintf(stderr, "[-] Cannot open request body: %s\n", file);
        return;
    }

    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    rewind(fp);

    if (size < 0) { fclose(fp); return; }

    char *jsonData = malloc((size_t)size + 1);
    if (!jsonData) { fclose(fp); return; }

    size_t got = fread(jsonData, 1, (size_t)size, fp);
    jsonData[got] = '\0';
    fclose(fp);

    FILE *out = fopen(out_path, "w");
    if (!out) { free(jsonData); return; }

    CURL *curl = curl_easy_init();
    if (curl) {
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");

        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonData);
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, out);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "Sentinel-scan/1.0");

        const char *proxy_str = proxy_get_socks();
        if (proxy_str)
            curl_easy_setopt(curl, CURLOPT_PROXY, proxy_str);

        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "[-] Request failed: %s\n", curl_easy_strerror(res));
        } else {
            long code = 0;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
            fprintf(out, "\nHTTP_CODE:%ld\n", code);
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }

    fclose(out);
    free(jsonData);
}


void run_request(const char *url, const char *data,
                 const char *out_path){
    FILE *out = fopen(out_path, "w");
    if (!out) {
        fprintf(stderr, "[-] Cannot open output: %s\n", out_path);
        return;
    }

    CURL *curl = curl_easy_init();

    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);

        /* POST request */
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);

        /* Save response */
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, out);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);

        curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "Sentinel-scan/1.0");

        const char *proxy_str = proxy_get_socks();
        if (proxy_str)
            curl_easy_setopt(curl, CURLOPT_PROXY, proxy_str);

        CURLcode res = curl_easy_perform(curl);

        if (res != CURLE_OK) {
            fprintf(stderr, "[-] Request failed: %s\n",
                    curl_easy_strerror(res));
        } else {
            long code = 0;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
            fprintf(out, "\nHTTP_CODE:%ld\n", code);
        }

        curl_easy_cleanup(curl);
    }

    fclose(out);
}



void delete_file(const char *file) {
    remove(file);
}

int line_count(const char *file) {
    FILE *fp = fopen(file, "r");
    if (!fp) return 0;
    int count = 0, c;
    while ((c = getc(fp)) != EOF)
        if (c == '\n') count++;
    fclose(fp);
    return count;
}