#include "../global.h"
#include <curl/curl.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

#include "http.h"

/* Per-process unique temp file counter, atomic. */
static _Atomic unsigned long g_http_seq = 0;

static size_t write_file(void *ptr, size_t size, size_t nmemb, void *stream) {
    return fwrite(ptr, size, nmemb, (FILE *)stream);
}

static const char* detect_content_type(const char *filename) {
    const char *ext = strrchr(filename, '.');
    if (!ext) return "application/octet-stream";
    if (strcmp(ext, ".json") == 0) return "application/json";
    if (strcmp(ext, ".png") == 0)  return "image/png";
    if (strcmp(ext, ".jpg") == 0 || strcmp(ext, ".jpeg") == 0) return "image/jpeg";
    if (strcmp(ext, ".gif") == 0)  return "image/gif";
    if (strcmp(ext, ".txt") == 0)  return "text/plain";
    if (strcmp(ext, ".html") == 0) return "text/html";
    if (strcmp(ext, ".css") == 0)  return "text/css";
    if (strcmp(ext, ".js") == 0)   return "application/javascript";
    if (strcmp(ext, ".xml") == 0)  return "application/xml";
    if (strcmp(ext, ".pdf") == 0)  return "application/pdf";
    if (strcmp(ext, ".zip") == 0)  return "application/zip";
    return "application/octet-stream";
}

static bool setup_curl(CURL *curl, const char *url, FILE *fp) {
    if (!curl || !url || !fp) return false;

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_file);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 10L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Sentinel-scan/1.0");
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    /* TLS verification ON. Use --insecure-style env override only if
     * explicitly asked for. */
    if (getenv("SENTINEL_INSECURE_TLS")) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }
    /* Route through proxy pool for ALL requests (was GET-only). */
    if (g.proxy) {
        const char *p = proxy_get_socks();
        if (p) curl_easy_setopt(curl, CURLOPT_PROXY, p);
    }
    return true;
}

static int save_response(request *r, CURL *curl, const char *filename) {
    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    if (r) {
        r->code = (int)code;
        snprintf(r->filename, sizeof(r->filename), "%s", filename);
    }
    return 1;
}

static void cleanup_fp(FILE *fp, CURL *curl, const char *filename) {
    if (fp) fclose(fp);
    if (curl) curl_easy_cleanup(curl);
    if (filename && filename[0]) remove(filename);
}

int http_send_get(request *r, const char *url) {
    char filename[64];
    snprintf(filename, sizeof(filename), "curl_%d_%lu.tmp",
             (int)getpid(), (unsigned long)++g_http_seq);

    FILE *fp = fopen(filename, "wb");
    if (!fp) return 0;

    CURL *curl = curl_easy_init();
    if (!curl) { cleanup_fp(fp, NULL, filename); return 0; }
    if (!setup_curl(curl, url, fp)) { cleanup_fp(fp, curl, filename); return 0; }

    CURLcode result = curl_easy_perform(curl);
    if (result != CURLE_OK) {
        fprintf(stderr, "GET failed: %s\n", curl_easy_strerror(result));
        cleanup_fp(fp, curl, filename);
        return 0;
    }
    fclose(fp);
    save_response(r, curl, filename);
    curl_easy_cleanup(curl);
    return 1;
}

int http_send_post(request *r, const char *url,
                   bool upload, const char *data,
                   bool is_raw, const char *raw_data) {
    char filename[64];
    snprintf(filename, sizeof(filename), "curl_%d_%lu.tmp",
             (int)getpid(), (unsigned long)++g_http_seq);

    FILE *fp = fopen(filename, "wb");
    if (!fp) return 0;

    CURL *curl = curl_easy_init();
    if (!curl) { cleanup_fp(fp, NULL, filename); return 0; }
    if (!setup_curl(curl, url, fp)) { cleanup_fp(fp, curl, filename); return 0; }

    CURLcode result = CURLE_OK;
    curl_mime *mime = NULL;
    struct curl_slist *headers = NULL;

    if (is_raw) {
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, raw_data ? raw_data : "");
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, raw_data ? strlen(raw_data) : 0);
    } else if (upload) {
        if (!data) { cleanup_fp(fp, curl, filename); return 0; }
        FILE *test = fopen(data, "rb");
        if (!test) {
            fprintf(stderr, "File does not exist: %s\n", data);
            cleanup_fp(fp, curl, filename);
            return 0;
        }
        fclose(test);
        mime = curl_mime_init(curl);
        if (!mime) { cleanup_fp(fp, curl, filename); return 0; }
        curl_mimepart *part = curl_mime_addpart(mime);
        curl_mime_filedata(part, data);
        curl_mime_type(part, detect_content_type(data));
        curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);
    } else {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "");
    }

    result = curl_easy_perform(curl);
    if (mime) curl_mime_free(mime);
    if (headers) curl_slist_free_all(headers);

    if (result != CURLE_OK) {
        fprintf(stderr, "POST failed: %s\n", curl_easy_strerror(result));
        cleanup_fp(fp, curl, filename);
        return 0;
    }
    fclose(fp);
    save_response(r, curl, filename);
    curl_easy_cleanup(curl);
    return 1;
}

int http_send_option(request *r, const char *url) {
        static unsigned int counter = 0;

    char filename[64];
    snprintf(filename, sizeof(filename), "curl_%u.txt", counter++);

    FILE *fp = fopen(filename, "wb");
    if (!fp) return 0;

    CURL *curl = curl_easy_init();
    if (!curl) { fclose(fp); remove(filename); return 0; }

    if (g.proxy) {
        proxy = proxy_get_socks();
        if (!proxy)
            fprintf(stderr, "gq_http_send: no proxy available — sending direct\n");
    }

    if (!setup_curl(curl, url, fp)) {
        fclose(fp);
        curl_easy_cleanup(curl);
        remove(filename);
        return 0;
    }
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "OPTIONS");

    // Optional: Include response headers in the output to see allowed methods
    curl_easy_setopt(curl, CURLOPT_HEADER, 1L);
    if (proxy) curl_easy_setopt(curl, CURLOPT_PROXY, proxy);
    CURLcode result = curl_easy_perform(curl);
    if (result != CURLE_OK) {
        fprintf(stderr, "GET failed: %s\n", curl_easy_strerror(result));
        fclose(fp);
        curl_easy_cleanup(curl);
        remove(filename);
        return 0;
    }

    fclose(fp);
    save_response(r, curl, filename);
    curl_easy_cleanup(curl);
    return 1;
}