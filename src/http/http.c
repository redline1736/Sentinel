#include "../global.h"
#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <time.h>

#include "http.h"
#include "../prox/prox.h"

/* ------------------------------------------------------------------ */
/* Shared connection/DNS cache: the single biggest speed win.        */
/* ------------------------------------------------------------------ */
static CURLSH *g_share = NULL;
static pthread_mutex_t g_share_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_curl_lock  = PTHREAD_MUTEX_INITIALIZER; /* global init guard */

static void share_lock_cb(CURL *handle, curl_lock_data data,
                          curl_lock_access access, void *userptr) {
    (void)handle; (void)data; (void)access; (void)userptr;
    pthread_mutex_lock(&g_share_lock);
}
static void share_unlock_cb(CURL *handle, curl_lock_data data, void *userptr) {
    (void)handle; (void)data; (void)userptr;
    pthread_mutex_unlock(&g_share_lock);
}

void curl_http_init(void) {
    pthread_mutex_lock(&g_curl_lock);
    curl_global_init(CURL_GLOBAL_ALL);
    g_share = curl_share_init();
    if (g_share) {
        curl_share_setopt(g_share, CURLSHOPT_SHARE,    CURL_LOCK_DATA_DNS);
        curl_share_setopt(g_share, CURLSHOPT_SHARE,    CURL_LOCK_DATA_CONNECT);
        curl_share_setopt(g_share, CURLSHOPT_SHARE,    CURL_LOCK_DATA_SSL_SESSION);
        curl_share_setopt(g_share, CURLSHOPT_LOCKFUNC,   share_lock_cb);
        curl_share_setopt(g_share, CURLSHOPT_UNLOCKFUNC, share_unlock_cb);
    }
    /* seed once; rand() alone isn't thread-unique, so we mix in pid + counter */
    srand((unsigned)(time(NULL) ^ getpid()));
    pthread_mutex_unlock(&g_curl_lock);
}

void curl_http_cleanup(void) {
    pthread_mutex_lock(&g_curl_lock);
    if (g_share) { curl_share_cleanup(g_share); g_share = NULL; }
    curl_global_cleanup();
    pthread_mutex_unlock(&g_curl_lock);
}

/* ---------------- auto filename generation ---------------- */

static pthread_mutex_t g_name_lock  = PTHREAD_MUTEX_INITIALIZER;
static unsigned long   g_name_seq   = 0;

/* thread-safe unique name: curl_<rand>_<pid>_<seq>.txt */
static char *make_filename(void)
{
    char buf[128];
    pthread_mutex_lock(&g_name_lock);
    unsigned long seq = ++g_name_seq;
    pthread_mutex_unlock(&g_name_lock);

    unsigned long rnd = ((unsigned long)rand() << 17) ^ (unsigned long)getpid();
    snprintf(buf, sizeof(buf), "curl_%lu_%lu_%lu.txt", rnd, (unsigned long)getpid(), seq);
    return strdup(buf);
}

/* ---------------- in-memory response buffers ---------------- */

typedef struct { char *buf; size_t len, cap; } membuf;

/* dual sink: memory + FILE mirror, one pass */
typedef struct {
    membuf mem;
    FILE  *file;      /* NULL = memory only */
    int    file_err;  /* set if a disk write fails mid-transfer */
} sink;

static size_t body_write(void *ptr, size_t size, size_t nmemb, void *ud) {
    sink *s = ud;
    size_t total = size * nmemb;
    if (total == 0) return 0;

    if (s->file) {
        if (fwrite(ptr, 1, total, s->file) != total)
            s->file_err = 1;          /* keep transfer alive, flag the failure */
    }

    if (s->mem.len + total + 1 > s->mem.cap) {
        size_t ncap = (s->mem.len + total + 1) * 2;
        char *nb = realloc(s->mem.buf, ncap);
        if (!nb) return 0;             /* aborts the transfer */
        s->mem.buf = nb; s->mem.cap = ncap;
    }
    memcpy(s->mem.buf + s->mem.len, ptr, total);
    s->mem.len += total;
    s->mem.buf[s->mem.len] = '\0';
    return total;
}

static size_t hdr_write(void *ptr, size_t size, size_t nmemb, void *ud) {
    request *r = ud;
    size_t total = size * nmemb;
    size_t used = strlen(r->headers);
    if (used + total >= sizeof(r->headers)) total = sizeof(r->headers) - 1 - used;
    if (total) {
        memcpy(r->headers + used, ptr, total);
        r->headers[used + total] = '\0';
    }
    return size * nmemb;   /* always claim full delivery to keep transfer alive */
}

static sink* sink_new(request *r) {
    sink *s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->mem.cap = 8192;
    s->mem.buf = malloc(s->mem.cap);
    if (!s->mem.buf) { free(s); return NULL; }
    s->mem.buf[0] = '\0';

    /* every request gets an auto-generated mirror file */
    r->filename = make_filename();
    if (!r->filename) { free(s->mem.buf); free(s); return NULL; }

    s->file = fopen(r->filename, "wb");
    if (!s->file) {
        fprintf(stderr, "[-] http: cannot open %s for write: %s\n",
                r->filename, strerror(errno));
        free(r->filename);
        r->filename = NULL;
        free(s->mem.buf);
        free(s);
        return NULL;
    }
    return s;
}

static void sink_close(sink *s) {
    if (!s) return;
    if (s->file) {
        if (fflush(s->file) != 0) s->file_err = 1;
        fclose(s->file);
        s->file = NULL;
        if (s->file_err)
            fprintf(stderr, "[!] http: disk write failed; response kept in memory\n");
    }
}

void request_free(request *r) {
    if (!r) return;
    free(r->body);
    r->body = NULL;
    r->body_len = 0;
    free(r->filename);       /* filename is heap-owned by the request */
    r->filename = NULL;
}

bool http_get_header(const request *r, const char *name, char *out, size_t outsz) {
    if (!r || !name) return false;
    size_t nlen = strlen(name);
    const char *p = r->headers;
    while ((p = strstr(p, "\r\n")) != NULL) {
        p += 2;
        if (strncasecmp(p, name, nlen) == 0 && p[nlen] == ':') {
            const char *v = p + nlen + 1;
            while (*v == ' ' || *v == '\t') v++;
            const char *e = strstr(v, "\r\n");
            size_t vlen = e ? (size_t)(e - v) : strlen(v);
            if (vlen >= outsz) vlen = outsz - 1;
            memcpy(out, v, vlen);
            out[vlen] = '\0';
            return true;
        }
    }
    return false;
}

/* ---------------- per-request setup ---------------- */

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

static bool setup_curl(CURL *curl, const char *url, request *r, sink *s) {
    if (!curl || !url || !r || !s) return false;

    r->headers[0] = '\0';
    r->code = 0;
    r->body = NULL;
    r->body_len = 0;

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, body_write);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, s);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, hdr_write);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, r);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 10L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Sentinel-scan/1.0");
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");   /* gzip/br deflate for free */
    if (g_share) curl_easy_setopt(curl, CURLOPT_SHARE, g_share);
    if (getenv("SENTINEL_INSECURE_TLS")) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }
    if (g.proxy) {
        const char *p = proxy_get_socks();
        if (p) curl_easy_setopt(curl, CURLOPT_PROXY, p);
    }
    return true;
}

/* fetch result into r, close the file sink, release the easy handle */
static int finish(CURL *curl, request *r, sink *s, CURLcode res) {
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &r->code);
    char *eurl = NULL;
    curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &eurl);
    if (eurl) snprintf(r->effective_url, sizeof(r->effective_url), "%s", eurl);

    if (s) {
        sink_close(s);
        r->body = s->mem.buf;        /* transfer ownership */
        r->body_len = s->mem.len;
        free(s);
    }
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        fprintf(stderr, "HTTP failed: %s\n", curl_easy_strerror(res));
        r->code = 0;
        return 0;
    }
    return 1;
}

/* reset only response fields — never touch r->filename */
static void request_reset(request *r) {
    free(r->body);
    r->body = NULL;
    r->body_len = 0;
    r->headers[0] = '\0';
    r->code = 0;
    r->effective_url[0] = '\0';
    /* filename is (re)created by sink_new() per request */
}

int http_send_get(request *r, const char *url) {
    if (!r || !url) return 0;
    request_reset(r);

    sink *s = sink_new(r);
    if (!s) return 0;

    CURL *curl = curl_easy_init();
    if (!curl) { sink_close(s); free(s->mem.buf); free(s); return 0; }
    if (!setup_curl(curl, url, r, s)) {
        curl_easy_cleanup(curl);
        sink_close(s); free(s->mem.buf); free(s);
        return 0;
    }

    CURLcode res = curl_easy_perform(curl);
    return finish(curl, r, s, res);
}

int http_send_post(request *r, const char *url,
                   bool upload, const char *data,
                   bool is_raw, const char *raw_data) {
    if (!r || !url) return 0;
    request_reset(r);

    sink *s = sink_new(r);
    if (!s) return 0;

    CURL *curl = curl_easy_init();
    if (!curl) { sink_close(s); free(s->mem.buf); free(s); return 0; }
    if (!setup_curl(curl, url, r, s)) {
        curl_easy_cleanup(curl);
        sink_close(s); free(s->mem.buf); free(s);
        return 0;
    }

    CURLcode res = CURLE_OK;
    curl_mime *mime = NULL;
    struct curl_slist *headers = NULL;
    int ok = 1;

    if (is_raw) {
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, raw_data ? raw_data : "");
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, raw_data ? (long)strlen(raw_data) : 0);
    } else if (upload) {
        if (!data) { ok = 0; goto done; }
        FILE *test = fopen(data, "rb");
        if (!test) {
            fprintf(stderr, "File does not exist: %s\n", data);
            ok = 0; goto done;
        }
        fclose(test);
        mime = curl_mime_init(curl);
        if (!mime) { ok = 0; goto done; }
        curl_mimepart *part = curl_mime_addpart(mime);
        curl_mime_filedata(part, data);
        curl_mime_type(part, detect_content_type(data));
        curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);
    } else {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "");
    }

    res = curl_easy_perform(curl);

done:
    if (mime)    curl_mime_free(mime);
    if (headers) curl_slist_free_all(headers);
    if (!ok) {
        curl_easy_cleanup(curl);
        sink_close(s); free(s->mem.buf); free(s);
        return 0;
    }
    return finish(curl, r, s, res);
}

int http_send_option(request *r, const char *url) {
    if (!r || !url) return 0;
    request_reset(r);

    sink *s = sink_new(r);
    if (!s) return 0;

    CURL *curl = curl_easy_init();
    if (!curl) { sink_close(s); free(s->mem.buf); free(s); return 0; }
    if (!setup_curl(curl, url, r, s)) {
        curl_easy_cleanup(curl);
        sink_close(s); free(s->mem.buf); free(s);
        return 0;
    }

    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "OPTIONS");

    CURLcode res = curl_easy_perform(curl);
    return finish(curl, r, s, res);
}