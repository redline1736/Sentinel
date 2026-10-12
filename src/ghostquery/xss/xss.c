#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>   /* waitpid */
#include <time.h>
#include <ctype.h>
#include <curl/curl.h>
#include <fcntl.h>
#include <dirent.h>
#include <signal.h>
#include <pthread.h>

#include "../../util/util.h"
#include "../../prox/prox.h"
#include "../../chrome/chrome.h"
#include "../../http/http.h"
#include "../../global.h"


/* ============================================================================
 * Constants
 * ============================================================================ */

#define MAX_URL_LEN     32768
#define MAX_PARAM_LEN   256
#define MAX_PAYLOAD_LEN 32768
#define MAX_BODY_READ   (1 << 20)   /* 1 MiB reflection-body cap */
#define CHROME_PORT     9222
#define CURL_TIMEOUT    10
#define CURL_CONNECT_TIMEOUT 5

/* Chrome-poll tuning: instead of a hard 300 ms sleep, poll quickly with a
 * bounded number of attempts. */
#define CHROME_POLL_ATTEMPTS   10
#define CHROME_POLL_INTERVAL_US 20000   /* 20 ms */

/* Thread pool size for the HTTP-only fallback path. */
#define HTTP_WORKERS 8

/* ============================================================================
 * Safe Path Utilities
 * ============================================================================ */

static int is_safe_path(const char *path) {
    if (!path || *path == '\0') return 0;
    if (path[0] == '/')         return 0;
    if (strstr(path, ".."))     return 0;
    if (path[0] == '.')         return 0;
    return 1;
}

static int create_unique_filename(char *dst, size_t dstsz, const char *prefix) {
    struct timespec ts;
    static unsigned int counter = 0;
    unsigned int my_counter;

    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        time_t t = time(NULL);
        my_counter = __sync_fetch_and_add(&counter, 1);
        return snprintf(dst, dstsz, "%s_%d_%ld_%u.txt",
                        prefix, getpid(), (long)t, my_counter);
    }
    my_counter = __sync_fetch_and_add(&counter, 1);
    return snprintf(dst, dstsz, "%s_%d_%ld_%ld_%u.txt",
                    prefix, getpid(), (long)ts.tv_sec, (long)ts.tv_nsec, my_counter);
}

static FILE *safe_fopen_exclusive(const char *filename, const char *mode) {
    if (!is_safe_path(filename)) { errno = EPERM; return NULL; }
    int fd = open(filename, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) return NULL;
    FILE *fp = fdopen(fd, mode);
    if (!fp) { close(fd); unlink(filename); return NULL; }
    return fp;
}

static int safe_remove(const char *filename) {
    if (!is_safe_path(filename)) return -1;
    return remove(filename);
}

/* ============================================================================
 * String Utilities
 * ============================================================================ */

static void strip_newline(char *s) {
    if (!s) return;
    size_t len = strlen(s);
    while (len > 0 && (s[len - 1] == '\n' || s[len - 1] == '\r'))
        s[--len] = '\0';
}

/* Insert or replace `param` in the query string, preserving other params
 * and any #fragment. */
static int build_param_url(char *dst, size_t dstsz,
                           const char *url, const char *param, const char *value) {
    if (!dst || !url || !param || !value) return 0;

    const char *frag    = strchr(url, '#');
    size_t      url_len = frag ? (size_t)(frag - url) : strlen(url);
    const char *q       = memchr(url, '?', url_len);

    const char *hit     = NULL;
    const char *seg_end = NULL;
    if (q) {
        size_t plen = strlen(param);
        const char *p   = q + 1;
        const char *end = url + url_len;
        while (p < end) {
            const char *amp = memchr(p, '&', (size_t)(end - p));
            const char *e   = amp ? amp : end;
            if ((size_t)(e - p) > plen && p[plen] == '=' &&
                strncmp(p, param, plen) == 0) {
                hit = p; seg_end = e; break;
            }
            p = amp ? amp + 1 : end;
        }
    }

    int n;
    if (hit) {
        n = snprintf(dst, dstsz, "%.*s%s=%s%s",
                     (int)(hit - url), url, param, value, seg_end);
    } else {
        const char *sep = q ? "&" : "?";
        n = snprintf(dst, dstsz, "%.*s%s%s=%s%s",
                     (int)url_len, url, sep, param, value,
                     frag ? frag : "");
    }
    if (n < 0 || (size_t)n >= dstsz) {
        fprintf(stderr, "[gq] URL too long for param '%s' (needed %d, had %zu)\n",
                param, n, dstsz);
        return 0;
    }
    return 1;
}

/* Recursive mkdir without shelling out. */
static int ensure_directory(const char *path) {
    if (!path) return -1;
    struct stat st;
    if (stat(path, &st) == 0)
        return S_ISDIR(st.st_mode) ? 0 : (errno = ENOTDIR, -1);

    char tmp[512];
    size_t len = strlen(path);
    if (len == 0 || len >= sizeof(tmp)) { errno = ENAMETOOLONG; return -1; }
    memcpy(tmp, path, len + 1);

    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return -1;
    return 0;
}

/* ============================================================================
 * Libcurl: reusable handle + in-memory body
 * ============================================================================ */

struct mem_buf {
    char  *data;
    size_t len;
    size_t cap;
};

static size_t write_mem(void *ptr, size_t size, size_t nmemb, void *ud) {
    struct mem_buf *b = ud;
    size_t n = size * nmemb;
    if (b->len + n + 1 > b->cap) {
        size_t nc = b->cap ? b->cap * 2 : 8192;
        while (nc < b->len + n + 1) nc *= 2;
        char *nd = realloc(b->data, nc);
        if (!nd) return 0;
        b->data = nd; b->cap = nc;
    }
    memcpy(b->data + b->len, ptr, n);
    b->len += n;
    b->data[b->len] = '\0';
    return n;
}

static void mem_buf_free(struct mem_buf *b) {
    if (!b) return;
    free(b->data);
    b->data = NULL; b->len = 0; b->cap = 0;
}

/* Per-thread curl handle so the HTTP worker pool is safe. */
static pthread_key_t  g_curl_key;
static pthread_once_t g_curl_once = PTHREAD_ONCE_INIT;

static void curl_key_destructor(void *p) {
    CURL *c = p;
    if (c) curl_easy_cleanup(c);
}

static void curl_key_init(void) {
    pthread_key_create(&g_curl_key, curl_key_destructor);
}

static CURL *get_curl(void) {
    pthread_once(&g_curl_once, curl_key_init);
    CURL *c = pthread_getspecific(g_curl_key);
    if (!c) {
        curl_global_init(CURL_GLOBAL_DEFAULT);
        c = curl_easy_init();
        pthread_setspecific(g_curl_key, c);
    } else {
        curl_easy_reset(c);
    }
    return c;
}

/* ============================================================================
 * HTTP Request Sender
 * ============================================================================ */

static int gq_http_send(request *r, const char *url, struct mem_buf *body_out) {
    if (!r || !url) {
        fprintf(stderr, "gq_http_send: invalid arguments\n");
        return 0;
    }

    r->code = -1;
    r->filename[0] = '\0';

    const char *proxy = g.proxy ? proxy_get_socks() : NULL;
    if (g.proxy && !proxy)
        fprintf(stderr, "gq_http_send: no proxy available — sending direct\n");

    CURL *curl = get_curl();
    if (!curl) {
        fprintf(stderr, "gq_http_send: curl_easy_init failed\n");
        return 0;
    }

    if (proxy) curl_easy_setopt(curl, CURLOPT_PROXY, proxy);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, CURL_TIMEOUT);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, CURL_CONNECT_TIMEOUT);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0");
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
    curl_easy_setopt(curl, CURLOPT_FRESH_CONNECT, 0L);
    curl_easy_setopt(curl, CURLOPT_FORBID_REUSE, 0L);

    if (body_out) {
        body_out->len = 0;
        if (!body_out->data) {
            body_out->data = malloc(8192);
            body_out->cap  = 8192;
        }
        if (!body_out->data) return 0;
        body_out->data[0] = '\0';
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_mem);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, body_out);
    } else {
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, NULL);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, NULL);
    }

    CURLcode result = curl_easy_perform(curl);
    if (result == CURLE_OK) {
        long http_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        r->code = (int)http_code;
        return 1;
    }
    return 0;
}

/* ============================================================================
 * Reflection-body matcher
 * ============================================================================ */

static int body_contains_payload(const char *body, const char *raw, const char *enc) {
    if (!body || !raw || !*raw) return 0;
    if (strstr(body, raw)) return 1;
    if (enc && *enc && strcmp(enc, raw) != 0 && strstr(body, enc)) return 1;
    if (raw[0] == '<' && raw[1] && strstr(body, "&lt;") && strstr(body, raw + 1))
        return 1;
    return 0;
}

/* ============================================================================
 * Find Reflecting Parameters
 * ============================================================================ */

int find_param_reflecting(char *url, char *path) {
    int size, allocated, i = 0;
    char full_url[MAX_URL_LEN];
    char buffer[MAX_PARAM_LEN];
    request *r;
    FILE *fp, *fptr;
    char *param_file = "/usr/share/sentinel/ghostquery/params.txt";
    char output_file[4096];
    char *output_dir = "ghostquery/xss";
    struct mem_buf body = {0};

    snprintf(output_file, sizeof(output_file), "%s/valid_params.txt", path);

    if (!url) { fprintf(stderr, "find_param_reflecting: url is NULL\n"); return 1; }
    if (ensure_directory(output_dir) != 0) {
        fprintf(stderr, "find_param_reflecting: failed to create %s\n", output_dir);
        return 1;
    }
    if (ensure_directory(path) != 0) {
        fprintf(stderr, "find_param_reflecting: failed to create %s\n", path);
        return 1;
    }

    size = line_count(param_file);
    if (size <= 0) {
        fprintf(stderr, "find_param_reflecting: %s is empty or missing\n", param_file);
        return 1;
    }

    allocated = size + 1;
    r = calloc((size_t)allocated, sizeof(request));
    if (!r) { fprintf(stderr, "find_param_reflecting: calloc failed\n"); return 1; }

    fp = fopen(param_file, "r");
    if (!fp) {
        fprintf(stderr, "find_param_reflecting: cannot open %s\n", param_file);
        free(r); return 1;
    }

    fptr = fopen(output_file, "w");
    if (!fptr) {
        fprintf(stderr, "find_param_reflecting: cannot open %s\n", output_file);
        fclose(fp); free(r); return 1;
    }

    printf("[find_param_reflecting] probing %d params against %s\n", size, url);

    while (fgets(buffer, sizeof(buffer), fp)) {
        strip_newline(buffer);
        if (buffer[0] == '\0' || buffer[0] == '#') continue;
        if (i >= allocated) break;

        if (!build_param_url(full_url, sizeof(full_url), url, buffer, "asdasda")) {
            fprintf(stderr, "[find_param_reflecting] URL too long for '%s'\n", buffer);
            i++;
            continue;
        }

        request *cur = &r[i];
        body.len = 0;

        if (gq_http_send(cur, full_url, &body)) {
            if (cur->code >= 200 && cur->code < 400 && body.data) {
                if (strstr(body.data, "asdasda")) {
                    fprintf(fptr, "%s\n", buffer);
                    fflush(fptr);
                    printf("[find_param_reflecting] REFLECTS: %s (HTTP %d, %zu bytes)\n",
                           buffer, cur->code, body.len);
                } else {
                    printf("[find_param_reflecting] no reflection: %s (HTTP %d)\n",
                           buffer, cur->code);
                }
            } else {
                printf("[find_param_reflecting] %s -> HTTP %d (skipped)\n",
                       buffer, cur->code);
            }
        } else {
            printf("[find_param_reflecting] %s -> request failed\n", buffer);
        }

        i++;
    }

    fclose(fp);
    fclose(fptr);
    free(r);
    mem_buf_free(&body);
    printf("find_param_reflecting: results written to %s\n", output_file);
    return 0;
}

/* ============================================================================
 * XSS payload runner
 * ============================================================================ */

struct xss_job {
    char *param;
    char *payload;
    char *enc;          /* URL-escaped payload (owned by pool, do not free) */
    char *full_url;
    int   event_type;
};

struct xss_shared {
    /* HTTP fallback path */
    char  *payload_file;
    FILE  *found;
    pthread_mutex_t found_lock;

    /* Counters */
    pthread_mutex_t stat_lock;
    int total_tested;
    int total_confirmed;

    /* Tag for logging */
    const char *tag;
};

/* ------ HTTP-only worker ------ */

static void *http_worker(void *arg) {
    struct xss_job    *j = arg;
    struct xss_shared *s = j->user;   /* not used — see below */
    (void)s;
    return NULL;
}

/* Because C doesn't let us tack extra fields cleanly onto a malloc'd job,
 * we carry the shared pointer inside the job struct. */
struct xss_job_full {
    struct xss_job base;
    struct xss_shared *shared;
};

static void *http_worker_full(void *arg) {
    struct xss_job_full *jf = arg;
    struct xss_job      *j  = &jf->base;
    struct xss_shared   *s  = jf->shared;

    request r = {0};
    struct mem_buf body = {0};

    if (gq_http_send(&r, j->full_url, &body) && r.code == 200 && body.data) {
        if (body_contains_payload(body.data, j->payload, j->enc)) {
            pthread_mutex_lock(&s->found_lock);
            fprintf(s->found, "%s -> %s\n", j->param, j->payload);
            fflush(s->found);
            pthread_mutex_lock(&s->stat_lock);
            s->total_confirmed++;
            pthread_mutex_unlock(&s->stat_lock);
            pthread_mutex_unlock(&s->found_lock);
            printf("[%s] *** CONFIRMED (HTTP): %s=%s ***\n",
                   s->tag, j->param, j->payload);
        }
    }

    pthread_mutex_lock(&s->stat_lock);
    s->total_tested++;
    pthread_mutex_unlock(&s->stat_lock);

    mem_buf_free(&body);
    free(j->param);
    free(j->payload);
    free(j->enc);
    free(j->full_url);
    free(jf);
    return NULL;
}

/* ------ Chrome path (serialized) ------ */

static int chrome_confirm(chrome *c, struct xss_job *j,
                          struct xss_shared *s) {
    if (navigate_to(c, j->full_url) != 0) return 0;

    /* Bounded poll instead of a fixed 300 ms sleep. */
    for (int a = 0; a < CHROME_POLL_ATTEMPTS; a++) {
        if (detect_xss(c, 5, j->event_type) == 0) {
            pthread_mutex_lock(&s->found_lock);
            fprintf(s->found, "%s -> %s\n", j->param, j->payload);
            fflush(s->found);
            pthread_mutex_unlock(&s->found_lock);
            printf("[%s] *** CONFIRMED: %s=%s ***\n",
                   s->tag, j->param, j->payload);
            return 1;
        }
        usleep(CHROME_POLL_INTERVAL_US);
    }
    return 0;
}

/* ============================================================================
 * Simple bounded thread queue for HTTP workers
 * ============================================================================ */

struct job_queue {
    struct xss_job_full **items;
    size_t cap, head, tail, count;
    pthread_mutex_t lock;
    pthread_cond_t  not_empty;
    pthread_cond_t  not_full;
    int shutdown;
};

static int queue_init(struct job_queue *q, size_t cap) {
    q->items = calloc(cap, sizeof(*q->items));
    if (!q->items) return -1;
    q->cap = cap; q->head = q->tail = q->count = 0; q->shutdown = 0;
    pthread_mutex_init(&q->lock, NULL);
    pthread_cond_init(&q->not_empty, NULL);
    pthread_cond_init(&q->not_full, NULL);
    return 0;
}

static void queue_destroy(struct job_queue *q) {
    free(q->items);
    pthread_mutex_destroy(&q->lock);
    pthread_cond_destroy(&q->not_empty);
    pthread_cond_destroy(&q->not_full);
}

static int queue_push(struct job_queue *q, struct xss_job_full *j) {
    pthread_mutex_lock(&q->lock);
    while (q->count == q->cap && !q->shutdown)
        pthread_cond_wait(&q->not_full, &q->lock);
    if (q->shutdown) { pthread_mutex_unlock(&q->lock); return -1; }
    q->items[q->tail] = j;
    q->tail = (q->tail + 1) % q->cap;
    q->count++;
    pthread_cond_signal(&q->not_empty);
    pthread_mutex_unlock(&q->lock);
    return 0;
}

static struct xss_job_full *queue_pop(struct job_queue *q) {
    pthread_mutex_lock(&q->lock);
    while (q->count == 0 && !q->shutdown)
        pthread_cond_wait(&q->not_empty, &q->lock);
    if (q->count == 0 && q->shutdown) {
        pthread_mutex_unlock(&q->lock);
        return NULL;
    }
    struct xss_job_full *j = q->items[q->head];
    q->head = (q->head + 1) % q->cap;
    q->count--;
    pthread_cond_signal(&q->not_full);
    pthread_mutex_unlock(&q->lock);
    return j;
}

static void queue_shutdown(struct job_queue *q) {
    pthread_mutex_lock(&q->lock);
    q->shutdown = 1;
    pthread_cond_broadcast(&q->not_empty);
    pthread_cond_broadcast(&q->not_full);
    pthread_mutex_unlock(&q->lock);
}

static void *http_worker_loop(void *arg) {
    struct job_queue *q = arg;
    struct xss_job_full *j;
    while ((j = queue_pop(q)) != NULL)
        http_worker_full(j);
    return NULL;
}

/* ============================================================================
 * Payload/param table loading
 * ============================================================================ */

static char **load_lines(const char *path, int *out_n) {
    FILE *fp = fopen(path, "r");
    if (!fp) { *out_n = 0; return NULL; }

    char **lines = NULL;
    int    n = 0;
    char   buf[MAX_PAYLOAD_LEN];

    while (fgets(buf, sizeof(buf), fp)) {
        strip_newline(buf);
        if (!buf[0] || buf[0] == '#') continue;
        char *dup = strdup(buf);
        if (!dup) break;
        char **tmp = realloc(lines, sizeof(char*) * (n + 1));
        if (!tmp) { free(dup); break; }
        lines = tmp;
        lines[n++] = dup;
    }
    fclose(fp);
    *out_n = n;
    return lines;
}

static void free_lines(char **lines, int n) {
    if (!lines) return;
    for (int i = 0; i < n; i++) free(lines[i]);
    free(lines);
}

/* ============================================================================
 * XSS payload runner
 * ============================================================================ */

static void xss_payload_run(const char *tag,
                            char *url, char *path,
                            const char *payload_file,
                            const char *out_file_name) {
    char   param_file[4096];
    char   valid_payloads_path[4096];
    FILE  *fp, *found;
    int    total_tested = 0, total_confirmed = 0;
    int    chrome_initialized = 0;
    chrome c;

    if (!url || !path) { fprintf(stderr, "[%s] invalid args\n", tag); return; }

    memset(&c, 0, sizeof(c));

    snprintf(param_file, sizeof(param_file), "%s/valid_params.txt", path);

    if (ensure_directory(path) != 0) {
        fprintf(stderr, "[%s] failed to create %s\n", tag, path);
        return;
    }

    snprintf(valid_payloads_path, sizeof(valid_payloads_path),
             "%s/%s", path, out_file_name);

    /* ---- Load payloads once ---- */
    int np = 0;
    char **payloads = load_lines(payload_file, &np);
    if (np <= 0) {
        fprintf(stderr, "[%s] %s empty or missing\n", tag, payload_file);
        free_lines(payloads, np);
        return;
    }

    /* ---- Pre-escape payloads once ---- */
    char **escaped = calloc((size_t)np, sizeof(char*));
    for (int k = 0; k < np; k++)
        escaped[k] = curl_easy_escape(NULL, payloads[k], 0);

    /* ---- Load params once ---- */
    int np_params = 0;
    char **params = load_lines(param_file, &np_params);
    if (np_params <= 0) {
        fprintf(stderr, "[%s] %s empty or missing\n", tag, param_file);
        for (int k = 0; k < np; k++) { free(payloads[k]); if (escaped[k]) curl_free(escaped[k]); }
        free(payloads); free(escaped); free_lines(params, np_params);
        return;
    }

    found = fopen(valid_payloads_path, "w");
    if (!found) {
        fprintf(stderr, "[%s] cannot write %s\n", tag, valid_payloads_path);
        for (int k = 0; k < np; k++) { free(payloads[k]); if (escaped[k]) curl_free(escaped[k]); }
        free(payloads); free(escaped); free_lines(params, np_params);
        return;
    }

    printf("[%s] Initializing Chrome (port %d)...\n", tag, CHROME_PORT);
    if (init_chrome(&c, CHROME_PORT) == 0) {
        chrome_initialized = 1;
        printf("[%s] Chrome initialized\n", tag);
    } else {
        printf("[%s] Chrome init failed — HTTP-only detection\n", tag);
    }

    struct xss_shared shared;
    memset(&shared, 0, sizeof(shared));
    shared.payload_file = (char*)payload_file;
    shared.found        = found;
    shared.tag          = tag;
    pthread_mutex_init(&shared.found_lock, NULL);
    pthread_mutex_init(&shared.stat_lock, NULL);

    if (chrome_initialized) {
        /* -------- Serialized Chrome path -------- */
        for (int pi = 0; pi < np_params; pi++) {
            const char *param = params[pi];
            for (int k = 0; k < np; k++) {
                if (!escaped[k]) continue;

                char full_url[MAX_URL_LEN];
                if (!build_param_url(full_url, sizeof(full_url), url, param, escaped[k]))
                    continue;

                int event_type = detect_payload_event_type(payloads[k]);

                printf("[%s] Testing: %s=%s (event=%d, url_len=%zu)\n",
                       tag, param, payloads[k], event_type, strlen(full_url));

                struct xss_job j = {
                    .param      = (char*)param,
                    .payload    = payloads[k],
                    .enc        = escaped[k],
                    .full_url   = full_url,
                    .event_type = event_type,
                };

                if (chrome_confirm(&c, &j, &shared))
                    shared.total_confirmed++;
                shared.total_tested++;
            }
        }
    } else {
        /* -------- Parallel HTTP path -------- */
        struct job_queue q;
        if (queue_init(&q, HTTP_WORKERS * 4) != 0) {
            fprintf(stderr, "[%s] queue_init failed\n", tag);
            goto cleanup;
        }

        pthread_t workers[HTTP_WORKERS];
        for (int w = 0; w < HTTP_WORKERS; w++)
            pthread_create(&workers[w], NULL, http_worker_loop, &q);

        for (int pi = 0; pi < np_params; pi++) {
            const char *param = params[pi];
            for (int k = 0; k < np; k++) {
                if (!escaped[k]) continue;

                char *full_url = malloc(MAX_URL_LEN);
                if (!full_url) continue;
                if (!build_param_url(full_url, MAX_URL_LEN, url, param, escaped[k])) {
                    free(full_url); continue;
                }

                struct xss_job_full *jf = calloc(1, sizeof(*jf));
                if (!jf) { free(full_url); continue; }

                jf->base.param      = strdup(param);
                jf->base.payload    = strdup(payloads[k]);
                jf->base.enc        = strdup(escaped[k]);
                jf->base.full_url   = full_url;
                jf->base.event_type = detect_payload_event_type(payloads[k]);
                jf->shared          = &shared;

                if (!jf->base.param || !jf->base.payload || !jf->base.enc) {
                    free(jf->base.param); free(jf->base.payload);
                    free(jf->base.enc);   free(full_url); free(jf);
                    continue;
                }

                if (queue_push(&q, jf) != 0) {
                    free(jf->base.param); free(jf->base.payload);
                    free(jf->base.enc);   free(full_url); free(jf);
                    break;
                }
            }
        }

        queue_shutdown(&q);
        for (int w = 0; w < HTTP_WORKERS; w++)
            pthread_join(workers[w], NULL);
        queue_destroy(&q);

        total_tested    = shared.total_tested;
        total_confirmed = shared.total_confirmed;
    }

cleanup:
    if (chrome_initialized) close_chrome(&c);

    pthread_mutex_destroy(&shared.found_lock);
    pthread_mutex_destroy(&shared.stat_lock);

    fclose(found);

    for (int k = 0; k < np; k++) {
        free(payloads[k]);
        if (escaped[k]) curl_free(escaped[k]);
    }
    free(payloads);
    free(escaped);
    free_lines(params, np_params);

    if (chrome_initialized) {
        total_tested    = shared.total_tested;
        total_confirmed = shared.total_confirmed;
    }

    printf("[%s] Done. Tested %d, confirmed %d. Results: %s\n",
           tag, total_tested, total_confirmed, valid_payloads_path);
}


void xss_generated(char *url, char *path) {
    xss_payload_run("xss_generated", url, path,
                    "/usr/share/sentinel/ghostquery/xss/payloads.txt",
                    "valid_payloads.txt");
}

void xss_custom(char *url, char *path) {
    xss_payload_run("xss_custom", url, path,
                    "/usr/share/sentinel/ghostquery/xss/custom.txt",
                    "valid_payloads_custom.txt");
}

/* ============================================================================
 * Mirror findings into <report_dir>/xss.txt
 * ============================================================================ */
static void mirror_xss_findings(const char *path, const char *report_dir) {
    if (!path || !report_dir) return;

    char mirror[4096];
    if (snprintf(mirror, sizeof(mirror), "%s/xss.txt", report_dir)
        >= (int)sizeof(mirror))
        return;

    FILE *out = fopen(mirror, "w");
    if (!out) return;

    const char *files[] = { "valid_payloads.txt", "valid_payloads_custom.txt", NULL };
    for (int k = 0; files[k]; k++) {
        char src[4096];
        if (snprintf(src, sizeof(src), "%s/%s", path, files[k])
            >= (int)sizeof(src))
            continue;
        FILE *in = fopen(src, "r");
        if (!in) continue;
        char line[4096];
        while (fgets(line, sizeof(line), in))
            fprintf(out, "%s:%s", path, line);
        fclose(in);
    }
    fclose(out);
}

/* ============================================================================
 * Main XSS Run Entry Point
 * ============================================================================ */

int file_exists(const char *filename) {
    return access(filename, F_OK) == 0;
}


int xss_run(char *url, char *path, char *report_dir) {
    if (!url || !path) {
        fprintf(stderr, "xss_run: invalid arguments\n");
        return 1;
    }
    if (!report_dir) report_dir = path;

    printf("[xss_run] Generating XSS payloads...\n");
    const char *payloads = "/usr/bin/sentinel/ghostquery/xss/payloads.txt";

    if (!file_exists(payloads)) {
        if (system("python3 /usr/bin/sentinel/ghostquery/xss/main.py") != 0)
            fprintf(stderr, "warning: generate_payloads.py failed (continuing)\n");
    } else {
        printf("[xss_run] Using existing payloads file: %s\n", payloads);
    }

    printf("[xss_run] Finding reflecting parameters...\n");
    if (find_param_reflecting(url, path) != 0)
        fprintf(stderr, "warning: find_param_reflecting failed\n");

    printf("[xss_run] Running generated payload scan...\n");
    xss_generated(url, path);

    printf("[xss_run] Running custom payload scan...\n");
    xss_custom(url, path);

    printf("[xss_run] Mirroring findings into %s/xss.txt\n", report_dir);
    mirror_xss_findings(path, report_dir);

    printf("[xss_run] XSS scanning complete.\n");
    return 0;
}

/* ============================================================================
 * Nuclei on discovered params (with wordlist fallback)
 * ============================================================================ */

int nuclei_run(char *url, char *path) {
    if (!url || !path) {
        fprintf(stderr, "[nuclei_run] invalid arguments\n");
        return 1;
    }

    char param_file[4096];
    char targets_path[4096];
    char nuclei_out[4096];
    char nuclei_merged[4096];

    if (snprintf(param_file, sizeof(param_file),
                 "%s/valid_params.txt", path) >= (int)sizeof(param_file) ||
        snprintf(targets_path, sizeof(targets_path),
                 "%s/nuclei_param_targets.txt", path) >= (int)sizeof(targets_path) ||
        snprintf(nuclei_out, sizeof(nuclei_out),
                 "%s/nuclei_params.txt", path) >= (int)sizeof(nuclei_out) ||
        snprintf(nuclei_merged, sizeof(nuclei_merged),
                 "%s/nuclei.txt", path) >= (int)sizeof(nuclei_merged)) {
        fprintf(stderr, "[nuclei_run] path too long\n");
        return 1;
    }

    FILE *tl = fopen(targets_path, "w");
    if (!tl) { fprintf(stderr, "[nuclei_run] cannot write %s\n", targets_path); return 1; }

    char param[MAX_PARAM_LEN];
    int ntargets = 0;

    FILE *fp = fopen(param_file, "r");
    if (fp) {
        while (fgets(param, sizeof(param), fp)) {
            size_t l = strlen(param);
            while (l && (param[l-1] == '\n' || param[l-1] == '\r'))
                param[--l] = '\0';
            if (l == 0 || param[0] == '#') continue;

            fprintf(tl, "%s%c%s=test\n",
                    url, strchr(url, '?') ? '&' : '?', param);
            ntargets++;
        }
        fclose(fp);
    } else {
        printf("[nuclei_run] %s not found — will use fallback wordlist\n", param_file);
    }

    if (ntargets == 0) {
        printf("[nuclei_run] no reflecting params — falling back to params.txt\n");
        FILE *wf = fopen("/usr/share/sentinel/ghostquery/params.txt", "r");
        if (!wf) {
            fprintf(stderr, "[nuclei_run] fallback wordlist missing\n");
            fclose(tl);
            return 1;
        }
        char wparam[MAX_PARAM_LEN];
        while (fgets(wparam, sizeof(wparam), wf)) {
            size_t l = strlen(wparam);
            while (l && (wparam[l-1] == '\n' || wparam[l-1] == '\r'))
                wparam[--l] = '\0';
            if (l == 0 || wparam[0] == '#') continue;

            fprintf(tl, "%s%c%s=test\n",
                    url, strchr(url, '?') ? '&' : '?', wparam);
            ntargets++;
        }
        fclose(wf);
    }
    fclose(tl);

    if (ntargets == 0) {
        printf("[nuclei_run] nothing to test\n");
        return 0;
    }

    printf("[nuclei_run] running nuclei on %d param URLs\n", ntargets);

    char *nuclei_args[] = {
        "nuclei",
        "-l", targets_path,
        "-o", nuclei_out,
        "-silent",
        "-tags", "xss,sqli,ssrf,lfi,rce,redirect,injection,open-redirect",
        "-severity", "critical,high,medium,low",
        "-type", "http",
        "-etags", "dos,intrusive",
        "-c", "50",
        "-timeout", "5",
        "-retries", "1",
        "-dast",
        NULL
    };

    int rc = run_tool(nuclei_args);
    if (rc != 0)
        printf("[!] nuclei failed on %s with code %d\n", url, rc);

    FILE *in  = fopen(nuclei_out, "r");
    FILE *out = fopen(nuclei_merged, "a");
    if (in && out) {
        char line[4096];
        while (fgets(line, sizeof(line), in))
            fputs(line, out);
    }
    if (in)  fclose(in);
    if (out) fclose(out);

    return 0;
}