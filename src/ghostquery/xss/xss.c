#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
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


#define MAX_URL_LEN     32768
#define MAX_PARAM_LEN   256
#define MAX_PAYLOAD_LEN 32768
#define CURL_TIMEOUT    10
#define CURL_CONNECT_TIMEOUT 5

#define CHROME_POLL_ATTEMPTS    10
#define CHROME_POLL_INTERVAL_US 20000   /* 20 ms */

#define WORKERS_PER_SCAN 4
#define CHROME_BASE_PORT_GENERATED 9222
#define CHROME_BASE_PORT_CUSTOM    9226


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
    unsigned int my_counter = __sync_fetch_and_add(&counter, 1);

    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        time_t t = time(NULL);
        return snprintf(dst, dstsz, "%s_%d_%ld_%u.txt",
                        prefix, getpid(), (long)t, my_counter);
    }
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
 * Libcurl Write Callback
 * ============================================================================ */

static size_t write_file(void *ptr, size_t size, size_t nmemb, void *stream) {
    return fwrite(ptr, size, nmemb, (FILE *)stream);
}

/* ============================================================================
 * HTTP Request Sender  — your original, unchanged
 * ============================================================================ */

static int gq_http_send(request *r, const char *url) {
    CURL *curl;
    CURLcode result;
    FILE *fp;
    char filename[128];
    const char *proxy = NULL;
    long http_code = 0;

    if (!r || !url) {
        fprintf(stderr, "gq_http_send: invalid arguments\n");
        return 0;
    }

    r->code = -1;
    r->filename[0] = '\0';

    if (g.proxy) {
        proxy = proxy_get_socks();
        if (!proxy)
            fprintf(stderr, "gq_http_send: no proxy available — sending direct\n");
    }

    if (create_unique_filename(filename, sizeof(filename), "curl") <= 0) {
        fprintf(stderr, "gq_http_send: failed to create filename\n");
        return 0;
    }

    fp = safe_fopen_exclusive(filename, "wb");
    if (!fp) { perror("gq_http_send: fopen"); return 0; }
    snprintf(r->filename, sizeof(r->filename), "%s", filename);

    curl = curl_easy_init();
    if (!curl) {
        fclose(fp); safe_remove(filename); r->filename[0] = '\0';
        fprintf(stderr, "gq_http_send: curl_easy_init failed\n");
        return 0;
    }

    if (proxy) curl_easy_setopt(curl, CURLOPT_PROXY, proxy);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_file);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, CURL_TIMEOUT);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, CURL_CONNECT_TIMEOUT);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "ghostquery/1.0");
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    result = curl_easy_perform(curl);
    fclose(fp);

    if (result == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        r->code = (int)http_code;
    } else {
        safe_remove(filename);
        r->filename[0] = '\0';
    }

    curl_easy_cleanup(curl);
    return result == CURLE_OK ? 1 : 0;
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
 * Read whole file into heap buffer
 * ============================================================================ */

static char *slurp_file(const char *path, size_t *out_len) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return NULL;
    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    if (sz < 0) { fclose(fp); return NULL; }
    rewind(fp);
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(fp); return NULL; }
    size_t rd = fread(buf, 1, (size_t)sz, fp);
    buf[rd] = '\0';
    fclose(fp);
    if (out_len) *out_len = rd;
    return buf;
}

/* ============================================================================
 * Line loaders
 * ============================================================================ */

static char **load_lines(const char *path, int *out_n) {
    *out_n = 0;
    FILE *fp = fopen(path, "r");
    if (!fp) return NULL;

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
 * Find Reflecting Parameters
 * ============================================================================ */

int find_param_reflecting(char *url, char *path) {
    int nparams = 0, i = 0;
    char full_url[MAX_URL_LEN];
    request *r;
    FILE *fptr;
    const char *param_file = "/usr/share/sentinel/ghostquery/params.txt";
    char output_file[4096];
    const char *output_dir = "ghostquery/xss";

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

    int total = line_count((char*)param_file);
    if (total <= 0) {
        fprintf(stderr, "find_param_reflecting: %s is empty or missing\n", param_file);
        return 1;
    }

    char **params = load_lines(param_file, &nparams);
    if (nparams <= 0) {
        fprintf(stderr, "find_param_reflecting: cannot load %s\n", param_file);
        free_lines(params, nparams);
        return 1;
    }

    r = calloc((size_t)(total + 1), sizeof(request));
    if (!r) { fprintf(stderr, "find_param_reflecting: calloc failed\n"); free_lines(params, nparams); return 1; }

    fptr = fopen(output_file, "w");
    if (!fptr) {
        fprintf(stderr, "find_param_reflecting: cannot open %s\n", output_file);
        free(r); free_lines(params, nparams); return 1;
    }

    printf("[find_param_reflecting] probing %d params against %s\n", nparams, url);

    for (i = 0; i < nparams; i++) {
        if (!build_param_url(full_url, sizeof(full_url), url, params[i], "asdasda")) {
            fprintf(stderr, "[find_param_reflecting] URL too long for '%s'\n", params[i]);
            continue;
        }

        request *cur = &r[i];
        if (gq_http_send(cur, full_url)) {
            if (cur->code >= 200 && cur->code < 400 && cur->filename[0]) {
                size_t blen = 0;
                char *body = slurp_file(cur->filename, &blen);
                if (body) {
                    if (strstr(body, "asdasda")) {
                        fprintf(fptr, "%s\n", params[i]);
                        fflush(fptr);
                        printf("[find_param_reflecting] REFLECTS: %s (HTTP %d, %zu bytes)\n",
                               params[i], cur->code, blen);
                    } else {
                        printf("[find_param_reflecting] no reflection: %s (HTTP %d)\n",
                               params[i], cur->code);
                    }
                    free(body);
                }
            } else {
                printf("[find_param_reflecting] %s -> HTTP %d (skipped)\n",
                       params[i], cur->code);
            }
        } else {
            printf("[find_param_reflecting] %s -> request failed\n", params[i]);
        }

        if (cur->filename[0]) { safe_remove(cur->filename); cur->filename[0] = '\0'; }
    }

    fclose(fptr);
    free(r);
    free_lines(params, nparams);
    printf("find_param_reflecting: results written to %s\n", output_file);
    return 0;
}

/* ============================================================================
 * XSS payload runner — parallelized
 * ============================================================================ */

struct xss_ctx {
    const char *tag;
    const char *url;
    char       *path;

    char      **params;      int nparams;
    char      **payloads;    int npayloads;
    char      **escaped;

    FILE           *found;
    pthread_mutex_t found_lock;

    int             total_tested;
    int             total_confirmed;
    pthread_mutex_t stat_lock;

    int             chrome_port_base;
};

struct worker_arg {
    struct xss_ctx *ctx;
    int             worker_id;
    int             start_param;
    int             end_param;
};

static void *xss_worker(void *arg) {
    struct worker_arg *wa = arg;
    struct xss_ctx    *ctx = wa->ctx;

    char   full_url[MAX_URL_LEN];
    chrome c;
    int    chrome_ok = 0;

    memset(&c, 0, sizeof(c));

    int port = ctx->chrome_port_base + wa->worker_id;
    printf("[%s/w%d] Initializing Chrome (port %d)...\n", ctx->tag, wa->worker_id, port);
    if (init_chrome(&c, port) == 0) {
        chrome_ok = 1;
        printf("[%s/w%d] Chrome initialized\n", ctx->tag, wa->worker_id);
    } else {
        printf("[%s/w%d] Chrome init failed — HTTP-only detection\n",
               ctx->tag, wa->worker_id);
    }

    for (int pi = wa->start_param; pi < wa->end_param; pi++) {
        const char *param = ctx->params[pi];

        for (int k = 0; k < ctx->npayloads; k++) {
            if (!ctx->escaped[k]) continue;

            if (!build_param_url(full_url, sizeof(full_url),
                                 ctx->url, param, ctx->escaped[k]))
                continue;

            int event_type = detect_payload_event_type(ctx->payloads[k]);

            printf("[%s/w%d] Testing: %s=%s (event=%d, url_len=%zu)\n",
                   ctx->tag, wa->worker_id, param, ctx->payloads[k],
                   event_type, strlen(full_url));

            int confirmed = 0;

            if (chrome_ok) {
                if (navigate_to(&c, full_url) == 0) {
                    for (int a = 0; a < CHROME_POLL_ATTEMPTS; a++) {
                        if (detect_xss(&c, 5, event_type) == 0) {
                            confirmed = 1;
                            break;
                        }
                        usleep(CHROME_POLL_INTERVAL_US);
                    }
                }
            } else {
                request r = {0};
                if (gq_http_send(&r, full_url) && r.code == 200 && r.filename[0]) {
                    char *body = slurp_file(r.filename, NULL);
                    if (body) {
                        if (body_contains_payload(body, ctx->payloads[k], ctx->escaped[k]))
                            confirmed = 1;
                        free(body);
                    }
                    safe_remove(r.filename);
                }
            }

            pthread_mutex_lock(&ctx->stat_lock);
            ctx->total_tested++;
            if (confirmed) ctx->total_confirmed++;
            pthread_mutex_unlock(&ctx->stat_lock);

            if (confirmed) {
                pthread_mutex_lock(&ctx->found_lock);
                fprintf(ctx->found, "%s -> %s\n", param, ctx->payloads[k]);
                fflush(ctx->found);
                pthread_mutex_unlock(&ctx->found_lock);
                printf("[%s/w%d] *** CONFIRMED: %s=%s ***\n",
                       ctx->tag, wa->worker_id, param, ctx->payloads[k]);
            }
        }
    }

    if (chrome_ok) close_chrome(&c);
    return NULL;
}

static void xss_payload_run(const char *tag,
                            char *url, char *path,
                            const char *payload_file,
                            const char *out_file_name,
                            int chrome_port_base) {
    if (!url || !path) { fprintf(stderr, "[%s] invalid args\n", tag); return; }

    char param_file[4096];
    char out_path[4096];
    snprintf(param_file, sizeof(param_file), "%s/valid_params.txt", path);
    snprintf(out_path,   sizeof(out_path),   "%s/%s", path, out_file_name);

    if (ensure_directory(path) != 0) {
        fprintf(stderr, "[%s] failed to create %s\n", tag, path);
        return;
    }

    struct xss_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.tag              = tag;
    ctx.url              = url;
    ctx.path             = path;
    ctx.chrome_port_base = chrome_port_base;

    ctx.payloads = load_lines(payload_file, &ctx.npayloads);
    ctx.params   = load_lines(param_file,   &ctx.nparams);

    if (ctx.npayloads <= 0 || ctx.nparams <= 0) {
        fprintf(stderr, "[%s] %s (%d) or %s (%d) empty/missing\n",
                tag, payload_file, ctx.npayloads, param_file, ctx.nparams);
        free_lines(ctx.payloads, ctx.npayloads);
        free_lines(ctx.params,   ctx.nparams);
        return;
    }

    ctx.escaped = calloc((size_t)ctx.npayloads, sizeof(char*));
    for (int k = 0; k < ctx.npayloads; k++)
        ctx.escaped[k] = curl_easy_escape(NULL, ctx.payloads[k], 0);

    ctx.found = fopen(out_path, "w");
    if (!ctx.found) {
        fprintf(stderr, "[%s] cannot write %s\n", tag, out_path);
        for (int k = 0; k < ctx.npayloads; k++)
            if (ctx.escaped[k]) curl_free(ctx.escaped[k]);
        free(ctx.escaped);
        free_lines(ctx.payloads, ctx.npayloads);
        free_lines(ctx.params,   ctx.nparams);
        return;
    }

    pthread_mutex_init(&ctx.found_lock, NULL);
    pthread_mutex_init(&ctx.stat_lock,  NULL);

    pthread_t         tids[WORKERS_PER_SCAN];
    struct worker_arg wargs[WORKERS_PER_SCAN];

    int per = ctx.nparams / WORKERS_PER_SCAN;
    int rem = ctx.nparams % WORKERS_PER_SCAN;
    int cursor = 0;

    for (int w = 0; w < WORKERS_PER_SCAN; w++) {
        int take = per + (w < rem ? 1 : 0);
        wargs[w].ctx         = &ctx;
        wargs[w].worker_id   = w;
        wargs[w].start_param = cursor;
        wargs[w].end_param   = cursor + take;
        cursor += take;

        if (pthread_create(&tids[w], NULL, xss_worker, &wargs[w]) != 0) {
            fprintf(stderr, "[%s] pthread_create failed for worker %d\n", tag, w);
            xss_worker(&wargs[w]);
            tids[w] = 0;
        }
    }

    for (int w = 0; w < WORKERS_PER_SCAN; w++) {
        if (tids[w]) pthread_join(tids[w], NULL);
    }

    printf("[%s] Done. Tested %d, confirmed %d. Results: %s\n",
           tag, ctx.total_tested, ctx.total_confirmed, out_path);

    fclose(ctx.found);
    pthread_mutex_destroy(&ctx.found_lock);
    pthread_mutex_destroy(&ctx.stat_lock);

    for (int k = 0; k < ctx.npayloads; k++)
        if (ctx.escaped[k]) curl_free(ctx.escaped[k]);
    free(ctx.escaped);
    free_lines(ctx.payloads, ctx.npayloads);
    free_lines(ctx.params,   ctx.nparams);
}

/* ============================================================================
 * Scan entrypoints
 * ============================================================================ */

struct scan_arg {
    char *url;
    char *path;
    int   which;
};

static void *scan_thread(void *arg) {
    struct scan_arg *sa = arg;
    if (sa->which == 0) {
        xss_payload_run("xss_generated", sa->url, sa->path,
                        "/usr/share/sentinel/ghostquery/xss/payloads.txt",
                        "valid_payloads.txt",
                        CHROME_BASE_PORT_GENERATED);
    } else {
        xss_payload_run("xss_custom", sa->url, sa->path,
                        "/usr/share/sentinel/ghostquery/xss/custom.txt",
                        "valid_payloads_custom.txt",
                        CHROME_BASE_PORT_CUSTOM);
    }
    return NULL;
}

void xss_generated(char *url, char *path) {
    xss_payload_run("xss_generated", url, path,
                    "/usr/share/sentinel/ghostquery/xss/payloads.txt",
                    "valid_payloads.txt",
                    CHROME_BASE_PORT_GENERATED);
}

void xss_custom(char *url, char *path) {
    xss_payload_run("xss_custom", url, path,
                    "/usr/share/sentinel/ghostquery/xss/custom.txt",
                    "valid_payloads_custom.txt",
                    CHROME_BASE_PORT_CUSTOM);
}

/* ============================================================================
 * Mirror findings
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
 * Entry point
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

    printf("[xss_run] Launching generated + custom scans in parallel...\n");
    struct scan_arg gen = { url, path, 0 };
    struct scan_arg cus = { url, path, 1 };
    pthread_t tgen = 0, tcus = 0;

    pthread_create(&tgen, NULL, scan_thread, &gen);
    pthread_create(&tcus, NULL, scan_thread, &cus);
    if (tgen) pthread_join(tgen, NULL);
    if (tcus) pthread_join(tcus, NULL);

    printf("[xss_run] Mirroring findings into %s/xss.txt\n", report_dir);
    mirror_xss_findings(path, report_dir);

    printf("[xss_run] XSS scanning complete.\n");
    return 0;
}

/* ============================================================================
 * nuclei_run — unchanged
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