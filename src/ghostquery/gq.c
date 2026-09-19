#define _DEFAULT_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <ctype.h>
#include <curl/curl.h>
#include <fcntl.h>
#include <dirent.h>

#include "../util/util.h"
#include "../prox/prox.h"
#include "../chrome/chrome.h"
#include "../glassworm/http/http.h"
#include "../global.h"
#include "gq.h"

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
 * and any #fragment. This is safer than appending: when the base URL is
 * /greet?name=x and we test param 'name', replacing (rather than appending
 * a second 'name=') prevents frameworks like Flask from returning the
 * original value via request.args.get('name'). */
static int build_param_url(char *dst, size_t dstsz,
                           const char *url, const char *param, const char *value) {
    if (!dst || !url || !param || !value) return 0;

    const char *frag    = strchr(url, '#');
    size_t      url_len = frag ? (size_t)(frag - url) : strlen(url);
    const char *q       = memchr(url, '?', url_len);

    /* Look for an existing `param=` segment in the query. */
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
                hit = p;
                seg_end = e;
                break;
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
    if (stat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) return 0;
        errno = ENOTDIR;
        return -1;
    }
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "mkdir -p %s 2>/dev/null", path);
    return system(tmp);
}

/* ============================================================================
 * Payload file iterator — yields ONE payload per call.
 *
 * Lines in custom.txt (and many SecLists payload lists) pack N payloads
 * separated by '|' on a single line. Treating the whole line as a single
 * value blows past MAX_URL_LEN and produces garbage. This iterator splits
 * on '|' and trims whitespace.
 * ============================================================================ */

typedef struct {
    FILE *fp;
    char  line[65536];
    char *cursor;
} payload_iter;

static void payload_iter_init(payload_iter *it, FILE *fp) {
    it->fp = fp;
    it->cursor = NULL;
}

static int payload_iter_next(payload_iter *it, char *buf, size_t bufsz) {
    if (bufsz == 0) return 0;

    for (;;) {
        if (it->cursor && *it->cursor) {
            char *sep = strchr(it->cursor, '|');
            char *end = sep ? sep : it->cursor + strlen(it->cursor);

            while (it->cursor < end && isspace((unsigned char)*it->cursor))
                it->cursor++;
            while (end > it->cursor && isspace((unsigned char)end[-1]))
                end--;

            size_t len = (size_t)(end - it->cursor);
            if (len == 0) {
                it->cursor = sep ? sep + 1 : NULL;
                continue;
            }
            if (len >= bufsz) len = bufsz - 1;
            memcpy(buf, it->cursor, len);
            buf[len] = '\0';
            it->cursor = sep ? sep + 1 : NULL;
            return 1;
        }

        if (!fgets(it->line, sizeof(it->line), it->fp)) return 0;

        strip_newline(it->line);

        /* Skip blank lines and comments */
        char *p = it->line;
        while (*p && isspace((unsigned char)*p)) p++;
        if (*p == '\0' || *p == '#') {
            it->cursor = NULL;
            continue;
        }
        it->cursor = it->line;
    }
}

/* ============================================================================
 * Libcurl Write Callback
 * ============================================================================ */

static size_t write_file(void *ptr, size_t size, size_t nmemb, void *stream) {
    return fwrite(ptr, size, nmemb, (FILE *)stream);
}

/* ============================================================================
 * HTTP Request Sender
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
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");  /* gzip/br/deflate */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    result = curl_easy_perform(curl);
    fclose(fp);

    if (result == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        r->code = (int)http_code;
    } else {
        fprintf(stderr, "Request failed for %s: %s\n",
                url, curl_easy_strerror(result));
        safe_remove(filename);
        r->filename[0] = '\0';
    }

    curl_easy_cleanup(curl);
    return result == CURLE_OK ? 1 : 0;
}

/* ============================================================================
 * Reflection-body matcher
 *
 * We look for three forms, because servers reflect input in different ways:
 *   1. raw        -> body contains the payload verbatim
 *   2. url-encoded-> body contains the encoded form we sent
 *   3. HTML-escaped first char (common partial-escape) -> "&lt;rest"
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
    char *param_file = "ghostquery/params.txt";
    char output_file[4096];
    char *output_dir = "ghostquery/xss";

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

        if (gq_http_send(cur, full_url)) {
            if (cur->code >= 200 && cur->code < 400 && cur->filename[0]) {
                FILE *fpr = fopen(cur->filename, "rb");
                if (fpr) {
                    char *body = malloc(MAX_BODY_READ + 1);
                    if (body) {
                        size_t total = 0, got;
                        while ((got = fread(body + total, 1,
                                            MAX_BODY_READ - total, fpr)) > 0) {
                            total += got;
                            if (total >= MAX_BODY_READ) break;
                        }
                        body[total] = '\0';
                        if (strstr(body, "asdasda")) {
                            fprintf(fptr, "%s\n", buffer);
                            fflush(fptr);
                            printf("[find_param_reflecting] REFLECTS: %s (HTTP %d, %zu bytes)\n",
                                   buffer, cur->code, total);
                        } else {
                            printf("[find_param_reflecting] no reflection: %s (HTTP %d)\n",
                                   buffer, cur->code);
                        }
                        free(body);
                    }
                    fclose(fpr);
                }
            } else {
                printf("[find_param_reflecting] %s -> HTTP %d (skipped)\n",
                       buffer, cur->code);
            }
        } else {
            printf("[find_param_reflecting] %s -> request failed\n", buffer);
        }

        if (cur->filename[0]) { safe_remove(cur->filename); cur->filename[0] = '\0'; }
        i++;
    }

    fclose(fp);
    fclose(fptr);
    free(r);
    printf("find_param_reflecting: results written to %s\n", output_file);
    return 0;
}

/* ============================================================================
 * Helper: read entire file into heap buffer
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
 * XSS payload runner — shared by generated and custom paths
 * ============================================================================ */
static void xss_payload_run(const char *tag,
                            char *url, char *path,
                            const char *payload_file,
                            const char *out_file_name) {
    int nparams, npayloads;
    char full_url[MAX_URL_LEN];
    char param[MAX_PARAM_LEN];
    char payload[MAX_PAYLOAD_LEN];
    char param_file[4096];
    char valid_payloads_path[4096];
    FILE *fp, *ex, *found;
    int total_tested = 0, total_confirmed = 0;
    int chrome_initialized = 0;

    if (!url || !path) { fprintf(stderr, "[%s] invalid args\n", tag); return; }

    snprintf(param_file, sizeof(param_file), "%s/valid_params.txt", path);

    nparams   = line_count(param_file);
    npayloads = line_count((char *)payload_file);

    if (nparams <= 0 || npayloads <= 0) {
        fprintf(stderr, "[%s] %s (%d) or %s (%d) empty/missing\n",
                tag, param_file, nparams, payload_file, npayloads);
        return;
    }

    if (ensure_directory(path) != 0) {
        fprintf(stderr, "[%s] failed to create %s\n", tag, path);
        return;
    }

    snprintf(valid_payloads_path, sizeof(valid_payloads_path),
             "%s/%s", path, out_file_name);

    fp = fopen(param_file, "r");
    if (!fp) { fprintf(stderr, "[%s] cannot open %s\n", tag, param_file); return; }

    found = fopen(valid_payloads_path, "w");
    if (!found) {
        fprintf(stderr, "[%s] cannot write %s\n", tag, valid_payloads_path);
        fclose(fp); return;
    }

    printf("[%s] Initializing Chrome (port %d)...\n", tag, CHROME_PORT);
    if (init_chrome(CHROME_PORT) == 0) {
        chrome_initialized = 1;
        printf("[%s] Chrome initialized\n", tag);
    } else {
        printf("[%s] Chrome init failed — HTTP-only detection\n", tag);
    }

    while (fgets(param, sizeof(param), fp)) {
        strip_newline(param);
        if (param[0] == '\0' || param[0] == '#') continue;

        ex = fopen(payload_file, "r");
        if (!ex) { fprintf(stderr, "[%s] cannot open %s\n", tag, payload_file); break; }

        payload_iter pit;
        payload_iter_init(&pit, ex);

        while (payload_iter_next(&pit, payload, sizeof(payload))) {
            char *enc;
            int interaction_type;

            total_tested++;

            enc = curl_easy_escape(NULL, payload, 0);
            if (!enc) continue;

            if (!build_param_url(full_url, sizeof(full_url), url, param, enc)) {
                curl_free(enc);
                continue;
            }

            interaction_type = detect_payload_event_type(payload);
            printf("[%s] Testing: %s=%s (event=%d, url_len=%zu)\n",
                   tag, param, payload, interaction_type, strlen(full_url));

            if (chrome_initialized) {
                if (navigate_to(full_url) == -1) { curl_free(enc); continue; }
                usleep(300000);
                if (detect_xss(50, interaction_type) == 0) {
                    fprintf(found, "%s -> %s\n", param, payload);
                    fflush(found);
                    total_confirmed++;
                    printf("[%s] *** CONFIRMED: %s=%s ***\n", tag, param, payload);
                }
            } else {
                request r = {0};
                if (gq_http_send(&r, full_url) && r.code == 200) {
                    char *resp = slurp_file(r.filename, NULL);
                    if (resp) {
                        if (body_contains_payload(resp, payload, enc)) {
                            fprintf(found, "%s -> %s\n", param, payload);
                            fflush(found);
                            total_confirmed++;
                            printf("[%s] *** CONFIRMED (HTTP): %s=%s ***\n",
                                   tag, param, payload);
                        }
                        free(resp);
                    }
                    safe_remove(r.filename);
                }
            }
            curl_free(enc);
        }
        fclose(ex);
    }

    fclose(fp);
    fclose(found);
    if (chrome_initialized) close_chrome();

    printf("[%s] Done. Tested %d, confirmed %d. Results: %s\n",
           tag, total_tested, total_confirmed, valid_payloads_path);
}

void xss_generated(char *url, char *path) {
    xss_payload_run("xss_generated", url, path,
                    "ghostquery/xss/payloads.txt",
                    "valid_payloads.txt");
}

void xss_custom(char *url, char *path) {
    /* Distinct output file — do NOT clobber xss_generated's results */
    xss_payload_run("xss_custom", url, path,
                    "ghostquery/xss/custom.txt",
                    "valid_payloads_custom.txt");
}

/* ============================================================================
 * Mirror findings into <report_dir>/xss.txt so analyze() in scan.c sees them
 * ============================================================================ */
static void mirror_xss_findings(const char *path, const char *report_dir) {
    if (!path || !report_dir) return;

    char mirror[4096];
    if (snprintf(mirror, sizeof(mirror), "%s/xss.txt", report_dir)
        >= (int)sizeof(mirror))
        return;

    /* Open with "w" so repeated runs don't grow the file unboundedly. */
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
    char *payloads = "ghostquery/xss/payloads.txt";

    if (!file_exists(payloads)) {
        /* Payload generation is done by an external generator that reads
         * xss.json. We shell out to the scanner's generation hook if present;
         * if the payload file still doesn't exist afterwards we warn and
         * continue — xss_custom does not depend on payloads.txt. */
        char cmd[4096];
        snprintf(cmd, sizeof(cmd),
                 "python3 ghostquery/xss/xss.py '%s' '%s' >/dev/null 2>&1",
                 url, path);
        if (system(cmd) != 0)
            fprintf(stderr, "warning: payload generator exited non-zero (continuing)\n");

        if (!file_exists(payloads)) {
            fprintf(stderr,
                    "warning: %s still missing — xss_generated will skip; "
                    "xss_custom will still run\n", payloads);
        }
    } else {
        printf("[xss_run] Using existing payloads file: %s\n", payloads);
    }

    printf("[xss_run] Finding reflecting parameters...\n");
    if (find_param_reflecting(url, path) != 0) {
        fprintf(stderr, "warning: find_param_reflecting failed\n");
    }

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

    /* ---- Fallback: seed the target list from the static wordlist ---- */
    if (ntargets == 0) {
        printf("[nuclei_run] no reflecting params — falling back to params.txt\n");
        FILE *wf = fopen("ghostquery/params.txt", "r");
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

    /* Merge into nuclei.txt so analyze() sees the findings */
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

/* ============================================================================
 * SQL Injection Run (Placeholder)
 * ============================================================================ */

int sql_run(void) {
    fprintf(stderr, "sql_run: not implemented yet\n");
    return 0;
}