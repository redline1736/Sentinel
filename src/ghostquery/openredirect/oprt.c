#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <curl/curl.h>

#include "../../chrome/chrome.h"
#include "../../util/util.h"
#include "../../prox/prox.h"
#include "../../global.h"
#include "oprt.h"

/* ============================================================================
 * Constants
 * ============================================================================ */

#define MAX_URL_LEN     32768
#define MAX_PARAM_LEN   256
#define MAX_PAYLOAD_LEN 2048
#define CHROME_PORT     9222
#define CURL_TIMEOUT 10L
#define CURL_CONNECT_TIMEOUT 5L

/* Canonical marker host — any redirect that lands here proves the bug. */
#define MARKER_HOST      "example.com"
#define MARKER_URL       "http://example.com/"

/* Payload file — read-only from this point on. */
#define PAYLOAD_FILE     "ghostquery/openredirect/payloads.txt"

/* ============================================================================
 * Small helpers
 * ============================================================================ */

static void strip_nl(char *s) {
    if (!s) return;
    size_t n = strlen(s);
    while (n && (s[n-1] == '\n' || s[n-1] == '\r')) s[--n] = '\0';
}

static int line_count_quick(const char *f) {
    FILE *fp = fopen(f, "r");
    if (!fp) return -1;
    int n = 0, c;
    while ((c = fgetc(fp)) != EOF) if (c == '\n') n++;
    fclose(fp);
    return n;
}

/* Same semantics as gq.c's build_param_url, but local. */
static int build_param_url(char *dst, size_t dstsz,
                           const char *url, const char *param, const char *value) {
    if (!dst || !url || !param || !value) return 0;

    const char *frag    = strchr(url, '#');
    size_t      url_len = frag ? (size_t)(frag - url) : strlen(url);
    const char *q       = memchr(url, '?', url_len);

    const char *hit = NULL, *seg_end = NULL;
    if (q) {
        size_t plen = strlen(param);
        const char *p = q + 1, *end = url + url_len;
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
    return (n >= 0 && (size_t)n < dstsz);
}

/* ============================================================================
 * Payload loading — read the file once into memory
 * ============================================================================ */

/*
 * Reads every non-empty, non-comment line from PAYLOAD_FILE into a
 * NULL-terminated array of heap-allocated strings. Caller must free
 * with free_payloads().
 *
 * Returns: number of payloads loaded, or -1 on error.
 */
static int load_payloads(char ***out) {
    *out = NULL;

    FILE *fp = fopen(PAYLOAD_FILE, "r");
    if (!fp) {
        fprintf(stderr, "[openredirect] cannot open %s\n", PAYLOAD_FILE);
        return -1;
    }

    int cap = 64, n = 0;
    char **arr = malloc(sizeof(char *) * cap);
    if (!arr) { fclose(fp); return -1; }

    char line[MAX_PAYLOAD_LEN];
    while (fgets(line, sizeof(line), fp)) {
        strip_nl(line);
        if (line[0] == '\0' || line[0] == '#') continue;

        if (n + 1 >= cap) {
            cap *= 2;
            char **tmp = realloc(arr, sizeof(char *) * cap);
            if (!tmp) {
                for (int i = 0; i < n; i++) free(arr[i]);
                free(arr);
                fclose(fp);
                return -1;
            }
            arr = tmp;
        }

        arr[n] = strdup(line);
        if (!arr[n]) {
            for (int i = 0; i < n; i++) free(arr[i]);
            free(arr);
            fclose(fp);
            return -1;
        }
        n++;
    }
    fclose(fp);

    arr[n] = NULL;
    *out = arr;
    return n;
}

static void free_payloads(char **arr) {
    if (!arr) return;
    for (int i = 0; arr[i]; i++) free(arr[i]);
    free(arr);
}

/* Kept for API compat — no longer writes anything, just reports. */
int openredirect_generate_payloads(void) {
    char **p = NULL;
    int n = load_payloads(&p);
    if (n < 0) return -1;
    printf("[openredirect] %d payloads available in %s\n", n, PAYLOAD_FILE);
    free_payloads(p);
    return 0;
}

/* ============================================================================
 * HTTP probe (fallback when Chrome is unavailable)
 * ============================================================================ */

static size_t discard_cb(char *p, size_t s, size_t n, void *u) {
    (void)p; (void)u;
    return s * n;
}

static int http_probe_open_redirect(const char *url,
                                    char *final_out, size_t final_sz,
                                    char *loc_out,   size_t loc_sz) {
    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    if (final_out && final_sz) final_out[0] = '\0';
    if (loc_out   && loc_sz)   loc_out[0]   = '\0';

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, CURL_TIMEOUT);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, CURL_CONNECT_TIMEOUT);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "ghostquery/1.0");
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, discard_cb);

    CURLcode rc = curl_easy_perform(curl);
    if (rc != CURLE_OK) {
        curl_easy_cleanup(curl);
        return -1;
    }

    long code = 0;
    char *loc = NULL;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_easy_getinfo(curl, CURLINFO_REDIRECT_URL, &loc);

    if (loc && loc_out && loc_sz)
        snprintf(loc_out, loc_sz, "%s", loc);

    if (code >= 300 && code < 400 && loc) {
        CURL *c2 = curl_easy_init();
        if (c2) {
            curl_easy_setopt(c2, CURLOPT_URL, loc);
            curl_easy_setopt(c2, CURLOPT_FOLLOWLOCATION, 1L);
            curl_easy_setopt(c2, CURLOPT_MAXREDIRS, 5L);
            curl_easy_setopt(c2, CURLOPT_TIMEOUT, CURL_TIMEOUT);
            curl_easy_setopt(c2, CURLOPT_CONNECTTIMEOUT, CURL_CONNECT_TIMEOUT);
            curl_easy_setopt(c2, CURLOPT_NOSIGNAL, 1L);
            curl_easy_setopt(c2, CURLOPT_WRITEFUNCTION, discard_cb);
            curl_easy_setopt(c2, CURLOPT_SSL_VERIFYPEER, 0L);
            curl_easy_setopt(c2, CURLOPT_SSL_VERIFYHOST, 0L);
            if (curl_easy_perform(c2) == CURLE_OK) {
                char *final = NULL;
                curl_easy_getinfo(c2, CURLINFO_EFFECTIVE_URL, &final);
                if (final && final_out && final_sz)
                    snprintf(final_out, final_sz, "%s", final);
            }
            curl_easy_cleanup(c2);
        }
    } else if (code >= 200 && code < 300) {
        if (final_out && final_sz)
            snprintf(final_out, final_sz, "%s", url);
    }

    curl_easy_cleanup(curl);
    return 0;
}

static int url_host_is_marker(const char *url) {
    if (!url || !*url) return 0;

    const char *p = strstr(url, "://");
    p = p ? p + 3 : url;

    const char *at = strchr(p, '@');
    if (at) p = at + 1;

    size_t hl = strlen(MARKER_HOST);
    for (size_t i = 0; i < hl; i++) {
        if (tolower((unsigned char)p[i]) != MARKER_HOST[i]) return 0;
    }
    char c = p[hl];
    return (c == '\0' || c == '/' || c == ':' || c == '?' || c == '#');
}

/* ============================================================================
 * Chrome-based probe
 * ============================================================================ */

static int cdp_current_url(chrome *c, char *out, size_t outsz) {
    if (!c || !c->use_websocket || outsz == 0) return 0;
    out[0] = '\0';

    const char *cmd =
        "{\"id\":201,\"method\":\"Runtime.evaluate\",\"params\":{"
        "\"expression\":\"location.href\","
        "\"returnByValue\":true}}";
    size_t sent = 0;
    if (curl_ws_send(c->curl, cmd, strlen(cmd), &sent, 0, CURLWS_TEXT) != CURLE_OK)
        return 0;

    for (int i = 0; i < 200; i++) {
        const struct curl_ws_frame *meta = NULL;
        char buf[8192];
        size_t n = 0;
        CURLcode rc = curl_ws_recv(c->curl, buf, sizeof(buf) - 1, &n, &meta);
        if (rc == CURLE_AGAIN) { usleep(30000); continue; }
        if (rc != CURLE_OK) break;
        if (n == 0) continue;
        buf[n] = '\0';

        if (!strstr(buf, "\"id\":201")) continue;

        const char *v = strstr(buf, "\"value\":\"");
        if (!v) break;
        v += 9;
        const char *end = strchr(v, '"');
        if (!end) break;
        size_t len = (size_t)(end - v);
        if (len >= outsz) len = outsz - 1;
        memcpy(out, v, len);
        out[len] = '\0';
        return 1;
    }
    return 0;
}

static int chrome_probe_open_redirect(chrome *c,
                                      const char *url,
                                      char *final_out, size_t final_sz) {
    if (final_out && final_sz) final_out[0] = '\0';
    if (!c || !c->use_websocket) return 0;

    if (navigate_to(c, url) != 0) return 0;

    usleep(800000);

    char cur[2048];
    if (!cdp_current_url(c, cur, sizeof(cur))) return 0;
    if (final_out && final_sz) snprintf(final_out, final_sz, "%s", cur);

    return url_host_is_marker(cur);
}

/* ============================================================================
 * Driver
 * ============================================================================ */

int openredirect_run(char *url, char *path) {
    if (!url || !path) {
        fprintf(stderr, "[openredirect] invalid arguments\n");
        return 1;
    }

    /* Load payloads once into memory. */
    char **payloads = NULL;
    int npayloads = load_payloads(&payloads);
    if (npayloads <= 0) {
        fprintf(stderr, "[openredirect] no payloads loaded from %s\n",
                PAYLOAD_FILE);
        free_payloads(payloads);
        return 1;
    }

    char param_file[4096], out_file[4096];
    snprintf(param_file, sizeof(param_file), "%s/valid_params.txt", path);
    snprintf(out_file,   sizeof(out_file),   "%s/openredirect.txt", path);

    int nparams = line_count_quick(param_file);
    if (nparams <= 0) {
        fprintf(stderr, "[openredirect] %s is empty or missing\n", param_file);
        free_payloads(payloads);
        return 1;
    }

    FILE *pf = fopen(param_file, "r");
    if (!pf) {
        fprintf(stderr, "[openredirect] cannot read %s\n", param_file);
        free_payloads(payloads);
        return 1;
    }

    FILE *out = fopen(out_file, "a");
    if (!out) {
        fprintf(stderr, "[openredirect] cannot write %s\n", out_file);
        fclose(pf);
        free_payloads(payloads);
        return 1;
    }

    chrome c;
    memset(&c, 0, sizeof(c));
    int have_chrome = (init_chrome(&c, CHROME_PORT) == 0);
    if (have_chrome) printf("[openredirect] Chrome ready\n");
    else             printf("[openredirect] Chrome unavailable — using libcurl\n");

    printf("[openredirect] loaded %d payloads from %s\n",
           npayloads, PAYLOAD_FILE);

    char param[MAX_PARAM_LEN];
    char full_url[MAX_URL_LEN];
    int  tested = 0, confirmed = 0;

    while (fgets(param, sizeof(param), pf)) {
        strip_nl(param);
        if (param[0] == '\0' || param[0] == '#') continue;

        for (int pi = 0; pi < npayloads; pi++) {
            const char *payload = payloads[pi];

            char *enc = curl_easy_escape(NULL, payload, 0);
            if (!enc) continue;

            if (!build_param_url(full_url, sizeof(full_url),
                                 url, param, enc)) {
                curl_free(enc);
                continue;
            }
            curl_free(enc);

            tested++;

            char final_url[2048] = {0};
            char loc_hdr[2048]   = {0};
            int  hit = 0;

            if (have_chrome) {
                hit = chrome_probe_open_redirect(&c, full_url,
                                                 final_url, sizeof(final_url));
            } else {
                if (http_probe_open_redirect(full_url,
                                             final_url, sizeof(final_url),
                                             loc_hdr, sizeof(loc_hdr)) == 0) {
                    hit = url_host_is_marker(final_url) ||
                          url_host_is_marker(loc_hdr);
                }
            }

            if (hit) {
                fprintf(out, "%s -> %s\n", param, payload);
                fflush(out);
                confirmed++;
                printf("[openredirect] *** CONFIRMED %s=%s  ->  %s ***\n",
                       param, payload,
                       final_url[0] ? final_url : loc_hdr);
            } else {
                printf("[openredirect] no redirect: %s=%s\n", param, payload);
            }
        }
    }

    fclose(pf);
    fclose(out);
    if (have_chrome) close_chrome(&c);
    free_payloads(payloads);

    printf("[openredirect] Done. Tested %d, confirmed %d. Results: %s\n",
           tested, confirmed, out_file);
    return 0;
}