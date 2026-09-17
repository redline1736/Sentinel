#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <curl/curl.h>
#include "sub.h"
/* ------------------------------------------------------------------ */
/* Tunables                                                            */
/* ------------------------------------------------------------------ */
#define BODY_MAX         (256 * 1024)   /* cap response body at 256 KB    */
#define CNAME_MAX        512
#define MAX_FP           256
#define HTTP_TIMEOUT     10L
#define CONNECT_TIMEOUT  5L
#define USER_AGENT       "Mozilla/5.0 (compatible; Sentinel-takeover/1.0)"

/* ------------------------------------------------------------------ */
/* Fingerprint table                                                   */
/* ------------------------------------------------------------------ */
typedef struct {
    char provider[128];
    char cname[256];
    char fingerprint[256];
} fp_t;

static fp_t  g_fps[MAX_FP];
static int   g_fp_count = 0;

/* ------------------------------------------------------------------ */
/* Response body buffer                                                */
/* ------------------------------------------------------------------ */
typedef struct {
    char   data[BODY_MAX + 1];
    size_t len;
} body_t;

static size_t body_write_cb(void *ptr, size_t size, size_t nmemb, void *ud) {
    size_t realsize = size * nmemb;
    body_t *b = (body_t *)ud;
    size_t space = BODY_MAX - b->len;
    if (realsize > space) realsize = space;
    if (realsize > 0) {
        memcpy(b->data + b->len, ptr, realsize);
        b->len += realsize;
        b->data[b->len] = '\0';
    }
    /* Always return the FULL size or curl aborts the transfer. */
    return size * nmemb;
}

/* ------------------------------------------------------------------ */
/* Case-insensitive substring search                                   */
/* ------------------------------------------------------------------ */
static const char *stristr(const char *hay, const char *needle) {
    if (!hay || !needle || !*needle) return NULL;
    size_t nlen = strlen(needle);
    for (; *hay; hay++) {
        if (strncasecmp(hay, needle, nlen) == 0) return hay;
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Strip trailing whitespace + CR/LF in place                          */
/* ------------------------------------------------------------------ */
static void rstrip(char *s) {
    if (!s) return;
    size_t n = strlen(s);
    while (n && (s[n-1] == '\n' || s[n-1] == '\r' ||
                 s[n-1] == ' '  || s[n-1] == '\t')) {
        s[--n] = '\0';
    }
}

/* ------------------------------------------------------------------ */
/* Load driver file:  provider|cname|fingerprint                       */
/* ------------------------------------------------------------------ */
static int load_driver(const char *file) {
    FILE *fp = fopen(file, "r");
    if (!fp) {
        fprintf(stderr, "[-] Cannot open driver file '%s': %s\n",
                file, strerror(errno));
        return -1;
    }

    char line[1024];
    int  lineno = 0;

    while (fgets(line, sizeof(line), fp)) {
        lineno++;
        rstrip(line);

        if (line[0] == '\0' || line[0] == '#') continue;

        char *save = NULL;
        char *provider    = strtok_r(line, "|", &save);
        char *cname       = strtok_r(NULL, "|", &save);
        char *fingerprint = strtok_r(NULL, "|", &save);

        if (!provider || !cname || !fingerprint) {
            fprintf(stderr, "[!] Driver line %d malformed, skipping: %s\n",
                    lineno, line);
            continue;
        }

        if (g_fp_count >= MAX_FP) {
            fprintf(stderr, "[!] Driver table full (%d entries), stopping\n",
                    MAX_FP);
            break;
        }

        /* snprintf always null-terminates; strncpy does NOT. */
        snprintf(g_fps[g_fp_count].provider,
                 sizeof(g_fps[g_fp_count].provider), "%s", provider);
        snprintf(g_fps[g_fp_count].cname,
                 sizeof(g_fps[g_fp_count].cname), "%s", cname);
        snprintf(g_fps[g_fp_count].fingerprint,
                 sizeof(g_fps[g_fp_count].fingerprint), "%s", fingerprint);
        g_fp_count++;
    }

    fclose(fp);
    return g_fp_count;
}

/* ------------------------------------------------------------------ */
/* DNS: does the host resolve at all?                                  */
/* ------------------------------------------------------------------ */
static int host_resolves(const char *host) {
    /* Use getent (portable, works without libresolv) via popen. */
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "getent hosts %s >/dev/null 2>&1", host);
    int rc = system(cmd);
    return rc == 0;
}

/* ------------------------------------------------------------------ */
/* CNAME: walk the full chain, concatenate into `out`.                 */
/* Returns 1 if at least one CNAME hop was found, else 0.              */
/* ------------------------------------------------------------------ */
static int get_cname_chain(const char *domain, char *out, size_t outsz) {
    char cmd[512];
    /* +short collapses the chain to one line per hop */
    snprintf(cmd, sizeof(cmd), "dig +short CNAME %s 2>/dev/null", domain);

    FILE *fp = popen(cmd, "r");
    if (!fp) return 0;

    out[0] = '\0';
    char line[256];
    int  found = 0;

    while (fgets(line, sizeof(line), fp)) {
        rstrip(line);
        if (line[0] == '\0') continue;
        found = 1;

        size_t cur = strlen(out);
        if (cur + strlen(line) + 2 >= outsz) break;

        if (cur) {
            out[cur++] = ' ';
            out[cur]   = '\0';
        }
        strncat(out, line, outsz - strlen(out) - 1);
    }
    pclose(fp);
    return found;
}

/* ------------------------------------------------------------------ */
/* HTTP GET with HTTPS→HTTP fallback. Returns status code or -1.       */
/* ------------------------------------------------------------------ */
static long http_get_sub(const char *url, body_t *body) {
    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    body->data[0] = '\0';
    body->len     = 0;

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, body_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, body);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 3L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, HTTP_TIMEOUT);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, CONNECT_TIMEOUT);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, USER_AGENT);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");  /* auto-gzip */

    /* Unclaimed services often have broken/expired certs. */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    CURLcode rc = curl_easy_perform(curl);

    long code = -1;
    if (rc == CURLE_OK)
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);

    curl_easy_cleanup(curl);
    return (rc == CURLE_OK) ? code : -1;
}

/* ------------------------------------------------------------------ */
/* Check one host. Returns 1 if vulnerable, 0 otherwise.               */
/* Writes provider name into provider_out and a human detail into      */
/* detail_out.                                                         */
/* ------------------------------------------------------------------ */
static int check_host(const char *host,
                      char *provider_out, size_t provider_sz,
                      char *detail_out,   size_t detail_sz,
                      long *http_code_out) {
    provider_out[0] = '\0';
    detail_out[0]   = '\0';
    *http_code_out  = 0;

    /* 1. If it doesn't resolve, nothing to take over. */
    if (!host_resolves(host)) {
        snprintf(detail_out, detail_sz, "does not resolve");
        return 0;
    }

    /* 2. Get the full CNAME chain (if any). */
    char cname[CNAME_MAX] = {0};
    int  has_cname = get_cname_chain(host, cname, sizeof(cname));

    /* 3. Fetch root over HTTPS, fall back to HTTP. */
    body_t body;
    char   url[600];
    long   code;

    snprintf(url, sizeof(url), "https://%s/", host);
    code = http_get_sub(url, &body);
    if (code < 0) {
        snprintf(url, sizeof(url), "http://%s/", host);
        code = http_get_sub(url, &body);
    }
    *http_code_out = code;

    if (code < 0 || body.len == 0) {
        snprintf(detail_out, detail_sz, "no HTTP response");
        return 0;
    }

    /* 4. Match fingerprints: CNAME (if we got one) AND body must match. */
    for (int i = 0; i < g_fp_count; i++) {
        /* If the driver row has a CNAME hint and we got a CNAME,
         * require the hint to appear. If we got NO CNAME, skip the row
         * entirely — a body-only match is too noisy. */
        if (!has_cname) break;
        if (!stristr(cname, g_fps[i].cname)) continue;
        if (!stristr(body.data, g_fps[i].fingerprint)) continue;

        snprintf(provider_out, provider_sz, "%s", g_fps[i].provider);
        snprintf(detail_out, detail_sz,
                 "cname='%s' sig='%s' http=%ld",
                 cname, g_fps[i].fingerprint, code);
        return 1;
    }

    snprintf(detail_out, detail_sz,
             "cname='%s' http=%ld no sig match",
             has_cname ? cname : "(none)", code);
    return 0;
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */
int atlas(char *hosts_file, char *hostdir) {
    char out_file[512];
    snprintf(out_file, sizeof(out_file), "%s/atlas.txt", hostdir);
 
    const char driver_file[] = "atlas/sig.txt";


    if (curl_global_init(CURL_GLOBAL_DEFAULT) != 0) {
        fprintf(stderr, "[-] curl_global_init failed\n");
        return 1;
    }

    int loaded = load_driver(driver_file);
    if (loaded <= 0) {
        fprintf(stderr, "[-] No fingerprints loaded from %s\n", driver_file);
        curl_global_cleanup();
        return 1;
    }
    printf("[*] Loaded %d fingerprints from %s\n", loaded, driver_file);

    FILE *in = fopen(hosts_file, "r");
    if (!in) {
        fprintf(stderr, "[-] Cannot open hosts file '%s': %s\n",
                hosts_file, strerror(errno));
        curl_global_cleanup();
        return 1;
    }

    FILE *out = fopen(out_file, "a");
    if (!out) {
        fprintf(stderr, "[-] Cannot open output file '%s': %s\n",
                out_file, strerror(errno));
        fclose(in);
        curl_global_cleanup();
        return 1;
    }

    char  line[512];
    int   total = 0, vuln = 0;
    time_t start = time(NULL);

    while (fgets(line, sizeof(line), in)) {
        rstrip(line);
        if (line[0] == '\0' || line[0] == '#') continue;

        /* Skip entries containing '/' — a host list shouldn't have paths. */
        if (strchr(line, '/')) {
            printf("[!] Skipping invalid host entry: %s\n", line);
            continue;
        }

        total++;
        printf("[*] Checking %s\n", line);

        char provider[128] = {0};
        char detail[512]   = {0};
        long http_code     = 0;

        int is_vuln = check_host(line, provider, sizeof(provider),
                                 detail, sizeof(detail), &http_code);

        if (is_vuln) {
            vuln++;
            printf("[+] VULNERABLE: %s -> %s (HTTP %ld)\n",
                   line, provider, http_code);
            /* Emit the exact tag subjack/subzy use so analyze() in
             * scan.c picks this up without modification. */
            fprintf(out, "[VULNERABLE] %s -> %s (HTTP %ld) %s\n",
                    line, provider, http_code, detail);
            fflush(out);
        } else {
            printf("[-] %s — %s\n", line, detail);
        }
    }

    fclose(in);
    fclose(out);
    curl_global_cleanup();

    double elapsed = difftime(time(NULL), start);
    printf("\n=== %d/%d hosts vulnerable (%.1fs) ===\n",
           vuln, total, elapsed);
    return 0;
}