#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <curl/curl.h>

#include "sub.h"

/* ------------------------------------------------------------------ */
/* Tunables                                                            */
/* ------------------------------------------------------------------ */
#define BODY_MAX         (1024 * 1024)   /* 1 MiB */
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

static fp_t g_fps[MAX_FP];
static int  g_fp_count = 0;

/* ------------------------------------------------------------------ */
/* Heap-allocated response body                                        */
/* ------------------------------------------------------------------ */
typedef struct {
    char  *data;
    size_t len;
    size_t cap;
} body_t;

static int body_init(body_t *b, size_t cap) {
    b->data = malloc(cap + 1);
    if (!b->data) return -1;
    b->data[0] = '\0';
    b->len     = 0;
    b->cap     = cap;
    return 0;
}

static void body_free(body_t *b) {
    if (!b) return;
    free(b->data);
    b->data = NULL;
    b->len  = b->cap = 0;
}

static size_t body_write_cb(void *ptr, size_t size, size_t nmemb, void *ud) {
    size_t realsize = size * nmemb;
    body_t *b = (body_t *)ud;
    if (!b || !b->data) return size * nmemb;

    size_t space = b->cap - b->len;
    if (realsize > space) realsize = space;
    if (realsize > 0) {
        memcpy(b->data + b->len, ptr, realsize);
        b->len += realsize;
        b->data[b->len] = '\0';
    }
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

        char *save        = NULL;
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

        snprintf(g_fps[g_fp_count].provider,
                 sizeof(g_fps[g_fp_count].provider), "%s", provider);
        snprintf(g_fps[g_fp_count].cname,
                 sizeof(g_fps[g_fp_count].cname),    "%s", cname);
        snprintf(g_fps[g_fp_count].fingerprint,
                 sizeof(g_fps[g_fp_count].fingerprint), "%s", fingerprint);
        g_fp_count++;
    }

    fclose(fp);
    return g_fp_count;
}

/* ------------------------------------------------------------------ */
/* CNAME chain.                                                        */
/*   glibc's getaddrinfo(AI_CANONNAME) does NOT reliably return the    */
/*   CNAME chain — it often returns the original name. Use `dig` as    */
/*   the primary source; keep getaddrinfo only as a fallback so the    */
/*   tool still works on hosts without dig.                            */
/*   Returns 1 if any CNAME hop was found, else 0.                     */
/* ------------------------------------------------------------------ */
static int get_cname_chain(const char *domain, char *out, size_t outsz) {
    if (!domain || !out || outsz == 0) return 0;
    out[0] = '\0';
    int found = 0;

    /* 1. dig +short CNAME (primary — this is what subzy uses) */
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "dig +short CNAME %s 2>/dev/null", domain);
    FILE *fp = popen(cmd, "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            rstrip(line);
            if (line[0] == '\0') continue;
            /* dig appends a trailing dot to FQDNs; strip it */
            size_t l = strlen(line);
            if (l && line[l-1] == '.') line[--l] = '\0';

            if (!found) {
                snprintf(out, outsz, "%s", line);
                found = 1;
            } else if (!stristr(out, line)) {
                size_t cur = strlen(out);
                if (cur + 1 + strlen(line) + 1 < outsz) {
                    out[cur] = ' ';
                    snprintf(out + cur + 1, outsz - cur - 1, "%s", line);
                }
            }
        }
        pclose(fp);
    }

    /* 2. getaddrinfo fallback — weak on glibc but harmless */
    if (!found) {
        struct addrinfo hints;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family   = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags    = AI_CANONNAME;

        struct addrinfo *res = NULL;
        if (getaddrinfo(domain, NULL, &hints, &res) == 0 && res) {
            const char *canon = res->ai_canonname;
            if (canon && *canon && strcasecmp(canon, domain) != 0) {
                size_t l = strlen(canon);
                if (l && canon[l-1] == '.') l--;
                if (l > 0 && l < outsz) {
                    memcpy(out, canon, l);
                    out[l] = '\0';
                    found = 1;
                }
            }
            freeaddrinfo(res);
        }
    }

    return found;
}

/* ------------------------------------------------------------------ */
/* HTTP GET. Returns status code or -1 on transport failure.           */
/* ------------------------------------------------------------------ */
static long http_get_sub(const char *url, body_t *body) {
    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    body->len     = 0;
    body->data[0] = '\0';

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, body_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, body);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 3L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, HTTP_TIMEOUT);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, CONNECT_TIMEOUT);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, USER_AGENT);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    CURLcode rc = curl_easy_perform(curl);

    long code = -1;
    if (rc == CURLE_OK)
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);

    curl_easy_cleanup(curl);
    return (rc == CURLE_OK) ? code : -1;
}

/* Try HTTP first, then HTTPS. Returns the first scheme that produced
 * a non-empty body. Records which scheme won in `used_scheme`.
 *
 * HTTP-first matters: several providers (Cargo Collective, UptimeRobot,
 * Heroku, ...) serve a distinctive unclaimed-site page over HTTP that
 * is either absent or different over HTTPS. subzy also probes HTTP
 * first (see its `--https No` default).                          */
static long fetch_both(const char *host, body_t *body,
                       char *used_scheme, size_t ss) {
    char url[600];
    long code;

    if (used_scheme && ss) used_scheme[0] = '\0';

    snprintf(url, sizeof(url), "http://%s/", host);
    code = http_get_sub(url, body);
    if (code > 0 && body->len > 0) {
        if (used_scheme && ss) snprintf(used_scheme, ss, "http");
        return code;
    }

    snprintf(url, sizeof(url), "https://%s/", host);
    code = http_get_sub(url, body);
    if (code > 0 && body->len > 0) {
        if (used_scheme && ss) snprintf(used_scheme, ss, "https");
        return code;
    }

    if (used_scheme && ss) snprintf(used_scheme, ss, "none");
    return code;
}

/* ------------------------------------------------------------------ */
/* Check one host. Returns 1 if vulnerable, 0 otherwise.               */
/* ------------------------------------------------------------------ */
static int check_host(const char *host,
                      char *provider_out, size_t provider_sz,
                      char *detail_out,   size_t detail_sz,
                      long *http_code_out) {
    provider_out[0] = '\0';
    detail_out[0]   = '\0';
    *http_code_out  = 0;

    char cname[CNAME_MAX] = {0};
    int  has_cname = get_cname_chain(host, cname, sizeof(cname));

    body_t body;
    if (body_init(&body, BODY_MAX) != 0) {
        snprintf(detail_out, detail_sz, "out of memory");
        return 0;
    }

    char scheme[8] = {0};
    long code = fetch_both(host, &body, scheme, sizeof(scheme));
    *http_code_out = code;

    if (code < 0 || body.len == 0) {
        snprintf(detail_out, detail_sz,
                 "no HTTP body (scheme=%s cname='%s' http=%ld)",
                 scheme[0] ? scheme : "none",
                 has_cname ? cname : "(none)", code);
        body_free(&body);
        return 0;
    }

    /* Body fingerprint is the evidence.  The CNAME column is an
     * additional constraint only when both sides have data — it must
     * never block a body-only match, and it must never `break` the
     * whole loop.  Also: keep the loop going past non-matching rows
     * instead of aborting on the first host-level condition. */
    for (int i = 0; i < g_fp_count; i++) {
        if (!stristr(body.data, g_fps[i].fingerprint)) continue;
        if (has_cname && g_fps[i].cname[0] &&
            !stristr(cname, g_fps[i].cname))
            continue;

        snprintf(provider_out, provider_sz, "%s", g_fps[i].provider);
        snprintf(detail_out, detail_sz,
                 "scheme=%s cname='%s' sig='%s' http=%ld bodylen=%zu",
                 scheme, has_cname ? cname : "(none)",
                 g_fps[i].fingerprint, code, body.len);
        body_free(&body);
        return 1;
    }

    snprintf(detail_out, detail_sz,
             "scheme=%s cname='%s' http=%ld bodylen=%zu no sig match",
             scheme, has_cname ? cname : "(none)", code, body.len);
    body_free(&body);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Public entry point                                                  */
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

    char   line[512];
    int    total = 0, vuln = 0;
    time_t start = time(NULL);

    while (fgets(line, sizeof(line), in)) {
        rstrip(line);
        if (line[0] == '\0' || line[0] == '#') continue;

        /* Accept bare hostnames AND URLs. Strip scheme + path in place. */
        char *host = line;
        if      (strncmp(host, "https://", 8) == 0) host += 8;
        else if (strncmp(host, "http://",  7) == 0) host += 7;

        char *slash = strchr(host, '/');
        if (slash) *slash = '\0';

        if (host[0] == '\0') continue;

        total++;
        printf("[*] Checking %s\n", host);

        char provider[128] = {0};
        char detail[512]   = {0};
        long http_code     = 0;

        int is_vuln = check_host(host, provider, sizeof(provider),
                                 detail, sizeof(detail), &http_code);

        if (is_vuln) {
            vuln++;
            printf("[+] VULNERABLE: %s -> %s (HTTP %ld)\n",
                   host, provider, http_code);
            fprintf(out, "[VULNERABLE] %s -> %s (HTTP %ld) %s\n",
                    host, provider, http_code, detail);
            fflush(out);
        } else {
            printf("[-] %s — %s\n", host, detail);
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