#include <dirent.h>
#include <pthread.h>
#include <ctype.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <curl/curl.h>

#include "scan.h"

/* Global includes */
#include "../util/util.h"
#include "../global.h"

/* Extra includes for scanning */
#include "../prox/prox.h"
#include "../http/http.h"
#include "../recon/info.h"
#include "../deepblue/deepblue.h"

/* Hacking Related Includes */
#include "../ghostquery/gq.h"
#include "../atlas/sub.h"
#include "../headers/hdr.h"
#include "../glassworm/gw.h"

/* Rate-limit tunables (declared extern in scan.h) */
int g_rate = 0;                 /* requests per second budget (0 = unlimited) */
double g_retry_minutes = 5.0;   /* backoff window for 429/503 */

/* ------------------------------------------------------------------ */
/* Worker-pool concurrency for the per-host pass. The old code walked */
/* the result dir serially: worst case ~N_hosts * 30s curl timeout.   */
/* Now: fixed worker pool + thread-safe job queue.                    */
/* ------------------------------------------------------------------ */

#define SCAN_POOL_MAX 16        /* host workers */
#define WP_THREADS_MAX 256      /* wpscan fan-out cap (unchanged behavior) */

typedef struct {
    char host[G_DOMAIN_MAX];
    bool wordpress;             /* pre-detected by the producer */
} host_job;

static host_job  *g_jobs = NULL;
static size_t     g_job_count = 0;
static size_t     g_job_next = 0;          /* next unclaimed job index */
static pthread_mutex_t g_job_lock = PTHREAD_MUTEX_INITIALIZER;

static pthread_t g_wp_threads[WP_THREADS_MAX];
static int       g_wp_thread_count = 0;
static pthread_mutex_t g_wp_spawn_lock = PTHREAD_MUTEX_INITIALIZER;

/* ---------- small C helpers (replace shell pipes/redirection) ---------- */

static int cmp_str(const void *a, const void *b) {
    return strcmp(*(char * const *)a, *(char * const *)b);
}

/* Reads file, strips empty lines, sorts, dedupes, writes back in place. */
static void dedupe_file(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "[!] Cannot open %s for dedupe\n", path);
        return;
    }

    char **lines = NULL;
    size_t n = 0, cap = 0;
    char buf[4096];

    while (fgets(buf, sizeof(buf), fp)) {
        size_t l = strlen(buf);
        while (l && (buf[l - 1] == '\n' || buf[l - 1] == '\r'))
            buf[--l] = '\0';
        if (l == 0)
            continue;

        if (n == cap) {
            cap = cap ? cap * 2 : 256;
            char **nl = realloc(lines, cap * sizeof(*lines));
            if (!nl) {
                fclose(fp);
                for (size_t i = 0; i < n; i++) free(lines[i]);
                free(lines);
                return;
            }
            lines = nl;
        }
        lines[n] = strdup(buf);
        if (lines[n])
            n++;
    }
    fclose(fp);

    qsort(lines, n, sizeof(*lines), cmp_str);

    /* dedupe in place */
    size_t w = 0;
    for (size_t i = 0; i < n; i++) {
        if (w == 0 || strcmp(lines[i], lines[w - 1]) != 0) {
            lines[w++] = lines[i];
        } else {
            free(lines[i]);
        }
    }
    n = w;

    fp = fopen(path, "w");
    if (!fp) {
        fprintf(stderr, "[!] Cannot rewrite %s for dedupe\n", path);
        for (size_t i = 0; i < n; i++) free(lines[i]);
        free(lines);
        return;
    }
    for (size_t i = 0; i < n; i++) {
        fprintf(fp, "%s\n", lines[i]);
        free(lines[i]);
    }
    free(lines);
    fclose(fp);
}

static bool is_result_dir(const struct dirent *entry) {
    if (entry->d_type != DT_DIR)
        return false;
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
        return false;
    return true;
}

static void ensure_dir(const char *path) {
    if (mkdir(path, 0755) != 0 && errno != EEXIST)
        fprintf(stderr, "[!] mkdir(%s): %s\n", path, strerror(errno));
}

/* ------------------------------------------------------------------ */
/* WordPress fingerprint (fixed: body in memory, no temp file)        */
/* ------------------------------------------------------------------ */

static bool detect_wordpress(const request *r) {
    if (!r || r->code == 0 || !r->body)
        return false;
    /* Harder-to-spoof fingerprints only: plain "WordPress" appears in
     * arbitrary page text; wp-content/ and /wp-json are WP infra. */
    return strstr(r->body, "wp-content/") != NULL ||
           strstr(r->body, "/wp-json")    != NULL;
}

/* Probe one host over https then http. Returns the request with a
 * nonzero code on success (caller frees). */
static bool probe_host(const char *host, request *r) {
    char target[512];

    snprintf(target, sizeof(target), "https://%s", host);
    if (http_send_get(r, target) && r->code != 0)
        return true;

    request_free(r);
    snprintf(target, sizeof(target), "http://%s", host);
    if (http_send_get(r, target) && r->code != 0)
        return true;

    request_free(r);
    return false;
}

/* ------------------------------------------------------------------ */
/* Per-host scan worker                                               */
/* ------------------------------------------------------------------ */

/* PLACEHOLDER — preserve your existing per-host logic here verbatim.
 * I could not fetch this function's body from the web; keep your
 * current implementation (it calls run_tool_out()/subzy/subjack/
 * nuclei/xss into hostdir). Signature unchanged. */
static void scan_one_host(const char *host, const char *hostdir);

static void *host_worker(void *arg) {
    (void)arg;
    for (;;) {
        pthread_mutex_lock(&g_job_lock);
        if (g_job_next >= g_job_count) {
            pthread_mutex_unlock(&g_job_lock);
            return NULL;
        }
        host_job *job = &g_jobs[g_job_next++];
        char host[G_DOMAIN_MAX];
        snprintf(host, sizeof(host), "%s", job->host);
        pthread_mutex_unlock(&g_job_lock);

        char hostdir[G_DIR_MAX];
        snprintf(hostdir, sizeof(hostdir), "%s/%s", g.dir, host);
        ensure_dir(hostdir);
        scan_one_host(host, hostdir);
    }
}

static void *wpscan_thread(void *arg) {
    char *host = arg;    /* owned; freed here */

    char hostdir[G_DIR_MAX];
    snprintf(hostdir, sizeof(hostdir), "%s/%s", g.dir, host);
    ensure_dir(hostdir);

    char out[2200];
    snprintf(out, sizeof(out), "%s/wpscan.txt", hostdir);

    char *argv[] = {
        (char *)"wpscan",
        (char *)"--url", host,
        (char *)"-o", out,
        NULL
    };
    run_tool(argv);

    free(host);
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Pipeline stages                                                    */
/* ------------------------------------------------------------------ */

void subdomain(void) {
    /* PLACEHOLDER — I could not fetch the full body; preserve your
     * existing implementation verbatim (wordlists, run_tool_out for
     * subfinder/assetfinder/httpx, write into <g.dir>/live.txt).
     * Signature unchanged. */
}

void scanning(char *target_url) {
    /* PLACEHOLDER — preserve your existing implementation verbatim
     * (dispatch to ghostquery/glassworm/deepblue per target_url and
     * g.sitescan/g.full). Signature unchanged. */
}

void analyze(void) {
    printf("[+] Analyzing scan results...\n");

    DIR *dir = opendir(g.dir);
    if (!dir) {
        perror("opendir");
        return;
    }

    struct dirent *entry;

    while ((entry = readdir(dir)) != NULL) {
        if (!is_result_dir(entry))
            continue;

        char subzy[2048], subjack[2048], nuclei[2048];
        char xss[2048], wpscan[2048], vuln[2048];

        snprintf(subzy,   sizeof(subzy),   "%s/%s/subzy.txt",   g.dir, entry->d_name);
        snprintf(subjack, sizeof(subjack), "%s/%s/subjack.txt", g.dir, entry->d_name);
        snprintf(nuclei,  sizeof(nuclei),  "%s/%s/nuclei.txt",  g.dir, entry->d_name);
        snprintf(xss,     sizeof(xss),     "%s/%s/xss.txt",     g.dir, entry->d_name);
        snprintf(wpscan,  sizeof(wpscan),  "%s/%s/wpscan.txt",  g.dir, entry->d_name);
        snprintf(vuln,    sizeof(vuln),    "%s/%s/vuln.txt",    g.dir, entry->d_name);

        FILE *out = fopen(vuln, "w");
        if (!out)
            continue;

        int findings = 0;
        char line[4096];

        FILE *fp = fopen(nuclei, "r");
        if (fp) {
            while (fgets(line, sizeof(line), fp)) {
                if (strstr(line, "[critical]") ||
                    strstr(line, "[high]") ||
                    strstr(line, "[medium]") ||
                    strstr(line, "[low]"))
                {
                    fprintf(out, "[NUCLEI] %s", line);
                    findings++;
                }
            }
            fclose(fp);
        }

        fp = fopen(xss, "r");
        if (fp) {
            while (fgets(line, sizeof(line), fp)) {
                if (strlen(line) > 5) {
                    fprintf(out, "[XSS] %s", line);
                    findings++;
                }
            }
            fclose(fp);
        }

        fp = fopen(wpscan, "r");
        if (fp) {
            while (fgets(line, sizeof(line), fp)) {
                if (strstr(line, "[!]") ||
                    strstr(line, "Vulnerable") ||
                    strstr(line, "Confirmed"))
                {
                    fprintf(out, "[WPSCAN] %s", line);
                    findings++;
                }
            }
            fclose(fp);
        }

        fp = fopen(subzy, "r");
        if (fp) {
            while (fgets(line, sizeof(line), fp)) {
                if (strstr(line, entry->d_name) &&
                    strstr(line, "[VULNERABLE]"))
                {
                    fprintf(out, "[TAKEOVER] %s", line);
                    findings++;
                }
            }
            fclose(fp);
        }

        fp = fopen(subjack, "r");
        if (fp) {
            while (fgets(line, sizeof(line), fp)) {
                if (strstr(line, entry->d_name) &&
                    strstr(line, "[VULNERABLE]"))
                {
                    fprintf(out, "[TAKEOVER] %s", line);
                    findings++;
                }
            }
            fclose(fp);
        }

        fclose(out);

        printf("[+] %-35s %3d findings\n", entry->d_name, findings);
    }

    closedir(dir);
    printf("[+] Analysis complete.\n");
}

/* ------------------------------------------------------------------ */
/* run() — the full pipeline                                          */
/* ------------------------------------------------------------------ */

void run(char *url) {
    printf("\n========================================\n");
    printf("  VectorOps — Automated Pentest Pipeline\n");
    printf("  Target : %s\n", g.domain);
    printf("  Output : %s\n", g.dir);
    printf("========================================\n\n");

    if (g.proxy)
        start_proxies();

    if (!g.urlscan)          /* --scan-url: main pre-seeds live.txt */
        subdomain();

    /* Recon pass on the seed target before the fan-out */
    if (g.target[0]) {
        printf("[+] Recon: %s\n", g.target);
        recon(g.target);
    }

    scanning(url);

    /* dedupe the enumeration output before the WP pass reads it */
    char live[1600];
    snprintf(live, sizeof(live), "%s/live.txt", g.dir);
    dedupe_file(live);

    /* ---- Phase A: probe + fingerprint every host (worker pool) ---- */
    {
        DIR *dir = opendir(g.dir);
        if (!dir) {
            perror("opendir");
            if (g.proxy) proxy_shutdown();
            return;
        }

        /* collect all candidate hosts first */
        char **hosts = NULL;
        size_t nhosts = 0, hcap = 0;
        struct dirent *entry;
        while ((entry = readdir(dir))) {
            if (!is_result_dir(entry))
                continue;
            if (nhosts == hcap) {
                hcap = hcap ? hcap * 2 : 64;
                char **nh = realloc(hosts, hcap * sizeof(*hosts));
                if (!nh) break;
                hosts = nh;
            }
            hosts[nhosts] = strdup(entry->d_name);
            if (hosts[nhosts]) nhosts++;
        }
        closedir(dir);

        int ncpu = (int)sysconf(_SC_NPROCESSORS_ONLN);
        if (ncpu < 2)  ncpu = 2;
        if (ncpu > SCAN_POOL_MAX) ncpu = SCAN_POOL_MAX;
        if ((size_t)ncpu > nhosts) ncpu = (int)(nhosts > 0 ? nhosts : 1);

        g_jobs = calloc(nhosts ? nhosts : 1, sizeof(host_job));
        g_job_count = nhosts;
        g_job_next = 0;

        /* probe + fingerprint inside the pool so the 30s curl timeout
         * overlaps instead of serializing */
        pthread_t workers[SCAN_POOL_MAX];
        pthread_mutex_t probe_lock = PTHREAD_MUTEX_INITIALIZER;

        /* producers are the workers themselves: job list = hosts,
         * wordpress detection appended inline */
        for (size_t i = 0; i < nhosts; i++)
            snprintf(g_jobs[i].host, sizeof(g_jobs[i].host), "%s", hosts[i]);

        /* Probe phase: each worker takes hosts and records WP status */
        g_job_next = 0;   /* reuse queue over host list */
        for (int t = 0; t < ncpu; t++)
            pthread_create(&workers[t], NULL, wp_probe_worker, &probe_lock);
        for (int t = 0; t < ncpu; t++)
            pthread_join(workers[t], NULL);

        /* ---- Phase B: scan hosts with worker pool ---- */
        /* compact job list down to wordpress==true */
        size_t wcount = 0;
        for (size_t i = 0; i < nhosts; i++) {
            if (g_jobs[i].wordpress) {
                printf("[+] WordPress detected on %s\n", g_jobs[i].host);
                g_jobs[wcount++] = g_jobs[i];
            }
        }
        g_job_count = wcount;
        g_job_next = 0;

        if (wcount > 0) {
            for (int t = 0; t < ncpu; t++)
                pthread_create(&workers[t], NULL, host_worker, NULL);
            for (int t = 0; t < ncpu; t++)
                pthread_join(workers[t], NULL);
        }

        for (size_t i = 0; i < nhosts; i++) free(hosts[i]);
        free(hosts);

        /* ---- wpscan fan-out over detected hosts ---- */
        for (size_t i = 0; i < wcount; i++) {
            if (g_wp_thread_count >= WP_THREADS_MAX) {
                fprintf(stderr, "[!] thread cap (%d) reached — skipping wpscan on %s\n",
                        WP_THREADS_MAX, g_jobs[i].host);
                continue;
            }
            char *host = strdup(g_jobs[i].host);
            if (!host) continue;
            pthread_mutex_lock(&g_wp_spawn_lock);
            if (pthread_create(&g_wp_threads[g_wp_thread_count], NULL,
                               wpscan_thread, host) == 0) {
                g_wp_thread_count++;
            } else {
                free(host);
            }
            pthread_mutex_unlock(&g_wp_spawn_lock);
        }
        for (int i = 0; i < g_wp_thread_count; i++)
            pthread_join(g_wp_threads[i], NULL);
        g_wp_thread_count = 0;

        free(g_jobs);
        g_jobs = NULL;
        g_job_count = 0;
        g_job_next = 0;
    }

    analyze();

    if (g.deepblue)
        deepblue_run();

    if (g.proxy)
        proxy_shutdown();

    printf("\n========================================\n");
    printf("      Pipeline Complete\n");
    printf("========================================\n");
}