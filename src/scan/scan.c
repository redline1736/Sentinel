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
// Global includes
#include "../util/util.h"
#include "../global.h"

// Extra includes for scanning
#include "../prox/prox.h"
#include "../http/http.h"
#include "../deepblue/deepblue.h"

// Hacking Related Includes
#include "../recon/info.h"
#include "../ghostquery/gq.h"
#include "../atlas/sub.h"
#include "../headers/hdr.h"
#include "../glassworm/gw.h"
#include "../ghostquery/xss/xss.h"

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
        if (!lines[n]) {                 /* FIXED: was leaving a hole -> NULL deref in qsort */
            fclose(fp);
            for (size_t i = 0; i < n; i++) free(lines[i]);
            free(lines);
            return;
        }
        n++;
    }
    fclose(fp);

    if (n > 1)                           /* FIXED: qsort(NULL, 0, ...) is UB */
        qsort(lines, n, sizeof(*lines), cmp_str);

    fp = fopen(path, "w");
    if (!fp) {
        fprintf(stderr, "[!] Cannot rewrite %s for dedupe\n", path);
        for (size_t i = 0; i < n; i++) free(lines[i]);
        free(lines);
        return;
    }

    for (size_t i = 0; i < n; i++) {
        if (i == 0 || strcmp(lines[i], lines[i - 1]) != 0)
            fprintf(fp, "%s\n", lines[i]);
        free(lines[i]);
    }
    fclose(fp);
    free(lines);
}

static void host_of_url(const char *url, char *out, size_t outsz) {
    const char *p = strstr(url, "://");
    const char *h = p ? p + 3 : url;
    const char *slash = strchr(h, '/');
    const char *colon = strchr(h, ':');
    size_t n;

    if (colon && (!slash || colon < slash))
        n = (size_t)(colon - h);
    else if (slash)
        n = (size_t)(slash - h);
    else
        n = strlen(h);

    if (n >= outsz) n = outsz - 1;
    memcpy(out, h, n);
    out[n] = '\0';

    for (char *q = out; *q; q++)
        *q = (char)tolower((unsigned char)*q);
}

/* ---------- directory helpers (DT_UNKNOWN-safe: XFS/FUSE/NFS) ---------- */

static int is_dir_entry(const char *parent, const char *name) {
    struct stat st;
    char path[2048];
    if (snprintf(path, sizeof(path), "%s/%s", parent, name) >= (int)sizeof(path))
        return 0;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

static int is_result_dir(const struct dirent *entry) {
    if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
        return 0;
    if (entry->d_type == DT_DIR)
        return 1;
    if (entry->d_type == DT_UNKNOWN)
        return is_dir_entry(g.dir, entry->d_name);
    return 0;
}

static void ensure_dir(const char *path) {
    if (mkdir(path, 0755) != 0 && errno != EEXIST)
        fprintf(stderr, "[-] mkdir %s: %s\n", path, strerror(errno));
}

/* ---------- wpscan worker ---------- */

static void *wpscan_thread(void *arg) {
    char *host = arg;

    printf("[+] Running wpscan on %s\n", host);

    char outfile[2048];
    snprintf(outfile, sizeof(outfile), "%s/%s/wpscan.txt", g.dir, host);

    char url[2048];
    snprintf(url, sizeof(url), "https://%s", host);

    char *wpscan_args[] = {"wpscan", "--url", url, "--output", outfile, NULL};
    int rc = run_tool(wpscan_args);
    if (rc != 0) printf("[!] wpscan failed on %s with code %d\n", host, rc);

    free(host);
    return NULL;
}

/* ---------- URL/host helpers ---------- */

/* Pull the authority out of a URL or bare host:
 *   https://user:pw@Example.COM:8443/path -> example.com
 * Handles IPv6 literals: https://[::1]:8080/ -> ::1
 * Writes "" when nothing usable is found. */
static void url_to_host(const char *url, char *out, size_t outsz)
{
    const char *p = strstr(url, "://");
    p = p ? p + 3 : url;

    size_t n = strcspn(p, "/?#");
    if (n == 0 || n >= outsz) {
        out[0] = '\0';
        return;
    }
    memcpy(out, p, n);
    out[n] = '\0';

    /* drop userinfo */
    char *at = strrchr(out, '@');
    if (at)
        memmove(out, at + 1, strlen(at + 1) + 1);

    /* drop :port, but only outside IPv6 brackets */
    char *colon  = strrchr(out, ':');
    char *bracket = strrchr(out, ']');
    if (colon && (!bracket || colon > bracket))
        *colon = '\0';

    /* unwrap [::1] -> ::1 so it is safe as a directory name */
    if (out[0] == '[') {
        char *rb = strchr(out, ']');
        if (rb) {
            size_t l = (size_t)(rb - out) - 1;
            memmove(out, out + 1, l);
            out[l] = '\0';
        }
    }

    for (char *q = out; *q; q++)
        *q = (char)tolower((unsigned char)*q);
}

/* ---------- per-host scan ---------- */

static void scan_one_host(const char *base_url, const char *hostdir)
{
    printf("[*] scanning %s\n", base_url);

    nuclei_run(base_url, hostdir);
    sql_run(base_url, hostdir);
    openredirect_run(base_url, hostdir);
    header(base_url, hostdir);
}

/* ---------- live.txt driver ---------- */

void scanning(char *target_url)
{
    char live[1600];
    snprintf(live, sizeof(live), "%s/live.txt", g.dir);

    FILE *fp = fopen(live, "r");
    if (!fp) {
        fprintf(stderr, "[-] scanning: cannot open %s: %s\n",
                live, strerror(errno));
        return;
    }

    char line[4096];

    while (fgets(line, sizeof(line), fp)) {
        size_t l = strlen(line);
        while (l && (line[l - 1] == '\n' || line[l - 1] == '\r'))
            line[--l] = '\0';
        if (l == 0)
            continue;

        char host[512];
        url_to_host(line, host, sizeof(host));
        if (!host[0])
            continue;

        char hostdir[1024];
        snprintf(hostdir, sizeof(hostdir), "%s/%s", g.dir, host);
        if (mkdir(hostdir, 0755) != 0 && errno != EEXIST) {
            fprintf(stderr, "[!] mkdir %s: %s\n", hostdir, strerror(errno));
            continue;
        }

        /* probe https, fall back to http */
        char base_url[2048];
        snprintf(base_url, sizeof(base_url), "https://%s", host);

        request root = {0};
        if (!http_send_get(&root, base_url)) {
            snprintf(base_url, sizeof(base_url), "http://%s", host);
            if (!http_send_get(&root, base_url)) {
                request_free(&root);   /* dead host: never feed a NULL body onward */
                continue;
            }
        }

        int is_api = check_api(&root, host, g.domain);
        request_free(&root);          /* freed on both paths — no leak */

        scan_one_host(base_url, hostdir);

        if (is_api == 1) {
            /* NOTE: reconstructed branch — restore your original action
             * (endpoint dump / report entry) here. */
            char apifile[1200];
            snprintf(apifile, sizeof(apifile), "%s/api.txt", hostdir);
            FILE *af = fopen(apifile, "a");
            if (af) {
                fprintf(af, "%s\n", base_url);
                fclose(af);
            }
            printf("[+] API endpoint: %s\n", base_url);
        }
    }

    fclose(fp);
    (void)target_url;   /* driver reads live.txt; keep arg for ABI/header compat */
}
/* --------------------------------------------------------------------------
 * analyze() — merge per-host tool outputs into vuln.txt
 * ------------------------------------------------------------------------ */

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

        char subzy[2048];
        char subjack[2048];
        char nuclei[2048];
        char xss[2048];
        char wpscan[2048];
        char vuln[2048];

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
        int takeover_found = 0;   /* FIXED: dedupe subzy vs subjack confirmation */

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
                    takeover_found = 1;
                }
            }
            fclose(fp);
        }

        /* only run subjack pass if subzy found nothing for this host,
         * otherwise the same takeover is reported twice */
        if (!takeover_found) {
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
        }

        fclose(out);

        printf("[+] %-35s %3d findings\n", entry->d_name, findings);
    }

    closedir(dir);
    printf("[+] Analysis complete.\n");
}

/* --------------------------------------------------------------------------
 * run() — the full pipeline
 * ------------------------------------------------------------------------ */

int run(char *url) {   /* FIXED: returns int so main() can propagate exit code */
    printf("\n========================================\n");
    printf("  VectorOps — Automated Pentest Pipeline\n");
    printf("  Target : %s\n", g.domain);
    printf("  Output : %s\n", g.dir);
    printf("========================================\n\n");

    if (g.proxy)
        start_proxies();

    if (!g.urlscan)          /* --scan-url/--scan-site: main() pre-seeds live.txt */
        subdomain();

    scanning(url);

    char live[1600];
    snprintf(live, sizeof(live), "%s/live.txt", g.dir);
    struct stat lst;
    if (stat(live, &lst) == 0)
        dedupe_file(live);

    int rc = 0;

    pthread_t threads[256];
    int thread_count = 0;

    DIR *dir = opendir(g.dir);
    if (!dir) {
        fprintf(stderr, "[-] run: opendir %s failed: %s\n", g.dir, strerror(errno));
        rc = -1;
        goto out;
    }

    struct dirent *entry;

    while ((entry = readdir(dir))) {
        if (!is_result_dir(entry))
            continue;


        char target[512];
        snprintf(target, sizeof(target), "https://%s", entry->d_name);
        request r = {0};
        if (!http_send_get(&r, target)) {
            snprintf(target, sizeof(target), "http://%s", entry->d_name);
            if (!http_send_get(&r, target)) {
                free(r.body);
                r.body = NULL;
                continue;
            }
        }

        bool wordpress = false;
        if (r.body) {
            if (strstr(r.body, "wp-content/") ||
                strstr(r.body, "/wp-json") ||
                strstr(r.body, "Generator: WordPress"))
                wordpress = true;

            free(r.body);        /* ownership: caller frees, even on failure */
            r.body = NULL;
            r.body_len = 0;
        }

        if (!wordpress)
            continue;

        printf("[+] WordPress detected on %s\n", entry->d_name);

        char *host = strdup(entry->d_name);
        if (!host)
            continue;

        if (thread_count < 256) {
            if (pthread_create(&threads[thread_count], NULL,
                               wpscan_thread, host) == 0) {
                thread_count++;
            } else {
                free(host);
            }
        } else {
            fprintf(stderr, "[!] thread cap (256) reached — "
                            "skipping wpscan on %s\n", entry->d_name);
            free(host);
        }
    }

    closedir(dir);

    for (int i = 0; i < thread_count; i++)
        pthread_join(threads[i], NULL);

    analyze();

    if (g.deepblue)
        deepblue_run();

out:
    /* NOTE: proxy shutdown lives in main() now — single shutdown point */

    printf("\n========================================\n");
    printf("      Pipeline Complete\n");
    printf("========================================\n");
    return rc;
}