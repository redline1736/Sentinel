#include <errno.h>
#include <sys/stat.h>
#include <ctype.h>
#include <unistd.h>
#include <pthread.h>
#include <stdatomic.h>

#include "util/util.h"
#include "prox/prox.h"
#include "scan/scan.h"
#include "ghostquery/xss/xss.h"
#include "glassworm/gw.h"
#include "global.h"

/* UI thread stop signal (set by main after the pipeline finishes) */
atomic_bool g_stop = false;

static void print_usage(const char *prog) {
    printf("Usage:\n");
    printf("  %s <outdir> --scan-url  <url>    [flags]\n", prog);
    printf("  %s <outdir> --scan-site <url>    [flags]\n", prog);
    printf("  %s <outdir> --xss-only  <url>    [flags]\n", prog);
    printf("  %s <outdir> -sub        <domain> [flags]\n", prog);
    printf("  %s <outdir> --full-scan <domain> [flags]\n", prog);
    printf("  %s <outdir> --fast-scan <domain> [flags]\n", prog);
    printf("  modes:\n");
    printf("    <outdir> --url <target_url>        scan a single GraphQL endpoint (output written to ./)\n");
    printf("    <outdir> --gobuster <gobuster_dir>  analyze gobuster.txt already in <gobuster_dir>\n");
    printf("Examples:\n");
    printf("  %s <outdir> --url https://example.com/graphql\n", prog);
    printf("  %s <outdir> --gobuster ~/gobuster/\n", prog);
    printf("\n");
    printf("  proxy flags (default: direct, no proxy):\n");
    printf("        --tor           route through a pool of local Tor SOCKS5 instances\n");
    printf("        --elite         use live ProxyScrape 'elite' public proxies\n");
    printf("        --proxy <file>  use a custom list of [proto://]host:port proxies\n");
    printf("        --no-proxy      force direct connections (default)\n");
    printf("  other flags:\n");
    printf("        --xss-no        disable XSS scanning\n");
    printf("        --deepblue      run deepblue exploit mapping after the scan\n");
    printf("\n");
    printf("  report: results are written to <outdir>; vuln.txt per host,\n");
    printf("  live.txt for live subdomains.\n");
}

/* PLACEHOLDER — I could not fetch the full ui() body from the web.
 * Preserve your existing implementation, but replace its loop
 * condition with:  while (!atomic_load(&g_stop))  ...
 * so main() can join it instead of leaking the thread. Signature
 * stays  void *ui(void *arg)  . */
static void *ui(void *arg);

/* PLACEHOLDER — preserve your existing host_of_url() implementation
 * verbatim (URL parse -> lowercase host into out buffer). Signature:
 * static void host_of_url(const char *url, char *out, size_t outsz); */
static void host_of_url(const char *url, char *out, size_t outsz);

static void write_live(const char *host) {
    char path[2048];
    snprintf(path, sizeof(path), "%s/live.txt", g.dir);

    FILE *fp = fopen(path, "w");
    if (!fp) {
        fprintf(stderr, "[-] cannot write %s: %s\n", path, strerror(errno));
        return;
    }
    fprintf(fp, "%s\n", host);
    fclose(fp);
    printf("[+] live.txt seeded with %s\n", host);

    if (strcmp(g.dir, ".") != 0 && strcmp(g.dir, "./") != 0) {
        FILE *mirror = fopen("live.txt", "w");
        if (mirror) {
            fprintf(mirror, "%s\n", host);
            fclose(mirror);
        }
    }
}

/* Returns 1 if the token is a URL-bearing mode. */
static int is_url_mode(const char *mode) {
    return (strcmp(mode, "--scan-url")  == 0) ||
           (strcmp(mode, "--scan-site") == 0) ||
           (strcmp(mode, "--xss-only")  == 0);
}

/* Returns 1 if the token is a domain-bearing mode. */
static int is_domain_mode(const char *mode) {
    return (strcmp(mode, "-sub")        == 0) ||
           (strcmp(mode, "--full-scan") == 0) ||
           (strcmp(mode, "--fast-scan") == 0);
}

/* safe bounded copy with truncation check */
static bool copy_arg(char *dst, size_t dstsz, const char *src, const char *what) {
    if (strlen(src) >= dstsz) {
        fprintf(stderr, "[-] %s too long (max %zu): %s\n", what, dstsz - 1, src);
        return false;
    }
    strcpy(dst, src);
    return true;
}

int main(int argc, char *argv[]) {

    if (argc < 4) {
        print_usage(argv[0]);
        return 1;
    }

    /* --- defaults --- */
    g.xss = true;
    g.deepblue = false;
    g.full = false;
    g.urlscan = false;
    g.proxy = false;
    g.tor = false;
    g.sitescan = false;
    g.proxy_mode = PROXY_NONE;
    g.proxy_list[0] = '\0';
    g.target[0] = '\0';
    g.domain[0] = '\0';

    /* -------------------------------------------------------------------
     * Universal shape:
     *
     *     sentinel <outdir> <mode> <arg> [flags]
     *
     *   <outdir>  = argv[1]   (always)
     *   <mode>    = argv[2]
     *   <arg>     = argv[3]   url (url modes) OR domain (domain modes)
     *   flags     = argv[4..]
     * ----------------------------------------------------------------- */

    const char *mode = argv[2];

    if (!copy_arg(g.dir, sizeof(g.dir), argv[1], "outdir"))
        return 1;

    const int flag_start = 4;

    if (is_url_mode(mode)) {
        if (!copy_arg(g.target, sizeof(g.target), argv[3], "target url"))
            return 1;
        /* domain is derived from the URL */
        host_of_url(g.target, g.domain, sizeof(g.domain));
        if (!g.domain[0]) {
            fprintf(stderr, "[-] cannot derive host from URL: %s\n", g.target);
            return 1;
        }
    }
    else if (is_domain_mode(mode)) {
        if (!copy_arg(g.domain, sizeof(g.domain), argv[3], "domain"))
            return 1;
    }
    else {
        fprintf(stderr, "[-] Unknown mode: %s\n", mode);
        print_usage(argv[0]);
        return 1;
    }

    /* --- optional flags --- */
    for (int i = flag_start; i < argc; i++) {
        if (strcmp(argv[i], "--xss-no") == 0) {
            g.xss = false;
        } else if (strcmp(argv[i], "--deepblue") == 0) {
            g.deepblue = true;
        } else if (strcmp(argv[i], "--tor") == 0) {
            g.proxy_mode = PROXY_TOR;
            g.proxy = true;
            g.tor = true;
        } else if (strcmp(argv[i], "--elite") == 0) {
            g.proxy_mode = PROXY_ELITE;
            g.proxy = true;
        } else if (strcmp(argv[i], "--proxy") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "[-] --proxy requires a list file\n");
                return 1;
            }
            if (!copy_arg(g.proxy_list, sizeof(g.proxy_list), argv[++i], "proxy list"))
                return 1;
            g.proxy_mode = PROXY_CUSTOM;
            g.proxy = true;
        } else if (strcmp(argv[i], "--no-proxy") == 0) {
            g.proxy_mode = PROXY_NONE;
            g.proxy = false;
            g.tor = false;
            g.proxy_list[0] = '\0';
        } else {
            fprintf(stderr, "[-] Unknown flag: %s\n", argv[i]);
            return 1;
        }
    }

    /* --- safe mkdir --- */
    if (mkdir(g.dir, 0755) != 0 && errno != EEXIST) {
        perror("mkdir");
        return 1;
    }

    curl_http_init();

    printf("[+] Sentinel starting\n");
    if (g.domain[0]) printf("[+] Target: %s\n", g.domain);
    printf("[+] Output: %s/\n", g.dir);
    if (g.target[0]) printf("[+] URL:    %s\n", g.target);

    int rc = 0;

    pthread_t ui_thread;
    if (pthread_create(&ui_thread, NULL, ui, NULL) != 0) {
        fprintf(stderr, "[-] pthread_create(ui) failed: %s\n", strerror(errno));
        curl_http_cleanup();
        return 1;
    }

    if (strcmp(mode, "-sub") == 0) {
        if (g.proxy) {
            if (start_proxies(), proxy_init(g.proxy_mode,
                    g.proxy_mode == PROXY_CUSTOM ? g.proxy_list : NULL) != 0) {
                fprintf(stderr, "[-] proxy pool init failed\n");
                rc = 2;
                goto done;
            }
        }
        subdomain();
        printf("[+] Subdomain enumeration complete. Results in %s/\n", g.dir);
    }
    else if (strcmp(mode, "--full-scan") == 0) {
        g.sitescan = true;
        g.full = true;
        run(NULL);
    }
    else if (strcmp(mode, "--fast-scan") == 0) {
        g.sitescan = true;
        g.full = false;
        run(NULL);
    }
    else if (strcmp(mode, "--xss-only") == 0) {
        xss_run(g.target, g.dir, g.dir);
    }
    else if (strcmp(mode, "--scan-url") == 0) {
        g.urlscan = true;
        g.full = true;
        write_live(g.domain);
        run(g.target);
    }
    else if (strcmp(mode, "--scan-site") == 0) {
        g.sitescan = true;
        g.urlscan = true;
        g.full = true;
        write_live(g.domain);
        run(NULL);
    }

done:
    /* run() shuts the proxy pool down itself in scan modes; only clean
     * up here for modes that bypass run() (and idempotent afterwards). */
    if (strcmp(mode, "-sub") == 0 && g.proxy)
        proxy_shutdown();

    atomic_store(&g_stop, true);
    pthread_join(ui_thread, NULL);

    curl_http_cleanup();
    return rc;
}