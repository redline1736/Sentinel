#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>3

#include <errno.h>
#include <sys/stat.h>
#include <ctype.h>

#include "glassworm/gw.h"
#include "util/util.h"
#include "prox/prox.h"
#include "scan/scan.h"
#include "ghostquery/gq.h"
#include "global.h"

static void print_usage(const char *prog) {
    printf("Usage: %s <domain> <output_dir> <mode> [flags]\n", prog);
    printf("  mode: -sub            subdomain enumeration + takeover checks\n");
    printf("        --fast-scan     full scan pipeline on interesting hosts\n");
    printf("        --full-scan     full scan on ALL hosts\n");
    printf("        --scan-url <url>  single-URL scan (full pipeline, no subdomain enum)\n");
    printf("        --scan-site <url>  single-site scan (gobuster + per-URL deep pass)\n");
    printf("  proxy flags (default: direct, no proxy):\n");
    printf("        --tor           route through a pool of local Tor SOCKS5 instances\n");
    printf("        --elite         use live ProxyScrape 'elite' public proxies (WARNING: untrusted)\n");
    printf("        --proxy <file>  use a custom list of [proto://]host:port proxies (WARNING: untrusted)\n");
    printf("        --no-proxy      force direct connections (default)\n");
    printf("  other flags:\n");
    printf("        --xss-no        disable XSS scanning\n");
    printf("        --deepblue      run DeepBlue exploit phase after scan\n\n");
    printf("Examples:\n");
    printf("  %s example.com output -sub --tor\n", prog);
    printf("  %s example.com output --full-scan --proxy mylist.txt\n", prog);
    printf("  %s example.com output --scan-url https://example.com/login.php?u=1 --tor\n", prog);
}

/* Extract the bare host from a URL: "https://example.com:8443/a?b=1" -> "example.com" */
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
    if (n >= outsz)
        n = outsz - 1;
    memcpy(out, h, n);
    out[n] = '\0';

    for (char *q = out; *q; q++)
        *q = (char)tolower((unsigned char)*q);
}

/* Seed the host list that scanning() consumes: the URL's host, one per line. */
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

    /* insurance: if scanning() opens live.txt relative to the CWD instead
     * of g.dir, mirror it so the single host is always picked up. */
    if (strcmp(g.dir, ".") != 0 && strcmp(g.dir, "./") != 0) {
        FILE *mirror = fopen("live.txt", "w");
        if (mirror) {
            fprintf(mirror, "%s\n", host);
            fclose(mirror);
        }
    }
}

int main(int argc, char *argv[]) {
    
    if (argc < 4) {
        print_usage(argv[0]);
        return 1;
    }

    /* --- bounds-checked copies (no overflow) --- */
    strncpy(g.domain, argv[1], sizeof(g.domain) - 1);
    g.domain[sizeof(g.domain) - 1] = '\0';

    strncpy(g.dir, argv[2], sizeof(g.dir) - 1);
    g.dir[sizeof(g.dir) - 1] = '\0';

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

    /* --scan-url / --scan-site put the URL at argv[4]; flags start at argv[5] */
    int flag_start = 4;
    if (strcmp(argv[3], "--scan-url") == 0) {
        if (argc < 5) {
            fprintf(stderr, "[-] --scan-url requires a URL argument\n");
            return 1;
        }
        flag_start = 5;
    }
    else if (strcmp(argv[3], "--scan-site") == 0) {
        if (argc < 5) {
            fprintf(stderr, "[-] --scan-site requires a URL argument\n");
            return 1;
        }
        flag_start = 5;
    }
    else if (strcmp(argv[3], "test-new-feature") == 0) {
        if (argc < 5) {
            fprintf(stderr, "[-] test-new-feature requires a URL argument\n");
            return 1;
        }
        flag_start = 5;
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
            strncpy(g.proxy_list, argv[++i], sizeof(g.proxy_list) - 1);
            g.proxy_list[sizeof(g.proxy_list) - 1] = '\0';
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

    /* --- safe mkdir (no system() / no shell injection) --- */
    if (mkdir(g.dir, 0755) != 0 && errno != EEXIST) {
        perror("mkdir");
        return 1;
    }

    curl_http_init();   /* libcurl global init ONCE */

    printf("[+] Sentinel starting\n");
    printf("[+] Target: %s\n", g.domain);
    printf("[+] Output: %s/\n", g.dir);

    int rc = 0;
    if (strcmp(argv[3], "-sub") == 0) {
        if (g.proxy)
            start_proxies();
        subdomain();
        if (g.proxy)
            proxy_shutdown();
        printf("[+] Subdomain enumeration complete. Results in %s/\n", g.dir);
    }
    else if (strcmp(argv[3], "--full-scan") == 0) {
        g.sitescan = true;
        g.full = true;
        run(NULL);
    }
    else if (strcmp(argv[3], "--fast-scan") == 0) {
        g.sitescan = true;
        g.full = false;
        run(NULL);
    }
    else if (strcmp(argv[3], "test-new-feature") == 0) {
        /* FIX: xss_run signature is (url, path, report_dir) */
        xss_run(argv[4], argv[2], argv[2]);
    }
    else if (strcmp(argv[3], "--scan-url") == 0) {
        g.urlscan = true;
        g.full = true;

        char host[G_DOMAIN_MAX];
        host_of_url(argv[4], host, sizeof(host));

        /* pipeline + per-host output dirs key off g.domain / live.txt */
        strncpy(g.domain, host, sizeof(g.domain) - 1);
        g.domain[sizeof(g.domain) - 1] = '\0';

        write_live(host);

        run(argv[4]);                      /* same pipeline as --full-scan, minus subdomain */
    }
    else if (strcmp(argv[3], "--scan-site") == 0) {
        g.sitescan = true;
        g.urlscan = true;
        g.full = true;

        char host[G_DOMAIN_MAX];
        host_of_url(argv[4], host, sizeof(host));

        /* pipeline + per-host output dirs key off g.domain / live.txt */
        strncpy(g.domain, host, sizeof(g.domain) - 1);
        g.domain[sizeof(g.domain) - 1] = '\0';

        write_live(host);

        run(NULL);                      /* same pipeline as --full-scan, minus subdomain */
    } else if (strcmp(argv[3], "--graphql-scan") == 0){
        
    }
    else {
        fprintf(stderr, "[-] Unknown mode: %s\n", argv[3]);
        print_usage(argv[0]);
        rc = 1;
    }

    proxy_shutdown();      /* idempotent; reaps Tor children if needed */
    curl_http_cleanup();
    return rc;
}