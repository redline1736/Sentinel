#include <errno.h>
#include <sys/stat.h>
#include <ctype.h>
#include <unistd.h>

#include "util/util.h"
#include "prox/prox.h"
#include "scan/scan.h"
#include "ghostquery/xss/xss.h"
#include "glassworm/gw.h"
#include "global.h"

static void print_usage(const char *prog) {
    printf("Usage:\n");
    printf("  %s <outdir> --scan-url  <url>    [flags]\n", prog);
    printf("  %s <outdir> --scan-site <url>    [flags]\n", prog);
    printf("  %s <outdir> --xss-only  <url>    [flags]\n", prog);
    printf("  %s <outdir> -sub        <domain> [flags]\n", prog);
    printf("  %s <outdir> --full-scan <domain> [flags]\n", prog);
    printf("  %s <outdir> --fast-scan <domain> [flags]\n", prog);
    printf("\n");
    printf("  proxy flags (default: direct, no proxy):\n");
    printf("        --tor           route through a pool of local Tor SOCKS5 instances\n");
    printf("        --elite         use live ProxyScrape 'elite' public proxies\n");
    printf("        --proxy <file>  use a custom list of [proto://]host:port proxies\n");
    printf("        --no-proxy      force direct connections (default)\n");
    printf("  other flags:\n");
    printf("        --xss-no        disable XSS scanning\n");
    printf("        --deepblue      run DeepBlue exploit phase after scan\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s output -sub example.com --tor\n", prog);
    printf("  %s output --scan-url https://example.com/login.php?u=1 --tor\n", prog);
    printf("  %s output --xss-only https://example.com/login.php?u=1\n", prog);
}

/* Extract host[:port] from a URL, IPv6-aware.
 * "https://example.com:8443/a?b=1"   -> "example.com:8443"
 * "http://[2001:db8::1]:8080/x"      -> "2001:db8::1:8080"  (see note)
 */
static void host_of_url(const char *url, char *out, size_t outsz) {
    const char *p = strstr(url, "://");
    const char *h = p ? p + 3 : url;
    size_t n;

    if (h[0] == '[') {                      /* IPv6 literal */
        const char *close = strchr(h, ']');
        if (close) {
            h++;                            /* skip '[' */
            n = (size_t)(close - h);
        } else {
            h++;
            n = strlen(h);
        }
    } else {
        /* keep host[:port] together; only cut at '/' */
        const char *slash = strchr(h, '/');
        n = slash ? (size_t)(slash - h) : strlen(h);
    }

    if (n >= outsz) n = outsz - 1;
    memcpy(out, h, n);
    out[n] = '\0';

    for (char *q = out; *q; q++)
        *q = (char)tolower((unsigned char)q[0]);
}

/* Copy src into dst (dstsz incl. NUL). 0 on success, -1 on truncation. */
static int copy_str(char *dst, size_t dstsz, const char *src) {
    size_t n = strlen(src);
    if (n >= dstsz)
        return -1;
    memcpy(dst, src, n + 1);
    return 0;
}

/* Strip trailing slashes (keep plain "/"). */
static void normalize_dir(char *dir) {
    size_t n = strlen(dir);
    while (n > 1 && dir[n - 1] == '/')
        dir[--n] = '\0';
}

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

    if (strcmp(g.dir, ".") != 0 && strcmp(g.dir, "/") != 0) {
        FILE *mirror = fopen("live.txt", "w");
        if (mirror) {
            fprintf(mirror, "%s\n", host);
            fclose(mirror);
        }
    }
}

static int is_url_mode(const char *mode) {
    return (strcmp(mode, "--scan-url")  == 0) ||
           (strcmp(mode, "--scan-site") == 0) ||
           (strcmp(mode, "--xss-only")  == 0);
}

static int is_domain_mode(const char *mode) {
    return (strcmp(mode, "-sub")        == 0) ||
           (strcmp(mode, "--full-scan") == 0) ||
           (strcmp(mode, "--fast-scan") == 0);
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

    /* Universal shape:
     *     sentinel <outdir> <mode> <arg> [flags]
     */
    const char *mode = argv[2];

    if (copy_str(g.dir, sizeof(g.dir), argv[1]) != 0) {
        fprintf(stderr, "[-] outdir path too long (max %zu)\n", sizeof(g.dir) - 1);
        return 1;
    }
    normalize_dir(g.dir);

    const int flag_start = 4;

    if (is_url_mode(mode)) {
        if (copy_str(g.target, sizeof(g.target), argv[3]) != 0) {
            fprintf(stderr, "[-] URL too long (max %zu)\n", sizeof(g.target) - 1);
            return 1;
        }
        host_of_url(g.target, g.domain, sizeof(g.domain));
    }
    else if (is_domain_mode(mode)) {
        if (copy_str(g.domain, sizeof(g.domain), argv[3]) != 0) {
            fprintf(stderr, "[-] domain too long (max %zu)\n", sizeof(g.domain) - 1);
            return 1;
        }
        for (char *q = g.domain; *q; q++)
            *q = (char)tolower((unsigned char)q[0]);
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
            if (copy_str(g.proxy_list, sizeof(g.proxy_list), argv[++i]) != 0) {
                fprintf(stderr, "[-] proxy list path too long\n");
                return 1;
            }
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

    if (strcmp(mode, "-sub") == 0) {
        if (g.proxy) start_proxies();
        subdomain();
        if (g.proxy) proxy_shutdown();
        printf("[+] Subdomain enumeration complete. Results in %s/\n", g.dir);
    }
    else if (strcmp(mode, "--full-scan") == 0) {
        g.sitescan = true;
        g.full = true;
        rc = run(NULL);
    }
    else if (strcmp(mode, "--fast-scan") == 0) {
        g.sitescan = true;
        g.full = false;
        rc = run(NULL);
    }
    else if (strcmp(mode, "--xss-only") == 0) {
        rc = xss_run(g.target, g.dir, g.dir);
    }
    else if (strcmp(mode, "--scan-url") == 0) {
        g.urlscan = true;
        g.full = true;
        write_live(g.domain);
        rc = run(g.target);
    }
    else if (strcmp(mode, "--scan-site") == 0) {
        g.sitescan = true;
        g.urlscan = true;
        g.full = true;
        write_live(g.domain);
        rc = run(NULL);
    }

    proxy_shutdown();
    curl_http_cleanup();
    return rc;
}