#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "util/util.h"
#include "prox/prox.h"
#include "scan/scan.h"
#include "ghostquery/xss/xss.h"
#include "glassworm/gw.h"
#include "global.h"

#include "gui/ui.h"

/* ---------------- usage ---------------- */

static void print_usage(const char *prog) {
    printf("Usage:\n");
    printf("  %s <outdir> --scan-url  <url>    [flags]\n", prog);
    printf("  %s <outdir> --scan-site <url>    [flags]\n", prog);
    printf("  %s <outdir> --xss-only  <url>    [flags]\n", prog);
    printf("  %s <outdir> -sub        <domain> [flags]\n", prog);
    printf("  %s <outdir> --full-scan <domain> [flags]\n", prog);
    printf("  %s <outdir> --fast-scan <domain> [flags]\n", prog);
    printf("  %s <outdir> --url       <target_url>\n", prog);
    printf("  %s <outdir> --gobuster  <gobuster_dir>\n", prog);
    printf("\n");
    printf("  With a full <outdir> <mode> <arg> invocation the built-in SDL3\n");
    printf("  GUI starts, prefilled with outdir, target and scan type, and\n");
    printf("  auto-starts the scan. The window stays open after each scan.\n");
    printf("  The scan itself runs as a child process (sentinel --no-ui).\n");
    printf("  --no-ui must come after the mode argument (it is matched in\n");
    printf("  argv[4..] only).\n");
    printf("\n");
    printf("  proxy flags (default: direct, no proxy):\n");
    printf("        --tor           route through a pool of local Tor SOCKS5 instances\n");
    printf("        --elite         use live ProxyScrape 'elite' public proxies\n");
    printf("        --proxy <file>  use a custom list of [proto://]host:port proxies\n");
    printf("        --no-proxy      force direct connections (default)\n");
    printf("  other flags:\n");
    printf("        --xss-no        disable XSS scanning\n");
    printf("        --deepblue      run DeepBlue exploit phase after scan\n");
    printf("        --no-ui         headless: do not open the GUI, just scan and exit\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s output -sub example.com --tor\n", prog);
    printf("  %s output --scan-url https://example.com/login.php?u=1 --tor\n", prog);
    printf("  %s output --xss-only https://example.com/login.php?u=1 --no-ui\n", prog);
    printf("  %s output --url https://example.com/graphql\n", prog);
    printf("  %s output --gobuster ~/gobuster/\n", prog);
}

/* ---------------- helpers ---------------- */

static int copy_str(char *dst, size_t dstsz, const char *src) {
    size_t n = strlen(src);
    if (n >= dstsz) return -1;
    memcpy(dst, src, n + 1);
    return 0;
}

static void normalize_dir(char *dir, size_t sz) {
    size_t n = strlen(dir);
    while (n > 1 && dir[n - 1] == '/') dir[--n] = '\0';
    (void)sz;
}

/* Extract the bare host from a URL. Drops scheme, userinfo, port,
 * path, query, and fragment. Handles bracketed IPv6 hosts. */
static void host_of_url(const char *url, char *out, size_t outsz) {
    if (!url || !out || outsz == 0) return;
    out[0] = '\0';

    const char *p = url;

    /* skip scheme:// */
    const char *sep = strstr(p, "://");
    if (sep) p = sep + 3;

    /* end of authority component */
    size_t n = strcspn(p, "/?#");

    /* strip userinfo@ */
    const char *at = memchr(p, '@', n);
    if (at) {
        n -= (size_t)(at + 1 - p);
        p  = at + 1;
    }

    /* strip port (respecting [::1] brackets) */
    if (n > 0 && p[0] == '[') {
        const char *rb = memchr(p, ']', n);
        if (rb) {
            size_t inner = (size_t)(rb - p + 1);
            const char *c = memchr(p + inner, ':', n - inner);
            if (c) n = (size_t)(c - p);
        }
    } else {
        const char *colon = memchr(p, ':', n);
        if (colon) n = (size_t)(colon - p);
    }

    /* strip trailing FQDN dot */
    if (n > 0 && p[n - 1] == '.') n--;

    if (n >= outsz) n = outsz - 1;
    memcpy(out, p, n);
    out[n] = '\0';
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

static int is_known_mode(const char *mode) {
    return is_url_mode(mode) || is_domain_mode(mode) ||
           (strcmp(mode, "--url") == 0) ||
           (strcmp(mode, "--gobuster") == 0);
}

/* M1 (documented, behavior kept): --no-ui is matched in argv[4..] only. */
static int wants_no_ui(int argc, char *argv[]) {
    for (int i = 4; i < argc; i++)
        if (strcmp(argv[i], "--no-ui") == 0)
            return 1;
    return 0;
}

/* ---------------- headless scan (scan-and-exit path) ---------------- */

static int run_headless(int argc, char *argv[], const char *mode) {
    /* --- defaults --- */
    g.xss          = true;
    g.deepblue     = false;
    g.full         = true;
    g.urlscan      = false;
    g.proxy        = false;
    g.tor          = false;
    g.sitescan     = false;
    g.proxy_mode   = PROXY_NONE;
    g.proxy_list[0]= '\0';
    g.target[0]    = '\0';
    g.domain[0]    = '\0';

    if (copy_str(g.dir, sizeof(g.dir), argv[1]) != 0) {
        fprintf(stderr, "[-] outdir path too long (max %zu)\n", sizeof(g.dir) - 1);
        return 1;
    }
    normalize_dir(g.dir, sizeof(g.dir));

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
    else if (strcmp(mode, "--url") == 0) {
        if (copy_str(g.target, sizeof(g.target), argv[3]) != 0) {
            fprintf(stderr, "[-] URL too long (max %zu)\n", sizeof(g.target) - 1);
            return 1;
        }
        host_of_url(g.target, g.domain, sizeof(g.domain));
    }
    else if (strcmp(mode, "--gobuster") == 0) {
        if (copy_str(g.target, sizeof(g.target), argv[3]) != 0) {
            fprintf(stderr, "[-] gobuster dir too long (max %zu)\n", sizeof(g.target) - 1);
            return 1;
        }
    }
    else {
        fprintf(stderr, "[-] Unknown mode: %s\n", mode);
        print_usage(argv[0]);
        return 1;
    }

    for (int i = 4; i < argc; i++) {
        if (strcmp(argv[i], "--xss-no") == 0) {
            g.xss = false;
        } else if (strcmp(argv[i], "--deepblue") == 0) {
            g.deepblue = true;
        } else if (strcmp(argv[i], "--no-ui") == 0) {
            /* handled by main() */
        } else if (strcmp(argv[i], "--tor") == 0) {
            g.proxy_mode = PROXY_TOR;
            g.proxy = true;
            g.tor   = true;
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
            g.proxy_mode   = PROXY_NONE;
            g.proxy        = false;
            g.tor          = false;
            g.proxy_list[0]= '\0';
        } else if (strcmp(argv[i], "--fast-scan") == 0) {
            g.sitescan = true;
            g.full     = false;
        } else {
            fprintf(stderr, "[-] Unknown flag: %s\n", argv[i]);
            return 1;
        }
    }

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
        g.full     = true;
        rc = run(NULL);
    }
    else if (strcmp(mode, "--xss-only") == 0) {
        rc = xss_run(g.target, g.dir, g.dir);
    }
    else if (strcmp(mode, "--scan-url") == 0 || strcmp(mode, "--url") == 0) {
        /* M3: --url is an alias of --scan-url (identical behavior) */
        g.urlscan = true;
        g.full    = true;
        write_live(g.domain);
        rc = run(g.target);
    }
    else if (strcmp(mode, "--scan-site") == 0) {
        g.sitescan = true;
        g.urlscan  = true;
        g.full     = true;
        write_live(g.domain);
        rc = run(NULL);
    }
    else if (strcmp(mode, "--gobuster") == 0) {
        /* explicit so the accepted mode can't silently do nothing;
         * wire this to the gobuster-ingest entry in scan.c when built */
        fprintf(stderr, "[-] --gobuster mode is not wired to the scan engine yet\n");
        rc = 1;
    }

    proxy_shutdown();
    curl_http_cleanup();
    return rc;
}

/* ---------------- main ---------------- */

int main(int argc, char *argv[]) {
    /* M4: line-buffer our own output so the GUI pipe gets logs in real
     * time. Note this only affects THIS process; external tools we spawn
     * (gobuster, httpx, ...) use their own buffering and may arrive in
     * chunks. That is a property of the child tools, not fixable here. */
    setvbuf(stdout, NULL, _IOLBF, 0);
    setvbuf(stderr, NULL, _IOLBF, 0);

    /* headless: --no-ui at argv[4..] -> scan and exit */
    if (argc >= 4 && wants_no_ui(argc, argv))
        return run_headless(argc, argv, argv[2]);

    /* validate shape + mode before we open a window */
    if (argc != 1 && argc < 4) {
        print_usage(argv[0]);
        return 1;
    }
    if (argc >= 4 && !is_known_mode(argv[2])) {
        fprintf(stderr, "[-] Unknown mode: %s\n", argv[2]);
        print_usage(argv[0]);
        return 1;
    }

    /* UI mode: SDL3 window runs in this process; each scan is a
     * forked `sentinel <outdir> <mode> <target> [flags] --no-ui`. */
    return ui_run(argc, argv);
}