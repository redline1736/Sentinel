#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <ctype.h>
#include <unistd.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "util/util.h"
#include "prox/prox.h"
#include "scan/scan.h"
#include "ghostquery/xss/xss.h"
#include "glassworm/gw.h"
#include "global.h"

/* ---------------- viewer (UI) ---------------- */

static pid_t g_viewer_pid = -1;

static void ui_reap(void) {
    if (g_viewer_pid > 0) {
        /* give it a chance to exit cleanly, then hard-kill */
        kill(g_viewer_pid, SIGTERM);
        for (int i = 0; i < 20; i++) {
            if (waitpid(g_viewer_pid, NULL, WNOHANG) == g_viewer_pid) {
                g_viewer_pid = -1;
                return;
            }
            usleep(50000); /* 50ms x 20 = 1s grace period */
        }
        kill(g_viewer_pid, SIGKILL);
        waitpid(g_viewer_pid, NULL, 0);
        g_viewer_pid = -1;
    }
}

static void *ui(void *arg) {
    (void)arg;

    pid_t pid = fork();
    if (pid == 0) {
        /* child: detach from the scanner's terminal so the viewer
         * cannot steal stdin/stdout or fight over the tty */
        setsid();
        int devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            dup2(devnull, STDIN_FILENO);
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            if (devnull > STDERR_FILENO)
                close(devnull);
        }

        execlp("python3", "python3",
               "/usr/share/sentinel/view/view.py", (char *)NULL);

        /* execlp only returns on failure */
        _exit(1);
    }
    if (pid > 0)
        g_viewer_pid = pid;
    /* parent returns immediately; reaped by ui_reap() at exit */
    return NULL;
}

static int ui_start(void) {
    pthread_t t;
    if (pthread_create(&t, NULL, ui, NULL) != 0) {
        fprintf(stderr, "[-] pthread_create(ui) failed: %s\n", strerror(errno));
        return -1;
    }
    pthread_detach(t);
    return 0;
}

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
    printf("  proxy flags (default: direct, no proxy):\n");
    printf("        --tor           route through a pool of local Tor SOCKS5 instances\n");
    printf("        --elite         use live ProxyScrape 'elite' public proxies\n");
    printf("        --proxy <file>  use a custom list of [proto://]host:port proxies\n");
    printf("        --no-proxy      force direct connections (default)\n");
    printf("  other flags:\n");
    printf("        --xss-no        disable XSS scanning\n");
    printf("        --deepblue      run DeepBlue exploit phase after scan\n");
    printf("        --no-ui         do not start the viewer\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s output -sub example.com --tor\n", prog);
    printf("  %s output --scan-url https://example.com/login.php?u=1 --tor\n", prog);
    printf("  %s output --xss-only https://example.com/login.php?u=1\n", prog);
    printf("  %s output --url https://example.com/graphql\n", prog);
    printf("  %s output --gobuster ~/gobuster/\n", prog);
}

/* ---------------- helpers ---------------- */

/* Copy src into dst (dstsz incl. NUL). Returns 0 on success, -1 on truncation. */
static int copy_str(char *dst, size_t dstsz, const char *src) {
    size_t n = strlen(src);
    if (n >= dstsz)
        return -1;
    memcpy(dst, src, n + 1);
    return 0;
}

/* Extract the bare host from a URL: "https://example.com:8443/a?b=1" -> "example.com"
 * IPv6-aware: "http://[2001:db8::1]:8080/" -> "2001:db8::1" */
static void host_of_url(const char *url, char *out, size_t outsz) {
    const char *p = strstr(url, "://");
    const char *h = p ? p + 3 : url;
    const char *end;
    size_t n;

    if (h[0] == '[') {                      /* IPv6 literal */
        const char *close = strchr(h, ']');
        if (close) {
            n = (size_t)(close - h - 1);
            h++;                            /* skip '[' */
        } else {
            n = strlen(h) - 1;
            h++;
        }
    } else {
        const char *slash = strchr(h, '/');
        const char *colon = strchr(h, ':');
        if (colon && (!slash || colon < slash))
            n = (size_t)(colon - h);
        else if (slash)
            n = (size_t)(slash - h);
        else
            n = strlen(h);
    }

    end = h + n;
    if (n >= outsz)
        n = outsz - 1;

    memcpy(out, h, n);
    out[n] = '\0';
    (void)end;

    for (char *q = out; *q; q++)
        *q = (char)tolower((unsigned char)q[0]);
}

/* Normalize outdir: strip one trailing '/' (keep plain "/"). */
static void normalize_dir(char *dir, size_t sz) {
    size_t n = strlen(dir);
    while (n > 1 && dir[n - 1] == '/')
        dir[--n] = '\0';
    (void)sz;
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

/* ---------------- main ---------------- */

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
    normalize_dir(g.dir, sizeof(g.dir));

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
    int start_ui = 1;

    for (int i = flag_start; i < argc; i++) {
        if (strcmp(argv[i], "--xss-no") == 0) {
            g.xss = false;
        } else if (strcmp(argv[i], "--deepblue") == 0) {
            g.deepblue = true;
        } else if (strcmp(argv[i], "--no-ui") == 0) {
            start_ui = 0;
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
    atexit(ui_reap);

    printf("[+] Sentinel starting\n");
    if (g.domain[0]) printf("[+] Target: %s\n", g.domain);
    printf("[+] Output: %s/\n", g.dir);
    if (g.target[0]) printf("[+] URL:    %s\n", g.target);

    int rc = 0;

    if (start_ui && ui_start() != 0)
        return 1;

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

    /* ui_reap runs via atexit(); explicit call here too for clarity */
    ui_reap();
    proxy_shutdown();
    curl_http_cleanup();
    return rc;
}