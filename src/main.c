#define _GNU_SOURCE
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

/* ---------------- viewer (UI) ---------------- */

static pid_t g_viewer_pid = -1;

/* Absolute path of this binary, for the UI to respawn us for scans. */
static void self_path(char *out, size_t outsz) {
    ssize_t n = readlink("/proc/self/exe", out, outsz - 1);
    if (n > 0) {
        out[n] = '\0';
        return;
    }
    /* fallback: whatever we were invoked as */
    snprintf(out, outsz, "sentinel");
}

/* Kill the viewer (used only on abnormal exits / signals). */
static void ui_reap(void) {
    if (g_viewer_pid > 0) {
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

/* Launch the viewer, forwarding <outdir> <mode> <arg> [flags] so it
 * prefills and auto-starts the scan. Returns child pid or -1. */
static pid_t ui_launch(int argc, char *argv[]) {
    char self[4096];
    self_path(self, sizeof(self));

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    }
    if (pid == 0) {
        /* the UI respawns this binary for each scan */
        setenv("SENTINEL_BIN", self, 1);

        /* argv: python3 view.py <outdir> <mode> <arg> [flags...] */
        char *nargv[argc + 2];
        int n = 0;
        nargv[n++] = (char *)"python3";
        nargv[n++] = (char *)"/usr/share/sentinel/view/view.py";
        for (int i = 1; i < argc; i++)
            nargv[n++] = argv[i];       /* forward everything, skip progname */
        nargv[n] = NULL;

        execvp(nargv[0], nargv);
        fprintf(stderr, "[-] cannot launch viewer: %s\n", strerror(errno));
        _exit(1);
    }
    return pid;
}

/* Block until the viewer window closes. Returns its exit status. */
static int ui_wait(void) {
    int st = 0;
    if (g_viewer_pid < 0)
        return 0;
    while (waitpid(g_viewer_pid, &st, 0) < 0 && errno == EINTR)
        ;
    g_viewer_pid = -1;
    if (WIFEXITED(st))
        return WEXITSTATUS(st);
    if (WIFSIGNALED(st))
        return 128 + WTERMSIG(st);
    return 0;
}

/* SIGINT/SIGTERM: take the viewer down with us */
static void on_signal(int sig) {
    if (g_viewer_pid > 0)
        kill(g_viewer_pid, sig);
    _exit(128 + sig);
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
    printf("  With a full <outdir> <mode> <arg> invocation the viewer starts\n");
    printf("  automatically, prefilled with your arguments; the process stays\n");
    printf("  alive until the viewer window is closed. Plain scan output also\n");
    printf("  goes to the terminal.\n");
    printf("\n");
    printf("  proxy flags (default: direct, no proxy):\n");
    printf("        --tor           route through a pool of local Tor SOCKS5 instances\n");
    printf("        --elite         use live ProxyScrape 'elite' public proxies\n");
    printf("        --proxy <file>  use a custom list of [proto://]host:port proxies\n");
    printf("        --no-proxy      force direct connections (default)\n");
    printf("  other flags:\n");
    printf("        --xss-no        disable XSS scanning\n");
    printf("        --deepblue      run DeepBlue exploit phase after scan\n");
    printf("        --no-ui         headless: do not start the viewer, just scan and exit\n");
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
    if (n >= dstsz)
        return -1;
    memcpy(dst, src, n + 1);
    return 0;
}

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

/* Is any flag in argv[4..] asking for headless mode? */
static int wants_no_ui(int argc, char *argv[]) {
    for (int i = 4; i < argc; i++)
        if (strcmp(argv[i], "--no-ui") == 0)
            return 1;
    return 0;
}

/* ---------------- headless scan (original path) ---------------- */

static int run_headless(int argc, char *argv[], const char *mode) {
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
            /* handled by caller */
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

/* ---------------- main ---------------- */

int main(int argc, char *argv[]) {

    /* -------- headless: --no-ui flag -> original scan-and-exit path */
    if (argc >= 4 && wants_no_ui(argc, argv))
        return run_headless(argc, argv, argv[2]);

    /* -------- UI mode: launch viewer with our args, wait for it.
     * Valid forms:
     *   sentinel                                (UI only)
     *   sentinel <outdir> <mode> <arg> [flags]  (UI prefilled + auto-run)
     */
    if (argc != 1 && argc < 4) {
        print_usage(argv[0]);
        return 1;
    }

    /* validate mode/target early so typos fail fast, before the UI */
    if (argc >= 4) {
        const char *m = argv[2];
        if (!is_url_mode(m) && !is_domain_mode(m) &&
            strcmp(m, "--url") != 0 && strcmp(m, "--gobuster") != 0) {
            fprintf(stderr, "[-] Unknown mode: %s\n", m);
            print_usage(argv[0]);
            return 1;
        }
    }

    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);

    g_viewer_pid = ui_launch(argc, argv);
    if (g_viewer_pid < 0)
        return 1;

    /* stay alive until the viewer window is closed — scan completion
     * does NOT end this process */
    int rc = ui_wait();
    return rc;
}