#include <errno.h>
#include <sys/stat.h>
#include <sys/wait.h>
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
    printf("  UI:\n");
    printf("        %s              launch the tkinter UI (view.py)\n", prog);
    printf("        %s --ui [args]  launch the UI, optionally prefilled\n", prog);
    printf("                        with <outdir> <mode> <arg> [flags]\n");
    printf("        SENTINEL_UI=path overrides the location of view.py\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s output -sub example.com --tor\n", prog);
    printf("  %s output --scan-url https://example.com/login.php?u=1 --tor\n", prog);
    printf("  %s output --xss-only https://example.com/login.php?u=1\n", prog);
    printf("  %s --ui output -sub example.com --tor\n", prog);
}

/* Resolve view.py next to the running binary (Linux /proc/self/exe),
 * falling back to "view.py" in the CWD. Overridable via $SENTINEL_UI. */
static void locate_viewpy(char *out, size_t outsz) {
    const char *env = getenv("SENTINEL_UI");
    if (env && *env) {
        snprintf(out, outsz, "%s", env);
        return;
    }

    /* 1. next to the binary */
    ssize_t n = readlink("/proc/self/exe", out, outsz - 1);
    if (n > 0) {
        out[n] = '\0';
        char *slash = strrchr(out, '/');
        if (slash)
            slash[1] = '\0';
        else
            out[0] = '\0';
        strncat(out, "view.py", outsz - strlen(out) - 1);
        if (access(out, R_OK) == 0)
            return;                         /* found it */
    }

    /* 2. installed share path */
    snprintf(out, outsz, "/usr/share/sentinel/view/view.py");
    if (access(out, R_OK) == 0)
        return;

    /* 3. CWD fallback */
    snprintf(out, outsz, "view.py");
}

/* Build "python3 view.py [prefill...]" argv from ours, skipping "--ui". */
static int build_ui_argv(int argc, char *argv[], char **nargv, int nmax) {
    char uipath[4096];
    locate_viewpy(uipath, sizeof(uipath));

    int n = 0;
    if (n + 2 > nmax) return -1;
    nargv[n++] = (char *)"python3";
    nargv[n++] = uipath;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--ui") == 0)
            continue;
        if (n + 1 > nmax) return -1;
        nargv[n++] = argv[i];
    }
    nargv[n] = NULL;
    return n;
}

/* Replace this process with the UI. Never returns on success. */
static void launch_ui_exec(int argc, char *argv[]) {
    char *nargv[argc + 2];
    if (build_ui_argv(argc, argv, nargv, argc + 2) < 0) {
        fprintf(stderr, "[-] too many arguments for UI launch\n");
        exit(1);
    }
    execvp(nargv[0], nargv);
    fprintf(stderr, "[-] cannot launch UI '%s': %s\n",
            nargv[1], strerror(errno));
    exit(1);
}

/* Fork the UI as a child and wait for it. Returns child rc, or -1. */
static int launch_ui_wait(int argc, char *argv[]) {
    char *nargv[argc + 2];
    if (build_ui_argv(argc, argv, nargv, argc + 2) < 0)
        return -1;

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    }
    if (pid == 0) {
        execvp(nargv[0], nargv);
        fprintf(stderr, "[-] cannot launch UI '%s': %s\n",
                nargv[1], strerror(errno));
        _exit(127);
    }

    int st;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR)
        ;
    if (WIFEXITED(st))
        return WEXITSTATUS(st);
    if (WIFSIGNALED(st))
        return 128 + WTERMSIG(st);
    return -1;
}

/* 1 = launch UI, 0 = normal scan path */
static int wants_ui(int argc, char *argv[]) {
    if (argc == 1)
        return 1;                            /* bare invocation */
    if (argc == 2 && strcmp(argv[1], "--ui") == 0)
        return 1;
    if (argc >= 2 && strcmp(argv[1], "--ui") == 0)
        return 1;                            /* --ui with prefill args */
    return 0;
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

    /* --- UI dispatch: bare run or --ui [prefill args] --- */
    if (wants_ui(argc, argv)) {
        return launch_ui_wait(argc, argv);   /* use launch_ui_exec(argc, argv)
                                              * instead if you prefer exec */
    }

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