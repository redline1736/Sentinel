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

/* Prototypes for the ghostquery stages called from scan_url(). */
#include "../ghostquery/sql/sql.h"
#include "../ghostquery/openredirect/oprt.h"

#define GOBUSTER_WORDLIST "/usr/share/seclists/Discovery/Web-Content/common.txt"

/* Safety cap: how many gobuster results get deep-scanned per host. */
#define MAX_SCAN_URLS 200

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
        if (!lines[n]) {
            fclose(fp);
            for (size_t i = 0; i < n; i++) free(lines[i]);
            free(lines);
            return;
        }
        n++;
    }
    fclose(fp);

    if (n > 1)
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

/* mkdir -p equivalent: creates every component of `path`. */
static int ensure_path(const char *path) {
    char tmp[2600];
    if (snprintf(tmp, sizeof(tmp), "%s", path) >= (int)sizeof(tmp))
        return -1;

    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return -1;
    return 0;
}

/* ---------- wpscan worker ---------- */

static void *wpscan_thread(void *arg) {
    char *host = arg;

    printf("[+] Running wpscan on %s\n", host);

    char outfile[2048];
    snprintf(outfile, sizeof(outfile), "%s/wpscan.txt", g.dir);
    /* wpscan output lives beside the host's gobuster results */

    char hostpath[2400];
    snprintf(hostpath, sizeof(hostpath), "%s/%s", g.dir, host);

    snprintf(outfile, sizeof(outfile), "%s/wpscan.txt", hostpath);

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
 * Handles IPv6 literals: https://[::1]:8080/ -> ::1 */
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

    char *at = strrchr(out, '@');
    if (at)
        memmove(out, at + 1, strlen(at + 1) + 1);

    char *colon   = strrchr(out, ':');
    char *bracket = strrchr(out, ']');
    if (colon && (!bracket || colon > bracket))
        *colon = '\0';

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

/* scheme://host[:port] — the prefix gobuster relative paths resolve against. */
static void url_root(const char *url, char *out, size_t outsz) {
    const char *p = strstr(url, "://");
    const char *h = p ? p + 3 : url;
    size_t n = strcspn(h, "/?#");
    size_t total = (size_t)(h - url) + n;

    if (total >= outsz) total = outsz - 1;
    memcpy(out, url, total);
    out[total] = '\0';
}

/* Filesystem-safe directory name for a discovered URL:
 * "https://h/admin/login.php?x=1" (root "https://h") -> "admin_login_php_x_1" */
static void url_slug(const char *url, const char *root, char *out, size_t outsz) {
    const char *p = url;
    size_t rl = strlen(root);

    if (!strncmp(url, root, rl))
        p = url + rl;
    if (!*p)
        p = "/";

    size_t i = 0;
    for (const char *s = p; *s && i + 1 < outsz && i < 96; s++) {
        unsigned char c = (unsigned char)*s;
        out[i++] = isalnum(c) ? (char)tolower(c) : '_';
    }
    if (i == 0)
        out[i++] = '_';
    out[i] = '\0';
}

/* Skip static assets — they can't carry XSS/SQLi/CSRF findings. */
static int is_asset_url(const char *url) {
    static const char *exts[] = {
        ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".webp", ".bmp",
        ".css", ".js", ".map", ".woff", ".woff2", ".ttf", ".eot", ".otf",
        ".pdf", ".zip", ".gz", ".tar", ".mp4", ".mp3", ".avi", NULL
    };

    char clean[2048];
    snprintf(clean, sizeof(clean), "%s", url);

    char *cut = strpbrk(clean, "?#");
    if (cut) *cut = '\0';

    for (char *q = clean; *q; q++)
        *q = (char)tolower((unsigned char)*q);

    size_t l = strlen(clean);
    for (int i = 0; exts[i]; i++) {
        size_t el = strlen(exts[i]);
        if (l >= el && !strcmp(clean + l - el, exts[i]))
            return 1;
    }
    return 0;
}

/* Parse one gobuster output line into an absolute URL.
 * Handles both formats:
 *   http://host/admin            (Status: 301) [Size: 0]
 *   /admin                        (Status: 200) [Size: 1234]
 * 404s are dropped. */
static int parse_gobuster_line(const char *line, const char *root,
                               char *out, size_t outsz) {
    while (*line == ' ' || *line == '\t')
        line++;
    if (!*line || *line == '#')
        return 0;
    if (strstr(line, "(Status: 404)"))
        return 0;

    size_t tok = strcspn(line, " \t");
    if (tok == 0 || tok >= 2048)
        return 0;

    char target[2048];
    memcpy(target, line, tok);
    target[tok] = '\0';

    int n;
    if (!strncmp(target, "http://", 7) || !strncmp(target, "https://", 8))
        n = snprintf(out, outsz, "%s", target);
    else if (target[0] == '/')
        n = snprintf(out, outsz, "%s%s", root, target);
    else
        return 0;

    return (n > 0 && (size_t)n < outsz);
}
/* ---------- subdomain enumeration (RESTORED) ----------
 * Declared in scan.h, called from main.c and run(), but the definition was
 * lost in a refactor. Delegates to atlas' atlas() and converts its output
 * into the live.txt format the scanning() driver consumes. */
void subdomain(void) {
    char domains_path[2400];
    char domains_dir[2400];

    snprintf(domains_path, sizeof(domains_path), "%s/domains.txt", g.dir);
    snprintf(domains_dir,  sizeof(domains_dir),  "%s/atlas",       g.dir);

    if (ensure_path(domains_dir) != 0) {
        fprintf(stderr, "[-] subdomain: cannot create %s\n", domains_dir);
        return;
    }

    printf("[+] Subdomain enumeration on %s\n", g.domain);

    /* atlas(host_file, hostdir): reads one domain per line from host_file,
     * writes results into hostdir. */
    char seed[1024];
    snprintf(seed, sizeof(seed), "%s\n", g.domain);

    FILE *sf = fopen(domains_path, "w");
    if (!sf) {
        fprintf(stderr, "[-] subdomain: cannot write %s\n", domains_path);
        return;
    }
    fputs(seed, sf);
    fclose(sf);

    int rc = atlas(domains_path, domains_dir);
    if (rc != 0)
        printf("[!] atlas exited with code %d\n", rc);

    /* Collect every discovered host from atlas' output into live.txt.
     * atlas writes a file per source; we scan the dir for lines that look
     * like hostnames of the target domain. */
    char live[1600];
    snprintf(live, sizeof(live), "%s/live.txt", g.dir);

    FILE *out = fopen(live, "w");
    if (!out) {
        fprintf(stderr, "[-] subdomain: cannot write %s\n", live);
        return;
    }

    DIR *d = opendir(domains_dir);
    if (d) {
        struct dirent *e;
        char line[4096];
        char *suffix = g.domain;    /* match hosts ending in the target domain */
        size_t slen = strlen(suffix);

        while ((e = readdir(d)) != NULL) {
            char path[2400];
            snprintf(path, sizeof(path), "%s/%s", domains_dir, e->d_name);
            if (is_dir_entry(domains_dir, e->d_name))
                continue;

            FILE *in = fopen(path, "r");
            if (!in) continue;

            while (fgets(line, sizeof(line), in)) {
                size_t l = strlen(line);
                while (l && (line[l - 1] == '\n' || line[l - 1] == '\r'))
                    line[--l] = '\0';
                if (l == 0 || l < slen)
                    continue;

                for (char *q = line; *q; q++)
                    *q = (char)tolower((unsigned char)*q);

                /* crude but effective: does the line end with ".domain" or
                 * equal the domain itself? */
                if (strcmp(line, suffix) == 0 ||
                    (l > slen && strcmp(line + l - slen, suffix) == 0 &&
                     line[l - slen - 1] == '.'))
                    fprintf(out, "%s\n", line);
            }
            fclose(in);
        }
        closedir(d);
    }

    /* Always include the apex itself so the homepage gets scanned even if
     * atlas found nothing. */
    fprintf(out, "%s\n", g.domain);
    fclose(out);

    dedupe_file(live);
    printf("[+] live.txt written from atlas results\n");
}

/* ---------- gobuster ---------- */

/* Runs gobuster on base_url. Raw output stays in the host folder;
 * every valid discovered path is also written as an absolute URL to
 * gobuster_urls.txt — one URL folder will be created per line. */
static void gobuster_run(const char *base_url, const char *hostdir) {
    char rawfile[2048];
    char urlfile[2048];

    snprintf(rawfile, sizeof(rawfile), "%s/gobuster.txt",      hostdir);
    snprintf(urlfile, sizeof(urlfile), "%s/gobuster_urls.txt", hostdir);

    char *args[] = {
        "gobuster", "dir",
        "-u", (char *)base_url,
        "-w", (char *)GOBUSTER_WORDLIST,
        "-o", rawfile,
        "-q",
        "-t", "20",
        "--no-error",
        "--timeout", "10s",
        NULL
    };

    printf("[+] Running gobuster on %s\n", base_url);

    int rc = run_tool(args);      /* proxychains-aware when a proxy mode is set */
    if (rc != 0)
        printf("[!] gobuster failed on %s with code %d\n", base_url, rc);

    FILE *in = fopen(rawfile, "r");
    if (!in) {
        fprintf(stderr, "[!] gobuster produced no output file for %s\n", base_url);
        return;
    }

    FILE *out = fopen(urlfile, "w");
    if (!out) {
        fclose(in);
        fprintf(stderr, "[!] cannot write %s\n", urlfile);
        return;
    }

    char root[1024];
    url_root(base_url, root, sizeof(root));

    char line[4096];
    char url[2048];
    int  n = 0;

    while (fgets(line, sizeof(line), in)) {
        if (!parse_gobuster_line(line, root, url, sizeof(url)))
            continue;
        if (is_asset_url(url))
            continue;
        fprintf(out, "%s\n", url);
        n++;
    }
    fclose(in);
    fclose(out);

    if (n > 0)
        dedupe_file(urlfile);

    printf("[+] gobuster: %d valid URL(s) -> %s\n", n, urlfile);
}

/* ---------- per-URL scan ---------- */

/* One URL through ghostquery -> glassworm -> headers.
 * Everything this URL produces lands in `urldir` and nowhere else. */
static void scan_url(const char *url, const char *urldir) {
    if (ensure_path(urldir) != 0) {
        fprintf(stderr, "[!] cannot create %s: %s\n", urldir, strerror(errno));
        return;
    }

    printf("  [url] %s\n", url);

    nuclei_run(url, (char *)urldir);         /* ghostquery: nuclei pass     */
    sql_run(url, (char *)urldir);            /* ghostquery: sqlmap pass     */
    openredirect_run(url, (char *)urldir);   /* ghostquery: open redirects  */
    if (g.xss)
        xss_run(url, (char *)urldir, (char *)urldir); /* ghostquery: XSS     */

    glassworm_run(url, urldir);              /* glassworm: CSRF + GraphQL   */
    header(url, urldir);                     /* security headers            */
}


static void scan_one_host(const char *base_url, const char *hostdir)
{
    printf("[*] scanning host %s\n", base_url);

    /* 1. gobuster is the only thing that writes into the host folder. */
    gobuster_run(base_url, hostdir);

    /* 2. The homepage itself is a valid URL — give it its own folder. */
    char rootdir[2600];
    snprintf(rootdir, sizeof(rootdir), "%s/root", hostdir);
    scan_url(base_url, rootdir);

    /* 3. Loop: every gobuster URL gets its own folder + scan results. */
    char urls_path[2048];
    snprintf(urls_path, sizeof(urls_path), "%s/gobuster_urls.txt", hostdir);

    FILE *fp = fopen(urls_path, "r");
    if (!fp) {
        printf("[*] no gobuster URLs for %s — homepage only\n", base_url);
        return;
    }

    char root[1024];
    url_root(base_url, root, sizeof(root));

    char line[4096];
    int  idx = 0, total = 0;

    while (fgets(line, sizeof(line), fp)) {
        size_t l = strlen(line);
        while (l && (line[l - 1] == '\n' || line[l - 1] == '\r'))
            line[--l] = '\0';
        if (l) total++;
    }
    rewind(fp);

    while (fgets(line, sizeof(line), fp)) {
        size_t l = strlen(line);
        while (l && (line[l - 1] == '\n' || line[l - 1] == '\r'))
            line[--l] = '\0';
        if (l == 0)
            continue;

        if (!strcmp(line, base_url))      /* homepage already scanned as root/ */
            continue;

        if (idx >= MAX_SCAN_URLS) {
            printf("[!] MAX_SCAN_URLS (%d) reached — %d URL(s) skipped on %s\n",
                   MAX_SCAN_URLS, total - idx, base_url);
            break;
        }

        char slug[128];
        char urldir[2800];

        url_slug(line, root, slug, sizeof(slug));
        snprintf(urldir, sizeof(urldir), "%s/%s", hostdir, slug);

        idx++;
        printf("  [%d/%d]\n", idx, total);

        scan_url(line, urldir);
    }

    fclose(fp);
    printf("[*] done with %s — %d URL folder(s)\n", base_url, idx + 1);
}

/* ---------- live.txt driver ---------- */

void scanning(char *target_url)
{
    /* --scan-url mode: no gobuster, no subdomain folders. The single URL's
     * ghostquery / glassworm / headers results go straight into g.dir. */
    if (g.urlscan && !g.sitescan) {
        const char *url = target_url ? target_url : g.target;
        if (!url || !url[0]) {
            fprintf(stderr, "[-] scanning: no URL for --scan-url mode\n");
            return;
        }
        printf("[*] URL scan mode — results written directly to %s\n", g.dir);
        scan_url(url, g.dir);
        return;
    }

    /* --full-scan / --fast-scan / --scan-site: one folder per live host. */
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

        char hostdir[2400];
        snprintf(hostdir, sizeof(hostdir), "%s/%s", g.dir, host);
        if (mkdir(hostdir, 0755) != 0 && errno != EEXIST) {
            fprintf(stderr, "[!] mkdir %s: %s\n", hostdir, strerror(errno));
            continue;
        }

        /* probe https, fall back to http */
        char base_url[2048];
        snprintf(base_url, sizeof(base_url), "https://%s", host);

        request root_req = {0};
        if (!http_send_get(&root_req, base_url)) {
            snprintf(base_url, sizeof(base_url), "http://%s", host);
            if (!http_send_get(&root_req, base_url)) {
                request_free(&root_req);
                continue;
            }
        }

        int is_api = check_api(&root_req, host, g.domain);
        request_free(&root_req);

        scan_one_host(base_url, hostdir);

        if (is_api == 1) {
            char apifile[2400];
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
}

/* --------------------------------------------------------------------------
 * analyze() — write vuln.txt into every URL folder that has findings
 * ------------------------------------------------------------------------ */

/* Writes <dir>/vuln.txt summarizing the tool outputs in that directory.
 * Returns the finding count (or -1 if the dir has nothing to analyze). */
static int analyze_dir(const char *dirpath) {
    char nuclei[2048], gobuster[2048], xss[2048], glassworm[2048];
    char headers[2048], wpscan[2048], vuln[2048];

    snprintf(nuclei,    sizeof(nuclei),    "%s/nuclei.txt",    dirpath);
    snprintf(gobuster,  sizeof(gobuster),  "%s/gobuster.txt",  dirpath);
    snprintf(xss,       sizeof(xss),       "%s/xss.txt",       dirpath);
    snprintf(glassworm, sizeof(glassworm), "%s/glassworm.txt", dirpath);
    snprintf(headers,   sizeof(headers),   "%s/headers.txt",   dirpath);
    snprintf(wpscan,    sizeof(wpscan),    "%s/wpscan.txt",    dirpath);
    snprintf(vuln,      sizeof(vuln),      "%s/vuln.txt",      dirpath);

    /* URL folders contain nuclei/xss/etc; host folders contain gobuster.
     * A directory with none of these isn't ours — skip it. */
    struct stat st;
    int relevant = 0;
    if (stat(nuclei, &st) == 0 || stat(xss, &st) == 0 ||
        stat(glassworm, &st) == 0 || stat(headers, &st) == 0 ||
        stat(gobuster, &st) == 0 || stat(wpscan, &st) == 0)
        relevant = 1;
    if (!relevant)
        return -1;

    FILE *out = fopen(vuln, "w");
    if (!out)
        return -1;

    int  findings = 0;
    char line[4096];
    FILE *fp;

    fp = fopen(nuclei, "r");
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

    fp = fopen(glassworm, "r");
    if (fp) {
        while (fgets(line, sizeof(line), fp)) {
            fprintf(out, "[GLASSWORM] %s", line);
            findings++;
        }
        fclose(fp);
    }

    fp = fopen(headers, "r");
    if (fp) {
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "[HEADER]") ||
                strstr(line, "[CORS]")   ||
                strstr(line, "[COOKIE]")) {
                fprintf(out, "[HEADERS] %s", line);
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

    /* gobuster is aggregated into the HOST folder's vuln.txt so the raw
     * path list is visible at the subdomain level. */
    fp = fopen(gobuster, "r");
    if (fp) {
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "Status: 2") ||
                strstr(line, "Status: 4") ||
                strstr(line, "Status: 5"))
            {
                fprintf(out, "[GOBUSTER] %s", line);
                findings++;
            }
        }
        fclose(fp);
    }

    fclose(out);
    return findings;
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

        char hostdir[2400];
        snprintf(hostdir, sizeof(hostdir), "%s/%s", g.dir, entry->d_name);

        /* host folder: gobuster (+ wpscan) summary */
        int n = analyze_dir(hostdir);
        if (n >= 0)
            printf("[+] %-35s %3d findings\n", entry->d_name, n);

        /* one level down: every URL folder gets its own vuln.txt */
        DIR *sub = opendir(hostdir);
        if (!sub)
            continue;

        struct dirent *se;
        while ((se = readdir(sub)) != NULL) {
            if (!strcmp(se->d_name, ".") || !strcmp(se->d_name, ".."))
                continue;

            char urldir[2800];
            snprintf(urldir, sizeof(urldir), "%s/%s", hostdir, se->d_name);
            if (!is_dir_entry(hostdir, se->d_name))
                continue;

            int m = analyze_dir(urldir);
            if (m >= 0)
                printf("[+] %-35s %3d findings\n", urldir, m);
        }
        closedir(sub);
    }

    closedir(dir);
    printf("[+] Analysis complete.\n");
}

/* --------------------------------------------------------------------------
 * run() — the full pipeline
 * ------------------------------------------------------------------------ */

int run(char *url) {
    printf("\n========================================\n");
    printf("  VectorOps — Automated Pentest Pipeline\n");
    printf("  Target : %s\n", g.domain);
    printf("  Output : %s\n", g.dir);
    printf("========================================\n\n");

    if (g.proxy)
        start_proxies();

    /* --scan-url: single URL, results directly in outdir — no subdomain step. */
    if (g.urlscan && !g.sitescan) {
        scanning(url);
        if (g.deepblue)
            deepblue_run();
        printf("\n========================================\n");
        printf("      Pipeline Complete\n");
        printf("========================================\n");
        return 0;
    }

    /* --full-scan / --fast-scan: enumerate subdomains first.
     * --scan-site: main() already seeded live.txt with the target — skip. */
    if (!g.urlscan)
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
                request_free(&r);
                continue;
            }
        }

        bool wordpress = false;
        if (r.body) {
            if (strstr(r.body, "wp-content/") ||
                strstr(r.body, "/wp-json") ||
                strstr(r.body, "Generator: WordPress"))
                wordpress = true;

            free(r.body);
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
    printf("\n========================================\n");
    printf("      Pipeline Complete\n");
    printf("========================================\n");
    return rc;
}