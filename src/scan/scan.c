// _GNU_SOURCE is set via compiler flags (-D_GNU_SOURCE) — do NOT redefine here
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
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
#include "../util/util.h"
#include "../prox/prox.h"
#include "../deepblue/deepblue.h"
#include "../ghostquery/gq.h"
#include "../global.h"

/* ---------- rate-limit tunables (declared extern in scan.h) ---------- */

int g_rate = 1;
double g_retry_minutes = 0.0;

/* ---------- HTTP wrapper (replaces the old run_request-based hack) ---------- */

static size_t body_cb(void *ptr, size_t size, size_t nmemb, void *stream) {
    return fwrite(ptr, size, nmemb, (FILE *)stream);
}

typedef struct { char retry_after[64]; } retry_ctx;

static size_t retry_header_cb(char *buf, size_t size, size_t nmemb, void *ud) {
    size_t n = size * nmemb;
    retry_ctx *ctx = ud;
    if (n > 12 && strncasecmp(buf, "Retry-After:", 12) == 0) {
        const char *v = buf + 12;
        while (isspace((unsigned char)*v)) v++;
        size_t vlen = n - (size_t)(v - buf);
        if (vlen >= sizeof(ctx->retry_after))
            vlen = sizeof(ctx->retry_after) - 1;
        memcpy(ctx->retry_after, v, vlen);
        ctx->retry_after[vlen] = '\0';
        size_t l = strlen(ctx->retry_after);
        while (l && (ctx->retry_after[l-1] == '\r' || ctx->retry_after[l-1] == '\n'))
            ctx->retry_after[--l] = '\0';
    }
    return n;
}

/* GET/HEAD through the current proxy; body + "HTTP_CODE:%ld" go to `file`.
 * Returns HTTP status (>=100) on success, -1 on transport error.
 * On 429/503 it parses Retry-After, sets g_retry_minutes, burns+rotates. */
int http_send(const char *url, const char *method, const char *file) {
    FILE *out = fopen(file, "w");
    if (!out) {
        fprintf(stderr, "[-] Cannot open output: %s\n", file);
        return -1;
    }

    CURL *curl = curl_easy_init();
    if (!curl) {
        fclose(out);
        return -1;
    }

    retry_ctx rctx = {0};
    long code = 0;

    const char *proxy_str = proxy_get_socks();
    if (proxy_str)
        curl_easy_setopt(curl, CURLOPT_PROXY, proxy_str);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, out);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, body_cb);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, retry_header_cb);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &rctx);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 3L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Sentinel-scan/1.0");
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    if (method && strcmp(method, "HEAD") == 0)
        curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    else
        curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);

    CURLcode res = curl_easy_perform(curl);
    if (res == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
        fprintf(out, "\nHTTP_CODE:%ld\n", code);
    } else {
        fprintf(stderr, "[-] Request failed: %s\n", curl_easy_strerror(res));
    }

    curl_easy_cleanup(curl);
    fclose(out);

    if (res != CURLE_OK)
        return -1;

    if ((code == 429 || code == 503) && rctx.retry_after[0]) {
        if (isdigit((unsigned char)rctx.retry_after[0])) {
            g_retry_minutes = atoi(rctx.retry_after) / 60.0;
        } else {
            struct tm tm = {0};
            if (strptime(rctx.retry_after, "%a, %d %b %Y %H:%M:%S GMT", &tm)) {
                time_t target = timegm(&tm);
                time_t now = time(NULL);
                double diff = difftime(target, now);
                g_retry_minutes = (diff > 0 ? diff : 0) / 60.0;
            }
        }
        printf("[!] Rate limited (HTTP %ld) — burning proxy and rotating\n", code);
        burn_rotate();
    }
    return (int)code;
}

void enumerate_rate(const char *url, const char *method, const char *file) {
    int code = http_send(url, method, file);
    if (g_retry_minutes > 0) {
        printf("[!] Rate limited — retrying after %.0f minutes...\n", g_retry_minutes);
        sleep((int)(g_retry_minutes * 60) + 1);
        g_retry_minutes = 0;
        http_send(url, method, file);
    } else if (code < 100) {
        int delay = g_rate > 0 ? g_rate : 1;
        printf("[!] Request failed (HTTP %d) — retrying in %ds\n", code, delay);
        sleep(delay);
        http_send(url, method, file);
    }
}

/* ---------- small C helpers (replace shell pipes/redirection) ---------- */

static int cmp_str(const void *a, const void *b) {
    return strcmp(*(char * const *)a, *(char * const *)b);
}

/* Reads file, strips empty lines, sorts, dedupes, writes back in place. */
static void dedupe_file(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) { fprintf(stderr, "[!] Cannot open %s for dedupe\n", path); return; }

    char **lines = NULL;
    size_t n = 0, cap = 0;
    char buf[4096];

    while (fgets(buf, sizeof(buf), fp)) {
        size_t len = strlen(buf);
        if (len && buf[len-1] == '\n') { buf[--len] = '\0'; }
        if (len && buf[len-1] == '\r') { buf[--len] = '\0'; }
        if (len == 0) continue;

        if (n >= cap) {
            cap = cap ? cap * 2 : 64;
            char **tmp = realloc(lines, cap * sizeof(char *));
            if (!tmp) {
                fprintf(stderr, "[!] realloc failed in dedupe_file\n");
                for (size_t i = 0; i < n; i++) free(lines[i]);
                free(lines); fclose(fp); return;
            }
            lines = tmp;
        }
        lines[n] = strdup(buf);
        if (!lines[n]) {
            fprintf(stderr, "[!] strdup failed in dedupe_file\n");
            for (size_t i = 0; i < n; i++) free(lines[i]);
            free(lines); fclose(fp); return;
        }
        n++;
    }
    fclose(fp);

    if (n == 0) { free(lines); return; }

    qsort(lines, n, sizeof(char *), cmp_str);

    FILE *out = fopen(path, "w");
    if (!out) {
        fprintf(stderr, "[!] Cannot open %s for writing\n", path);
        for (size_t i = 0; i < n; i++) free(lines[i]);
        free(lines); return;
    }

    char *prev = NULL;                       /* last line actually written */
    for (size_t i = 0; i < n; i++) {
        if (prev && strcmp(lines[i], prev) == 0)
            continue;                        /* drop duplicate; free later */
        fprintf(out, "%s\n", lines[i]);
        prev = lines[i];                     /* lines[i] still alive here */
    }
    fclose(out);

    for (size_t i = 0; i < n; i++)           /* single cleanup pass */
        free(lines[i]);
    free(lines);
}

/* ---------- subdomain enumeration ---------- */

void subdomain() {
    printf("[+] Starting subdomain enumeration...\n");

    char subfile[2048];
    snprintf(subfile, sizeof(subfile), "%s/subdomains.txt", g.dir);

    /* Passive: subfinder – no built-in output; we capture stdout */
    char *sf_args[] = {"subfinder", "-d", g.domain, "-silent", "-all", NULL};
    int rc = run_tool_out(sf_args, subfile, false);
    if (rc != 0) printf("[!] subfinder failed with code %d\n", rc);

    /* Passive: assetfinder – no built-in output; capture stdout */
    char *af_args[] = {"assetfinder", "--subs-only", g.domain, NULL};
    rc = run_tool_out(af_args, subfile, true);
    if (rc != 0) printf("[!] assetfinder failed with code %d\n", rc);

    dedupe_file(subfile);

    /* Active: gobuster DNS – no built-in output; capture stdout */
    const char *sl = getenv("SECLISTS");
    char wl[1024];
    if (sl && sl[0])
        snprintf(wl, sizeof(wl), "%s/Discovery/DNS/subdomains-top1million-5000.txt", sl);
    else
        snprintf(wl, sizeof(wl), "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt");
    
    char *gb_args[] = {"gobuster", "dns", "-d", g.domain, "-w", wl, "-q", NULL};
    rc = run_tool_out(gb_args, subfile, true);
    if (rc != 0) printf("[!] gobuster failed with code %d\n", rc);
    
    dedupe_file(subfile);

    /* Health check: httpx – no built-in output; capture stdout */
    char live[2048];
    snprintf(live, sizeof(live), "%s/live.txt", g.dir);
    char *hx_args[] = {"httpx", "-silent", "-l", subfile, NULL};
    rc = run_tool_out(hx_args, live, false);
    if (rc != 0) printf("[!] httpx failed with code %d\n", rc);
    
    dedupe_file(live);

    /* Takeover checks: subzy – no built-in output (writes to stdout) */
    char subzy_out[2048], subjack_out[2048];
    snprintf(subzy_out,  sizeof(subzy_out),  "%s/subzy.txt",    g.dir);
    snprintf(subjack_out, sizeof(subjack_out), "%s/subjack.txt", g.dir);

    char *sz_args[] = {"subzy", "run", "--targets", live, NULL};
    rc = run_tool_out(sz_args, subzy_out, false);
    if (rc != 0) printf("[!] subzy failed with code %d\n", rc);

    /* subjack has its own -o flag – we should NOT capture stdout to the same file */
    char *sj_args[] = {"subjack", "-w", live, "-t", "100", "-timeout", "30",
                       "-o", subjack_out, NULL};
    rc = run_tool(sj_args);   /* use run_tool (no redirection) */
    if (rc != 0) printf("[!] subjack failed with code %d\n", rc);

    printf("[+] Subdomain enumeration complete.\n");
}

/* ---------- targeted scanning on live hosts ---------- */

void scanning() {
    printf("[+] Starting targeted scanning...\n");

    char path[2048];
    snprintf(path, sizeof(path), "%s/live.txt", g.dir);

    FILE *fp = fopen(path, "r");
    if (!fp) {
        printf("[-] No live hosts found at %s\n", path);
        return;
    }

    char buffer[512];
    char hostdir[2048];

    while (fgets(buffer, sizeof(buffer), fp)) {
        buffer[strcspn(buffer, "\n")] = 0;
        if (strlen(buffer) == 0) continue;

        printf("[*] Scanning: %s\n", buffer);
        snprintf(hostdir, sizeof(hostdir), "%s/%s", g.dir, buffer);
        mkdir(hostdir, 0755);

        char url[1024];
        snprintf(url, sizeof(url), "https://%s", buffer);

        /* nuclei – has -o, so we use run_tool (no redirection) */
        char nuclei_out[4096];
        snprintf(nuclei_out, sizeof(nuclei_out), "%s/nuclei.txt", hostdir);
        char *nuclei_args[] = {"nuclei", "-u", url, "-o", nuclei_out, "-silent", NULL};
        int rc = run_tool(nuclei_args);
        if (rc != 0) printf("[!] nuclei failed on %s with code %d\n", buffer, rc);

        /* nikto – no built-in output; capture stdout */
        char nikto_out[4096];
        snprintf(nikto_out, sizeof(nikto_out), "%s/nikto.txt", hostdir);
        char *nikto_args[] = {"nikto", "-host", url, NULL};
        rc = run_tool_out(nikto_args, nikto_out, false);
        if (rc != 0) printf("[!] nikto failed on %s with code %d\n", buffer, rc);

        /* xss */
        char xss_out[4096];
        snprintf(xss_out, sizeof(xss_out), "%s/xss.txt", hostdir);

        char *xss_fallback[] = {"python3", "ghostquery/xss/main.py", buffer, hostdir, NULL};
        rc = run_tool_out(xss_fallback, xss_out, true);
        if (rc != 0) printf("[!] xss fallback failed on %s with code %d\n", buffer, rc);
        // remove for now xss_run(buffer, hostdir);
    }
    fclose(fp);
    printf("[+] Targeted scanning complete.\n");
}

void *wpscan(void *arg){
    
    char *host = arg;
    
    printf("[+] Running wpscan on %s\n", host);

    char outfile[2048];
    snprintf(outfile, sizeof(outfile), "%s/%s/wpscan.txt", g.dir, host);

    char url[2048];
    snprintf(url, sizeof(url), "https://%s", host);

    /* wpscan has --output – use run_tool */
    char *wpscan_args[] = {"wpscan", "--url", url, "--output", outfile, NULL};
    int rc = run_tool(wpscan_args);
    if (rc != 0) printf("[!] wpscan failed on %s with code %d\n", host, rc);

    free(host);
    return NULL;
}

void analyze(){
    printf("[+] Analyzing scan results...\n");

    DIR *dir = opendir(g.dir);
    if (!dir) {
        perror("opendir");
        return;
    }

    struct dirent *entry;

    while ((entry = readdir(dir)) != NULL){
        if (entry->d_type != DT_DIR)
            continue;
        if (!strcmp(entry->d_name, "."))
            continue;
        if (!strcmp(entry->d_name, ".."))
            continue;

        char subzy[2048];
        char subjack[2048];
        char nuclei[2048];
        char xss[2048];
        char wpscan[2048];
        char vuln[2048];

        snprintf(subzy, sizeof(subzy), "%s/%s/subzy.txt", g.dir, entry->d_name);
        snprintf(subjack, sizeof(subjack), "%s/%s/subjack.txt", g.dir, entry->d_name);

        snprintf(nuclei, sizeof(nuclei), "%s/%s/nuclei.txt", g.dir, entry->d_name);
        snprintf(xss, sizeof(xss), "%s/%s/xss.txt", g.dir, entry->d_name);
        snprintf(wpscan, sizeof(wpscan), "%s/%s/wpscan.txt", g.dir, entry->d_name);
        snprintf(vuln, sizeof(vuln), "%s/%s/vuln.txt", g.dir, entry->d_name);

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
                if (strlen(line) > 5)
                {
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

void run() {
    printf("\n========================================\n");
    printf("  VectorOps — Automated Pentest Pipeline\n");
    printf("  Target : %s\n", g.domain);
    printf("  Output : %s\n", g.dir);
    printf("========================================\n\n");
    if (g.proxy)
        start_proxies();

    if (!g.urlscan)          /* --scan-url: main pre-seeds live.txt */
        subdomain();

    scanning();

    pthread_t threads[256];
    int thread_count = 0;

    DIR *dir = opendir(g.dir);

    if (dir) {
        struct dirent *entry;

        while ((entry = readdir(dir))) {
            if (entry->d_type != DT_DIR)
                continue;
            if (!strcmp(entry->d_name, "."))
                continue;
            if (!strcmp(entry->d_name, ".."))
                continue;

            char nikto[2048];
            snprintf(nikto, sizeof(nikto), "%s/%s/nikto.txt", g.dir, entry->d_name);

            FILE *fp = fopen(nikto, "r");
            if (!fp)
                continue;

            bool wordpress = false;
            char buf[1024];

            while (fgets(buf, sizeof(buf), fp)) {
                if (strstr(buf, "WordPress")) {
                    wordpress = true;
                    break;
                }
            }
            fclose(fp);

            if (!wordpress)
                continue;

            printf("[+] WordPress detected on %s\n", entry->d_name);

            char *host = strdup(entry->d_name);
            if (!host)
                continue;

            if (thread_count < 256 &&
                pthread_create(&threads[thread_count], NULL, wpscan, host) == 0) {
                thread_count++;
            } else {
                free(host);
            }
        }

        closedir(dir);
    }

    for (int i = 0; i < thread_count; i++)
        pthread_join(threads[i], NULL);

    analyze();

    if (g.deepblue) {
        deepblue_run();
    }
    if (g.proxy){
        proxy_shutdown();       /* covers all modes — was kill_tor_processes() */
    }

    printf("\n========================================\n");
    printf("      Pipeline Complete\n");
    printf("========================================\n");
}