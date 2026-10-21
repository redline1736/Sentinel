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
#include "../ghostquery/gq.h"
#include "../atlas/sub.h"
#include "../headers/hdr.h"
#include "../glassworm/gw.h"
/* ---------- rate-limit tunables (declared extern in scan.h) ---------- */

int g_rate = 1;
double g_retry_minutes = 0.0;

/* ---------- HTTP wrapper (replaces the old run_request-based hack) ---------- */
void enumerate_rate(const char *url, const char *method, const char *file) {
    request r = {0};
    http_send_post(&r, url, false, NULL, false, NULL);
    if (g_retry_minutes > 0) {
        printf("[!] Rate limited — retrying after %.0f minutes...\n", g_retry_minutes);
        sleep((int)(g_retry_minutes * 60) + 1);
        g_retry_minutes = 0;
        http_send_post(&r, url, false, NULL, false, NULL);
    } else if (r.code < 100) {
        int delay = g_rate > 0 ? g_rate : 1;
        printf("[!] Request failed (HTTP %d) — retrying in %ds\n", r.code, delay);
        sleep(delay);
        http_send_post(&r, url, false, NULL, false, NULL);
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
s
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

    char *sz_args[] = {"subzy", "run", "--targets", live, "--hide_fails", NULL};
    rc = run_tool_out(sz_args, subzy_out, false);
    if (rc != 0) printf("[!] subzy failed with code %d\n", rc);

    /* subjack has its own -o flag – we should NOT capture stdout to the same file */
    char *sj_args[] = {"subjack", "-w", live, "-t", "100", "-o", subjack_out, NULL};
    rc = run_tool(sj_args);   /* use run_tool (no redirection) */
    if (rc != 0) printf("[!] subjack failed with code %d\n", rc);

    // custom tooling
    atlas(subfile, g.dir);

    printf("[+] Subdomain enumeration complete.\n");
}

/* ---------- targeted scanning on live hosts ---------- */
/* Turn "https://host/path?x=y" into a filesystem-safe dir name.
 *   https://host/          -> "root"
 *   https://host/admin     -> "admin"
 *   https://host/a/b?c=d   -> "a_b"
 */
static void url_to_dirname(const char *url, char *out, size_t outsz) {
    if (!url || !out || outsz == 0) return;

    const char *p = strstr(url, "://");
    p = p ? p + 3 : url;

    const char *slash = strchr(p, '/');
    if (!slash || slash[1] == '\0') {
        snprintf(out, outsz, "root");
        return;
    }

    size_t i = 0;
    for (const char *q = slash + 1; *q && i + 1 < outsz; q++) {
        char c = *q;
        if (c == '/' || c == '?' || c == '&' || c == '=' ||
            c == ':' || c == '*' || c == '\\' || c == '"' ||
            c == '<' || c == '>' || c == '|')
            c = '_';
        out[i++] = c;
    }
    out[i] = '\0';
    if (i == 0) snprintf(out, outsz, "root");
}

void scanning(char *target_url) {
    printf("[+] Starting targeted scanning...\n");
    // Live.txt Paths
    char path[2048];
    if (snprintf(path, sizeof(path), "%s/live.txt", g.dir) >= (int)sizeof(path)) {
        fprintf(stderr, "[-] live.txt path too long\n");
        return;
    }

    FILE *fp = fopen(path, "r");
    if (!fp) {
        printf("[-] No live hosts found at %s\n", path);
        return;
    }

    char live_txt_content[512];
    char hostdir[2048];

    pthread_t[5] threads;
    
    headers_t hdr_args;
    ghostquery_t gq_args;

    const char *wl = "/usr/share/seclists/Discovery/Web-Content/common.txt";

    FILE *sg = NULL;
    if (!g.full) {
        sg = fopen("signatures.txt", "r");
        if (!sg) {
            fprintf(stderr, "[-] signatures.txt not found\n");
            fclose(fp);
            return;
        }
    }

    while (fgets(live_txt_content, sizeof(live_txt_content), fp)) {
        live_txt_content[strcspn(live_txt_content, "\r\n")] = 0;
        if (strlen(live_txt_content) == 0) continue;

        if (strchr(live_txt_content, '/') != NULL) {
            printf("[!] Skipping invalid host entry: %s\n", live_txt_content);
            continue;
        }

        printf("[*] Scanning: %s\n", live_txt_content);

        if (snprintf(hostdir, sizeof(hostdir), "%s/%s", g.dir, live_txt_content)
            >= (int)sizeof(hostdir)) {
            fprintf(stderr, "[-] hostdir path too long for %s\n", live_txt_content);
            continue;
        }

        if (mkdir(hostdir, 0755) != 0 && errno != EEXIST) {
            perror("mkdir");
            continue;
        }

        if (!g.full) {
            int found = 0;
            char sig[1024];
            rewind(sg);
            while (fgets(sig, sizeof(sig), sg)) {
                sig[strcspn(sig, "\r\n")] = 0;
                if (strlen(sig) == 0) continue;
                if (strncmp(live_txt_content, sig, strlen(sig)) == 0) {
                    printf("[+] Signature match: %s\n", sig);
                    found = 1;
                    break;
                }
            }
            if (!found) {
                printf("[!] No signature match for %s, skipping scanning\n", live_txt_content);
                continue;
            }
        }

        char url[1024];
        if (snprintf(url, sizeof(url), "https://%s", live_txt_content)
            >= (int)sizeof(url)) {
            fprintf(stderr, "[-] URL too long for %s\n", live_txt_content);
            continue;
        }

        char nuclei_out[4096];
        if (snprintf(nuclei_out, sizeof(nuclei_out), "%s/nuclei.txt", hostdir)
            >= (int)sizeof(nuclei_out)) {
            fprintf(stderr, "[-] nuclei_out path too long\n");
            continue;
        }

        int rc;

        if (g.sitescan) {
            /* ---- 1. gobuster dir ---- */
            char gobuster_out[4096];
            if (snprintf(gobuster_out, sizeof(gobuster_out),
                         "%s/gobuster.txt", hostdir) >= (int)sizeof(gobuster_out)) {
                fprintf(stderr, "[-] gobuster_out path too long\n");
                continue;
            }

            char *gb_args[] = {
                "gobuster", "dir",
                "-u", url,
                "-w", (char *)wl,
                "-q",
                "-o", gobuster_out,
                NULL
            };
            rc = run_tool(gb_args);
            if (rc != 0)
                printf("[!] gobuster failed on %s with code %d\n", live_txt_content, rc);

            /* ---- 2. build general nuclei target list ---- */
            char targets[4096];
            if (snprintf(targets, sizeof(targets),
                         "%s/nuclei_targets.txt", hostdir)
                >= (int)sizeof(targets)) {
                fprintf(stderr, "[-] targets path too long\n");
                continue;
            }

            FILE *nt = fopen(targets, "w");
            if (nt) {
                fprintf(nt, "%s\n", url);

                FILE *gb = fopen(gobuster_out, "r");
                if (gb) {
                    char line[1024];
                    while (fgets(line, sizeof(line), gb)) {
                        char *p = line;
                        while (*p == ' ' || *p == '\t') p++;
                        if (*p != '/') continue;

                        char *end = p + strlen(p);
                        while (end > p && (end[-1] == '\n' || end[-1] == '\r' ||
                                           end[-1] == ' '  || end[-1] == '\t'))
                            *--end = '\0';
                        if (end == p) continue;

                        char *space = strchr(p, ' ');
                        if (space) *space = '\0';

                        fprintf(nt, "https://%s%s\n", live_txt_content, p);
                    }
                    fclose(gb);
                } else {
                    printf("[!] Could not open gobuster output %s\n", gobuster_out);
                }
                fclose(nt);
            } else {
                printf("[!] Could not create nuclei targets file %s\n", targets);
            }

            /* ---- 3. General nuclei across ALL targets (no -dast) ---- */
            char *nuclei_args[] = {
                "nuclei",
                "-l", targets,
                "-o", nuclei_out,
                "-silent",
                "-tags", "xss,sqli,ssrf,lfi,rce,redirect,exposure,"
                         "misconfig,auth-bypass,default-login",
                "-severity", "critical,high,medium,low",
                "-type", "http",
                "-etags", "dos,intrusive",
                "-c", "50",
                "-timeout", "5",
                "-retries", "1",
                NULL
            };
            rc = run_tool(nuclei_args);
            if (rc != 0)
                printf("[!] general nuclei failed on %s with code %d\n", live_txt_content, rc);

            /* ---- 4. Per-URL deep pass: XSS scan + param nuclei ---- */
            FILE *tf = fopen(targets, "r");
            if (!tf) {
                printf("[!] Cannot reopen %s for per-target loop\n", targets);
            } else {
                char tline[1024];
                while (fgets(tline, sizeof(tline), tf)) {
                    tline[strcspn(tline, "\r\n")] = 0;
                    if (strlen(tline) == 0) continue;

                    char subname[256];
                    url_to_dirname(tline, subname, sizeof(subname));

                    char subdir[4096];
                    if (snprintf(subdir, sizeof(subdir), "%s/%s", hostdir, subname)
                        >= (int)sizeof(subdir)) {
                        fprintf(stderr, "[-] subdir path too long for %s\n", tline);
                        continue;
                    }

                    if (mkdir(subdir, 0755) != 0 && errno != EEXIST) {
                        perror("mkdir subdir");
                        continue;
                    }

                    printf("[*] Deep scan: %s -> %s\n", tline, subdir);

                    /* 4a. per-URL general nuclei (quick single-target run) */
                    char sub_nuclei[4096];
                    if (snprintf(sub_nuclei, sizeof(sub_nuclei),
                                 "%s/nuclei.txt", subdir) >= (int)sizeof(sub_nuclei)) {
                        fprintf(stderr, "[-] sub_nuclei path too long\n");
                        continue;
                    }

                    char *sub_args[] = {
                        "nuclei",
                        "-u", tline,
                        "-o", sub_nuclei,
                        "-silent",
                        "-tags", "xss,sqli,ssrf,lfi,rce,redirect,exposure,"
                                 "misconfig,auth-bypass,default-login",
                        "-severity", "critical,high,medium,low",
                        "-type", "http",
                        "-etags", "dos,intrusive",
                        "-timeout", "5",
                        "-retries", "1",
                        NULL
                    };
                    rc = run_tool(sub_args);
                    if (rc != 0)
                        printf("[!] per-URL nuclei failed on %s with code %d\n",
                               tline, rc);
                    
                    hdr_args.host = target
                    hdr_args.outdir = hostdir;

                    gq_args.url = tline;
                    gq_args.path = subdir;
                    gq_args.report_dir = hostdir;

                    pthread_create(&thread[1], NULL, ghostquery_run, &gq_args);
                    pthread_create(&thread[2], NULL, header_scan, &hdr_args);
            
                    ghostquery_full(tline, subdir, hostdir);
                }
                fclose(tf);
            }

        } else {

            /* General nuclei on the bare URL (no -dast) */
            char *nuclei_args[] = {
                "nuclei",
                "-u", target_url,
                "-o", nuclei_out,
                "-silent",
                "-tags", "misconfig,auth-bypass,default-login",
                "-severity", "critical,high,medium,low",
                "-type", "http",
                "-etags", "dos,intrusive",
                "-timeout", "5",
                "-retries", "1",
                NULL
            };
            rc = run_tool(nuclei_args);
            if (rc != 0)
                printf("[!] nuclei failed on %s with code %d\n", live_txt_content, rc);

            /* XSS scanner finds params on target_url */
            char *xss_args[] = {
                "python3", "ghostquery/xss/xss.py",
                target_url,
                hostdir,
                NULL
            };
            int xrc = run_tool(xss_args);
            if (xrc != 0)
                printf("[!] xss pipeline failed on %s with code %d\n", live_txt_content, xrc);

            hdr_args.host = target
            hdr_args.outdir = hostdir;

            gq_args.url = target_url;
            gq_args.path = hostdir;
            gq_args.report_dir = hostdir;

            pthread_create(&thread[1], NULL, ghostquery_run, &gq_args);
            pthread_create(&thread[2], NULL, header_scan, &hdr_args);
            
        }
    }

    if (sg) fclose(sg);
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


void run(char *url) {
    printf("\n========================================\n");
    printf("  VectorOps — Automated Pentest Pipeline\n");
    printf("  Target : %s\n", g.domain);
    printf("  Output : %s\n", g.dir);
    printf("========================================\n\n");
    if (g.proxy)
        start_proxies();

    if (!g.urlscan)          /* --scan-url: main pre-seeds live.txt */
        subdomain();

    scanning(url);

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

            char target[512];
            snprintf(target, sizeof(target), "https://%s", entry->d_name);
            request r = {0};
            if (http_send_post(&r, target, false, NULL, false, NULL) < 0) {
                snprintf(target, sizeof(target), "http://%s", entry->d_name);
                if (http_send_post(&r, target, false, NULL, false, NULL) < 0) continue;
            }

            FILE *fp = fopen(r.filename, "r");
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

    // todo anal; from rust 
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