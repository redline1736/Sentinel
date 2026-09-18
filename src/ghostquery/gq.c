#define _DEFAULT_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <ctype.h>
#include <curl/curl.h>
#include <fcntl.h>
#include <dirent.h>

#include "../util/util.h"
#include "../prox/prox.h"
#include "../chrome/chrome.h"
#include "../glassworm/http/http.h"
#include "../global.h"
#include "gq.h"

/* ============================================================================
 * Constants
 * ============================================================================ */

#define MAX_URL_LEN     2048
#define MAX_PARAM_LEN   256
#define MAX_PAYLOAD_LEN 4096
#define CHROME_PORT     9222
#define CURL_TIMEOUT    10
#define CURL_CONNECT_TIMEOUT 5

/* ============================================================================
 * Safe Path Utilities
 * ============================================================================ */

static int is_safe_path(const char *path) {
    if (!path || *path == '\0')
        return 0;
    
    if (path[0] == '/')
        return 0;
    
    if (strstr(path, "..") != NULL)
        return 0;
    
    if (path[0] == '.')
        return 0;
    
    return 1;
}

static int create_unique_filename(char *dst, size_t dstsz, const char *prefix) {
    struct timespec ts;
    static unsigned int counter = 0;
    unsigned int my_counter;
    
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        time_t t = time(NULL);
        my_counter = __sync_fetch_and_add(&counter, 1);
        return snprintf(dst, dstsz, "%s_%d_%ld_%u.txt", 
                        prefix, getpid(), (long)t, my_counter);
    }
    
    my_counter = __sync_fetch_and_add(&counter, 1);
    return snprintf(dst, dstsz, "%s_%d_%ld_%ld_%u.txt",
                    prefix, getpid(), (long)ts.tv_sec, (long)ts.tv_nsec, my_counter);
}

static FILE *safe_fopen_exclusive(const char *filename, const char *mode) {
    if (!is_safe_path(filename)) {
        errno = EPERM;
        return NULL;
    }
    
    int flags = O_WRONLY | O_CREAT | O_EXCL;
    int fd = open(filename, flags, 0600);
    if (fd < 0)
        return NULL;
    
    FILE *fp = fdopen(fd, mode);
    if (!fp) {
        close(fd);
        unlink(filename);
        return NULL;
    }
    
    return fp;
}

static int safe_remove(const char *filename) {
    if (!is_safe_path(filename))
        return -1;
    return remove(filename);
}

/* ============================================================================
 * String Utilities
 * ============================================================================ */

static void strip_newline(char *s) {
    if (!s) return;
    size_t len = strlen(s);
    while (len > 0 && (s[len - 1] == '\n' || s[len - 1] == '\r'))
        s[--len] = '\0';
}

static int url_append_param(char *dst, size_t dstsz, const char *url,
                            const char *param, const char *value) {
    if (!dst || !url || !param || !value)
        return 0;
    
    const char *sep = strchr(url, '?') ? "&" : "?";
    int n = snprintf(dst, dstsz, "%s%s%s=%s", url, sep, param, value);
    
    if (n < 0 || (size_t)n >= dstsz) {
        fprintf(stderr, "Warning: URL construction truncated (needed %d bytes, had %zu)\n",
                n, dstsz);
        return 0;
    }
    return 1;
}

static int ensure_directory(const char *path) {
    if (!path) return -1;
    
    struct stat st;
    if (stat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode))
            return 0;
        errno = ENOTDIR;
        return -1;
    }
    
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "mkdir -p %s 2>/dev/null", path);
    return system(tmp);
}

/* ============================================================================
 * Libcurl Write Callback
 * ============================================================================ */

static size_t write_file(void *ptr, size_t size, size_t nmemb, void *stream) {
    return fwrite(ptr, size, nmemb, (FILE *)stream);
}

/* ============================================================================
 * HTTP Request Sender
 * ============================================================================ */

static int gq_http_send(request *r, const char *url) {
    CURL *curl;
    CURLcode result;
    FILE *fp;
    char filename[128];
    const char *proxy = NULL;
    long http_code = 0;
    
    if (!r || !url) {
        fprintf(stderr, "gq_http_send: invalid arguments\n");
        return 0;
    }
    
    r->code = -1;
    r->filename[0] = '\0';
    
    if (g.proxy) {
        proxy = proxy_get_socks();
        if (!proxy)
            return 0;
    }
    
    if (create_unique_filename(filename, sizeof(filename), "curl") <= 0) {
        fprintf(stderr, "gq_http_send: failed to create filename\n");
        return 0;
    }
    
    fp = safe_fopen_exclusive(filename, "wb");
    if (!fp) {
        perror("gq_http_send: fopen");
        return 0;
    }
    
    snprintf(r->filename, sizeof(r->filename), "%s", filename);
    
    curl = curl_easy_init();
    if (!curl) {
        fclose(fp);
        safe_remove(filename);
        r->filename[0] = '\0';
        fprintf(stderr, "gq_http_send: curl_easy_init failed\n");
        return 0;
    }
    
    if (proxy)
        curl_easy_setopt(curl, CURLOPT_PROXY, proxy);
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_file);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, CURL_TIMEOUT);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, CURL_CONNECT_TIMEOUT);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "ghostquery/1.0");
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    
    result = curl_easy_perform(curl);
    
    fclose(fp);
    
    if (result == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        r->code = (int)http_code;
    } else {
        fprintf(stderr, "Request failed for %s: %s\n", url, curl_easy_strerror(result));
        safe_remove(filename);
        r->filename[0] = '\0';
    }
    
    curl_easy_cleanup(curl);
    return result == CURLE_OK ? 1 : 0;
}

/* ============================================================================
 * Find Reflecting Parameters
 * ============================================================================ */

int find_param_reflecting(char *url, char *path) {
    int size;
    int allocated;
    char full_url[MAX_URL_LEN];
    char buffer[MAX_PARAM_LEN];
    request *r;
    FILE *fp;
    FILE *fptr;
    int i = 0;
    char *param_file = "ghostquery/params.txt";
    char output_file[256];
    snprintf(output_file, sizeof(output_file), "%s/valid_params.txt", path);

    char *output_dir = "ghostquery/xss";
    
    if (!url) {
        fprintf(stderr, "find_param_reflecting: url is NULL\n");
        return 1;
    }
    
    if (ensure_directory(output_dir) != 0) {
        fprintf(stderr, "find_param_reflecting: failed to create %s\n", output_dir);
        return 1;
    }
    
    size = line_count(param_file);
    if (size <= 0) {
        fprintf(stderr, "find_param_reflecting: %s is empty or missing\n", param_file);
        return 1;
    }
    
    allocated = size + 1;
    r = calloc((size_t)allocated, sizeof(request));
    if (!r) {
        fprintf(stderr, "find_param_reflecting: memory allocation failed\n");
        return 1;
    }
    
    fp = fopen(param_file, "r");
    if (!fp) {
        fprintf(stderr, "find_param_reflecting: error opening %s\n", param_file);
        free(r);
        return 1;
    }
    
    fptr = fopen(output_file, "w");
    if (!fptr) {
        fprintf(stderr, "find_param_reflecting: error opening %s\n", output_file);
        fclose(fp);
        free(r);
        return 1;
    }
    
    while (fgets(buffer, sizeof(buffer), fp)) {
        strip_newline(buffer);
        
        if (buffer[0] == '\0' || buffer[0] == '#')
            continue;
        
        if (i >= allocated) {
            fprintf(stderr, "find_param_reflecting: warning - too many params, stopping at %d\n", i);
            break;
        }
        
        if (!url_append_param(full_url, sizeof(full_url), url, buffer, "asdasda")) {
            fprintf(stderr, "find_param_reflecting: warning - URL too long for param '%s'\n", buffer);
            continue;
        }
        
        if (gq_http_send(&r[i], full_url) && r[i].code == 200) {
            char line_buf[2048];
            int found = 0;
            FILE *fpr = fopen(r[i].filename, "r");
            
            if (!fpr) {
                fprintf(stderr, "find_param_reflecting: warning - cannot read %s\n", r[i].filename);
                safe_remove(r[i].filename);
                i++;
                continue;
            }
            
            while (fgets(line_buf, sizeof(line_buf), fpr)) {
                if (strstr(line_buf, "asdasda")) {
                    found = 1;
                    break;
                }
            }
            fclose(fpr);
            
            if (found) {
                fprintf(fptr, "%s\n", buffer);
                fflush(fptr);
                printf("find_param_reflecting: found reflecting param: %s\n", buffer);
            }
        }
        
        if (r[i].filename[0] != '\0') {
            safe_remove(r[i].filename);
            r[i].filename[0] = '\0';
        }
        i++;
    }
    
    fclose(fp);
    fclose(fptr);
    free(r);
    
    printf("find_param_reflecting: results written to %s\n", output_file);
    return 0;
}

void xss_generated(char *url, char *path) {
    int nparams;
    int npayloads;
    char full_url[MAX_URL_LEN];
    char param[MAX_PARAM_LEN];
    char payload[MAX_PAYLOAD_LEN];
    char param_file[256];
    snprintf(param_file, sizeof(param_file), "%s/valid_params.txt", path);
    char *payload_file = "ghostquery/xss/payloads.txt";
    char valid_payloads_path[256];
    FILE *fp, *ex, *found;
    int total_tested = 0, total_confirmed = 0;
    int chrome_initialized = 0;
    
    if (!url || !path) {
        fprintf(stderr, "[xss_generated] invalid arguments\n");
        return;
    }
    
    nparams = line_count(param_file);
    npayloads = line_count(payload_file);
    
    if (nparams <= 0 || npayloads <= 0) {
        fprintf(stderr, "[xss_generated] %s or %s empty/missing\n", 
                param_file, payload_file);
        return;
    }
    
    if (ensure_directory(path) != 0) {
        fprintf(stderr, "[xss_generated] failed to create %s\n", path);
        return;
    }
    
    snprintf(valid_payloads_path, sizeof(valid_payloads_path),
             "%s/valid_payloads.txt", path);
    
    fp = fopen(param_file, "r");
    if (!fp) {
        fprintf(stderr, "[xss_generated] error opening %s\n", param_file);
        return;
    }
    
    found = fopen(valid_payloads_path, "w");
    if (!found) {
        fprintf(stderr, "[xss_generated] error opening %s for writing\n", 
                valid_payloads_path);
        fclose(fp);
        return;
    }
    
    printf("[xss_generated] Initializing Chrome (port %d)...\n", CHROME_PORT);
    if (init_chrome(CHROME_PORT) == 0) {
        chrome_initialized = 1;
        printf("[xss_generated] Chrome initialized successfully\n");
    } else {
        printf("[xss_generated] Chrome init failed - using HTTP-only detection\n");
    }
    
    while (fgets(param, sizeof(param), fp)) {
        strip_newline(param);
        if (param[0] == '\0' || param[0] == '#')
            continue;
        
        ex = fopen(payload_file, "r");
        if (!ex) {
            fprintf(stderr, "[xss_generated] error opening %s\n", payload_file);
            break;
        }
        
        while (fgets(payload, sizeof(payload), ex)) {
            char *enc;
            int interaction_type;
            
            strip_newline(payload);
            if (payload[0] == '\0' || payload[0] == '#')
                continue;
            
            total_tested++;
            
            enc = curl_easy_escape(NULL, payload, 0);
            if (!enc) {
                fprintf(stderr, "[xss_generated] curl_easy_escape failed for payload\n");
                continue;
            }
            
            if (!url_append_param(full_url, sizeof(full_url), url, param, enc)) {
                curl_free(enc);
                continue;
            }
            
            interaction_type = detect_payload_event_type(payload);
            
            printf("[xss_generated] Testing: %s=%s (event_type=%d)\n",
                   param, payload, interaction_type);
            
            if (chrome_initialized) {
                if (navigate_to(full_url) == -1) {
                    curl_free(enc);
                    continue;
                }
                usleep(300000);
                
                if (detect_xss(50, interaction_type) == 0) {
                    fprintf(found, "%s -> %s\n", param, payload);
                    fflush(found);
                    total_confirmed++;
                    printf("[xss_generated] *** XSS CONFIRMED: %s=%s ***\n", 
                           param, payload);
                } else {
                    printf("[xss_generated] No trigger for: %s=%s\n", param, payload);
                }
            } else {
                /* HTTP-only detection fallback */
                request r = {0};
                if (gq_http_send(&r, full_url) && r.code == 200) {
                    char *resp = malloc(8192);
                    if (resp) {
                        FILE *fpr = fopen(r.filename, "r");
                        if (fpr) {
                            size_t bytes = fread(resp, 1, 8191, fpr);
                            resp[bytes] = '\0';
                            if (strstr(resp, payload)) {
                                fprintf(found, "%s -> %s\n", param, payload);
                                fflush(found);
                                total_confirmed++;
                                printf("[xss_generated] *** XSS CONFIRMED (HTTP): %s=%s ***\n", 
                                       param, payload);
                            }
                            fclose(fpr);
                        }
                        free(resp);
                    }
                    safe_remove(r.filename);
                }
            }
            
            curl_free(enc);
        }
        fclose(ex);
    }
    
    fclose(fp);
    fclose(found);
    
    if (chrome_initialized) {
        close_chrome();
    }
    
    printf("[xss_generated] Done. Tested %d payloads, confirmed %d XSS.\n",
           total_tested, total_confirmed);
    printf("[xss_generated] Results written to %s\n", valid_payloads_path);
}

void xss_custom(char *url, char *path) {
    int nparams;
    int npayloads;
    char full_url[MAX_URL_LEN];
    char param[MAX_PARAM_LEN];
    char payload[MAX_PAYLOAD_LEN];
    char param_file[256];
    snprintf(param_file, sizeof(param_file), "%s/valid_params.txt", path);
    char *payload_file = "ghostquery/xss/custom.txt";
    char valid_payloads_path[256];
    FILE *fp, *ex, *found;
    int total_tested = 0, total_confirmed = 0;
    int chrome_initialized = 0;
    
    if (!url || !path) {
        fprintf(stderr, "[xss_custom] invalid arguments\n");
        return;
    }
    
    nparams = line_count(param_file);
    npayloads = line_count(payload_file);
    
    if (nparams <= 0 || npayloads <= 0) {
        fprintf(stderr, "[xss_custom] %s or %s empty/missing\n", 
                param_file, payload_file);
        return;
    }
    
    if (ensure_directory(path) != 0) {
        fprintf(stderr, "[xss_custom] failed to create %s\n", path);
        return;
    }
    
    snprintf(valid_payloads_path, sizeof(valid_payloads_path),
             "%s/valid_payloads.txt", path);
    
    fp = fopen(param_file, "r");
    if (!fp) {
        fprintf(stderr, "[xss_custom] error opening %s\n", param_file);
        return;
    }
    
    found = fopen(valid_payloads_path, "w");
    if (!found) {
        fprintf(stderr, "[xss_custom] error opening %s for writing\n", 
                valid_payloads_path);
        fclose(fp);
        return;
    }
    
    printf("[xss_custom] Initializing Chrome (port %d)...\n", CHROME_PORT);
    if (init_chrome(CHROME_PORT) == 0) {
        chrome_initialized = 1;
        printf("[xss_custom] Chrome initialized successfully\n");
    } else {
        printf("[xss_custom] Chrome init failed - using HTTP-only detection\n");
    }
    
    while (fgets(param, sizeof(param), fp)) {
        strip_newline(param);
        if (param[0] == '\0' || param[0] == '#')
            continue;
        
        ex = fopen(payload_file, "r");
        if (!ex) {
            fprintf(stderr, "[xss_custom] error opening %s\n", payload_file);
            break;
        }
        
        while (fgets(payload, sizeof(payload), ex)) {
            char *enc;
            int interaction_type;
            
            strip_newline(payload);
            if (payload[0] == '\0' || payload[0] == '#')
                continue;
            
            total_tested++;
            
            enc = curl_easy_escape(NULL, payload, 0);
            if (!enc) {
                fprintf(stderr, "[xss_custom] curl_easy_escape failed for payload\n");
                continue;
            }
            
            if (!url_append_param(full_url, sizeof(full_url), url, param, enc)) {
                curl_free(enc);
                continue;
            }
            
            interaction_type = detect_payload_event_type(payload);
            
            printf("[xss_custom] Testing: %s=%s (event_type=%d)\n",
                   param, payload, interaction_type);
            
            if (chrome_initialized) {
                if (navigate_to(full_url) == -1) {
                    curl_free(enc);
                    continue;
                }
                usleep(300000);
                
                if (detect_xss(50, interaction_type) == 0) {
                    fprintf(found, "%s -> %s\n", param, payload);
                    fflush(found);
                    total_confirmed++;
                    printf("[xss_custom] *** XSS CONFIRMED: %s=%s ***\n", 
                           param, payload);
                } else {
                    printf("[xss_custom] No trigger for: %s=%s\n", param, payload);
                }
            } else {
                /* HTTP-only detection fallback */
                request r = {0};
                if (gq_http_send(&r, full_url) && r.code == 200) {
                    char *resp = malloc(8192);
                    if (resp) {
                        FILE *fpr = fopen(r.filename, "r");
                        if (fpr) {
                            size_t bytes = fread(resp, 1, 8191, fpr);
                            resp[bytes] = '\0';
                            if (strstr(resp, payload)) {
                                fprintf(found, "%s -> %s\n", param, payload);
                                fflush(found);
                                total_confirmed++;
                                printf("[xss_custom] *** XSS CONFIRMED (HTTP): %s=%s ***\n", 
                                       param, payload);
                            }
                            fclose(fpr);
                        }
                        free(resp);
                    }
                    safe_remove(r.filename);
                }
            }
            
            curl_free(enc);
        }
        fclose(ex);
    }
    
    fclose(fp);
    fclose(found);
    
    if (chrome_initialized) {
        close_chrome();
    }
    
    printf("[xss_custom] Done. Tested %d payloads, confirmed %d XSS.\n",
           total_tested, total_confirmed);
    printf("[xss_custom] Results written to %s\n", valid_payloads_path);
}

/* ============================================================================
 * Main XSS Run Entry Point
 * ============================================================================ */

int file_exists(const char *filename) {
    return access(filename, F_OK) == 0;
}

int xss_run(char *url, char *path) {
    if (!url || !path) {
        fprintf(stderr, "xss_run: invalid arguments\n");
        return 1;
    }
    
    printf("[xss_run] Generating XSS payloads...\n");
    char *payloads = "ghostquery/xss/payloads.txt";

    if (file_exists(payloads)) {
        printf("[xss_run] Using existing valid parameters file: %s\n", payloads);
    } else {
        if (system("python3 ghostquery/xss/xss.py") != 0) {
            fprintf(stderr, "warning: xss.py exited with an error (continuing anyway)\n");
        }
    }
    
    printf("[xss_run] Finding reflecting parameters...\n");
    if (find_param_reflecting(url, path) != 0) {
        fprintf(stderr, "warning: find_param_reflecting failed\n");
    }
    
    printf("[xss_run] Running generated payload scan...\n");
    xss_generated(url, path);
    
    printf("[xss_run] Running custom payload scan...\n");
    xss_custom(url, path);
    
    printf("[xss_run] XSS scanning complete.\n");
    return 0;
}

int nuclei_run(char *url, char *path) {
    if (!url || !path) {
        fprintf(stderr, "[nuclei_run] invalid arguments\n");
        return 1;
    }

    char param_file[4096];
    char targets_path[4096];
    char nuclei_out[4096];
    char nuclei_merged[4096];

    if (snprintf(param_file, sizeof(param_file),
                 "%s/valid_params.txt", path) >= (int)sizeof(param_file) ||
        snprintf(targets_path, sizeof(targets_path),
                 "%s/nuclei_param_targets.txt", path) >= (int)sizeof(targets_path) ||
        snprintf(nuclei_out, sizeof(nuclei_out),
                 "%s/nuclei_params.txt", path) >= (int)sizeof(nuclei_out) ||
        snprintf(nuclei_merged, sizeof(nuclei_merged),
                 "%s/nuclei.txt", path) >= (int)sizeof(nuclei_merged)) {
        fprintf(stderr, "[nuclei_run] path too long\n");
        return 1;
    }

    FILE *fp = fopen(param_file, "r");
    if (!fp) {
        printf("[nuclei_run] %s not found — skipping\n", param_file);
        return 1;
    }

    /* Build a target list: one line per reflecting param, with a real value */
    FILE *tl = fopen(targets_path, "w");
    if (!tl) {
        fprintf(stderr, "[nuclei_run] cannot write %s\n", targets_path);
        fclose(fp);
        return 1;
    }

    char param[MAX_PARAM_LEN];
    int ntargets = 0;
    while (fgets(param, sizeof(param), fp)) {
        size_t l = strlen(param);
        while (l && (param[l-1] == '\n' || param[l-1] == '\r'))
            param[--l] = '\0';
        if (l == 0 || param[0] == '#')
            continue;

        /* Proper "?param=test" shape so DAST and standard templates work */
        fprintf(tl, "%s%c%s=test\n",
                url, strchr(url, '?') ? '&' : '?', param);
        ntargets++;
    }
    fclose(fp);
    fclose(tl);

    if (ntargets == 0) {
        printf("[nuclei_run] no reflecting params — nothing to test\n");
        return 0;
    }

    printf("[nuclei_run] running nuclei on %d param URLs\n", ntargets);

    char *nuclei_args[] = {
        "nuclei",
        "-l", targets_path,
        "-o", nuclei_out,
        "-silent",
        "-tags", "xss,sqli,ssrf,lfi,rce,redirect,injection,open-redirect",
        "-severity", "critical,high,medium,low",
        "-type", "http",
        "-etags", "dos,intrusive",
        "-c", "50",
        "-timeout", "5",
        "-retries", "1",
        "-dast",
        NULL
    };

    int rc = run_tool(nuclei_args);
    if (rc != 0)
        printf("[!] nuclei failed on %s with code %d\n", url, rc);

    /* Merge into nuclei.txt so analyze() sees the findings */
    FILE *in  = fopen(nuclei_out, "r");
    FILE *out = fopen(nuclei_merged, "a");   /* append, don't clobber general phase */
    if (in && out) {
        char line[4096];
        while (fgets(line, sizeof(line), in))
            fputs(line, out);
    }
    if (in)  fclose(in);
    if (out) fclose(out);

    return 0;
}

/* ============================================================================
 * SQL Injection Run (Placeholder)
 * ============================================================================ */

int sql_run(void) {
    fprintf(stderr, "sql_run: not implemented yet\n");
    return 0;
}