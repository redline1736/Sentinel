#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <ctype.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <curl/curl.h>

#include "prox.h"
#include "../global.h"

#define MAX_TOR_PROXIES      5
#define SOCKS_BASE_PORT      9050
#define TOR_START_TIMEOUT    25
#define MAX_LIST_LINES       64
#define MAX_READY_PROXIES    32
#define MIN_REQUIRED_PROXIES 5
#define MAX_PROBE_THREADS    16

#define CONF_DIR      "darkshield/proxy/tor"
#define CUSTOM_DIR    "darkshield/proxy/custom"
#define BUNDLED_LIST  "darkshield/proxy/custom/proxy.txt"
#define SCRAPE_CACHE  "darkshield/proxy/custom/proxyscrape.txt"

#define SCRAPE_V4_URL \
    "https://api.proxyscrape.com/v4/free-proxy-list/get" \
    "?request=display_proxies&proxy_format=protocolipport&format=text" \
    "&anonymity=elite&timeout=10000"

#define SCRAPE_V2_URL \
    "https://api.proxyscrape.com/v2/?request=displayproxies" \
    "&protocol=socks5&timeout=10000&country=all&ssl=all&anonymity=elite"

#define PROBE_URL "http://www.gstatic.com/generate_204"

/* ---------------- pool state ---------------- */

typedef struct {
    char  uri[320];   /* canonical URI: socks5h://127.0.0.1:9050, http://h:p, ... */
    pid_t pid;        /* Tor child pid (0 = external proxy, no child) */
    bool  ready;
    bool  burned;
    bool  current;
} pool_proxy;

static pool_proxy      pool[MAX_READY_PROXIES];
static int             pool_count = 0;
static int             pool_mode  = PROXY_NONE;
static pthread_mutex_t pool_lock  = PTHREAD_MUTEX_INITIALIZER;

static void lock_acquire(void) { pthread_mutex_lock(&pool_lock); }
static void lock_release(void) { pthread_mutex_unlock(&pool_lock); }

/* ---------------- small helpers ---------------- */

static void ensure_dir(const char *path) {
    if (mkdir(path, 0755) != 0 && errno != EEXIST)
        fprintf(stderr, "[-] mkdir %s: %s\n", path, strerror(errno));
}

static void ensure_conf_dirs(void) {
    ensure_dir("darkshield");
    ensure_dir("darkshield/proxy");
    ensure_dir(CONF_DIR);
    ensure_dir(CUSTOM_DIR);
}

/* Parse one list line into a canonical proxy URI.
 * Accepts:  host:port | http://host:port | https://host:port
 *           socks4:// | socks4a:// | socks5:// | socks5h://
 * Bare host:port lines default to socks5 (matches the bundled list). */
static bool parse_proxy_line(const char *line, char *out, size_t outsz) {
    const char *p = line;
    char scheme[16] = "socks5";
    char host[256] = "";
    char port[8] = "";
    char buf[320];

    while (isspace((unsigned char)*p))
        p++;
    if (*p == '\0' || *p == '#')
        return false;

    size_t len = strlen(p);
    while (len > 0 && isspace((unsigned char)p[len - 1]))
        len--;
    if (len == 0 || len >= sizeof(buf))
        return false;
    memcpy(buf, p, len);
    buf[len] = '\0';

    /* optional scheme prefix */
    const char *rest = buf;
    const char *sep = strstr(buf, "://");
    if (sep) {
        size_t slen = (size_t)(sep - buf);
        if (slen == 0 || slen >= sizeof(scheme))
            return false;
        memcpy(scheme, buf, slen);
        scheme[slen] = '\0';
        rest = sep + 3;
        if (strcmp(scheme, "http") && strcmp(scheme, "https") &&
            strcmp(scheme, "socks4") && strcmp(scheme, "socks4a") &&
            strcmp(scheme, "socks5") && strcmp(scheme, "socks5h"))
            return false;
        if (strcmp(scheme, "https") == 0)
            strcpy(scheme, "http");   /* https:// entries act as HTTP CONNECT */
    }

    const char *colon = strrchr(rest, ':');
    if (!colon || colon == rest)
        return false;
    size_t hlen = (size_t)(colon - rest);
    if (hlen == 0 || hlen >= sizeof(host))
        return false;
    memcpy(host, rest, hlen);
    host[hlen] = '\0';

    if (strlen(colon + 1) == 0 || strlen(colon + 1) >= sizeof(port))
        return false;
    snprintf(port, sizeof(port), "%s", colon + 1);
    for (const char *c = port; *c; c++)
        if (!isdigit((unsigned char)*c))
            return false;
    int pnum = atoi(port);
    if (pnum < 1 || pnum > 65535)
        return false;

    snprintf(out, outsz, "%s://%s:%s", scheme, host, port);
    return true;
}

/* ---------------- connectivity probing ---------------- */

static size_t discard_cb(void *ptr, size_t size, size_t nmemb, void *userdata) {
    (void)ptr; (void)userdata;
    return size * nmemb;
}

/* Connectivity probe through a proxy URI (expects HTTP 204). */
static bool proxy_probe(const char *uri) {
    CURL *curl = curl_easy_init();
    if (!curl)
        return false;

    long code = 0;
    curl_easy_setopt(curl, CURLOPT_URL, PROBE_URL);
    curl_easy_setopt(curl, CURLOPT_PROXY, uri);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, discard_cb);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Sentinel-scan/1.0");
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);   /* thread-safe */

    CURLcode res = curl_easy_perform(curl);
    if (res == CURLE_OK)
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_easy_cleanup(curl);

    return res == CURLE_OK && code == 204;
}

/* ---------------- Tor pool ---------------- */

static int tor_spawn_one(int idx) {
    int port = SOCKS_BASE_PORT + idx;

    char conf[512], data[512], logf[512];
    snprintf(conf, sizeof(conf), "%s/tor_%d.conf", CONF_DIR, port);
    snprintf(data, sizeof(data), "%s/data_%d", CONF_DIR, port);
    snprintf(logf, sizeof(logf), "%s/tor_%d.log", CONF_DIR, port);

    FILE *f = fopen(conf, "w");
    if (!f) {
        fprintf(stderr, "[-] cannot write %s: %s\n", conf, strerror(errno));
        return -1;
    }
    fprintf(f, "SocksPort 127.0.0.1:%d\n", port);
    fprintf(f, "SocksPolicy accept 127.0.0.1\n");
    fprintf(f, "SocksPolicy reject *\n");
    fprintf(f, "DataDirectory %s\n", data);
    fprintf(f, "Log notice file %s\n", logf);
    fprintf(f, "ClientOnly 1\n");
    fprintf(f, "CircuitBuildTimeout 30\n");
    fprintf(f, "LearnCircuitBuildTimeout 0\n");
    fclose(f);

    pid_t pid = fork();
    if (pid < 0)
        return -1;

    if (pid == 0) {
        setsid();
        int devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            dup2(devnull, STDIN_FILENO);
            close(devnull);
        }
        int lfd = open(logf, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (lfd >= 0) {
            dup2(lfd, STDOUT_FILENO);
            dup2(lfd, STDERR_FILENO);
            close(lfd);
        }
        execlp("tor", "tor", "-f", conf, (char *)NULL);
        _exit(127);
    }
    return pid;
}

static int start_tor_pool(void) {
    ensure_conf_dirs();

    for (int i = 0; i < MAX_TOR_PROXIES; i++) {
        snprintf(pool[i].uri, sizeof(pool[i].uri),
                 "socks5h://127.0.0.1:%d", SOCKS_BASE_PORT + i);
        pool[i].pid     = tor_spawn_one(i);
        pool[i].ready   = false;
        pool[i].burned  = false;
        pool[i].current = false;
    }
    pool_count = MAX_TOR_PROXIES;

    /* Wait for the SOCKS ports to come up (Tor bootstrap). */
    time_t start = time(NULL);
    while (time(NULL) - start < TOR_START_TIMEOUT) {
        bool all_ready = true;
        for (int i = 0; i < MAX_TOR_PROXIES; i++) {
            if (pool[i].ready)
                continue;
            if (proxy_probe(pool[i].uri)) {
                pool[i].ready = true;
                printf("[+] Tor instance on %s is up\n", pool[i].uri);
            } else {
                all_ready = false;
            }
        }
        if (all_ready)
            break;
        sleep(2);
    }

    int ready_count = 0;
    for (int i = 0; i < MAX_TOR_PROXIES; i++) {
        if (!pool[i].ready) {
            pool[i].burned = true;          /* stragglers are unusable */
            continue;
        }
        if (ready_count == 0)
            pool[i].current = true;
        ready_count++;
    }

    if (ready_count == 0) {
        fprintf(stderr, "[-] No Tor instance became ready within %ds\n",
                TOR_START_TIMEOUT);
        return -1;
    }
    printf("[+] Tor pool ready: %d/%d instances\n",
           ready_count, MAX_TOR_PROXIES);
    return 0;
}

/* ---------------- ProxyScrape elite fetch ---------------- */

typedef struct {
    char  *buf;
    size_t len, cap;
} mem_buf;

static size_t write_mem(void *ptr, size_t size, size_t nmemb, void *ud) {
    mem_buf *m = ud;
    size_t n = size * nmemb;
    if (m->len + n + 1 > m->cap) {
        size_t nc = m->cap ? m->cap : 65536;
        while (nc < m->len + n + 1)
            nc *= 2;
        char *nb = realloc(m->buf, nc);
        if (!nb)
            return 0;
        m->buf = nb;
        m->cap = nc;
    }
    memcpy(m->buf + m->len, ptr, n);
    m->len += n;
    m->buf[m->len] = '\0';
    return n;
}

/* GET a text URL into *out (caller frees). 0 on success. */
static int http_get_text(const char *url, char **out) {
    mem_buf m = {0};
    CURL *curl = curl_easy_init();
    if (!curl)
        return -1;

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_mem);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &m);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Sentinel-scan/1.0");
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 3L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        free(m.buf);
        return -1;
    }
    *out = m.buf ? m.buf : strdup("");
    return 0;
}

/* Fetch elite proxies from ProxyScrape and cache them locally.
 * v4 is the current API; v2 is the legacy fallback. */
static int fetch_elite_proxies(void) {
    ensure_conf_dirs();

    char *text = NULL;
    if (http_get_text(SCRAPE_V4_URL, &text) != 0 || !text ||
        strstr(text, "<html") != NULL || strlen(text) < 20) {
        free(text);
        text = NULL;
        fprintf(stderr, "[!] ProxyScrape v4 fetch failed — trying legacy v2 endpoint\n");
        if (http_get_text(SCRAPE_V2_URL, &text) != 0 || !text ||
            strlen(text) < 20) {
            free(text);
            fprintf(stderr, "[-] ProxyScrape unreachable; use --proxy <file> instead\n");
            return -1;
        }
    }

    FILE *out = fopen(SCRAPE_CACHE, "w");
    if (!out) {
        free(text);
        return -1;
    }

    int n = 0;
    char *save = NULL;
    for (char *tok = strtok_r(text, "\n", &save);
         tok && n < MAX_LIST_LINES;
         tok = strtok_r(NULL, "\n", &save)) {
        char uri[320];
        if (parse_proxy_line(tok, uri, sizeof(uri))) {
            fprintf(out, "%s\n", uri);
            n++;
        }
    }
    fclose(out);
    free(text);

    if (n < MIN_REQUIRED_PROXIES) {
        fprintf(stderr, "[-] Only %d elite proxies returned by ProxyScrape\n", n);
        return -1;
    }
    printf("[+] Cached %d elite proxies -> %s\n", n, SCRAPE_CACHE);
    return 0;
}

/* ---------------- external list load (custom + elite) ---------------- */

typedef struct {
    const char *uri;
    bool ok;
} probe_job;

static void *probe_worker(void *arg) {
    probe_job *j = arg;
    j->ok = proxy_probe(j->uri);
    return NULL;
}

/* Load + health-check an external proxy list into the pool.
 * Requires >= MIN_REQUIRED_PROXIES parseable lines. */
static int load_external_list(const char *list_path, const char *display) {
    FILE *fp = fopen(list_path, "r");
    if (!fp) {
        fprintf(stderr, "[-] cannot open proxy list %s: %s\n",
                list_path, strerror(errno));
        return -1;
    }

    char lines[MAX_LIST_LINES][320];
    int n = 0;
    char buf[512];
    while (n < MAX_LIST_LINES && fgets(buf, sizeof(buf), fp)) {
        char uri[320];
        if (parse_proxy_line(buf, uri, sizeof(uri)))
            snprintf(lines[n++], sizeof(lines[0]), "%s", uri);
    }
    fclose(fp);

    if (n < MIN_REQUIRED_PROXIES) {
        fprintf(stderr, "[-] %s: need at least %d proxies, found %d\n",
                list_path, MIN_REQUIRED_PROXIES, n);
        return -1;
    }

    printf("[+] %s: health-checking %d proxies\n", display, n);

    probe_job jobs[MAX_LIST_LINES];
    for (int i = 0; i < n; i++) {
        jobs[i].uri = lines[i];
        jobs[i].ok  = false;
    }

    /* parallel probes, MAX_PROBE_THREADS at a time */
    for (int base = 0; base < n; base += MAX_PROBE_THREADS) {
        int batch = n - base;
        if (batch > MAX_PROBE_THREADS)
            batch = MAX_PROBE_THREADS;
        pthread_t th[MAX_PROBE_THREADS];
        int spawned = 0;
        for (int i = 0; i < batch; i++) {
            if (pthread_create(&th[i], NULL, probe_worker,
                               &jobs[base + i]) == 0)
                spawned++;
        }
        for (int i = 0; i < spawned; i++)
            pthread_join(th[i], NULL);
    }

    pool_count = 0;
    for (int i = 0; i < n && pool_count < MAX_READY_PROXIES; i++) {
        if (!jobs[i].ok)
            continue;
        snprintf(pool[pool_count].uri, sizeof(pool[0].uri), "%.319s", lines[i]);
        pool[pool_count].pid     = 0;
        pool[pool_count].ready   = true;
        pool[pool_count].burned  = false;
        pool[pool_count].current = false;
        pool_count++;
    }

    if (pool_count < 1) {
        fprintf(stderr, "[-] No usable proxies in %s (all failed health check)\n",
                list_path);
        return -1;
    }
    pool[0].current = true;
    printf("[+] %d/%d proxies healthy; current: %s\n",
           pool_count, n, pool[0].uri);
    return 0;
}

/* ---------------- lifecycle API ---------------- */

static const char *proxy_mode_name(int mode) {
    switch (mode) {
    case PROXY_TOR:    return "Tor pool";
    case PROXY_CUSTOM: return "custom list";
    case PROXY_ELITE:  return "ProxyScrape elite";
    default:           return "direct";
    }
}

/* Printed for EVERY proxy mode except PROXY_NONE — user-supplied lists
 * are third-party endpoints too, so the warning must not be skipped. */
static void print_public_disclaimer(void) {
    printf("\n[!] WARNING: proxy entries are public, third-party endpoints.\n");
    printf("[!] They are not operated by you or Sentinel, may log or tamper\n");
    printf("[!] with traffic, and can be slow, unstable, or malicious. Use\n");
    printf("[!] them only against targets you are authorized to test, and\n");
    printf("[!] never send credentials, tokens, or sensitive data through\n");
    printf("[!] them.\n\n");
}

void kill_tor_processes(void) {
    lock_acquire();
    for (int i = 0; i < MAX_READY_PROXIES; i++) {
        pid_t pid = pool[i].pid;
        if (pid <= 0)
            continue;
        pool[i].pid = 0;

        kill(pid, SIGTERM);
        for (int w = 0; w < 20; w++) {
            pid_t r = waitpid(pid, NULL, WNOHANG);
            if (r == pid || (r < 0 && errno == ECHILD))
                break;
            usleep(100000);
        }
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
    }
    lock_release();
}

void proxy_shutdown(void) {
    kill_tor_processes();
    lock_acquire();
    memset(pool, 0, sizeof(pool));
    pool_count = 0;
    pool_mode  = PROXY_NONE;
    lock_release();
}

int proxy_init(int mode, const char *list_path) {
    if (mode < PROXY_NONE || mode > PROXY_ELITE)
        return -1;

    lock_acquire();
    if (pool_mode == mode && pool_count > 0) {
        lock_release();
        return 0;
    }
    lock_release();

    proxy_shutdown();          /* switch modes: tear the old pool down */

    lock_acquire();
    pool_mode = mode;
    lock_release();

    int rc = 0;
    switch (mode) {
    case PROXY_NONE:
        return 0;              /* direct mode: pool stays empty, no wrapper */
    case PROXY_TOR:
        rc = start_tor_pool();
        break;
    case PROXY_CUSTOM:
        if (!list_path || list_path[0] == '\0') {
            fprintf(stderr, "[-] --proxy requires a list file with >= %d proxies\n",
                    MIN_REQUIRED_PROXIES);
            rc = -1;
            break;
        }
        /* User-supplied lists get the same public-proxy warning. */
        print_public_disclaimer();
        rc = load_external_list(list_path, "Custom proxy list");
        break;
    case PROXY_ELITE:
        print_public_disclaimer();
        rc = fetch_elite_proxies();
        if (rc == 0)
            rc = load_external_list(SCRAPE_CACHE, "ProxyScrape elite list");
        break;
    }

    if (rc != 0) {
        lock_acquire();
        pool_mode = PROXY_NONE;   /* degrade to direct mode, loudly */
        lock_release();
        fprintf(stderr, "[-] Proxy setup failed — falling back to direct mode\n");
        return -1;
    }

    printf("[+] Proxy mode active: %s\n", proxy_mode_name(mode));
    return 0;
}

/* Compatibility entry point: uses the mode already stored in g. */
void start_proxies(void) {
    proxy_init(g.proxy_mode, g.proxy_list);
}

/* ---------------- current proxy access ---------------- */

const char *proxy_get_socks(void) {
    static __thread char buf[512];

    lock_acquire();
    if (pool_mode == PROXY_NONE || pool_count == 0) {
        lock_release();
        return NULL;           /* direct mode: callers do plain curl */
    }
    const char *uri = NULL;
    for (int i = 0; i < pool_count; i++) {
        if (pool[i].current && pool[i].ready && !pool[i].burned) {
            uri = pool[i].uri;
            break;
        }
    }
    if (!uri) {
        lock_release();
        return NULL;
    }
    snprintf(buf, sizeof(buf), "%s", uri);
    lock_release();
    return buf;
}

/* ---------------- burn / rotate ---------------- */

static void proxy_rebuild(void) {
    int mode;
    lock_acquire();
    mode = pool_mode;
    lock_release();

    if (mode == PROXY_TOR) {
        proxy_shutdown();
        proxy_init(PROXY_TOR, NULL);
    } else if (mode == PROXY_CUSTOM) {
        char path[G_PROXY_MAX];
        snprintf(path, sizeof(path), "%s", g.proxy_list);
        proxy_shutdown();
        proxy_init(PROXY_CUSTOM, path);
    } else if (mode == PROXY_ELITE) {
        proxy_shutdown();
        proxy_init(PROXY_ELITE, NULL);
    }
}

int burn_rotate(void) {
    lock_acquire();
    if (pool_mode == PROXY_NONE || pool_count <= 0) {
        lock_release();
        return -1;             /* nothing to rotate in direct mode */
    }
    int cur = -1;
    for (int i = 0; i < pool_count; i++)
        if (pool[i].current) {
            cur = i;
            break;
        }
    if (cur >= 0) {
        pool[cur].current = false;
        pool[cur].burned  = true;
    }

    for (int step = 1; step <= pool_count; step++) {
        int j = (cur + step) % pool_count;
        if (pool[j].ready && !pool[j].burned) {
            pool[j].current = true;
            lock_release();
            printf("[+] Rotated to proxy %s\n", pool[j].uri);
            return 0;
        }
    }
    lock_release();

    /* entire pool burned -> rebuild it */
    printf("[!] Proxy pool exhausted — re-probing proxies\n");
    proxy_rebuild();
    return -1;
}

/* ---------------- proxychains wrapper ---------------- */

typedef struct {
    char type[16];
    char host[256];
    char port[8];
} px_uri;

static bool split_proxy_uri(const char *uri, px_uri *out) {
    const char *sep = strstr(uri, "://");
    if (!sep)
        return false;
    size_t slen = (size_t)(sep - uri);
    if (slen == 0 || slen >= sizeof(out->type))
        return false;
    memcpy(out->type, uri, slen);
    out->type[slen] = '\0';

    const char *rest = sep + 3;
    const char *colon = strrchr(rest, ':');
    if (!colon || colon == rest)
        return false;
    size_t hlen = (size_t)(colon - rest);
    if (hlen == 0 || hlen >= sizeof(out->host))
        return false;
    memcpy(out->host, rest, hlen);
    out->host[hlen] = '\0';
    snprintf(out->port, sizeof(out->port), "%s", colon + 1);

    if (strcmp(out->type, "socks5h") == 0) strcpy(out->type, "socks5");
    if (strcmp(out->type, "socks4a") == 0) strcpy(out->type, "socks4");
    if (strcmp(out->type, "https") == 0)   strcpy(out->type, "http");
    if (strcmp(out->type, "http") && strcmp(out->type, "socks4") &&
        strcmp(out->type, "socks5"))
        return false;
    return true;
}

/* Unique per-invocation proxychains config (thread-safe). */
static int write_proxychains_conf(const char *uri, char *conf_path, size_t cap) {
    px_uri p;
    if (!split_proxy_uri(uri, &p))
        return -1;

    static unsigned counter = 0;
    lock_acquire();                       /* counter is shared state */
    snprintf(conf_path, cap, "%s/prox_%d_%u.conf", CONF_DIR,
             (int)getpid(), counter++);
    lock_release();

    FILE *f = fopen(conf_path, "w");
    if (!f)
        return -1;
    fprintf(f, "strict_chain\n");
    fprintf(f, "proxy_dns\n");
    fprintf(f, "tcp_read_time_out 15000\n");
    fprintf(f, "tcp_connect_time_out 8000\n");
    fprintf(f, "[ProxyList]\n");
    fprintf(f, "%s %s %s\n", p.type, p.host, p.port);
    fclose(f);
    return 0;
}

/* Check if a tool should use HTTP pre-flight */
static bool tool_uses_http(const char *tool_name) {
    const char *http_tools[] = {
        "nuclei", "nikto", "httpx", "curl", "wpscan", "dalfox",
        "ffuf", "gobuster", "dirb", "dirsearch", "hydra", "medusa",
        "whatweb", "wafw00f", NULL
    };
    
    for (int i = 0; http_tools[i] != NULL; i++) {
        if (strstr(tool_name, http_tools[i]) != NULL) {
            return true;
        }
    }
    return false;
}

/* Check if a tool should skip proxy entirely */
static bool tool_skip_proxy(const char *tool_name) {
    const char *skip_tools[] = {
        "subfinder", "assetfinder", "gobuster", "subzy", "subjack",
        "dns", "nmap", "masscan", "dnsrecon", "dnsenum", "fierce",
        "amass", "knock", "dnsx", "puredns", "shuffledns", NULL
    };
    
    for (int i = 0; skip_tools[i] != NULL; i++) {
        if (strstr(tool_name, skip_tools[i]) != NULL) {
            return true;
        }
    }
    return false;
}

/* Pre-flight request through the current proxy (GET/HEAD only).
 * Returns HTTP status (>=100), -1 transport error,
 *         -2 proxy rotated (429/503), -3 pool down. */
static int proxy_preflight(const char *url) {
    const char *proxy = proxy_get_socks();
    if (!proxy)
        return -3;

    CURL *curl = curl_easy_init();
    if (!curl)
        return -1;

    long code = 0;
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_PROXY, proxy);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, discard_cb);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Sentinel-scan/1.0");
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 3L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);

    res = curl_easy_perform(curl);
    if (res == CURLE_OK)
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        fprintf(stderr, "[-] pre-flight %s failed: %s\n",
                url, curl_easy_strerror(res));
        return -1;
    }
    if (code == 429 || code == 503) {
        printf("[!] HTTP %ld from %s — burning proxy and rotating\n", code, url);
        return (burn_rotate() == 0) ? -2 : -3;
    }
    return (int)code;
}

/* ---------------- tool execution using popen ---------------- */

static int run_tool_impl(char *const argv[], const char *out_path, bool append)
{
    char conf_path[512] = {0};
    bool proxied = false;
    bool skip_proxy = false;
    bool uses_http = false;

    const char *tool_name = argv[0];
    if (tool_name) {
        skip_proxy = tool_skip_proxy(tool_name);
        uses_http = tool_uses_http(tool_name);
    }

    /* Snapshot mode + current proxy URI under the lock (may rotate below). */
    int mode;
    const char *cur_uri = NULL;
    lock_acquire();
    mode = pool_mode;
    if (mode != PROXY_NONE && pool_count > 0 && !skip_proxy) {
        for (int i = 0; i < pool_count; i++) {
            if (pool[i].current && pool[i].ready && !pool[i].burned) {
                cur_uri = pool[i].uri;
                break;
            }
        }
    }
    lock_release();

    if (mode != PROXY_NONE && !skip_proxy) {
        if (!cur_uri) {
            fprintf(stderr, "[-] No healthy proxy — aborting tool launch\n");
            return -2;
        }
        proxied = true;

        /* Pre-flight for HTTP tools with a URL argument */
        if (uses_http) {
            for (int i = 0; argv[i] != NULL; i++) {
                if (strncmp(argv[i], "http://", 7) == 0 ||
                    strncmp(argv[i], "https://", 8) == 0) {
                    int r = proxy_preflight(argv[i]);
                    if (r == -3) {
                        fprintf(stderr, "[-] Proxy pool unavailable — aborting tool launch\n");
                        return -2;
                    }
                    /* If rotated, fetch the new current proxy */
                    if (r == -2) {
                        lock_acquire();
                        cur_uri = NULL;
                        for (int j = 0; j < pool_count; j++) {
                            if (pool[j].current && pool[j].ready && !pool[j].burned) {
                                cur_uri = pool[j].uri;
                                break;
                            }
                        }
                        lock_release();
                        if (!cur_uri) {
                            fprintf(stderr, "[-] Proxy pool unavailable after rotation\n");
                            return -2;
                        }
                    }
                }
            }
        }

        /* Write proxychains config for the (possibly rotated) proxy */
        if (write_proxychains_conf(cur_uri, conf_path, sizeof(conf_path)) != 0)
            return -1;
    }

    /* Build the command line as a single string for popen */
    char cmd[4096] = {0};
    int pos = 0;

    if (proxied && !skip_proxy) {
        pos += snprintf(cmd + pos, sizeof(cmd) - pos,
                        "proxychains4 -f %s ", conf_path);
    }

    for (int i = 0; argv[i] != NULL && pos < (int)sizeof(cmd) - 1; i++) {
        /* Simple quoting: if arg contains spaces, wrap in double quotes */
        if (strchr(argv[i], ' ') != NULL) {
            pos += snprintf(cmd + pos, sizeof(cmd) - pos, "\"%s\" ", argv[i]);
        } else {
            pos += snprintf(cmd + pos, sizeof(cmd) - pos, "%s ", argv[i]);
        }
    }
    if (pos > 0) cmd[pos - 1] = '\0';   /* remove trailing space */

#ifdef DEBUG
    printf("[DEBUG] popen command: %s\n", cmd);
#endif

    /* Append redirection to capture stderr as well */
    char full_cmd[sizeof(cmd) + 16];
    snprintf(full_cmd, sizeof(full_cmd), "%s 2>&1", cmd);

    FILE *fp = popen(full_cmd, "r");
    if (!fp) {
        fprintf(stderr, "[-] popen failed: %s\n", strerror(errno));
        return -1;
    }

    /* Output handling: write to file only if out_path is non-NULL and non-empty */
    FILE *out_fp = NULL;
    if (out_path && out_path[0] != '\0') {
        int flags = O_WRONLY | O_CREAT | (append ? O_APPEND : O_TRUNC);
        int fd = open(out_path, flags, 0644);
        if (fd >= 0) {
            out_fp = fdopen(fd, append ? "a" : "w");
            if (!out_fp) {
                close(fd);
                out_fp = NULL;
            }
        }
        if (!out_fp) {
            fprintf(stderr, "[-] Cannot open output file %s: %s\n",
                    out_path, strerror(errno));
            pclose(fp);
            return -1;
        }
    }

    /* Read output and write to out_fp or stdout */
    char buf[4096];
    while (fgets(buf, sizeof(buf), fp) != NULL) {
        if (out_fp) {
            fputs(buf, out_fp);
        } else {
            fputs(buf, stdout);
        }
    }

    int status = pclose(fp);
    if (out_fp) fclose(out_fp);

    /* pclose returns exit status as if from waitpid */
    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    if (WIFSIGNALED(status))
        return 128 + WTERMSIG(status);
    return 1;
}

/* Public wrappers – timeout parameter removed */
int run_tool(char *const argv[]) {
    return run_tool_impl(argv, NULL, false);
}

int run_tool_out(char *const argv[], const char *out_path, bool append) {
    return run_tool_impl(argv, out_path, append);
}