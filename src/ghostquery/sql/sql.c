#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>   /* waitpid */
#include <time.h>
#include <ctype.h>
#include <curl/curl.h>
#include <fcntl.h>
#include <dirent.h>
#include <signal.h>

#include "../../util/util.h"
#include "../../prox/prox.h"
#include "../../http/http.h"
#include "../../global.h"
#include "../sql/sql.h"
#include "../gq.h"


#ifndef MAX_URL_LEN
#define MAX_URL_LEN     32768
#endif

#ifndef MAX_PARAM_LEN
#define MAX_PARAM_LEN   256
#endif

/* Insert or replace `param` in the query string, preserving other params
 * and any #fragment. Safer than appending: /greet?name=x + param 'name'
 * stays a single `name=` (Flask's request.args.get returns the FIRST). */
static int build_param_url(char *dst, size_t dstsz,
                           const char *url, const char *param, const char *value) {
    if (!dst || !url || !param || !value) return 0;

    const char *frag    = strchr(url, '#');
    size_t      url_len = frag ? (size_t)(frag - url) : strlen(url);
    const char *q       = memchr(url, '?', url_len);

    const char *hit     = NULL;
    const char *seg_end = NULL;
    if (q) {
        size_t plen = strlen(param);
        const char *p   = q + 1;
        const char *end = url + url_len;
        while (p < end) {
            const char *amp = memchr(p, '&', (size_t)(end - p));
            const char *e   = amp ? amp : end;
            if ((size_t)(e - p) > plen && p[plen] == '=' &&
                strncmp(p, param, plen) == 0) {
                hit = p; seg_end = e; break;
            }
            p = amp ? amp + 1 : end;
        }
    }

    int n;
    if (hit) {
        n = snprintf(dst, dstsz, "%.*s%s=%s%s",
                     (int)(hit - url), url, param, value, seg_end);
    } else {
        const char *sep = q ? "&" : "?";
        n = snprintf(dst, dstsz, "%.*s%s%s=%s%s",
                     (int)url_len, url, sep, param, value,
                     frag ? frag : "");
    }
    if (n < 0 || (size_t)n >= dstsz) {
        fprintf(stderr, "[gq] URL too long for param '%s' (needed %d, had %zu)\n",
                param, n, dstsz);
        return 0;
    }
    return 1;
}

static int ensure_directory(const char *path) {
    if (!path) return -1;
    struct stat st;
    if (stat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) return 0;
        errno = ENOTDIR;
        return -1;
    }
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "mkdir -p %s 2>/dev/null", path);
    return system(tmp);
}

/* ============================================================================
 * SQL Injection Run (SQLMap)
 * ============================================================================ */

/* Parse one line of sqlmap output: "Parameter: id (GET)" */
static int sqlmap_line_is_finding(const char *line) {
    if (!line) return 0;
    /* sqlmap prints findings like:
     *   Parameter: id (GET)
     *   Type: boolean-based blind
     *   Title: AND boolean-based blind - WHERE or HAVING clause
     *   Payload: id=1 AND 1=1
     * We treat "Parameter:" and "Payload:" as confirmed findings. */
    if (strncmp(line, "Parameter:", 10) == 0) return 1;
    if (strncmp(line, "Payload:",    8) == 0) return 1;
    if (strncmp(line, "Type:",       5) == 0) return 1;
    if (strstr(line, "is vulnerable"))         return 1;
    if (strstr(line, "injectable"))            return 1;
    return 0;
}

int sql_run(char *url, char *path) {
    char param_file[4096];
    char targets_path[4096];
    char sqlmap_out[4096];
    char sqlmap_raw[4096];
    char sqlmap_dir[4096];
    char fallback_wl[512];

    if (snprintf(param_file,   sizeof(param_file),   "%s/valid_params.txt", path) >= (int)sizeof(param_file) ||
        snprintf(targets_path, sizeof(targets_path), "%s/sql_targets.txt",  path)   >= (int)sizeof(targets_path) ||
        snprintf(sqlmap_out,   sizeof(sqlmap_out),   "%s/sql.txt",          path)   >= (int)sizeof(sqlmap_out) ||
        snprintf(sqlmap_raw,   sizeof(sqlmap_raw),   "%s/sqlmap_raw.txt",   path)   >= (int)sizeof(sqlmap_raw) ||
        snprintf(sqlmap_dir,   sizeof(sqlmap_dir),   "%s/sqlmap_sessions",  path)   >= (int)sizeof(sqlmap_dir)) {
        fprintf(stderr, "[sql_run] path too long\n");
        return 1;
    }

    if (ensure_directory(path)         != 0 ||
        ensure_directory(sqlmap_dir)   != 0) {
        fprintf(stderr, "[sql_run] failed to create output directories under %s\n", path);
        return 1;
    }

    /* -- 1. Build target list -------------------------------------------- */
    FILE *tl = fopen(targets_path, "w");
    if (!tl) {
        fprintf(stderr, "[sql_run] cannot write %s\n", targets_path);
        return 1;
    }

    char param[MAX_PARAM_LEN];
    int ntargets = 0;

    FILE *fp = fopen(param_file, "r");
    if (fp) {
        while (fgets(param, sizeof(param), fp)) {
            size_t l = strlen(param);
            while (l && (param[l-1] == '\n' || param[l-1] == '\r'))
                param[--l] = '\0';
            if (l == 0 || param[0] == '#') continue;

            char full_url[MAX_URL_LEN];
            if (!build_param_url(full_url, sizeof(full_url), url, param, "1")) {
                fprintf(stderr, "[sql_run] URL too long for param '%s'\n", param);
                continue;
            }
            fprintf(tl, "%s\n", full_url);
            ntargets++;
        }
        fclose(fp);
    } else {
        printf("[sql_run] %s not found — will use fallback wordlist\n", param_file);
    }

    if (ntargets == 0) {
        printf("[sql_run] no reflecting params — falling back to params.txt\n");
        data_path("ghostquery/params.txt", fallback_wl, sizeof(fallback_wl));
        FILE *wf = fopen(fallback_wl, "r");
        if (!wf) {
            fprintf(stderr, "[sql_run] fallback wordlist missing (%s)\n", fallback_wl);
            fclose(tl);
            return 1;
        }
        char wparam[MAX_PARAM_LEN];
        while (fgets(wparam, sizeof(wparam), wf)) {
            size_t l = strlen(wparam);
            while (l && (wparam[l-1] == '\n' || wparam[l-1] == '\r'))
                wparam[--l] = '\0';
            if (l == 0 || wparam[0] == '#') continue;

            char full_url[MAX_URL_LEN];
            if (!build_param_url(full_url, sizeof(full_url), url, wparam, "1"))
                continue;
            fprintf(tl, "%s\n", full_url);
            ntargets++;
        }
        fclose(wf);
    }
    fclose(tl);

    if (ntargets == 0) {
        printf("[sql_run] nothing to test\n");
        return 0;
    }

    printf("[sql_run] running sqlmap on %d param URLs\n", ntargets);

    /* -- 2. Invoke sqlmap ------------------------------------------------ *
     * run_tool_out() fork/execs directly (no shell) and dup2's stdout+stderr
     * into the raw log — session logs go into sqlmap_dir, findings are
     * post-processed from the raw log below. */
    char *sqlmap_args[] = {
        "sqlmap",
        "-m",           targets_path,
        "--batch",
        "--smart",
        "--level=3",
        "--risk=2",
        "--technique=BEUSTQ",
        "--random-agent",
        "--timeout=10",
        "--retries=1",
        "--threads=10",
        "--flush-session",
        "--disable-coloring",
        "--output-dir", sqlmap_dir,
        "--answers=redirect=Y,skip-urlencode=N,optimize=N,keep-alive=Y",
        NULL
    };

    int rc = run_tool_out(sqlmap_args, sqlmap_raw, true);
    if (rc != 0)
        printf("[!] sqlmap exited with code %d (findings may still exist)\n", rc);

    /* -- 3. Parse raw log for confirmed findings -------------------------- */
    /* >>> UNCHANGED: keep your existing parsing block (current_target
     * >>> tracking, sqlmap_line_is_finding, [VULN]/payload output) verbatim
     * >>> from "FILE *raw = fopen(sqlmap_raw, \"r\");" to the end. */
}