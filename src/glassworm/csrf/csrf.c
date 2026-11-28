#include "csrf.h"
#include "../../global.h"
#include "../../util/util.h"
#include <unistd.h>
#include <sys/wait.h>

/* ============================================================
 * CSRF detection constants (unchanged)
 * ============================================================ */

static const char *CSRF_COOKIE_NAMES[] = {
    "XSRF-TOKEN", "csrftoken", "_csrf", "csrf_token",
    "CSRF-TOKEN", "X-CSRF-TOKEN", NULL
};

static const char *CSRF_META_NAMES[] = {
    "csrf-token", "csrf-param", "_csrf", "_csrf_header",
    "xsrf-token", NULL
};

static const char *CSRF_FORM_FIELDS[] = {
    "csrf_token", "_csrf", "_token", "authenticity_token",
    "__RequestVerificationToken", "csrfmiddlewaretoken",
    "X-CSRF-Token", NULL
};

static const char *CSRF_ERROR_PHRASES[] = {
    "CSRF token missing", "CSRF verification failed",
    "CSRF token mismatch", "Invalid CSRF token",
    "Invalid authenticity token", "Can't verify CSRF token authenticity",
    "RequestVerificationToken", "Anti-forgery token",
    "anti-forgery", "_csrf token required", NULL
};

/* ============================================================
 * Shell-based POST helper
 *
 * Runs:  curl -sS -L --max-time 30 --connect-timeout 10 \
 *              -o <outfile> -w '%{http_code}' \
 *              -X POST <url>
 *
 * The -w prints the HTTP status to stdout; -o writes the body
 * to <outfile>. We capture stdout to learn the status code.
 *
 * Returns:
 *    1  -> request completed, body in outfile, *code set
 *    0  -> curl failed (transport error / timeout / non-zero exit)
 *   -1  -> internal error (fork/pipe/tmp setup)
 * ============================================================ */

/* Quote a string for safe inclusion in a /bin/sh command line. */
static void sh_quote(const char *in, char *out, size_t outsz) {
    size_t o = 0;
    if (outsz < 3) { if (outsz) out[0] = '\0'; return; }
    out[o++] = '\'';
    for (const char *p = in; *p && o + 5 < outsz; p++) {
        if (*p == '\'') {
            /* close quote, escaped quote, reopen quote:  '\'' */
            out[o++] = '\''; out[o++] = '\\'; out[o++] = '\'';
            out[o++] = '\'';
        } else {
            out[o++] = *p;
        }
    }
    out[o++] = '\'';
    out[o]   = '\0';
}

static int shell_post(const char *url, const char *outfile, long *http_code) {
    char qurl[4096], qout[4096], cmd[8192];
    sh_quote(url,     qurl, sizeof(qurl));
    sh_quote(outfile, qout, sizeof(qout));

    /* -sS: silent + show errors; -L follow redirects; -X POST empty body;
     * -o writes body; -w prints final status code to stdout. */
    snprintf(cmd, sizeof(cmd),
             "curl -sS -L --max-time 30 --connect-timeout 10 "
             "-A 'Sentinel-scan/1.0' "
             "-X POST -o %s -w '%%{http_code}' %s",
             qout, qurl);

    FILE *pipe = popen(cmd, "r");
    if (!pipe) {
        fprintf(stderr, "[-] csrf: popen failed: %s\n", strerror(errno));
        return -1;
    }

    char codebuf[32] = {0};
    size_t n = fread(codebuf, 1, sizeof(codebuf) - 1, pipe);
    codebuf[n] = '\0';

    int status = pclose(pipe);
    if (status == -1) {
        fprintf(stderr, "[-] csrf: pclose failed: %s\n", strerror(errno));
        return 0;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "[-] csrf: curl exited with status %d for %s\n",
                WIFEXITED(status) ? WEXITSTATUS(status) : -1, url);
        return 0;
    }

    if (http_code) *http_code = strtol(codebuf, NULL, 10);
    return 1;
}

/* ============================================================
 * Main entry point (same signature, same return semantics)
 * ============================================================ */

int csrf_token_exists(char *target_url, char *output_dir) {
    printf("[csrf] Checking for CSRF token on %s\n", target_url);

    /* Mirror file for the response body, unique per call. */
    char bodyfile[2048];
    snprintf(bodyfile, sizeof(bodyfile), "%s/csrf_body_%ld.txt",
             output_dir, (long)getpid());

    long code = 0;
    if (shell_post(target_url, bodyfile, &code) == 0) {
        fprintf(stderr, "HTTP POST failed for %s\n", target_url);
        unlink(bodyfile);
        return -1;
    }
    printf("[csrf] HTTP %ld, response mirrored to %s\n", code, bodyfile);

    char output_path[2048];
    snprintf(output_path, sizeof(output_path), "%s/csrf_results.txt", output_dir);

    FILE *fp = fopen(output_path, "w");
    if (!fp) {
        fprintf(stderr, "[-] cannot write csrf_results.txt: %s\n", strerror(errno));
        unlink(bodyfile);
        return 1;
    }

    int found = 0;

    printf("[csrf] Checking for CSRF cookie names...\n");
    for (int i = 0; CSRF_COOKIE_NAMES[i] && !found; i++) {
        if (find_string_in_file(bodyfile, CSRF_COOKIE_NAMES[i])) {
            printf("[csrf] Found CSRF cookie name: %s\n", CSRF_COOKIE_NAMES[i]);
            fprintf(fp, "[csrf] Found CSRF cookie name: %s\n", CSRF_COOKIE_NAMES[i]);
            found = 1;
        }
    }

    printf("[csrf] Checking for CSRF meta names...\n");
    for (int i = 0; CSRF_META_NAMES[i] && !found; i++) {
        if (find_string_in_file(bodyfile, CSRF_META_NAMES[i])) {
            printf("[csrf] Found CSRF meta name: %s\n", CSRF_META_NAMES[i]);
            fprintf(fp, "[csrf] Found CSRF meta name: %s\n", CSRF_META_NAMES[i]);
            found = 1;
        }
    }

    printf("[csrf] Checking for CSRF form field names...\n");
    for (int i = 0; CSRF_FORM_FIELDS[i] && !found; i++) {
        if (find_string_in_file(bodyfile, CSRF_FORM_FIELDS[i])) {
            printf("[csrf] Found CSRF form field name: %s\n", CSRF_FORM_FIELDS[i]);
            fprintf(fp, "[csrf] Found CSRF form field name: %s\n", CSRF_FORM_FIELDS[i]);
            found = 1;
        }
    }

    printf("[csrf] Checking for CSRF error phrases...\n");
    for (int i = 0; CSRF_ERROR_PHRASES[i] && !found; i++) {
        if (find_string_in_file(bodyfile, CSRF_ERROR_PHRASES[i])) {
            printf("[csrf] Found CSRF error phrase: %s\n", CSRF_ERROR_PHRASES[i]);
            fprintf(fp, "[csrf] Found CSRF error phrase: %s\n", CSRF_ERROR_PHRASES[i]);
            found = 1;
        }
    }

    remove(bodyfile);

    printf("[csrf] CSRF token %sfound on %s\n", found ? "" : "not ", target_url);
    fprintf(fp, "[csrf] CSRF token %sfound on %s\n", found ? "" : "not ", target_url);
    fclose(fp);

    return found;
}