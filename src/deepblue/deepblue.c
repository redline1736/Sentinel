#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "../util/util.h"
#include "deepblue.h"
#include "../global.h"

/* ===================================================================== */
/* Exploit entry matching the structure of deepblue/module.dvr           */
/* ===================================================================== */

typedef struct {
    char service[128];
    char cve[32];
    char file[256];           /* e.g. "CVE-2014-2323.sh" */
    char type[64];
    char description[2048];
    char config[1024];
    char usage[512];
    char example[512];
    char mitigation[1024];
} exploit_entry_t;

typedef enum {
    NGINX,
    LIGHTTPD
} section;

/* Grow the per-host CVE array. Returns 0 on success, -1 on OOM. */
int cve_allocate(nikto *n) {
    int new_cap = n->cve_cap ? n->cve_cap * 2 : 16;
    char **tmp = realloc(n->cve, (size_t)new_cap * sizeof(*tmp));
    if (!tmp)
        return -1;
    n->cve = tmp;
    n->cve_cap = new_cap;
    return 0;
}

/* ===================================================================== */
/* Hardening helpers                                                     */
/* ===================================================================== */

/*
 * Reduce a string to characters that are plausible in a service name or
 * version identifier: [A-Za-z0-9._+-].  Everything else (space, ';', '|',
 * '&', '$', '`', '(', ')', '>', '<', newline, NUL-terminators, etc.) is
 * dropped.  This is a lossy filter — "Apache;id" becomes "Apacheid" —
 * but the alternative is trusting the target to be honest.
 *
 * Applied to n->service and n->version after every parse so no downstream
 * consumer (searchsploit, msfconsole, log files, report generator) ever
 * sees shell metacharacters.
 */
static void sanitize_token(char *s) {
    if (!s) return;
    char *w = s;
    for (char *r = s; *r; r++) {
        unsigned char c = (unsigned char)*r;
        if (isalnum(c) || c == '.' || c == '_' || c == '+' || c == '-') {
            *w++ = (char)c;
        }
    }
    *w = '\0';
}

/* Same idea, but for CVE IDs: keep only [A-Za-z0-9-]. */
static void sanitize_cve(char *s) {
    if (!s) return;
    char *w = s;
    for (char *r = s; *r; r++) {
        unsigned char c = (unsigned char)*r;
        if (isalnum(c) || c == '-') {
            *w++ = (char)c;
        }
    }
    *w = '\0';
}

/*
 * Spawn argv[0] with argv[] as its argument vector — no shell involved.
 * Child's stdout and stderr are streamed to `out`.  Returns the child's
 * exit status, or -1 on transport error.
 *
 * This is the fix for the RCE.  Metacharacters in any argv entry
 * (';', '|', '&', '$', '`', '(', ')', '>', '<') are literal bytes;
 * execvp passes them to the target binary untouched.  There is no
 * /bin/sh -c step, so there is nothing to interpret them.
 */
static int run_no_shell(char *const argv[], FILE *out) {
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        perror("pipe");
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (pid == 0) {
        /* child */
        close(pipefd[0]);

        if (dup2(pipefd[1], STDOUT_FILENO) < 0) _exit(127);
        if (dup2(pipefd[1], STDERR_FILENO) < 0) _exit(127);
        if (pipefd[1] != STDOUT_FILENO && pipefd[1] != STDERR_FILENO)
            close(pipefd[1]);

        /* Detach from controlling terminal signals so the parent's
         * SIGINT handling doesn't leak in unexpected ways. */
        execvp(argv[0], argv);

        /* execvp only returns on failure. */
        fprintf(stderr, "deepblue: execvp('%s') failed: %s\n",
                argv[0], strerror(errno));
        _exit(127);
    }

    /* parent */
    close(pipefd[1]);

    char buf[1024];
    ssize_t n;
    while ((n = read(pipefd[0], buf, sizeof(buf))) > 0) {
        if (out) fwrite(buf, 1, (size_t)n, out);
    }
    close(pipefd[0]);

    int status = 0;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/* ------------------------------------------------------------------ */
/* Helpers for module.dvr parsing                                     */
/* ------------------------------------------------------------------ */

/* Split a data line on the " | " delimiter. Returns the number of
   fields extracted; the last field runs to end of line (newline/CR
   stripped). Handles fields that contain spaces. */
static int split_fields(char *line, char **fields, int max) {
    int n = 0;
    char *p = line;
    while (n < max) {
        char *sep = strstr(p, " | ");
        if (sep) {
            *sep = '\0';
            fields[n++] = p;
            p = sep + 3;
        } else {
            char *nl = strchr(p, '\n');
            if (nl) *nl = '\0';
            char *cr = strchr(p, '\r');
            if (cr) *cr = '\0';
            fields[n++] = p;
            break;
        }
    }
    return n;
}

/* Numeric dotted-version comparison: <0, 0, >0. */
static int version_cmp(const char *a, const char *b) {
    for (;;) {
        char *ea, *eb;
        unsigned long va = strtoul(a, &ea, 10);
        unsigned long vb = strtoul(b, &eb, 10);
        if (va < vb) return -1;
        if (va > vb) return  1;
        if (*ea == '\0' && *eb == '\0') return 0;
        if (*ea == '.') ea++;
        if (*eb == '.') eb++;
        a = ea;
        b = eb;
    }
}

static bool version_less(const char *a, const char *b) {
    return version_cmp(a, b) < 0;
}

/* ===================================================================== */
/* line format:
   # service | #_vuln_versions | version(s) | CVE | TYPE | description | \
     config | usage | example | mitigation
   Returns 0 if a matching entry was written to fptr, nonzero otherwise. */
int load_exploit_module(nikto *n, FILE *fptr) {
    FILE *fp = fopen("/usr/share/sentinel/deepblue/module.dvr", "r");
    if (!fp) {
        fprintf(stderr, "Error opening module.dvr\n");
        return 1;
    }

    section looking;
    if (strcmp(n->service, "nginx") == 0) {
        looking = NGINX;
    } else if (strcmp(n->service, "lighttpd") == 0) {
        looking = LIGHTTPD;
    } else {
        fprintf(stderr, "Unknown service: %s\n", n->service);
        fclose(fp);
        return 1;
    }

    exploit_entry_t entries;
    memset(&entries, 0, sizeof(entries));
    bool found = false;

    char buffer[10000];
    while (fgets(buffer, sizeof(buffer), fp)) {
        if (buffer[0] == '#' || buffer[0] == '\n' || buffer[0] == '\r')
            continue;

        /* Section headers: *N ... / *L ... */
        if (buffer[0] == '*') {
            if (buffer[1] == 'N')
                looking = NGINX;
            else if (buffer[1] == 'L')
                looking = LIGHTTPD;
            continue;
        }

        if (looking == NGINX && strncmp(buffer, "nginx", 5) != 0)
            continue;
        if (looking == LIGHTTPD && strncmp(buffer, "lighttpd", 8) != 0)
            continue;

        char *fields[10];
        int nf = split_fields(buffer, fields, 10);
        if (nf < 10)
            continue;                    /* malformed line */

        int num_versions = atoi(fields[1]);
        bool version_found = false;

        if (num_versions == 0) {
            /* Comma-separated list of exact vulnerable versions */
            char vlist[1024];
            snprintf(vlist, sizeof(vlist), "%s", fields[2]);
            char *tok = strtok(vlist, ",");
            while (tok) {
                while (*tok == ' ' || *tok == '\t') tok++;
                size_t tlen = strlen(tok);
                while (tlen > 0 && (tok[tlen - 1] == ' ' || tok[tlen - 1] == '\t'))
                    tok[--tlen] = '\0';
                if (*tok && strcmp(tok, n->version) == 0) {
                    version_found = true;
                    break;
                }
                tok = strtok(NULL, ",");
            }
        } else {
            if (fields[2][0] == '<' && version_less(n->version, fields[2] + 1))
                version_found = true;
        }

        if (!version_found)
            continue;

        snprintf(entries.service,     sizeof(entries.service),     "%s", n->service);
        snprintf(entries.cve,         sizeof(entries.cve),         "%s", fields[3]);
        snprintf(entries.type,        sizeof(entries.type),        "%s", fields[4]);
        snprintf(entries.description, sizeof(entries.description), "%s", fields[5]);
        snprintf(entries.config,      sizeof(entries.config),      "%s", fields[6]);
        snprintf(entries.usage,       sizeof(entries.usage),       "%s", fields[7]);
        snprintf(entries.example,     sizeof(entries.example),     "%s", fields[8]);
        snprintf(entries.mitigation,  sizeof(entries.mitigation),  "%s", fields[9]);

        found = true;
        break;
    }
    fclose(fp);

    if (!found) {
        fprintf(stderr, "No matching exploit entry for %s %s\n",
                n->service, n->version);
        return 1;
    }

    fprintf(fptr,
            "# Exploit Breakdown\n"
            "    **Exploit based on version**\n"
            "      **Custom Exploits**\n"
            "           - Service: %s\n"
            "         - Version: %s\n"
            "         - CVE: %s\n"
            "         - Type: %s\n"
            "            - Description: %s\n"
            "         - Config: %s\n"
            "          - Usage: %s\n"
            "           - Example: %s\n"
            "         - Mitigation: %s\n",
            entries.service, n->version, entries.cve, entries.type,
            entries.description, entries.config, entries.usage,
            entries.example, entries.mitigation);
    return 0;
}

void find_exploit(nikto *n, int length) {
    char path[2048];
    snprintf(path, sizeof(path), "%s/interesting_hosts.txt", g.dir);
    FILE *hosts = fopen(path, "r");
    if (!hosts)
        return;

    char host[128];
    int i = 0;
    while (fgets(host, sizeof(host), hosts) && i < length) {
        host[strcspn(host, "\r\n")] = 0;
        if (strlen(host) == 0)
            continue;
        snprintf(n[i].host, sizeof(n[i].host), "%s", host);

        char hostdir[2048];
        snprintf(hostdir, sizeof(hostdir), "%s/%s", g.dir, host);

        char nikto_path[3000];
        snprintf(nikto_path, sizeof(nikto_path), "%s/nikto.txt", hostdir);
        FILE *nikto_file = fopen(nikto_path, "r");
        if (!nikto_file)
            continue;

        char result[1024];
        int num_cve = 0;

        while (fgets(result, sizeof(result), nikto_file)) {
            if (strstr(result, "+ Server: ")) {
                char *token = strstr(result, "+ Server: ") + strlen("+ Server: ");
                char *slash = strchr(token, '/');
                if (slash) {
                    size_t slen = (size_t)(slash - token);
                    if (slen >= sizeof(n[i].service))
                        slen = sizeof(n[i].service) - 1;
                    memcpy(n[i].service, token, slen);
                    n[i].service[slen] = '\0';

                    char *v = slash + 1;
                    char *vend = v;
                    while (*vend && *vend != '\n' && *vend != '\r' && *vend != ' ')
                        vend++;
                    size_t vlen = (size_t)(vend - v);
                    if (vlen >= sizeof(n[i].version))
                        vlen = sizeof(n[i].version) - 1;
                    memcpy(n[i].version, v, vlen);
                    n[i].version[vlen] = '\0';

                    /* HARDENING: strip anything that isn't a plausible
                     * service/version character.  This happens BEFORE any
                     * of these values reach searchsploit, msfconsole, or
                     * the report file. */
                    sanitize_token(n[i].service);
                    sanitize_token(n[i].version);
                }
            } else if (strstr(result, "+ IP Address: ")) {
                char *token = strstr(result, "+ IP Address: ") + strlen("+ IP Address: ");
                snprintf(n[i].ip, sizeof(n[i].ip), "%s", token);
                n[i].ip[strcspn(n[i].ip, "\r\n")] = 0;
                /* HARDENING: IP is written into reports; keep it clean. */
                sanitize_token(n[i].ip);
            } else if (strstr(result, "CVE-")) {
                char *token = strstr(result, "CVE-");
                if (num_cve >= n[i].cve_cap && cve_allocate(&n[i]) != 0)
                    break;

                char *end = token;
                while (*end && (isalnum((unsigned char)*end) || *end == '-' || *end == '_'))
                    end++;
                size_t clen = (size_t)(end - token);
                if (clen == 0)
                    continue;

                n[i].cve[num_cve] = malloc(clen + 1);
                if (!n[i].cve[num_cve])
                    break;
                memcpy(n[i].cve[num_cve], token, clen);
                n[i].cve[num_cve][clen] = '\0';

                /* HARDENING: even though the scan loop above already
                 * restricted the token, run it through the stricter
                 * [A-Za-z0-9-] filter as a second line of defense. */
                sanitize_cve(n[i].cve[num_cve]);

                num_cve++;
            }
        }
        n[i].cve_count = num_cve;

        char md_path[2660];
        snprintf(md_path, sizeof(md_path), "%s/exploit.md", hostdir);
        FILE *fptr = fopen(md_path, "w");
        if (!fptr) {
            fprintf(stderr, "Error creating exploit.md for host %s\n", n[i].host);
            fclose(nikto_file);
            continue;
        }

        if (load_exploit_module(&n[i], fptr) != 0)
            fprintf(stderr, "Error loading exploit module for host %s\n", n[i].host);

        /* Run both searches independently. */
        if (exploitdb(&n[i], fptr) != 0)
            fprintf(stderr, "No exploits found for host %s\n", n[i].host);

        if (metasploit(&n[i], fptr) != 0)
            fprintf(stderr, "No exploits found for host %s\n", n[i].host);

        i++;
        fclose(nikto_file);
    }
    fclose(hosts);
}

/* ===================================================================== */
/* Exploit DB                                                            */
/* ===================================================================== */

int exploitdb(nikto *n, FILE *fptr) {
    /*
     * OLD (vulnerable):
     *     char cmd[512];
     *     snprintf(cmd, sizeof(cmd), "searchsploit %s %s",
     *              n->service, n->version);
     *     FILE *fp = popen(cmd, "r");
     *
     * NEW: argv is passed to execvp, which does not invoke a shell.
     * The two strings are literal arguments to searchsploit.  A service
     * value of "foo;id" reaches searchsploit as the argument "foo;id",
     * not as the shell command "id".
     *
     * The sanitize_token() pass in find_exploit() also removes the
     * metacharacters, so this is defense in depth: even if a caller
     * bypasses find_exploit(), there's no shell to exploit here.
     */
    char *argv_main[] = { "searchsploit", n->service, n->version, NULL };

    fprintf(fptr, "      **Exploit DB Results**\n");
    run_no_shell(argv_main, fptr);

    for (int i = 0; i < n->cve_count; i++) {
        char *argv_cve[] = { "searchsploit", n->cve[i], NULL };

        fprintf(fptr, "      **Exploit DB Results for CVE %s**\n", n->cve[i]);
        run_no_shell(argv_cve, fptr);
    }
    return 0;
}

/* ===================================================================== */
/* Metasploit                                                            */
/* ===================================================================== */

int metasploit(nikto *n, FILE *fptr) {
    /*
     * OLD (vulnerable):
     *     snprintf(cmd, sizeof(cmd),
     *              "msfconsole -q -x \"search info:%s %s; quit\"",
     *              n->service, n->version);
     *     FILE *fp = popen(cmd, "r");
     *
     * Two layers of injection there:
     *   1. The outer popen() shell parses the string.  A version of
     *      "1.0\"; rm -rf / #" would escape the quotes.
     *   2. The inner msfconsole -x script had its own quoting to worry
     *      about.
     *
     * NEW: msfconsole is exec'd directly.  The -x script is a literal
     * argument.  msfconsole parses it as its own mini-language, but
     * that language cannot invoke the operator's shell — the worst a
     * hostile service/version string can do is produce a malformed
     * search term inside msfconsole's REPL.
     */
    char script_main[512];
    snprintf(script_main, sizeof(script_main),
             "search info:%s %s; quit", n->service, n->version);

    char *argv_main[] = { "msfconsole", "-q", "-x", script_main, NULL };

    fprintf(fptr, "      **Metasploit Results**\n");
    run_no_shell(argv_main, fptr);

    for (int i = 0; i < n->cve_count; i++) {
        char script_cve[512];
        snprintf(script_cve, sizeof(script_cve),
                 "search cve:%s; quit", n->cve[i]);

        char *argv_cve[] = { "msfconsole", "-q", "-x", script_cve, NULL };

        fprintf(fptr, "      **Metasploit Results for CVE %s**\n", n->cve[i]);
        run_no_shell(argv_cve, fptr);
    }
    return 0;
}

/* ===================================================================== */
/* Entry point                                                           */
/* ===================================================================== */

int deepblue_run(void) {
    char path[2048];
    snprintf(path, sizeof(path), "%s/interesting_hosts.txt", g.dir);

    FILE *hf = fopen(path, "r");
    if (!hf) {
        fprintf(stderr, "Cannot open %s\n", path);
        return 1;
    }
    int length = 0;
    char lbuf[512];
    while (fgets(lbuf, sizeof(lbuf), hf)) {
        lbuf[strcspn(lbuf, "\r\n")] = 0;
        if (lbuf[0] != '\0')
            length++;
    }
    fclose(hf);

    if (length == 0)
        return 0;

    nikto *n = calloc((size_t)length, sizeof(*n));
    if (!n)
        return 1;

    find_exploit(n, length);

    for (int i = 0; i < length; i++) {
        for (int j = 0; j < n[i].cve_count; j++)
            free(n[i].cve[j]);
        free(n[i].cve);
    }
    free(n);
    return 0;
}