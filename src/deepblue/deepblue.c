#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/types.h>
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

/* ------------------------------------------------------------------ */
/* Helpers for module.dvr parsing                                     */
/* ------------------------------------------------------------------ */

/* Split a data line on the " | " delimiter. Returns the number of
   fields extracted; the last field runs to end of line (newline/CR
   stripped). Handles fields that contain spaces, unlike the old
   "read until ' '" parser. */
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
    FILE *fp = fopen("deepblue/module.dvr", "r");
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

        /* Only parse data lines belonging to the section we want.
           (Previously the LIGHTTPD branch was an empty if-block:
           lighttpd hosts never matched anything.) */
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
                while (*tok == ' ' || *tok == '\t') tok++;   /* trim left */
                size_t tlen = strlen(tok);
                while (tlen > 0 && (tok[tlen - 1] == ' ' || tok[tlen - 1] == '\t'))
                    tok[--tlen] = '\0';                      /* trim right */
                if (*tok && strcmp(tok, n->version) == 0) {
                    version_found = true;
                    break;
                }
                tok = strtok(NULL, ",");
            }
        } else {
            /* "<x.y.z" ceiling: vulnerable when n->version < ceiling.
               (Old code compared "ceiling-middle < target-middle", i.e.
               the opposite direction on the minor/patch components.) */
            if (fields[2][0] == '<' && version_less(n->version, fields[2] + 1))
                version_found = true;
        }

        if (!version_found)
            continue;                    /* try the next module entry */

        snprintf(entries.service, sizeof(entries.service), "%s", n->service);
        snprintf(entries.cve, sizeof(entries.cve), "%s", fields[3]);
        snprintf(entries.type, sizeof(entries.type), "%s", fields[4]);
        snprintf(entries.description, sizeof(entries.description), "%s", fields[5]);
        snprintf(entries.config, sizeof(entries.config), "%s", fields[6]);
        snprintf(entries.usage, sizeof(entries.usage), "%s", fields[7]);
        snprintf(entries.example, sizeof(entries.example), "%s", fields[8]);
        snprintf(entries.mitigation, sizeof(entries.mitigation), "%s", fields[9]);

        found = true;
        break;
    }
    fclose(fp);

    if (!found) {
        fprintf(stderr, "No matching exploit entry for %s %s\n",
                n->service, n->version);
        return 1;                        /* don't print uninitialized entries */
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
        host[strcspn(host, "\r\n")] = 0;     /* strip before storing */
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
                    /* service: everything before '/'  */
                    size_t slen = (size_t)(slash - token);
                    if (slen >= sizeof(n[i].service))
                        slen = sizeof(n[i].service) - 1;
                    memcpy(n[i].service, token, slen);
                    n[i].service[slen] = '\0';

                    /* version: after '/' up to space/newline, trimmed */
                    char *v = slash + 1;
                    char *vend = v;
                    while (*vend && *vend != '\n' && *vend != '\r' && *vend != ' ')
                        vend++;
                    size_t vlen = (size_t)(vend - v);
                    if (vlen >= sizeof(n[i].version))
                        vlen = sizeof(n[i].version) - 1;
                    memcpy(n[i].version, v, vlen);
                    n[i].version[vlen] = '\0';
                }
            } else if (strstr(result, "+ IP Address: ")) {
                char *token = strstr(result, "+ IP Address: ") + strlen("+ IP Address: ");
                snprintf(n[i].ip, sizeof(n[i].ip), "%s", token);
                n[i].ip[strcspn(n[i].ip, "\r\n")] = 0;
            } else if (strstr(result, "CVE-")) {
                char *token = strstr(result, "CVE-");
                if (num_cve >= n[i].cve_cap && cve_allocate(&n[i]) != 0)
                    break;                 /* OOM: stop collecting CVEs */

                /* Copy only the CVE token (CVE-YYYY-NNNN), not the rest
                   of the line — the old code stored trailing description
                   text + newline, which broke every searchsploit call. */
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
                num_cve++;
            }
        }
        n[i].cve_count = num_cve;

        char md_path[2660];//   2048 + 512   was `path`, shadowing the outer one 
        snprintf(md_path, sizeof(md_path), "%s/exploit.md", hostdir);
        FILE *fptr = fopen(md_path, "w");
        if (!fptr) {
            fprintf(stderr, "Error creating exploit.md for host %s\n", n[i].host);
            fclose(nikto_file);
            continue;
        }

        if (load_exploit_module(&n[i], fptr) != 0)
            fprintf(stderr, "Error loading exploit module for host %s\n", n[i].host);

        /* Run both searches independently — the old `else if` chain meant
           metasploit() only ever ran when exploitdb() "succeeded". */
        if (exploitdb(&n[i], fptr) != 0)
            fprintf(stderr, "No exploits found for host %s\n", n[i].host);

        if (metasploit(&n[i], fptr) != 0)
            fprintf(stderr, "No exploits found for host %s\n", n[i].host);

        i++;
        fclose(nikto_file);
    }
    fclose(hosts);
}

int exploitdb(nikto *n, FILE *fptr) {
    char exploit_cmd[512];
    snprintf(exploit_cmd, sizeof(exploit_cmd), "searchsploit %s %s",
             n->service, n->version);
    FILE *fp = popen(exploit_cmd, "r");
    if (fp == NULL) {
        printf("Failed to run command\n");
        return 1;
    }

    fprintf(fptr, "      **Exploit DB Results**\n");
    char path[1024];
    while (fgets(path, sizeof(path), fp) != NULL)
        fprintf(fptr, "           - %s", path);
    pclose(fp);

    for (int i = 0; i < n->cve_count; i++) {
        char cve_cmd[512];
        snprintf(cve_cmd, sizeof(cve_cmd), "searchsploit %s", n->cve[i]);
        FILE *cve_fp = popen(cve_cmd, "r");
        if (cve_fp == NULL) {
            printf("Failed to run command for CVE %s\n", n->cve[i]);
            continue;
        }
        fprintf(fptr, "      **Exploit DB Results for CVE %s**\n", n->cve[i]);
        while (fgets(path, sizeof(path), cve_fp) != NULL)
            fprintf(fptr, "           - %s", path);
        pclose(cve_fp);
    }
    return 0;
}

int metasploit(nikto *n, FILE *fptr) {
    char metasploit_cmd[512];
    snprintf(metasploit_cmd, sizeof(metasploit_cmd),
             "msfconsole -q -x \"search info:%s %s; quit\"",
             n->service, n->version);
    FILE *fp = popen(metasploit_cmd, "r");
    if (fp == NULL) {
        printf("Failed to run command\n");
        return 1;
    }

    fprintf(fptr, "      **Metasploit Results**\n");
    char path[1024];
    while (fgets(path, sizeof(path), fp) != NULL)
        fprintf(fptr, "           - %s", path);
    pclose(fp);

    for (int i = 0; i < n->cve_count; i++) {
        char cve_cmd[512];
        snprintf(cve_cmd, sizeof(cve_cmd),
                 "msfconsole -q -x \"search cve:%s; quit\"", n->cve[i]);
        FILE *cve_fp = popen(cve_cmd, "r");
        if (cve_fp == NULL) {
            printf("Failed to run command for CVE %s\n", n->cve[i]);
            continue;
        }
        fprintf(fptr, "      **Metasploit Results for CVE %s**\n", n->cve[i]);
        while (fgets(path, sizeof(path), cve_fp) != NULL)
            fprintf(fptr, "           - %s", path);
        pclose(cve_fp);
    }
    return 0;
}

int deepblue_run(void) {
    char path[2048];
    snprintf(path, sizeof(path), "%s/interesting_hosts.txt", g.dir);

    /* Count non-empty lines locally instead of relying on line() */
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

    /* calloc so every host starts with cve=NULL, cve_cap=0 */
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