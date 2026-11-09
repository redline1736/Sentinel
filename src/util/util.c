/* _GNU_SOURCE supplied via CFLAGS (-D_GNU_SOURCE) — do not redefine. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "util.h"
#include "../prox/prox.h"
#include "../global.h"

struct global g;   /* single definition of the global struct */

void delete_file(const char *file) {
    if (file) remove(file);
}

/* File size without reading it — replaces the getc() line counter
 * for callers that only used line_count() as a progress heuristic. */
long file_size(const char *file) {
    FILE *fp = fopen(file, "rb");
    if (!fp) return -1;
    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    fclose(fp);
    return sz;
}

int line_count(const char *file) {
    FILE *fp = fopen(file, "r");
    if (!fp) return 0;
    int count = 0;
    char buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0)
        for (size_t i = 0; i < n; i++)
            if (buf[i] == '\n') count++;
    fclose(fp);
    return count;
}

int find_string_in_file(const char *file, const char *string) {
    if (!file || !string) return 0;
    FILE *fp = fopen(file, "r");
    if (!fp) return 0;
    int found = 0;
    char *line = NULL;
    size_t cap = 0;
    ssize_t len;
    while ((len = getline(&line, &cap, fp)) > 0) {   /* no 1024-byte truncation */
        if (strstr(line, string)) { found = 1; break; }
    }
    free(line);
    fclose(fp);
    return found;
}

void data_path(const char *rel, char *dst, size_t dstsz) {
    static const char *bases[] = {
        "/usr/share/sentinel/",
        "",                    /* run from repo root: ./ghostquery/params.txt */
        NULL
    };

    if (!rel || !dst || dstsz == 0) return;

    for (int i = 0; bases[i]; i++) {
        char cand[1024];
        if (snprintf(cand, sizeof(cand), "%s%s", bases[i], rel)
                >= (int)sizeof(cand))
            continue;
        if (access(cand, F_OK) == 0) {
            snprintf(dst, dstsz, "%s", cand);
            return;
        }
    }
    /* fallback even if missing, so error messages show a sane path */
    snprintf(dst, dstsz, "/usr/share/sentinel/%s", rel);
}

/* FIXED: correct variable, non-NULL out-params, sane return code.
 * parse = sscanf format with exactly one conversion (%s or %d).
 * Pass svalue (char*, size sbuf) for strings, or &ivalue for ints. */
int get_value_from_file(const char *file, const char *key,
                        const char *parse, char *svalue, size_t sbuf, int *ivalue) {
    if (!file || !key || !parse) return 0;
    FILE *fp = fopen(file, "rb");
    if (!fp) return 0;

    char *line = NULL;
    size_t cap = 0;
    int found = 0;
    ssize_t len;
    while ((len = getline(&line, &cap, fp)) > 0) {
        if (strstr(line, key)) {
            if (svalue) {
                if (sscanf(line, parse, svalue) == 1) {
                    svalue[sbuf - 1] = '\0';
                    found = 1;
                }
            } else if (ivalue) {
                if (sscanf(line, parse, ivalue) == 1) found = 1;
            }
            break;
        }
    }
    free(line);
    fclose(fp);
    return found;   /* 1 = found, 0 = not found */
}

bool contains(const char *haystack, const char *needle) {
    if (!haystack || !needle) return false;
    return strstr(haystack, needle) != NULL;
}