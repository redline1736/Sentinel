/* _GNU_SOURCE supplied via CFLAGS (-D_GNU_SOURCE) — do not redefine. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>
#include "util.h"
#include "../prox/prox.h"
#include "../global.h"

struct global g;   /* single definition of the global struct */

static size_t write_callback(void *ptr, size_t size, size_t nmemb, void *stream) {
    return fwrite(ptr, size, nmemb, (FILE *)stream);
}

/* libcurl must be global-init'd exactly once across all threads. */
void curl_http_init(void)      { curl_global_init(CURL_GLOBAL_ALL); }
void curl_http_cleanup(void)   { curl_global_cleanup(); }


void delete_file(const char *file) {
    remove(file);
}

int line_count(const char *file) {
    FILE *fp = fopen(file, "r");
    if (!fp) return 0;
    int count = 0, c;
    while ((c = getc(fp)) != EOF)
        if (c == '\n') count++;
    fclose(fp);
    return count;
}


int find_string_in_file(const char *file, const char *string) {
    FILE *fp = fopen(file, "r");
    if (!fp) return 0;
    char line[1024];
    int found = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (contains(line, string)) {
            found = 1;
            break;
        }
    }
    fclose(fp);
    return found;
}
bool contains(const char *haystack, const char *needle) {
    return strstr(haystack, needle) != NULL;
}