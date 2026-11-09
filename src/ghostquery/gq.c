#define _DEFAULT_SOURCE
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <ctype.h>
#include <curl/curl.h>
#include <fcntl.h>
#include <dirent.h>
#include <signal.h>

#include "../util/util.h"
#include "../prox/prox.h"
#include "../chrome/chrome.h"
#include "../http/http.h"
#include "../global.h"
#include "sql/sql.h"
#include "xss/xss.h"
#include "openredirect/oprt.h"
#include "gq.h"

/* ============================================================================
 * ghostquery_full — the full ghostquery chain for one URL
 * ============================================================================ */

int ghostquery_full(char *url, char *path, char *report_dir) {
    if (!url || !path) {
        fprintf(stderr, "ghostquery_full: invalid arguments\n");
        return 1;
    }
    if (!report_dir) report_dir = path;

    printf("[ghostquery_full] Starting on %s\n", url);

    xss_run(url, path, report_dir);
    nuclei_run(url, path);
    sql_run(url, path);
    openredirect_run(url, path);

    printf("[ghostquery_full] Done on %s\n", url);
    return 0;
}

void *ghostquery_run(void *arg) {
    ghostquery_t *gq_args = (ghostquery_t *)arg;
    if (!gq_args) return NULL;
    ghostquery_full(gq_args->url, gq_args->path, gq_args->report_dir);
    return NULL;
}