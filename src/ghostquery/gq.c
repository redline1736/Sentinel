#define _DEFAULT_SOURCE
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
 * Constants
 * ============================================================================ */

int ghostquery_full(char *url, char *path, char *report_dir) {
    if (!url || !path) {
        fprintf(stderr, "ghostquery_full: invalid arguments\n");
        return 1;
    }
    printf("[ghostquery_full] Starting XSS scan on %s\n", url);
    xss_run(url, path, report_dir);
    nuclei_run(url, path);
    sql_run(url, path);
    openredirect_run(url, path);
    return 0;                              /* <-- add this */
}