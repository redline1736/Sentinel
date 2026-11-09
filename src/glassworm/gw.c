#include "../global.h"
#include "../util/util.h"
#include "../http/http.h"
#include "csrf/csrf.h"


int csrf(char *target_url) {
    return csrf_token_exists(target_url);
}

int glassworm_run(char *url, char *path) {
    if (!url || !path) {
        fprintf(stderr, "glassworm_run: invalid arguments\n");
        return 1;
    }

    printf("[glassworm_run] Running CSRF scan...\n");
    int rc = csrf(url);
    if (rc == 1) {
        printf("[glassworm_run] CSRF token found on %s\n", url);
    } else if (rc == 0) {
        printf("[glassworm_run] No CSRF token found on %s\n", url);
    } else {
        fprintf(stderr, "[glassworm_run] Error checking CSRF token on %s\n", url);
    }

    return rc;
}