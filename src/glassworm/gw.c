#include "../global.h"
#include "../util/util.h"
#include "../http/http.h"
#include "csrf/csrf.h"
#include "xxe/xxe.h"

int csrf(char *target_url) {
    return csrf_token_exists(target_url);
}

int glassworm_run(char *url, char *path) {
    if (!url || !path) {
        fprintf(stderr, "glassworm_run: invalid arguments\n");
        return 1;
    }

    printf("[glassworm_run] Running CSRF scan...\n");
    int rc = csrf(url, path);
    if (rc == 1) {
        printf("[glassworm_run] CSRF token found on %s\n", url);
    } else if (rc == 0) {
        printf("[glassworm_run] No CSRF token found on %s\n", url);
    } else {
        fprintf(stderr, "[glassworm_run] Error checking CSRF token on %s\n", url);
    }
    rc = xxe(url, path);
    if (rc == 0) {
        printf("[glassworm_run] XXE scan completed successfully on %s\n", url);
    } else {
        fprintf(stderr, "[glassworm_run] Error running XXE scan on %s\n", url);
    }
    return 0;
}