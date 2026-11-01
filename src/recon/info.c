#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "info.h"

/* Returns 1 if an API surface was indicated, 0 otherwise. */
static int check_api(const request *root, const request *api, const char *target_url) {
    static const char *api_markers[] = {
        "X-API-Endpoint", "X-API-KEY", "X-API-Token",
        "X-RateLimit", "Allow:", NULL
    };
    char val[512];
    int found = 0;

    for (const char **m = api_markers; *m; m++) {
        if (http_get_header(root, *m, val, sizeof(val)) ||
            http_get_header(api,  *m, val, sizeof(val))) {
            printf("[recon] API marker '%s' -> %s\n", *m, val);
            found = 1;
        }
    }

    /* OPTIONS response tells us which methods <target>/api actually speaks */
    if (http_get_header(api, "Allow", val, sizeof(val))) {
        printf("[recon] %s/api methods: %s\n", target_url, val);
        found = 1;
    }

    if (found)
        printf("[recon] API endpoint found at: %s/api\n", target_url);
    else
        printf("[recon] API endpoint not found at: %s/api\n", target_url);
    return found;
}

static void header_rate(const request *r) {
    char val[64];
    if (http_get_header(r, "X-RateLimit-Limit", val, sizeof(val)))
        printf("[recon] X-RateLimit-Limit: %s\n", val);
    else
        printf("[recon] X-RateLimit-Limit: not found in response.\n");

    if (http_get_header(r, "X-RateLimit-Remaining", val, sizeof(val)))
        printf("[recon] X-RateLimit-Remaining: %s\n", val);
    else
        printf("[recon] X-RateLimit-Remaining: not found in response.\n");
}

int recon(const char *target_url) {
    if (!target_url || !target_url[0]) return -1;

    request root = {0}, api = {0};
    char api_url[2048];
    snprintf(api_url, sizeof(api_url), "%s/api", target_url);
    /* strip a possible trailing slash so we don't probe /api// */
    size_t n = strlen(api_url);
    if (n > 1 && api_url[n - 1] == '/') api_url[n - 1] = '\0';

    int findings = 0;
    int ok_root = http_send_get(&root, target_url);
    int ok_api  = http_send_option(&api, api_url);

    if (!ok_root || root.code == 0) {
        fprintf(stderr, "[recon] root request failed for %s\n", target_url);
    } else {
        printf("[recon] %s -> HTTP %d\n", target_url, root.code);
        header_rate(&root);
        findings++;
    }

    if (ok_api && api.code != 0)
        findings += check_api(&root, &api, target_url);
    else
        printf("[recon] OPTIONS probe of %s failed\n", api_url);

    request_free(&root);
    request_free(&api);
    return findings;
}