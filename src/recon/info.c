#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "info.h"

int check_api(const request *root, const char *target_url, char * output) {
    static const char *api_markers[] = {
        "X-API-Endpoint", "X-API-KEY", "X-API-Token",
        "X-RateLimit", "Allow:", NULL
    };
    char api_file[2048];
    snprintf(api_file, sizeof(api_file), "%s/api.txt", output);
    char api_url[2048];
    snprintf(api_url, sizeof(api_url), "%s/api", target_url);

    FILE *fp = fopen(api_file, "w");
    if (!fp) {
        fprintf(stderr, "[recon] failed to open %s for writing\n", api_file);
        fclose(fp);
        return 1;
    }

    char val[512];
    int found = 0;

    for (const char **m = api_markers; *m; m++) {
        if (http_get_header(root, *m, val, sizeof(val))) {
            printf("[recon] API marker '%s' -> %s\n", *m, val);
            if (strcmp(*m, "X-API-Endpoint") != 0){
                fprintf(fp, "%s\n", target_url);
            }
            found++;
        }
    }

    /* OPTIONS response tells us which methods <target>/api actually speaks */
    if (http_get_header(root, "Allow", val, sizeof(val))) {
        printf("[recon] %s/api methods: %s\n", target_url, val);
        found++;
    }

    if (found)
        printf("[recon] API endpoint found at: %s/api\n", target_url);
    else
        printf("[recon] API endpoint not found at: %s/api\n", target_url);
    return found;
}

static void header_rate(const request *r, char *output) {
    char info_file[2048];
    snprintf(info_file, sizeof(info_file), "%s/info.txt", output);
    FILE *fp = fopen(info_file, "w");
    if (!fp) {
        fprintf(stderr, "[recon] failed to open %s for writing\n", info_file);
        fclose(fp);
        return;
    }
    char val[64];
    if (http_get_header(r, "X-RateLimit-Limit", val, sizeof(val))){
        printf("[recon] X-RateLimit-Limit: %s\n", val);
        fprintf(fp, "[recon] X-RateLimit-Limit: %s\n", val);
    
    } else
        printf("[recon] X-RateLimit-Limit: not found in response.\n");

    if (http_get_header(r, "X-RateLimit-Remaining", val, sizeof(val))){
        printf("[recon] X-RateLimit-Remaining: %s\n", val);
        fprintf(fp, "[recon] X-RateLimit-Remaining: %s\n", val);
    }else
        printf("[recon] X-RateLimit-Remaining: not found in response.\n");
}

int recon(const char *target_url, char * output) {
    if (!target_url || !target_url[0]) return -1;

    request root = {0};
    /* strip a possible trailing slash so we don't probe /api// */

    int findings = 0;
    int ok_root = http_send_get(&root, target_url);

    if (!ok_root || root.code == 0) {
        fprintf(stderr, "[recon] root request failed for %s\n", target_url);
    } else {
        printf("[recon] %s -> HTTP %d\n", target_url, root.code);
        header_rate(&root, output);
        findings++;
    }

    findings += check_api(&root, target_url, output);
    request_free(&root);
    return findings;
}