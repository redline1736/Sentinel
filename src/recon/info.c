
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "info.h"

#define PATH_SIZE 2048
#define VALUE_SIZE 512

static int build_path(char *dest, size_t size,
                      const char *directory, const char *filename) {
    if (!dest || !directory || !filename)
        return -1;

    int written = snprintf(dest, size, "%s/%s", directory, filename);

    if (written < 0 || (size_t)written >= size)
        return -1;

    return 0;
}

int check_api(const request *root, const char *target_url, const char *output) {

    static const char *api_markers[] = {
        "X-API-Endpoint",
        "X-API-KEY",
        "X-API-Token",
        "X-RateLimit",
        "Allow",
        NULL
    };

    if (!root || !target_url || !output)
        return -1;

    char api_file[PATH_SIZE];

    if (build_path(api_file, sizeof(api_file), output, "api.txt") != 0) {
        fprintf(stderr, "[recon] API output path too long\n");
        return -1;
    }

    FILE *fp = fopen(api_file, "w");

    if (!fp) {
        perror("[recon] failed to open api.txt");
        return -1;
    }

    char val[VALUE_SIZE];
    int found = 0;

    for (const char **m = api_markers; *m; m++) {

        if (http_get_header(root, *m, val, sizeof(val))) {

            printf("[recon] API marker '%s' -> %s\n", *m, val);

            fprintf(fp, "%s: %s\n", *m, val);

            found++;
        }
    }

    if (found) {
        printf("[recon] API-related headers found for: %s\n",
               target_url);
    } else {
        printf("[recon] No API-related headers found for: %s\n",
               target_url);
    }

    if (fclose(fp) != 0) {
        perror("[recon] failed to close api.txt");
        return -1;
    }

    return found;
}

static int header_rate(const request *r, const char *output) {

    if (!r || !output)
        return -1;

    char info_file[PATH_SIZE];

    if (build_path(info_file, sizeof(info_file), output, "info.txt") != 0) {
        fprintf(stderr, "[recon] info output path too long\n");
        return -1;
    }

    FILE *fp = fopen(info_file, "w");

    if (!fp) {
        perror("[recon] failed to open info.txt");
        return -1;
    }

    char val[VALUE_SIZE];
    int found = 0;

    if (http_get_header(r, "X-RateLimit-Limit",
                        val, sizeof(val))) {

        printf("[recon] X-RateLimit-Limit: %s\n", val);
        fprintf(fp, "X-RateLimit-Limit: %s\n", val);
        found++;

    } else {
        printf("[recon] X-RateLimit-Limit: not found in response.\n");
    }

    if (http_get_header(r, "X-RateLimit-Remaining",
                        val, sizeof(val))) {

        printf("[recon] X-RateLimit-Remaining: %s\n", val);
        fprintf(fp, "X-RateLimit-Remaining: %s\n", val);
        found++;

    } else {
        printf("[recon] X-RateLimit-Remaining: not found in response.\n");
    }

    if (fclose(fp) != 0) {
        perror("[recon] failed to close info.txt");
        return -1;
    }

    return found;
}

int recon(const char *target_url, const char *output) {

    if (!target_url || !target_url[0] ||
        !output || !output[0]) {
        fprintf(stderr, "[recon] invalid arguments\n");
        return -1;
    }

    request root = {0};

    int findings = 0;

    int ok_root = http_send_get(&root, target_url);

    if (!ok_root || root.code == 0) {

        fprintf(stderr,
                "[recon] root request failed for %s\n",
                target_url);

    } else {

        printf("[recon] %s -> HTTP %d\n",
               target_url, root.code);

        int rate_findings = header_rate(&root, output);

        if (rate_findings > 0)
            findings += rate_findings;

        int api_findings = check_api(&root, target_url, output);

        if (api_findings > 0)
            findings += api_findings;
    }

    request_free(&root);

    return findings;
}
