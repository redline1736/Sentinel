#include "info.h"

int check_api(request* r[2], char* target_url) {
    char api_url[256];
    snprintf(api_url, sizeof(api_url), "%s/api", target_url);
    http_send_post(r[0], target_url, false, NULL, false, NULL);
    http_send_option(r[1], api_url);
    // API IDENFICATION: Check for specific headers in the response files
    if (find_string_in_file(r[0].filename, "X-API-Endpoint")|| find_string_in_file(r[0].filename, "X-API-KEY")|| find_string_in_file(r[0].filename, "X-API-Token")) {
        printf("API endpoint found at: %s\n", api_url);
        return 0;
    } else {
        printf("API endpoint not found at: %s\n", api_url);
    }
    return 1;
}
int header_rate(request* r, char* target url){
    int ratelimit =  0;
    int ratelimit_remaining = 0;
    if (get_value_from_file(r.filename, "X-RateLimit-Limit: %d", NULL, ratelimit)) {
        printf("X-RateLimit-Limit: %d\n", ratelimit);
    } else {
        printf("X-RateLimit-Limit: not found in response.\n");
    }
    if (get_value_from_file(r.filename, "X-RateLimit-Remaining: %d", NULL, ratelimit_remaining)) {
        printf("X-RateLimit-Remaining: %d\n", ratelimit_remaining);
    } else {
        printf("X-RateLimit-Remaining: not found in response.\n");
    }
}

int recon(char *target_url) {
    request r[2];

    int api = check_api(&r, target_url);

    return 0;
}