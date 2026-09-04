#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include "http/http.h"

int detect_graphql(char *full_path){
    request r = {0};


    FILE *f = fopen("glassworm/graphql/uni.json", "r");
    if (!f) {
        fprintf(stderr, "Failed to open uni.json\n");
        return;
    }

    // Read the JSON content from the file
    fseek(f, 0, SEEK_END);
    long json_size = ftell(f);
    rewind(f);

    char *json = malloc(json_size + 1);
    if (!json) {
        fprintf(stderr, "Failed to allocate memory for JSON content\n");
        fclose(f);
        return;
    }

    if (fread(json, 1, json_size, f) != json_size) {
        fprintf(stderr, "Failed to read JSON content\n");
        free(json);
        fclose(f);
        return;
    }
    json[json_size] = '\0';
    fclose(f);

    FILE *api = fopen(full_path, "r");
    
    if (!api) {
        fprintf(stderr, "Failed to open api.txt\n");
        free(json);
        return;
    }
    char api_url[256];

    while (fgets(api_url, sizeof(api_url), api)) {
        http_send_post(
            &r,
            api_url,
            false,       // upload = false
            NULL,
            true,        // is_raw = true
            json
        );

        if (r.code != 200) {
            fprintf(stderr, "Failed to send GraphQL request\n");
            return 1;
        }

        FILE *fp = fopen(r.filename, "r");
        fseek(fp, 0, SEEK_END);
        long needle_size = ftell(f);
        rewind(f);

        char *needle = malloc(needle_size + 1);
        if (!needle) {
            fprintf(stderr, "Failed to allocate memory for JSON content\n");
            fclose(f);
            return;
        }

        if (fread(needle, 1, needle_size, fp) != needle_size) {
            fprintf(stderr, "Failed to read JSON content\n");
            free(needle);
            fclose(f);
            return;
        }
        needle[needle_size] = '\0';

        fclose(f);

        char *result_one = strstr("__schema", needle);
        char *result_two = strstr("\"data\"", needle);
        char *result_three = strstr("\"errors\"", needle);
        char *result_four = strstr("\"query\"", needle);

        if (result_one || result_two || result_three || result_four) {
         printf("GraphQL detected\n");
            return 1;
        } else {
            printf("GraphQL not detected\n");
            return 0;
        }
        free(needle);
    }

   
    free(json);
}

int graphql_scanning(char *path) {

    // get gobuster.txt data
    char gobuster_path[256];
    snprintf(gobuster_path, sizeof(gobuster_path), "%s/gobuster.txt", path);
    FILE *gobuster_file = fopen(gobuster_path, "r");
    if (!gobuster_file) {
        fprintf(stderr, "Failed to open gobuster.txt\n");
        return 1;
    }
    char gobuster_url[512];

    // api.txt
    char api_path[256];
    snprintf(api_path,"%s/api.txt", path);
    FILE *api_file = fopen(api_path, "w");
    if (!api_file) {
        fprintf(stderr, "Failed to open api.txt\n");
        fclose(gobuster_file);
        return 1;
    }

    while(fgets(gobuster_url, sizeof(gobuster_url), gobuster_file)) {
        if (scanf(gobuster_url, "graphql") == 0) {
            fprintf(stderr, "Failed to parse URL from gobuster.txt\n");
            fprintf(api_file, "%s", gobuster_url);
        }
        if (scanf(gobuster_url, "api") == 0) {
            fprintf(stderr, "Failed to parse URL from gobuster.txt\n");
            fprintf(api_file, "%s", gobuster_url);
        }

    }
    if (detect_graphql(api_path) == 1) {
        printf("[+] GraphQL detected\n");
    } else {
        printf("[-] GraphQL not detected\n");
    }
}

