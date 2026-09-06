#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <curl/curl.h>

#include "http.h"

/* Trim helper */
static char *local_trim(char *s) {
    if (!s) return s;
    char *end = s + strlen(s);
    while (end > s && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r' || end[-1] == '\n')) end--;
    *end = '\0';
    char *start = s;
    while (*start && (*start == ' ' || *start == '\t')) start++;
    if (start != s) memmove(s, start, strlen(start) + 1);
    return s;
}

static size_t write_file(void *ptr, size_t size, size_t nmemb, void *stream) {
    return fwrite(ptr, size, nmemb, (FILE *)stream);
}

static const char* detect_content_type(const char *filename) {
    const char *ext = strrchr(filename, '.');
    if (!ext) return "application/octet-stream";
    
    if (strcmp(ext, ".json") == 0) return "application/json";
    if (strcmp(ext, ".png") == 0) return "image/png";
    if (strcmp(ext, ".jpg") == 0 || strcmp(ext, ".jpeg") == 0) return "image/jpeg";
    if (strcmp(ext, ".gif") == 0) return "image/gif";
    if (strcmp(ext, ".txt") == 0) return "text/plain";
    if (strcmp(ext, ".html") == 0) return "text/html";
    if (strcmp(ext, ".css") == 0) return "text/css";
    if (strcmp(ext, ".js") == 0) return "application/javascript";
    if (strcmp(ext, ".xml") == 0) return "application/xml";
    if (strcmp(ext, ".pdf") == 0) return "application/pdf";
    if (strcmp(ext, ".zip") == 0) return "application/zip";
    
    return "application/octet-stream";
}


static bool setup_curl(CURL *curl, const char *url, FILE *fp) {
    if (!curl || !url || !fp) return false;

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_file);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 10L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "minilang/1.0");
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    // Disable verbose for production, but keep for debugging
    // curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    
    return true;
}

static int save_response(request *r, CURL *curl, const char *filename) {
    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);

    if (r) {
        r->code = (int)code;
        snprintf(r->filename, sizeof(r->filename), "%s", filename);
    }

    return 1;
}

int http_send_get(request *r, const char *url) {
    static unsigned int counter = 0;

    char filename[64];
    snprintf(filename, sizeof(filename), "curl_%u.txt", counter++);

    FILE *fp = fopen(filename, "wb");
    if (!fp) return 0;

    CURL *curl = curl_easy_init();
    if (!curl) { fclose(fp); remove(filename); return 0; }

    if (!setup_curl(curl, url, fp)) {
        fclose(fp);
        curl_easy_cleanup(curl);
        remove(filename);
        return 0;
    }

    CURLcode result = curl_easy_perform(curl);
    if (result != CURLE_OK) {
        fprintf(stderr, "GET failed: %s\n", curl_easy_strerror(result));
        fclose(fp);
        curl_easy_cleanup(curl);
        remove(filename);
        return 0;
    }

    fclose(fp);
    save_response(r, curl, filename);
    curl_easy_cleanup(curl);
    return 1;
}

int http_send_post(request *r, const char *url,
                   bool upload, const char *data,
                   bool is_raw, const char *raw_data) {
    static unsigned int counter = 0;

    char filename[64];
    snprintf(filename, sizeof(filename), "curl_%u.txt", counter++);

    FILE *fp = fopen(filename, "wb");
    if (!fp) return 0;

    CURL *curl = curl_easy_init();
    if (!curl) { fclose(fp); remove(filename); return 0; }

    if (!setup_curl(curl, url, fp)) {
        fclose(fp);
        curl_easy_cleanup(curl);
        remove(filename);
        return 0;
    }

    CURLcode result;
    curl_mime *mime = NULL;
    struct curl_slist *headers = NULL;

    if (is_raw) {
        // Raw POST (JSON, XML, etc.)
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, raw_data ? raw_data : "");
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, raw_data ? strlen(raw_data) : 0);
        result = curl_easy_perform(curl);
        curl_slist_free_all(headers);
    } else if (upload) {
        // Multipart file upload
        if (!data) {
            fclose(fp);
            curl_easy_cleanup(curl);
            remove(filename);
            return 0;
        }
        
        FILE *test = fopen(data, "rb");
        if (!test) {
            fprintf(stderr, "File does not exist: %s\n", data);
            fclose(fp);
            curl_easy_cleanup(curl);
            remove(filename);
            return 0;
        }
        fclose(test);
        
        mime = curl_mime_init(curl);
        if (!mime) {
            fclose(fp);
            curl_easy_cleanup(curl);
            remove(filename);
            return 0;
        }

        curl_mimepart *part = curl_mime_addpart(mime);
        curl_mime_filedata(part, data);
        
        const char *content_type = detect_content_type(data);
        curl_mime_type(part, content_type);
        
        curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);

        result = curl_easy_perform(curl);
        curl_mime_free(mime);
    } else {
        // Empty POST (default)
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "");
        result = curl_easy_perform(curl);
    }

    if (result != CURLE_OK) {
        fprintf(stderr, "POST failed: %s\n", curl_easy_strerror(result));
        fclose(fp);
        curl_easy_cleanup(curl);
        remove(filename);
        return 0;
    }

    fclose(fp);
    save_response(r, curl, filename);
    curl_easy_cleanup(curl);
    return 1;
}