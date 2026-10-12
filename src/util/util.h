#ifndef UTIL_H
#define UTIL_H

void curl_http_init(void);
void curl_http_cleanup(void);
void run_request(const char *url, const char *data, const char *out_path);
void run_requests_json(const char *url, const char *method,
                       const char *file, const char *out_path);
void delete_file(const char *file);
int  line_count(const char *file);
int  find_string_in_file(const char *file, const char *string);
bool contains(const char *haystack, const char *needle);

#endif