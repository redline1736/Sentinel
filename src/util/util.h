#ifndef UTIL_H
#define UTIL_H
#include <stdbool.h>’
void curl_http_init(void);
void curl_http_cleanup(void);
void delete_file(const char *file);
int  line_count(const char *file);
int  find_string_in_file(const char *file, const char *string);
bool contains(const char *haystack, const char *needle);

#endif