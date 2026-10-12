#ifndef GQ_H
#define GQ_H

#include <stdbool.h>

int  introspection_check(char *intro_json);
int  detect_graphql(char *api_path, char *graphql_path);
int  graphql_scanning(char *path, bool gobuster, char *target_url);

#endif /* GLASSWORM_SCAN_H */