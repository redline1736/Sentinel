#ifndef GQ_H
#define GQ_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Function prototypes
int inrropection_check(char *intro_json);

int detect_graphql(char *api_path, char *graphql_path);

int graphql_scanning(char *path, bool gobuster, char target_url);

#endif // GQ_H