#include "../global.h"
#include "graphql/gq.h"
#include "sock/sock.h"
#include "../util/util.h"
#include "../http/http.h"
#include "csrf/csrf.h"

int graphql(char *path, bool gobuster, char *target_url) {
    return graphql_scanning(path, gobuster, target_url);
}

int csrf(char *target_url) {
    return csrf_token_exists(target_url);
}