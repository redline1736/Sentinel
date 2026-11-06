#include "../global.h"
#include "../util/util.h"
#include "../http/http.h"
#include "csrf/csrf.h"


int csrf(char *target_url) {
    return csrf_token_exists(target_url);
}