#include "../../global.h"
#include "../../util/util.h"
#include "../../http/http.h"

int find_parameter(char *url, char *parameter) {
    char *param_start = strstr(url, parameter);
    if (param_start == NULL) {
        return -1; // Parameter not found
    }
    return param_start - url; // Return the index of the parameter in the URL
}