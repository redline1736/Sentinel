#ifndef INFO_H
#define INFO_H

#include "../util/util.h"
#include "../global.h"
#include "../http/http.h"

int recon(const char *target_url, const char *output);
int check_api(const request *root, const char *target_url, const char *output);

#endif /* INFO_H */