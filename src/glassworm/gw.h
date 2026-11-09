#ifndef GW_H
#define GW_H

/* CSRF check only — thin wrapper over csrf_token_exists().
 * Returns 1 = token present/enforced, 0 = none detected, -1 = probe failed. */
int csrf(char *target_url);


int glassworm_run(const char *base_url, const char *hostdir);

#endif /* GW_H */