#ifndef OPRT_H
#define OPRT_H
#include <sys/types.h>

/* Open-redirect pass against one URL. Findings -> <path>/openredirect.txt. */
int openredirect_run(const char *url, char *path);
int openredirect_generate_payloads(void);

#endif /* OPRT_H */