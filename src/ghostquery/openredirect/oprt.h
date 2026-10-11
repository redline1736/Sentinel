#ifndef OPRT_H
#define OPRT_H
#include <sys/types.h>

int openredirect_run(char *url, char *path);
int openredirect_generate_payloads(void);

#endif /* OPENREDIRECT_H */