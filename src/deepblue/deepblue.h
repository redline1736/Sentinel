#ifndef DEEPBLUE_H
#define DEEPBLUE_H

#include <stdio.h>

/* Per-host CVE collection parsed from nikto output. Moved out of
   deepblue.c so scan.c (which includes this header) compiles. */
typedef struct {
    char host[128];
    char service[128];
    char version[128];
    char ip[128];
    char **cve;       /* dynamic array of CVE string pointers */
    int  cve_count;   /* number of CVEs stored          */
    int  cve_cap;     /* allocated capacity of cve[]    */
} nikto;

int cve_allocate(nikto *n);
int metasploit(nikto *n, FILE *fptr);
int exploitdb(nikto *n, FILE *fptr);
int load_exploit_module(nikto *n, FILE *fptr);
void find_exploit(nikto *n, int length);
int deepblue_run(void);

#endif /* DEEPBLUE_H */