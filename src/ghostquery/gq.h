#ifndef GQ_H
#define GQ_H

typedef struct {
    char *url;
    char *path;
    char *report_dir;
} ghostquery_t;

/* Function prototypes */
int ghostquery_full(char *url, char *path, char *report_dir);
void *ghostquery_run(void *arg);

#endif /* GQ_H */