#ifndef GQ_H
#define GQ_H

typedef struct {
    char *url;
    char *path;
    char *report_dir;
} ghostquery_t;

/* Run every ghostquery stage against one URL:
 * xss -> nuclei -> sql -> openredirect. Results in `path`. */
int   ghostquery_full(char *url, char *path, char *report_dir);

/* Thread entry point: arg is a ghostquery_t*. */
void *ghostquery_run(void *arg);

#endif /* GQ_H */