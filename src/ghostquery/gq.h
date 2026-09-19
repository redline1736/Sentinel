#ifndef GQ_H
#define GQ_H

/* Function prototypes */
int xss_run(char *url, char *path, char *report_dir);
int nuclei_run(char *url, char *path);
int sql_run(void);
int find_param_reflecting(char *url, char *path);
int file_exists(const char *filename);

#endif /* GQ_H */