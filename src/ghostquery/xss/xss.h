#ifndef XSS_H
#define XSS_H

int xss_run(const char *url, const char *path, const char *report_dir);
int nuclei_run(const char *url, const char *path);
int find_param_reflecting(const char *url, const char *path);
int file_exists(const char *filename);

#endif /* XSS_H */