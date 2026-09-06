#ifndef GQ_H
#define GQ_H

#ifdef __cplusplus
extern "C" {
#endif

/* Function prototypes */
int xss_run(char *url, char *path);
int sql_run(void);
int find_param_reflecting(char *url, char *path);
int file_exists(const char *filename);

#ifdef __cplusplus
}
#endif

#endif /* GQ_H */