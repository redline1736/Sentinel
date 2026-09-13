#ifndef SOCK_H
#define SOCK_H

int init_socket(const char *path);
int accept_connection(int sockfd);
int send_message(int sockfd, const char *msg);
int receive_message(int sockfd, char *buf, size_t buf_size);
int close_socket(int sockfd, int client);

#endif