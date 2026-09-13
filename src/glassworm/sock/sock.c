#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "sock.h"


int init_socket(const char *path) {
    unlink(path); 
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return -1; }

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind"); close(fd); return -1;
    }
    listen(fd, 1);
    printf("Listening on %s\n", SOCK_PATH);
    return fd;
}
int accept_connection(int sockfd){
    int client = accept(sockfd, NULL, NULL);
    if (client < 0) { perror("accept"); return -1; }
    return client;
}
int send_message(int client, const char *msg){
    ssize_t n = send(client, msg, strlen(msg), 0);
    if (n < 0) { perror("send"); return -1; }
    return 0;
}
int receive_message(int client, char *buf, size_t buf_size){
    ssize_t n = recv(client, buf, buf_size - 1, 0);
    if (n < 0) { perror("recv"); return -1; }
    buf[n] = '\0';
    return n;
}
int close_socket(int sockfd, int client){
    if (close(sockfd) < 0 && close(client) < 0) { perror("close"); return -1; }
    unlink(SOCK_PATH);
    return 0;
}
