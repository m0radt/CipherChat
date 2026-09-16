#include "network.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

int create_server_socket(int server_port){
    int server_fd;
    struct sockaddr_in server_addr;

    server_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (server_fd == -1) {
        perror("Socket creation failed");
        return -1;
    }
    printf("Socket successfully created\n");

    int reuse_address = 1;
    if (setsockopt(
            server_fd,
            SOL_SOCKET,
            SO_REUSEADDR,
            &reuse_address,
            sizeof(reuse_address)
        ) == -1) {
        perror("setsockopt SO_REUSEADDR");
        close(server_fd);
        return -1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(server_port);

    

    if(bind(server_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) == -1){
        perror("Socket binding failed");
        close(server_fd);
        return -1;
    }
    printf("Socket successfully binded\n");
    if(listen(server_fd, LISTEN_BACKLOG) == -1){
       perror("listen failed");
       close(server_fd);
       return -1;      
    }
    printf("Server listening\n");
    return server_fd;
}

int accept_client(int server_fd){
    int client_fd;
    socklen_t client_addr_size;
    struct sockaddr_in client_addr;
    client_addr_size = sizeof(client_addr);
    client_fd = accept(server_fd, (struct sockaddr *) &client_addr, &client_addr_size);
    if(client_fd == -1){
        if (errno != EINTR) {
            perror("Server accept failed");
        }
        return -1;
    }
    return client_fd;
}

int connect_to_server(const char *server_ip, int server_port){
    int client_fd;
    struct sockaddr_in server_addr;

    client_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (client_fd == -1) {
        perror("Socket creation failed");
        return -1;
    }
    printf("Socket successfully created\n");

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr.s_addr) != 1) {
        fprintf(stderr, "Invalid server IP address: %s\n", server_ip);
        close(client_fd);
        errno = EINVAL;
        return -1;
    }
    server_addr.sin_port = htons(server_port);


    if(connect(client_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) == -1){
        perror("Connection with server failed");
        close(client_fd);
        return -1;
    }
    printf("connected successfully to the server\n");
    return client_fd;
}

