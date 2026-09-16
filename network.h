#ifndef NETWORK_H
#define NETWORK_H

#define LISTEN_BACKLOG 5


int create_server_socket(int server_port);
int accept_client(int server_fd);
int connect_to_server(const char *server_ip, int server_port);

#endif
