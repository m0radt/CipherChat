#ifndef NETWORK_H
#define NETWORK_H

#define LISTEN_BACKLOG 5
#define TLS_HANDSHAKE_TIMEOUT_SEC 10
#define TLS_SHUTDOWN_TIMEOUT_SEC 2

#include <stdbool.h>
#include <openssl/ssl.h>

typedef struct {
    int socket_fd;
    SSL *ssl;
    /* A fatal TLS error or abandoned write prevents a shutdown exchange. */
    bool tls_io_failed;
} Connection;

int create_server_socket(int server_port);
int accept_client(int server_fd, Connection *connection);
int connect_to_server(const char *server_ip, int server_port, Connection *connection);
int perform_tls_handshake(Connection *connection, int is_client, const char *server_ip);
/* Best-effort bounded TLS shutdown, then always free/close and reset. */
void close_connection(Connection *connection, bool graceful);

#endif
