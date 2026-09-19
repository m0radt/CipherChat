#define _POSIX_C_SOURCE 200809L
#include "network.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdint.h>
#include <time.h>
#include <openssl/ssl.h>
#include <openssl/err.h>


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

int accept_client(int server_fd, Connection *connection) {
    *connection = (Connection){.socket_fd = -1, .ssl = NULL};
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
    connection->socket_fd = client_fd;

    /* The client worker performs the handshake, leaving accept responsive. */
    return 0;
}

int connect_to_server(const char *server_ip, int server_port, Connection *connection) {
    *connection = (Connection){.socket_fd = -1, .ssl = NULL};
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
    connection->socket_fd = client_fd;
    return perform_tls_handshake(connection, 1, server_ip);
}

// SSL/TLS functions
static SSL_CTX *create_context(int is_client) {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = is_client ? TLS_client_method() : TLS_server_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Set the minimum and maximum TLS version to 1.3
    if (SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1 ||
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) != 1) {
        fprintf(stderr, "Failed to set TLS version to 1.3\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    // Load the server's certificate and private key and check if they are valid
    if (!is_client) {
        if (SSL_CTX_use_certificate_chain_file(ctx, "certs/server.crt") != 1 ||
            SSL_CTX_use_PrivateKey_file(
                ctx, "certs/server.key", SSL_FILETYPE_PEM
            ) != 1 ||
            SSL_CTX_check_private_key(ctx) != 1) {

            fprintf(stderr, "Failed to load server certificate/private key\n");
            ERR_print_errors_fp(stderr);
            SSL_CTX_free(ctx);
            exit(EXIT_FAILURE);
        }
    }
    else {
        // Load the CA certificate for client verification
        if (SSL_CTX_load_verify_locations(ctx, "certs/server.crt", NULL) != 1) {
            fprintf(stderr, "Failed to load CA certificate\n");
            ERR_print_errors_fp(stderr);
            SSL_CTX_free(ctx);
            exit(EXIT_FAILURE);
        }
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    }
    return ctx;
}

static int64_t monotonic_milliseconds(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
        return -1;
    }
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static int remaining_milliseconds(int64_t deadline) {
    int64_t now = monotonic_milliseconds();
    if (now == -1) {
        return -1;
    }
    if (now >= deadline) {
        errno = ETIMEDOUT;
        return -1;
    }
    int64_t remaining = deadline - now;
    return remaining > INT_MAX ? INT_MAX : (int)remaining;
}

static int wait_for_tls(int socket_fd, int error, int64_t deadline) {
    struct pollfd descriptor = {
        .fd = socket_fd,
        .events = error == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT
    };
    for (;;) {
        int remaining = remaining_milliseconds(deadline);
        if (remaining == -1) {
            return -1;
        }
        int result = poll(&descriptor, 1, remaining);
        if (result == -1 && errno == EINTR) {
            continue; /* Recompute the time left; never restart the timer. */
        }
        if (result == 0) {
            errno = ETIMEDOUT;
            return -1;
        }
        if (result == -1) {
            return -1;
        }
        if (descriptor.revents & POLLNVAL) {
            errno = EBADF;
            return -1;
        }
        return 0; /* TLS resolves readable data, EOF, or a socket error. */
    }
}

/* Both TLS roles use one absolute deadline, including all I/O retries. */
int perform_tls_handshake(Connection *connection, int is_client, const char *server_ip) {
    int64_t started = monotonic_milliseconds();
    if (started == -1) {
        close_connection(connection, false);
        return -1;
    }
    int64_t deadline = started + TLS_HANDSHAKE_TIMEOUT_SEC * 1000;
    SSL_CTX *ssl_ctx = create_context(is_client);
    SSL *ssl = SSL_new(ssl_ctx);

    // Release our reference; a successfully created SSL retains the context.
    SSL_CTX_free(ssl_ctx);

    if (ssl == NULL) {
        goto fail;
    }

    int flags = fcntl(connection->socket_fd, F_GETFL);
    if (flags == -1 ||
        fcntl(connection->socket_fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        goto fail;
    }

    // Bind OpenSSL to the socket descriptor
    if (SSL_set_fd(ssl, connection->socket_fd) != 1) {
        goto fail;
    }
    // If this is a client, set the expected server IP address for verification
    if (is_client) {
        X509_VERIFY_PARAM *param = SSL_get0_param(ssl);

        if (X509_VERIFY_PARAM_set1_ip_asc(param, server_ip) != 1) {
            fprintf(stderr, "Failed to set expected server IP\n");
            goto fail;
        }
    }
    // Perform the TLS Handshake
    printf("Performing TLS handshake...\n");
    for (;;) {
        if (remaining_milliseconds(deadline) == -1) {
            goto fail;
        }
        ERR_clear_error();
        errno = 0;
        int result = is_client ? SSL_connect(ssl) : SSL_accept(ssl);
        int saved_errno = errno;
        if (result == 1) {
            if (remaining_milliseconds(deadline) == -1) {
                goto fail;
            }
            break;
        }
        int error = SSL_get_error(ssl, result);
        if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) {
            fprintf(stderr, "TLS handshake failed (SSL error %d)\n", error);
            errno = error == SSL_ERROR_SYSCALL && saved_errno != 0
                ? saved_errno : EPROTO;
            goto fail;
        }
        if (wait_for_tls(connection->socket_fd, error, deadline) == -1) {
            goto fail;
        }
    }
    /* Login and the interactive client still use blocking I/O. */
    if (fcntl(connection->socket_fd, F_SETFL, flags) == -1) {
        goto fail;
    }
    connection->ssl = ssl;
    connection->tls_io_failed = false;
    printf("TLS handshake successful! Cipher: %s\n", SSL_get_cipher(ssl));
    return 0;
fail: {
    int saved_errno = errno != 0 ? errno : EPROTO;
    if (saved_errno == ETIMEDOUT) {
        fprintf(stderr, "TLS handshake timed out\n");
    }
    ERR_print_errors_fp(stderr);
    SSL_free(ssl);
    close_connection(connection, false);
    errno = saved_errno;
    return -1;
}
}

static void shutdown_tls(Connection *connection) {
    int64_t started = monotonic_milliseconds();
    if (started == -1) {
        return;
    }
    int64_t deadline = started + TLS_SHUTDOWN_TIMEOUT_SEC * 1000;
    int flags = fcntl(connection->socket_fd, F_GETFL);
    if (flags == -1 ||
        fcntl(connection->socket_fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        return;
    }

    bool sent_notify = false;
    unsigned char discarded[4096];
    while (remaining_milliseconds(deadline) != -1) {
        ERR_clear_error();
        errno = 0;
        int result;
        if (!sent_notify) {
            result = SSL_shutdown(connection->ssl);
            if (result == 1) {
                return;
            }
            if (result == 0) {
                /* Zero is success for the sending half, not a TLS error. */
                sent_notify = true;
                continue;
            }
        } else {
            /* The application is closing. Drain any in-flight application
             * data and TLS tickets until the peer replies with close_notify. */
            size_t count;
            result = SSL_read_ex(connection->ssl, discarded,
                                 sizeof(discarded), &count);
            if (result == 1) {
                continue;
            }
        }
        int error = SSL_get_error(connection->ssl, result);
        if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) {
            return; /* Includes the peer's close_notify and fatal TLS errors. */
        }
        if (wait_for_tls(connection->socket_fd, error, deadline) == -1) {
            return;
        }
    }
}

void close_connection(Connection *connection, bool graceful) {
    int saved_errno = errno;
    if (connection->ssl != NULL && connection->socket_fd >= 0 &&
        graceful && !connection->tls_io_failed) {
        shutdown_tls(connection);
    }
    SSL_free(connection->ssl);
    if (connection->socket_fd >= 0) {
        close(connection->socket_fd);
    }
    *connection = (Connection){ .socket_fd = -1 };
    errno = saved_errno;
}
