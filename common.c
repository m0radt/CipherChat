#include "common.h"
#include <stdio.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdarg.h>
#include <openssl/err.h>
#include <poll.h>

static int is_valid_frame_type(FrameType type){
    switch (type) {
    case FRAME_FILE_BEGIN:
    case FRAME_FILE_CHUNK:
    case FRAME_FILE_END:
    case FRAME_FILE_ERROR:
    case FRAME_TEXT:
        return 1;
    }

    return 0;
}


ssize_t send_all(Connection *connection, const void *buff, size_t length){
    if (connection == NULL || connection->ssl == NULL ||
        connection->socket_fd < 0 ||(buff == NULL && length != 0)) {
        errno = EINVAL;
        return -1;
    }

    const unsigned char *bytes = buff;
    if (connection->tls_io_failed) {
        errno = ECONNRESET;
        return -1;
    }
    size_t total_sent = 0;

    while (total_sent < length){
        size_t written  = 0;
        ERR_clear_error();
        errno = 0;

        int result = SSL_write_ex(connection->ssl, bytes + total_sent, length - total_sent, &written);
        int saved_errno = errno;

        if (result == 1) {
            total_sent += written;
            continue;
        }

        int ssl_error = SSL_get_error(connection->ssl, result);

        if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
            struct pollfd pfd = {
                .fd = connection->socket_fd,
                .events = ssl_error == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT
            };
            int ready = 0;
            do{
                ready = poll(&pfd, 1, -1);
            } while (ready == -1 && errno == EINTR);

            if (ready == -1) {
                connection->tls_io_failed = true;
                return -1;
            }
            if (pfd.revents & POLLNVAL) {
                connection->tls_io_failed = true;
                errno = EBADF;
                return -1;
            }
            continue;
        }
        if (ssl_error != SSL_ERROR_ZERO_RETURN) {
            connection->tls_io_failed = true;
        }
        ERR_print_errors_fp(stderr);
        if (ssl_error == SSL_ERROR_ZERO_RETURN) {
            errno = EPIPE;
        } else if (ssl_error == SSL_ERROR_SYSCALL && saved_errno != 0) {
            errno = saved_errno;
        } else {
            errno = ECONNRESET;
        }
        return -1;
    }

    return (ssize_t)total_sent;
}




ssize_t send_message(Connection *connection, const char *message, size_t length){

    if (message == NULL || length == 0) {
        errno = EINVAL;
        return -1;
    }

    /* Text receivers need one additional byte for the null terminator. */
    if (length >= BUFFER_SIZE) {
        errno = EMSGSIZE;
        return -1;
    }

    uint32_t network_length = htonl((uint32_t)length);

    if (send_all(connection, &network_length, sizeof(network_length)) == -1) {
        return -1;
    }

    if (send_all(connection, message, length) == -1) {
        return -1;
    }

    return (ssize_t)length;
}

ssize_t send_frame(Connection *connection, FrameType type, const void *payload, size_t payload_length){
    if (!is_valid_frame_type(type) ||
        (payload == NULL && payload_length != 0)) {
        errno = EINVAL;
        return -1;
    }

    if (payload_length > FRAME_MAX_SIZE - 1) {
        errno = EMSGSIZE;
        return -1;
    }

    size_t frame_length = 1 + payload_length;
    uint32_t network_length = htonl((uint32_t)frame_length);
    unsigned char frame_type = (unsigned char)type;

    if (send_all(connection, &network_length, sizeof(network_length)) == -1) {
        return -1;
    }

    if (send_all(connection, &frame_type, sizeof(frame_type)) == -1) {
        return -1;
    }

    if (payload_length != 0 &&
        send_all(connection, payload, payload_length) == -1) {
        return -1;
    }

    return (ssize_t)frame_length;
}

ssize_t recv_all(Connection *connection, void *buff, size_t length) {
    if (connection == NULL || connection->ssl == NULL ||
        connection->socket_fd < 0 || (buff == NULL && length != 0)) {
        errno = EINVAL;
        return -1;
    }

    unsigned char *bytes = buff;
    if (connection->tls_io_failed) {
        errno = ECONNRESET;
        return -1;
    }
    size_t total_received = 0;

    while (total_received < length) {
        size_t bytes_received = 0;

        ERR_clear_error();
        errno = 0;

        int result = SSL_read_ex(
            connection->ssl,
            bytes + total_received,
            length - total_received,
            &bytes_received
        );
        int saved_errno = errno;

        if (result == 1) {
            total_received += bytes_received;
            continue;
        }

        int error = SSL_get_error(connection->ssl, result);

        if (error == SSL_ERROR_ZERO_RETURN) {
            break;
        }

        if (error == SSL_ERROR_WANT_READ ||
            error == SSL_ERROR_WANT_WRITE) {
            /* On our blocking sockets, this indicates a timeout. */
            if (saved_errno == EAGAIN || saved_errno == EWOULDBLOCK) {
                if (error == SSL_ERROR_WANT_WRITE) {
                    connection->tls_io_failed = true;
                }
                errno = saved_errno;
                return -1;
            }

            continue;
        }

        connection->tls_io_failed = true;
        ERR_print_errors_fp(stderr);

        if (error == SSL_ERROR_SYSCALL && saved_errno != 0) {
            errno = saved_errno;
        } else {
            errno = ECONNRESET;
        }

        return -1;
    }

    return (ssize_t)total_received;
}

ssize_t receive_message(Connection *connection, char *buffer, size_t capacity) {
    if (buffer == NULL || capacity < 2) {
        errno = EINVAL;
        return -1;
    }

    uint32_t network_length;

    ssize_t header_bytes = recv_all(connection, &network_length, sizeof(network_length));

    if (header_bytes == 0) {
        /* Clean disconnection before a new field/message. */
        return 0;
    }

    if (header_bytes != (ssize_t)sizeof(network_length)) {
        /* Disconnected in the middle of a field/message. */
        if (header_bytes >= 0) {
            errno = ECONNRESET;
        }

        return -1;
    }

    uint32_t message_length = ntohl(network_length);

    if (message_length == 0 ||
        message_length >= BUFFER_SIZE ||
        message_length >= capacity) {
        errno = EMSGSIZE;
        return -1;
    }

    ssize_t payload_bytes = recv_all(connection, buffer, message_length);

    if (payload_bytes != (ssize_t)message_length) {
        if (payload_bytes >= 0) {
            /* Disconnected in the middle of a field/message. */
            errno = ECONNRESET;
        }

        return -1;
    }

    buffer[message_length] = '\0';
    return (ssize_t)message_length;
}

ssize_t receive_frame(Connection *connection, unsigned char *frame, size_t capacity){
    if (frame == NULL || capacity == 0) {
        errno = EINVAL;
        return -1;
    }

    uint32_t network_length;
    ssize_t header_bytes = recv_all(
        connection,
        &network_length,
        sizeof(network_length)
    );

    if (header_bytes == 0) {
        return 0;
    }

    if (header_bytes != (ssize_t)sizeof(network_length)) {
        if (header_bytes >= 0) {
            errno = ECONNRESET;
        }

        return -1;
    }

    uint32_t frame_length = ntohl(network_length);

    if (frame_length == 0 ||
        frame_length > FRAME_MAX_SIZE ||
        frame_length > capacity) {
        errno = EMSGSIZE;
        return -1;
    }

    ssize_t frame_bytes = recv_all(connection, frame, frame_length);

    if (frame_bytes != (ssize_t)frame_length) {
        if (frame_bytes >= 0) {
            errno = ECONNRESET;
        }

        return -1;
    }

    if (!is_valid_frame_type((FrameType)frame[0])) {
        errno = EPROTO;
        return -1;
    }

    return frame_bytes;
}



void set_timeout_for_socket(int socket_fd){
    struct timeval timeout = {
        .tv_sec = LOGIN_TIMEOUT_SEC,
        .tv_usec = 0
    };

    if (setsockopt(
            socket_fd,
            SOL_SOCKET,
            SO_RCVTIMEO,
            &timeout,
            sizeof(timeout)
        ) < 0) {
        perror("setsockopt set_timeout");
    }
}
void unset_timeout_for_socket(int socket_fd){
    struct timeval no_timeout = {0};
    if (setsockopt(
            socket_fd,
            SOL_SOCKET,
            SO_RCVTIMEO,
            &no_timeout,
            sizeof(no_timeout)
        ) < 0) {
        perror("setsockopt unset_timeout");
    }
}




int format_message(char *buffer, size_t capacity, const char *format, ...){
    va_list arguments;

    va_start(arguments, format);

    int written = vsnprintf(
        buffer,
        capacity,
        format,
        arguments
    );

    va_end(arguments);

    if (written < 0) {
        return -1;
    }

    if ((size_t)written >= capacity) {
        /* The formatted message did not fit. */
        return -1;
    }

    return written;
}
