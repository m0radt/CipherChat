#include "server_worker.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/err.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>

/* Return 1 for retry, 0 for TLS EOF, and -1 for a fatal error. */
static int tls_retry(Connection *connection, int result, int saved_errno,
                     short *wait_for) {
    int error = SSL_get_error(connection->ssl, result);
    if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
        *wait_for = error == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT;
        return 1;
    }
    if (error == SSL_ERROR_ZERO_RETURN) {
        return 0;
    }
    connection->tls_io_failed = true;
    errno = error == SSL_ERROR_SYSCALL && saved_errno != 0
        ? saved_errno : ECONNRESET;
    return -1;
}

int run_client_worker(
    Connection *connection,
    ClientId client_id,
    const char *username,
    ServerFrameHandler handle_frame
) {
    int wake_fd = get_client_wake_fd(client_id);
    if (wake_fd == -1) {
        return -1;
    }
    int flags = fcntl(connection->socket_fd, F_GETFL);
    if (flags == -1 ||
        fcntl(connection->socket_fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        return -1;
    }

    /* Buffers and offsets survive WANT_READ/WANT_WRITE. Read exactly one
     * header/body at a time so fragmented and coalesced frames both work. */
    unsigned char incoming[sizeof(uint32_t) + FRAME_MAX_SIZE];
    size_t received = 0;
    size_t needed = sizeof(uint32_t);
    short read_wait = 0;

    unsigned char outgoing[sizeof(uint32_t) + FRAME_MAX_SIZE];
    size_t outgoing_length = 0;
    size_t sent = 0;
    short write_wait = 0;

    for (;;) {
        eventfd_t notifications;
        int result;
        do {
            result = eventfd_read(wake_fd, &notifications);
        } while (result == -1 && errno == EINTR);
        if (result == -1 && errno != EAGAIN) {
            return -1;
        }
        if (client_output_status(client_id) == -1) {
            return -1;
        }

        if (outgoing_length == 0) {
            OutgoingFrame *frame;
            int available = take_outgoing_frame(client_id, &frame);
            if (available == -1) {
                return -1;
            }
            if (available == 1) {
                uint32_t length = htonl((uint32_t)(1 + frame->payload_length));
                memcpy(outgoing, &length, sizeof(length));
                outgoing[sizeof(length)] = (unsigned char)frame->type;
                memcpy(outgoing + sizeof(length) + 1,
                       frame->payload, frame->payload_length);
                outgoing_length = sizeof(length) + 1 + frame->payload_length;
                sent = 0;
                free(frame);
            }
        }

        bool progress = false;

        /* Finish a read that needs to write TLS control data before starting
         * an application write. Otherwise give each direction one turn. */
        if (outgoing_length != 0 && read_wait != POLLOUT) {
            size_t written = 0;
            ERR_clear_error();
            errno = 0;
            result = SSL_write_ex(connection->ssl, outgoing + sent,
                                  outgoing_length - sent, &written);
            int saved_errno = errno;
            if (result == 1) {
                sent += written;
                write_wait = 0;
                progress = true;
                if (sent == outgoing_length) {
                    outgoing_length = 0;
                }
            } else {
                int retry = tls_retry(connection, result, saved_errno,
                                      &write_wait);
                if (retry != 1) {
                    if (retry == 0) {
                        errno = EPIPE;
                    }
                    return -1;
                }
            }
        }

        /* A pending SSL_write is retried with the same pointer and length.
         * In particular WANT_WRITE forbids other TLS I/O until that retry. */
        if (write_wait == 0) {
            size_t count = 0;
            ERR_clear_error();
            errno = 0;
            result = SSL_read_ex(connection->ssl, incoming + received,
                                 needed - received, &count);
            int saved_errno = errno;
            if (result == 1) {
                received += count;
                read_wait = 0;
                progress = true;
                if (received == needed) {
                    if (needed == sizeof(uint32_t)) {
                        uint32_t length;
                        memcpy(&length, incoming, sizeof(length));
                        length = ntohl(length);
                        if (length == 0 || length > FRAME_MAX_SIZE) {
                            errno = EMSGSIZE;
                            return -1;
                        }
                        needed += length;
                    } else {
                        const unsigned char *frame = incoming + sizeof(uint32_t);
                        if (frame[0] > FRAME_TEXT) {
                            errno = EPROTO;
                            return -1;
                        }
                        if (!handle_frame(client_id, username, frame,
                                          needed - sizeof(uint32_t))) {
                            return 0;
                        }
                        received = 0;
                        needed = sizeof(uint32_t);
                    }
                }
            } else {
                int retry = tls_retry(connection, result, saved_errno,
                                      &read_wait);
                if (retry == 0 && received != 0) {
                    errno = ECONNRESET;
                    return -1;
                }
                if (retry != 1) {
                    return retry;
                }
            }
        }

        /* Keep draining decrypted data after every successful read: it may
         * already be inside OpenSSL even when the socket is not readable. */
        if (progress) {
            continue;
        }
        struct pollfd descriptors[2] = {
            {
                .fd = connection->socket_fd,
                .events = write_wait != 0 ? write_wait : read_wait
            },
            { .fd = wake_fd, .events = POLLIN }
        };
        do {
            result = poll(descriptors, 2, -1);
        } while (result == -1 && errno == EINTR);
        if (result == -1) {
            return -1;
        }
        if ((descriptors[0].revents | descriptors[1].revents) & POLLNVAL) {
            errno = EBADF;
            return -1;
        }
        if (descriptors[1].revents & (POLLERR | POLLHUP)) {
            errno = EIO;
            return -1;
        }
        /* Socket HUP/ERR is resolved by the next TLS call, allowing any
         * application data preceding EOF to be consumed first. */
    }
}
