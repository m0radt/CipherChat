
#ifndef COMMON_H
#define COMMON_H
#include "network.h"
#include <unistd.h>
#define BUFFER_SIZE 1024
#define FRAME_MAX_SIZE BUFFER_SIZE
#define SERVER_PORT 8080
#define USERNAME_SIZE 32
#define SERVER_IP "127.0.0.1"
#define TIMEOUT 200
#define LOGIN_TIMEOUT_SEC 10
#define FILE_CHUNK_SIZE 900

typedef enum {
    FRAME_FILE_BEGIN,
    FRAME_FILE_CHUNK,
    FRAME_FILE_END,
    FRAME_FILE_ERROR,
    FRAME_TEXT
} FrameType;

ssize_t send_all(Connection *connection, const void *buff, size_t length);
ssize_t recv_all(Connection *connection, void *buff, size_t length);
ssize_t send_message(Connection *connection, const char *message, size_t length);
ssize_t receive_message(Connection *connection, char *buffer, size_t capacity);
ssize_t send_frame(Connection *connection, FrameType type, const void *payload, size_t payload_length);
ssize_t receive_frame(Connection *connection, unsigned char *frame, size_t capacity);
void set_timeout_for_socket(int socket_fd);
void unset_timeout_for_socket(int socket_fd);
int format_message(char *buffer, size_t capacity, const char *format, ...);

#endif
