#ifndef CLIENT_MANAGER_H
#define CLIENT_MANAGER_H

#include "common.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MAX_CLIENTS 100

typedef uint64_t ClientId;

#define INVALID_CLIENT_ID ((ClientId)0)

typedef struct {
    int socket_fd;
    char username[USERNAME_SIZE];
    bool active;
    bool ready;
    ClientId id;
} Client;

void init_clients(void);
int add_client(int socket_fd, const char *username);
int activate_client(int index);
void remove_client(int index);
ClientId get_client_id(int index);
ClientId find_client_id(const char *username);

int send_frame_to_client_id(
    ClientId client_id,
    FrameType type,
    const void *payload,
    size_t payload_length
);
int send_text_to_client_id(ClientId client_id, const char *message);

void send_message_to_client(
    const char *username,
    const char *message,
    ClientId sender_id
);
void send_message_to_all_clients(
    const char *message,
    ClientId sender_id
);
void log_connected_clients(ClientId client_id);
void send_help(ClientId client_id);
void send_unknown_command(ClientId client_id, const char *command);
void send_invalid_command(ClientId client_id, const char *command);

#endif
