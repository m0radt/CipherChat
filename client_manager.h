#ifndef CLIENT_MANAGER_H
#define CLIENT_MANAGER_H

#include "common.h"
#include "network.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MAX_CLIENTS 100

typedef uint64_t ClientId;

#define INVALID_CLIENT_ID ((ClientId)0)

#define MAX_OUTGOING_FRAMES 128

int queue_frame_to_client_id(
    ClientId client_id,
    FrameType type,
    const void *payload,
    size_t payload_length
);

typedef struct OutgoingFrame {
    FrameType type;
    size_t payload_length;
    unsigned char payload[FRAME_MAX_SIZE - 1];
    struct OutgoingFrame *next;
} OutgoingFrame;

typedef struct {
    Connection connection;
    int wake_fd;
    char username[USERNAME_SIZE];
    bool active;
    bool ready;
    ClientId id;
    OutgoingFrame *outgoing_head;
    OutgoingFrame *outgoing_tail;
    size_t outgoing_count;
    bool outgoing_failed;
} Client;

void init_clients(void);
int add_client(Connection *connection, const char *username);
int activate_client(int index);
void remove_client(int index, bool graceful);
ClientId get_client_id(int index);
ClientId find_client_id(const char *username);
/* Borrowed descriptor: only the owning worker uses it, until remove_client(). */
int get_client_wake_fd(ClientId client_id);
int client_output_status(ClientId client_id);

/* Success means queued, not yet delivered to the peer. */
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
int take_outgoing_frame(ClientId client_id, OutgoingFrame **frame);

#endif
