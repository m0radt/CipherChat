#include "client_manager.h"
#include "server_messages.h"

#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/eventfd.h>

static Client clients[MAX_CLIENTS];
static pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;
static ClientId next_client_id = 1;

static bool username_is_valid(const char *username) {
    if (username == NULL) {
        return false;
    }

    size_t length = strlen(username);
    if (length == 0 || length >= USERNAME_SIZE) {
        return false;
    }

    for (size_t i = 0; i < length; i++) {
        unsigned char character = (unsigned char)username[i];
        if (iscntrl(character) || isspace(character)) {
            return false;
        }
    }

    return true;
}

static ClientId allocate_client_id(void) {
    ClientId client_id = next_client_id++;

    if (client_id == INVALID_CLIENT_ID) {
        client_id = next_client_id++;
    }

    return client_id;
}

void init_clients(void) {
    pthread_mutex_lock(&clients_mutex);

    for (int i = 0; i < MAX_CLIENTS; i++) {
        clients[i].connection = (Connection){ .socket_fd = -1, .ssl = NULL };
        clients[i].wake_fd = -1;
        clients[i].username[0] = '\0';
        clients[i].active = false;
        clients[i].ready = false;
        clients[i].id = INVALID_CLIENT_ID;
        clients[i].outgoing_head = NULL;
        clients[i].outgoing_tail = NULL;
        clients[i].outgoing_count = 0;
        clients[i].outgoing_failed = false;
    }

    next_client_id = 1;
    pthread_mutex_unlock(&clients_mutex);
}

int add_client(Connection *connection, const char *username) {
    if (connection == NULL || connection->socket_fd < 0 || connection->ssl == NULL || !username_is_valid(username)) {
        errno = EINVAL;
        return -1;
    }

    pthread_mutex_lock(&clients_mutex);

    int free_index = -1;
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active && strcmp(clients[i].username, username) == 0) {
            pthread_mutex_unlock(&clients_mutex);
            errno = EEXIST;
            return -1;
        }

        if (!clients[i].active && free_index == -1) {
            free_index = i;
        }
    }

    if (free_index == -1) {
        pthread_mutex_unlock(&clients_mutex);
        errno = ENOSPC;
        return -1;
    }

    int wake_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (wake_fd == -1) {
        int saved_errno = errno;
        pthread_mutex_unlock(&clients_mutex);
        errno = saved_errno;
        return -1;
    }

    clients[free_index].wake_fd = wake_fd;
    clients[free_index].outgoing_failed = false;
    clients[free_index].connection = *connection;
    clients[free_index].active = true;
    clients[free_index].ready = false;
    clients[free_index].id = allocate_client_id();
    memcpy(clients[free_index].username, username, strlen(username) + 1);

    pthread_mutex_unlock(&clients_mutex);
    return free_index;
}

int activate_client(int index) {
    if (index < 0 || index >= MAX_CLIENTS) {
        errno = EINVAL;
        return -1;
    }

    pthread_mutex_lock(&clients_mutex);
    if (!clients[index].active) {
        pthread_mutex_unlock(&clients_mutex);
        errno = ENOENT;
        return -1;
    }

    clients[index].ready = true;
    pthread_mutex_unlock(&clients_mutex);
    return 0;
}

void remove_client(int index, bool graceful) {
    if (index < 0 || index >= MAX_CLIENTS) {
        return;
    }

    pthread_mutex_lock(&clients_mutex);

    if (!clients[index].active) {
        pthread_mutex_unlock(&clients_mutex);
        return;
    }

    Connection connection = clients[index].connection;
    int wake_fd = clients[index].wake_fd;
    clients[index].wake_fd = -1;
    clients[index].connection = (Connection){ .socket_fd = -1, .ssl = NULL };
    clients[index].username[0] = '\0';
    clients[index].active = false;
    clients[index].ready = false;
    clients[index].id = INVALID_CLIENT_ID;
    OutgoingFrame *pending = clients[index].outgoing_head;

    clients[index].outgoing_head = NULL;
    clients[index].outgoing_tail = NULL;
    clients[index].outgoing_count = 0;
    clients[index].outgoing_failed = false;

    pthread_mutex_unlock(&clients_mutex);
    if (wake_fd >= 0) {
        close(wake_fd);
    }
    // Free any pending outgoing frames for the client
    while (pending != NULL) {
        OutgoingFrame *next = pending->next;
        free(pending);
        pending = next;
    }
    /* No registry lock is held during the bounded shutdown exchange. */
    close_connection(&connection, graceful);
}

ClientId get_client_id(int index) {
    if (index < 0 || index >= MAX_CLIENTS) {
        return INVALID_CLIENT_ID;
    }

    pthread_mutex_lock(&clients_mutex);
    ClientId client_id = clients[index].active
        ? clients[index].id
        : INVALID_CLIENT_ID;
    pthread_mutex_unlock(&clients_mutex);

    return client_id;
}

ClientId find_client_id(const char *username) {
    if (username == NULL) {
        return INVALID_CLIENT_ID;
    }

    pthread_mutex_lock(&clients_mutex);

    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active && clients[i].ready &&
            strcmp(clients[i].username, username) == 0) {
            ClientId client_id = clients[i].id;
            pthread_mutex_unlock(&clients_mutex);
            return client_id;
        }
    }

    pthread_mutex_unlock(&clients_mutex);
    return INVALID_CLIENT_ID;
}

int send_frame_to_client_id(
    ClientId client_id,
    FrameType type,
    const void *payload,
    size_t payload_length
) {
    return queue_frame_to_client_id(client_id, type, payload, payload_length);
}

int send_text_to_client_id(ClientId client_id, const char *message) {
    if (message == NULL || message[0] == '\0') {
        errno = EINVAL;
        return -1;
    }

    return send_frame_to_client_id(
        client_id,
        FRAME_TEXT,
        message,
        strlen(message)
    );
}

void send_message_to_client(
    const char *username,
    const char *message,
    ClientId sender_id
) {
    if (username == NULL || message == NULL) {
        return;
    }

    ClientId recipient_id = find_client_id(username);
    if (recipient_id != INVALID_CLIENT_ID) {
        if (send_text_to_client_id(recipient_id, message) == 0) {
            return;
        }
    }

    char error_message[BUFFER_SIZE];
    int written = snprintf(
        error_message,
        sizeof(error_message),
        MSG_USER_NOT_FOUND,
        username
    );
    if (written > 0 && (size_t)written < sizeof(error_message)) {
        (void)send_text_to_client_id(sender_id, error_message);
    }
}

void send_message_to_all_clients(
    const char *message,
    ClientId sender_id
) {
    if (message == NULL || message[0] == '\0') {
        return;
    }

    ClientId recipients[MAX_CLIENTS];
    size_t recipient_count = 0;
    pthread_mutex_lock(&clients_mutex);

    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active && clients[i].ready &&
            clients[i].id != sender_id) {
            recipients[recipient_count++] = clients[i].id;
        }
    }

    pthread_mutex_unlock(&clients_mutex);

    for (size_t i = 0; i < recipient_count; i++) {
        (void)send_text_to_client_id(recipients[i], message);
    }
}

void log_connected_clients(ClientId client_id) {
    char client_list[BUFFER_SIZE] = {0};
    int written = snprintf(client_list, sizeof(client_list), "%s", MSG_CLIENT_LIST);
    if (written < 0 || (size_t)written >= sizeof(client_list)) {
        return;
    }

    size_t offset = (size_t)written;
    pthread_mutex_lock(&clients_mutex);

    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!clients[i].active || !clients[i].ready) {
            continue;
        }

        size_t remaining = sizeof(client_list) - offset;
        written = snprintf(
            client_list + offset,
            remaining,
            "\n%s",
            clients[i].username
        );
        if (written < 0 || (size_t)written >= remaining) {
            break;
        }
        offset += (size_t)written;
    }

    pthread_mutex_unlock(&clients_mutex);
    (void)send_text_to_client_id(client_id, client_list);
}

void send_help(ClientId client_id) {
    (void)send_text_to_client_id(client_id, HELP_MESSAGE);
}

void send_unknown_command(ClientId client_id, const char *command) {
    char error_message[BUFFER_SIZE];
    int written = snprintf(
        error_message,
        sizeof(error_message),
        MSG_UNKNOWN_COMMAND,
        command
    );
    if (written > 0 && (size_t)written < sizeof(error_message)) {
        (void)send_text_to_client_id(client_id, error_message);
    }
}

void send_invalid_command(ClientId client_id, const char *command) {
    char error_message[BUFFER_SIZE];
    int written = snprintf(
        error_message,
        sizeof(error_message),
        MSG_INVALID_COMMAND,
        command
    );
    if (written > 0 && (size_t)written < sizeof(error_message)) {
        (void)send_text_to_client_id(client_id, error_message);
    }
}
int queue_frame_to_client_id(
    ClientId client_id,
    FrameType type,
    const void *payload,
    size_t payload_length
) {
    if (client_id == INVALID_CLIENT_ID ||
        (unsigned int)type > (unsigned int)FRAME_TEXT ||
        (payload == NULL && payload_length != 0)) {
        errno = EINVAL;
        return -1;
    }

    if (payload_length > FRAME_MAX_SIZE - 1) {
        errno = EMSGSIZE;
        return -1;
    }

    OutgoingFrame *frame = malloc(sizeof(*frame));
    if (frame == NULL) {
        errno = ENOMEM;
        return -1;
    }

    frame->type = type;
    frame->payload_length = payload_length;
    frame->next = NULL;

    if (payload_length > 0) {
        memcpy(frame->payload, payload, payload_length);
    }

    pthread_mutex_lock(&clients_mutex);

    for (int i = 0; i < MAX_CLIENTS; i++) {
        Client *client = &clients[i];

        if (!client->active || !client->ready ||
            client->id != client_id) {
            continue;
        }

        /* Signal under the lock: the worker cannot dequeue until we finish.
         * EAGAIN means a wake-up is already pending in the event counter. */
        int notified;
        do {
            notified = eventfd_write(client->wake_fd, 1);
        } while (notified == -1 && errno == EINTR);
        if (notified == -1 && errno != EAGAIN) {
            int saved_errno = errno;
            pthread_mutex_unlock(&clients_mutex);
            free(frame);
            errno = saved_errno;
            return -1;
        }

        if (client->outgoing_count >= MAX_OUTGOING_FRAMES) {
            /* Dropping a file chunk would leave an incomplete transfer.
             * Let the owner close this slow connection and abort its routes. */
            client->outgoing_failed = true;
            client->ready = false;
            pthread_mutex_unlock(&clients_mutex);
            free(frame);
            errno = ENOBUFS;
            return -1;
        }

        if (client->outgoing_tail != NULL) {
            client->outgoing_tail->next = frame;
        } else {
            client->outgoing_head = frame;
        }

        client->outgoing_tail = frame;
        client->outgoing_count++;

        pthread_mutex_unlock(&clients_mutex);
        return 0;
    }

    pthread_mutex_unlock(&clients_mutex);
    free(frame);
    errno = ENOENT;
    return -1;
}
int take_outgoing_frame(ClientId client_id, OutgoingFrame **frame) {
    if (frame == NULL || client_id == INVALID_CLIENT_ID) {
        errno = EINVAL;
        return -1;
    }

    *frame = NULL;

    pthread_mutex_lock(&clients_mutex);

    for (int i = 0; i < MAX_CLIENTS; i++) {
        Client *client = &clients[i];

        if (!client->active || client->id != client_id) {
            continue;
        }

        if (client->outgoing_failed) {
            pthread_mutex_unlock(&clients_mutex);
            errno = ENOBUFS;
            return -1;
        }

        *frame = client->outgoing_head;

        if (*frame != NULL) {
            client->outgoing_head = (*frame)->next;

            if (client->outgoing_head == NULL) {
                client->outgoing_tail = NULL;
            }

            client->outgoing_count--;
            (*frame)->next = NULL;
        }

        pthread_mutex_unlock(&clients_mutex);
        return *frame != NULL ? 1 : 0;
    }

    pthread_mutex_unlock(&clients_mutex);
    errno = ENOENT;
    return -1;
}

int get_client_wake_fd(ClientId client_id) {
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active && clients[i].id == client_id) {
            int wake_fd = clients[i].wake_fd;
            pthread_mutex_unlock(&clients_mutex);
            return wake_fd;
        }
    }
    pthread_mutex_unlock(&clients_mutex);
    errno = ENOENT;
    return -1;
}

int client_output_status(ClientId client_id) {
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active && clients[i].id == client_id) {
            bool failed = clients[i].outgoing_failed;
            pthread_mutex_unlock(&clients_mutex);
            if (failed) {
                errno = ENOBUFS;
                return -1;
            }
            return 0;
        }
    }
    pthread_mutex_unlock(&clients_mutex);
    errno = ENOENT;
    return -1;
}
