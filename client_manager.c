#include "client_manager.h"
#include "server_messages.h"

#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

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
        clients[i].socket_fd = -1;
        clients[i].username[0] = '\0';
        clients[i].active = false;
        clients[i].ready = false;
        clients[i].id = INVALID_CLIENT_ID;
    }

    next_client_id = 1;
    pthread_mutex_unlock(&clients_mutex);
}

int add_client(int socket_fd, const char *username) {
    if (socket_fd < 0 || !username_is_valid(username)) {
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

    clients[free_index].socket_fd = socket_fd;
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

void remove_client(int index) {
    if (index < 0 || index >= MAX_CLIENTS) {
        return;
    }

    pthread_mutex_lock(&clients_mutex);

    if (!clients[index].active) {
        pthread_mutex_unlock(&clients_mutex);
        return;
    }

    int socket_fd = clients[index].socket_fd;
    clients[index].socket_fd = -1;
    clients[index].username[0] = '\0';
    clients[index].active = false;
    clients[index].ready = false;
    clients[index].id = INVALID_CLIENT_ID;

    pthread_mutex_unlock(&clients_mutex);
    close(socket_fd);
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
    if (client_id == INVALID_CLIENT_ID) {
        errno = EINVAL;
        return -1;
    }

    pthread_mutex_lock(&clients_mutex);

    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active && clients[i].ready &&
            clients[i].id == client_id) {
            int result = send_frame(
                clients[i].socket_fd,
                type,
                payload,
                payload_length
            ) == -1 ? -1 : 0;
            int saved_errno = errno;
            pthread_mutex_unlock(&clients_mutex);
            errno = saved_errno;
            return result;
        }
    }

    pthread_mutex_unlock(&clients_mutex);
    errno = ENOENT;
    return -1;
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

    size_t message_length = strlen(message);
    pthread_mutex_lock(&clients_mutex);

    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active && clients[i].ready &&
            clients[i].id != sender_id) {
            (void)send_frame(
                clients[i].socket_fd,
                FRAME_TEXT,
                message,
                message_length
            );
        }
    }

    pthread_mutex_unlock(&clients_mutex);
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
