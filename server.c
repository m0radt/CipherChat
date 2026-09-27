#include "client_manager.h"
#include "command_parser.h"
#include "common.h"
#include "network.h"
#include "server_files.h"
#include "server_messages.h"
#include "server_worker.h"

#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static volatile sig_atomic_t running = 1;
static int server_fd = -1;

static void *handle_client(void *argument);
static int send_welcome_message(const char *username, Connection *connection);
static void stop_server(int signal_number);
static bool handle_client_frame(
    ClientId client_id,
    const char *username,
    const unsigned char *frame,
    size_t length
);
static bool handle_command(
    ClientId client_id,
    const char *sender_username,
    char *command,
    const char *original_command
);

int main(void) {
    signal(SIGINT, stop_server);
    signal(SIGTERM, stop_server);
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        perror("ignore SIGPIPE");
        return 1;
    }

    init_clients();
    init_file_routes();

    server_fd = create_server_socket(SERVER_PORT);
    if (server_fd == -1) {
        return 1;
    }

    while (running) {
        Connection connection;

        if (accept_client(server_fd, &connection) == -1) {
            if (!running) {
                break;
            }
            continue;
        }

        Connection *client_connection = malloc(sizeof(*client_connection));
        if (client_connection == NULL) {
            perror("malloc client connection");
            close_connection(&connection, false);
            continue;
        }
        *client_connection = connection;

        pthread_t receiver_thread;
        if (pthread_create(
                &receiver_thread,
                NULL,
                handle_client,
                client_connection
            ) != 0) {
            perror("pthread_create");
            free(client_connection);
            close_connection(&connection, false);
            continue;
        }

        if (pthread_detach(receiver_thread) != 0) {
            perror("pthread_detach");
        }
    }

    if (server_fd != -1) {
        if (close(server_fd) == -1) {
            perror("Server socket closing failed");
            return 1;
        }
    }

    printf("Server socket successfully closed\n");
    return 0;
}

static void *handle_client(void *argument) {
    Connection connection = *(Connection *)argument;
    free(argument);

    char username[USERNAME_SIZE];

    printf("New client connected\n");
    set_timeout_for_socket(connection.socket_fd);

    if (perform_tls_handshake(&connection, 0, NULL) == -1) {
        return NULL;
    }

    ssize_t received = receive_message(&connection, username, sizeof(username));
    if (received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            const char *message = "Login failed: username timeout.\n";
            (void)send_message(&connection, message, strlen(message));
            fprintf(stderr, "Client login timed out\n");
        } else {
            perror("receive username");
        }
        close_connection(&connection, true);
        return NULL;
    }

    if (received == 0) {
        printf("Client disconnected before login\n");
        close_connection(&connection, true);
        return NULL;
    }

    if (memchr(username, '\0', (size_t)received) != NULL) {
        const char *message = "Login failed: invalid username.\n";
        (void)send_message(&connection, message, strlen(message));
        close_connection(&connection, true);
        return NULL;
    }

    unset_timeout_for_socket(connection.socket_fd);

    int client_index = add_client(&connection, username);
    if (client_index == -1) {
        char login_error[BUFFER_SIZE];
        const char *reason = errno == EEXIST
            ? "username is already in use"
            : "invalid username or server is full";
        int written = snprintf(
            login_error,
            sizeof(login_error),
            "Login failed: %s.\n",
            reason
        );
        if (written > 0 && (size_t)written < sizeof(login_error)) {
            (void)send_message(&connection, login_error, (size_t)written);
        }
        close_connection(&connection, true);
        return NULL;
    }

    ClientId client_id = get_client_id(client_index);
    if (send_welcome_message(username, &connection) == -1) {
        remove_client(client_index, false);
        return NULL;
    }
    if (activate_client(client_index) == -1) {
        remove_client(client_index, true);
        return NULL;
    }

    printf("Client \"%s\" logged in successfully\n", username);

    int worker_result = run_client_worker(&connection, client_id, username,
                                          handle_client_frame);
    if (worker_result == -1) {
        perror("client worker");
    }

    printf("Client \"%s\" disconnected\n", username);
    /* Stop accepting new queued frames before notifying the other endpoints. */
    remove_client(client_index, worker_result == 0);
    abort_file_routes_for_client(client_id);
    return NULL;
}

/* Usernames are length-delimited on the wire and cannot contain controls. */
static bool copy_peer_name(char *name, const unsigned char *bytes, size_t length) {
    if (length == 0 || length >= USERNAME_SIZE) {
        return false;
    }
    for (size_t i = 0; i < length; i++) {
        if (isspace(bytes[i]) || iscntrl(bytes[i])) {
            return false;
        }
    }
    memcpy(name, bytes, length);
    name[length] = '\0';
    return true;
}

static void handle_encrypted_chat(ClientId client_id,
                                  const char *sender_username,
                                  const unsigned char *frame, size_t length) {
    FrameType type = (FrameType)frame[0];
    const unsigned char *payload = frame + 1;
    size_t payload_length = length - 1;
    char recipient[USERNAME_SIZE];

    if (type == FRAME_REGISTER_PK) {
        if (payload_length != CHAT_PUBLIC_KEY_SIZE ||
            register_client_public_key(client_id, payload) == -1) {
            send_invalid_command(client_id, "public key registration");
        }
        return;
    }

    if (type == FRAME_REQUEST_PK) {
        if (!copy_peer_name(recipient, payload, payload_length)) {
            send_invalid_command(client_id, "public key request");
            return;
        }
        unsigned char response[1 + USERNAME_SIZE - 1 + CHAT_PUBLIC_KEY_SIZE];
        response[0] = (unsigned char)payload_length;
        memcpy(response + 1, payload, payload_length);
        size_t response_length = 1 + payload_length;
        ClientId recipient_id = find_client_id(recipient);
        if (get_client_public_key(recipient_id, response + response_length) == 0) {
            response_length += CHAT_PUBLIC_KEY_SIZE;
        }
        /* A name-only reply cancels this request when the peer/key is absent. */
        (void)send_frame_to_client_id(client_id, FRAME_PEER_PK,
                                      response, response_length);
        return;
    }

    if (payload_length < CHAT_OVERHEAD ||
        payload_length < CHAT_OVERHEAD + (size_t)payload[0] ||
        !copy_peer_name(recipient, payload + 1, payload[0])) {
        send_invalid_command(client_id, "encrypted message");
        return;
    }
    size_t recipient_length = payload[0];
    size_t encrypted_offset = 1 + recipient_length;
    size_t encrypted_length = payload_length - encrypted_offset;
    size_t message_length = encrypted_length - CHAT_NONCE_SIZE -
        CHAT_PUBLIC_KEY_SIZE - CHAT_MAC_SIZE;
    if (message_length > CHAT_MAX_MESSAGE_SIZE) {
        send_invalid_command(client_id, "encrypted message too long");
        return;
    }

    unsigned char sender_key[CHAT_PUBLIC_KEY_SIZE];
    const unsigned char *claimed_key = payload + encrypted_offset + CHAT_NONCE_SIZE;
    if (get_client_public_key(client_id, sender_key) == -1 ||
        memcmp(sender_key, claimed_key, CHAT_PUBLIC_KEY_SIZE) != 0) {
        send_invalid_command(client_id, "encrypted message sender key");
        return;
    }
    size_t sender_length = strlen(sender_username);
    size_t forwarded_length = 1 + sender_length + encrypted_length;
    if (sender_length == 0 || sender_length >= USERNAME_SIZE ||
        forwarded_length > FRAME_MAX_SIZE - 1) {
        send_invalid_command(client_id, "encrypted message sender");
        return;
    }

    /* Replace the routing recipient with the authenticated login name. */
    unsigned char forwarded[FRAME_MAX_SIZE - 1];
    forwarded[0] = (unsigned char)sender_length;
    memcpy(forwarded + 1, sender_username, sender_length);
    memcpy(forwarded + 1 + sender_length,
           payload + encrypted_offset, encrypted_length);

    ClientId recipient_id = find_client_id(recipient);
    if (send_frame_to_client_id(recipient_id, FRAME_CIPHERTEXT,
                               forwarded, forwarded_length) == -1) {
        char error[BUFFER_SIZE];
        if (format_message(error, sizeof(error), MSG_USER_NOT_FOUND, recipient) != -1) {
            (void)send_text_to_client_id(client_id, error);
        }
    }
}

static bool handle_client_frame(
    ClientId client_id,
    const char *username,
    const unsigned char *frame,
    size_t length
) {
    if (frame[0] == FRAME_TEXT) {
        size_t command_length = length - 1;
        if (command_length == 0 ||
            memchr(frame + 1, '\0', command_length) != NULL) {
            send_invalid_command(client_id, "binary text frame");
            return true;
        }

        char command[FRAME_MAX_SIZE];
        char original_command[FRAME_MAX_SIZE];
        memcpy(command, frame + 1, command_length);
        command[command_length] = '\0';
        memcpy(original_command, command, command_length + 1);
        printf("Received command from \"%s\": %s\n", username, original_command);
        return handle_command(client_id, username, command, original_command);
    }

    if (frame[0] == FRAME_REGISTER_PK || frame[0] == FRAME_REQUEST_PK ||
        frame[0] == FRAME_CIPHERTEXT) {
        handle_encrypted_chat(client_id, username, frame, length);
        return true;
    }
    if (frame[0] == FRAME_PEER_PK) {
        send_invalid_command(client_id, "unexpected public key reply");
        return true;
    }

    if (route_file_frame(client_id, username, frame, length) == -1) {
        fprintf(stderr, "Rejected file frame from \"%s\": %s\n",
                username, strerror(errno));
    }
    return true;
}

static int send_welcome_message(const char *username, Connection *connection) {
    char welcome_message[BUFFER_SIZE];
    int written = snprintf(
        welcome_message,
        sizeof(welcome_message),
        MSG_WELCOME,
        username
    );
    if (written < 0 || (size_t)written >= sizeof(welcome_message)) {
        errno = EMSGSIZE;
        return -1;
    }

    if (send_message(connection, welcome_message, (size_t)written) == -1) {
        perror("send welcome message");
        return -1;
    }
    return 0;
}

static void stop_server(int signal_number) {
    (void)signal_number;
    running = 0;

    if (server_fd != -1) {
        close(server_fd);
        server_fd = -1;
    }
}

static bool handle_command(
    ClientId client_id,
    const char *sender_username,
    char *command,
    const char *original_command
) {
    ParsedCommand parsed = parse_command(command);

    switch (parsed.type) {
    case CMD_PRIVATE_MESSAGE: {
        char private_message[FRAME_MAX_SIZE];
        if (strlen(parsed.message) > MESSAGE_MAX_SIZE) {
            (void)send_text_to_client_id(client_id,
                "Message too long (maximum: 65536 bytes)\n");
            break;
        }
        if (format_message(
                private_message,
                sizeof(private_message),
                MSG_PRIVATE_MESSAGE,
                sender_username,
                parsed.message
            ) != -1) {
            send_message_to_client(
                parsed.username,
                private_message,
                client_id
            );
        }
        break;
    }

    case CMD_BROADCAST_MESSAGE: {
        char broadcast_message[FRAME_MAX_SIZE];
        if (strlen(parsed.message) > MESSAGE_MAX_SIZE) {
            (void)send_text_to_client_id(client_id,
                "Message too long (maximum: 65536 bytes)\n");
            break;
        }
        if (format_message(
                broadcast_message,
                sizeof(broadcast_message),
                MSG_BROADCAST,
                sender_username,
                parsed.message
            ) != -1) {
            send_message_to_all_clients(broadcast_message, client_id);
        }
        break;
    }

    case CMD_LIST_USERS:
        log_connected_clients(client_id);
        break;

    case CMD_HELP:
        send_help(client_id);
        break;

    case CMD_QUIT:
        return false;

    case CMD_INVALID:
        send_invalid_command(client_id, original_command);
        break;

    case CMD_UNKNOWN:
    default:
        send_unknown_command(client_id, original_command);
        break;
    }

    return true;
}
