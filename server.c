#include "client_manager.h"
#include "command_parser.h"
#include "common.h"
#include "network.h"
#include "server_files.h"
#include "server_messages.h"
#include "server_worker.h"

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
        char private_message[BUFFER_SIZE];
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
        char broadcast_message[BUFFER_SIZE];
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
