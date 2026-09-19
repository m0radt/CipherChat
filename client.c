#include "client_files.h"
#include "common.h"
#include "network.h"

#include <ctype.h>
#include <errno.h>
#include <poll.h>
#include <readline/history.h>
#include <readline/readline.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <signal.h>

static bool connected = true;
static Connection *active_connection = NULL;
static int client_exit_code = 0;

static void display_message(const unsigned char *message, size_t length);
static void handle_input(char *line);
static void handle_server_frame(const unsigned char *frame, size_t frame_length);
static bool is_connection_error(int error_number);
static int get_username_and_register_in_server(Connection *connection);
static int receive_welcome_message(Connection *connection);
static int handle_file_command(Connection *connection, char *line);

int main(void) {
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        perror("ignore SIGPIPE");
        return 1;
    }
    Connection connection;
    if (connect_to_server(SERVER_IP, SERVER_PORT, &connection) == -1) {
        return 1;
    }

    if (get_username_and_register_in_server(&connection) == -1 ||
        receive_welcome_message(&connection) == -1) {
        close_connection(&connection, true);
        return 1;
    }

    if (ensure_download_directory(DOWNLOAD_DIRECTORY) == -1) {
        perror("prepare downloads directory");
        close_connection(&connection, true);
        return 1;
    }

    active_connection = &connection;

    rl_variable_bind("horizontal-scroll-mode", "off");
    rl_callback_handler_install("> ", handle_input);

    while (connected) {
        struct pollfd fds[2] = {
            {
                .fd = STDIN_FILENO,
                .events = POLLIN
            },
            {
                .fd = connection.socket_fd,
                .events = POLLIN
            }
        };
        bool tls_data_ready = SSL_pending(connection.ssl) > 0;

        int result;
        do {
            result = poll(fds, 2, tls_data_ready ? 0 /*Check events without waiting.*/: -1 /*Wait for an event.*/);

        } while (result == -1 && errno == EINTR);

        if (result == -1) {
            perror("poll");
            client_exit_code = 1;
            break;
        }

        if (tls_data_ready || (fds[1].revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL))) {
            unsigned char frame[FRAME_MAX_SIZE];
            ssize_t received = receive_frame(
                &connection,
                frame,
                sizeof(frame)
            );

            if (received == -1) {
                perror("receive frame");
                client_exit_code = 1;
                connected = false;
            } else if (received == 0) {
                rl_clear_visible_line();
                printf("Connection closed\n");
                fflush(stdout);
                connected = false;
            } else {
                handle_server_frame(frame, (size_t)received);
            }
        }

        if (connected && (fds[0].revents & (POLLIN | POLLHUP))) {
            rl_callback_read_char();
        }
    }

    rl_clear_visible_line();
    rl_callback_handler_remove();
    active_connection = NULL;
    cleanup_incoming_files();

    close_connection(&connection, true);

    printf("Socket successfully closed\n");
    return client_exit_code;
}

static void display_message(const unsigned char *message, size_t length) {
    rl_clear_visible_line();

    if (length > 0) {
        (void)fwrite(message, 1, length, stdout);
    }
    if (length == 0 || message[length - 1] != '\n') {
        putchar('\n');
    }

    fflush(stdout);
    rl_on_new_line();
    rl_redisplay();
}

static void handle_server_frame(
    const unsigned char *frame,
    size_t frame_length
) {
    FrameType type = (FrameType)frame[0];

    if (type == FRAME_TEXT) {
        display_message(frame + 1, frame_length - 1);
        return;
    }

    rl_clear_visible_line();
    if (handle_incoming_file_frame(
            frame,
            frame_length,
            DOWNLOAD_DIRECTORY
        ) == -1) {
        int saved_errno = errno;
        fprintf(stderr, "File receive failed: %s\n", strerror(saved_errno));
    }
    fflush(stdout);
    fflush(stderr);
    rl_on_new_line();
    rl_redisplay();
}

static void handle_input(char *line) {
    if (line == NULL) {
        connected = false;
        return;
    }

    if (line[0] == '\0') {
        free(line);
        return;
    }

    add_history(line);

    bool is_file_command = strncmp(line, "/file", 5) == 0 &&
        (line[5] == '\0' || isspace((unsigned char)line[5]));

    if (is_file_command) {
        if (handle_file_command(active_connection, line) == -1) {
            int saved_errno = errno;
            fprintf(stderr, "File send failed: %s\n", strerror(saved_errno));
            if (is_connection_error(saved_errno)) {
                client_exit_code = 1;
                connected = false;
            }
        }
        free(line);
        return;
    }

    if (send_frame(
            active_connection,
            FRAME_TEXT,
            line,
            strlen(line)
        ) == -1) {
        int saved_errno = errno;
        fprintf(stderr, "Send failed: %s\n", strerror(saved_errno));
        if (is_connection_error(saved_errno)) {
            client_exit_code = 1;
            connected = false;
        }
    } else if (strcmp(line, "/quit") == 0) {
        connected = false;
    }

    free(line);
}

static bool is_connection_error(int error_number) {
    return error_number == EPIPE ||
        error_number == ECONNRESET ||
        error_number == ENOTCONN ||
        error_number == EBADF;
}

static int get_username_and_register_in_server(Connection *connection) {
    char username[USERNAME_SIZE + 1];

    printf("Username: ");
    fflush(stdout);

    if (fgets(username, sizeof(username), stdin) == NULL) {
        return -1;
    }

    char *newline = strchr(username, '\n');
    if (newline == NULL) {
        int character;
        while ((character = getchar()) != '\n' && character != EOF) {
        }
        fprintf(stderr, "Username must be shorter than %d characters\n", USERNAME_SIZE);
        errno = EINVAL;
        return -1;
    }
    *newline = '\0';

    size_t username_length = strlen(username);
    if (username_length == 0 || username_length >= USERNAME_SIZE) {
        fprintf(stderr, "Username must contain 1-%d characters\n", USERNAME_SIZE - 1);
        errno = EINVAL;
        return -1;
    }

    for (size_t i = 0; i < username_length; i++) {
        unsigned char character = (unsigned char)username[i];
        if (isspace(character) || iscntrl(character)) {
            fprintf(stderr, "Username cannot contain whitespace or control characters\n");
            errno = EINVAL;
            return -1;
        }
    }

    if (send_message(connection, username, username_length) == -1) {
        perror("send username");
        return -1;
    }
    return 0;
}

static int receive_welcome_message(Connection *connection) {
    char welcome_message[BUFFER_SIZE];
    ssize_t received = receive_message(
        connection,
        welcome_message,
        sizeof(welcome_message)
    );

    if (received == -1) {
        perror("receive welcome message");
        return -1;
    }
    if (received == 0) {
        fprintf(stderr, "Server disconnected during login\n");
        errno = ECONNRESET;
        return -1;
    }

    fputs(welcome_message, stdout);
    if (strncmp(welcome_message, "Login failed:", 13) == 0) {
        errno = EACCES;
        return -1;
    }

    return 0;
}

static int handle_file_command(Connection *connection, char *line) {
    char *cursor = line + 5;

    while (isspace((unsigned char)*cursor)) {
        cursor++;
    }

    if (*cursor == '\0') {
        fprintf(stderr, "Usage: /file <username> <path>\n");
        errno = EINVAL;
        return -1;
    }

    char *recipient = cursor;
    while (*cursor != '\0' && !isspace((unsigned char)*cursor)) {
        cursor++;
    }

    if (*cursor == '\0') {
        fprintf(stderr, "Missing file path\n");
        errno = EINVAL;
        return -1;
    }

    *cursor++ = '\0';
    while (isspace((unsigned char)*cursor)) {
        cursor++;
    }

    if (*cursor == '\0') {
        fprintf(stderr, "Missing file path\n");
        errno = EINVAL;
        return -1;
    }

    return send_file(connection, recipient, cursor) == -1 ? -1 : 0;
}
