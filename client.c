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

static bool connected = true;
static int active_client_fd = -1;
static int client_exit_code = 0;

static void display_message(const unsigned char *message, size_t length);
static void handle_input(char *line);
static void handle_server_frame(const unsigned char *frame, size_t frame_length);
static bool is_connection_error(int error_number);
static int get_username_and_register_in_server(int client_fd);
static int receive_welcome_message(int client_fd);
static int handle_file_command(int client_fd, char *line);

int main(void) {
    int client_fd = connect_to_server(SERVER_IP, SERVER_PORT);
    if (client_fd == -1) {
        return 1;
    }

    if (get_username_and_register_in_server(client_fd) == -1 ||
        receive_welcome_message(client_fd) == -1) {
        close(client_fd);
        return 1;
    }

    if (ensure_download_directory(DOWNLOAD_DIRECTORY) == -1) {
        perror("prepare downloads directory");
        close(client_fd);
        return 1;
    }

    active_client_fd = client_fd;

    rl_variable_bind("horizontal-scroll-mode", "off");
    rl_callback_handler_install("> ", handle_input);

    while (connected) {
        struct pollfd fds[2] = {
            {
                .fd = STDIN_FILENO,
                .events = POLLIN
            },
            {
                .fd = client_fd,
                .events = POLLIN
            }
        };

        int result;
        do {
            result = poll(fds, 2, -1);
        } while (result == -1 && errno == EINTR);

        if (result == -1) {
            perror("poll");
            client_exit_code = 1;
            break;
        }

        if (fds[1].revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL)) {
            unsigned char frame[FRAME_MAX_SIZE];
            ssize_t received = receive_frame(
                client_fd,
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
    cleanup_incoming_files();

    if (shutdown(client_fd, SHUT_RDWR) == -1 && errno != ENOTCONN) {
        perror("shutdown");
    }

    if (close(client_fd) == -1) {
        perror("Socket closing failed");
        return 1;
    }

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
        if (handle_file_command(active_client_fd, line) == -1) {
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
            active_client_fd,
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

static int get_username_and_register_in_server(int client_fd) {
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

    if (send_message(client_fd, username, username_length) == -1) {
        perror("send username");
        return -1;
    }
    return 0;
}

static int receive_welcome_message(int client_fd) {
    char welcome_message[BUFFER_SIZE];
    ssize_t received = receive_message(
        client_fd,
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

static int handle_file_command(int client_fd, char *line) {
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

    return send_file(client_fd, recipient, cursor) == -1 ? -1 : 0;
}
