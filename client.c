#define _POSIX_C_SOURCE 200809L

#include "client_files.h"
#include "command_parser.h"
#include "common.h"
#include "network.h"

#include <ctype.h>
#include <errno.h>
#include <poll.h>
#include <readline/history.h>
#include <readline/readline.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <signal.h>
#include <sodium.h>

static bool connected = true;
static Connection *active_connection = NULL;
static int client_exit_code = 0;

typedef struct PendingMessage {
    char recipient[USERNAME_SIZE];
    char *message;  // Owned copy of the message text
    struct PendingMessage *next;
} PendingMessage;

static PendingMessage *pending_head = NULL;
static PendingMessage *pending_tail = NULL;
static size_t pending_count = 0;
#define MAX_PENDING_MESSAGES 128

_Static_assert(CHAT_PUBLIC_KEY_SIZE == crypto_box_PUBLICKEYBYTES,
               "public key wire size mismatch");
_Static_assert(CHAT_NONCE_SIZE == crypto_box_NONCEBYTES, "nonce wire size mismatch");
_Static_assert(CHAT_MAC_SIZE == crypto_box_MACBYTES, "MAC wire size mismatch");

static unsigned char public_key[crypto_box_PUBLICKEYBYTES];
static unsigned char private_key[crypto_box_SECRETKEYBYTES];

static void display_message(const unsigned char *message, size_t length);
static void display_private_message(
    const char *sender,
    const unsigned char *message,
    size_t length
);
static void handle_input(char *line);
static void handle_server_frame(const unsigned char *frame, size_t frame_length);
static bool is_connection_error(int error_number);
static int get_username_and_register_in_server(Connection *connection);
static int receive_welcome_message(Connection *connection);
static int handle_file_command(Connection *connection, char *line);
static int handle_private_message(Connection *connection, char *line);

int main(void) {
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        perror("ignore SIGPIPE");
        return 1;
    }
    /* Generate a new encryption key pair for this connection. */
    if (sodium_init() == -1) {
        printf("Error: libsodium initialization failed.\n");
        return 1;
    }
    crypto_box_keypair(public_key, private_key);

    Connection connection;
    if (connect_to_server(SERVER_IP, SERVER_PORT, &connection) == -1) {
        return 1;
    }

    if (get_username_and_register_in_server(&connection) == -1 ||
        receive_welcome_message(&connection) == -1) {
        close_connection(&connection, true);
        return 1;
    }

    if (send_frame(&connection, FRAME_REGISTER_PK, public_key,
                   sizeof(public_key)) == -1) {
        perror("register public key");
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

    while (pending_head != NULL) {
        PendingMessage *pending = pending_head;
        pending_head = pending->next;
        free(pending->message);
        free(pending);
    }
    pending_tail = NULL;

    sodium_memzero(private_key, sizeof(private_key));
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

static void display_private_message(
    const char *sender,
    const unsigned char *message,
    size_t length
) {
    rl_clear_visible_line();
    printf("Private message from %s: ", sender);
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

static int send_private_chat(const char *recipient, const unsigned char *message, size_t message_len, const unsigned char *nonce, const unsigned char *recipient_public_key) {
    size_t recipient_len = strlen(recipient);
    if (recipient_len == 0 || recipient_len >= USERNAME_SIZE) {
        errno = EINVAL;
        return -1;
    }

    size_t ciphertext_offset = 1 + recipient_len + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES;
    if (message_len > CHAT_MAX_MESSAGE_SIZE) {
        errno = EMSGSIZE;
        return -1;
    }
    size_t payload_len = ciphertext_offset + crypto_box_MACBYTES + message_len;
    unsigned char *payload = malloc(payload_len);
    if (payload == NULL) {
        return -1;
    }

    /* Payload: username length, username bytes, nonce, sender public key, authenticated ciphertext. */
    payload[0] = (unsigned char)recipient_len;
    memcpy(payload + 1, recipient, recipient_len);
    memcpy(payload + 1 + recipient_len, nonce, crypto_box_NONCEBYTES);
    memcpy(payload + 1 + recipient_len + crypto_box_NONCEBYTES, public_key, crypto_box_PUBLICKEYBYTES);
    if (crypto_box_easy(payload + ciphertext_offset, message, message_len, nonce,
                        recipient_public_key, private_key) != 0) {
        free(payload);
        errno = EINVAL;
        return -1;
    }

    int result = send_frame(active_connection, FRAME_CIPHERTEXT, payload,
                            payload_len) == -1 ? -1 : 0;
    int saved_errno = errno;
    free(payload);
    errno = saved_errno;
    return result;
}
static int receive_private_chat(const unsigned char *frame, size_t frame_length) {
    if (frame_length < 1 + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + crypto_box_MACBYTES) {
        errno = EMSGSIZE;
        return -1;
    }

    size_t sender_len = frame[0];
    if (sender_len == 0 || sender_len >= USERNAME_SIZE ||
        frame_length < 1 + sender_len + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + crypto_box_MACBYTES) {
        errno = EMSGSIZE;
        return -1;
    }

    char sender[USERNAME_SIZE];
    for (size_t i = 0; i < sender_len; i++) {
        if (isspace(frame[1 + i]) || iscntrl(frame[1 + i])) {
            errno = EPROTO;
            return -1;
        }
    }
    memcpy(sender, frame + 1, sender_len);
    sender[sender_len] = '\0';

    const unsigned char *nonce = frame + 1 + sender_len;
    const unsigned char *sender_public_key = nonce + crypto_box_NONCEBYTES;
    const unsigned char *ciphertext = sender_public_key + crypto_box_PUBLICKEYBYTES;
    size_t ciphertext_len = frame_length - (size_t)(ciphertext - frame);
    if (ciphertext_len > crypto_box_MACBYTES + CHAT_MAX_MESSAGE_SIZE) {
        errno = EMSGSIZE;
        return -1;
    }

    unsigned char decrypted_message[FRAME_MAX_SIZE];

    if (crypto_box_open_easy(decrypted_message, ciphertext, ciphertext_len, nonce,
                             sender_public_key, private_key) != 0) {
        errno = EINVAL;
        return -1;
    }

    display_private_message(
        sender,
        decrypted_message,
        ciphertext_len - crypto_box_MACBYTES
    );
    sodium_memzero(decrypted_message, sizeof(decrypted_message));
    return 0;
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
    if (type == FRAME_PEER_PK) {
        if (frame_length < 2) {
            fprintf(stderr, "Invalid public key response.\n");
            return;
        }
        size_t name_length = frame[1];
        size_t key_offset = 2 + name_length;
        if (name_length == 0 || name_length >= USERNAME_SIZE ||
            (frame_length != key_offset &&
             frame_length != key_offset + crypto_box_PUBLICKEYBYTES) ||
            memchr(frame + 2, '\0', name_length) != NULL) {
            fprintf(stderr, "Invalid public key response.\n");
            return;
        }
        char recipient[USERNAME_SIZE];
        memcpy(recipient, frame + 2, name_length);
        recipient[name_length] = '\0';

        PendingMessage *previous = NULL;
        PendingMessage *pending = pending_head;
        while (pending != NULL && strcmp(pending->recipient, recipient) != 0) {
            previous = pending;
            pending = pending->next;
        }
        if (pending == NULL) {
            return; /* Ignore duplicate or unsolicited replies. */
        }
        if (previous != NULL) {
            previous->next = pending->next;
        } else {
            pending_head = pending->next;
        }
        if (pending_tail == pending) {
            pending_tail = previous;
        }
        pending_count--;

        if (frame_length == key_offset) {
            fprintf(stderr, "Private message failed: public key unavailable for %s.\n",
                    recipient);
        } else {
            unsigned char nonce[crypto_box_NONCEBYTES];
            randombytes_buf(nonce, sizeof(nonce));
            if (send_private_chat(recipient, (const unsigned char *)pending->message,
                                  strlen(pending->message), nonce,
                                  frame + key_offset) == -1) {
                int saved_errno = errno;
                fprintf(stderr, "Private message failed: %s\n", strerror(saved_errno));
                if (is_connection_error(saved_errno)) {
                    client_exit_code = 1;
                    connected = false;
                }
            }
        }
        free(pending->message);
        free(pending);
        return;
    }
    if (type == FRAME_CIPHERTEXT) {
        if (receive_private_chat(frame + 1, frame_length - 1) == -1) {
            int saved_errno = errno;
            fprintf(stderr, "Failed to decrypt private message: %s\n", strerror(saved_errno));
        }
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

    const char *verb = line;
    while (isspace((unsigned char)*verb)) {
        verb++;
    }
    bool is_private_message = strncmp(verb, "/msg", 4) == 0 &&
        (verb[4] == '\0' || isspace((unsigned char)verb[4]));
    if (is_private_message) {
        if (handle_private_message(active_connection, line) == -1) {
            int saved_errno = errno;
            fprintf(stderr, "Private message failed: %s\n", strerror(saved_errno));
            if (is_connection_error(saved_errno)) {
                client_exit_code = 1;
                connected = false;
            }
        }
        free(line);
        return;
    }

    if (strlen(line) > FRAME_MAX_SIZE - 1) {
        fprintf(stderr, "Message too long (maximum text size: %u bytes)\n",
                MESSAGE_MAX_SIZE);
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


static int handle_private_message(Connection *connection, char *line) {
    ParsedCommand parsed = parse_command(line);
    if (parsed.type != CMD_PRIVATE_MESSAGE) {
        fprintf(stderr, "Usage: /msg <username> <message>\n");
        errno = EINVAL;
        return -1;
    }
    size_t recipient_length = strlen(parsed.username);
    if (strlen(parsed.message) > CHAT_MAX_MESSAGE_SIZE) {
        errno = EMSGSIZE;
        return -1;
    }
    if (pending_count >= MAX_PENDING_MESSAGES) {
        errno = ENOBUFS;
        return -1;
    }
    PendingMessage *pending = malloc(sizeof(*pending));
    if (pending == NULL) {
        return -1;
    }
    pending->message = strdup(parsed.message);
    if (pending->message == NULL) {
        free(pending);
        return -1;
    }
    memcpy(pending->recipient, parsed.username, recipient_length + 1);
    pending->next = NULL;

    if (send_frame(connection, FRAME_REQUEST_PK, parsed.username, recipient_length) == -1) {
        int saved_errno = errno;
        free(pending->message);
        free(pending);
        errno = saved_errno;
        return -1;
    }
    /* The event loop cannot process a reply until this callback returns. */
    if (pending_tail != NULL) {
        pending_tail->next = pending;
    } else {
        pending_head = pending;
    }
    pending_tail = pending;
    pending_count++;
    return 0;
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
