#include <ctype.h>
#include <string.h>
#include "command_parser.h"
#include "common.h"

static char *skip_whitespace(char *text)
{
    while (*text != '\0' &&
           isspace((unsigned char)*text)) {
        text++;
    }

    return text;
}

static void remove_line_ending(char *text)
{
    size_t length = strlen(text);

    while (length > 0 &&
           (text[length - 1] == '\n' ||
            text[length - 1] == '\r')) {
        text[--length] = '\0';
    }
}

ParsedCommand parse_command(char *command)
{
    ParsedCommand result = {
        .type = CMD_UNKNOWN,
        .username = NULL,
        .message = NULL
    };

    if (command == NULL) {
        result.type = CMD_INVALID;
        return result;
    }

    remove_line_ending(command);

    char *verb = skip_whitespace(command);
    char *cursor = verb;

    /* Separate the command name from its arguments. */
    while (*cursor != '\0' &&
           !isspace((unsigned char)*cursor)) {
        cursor++;
    }

    char *arguments = cursor;

    if (*cursor != '\0') {
        *cursor = '\0';
        arguments = skip_whitespace(cursor + 1);
    }

    if (strcmp(verb, "/list") == 0) {
        result.type = (*arguments == '\0')
            ? CMD_LIST_USERS
            : CMD_INVALID;
        return result;
    }

    if (strcmp(verb, "/help") == 0) {
        result.type = (*arguments == '\0')
            ? CMD_HELP
            : CMD_INVALID;
        return result;
    }

    if (strcmp(verb, "/quit") == 0) {
        result.type = (*arguments == '\0')
            ? CMD_QUIT
            : CMD_INVALID;
        return result;
    }

    if (strcmp(verb, "/broadcast") == 0) {
        if (*arguments == '\0') {
            result.type = CMD_INVALID;
            return result;
        }

        result.type = CMD_BROADCAST_MESSAGE;
        result.message = arguments;
        return result;
    }

    if (strcmp(verb, "/msg") == 0) {
        if (*arguments == '\0') {
            result.type = CMD_INVALID;
            return result;
        }

        char *username = arguments;

        while (*arguments != '\0' &&
               !isspace((unsigned char)*arguments)) {
            arguments++;
        }

        /* `/msg username` has no message. */
        if (*arguments == '\0') {
            result.type = CMD_INVALID;
            return result;
        }

        *arguments = '\0';
        char *message = skip_whitespace(arguments + 1);

        if (*message == '\0' ||
            strlen(username) >= USERNAME_SIZE) {
            result.type = CMD_INVALID;
            return result;
        }

        result.type = CMD_PRIVATE_MESSAGE;
        result.username = username;
        result.message = message;
        return result;
    }

    return result;
}
