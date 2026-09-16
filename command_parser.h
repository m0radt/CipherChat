#ifndef COMMAND_PARSER_H
#define COMMAND_PARSER_H

typedef enum {
    CMD_UNKNOWN,
    CMD_INVALID,
    CMD_PRIVATE_MESSAGE,
    CMD_BROADCAST_MESSAGE,
    CMD_LIST_USERS,
    CMD_HELP,
    CMD_QUIT
} ClientCommand;

typedef struct {
    ClientCommand type;
    char *username;
    char *message;
} ParsedCommand;


ParsedCommand parse_command(char *command);

#endif
