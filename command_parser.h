#ifndef COMMAND_PARSER_H
#define COMMAND_PARSER_H

typedef enum {
    CMD_UNKNOWN,
    CMD_INVALID,
    CMD_PRIVATE_MESSAGE,
    CMD_BROADCAST_MESSAGE,
    CMD_LIST_USERS,
    CMD_HELP,
    CMD_QUIT,
    CMD_FILE_TRANSFER
} ClientCommand;

typedef struct {
    ClientCommand type;
    char *username;
    char *message;
    char *filepath;
} ParsedCommand;


ParsedCommand parse_command(char *command);

#endif
