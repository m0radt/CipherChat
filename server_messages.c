const char MSG_USER_NOT_FOUND[] = "User %s not found\n";
const char MSG_UNKNOWN_COMMAND[] = "Unknown command: %s\n";
const char MSG_INVALID_COMMAND[] = "Invalid command format: %s\n";
const char MSG_INVALID_USERNAME[] = "Invalid username: %s\n";
const char MSG_USERNAME_TAKEN[] = "Username %s is already taken\n";
const char MSG_WELCOME[] = "Welcome to CipherChat, %s!\n";
const char MSG_BROADCAST[] = "Broadcast from %s: %s\n";
const char MSG_PRIVATE_MESSAGE[] = "Private message from %s: %s\n";
const char MSG_CLIENT_DISCONNECTED[] = "Client %s disconnected\n";
const char MSG_SERVER_SHUTDOWN[] = "Server is shutting down\n";
const char MSG_CLIENT_CONNECTED[] = "Client %s connected\n";
const char MSG_CLIENT_LIST[] = "Connected clients:";
const char MSG_TIMEOUT[] = "Connection timed out\n";
const char MSG_CONNECTION_CLOSED[] = "Connection closed by peer\n";
const char MSG_LOGIN_FAILED[] = "Login failed: %s\n";
const char MSG_LOGIN_SUCCESS[] = "Login successful: %s\n";
const char MSG_LOGOUT_SUCCESS[] = "Logout successful: %s\n";
const char MSG_LOGOUT_FAILED[] = "Logout failed: %s\n";
const char MSG_INVALID_MESSAGE[] = "Invalid message format: %s\n";
const char MSG_MESSAGE_TOO_LONG[] = "Message too long: %s\n";
const char MSG_SERVER_ERROR[] = "Server error: %s\n";
const char MSG_CLIENT_ERROR[] = "Client error: %s\n";
const char MSG_UNKNOWN_ERROR[] = "Unknown error: %s\n";
const char MSG_COMMAND_NOT_IMPLEMENTED[] = "Command not implemented: %s\n";
const char MSG_COMMAND_EXECUTION_FAILED[] = "Command execution failed: %s\n";
const char HELP_MESSAGE[] =
    "Available commands:\n"
    "  /msg <username> <message>  Send a private message\n"
    "  /broadcast <message>       Send a message to everyone\n"
    "  /file <username> <path>    Send a file privately\n"
    "  /list                      List connected users\n"
    "  /help                      Display this help\n"
    "  /quit                      Disconnect from the server\n";
