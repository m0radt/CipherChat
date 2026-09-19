#ifndef CLIENT_FILES_H
#define CLIENT_FILES_H
#include "network.h"
#include <stddef.h>
#include <sys/types.h>

#define DOWNLOAD_DIRECTORY "downloads"
#define DOWNLOAD_PATH_LIMIT 4096
#define MAX_INCOMING_FILES 16

ssize_t send_file(Connection *connection, const char *recipient, const char *path);

/* frame contains the complete decoded frame: [type][payload]. */
int handle_incoming_file_frame(
    const unsigned char *frame,
    size_t frame_length,
    const char *download_directory
);

int ensure_download_directory(const char *download_directory);
void cleanup_incoming_files(void);

#endif
