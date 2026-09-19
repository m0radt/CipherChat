#define _POSIX_C_SOURCE 200809L

#include "client_files.h"

#include "common.h"
#include "file_protocol.h"

#include <errno.h>
#include <inttypes.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

static _Atomic uint32_t next_transfer_id = 1U;

static uint32_t create_transfer_id(void);
static int get_regular_file_size(FILE *file, uint64_t *file_size);
static const char *path_basename(const char *path);
static int send_file_begin(
    Connection *connection,
    uint32_t transfer_id,
    const char *recipient,
    const char *filename,
    uint64_t file_size
);
static int send_file_chunk(
    Connection *connection,
    uint32_t transfer_id,
    const unsigned char *chunk,
    size_t chunk_length
);
static int send_file_control(
    Connection *connection,
    FrameType type,
    uint32_t transfer_id
);

static uint32_t create_transfer_id(void)
{
    uint32_t transfer_id;

    do {
        transfer_id = atomic_fetch_add_explicit(
            &next_transfer_id,
            1U,
            memory_order_relaxed
        );
    } while (transfer_id == 0U);

    return transfer_id;
}

static int get_regular_file_size(FILE *file, uint64_t *file_size)
{
    struct stat file_status;
    int file_fd;

    if (file == NULL || file_size == NULL) {
        errno = EINVAL;
        return -1;
    }

    file_fd = fileno(file);
    if (file_fd == -1) {
        return -1;
    }

    if (fstat(file_fd, &file_status) == -1) {
        return -1;
    }

    if (!S_ISREG(file_status.st_mode) || file_status.st_size < 0) {
        errno = EINVAL;
        return -1;
    }

    *file_size = (uint64_t)file_status.st_size;
    return 0;
}

static const char *path_basename(const char *path)
{
    const char *separator;

    if (path == NULL || path[0] == '\0') {
        return NULL;
    }

    separator = strrchr(path, '/');
    return separator == NULL ? path : separator + 1;
}

static int send_file_begin(
    Connection *connection,
    uint32_t transfer_id,
    const char *recipient,
    const char *filename,
    uint64_t file_size
)
{
    unsigned char payload[FILE_BEGIN_PAYLOAD_MAX_SIZE];
    size_t payload_length;

    if (file_protocol_encode_begin(
            payload,
            sizeof(payload),
            &payload_length,
            transfer_id,
            file_size,
            recipient,
            filename
        ) == -1) {
        return -1;
    }

    return send_frame(
        connection,
        FRAME_FILE_BEGIN,
        payload,
        payload_length
    ) == -1 ? -1 : 0;
}

static int send_file_chunk(
    Connection *connection,
    uint32_t transfer_id,
    const unsigned char *chunk,
    size_t chunk_length
)
{
    unsigned char payload[FILE_CHUNK_PAYLOAD_MAX_SIZE];
    size_t payload_length;

    if (file_protocol_encode_chunk(
            payload,
            sizeof(payload),
            &payload_length,
            transfer_id,
            chunk,
            chunk_length
        ) == -1) {
        return -1;
    }

    return send_frame(
        connection,
        FRAME_FILE_CHUNK,
        payload,
        payload_length
    ) == -1 ? -1 : 0;
}

static int send_file_control(
    Connection *connection,
    FrameType type,
    uint32_t transfer_id
)
{
    unsigned char payload[FILE_CONTROL_PAYLOAD_SIZE];
    size_t payload_length;

    if (type != FRAME_FILE_END && type != FRAME_FILE_ERROR) {
        errno = EINVAL;
        return -1;
    }

    if (file_protocol_encode_control(
            payload,
            sizeof(payload),
            &payload_length,
            transfer_id
        ) == -1) {
        return -1;
    }

    return send_frame(
        connection,
        type,
        payload,
        payload_length
    ) == -1 ? -1 : 0;
}

ssize_t send_file(Connection *connection, const char *recipient, const char *path)
{
    FILE *file;
    const char *filename;
    size_t recipient_length;
    size_t filename_length;
    uint64_t file_size;
    uint32_t transfer_id;
    unsigned char chunk[FILE_CHUNK_SIZE];
    size_t bytes_read;
    int saved_errno;

    if (connection == NULL || recipient == NULL || path == NULL) {
        errno = EINVAL;
        return -1;
    }

    filename = path_basename(path);
    recipient_length = strlen(recipient);
    filename_length = filename == NULL ? 0 : strlen(filename);

    if (!file_protocol_valid_peer_name(
            (const unsigned char *)recipient,
            recipient_length
        ) ||
        !file_protocol_valid_filename(
            (const unsigned char *)filename,
            filename_length
        )) {
        errno = EINVAL;
        return -1;
    }

    file = fopen(path, "rb");
    if (file == NULL) {
        return -1;
    }

    if (get_regular_file_size(file, &file_size) == -1) {
        saved_errno = errno;
        (void)fclose(file);
        errno = saved_errno;
        return -1;
    }

    transfer_id = create_transfer_id();
    if (send_file_begin(
            connection,
            transfer_id,
            recipient,
            filename,
            file_size
        ) == -1) {
        saved_errno = errno;
        (void)fclose(file);
        errno = saved_errno;
        return -1;
    }

    while ((bytes_read = fread(chunk, 1, sizeof(chunk), file)) > 0) {
        if (send_file_chunk(
                connection,
                transfer_id,
                chunk,
                bytes_read
            ) == -1) {
            saved_errno = errno;
            (void)fclose(file);
            errno = saved_errno;
            return -1;
        }
    }

    if (ferror(file)) {
        saved_errno = errno == 0 ? EIO : errno;
        (void)send_file_control(
            connection,
            FRAME_FILE_ERROR,
            transfer_id
        );
        (void)fclose(file);
        errno = saved_errno;
        return -1;
    }

    if (fclose(file) == EOF) {
        saved_errno = errno == 0 ? EIO : errno;
        (void)send_file_control(
            connection,
            FRAME_FILE_ERROR,
            transfer_id
        );
        errno = saved_errno;
        return -1;
    }

    if (send_file_control(
            connection,
            FRAME_FILE_END,
            transfer_id
        ) == -1) {
        return -1;
    }

    printf(
        "File \"%s\" sent to %s (%" PRIu64 " bytes)\n",
        filename,
        recipient,
        file_size
    );
    fflush(stdout);
    return 0;
}
