#define _POSIX_C_SOURCE 200809L

#include "client_files.h"

#include "file_protocol.h"

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

typedef struct {
    bool active;
    uint32_t transfer_id;
    uint64_t expected_size;
    uint64_t received_size;
    char sender[USERNAME_SIZE];
    char filename[FILE_NAME_MAX_LENGTH + 1U];
    FILE *file;
    char temp_path[DOWNLOAD_PATH_LIMIT];
    char final_path[DOWNLOAD_PATH_LIMIT];
} IncomingFile;

static IncomingFile incoming_files[MAX_INCOMING_FILES];

static IncomingFile *find_incoming_file(uint32_t transfer_id);
static IncomingFile *create_incoming_file(uint32_t transfer_id);
static void discard_incoming_file(IncomingFile *incoming_file);
static int build_path(
    char *destination,
    size_t destination_size,
    const char *directory,
    const char *filename
);
static int receive_file_begin(
    const unsigned char *frame,
    size_t frame_length,
    const char *download_directory
);
static int receive_file_chunk(
    const unsigned char *frame,
    size_t frame_length
);
static int receive_file_end(
    const unsigned char *frame,
    size_t frame_length
);
static int receive_file_error(
    const unsigned char *frame,
    size_t frame_length
);

static IncomingFile *find_incoming_file(uint32_t transfer_id)
{
    size_t index;

    for (index = 0; index < MAX_INCOMING_FILES; index++) {
        if (incoming_files[index].active &&
            incoming_files[index].transfer_id == transfer_id) {
            return &incoming_files[index];
        }
    }

    return NULL;
}

static IncomingFile *create_incoming_file(uint32_t transfer_id)
{
    size_t index;

    if (find_incoming_file(transfer_id) != NULL) {
        errno = EEXIST;
        return NULL;
    }

    for (index = 0; index < MAX_INCOMING_FILES; index++) {
        if (!incoming_files[index].active) {
            memset(&incoming_files[index], 0, sizeof(incoming_files[index]));
            incoming_files[index].active = true;
            incoming_files[index].transfer_id = transfer_id;
            return &incoming_files[index];
        }
    }

    errno = ENOSPC;
    return NULL;
}

static void discard_incoming_file(IncomingFile *incoming_file)
{
    int saved_errno = errno;

    if (incoming_file == NULL) {
        return;
    }

    if (incoming_file->file != NULL) {
        (void)fclose(incoming_file->file);
        incoming_file->file = NULL;
    }

    if (incoming_file->temp_path[0] != '\0') {
        (void)unlink(incoming_file->temp_path);
    }

    memset(incoming_file, 0, sizeof(*incoming_file));
    errno = saved_errno;
}

void cleanup_incoming_files(void)
{
    size_t index;
    int saved_errno = errno;

    for (index = 0; index < MAX_INCOMING_FILES; index++) {
        if (incoming_files[index].active) {
            fprintf(
                stderr,
                "Discarding incomplete file transfer %" PRIu32
                " from %s\n",
                incoming_files[index].transfer_id,
                incoming_files[index].sender[0] != '\0'
                    ? incoming_files[index].sender
                    : "unknown sender"
            );
            discard_incoming_file(&incoming_files[index]);
        }
    }

    errno = saved_errno;
}

int ensure_download_directory(const char *download_directory)
{
    struct stat directory_status;

    if (download_directory == NULL || download_directory[0] == '\0') {
        errno = EINVAL;
        return -1;
    }

    if (mkdir(download_directory, S_IRWXU) == 0) {
        return 0;
    }

    if (errno != EEXIST) {
        return -1;
    }

    if (stat(download_directory, &directory_status) == -1) {
        return -1;
    }

    if (!S_ISDIR(directory_status.st_mode)) {
        errno = ENOTDIR;
        return -1;
    }

    return 0;
}

static int build_path(
    char *destination,
    size_t destination_size,
    const char *directory,
    const char *filename
)
{
    int written;

    if (destination == NULL || destination_size == 0 || directory == NULL ||
        filename == NULL) {
        errno = EINVAL;
        return -1;
    }

    written = snprintf(
        destination,
        destination_size,
        "%s/%s",
        directory,
        filename
    );

    if (written < 0) {
        return -1;
    }

    if ((size_t)written >= destination_size) {
        errno = ENAMETOOLONG;
        return -1;
    }

    return 0;
}

static int receive_file_begin(
    const unsigned char *frame,
    size_t frame_length,
    const char *download_directory
)
{
    FileBeginFrame decoded;
    IncomingFile *incoming_file;
    struct stat final_status;
    int temporary_fd;
    int written;
    int saved_errno;

    if (download_directory == NULL) {
        errno = EINVAL;
        return -1;
    }

    if (file_protocol_decode_begin(frame, frame_length, &decoded) == -1) {
        return -1;
    }

    if (ensure_download_directory(download_directory) == -1) {
        return -1;
    }

    incoming_file = create_incoming_file(decoded.transfer_id);
    if (incoming_file == NULL) {
        return -1;
    }

    memcpy(incoming_file->sender, decoded.peer, sizeof(decoded.peer));
    memcpy(incoming_file->filename, decoded.filename, sizeof(decoded.filename));
    incoming_file->expected_size = decoded.file_size;

    if (build_path(
            incoming_file->final_path,
            sizeof(incoming_file->final_path),
            download_directory,
            incoming_file->filename
        ) == -1) {
        saved_errno = errno;
        discard_incoming_file(incoming_file);
        errno = saved_errno;
        return -1;
    }

    if (lstat(incoming_file->final_path, &final_status) == 0) {
        discard_incoming_file(incoming_file);
        errno = EEXIST;
        return -1;
    }
    if (errno != ENOENT) {
        saved_errno = errno;
        discard_incoming_file(incoming_file);
        errno = saved_errno;
        return -1;
    }

    written = snprintf(
        incoming_file->temp_path,
        sizeof(incoming_file->temp_path),
        "%s/.cipher-chat-%ld-%" PRIu32 "-XXXXXX",
        download_directory,
        (long)getpid(),
        decoded.transfer_id
    );
    if (written < 0 ||
        (size_t)written >= sizeof(incoming_file->temp_path)) {
        discard_incoming_file(incoming_file);
        errno = ENAMETOOLONG;
        return -1;
    }

    temporary_fd = mkstemp(incoming_file->temp_path);
    if (temporary_fd == -1) {
        saved_errno = errno;
        discard_incoming_file(incoming_file);
        errno = saved_errno;
        return -1;
    }

    incoming_file->file = fdopen(temporary_fd, "wb");
    if (incoming_file->file == NULL) {
        saved_errno = errno;
        (void)close(temporary_fd);
        discard_incoming_file(incoming_file);
        errno = saved_errno;
        return -1;
    }

    printf(
        "Receiving file \"%s\" (%" PRIu64 " bytes) from %s\n",
        incoming_file->filename,
        incoming_file->expected_size,
        incoming_file->sender
    );
    fflush(stdout);
    return 0;
}

static int receive_file_chunk(
    const unsigned char *frame,
    size_t frame_length
)
{
    FileChunkFrame decoded;
    IncomingFile *incoming_file;
    size_t written;
    int saved_errno;

    if (file_protocol_decode_chunk(frame, frame_length, &decoded) == -1) {
        return -1;
    }

    incoming_file = find_incoming_file(decoded.transfer_id);
    if (incoming_file == NULL) {
        errno = ENOENT;
        return -1;
    }

    if (incoming_file->received_size > incoming_file->expected_size ||
        decoded.data_length > incoming_file->expected_size -
            incoming_file->received_size) {
        fprintf(
            stderr,
            "File transfer %" PRIu32 " from %s exceeded its declared size\n",
            decoded.transfer_id,
            incoming_file->sender
        );
        saved_errno = EFBIG;
        discard_incoming_file(incoming_file);
        errno = saved_errno;
        return -1;
    }

    written = fwrite(
        decoded.data,
        1,
        decoded.data_length,
        incoming_file->file
    );
    if (written != decoded.data_length) {
        saved_errno = errno == 0 ? EIO : errno;
        fprintf(
            stderr,
            "Failed writing file transfer %" PRIu32 " from %s: %s\n",
            decoded.transfer_id,
            incoming_file->sender,
            strerror(saved_errno)
        );
        discard_incoming_file(incoming_file);
        errno = saved_errno;
        return -1;
    }

    incoming_file->received_size += (uint64_t)written;
    return 0;
}

static int receive_file_end(
    const unsigned char *frame,
    size_t frame_length
)
{
    uint32_t transfer_id;
    IncomingFile *incoming_file;
    FILE *completed_file;
    int saved_errno;

    if (file_protocol_decode_control(
            frame,
            frame_length,
            FRAME_FILE_END,
            &transfer_id
        ) == -1) {
        return -1;
    }

    incoming_file = find_incoming_file(transfer_id);
    if (incoming_file == NULL) {
        errno = ENOENT;
        return -1;
    }

    if (incoming_file->received_size != incoming_file->expected_size) {
        fprintf(
            stderr,
            "Incomplete file from %s: expected %" PRIu64
            " bytes, received %" PRIu64 " bytes\n",
            incoming_file->sender,
            incoming_file->expected_size,
            incoming_file->received_size
        );
        saved_errno = EIO;
        discard_incoming_file(incoming_file);
        errno = saved_errno;
        return -1;
    }

    completed_file = incoming_file->file;
    incoming_file->file = NULL;
    if (fclose(completed_file) == EOF) {
        saved_errno = errno == 0 ? EIO : errno;
        discard_incoming_file(incoming_file);
        errno = saved_errno;
        return -1;
    }

    if (link(incoming_file->temp_path, incoming_file->final_path) == -1) {
        saved_errno = errno;
        fprintf(
            stderr,
            "Could not save file \"%s\" from %s: %s\n",
            incoming_file->filename,
            incoming_file->sender,
            strerror(saved_errno)
        );
        discard_incoming_file(incoming_file);
        errno = saved_errno;
        return -1;
    }

    if (unlink(incoming_file->temp_path) == -1) {
        fprintf(
            stderr,
            "Warning: received file was saved, but temporary file %s "
            "could not be removed: %s\n",
            incoming_file->temp_path,
            strerror(errno)
        );
    }

    printf(
        "Received file from %s: %s (%" PRIu64 " bytes)\n",
        incoming_file->sender,
        incoming_file->final_path,
        incoming_file->received_size
    );
    fflush(stdout);
    memset(incoming_file, 0, sizeof(*incoming_file));
    return 0;
}

static int receive_file_error(
    const unsigned char *frame,
    size_t frame_length
)
{
    uint32_t transfer_id;
    IncomingFile *incoming_file;

    if (file_protocol_decode_control(
            frame,
            frame_length,
            FRAME_FILE_ERROR,
            &transfer_id
        ) == -1) {
        return -1;
    }

    incoming_file = find_incoming_file(transfer_id);
    if (incoming_file == NULL) {
        fprintf(
            stderr,
            "File transfer %" PRIu32 " failed\n",
            transfer_id
        );
        return 0;
    }

    fprintf(
        stderr,
        "File transfer %" PRIu32 " from %s failed\n",
        transfer_id,
        incoming_file->sender
    );
    discard_incoming_file(incoming_file);
    return 0;
}

int handle_incoming_file_frame(
    const unsigned char *frame,
    size_t frame_length,
    const char *download_directory
)
{
    if (frame == NULL || frame_length == 0) {
        errno = EINVAL;
        return -1;
    }

    switch ((FrameType)frame[0]) {
    case FRAME_FILE_BEGIN:
        return receive_file_begin(
            frame,
            frame_length,
            download_directory
        );
    case FRAME_FILE_CHUNK:
        return receive_file_chunk(frame, frame_length);
    case FRAME_FILE_END:
        return receive_file_end(frame, frame_length);
    case FRAME_FILE_ERROR:
        return receive_file_error(frame, frame_length);
    case FRAME_TEXT:
    default:
        errno = EINVAL;
        return -1;
    }
}
