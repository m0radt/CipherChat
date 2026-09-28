#define _POSIX_C_SOURCE 200809L

#include "client_files.h"

#include "common.h"
#include "file_protocol.h"

#include <errno.h>
#include <inttypes.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
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

ssize_t send_file(
    Connection *connection, const char *recipient, const char *path,
    const unsigned char recipient_public_key[crypto_box_PUBLICKEYBYTES],
    const unsigned char sender_public_key[crypto_box_PUBLICKEYBYTES],
    const unsigned char sender_private_key[crypto_box_SECRETKEYBYTES]
)
{
    FILE *file = NULL;
    const char *filename;
    size_t recipient_length;
    size_t filename_length;
    uint64_t file_size;
    uint32_t transfer_id;
    unsigned char *plaintext = NULL;
    unsigned char *encrypted = NULL;
    size_t plaintext_length = 0;
    size_t encrypted_length;
    int result = -1;
    int saved_errno;

    if (connection == NULL || recipient == NULL || path == NULL ||
        recipient_public_key == NULL || sender_public_key == NULL ||
        sender_private_key == NULL) {
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
        goto cleanup;
    }
    if (file_size > FILE_PLAINTEXT_MAX_SIZE) {
        fprintf(stderr, "Encrypted files are limited to 16 MiB.\n");
        errno = EFBIG;
        goto cleanup;
    }

    plaintext_length = FILE_CRYPTO_METADATA_SIZE + filename_length +
        (size_t)file_size;
    encrypted_length = FILE_CRYPTO_HEADER_SIZE + crypto_box_MACBYTES +
        plaintext_length;
    plaintext = malloc(plaintext_length);
    encrypted = malloc(encrypted_length);
    if (plaintext == NULL || encrypted == NULL) {
        errno = ENOMEM;
        goto cleanup;
    }

    memcpy(plaintext, FILE_CRYPTO_MAGIC, FILE_CRYPTO_MAGIC_SIZE);
    plaintext[FILE_CRYPTO_MAGIC_SIZE] = (unsigned char)(filename_length >> 8);
    plaintext[FILE_CRYPTO_MAGIC_SIZE + 1] = (unsigned char)filename_length;
    memcpy(plaintext + FILE_CRYPTO_METADATA_SIZE, filename, filename_length);
    if (fread(plaintext + FILE_CRYPTO_METADATA_SIZE + filename_length,
              1, (size_t)file_size, file) != (size_t)file_size ||
        fgetc(file) != EOF || ferror(file)) {
        /* Do not send a truncated file if it changes while being read. */
        errno = EIO;
        goto cleanup;
    }
    int close_result = fclose(file);
    file = NULL;
    if (close_result == EOF) {
        goto cleanup;
    }

    memcpy(encrypted, FILE_CRYPTO_MAGIC, FILE_CRYPTO_MAGIC_SIZE);
    memcpy(encrypted + FILE_CRYPTO_MAGIC_SIZE, sender_public_key,
           crypto_box_PUBLICKEYBYTES);
    unsigned char *nonce = encrypted + FILE_CRYPTO_MAGIC_SIZE +
        crypto_box_PUBLICKEYBYTES;
    randombytes_buf(nonce, crypto_box_NONCEBYTES);
    if (crypto_box_easy(encrypted + FILE_CRYPTO_HEADER_SIZE, plaintext,
                        plaintext_length, nonce, recipient_public_key,
                        sender_private_key) != 0) {
        errno = EINVAL;
        goto cleanup;
    }
    sodium_memzero(plaintext, plaintext_length);
    free(plaintext);
    plaintext = NULL;

    transfer_id = create_transfer_id();
    if (send_file_begin(
            connection,
            transfer_id,
            recipient,
            filename,
            encrypted_length
        ) == -1) {
        goto cleanup;
    }

    for (size_t offset = 0; offset < encrypted_length;) {
        size_t chunk_length = encrypted_length - offset;
        if (chunk_length > FILE_CHUNK_SIZE) {
            chunk_length = FILE_CHUNK_SIZE;
        }
        if (send_file_chunk(
                connection,
                transfer_id,
                encrypted + offset,
                chunk_length
            ) == -1) {
            goto cleanup;
        }
        offset += chunk_length;
    }

    if (send_file_control(
            connection,
            FRAME_FILE_END,
            transfer_id
        ) == -1) {
        goto cleanup;
    }

    printf(
        "File \"%s\" sent to %s (%" PRIu64 " bytes)\n",
        filename,
        recipient,
        file_size
    );
    fflush(stdout);
    result = 0;

cleanup:
    saved_errno = errno;
    if (file != NULL) {
        (void)fclose(file);
    }
    if (plaintext != NULL) {
        sodium_memzero(plaintext, plaintext_length);
        free(plaintext);
    }
    free(encrypted);
    errno = saved_errno;
    return result;
}
