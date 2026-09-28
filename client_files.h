#ifndef CLIENT_FILES_H
#define CLIENT_FILES_H
#include "network.h"
#include "file_protocol.h"
#include <sodium.h>
#include <stddef.h>
#include <sys/types.h>

#define DOWNLOAD_DIRECTORY "downloads"
#define DOWNLOAD_PATH_LIMIT 4096
#define MAX_INCOMING_FILES 16

/* Whole-file crypto_box format, carried as opaque FILE_CHUNK bytes:
 * [magic][sender public key][nonce][MAC + encrypted plaintext]
 * Plaintext: [magic][2-byte big-endian filename length][filename][file bytes].
 * The authenticated magic separates files from private chat messages.
 * All clients must use this format; plaintext file transfers are rejected.
 */
#define FILE_CRYPTO_MAGIC "CCFILE01"
#define FILE_CRYPTO_MAGIC_SIZE (sizeof(FILE_CRYPTO_MAGIC) - 1U)
#define FILE_PLAINTEXT_MAX_SIZE (16U * 1024U * 1024U)
#define FILE_CRYPTO_HEADER_SIZE \
    (FILE_CRYPTO_MAGIC_SIZE + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES)
#define FILE_CRYPTO_METADATA_SIZE (FILE_CRYPTO_MAGIC_SIZE + 2U)
#define FILE_CRYPTO_OVERHEAD \
    (FILE_CRYPTO_HEADER_SIZE + crypto_box_MACBYTES + FILE_CRYPTO_METADATA_SIZE)

ssize_t send_file(
    Connection *connection, const char *recipient, const char *path,
    const unsigned char recipient_public_key[crypto_box_PUBLICKEYBYTES],
    const unsigned char sender_public_key[crypto_box_PUBLICKEYBYTES],
    const unsigned char sender_private_key[crypto_box_SECRETKEYBYTES]
);

/* frame contains the complete decoded frame: [type][payload]. */
int handle_incoming_file_frame(
    const unsigned char *frame,
    size_t frame_length,
    const char *download_directory,
    const unsigned char recipient_private_key[crypto_box_SECRETKEYBYTES]
);

int ensure_download_directory(const char *download_directory);
void cleanup_incoming_files(void);

#endif
