#ifndef FILE_PROTOCOL_H
#define FILE_PROTOCOL_H

#include "common.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define FILE_NAME_MAX_LENGTH 255U
#define FILE_BEGIN_FIXED_PAYLOAD_SIZE \
    (sizeof(uint32_t) + (2U * sizeof(uint32_t)) + \
     (2U * sizeof(uint16_t)))
#define FILE_BEGIN_PAYLOAD_MAX_SIZE \
    (FILE_BEGIN_FIXED_PAYLOAD_SIZE + (USERNAME_SIZE - 1U) + \
     FILE_NAME_MAX_LENGTH)
#define FILE_CHUNK_PAYLOAD_MAX_SIZE \
    (sizeof(uint32_t) + FILE_CHUNK_SIZE)
#define FILE_CONTROL_PAYLOAD_SIZE sizeof(uint32_t)

typedef struct {
    uint32_t transfer_id;
    uint64_t file_size;
    char peer[USERNAME_SIZE];
    char filename[FILE_NAME_MAX_LENGTH + 1U];
} FileBeginFrame;

typedef struct {
    uint32_t transfer_id;
    const unsigned char *data;
    size_t data_length;
} FileChunkFrame;

bool file_protocol_valid_peer_name(
    const unsigned char *name,
    size_t length
);
bool file_protocol_valid_filename(
    const unsigned char *name,
    size_t length
);
int file_protocol_encode_begin(
    unsigned char *payload,
    size_t capacity,
    size_t *payload_length,
    uint32_t transfer_id,
    uint64_t file_size,
    const char *peer,
    const char *filename
);
int file_protocol_decode_begin(
    const unsigned char *frame,
    size_t frame_length,
    FileBeginFrame *decoded
);
int file_protocol_encode_chunk(
    unsigned char *payload,
    size_t capacity,
    size_t *payload_length,
    uint32_t transfer_id,
    const unsigned char *data,
    size_t data_length
);
int file_protocol_decode_chunk(
    const unsigned char *frame,
    size_t frame_length,
    FileChunkFrame *decoded
);
int file_protocol_encode_control(
    unsigned char *payload,
    size_t capacity,
    size_t *payload_length,
    uint32_t transfer_id
);
int file_protocol_decode_control(
    const unsigned char *frame,
    size_t frame_length,
    FrameType expected_type,
    uint32_t *transfer_id
);
int file_protocol_read_transfer_id(
    const unsigned char *frame,
    size_t frame_length,
    uint32_t *transfer_id
);

#endif
