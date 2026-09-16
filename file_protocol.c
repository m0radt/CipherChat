#include "file_protocol.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

static uint16_t read_u16(const unsigned char *bytes)
{
    uint16_t network_value;

    memcpy(&network_value, bytes, sizeof(network_value));
    return ntohs(network_value);
}

static uint32_t read_u32(const unsigned char *bytes)
{
    uint32_t network_value;

    memcpy(&network_value, bytes, sizeof(network_value));
    return ntohl(network_value);
}

static uint64_t read_u64(const unsigned char *bytes)
{
    uint32_t high = read_u32(bytes);
    uint32_t low = read_u32(bytes + sizeof(uint32_t));

    return ((uint64_t)high << 32) | (uint64_t)low;
}

static void write_u16(unsigned char *bytes, uint16_t value)
{
    uint16_t network_value = htons(value);

    memcpy(bytes, &network_value, sizeof(network_value));
}

static void write_u32(unsigned char *bytes, uint32_t value)
{
    uint32_t network_value = htonl(value);

    memcpy(bytes, &network_value, sizeof(network_value));
}

static void write_u64(unsigned char *bytes, uint64_t value)
{
    write_u32(bytes, (uint32_t)(value >> 32));
    write_u32(bytes + sizeof(uint32_t), (uint32_t)value);
}

static bool bounded_string_length(
    const char *value,
    size_t maximum_length,
    size_t *length
)
{
    size_t index;

    for (index = 0; index <= maximum_length; index++) {
        if (value[index] == '\0') {
            *length = index;
            return true;
        }
    }

    return false;
}

bool file_protocol_valid_peer_name(
    const unsigned char *name,
    size_t length
)
{
    size_t index;

    if (name == NULL || length == 0 || length >= USERNAME_SIZE) {
        return false;
    }

    for (index = 0; index < length; index++) {
        if (name[index] == '\0' || isspace((int)name[index]) ||
            iscntrl((int)name[index])) {
            return false;
        }
    }

    return true;
}

bool file_protocol_valid_filename(
    const unsigned char *name,
    size_t length
)
{
    size_t index;

    if (name == NULL || length == 0 || length > FILE_NAME_MAX_LENGTH) {
        return false;
    }

    if ((length == 1U && name[0] == '.') ||
        (length == 2U && name[0] == '.' && name[1] == '.')) {
        return false;
    }

    for (index = 0; index < length; index++) {
        if (name[index] == '\0' || name[index] == '/' ||
            name[index] == '\\' || iscntrl((int)name[index])) {
            return false;
        }
    }

    return true;
}

int file_protocol_encode_begin(
    unsigned char *payload,
    size_t capacity,
    size_t *payload_length,
    uint32_t transfer_id,
    uint64_t file_size,
    const char *peer,
    const char *filename
)
{
    size_t peer_length;
    size_t filename_length;
    size_t encoded_length;
    size_t offset = 0;

    if (payload == NULL || payload_length == NULL || peer == NULL ||
        filename == NULL) {
        errno = EINVAL;
        return -1;
    }

    if (!bounded_string_length(peer, USERNAME_SIZE - 1U, &peer_length) ||
        !bounded_string_length(
            filename,
            FILE_NAME_MAX_LENGTH,
            &filename_length
        ) ||
        !file_protocol_valid_peer_name(
            (const unsigned char *)peer,
            peer_length
        ) ||
        !file_protocol_valid_filename(
            (const unsigned char *)filename,
            filename_length
        )) {
        errno = EINVAL;
        return -1;
    }

    encoded_length = FILE_BEGIN_FIXED_PAYLOAD_SIZE + peer_length +
        filename_length;
    if (capacity < encoded_length) {
        errno = EMSGSIZE;
        return -1;
    }

    write_u32(payload + offset, transfer_id);
    offset += sizeof(uint32_t);
    write_u64(payload + offset, file_size);
    offset += 2U * sizeof(uint32_t);
    write_u16(payload + offset, (uint16_t)peer_length);
    offset += sizeof(uint16_t);
    write_u16(payload + offset, (uint16_t)filename_length);
    offset += sizeof(uint16_t);
    memcpy(payload + offset, peer, peer_length);
    offset += peer_length;
    memcpy(payload + offset, filename, filename_length);
    offset += filename_length;

    *payload_length = offset;
    return 0;
}

int file_protocol_decode_begin(
    const unsigned char *frame,
    size_t frame_length,
    FileBeginFrame *decoded
)
{
    const size_t header_length = 1U + FILE_BEGIN_FIXED_PAYLOAD_SIZE;
    FileBeginFrame parsed = {0};
    size_t offset = 1U;
    size_t peer_length;
    size_t filename_length;
    size_t variable_length;

    if (frame == NULL || decoded == NULL) {
        errno = EINVAL;
        return -1;
    }

    if (frame_length < header_length ||
        frame[0] != (unsigned char)FRAME_FILE_BEGIN) {
        errno = EPROTO;
        return -1;
    }

    parsed.transfer_id = read_u32(frame + offset);
    offset += sizeof(uint32_t);
    parsed.file_size = read_u64(frame + offset);
    offset += 2U * sizeof(uint32_t);
    peer_length = read_u16(frame + offset);
    offset += sizeof(uint16_t);
    filename_length = read_u16(frame + offset);
    offset += sizeof(uint16_t);
    variable_length = peer_length + filename_length;

    if (variable_length != frame_length - header_length ||
        !file_protocol_valid_peer_name(frame + offset, peer_length) ||
        !file_protocol_valid_filename(
            frame + offset + peer_length,
            filename_length
        )) {
        errno = EPROTO;
        return -1;
    }

    memcpy(parsed.peer, frame + offset, peer_length);
    parsed.peer[peer_length] = '\0';
    offset += peer_length;
    memcpy(parsed.filename, frame + offset, filename_length);
    parsed.filename[filename_length] = '\0';

    *decoded = parsed;
    return 0;
}

int file_protocol_encode_chunk(
    unsigned char *payload,
    size_t capacity,
    size_t *payload_length,
    uint32_t transfer_id,
    const unsigned char *data,
    size_t data_length
)
{
    size_t encoded_length;

    if (payload == NULL || payload_length == NULL || data == NULL ||
        data_length == 0 || data_length > FILE_CHUNK_SIZE) {
        errno = EINVAL;
        return -1;
    }

    encoded_length = sizeof(uint32_t) + data_length;
    if (capacity < encoded_length) {
        errno = EMSGSIZE;
        return -1;
    }

    write_u32(payload, transfer_id);
    memcpy(payload + sizeof(uint32_t), data, data_length);
    *payload_length = encoded_length;
    return 0;
}

int file_protocol_decode_chunk(
    const unsigned char *frame,
    size_t frame_length,
    FileChunkFrame *decoded
)
{
    const size_t header_length = 1U + sizeof(uint32_t);
    FileChunkFrame parsed;

    if (frame == NULL || decoded == NULL) {
        errno = EINVAL;
        return -1;
    }

    if (frame_length <= header_length ||
        frame[0] != (unsigned char)FRAME_FILE_CHUNK ||
        frame_length > header_length + FILE_CHUNK_SIZE) {
        errno = EPROTO;
        return -1;
    }

    parsed.transfer_id = read_u32(frame + 1U);
    parsed.data = frame + header_length;
    parsed.data_length = frame_length - header_length;
    *decoded = parsed;
    return 0;
}

int file_protocol_encode_control(
    unsigned char *payload,
    size_t capacity,
    size_t *payload_length,
    uint32_t transfer_id
)
{
    if (payload == NULL || payload_length == NULL) {
        errno = EINVAL;
        return -1;
    }

    if (capacity < FILE_CONTROL_PAYLOAD_SIZE) {
        errno = EMSGSIZE;
        return -1;
    }

    write_u32(payload, transfer_id);
    *payload_length = FILE_CONTROL_PAYLOAD_SIZE;
    return 0;
}

int file_protocol_decode_control(
    const unsigned char *frame,
    size_t frame_length,
    FrameType expected_type,
    uint32_t *transfer_id
)
{
    if (frame == NULL || transfer_id == NULL ||
        (expected_type != FRAME_FILE_END &&
         expected_type != FRAME_FILE_ERROR)) {
        errno = EINVAL;
        return -1;
    }

    if (frame_length != 1U + FILE_CONTROL_PAYLOAD_SIZE ||
        frame[0] != (unsigned char)expected_type) {
        errno = EPROTO;
        return -1;
    }

    *transfer_id = read_u32(frame + 1U);
    return 0;
}

int file_protocol_read_transfer_id(
    const unsigned char *frame,
    size_t frame_length,
    uint32_t *transfer_id
)
{
    if (frame == NULL || transfer_id == NULL) {
        errno = EINVAL;
        return -1;
    }

    if (frame_length < 1U + sizeof(uint32_t)) {
        errno = EPROTO;
        return -1;
    }

    *transfer_id = read_u32(frame + 1U);
    return 0;
}
