#include "server_files.h"

#include "common.h"
#include "file_protocol.h"
#include "server_file_routes.h"

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int handle_file_begin(
    ClientId sender_id,
    const char *sender_username,
    const unsigned char *frame,
    size_t frame_length
);
static int handle_file_chunk(
    ClientId sender_id,
    const unsigned char *frame,
    size_t frame_length
);
static int handle_file_end(
    ClientId sender_id,
    const unsigned char *frame,
    size_t frame_length
);
static int handle_file_error(
    ClientId sender_id,
    const unsigned char *frame,
    size_t frame_length
);
static bool get_username_length(const char *username, size_t *length);
static int send_receiver_error(FileRouteEndpoint endpoint);
static void notify_sender(ClientId sender_id, const char *message);
static void notify_sender_for_transfer(
    ClientId sender_id,
    uint32_t source_transfer_id,
    const char *message
);
static int reject_known_transfer(
    ClientId sender_id,
    uint32_t source_transfer_id,
    const char *message,
    bool keep_discard
);

void init_file_routes(void) {
    file_routes_init();
}

int route_file_frame(
    ClientId sender_id,
    const char *sender_username,
    const unsigned char *full_frame,
    size_t frame_len
) {
    if (sender_id == INVALID_CLIENT_ID || sender_username == NULL ||
        full_frame == NULL || frame_len == 0) {
        errno = EINVAL;
        return -1;
    }

    if (frame_len > FRAME_MAX_SIZE) {
        notify_sender(
            sender_id,
            "File transfer rejected: frame is too large\n"
        );
        errno = EMSGSIZE;
        return -1;
    }

    switch ((FrameType)full_frame[0]) {
    case FRAME_FILE_BEGIN:
        return handle_file_begin(
            sender_id,
            sender_username,
            full_frame,
            frame_len
        );
    case FRAME_FILE_CHUNK:
        return handle_file_chunk(sender_id, full_frame, frame_len);
    case FRAME_FILE_END:
        return handle_file_end(sender_id, full_frame, frame_len);
    case FRAME_FILE_ERROR:
        return handle_file_error(sender_id, full_frame, frame_len);
    case FRAME_TEXT:
    default:
        notify_sender(
            sender_id,
            "File transfer rejected: invalid file frame type\n"
        );
        errno = EPROTO;
        return -1;
    }
}

void abort_file_routes_for_client(ClientId client_id) {
    if (client_id == INVALID_CLIENT_ID) {
        return;
    }

    FileRouteAbortAction actions[FILE_ROUTE_CAPACITY];
    size_t action_count = file_routes_abort_client(
        client_id,
        actions,
        FILE_ROUTE_CAPACITY
    );

    for (size_t index = 0; index < action_count; index++) {
        if (actions[index].type == FILE_ROUTE_ABORT_SEND_ERROR) {
            FileRouteEndpoint endpoint = {
                .target_id = actions[index].client_id,
                .outbound_transfer_id = actions[index].outbound_transfer_id
            };
            (void)send_receiver_error(endpoint);
        } else {
            notify_sender(
                actions[index].client_id,
                "File transfer failed: recipient disconnected\n"
            );
        }
    }
}

static int handle_file_begin(
    ClientId sender_id,
    const char *sender_username,
    const unsigned char *frame,
    size_t frame_length
) {
    size_t sender_username_length;
    if (!get_username_length(sender_username, &sender_username_length) ||
        !file_protocol_valid_peer_name(
            (const unsigned char *)sender_username,
            sender_username_length
        )) {
        notify_sender(
            sender_id,
            "File transfer rejected: invalid sender username\n"
        );
        errno = EINVAL;
        return -1;
    }

    FileBeginFrame begin;
    if (file_protocol_decode_begin(frame, frame_length, &begin) == -1) {
        uint32_t source_transfer_id;
        if (file_protocol_read_transfer_id(
                frame,
                frame_length,
                &source_transfer_id
            ) == 0) {
            return reject_known_transfer(
                sender_id,
                source_transfer_id,
                "File transfer rejected: malformed begin frame\n",
                true
            );
        }

        notify_sender(
            sender_id,
            "File transfer rejected: malformed begin frame\n"
        );
        errno = EPROTO;
        return -1;
    }

    ClientId target_id = find_client_id(begin.peer);
    bool discard = target_id == INVALID_CLIENT_ID || target_id == sender_id;
    FileRouteEndpoint endpoint = {
        .target_id = INVALID_CLIENT_ID,
        .outbound_transfer_id = 0
    };
    FileRouteEndpoint replaced = endpoint;

    FileRouteAddResult add_result = file_routes_add(
        sender_id,
        begin.transfer_id,
        target_id,
        begin.file_size,
        discard,
        &endpoint,
        &replaced
    );

    switch (add_result) {
    case FILE_ROUTE_ADD_DUPLICATE:
        if (replaced.target_id != INVALID_CLIENT_ID) {
            (void)send_receiver_error(replaced);
        }
        notify_sender_for_transfer(
            sender_id,
            begin.transfer_id,
            "File transfer rejected: duplicate transfer id\n"
        );
        errno = EPROTO;
        return -1;

    case FILE_ROUTE_ADD_FULL:
        notify_sender(
            sender_id,
            "File transfer rejected: server transfer limit reached\n"
        );
        errno = ENOSPC;
        return -1;

    case FILE_ROUTE_ADD_ID_UNAVAILABLE:
        notify_sender(
            sender_id,
            "File transfer rejected: no transfer id is available\n"
        );
        errno = ENOSPC;
        return -1;

    case FILE_ROUTE_ADD_DISCARD: {
        char message[BUFFER_SIZE];
        int written;

        if (target_id == sender_id) {
            written = snprintf(
                message,
                sizeof(message),
                "File transfer rejected: cannot send a file to yourself\n"
            );
        } else {
            written = snprintf(
                message,
                sizeof(message),
                "File transfer rejected: user %s is not connected\n",
                begin.peer
            );
        }

        if (written > 0 && (size_t)written < sizeof(message)) {
            notify_sender_for_transfer(
                sender_id,
                begin.transfer_id,
                message
            );
        } else {
            notify_sender_for_transfer(
                sender_id,
                begin.transfer_id,
                "File transfer rejected: recipient is not connected\n"
            );
        }
        return 0;
    }

    case FILE_ROUTE_ADD_READY:
        break;
    }

    unsigned char payload[FILE_BEGIN_PAYLOAD_MAX_SIZE];
    size_t payload_length;
    if (file_protocol_encode_begin(
            payload,
            sizeof(payload),
            &payload_length,
            endpoint.outbound_transfer_id,
            begin.file_size,
            sender_username,
            begin.filename
        ) == -1) {
        return reject_known_transfer(
            sender_id,
            begin.transfer_id,
            "File transfer rejected: begin frame is too large\n",
            true
        );
    }

    if (send_frame_to_client_id(
            endpoint.target_id,
            FRAME_FILE_BEGIN,
            payload,
            payload_length
        ) == -1) {
        FileRouteEndpoint ignored;
        (void)file_routes_quarantine(
            sender_id,
            begin.transfer_id,
            true,
            &ignored
        );
        notify_sender_for_transfer(
            sender_id,
            begin.transfer_id,
            "File transfer failed: could not reach recipient\n"
        );
        return -1;
    }

    return 0;
}

static int handle_file_chunk(
    ClientId sender_id,
    const unsigned char *frame,
    size_t frame_length
) {
    FileChunkFrame chunk;
    if (file_protocol_decode_chunk(frame, frame_length, &chunk) == -1) {
        uint32_t source_transfer_id;
        if (file_protocol_read_transfer_id(
                frame,
                frame_length,
                &source_transfer_id
            ) == 0) {
            return reject_known_transfer(
                sender_id,
                source_transfer_id,
                "File transfer failed: invalid chunk size\n",
                true
            );
        }

        notify_sender(
            sender_id,
            "File transfer rejected: malformed chunk frame\n"
        );
        errno = EPROTO;
        return -1;
    }

    FileRouteEndpoint endpoint = {
        .target_id = INVALID_CLIENT_ID,
        .outbound_transfer_id = 0
    };
    FileRouteChunkResult route_result = file_routes_accept_chunk(
        sender_id,
        chunk.transfer_id,
        chunk.data_length,
        &endpoint
    );

    switch (route_result) {
    case FILE_ROUTE_CHUNK_MISSING:
        notify_sender_for_transfer(
            sender_id,
            chunk.transfer_id,
            "File transfer rejected: chunk has no matching begin frame\n"
        );
        errno = EPROTO;
        return -1;

    case FILE_ROUTE_CHUNK_DISCARD:
        return 0;

    case FILE_ROUTE_CHUNK_OVERRUN:
        (void)send_receiver_error(endpoint);
        notify_sender_for_transfer(
            sender_id,
            chunk.transfer_id,
            "File transfer failed: data exceeds declared file size\n"
        );
        errno = EPROTO;
        return -1;

    case FILE_ROUTE_CHUNK_READY:
        break;
    }

    unsigned char payload[FILE_CHUNK_PAYLOAD_MAX_SIZE];
    size_t payload_length;
    if (file_protocol_encode_chunk(
            payload,
            sizeof(payload),
            &payload_length,
            endpoint.outbound_transfer_id,
            chunk.data,
            chunk.data_length
        ) == -1) {
        return reject_known_transfer(
            sender_id,
            chunk.transfer_id,
            "File transfer failed: could not encode chunk\n",
            true
        );
    }

    if (send_frame_to_client_id(
            endpoint.target_id,
            FRAME_FILE_CHUNK,
            payload,
            payload_length
        ) == -1) {
        if (file_routes_mark_forward_failed(
                sender_id,
                chunk.transfer_id,
                endpoint.outbound_transfer_id
            )) {
            notify_sender_for_transfer(
                sender_id,
                chunk.transfer_id,
                "File transfer failed: recipient disconnected\n"
            );
        }
        return -1;
    }

    return 0;
}

static int handle_file_end(
    ClientId sender_id,
    const unsigned char *frame,
    size_t frame_length
) {
    uint32_t source_transfer_id;
    if (file_protocol_decode_control(
            frame,
            frame_length,
            FRAME_FILE_END,
            &source_transfer_id
        ) == -1) {
        if (file_protocol_read_transfer_id(
                frame,
                frame_length,
                &source_transfer_id
            ) == 0) {
            return reject_known_transfer(
                sender_id,
                source_transfer_id,
                "File transfer failed: malformed end frame\n",
                false
            );
        }

        notify_sender(
            sender_id,
            "File transfer rejected: malformed end frame\n"
        );
        errno = EPROTO;
        return -1;
    }

    FileRouteEndpoint endpoint = {
        .target_id = INVALID_CLIENT_ID,
        .outbound_transfer_id = 0
    };
    FileRouteFinishResult finish_result = file_routes_finish(
        sender_id,
        source_transfer_id,
        true,
        &endpoint
    );

    switch (finish_result) {
    case FILE_ROUTE_FINISH_MISSING:
        notify_sender_for_transfer(
            sender_id,
            source_transfer_id,
            "File transfer rejected: end has no matching begin frame\n"
        );
        errno = EPROTO;
        return -1;

    case FILE_ROUTE_FINISH_DISCARD:
        return 0;

    case FILE_ROUTE_FINISH_INCOMPLETE:
        (void)send_receiver_error(endpoint);
        notify_sender_for_transfer(
            sender_id,
            source_transfer_id,
            "File transfer failed: received size does not match declared size\n"
        );
        errno = EPROTO;
        return -1;

    case FILE_ROUTE_FINISH_READY:
        break;
    }

    unsigned char payload[FILE_CONTROL_PAYLOAD_SIZE];
    size_t payload_length;
    if (file_protocol_encode_control(
            payload,
            sizeof(payload),
            &payload_length,
            endpoint.outbound_transfer_id
        ) == -1 ||
        send_frame_to_client_id(
            endpoint.target_id,
            FRAME_FILE_END,
            payload,
            payload_length
        ) == -1) {
        notify_sender_for_transfer(
            sender_id,
            source_transfer_id,
            "File transfer failed: recipient disconnected\n"
        );
        return -1;
    }

    return 0;
}

static int handle_file_error(
    ClientId sender_id,
    const unsigned char *frame,
    size_t frame_length
) {
    uint32_t source_transfer_id;
    if (file_protocol_decode_control(
            frame,
            frame_length,
            FRAME_FILE_ERROR,
            &source_transfer_id
        ) == -1) {
        if (file_protocol_read_transfer_id(
                frame,
                frame_length,
                &source_transfer_id
            ) == 0) {
            return reject_known_transfer(
                sender_id,
                source_transfer_id,
                "File transfer rejected: malformed error frame\n",
                false
            );
        }

        notify_sender(
            sender_id,
            "File transfer rejected: malformed error frame\n"
        );
        errno = EPROTO;
        return -1;
    }

    FileRouteEndpoint endpoint = {
        .target_id = INVALID_CLIENT_ID,
        .outbound_transfer_id = 0
    };
    FileRouteFinishResult finish_result = file_routes_finish(
        sender_id,
        source_transfer_id,
        false,
        &endpoint
    );

    switch (finish_result) {
    case FILE_ROUTE_FINISH_MISSING:
        notify_sender_for_transfer(
            sender_id,
            source_transfer_id,
            "File transfer rejected: error has no matching begin frame\n"
        );
        errno = EPROTO;
        return -1;
    case FILE_ROUTE_FINISH_DISCARD:
        return 0;
    case FILE_ROUTE_FINISH_INCOMPLETE:
    case FILE_ROUTE_FINISH_READY:
        return send_receiver_error(endpoint);
    }

    errno = EPROTO;
    return -1;
}

static bool get_username_length(const char *username, size_t *length) {
    if (username == NULL || length == NULL) {
        return false;
    }

    size_t current_length = 0;
    while (current_length < USERNAME_SIZE &&
           username[current_length] != '\0') {
        current_length++;
    }

    if (current_length == 0 || current_length >= USERNAME_SIZE) {
        return false;
    }

    *length = current_length;
    return true;
}

static int send_receiver_error(FileRouteEndpoint endpoint) {
    if (endpoint.target_id == INVALID_CLIENT_ID) {
        errno = EINVAL;
        return -1;
    }

    unsigned char payload[FILE_CONTROL_PAYLOAD_SIZE];
    size_t payload_length;
    if (file_protocol_encode_control(
            payload,
            sizeof(payload),
            &payload_length,
            endpoint.outbound_transfer_id
        ) == -1) {
        return -1;
    }

    return send_frame_to_client_id(
        endpoint.target_id,
        FRAME_FILE_ERROR,
        payload,
        payload_length
    );
}

static void notify_sender(ClientId sender_id, const char *message) {
    if (sender_id != INVALID_CLIENT_ID && message != NULL) {
        (void)send_text_to_client_id(sender_id, message);
    }
}

static void notify_sender_for_transfer(
    ClientId sender_id,
    uint32_t source_transfer_id,
    const char *message
) {
    char formatted[BUFFER_SIZE];
    int written = snprintf(
        formatted,
        sizeof(formatted),
        "Transfer id %" PRIu32 ": %s",
        source_transfer_id,
        message
    );

    if (written > 0 && (size_t)written < sizeof(formatted)) {
        notify_sender(sender_id, formatted);
    } else {
        notify_sender(sender_id, message);
    }
}

static int reject_known_transfer(
    ClientId sender_id,
    uint32_t source_transfer_id,
    const char *message,
    bool keep_discard
) {
    FileRouteEndpoint previous = {
        .target_id = INVALID_CLIENT_ID,
        .outbound_transfer_id = 0
    };
    if (file_routes_quarantine(
            sender_id,
            source_transfer_id,
            keep_discard,
            &previous
        )) {
        (void)send_receiver_error(previous);
    }

    notify_sender_for_transfer(sender_id, source_transfer_id, message);
    errno = EPROTO;
    return -1;
}
