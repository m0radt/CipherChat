#ifndef SERVER_FILES_H
#define SERVER_FILES_H

#include <stddef.h>

#include "client_manager.h"

/* Initialize the routing table before the server starts accepting clients. */
void init_file_routes(void);

/*
 * Route one decoded file frame.  full_frame includes the one-byte FrameType.
 * Returns 0 when the frame was consumed (including a rejected transfer that is
 * being drained), and -1 for a malformed frame or a forwarding failure.
 */
int route_file_frame(
    ClientId sender_id,
    const char *sender_username,
    const unsigned char *full_frame,
    size_t frame_len
);

/* Cancel every transfer whose sender or recipient is client_id. */
void abort_file_routes_for_client(ClientId client_id);

#endif
