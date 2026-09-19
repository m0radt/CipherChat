#ifndef SERVER_WORKER_H
#define SERVER_WORKER_H

#include "client_manager.h"

typedef bool (*ServerFrameHandler)(
    ClientId client_id,
    const char *username,
    const unsigned char *frame,
    size_t length
);

/* Called only by the connection's owner, after login. Returns 0 on quit/EOF,
 * or -1 on error. The caller retains responsibility for removing the client. */
int run_client_worker(
    Connection *connection,
    ClientId client_id,
    const char *username,
    ServerFrameHandler handle_frame
);

#endif
