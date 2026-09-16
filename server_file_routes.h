#ifndef SERVER_FILE_ROUTES_H
#define SERVER_FILE_ROUTES_H

#include "client_manager.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define FILE_ROUTE_CAPACITY (MAX_CLIENTS * 4)

typedef struct {
    ClientId target_id;
    uint32_t outbound_transfer_id;
} FileRouteEndpoint;

typedef enum {
    FILE_ROUTE_ADD_READY,
    FILE_ROUTE_ADD_DISCARD,
    FILE_ROUTE_ADD_DUPLICATE,
    FILE_ROUTE_ADD_FULL,
    FILE_ROUTE_ADD_ID_UNAVAILABLE
} FileRouteAddResult;

typedef enum {
    FILE_ROUTE_CHUNK_READY,
    FILE_ROUTE_CHUNK_DISCARD,
    FILE_ROUTE_CHUNK_MISSING,
    FILE_ROUTE_CHUNK_OVERRUN
} FileRouteChunkResult;

typedef enum {
    FILE_ROUTE_FINISH_READY,
    FILE_ROUTE_FINISH_DISCARD,
    FILE_ROUTE_FINISH_MISSING,
    FILE_ROUTE_FINISH_INCOMPLETE
} FileRouteFinishResult;

typedef enum {
    FILE_ROUTE_ABORT_SEND_ERROR,
    FILE_ROUTE_ABORT_NOTIFY_SENDER
} FileRouteAbortActionType;

typedef struct {
    FileRouteAbortActionType type;
    ClientId client_id;
    uint32_t outbound_transfer_id;
} FileRouteAbortAction;

/* Reset every route and restart outbound transfer-id allocation. */
void file_routes_init(void);

/*
 * Add a route keyed by (sender_id, source_transfer_id).
 *
 * A duplicate key is atomically replaced by a discard tombstone.  When the
 * old entry was forwarding, replaced receives its endpoint.  A requested
 * discard entry also becomes a tombstone, but is reported as DISCARD rather
 * than DUPLICATE.  On READY, endpoint receives the newly allocated endpoint.
 * Unused output endpoints are reset to INVALID_CLIENT_ID/0.
 */
FileRouteAddResult file_routes_add(
    ClientId sender_id,
    uint32_t source_transfer_id,
    ClientId target_id,
    uint64_t expected_size,
    bool discard,
    FileRouteEndpoint *endpoint,
    FileRouteEndpoint *replaced
);

/*
 * Replace or remove a route.  Returns true only when the old entry was a
 * forwarding route, in which case previous receives its endpoint.  If no
 * entry exists and keep_discard is true, a tombstone is added when possible.
 */
bool file_routes_quarantine(
    ClientId sender_id,
    uint32_t source_transfer_id,
    bool keep_discard,
    FileRouteEndpoint *previous
);

/* Atomically account for a chunk and return the endpoint to forward it to. */
FileRouteChunkResult file_routes_accept_chunk(
    ClientId sender_id,
    uint32_t source_transfer_id,
    size_t chunk_length,
    FileRouteEndpoint *endpoint
);

/* Convert the matching live route to a tombstone after a forwarding error. */
bool file_routes_mark_forward_failed(
    ClientId sender_id,
    uint32_t source_transfer_id,
    uint32_t outbound_transfer_id
);

/*
 * Remove a route for FILE_END (validate_size=true) or FILE_ERROR
 * (validate_size=false).  Live-route endpoints are returned for READY and
 * INCOMPLETE results.
 */
FileRouteFinishResult file_routes_finish(
    ClientId sender_id,
    uint32_t source_transfer_id,
    bool validate_size,
    FileRouteEndpoint *endpoint
);

/*
 * Abort routes involving client_id and fill at most action_capacity actions.
 * The return value is the number of actions written.
 */
size_t file_routes_abort_client(
    ClientId client_id,
    FileRouteAbortAction *actions,
    size_t action_capacity
);

#endif
