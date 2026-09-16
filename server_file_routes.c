#include "server_file_routes.h"

#include <pthread.h>
#include <string.h>

typedef struct {
    bool active;
    bool discard;
    ClientId sender_id;
    ClientId target_id;
    uint32_t source_transfer_id;
    uint32_t outbound_transfer_id;
    uint64_t expected_size;
    uint64_t forwarded_size;
} FileRoute;

static FileRoute routes[FILE_ROUTE_CAPACITY];
static pthread_mutex_t routes_mutex = PTHREAD_MUTEX_INITIALIZER;
static uint32_t next_outbound_transfer_id = 1U;

static void clear_endpoint(FileRouteEndpoint *endpoint);
static void copy_endpoint(
    FileRouteEndpoint *endpoint,
    const FileRoute *route
);
static FileRoute *find_route_locked(
    ClientId sender_id,
    uint32_t source_transfer_id
);
static FileRoute *find_free_route_locked(void);
static uint32_t allocate_outbound_id_locked(void);
static void make_discard_route_locked(
    FileRoute *route,
    ClientId sender_id,
    uint32_t source_transfer_id
);


void file_routes_init(void){
    pthread_mutex_lock(&routes_mutex);
    memset(routes, 0, sizeof(routes));
    next_outbound_transfer_id = 1U;
    pthread_mutex_unlock(&routes_mutex);
}


FileRouteAddResult file_routes_add(
    ClientId sender_id,
    uint32_t source_transfer_id,
    ClientId target_id,
    uint64_t expected_size,
    bool discard,
    FileRouteEndpoint *endpoint,
    FileRouteEndpoint *replaced
){
    clear_endpoint(endpoint);
    clear_endpoint(replaced);

    pthread_mutex_lock(&routes_mutex);

    FileRoute *route = find_route_locked(sender_id, source_transfer_id);

    if (route != NULL) {
        if (!route->discard) {
            copy_endpoint(replaced, route);
        }

        make_discard_route_locked(route, sender_id, source_transfer_id);
        pthread_mutex_unlock(&routes_mutex);
        return FILE_ROUTE_ADD_DUPLICATE;
    }

    route = find_free_route_locked();

    if (route == NULL) {
        pthread_mutex_unlock(&routes_mutex);
        return FILE_ROUTE_ADD_FULL;
    }

    if (discard) {
        make_discard_route_locked(route, sender_id, source_transfer_id);
        pthread_mutex_unlock(&routes_mutex);
        return FILE_ROUTE_ADD_DISCARD;
    }

    uint32_t outbound_transfer_id = allocate_outbound_id_locked();

    if (outbound_transfer_id == 0U) {
        pthread_mutex_unlock(&routes_mutex);
        return FILE_ROUTE_ADD_ID_UNAVAILABLE;
    }

    memset(route, 0, sizeof(*route));
    route->active = true;
    route->sender_id = sender_id;
    route->target_id = target_id;
    route->source_transfer_id = source_transfer_id;
    route->outbound_transfer_id = outbound_transfer_id;
    route->expected_size = expected_size;

    copy_endpoint(endpoint, route);
    pthread_mutex_unlock(&routes_mutex);
    return FILE_ROUTE_ADD_READY;
}


bool file_routes_quarantine(
    ClientId sender_id,
    uint32_t source_transfer_id,
    bool keep_discard,
    FileRouteEndpoint *previous
){
    bool was_forwarding = false;
    clear_endpoint(previous);

    pthread_mutex_lock(&routes_mutex);

    FileRoute *route = find_route_locked(sender_id, source_transfer_id);

    if (route != NULL) {
        if (!route->discard) {
            copy_endpoint(previous, route);
            was_forwarding = true;
        }

        if (keep_discard) {
            make_discard_route_locked(
                route,
                sender_id,
                source_transfer_id
            );
        }
        else {
            memset(route, 0, sizeof(*route));
        }
    }
    else if (keep_discard) {
        route = find_free_route_locked();

        if (route != NULL) {
            make_discard_route_locked(
                route,
                sender_id,
                source_transfer_id
            );
        }
    }

    pthread_mutex_unlock(&routes_mutex);
    return was_forwarding;
}


FileRouteChunkResult file_routes_accept_chunk(
    ClientId sender_id,
    uint32_t source_transfer_id,
    size_t chunk_length,
    FileRouteEndpoint *endpoint
){
    clear_endpoint(endpoint);
    pthread_mutex_lock(&routes_mutex);

    FileRoute *route = find_route_locked(sender_id, source_transfer_id);

    if (route == NULL) {
        route = find_free_route_locked();

        if (route != NULL) {
            make_discard_route_locked(
                route,
                sender_id,
                source_transfer_id
            );
        }

        pthread_mutex_unlock(&routes_mutex);
        return FILE_ROUTE_CHUNK_MISSING;
    }

    if (route->discard) {
        pthread_mutex_unlock(&routes_mutex);
        return FILE_ROUTE_CHUNK_DISCARD;
    }

    if (route->forwarded_size > route->expected_size ||
        (uint64_t)chunk_length >
            route->expected_size - route->forwarded_size) {
        copy_endpoint(endpoint, route);
        make_discard_route_locked(route, sender_id, source_transfer_id);
        pthread_mutex_unlock(&routes_mutex);
        return FILE_ROUTE_CHUNK_OVERRUN;
    }

    route->forwarded_size += (uint64_t)chunk_length;
    copy_endpoint(endpoint, route);

    pthread_mutex_unlock(&routes_mutex);
    return FILE_ROUTE_CHUNK_READY;
}


bool file_routes_mark_forward_failed(
    ClientId sender_id,
    uint32_t source_transfer_id,
    uint32_t outbound_transfer_id
){
    bool converted = false;
    pthread_mutex_lock(&routes_mutex);

    FileRoute *route = find_route_locked(sender_id, source_transfer_id);

    if (route != NULL &&
        !route->discard &&
        route->outbound_transfer_id == outbound_transfer_id) {
        make_discard_route_locked(route, sender_id, source_transfer_id);
        converted = true;
    }

    pthread_mutex_unlock(&routes_mutex);
    return converted;
}


FileRouteFinishResult file_routes_finish(
    ClientId sender_id,
    uint32_t source_transfer_id,
    bool validate_size,
    FileRouteEndpoint *endpoint
){
    clear_endpoint(endpoint);
    pthread_mutex_lock(&routes_mutex);

    FileRoute *route = find_route_locked(sender_id, source_transfer_id);

    if (route == NULL) {
        pthread_mutex_unlock(&routes_mutex);
        return FILE_ROUTE_FINISH_MISSING;
    }

    if (route->discard) {
        memset(route, 0, sizeof(*route));
        pthread_mutex_unlock(&routes_mutex);
        return FILE_ROUTE_FINISH_DISCARD;
    }

    copy_endpoint(endpoint, route);
    bool incomplete = validate_size &&
                      route->forwarded_size != route->expected_size;
    memset(route, 0, sizeof(*route));

    pthread_mutex_unlock(&routes_mutex);

    if (incomplete) {
        return FILE_ROUTE_FINISH_INCOMPLETE;
    }

    return FILE_ROUTE_FINISH_READY;
}


size_t file_routes_abort_client(
    ClientId client_id,
    FileRouteAbortAction *actions,
    size_t action_capacity
){
    if (client_id == INVALID_CLIENT_ID) {
        return 0U;
    }

    if (actions == NULL) {
        action_capacity = 0U;
    }

    size_t action_count = 0U;
    pthread_mutex_lock(&routes_mutex);

    for (size_t index = 0U; index < FILE_ROUTE_CAPACITY; index++) {
        FileRoute *route = &routes[index];

        if (!route->active ||
            (route->sender_id != client_id &&
             route->target_id != client_id)) {
            continue;
        }

        if (!route->discard &&
            route->sender_id == client_id &&
            route->target_id != INVALID_CLIENT_ID &&
            route->target_id != client_id) {
            if (action_count < action_capacity) {
                actions[action_count].type =
                    FILE_ROUTE_ABORT_SEND_ERROR;
                actions[action_count].client_id = route->target_id;
                actions[action_count].outbound_transfer_id =
                    route->outbound_transfer_id;
                action_count++;
            }
        }
        else if (!route->discard &&
                 route->target_id == client_id &&
                 route->sender_id != INVALID_CLIENT_ID &&
                 route->sender_id != client_id) {
            if (action_count < action_capacity) {
                actions[action_count].type =
                    FILE_ROUTE_ABORT_NOTIFY_SENDER;
                actions[action_count].client_id = route->sender_id;
                actions[action_count].outbound_transfer_id = 0U;
                action_count++;
            }

            make_discard_route_locked(
                route,
                route->sender_id,
                route->source_transfer_id
            );
            continue;
        }

        memset(route, 0, sizeof(*route));
    }

    pthread_mutex_unlock(&routes_mutex);
    return action_count;
}


static void clear_endpoint(FileRouteEndpoint *endpoint){
    if (endpoint != NULL) {
        endpoint->target_id = INVALID_CLIENT_ID;
        endpoint->outbound_transfer_id = 0U;
    }
}


static void copy_endpoint(
    FileRouteEndpoint *endpoint,
    const FileRoute *route
){
    if (endpoint != NULL) {
        endpoint->target_id = route->target_id;
        endpoint->outbound_transfer_id = route->outbound_transfer_id;
    }
}


static FileRoute *find_route_locked(
    ClientId sender_id,
    uint32_t source_transfer_id
){
    for (size_t index = 0U; index < FILE_ROUTE_CAPACITY; index++) {
        if (routes[index].active &&
            routes[index].sender_id == sender_id &&
            routes[index].source_transfer_id == source_transfer_id) {
            return &routes[index];
        }
    }

    return NULL;
}


static FileRoute *find_free_route_locked(void){
    for (size_t index = 0U; index < FILE_ROUTE_CAPACITY; index++) {
        if (!routes[index].active) {
            return &routes[index];
        }
    }

    return NULL;
}


static uint32_t allocate_outbound_id_locked(void){
    for (size_t attempt = 0U;
         attempt <= FILE_ROUTE_CAPACITY;
         attempt++) {
        uint32_t candidate = next_outbound_transfer_id++;

        if (candidate == 0U) {
            candidate = next_outbound_transfer_id++;
        }

        bool in_use = false;

        for (size_t index = 0U; index < FILE_ROUTE_CAPACITY; index++) {
            if (routes[index].active &&
                !routes[index].discard &&
                routes[index].outbound_transfer_id == candidate) {
                in_use = true;
                break;
            }
        }

        if (!in_use) {
            return candidate;
        }
    }

    return 0U;
}


static void make_discard_route_locked(
    FileRoute *route,
    ClientId sender_id,
    uint32_t source_transfer_id
){
    memset(route, 0, sizeof(*route));
    route->active = true;
    route->discard = true;
    route->sender_id = sender_id;
    route->target_id = INVALID_CLIENT_ID;
    route->source_transfer_id = source_transfer_id;
}
