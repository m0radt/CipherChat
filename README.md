# CipherChat

A small C17 TCP chat server and terminal client. It supports private messages,
broadcasts, connected-user listings, and private binary file transfers.

## Build

GNU Readline and a C compiler are required.

```sh
make
```

Start the server in one terminal:

```sh
./server
```

Then start one or more clients in other terminals:

```sh
./client
```

The client connects to `127.0.0.1:8080` by default.

## Commands

```text
/msg <username> <message>  Send a private message
/broadcast <message>       Send a message to everyone
/file <username> <path>    Send a file privately
/list                      List connected users
/help                      Display help
/quit                      Disconnect
```

For example:

```text
/file alice ./photo.png
```

Received files are saved in the client's `downloads/` directory. Existing
files are never overwritten. Incomplete transfers use temporary files that are
removed if the transfer or connection fails. Empty files and binary data are
supported. File transfers to your own username are rejected.

## Protocol

Login uses a length-prefixed username followed by a length-prefixed welcome or
error message. After login, every packet has one binary-safe envelope:

```text
[4-byte network-order frame length][1-byte frame type][frame payload]
```

The server tracks each upload by sender connection and transfer ID, assigns a
globally unique ID for the receiving client, validates sizes and names, and
serializes complete frames so concurrent senders cannot corrupt one another's
stream.

## Source layout

- `common.c` implements the generic length-prefixed transport.
- `file_protocol.c` is the single encoder, decoder, and validator for file
  frame payloads shared by the client and server.
- `client_file_sender.c` reads local files and produces file frames.
- `client_file_receiver.c` owns incoming-transfer and filesystem state.
- `server_files.c` handles file-frame routing decisions and notifications.
- `server_file_routes.c` owns the synchronized server transfer table and ID
  remapping.

## Test

```sh
make test
```

The integration test exercises typed text routing, multi-chunk binary and empty
files, colliding sender transfer IDs, missing recipients, invalid size handling,
unsafe names, no-overwrite behavior, fragmented/coalesced TCP input, and a real
two-client transfer written to disk. Python 3 is required only for this test.
