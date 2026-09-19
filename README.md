# CipherChat

A small C17 chat server and terminal client using **TLS 1.3 over TCP**. It supports
private messages, broadcasts, connected-user listings, and private binary file
transfers. Clients verify the server's certificate and IP address; older TLS
versions are rejected.

## Build

Linux, a C17 compiler, Make, POSIX threads, and the development libraries for
GNU Readline and OpenSSL 3 are required. Install the OpenSSL command-line tool
for certificate setup as well.

```sh
make
```

## TLS certificate setup

Before starting the programs, the server needs a certificate and its matching
private key. For a fresh local setup, run this from the project directory to
create a self-signed certificate valid for 365 days:

```sh
mkdir -p certs
(
    umask 077
    openssl req -x509 -newkey rsa:3072 -sha256 -noenc -days 365 \
        -subj "/CN=CipherChat" \
        -addext "subjectAltName=IP:127.0.0.1" \
        -addext "basicConstraints=critical,CA:FALSE" \
        -addext "extendedKeyUsage=serverAuth" \
        -keyout certs/server.key \
        -out certs/server.crt
)
```

This creates:

- `certs/server.crt`: the public server certificate, also used by clients to
  establish trust in this self-signed server.
- `certs/server.key`: the unencrypted private key. Keep it on the server and
  readable only by the server's user; do not distribute it to clients.

The command creates a new key and certificate each time. If you already have a
matching self-signed certificate and key in PEM format, install them at those
paths instead. The certificate's Subject Alternative Name (SAN) must contain
the server's IP address. The OpenSSL command options are documented in
[openssl req](https://docs.openssl.org/3.0/man1/openssl-req/).

When server and client run from the same project directory, both use the
certificate above. For a client in another directory or on another machine,
obtain the server's public certificate through a trusted channel and install it
in that client's working directory:

```sh
mkdir -p certs
cp /path/to/trusted/server.crt certs/server.crt
```

The client needs only the certificate. If you replace the server's self-signed
certificate, update each client's trusted copy too. The `certs/` directory is
ignored by Git.

To connect to a different IPv4 address, change `SERVER_IP` in `common.h`, rebuild,
and create a certificate whose `subjectAltName=IP:...` matches that address.
The default certificate above covers `127.0.0.1`.

## Run

Run the programs from their project directories: certificate paths are relative
to the current working directory.

Start the server in one terminal:

```sh
./server
```

Then start one or more clients in other terminals:

```sh
./client
```

The client connects to `127.0.0.1:8080` by default.
TLS handshakes have a 10-second total deadline. Normal disconnects exchange TLS
`close_notify` alerts, allowing up to 2 seconds before closing the socket.

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

After the TLS 1.3 handshake, login uses a length-prefixed username followed by a
length-prefixed welcome or error message. All login, chat, and file data travels
inside the TLS connection. After login, every packet has one binary-safe envelope:

```text
[4-byte network-order frame length][1-byte frame type][frame payload]
```

The server tracks each upload by sender connection and transfer ID, assigns a
globally unique ID for the receiving client, validates sizes and names, and
serializes complete frames so concurrent senders cannot corrupt one another's
stream.

## Source layout

- `common.c` implements the generic length-prefixed transport.
- `network.c` handles certificate loading, TLS 1.3 handshakes, verification,
  handshake deadlines, and TLS shutdown.
- `server_worker.c` runs each client's nonblocking TLS read/write loop.
- `client_manager.c` manages clients and bounded outgoing queues, waking workers
  with Linux `eventfd` notifications.
- `file_protocol.c` is the single encoder, decoder, and validator for file
  frame payloads shared by the client and server.
- `client_file_sender.c` reads local files and produces file frames.
- `client_file_receiver.c` owns incoming-transfer and filesystem state.
- `server_files.c` handles file-frame routing decisions and notifications.
- `server_file_routes.c` owns the synchronized server transfer table and ID
  remapping.

## Test

Python 3.11 or newer and the OpenSSL command-line tool are required. Create the
local certificate above first, and stop any server using port `8080` before
running the tests:

```sh
make test
```

The integration test exercises typed text routing, multi-chunk binary and empty
files, colliding sender transfer IDs, missing recipients, invalid size handling,
unsafe names, no-overwrite behavior, fragmented/coalesced input over TLS, and a
real two-client transfer written to disk.

Additional suites cover certificate and IP rejection, TLS 1.2 rejection,
concurrent senders, slow recipients, connection cleanup, handshake deadlines
with silent and trickling peers, and bounded TLS shutdown. TLS failure and
lifecycle tests generate their own certificates in temporary directories.
