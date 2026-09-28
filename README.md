# CipherChat

A small C17 chat server and terminal client using **TLS 1.3 over TCP**. It supports
private messages, broadcasts, connected-user listings, and private binary file
transfers. Clients verify the server's certificate and IP address; older TLS
versions are rejected.
Private messages and file contents also use end-to-end authenticated encryption
with libsodium.

## Build

Linux, a C17 compiler, Make, POSIX threads, and the development libraries for
GNU Readline, OpenSSL 3, and libsodium are required. Install the OpenSSL command-line tool
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

Original files are limited to **16 MiB** because the client encrypts each whole
file in memory using libsodium's `crypto_box_easy` and a fresh random nonce.
The receiver stages encrypted bytes in a temporary file, then authenticates and
decrypts the complete transfer before saving the final download. The filename
is included in the authenticated contents, but filenames, routing information,
and encrypted transfer sizes remain visible to the server.

## Protocol

After the TLS 1.3 handshake, login uses a length-prefixed username followed by a
length-prefixed welcome or error message. All login, chat, and file data travels
inside the TLS connection. After login, every packet has one binary-safe envelope:

```text
[4-byte network-order frame length][1-byte frame type][frame payload]
```

User messages are limited to 64 KiB. Frames allow an additional 256 bytes for
command, username, and encryption metadata. The client registers a fresh
`crypto_box` public key after login. `/msg` and `/file` request the recipient's
key, then encrypt the message or file with a fresh nonce before sending it to
the server.

| Type | Value | Payload |
| --- | --- | --- |
| `FRAME_REQUEST_PK` | 5 | Recipient username bytes |
| `FRAME_PEER_PK` | 6 | 1-byte username length, username, 32-byte public key |
| `FRAME_CIPHERTEXT` | 7 | Client to server: recipient name, nonce, sender public key, ciphertext. Server to recipient: authenticated sender name, nonce, sender public key, ciphertext. |
| `FRAME_REGISTER_PK` | 8 | 32-byte public key for the current connection |

A name-only `FRAME_PEER_PK` reply indicates an unavailable recipient or key and
cancels that pending message or file transfer. Keys are removed on disconnect.
For private message frames, the server checks
the sender's registered key and forwards the ciphertext unchanged. Private
message text is limited to 64 KiB. Recipients display the
sender name authenticated by that user's logged-in TLS connection.

Key distribution trusts the server; clients do not independently verify peer
identities. Broadcasts and legacy text-frame private messages use TLS
without the additional client-to-client encryption. Restart the server and
clients together after updating the encrypted-message protocol.

File encryption uses the existing file frames to carry an opaque byte stream:

```text
[CCFILE01][sender public key][nonce][MAC + encrypted contents]
```

The encrypted contents contain a format marker, a two-byte big-endian filename
length, the filename, and the original file bytes. The receiver verifies the
authentication tag and checks that the authenticated filename matches the
announced filename. Both sending and receiving clients must support this format;
updated clients reject older plaintext file transfers.

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
- `client_file_sender.c` reads and encrypts local files, then produces file frames.
- `client_file_receiver.c` authenticates and decrypts received files and owns
  incoming-transfer and filesystem state.
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

Encrypted messaging tests cover key registration and reconnect cleanup,
recipient lookup, ciphertext forwarding and decryption, tamper rejection,
malformed replies, pending requests, message limits, and a real two-client
private-message exchange.
