#!/usr/bin/env python3
"""End-to-end checks for typed chat frames and binary files over TLS 1.3."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]
SERVER = Path(os.environ.get("TCP_CHAT_SERVER", ROOT / "server"))
CLIENT = Path(os.environ.get("TCP_CHAT_CLIENT", ROOT / "client"))
HOST = "127.0.0.1"
PORT = 8080

FRAME_FILE_BEGIN = 0
FRAME_FILE_CHUNK = 1
FRAME_FILE_END = 2
FRAME_FILE_ERROR = 3
FRAME_TEXT = 4
FILE_CHUNK_SIZE = 900


def receive_exact(sock: socket.socket, length: int) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise AssertionError("connection closed in the middle of a frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def send_legacy_message(sock: socket.socket, payload: bytes) -> None:
    sock.sendall(struct.pack("!I", len(payload)) + payload)


def receive_legacy_message(sock: socket.socket) -> bytes:
    (length,) = struct.unpack("!I", receive_exact(sock, 4))
    return receive_exact(sock, length)


def encode_frame(frame_type: int, payload: bytes = b"") -> bytes:
    frame = bytes([frame_type]) + payload
    return struct.pack("!I", len(frame)) + frame


def send_frame(sock: socket.socket, frame_type: int, payload: bytes = b"") -> None:
    sock.sendall(encode_frame(frame_type, payload))


def receive_frame(sock: socket.socket) -> tuple[int, bytes]:
    (length,) = struct.unpack("!I", receive_exact(sock, 4))
    assert 1 <= length <= 1024, f"invalid frame length {length}"
    frame = receive_exact(sock, length)
    return frame[0], frame[1:]


def make_begin(
    transfer_id: int,
    file_size: int,
    peer: str,
    filename: str,
) -> bytes:
    peer_bytes = peer.encode()
    filename_bytes = filename.encode()
    return (
        struct.pack(
            "!IQHH",
            transfer_id,
            file_size,
            len(peer_bytes),
            len(filename_bytes),
        )
        + peer_bytes
        + filename_bytes
    )


def parse_begin(payload: bytes) -> tuple[int, int, str, str]:
    assert len(payload) >= 16
    transfer_id, size, peer_length, filename_length = struct.unpack(
        "!IQHH", payload[:16]
    )
    assert len(payload) == 16 + peer_length + filename_length
    peer_start = 16
    filename_start = peer_start + peer_length
    return (
        transfer_id,
        size,
        payload[peer_start:filename_start].decode(),
        payload[filename_start:].decode(),
    )


def connect_client(username: str, deadline: float | None = None) -> ssl.SSLSocket:
    context = ssl.create_default_context(
        cafile=str(ROOT / "certs" / "server.crt")
    )
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3

    if deadline is None:
        deadline = time.monotonic() + 3

    while True:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        try:
            sock.connect((HOST, PORT))
            break
        except ConnectionRefusedError:
            sock.close()
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.03)

    try:
        sock = context.wrap_socket(sock, server_hostname=HOST)
        assert sock.version() == "TLSv1.3", sock.version()
        send_legacy_message(sock, username.encode())
        welcome = receive_legacy_message(sock)
        assert welcome.startswith(b"Welcome to CipherChat"), welcome
        return sock
    except Exception:
        sock.close()
        raise


def receive_text_containing(sock: socket.socket, needle: bytes) -> bytes:
    for _ in range(8):
        frame_type, payload = receive_frame(sock)
        if frame_type == FRAME_TEXT and needle in payload:
            return payload
    raise AssertionError(f"did not receive text containing {needle!r}")


def run_protocol_checks() -> None:
    alice = connect_client("alice")
    bob = connect_client("bob")
    charlie = connect_client("charlie")

    try:
        send_frame(alice, FRAME_TEXT, b"/msg bob hello over typed frames")
        frame_type, payload = receive_frame(bob)
        assert frame_type == FRAME_TEXT
        assert payload == b"Private message from alice: hello over typed frames\n"

        fragmented = encode_frame(FRAME_TEXT, b"/list")
        for byte in fragmented:
            alice.sendall(bytes([byte]))
        receive_text_containing(alice, b"Connected clients:")

        alice.sendall(
            encode_frame(FRAME_TEXT, b"/help")
            + encode_frame(FRAME_TEXT, b"/list")
        )
        receive_text_containing(alice, b"Available commands:")
        receive_text_containing(alice, b"Connected clients:")

        content = bytes(range(256)) * 9 + b"\x00binary-tail\xff"
        source_id = 77
        send_frame(
            alice,
            FRAME_FILE_BEGIN,
            make_begin(source_id, len(content), "bob", "payload.bin"),
        )

        frame_type, payload = receive_frame(bob)
        assert frame_type == FRAME_FILE_BEGIN
        outbound_id, size, sender, filename = parse_begin(payload)
        assert size == len(content)
        assert sender == "alice"
        assert filename == "payload.bin"

        for offset in range(0, len(content), FILE_CHUNK_SIZE):
            chunk = content[offset : offset + FILE_CHUNK_SIZE]
            send_frame(
                alice,
                FRAME_FILE_CHUNK,
                struct.pack("!I", source_id) + chunk,
            )
            chunk_type, chunk_payload = receive_frame(bob)
            assert chunk_type == FRAME_FILE_CHUNK
            assert struct.unpack("!I", chunk_payload[:4])[0] == outbound_id
            assert chunk_payload[4:] == chunk

        send_frame(alice, FRAME_FILE_END, struct.pack("!I", source_id))
        frame_type, payload = receive_frame(bob)
        assert frame_type == FRAME_FILE_END
        assert payload == struct.pack("!I", outbound_id)

        send_frame(
            alice,
            FRAME_FILE_BEGIN,
            make_begin(78, 0, "bob", "empty.bin"),
        )
        frame_type, payload = receive_frame(bob)
        assert frame_type == FRAME_FILE_BEGIN
        empty_outbound_id, size, sender, filename = parse_begin(payload)
        assert (size, sender, filename) == (0, "alice", "empty.bin")
        send_frame(alice, FRAME_FILE_END, struct.pack("!I", 78))
        assert receive_frame(bob) == (
            FRAME_FILE_END,
            struct.pack("!I", empty_outbound_id),
        )

        # Identical source IDs from two clients must be remapped independently.
        collision_id = 5
        send_frame(
            alice,
            FRAME_FILE_BEGIN,
            make_begin(collision_id, 1, "bob", "from-alice.bin"),
        )
        send_frame(
            charlie,
            FRAME_FILE_BEGIN,
            make_begin(collision_id, 1, "bob", "from-charlie.bin"),
        )

        routes: dict[str, int] = {}
        for _ in range(2):
            frame_type, payload = receive_frame(bob)
            assert frame_type == FRAME_FILE_BEGIN
            route_id, size, sender, _ = parse_begin(payload)
            assert size == 1
            routes[sender] = route_id
        assert set(routes) == {"alice", "charlie"}
        assert routes["alice"] != routes["charlie"]

        send_frame(
            alice,
            FRAME_FILE_CHUNK,
            struct.pack("!I", collision_id) + b"A",
        )
        send_frame(alice, FRAME_FILE_END, struct.pack("!I", collision_id))
        send_frame(
            charlie,
            FRAME_FILE_CHUNK,
            struct.pack("!I", collision_id) + b"C",
        )
        send_frame(charlie, FRAME_FILE_END, struct.pack("!I", collision_id))

        completed: dict[int, bytes] = {}
        partial: dict[int, bytes] = {}
        while len(completed) < 2:
            frame_type, payload = receive_frame(bob)
            route_id = struct.unpack("!I", payload[:4])[0]
            if frame_type == FRAME_FILE_CHUNK:
                partial[route_id] = partial.get(route_id, b"") + payload[4:]
            elif frame_type == FRAME_FILE_END:
                completed[route_id] = partial.get(route_id, b"")
            else:
                raise AssertionError(f"unexpected collision frame {frame_type}")
        assert completed[routes["alice"]] == b"A"
        assert completed[routes["charlie"]] == b"C"

        # A missing destination is consumed as a rejected transfer; the stream stays usable.
        send_frame(
            alice,
            FRAME_FILE_BEGIN,
            make_begin(90, 4, "nobody", "lost.bin"),
        )
        send_frame(
            alice,
            FRAME_FILE_CHUNK,
            struct.pack("!I", 90) + b"lost",
        )
        send_frame(alice, FRAME_FILE_END, struct.pack("!I", 90))
        receive_text_containing(alice, b"nobody")
        send_frame(alice, FRAME_TEXT, b"/list")
        receive_text_containing(alice, b"Connected clients:")

        # Unsafe names and self-transfers are rejected and drained cleanly.
        send_frame(
            alice,
            FRAME_FILE_BEGIN,
            make_begin(92, 0, "bob", "../escape.bin"),
        )
        receive_text_containing(alice, b"malformed begin")
        send_frame(alice, FRAME_FILE_END, struct.pack("!I", 92))

        send_frame(
            alice,
            FRAME_FILE_BEGIN,
            make_begin(93, 0, "alice", "self.bin"),
        )
        receive_text_containing(alice, b"yourself")
        send_frame(alice, FRAME_FILE_END, struct.pack("!I", 93))

        # An overrun aborts the route but does not desynchronize later text.
        send_frame(
            alice,
            FRAME_FILE_BEGIN,
            make_begin(91, 1, "bob", "overrun.bin"),
        )
        frame_type, begin_payload = receive_frame(bob)
        assert frame_type == FRAME_FILE_BEGIN
        overrun_outbound_id, _, _, _ = parse_begin(begin_payload)
        send_frame(
            alice,
            FRAME_FILE_CHUNK,
            struct.pack("!I", 91) + b"too long",
        )
        assert receive_frame(bob) == (
            FRAME_FILE_ERROR,
            struct.pack("!I", overrun_outbound_id),
        )
        receive_text_containing(alice, b"91")
        send_frame(alice, FRAME_TEXT, b"/help")
        receive_text_containing(alice, b"/file <username> <path>")
    finally:
        for sock in (alice, bob, charlie):
            sock.close()


def wait_for_file(path: Path, expected: bytes, timeout: float = 6) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists() and path.read_bytes() == expected:
            return
        time.sleep(0.05)
    raise AssertionError(f"client did not create expected file: {path}")


def run_real_client_check() -> None:
    work_directory = Path(tempfile.mkdtemp(prefix="cipher-chat-test-"))
    sender_directory = work_directory / "sender"
    receiver_directory = work_directory / "receiver"
    sender_directory.mkdir()
    receiver_directory.mkdir()

    for directory in (sender_directory, receiver_directory):
        certificate_directory = directory / "certs"
        certificate_directory.mkdir()
        shutil.copy2(
            ROOT / "certs" / "server.crt",
            certificate_directory / "server.crt",
        )

    content = os.urandom(FILE_CHUNK_SIZE * 3 + 37) + b"\x00\xffend"
    source_file = sender_directory / "client-e2e.bin"
    source_file.write_bytes(content)

    receiver = subprocess.Popen(
        [str(CLIENT)],
        cwd=receiver_directory,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    sender = subprocess.Popen(
        [str(CLIENT)],
        cwd=sender_directory,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    try:
        assert receiver.stdin is not None
        assert sender.stdin is not None
        receiver.stdin.write("receivercli\n")
        receiver.stdin.flush()
        sender.stdin.write("sendercli\n")
        sender.stdin.flush()
        time.sleep(0.2)
        sender.stdin.write(f"/file receivercli {source_file}\n")
        sender.stdin.flush()

        destination = receiver_directory / "downloads" / source_file.name
        wait_for_file(destination, content)

        # Sending the same name again must not replace the completed file.
        source_file.write_bytes(b"replacement data must not win")
        sender.stdin.write(f"/file receivercli {source_file}\n")
        sender.stdin.flush()
        time.sleep(0.3)
        assert destination.read_bytes() == content
        assert not list((receiver_directory / "downloads").glob(".cipher-chat-*"))

        sender.stdin.write("/quit\n")
        sender.stdin.flush()
        receiver.stdin.write("/quit\n")
        receiver.stdin.flush()

        sender_output, _ = sender.communicate(timeout=3)
        receiver_output, _ = receiver.communicate(timeout=3)
        assert sender.returncode == 0, sender_output
        assert receiver.returncode == 0, receiver_output
        assert "sent to receivercli" in sender_output
        assert "from sendercli" in receiver_output
    finally:
        for process in (sender, receiver):
            if process.poll() is None:
                process.kill()
                process.wait()
        shutil.rmtree(work_directory)


def main() -> None:
    server = subprocess.Popen(
        [str(SERVER)],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    try:
        run_protocol_checks()
        time.sleep(0.1)
        run_real_client_check()
    except BaseException:
        server.terminate()
        try:
            output, _ = server.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            server.kill()
            output, _ = server.communicate()
        if output:
            print("\n--- server output ---")
            print(output)
        raise
    else:
        server.terminate()
        try:
            server.wait(timeout=2)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait()

    print("integration tests passed")


if __name__ == "__main__":
    main()
