#!/usr/bin/env python3
"""Exercise queued TLS delivery, partial input, concurrency and backpressure."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import socket
import struct
import tempfile
import threading
import time
import unittest

from integration_test import (
    FRAME_FILE_BEGIN, FRAME_FILE_END, FRAME_FILE_ERROR, FRAME_TEXT,
    HOST, PORT, encode_frame, make_begin, parse_begin, receive_frame,
    receive_legacy_message, send_frame, send_legacy_message,
)
from tls_failure_test import client_context, create_certificate, running_server


class ServerWorkerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="cipherchat-worker-")
        cls.addClassCleanup(temporary.cleanup)
        cls.directory = Path(temporary.name)
        cls.context = client_context(create_certificate(cls.directory, HOST))

    def setUp(self) -> None:
        self.enterContext(running_server(self.directory))

    def connect(self, username, receive_buffer=None):
        raw = socket.socket()
        self.addCleanup(raw.close)
        raw.settimeout(3)
        if receive_buffer is not None:
            raw.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, receive_buffer)
        raw.connect((HOST, PORT))
        sock = self.context.wrap_socket(raw, server_hostname=HOST)
        self.addCleanup(sock.close)
        send_legacy_message(sock, username.encode())
        self.assertTrue(receive_legacy_message(sock).startswith(b"Welcome"))
        # The welcome precedes activation; this round trip confirms readiness.
        send_frame(sock, FRAME_TEXT, b"/list")
        self.assertIn(username.encode(), receive_frame(sock)[1])
        return sock

    def test_delivery_while_idle_or_receiving_partial_frame(self):
        alice = self.connect("alice")
        bob = self.connect("bob")
        command = encode_frame(FRAME_TEXT, b"/help")
        # No input, partial length, and partial body must all allow output.
        for split in (0, 2, 7):
            with self.subTest(split=split):
                if split:
                    bob.sendall(command[:split])
                send_frame(alice, FRAME_TEXT, b"/msg bob wake up")
                self.assertEqual(receive_frame(bob), (
                    FRAME_TEXT, b"Private message from alice: wake up\n"
                ))
                bob.sendall(command[split:])
                self.assertIn(b"Available commands:", receive_frame(bob)[1])

        send_frame(alice, FRAME_TEXT, b"/broadcast queued broadcast")
        self.assertEqual(receive_frame(bob), (
            FRAME_TEXT, b"Broadcast from alice: queued broadcast\n"
        ))

    def test_concurrent_senders_while_recipient_sends_commands(self):
        recipient = self.connect("recipient")
        senders = [self.connect(f"sender{i}") for i in range(3)]
        barrier = threading.Barrier(4, timeout=5)

        def send_messages(index):
            # Each Python SSL socket also has exactly one owning thread.
            for number in range(40):
                barrier.wait()
                send_frame(senders[index], FRAME_TEXT,
                           f"/msg recipient {index}:{number}".encode())
                barrier.wait()

        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(send_messages, i) for i in range(3)]
            try:
                for number in range(40):
                    barrier.wait()
                    send_frame(recipient, FRAME_TEXT, b"/list")
                    messages = []
                    for _ in range(4):
                        frame_type, payload = receive_frame(recipient)
                        self.assertEqual(frame_type, FRAME_TEXT)
                        messages.append(payload)
                    expected = {
                        f"Private message from sender{i}: {i}:{number}\n".encode()
                        for i in range(3)
                    }
                    self.assertEqual(
                        {p for p in messages if p.startswith(b"Private")}, expected
                    )
                    self.assertEqual(sum(p.startswith(b"Connected clients:")
                                         for p in messages), 1)
                    barrier.wait()
                for future in futures:
                    future.result(timeout=5)
            finally:
                barrier.abort()

    def test_slow_recipient_does_not_block_other_clients(self):
        self.connect("slowworker", receive_buffer=4096)
        sender = self.connect("sender")
        healthy = self.connect("healthy")
        message = encode_frame(FRAME_TEXT, b"/msg slowworker " + b"x" * 900)
        deadline = time.monotonic() + 15
        for _ in range(128):
            # Batches smaller than the queue cap avoid overflowing merely
            # because a healthy worker has not been scheduled for one burst.
            sender.sendall(message * 64 + encode_frame(FRAME_TEXT, b"/list"))
            while True:
                kind, users = receive_frame(sender)
                self.assertEqual(kind, FRAME_TEXT)
                if users.startswith(b"Connected clients:"):
                    break
                self.assertIn(b"slowworker", users)
            send_frame(healthy, FRAME_TEXT, b"/help")
            self.assertIn(b"Available commands:", receive_frame(healthy)[1])
            if b"slowworker" not in users.splitlines():
                break
            self.assertLess(time.monotonic(), deadline,
                            "slow recipient was not disconnected")
        else:
            self.fail("outgoing queue never rejected the slow recipient")

        send_frame(sender, FRAME_TEXT, b"/msg healthy still responsive")
        self.assertEqual(receive_frame(healthy), (
            FRAME_TEXT, b"Private message from sender: still responsive\n"
        ))

    def test_disconnect_discards_queued_frames_before_slot_reuse(self):
        sender = self.connect("sender")
        for cycle in range(10):
            recipient = self.connect("reused")
            sender.sendall(encode_frame(FRAME_TEXT, b"/msg reused old") * 32)
            recipient.close()
            deadline = time.monotonic() + 3
            while True:
                send_frame(sender, FRAME_TEXT, b"/list")
                while True:
                    _, users = receive_frame(sender)
                    if users.startswith(b"Connected clients:"):
                        break
                if b"reused" not in users.splitlines():
                    break
                self.assertLess(time.monotonic(), deadline)
                time.sleep(0.01)
            replacement = self.connect("reused")
            tag = f"fresh-{cycle}".encode()
            send_frame(sender, FRAME_TEXT, b"/msg reused " + tag)
            self.assertEqual(receive_frame(replacement), (
                FRAME_TEXT, b"Private message from sender: " + tag + b"\n"
            ))
            # Wait for removal before the next cycle reuses the same name.
            send_frame(replacement, FRAME_TEXT, b"/quit")
            self.assertEqual(replacement.recv(1), b"")
            replacement.close()

    def test_invalid_frame_headers_and_types_disconnect_only_sender(self):
        healthy = self.connect("healthy")
        for i, invalid in enumerate((struct.pack("!I", 0),
                                     struct.pack("!I", 1025),
                                     encode_frame(255))):
            bad = self.connect(f"bad{i}")
            bad.sendall(invalid)
            self.assertEqual(bad.recv(1), b"")
            send_frame(healthy, FRAME_TEXT, b"/list")
            self.assertIn(b"healthy", receive_frame(healthy)[1])

    def test_disconnect_aborts_active_file_transfers(self):
        sender = self.connect("sender")
        recipient = self.connect("recipient")
        send_frame(sender, FRAME_FILE_BEGIN,
                   make_begin(1, 100, "recipient", "unfinished.bin"))
        self.assertEqual(receive_frame(recipient)[0], FRAME_FILE_BEGIN)
        recipient.close()
        self.assertIn(b"recipient disconnected", receive_frame(sender)[1])
        send_frame(sender, FRAME_FILE_END, struct.pack("!I", 1))
        send_frame(sender, FRAME_TEXT, b"/list")
        self.assertIn(b"Connected clients:", receive_frame(sender)[1])

        recipient = self.connect("recipient")
        send_frame(sender, FRAME_FILE_BEGIN,
                   make_begin(2, 100, "recipient", "unfinished.bin"))
        kind, payload = receive_frame(recipient)
        self.assertEqual(kind, FRAME_FILE_BEGIN)
        route_id, _, _, _ = parse_begin(payload)
        sender.close()
        self.assertEqual(receive_frame(recipient), (
            FRAME_FILE_ERROR, struct.pack("!I", route_id)
        ))


if __name__ == "__main__":
    unittest.main(verbosity=2)
