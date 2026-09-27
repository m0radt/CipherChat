#!/usr/bin/env python3
"""E2EE client wire checks over TLS and server forwarding regressions.

The TLS peer supplies recipient keys but never receives their private keys.
Crypto fixtures use the installed libsodium through ctypes; no Python crypto
package is required.
"""

from contextlib import contextmanager
import ctypes
from ctypes.util import find_library
import os
import select
import subprocess
import tempfile
import time
import unittest

from integration_test import (
    FRAME_CIPHERTEXT, FRAME_PEER_PK, FRAME_REGISTER_PK, FRAME_REQUEST_PK, FRAME_TEXT,
    MESSAGE_MAX_SIZE, receive_frame, send_frame,
)
from tls_failure_test import running_server, stop_process
from tls_lifecycle_test import TLSClientTestCase


class Sodium:
    def __init__(self):
        library = find_library("sodium")
        if library is None:
            raise RuntimeError("E2EE tests require the libsodium shared library")
        self.lib = ctypes.CDLL(library)
        self.lib.sodium_init.argtypes = []
        self.lib.sodium_init.restype = ctypes.c_int
        if self.lib.sodium_init() < 0:
            raise RuntimeError("libsodium initialization failed")
        for name in ("publickeybytes", "secretkeybytes", "noncebytes", "macbytes"):
            function = getattr(self.lib, "crypto_box_" + name)
            function.argtypes = []
            function.restype = ctypes.c_size_t
            setattr(self, name, function())
        self.lib.crypto_box_keypair.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        self.lib.crypto_box_keypair.restype = ctypes.c_int
        for name in ("crypto_box_easy", "crypto_box_open_easy"):
            function = getattr(self.lib, name)
            function.argtypes = [
                ctypes.c_void_p, ctypes.c_char_p, ctypes.c_ulonglong,
                ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
            ]
            function.restype = ctypes.c_int

    def keypair(self):
        public = ctypes.create_string_buffer(self.publickeybytes)
        private = ctypes.create_string_buffer(self.secretkeybytes)
        assert self.lib.crypto_box_keypair(public, private) == 0
        return public.raw, private.raw

    def encrypt(self, message, nonce, recipient_public, sender_private):
        output = ctypes.create_string_buffer(len(message) + self.macbytes)
        assert self.lib.crypto_box_easy(
            output, message, len(message), nonce, recipient_public, sender_private
        ) == 0
        return output.raw

    def decrypt(self, ciphertext, nonce, sender_public, recipient_private):
        assert len(ciphertext) >= self.macbytes
        length = len(ciphertext) - self.macbytes
        output = ctypes.create_string_buffer(max(1, length))
        result = self.lib.crypto_box_open_easy(
            output, ciphertext, len(ciphertext), nonce, sender_public, recipient_private
        )
        assert result == 0, "ciphertext does not authenticate with the recipient's key"
        return output.raw[:length]

    def payload(self, recipient, message, recipient_public, sender_keys):
        sender_public, sender_private = sender_keys
        nonce = os.urandom(self.noncebytes)
        return (bytes([len(recipient)]) + recipient + nonce + sender_public
                + self.encrypt(message, nonce, recipient_public, sender_private))

    def unpack(self, payload):
        assert payload, "empty ciphertext payload"
        username_length = payload[0]
        assert 1 <= username_length < 32, "invalid recipient length"
        nonce_start = 1 + username_length
        key_start = nonce_start + self.noncebytes
        ciphertext_start = key_start + self.publickeybytes
        assert len(payload) >= ciphertext_start + self.macbytes, "truncated payload"
        return (payload[1:nonce_start], payload[nonce_start:key_start],
                payload[key_start:ciphertext_start], payload[ciphertext_start:])


def wait_for_output(process, marker, timeout=3):
    """Read flushed CLI output until a server marker confirms frame processing."""
    output = b""
    deadline = time.monotonic() + timeout
    while marker not in output:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([process.stdout], [], [], remaining)[0]:
            raise AssertionError(f"client did not display {marker!r}: {output!r}")
        chunk = os.read(process.stdout.fileno(), 4096)
        if not chunk:
            raise AssertionError(f"client exited before displaying {marker!r}: {output!r}")
        output += chunk
    return output


class E2EETests(TLSClientTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.sodium = Sodium()

    @contextmanager
    def session(self, *, stdout=subprocess.PIPE):
        with self.listener() as listener:
            process = self.start_client(stdout=stdout)
            try:
                peer = self.accept_client(listener, process)
                try:
                    yield process, peer
                finally:
                    peer.close()
            finally:
                stop_process(process)
                for stream in (process.stdin, process.stdout, process.stderr):
                    if stream is not None:
                        stream.close()

    def command(self, process, command):
        process.stdin.write(command + "\n")
        process.stdin.flush()

    def finish(self, process, peer, mode="quit", *, output_file=None):
        if mode == "quit":
            self.command(process, "/quit")
            self.assertEqual(receive_frame(peer), (FRAME_TEXT, b"/quit"))
        elif mode == "stdin_eof":
            process.stdin.close()
            process.stdin = None
        with peer.unwrap() as transport:
            self.assertEqual(transport.recv(1), b"")
        output, _ = process.communicate(timeout=3)
        if output_file is not None:
            output_file.seek(0)
            output = output_file.read()
        self.assertEqual(process.returncode, 0, output)
        return output

    def key_response(self, peer, username, public_key):
        send_frame(peer, FRAME_PEER_PK,
                   bytes([len(username)]) + username + public_key)

    def receive_ciphertext(self, peer):
        kind, payload = receive_frame(peer)
        self.assertEqual(kind, FRAME_CIPHERTEXT)
        return self.sodium.unpack(payload)

    def client_public_key(self, process, peer):
        # The sender key is public metadata in the client's outgoing payload.
        peer_public, _ = self.sodium.keypair()
        self.command(process, "/msg peer establish sender key")
        self.assertEqual(receive_frame(peer), (FRAME_REQUEST_PK, b"peer"))
        self.key_response(peer, b"peer", peer_public)
        _, _, client_public, _ = self.receive_ciphertext(peer)
        return client_public

    def test_outgoing_ciphertext_decrypts_and_uses_fresh_nonces(self):
        recipient_public, recipient_private = self.sodium.keypair()
        for username in (b"b", b"bob", b"x" * 31):
            with self.subTest(username=username), self.session() as (process, peer):
                nonces = set()
                sender_keys = set()
                message = b"a private message with  repeated spaces"
                for _ in range(2):
                    self.command(process, f"/msg {username.decode()} {message.decode()}")
                    self.assertEqual(receive_frame(peer), (FRAME_REQUEST_PK, username))
                    # The next command must arrive without a plaintext /msg frame.
                    self.command(process, "/list")
                    self.assertEqual(receive_frame(peer), (FRAME_TEXT, b"/list"))
                    self.key_response(peer, username, recipient_public)
                    recipient, nonce, sender_public, ciphertext = self.receive_ciphertext(peer)
                    self.assertEqual(recipient, username)
                    self.assertNotEqual(sender_public, recipient_public)
                    self.assertEqual(sender_public, process.public_key)
                    self.assertNotIn(message, ciphertext)
                    self.assertEqual(len(ciphertext), len(message) + self.sodium.macbytes)
                    self.assertEqual(self.sodium.decrypt(
                        ciphertext, nonce, sender_public, recipient_private
                    ), message)
                    nonces.add(nonce)
                    sender_keys.add(sender_public)
                self.assertEqual(len(nonces), 2)
                self.assertEqual(len(sender_keys), 1)
                self.finish(process, peer)

    def test_key_responses_select_the_matching_pending_recipient(self):
        bob_keys = self.sodium.keypair()
        sara_keys = self.sodium.keypair()
        with self.session() as (process, peer):
            for username in (b"bob", b"sara"):
                self.command(process, f"/msg {username.decode()} secret for {username.decode()}")
                self.assertEqual(receive_frame(peer), (FRAME_REQUEST_PK, username))
            for username, keys in ((b"sara", sara_keys), (b"bob", bob_keys)):
                self.key_response(peer, username, keys[0])
                recipient, nonce, sender_public, ciphertext = self.receive_ciphertext(peer)
                self.assertEqual(recipient, username)
                self.assertEqual(self.sodium.decrypt(
                    ciphertext, nonce, sender_public, keys[1]
                ), b"secret for " + username)
            self.finish(process, peer)

    def test_incoming_ciphertext_displays_binary_safe_plaintext(self):
        sender_keys = self.sodium.keypair()
        with self.session() as (process, peer):
            client_public = self.client_public_key(process, peer)
            messages = (b"decrypted private message", b"binary\x00message",
                        "encrypted unicode: שלום".encode())
            for message in messages:
                send_frame(peer, FRAME_CIPHERTEXT, self.sodium.payload(
                    b"lifecycle", message, client_public, sender_keys
                ))
            marker = b"incoming-e2ee-check-complete"
            send_frame(peer, FRAME_TEXT, marker)
            output = wait_for_output(process, marker)
            for message in messages:
                self.assertIn(message, output)
            self.assertNotIn(b"Failed to decrypt", output)
            self.finish(process, peer)

    def test_tampered_nonce_sender_key_and_ciphertext_are_rejected(self):
        sender_keys = self.sodium.keypair()
        with self.session() as (process, peer):
            client_public = self.client_public_key(process, peer)
            message = b"tampered secret must never be displayed"
            payload = self.sodium.payload(b"lifecycle", message, client_public, sender_keys)
            nonce_start = 1 + len(b"lifecycle")
            for offset in (nonce_start, nonce_start + self.sodium.noncebytes, len(payload) - 1):
                altered = bytearray(payload)
                altered[offset] ^= 1
                send_frame(peer, FRAME_CIPHERTEXT, altered)
            valid = b"valid encrypted message after rejection"
            send_frame(peer, FRAME_CIPHERTEXT, self.sodium.payload(
                b"lifecycle", valid, client_public, sender_keys
            ))
            marker = b"tamper-check-complete"
            send_frame(peer, FRAME_TEXT, marker)
            output = wait_for_output(process, marker)
            self.assertEqual(output.count(b"Failed to decrypt private message:"), 3)
            self.assertNotIn(message, output)
            self.assertIn(valid, output)
            self.finish(process, peer)

    def test_malformed_ciphertext_is_rejected_without_disconnect(self):
        public, _ = self.sodium.keypair()
        valid = self.sodium.payload(b"lifecycle", b"", public, self.sodium.keypair())
        malformed = (b"", b"\x00", b"\x20" + valid[1:],
                     valid[:1 + len(b"lifecycle")],
                     valid[:1 + len(b"lifecycle") + self.sodium.noncebytes],
                     valid[:-1])
        with self.session() as (process, peer):
            for payload in malformed:
                send_frame(peer, FRAME_CIPHERTEXT, payload)
            marker = b"malformed-ciphertext-check-complete"
            send_frame(peer, FRAME_TEXT, marker)
            output = wait_for_output(process, marker)
            self.assertEqual(output.count(b"Failed to decrypt private message:"), len(malformed))
            self.finish(process, peer)

    def test_malformed_or_unsolicited_public_keys_do_not_crash_client(self):
        public, _ = self.sodium.keypair()
        for payload in (b"", b"\x00", b"\x20", b"\x03bob" + public[:-1],
                        b"\x03bob" + public):
            with self.subTest(payload_length=len(payload)), self.session() as (process, peer):
                send_frame(peer, FRAME_PEER_PK, payload)
                marker = b"invalid-key-check-complete"
                send_frame(peer, FRAME_TEXT, marker)
                wait_for_output(process, marker)
                self.finish(process, peer)

    def test_shutdown_with_pending_key_requests(self):
        for mode in ("quit", "stdin_eof", "server_close"):
            with self.subTest(mode=mode), self.session() as (process, peer):
                for username in (b"bob", b"sara"):
                    self.command(process, f"/msg {username.decode()} waiting for key")
                    self.assertEqual(receive_frame(peer), (FRAME_REQUEST_PK, username))
                self.finish(process, peer, mode)

    def test_failed_key_request_discards_only_its_pending_message(self):
        public, private = self.sodium.keypair()
        with self.session() as (process, peer):
            for message in ("discard this", "deliver this"):
                self.command(process, f"/msg bob {message}")
                self.assertEqual(receive_frame(peer), (FRAME_REQUEST_PK, b"bob"))
                self.key_response(peer, b"bob", b"" if message == "discard this" else public)
                if message == "discard this":
                    marker = b"missing-key-processed"
                    send_frame(peer, FRAME_TEXT, marker)
                    output = wait_for_output(process, marker)
                    self.assertIn(b"public key unavailable for bob", output)
            recipient, nonce, sender_public, ciphertext = self.receive_ciphertext(peer)
            self.assertEqual(recipient, b"bob")
            self.assertEqual(self.sodium.decrypt(ciphertext, nonce, sender_public, private),
                             b"deliver this")
            self.finish(process, peer)

    def test_message_size_limit_preserves_connection(self):
        public, private = self.sodium.keypair()
        # Capture the echoed 64 KiB commands without filling an unread pipe.
        output_file = self.enterContext(tempfile.TemporaryFile(mode="w+t"))
        with self.session(stdout=output_file) as (process, peer):
            maximum = MESSAGE_MAX_SIZE
            self.command(process, "/msg bob " + "x" * (maximum + 1))
            self.command(process, "/list")
            self.assertEqual(receive_frame(peer), (FRAME_TEXT, b"/list"))
            self.command(process, "/msg bob " + "x" * maximum)
            self.assertEqual(receive_frame(peer), (FRAME_REQUEST_PK, b"bob"))
            self.key_response(peer, b"bob", public)
            _, nonce, sender_public, ciphertext = self.receive_ciphertext(peer)
            self.assertEqual(self.sodium.decrypt(ciphertext, nonce, sender_public, private),
                             b"x" * maximum)
            self.finish(process, peer, output_file=output_file)

    def test_real_clients_exchange_private_messages(self):
        with running_server(self.server_directory):
            bob = self.start_client()
            self.command(bob, "y")
            wait_for_output(bob, b"Welcome to CipherChat, y!")
            self.command(bob, "/list")
            wait_for_output(bob, b"Connected clients:")
            alice = self.start_client()
            self.command(alice, "x")
            wait_for_output(alice, b"Welcome to CipherChat, x!")
            self.command(alice, "/msg y hi mf")
            wait_for_output(bob, b"Private message from x: hi mf")
            self.command(bob, "/msg x hello back")
            wait_for_output(alice, b"Private message from y: hello back")
            for process in (alice, bob):
                self.command(process, "/list")
                output = wait_for_output(process, b"Connected clients:")
                self.assertNotIn(b"receive frame:", output)
                self.command(process, "/quit")
                output, _ = process.communicate(timeout=3)
                self.assertEqual(process.returncode, 0, output)

    def test_server_key_registration_lookup_and_reconnect(self):
        with running_server(self.server_directory):
            alice = self.connect("alice")
            bob = self.connect("bob")
            send_frame(bob, FRAME_TEXT, b"/list")
            receive_frame(bob)
            send_frame(alice, FRAME_REQUEST_PK, b"bob")
            self.assertEqual(receive_frame(alice), (FRAME_PEER_PK, b"\x03bob"))
            for peer, name in ((bob, b"bob"), (alice, b"alice")):
                public, _ = self.sodium.keypair()
                send_frame(peer, FRAME_REGISTER_PK, public)
                send_frame(peer, FRAME_REQUEST_PK, name)
                self.assertEqual(receive_frame(peer), (
                    FRAME_PEER_PK, bytes([len(name)]) + name + public
                ))
                replacement, _ = self.sodium.keypair()
                send_frame(peer, FRAME_REGISTER_PK, replacement)
                self.assertEqual(receive_frame(peer)[0], FRAME_TEXT)
                send_frame(peer, FRAME_REQUEST_PK, name)
                self.assertEqual(receive_frame(peer)[1][-32:], public)
            send_frame(bob, FRAME_TEXT, b"/quit")
            with bob.unwrap():
                pass
            bob = self.connect("bob")
            send_frame(bob, FRAME_REQUEST_PK, b"bob")
            self.assertEqual(receive_frame(bob), (FRAME_PEER_PK, b"\x03bob"))

    def test_server_rejects_malformed_encryption_frames_without_disconnect(self):
        public, _ = self.sodium.keypair()
        sender_keys = self.sodium.keypair()
        payload = self.sodium.payload(b"alice", b"secret", public, sender_keys)
        with running_server(self.server_directory):
            alice = self.connect("alice")
            for kind, body in (
                (FRAME_REGISTER_PK, b""), (FRAME_REGISTER_PK, public[:-1]),
                (FRAME_REQUEST_PK, b""), (FRAME_REQUEST_PK, b"x" * 32),
                (FRAME_REQUEST_PK, b"bad\x00name"), (FRAME_REQUEST_PK, b"bad name"),
                (FRAME_CIPHERTEXT, b""), (FRAME_CIPHERTEXT, b"\xff" + payload[1:]),
                (FRAME_CIPHERTEXT, payload), (FRAME_PEER_PK, b"\x03bob" + public),
            ):
                send_frame(alice, kind, body)
                self.assertEqual(receive_frame(alice)[0], FRAME_TEXT)
                send_frame(alice, FRAME_TEXT, b"/list")
                self.assertIn(b"alice", receive_frame(alice)[1])

            send_frame(alice, FRAME_REGISTER_PK, sender_keys[0])
            oversized = self.sodium.payload(
                b"bob", b"x" * (MESSAGE_MAX_SIZE + 1), public, sender_keys
            )
            send_frame(alice, FRAME_CIPHERTEXT, oversized)
            self.assertEqual(receive_frame(alice)[0], FRAME_TEXT)
            send_frame(alice, FRAME_TEXT, b"/list")
            self.assertIn(b"alice", receive_frame(alice)[1])

    def test_server_reports_missing_key_recipient_and_keeps_connection(self):
        with running_server(self.server_directory):
            alice = self.connect("alice")
            send_frame(alice, FRAME_REQUEST_PK, b"nobody")
            kind, payload = receive_frame(alice)
            self.assertEqual(kind, FRAME_PEER_PK)
            self.assertEqual(payload, b"\x06nobody")
            send_frame(alice, FRAME_TEXT, b"/list")
            self.assertIn(b"alice", receive_frame(alice)[1])

    def test_server_forwards_ciphertext_to_recipient(self):
        sender_keys = self.sodium.keypair()
        recipient_public, recipient_private = self.sodium.keypair()
        with running_server(self.server_directory):
            alice = self.connect("alice")
            bob = self.connect("bob")
            send_frame(alice, FRAME_REGISTER_PK, sender_keys[0])
            # Confirm both workers have activated before attempting delivery.
            for peer in (alice, bob):
                send_frame(peer, FRAME_TEXT, b"/list")
                self.assertIn(b"bob", receive_frame(peer)[1])
            message = b"server must forward these encrypted bytes unchanged"
            payload = self.sodium.payload(b"bob", message, recipient_public, sender_keys)
            send_frame(alice, FRAME_CIPHERTEXT, payload)
            kind, forwarded = receive_frame(bob)
            self.assertEqual(kind, FRAME_CIPHERTEXT)
            sender, nonce, sender_public, ciphertext = self.sodium.unpack(forwarded)
            self.assertEqual(sender, b"alice")
            self.assertEqual(self.sodium.decrypt(
                ciphertext, nonce, sender_public, recipient_private
            ), message)


if __name__ == "__main__":
    unittest.main(verbosity=2)
