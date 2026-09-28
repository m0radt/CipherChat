#!/usr/bin/env python3
"""Check absolute handshake deadlines and bounded TLS close_notify exchanges."""

from pathlib import Path
import os
import pty
import select
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import tempfile
import termios
import time
import unittest

from integration_test import (
    CLIENT, FRAME_REGISTER_PK, FRAME_REQUEST_PK, FRAME_TEXT, HOST, MESSAGE_MAX_SIZE, PORT, receive_exact, receive_frame,
    receive_legacy_message, send_frame, send_legacy_message,
)
from tls_failure_test import (
    STALL_TIMEOUT, client_context, create_certificate, running_server, stop_process,
)


class TLSClientTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix="cipherchat-lifecycle-")
        cls.addClassCleanup(temporary.cleanup)
        root = Path(temporary.name)
        cls.server_directory = root / "server"
        certificate = create_certificate(cls.server_directory, HOST)
        cls.context = client_context(certificate)
        cls.server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cls.server_context.minimum_version = ssl.TLSVersion.TLSv1_3
        cls.server_context.maximum_version = ssl.TLSVersion.TLSv1_3
        cls.server_context.load_cert_chain(
            str(certificate), str(cls.server_directory / "certs" / "server.key")
        )
        cls.client_directory = root / "client"
        (cls.client_directory / "certs").mkdir(parents=True)
        shutil.copy2(certificate, cls.client_directory / "certs" / "server.crt")

    def listener(self):
        listener = socket.socket()
        self.addCleanup(listener.close)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((HOST, PORT))
        listener.listen(2)
        listener.settimeout(3)
        return listener

    def connect(self, username):
        raw = socket.create_connection((HOST, PORT), timeout=3)
        self.addCleanup(raw.close)
        peer = self.context.wrap_socket(
            raw, server_hostname=HOST, suppress_ragged_eofs=False
        )
        self.addCleanup(peer.close)
        send_legacy_message(peer, username.encode())
        self.assertTrue(receive_legacy_message(peer).startswith(b"Welcome"))
        return peer

    def start_client(self, *, stdout=subprocess.PIPE):
        process = self.enterContext(subprocess.Popen(
            [str(CLIENT.resolve())], cwd=self.client_directory,
            stdin=subprocess.PIPE, stdout=stdout,
            stderr=subprocess.STDOUT, text=True,
        ))
        # Stop before Popen's context cleanup closes streams and waits for exit.
        self.addCleanup(stop_process, process)
        return process

    def accept_client(self, listener, process):
        raw, _ = listener.accept()
        self.addCleanup(raw.close)
        raw.settimeout(3)
        peer = self.server_context.wrap_socket(
            raw, server_side=True, suppress_ragged_eofs=False
        )
        self.addCleanup(peer.close)
        process.stdin.write("lifecycle\n")
        process.stdin.flush()
        self.assertEqual(receive_legacy_message(peer), b"lifecycle")
        send_legacy_message(peer, b"Welcome to CipherChat, lifecycle!\n")
        kind, public_key = receive_frame(peer)
        self.assertEqual(kind, FRAME_REGISTER_PK)
        self.assertEqual(len(public_key), 32)
        process.public_key = public_key
        return peer


class TLSLifecycleTests(TLSClientTestCase):
    def test_client_redraws_partial_input_after_terminal_resize(self):
        master_fd, slave_fd = pty.openpty()
        terminal = self.enterContext(os.fdopen(master_fd, "r+b", buffering=0))
        client_terminal = self.enterContext(os.fdopen(slave_fd, "r+b", buffering=0))
        termios.tcsetwinsize(client_terminal, (24, 80))

        def read_until(marker):
            output = b""
            deadline = time.monotonic() + 3
            while marker not in output:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not select.select([terminal], [], [], remaining)[0]:
                    self.fail(f"Client did not redraw {marker!r}: {output!r}")
                chunk = os.read(terminal.fileno(), 4096)
                self.assertTrue(chunk, "Client closed its terminal")
                output += chunk
            return output

        with self.listener() as listener:
            process = self.enterContext(subprocess.Popen(
                [str(CLIENT.resolve())], cwd=self.client_directory,
                stdin=client_terminal, stdout=client_terminal,
                stderr=subprocess.STDOUT,
                env={**os.environ, "TERM": "xterm-256color"},
            ))
            self.addCleanup(stop_process, process)
            raw, _ = listener.accept()
            self.addCleanup(raw.close)
            raw.settimeout(3)
            peer = self.server_context.wrap_socket(raw, server_side=True)
            self.addCleanup(peer.close)
            read_until(b"Username: ")
            terminal.write(b"resize\n")
            self.assertEqual(receive_legacy_message(peer), b"resize")
            send_legacy_message(peer, b"Welcome to CipherChat, resize!\n")
            self.assertEqual(receive_frame(peer)[0], FRAME_REGISTER_PK)
            read_until(b"> ")

            command = b"/broadcast " + b"x" * 20
            terminal.write(command)
            read_until(command)
            for dimensions in ((17, 125), (24, 80), (17, 125)):
                with self.subTest(dimensions=dimensions):
                    termios.tcsetwinsize(client_terminal, dimensions)
                    # Popen's PTY is not the child's controlling terminal, so
                    # send the notification a real terminal would deliver.
                    process.send_signal(signal.SIGWINCH)
                    read_until(b"> " + command)

            terminal.write(b"y" * 100 + b"\n")
            self.assertEqual(receive_frame(peer), (FRAME_TEXT, command + b"y" * 100))
            terminal.write(b"/quit\n")
            self.assertEqual(receive_frame(peer), (FRAME_TEXT, b"/quit"))
            with peer.unwrap() as transport:
                self.assertEqual(transport.recv(1), b"")
            self.assertEqual(process.wait(timeout=3), 0)

    def test_client_parses_only_private_messages(self):
        # Readline can echo more than a pipe can hold before we read the output.
        output_file = self.enterContext(tempfile.TemporaryFile(mode="w+t"))
        with self.listener() as listener:
            process = self.start_client(stdout=output_file)
            peer = self.accept_client(listener, process)
            cases = (
                ("/msg sara hello there", FRAME_REQUEST_PK, b"sara"),
                ("  /msg\t sara\t hello  there", FRAME_REQUEST_PK, b"sara"),
                ("/msg " + "x" * 31 + " hello", FRAME_REQUEST_PK, b"x" * 31),
                ("/msgx sara hello", FRAME_TEXT, b"/msgx sara hello"),
                ("  /broadcast   hello  all", FRAME_TEXT, b"  /broadcast   hello  all"),
                ("/broadcast", FRAME_TEXT, b"/broadcast"),
                ("/help", FRAME_TEXT, b"/help"),
            )
            for command, frame_type, payload in cases:
                with self.subTest(command=command):
                    process.stdin.write(command + "\n")
                    process.stdin.flush()
                    self.assertEqual(receive_frame(peer), (frame_type, payload))

            invalid = ("/msg", "/msg sara", "/msg sara   ",
                       "/msg " + "x" * 32 + " hello",
                       "/msg sara " + "x" * (MESSAGE_MAX_SIZE + 1))
            for command in invalid:
                with self.subTest(command=command[:60]):
                    process.stdin.write(command + "\n/list\n")
                    process.stdin.flush()
                    # Invalid /msg input is rejected before reaching the server.
                    self.assertEqual(receive_frame(peer), (FRAME_TEXT, b"/list"))

            process.stdin.write("/quit\n")
            process.stdin.flush()
            self.assertEqual(receive_frame(peer), (FRAME_TEXT, b"/quit"))
            with peer.unwrap() as transport:
                self.assertEqual(transport.recv(1), b"")
            process.communicate(timeout=3)
            output_file.seek(0)
            output = output_file.read()
            self.assertEqual(process.returncode, 0, output)
            self.assertIn("Usage: /msg <username> <message>", output)

    def test_client_deadline_with_silent_and_trickling_servers(self):
        with self.listener() as listener:
            started = time.monotonic()
            processes = []
            peers = []
            for _ in range(2):
                process = self.start_client()
                processes.append(process)
                raw, _ = listener.accept()
                self.addCleanup(raw.close)
                raw.settimeout(3)
                peers.append(raw)
                header = receive_exact(raw, 5)
                hello = header + receive_exact(raw, struct.unpack("!H", header[3:])[0])

            # Generate a real response to the second client's ClientHello, but
            # deliver its first record a byte at a time without completing it.
            incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
            handshake = self.server_context.wrap_bio(incoming, outgoing, server_side=True)
            incoming.write(hello)
            with self.assertRaises(ssl.SSLWantReadError):
                handshake.do_handshake()
            response = outgoing.read()
            self.assertGreater(struct.unpack("!H", response[3:5])[0], 80)
            peers[1].sendall(response[:5])
            live = set(peers)
            offset = 5
            next_byte = time.monotonic()
            while any(process.poll() is None for process in processes):
                self.assertLess(time.monotonic() - started, STALL_TIMEOUT,
                                "C client exceeded the total handshake deadline")
                for peer in select.select(list(live), [], [], 0.1)[0]:
                    try:
                        data = peer.recv(4096)
                    except ConnectionResetError:
                        data = b""
                    if not data:
                        live.remove(peer)
                if peers[1] in live and time.monotonic() >= next_byte:
                    try:
                        peers[1].sendall(response[offset:offset + 1])
                    except (BrokenPipeError, ConnectionResetError):
                        live.remove(peers[1])
                    offset += 1
                    next_byte = time.monotonic() + 0.2

            self.assertGreater(offset, 30, "trickling handshake failed too early")
            for process in processes:
                output, _ = process.communicate(timeout=1)
                self.assertEqual(process.returncode, 1, output)
                self.assertIn("TLS handshake timed out", output)
                self.assertNotIn("TLS handshake successful!", output)
                self.assertNotIn("Username:", output)

    def test_server_sends_and_replies_to_close_notify(self):
        with running_server(self.server_directory):
            peer = self.connect("quitter")
            send_frame(peer, FRAME_TEXT, b"/quit")
            # With suppress_ragged_eofs=False, a bare TCP EOF raises an error.
            self.assertEqual(peer.recv(1), b"")
            with peer.unwrap() as transport:
                self.assertEqual(transport.recv(1), b"")

            peer = self.connect("peerinitiated")
            with peer.unwrap() as transport:
                self.assertEqual(transport.recv(1), b"")

    def test_server_shutdown_wait_is_bounded_and_does_not_hold_registry_lock(self):
        with running_server(self.server_directory):
            peer = self.connect("uncooperative")
            started = time.monotonic()
            send_frame(peer, FRAME_TEXT, b"/quit")
            self.assertEqual(peer.recv(1), b"")
            # Keep our TLS write side open instead of answering close_notify.
            healthy = self.connect("healthy")
            send_frame(healthy, FRAME_TEXT, b"/list")
            self.assertIn(b"healthy", receive_frame(healthy)[1])
            with socket.socket(fileno=os.dup(peer.fileno())) as transport:
                transport.settimeout(4)
                self.assertEqual(transport.recv(1), b"")
            elapsed = time.monotonic() - started
            self.assertGreater(elapsed, 1.5)
            self.assertLess(elapsed, 4)

    def test_client_sends_and_replies_to_close_notify(self):
        for mode in ("quit", "stdin_eof", "server_close"):
            with self.subTest(mode=mode), self.listener() as listener:
                process = self.start_client()
                peer = self.accept_client(listener, process)
                if mode == "quit":
                    process.stdin.write("/quit\n")
                    process.stdin.flush()
                    self.assertEqual(receive_frame(peer), (FRAME_TEXT, b"/quit"))
                elif mode == "stdin_eof":
                    process.stdin.close()
                    process.stdin = None
                if mode != "server_close":
                    self.assertEqual(peer.recv(1), b"")
                with peer.unwrap() as transport:
                    self.assertEqual(transport.recv(1), b"")
                output, _ = process.communicate(timeout=3)
                self.assertEqual(process.returncode, 0, output)

    def test_client_shutdown_wait_is_bounded(self):
        with self.listener() as listener:
            process = self.start_client()
            peer = self.accept_client(listener, process)
            started = time.monotonic()
            process.stdin.close()
            process.stdin = None
            self.assertEqual(peer.recv(1), b"")
            # Do not answer with unwrap(); the client must still exit promptly.
            output, _ = process.communicate(timeout=4)
            elapsed = time.monotonic() - started
            self.assertEqual(process.returncode, 0, output)
            self.assertGreater(elapsed, 1.5)
            self.assertLess(elapsed, 4)

    def test_client_reports_abrupt_tls_eof(self):
        with self.listener() as listener:
            process = self.start_client()
            peer = self.accept_client(listener, process)
            with socket.socket(fileno=peer.detach()):
                pass  # Close TCP without a TLS close_notify.
            output, _ = process.communicate(timeout=3)
            self.assertEqual(process.returncode, 1, output)
            self.assertIn("receive frame", output)


if __name__ == "__main__":
    unittest.main(verbosity=2)
