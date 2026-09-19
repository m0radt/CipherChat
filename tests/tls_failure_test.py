#!/usr/bin/env python3
"""TLS rejection and handshake deadline checks against the actual C programs.

Certificates and keys are generated in temporary directories. Handshake tests
cover both silent peers and peers that keep sending fragments of valid records.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager, ExitStack
from pathlib import Path
import select
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import unittest

from integration_test import (
    CLIENT,
    HOST,
    PORT,
    SERVER,
    receive_legacy_message,
    send_legacy_message,
)


IO_TIMEOUT = 3
CLIENT_TIMEOUT = 5
# Handshake deadlines and the separate username receive timeout are 10 seconds.
STALL_TIMEOUT = 15


def create_certificate(directory: Path, ip_address: str) -> Path:
    certificates = directory / "certs"
    certificates.mkdir(parents=True)
    certificate = certificates / "server.crt"
    result = subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "ec",
            "-pkeyopt", "ec_paramgen_curve:prime256v1",
            "-noenc", "-sha256", "-days", "1", "-batch",
            "-subj", "/CN=CipherChat TLS test",
            "-addext", f"subjectAltName=IP:{ip_address}",
            "-addext", "basicConstraints=critical,CA:FALSE",
            "-addext", "extendedKeyUsage=serverAuth",
            "-keyout", str(certificates / "server.key"),
            "-out", str(certificate),
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Cannot generate test certificate: {result.stderr}")
    return certificate


def client_context(certificate: Path) -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=str(certificate))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    return context


def stop_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)


@contextmanager
def running_server(directory: Path) -> Iterator[subprocess.Popen[str]]:
    # Fail before connecting to a server belonging to another terminal/test.
    with socket.socket() as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind((HOST, PORT))
        except OSError as error:
            raise RuntimeError(f"Test port {PORT} is unavailable: {error}") from error

    with tempfile.TemporaryFile(mode="w+t") as output:
        process = subprocess.Popen(
            [str(SERVER.resolve())],
            cwd=directory,
            stdout=output,
            stderr=subprocess.STDOUT,
            text=True,
        )
        try:
            deadline = time.monotonic() + IO_TIMEOUT
            while True:
                if process.poll() is not None:
                    raise AssertionError("Test server exited during startup")
                try:
                    with socket.create_connection((HOST, PORT), timeout=0.2):
                        break
                except ConnectionRefusedError:
                    if time.monotonic() >= deadline:
                        raise AssertionError("Test server did not start")
                    time.sleep(0.03)

            yield process
            if process.poll() is not None:
                raise AssertionError("Test server exited unexpectedly")
        except BaseException:
            stop_process(process)
            output.seek(0)
            print("\nTLS test server output:\n" + output.read(), flush=True)
            raise
        finally:
            stop_process(process)


class TLSFailureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="cipherchat-tls-fixtures-")
        cls.addClassCleanup(temporary.cleanup)
        cls.fixtures = Path(temporary.name)
        cls.good_server = cls.fixtures / "good-server"
        cls.good_certificate = create_certificate(cls.good_server, HOST)
        cls.other_certificate = create_certificate(cls.fixtures / "other", HOST)
        cls.wrong_ip_server = cls.fixtures / "wrong-ip-server"
        cls.wrong_ip_certificate = create_certificate(
            cls.wrong_ip_server, "127.0.0.2"
        )

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="cipherchat-tls-client-")
        self.addCleanup(temporary.cleanup)
        self.client_directory = Path(temporary.name)
        (self.client_directory / "certs").mkdir()

    def trust_certificate(self, certificate: Path) -> None:
        shutil.copy2(certificate, self.client_directory / "certs" / "server.crt")

    def run_client(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(CLIENT.resolve())],
            cwd=self.client_directory,
            input="tlscontrol\n",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=CLIENT_TIMEOUT,
        )

    def assert_client_accepts_server(self) -> None:
        result = self.run_client()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("TLS handshake successful!", result.stdout)
        self.assertIn("Welcome to CipherChat", result.stdout)

    def assert_client_rejects_certificate(self) -> None:
        result = self.run_client()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("certificate verify failed", result.stdout.lower())
        self.assertNotIn("TLS handshake successful!", result.stdout)
        self.assertNotIn("Username:", result.stdout)

    def test_client_rejects_untrusted_certificate(self) -> None:
        with running_server(self.good_server):
            # Positive control: the same server works with the correct trust.
            self.trust_certificate(self.good_certificate)
            self.assert_client_accepts_server()
            self.trust_certificate(self.other_certificate)
            self.assert_client_rejects_certificate()

    def test_client_rejects_wrong_ip(self) -> None:
        self.trust_certificate(self.wrong_ip_certificate)
        with running_server(self.wrong_ip_server):
            # Prove the certificate is trusted and usable for its declared IP.
            context = client_context(self.wrong_ip_certificate)
            with socket.create_connection((HOST, PORT), timeout=IO_TIMEOUT) as raw:
                with context.wrap_socket(raw, server_hostname="127.0.0.2") as peer:
                    send_legacy_message(peer, b"sancontrol")
                    self.assertTrue(
                        receive_legacy_message(peer).startswith(b"Welcome to CipherChat")
                    )
            # The C client expects HOST (127.0.0.1), which is absent from the SAN.
            self.assert_client_rejects_certificate()

    def test_server_rejects_tls12(self) -> None:
        context = client_context(self.good_certificate)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_2
        with running_server(self.good_server):
            with socket.create_connection((HOST, PORT), timeout=IO_TIMEOUT) as raw:
                with self.assertRaises(ssl.SSLError) as caught:
                    with context.wrap_socket(raw, server_hostname=HOST):
                        self.fail("Server accepted TLS 1.2")
            self.assertEqual(caught.exception.reason, "TLSV1_ALERT_PROTOCOL_VERSION")
            self.trust_certificate(self.good_certificate)
            self.assert_client_accepts_server()

    def test_client_rejects_tls12(self) -> None:
        self.trust_certificate(self.good_certificate)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(
            str(self.good_certificate),
            str(self.good_server / "certs" / "server.key"),
        )
        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((HOST, PORT))
            listener.listen(1)
            listener.settimeout(IO_TIMEOUT)
            with subprocess.Popen(
                [str(CLIENT.resolve())],
                cwd=self.client_directory,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            ) as process:
                try:
                    raw, _ = listener.accept()
                    with raw:
                        raw.settimeout(IO_TIMEOUT)
                        with self.assertRaises(ssl.SSLError) as caught:
                            with context.wrap_socket(raw, server_side=True):
                                self.fail("C client negotiated TLS 1.2")
                    self.assertEqual(caught.exception.reason, "UNSUPPORTED_PROTOCOL")
                    output, _ = process.communicate(timeout=CLIENT_TIMEOUT)
                    self.assertEqual(process.returncode, 1, output)
                    self.assertIn("protocol version", output.lower())
                    self.assertNotIn("TLS handshake successful!", output)
                finally:
                    stop_process(process)

    def test_stalled_connections_timeout_without_blocking_clients(self) -> None:
        context = client_context(self.good_certificate)
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        handshake = context.wrap_bio(incoming, outgoing, server_hostname=HOST)
        with self.assertRaises(ssl.SSLWantReadError):
            handshake.do_handshake()
        hello = outgoing.read()
        self.assertGreater(len(hello), 5)

        with running_server(self.good_server), ExitStack() as connections:
            deadline = time.monotonic() + STALL_TIMEOUT
            silent = connections.enter_context(
                socket.create_connection((HOST, PORT), timeout=IO_TIMEOUT)
            )
            partial = connections.enter_context(
                socket.create_connection((HOST, PORT), timeout=IO_TIMEOUT)
            )
            trickle = connections.enter_context(
                socket.create_connection((HOST, PORT), timeout=IO_TIMEOUT)
            )
            # Send a valid TLS record header, then withhold the ClientHello body.
            partial.sendall(hello[:5])
            trickle.sendall(hello[:5])
            raw = connections.enter_context(
                socket.create_connection((HOST, PORT), timeout=IO_TIMEOUT)
            )
            no_username = connections.enter_context(
                context.wrap_socket(raw, server_hostname=HOST)
            )

            self.assertFalse(
                select.select([silent, partial], [], [], 0.2)[0],
                "Incomplete handshakes closed immediately instead of waiting",
            )
            # A healthy client must work while the stalled peers remain open.
            self.trust_certificate(self.good_certificate)
            self.assert_client_accepts_server()

            pending = {silent, partial, trickle}
            offset = 5
            next_byte = time.monotonic()
            while pending:
                self.assertLess(time.monotonic(), deadline,
                                "handshake deadline restarted after incoming bytes")
                for peer in select.select(list(pending), [], [], 0.1)[0]:
                    try:
                        closed = peer.recv(1) == b""
                    except ConnectionResetError:
                        closed = True
                    self.assertTrue(closed, "Incomplete hello produced a response")
                    pending.remove(peer)
                if trickle in pending and time.monotonic() >= next_byte:
                    try:
                        trickle.sendall(hello[offset:offset + 1])
                    except (BrokenPipeError, ConnectionResetError):
                        pending.remove(trickle)
                    offset += 1
                    self.assertLess(offset, len(hello), "test completed the hello")
                    next_byte = time.monotonic() + 0.2

            self.assertGreater(offset, 30, "trickle peer disconnected too early")

            no_username.settimeout(max(0.1, deadline - time.monotonic()))
            self.assertEqual(
                receive_legacy_message(no_username),
                b"Login failed: username timeout.\n",
            )
            self.assertEqual(no_username.recv(1), b"")


if __name__ == "__main__":
    unittest.main(verbosity=2)
