"""Tests for research.echo_server.EchoServer."""

from __future__ import annotations

import asyncio
import functools
import json
import os
import socket
import ssl
from collections import deque
from typing import Callable, Coroutine, ParamSpec, TypeVar
from unittest import TestCase

from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, H3Event, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import QuicEvent

from research.echo_server import EchoServer, RequestRecord

P = ParamSpec("P")

SERVER_CERTFILE = os.path.join(
    os.path.dirname(__file__), "..", "..", "tests", "ssl_cert.pem"
)
SERVER_KEYFILE = os.path.join(
    os.path.dirname(__file__), "..", "..", "tests", "ssl_key.pem"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def asynctest(
    coro: Callable[P, Coroutine[None, None, None]],
) -> Callable[P, None]:
    @functools.wraps(coro)
    def wrap(*args, **kwargs):
        asyncio.run(coro(*args, **kwargs))
    return wrap


class _SimpleH3Client(QuicConnectionProtocol):
    """Minimal HTTP/3 GET client."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._request_events: dict[int, deque[H3Event]] = {}
        self._request_waiters: dict[int, asyncio.Future] = {}
        self._http: H3Connection = H3Connection(self._quic)

    def quic_event_received(self, event: QuicEvent) -> None:
        for h3ev in self._http.handle_event(event):
            self._on_h3_event(h3ev)

    def _on_h3_event(self, event: H3Event) -> None:
        if isinstance(event, (HeadersReceived, DataReceived)):
            sid = event.stream_id
            self._request_events.setdefault(sid, deque()).append(event)
            if event.stream_ended and sid in self._request_waiters:
                waiter = self._request_waiters.pop(sid)
                if not waiter.done():
                    waiter.set_result(self._request_events.pop(sid))

    async def get(
        self,
        host: str,
        port: int,
        path: str = "/",
        extra_headers: list[tuple[bytes, bytes]] | None = None,
    ) -> deque[H3Event]:
        headers = [
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":authority", f"{host}:{port}".encode()),
            (b":path", path.encode()),
        ]
        if extra_headers:
            headers.extend(extra_headers)
        sid = self._quic.get_next_available_stream_id()
        self._http.send_headers(stream_id=sid, headers=headers, end_stream=True)
        waiter = self._loop.create_future()
        self._request_events[sid] = deque()
        self._request_waiters[sid] = waiter
        self.transmit()
        return await asyncio.wait_for(asyncio.shield(waiter), timeout=10.0)


async def _create_client(host: str, port: int) -> tuple[_SimpleH3Client, asyncio.BaseTransport]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
    addr = infos[0][4]
    if len(addr) == 2:
        addr = ("::ffff:" + addr[0], addr[1], 0, 0)

    config = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
    config.verify_mode = ssl.CERT_NONE
    config.server_name = host

    connection = QuicConnection(configuration=config)
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        sock.bind(("::", 0, 0, 0))
    except Exception:
        sock.close()
        raise

    transport, protocol = await loop.create_datagram_endpoint(
        lambda: _SimpleH3Client(connection),
        sock=sock,
    )
    protocol: _SimpleH3Client = protocol
    protocol.connect(addr)
    await protocol.wait_connected()
    return protocol, transport


def _parse_json_body(events: deque[H3Event]) -> dict:
    body = b"".join(ev.data for ev in events if isinstance(ev, DataReceived))
    return json.loads(body) if body else {}


def _response_status(events: deque[H3Event]) -> str:
    for ev in events:
        if isinstance(ev, HeadersReceived):
            for k, v in ev.headers:
                if k == b":status":
                    return v.decode()
    return ""


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class EchoServerTest(TestCase):
    """Tests for EchoServer."""

    # ------------------------------------------------------------------
    # 1. Basic response shape
    # ------------------------------------------------------------------

    @asynctest
    async def test_returns_200_with_json_body(self):
        """Server responds with HTTP 200 and a JSON body."""
        server = EchoServer()
        port = await server.start(cert_file=SERVER_CERTFILE, key_file=SERVER_KEYFILE)
        client, transport = await _create_client("localhost", port)
        try:
            events = await client.get("localhost", port, "/ping")
            self.assertEqual(_response_status(events), "200")
            data = _parse_json_body(events)
            self.assertIn("headers", data)
            self.assertIsInstance(data["headers"], list)
        finally:
            client.close()
            transport.close()
            server.close()

    # ------------------------------------------------------------------
    # 2. JSON body contains the request headers
    # ------------------------------------------------------------------

    @asynctest
    async def test_response_body_contains_request_headers(self):
        """Echo body includes all request headers sent by the client."""
        server = EchoServer()
        port = await server.start(cert_file=SERVER_CERTFILE, key_file=SERVER_KEYFILE)
        client, transport = await _create_client("localhost", port)
        try:
            events = await client.get(
                "localhost", port, "/check",
                extra_headers=[(b"x-custom", b"hello")],
            )
            data = _parse_json_body(events)
            header_dict = {row[0]: row[1] for row in data["headers"]}
            self.assertEqual(header_dict.get(":path"), "/check")
            self.assertEqual(header_dict.get("x-custom"), "hello")
        finally:
            client.close()
            transport.close()
            server.close()

    # ------------------------------------------------------------------
    # 3. Request log is populated
    # ------------------------------------------------------------------

    @asynctest
    async def test_request_log_populated(self):
        """EchoServer.get_log() returns a RequestRecord for each request."""
        server = EchoServer()
        port = await server.start(cert_file=SERVER_CERTFILE, key_file=SERVER_KEYFILE)
        client, transport = await _create_client("localhost", port)
        try:
            await client.get("localhost", port, "/log-test")
            log = server.get_log()
            self.assertEqual(len(log), 1)
            rec = log[0]
            self.assertIsInstance(rec, RequestRecord)
            self.assertEqual(rec.seq, 0)
            self.assertEqual(rec.path, "/log-test")
            self.assertEqual(rec.method, "GET")
        finally:
            client.close()
            transport.close()
            server.close()

    # ------------------------------------------------------------------
    # 4. Sequence numbers are monotonically increasing
    # ------------------------------------------------------------------

    @asynctest
    async def test_sequence_numbers_monotonic(self):
        """Sequence numbers increment across requests."""
        server = EchoServer()
        port = await server.start(cert_file=SERVER_CERTFILE, key_file=SERVER_KEYFILE)
        client, transport = await _create_client("localhost", port)
        try:
            await client.get("localhost", port, "/first")
            await client.get("localhost", port, "/second")
            await client.get("localhost", port, "/third")
            log = server.get_log()
            self.assertEqual(len(log), 3)
            seqs = [r.seq for r in log]
            self.assertEqual(seqs, [0, 1, 2])
        finally:
            client.close()
            transport.close()
            server.close()

    # ------------------------------------------------------------------
    # 5. JSON body includes the seq number
    # ------------------------------------------------------------------

    @asynctest
    async def test_response_body_includes_seq(self):
        """JSON response body includes the 'seq' field matching the log entry."""
        server = EchoServer()
        port = await server.start(cert_file=SERVER_CERTFILE, key_file=SERVER_KEYFILE)
        client, transport = await _create_client("localhost", port)
        try:
            events_a = await client.get("localhost", port, "/a")
            events_b = await client.get("localhost", port, "/b")
            self.assertEqual(_parse_json_body(events_a).get("seq"), 0)
            self.assertEqual(_parse_json_body(events_b).get("seq"), 1)
        finally:
            client.close()
            transport.close()
            server.close()

    # ------------------------------------------------------------------
    # 6. RequestRecord.header_dict convenience method
    # ------------------------------------------------------------------

    @asynctest
    async def test_record_header_dict(self):
        """RequestRecord.header_dict() returns a str→str dict."""
        server = EchoServer()
        port = await server.start(cert_file=SERVER_CERTFILE, key_file=SERVER_KEYFILE)
        client, transport = await _create_client("localhost", port)
        try:
            await client.get(
                "localhost", port, "/hd",
                extra_headers=[(b"authorization", b"Bearer tok123")],
            )
            rec = server.last_request()
            self.assertIsNotNone(rec)
            hd = rec.header_dict() # type: ignore
            self.assertEqual(hd.get("authorization"), "Bearer tok123")
            self.assertEqual(hd.get(":path"), "/hd")
        finally:
            client.close()
            transport.close()
            server.close()

    # ------------------------------------------------------------------
    # 7. RequestRecord.get_header case-insensitive lookup
    # ------------------------------------------------------------------

    @asynctest
    async def test_record_get_header_case_insensitive(self):
        """RequestRecord.get_header() is case-insensitive."""
        server = EchoServer()
        port = await server.start(cert_file=SERVER_CERTFILE, key_file=SERVER_KEYFILE)
        client, transport = await _create_client("localhost", port)
        try:
            await client.get(
                "localhost", port, "/gh",
                extra_headers=[(b"x-request-id", b"abc-123")],
            )
            rec = server.last_request()
            self.assertIsNotNone(rec)
            self.assertEqual(rec.get_header("X-Request-ID"), "abc-123") # type: ignore
            self.assertEqual(rec.get_header("x-request-id"), "abc-123") # type: ignore
            self.assertEqual(rec.get_header("missing", "default"), "default") # type: ignore
        finally:
            client.close()
            transport.close()
            server.close()

    # ------------------------------------------------------------------
    # 8. clear_log resets the log and sequence counter
    # ------------------------------------------------------------------

    @asynctest
    async def test_clear_log(self):
        """clear_log() empties the log and resets seq numbering."""
        server = EchoServer()
        port = await server.start(cert_file=SERVER_CERTFILE, key_file=SERVER_KEYFILE)
        client, transport = await _create_client("localhost", port)
        try:
            await client.get("localhost", port, "/before")
            self.assertEqual(server.request_count, 1)
            server.clear_log()
            self.assertEqual(server.get_log(), [])
            self.assertEqual(server.request_count, 0)
            # After clear, seq numbering restarts at 0
            await client.get("localhost", port, "/after")
            log = server.get_log()
            self.assertEqual(len(log), 1)
            self.assertEqual(log[0].seq, 0)
            self.assertEqual(log[0].path, "/after")
        finally:
            client.close()
            transport.close()
            server.close()

    # ------------------------------------------------------------------
    # 9. connection_count reflects distinct QUIC connections
    # ------------------------------------------------------------------

    @asynctest
    async def test_connection_count(self):
        """connection_count increments per QUIC connection, not per request."""
        server = EchoServer()
        port = await server.start(cert_file=SERVER_CERTFILE, key_file=SERVER_KEYFILE)
        client_a, transport_a = await _create_client("localhost", port)
        client_b, transport_b = await _create_client("localhost", port)
        try:
            await client_a.get("localhost", port, "/from-a")
            await client_b.get("localhost", port, "/from-b")
            # Two distinct QUIC connections
            self.assertEqual(server.connection_count, 2)
            # Both requests logged
            self.assertEqual(server.request_count, 2)
            # Connections have different ids
            log = server.get_log()
            conn_ids = {r.connection_id for r in log}
            self.assertEqual(len(conn_ids), 2)
        finally:
            client_a.close()
            client_b.close()
            transport_a.close()
            transport_b.close()
            server.close()

    # ------------------------------------------------------------------
    # 10. requests_for_path helper
    # ------------------------------------------------------------------

    @asynctest
    async def test_requests_for_path(self):
        """requests_for_path() filters by :path."""
        server = EchoServer()
        port = await server.start(cert_file=SERVER_CERTFILE, key_file=SERVER_KEYFILE)
        client, transport = await _create_client("localhost", port)
        try:
            await client.get("localhost", port, "/api/data")
            await client.get("localhost", port, "/api/data")
            await client.get("localhost", port, "/other")
            matches = server.requests_for_path("/api/data")
            self.assertEqual(len(matches), 2)
            others = server.requests_for_path("/other")
            self.assertEqual(len(others), 1)
        finally:
            client.close()
            transport.close()
            server.close()

    # ------------------------------------------------------------------
    # 11. Two independent EchoServer instances are fully isolated
    # ------------------------------------------------------------------

    @asynctest
    async def test_two_instances_isolated(self):
        """Two EchoServer instances maintain independent logs."""
        server_a = EchoServer()
        server_b = EchoServer()
        port_a = await server_a.start(cert_file=SERVER_CERTFILE, key_file=SERVER_KEYFILE)
        port_b = await server_b.start(cert_file=SERVER_CERTFILE, key_file=SERVER_KEYFILE)
        client_a, transport_a = await _create_client("localhost", port_a)
        client_b, transport_b = await _create_client("localhost", port_b)
        try:
            await client_a.get("localhost", port_a, "/from-a")
            await client_a.get("localhost", port_a, "/from-a-again")
            await client_b.get("localhost", port_b, "/from-b")

            log_a = server_a.get_log()
            log_b = server_b.get_log()

            self.assertEqual(len(log_a), 2)
            self.assertEqual(len(log_b), 1)
            # seq counter is per-instance
            self.assertEqual(log_a[0].seq, 0)
            self.assertEqual(log_a[1].seq, 1)
            self.assertEqual(log_b[0].seq, 0)
        finally:
            client_a.close()
            client_b.close()
            transport_a.close()
            transport_b.close()
            server_a.close()
            server_b.close()
