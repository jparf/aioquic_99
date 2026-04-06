"""Integration tests for FaultyProxy (Task 1).

Each test starts an in-process stack (echo server + FaultyProxy + 1-2 HTTP/3
clients) and tears it down cleanly after the assertion.
"""

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
from aioquic.asyncio.server import QuicServer, serve
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, H3Event, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import ProtocolNegotiated, QuicEvent

from research.faulty_proxy import FaultyProxy, InsertionEvent, ReferenceEvent

P = ParamSpec("P")

SERVER_CERTFILE = os.path.join(
    os.path.dirname(__file__), "..", "..", "tests", "ssl_cert.pem"
)
SERVER_KEYFILE = os.path.join(
    os.path.dirname(__file__), "..", "..", "tests", "ssl_key.pem"
)


def asynctest(
    coro: Callable[P, Coroutine[None, None, None]],
) -> Callable[P, None]:
    @functools.wraps(coro)
    def wrap(*args, **kwargs):
        asyncio.run(coro(*args, **kwargs))
    return wrap


# ---------------------------------------------------------------------------
# _EchoH3Server — returns all request headers as a JSON body
# ---------------------------------------------------------------------------


class _EchoH3Server(QuicConnectionProtocol):
    """HTTP/3 server that echoes received request headers as a JSON body.

    Also counts how many connections have been established, so tests can
    verify the shared backend connection behavior.
    """

    connection_count: int = 0

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._http: H3Connection | None = None
        _EchoH3Server.connection_count += 1

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, ProtocolNegotiated):
            if event.alpn_protocol in H3_ALPN:
                self._http = H3Connection(self._quic)
        if self._http is not None:
            for h3ev in self._http.handle_event(event):
                self._on_h3_event(h3ev)

    def _on_h3_event(self, event: H3Event) -> None:
        if self._http is None:
            return
        if isinstance(event, HeadersReceived) and event.stream_ended:
            # Build a JSON response containing the received headers
            headers_list = [
                [name.decode(errors="replace"), value.decode(errors="replace")]
                for name, value in event.headers
            ]
            body = json.dumps({"headers": headers_list}).encode()
            self._http.send_headers(
                stream_id=event.stream_id,
                headers=[
                    (b":status", b"200"),
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                ],
            )
            self._http.send_data(
                stream_id=event.stream_id, data=body, end_stream=True
            )
            self.transmit()


# ---------------------------------------------------------------------------
# _SimpleH3Client — minimal HTTP/3 client for test use
# ---------------------------------------------------------------------------


class _SimpleH3Client(QuicConnectionProtocol):
    """Minimal HTTP/3 client that supports a single GET request."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._request_events: dict[int, deque[H3Event]] = {}
        self._request_waiters: dict[int, asyncio.Future] = {}

        # Create the H3Connection immediately so it can process QUIC events
        self._http: H3Connection = H3Connection(self._quic)

    def quic_event_received(self, event: QuicEvent) -> None:
        if self._http is not None:
            for h3ev in self._http.handle_event(event):
                self._on_h3_event(h3ev)

    def _on_h3_event(self, event: H3Event) -> None:
        if isinstance(event, (HeadersReceived, DataReceived)):
            sid = event.stream_id
            if sid not in self._request_events:
                self._request_events[sid] = deque()
            self._request_events[sid].append(event)
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
        """Perform a GET request and return all response events."""
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
    """Connect a _SimpleH3Client to host:port. Returns (protocol, transport)."""
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
    completed = False
    try:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        sock.bind(("::", 0, 0, 0))
        completed = True
    finally:
        if not completed:
            sock.close()

    transport, protocol = await loop.create_datagram_endpoint(
        lambda: _SimpleH3Client(connection),
        sock=sock,
    )
    protocol: _SimpleH3Client = protocol
    protocol.connect(addr)
    await protocol.wait_connected()
    return protocol, transport


async def _start_echo_server() -> tuple[QuicServer, int]:
    """Start an in-process echo server on an ephemeral port."""
    _EchoH3Server.connection_count = 0
    config = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN)
    config.load_cert_chain(SERVER_CERTFILE, SERVER_KEYFILE)
    server = await serve(
        host="::",
        port=0,
        configuration=config,
        create_protocol=_EchoH3Server,
    )
    assert server._transport is not None
    port = server._transport.get_extra_info("sockname")[1]
    return server, port


def _get_response_headers(events: deque[H3Event]) -> dict[str, str]:
    """Extract response headers dict from event stream."""
    for ev in events:
        if isinstance(ev, HeadersReceived):
            return {
                k.decode(errors="replace"): v.decode(errors="replace")
                for k, v in ev.headers
            }
    return {}


def _get_response_body(events: deque[H3Event]) -> bytes:
    """Concatenate all DataReceived payloads."""
    return b"".join(ev.data for ev in events if isinstance(ev, DataReceived))


def _parse_echo_headers(events: deque[H3Event]) -> dict[str, str]:
    """Parse the echo server's JSON body into a header dict."""
    body = _get_response_body(events)
    if not body:
        return {}
    data = json.loads(body)
    return {row[0]: row[1] for row in data.get("headers", [])}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class FaultyProxyTest(TestCase):
    """Integration tests for FaultyProxy."""

    @asynctest
    async def test_shared_backend_connection(self):
        """Two frontend clients share exactly ONE backend connection."""
        echo_server, echo_port = await _start_echo_server()
        proxy = FaultyProxy(mode="naive_name_reuse")
        proxy_port = await proxy.start(
            listen_port=0,
            backend_host="localhost",
            backend_port=echo_port,
            cert_file=SERVER_CERTFILE,
            key_file=SERVER_KEYFILE,
        )
        try:
            # Connect two independent clients to the proxy
            client_a, transport_a = await _create_client("localhost", proxy_port)
            client_b, transport_b = await _create_client("localhost", proxy_port)
            try:
                events_a = await client_a.get("localhost", proxy_port, "/a")
                events_b = await client_b.get("localhost", proxy_port, "/b")
                self.assertEqual(_get_response_headers(events_a).get(":status"), "200")
                self.assertEqual(_get_response_headers(events_b).get(":status"), "200")
                # Only ONE backend connection should have been established
                self.assertEqual(_EchoH3Server.connection_count, 1)
            finally:
                client_a.close()
                client_b.close()
                transport_a.close()
                transport_b.close()
        finally:
            proxy.stop()
            echo_server.close()

    @asynctest
    async def test_naive_name_reuse_client_b_victim(self):
        """Client B gets Client A's credential due to shared table contamination.

        Client A sends Authorization: Bearer tokenA first, inserting it into
        the shared dynamic table. Client B then sends Authorization: Bearer tokenB,
        but the proxy finds 'authorization' by name in the table and emits a
        dynamic reference to tokenA instead. The echo server decodes tokenA.
        """
        echo_server, echo_port = await _start_echo_server()
        proxy = FaultyProxy(mode="naive_name_reuse")
        proxy_port = await proxy.start(
            listen_port=0,
            backend_host="localhost",
            backend_port=echo_port,
            cert_file=SERVER_CERTFILE,
            key_file=SERVER_KEYFILE,
        )
        try:
            client_a, transport_a = await _create_client("localhost", proxy_port)
            client_b, transport_b = await _create_client("localhost", proxy_port)
            try:
                # Client A goes first — inserts Authorization: Bearer tokenA
                events_a = await client_a.get(
                    "localhost", proxy_port, "/resource",
                    extra_headers=[(b"authorization", b"Bearer tokenA")],
                )
                self.assertEqual(_get_response_headers(events_a).get(":status"), "200")

                # Allow encoder stream instruction to reach the backend
                await asyncio.sleep(0.05)

                # Client B sends Authorization: Bearer tokenB
                events_b = await client_b.get(
                    "localhost", proxy_port, "/resource",
                    extra_headers=[(b"authorization", b"Bearer tokenB")],
                )
                self.assertEqual(_get_response_headers(events_b).get(":status"), "200")

                # The echo server should have received tokenA for Client B's request
                headers_b = _parse_echo_headers(events_b)
                auth_at_backend = headers_b.get("authorization")
                self.assertEqual(
                    auth_at_backend,
                    "Bearer tokenA",
                    msg=(
                        f"Expected Client B's request to arrive with 'Bearer tokenA' "
                        f"(Client A's token) but got {auth_at_backend!r}. "
                        f"Report:\n{proxy.instrumentation.report()}"
                    ),
                )
            finally:
                client_a.close()
                client_b.close()
                transport_a.close()
                transport_b.close()
        finally:
            proxy.stop()
            echo_server.close()

    @asynctest
    async def test_naive_name_reuse_client_a_victim(self):
        """Reversed order: Client B inserts first, Client A gets Client B's token."""
        echo_server, echo_port = await _start_echo_server()
        proxy = FaultyProxy(mode="naive_name_reuse")
        proxy_port = await proxy.start(
            listen_port=0,
            backend_host="localhost",
            backend_port=echo_port,
            cert_file=SERVER_CERTFILE,
            key_file=SERVER_KEYFILE,
        )
        try:
            client_a, transport_a = await _create_client("localhost", proxy_port)
            client_b, transport_b = await _create_client("localhost", proxy_port)
            try:
                # Client B goes first
                events_b = await client_b.get(
                    "localhost", proxy_port, "/resource",
                    extra_headers=[(b"authorization", b"Bearer tokenB")],
                )
                self.assertEqual(_get_response_headers(events_b).get(":status"), "200")

                await asyncio.sleep(0.05)

                # Client A sends its token — should get tokenB
                events_a = await client_a.get(
                    "localhost", proxy_port, "/resource",
                    extra_headers=[(b"authorization", b"Bearer tokenA")],
                )
                self.assertEqual(_get_response_headers(events_a).get(":status"), "200")

                headers_a = _parse_echo_headers(events_a)
                auth_at_backend = headers_a.get("authorization")
                self.assertEqual(
                    auth_at_backend,
                    "Bearer tokenB",
                    msg=(
                        f"Expected Client A's request to arrive with 'Bearer tokenB' "
                        f"but got {auth_at_backend!r}. "
                        f"Report:\n{proxy.instrumentation.report()}"
                    ),
                )
            finally:
                client_a.close()
                client_b.close()
                transport_a.close()
                transport_b.close()
        finally:
            proxy.stop()
            echo_server.close()

    @asynctest
    async def test_insert_all_populates_table(self):
        """insert_all mode records insertion events from both clients."""
        echo_server, echo_port = await _start_echo_server()
        proxy = FaultyProxy(mode="insert_all")
        proxy_port = await proxy.start(
            listen_port=0,
            backend_host="localhost",
            backend_port=echo_port,
            cert_file=SERVER_CERTFILE,
            key_file=SERVER_KEYFILE,
        )
        try:
            client_a, transport_a = await _create_client("localhost", proxy_port)
            client_b, transport_b = await _create_client("localhost", proxy_port)
            try:
                events_a = await client_a.get(
                    "localhost", proxy_port, "/",
                    extra_headers=[(b"x-client-a", b"value-a")],
                )
                self.assertEqual(_get_response_headers(events_a).get(":status"), "200")

                events_b = await client_b.get(
                    "localhost", proxy_port, "/",
                    extra_headers=[(b"x-client-b", b"value-b")],
                )
                self.assertEqual(_get_response_headers(events_b).get(":status"), "200")

                # Both clients' custom headers should appear as insertion events
                insertions = [
                    e for e in proxy.instrumentation.events
                    if isinstance(e, InsertionEvent)
                ]
                inserted_names = {ev.name for ev in insertions}
                self.assertIn(b"x-client-a", inserted_names)
                self.assertIn(b"x-client-b", inserted_names)

                # Entries from both clients should be in the shared table
                client_ids = {ev.client_id for ev in insertions}
                self.assertEqual(len(client_ids), 2)
            finally:
                client_a.close()
                client_b.close()
                transport_a.close()
                transport_b.close()
        finally:
            proxy.stop()
            echo_server.close()

    @asynctest
    async def test_instrumentation_insertion_events(self):
        """InsertionEvents have correct client_id, name, value, and abs_index."""
        echo_server, echo_port = await _start_echo_server()
        proxy = FaultyProxy(mode="insert_all")
        proxy_port = await proxy.start(
            listen_port=0,
            backend_host="localhost",
            backend_port=echo_port,
            cert_file=SERVER_CERTFILE,
            key_file=SERVER_KEYFILE,
        )
        try:
            client_a, transport_a = await _create_client("localhost", proxy_port)
            try:
                # Two requests from the same client with unique header names
                await client_a.get(
                    "localhost", proxy_port, "/first",
                    extra_headers=[(b"x-first", b"val-first")],
                )
                await client_a.get(
                    "localhost", proxy_port, "/second",
                    extra_headers=[(b"x-second", b"val-second")],
                )

                insertions = [
                    e for e in proxy.instrumentation.events
                    if isinstance(e, InsertionEvent)
                    and e.name in (b"x-first", b"x-second")
                ]
                # Both headers should be recorded
                self.assertEqual(len(insertions), 2)

                # All events are from client-0
                for ev in insertions:
                    self.assertEqual(ev.client_id, "client-0")

                # Absolute indices should be strictly increasing
                abs_indices = [ev.abs_index for ev in insertions]
                self.assertEqual(abs_indices, sorted(abs_indices))
                self.assertEqual(len(set(abs_indices)), 2)
            finally:
                client_a.close()
                transport_a.close()
        finally:
            proxy.stop()
            echo_server.close()

    @asynctest
    async def test_instrumentation_reference_events(self):
        """ReferenceEvents show referenced_value != intended_value on contamination."""
        echo_server, echo_port = await _start_echo_server()
        proxy = FaultyProxy(mode="naive_name_reuse")
        proxy_port = await proxy.start(
            listen_port=0,
            backend_host="localhost",
            backend_port=echo_port,
            cert_file=SERVER_CERTFILE,
            key_file=SERVER_KEYFILE,
        )
        try:
            client_a, transport_a = await _create_client("localhost", proxy_port)
            client_b, transport_b = await _create_client("localhost", proxy_port)
            try:
                # Client A inserts its token
                await client_a.get(
                    "localhost", proxy_port, "/",
                    extra_headers=[(b"authorization", b"Bearer tokenA")],
                )
                await asyncio.sleep(0.05)

                # Client B's request triggers contaminated reference
                await client_b.get(
                    "localhost", proxy_port, "/",
                    extra_headers=[(b"authorization", b"Bearer tokenB")],
                )

                # Find a ReferenceEvent for authorization from client-1
                ref_events = [
                    e for e in proxy.instrumentation.events
                    if isinstance(e, ReferenceEvent)
                    and e.name == b"authorization"
                    and e.client_id == "client-1"
                ]
                self.assertTrue(
                    len(ref_events) > 0,
                    "Expected at least one ReferenceEvent for 'authorization' from client-1",
                )
                ref = ref_events[0]
                self.assertEqual(ref.intended_value, b"Bearer tokenB")
                self.assertEqual(ref.referenced_value, b"Bearer tokenA")
                self.assertNotEqual(ref.referenced_value, ref.intended_value)
            finally:
                client_a.close()
                client_b.close()
                transport_a.close()
                transport_b.close()
        finally:
            proxy.stop()
            echo_server.close()
