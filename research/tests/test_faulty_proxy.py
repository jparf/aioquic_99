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

from research.faulty_proxy import (
    EvictionEvent, FaultyProxy, InsertionEvent, ProxyInstrumentation,
    ReferenceEvent, _SharedQpackReencoder,
)

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


def _parse_echo_headers_as_list(events: deque[H3Event]) -> list[tuple[bytes, bytes]]:
    """Parse the echo server's JSON body into a (name, value) bytes list.

    Suitable for passing directly to
    ``ProxyInstrumentation.record_backend_response()``.
    """
    body = _get_response_body(events)
    if not body:
        return []
    data = json.loads(body)
    return [
        (row[0].encode(), row[1].encode())
        for row in data.get("headers", [])
    ]


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
    async def test_naive_name_reuse_correct_value_delivered(self):
        """With correct encoding, client B receives its own token despite shared table.

        Client A's insertion seeds the shared table with 'authorization: tokenA'.
        Client B sends 'authorization: tokenB' — the proxy correctly emits a
        Literal Field Line with Name Reference (RFC 9204 §4.5.4): name from the
        table, literal value tokenB. The backend decodes tokenB, not tokenA.
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

                await asyncio.sleep(0.05)

                # Client B sends Authorization: Bearer tokenB
                events_b = await client_b.get(
                    "localhost", proxy_port, "/resource",
                    extra_headers=[(b"authorization", b"Bearer tokenB")],
                )
                self.assertEqual(_get_response_headers(events_b).get(":status"), "200")

                # Backend must receive tokenB — not tokenA from the shared table
                headers_b = _parse_echo_headers(events_b)
                auth_at_backend = headers_b.get("authorization")
                self.assertEqual(
                    auth_at_backend,
                    "Bearer tokenB",
                    msg=(
                        f"Expected 'Bearer tokenB' but got {auth_at_backend!r}. "
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
    async def test_naive_name_reuse_reversed_order_correct(self):
        """Reversed order: client B inserts first, client A still receives its own token."""
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
                # Client B goes first — inserts tokenB into shared table
                events_b = await client_b.get(
                    "localhost", proxy_port, "/resource",
                    extra_headers=[(b"authorization", b"Bearer tokenB")],
                )
                self.assertEqual(_get_response_headers(events_b).get(":status"), "200")

                await asyncio.sleep(0.05)

                # Client A sends tokenA — must receive tokenA, not tokenB
                events_a = await client_a.get(
                    "localhost", proxy_port, "/resource",
                    extra_headers=[(b"authorization", b"Bearer tokenA")],
                )
                self.assertEqual(_get_response_headers(events_a).get(":status"), "200")

                headers_a = _parse_echo_headers(events_a)
                auth_at_backend = headers_a.get("authorization")
                self.assertEqual(
                    auth_at_backend,
                    "Bearer tokenA",
                    msg=(
                        f"Expected 'Bearer tokenA' but got {auth_at_backend!r}. "
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
        """ReferenceEvents are only recorded for exact-match indexed references.

        With correct RFC 9204 encoding, a name-only match in the shared table
        produces a Literal with Name Reference — not an indexed reference — so
        no ReferenceEvent is emitted for client-1's authorization header.
        Client-0's first request (exact match after self-insert) records a clean
        ReferenceEvent via insert_all mode.
        """
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
                # Client A inserts and references its own token (insert_all mode)
                await client_a.get(
                    "localhost", proxy_port, "/",
                    extra_headers=[(b"x-token", b"valA")],
                )
                await asyncio.sleep(0.05)

                # Client B sends a different value for the same header name
                await client_b.get(
                    "localhost", proxy_port, "/",
                    extra_headers=[(b"x-token", b"valB")],
                )

                # Client A's reference to its own just-inserted entry is clean
                ref_a = [
                    e for e in proxy.instrumentation.events
                    if isinstance(e, ReferenceEvent)
                    and e.client_id == "client-0"
                ]
                self.assertEqual(len(ref_a), 1)
                self.assertEqual(ref_a[0].referenced_value, b"valA")
                self.assertEqual(ref_a[0].intended_value, b"valA")
                self.assertEqual(ref_a[0].root_cause, "clean")

                # Client B inserted its own value first (insert_all), so its
                # reference is also an exact match — clean
                ref_b = [
                    e for e in proxy.instrumentation.events
                    if isinstance(e, ReferenceEvent)
                    and e.client_id == "client-1"
                ]
                self.assertEqual(len(ref_b), 1)
                self.assertEqual(ref_b[0].referenced_value, b"valB")
                self.assertEqual(ref_b[0].intended_value, b"valB")
                self.assertEqual(ref_b[0].root_cause, "clean")
            finally:
                client_a.close()
                client_b.close()
                transport_a.close()
                transport_b.close()
        finally:
            proxy.stop()
            echo_server.close()

    @asynctest
    async def test_generate_report(self):
        """generate_report() shows both requests clean when encoding is correct.

        With the shared table and RFC-compliant encoding:
          - Client A inserts 'authorization: tokenA' into the shared table and the
            backend receives tokenA (clean).
          - Client B sends 'authorization: tokenB'; the proxy emits a Literal with
            Name Reference, so the backend also receives tokenB (clean).
        Both RequestRecords are CLEAN and there are no discrepancies.
        """
        echo_server, echo_port = await _start_echo_server()
        proxy = FaultyProxy(mode="naive_name_reuse", table_capacity=4096)
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
                    "localhost", proxy_port, "/resource",
                    extra_headers=[(b"authorization", b"Bearer tokenA")],
                )
                self.assertEqual(_get_response_headers(events_a).get(":status"), "200")
                proxy.instrumentation.record_backend_response(
                    "client-0", _parse_echo_headers_as_list(events_a)
                )

                await asyncio.sleep(0.05)

                events_b = await client_b.get(
                    "localhost", proxy_port, "/resource",
                    extra_headers=[(b"authorization", b"Bearer tokenB")],
                )
                self.assertEqual(_get_response_headers(events_b).get(":status"), "200")
                proxy.instrumentation.record_backend_response(
                    "client-1", _parse_echo_headers_as_list(events_b)
                )

                report = proxy.instrumentation.generate_report()

                # Header and summary
                self.assertIn("FAULTY PROXY REPORT", report)
                self.assertIn("naive_name_reuse", report)
                self.assertIn("Contaminated: 0", report)
                self.assertIn("Clean: 2", report)

                # Both requests clean
                self.assertIn("CLEAN", report)
                self.assertNotIn("*** CONTAMINATED ***", report)
                self.assertNotIn("DIFFERS FROM INTENDED", report)

                # Verify RequestRecord objects directly
                records = proxy.instrumentation.request_records
                self.assertEqual(len(records), 2)

                for rec in records:
                    self.assertFalse(rec.is_contaminated())
                    self.assertIsNotNone(rec.backend_headers)
                    self.assertEqual(rec.compute_discrepancies(), [])

                # Client B received its own token
                backend_b = dict(records[1].backend_headers or [])
                self.assertEqual(
                    backend_b.get(b"authorization"), b"Bearer tokenB"
                )

            finally:
                client_a.close()
                client_b.close()
                transport_a.close()
                transport_b.close()
        finally:
            proxy.stop()
            echo_server.close()

    def test_eviction_tracked_on_overflow(self):
        """EvictionEvent is recorded when a new insertion evicts an older entry.

        Unit test: calls _SharedQpackReencoder.encode_request() directly to avoid
        network-layer QPACK blocking complications.

        Entry sizes (name + value + 32 overhead):
          x-foo: bar  →  5 + 3 + 32 = 40 bytes
          x-baz: qux  →  5 + 3 + 32 = 40 bytes
        With capacity=60: first entry fits (40 ≤ 60); second needs 80 > 60 → evict first.
        """
        CAPACITY = 60
        instr = ProxyInstrumentation(mode="insert_all", capacity=CAPACITY)
        enc = _SharedQpackReencoder("insert_all", desired_capacity=CAPACITY,
                                    instrumentation=instr)
        enc.initialize(4096)  # simulate backend SETTINGS with large max

        base_headers = [
            (b":method", b"GET"), (b":scheme", b"https"),
            (b":authority", b"localhost"), (b":path", b"/"),
        ]

        # Request 0 — client-0 inserts x-foo:bar (fits, no eviction)
        enc.encode_request(base_headers + [(b"x-foo", b"bar")], "client-0")
        self.assertEqual(len(instr.eviction_events), 0)

        # Request 1 — client-1 inserts x-baz:qux (evicts x-foo:bar)
        enc.encode_request(base_headers + [(b"x-baz", b"qux")], "client-1")

        evictions = instr.eviction_events
        self.assertEqual(
            len(evictions), 1,
            f"Expected 1 eviction, got {len(evictions)}: "
            f"{[(e.evicted_name, e.evicted_value) for e in evictions]}",
        )
        ev = evictions[0]
        self.assertIsInstance(ev, EvictionEvent)
        self.assertEqual(ev.evicted_name, b"x-foo")
        self.assertEqual(ev.evicted_value, b"bar")
        self.assertEqual(ev.evicted_inserted_by, "client-0")
        self.assertEqual(ev.triggered_by_client_id, "client-1")
        self.assertEqual(ev.triggered_by_request_id, 1)

        # The eviction event should appear on the triggering request's record
        records = instr.request_records
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0].evictions, [])   # client-0's request caused no eviction
        self.assertEqual(len(records[1].evictions), 1)
        self.assertEqual(records[1].evictions[0].evicted_name, b"x-foo")

    def test_eviction_report_section(self):
        """generate_report() shows eviction count in the summary and per-request detail.

        Unit test: exercises report generation without any network stack.
        """
        CAPACITY = 60
        instr = ProxyInstrumentation(mode="insert_all", capacity=CAPACITY)
        enc = _SharedQpackReencoder("insert_all", desired_capacity=CAPACITY,
                                    instrumentation=instr)
        enc.initialize(4096)

        base_headers = [
            (b":method", b"GET"), (b":scheme", b"https"),
            (b":authority", b"localhost"), (b":path", b"/"),
        ]
        enc.encode_request(base_headers + [(b"x-foo", b"bar")], "client-0")
        enc.encode_request(base_headers + [(b"x-baz", b"qux")], "client-1")

        report = instr.generate_report()

        # Summary line should count the eviction
        self.assertIn("Evictions: 1", report)
        # Eviction detail: header name, owner, and keyword
        self.assertIn("EVICTED", report)
        self.assertIn("x-foo", report)
        self.assertIn("client-0", report)  # evicted_inserted_by
        # Capacity and mode in header
        self.assertIn("insert_all", report)
        self.assertIn("60", report)
