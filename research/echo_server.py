"""Standalone HTTP/3 echo server for QPACK research scenarios.

The echo server receives HTTP/3 requests and returns all decoded request
headers as a JSON body. Every request is recorded in a persistent log that
scenario orchestrators and tests can inspect programmatically.

Typical use
-----------
    server = EchoServer()
    port = await server.start(cert_file=..., key_file=...)

    # ... run scenario ...

    log = server.get_log()          # list[RequestRecord]
    await server.stop()

Each ``RequestRecord`` in the log contains:

- ``seq``        — zero-based request sequence number (across all connections)
- ``timestamp``  — ``asyncio.get_event_loop().time()`` when headers arrived
- ``client_addr``— remote (host, port) of the QUIC connection
- ``headers``    — list of (name: bytes, value: bytes) as received by the server
- ``path``       — decoded ``b":path"`` value (convenience)
- ``method``     — decoded ``b":method"`` value (convenience)
- ``connection_id`` — monotonically increasing integer per QUIC connection
"""

from __future__ import annotations

import asyncio
import json
import socket
import ssl
from dataclasses import dataclass, field
from typing import Any

from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.asyncio.server import QuicServer, serve
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, H3Event, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ProtocolNegotiated, QuicEvent


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class RequestRecord:
    """A single request received by the echo server."""

    seq: int                              # global sequence (0-based)
    timestamp: float                      # asyncio loop time
    connection_id: int                    # monotonic per-QUIC-connection counter
    client_addr: tuple[str, int]          # (host, port) of remote peer
    headers: list[tuple[bytes, bytes]]    # all headers as received (bytes)
    method: str = ""                      # decoded :method
    path: str = ""                        # decoded :path
    authority: str = ""                   # decoded :authority

    def header_dict(self) -> dict[str, str]:
        """Return headers as a str→str dict (last-wins for duplicates)."""
        return {
            k.decode(errors="replace"): v.decode(errors="replace")
            for k, v in self.headers
        }

    def get_header(self, name: str, default: str = "") -> str:
        """Return the first header value matching *name* (case-insensitive)."""
        target = name.lower().encode()
        for k, v in self.headers:
            if k.lower() == target:
                return v.decode(errors="replace")
        return default


# ---------------------------------------------------------------------------
# Internal QUIC/H3 protocol
# ---------------------------------------------------------------------------


class _EchoProtocol(QuicConnectionProtocol):
    """H3 server protocol that logs requests and returns headers as JSON."""

    # Shared across all protocol instances; set by EchoServer before serving.
    _log: list[RequestRecord] = []
    _seq_counter: list[int] = [0]         # mutable singleton for atomic increment
    _conn_counter: list[int] = [0]        # monotonic connection counter

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._http: H3Connection | None = None
        # Use type(self) so _BoundProtocol subclasses see their own counters.
        cls = type(self)
        cls._conn_counter[0] += 1
        self._connection_id: int = cls._conn_counter[0]

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
            self._handle_request(event)

    def _handle_request(self, event: HeadersReceived) -> None:
        assert self._http is not None

        # --- Log the request ---
        cls = type(self)
        seq = cls._seq_counter[0]
        cls._seq_counter[0] += 1

        loop = asyncio.get_event_loop()
        ts = loop.time()

        # Extract pseudo-headers for convenience fields
        method = ""
        path = ""
        authority = ""
        for k, v in event.headers:
            if k == b":method":
                method = v.decode(errors="replace")
            elif k == b":path":
                path = v.decode(errors="replace")
            elif k == b":authority":
                authority = v.decode(errors="replace")

        # Attempt to get the remote address from the underlying transport.
        # QuicConnectionProtocol stores the peer address in the QUIC connection.
        try:
            addr = self._quic._network_paths[0].addr
            if len(addr) == 4:
                # IPv6 4-tuple → (host, port, flow, scope)
                client_addr = (addr[0], addr[1])
            else:
                client_addr = (addr[0], addr[1])
        except Exception:
            client_addr = ("unknown", 0)

        record = RequestRecord(
            seq=seq,
            timestamp=ts,
            connection_id=self._connection_id,
            client_addr=client_addr,
            headers=list(event.headers),
            method=method,
            path=path,
            authority=authority,
        )
        cls._log.append(record)

        # --- Build JSON response body ---
        headers_list = [
            [k.decode(errors="replace"), v.decode(errors="replace")]
            for k, v in event.headers
        ]
        body = json.dumps({"headers": headers_list, "seq": seq}).encode()

        # --- Send response ---
        self._http.send_headers(
            stream_id=event.stream_id,
            headers=[
                (b":status", b"200"),
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
            ],
        )
        self._http.send_data(
            stream_id=event.stream_id,
            data=body,
            end_stream=True,
        )
        self.transmit()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class EchoServer:
    """Standalone HTTP/3 echo server.

    Usage::

        server = EchoServer()
        port = await server.start(cert_file="...", key_file="...")
        # ... exercise the stack ...
        records = server.get_log()   # list[RequestRecord]
        await server.stop()

    The log is shared across all connections accepted by this server instance.
    Calling ``clear_log()`` resets both the records and the sequence counter.
    """

    def __init__(self) -> None:
        self._server: QuicServer | None = None
        self._port: int = 0
        # Each EchoServer instance gets its own isolated log list.
        self._log: list[RequestRecord] = []
        self._seq: list[int] = [0]
        self._conn_count: list[int] = [0]

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(
        self,
        cert_file: str,
        key_file: str,
        host: str = "::",
        port: int = 0,
    ) -> int:
        """Start listening. Returns the bound port (useful when port=0)."""
        if self._server is not None:
            raise RuntimeError("EchoServer is already running")

        # Wire the shared mutable singletons to this instance's storage so
        # each EchoServer is fully isolated even within the same process.
        log = self._log
        seq = self._seq
        conn_count = self._conn_count

        class _BoundProtocol(_EchoProtocol):
            _log = log           # type: ignore[assignment]
            _seq_counter = seq   # type: ignore[assignment]
            _conn_counter = conn_count  # type: ignore[assignment]

        config = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN)
        config.load_cert_chain(cert_file, key_file)

        self._server = await serve(
            host=host,
            port=port,
            configuration=config,
            create_protocol=_BoundProtocol,
        )
        assert self._server._transport is not None
        sockname = self._server._transport.get_extra_info("sockname")
        self._port = sockname[1]
        return self._port

    async def stop(self) -> None:
        """Close the server and release the port."""
        if self._server is not None:
            self._server.close()
            self._server = None

    # Synchronous alias for use in test tearDown / finally blocks
    def close(self) -> None:
        """Synchronous close — safe to call from non-async contexts."""
        if self._server is not None:
            self._server.close()
            self._server = None

    # ------------------------------------------------------------------
    # Log access
    # ------------------------------------------------------------------

    def get_log(self) -> list[RequestRecord]:
        """Return a snapshot of all requests received so far."""
        return list(self._log)

    def clear_log(self) -> None:
        """Reset the request log and sequence counter."""
        self._log.clear()
        self._seq[0] = 0

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def port(self) -> int:
        """The port the server is listening on (0 if not started)."""
        return self._port

    @property
    def connection_count(self) -> int:
        """Number of QUIC connections accepted since start (or last clear)."""
        return self._conn_count[0]

    @property
    def request_count(self) -> int:
        """Number of requests logged since start (or last clear_log)."""
        return len(self._log)

    # ------------------------------------------------------------------
    # Convenience helpers for scenario orchestrators
    # ------------------------------------------------------------------

    def last_request(self) -> RequestRecord | None:
        """Return the most recently received request, or None."""
        return self._log[-1] if self._log else None

    def requests_for_path(self, path: str) -> list[RequestRecord]:
        """Return all requests matching *path*."""
        return [r for r in self._log if r.path == path]

    def requests_from_connection(self, connection_id: int) -> list[RequestRecord]:
        """Return all requests from a particular connection."""
        return [r for r in self._log if r.connection_id == connection_id]

    def parse_headers(self, record: RequestRecord) -> dict[str, str]:
        """Return headers from *record* as a str→str dict."""
        return record.header_dict()
