"""FaultyProxy — HTTP/3 reverse proxy with a shared QPACK re-encoder.

The proxy maintains a *single* ManualQpackEncoder for all backend requests.
Every forwarded request header block is re-encoded using this shared encoder,
enabling cross-client dynamic table contamination (the vulnerability).

Two encoding modes:

  naive_name_reuse — Phase 1: insert a header only when its *name* is not yet
                     in the dynamic table. Phase 2: reference by name, ignoring
                     whose value is stored. This causes value leakage between
                     clients as soon as two clients send the same header name.

  insert_all       — Phase 1: always insert every non-static header. Phase 2:
                     reference by name (picks most-recent). Useful for forced
                     eviction scenarios.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import ssl
from dataclasses import dataclass, field
from typing import Callable, Optional

import pylsqpack

from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.asyncio.server import QuicServer, serve
from aioquic.h3.connection import H3Connection, H3_ALPN, Setting
from aioquic.h3.events import DataReceived, H3Event, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import ProtocolNegotiated, QuicEvent

from .qpack_static_table import STATIC_TABLE
from .qpack_manual import ManualQpackEncoder, encode_integer

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Instrumentation data classes
# ---------------------------------------------------------------------------


@dataclass
class InsertionEvent:
    client_id: str
    abs_index: int      # absolute table index of the new entry
    name: bytes
    value: bytes


@dataclass
class ReferenceEvent:
    client_id: str
    rel_index: int          # relative table index used in the header block
    name: bytes
    referenced_value: bytes  # value actually in the table (may differ)
    intended_value: bytes    # value the client meant to send


class ProxyInstrumentation:
    """Collects insertion and reference events; produces a human-readable report."""

    def __init__(self) -> None:
        self.events: list[InsertionEvent | ReferenceEvent] = []

    def record_insertion(
        self, client_id: str, abs_index: int, name: bytes, value: bytes
    ) -> None:
        self.events.append(InsertionEvent(client_id, abs_index, name, value))

    def record_reference(
        self,
        client_id: str,
        rel_index: int,
        name: bytes,
        referenced_value: bytes,
        intended_value: bytes,
    ) -> None:
        self.events.append(
            ReferenceEvent(client_id, rel_index, name, referenced_value, intended_value)
        )

    def report(self) -> str:
        lines = [f"ProxyInstrumentation: {len(self.events)} event(s)"]
        for i, ev in enumerate(self.events):
            if isinstance(ev, InsertionEvent):
                lines.append(
                    f"  [{i}] INSERT  client={ev.client_id} abs={ev.abs_index}"
                    f" name={ev.name!r} value={ev.value!r}"
                )
            else:
                contaminated = ev.referenced_value != ev.intended_value
                flag = " *** CONTAMINATED ***" if contaminated else ""
                lines.append(
                    f"  [{i}] REF     client={ev.client_id} rel={ev.rel_index}"
                    f" name={ev.name!r}"
                    f" referenced={ev.referenced_value!r}"
                    f" intended={ev.intended_value!r}{flag}"
                )
        return "\n".join(lines)

    def clear(self) -> None:
        self.events.clear()


# ---------------------------------------------------------------------------
# _EncoderProxy — wraps pylsqpack.Encoder (C extension, read-only attrs)
# ---------------------------------------------------------------------------


class _EncoderProxy:
    """Wraps pylsqpack.Encoder, intercepting apply_settings and feed_decoder.

    - apply_settings() calls the on_settings callback then returns b"" so
      pylsqpack never uses the dynamic table (capacity stays 0 from its POV).
    - feed_decoder() logs data without forwarding — prevents DecoderStreamError
      since our manual entries are unknown to pylsqpack.
    - Everything else is delegated to the real encoder via __getattr__.
    """

    def __init__(
        self,
        real_encoder: pylsqpack.Encoder,
        on_settings: Callable[[int, int], None],
        decoder_log: list[bytes],
    ) -> None:
        object.__setattr__(self, "_real", real_encoder)
        object.__setattr__(self, "_on_settings", on_settings)
        object.__setattr__(self, "_decoder_log", decoder_log)

    def apply_settings(self, max_table_capacity: int, blocked_streams: int) -> bytes:
        self._on_settings(max_table_capacity, blocked_streams)
        return b""

    def feed_decoder(self, data: bytes) -> None:
        logger.debug("_EncoderProxy: swallowing %d bytes of decoder stream", len(data))
        self._decoder_log.append(data)

    def __getattr__(self, name: str):
        return getattr(self._real, name)


# ---------------------------------------------------------------------------
# _SharedQpackReencoder — core of the vulnerability
# ---------------------------------------------------------------------------


class _SharedQpackReencoder:
    """Shared QPACK encoder for all backend requests.

    A single ManualQpackEncoder is used for ALL clients. When multiple clients
    send headers with the same name, the shared dynamic table causes value
    leakage: one client's value is referenced in another client's header block.
    """

    def __init__(
        self,
        mode: str,
        desired_capacity: int,
        instrumentation: ProxyInstrumentation,
    ) -> None:
        if mode not in ("naive_name_reuse", "insert_all"):
            raise ValueError(f"Unknown mode: {mode!r}")
        self._mode = mode
        self._desired_capacity = desired_capacity
        self._instrumentation = instrumentation
        # Initialized with max_table_capacity=0; updated when backend SETTINGS arrive.
        self._encoder = ManualQpackEncoder(max_table_capacity=desired_capacity)
        self._initialized = False

    def initialize(self, peer_max_capacity: int) -> bytes:
        """Called when backend SETTINGS arrive. Sets the actual table capacity.

        Returns the Set Dynamic Table Capacity encoder stream instruction bytes,
        or b"" if capacity is 0.
        """
        if peer_max_capacity:
            actual = min(self._desired_capacity, peer_max_capacity)
        else:
            actual = 0
        self._encoder.max_table_capacity = actual
        self._initialized = True
        if actual == 0:
            return b""
        return self._encoder.set_capacity(actual)

    def encode_request(
        self, headers: list[tuple[bytes, bytes]], client_id: str
    ) -> tuple[bytes, bytes]:
        """Re-encode headers for the backend using the shared table.

        Returns (encoder_stream_instructions, header_block_bytes).
        """
        encoder_instructions = bytearray()

        if self._mode == "naive_name_reuse":
            for name, value in headers:
                if name.startswith(b":"):
                    continue  # pseudo-headers: never insert
                if self._static_exact(name, value) is not None:
                    continue  # already in static table
                if self._dynamic_by_name(name) is not None:
                    continue  # name already in table — reuse whatever is there
                instr = self._try_insert(name, value)
                if instr:
                    encoder_instructions.extend(instr)
                    abs_idx = self._encoder.table.insert_count - 1
                    self._instrumentation.record_insertion(client_id, abs_idx, name, value)

        elif self._mode == "insert_all":
            for name, value in headers:
                if name.startswith(b":"):
                    continue
                if self._static_exact(name, value) is not None:
                    continue
                instr = self._try_insert(name, value)
                if instr:
                    encoder_instructions.extend(instr)
                    abs_idx = self._encoder.table.insert_count - 1
                    self._instrumentation.record_insertion(client_id, abs_idx, name, value)

        # Phase 2: build header block
        header_entries = []
        has_dynamic = False
        for name, value in headers:
            static_idx = self._static_exact(name, value)
            if static_idx is not None:
                header_entries.append(("static", static_idx, name, value))
            else:
                dyn = self._dynamic_by_name(name)
                if dyn is not None:
                    rel_idx, stored_value = dyn
                    self._instrumentation.record_reference(
                        client_id, rel_idx, name, stored_value, value
                    )
                    header_entries.append(("dynamic", rel_idx, name, stored_value))
                    has_dynamic = True
                else:
                    header_entries.append(("literal", 0, name, value))

        ric = self._encoder.table.insert_count if has_dynamic else 0
        header_block = self._build_header_block(header_entries, ric)

        return bytes(encoder_instructions), header_block

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _try_insert(self, name: bytes, value: bytes) -> Optional[bytes]:
        """Attempt to insert (name, value) into the dynamic table.

        Prefers insert_name_ref if the name is in the static table.
        Returns the wire-format instruction bytes, or None if it doesn't fit.
        """
        if self._encoder.table.capacity == 0:
            return None
        try:
            static_idx = self._static_name_only(name)
            if static_idx is not None:
                return self._encoder.insert_name_ref(static_idx, value, is_static=True)
            else:
                return self._encoder.insert_literal(name, value)
        except ValueError:
            return None  # entry too large for current capacity

    def _static_exact(self, name: bytes, value: bytes) -> Optional[int]:
        """Return the 0-based static table index for an exact (name, value) match."""
        for i, (sn, sv) in enumerate(STATIC_TABLE):
            if sn == name and sv == value:
                return i
        return None

    def _static_name_only(self, name: bytes) -> Optional[int]:
        """Return the 0-based static table index for the first name match."""
        for i, (sn, _) in enumerate(STATIC_TABLE):
            if sn == name:
                return i
        return None

    def _dynamic_by_name(self, name: bytes) -> Optional[tuple[int, bytes]]:
        """Return (relative_index, stored_value) for the first name match.

        Relative index 0 = most recently inserted entry (entries[0]).
        With Base = RIC = insert_count, relative_index equals the position
        in the entries list.
        """
        for i, entry in enumerate(self._encoder.table.entries):
            if entry.name == name:
                return (i, entry.value)
        return None

    def _build_header_block(
        self,
        header_entries: list,
        ric: int,
    ) -> bytes:
        """Encode a QPACK header block.

        header_entries items:
          ("static",  idx,     name, value)
          ("dynamic", rel_idx, name, stored_value)
          ("literal", 0,       name, value)

        Encoding per RFC 9204:
          Prefix: encode_integer(encoded_ric, 8) + 0x00 (S=0, DeltaBase=0)
          Static ref:  encode_integer(idx, 6) with byte[0] |= 0xC0
          Dynamic ref: encode_integer(rel, 6) with byte[0] |= 0x80  (T=0, pre-base)
          Literal:     0x20|encode_integer(len(name),3) + name + encode_integer(len(val),7) + val
        """
        buf = bytearray()

        # --- Prefix ---
        if ric == 0:
            buf.extend(b"\x00\x00")
        else:
            capacity = self._encoder.table.capacity
            max_entries = max(1, capacity // 32)
            encoded_ric = (ric % (2 * max_entries)) + 1
            ric_bytes = bytearray(encode_integer(encoded_ric, 8))
            buf.extend(ric_bytes)
            buf.extend(b"\x00")  # S=0, Delta Base=0

        # --- Field representations ---
        for kind, arg, name, value in header_entries:
            if kind == "static":
                idx = arg
                b = bytearray(encode_integer(idx, 6))
                b[0] |= 0xC0
                buf.extend(b)

            elif kind == "dynamic":
                rel_idx = arg
                b = bytearray(encode_integer(rel_idx, 6))
                b[0] |= 0x80  # T=0, pre-base indexed field line
                buf.extend(b)

            else:  # "literal"
                # Literal Field Line with Literal Name (RFC 9204 §4.5.6)
                name_len_b = bytearray(encode_integer(len(name), 3))
                name_len_b[0] |= 0x20  # opcode bits 7-5 = 001
                buf.extend(name_len_b)
                buf.extend(name)
                val_len_b = encode_integer(len(value), 7)
                buf.extend(val_len_b)
                buf.extend(value)

        return bytes(buf)


# ---------------------------------------------------------------------------
# _BackendH3Connection — overrides _encode_headers to use shared re-encoder
# ---------------------------------------------------------------------------


class _BackendH3Connection(H3Connection):
    """H3Connection subclass that re-encodes headers through the shared table."""

    def __init__(
        self,
        quic: QuicConnection,
        shared_qpack: _SharedQpackReencoder,
        on_settings_ready: Callable[[], None],
    ) -> None:
        self._shared_qpack = shared_qpack
        self._on_settings_ready = on_settings_ready
        self._decoder_log: list[bytes] = []
        self._active_client_id: str = ""

        # super().__init__ calls _init_connection() which sends SETTINGS.
        # It creates self._encoder = pylsqpack.Encoder() before we can intercept.
        super().__init__(quic)

        # Replace encoder with our proxy AFTER super().__init__
        real_encoder = self._encoder
        self._encoder = _EncoderProxy(  # type: ignore
            real_encoder,
            on_settings=self._handle_peer_settings,
            decoder_log=self._decoder_log,
        )

    def _handle_peer_settings(self, max_cap: int, blocked: int) -> None:
        """Called by _EncoderProxy when backend SETTINGS arrive."""
        assert self._local_encoder_stream_id is not None
        instructions = self._shared_qpack.initialize(max_cap)
        if instructions:
            self._quic.send_stream_data(self._local_encoder_stream_id, instructions)
        self._on_settings_ready()

    def _encode_headers(self, stream_id: int, headers) -> bytes:
        """Override: use shared QPACK re-encoder instead of pylsqpack."""
        assert self._local_encoder_stream_id is not None
        encoder_instr, header_block = self._shared_qpack.encode_request(
            list(headers), self._active_client_id
        )
        if encoder_instr:
            self._quic.send_stream_data(self._local_encoder_stream_id, encoder_instr)
        return header_block

    def send_for_client(
        self,
        stream_id: int,
        headers: list[tuple[bytes, bytes]],
        client_id: str,
        end_stream: bool = False,
    ) -> None:
        """Send headers tagged with the originating client ID."""
        self._active_client_id = client_id
        self.send_headers(stream_id, headers, end_stream=end_stream)
        self._active_client_id = ""


# ---------------------------------------------------------------------------
# _BackendProtocol
# ---------------------------------------------------------------------------


class _BackendProtocol(QuicConnectionProtocol):
    """Proxy's outbound H3 connection to the backend server."""

    def __init__(self, *args, shared_qpack: _SharedQpackReencoder, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._shared_qpack = shared_qpack
        self._http: Optional[_BackendH3Connection] = None
        # backend_stream_id -> (frontend_protocol, client_stream_id)
        self._routes: dict[int, tuple] = {}
        self._settings_event = asyncio.Event()

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, ProtocolNegotiated):
            if event.alpn_protocol in H3_ALPN:
                self._http = _BackendH3Connection(
                    self._quic,
                    shared_qpack=self._shared_qpack,
                    on_settings_ready=self._settings_event.set,
                )
        if self._http is not None:
            for h3ev in self._http.handle_event(event):
                self._on_h3_event(h3ev)

    def _on_h3_event(self, event: H3Event) -> None:
        if isinstance(event, HeadersReceived):
            route = self._routes.get(event.stream_id)
            if route:
                frontend, client_sid = route
                assert frontend._http is not None
                frontend._http.send_headers(
                    stream_id=client_sid,
                    headers=event.headers,
                    end_stream=event.stream_ended,
                )
                frontend.transmit()
                if event.stream_ended:
                    del self._routes[event.stream_id]
        elif isinstance(event, DataReceived):
            route = self._routes.get(event.stream_id)
            if route:
                frontend, client_sid = route
                assert frontend._http is not None
                frontend._http.send_data(
                    stream_id=client_sid,
                    data=event.data,
                    end_stream=event.stream_ended,
                )
                frontend.transmit()
                if event.stream_ended:
                    self._routes.pop(event.stream_id, None)

    async def wait_ready(self) -> None:
        """Wait for TLS handshake AND backend SETTINGS to be processed."""
        await self.wait_connected()
        await asyncio.wait_for(self._settings_event.wait(), timeout=10.0)

    def forward_request(
        self,
        frontend: "_FrontendProtocol",
        client_sid: int,
        headers: list[tuple[bytes, bytes]],
        client_id: str,
        data: bytes = b"",
        stream_ended: bool = True,
    ) -> int:
        """Open a new backend stream and forward the re-encoded headers."""
        assert self._http is not None
        sid = self._quic.get_next_available_stream_id()
        self._routes[sid] = (frontend, client_sid)
        end_headers = stream_ended and not data
        self._http.send_for_client(sid, headers, client_id, end_stream=end_headers)
        if data:
            self._http.send_data(stream_id=sid, data=data, end_stream=stream_ended)
        self.transmit()
        return sid


# ---------------------------------------------------------------------------
# _PendingRequest
# ---------------------------------------------------------------------------


class _PendingRequest:
    """Buffers a client request until the backend connection is ready."""
    __slots__ = ("headers", "data", "stream_ended", "client_id")

    def __init__(
        self, headers: list, stream_ended: bool, client_id: str
    ) -> None:
        self.headers = headers
        self.data = b""
        self.stream_ended = stream_ended
        self.client_id = client_id


# ---------------------------------------------------------------------------
# _FrontendProtocol
# ---------------------------------------------------------------------------

_client_counter = 0


class _FrontendProtocol(QuicConnectionProtocol):
    """Accepts incoming client H3 connections and forwards requests via backend."""

    def __init__(self, *args, proxy: "FaultyProxy", **kwargs) -> None:
        super().__init__(*args, **kwargs)
        global _client_counter
        _client_counter += 1
        self._client_id = f"client-{_client_counter - 1}"
        self._http: Optional[H3Connection] = None
        self._proxy = proxy
        self._backend: Optional[_BackendProtocol] = None
        self._pending: dict[int, _PendingRequest] = {}
        self._client_to_backend: dict[int, int] = {}

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, ProtocolNegotiated):
            if event.alpn_protocol in H3_ALPN:
                self._http = H3Connection(self._quic)
                asyncio.ensure_future(self._setup_backend())
        if self._http is not None:
            for h3ev in self._http.handle_event(event):
                self._on_h3_event(h3ev)

    async def _setup_backend(self) -> None:
        try:
            self._backend = await self._proxy.get_backend()
            for client_sid, req in self._pending.items():
                backend_sid = self._backend.forward_request(
                    self, client_sid, req.headers, req.client_id,
                    req.data, req.stream_ended,
                )
                if not req.stream_ended:
                    self._client_to_backend[client_sid] = backend_sid
            self._pending.clear()
        except Exception as exc:
            logger.error("[proxy] Backend setup failed: %s", exc)

    def _on_h3_event(self, event: H3Event) -> None:
        if isinstance(event, HeadersReceived):
            if self._backend is not None:
                backend_sid = self._backend.forward_request(
                    self, event.stream_id, event.headers, self._client_id,
                    stream_ended=event.stream_ended,
                )
                if not event.stream_ended:
                    self._client_to_backend[event.stream_id] = backend_sid
            else:
                self._pending[event.stream_id] = _PendingRequest(
                    headers=event.headers,
                    stream_ended=event.stream_ended,
                    client_id=self._client_id,
                )
        elif isinstance(event, DataReceived):
            if event.stream_id in self._client_to_backend:
                assert self._backend is not None
                assert self._backend._http is not None
                backend_sid = self._client_to_backend[event.stream_id]
                self._backend._http.send_data(
                    stream_id=backend_sid,
                    data=event.data,
                    end_stream=event.stream_ended,
                )
                self._backend.transmit()
                if event.stream_ended:
                    del self._client_to_backend[event.stream_id]
            elif event.stream_id in self._pending:
                self._pending[event.stream_id].data += event.data
                if event.stream_ended:
                    self._pending[event.stream_id].stream_ended = True


# ---------------------------------------------------------------------------
# FaultyProxy — top-level orchestrator
# ---------------------------------------------------------------------------


class FaultyProxy:
    """HTTP/3 reverse proxy with a shared QPACK re-encoder (the vulnerability).

    All frontend clients share a single backend H3 connection with a single
    QPACK encoder. Forwarded headers are re-encoded using that shared table,
    enabling cross-client dynamic table contamination.

    Args:
        mode: ``"naive_name_reuse"`` (primary attack) or ``"insert_all"``.
        table_capacity: Desired dynamic table capacity in bytes.
    """

    def __init__(
        self,
        mode: str = "naive_name_reuse",
        table_capacity: int = 4096,
    ) -> None:
        if mode not in ("naive_name_reuse", "insert_all"):
            raise ValueError(f"mode must be 'naive_name_reuse' or 'insert_all', got {mode!r}")
        self._mode = mode
        self._table_capacity = table_capacity
        self._instrumentation = ProxyInstrumentation()
        self._shared_qpack = _SharedQpackReencoder(
            mode=mode,
            desired_capacity=table_capacity,
            instrumentation=self._instrumentation,
        )
        self._server: Optional[QuicServer] = None
        self._port: Optional[int] = None
        self._backend_host: Optional[str] = None
        self._backend_port: Optional[int] = None
        self._backend_addr = None
        self._backend_transports: list = []
        # Shared backend Future — prevents duplicate connections on concurrent connects
        self._shared_future: Optional[asyncio.Future] = None

    async def start(
        self,
        listen_port: int,
        backend_host: str,
        backend_port: int,
        cert_file: str,
        key_file: str,
    ) -> int:
        """Start the proxy. Returns the actual listening port."""
        global _client_counter
        _client_counter = 0  # reset for each test

        self._backend_host = backend_host
        self._backend_port = backend_port

        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(backend_host, backend_port, type=socket.SOCK_DGRAM)
        addr = infos[0][4]
        if len(addr) == 2:
            addr = ("::ffff:" + addr[0], addr[1], 0, 0)
        self._backend_addr = addr

        config = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN)
        config.load_cert_chain(cert_file, key_file)
        self._server = await serve(
            host="::",
            port=listen_port,
            configuration=config,
            create_protocol=lambda *a, **kw: _FrontendProtocol(*a, proxy=self, **kw),
        )
        assert self._server._transport is not None
        port: int = self._server._transport.get_extra_info("sockname")[1]
        self._port = port
        return port

    def stop(self) -> None:
        """Stop the proxy and close all backend connections."""
        if self._server:
            self._server.close()
        for transport in self._backend_transports:
            transport.close()
        self._backend_transports.clear()
        self._shared_future = None

    @property
    def port(self) -> int:
        assert self._port is not None
        return self._port

    @property
    def mode(self) -> str:
        return self._mode

    @property
    def instrumentation(self) -> ProxyInstrumentation:
        return self._instrumentation

    async def get_backend(self) -> _BackendProtocol:
        """Return the single shared backend connection (create on first call)."""
        if self._shared_future is None:
            loop = asyncio.get_running_loop()
            self._shared_future = loop.create_future()
            backend = await self._connect_backend()
            self._shared_future.set_result(backend)
        return await asyncio.shield(self._shared_future)

    async def _connect_backend(self) -> _BackendProtocol:
        config = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
        config.verify_mode = ssl.CERT_NONE
        config.server_name = self._backend_host

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

        loop = asyncio.get_running_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: _BackendProtocol(connection, shared_qpack=self._shared_qpack),
            sock=sock,
        )
        self._backend_transports.append(transport)
        protocol: _BackendProtocol = protocol
        protocol.connect(self._backend_addr)
        await protocol.wait_ready()

        logger.info("[proxy] Backend connection ready (mode=%s)", self._mode)
        return protocol
