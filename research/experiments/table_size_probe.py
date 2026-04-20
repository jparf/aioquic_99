"""Table size discovery via QPACK encoder stream observation.

An observer who can read the encoder stream (the QPACK insertion instructions
the proxy sends to the backend server) can determine the proxy's shared dynamic
table capacity without ever accessing the proxy directly.

Algorithm
---------
1. Insert a "canary" (unique name-value pair) and confirm it appears as an
   insert_literal instruction in the encoder stream.

2. Fill loop: insert minimal unique "filler" headers one at a time.
   After each filler, re-probe the canary (send the same name-value pair again).

   Two outcomes at the proxy:
     Canary still in table → proxy finds exact match → no new insertion →
       encoder stream unchanged for that request.
     Canary evicted        → proxy re-inserts canary → new insert_literal
       instruction → visible increment in the encoder stream instruction count.

3. When eviction is detected at filler-N, the table capacity is bounded by:
     lower = CANARY_SIZE + N × FILLER_SIZE
     upper = lower + FILLER_SIZE − 1
   because the table held the canary + N fillers (lower bytes) without
   evicting the canary, but could not hold canary + N fillers + one more filler.

Usage
-----
    cd aioquic_99
    python -m research.experiments.table_size_probe
"""

from __future__ import annotations

import asyncio
import os
import sys
import socket
import ssl
from collections import deque

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection, Setting
from aioquic.h3.events import H3Event
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import QuicEvent

from research.echo_server import EchoServer, EncStreamRecord
from research.faulty_proxy import FaultyProxy
from research.qpack_manual import ENTRY_OVERHEAD

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_HERE = os.path.dirname(os.path.abspath(__file__))
CERT = os.path.join(_HERE, "..", "..", "tests", "ssl_cert.pem")
KEY  = os.path.join(_HERE, "..", "..", "tests", "ssl_key.pem")

# ---------------------------------------------------------------------------
# Experiment parameters
# ---------------------------------------------------------------------------

TABLE_CAPACITY = 4096   # proxy's actual table size — the value we are measuring
MAX_FILLERS    = 500    # safety limit

# Canary: a single unique name-value pair inserted first to act as a sentinel.
CANARY_NAME  = b"x-canary"
CANARY_VALUE = b"sentinel0"
CANARY_SIZE  = len(CANARY_NAME) + len(CANARY_VALUE) + ENTRY_OVERHEAD  # 49 bytes

# Fillers: minimal unique entries, one per probe step.
# Name format p{NNN} is 4 bytes; value is 1 byte; each entry costs 37 bytes.
FILLER_VALUE = b"q"
FILLER_SIZE  = 4 + len(FILLER_VALUE) + ENTRY_OVERHEAD  # 37 bytes (for NNN = 000–499)


def filler_name(i: int) -> bytes:
    return f"p{i:03d}".encode()


# ---------------------------------------------------------------------------
# Minimal H3 client (same pattern as orchestrator._H3Client)
# ---------------------------------------------------------------------------


class _ZeroCapEncoder:
    """Wraps pylsqpack.Encoder so it never uses the dynamic table.

    Two-directional protection:
    - apply_settings(): always passes capacity=0 to pylsqpack regardless of
      what the peer (proxy) advertises, so the client encoder never inserts
      request headers into a dynamic table.
    - feed_decoder(): swallowed — with 0 capacity there are no decoder acks.
    """

    def __init__(self, real) -> None:
        object.__setattr__(self, "_real", real)

    def apply_settings(self, max_table_capacity: int, blocked_streams: int) -> bytes:
        return self._real.apply_settings(0, 0)

    def feed_decoder(self, data: bytes) -> None:
        pass

    def __getattr__(self, name: str):
        return getattr(self._real, name)


class _NoTableH3Connection(H3Connection):
    """H3Connection that uses no dynamic table in either direction.

    - Advertises max_table_capacity=0 to the proxy → proxy's response encoder
      never uses dynamic table entries for this client (no encoder stream
      instructions, no blocking race with DATA frames).
    - Wraps its own pylsqpack encoder with _ZeroCapEncoder → the client's
      request encoder never uses dynamic table entries either (no encoder
      stream instructions sent to proxy, so proxy decoder never blocks).
    """

    def __init__(self, quic) -> None:
        super().__init__(quic)
        self._encoder = _ZeroCapEncoder(self._encoder)

    def _get_local_settings(self) -> dict:
        settings = super()._get_local_settings()
        settings[Setting.QPACK_MAX_TABLE_CAPACITY] = 0
        settings[Setting.QPACK_BLOCKED_STREAMS] = 0
        return settings


class _H3Client(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._request_events: dict[int, deque[H3Event]] = {}
        self._request_waiters: dict[int, asyncio.Future] = {}
        self._http: H3Connection = _NoTableH3Connection(self._quic)

    def quic_event_received(self, event: QuicEvent) -> None:
        for h3ev in self._http.handle_event(event):
            sid = h3ev.stream_id  # type: ignore[attr-defined]
            self._request_events.setdefault(sid, deque()).append(h3ev)
            if getattr(h3ev, "stream_ended", False) and sid in self._request_waiters:
                waiter = self._request_waiters.pop(sid)
                if not waiter.done():
                    waiter.set_result(self._request_events.pop(sid))

    async def get(
        self,
        host: str,
        port: int,
        path: str,
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


async def _connect_client(host: str, port: int) -> tuple[_H3Client, asyncio.BaseTransport]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
    addr = infos[0][4]
    if len(addr) == 2:
        addr = ("::ffff:" + addr[0], addr[1], 0, 0)

    config = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
    config.verify_mode = ssl.CERT_NONE
    config.server_name = host

    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        sock.bind(("::", 0, 0, 0))
    except Exception:
        sock.close()
        raise

    transport, protocol = await loop.create_datagram_endpoint(
        lambda: _H3Client(QuicConnection(configuration=config)),
        sock=sock,
    )
    protocol: _H3Client = protocol
    protocol.connect(addr)
    await protocol.wait_connected()
    return protocol, transport


# ---------------------------------------------------------------------------
# Detection helper
# ---------------------------------------------------------------------------


def _count_canary_insertions(enc_log: list[EncStreamRecord]) -> int:
    """Count how many times the canary has appeared as an insert_literal instruction."""
    count = 0
    for record in enc_log:
        for instr in record.instructions:
            if (
                instr[0] == "insert_literal"
                and instr[1] == CANARY_NAME
                and instr[2] == CANARY_VALUE
            ):
                count += 1
    return count


# ---------------------------------------------------------------------------
# Experiment
# ---------------------------------------------------------------------------


async def run() -> None:
    print("=" * 70)
    print("QPACK TABLE SIZE DISCOVERY VIA ENCODER STREAM")
    print("=" * 70)
    print()
    print("The faulty proxy shares a single QPACK dynamic table across all")
    print("clients. The encoder stream — QPACK insertion instructions sent")
    print("from the proxy to the backend server — is observable in this setup.")
    print("By watching when a known 'canary' entry is evicted and re-inserted,")
    print("we can deduce the table capacity to within one filler entry's size.")
    print()

    server = EchoServer()
    proxy  = FaultyProxy(table_capacity=TABLE_CAPACITY)

    echo_port  = await server.start(cert_file=CERT, key_file=KEY)
    proxy_port = await proxy.start(
        listen_port=0,
        backend_host="localhost",
        backend_port=echo_port,
        cert_file=CERT,
        key_file=KEY,
    )

    client, transport = await _connect_client("localhost", proxy_port)

    try:
        print("Parameters")
        print(f"  Table capacity (unknown to probe): {TABLE_CAPACITY} bytes")
        print(f"  Canary:  name={CANARY_NAME!r:<20s} value={CANARY_VALUE!r:<12s} size={CANARY_SIZE} bytes")
        print(f"  Fillers: name=p{{NNN}} (4 bytes)  value={FILLER_VALUE!r:<12s} size={FILLER_SIZE} bytes each")
        print()

        # ── Phase 1: Insert canary ─────────────────────────────────────────
        print("Phase 1: Insert canary and confirm it appears in the encoder stream")
        print("─" * 70)

        await client.get("localhost", proxy_port, "/canary",
                         extra_headers=[(CANARY_NAME, CANARY_VALUE)])

        enc_log = server.get_enc_log()
        canary_count = _count_canary_insertions(enc_log)

        print("  Encoder stream instructions received at the backend so far:")
        for record in enc_log:
            for instr in record.instructions:
                tag = " ← canary" if (
                    instr[0] == "insert_literal"
                    and instr[1] == CANARY_NAME
                ) else ""
                print(f"    {instr}{tag}")

        if canary_count != 1:
            print(f"\n  ERROR: expected 1 canary insertion, saw {canary_count}. Aborting.")
            return

        print(f"\n  Canary confirmed in encoder stream. ✓")
        print()

        # ── Phase 2: Fill loop ─────────────────────────────────────────────
        print("Phase 2: Insert fillers one-by-one, probing the canary after each")
        print("─" * 70)
        print("  Each 'probe' re-sends the canary name-value pair.")
        print("  No new encoder instruction  →  proxy found exact match  →  canary still present.")
        print("  New insert_literal appears  →  proxy re-inserted canary  →  canary was evicted.")
        print()
        print(f"  {'#':<5}  {'Name':<8}  {'Filler sz':>9}  {'Cumul. fillers':>14}  {'Canary ins.':>11}  Status")
        print(f"  {'─'*5}  {'─'*8}  {'─'*9}  {'─'*14}  {'─'*11}  {'─'*28}")

        cumulative_filler = 0
        eviction_step     = None

        for i in range(MAX_FILLERS):
            name = filler_name(i)
            cumulative_filler += FILLER_SIZE

            await client.get("localhost", proxy_port, f"/filler/{i}",
                             extra_headers=[(name, FILLER_VALUE)])

            await client.get("localhost", proxy_port, f"/probe/{i}",
                             extra_headers=[(CANARY_NAME, CANARY_VALUE)])

            enc_log = server.get_enc_log()
            count   = _count_canary_insertions(enc_log)

            if count > canary_count:
                status       = "EVICTED — canary re-inserted !"
                canary_count = count
                eviction_step = i
            else:
                status = "canary still in table"

            print(
                f"  {i:<5}  {name.decode():<8}  {FILLER_SIZE:>9}  "
                f"{cumulative_filler:>14}  {count:>11}  {status}"
            )

            if eviction_step is not None:
                break

        print()

        # ── Phase 3: Compute capacity ──────────────────────────────────────
        print("Phase 3: Compute table capacity from eviction point")
        print("─" * 70)

        if eviction_step is None:
            print(f"  Canary survived all {MAX_FILLERS} fillers.")
            print(f"  Increase MAX_FILLERS or reduce TABLE_CAPACITY and retry.")
            return

        N = eviction_step
        filler_bytes_before = N * FILLER_SIZE   # fillers 0 … N-1 were present with canary
        lower = CANARY_SIZE + filler_bytes_before
        upper = lower + FILLER_SIZE - 1

        print(f"  Eviction detected at filler-{N}.")
        print()
        print(f"  Just before filler-{N} was inserted, the table held:")
        print(f"    canary:         {CANARY_SIZE:>5} bytes")
        print(f"    {N} filler(s): {filler_bytes_before:>5} bytes  ({N} × {FILLER_SIZE})")
        print(f"    ─────────────────────────────")
        print(f"    total:          {lower:>5} bytes  ≤ capacity")
        print()
        print(f"  Filler-{N} ({FILLER_SIZE} bytes) did not fit alongside the canary,")
        print(f"  so the canary was evicted. Therefore:")
        print()
        print(f"    {lower} ≤ capacity < {lower + FILLER_SIZE}")
        print()

        midpoint = (lower + upper) // 2
        in_range = lower <= TABLE_CAPACITY <= upper

        print(f"  Measured range:    [{lower}, {upper}]  (midpoint {midpoint})")
        print(f"  Actual capacity:    {TABLE_CAPACITY}")
        print(f"  Max error:          {FILLER_SIZE // 2} bytes  (half of filler entry size = {FILLER_SIZE} bytes)")
        print(f"  True value in range: {'YES ✓' if in_range else 'NO ✗ — check for bugs'}")

    finally:
        client.close()
        transport.close()
        proxy.stop()
        server.close()


if __name__ == "__main__":
    asyncio.run(run())
