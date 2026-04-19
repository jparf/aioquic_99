"""Timing side-channel: canary insertion vs. cache-hit probe latency.

Runs eviction cycles using the same canary/filler approach as
table_size_probe, recording the round-trip time of every probe request
with time.perf_counter_ns() (nanosecond integer monotonic clock — the
highest-resolution timer available in CPython on Linux).

Table sizing
------------
The proxy advertises a 512-byte dynamic table capacity to the backend
echo server via a QPACK Set Dynamic Table Capacity instruction on the
encoder stream at connection time (RFC 9204 §3.2.3).  FaultyProxy
sends this instruction inside _SharedQpackReencoder.initialize(), which
is called as soon as the backend SETTINGS frame is received.

With a 512-byte table:
    canary size  = 49 bytes   (name=b"x-canary", value=b"sentinel0", +32 overhead)
    filler size  = 38 bytes   (name=f{NNNN} 5 bytes, value=b"q", +32 overhead)
    max fillers alongside canary = floor((512-49)/38) = 12
    eviction period = 13 fillers  (every 13 filler inserts evicts the canary)
    fillers needed for 100 evictions ≈ 13 × 100 = 1300

Two timing groups compared:

  hit  — proxy found canary in the dynamic table; no encoder stream
          instruction emitted.

  miss — canary had been evicted; proxy emits an insert_literal
          instruction on the encoder stream and the backend must call
          feed_encoder() before decoding the HEADERS frame.

The Phase-1 initial insert (which includes TLS + QUIC connection
warm-up) is recorded separately and excluded from the miss bucket so
it does not bias the statistics.

Usage
-----
    cd aioquic_99
    python -m research.experiments.probe_timing
"""

from __future__ import annotations

import asyncio
import os
import socket
import ssl
import statistics
import time
from collections import deque

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

# RFC 9204 §3.2.3 — the proxy sends Set Dynamic Table Capacity = 512 on the
# encoder stream at backend-connection time, reducing from the echo server's
# advertised maximum to this smaller working capacity.
TABLE_CAPACITY  = 512

TARGET_MISSES = 100   # stop after this many eviction detections
MAX_FILLERS   = 1350  # safety upper bound (100 evictions need ≈1300 fillers)

CANARY_NAME  = b"x-canary"
CANARY_VALUE = b"sentinel0"
CANARY_SIZE  = len(CANARY_NAME) + len(CANARY_VALUE) + ENTRY_OVERHEAD  # 49 bytes

# 5-byte fixed-length names (f0000-f9999) keep FILLER_SIZE constant across
# the full 1300-filler range.  Mixing 4- and 5-byte names would silently
# shift the eviction boundary mid-experiment.
FILLER_VALUE = b"q"
FILLER_SIZE  = 5 + len(FILLER_VALUE) + ENTRY_OVERHEAD  # 38 bytes


def filler_name(i: int) -> bytes:
    return f"f{i:04d}".encode()


# ---------------------------------------------------------------------------
# Minimal H3 client (zero dynamic-table; same design as table_size_probe)
# ---------------------------------------------------------------------------


class _ZeroCapEncoder:
    def __init__(self, real) -> None:
        object.__setattr__(self, "_real", real)

    def apply_settings(self, max_table_capacity: int, blocked_streams: int) -> bytes:
        return self._real.apply_settings(0, 0)

    def feed_decoder(self, data: bytes) -> None:
        pass

    def __getattr__(self, name: str):
        return getattr(self._real, name)


class _NoTableH3Connection(H3Connection):
    def __init__(self, quic) -> None:
        super().__init__(quic)
        self._encoder = _ZeroCapEncoder(self._encoder)

    def _get_local_settings(self) -> dict:
        settings = super()._get_local_settings()
        settings[Setting.QPACK_MAX_TABLE_CAPACITY] = 0
        settings[Setting.QPACK_BLOCKED_STREAMS] = 0
        return settings


class _TimedH3Client(QuicConnectionProtocol):
    """H3 client with a timed get() that uses time.perf_counter_ns()."""

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
    ) -> tuple[deque[H3Event], int]:
        """Send a GET and return (events, elapsed_ns).

        t0 is taken immediately after transmit() — i.e., after the UDP
        datagram carrying the request has been handed to the kernel — so
        elapsed_ns is pure round-trip + processing time, not encoding time.
        """
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
        t0 = time.perf_counter_ns()
        events = await asyncio.wait_for(asyncio.shield(waiter), timeout=10.0)
        t1 = time.perf_counter_ns()
        return events, t1 - t0


async def _connect_client(
    host: str, port: int
) -> tuple[_TimedH3Client, asyncio.BaseTransport]:
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
        lambda: _TimedH3Client(QuicConnection(configuration=config)),
        sock=sock,
    )
    protocol: _TimedH3Client = protocol
    protocol.connect(addr)
    await protocol.wait_connected()
    return protocol, transport


# ---------------------------------------------------------------------------
# Encoder-stream helpers
# ---------------------------------------------------------------------------


def _count_canary_insertions(enc_log: list[EncStreamRecord]) -> int:
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
# Statistics helpers
# ---------------------------------------------------------------------------


def _stats(samples: list[int]) -> dict:
    n = len(samples)
    if n == 0:
        return {}
    mean  = statistics.mean(samples)
    stdev = statistics.stdev(samples) if n > 1 else 0.0
    med   = statistics.median(samples)
    return {
        "n": n, "mean_ns": mean, "stdev_ns": stdev,
        "median_ns": med, "min_ns": min(samples), "max_ns": max(samples),
    }


def _µs(ns: float) -> str:
    return f"{ns / 1_000:.2f} µs"


def _print_stats(label: str, s: dict) -> None:
    if not s:
        print(f"  {label}: no samples")
        return
    print(
        f"  {label:<8} n={s['n']:>4}   "
        f"mean={_µs(s['mean_ns']):>10}  ±{_µs(s['stdev_ns']):>9}   "
        f"median={_µs(s['median_ns']):>10}   "
        f"[{_µs(s['min_ns'])} – {_µs(s['max_ns'])}]"
    )


# ---------------------------------------------------------------------------
# Experiment
# ---------------------------------------------------------------------------


async def run() -> None:
    # Expected eviction period given table / entry sizes
    max_fillers_with_canary = (TABLE_CAPACITY - CANARY_SIZE) // FILLER_SIZE
    eviction_period = max_fillers_with_canary + 1

    print("=" * 78)
    print("PROBE TIMING: CANARY HIT vs. MISS LATENCY  (512-byte table, 100 misses)")
    print("=" * 78)
    print()
    print("Timer:  time.perf_counter_ns()  (CLOCK_MONOTONIC, nanosecond resolution)")
    print(f"Table:  {TABLE_CAPACITY} bytes  "
          f"(Set Dynamic Table Capacity, RFC 9204 §3.2.3)")
    print(f"Canary: {CANARY_NAME!r} = {CANARY_VALUE!r}  ({CANARY_SIZE} bytes)")
    print(f"Filler: f{{NNNN}} = {FILLER_VALUE!r}  ({FILLER_SIZE} bytes, 5-byte fixed name)")
    print(f"Max fillers alongside canary: {max_fillers_with_canary}  "
          f"→ eviction every {eviction_period} fillers")
    print(f"Target: {TARGET_MISSES} miss samples  "
          f"(Phase-1 warm-up excluded from miss bucket)")
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

    hit_ns:  list[int] = []
    miss_ns: list[int] = []

    try:
        # ── Phase 1: insert canary (excluded from miss bucket) ──────────────
        print("Phase 1: Insert canary  [timing excluded from stats — connection warm-up]")
        print("─" * 78)
        _, t_warmup = await client.get(
            "localhost", proxy_port, "/canary",
            extra_headers=[(CANARY_NAME, CANARY_VALUE)],
        )
        enc_log = server.get_enc_log()
        canary_count = _count_canary_insertions(enc_log)
        if canary_count != 1:
            print(f"  ERROR: expected 1 canary insertion, saw {canary_count}. Aborting.")
            return
        print(f"  Canary confirmed in encoder stream.  Warm-up RTT: {_µs(t_warmup)}")
        print()

        # ── Phase 2: fill + probe loop ──────────────────────────────────────
        print(f"Phase 2: Fill loop  (printing eviction events only)")
        print("─" * 78)
        print(
            f"  {'miss#':>5}  {'step':>5}  {'filler':<7}  "
            f"{'miss RTT':>10}   "
            f"hits since last miss  hit RTTs (mean ± sd)"
        )
        print(
            f"  {'─'*5}  {'─'*5}  {'─'*7}  "
            f"{'─'*10}   {'─'*20}  {'─'*26}"
        )

        eviction_count = 0
        hits_this_cycle: list[int] = []

        for i in range(MAX_FILLERS):
            name = filler_name(i)

            # Filler: not timed.
            await client.get(
                "localhost", proxy_port, f"/filler/{i}",
                extra_headers=[(name, FILLER_VALUE)],
            )

            # Probe: timed.
            _, elapsed_ns = await client.get(
                "localhost", proxy_port, f"/probe/{i}",
                extra_headers=[(CANARY_NAME, CANARY_VALUE)],
            )

            enc_log   = server.get_enc_log()
            new_count = _count_canary_insertions(enc_log)
            evicted   = new_count > canary_count

            if evicted:
                canary_count = new_count
                eviction_count += 1
                miss_ns.append(elapsed_ns)

                # Summarise this cycle's hit samples before printing the eviction.
                cyc_s = _stats(hits_this_cycle)
                if cyc_s:
                    cyc_summary = (
                        f"{cyc_s['n']:>4} hits   "
                        f"{_µs(cyc_s['mean_ns'])} ± {_µs(cyc_s['stdev_ns'])}"
                    )
                else:
                    cyc_summary = "     0 hits"

                print(
                    f"  {eviction_count:>5}  {i:>5}  {name.decode():<7}  "
                    f"{_µs(elapsed_ns):>10}   {cyc_summary}"
                )
                hits_this_cycle = []

            else:
                hit_ns.append(elapsed_ns)
                hits_this_cycle.append(elapsed_ns)

            if eviction_count >= TARGET_MISSES:
                break

        print()

        # ── Phase 3: results ────────────────────────────────────────────────
        print("Phase 3: Timing results")
        print("─" * 78)
        print()
        print(f"  Probe requests:  {len(hit_ns) + len(miss_ns)}  total  "
              f"({len(hit_ns)} hits, {len(miss_ns)} misses)")
        print(f"  Warm-up RTT (Phase-1, excluded): {_µs(t_warmup)}")
        print()

        hit_s  = _stats(hit_ns)
        miss_s = _stats(miss_ns)

        print("  Round-trip latency (time.perf_counter_ns, client perspective):")
        print()
        _print_stats("hit", hit_s)
        _print_stats("miss", miss_s)
        print()

        if hit_s and miss_s:
            delta = miss_s["mean_ns"] - hit_s["mean_ns"]
            direction = "SLOWER" if delta > 0 else "FASTER"
            se_diff = (
                (hit_s["stdev_ns"] ** 2 / hit_s["n"]
                 + miss_s["stdev_ns"] ** 2 / miss_s["n"]) ** 0.5
            )
            print(f"  Miss − hit (mean):  {_µs(abs(delta))}  ({direction})")
            print(f"  Std error of diff:  {_µs(se_diff)}")
            if se_diff > 0:
                z = abs(delta) / se_diff
                print(f"  z-score:            {z:.2f}  "
                      f"({'signal detectable' if z > 2 else 'within noise floor'})")

    finally:
        client.close()
        transport.close()
        proxy.stop()
        server.close()


if __name__ == "__main__":
    asyncio.run(run())
