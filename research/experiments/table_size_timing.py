"""QPACK table-size inference via timing side-channel.

For each candidate table size T ∈ CANDIDATE_SIZES, repeatedly fills the proxy's
shared QPACK dynamic table assuming capacity = T, then times a canary probe.

  re-insertion (slow): proxy calls _try_insert → emits insert_literal
                        → backend processes encoder stream before HEADERS → high RTT
  hit          (fast): proxy calls _dynamic_exact → entry found → no encoder
                        stream instruction → backend decodes immediately → low RTT

A two-sided Mann-Whitney U test compares the hit and re-insertion latency
distributions for each assumed T.  The candidate with the most statistically
smallest candidate with a statistically distinct distribution is inferred to be
the true table capacity.  If no candidate reaches significance at α (default 0.05), the
inferred size is 0 (table disabled or too small to measure).

Fill mechanism (per round)
--------------------------
All entries use 7-byte names and empty values → QPACK entry = 39 bytes.

  1. Insert unique canary c{R:06d} — proxy emits insert_literal (new name)
  2. HIT probe: re-send canary — proxy finds exact match → no encoder instr → fast
  3. Insert n_fill = floor((T − 39) / 39) unique fillers f{G:06d}
  4. Insert unique overflow o{R:06d}
       If T ≥ actual capacity: canary is oldest → overflow evicts it
       If T <  actual capacity: canary survives (table not yet full enough)
  5. REINSERTION probe: re-send canary
       Evicted → proxy emits insert_literal → SLOW
       In table → proxy finds exact match → FAST

Single proxy (table_capacity = SECRET_TABLE_SIZE) and echo server shared across
all candidate sizes.  Per-round unique names (global counters) prevent the
proxy from re-using existing table entries and skipping insertion.

Usage
-----
    cd aioquic_99
    python -m research.experiments.table_size_timing [options]

Examples
--------
    python -m research.experiments.table_size_timing
    python -m research.experiments.table_size_timing --secret-table-size 1024 --n-rounds 80
"""

from __future__ import annotations

import argparse
import asyncio
import os
import random
import socket
import ssl
import statistics
import sys
import time
from collections import deque

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from scipy import stats as scipy_stats

from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection, Setting
from aioquic.h3.events import H3Event
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import QuicEvent

from research.echo_server import EchoServer
from research.faulty_proxy import FaultyProxy
from research.qpack_manual import ENTRY_OVERHEAD

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

CERT = os.path.join(_HERE, "..", "..", "tests", "ssl_cert.pem")
KEY  = os.path.join(_HERE, "..", "..", "tests", "ssl_key.pem")

# ---------------------------------------------------------------------------
# Experiment parameters
# ---------------------------------------------------------------------------

CANDIDATE_SIZES = [512, 1024, 2048, 4096]
N_ROUNDS_DEFAULT = 150
N_WARMUP = 5   # initial rounds discarded to allow table to reach steady state
ALPHA_DEFAULT = 0.05

# All entries use 7-byte names and b"" values.
# QPACK entry = 7 (name) + 0 (value) + 32 (overhead) = 39 bytes.
_NAME_LEN  = 7
_ENTRY_SIZE = _NAME_LEN + 0 + ENTRY_OVERHEAD  # 39 bytes


def _canary_name(r: int) -> bytes:
    return f"c{r:06d}".encode()   # exactly 7 bytes


def _filler_name(g: int) -> bytes:
    return f"f{g:06d}".encode()   # exactly 7 bytes


def _overflow_name(r: int) -> bytes:
    return f"o{r:06d}".encode()   # exactly 7 bytes


def _n_fill(t_assumed: int) -> int:
    """Number of 39-byte filler entries to insert before the overflow."""
    # canary (39B) + n_fill fillers (39B each) < t_assumed
    # canary + n_fill + overflow (39B) ≥ t_assumed
    # → n_fill = floor((t_assumed - _ENTRY_SIZE) / _ENTRY_SIZE)
    return max(0, (t_assumed - _ENTRY_SIZE) // _ENTRY_SIZE)


# ---------------------------------------------------------------------------
# Minimal H3 client — zero dynamic table, nanosecond-timed GET
# ---------------------------------------------------------------------------


class _ZeroCapEncoder:
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


class _TimedH3Client(QuicConnectionProtocol):
    """H3 client whose get() returns (events, elapsed_ns).

    t0 starts after transmit() — i.e., after the datagram is handed to the
    kernel — so elapsed_ns captures pure round-trip + server-side processing.
    """

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
        header: tuple[bytes, bytes] | None = None,
    ) -> tuple[deque[H3Event], int]:
        headers = [
            (b":method",    b"GET"),
            (b":scheme",    b"https"),
            (b":authority", f"{host}:{port}".encode()),
            (b":path",      path.encode()),
        ]
        if header:
            headers.append(header)
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
    protocol.connect(addr)
    await protocol.wait_connected()
    return protocol, transport


# ---------------------------------------------------------------------------
# Statistics helpers
# ---------------------------------------------------------------------------


def _µs(ns: float) -> str:
    return f"{ns / 1_000:.2f} µs"


def _row(label: str, samples: list[int]) -> None:
    if not samples:
        print(f"  {label}: no data")
        return
    mean = statistics.mean(samples)
    std  = statistics.stdev(samples) if len(samples) > 1 else 0.0
    med  = statistics.median(samples)
    print(
        f"  {label:<14} n={len(samples):>4}   "
        f"mean={_µs(mean):>10}  ±{_µs(std):>9}   "
        f"median={_µs(med):>10}   "
        f"[{_µs(min(samples))} – {_µs(max(samples))}]"
    )


# ---------------------------------------------------------------------------
# Per-assumed-T data collection
# ---------------------------------------------------------------------------


async def _collect(
    client: _TimedH3Client,
    proxy_port: int,
    t_assumed: int,
    n_rounds: int,
    n_warmup: int,
    global_round: int,
    global_filler: int,
) -> tuple[list[int], list[int], int, int]:
    """Run n_warmup + n_rounds timing cycles for t_assumed.

    Returns (hit_ns, rein_ns, new_global_round, new_global_filler).
    The warmup rounds are discarded.
    """
    n_fill  = _n_fill(t_assumed)
    host    = "localhost"
    hit_ns: list[int]  = []
    rein_ns: list[int] = []

    for i in range(n_warmup + n_rounds):
        r = global_round
        g = global_filler
        global_round  += 1
        global_filler += n_fill

        cn = _canary_name(r)
        on = _overflow_name(r)

        # 1. Insert canary (new unique name → always insert_literal)
        await client.get(host, proxy_port, f"/ts/insert/{r}", header=(cn, b""))

        # 2. HIT probe: canary just inserted, exact match in table → fast
        _, t_hit = await client.get(host, proxy_port, f"/ts/hit/{r}", header=(cn, b""))

        # 3. Insert fillers (unique names → always insert_literal → always evict)
        for k in range(n_fill):
            fn = _filler_name(g + k)
            await client.get(host, proxy_port, f"/ts/fill/{r}/{k}", header=(fn, b""))

        # 4. Insert overflow (unique name → always insert_literal)
        await client.get(host, proxy_port, f"/ts/overflow/{r}", header=(on, b""))

        # 5. REINSERTION probe: slow if canary evicted, fast if still in table
        _, t_rein = await client.get(host, proxy_port, f"/ts/rein/{r}", header=(cn, b""))

        if i >= n_warmup:
            hit_ns.append(t_hit)
            rein_ns.append(t_rein)

    return hit_ns, rein_ns, global_round, global_filler


# ---------------------------------------------------------------------------
# Single-trial inference (returns inferred size, prints compact progress)
# ---------------------------------------------------------------------------


async def _run_trial(
    echo_port: int,
    secret_size: int,
    n_rounds: int,
    alpha: float,
    global_round: int,
    global_filler: int,
    W: int,
) -> tuple[int, list[tuple[int, list[int], list[int], float, float]], int, int]:
    """Run one full inference trial.

    Returns (inferred_size, per_candidate_results, new_global_round, new_global_filler).
    """
    cand_results: list[tuple[int, list[int], list[int], float, float]] = []

    for t_assumed in CANDIDATE_SIZES:
        n_fill = _n_fill(t_assumed)
        print(f"  T_assumed={t_assumed:>5}  ({n_fill} fillers/round × "
              f"{n_rounds + N_WARMUP} rounds) …", end="", flush=True)

        proxy = FaultyProxy(table_capacity=secret_size)
        proxy_port = await proxy.start(
            listen_port=0,
            backend_host="localhost",
            backend_port=echo_port,
            cert_file=CERT,
            key_file=KEY,
        )
        client, transport = await _connect_client("localhost", proxy_port)

        try:
            hit_ns, rein_ns, global_round, global_filler = await _collect(
                client, proxy_port, t_assumed, n_rounds, N_WARMUP,
                global_round, global_filler,
            )
        finally:
            client.close()
            transport.close()
            proxy.stop()

        stat, p = scipy_stats.mannwhitneyu(hit_ns, rein_ns, alternative="two-sided")
        cand_results.append((t_assumed, hit_ns, rein_ns, float(stat), p))
        sig = p < alpha
        p_fmt = f"{p:.4f}" if p >= 0.0001 else f"{p:.2e}"
        print(f"  U={stat:.0f}  p={p_fmt}  "
              f"{'DISTINCT' if sig else 'not distinct'}")

    distinct = [(t, stat, p) for t, _, _, stat, p in cand_results if p < alpha]
    if not distinct:
        inferred = 0
    else:
        inferred, _, _ = min(distinct, key=lambda x: x[0])

    return inferred, cand_results, global_round, global_filler


# ---------------------------------------------------------------------------
# Main experiment
# ---------------------------------------------------------------------------


async def run(
    n_trials: int,
    n_rounds: int,
    alpha: float,
    fixed_secret: int | None,
) -> None:
    W = 78

    print("=" * W)
    print(f"QPACK TABLE-SIZE TIMING ORACLE")
    print("=" * W)
    print()
    print(f"  Trials            : {n_trials}")
    print(f"  Secret per trial  : "
          f"{'fixed = ' + str(fixed_secret) + ' bytes' if fixed_secret else 'random from ' + str(CANDIDATE_SIZES)}")
    print(f"  Rounds per cand.  : {n_rounds}  (+{N_WARMUP} warmup discarded)")
    print(f"  Candidates        : {CANDIDATE_SIZES}")
    print(f"  Entry size        : {_ENTRY_SIZE} bytes  "
          f"({_NAME_LEN}-byte name + b\"\" value + {ENTRY_OVERHEAD} overhead)")
    print(f"  Significance (α)  : {alpha}")
    print()
    print("  n_fill per candidate:")
    for t in CANDIDATE_SIZES:
        nf = _n_fill(t)
        filled = (nf + 1) * _ENTRY_SIZE
        total  = (nf + 2) * _ENTRY_SIZE
        print(f"    T={t:>5}: {nf:>4} fillers  "
              f"(fill={filled} B  →  fill+overflow={total} B)")
    print()

    server = EchoServer()
    echo_port = await server.start(cert_file=CERT, key_file=KEY)

    global_round  = 0
    global_filler = 0
    trial_log: list[tuple[int, int, bool,
                          list[tuple[int, list[int], list[int], float, float]]]] = []

    try:
        for trial_idx in range(n_trials):
            secret = fixed_secret if fixed_secret is not None else random.choice(CANDIDATE_SIZES)

            print(f"Trial {trial_idx + 1}/{n_trials}  "
                  f"(secret={secret} bytes)")
            print("─" * W)

            inferred, cand_results, global_round, global_filler = await _run_trial(
                echo_port, secret, n_rounds, alpha, global_round, global_filler, W,
            )

            correct = inferred == secret
            trial_log.append((secret, inferred, correct, cand_results))

            result_str = "YES" if correct else "NO "
            print(f"  → secret={secret}  inferred={inferred}  correct={result_str}")
            print()

        # ── Per-trial detail ─────────────────────────────────────────────────
        print("=" * W)
        print("PER-TRIAL DETAIL")
        print("=" * W)
        print()

        for i, (secret, inferred, correct, cand_results) in enumerate(trial_log):
            print(f"Trial {i + 1}  secret={secret}  inferred={inferred}  "
                  f"{'✓ correct' if correct else '✗ wrong'}")
            print(f"  {'─'*70}")
            for t_assumed, hit_ns, rein_ns, stat, p in cand_results:
                sig = p < alpha
                delta = statistics.mean(rein_ns) - statistics.mean(hit_ns)
                p_fmt = f"{p:.4f}" if p >= 0.0001 else f"{p:.2e}"
                marker = " ← inferred" if t_assumed == inferred else ""
                print(f"  T={t_assumed:>5}  Δ={_µs(abs(delta)):>9}  "
                      f"p={p_fmt}  "
                      f"{'DISTINCT' if sig else 'not dist'}  {marker}")
            print()

        # ── Summary ──────────────────────────────────────────────────────────
        print("=" * W)
        print("SUMMARY")
        print("=" * W)
        print()

        n_correct = sum(c for _, _, c, _ in trial_log)
        accuracy  = n_correct / n_trials if n_trials else 0.0

        by_secret: dict[int, list[bool]] = {}
        for secret, inferred, correct, _ in trial_log:
            by_secret.setdefault(secret, []).append(correct)

        print(f"  {'Secret':>7}  {'Trials':>6}  {'Correct':>7}  {'Accuracy':>9}")
        print(f"  {'─'*7}  {'─'*6}  {'─'*7}  {'─'*9}")
        for s in sorted(by_secret):
            outcomes = by_secret[s]
            n = len(outcomes)
            c = sum(outcomes)
            print(f"  {s:>7}  {n:>6}  {c:>7}  {c/n*100:>8.1f}%")
        print(f"  {'─'*7}  {'─'*6}  {'─'*7}  {'─'*9}")
        print(f"  {'TOTAL':>7}  {n_trials:>6}  {n_correct:>7}  {accuracy*100:>8.1f}%")
        print()

    finally:
        server.close()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


N_TRIALS_DEFAULT = 5


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Infer QPACK dynamic table capacity via RTT timing side-channel",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python -m research.experiments.table_size_timing
  python -m research.experiments.table_size_timing --n-trials 10
  python -m research.experiments.table_size_timing --secret-table-size 1024 --n-trials 3
  python -m research.experiments.table_size_timing --n-rounds 80 --n-trials 8
        """,
    )
    parser.add_argument(
        "--secret-table-size",
        type=int,
        choices=CANDIDATE_SIZES,
        default=None,
        help=f"Fix the secret size for every trial (default: random each trial)",
    )
    parser.add_argument(
        "--n-trials",
        type=int,
        default=N_TRIALS_DEFAULT,
        help=f"Number of independent inference trials (default: {N_TRIALS_DEFAULT})",
    )
    parser.add_argument(
        "--n-rounds",
        type=int,
        default=N_ROUNDS_DEFAULT,
        help=f"Timing samples per candidate per trial (default: {N_ROUNDS_DEFAULT})",
    )
    parser.add_argument(
        "--alpha",
        type=float,
        default=ALPHA_DEFAULT,
        help=f"Significance threshold for Mann-Whitney test (default: {ALPHA_DEFAULT})",
    )
    args = parser.parse_args()
    asyncio.run(run(
        n_trials=args.n_trials,
        n_rounds=args.n_rounds,
        alpha=args.alpha,
        fixed_secret=args.secret_table_size,
    ))


if __name__ == "__main__":
    main()
