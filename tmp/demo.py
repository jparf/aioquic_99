"""RFC 9204 QPACK pooled-proxy behaviour verification.

The proxy maintains a single shared QPACK dynamic table across all client
connections on its backend leg.  Three distinct table outcomes are possible
depending on what two clients send:

  Case 1 — Different names
    Client A: secret-header: guess1   Client B: wrong-header: guess2
    Both names are new → two independent §4.3.3 literal inserts.
    Table ends with two unrelated entries.

  Case 2 — Same name, different value
    Client A: secret-header: guess1   Client B: secret-header: guess2
    Client A's insert is §4.3.3 literal.  Client B's name already exists
    in the table so the proxy uses §4.3.2 name-reference (more compact).
    Table ends with two entries sharing the same name.

  Case 3 — Same name, same value  (the oracle case)
    Client A: secret-header: guess1   Client B: secret-header: guess1
    Client A inserts via §4.3.3 literal.  Client B finds an exact
    (name, value) match → NO new insertion, §4.5.2 indexed reference.
    Table ends with one entry referenced twice.
    The absence of an insertion for Client B is the observable signal
    that Client B guessed Client A's value correctly.

Run from the aioquic_99 directory:
    python3 tmp/demo.py
"""

from __future__ import annotations

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from research.echo_server import AckRecord, EncStreamRecord, EchoServer
from research.faulty_proxy import FaultyProxy, InsertionEvent, ReferenceEvent
from research.orchestrator import (
    Orchestrator, Scenario, ScenarioResult, Step, StepOutcome,
    _connect_client, _parse_echo_response, _nonpseudo_dict,
)

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CERT  = os.path.join(_ROOT, "tests", "ssl_cert.pem")
KEY   = os.path.join(_ROOT, "tests", "ssl_key.pem")

W = 72
DIVIDER = "=" * W
SUBDIV  = "-" * W


# ---------------------------------------------------------------------------
# Extended orchestrator that exposes raw instrumentation events
# ---------------------------------------------------------------------------


class _InstrumentedResult(ScenarioResult):
    raw_events: list
    proxy_instrumentation_report: str
    ack_log: list[AckRecord]
    enc_log: list[EncStreamRecord]


class _Orchestrator(Orchestrator):
    async def run(self, scenario: Scenario) -> _InstrumentedResult:
        echo  = EchoServer()
        proxy = FaultyProxy(table_capacity=scenario.table_capacity)

        echo_port  = await echo.start(cert_file=self._cert, key_file=self._key)
        proxy_port = await proxy.start(
            listen_port=0,
            backend_host="localhost",
            backend_port=echo_port,
            cert_file=self._cert,
            key_file=self._key,
        )

        seen: list[str] = []
        for step in scenario.steps:
            if step.client not in seen:
                seen.append(step.client)

        clients: dict = {}
        id_map:  dict = {}

        try:
            for i, name in enumerate(seen):
                proto, transport = await _connect_client("localhost", proxy_port)
                clients[name] = (proto, transport)
                id_map[name]  = f"client-{i}"

            outcomes: list[StepOutcome] = []
            for idx, step in enumerate(scenario.steps):
                proto, _ = clients[step.client]
                cid      = id_map[step.client]
                pre      = len(proxy.instrumentation.request_records)

                events = await proto.get(
                    "localhost", proxy_port, step.path,
                    extra_headers=step.headers or None,
                )
                backend = _parse_echo_response(events)
                proxy.instrumentation.record_backend_response(cid, backend)

                recs = proxy.instrumentation.request_records
                rec  = recs[pre] if pre < len(recs) else None

                outcomes.append(StepOutcome(
                    index=idx,
                    label=step.label or f"step-{idx}",
                    client=step.client,
                    proxy_client_id=cid,
                    path=step.path,
                    intended=_nonpseudo_dict(step.headers),
                    received=_nonpseudo_dict(backend),
                    contaminated=rec.is_contaminated() if rec else False,
                    discrepancies=rec.compute_discrepancies() if rec else [],
                    request_id=rec.request_id if rec else -1,
                ))

        finally:
            for proto, transport in clients.values():
                proto.close()
                transport.close()
            proxy.stop()
            ack_log = echo.get_ack_log()   # capture before close
            enc_log = echo.get_enc_log()
            echo.close()

        result = _InstrumentedResult(
            scenario_name=scenario.name,
            table_capacity=scenario.table_capacity,
            steps=outcomes,
            instrumentation_report=proxy.instrumentation.generate_report(),
            eviction_events=proxy.instrumentation.eviction_events,
        )
        result.raw_events = list(proxy.instrumentation.events)
        result.proxy_instrumentation_report = proxy.instrumentation.generate_report()
        result.ack_log = ack_log
        result.enc_log = enc_log
        return result


# ---------------------------------------------------------------------------
# Print helpers
# ---------------------------------------------------------------------------


def header(title: str, description: str) -> None:
    print()
    print(DIVIDER)
    print(f"CASE: {title}")
    print(SUBDIV)
    words = description.split()
    line  = "  "
    for word in words:
        candidate = (line + " " + word).lstrip()
        if len("  " + candidate) > 70 and line.strip():
            print(line)
            line = "  " + word
        else:
            line = line + (" " if line != "  " else "") + word
    if line.strip():
        print(line)
    print()


def check(label: str, passed: bool) -> bool:
    sym = "PASS" if passed else "FAIL"
    print(f"  [{sym}] {label}")
    return passed


def show_enc_stream(enc_log: list[EncStreamRecord]) -> None:
    """Print encoder stream instructions received by the server from the proxy."""
    if not enc_log:
        print("  Encoder stream (proxy → server): (none)")
        return
    total = sum(len(r.instructions) for r in enc_log)
    print(f"  Encoder stream (proxy → server): {total} instruction(s) in {len(enc_log)} write(s)")
    for rec in enc_log:
        for instr in rec.instructions:
            if instr[0] == "set_capacity":
                print(f"    [enc #{rec.seq}] Set Dynamic Table Capacity  capacity={instr[1]}")
            elif instr[0] == "insert_name_ref":
                _, idx, is_static, value = instr
                src = "static" if is_static else "dynamic"
                print(f"    [enc #{rec.seq}] Insert With Name Reference  "
                      f"idx={idx} ({src})  value={value.decode(errors='replace')!r}")
            elif instr[0] == "insert_literal":
                _, name, value = instr
                print(f"    [enc #{rec.seq}] Insert With Literal Name  "
                      f"name={name.decode(errors='replace')!r}  "
                      f"value={value.decode(errors='replace')!r}")
            elif instr[0] == "duplicate":
                print(f"    [enc #{rec.seq}] Duplicate  idx={instr[1]}")


def show_acks(ack_log: list[AckRecord]) -> None:
    """Print the server's QPACK decoder stream writes in human-readable form."""
    if not ack_log:
        print("  Decoder stream acks: (none — no dynamic table references in header blocks)")
        return
    print(f"  Decoder stream acks: {len(ack_log)} write(s) from server → proxy")
    for rec in ack_log:
        for kind, value in rec.instructions:
            if kind == "section_ack":
                print(f"    [ack #{rec.seq}] Section Acknowledgment  stream_id={value}")
            elif kind == "insert_count_increment":
                print(f"    [ack #{rec.seq}] Insert Count Increment  +{value}")
            elif kind == "stream_cancellation":
                print(f"    [ack #{rec.seq}] Stream Cancellation  stream_id={value}")


def insertions_for(events: list, client_id: str) -> list[InsertionEvent]:
    return [e for e in events if isinstance(e, InsertionEvent) and e.client_id == client_id]


def references_for(events: list, client_id: str) -> list[ReferenceEvent]:
    return [e for e in events if isinstance(e, ReferenceEvent) and e.client_id == client_id]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


async def main() -> None:
    orch   = _Orchestrator(cert_file=CERT, key_file=KEY)
    all_ok = True

    # ----------------------------------------------------------------
    # Case 1 — Different names: two independent literal inserts
    # ----------------------------------------------------------------
    header(
        "1 — Different names",
        "Client A sends 'secret-header: guess1', Client B sends "
        "'wrong-header: guess2'.  Neither name exists anywhere so the "
        "proxy emits two §4.3.3 literal inserts.  Both values must arrive "
        "correctly and the table must contain two independent entries.",
    )

    r1 = await orch.run(Scenario(
        name="case-1-different-names",
        steps=[
            Step("a", "/", [(b"secret-header", b"guess1")],
                 label="client-A inserts secret-header:guess1 (§4.3.3 literal)"),
            Step("b", "/", [(b"wrong-header", b"guess2")],
                 label="client-B inserts wrong-header:guess2 (§4.3.3 literal)"),
        ],
    ))

    ins_a1 = insertions_for(r1.raw_events, "client-0")
    ins_b1 = insertions_for(r1.raw_events, "client-1")

    for out in r1.steps:
        for k, v in out.intended.items():
            print(f"  [{out.proxy_client_id}]  intended {k}: {v!r}  "
                  f"received: {out.received.get(k)!r}")
    print()

    ok = check(
        f"client-A: 1 insertion, kind='literal' "
        f"(got {len(ins_a1)}, kind={repr(ins_a1[0].kind) if ins_a1 else 'n/a'})",
        len(ins_a1) == 1 and ins_a1[0].kind == "literal",
    )
    all_ok = all_ok and ok

    ok = check(
        f"client-B: 1 insertion, kind='literal' "
        f"(got {len(ins_b1)}, kind={repr(ins_b1[0].kind) if ins_b1 else 'n/a'})",
        len(ins_b1) == 1 and ins_b1[0].kind == "literal",
    )
    all_ok = all_ok and ok

    ok = check(
        "table has 2 entries — names are independent",
        len(ins_a1) + len(ins_b1) == 2,
    )
    all_ok = all_ok and ok

    ok = check(
        "both values delivered correctly",
        all(out.received.get(k) == v
            for out in r1.steps for k, v in out.intended.items()),
    )
    all_ok = all_ok and ok
    print()
    show_enc_stream(r1.enc_log)
    show_acks(r1.ack_log)

    # ----------------------------------------------------------------
    # Case 2 — Same name, different value: name-reference insert
    # ----------------------------------------------------------------
    header(
        "2 — Same name, different value",
        "Client A sends 'secret-header: guess1' (§4.3.3 literal insert). "
        "Client B sends 'secret-header: guess2'.  The name already exists "
        "in the table so the proxy inserts using §4.3.2 name-reference — "
        "more compact because the name bytes are not repeated. "
        "Table ends with two entries sharing the name.  Both values delivered correctly.",
    )

    r2 = await orch.run(Scenario(
        name="case-2-same-name-different-value",
        steps=[
            Step("a", "/", [(b"secret-header", b"guess1")],
                 label="client-A: literal insert of secret-header:guess1"),
            Step("b", "/", [(b"secret-header", b"guess2")],
                 label="client-B: name-ref insert of secret-header:guess2"),
        ],
    ))

    ins_a2 = insertions_for(r2.raw_events, "client-0")
    ins_b2 = insertions_for(r2.raw_events, "client-1")

    for out in r2.steps:
        for k, v in out.intended.items():
            print(f"  [{out.proxy_client_id}]  intended {k}: {v!r}  "
                  f"received: {out.received.get(k)!r}")
    print()

    ok = check(
        f"client-A: 1 insertion, kind='literal' "
        f"(got {len(ins_a2)}, kind={repr(ins_a2[0].kind) if ins_a2 else 'n/a'})",
        len(ins_a2) == 1 and ins_a2[0].kind == "literal",
    )
    all_ok = all_ok and ok

    ok = check(
        f"client-B: 1 insertion, kind='dynamic_name_ref' "
        f"(got {len(ins_b2)}, kind={repr(ins_b2[0].kind) if ins_b2 else 'n/a'})",
        len(ins_b2) == 1 and ins_b2[0].kind == "dynamic_name_ref",
    )
    all_ok = all_ok and ok

    ok = check(
        "table has 2 entries — shared name, distinct values",
        len(ins_a2) + len(ins_b2) == 2,
    )
    all_ok = all_ok and ok

    ok = check(
        "both values delivered correctly",
        all(out.received.get(k) == v
            for out in r2.steps for k, v in out.intended.items()),
    )
    all_ok = all_ok and ok
    print()
    show_enc_stream(r2.enc_log)
    show_acks(r2.ack_log)

    # ----------------------------------------------------------------
    # Case 3 — Same name, same value: no insert, indexed reference
    # ----------------------------------------------------------------
    header(
        "3 — Same name, same value (oracle case)",
        "Client A sends 'secret-header: guess1' — §4.3.3 literal insert. "
        "Client B sends 'secret-header: guess1' — exact (name, value) match "
        "already in the table, so the proxy emits NO new insertion and uses "
        "a §4.5.2 indexed field line.  Table ends with one entry referenced "
        "twice.  The absence of an insertion for Client B is the observable "
        "oracle signal that Client B guessed Client A's exact value.",
    )

    r3 = await orch.run(Scenario(
        name="case-3-same-name-same-value",
        steps=[
            Step("a", "/", [(b"secret-header", b"guess1")],
                 label="client-A: literal insert of secret-header:guess1"),
            Step("b", "/", [(b"secret-header", b"guess1")],
                 label="client-B: exact match → §4.5.2 indexed ref, no insert"),
        ],
    ))

    ins_a3  = insertions_for(r3.raw_events, "client-0")
    ins_b3  = insertions_for(r3.raw_events, "client-1")
    refs_b3 = references_for(r3.raw_events, "client-1")

    for out in r3.steps:
        for k, v in out.intended.items():
            print(f"  [{out.proxy_client_id}]  intended {k}: {v!r}  "
                  f"received: {out.received.get(k)!r}")
    print()

    ok = check(
        f"client-A: 1 insertion, kind='literal' "
        f"(got {len(ins_a3)}, kind={repr(ins_a3[0].kind) if ins_a3 else 'n/a'})",
        len(ins_a3) == 1 and ins_a3[0].kind == "literal",
    )
    all_ok = all_ok and ok

    ok = check(
        f"client-B: 0 insertions — exact match, no new entry "
        f"(got {len(ins_b3)})",
        len(ins_b3) == 0,
    )
    all_ok = all_ok and ok

    ok = check(
        f"client-B: 1 §4.5.2 indexed reference, root_cause='clean' "
        f"(got {len(refs_b3)} ref(s))",
        len(refs_b3) == 1 and refs_b3[0].root_cause == "clean",
    )
    all_ok = all_ok and ok

    ok = check(
        "table has 1 entry — referenced twice, never re-inserted",
        len(ins_a3) + len(ins_b3) == 1,
    )
    all_ok = all_ok and ok

    ok = check(
        "both values delivered correctly",
        all(out.received.get(k) == v
            for out in r3.steps for k, v in out.intended.items()),
    )
    all_ok = all_ok and ok
    print()
    show_enc_stream(r3.enc_log)
    show_acks(r3.ack_log)

    # ----------------------------------------------------------------
    # Summary
    # ----------------------------------------------------------------
    print()
    print(DIVIDER)
    print("SUMMARY")
    print(SUBDIV)
    fmt = "  {:<40}  {:>8}  {:>8}  {:>8}"
    print(fmt.format("Case", "Ins A", "Ins B", "Table"))
    print(fmt.format("-" * 40, "------", "------", "-----"))

    for label, r, ia, ib in [
        ("1 — different names",            r1,
         insertions_for(r1.raw_events, "client-0"),
         insertions_for(r1.raw_events, "client-1")),
        ("2 — same name, different value", r2,
         insertions_for(r2.raw_events, "client-0"),
         insertions_for(r2.raw_events, "client-1")),
        ("3 — same name, same value",      r3,
         insertions_for(r3.raw_events, "client-0"),
         insertions_for(r3.raw_events, "client-1")),
    ]:
        ins_a_kind = ia[0].kind if ia else "-"
        ins_b_kind = ib[0].kind if ib else "none"
        table_size = len(ia) + len(ib)
        print(fmt.format(label, ins_a_kind, ins_b_kind, table_size))

    print()
    print(DIVIDER)
    if all_ok:
        print("RESULT: ALL CHECKS PASS")
        print()
        print("  The proxy correctly implements RFC 9204 pooled QPACK encoding.")
        print()
        print("  Table outcomes per case:")
        print("    Case 1 — 2 independent §4.3.3 literal inserts")
        print("    Case 2 — §4.3.3 literal (A) + §4.3.2 dynamic name-ref (B)")
        print("    Case 3 — §4.3.3 literal (A) + no insert (B), §4.5.2 indexed ref")
        print()
        print("  Case 3 is the oracle: Client B's absence of insertion reveals")
        print("  that it sent the exact value already present in the shared table.")
    else:
        print("RESULT: SOME CHECKS FAILED — see [FAIL] lines above")
    print(DIVIDER)

    sys.stdout.flush()
    os._exit(0)


asyncio.run(main())
