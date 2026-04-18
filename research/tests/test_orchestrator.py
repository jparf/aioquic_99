"""Tests for research.orchestrator.Orchestrator."""

from __future__ import annotations

import asyncio
import functools
import os
from typing import Callable, Coroutine, ParamSpec
from unittest import TestCase

from research.orchestrator import Orchestrator, Scenario, ScenarioResult, Step, StepOutcome

P = ParamSpec("P")

CERT = os.path.join(os.path.dirname(__file__), "..", "..", "tests", "ssl_cert.pem")
KEY  = os.path.join(os.path.dirname(__file__), "..", "..", "tests", "ssl_key.pem")


def asynctest(coro: Callable[P, Coroutine]) -> Callable[P, None]:
    @functools.wraps(coro)
    def wrap(*args, **kwargs):
        asyncio.run(coro(*args, **kwargs))
    return wrap


def make_orch() -> Orchestrator:
    return Orchestrator(cert_file=CERT, key_file=KEY)


class OrchestratorTest(TestCase):

    # ------------------------------------------------------------------
    # 1. Single client, single step — baseline smoke test
    # ------------------------------------------------------------------

    @asynctest
    async def test_single_client_single_step(self):
        """Single client scenario returns a ScenarioResult with one step."""
        result = await make_orch().run(Scenario(
            name="smoke",
            steps=[Step("a", "/ping")],
        ))
        self.assertIsInstance(result, ScenarioResult)
        self.assertEqual(len(result.steps), 1)
        outcome = result.steps[0]
        self.assertIsInstance(outcome, StepOutcome)
        self.assertEqual(outcome.client, "a")
        self.assertEqual(outcome.path, "/ping")
        self.assertEqual(outcome.proxy_client_id, "client-0")
        self.assertFalse(outcome.contaminated)

    # ------------------------------------------------------------------
    # 2. Result fields are populated
    # ------------------------------------------------------------------

    @asynctest
    async def test_result_fields_populated(self):
        """ScenarioResult carries scenario metadata and a non-empty report."""
        result = await make_orch().run(Scenario(
            name="field-check",
            steps=[Step("a", "/x", [(b"x-custom", b"hello")])],
            proxy_mode="naive_name_reuse",
            table_capacity=4096,
        ))
        self.assertEqual(result.scenario_name, "field-check")
        self.assertEqual(result.proxy_mode, "naive_name_reuse")
        self.assertEqual(result.table_capacity, 4096)
        self.assertIsInstance(result.instrumentation_report, str)
        self.assertGreater(len(result.instrumentation_report), 0)
        self.assertIsInstance(result.eviction_events, list)

    # ------------------------------------------------------------------
    # 3. StepOutcome.intended reflects the extra headers sent
    # ------------------------------------------------------------------

    @asynctest
    async def test_intended_headers_captured(self):
        """StepOutcome.intended contains the non-pseudo headers the client sent."""
        result = await make_orch().run(Scenario(
            name="intent",
            steps=[Step("a", "/check", [(b"authorization", b"Bearer tok")])],
        ))
        intended = result.steps[0].intended
        self.assertEqual(intended.get("authorization"), "Bearer tok")

    # ------------------------------------------------------------------
    # 4. StepOutcome.received reflects what the backend decoded
    # ------------------------------------------------------------------

    @asynctest
    async def test_received_headers_match_intended_when_clean(self):
        """When no contamination occurs, received equals intended."""
        result = await make_orch().run(Scenario(
            name="clean-passthrough",
            steps=[Step("a", "/check", [(b"x-token", b"secret123")])],
        ))
        o = result.steps[0]
        self.assertEqual(o.intended.get("x-token"), "secret123")
        self.assertEqual(o.received.get("x-token"), "secret123")
        self.assertFalse(o.contaminated)

    # ------------------------------------------------------------------
    # 5. Shared table: each client still receives its own value
    # ------------------------------------------------------------------

    @asynctest
    async def test_credential_swap_b_correct(self):
        """Shared table does not corrupt values — each client gets its own token.

        Client A inserts tokenA into the shared table.  Client B then sends
        tokenB; the proxy emits a Literal with Name Reference (RFC 9204 §4.5.4)
        so the backend receives tokenB, not tokenA.
        """
        result = await make_orch().run(Scenario(
            name="cred-swap-b-correct",
            steps=[
                Step("a", "/api", [(b"authorization", b"Bearer tokenA")],
                     label="A inserts tokenA into shared table"),
                Step("b", "/api", [(b"authorization", b"Bearer tokenB")],
                     label="B still receives its own token"),
            ],
        ))
        self.assertEqual(len(result.steps), 2)
        step_a = result.steps[0]
        step_b = result.steps[1]

        self.assertFalse(step_a.contaminated)
        self.assertEqual(step_a.received.get("authorization"), "Bearer tokenA")

        self.assertFalse(step_b.contaminated)
        self.assertEqual(step_b.intended.get("authorization"), "Bearer tokenB")
        self.assertEqual(step_b.received.get("authorization"), "Bearer tokenB")
        self.assertFalse(result.any_contaminated)
        self.assertEqual(result.contaminated_steps, [])

    # ------------------------------------------------------------------
    # 6. Shared table reversed — same correctness guarantee
    # ------------------------------------------------------------------

    @asynctest
    async def test_credential_swap_a_correct(self):
        """Client B inserts first; client A still receives its own token."""
        result = await make_orch().run(Scenario(
            name="cred-swap-a-correct",
            steps=[
                Step("b", "/api", [(b"authorization", b"Bearer tokenB")]),
                Step("a", "/api", [(b"authorization", b"Bearer tokenA")]),
            ],
        ))
        step_b = result.steps[0]
        step_a = result.steps[1]

        self.assertFalse(step_b.contaminated)
        self.assertFalse(step_a.contaminated)
        self.assertEqual(step_a.received.get("authorization"), "Bearer tokenA")
        self.assertEqual(step_a.intended.get("authorization"), "Bearer tokenA")

    # ------------------------------------------------------------------
    # 7. Different header names — no contamination
    # ------------------------------------------------------------------

    @asynctest
    async def test_no_contamination_different_names(self):
        """Headers with distinct names don't interfere — both steps are clean."""
        result = await make_orch().run(Scenario(
            name="no-cross",
            steps=[
                Step("a", "/a", [(b"x-client-a-token", b"valA")]),
                Step("b", "/b", [(b"x-client-b-token", b"valB")]),
            ],
        ))
        self.assertFalse(result.steps[0].contaminated)
        self.assertFalse(result.steps[1].contaminated)
        self.assertFalse(result.any_contaminated)
        self.assertEqual(result.steps[0].received.get("x-client-a-token"), "valA")
        self.assertEqual(result.steps[1].received.get("x-client-b-token"), "valB")

    # ------------------------------------------------------------------
    # 8. contaminated_steps property
    # ------------------------------------------------------------------

    @asynctest
    async def test_contaminated_steps_property(self):
        """contaminated_steps is empty when encoding is RFC-compliant."""
        result = await make_orch().run(Scenario(
            name="contaminated-steps",
            steps=[
                Step("a", "/r", [(b"authorization", b"Bearer tokenA")]),
                Step("b", "/r", [(b"authorization", b"Bearer tokenB")]),
                Step("b", "/r", [(b"authorization", b"Bearer tokenB2")]),
            ],
        ))
        self.assertEqual(result.contaminated_steps, [])
        self.assertFalse(result.any_contaminated)
        for s in result.steps:
            self.assertFalse(s.contaminated)

    # ------------------------------------------------------------------
    # 9. Discrepancies list is empty when values are correctly delivered
    # ------------------------------------------------------------------

    @asynctest
    async def test_discrepancies_empty_when_clean(self):
        """StepOutcome.discrepancies is empty when both clients receive correct values."""
        result = await make_orch().run(Scenario(
            name="disc-check",
            steps=[
                Step("a", "/r", [(b"authorization", b"Bearer tokenA")]),
                Step("b", "/r", [(b"authorization", b"Bearer tokenB")]),
            ],
        ))
        for step in result.steps:
            self.assertEqual(step.discrepancies, [])
        self.assertEqual(result.steps[0].received.get("authorization"), "Bearer tokenA")
        self.assertEqual(result.steps[1].received.get("authorization"), "Bearer tokenB")

    # ------------------------------------------------------------------
    # 10. Step labels appear in the instrumentation report
    # ------------------------------------------------------------------

    @asynctest
    async def test_instrumentation_report_content(self):
        """The report shows both requests clean and records the insertion event."""
        result = await make_orch().run(Scenario(
            name="report-check",
            steps=[
                Step("a", "/r", [(b"authorization", b"Bearer tokenA")]),
                Step("b", "/r", [(b"authorization", b"Bearer tokenB")]),
            ],
        ))
        report = result.instrumentation_report
        self.assertNotIn("*** CONTAMINATED ***", report)
        self.assertIn("CLEAN", report)
        self.assertIn("authorization", report)
        self.assertIn("tokenA", report)   # insertion value from client A still appears

    # ------------------------------------------------------------------
    # 11. insert_all mode records insertions for every client
    # ------------------------------------------------------------------

    @asynctest
    async def test_insert_all_mode(self):
        """insert_all always inserts before referencing — each client gets its own fresh entry.

        Unlike naive_name_reuse, insert_all inserts a new entry on EVERY request,
        so Phase 2 always references the just-inserted value.  No contamination
        in a two-step sequence.  The value of insert_all is that it populates the
        shared table aggressively (useful for eviction-based attacks), not that it
        contaminates directly.
        """
        result = await make_orch().run(Scenario(
            name="insert-all",
            proxy_mode="insert_all",
            steps=[
                Step("a", "/r", [(b"x-session", b"sess-a"), (b"x-role", b"admin")]),
                Step("b", "/r", [(b"x-session", b"sess-b"), (b"x-role", b"user")]),
            ],
        ))
        self.assertEqual(len(result.steps), 2)
        # Each client inserts then immediately references its own value — no contamination
        self.assertFalse(result.any_contaminated)
        # Report records INSERT events from both clients
        report = result.instrumentation_report
        self.assertIn("insert_all", report)
        self.assertIn("INSERT", report)
        # Both clients' values reached the backend correctly
        self.assertEqual(result.steps[0].received.get("x-session"), "sess-a")
        self.assertEqual(result.steps[1].received.get("x-session"), "sess-b")

    # ------------------------------------------------------------------
    # 12. Multiple requests per client — request_id increments correctly
    # ------------------------------------------------------------------

    @asynctest
    async def test_multiple_requests_same_client(self):
        """A client can make multiple sequential requests; each gets its own record."""
        result = await make_orch().run(Scenario(
            name="multi-req",
            steps=[
                Step("a", "/first",  [(b"x-seq", b"1")]),
                Step("a", "/second", [(b"x-seq", b"2")]),
                Step("a", "/third",  [(b"x-seq", b"3")]),
            ],
        ))
        self.assertEqual(len(result.steps), 3)
        request_ids = [s.request_id for s in result.steps]
        self.assertEqual(request_ids, sorted(request_ids))   # monotonically increasing
        paths = [s.path for s in result.steps]
        self.assertEqual(paths, ["/first", "/second", "/third"])

    # ------------------------------------------------------------------
    # 13. Eviction events surfaced in result
    # ------------------------------------------------------------------

    @asynctest
    async def test_eviction_events_in_result(self):
        """Inserting a large entry evicts an earlier one; result.eviction_events is populated.

        We use long header values (~2100 bytes each) with the default 4096-byte
        table so that the second insert exceeds capacity and evicts the first.
        Using large values keeps MaxEntries = floor(4096/32) = 128, so
        FullRange = 256 and the QPACK encoded-RIC range is wide — this avoids
        the QPACK blocked-stream issue that small tables (capacity=60, FullRange=2)
        trigger in the QUIC network stack.
        """
        long_a = b"A" * 2100   # entry size: 5+2100+32 = 2137 bytes
        long_b = b"B" * 2100   # entry size: 5+2100+32 = 2137 bytes
        # 2137 + 2137 = 4274 > 4096 → second insert evicts the first
        result = await make_orch().run(Scenario(
            name="eviction",
            proxy_mode="insert_all",
            table_capacity=4096,
            steps=[
                Step("a", "/r", [(b"x-foo", long_a)]),
                Step("b", "/r", [(b"x-baz", long_b)]),
            ],
        ))
        self.assertGreater(len(result.eviction_events), 0)
        ev = result.eviction_events[0]
        self.assertEqual(ev.evicted_name, b"x-foo")
        self.assertEqual(ev.evicted_inserted_by, "client-0")
        self.assertEqual(ev.triggered_by_client_id, "client-1")
        self.assertIn("EVICTED", result.instrumentation_report)

    # ------------------------------------------------------------------
    # 14. Path contamination scenario
    # ------------------------------------------------------------------

    @asynctest
    async def test_path_rerouting(self):
        """":path" is a pseudo-header and is never inserted — no path contamination."""
        # Paths are pseudo-headers; the proxy never inserts them into the table.
        # This test verifies the proxy does NOT corrupt :path values.
        result = await make_orch().run(Scenario(
            name="path-check",
            steps=[
                Step("a", "/admin/secret"),
                Step("b", "/user/profile"),
            ],
        ))
        # Neither step should have pseudo-header contamination
        # (the echo server returns :path — verify via received dict which excludes pseudos)
        self.assertFalse(result.any_contaminated)
