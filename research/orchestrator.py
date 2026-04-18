"""Scenario orchestrator for QPACK contamination research.

Runs end-to-end attack scenarios through the full stack:
    EchoServer  ←  FaultyProxy  ←  multiple HTTP/3 clients

Each ``Scenario`` is a named sequence of ``Step`` objects.  A ``Step``
names a client handle (e.g. ``"a"``, ``"attacker"``), a request path, and
any extra headers.  The orchestrator connects all clients, executes each
step in order, reads what the backend actually decoded from the echo server,
feeds the result back to ``ProxyInstrumentation.record_backend_response()``,
and returns a ``ScenarioResult`` with per-step outcomes and the full
QPACK instrumentation report.

Typical usage::

    orch = Orchestrator(cert_file=CERT, key_file=KEY)

    result = await orch.run(Scenario(
        name="credential-swap",
        steps=[
            Step("a", "/api", [(b"authorization", b"Bearer tokenA")],
                 label="client-a inserts credential"),
            Step("b", "/api", [(b"authorization", b"Bearer tokenB")],
                 label="client-b — proxy references tokenA"),
        ],
    ))

    print(result.instrumentation_report)
    for s in result.contaminated_steps:
        print(f"  Step {s.index} ({s.client}): intended {s.intended}, received {s.received}")
"""

from __future__ import annotations

import asyncio
import json
import socket
import ssl
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, H3Event, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import QuicEvent

from .echo_server import EchoServer
from .faulty_proxy import EvictionEvent, FaultyProxy


# ---------------------------------------------------------------------------
# Scenario definition types
# ---------------------------------------------------------------------------


@dataclass
class Step:
    """One request in a scenario.

    Args:
        client:  Named client handle (e.g. ``"a"``, ``"attacker"``).  The
                 orchestrator connects one QUIC session per unique name.
        path:    HTTP path (``":path"`` pseudo-header value).
        headers: Extra request headers beyond the four required pseudo-headers.
        label:   Optional human-readable description for reports.
    """

    client: str
    path: str
    headers: list[tuple[bytes, bytes]] = field(default_factory=list)
    label: str = ""


@dataclass
class Scenario:
    """A named sequence of steps to run through the proxy.

    Args:
        name:           Human-readable scenario identifier.
        steps:          Ordered list of requests to execute.
        table_capacity: QPACK dynamic table capacity in bytes.
    """

    name: str
    steps: list[Step]
    table_capacity: int = 4096


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass
class StepOutcome:
    """Result of a single scenario step."""

    index: int                      # 0-based position in the scenario
    label: str                      # step label or auto "step-N"
    client: str                     # named client handle
    proxy_client_id: str            # proxy's internal client id ("client-0", …)
    path: str                       # requested path
    intended: dict[str, str]        # non-pseudo headers the client sent
    received: dict[str, str]        # non-pseudo headers the backend decoded
    contaminated: bool              # True if any header value was swapped
    discrepancies: list[dict]       # [{name, intended, backend, root_cause}, …]
    request_id: int                 # ProxyInstrumentation request_id


@dataclass
class ScenarioResult:
    """Complete outcome of a scenario run."""

    scenario_name: str
    table_capacity: int
    steps: list[StepOutcome]
    instrumentation_report: str          # full text from ProxyInstrumentation
    eviction_events: list[EvictionEvent]

    @property
    def contaminated_steps(self) -> list[StepOutcome]:
        """Steps where the proxy served a wrong header value to the backend."""
        return [s for s in self.steps if s.contaminated]

    @property
    def any_contaminated(self) -> bool:
        """True if at least one step was contaminated."""
        return any(s.contaminated for s in self.steps)


# ---------------------------------------------------------------------------
# Internal HTTP/3 client (minimal — not exposed publicly)
# ---------------------------------------------------------------------------


class _H3Client(QuicConnectionProtocol):
    """Minimal HTTP/3 GET client for use inside the orchestrator."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._request_events: dict[int, deque[H3Event]] = {}
        self._request_waiters: dict[int, asyncio.Future] = {}
        self._http: H3Connection = H3Connection(self._quic)

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
        """Send a GET request and wait for the full response."""
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


async def _connect_client(
    host: str, port: int
) -> tuple[_H3Client, asyncio.BaseTransport]:
    """Open a QUIC connection to host:port and return (protocol, transport)."""
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
# Helpers
# ---------------------------------------------------------------------------


def _parse_echo_response(events: deque[H3Event]) -> list[tuple[bytes, bytes]]:
    """Parse the echo server's JSON body into raw (name, value) bytes tuples."""
    body = b"".join(ev.data for ev in events if isinstance(ev, DataReceived))
    if not body:
        return []
    data = json.loads(body)
    return [
        (row[0].encode(), row[1].encode())
        for row in data.get("headers", [])
    ]


def _nonpseudo_dict(headers: list[tuple[bytes, bytes]]) -> dict[str, str]:
    """Convert a header list to a str→str dict, excluding pseudo-headers."""
    return {
        k.decode(errors="replace"): v.decode(errors="replace")
        for k, v in headers
        if not k.startswith(b":")
    }


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


class Orchestrator:
    """Runs QPACK contamination scenarios end-to-end.

    The orchestrator is stateless between ``run()`` calls — each invocation
    creates a fresh ``EchoServer`` and ``FaultyProxy``, tears them down after
    the scenario completes, and returns a self-contained ``ScenarioResult``.

    Args:
        cert_file: Path to the TLS certificate file (PEM).
        key_file:  Path to the TLS private key file (PEM).
    """

    def __init__(self, cert_file: str, key_file: str) -> None:
        self._cert = cert_file
        self._key = key_file

    async def run(self, scenario: Scenario) -> ScenarioResult:
        """Execute *scenario* and return a complete ``ScenarioResult``.

        Lifecycle per call:
        1. Start ``EchoServer`` and ``FaultyProxy`` on ephemeral ports.
        2. Connect one QUIC client per unique client name (in first-appearance
           order), establishing the proxy's ``client-N`` ID mapping.
        3. Execute each step sequentially: send GET, parse echo response, feed
           ``ProxyInstrumentation.record_backend_response()``.
        4. Tear down all connections, proxy, and echo server.
        5. Return ``ScenarioResult``.
        """
        echo = EchoServer()
        proxy = FaultyProxy(
            table_capacity=scenario.table_capacity,
        )

        echo_port = await echo.start(cert_file=self._cert, key_file=self._key)
        proxy_port = await proxy.start(
            listen_port=0,
            backend_host="localhost",
            backend_port=echo_port,
            cert_file=self._cert,
            key_file=self._key,
        )

        # Collect unique client names in first-appearance order.
        # The proxy assigns "client-0", "client-1", … in connection order,
        # so we connect them here in the same order.
        seen: list[str] = []
        for step in scenario.steps:
            if step.client not in seen:
                seen.append(step.client)

        clients: dict[str, tuple[_H3Client, asyncio.BaseTransport]] = {}
        client_id_map: dict[str, str] = {}   # handle name → proxy client_id

        try:
            for i, name in enumerate(seen):
                proto, transport = await _connect_client("localhost", proxy_port)
                clients[name] = (proto, transport)
                client_id_map[name] = f"client-{i}"

            # Execute steps sequentially.
            outcomes: list[StepOutcome] = []

            for idx, step in enumerate(scenario.steps):
                proto, _ = clients[step.client]
                proxy_cid = client_id_map[step.client]

                # Snapshot request count before sending — the proxy will call
                # begin_request() synchronously during forwarding, so after
                # await the new record is at index pre_count.
                pre_count = len(proxy.instrumentation.request_records)

                events = await proto.get(
                    "localhost", proxy_port, step.path,
                    extra_headers=step.headers if step.headers else None,
                )

                # Decode what the backend actually saw.
                backend_headers = _parse_echo_response(events)

                # Associate backend headers with the proxy's pending request.
                proxy.instrumentation.record_backend_response(proxy_cid, backend_headers)

                # Retrieve the RequestRecord for this step.
                all_records = proxy.instrumentation.request_records
                req_record = (
                    all_records[pre_count]
                    if pre_count < len(all_records)
                    else None
                )

                outcomes.append(StepOutcome(
                    index=idx,
                    label=step.label or f"step-{idx}",
                    client=step.client,
                    proxy_client_id=proxy_cid,
                    path=step.path,
                    intended=_nonpseudo_dict(step.headers),
                    received=_nonpseudo_dict(backend_headers),
                    contaminated=req_record.is_contaminated() if req_record else False,
                    discrepancies=req_record.compute_discrepancies() if req_record else [],
                    request_id=req_record.request_id if req_record else -1,
                ))

        finally:
            for proto, transport in clients.values():
                proto.close()
                transport.close()
            proxy.stop()
            echo.close()

        return ScenarioResult(
            scenario_name=scenario.name,
            table_capacity=scenario.table_capacity,
            steps=outcomes,
            instrumentation_report=proxy.instrumentation.generate_report(),
            eviction_events=proxy.instrumentation.eviction_events,
        )
