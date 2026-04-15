"""Credential-swap demo for FaultyProxy.

Demonstrates that Client B's Authorization header arrives at the backend
carrying Client A's token value, due to the shared QPACK dynamic table.

Run from the aioquic_99 directory:
    python3 tmp/demo.py
"""

import asyncio
import json
import os
import socket
import ssl
import sys  # noqa: F401 (used by sys.path.insert below)

# Ensure the project root (parent of tmp/) is on sys.path so `research` is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.asyncio.server import serve
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import ProtocolNegotiated

from research.faulty_proxy import FaultyProxy

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CERT = os.path.join(_ROOT, "tests", "ssl_cert.pem")
KEY  = os.path.join(_ROOT, "tests", "ssl_key.pem")


# ---------------------------------------------------------------------------
# Minimal echo server — returns all received request headers as JSON
# ---------------------------------------------------------------------------

class Echo(QuicConnectionProtocol):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._h = None

    def quic_event_received(self, ev): # type: ignore
        if isinstance(ev, ProtocolNegotiated) and ev.alpn_protocol in H3_ALPN:
            self._h = H3Connection(self._quic)
        if self._h:
            for e in self._h.handle_event(ev):
                if isinstance(e, HeadersReceived) and e.stream_ended:
                    hdrs = [
                        [n.decode(), v.decode(errors="replace")]
                        for n, v in e.headers
                    ]
                    body = json.dumps({"headers": hdrs}).encode()
                    self._h.send_headers(
                        e.stream_id,
                        [
                            (b":status", b"200"),
                            (b"content-length", str(len(body)).encode()),
                        ],
                    )
                    self._h.send_data(e.stream_id, body, end_stream=True)
                    self.transmit()


# ---------------------------------------------------------------------------
# Minimal HTTP/3 client
# ---------------------------------------------------------------------------

class Client(QuicConnectionProtocol):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._h = H3Connection(self._quic)
        self._waiters: dict = {}
        self._bufs: dict = {}

    def quic_event_received(self, ev): # type: ignore
        for e in self._h.handle_event(ev):
            sid = e.stream_id # type: ignore
            self._bufs.setdefault(sid, []).append(e)
            if getattr(e, "stream_ended", False) and sid in self._waiters:
                self._waiters.pop(sid).set_result(self._bufs.pop(sid))

    async def get(self, host: str, port: int, path: str, extra=()):
        headers = [
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":authority", f"{host}:{port}".encode()),
            (b":path", path.encode()),
        ] + list(extra)
        sid = self._quic.get_next_available_stream_id()
        self._h.send_headers(sid, headers, end_stream=True)
        fut = self._loop.create_future()
        self._bufs[sid] = []
        self._waiters[sid] = fut
        self.transmit()
        return await asyncio.wait_for(fut, timeout=10)


async def make_client(host: str, port: int) -> tuple:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
    addr = infos[0][4]
    if len(addr) == 2:
        addr = ("::ffff:" + addr[0], addr[1], 0, 0)
    cfg = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
    cfg.verify_mode = ssl.CERT_NONE
    cfg.server_name = host
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    sock.bind(("::", 0, 0, 0))
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: Client(QuicConnection(configuration=cfg)), sock=sock
    )
    protocol.connect(addr)
    await protocol.wait_connected()
    return protocol, transport


def parse_body(events) -> list:
    """Extract the echo server's JSON headers as [(name_bytes, value_bytes)]."""
    body = b"".join(e.data for e in events if isinstance(e, DataReceived))
    if not body:
        return []
    return [
        (row[0].encode(), row[1].encode())
        for row in json.loads(body).get("headers", [])
    ]


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

async def main():
    # Start echo backend
    srv_cfg = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN)
    srv_cfg.load_cert_chain(CERT, KEY)
    server = await serve("::", 0, configuration=srv_cfg, create_protocol=Echo)
    srv_port = server._transport.get_extra_info("sockname")[1] # type: ignore

    # Start faulty proxy in front of it
    proxy = FaultyProxy(mode="naive_name_reuse", table_capacity=4096)
    px_port = await proxy.start(0, "localhost", srv_port, CERT, KEY)

    print(f"Backend on :{srv_port}, proxy on :{px_port}")
    print()

    # Connect two independent clients to the proxy
    ca, ta = await make_client("localhost", px_port)
    cb, tb = await make_client("localhost", px_port)

    # Client A — inserts Authorization: Bearer tokenA into the shared table
    print(">>> Client A sends  Authorization: Bearer tokenA")
    ev_a = await ca.get(
        "localhost", px_port, "/resource",
        extra=[(b"authorization", b"Bearer tokenA")],
    )
    proxy.instrumentation.record_backend_response("client-0", parse_body(ev_a))

    # Give the encoder stream instruction time to reach the backend
    await asyncio.sleep(0.05)

    # Client B — proxy finds "authorization" by name → references tokenA instead
    print(">>> Client B sends  Authorization: Bearer tokenB")
    ev_b = await cb.get(
        "localhost", px_port, "/resource",
        extra=[(b"authorization", b"Bearer tokenB")],
    )
    proxy.instrumentation.record_backend_response("client-1", parse_body(ev_b))

    print()
    print(proxy.instrumentation.generate_report())

    # Close connections before exiting.
    for c in (ca, cb):
        c.close()
    for t in (ta, tb):
        t.close()
    proxy.stop()
    server.close()

    # Hard exit: QUIC retransmit timers are still pending in the event loop.
    # If we let asyncio.run() tear down normally they fire on already-closed
    # sockets (transport._loop is None by then) and print a noisy traceback.
    # Flush stdout first so the report is visible, then os._exit() skips
    # asyncio's cleanup entirely — fine for a demo script.
    sys.stdout.flush()
    os._exit(0)


asyncio.run(main())
