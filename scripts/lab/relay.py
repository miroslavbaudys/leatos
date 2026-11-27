#!/usr/bin/env python3
"""A lab link relay between the router's LAN NIC and the client VM
(scripts/lab-test.sh LAB_TCP_LOSS=N, docs/lab-tests.md).

QEMU's dgram netdevs send each Ethernet frame as one UDP datagram to
127.0.0.1:<peer>. The router sends to ROUTER_PEER, the client to
CLIENT_PEER; the relay forwards each to the other side's own port. It
drops LOSS percent of the TCP frames (IPv4 or IPv6, either direction,
VLAN-tagged too), nothing else, so the rest of the lab is unaffected.

Also: a datagram to INJECT_PORT is sent to the router as if it came from
the client (the lab's probe with an IP protocol nobody serves). The
datagrams `rst blind` and `rst exact` instead make the relay send RSTs
into the client's latest IPv4 connection to the router's port 80 (the
lab's blind-RST check, RFC 5961): it knows the router's next expected
sequence number from the client's last segment. `blind`: four RSTs in the
window but not at that number, and one far outside it; `exact`: one at it
(the negative control, which ends the connection).

Every 0.5 s (and on exit) it writes `forwarded=N tcp=N dropped=N
injected=N rst=N` to STATS, the check's proof that the loss (or the
injection) happened.

usage: relay.py ROUTER_PORT ROUTER_PEER CLIENT_PORT CLIENT_PEER LOSS SEED INJECT_PORT STATS
"""

import os
import random
import selectors
import signal
import socket
import struct
import sys
import time


def is_tcp(f):
    off = 12
    et = int.from_bytes(f[off:off + 2], "big") if len(f) >= 14 else 0
    while et in (0x8100, 0x88A8) and len(f) >= off + 6:
        off += 4
        et = int.from_bytes(f[off:off + 2], "big")
    ip = off + 2
    if et == 0x0800 and len(f) > ip + 9:
        return f[ip + 9] == 6
    if et == 0x86DD and len(f) > ip + 6:
        return f[ip + 6] == 6
    return False


def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s > 0xFFFF:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def to_router80(f):
    """The client's IPv4 TCP segment to port 80: (frame header, src, dst,
    sport, the sequence number after it), else None."""
    off = 12
    et = int.from_bytes(f[off:off + 2], "big") if len(f) >= 14 else 0
    while et in (0x8100, 0x88A8) and len(f) >= off + 6:
        off += 4
        et = int.from_bytes(f[off:off + 2], "big")
    ip = off + 2
    if et != 0x0800 or len(f) < ip + 20 or f[ip + 9] != 6:
        return None
    ihl = (f[ip] & 0xF) * 4
    tot = int.from_bytes(f[ip + 2:ip + 4], "big")
    t = ip + ihl
    if len(f) < t + 20 or int.from_bytes(f[t + 2:t + 4], "big") != 80:
        return None
    doff = (f[t + 12] >> 4) * 4
    flags = f[t + 13]
    seq = int.from_bytes(f[t + 4:t + 8], "big")
    nxt = seq + (tot - ihl - doff) + (flags & 1) + ((flags >> 1) & 1)
    sport = int.from_bytes(f[t:t + 2], "big")
    return f[:ip], f[ip + 12:ip + 16], f[ip + 16:ip + 20], sport, nxt & 0xFFFFFFFF


def rst(conn, seq, ident):
    eth, src, dst, sport, _ = conn
    tcp = struct.pack("!HHIIBBHHH", sport, 80, seq & 0xFFFFFFFF, 0, 5 << 4, 0x04, 0, 0, 0)
    c = csum(src + dst + struct.pack("!BBH", 0, 6, len(tcp)) + tcp)
    tcp = tcp[:16] + struct.pack("!H", c) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), ident, 0, 64, 6, 0, src, dst)
    ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
    return eth + ip + tcp


def main():
    rport, rpeer, cport, cpeer, loss, seed, inject, stats = sys.argv[1:9]
    rport, rpeer, cport, cpeer, inject = map(int, (rport, rpeer, cport, cpeer, inject))
    loss = float(loss)
    rng = random.Random(int(seed))
    lo = "127.0.0.1"
    from_router = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    from_router.bind((lo, rpeer))
    from_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    from_client.bind((lo, cpeer))
    inj = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    inj.bind((lo, inject))
    sel = selectors.DefaultSelector()
    # Each side's frames leave from the socket the other side sends to.
    sel.register(from_router, selectors.EVENT_READ, (from_client, cport))
    sel.register(from_client, selectors.EVENT_READ, (from_router, rport))
    sel.register(inj, selectors.EVENT_READ, (from_client, rport))
    n = {"forwarded": 0, "tcp": 0, "dropped": 0, "injected": 0, "rst": 0}
    conn = None  # the client's latest segment to the router's port 80

    def dump():
        with open(stats + ".tmp", "w") as fh:
            fh.write(" ".join("%s=%d" % kv for kv in n.items()) + "\n")
        os.replace(stats + ".tmp", stats)

    def stop(*_):
        dump()
        sys.exit(0)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    last = 0.0
    while True:
        for key, _ in sel.select(0.5):
            out, port = key.data
            f, _ = key.fileobj.recvfrom(65536)
            if key.fileobj is inj and f.startswith(b"rst "):
                if conn is not None:
                    nxt = conn[4]
                    offs = [0] if f[4:].strip() == b"exact" else [1, 100, 1000, 20000, 1 << 31]
                    for i, d in enumerate(offs):
                        out.sendto(rst(conn, nxt + d, 0x5200 + i), (lo, port))
                        n["rst"] += 1
                continue
            if key.fileobj is inj:
                n["injected"] += 1  # from the client's side, to the router
            elif is_tcp(f):
                if key.fileobj is from_client:
                    conn = to_router80(f) or conn
                n["tcp"] += 1
                if rng.random() * 100 < loss:
                    n["dropped"] += 1
                    continue
            out.sendto(f, (lo, port))
            n["forwarded"] += 1
        now = time.monotonic()
        if now - last >= 0.5:
            dump()
            last = now


if __name__ == "__main__":
    main()
