#!/usr/bin/env python3
"""Send probe frames into a lab link (scripts/lab-test.sh, the "other
protocol" check): COUNT IPv4 packets with IP protocol PROTO from the
client (52:54:00:00:00:10, 192.168.1.100) to the router's LAN address
(52:54:00:00:00:02, 192.168.1.1), as UDP datagrams to 127.0.0.1:PORT
(the router's dgram netdev, or the relay's inject port). PROTO 17 sends
UDP to the unbound port 9 instead (the check's negative control with the
router's udp_unbound_drop=0, which answers it with a port unreachable).

usage: inject.py PORT PROTO COUNT
"""

import socket
import struct
import sys


def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s > 0xFFFF:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def frame(proto, ident):
    src, dst = bytes([192, 168, 1, 100]), bytes([192, 168, 1, 1])
    if proto == 17:
        data = b"probe"
        udp = struct.pack("!HHHH", 40140, 9, 8 + len(data), 0) + data
        pseudo = src + dst + struct.pack("!BBH", 0, 17, len(udp))
        c = csum(pseudo + udp) or 0xFFFF
        l4 = udp[:6] + struct.pack("!H", c) + udp[8:]
    else:
        l4 = b"leatos lab probe....."
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), ident, 0, 64, proto, 0, src, dst)
    ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
    eth = bytes.fromhex("525400000002") + bytes.fromhex("525400000010") + b"\x08\x00"
    return eth + ip + l4


def main():
    port, proto, count = map(int, sys.argv[1:4])
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for i in range(count):
        s.sendto(frame(proto, 0x4c00 + i), ("127.0.0.1", port))


if __name__ == "__main__":
    main()
