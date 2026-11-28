#!/usr/bin/env python3
"""Type TEXT on the guest's keyboard through QEMU's QMP socket (send-key:
the PS/2 keyboard, the path of a Proxmox noVNC console or the QEMU
window), for scripts/cli-test.sh's keyboard check. Lower case, digits,
space, Enter (newline) and a few punctuation keys; upper case with Shift.

usage: qmp-type.py SOCKET TEXT
"""

import json
import socket
import sys
import time

NAMES = {" ": "spc", "\n": "ret", "-": "minus", ".": "dot", "/": "slash", "=": "equal"}


def main():
    path, text = sys.argv[1], sys.argv[2]
    s = socket.socket(socket.AF_UNIX)
    s.connect(path)
    f = s.makefile("rw")
    f.readline()  # greeting

    def cmd(name, args=None):
        msg = {"execute": name}
        if args:
            msg["arguments"] = args
        f.write(json.dumps(msg) + "\n")
        f.flush()
        while True:
            r = json.loads(f.readline())
            if "return" in r or "error" in r:
                return r

    cmd("qmp_capabilities")
    for ch in text:
        keys = [{"type": "qcode", "data": "shift"}] if ch.isupper() else []
        keys.append({"type": "qcode", "data": NAMES.get(ch, ch.lower())})
        r = cmd("send-key", {"keys": keys})
        if "error" in r:
            sys.exit("qmp-type: %s" % r["error"])
        time.sleep(0.05)


main()
