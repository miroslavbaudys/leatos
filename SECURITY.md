# Security policy

LeatOS is a router: it faces the internet, so security bugs matter. Thank you
for reporting them responsibly.

## Reporting a vulnerability

Please **do not open a public issue**. Report it privately through GitHub:
[Report a vulnerability](https://github.com/miroslavbaudys/leatos/security/advisories/new)
(Security tab → *Report a vulnerability*).

Useful to include:

- what is affected (forwarding/NAT, firewall, DNS, DHCP, PPPoE, the web
  interface, upgrades, …) and the commit or build you tested
- how to reproduce it, ideally a packet capture or a sequence of requests, and
  whether it needs access from the LAN or works from the WAN
- what an attacker gains (crash or reboot, firewall bypass, memory corruption,
  information leak, …)

## What to expect

This is a one-person project maintained in spare time. I aim to confirm a
report within a week and to agree on a disclosure date with you; fixes are
published as a GitHub security advisory together with the fix.

## Supported versions

There are no releases yet. Only the latest `main` is supported; fixes are not
backported.
