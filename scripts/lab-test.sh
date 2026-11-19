#!/usr/bin/env bash
# End-to-end lab: three QEMU VMs joined by UDP socket links (no root needed).
#
#   [client]  ──LAN 10004<->10003──  [rrouter]  ──WAN 10005<->10006──  [ISP]
#   Alpine, DHCP client              192.168.1.1 / DHCP from ISP        203.0.113.1
#   runs all checks                  DHCP srv, DNS, NAT, firewall       udhcpd, httpd, dnsd
#
# The client (lab/client/init) checks LAN services (DHCP, DNS zone,
# upstream DNS via the ISP, cache prefetch, serve-stale) and forwarding (TCP/ICMP through NAT, NATed
# source, traceroute = TTL + ICMP-error NAT, 20 connections, firewall probe
# from the ISP side), printing "LAB PASS/FAIL" lines.
# Exit code 0 = all checks passed.
#
#   LAB_VERBOSE=1        print all three consoles
#   LAB_PCAP_DIR=dir     capture router WAN/LAN traffic to pcap
#   LAB_KEEP_LOGS=1      keep console logs (path printed)
#   LAB_TIMEOUT=150      seconds before giving up
#   QEMU_ACCEL=tcg       run without hardware acceleration
#   RROUTER_ARCH=x86_64  run the x86_64 router kernel (QEMU q35, TCG); the
#                        client and ISP VMs stay aarch64
#   LAB_SHAPE_KBIT=10000 router shapes both directions at this rate and the
#                        client checks throughput + latency under load
#                        (0 = unshaped router, shaping checks skipped)
#   LAB_EXPECT_KBIT=N    what the client expects (default: LAB_SHAPE_KBIT);
#                        set it with LAB_SHAPE_KBIT=0 as a negative control
#   LAB_ROUTER_ARGS="…"  extra router boot arguments, e.g. qdisc=codel (single
#                        CoDel queue: the negative control for the flow-
#                        isolation latency check), or dns_prefetch=0 (the
#                        negative control for the DNS prefetch check: a
#                        second forwarded query, no renewal), or dns_stale=0
#                        (the negative control for the serve-stale check:
#                        SERVFAIL with the ISP's DNS stopped)
#   LAB_EXPECT_ECN=U:D   ECN the check expects per direction (1 = marks, 0 =
#                        drops; default: derived from the router arguments,
#                        i.e. 0:1). Set it against the router's real setting
#                        as a negative control, e.g. LAB_ROUTER_ARGS=ecn=1
#                        with the default expectation.
#
#   LAB_VLAN=N           the ISP serves on 802.1Q VLAN N only and the router
#                        gets wan_vlan=N (after LAB_ROUTER_ARGS, so those win).
#                        Negative controls: LAB_ROUTER_ARGS=wan_vlan=0
#                        (untagged) or another VLAN must fail (no WAN lease).
#   LAB_BIG_PING=1472    ICMP data size of the client's full-size ping
#                        (1473 = fragmented: passes since fragments are
#                        forwarded; with LAB_ROUTER_ARGS=fw_frag=0 it is the
#                        negative control). The fragmented ping (-s 3000,
#                        fwd::frag) has fw_frag=0 as its negative control;
#                        over PPPoE the router splits its 1500 B fragments
#                        (fw_split=0: the negative control).
#                        With PPPoE the default is 1464 (MTU 1492; 1465 =
#                        too big for the session: the client's ping has DF,
#                        gets "fragmentation needed" and passes as fragments
#                        it cuts itself; LAB_ROUTER_ARGS=fw_frag=0 is then
#                        its negative control).
#   LAB_PPPOE=pap|chap|none  the ISP is a PPPoE access concentrator only (no
#                        DHCP; pppoe-server from the pinned packages, needs
#                        modloop) requiring PAP or CHAP; the router gets
#                        wan_mode=pppoe pppoe_user=rrouter pppoe_pass=lab-secret
#                        (LAB_ROUTER_ARGS win). Checks: session up (router
#                        log), all client checks through it, and a reconnect
#                        after the ISP ends the session. Negative controls:
#                        LAB_ROUTER_ARGS=pppoe_pass=wrong or wan_mode=dhcp
#                        (no session, everything fails), LAB_PPPOE_KICK=stop
#                        (the ISP's server is stopped too: no reconnect).
#                        Combines with LAB_VLAN=N (PPPoE on the VLAN).
#                        none: the ISP asks for no authentication and the
#                        router has no user name (wan_mode=pppoe only);
#                        negative control: LAB_PPPOE=pap
#                        LAB_PPPOE_ANON=1 (no user name against an ISP
#                        requiring PAP: no session).
#   LAB_WAN_STATIC=1     the ISP runs no DHCP server; the router gets
#                        wan_mode=static wan_ip=203.0.113.60/24
#                        wan_gw=203.0.113.1 wan_dns=203.0.113.1 (LAB_ROUTER_ARGS
#                        win). Checks: the router's static line and the ISP
#                        seeing 203.0.113.60 as the NATed source; all other
#                        checks run through it. Negative control:
#                        LAB_ROUTER_ARGS=wan_mode=dhcp (no address, everything
#                        fails).
#   LAB_GUEST=1          the router boots from a store (tools/rrstore) with a
#                        second network: VLAN 20 on lan0, 10.20.0.1/24, zone
#                        "guest" (input: DHCP, DNS, ping; forwards to the
#                        WAN only). The client adds eth0.20 (8021q from
#                        modloop) and checks: guest lease, guest -> ISP,
#                        DNS + ping to the router allowed, the router's web
#                        interface blocked, new connections to the main LAN
#                        refused (router firewall drop counter). Negative
#                        control: LAB_GUEST_ZONE=lan puts the network in the
#                        main zone, so the last two checks must fail.
#                        Rules (step 4): guest-ping-nas (accept ICMP from
#                        the guest to 192.168.1.10, which the zones refuse)
#                        and guest-no-isp-web (reject guest TCP 80 to the
#                        WAN); the client checks both through the rules'
#                        hit counters and the traffic. Negative control:
#                        LAB_GUEST_RULES=0 (config without them: both fail).
#                        Reject: the refused HTTP fails at once ("Connection
#                        refused": the router's RST) and the router's
#                        "rejected" counter rises; negative control
#                        LAB_GUEST_REJECT=drop (the rule drops: it times out).
#                        Recheck: a guest ping to the ISP stops when a live
#                        config takes the guest zone's internet away
#                        (tracked connections removed, "revoked" counter);
#                        negative control LAB_ROUTER_ARGS=fw_recheck=0.
#                        Port forward (step 5): lab-web, the WAN address
#                        :8080 -> the client's httpd (reserved at .100),
#                        with hairpin; the ISP fetches through it and the
#                        client through the WAN address. Negative control:
#                        LAB_FORWARD=0 (no forward: both fail).
#                        Forward target out: forward lab-src (WAN :8090 ->
#                        client :8090); a connection from the client's
#                        :8090 leaves from the WAN's :8090 (ISP
#                        cgi-bin/srcport reports the port); LAB_FORWARD=0
#                        fails it (a NAPT port). Such a connection survives
#                        a live config change elsewhere (a rule added while
#                        cgi-bin/slow idles 12 s); negative control
#                        LAB_FWD_CUT=1 (the rule rejects the ISP: it ends).
#                        Anti-spoofing: the ISP opens a connection to the
#                        forward from the forged source 192.168.1.77
#                        (cgi-bin/spoof): dropped as "spoofed", forward
#                        hits unchanged; negative control
#                        LAB_ROUTER_ARGS=wan_antispoof=0.
#                        Redirect: lab-ntp sends NTP (UDP 123) to any outside
#                        server to 192.168.1.101 (a second address on the
#                        client, busybox ntpd -l); the client asks
#                        203.0.113.99 (no such host) from the main LAN and
#                        from the guest, both must be answered, and the
#                        redirect's hit counter must rise. Negative control:
#                        LAB_REDIRECT=0 (no redirect: both fail).
#                        DNS domain: the guest network has its own,
#                        guest.lan (nested in the LAN's lan); checks: the
#                        guest lease's domain, labguest.guest.lan and
#                        router.guest.lan resolve, labclient.guest.lan is
#                        NXDOMAIN. Negative control: LAB_GUEST_DOMAIN=0
#                        (no domain line: the first three fail).
#   LAB_MDNS=1           (implies LAB_GUEST=1) mDNS across networks
#                        (docs/mdns.md): the guest zone allows "mdns" and
#                        the rule guest-printers reflects _ipp._tcp from
#                        guest to lan. The client announces a printer
#                        (_ipp._tcp + _ssh._tcp) on VLAN 20; checks: the
#                        router's counters (guest received, lan sent) and,
#                        on the LAN capture, the copy from 192.168.1.1 to
#                        224.0.0.251 with TTL 255 holding _ipp but not
#                        _ssh, plus the router's IGMP joins on both
#                        networks. Negative control: LAB_MDNS_RULES=0 (the
#                        rule disabled: every mDNS check fails).
#   LAB_DNS_VIEWS=1      (implies LAB_GUEST=1) split-horizon local DNS
#                        (docs/dns-views.md): dns.views = "firewall", a
#                        name with one address per network (split.lan:
#                        .50 on each) and an override of a public name for
#                        the LAN only (files.isp.example -> the client).
#                        Checks: from the guest, labclient.lan and its PTR
#                        are NXDOMAIN (the guest zone cannot reach the LAN)
#                        and the router's "hidden" counter rises, nas.lan
#                        still resolves (rule guest-ping-nas reaches it);
#                        split.lan answers per network (and its entries'
#                        hits in /api/status dns.hosts rise); files.isp.example
#                        is the client on the LAN and the ISP's answer on
#                        the guest network. Negative controls:
#                        LAB_DNS_VIEWS=0 (views "all": the hiding checks
#                        fail), LAB_DNS_HOSTS=0 (no [[dns.host]]: split,
#                        its hits and override fail), LAB_GUEST_RULES=0 (nas.lan hidden).
#   LAB_DOT=1            DNS over TLS, strict (docs/dns-over-tls.md): the
#                        router boots from a store with dns.tls, upstream
#                        203.0.113.1#dns.isp.example and a CA made for this
#                        run in dns.tls_ca; the ISP serves DoT (stunnel +
#                        dnsmasq) with that CA's certificate. Checks: the
#                        client resolves dot.isp.example (only the DoT
#                        server has it) but not plain.isp.example (only the
#                        plain dnsd has it), the router's connection came
#                        up (log), the ISP's DoT server saw the queries.
#                        Negative controls: LAB_DOT_NAME=wrong.example (name
#                        mismatch), LAB_DOT_CA=0 (lab CA not trusted: only
#                        Mozilla's roots) and LAB_ROUTER_ARGS=dns_tls=0
#                        (plain DNS to the same server): the checks fail,
#                        the first two without any plain DNS either.
#                        Certificate dates before SNTP: checked against the
#                        battery-backed RTC on x86_64 (CMOS), at the
#                        certificate's issue time on aarch64 (no RTC); the
#                        check reads which from the router's log
#                        (LAB_EXPECT_DATES=rtc|issue|expired overrides).
#                        Control: RROUTER_ARCH=x86_64
#                        QEMU_EXTRA="-rtc base=2040-01-01" with
#                        LAB_EXPECT_DATES=expired: an RTC far ahead must not
#                        break DNS (accepted until SNTP), and SNTP then
#                        sets the RTC ("rtc ... was N s off, set").
#   LAB_WAN_OPEN=1       (implies LAB_GUEST=1) negative control for the WAN
#                        input check: a rule accepting wan -> router, so the
#                        router answers the ISP's probes (RST, ping) again.
#   LAB_ROUTES=1         (implies LAB_GUEST=1) static routes: [[route]]
#                        lab-behind = 10.30.0.0/24 via the client
#                        (192.168.1.100), which puts 10.30.0.5 on its
#                        loopback. Checks: DHCP option 121 (the route plus
#                        the default), 10.30.0.5 reaches the ISP through
#                        NAT and the router itself, /api/status lists the
#                        route, the ISP forging 10.30.0.5 is dropped as
#                        spoofed. Negative control: LAB_ROUTES=0 (the route
#                        disabled: every check fails).
#   LAB_PORTS=1          (implies LAB_GUEST=1) a second LAN port: the router
#                        gets a third NIC (lan1), network "wired"
#                        10.40.0.1/24 untagged on it (zone lan); the client
#                        gets a second NIC on that wire and moves it into a
#                        network namespace. Checks: a lease from 10.40.0.0/24
#                        on it, ping router and ISP from there, /api/status
#                        shows wired on lan1, main LAN -> wired runs above
#                        twice the download rate. Negative control:
#                        LAB_PORTS_NET=lan0 (the network on lan0, VLAN 40:
#                        the lan1 wire gets no lease, so the checks fail).
#                        With LAB_GUEST_LIVE=1 the network is added live.
#   LAB_GUEST_LIVE=1     the same, but added live: the router boots with the
#                        main LAN only (and mgmt_pass=lab-pass); the client
#                        POSTs the guest config (in its initrd) to
#                        /api/config first, expects it applied without a
#                        reboot, then runs every check against it.
#
# SNTP: the router syncs from the ISP's ntpd (ntp=ntp.isp.example: resolved
# through the router's DNS forwarder) and its clock must then be within 5 s
# of the host's. Negative control: LAB_ROUTER_ARGS=ntp=203.0.113.99
# (nothing answers there) must fail the check.
set -euo pipefail
cd "$(dirname "$0")/.."

TIMEOUT="${LAB_TIMEOUT:-150}"
SHAPE_KBIT="${LAB_SHAPE_KBIT:-10000}"
EXPECT_KBIT="${LAB_EXPECT_KBIT:-$SHAPE_KBIT}"
ROUTER_ARGS=""
[[ "$SHAPE_KBIT" != 0 ]] && ROUTER_ARGS="shape_up=$SHAPE_KBIT shape_down=$SHAPE_KBIT"
ROUTER_ARGS="$ROUTER_ARGS ${LAB_ROUTER_ARGS:-}"
# The first ntp= wins: only add the default when the caller sets none.
[[ " ${LAB_ROUTER_ARGS:-} " == *" ntp="* ]] || ROUTER_ARGS="$ROUTER_ARGS ntp=ntp.isp.example"
ISP_VLAN="${LAB_VLAN:-}"
# The router takes the first occurrence of an argument: LAB_ROUTER_ARGS wins.
[[ -n "$ISP_VLAN" ]] && ROUTER_ARGS="$ROUTER_ARGS wan_vlan=$ISP_VLAN"
ISP_PPPOE="${LAB_PPPOE:-}"
[[ "$ISP_PPPOE" == 1 ]] && ISP_PPPOE=pap
BIG_PING="${LAB_BIG_PING:-1472}"
if [[ -n "$ISP_PPPOE" ]]; then
  # No user name with LAB_PPPOE=none (or the LAB_PPPOE_ANON=1 control).
  if [[ "$ISP_PPPOE" == none || -n "${LAB_PPPOE_ANON:-}" ]]; then
    ROUTER_ARGS="$ROUTER_ARGS wan_mode=pppoe"
  else
    ROUTER_ARGS="$ROUTER_ARGS wan_mode=pppoe pppoe_user=rrouter pppoe_pass=lab-secret"
  fi
  BIG_PING="${LAB_BIG_PING:-1464}"
fi
ISP_STATIC="${LAB_WAN_STATIC:-}"
[[ -n "$ISP_STATIC" ]] && ROUTER_ARGS="$ROUTER_ARGS wan_mode=static wan_ip=203.0.113.60/24 wan_gw=203.0.113.1 wan_dns=203.0.113.1"
GUEST="${LAB_GUEST:-}"
GUEST_LIVE="${LAB_GUEST_LIVE:-}"
[[ -n "$GUEST_LIVE" ]] && GUEST=1
MDNS="${LAB_MDNS:-}"
MDNS_RULES="${LAB_MDNS_RULES:-1}"
[[ -n "$MDNS" ]] && GUEST=1
WAN_OPEN="${LAB_WAN_OPEN:-}"
DNS_VIEWS="${LAB_DNS_VIEWS:-}"
ROUTES="${LAB_ROUTES:-}"
[[ -n "$ROUTES" ]] && GUEST=1
PORTS="${LAB_PORTS:-}"
PORTS_NET="${LAB_PORTS_NET:-lan1}"
[[ -n "$PORTS" ]] && GUEST=1
DNS_HOSTS="${LAB_DNS_HOSTS:-1}"
[[ -n "$DNS_VIEWS" ]] && GUEST=1
[[ -n "$WAN_OPEN" ]] && GUEST=1
GUEST_ZONE="${LAB_GUEST_ZONE:-guest}"
GUEST_RULES="${LAB_GUEST_RULES:-1}"
GUEST_REJECT="${LAB_GUEST_REJECT:-reject}"
FORWARD="${LAB_FORWARD:-1}"
FWD_CUT="${LAB_FWD_CUT:-}"
REDIRECT="${LAB_REDIRECT:-1}"
GUEST_DOMAIN="${LAB_GUEST_DOMAIN:-1}"
DOT="${LAB_DOT:-}"
DOT_NAME="${LAB_DOT_NAME:-dns.isp.example}"
DOT_CA="${LAB_DOT_CA:-1}"
LAN_PORT="${LAB_LAN_PORT:-10003}"
WAN_PORT="${LAB_WAN_PORT:-10005}"
LAN1_PORT="${LAB_LAN1_PORT:-10007}"
WORK=$(mktemp -d -t rrouter-lab)
PCAP_DIR="${LAB_PCAP_DIR:-}"
[[ -n "$MDNS" && -z "$PCAP_DIR" ]] && PCAP_DIR="$WORK/pcap"
PIDS=()
cleanup() {
  for p in "${PIDS[@]:-}"; do [[ -n "$p" ]] && kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  if [[ "${LAB_KEEP_LOGS:-0}" == "1" ]]; then echo "logs: $WORK"; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

source scripts/lab/common.sh
lab_cpu_flags

echo "== build"
ARCH="${RROUTER_ARCH:-aarch64}"
cargo build -q -p rrouter-kernel --target "$ARCH-unknown-none"
MODLOOP=""
[[ -n "$ISP_VLAN$ISP_PPPOE$GUEST" ]] && MODLOOP=modloop
ALPINE_DIR=$(scripts/lab/fetch-alpine.sh $MODLOOP | tail -1)
ISP_INITRD=$(scripts/lab/build-initrd.sh isp | tail -1)
CLIENT_INITRD=$(scripts/lab/build-initrd.sh client | tail -1)

if [[ -n "$DOT" ]]; then
  # A CA and the ISP's DoT certificate (RSA under an ECDSA CA), made per run
  # and valid from now; the server's half goes into the ISP's initrd.
  mkdir -p "$WORK/dot/etc/dot"; d="$WORK/dot"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$d/ca.key" -out "$d/ca.pem" -days 30 \
    -subj "/CN=rrouter lab CA" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
  openssl req -newkey rsa:2048 -nodes -keyout "$d/etc/dot/server.key" -out "$d/server.csr" -subj "/CN=dns.isp.example" 2>/dev/null
  printf 'subjectAltName=DNS:dns.isp.example\nbasicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n' >"$d/ext.cnf"
  openssl x509 -req -in "$d/server.csr" -CA "$d/ca.pem" -CAkey "$d/ca.key" -CAcreateserial -days 30 -extfile "$d/ext.cnf" -out "$d/etc/dot/server.pem" 2>/dev/null
  ( cd "$d" && find etc | cpio -o -H newc 2>/dev/null | gzip -9 ) >"$WORK/isp-dot.cpio.gz"
  cat "$ISP_INITRD" "$WORK/isp-dot.cpio.gz" >"$WORK/isp-initrd.img"
  ISP_INITRD="$WORK/isp-initrd.img"
fi
# The router's [dns] section: DNS over TLS (LAB_DOT=1), views and local
# records (LAB_DNS_VIEWS); nothing without either.
dns_toml() {
  [[ -n "$DOT$DNS_VIEWS" ]] || return 0
  printf '\n[dns]\n'
  if [[ -n "$DOT" ]]; then
    printf 'tls = true\nupstreams = ["203.0.113.1#%s"]\n' "$DOT_NAME"
    if [[ "$DOT_CA" == 1 ]]; then printf 'tls_ca = """\n'; cat "$WORK/dot/ca.pem"; printf '"""\n'; fi
  fi
  [[ "$DNS_VIEWS" == 1 ]] && printf 'views = "firewall"\n'
  if [[ -n "$DNS_VIEWS" && "$DNS_HOSTS" == 1 ]]; then
    printf '\n[[dns.host]]\nname = "split"\nip = "192.168.1.50"\nnetworks = ["lan"]\n'
    printf '\n[[dns.host]]\nname = "split"\nip = "10.20.0.50"\nnetworks = ["guest"]\n'
    printf '\n[[dns.host]]\nname = "files.isp.example"\nip = "192.168.1.100"\nnetworks = ["lan"]\n'
  fi
  return 0
}

echo "== start ISP (203.0.113.1${ISP_VLAN:+ on VLAN $ISP_VLAN}${ISP_PPPOE:+, PPPoE $ISP_PPPOE}${DOT:+, DNS over TLS})"
start_isp "$WAN_PORT" "$WORK/isp.log" || exit 1

ROUTER_STORE=""
if [[ -n "$GUEST" ]]; then
  # Two networks; the stored config replaces the VM fixtures, so the nas
  # reservation the client resolves is listed here.
  cat >"$WORK/config.toml" <<CFG
version = 2

[[network]]
name = "lan"
ipv4 = "192.168.1.1/24"
[[network.dhcp.static]]
mac = "52:54:00:00:00:05"
ip = "192.168.1.10"
hostname = "nas"
[[network.dhcp.static]]
mac = "52:54:00:00:00:10"
ip = "192.168.1.100"
hostname = "labclient"

[[network]]
name = "guest"
vlan = 20
ipv4 = "10.20.0.1/24"
zone = "$GUEST_ZONE"
$([[ "$GUEST_DOMAIN" == 1 ]] && echo 'domain = "guest.lan"')

[[zone]]
name = "guest"
input = "drop"
allow = ["dhcp", "dns", "ping"$([[ -n "$MDNS" ]] && echo ', "mdns"')]
forward_to = ["wan"]

$([[ -n "$PORTS" ]] && printf '\n# The second LAN port (LAB_PORTS): untagged on lan1, or the negative\n# control on lan0 as VLAN 40.\n[[network]]\nname = "wired"\nports = ["%s"]\n%s\nipv4 = "10.40.0.1/24"\n' "$PORTS_NET" "$([[ "$PORTS_NET" == lan0 ]] && echo 'vlan = 40')")

# The client's "lan to guest" throughput check (WAN ingress shaping).
[[firewall.rule]]
name = "lab-lan-to-guest"
from = "lan"
to = "guest"
proto = "tcp"
dst_port = 8081
action = "accept"
CFG
  [[ -n "$MDNS" ]] && cat >>"$WORK/config.toml" <<CFG

[[mdns.reflect]]
name = "guest-printers"
enabled = $([[ "$MDNS_RULES" == 1 ]] && echo true || echo false)
from = "guest"
to = ["lan"]
services = ["_ipp._tcp"]
CFG
  [[ "$GUEST_RULES" == 1 ]] && cat >>"$WORK/config.toml" <<CFG

[[firewall.rule]]
name = "guest-ping-nas"
from = "guest"
to = "lan"
proto = "icmp"
dst = "192.168.1.10"
action = "accept"

[[firewall.rule]]
name = "guest-no-isp-web"
from = "guest"
to = "wan"
proto = "tcp"
dst_port = 80
action = "$GUEST_REJECT"
CFG
  [[ -n "$WAN_OPEN" ]] && cat >>"$WORK/config.toml" <<'CFG'

[[firewall.rule]]
name = "wan-open"
from = "wan"
to = "router"
action = "accept"
CFG
  [[ "$FORWARD" == 1 ]] && cat >>"$WORK/config.toml" <<'CFG'

[[firewall.forward]]
name = "lab-web"
wan_port = 8080
to = "192.168.1.100:8080"

[[firewall.forward]]
name = "lab-src"
wan_port = 8090
to = "192.168.1.100:8090"
CFG
  [[ "$REDIRECT" == 1 ]] && cat >>"$WORK/config.toml" <<'CFG'

[[firewall.redirect]]
name = "lab-ntp"
from = "any"
dst_port = 123
to = "192.168.1.101"
CFG
  [[ -n "$ROUTES" ]] && cat >>"$WORK/config.toml" <<CFG

[[route]]
name = "lab-behind"
enabled = $([[ "$ROUTES" == 1 ]] && echo true || echo false)
dst = "10.30.0.0/24"
via = "192.168.1.100"
CFG
  dns_toml >>"$WORK/config.toml"
  cargo build -q -p rrstore --release
  target/release/rrstore create "$WORK/store.img" --mib 32 >/dev/null
  target/release/rrstore put "$WORK/store.img" config "$WORK/config.toml" >/dev/null
  if [[ -n "$GUEST_LIVE" ]]; then
    # Boot with the main LAN only (everything before the second network);
    # the client adds the rest live.
    awk '/^\[\[network\]\]$/ { n++ } n < 2' "$WORK/config.toml" >"$WORK/boot.toml"
    target/release/rrstore create "$WORK/store.img" --mib 32 >/dev/null
    target/release/rrstore put "$WORK/store.img" config "$WORK/boot.toml" >/dev/null
    # The full config goes into the client's initrd (an extra cpio archive).
    mkdir -p "$WORK/extra"; cp "$WORK/config.toml" "$WORK/extra/guest.toml"
    ( cd "$WORK/extra" && echo guest.toml | cpio -o -H newc 2>/dev/null | gzip -9 ) >"$WORK/extra.cpio.gz"
    cat "$CLIENT_INITRD" "$WORK/extra.cpio.gz" >"$WORK/client-initrd.img"
    CLIENT_INITRD="$WORK/client-initrd.img"
  fi
  ROUTER_STORE="$WORK/store.img"
  # Live config changes (LAB_GUEST_LIVE, the recheck check) need it.
  ROUTER_ARGS="$ROUTER_ARGS mgmt_pass=lab-pass"
  echo "== router config${GUEST_LIVE:+ (added live by the client)}: networks lan + guest (VLAN 20, zone $GUEST_ZONE)$([[ "$GUEST_RULES" == 1 ]] && echo ", 2 rules")$([[ "$FORWARD" == 1 ]] && echo ", port forward")$([[ "$REDIRECT" == 1 ]] && echo ", NTP redirect")$([[ "$GUEST_DOMAIN" == 1 ]] && echo ", domain guest.lan")$([[ -n "$MDNS" ]] && echo ", mdns reflect (enabled: $MDNS_RULES)")$([[ -n "$ROUTES" ]] && echo ", route lab-behind (enabled: $([[ "$ROUTES" == 1 ]] && echo yes || echo no))")$([[ -n "$DNS_VIEWS" ]] && echo ", dns views $([[ "$DNS_VIEWS" == 1 ]] && echo firewall || echo all), dns hosts $DNS_HOSTS")"
fi

if [[ -n "$DOT" && -z "$GUEST" ]]; then
  # The main LAN as the VM defaults have it (the nas reservation), plus DNS over TLS.
  cat >"$WORK/config.toml" <<'CFG'
version = 2

[[network]]
name = "lan"
ipv4 = "192.168.1.1/24"
[[network.dhcp.static]]
mac = "52:54:00:00:00:05"
ip = "192.168.1.10"
hostname = "nas"
CFG
  dns_toml >>"$WORK/config.toml"
  cargo build -q -p rrstore --release
  target/release/rrstore create "$WORK/store.img" --mib 32 >/dev/null
  target/release/rrstore put "$WORK/store.img" config "$WORK/config.toml" >/dev/null
  ROUTER_STORE="$WORK/store.img"
fi
[[ -n "$DOT" ]] && echo "== router config: DNS over TLS to 203.0.113.1#$DOT_NAME$([[ "$DOT_CA" == 1 ]] && echo ", lab CA trusted" || echo ", Mozilla's roots only")"

echo "== start rrouter${ROUTER_ARGS:+ ($(echo "$ROUTER_ARGS" | sed 's/pppoe_pass=[^ ]*/pppoe_pass=***/'))}"
QEMU_STORE="$ROUTER_STORE" QEMU_NET=lab LAB_LAN_PORT="$LAN_PORT" LAB_WAN_PORT="$WAN_PORT" LAB_LAN1_PORT="${PORTS:+$LAN1_PORT}" QEMU_PCAP_DIR="$PCAP_DIR" QEMU_ACCEL="$QEMU_ACCEL" QEMU_APPEND="$ROUTER_ARGS" \
  scripts/qemu-run.sh "target/$ARCH-unknown-none/debug/rrouter" >"$WORK/router.log" 2>&1 &
PIDS+=($!)
wait_for "$WORK/router.log" "rrouter: boot ok" 40 || { echo "router did not boot:"; cat "$WORK/router.log"; exit 1; }
# When the host sees the router's first SNTP sync (compared with the time
# the router then reports).
( wait_for "$WORK/router.log" "ntp  .*synced to" 90 && date -u +%s >"$WORK/ntp-seen" ) &
PIDS+=($!)

echo "== start client"
VM_DISK="${GUEST:+$ALPINE_DIR/modloop-virt}" \
  VM_NIC2="${PORTS:+52:54:00:00:00:11 $((LAN1_PORT + 1)) $LAN1_PORT}" \
  linux_vm "$CLIENT_INITRD" 52:54:00:00:00:10 $((LAN_PORT + 1)) "$LAN_PORT" "$WORK/client.log" "lab_shape_kbit=$EXPECT_KBIT lab_big_ping=$BIG_PING${ISP_PPPOE:+ lab_pppoe_kick=${LAB_PPPOE_KICK:-kick}}${GUEST:+ lab_guest=$GUEST_ZONE lab_guest_rules=$GUEST_RULES lab_forward=$FORWARD${FWD_CUT:+ lab_fwd_cut=1} lab_redirect=$REDIRECT lab_guest_domain=$GUEST_DOMAIN}${GUEST_LIVE:+ lab_guest_live=1}${MDNS:+ lab_mdns=$MDNS_RULES}${DOT:+ lab_dot=1}${DNS_VIEWS:+ lab_dns_views=$DNS_VIEWS lab_dns_hosts=$DNS_HOSTS}${ROUTES:+ lab_routes=$ROUTES}${PORTS:+ lab_ports=$PORTS_NET}"
wait_for "$WORK/client.log" "LAB DONE" "$TIMEOUT" || echo "client did not finish within ${TIMEOUT}s"
sleep 0.5
# The router prints qdisc counters every 10 s: wait for one more round so
# they include the client's last (upload) phase.
if [[ "$SHAPE_KBIT" != 0 ]]; then
  n0=$(tr -d '\r' <"$WORK/router.log" | grep -c "qdisc wan0" || true)
  for _ in $(seq 1 130); do
    [[ $(tr -d '\r' <"$WORK/router.log" | grep -c "qdisc wan0" || true) -gt "$n0" ]] && break
    sleep 0.1
  done
fi

if [[ "${LAB_VERBOSE:-0}" == "1" ]]; then
  for vm in isp router client; do
    echo "== $vm console"; tr -d '\r' <"$WORK/$vm.log" | sed "s/^/  ${vm:0:1}| /"
  done
fi

echo "== router"
tr -d '\r' <"$WORK/router.log" | grep -E "dhcp  |lan services|dns-over-tls|rtc  |dns upstreams|net lan0  |net wan0 .*(lease|vlan|PPPoE)|pppoe |net ping|qos |qdisc |cpu  |ntp  |watchdog  |vlan  " | sed 's/^/  /' || true
echo "== results"
tr -d '\r' <"$WORK/client.log" | grep -E "^LAB (PASS|FAIL|INFO|WARN)|^    \|" | sed 's/^/  /' || true

# Per-direction ECN (router side): with ECN on, the AQM marks the client's
# ECN-capable traffic; with it off, it drops and never marks. Upload = WAN
# egress, download = the WAN ingress stage (LAN egress with
# shape_ingress=0).
router_fails=0
if [[ "$SHAPE_KBIT" != 0 ]]; then
  bootarg() { echo " $ROUTER_ARGS " | sed -n "s/.* $1=\([0-9]*\) .*/\1/p"; }
  all=$(bootarg ecn)
  up=$(bootarg ecn_up); up=${up:-${all:-0}}
  down=$(bootarg ecn_down); down=${down:-${all:-1}}
  if [[ -n "${LAB_EXPECT_ECN:-}" ]]; then up=${LAB_EXPECT_ECN%%:*}; down=${LAB_EXPECT_ECN##*:}; fi
  downq=ingress
  [[ " $ROUTER_ARGS " == *" shape_ingress=0 "* ]] && downq=lan0
  for pair in "wan0 upload $up" "$downq download $down"; do
    set -- $pair
    line=$(tr -d '\r' <"$WORK/router.log" | grep "qdisc $1 " | tail -1)
    drops=$(echo "$line" | sed -n 's/.*aqm drops \([0-9]*\).*/\1/p')
    marks=$(echo "$line" | sed -n 's/.*ecn marks \([0-9]*\).*/\1/p')
    what="$2 ($1): aqm drops ${drops:-?}, ecn marks ${marks:-?}"
    if [[ -z "$drops" || -z "$marks" ]]; then
      echo "  LAB FAIL: ecn $what (no router counters)"; router_fails=$((router_fails + 1))
    elif [[ "$3" == 1 && "$marks" -gt 0 ]]; then
      echo "  LAB PASS: ecn $2 on: $what"
    elif [[ "$3" == 0 && "$marks" == 0 && "$drops" -gt 0 ]]; then
      echo "  LAB PASS: ecn $2 off: $what"
    else
      echo "  LAB FAIL: ecn $2 expected $([[ "$3" == 1 ]] && echo marks || echo 'drops, no marks'): $what"
      router_fails=$((router_fails + 1))
    fi
  done
fi

# PPPoE: the session came up (MTU 1492, DNS from IPCP) before the client
# ran; the reconnect is the client's check.
if [[ -n "$ISP_PPPOE" ]]; then
  up=$(tr -d '\r' <"$WORK/router.log" | grep "pppoe wan0 .*: up," | head -1 || true)
  if echo "$up" | grep -q "203.0.113.50 peer 203.0.113.1 dns \[203.0.113.1\] mtu 1492 (AC isp-ac)"; then
    echo "  LAB PASS: pppoe ($ISP_PPPOE): ${up##*: }"
  else
    echo "  LAB FAIL: pppoe ($ISP_PPPOE): no session (${up:-no 'up' line in the router log})"
    tr -d '\r' <"$WORK/router.log" | grep "pppoe " | tail -3 | sed 's/^/    | /'
    router_fails=$((router_fails + 1))
  fi
fi

# Static WAN: the router configured its address (no DHCP server at the
# ISP), and the ISP saw it as the NATed source.
if [[ -n "$ISP_STATIC" ]]; then
  st=$(tr -d '\r' <"$WORK/router.log" | grep "net wan0 .*: static " | head -1 || true)
  seen=$(tr -d '\r' <"$WORK/client.log" | grep "LAB PASS: nat: ISP sees source" | head -1 || true)
  if echo "$st" | grep -q "static 203.0.113.60/24 gw 203.0.113.1 dns \[203.0.113.1\]" && echo "$seen" | grep -q "source 203.0.113.60 "; then
    echo "  LAB PASS: static wan: ${st##*: } (NATed source 203.0.113.60)"
  else
    echo "  LAB FAIL: static wan: ${st:-no 'static' line in the router log}; ${seen:-no NAT pass from the client}"
    router_fails=$((router_fails + 1))
  fi
fi

# DNS over TLS: the router's connection came up, and the ISP's DoT server
# (dnsmasq behind stunnel) answered queries.
if [[ -n "$DOT" ]]; then
  up=$(tr -d '\r' <"$WORK/router.log" | grep "dns-over-tls    : 203.0.113.1#.* up:" | head -1 || true)
  n=$(tr -d '\r' <"$WORK/isp.log" | grep -c "isp-dot: .*query\[" || true)
  if [[ -n "$up" && "$n" -gt 0 ]]; then
    echo "  LAB PASS: dns over tls: ${up##*: 203.0.113.1#} ($n queries at the ISP's DoT server)"
    want=${LAB_EXPECT_DATES:-$([[ "$ARCH" == x86_64 ]] && echo rtc || echo issue)}
    case "$want" in
      rtc) pat="dates checked against the RTC" ;;
      issue) pat="dates checked at issue time" ;;
      expired) pat="expired by the RTC: accepted until SNTP" ;;
    esac
    if [[ "$up" == *"$pat"* ]]; then
      echo "  LAB PASS: dns over tls dates before SNTP: $pat"
    else
      echo "  LAB FAIL: dns over tls dates before SNTP: expected '$pat' ($want)"; router_fails=$((router_fails + 1))
    fi
    if [[ "$want" == expired ]]; then
      set_line=$(tr -d '\r' <"$WORK/router.log" | grep "rtc  .*: was .* s off, set to" | head -1 || true)
      if [[ -n "$set_line" ]]; then
        echo "  LAB PASS: rtc corrected after SNTP: ${set_line##*: }"
      else
        echo "  LAB FAIL: rtc not corrected after SNTP"; router_fails=$((router_fails + 1))
      fi
    fi
  else
    echo "  LAB FAIL: dns over tls: ${up:-no connection} ($n queries at the ISP's DoT server)"
    tr -d '\r' <"$WORK/router.log" | grep "dns-over-tls" | tail -3 | sed 's/^/    | /'
    router_fails=$((router_fails + 1))
  fi
fi

# SNTP: synced, and the time it then reported is the host's (±5 s; the
# ISP VM's clock comes from the host's RTC).
sync=$(tr -d '\r' <"$WORK/router.log" | grep "ntp  .*synced to" | head -1 || true)
utc=$(echo "$sync" | sed -n 's/.*: \([0-9-]*T[0-9:]*Z\)$/\1/p')
router_s=$( [[ -n "$utc" ]] && date -j -u -f "%Y-%m-%dT%H:%M:%SZ" "$utc" +%s 2>/dev/null || true)
seen_s=$(cat "$WORK/ntp-seen" 2>/dev/null || true)
if [[ -n "$router_s" && -n "$seen_s" ]]; then
  skew=$((router_s - seen_s)); abs=${skew#-}
  if [[ "$abs" -le 5 ]]; then
    echo "  LAB PASS: ntp: ${sync##*ntp             : } (host clock difference ${skew} s)"
  else
    echo "  LAB FAIL: ntp: router says $utc, host $(date -u -r "$seen_s" +%Y-%m-%dT%H:%M:%SZ) (${skew} s)"; router_fails=$((router_fails + 1))
  fi
else
  echo "  LAB FAIL: ntp: no sync (${sync:-no 'synced' line in the router log})"; router_fails=$((router_fails + 1))
fi

# CPU time per task (M11). Forwarding runs in the datapath tasks: dp_down
# (WAN RX -> LAN TX) and dp_up (LAN RX -> WAN TX); DHCP/DNS/web in svc.
# 1. split: svc did work, and each direction's task (loaded by the client's
#    download resp. upload phase) more of it, counted over that load phase
#    (the client's "LAB CPU load:" line, from /api/status before and after):
#    over the whole run svc's idle work (~3 ms/s, ~35 ms/s under TCG) would
#    decide it. Without a load phase (the client expects no shaping) the
#    split is not checked, only that the counters exist.
#    Negative control: a kernel with one task doing everything (bdcf72e)
#    has no svc/dp_* tasks.
# 2. placement: with QEMU_SMP >= 3 dp_up runs on core 1, else on core 0
#    (LAB_EXPECT_UP_CORE overrides). Negative control: QEMU_SMP=4 with
#    LAB_ROUTER_ARGS=cores=2 keeps dp_up on core 0 and fails.
line=$(tr -d '\r' <"$WORK/router.log" | grep "  cpu  " | tail -1 || true)
task_ms() { echo "$line" | sed -n "s/.*, $1@[0-9]* \([0-9]*\) ms.*/\1/p"; }
task_core() { echo "$line" | sed -n "s/.*, $1@\([0-9]*\) .*/\1/p"; }
load=$(tr -d '\r' <"$WORK/client.log" | grep "^LAB CPU load:" | tail -1 || true)
load_ms() { echo "$load" | sed -n "s/.* $1=\([0-9]*\).*/\1/p"; }
if [[ -n "$(load_ms svc)" ]]; then
  down_ms=$(load_ms dp_down); up_ms=$(load_ms dp_up); svc_ms=$(load_ms svc); span="load phase"
else
  down_ms=$(task_ms dp_down); up_ms=$(task_ms dp_up); svc_ms=$(task_ms svc); span="whole run"
fi
what="$span: dp_down ${down_ms:-?} ms, dp_up ${up_ms:-?} ms, svc ${svc_ms:-?} ms"
if [[ -z "$down_ms" || -z "$up_ms" || -z "$svc_ms" ]]; then
  echo "  LAB FAIL: cpu split: $what (no per-task counters)"; router_fails=$((router_fails + 1))
elif [[ -z "$load" ]]; then
  echo "  LAB INFO: cpu split: not checked without a load phase ($what)"
elif [[ "$svc_ms" -gt 0 && "$down_ms" -gt "$svc_ms" && "$up_ms" -gt "$svc_ms" ]]; then
  echo "  LAB PASS: cpu split: $what"
else
  echo "  LAB FAIL: cpu split: expected svc > 0 and each direction > svc: $what"; router_fails=$((router_fails + 1))
fi
smp="${QEMU_SMP:-1}"
want_up=${LAB_EXPECT_UP_CORE:-$([[ "$smp" -ge 3 ]] && echo 1 || echo 0)}
up_core=$(task_core dp_up); down_core=$(task_core dp_down)
if [[ "$up_core" == "$want_up" && "$down_core" == 0 ]]; then
  echo "  LAB PASS: cpu placement: dp_down on core ${down_core}, dp_up on core ${up_core} (QEMU_SMP=$smp)"
else
  echo "  LAB FAIL: cpu placement: expected dp_down on core 0, dp_up on core $want_up, got ${down_core:-?}/${up_core:-?}"
  router_fails=$((router_fails + 1))
fi
# 3. interrupts: the LAN NIC's interrupts are delivered to dp_up's core
#    (x86_64: MSI-X destination; aarch64: GIC routing on unmask), so with
#    QEMU_SMP >= 3 core 1 handles device interrupts. Same negative control.
irqs=$(echo "$line" | sed -n 's/.*dev irqs \[\(.*\)\].*/\1/p' | tr -d ' ')
irq_up=$(echo "$irqs" | cut -d, -f$((want_up + 1)))
if [[ -n "$irq_up" && "$irq_up" -gt 0 ]]; then
  echo "  LAB PASS: irq placement: device interrupts per core [$irqs], core $want_up handles the LAN NIC"
else
  echo "  LAB FAIL: irq placement: expected device interrupts on core $want_up, got [${irqs:-?}]"
  router_fails=$((router_fails + 1))
fi

# mDNS on the wire (LAB_MDNS=1): the reflected copy on the main LAN comes
# from the router's LAN address, to the group, with TTL 255, and carries
# only the allowed service; the router joined 224.0.0.251 on both networks.
if [[ -n "$MDNS" ]]; then
  tcpdump -nn -e -v -r "$PCAP_DIR/lan.pcap" 'udp port 5353 or igmp or (vlan and (udp port 5353 or igmp))' 2>/dev/null \
    | awk '/^[^ \t]/ { if (l != "") print l; l = $0; next } { l = l " " $0 } END { if (l != "") print l }' >"$WORK/mdns.txt"
  if ! tr -d '\r' <"$WORK/client.log" | grep -q "LAB MDNS SENT"; then
    echo "  LAB FAIL: mdns wire: the client's reflection check did not pass"; router_fails=$((router_fails + 1))
  else
    copy=$(grep -v "vlan 20" "$WORK/mdns.txt" | grep "192.168.1.1.5353 > 224.0.0.251.5353" || true)
    if [[ "$copy" == *"ttl 255"* && "$copy" == *"labprn._ipp._tcp.local"* && "$copy" != *"_ssh"* ]]; then
      echo "  LAB PASS: mdns wire: copy from 192.168.1.1 to 224.0.0.251, ttl 255, _ipp only"
    else
      echo "  LAB FAIL: mdns wire: no proper copy on the LAN (${copy:0:300})"; router_fails=$((router_fails + 1))
    fi
  fi
  igmp_lan=$(grep -v "vlan 20" "$WORK/mdns.txt" | grep -c "192.168.1.1 > 224.0.0.251: igmp v2 report 224.0.0.251" || true)
  igmp_guest=$(grep "vlan 20" "$WORK/mdns.txt" | grep -c "10.20.0.1 > 224.0.0.251: igmp v2 report 224.0.0.251" || true)
  if [[ "$igmp_lan" -ge 1 && "$igmp_guest" -ge 1 ]]; then
    echo "  LAB PASS: mdns igmp: router joined 224.0.0.251 on lan ($igmp_lan) and guest ($igmp_guest)"
  else
    echo "  LAB FAIL: mdns igmp: joins lan=$igmp_lan guest=$igmp_guest"; router_fails=$((router_fails + 1))
  fi
fi

if [[ "$router_fails" == 0 ]] && tr -d '\r' <"$WORK/client.log" | grep -q "LAB DONE fails=0" && ! tr -d '\r' <"$WORK/client.log" | grep -q "LAB FAIL"; then
  echo "LAB TEST: PASS"
else
  echo "LAB TEST: FAIL" >&2
  if [[ "${LAB_VERBOSE:-0}" != "1" ]]; then
    echo "-- client console tail"; tr -d '\r' <"$WORK/client.log" | tail -25
  fi
  exit 1
fi
