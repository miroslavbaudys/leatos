#!/usr/bin/env bash
# End-to-end lab: three QEMU VMs joined by UDP socket links (no root needed).
#
#   [client]  ──LAN 10004<->10003──  [leatos]  ──WAN 10005<->10006──  [ISP]
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
#   LEATOS_ARCH=x86_64  run the x86_64 router kernel (QEMU q35, TCG); the
#                        client and ISP VMs stay aarch64
#   LAB_SHAPE_KBIT=10000 router shapes both directions at this rate and the
#                        client checks throughput + latency under load
#                        (0 = unshaped router, shaping checks skipped)
#   LAB_ACK=1            asymmetric line for CAKE's ACK filter: upload shaped
#                        at LAB_ACK_UP_KBIT (150) with ack_filter=1, download
#                        at LAB_SHAPE_KBIT; the client runs only the download
#                        (its ACKs, ~230 kbit/s, queue on the upload), the
#                        router must drop redundant ACKs and the download
#                        must arrive whole. Negative control LAB_ACK_FILTER=0
#   LAB_SWARM=N          a torrent-like download (apu4, 2026-11-21): the
#                        download shaped at LAB_SWARM_KBIT (98000, the home
#                        line), the client opens N parallel HTTP downloads
#                        (256 when N=1; HVF: TCG cannot reach the rate) with MTU LAB_SWARM_MTU (680: small
#                        packets) for LAB_SWARM_SECS (15) and checks that the
#                        ingress queue's drops come from the AQM, overflow
#                        drops at most LAB_SWARM_OVF (10) percent; the usual
#                        shaping phase is skipped. Negative control
#                        LAB_ROUTER_ARGS=queue_pkts=384 (the old limit: the
#                        queue fills by packet count, overflow decides)
#   LAB_NEIGH=1          neighbors (apu4, 2026-11-22: wired hosts lost
#                        packets every 5 min, DNS answers got lost):
#                        unshaped unless LAB_SHAPE_KBIT is set, router
#                        neigh_secs=10 (LAB_NEIGH_LIFETIME). The client pins
#                        the router's MAC, pings the router from
#                        LAB_NEIGH_HOSTS (40) addresses of its own, 3 rounds,
#                        without loss (round 1 = first contact: smoltcp's ARP
#                        hints; rounds 2-3: its neighbor cache holds them
#                        all), then downloads for LAB_NEIGH_SECS (35) with
#                        no `neighbor` drops and some probes. Negative
#                        controls LAB_ROUTER_ARGS=arp_hints=0 (round 1
#                        fails), LAB_NEIGH_CACHE=8 (smoltcp's default cache:
#                        rounds 2-3 fail), LAB_ROUTER_ARGS=neigh_probe=0
#                        (forwarded fails)
#   LAB_EXPECT_KBIT=N    what the client expects (default: LAB_SHAPE_KBIT);
#                        set it with LAB_SHAPE_KBIT=0 as a negative control
#                        The web interface's origin checks run in every mode
#                        (docs/security-audit.md §5; the router always gets
#                        mgmt_pass=lab-pass): a rebound Host gets 421, a
#                        cross-site POST with Basic credentials 403, while
#                        the address, router.lan and same-origin POSTs pass.
#                        Negative control LAB_ROUTER_ARGS=mgmt_origin=0
#                        (both refusal checks fail). Lockouts (§5 item 6):
#                        a second client address guesses wrong passwords
#                        while the client's own logs in (always answered),
#                        then holds 8 idle connections (the client's
#                        request is still answered, mgmt.throttle.evicted
#                        rises). Negative controls LAB_MGMT_SAME_SOURCE=1
#                        (the guesses come from the client's own address:
#                        its logins get 429) and LAB_ROUTER_ARGS=mgmt_evict=0
#                        (no free slot: the request is refused)
#   LAB_ROUTER_ARGS="…"  extra router boot arguments, e.g. qdisc=codel (single
#                        CoDel queue: the negative control for the flow-
#                        isolation latency check), or dns_prefetch=0 (the
#                        negative control for the DNS prefetch check: a
#                        second forwarded query, no renewal), or dns_stale=0
#                        (the negative control for the serve-stale check:
#                        SERVFAIL with the ISP's DNS stopped)
#   LAB_EXPECT_QUEUE_MS=N the WAN queue's worst delay the check allows, minus
#                        20 ms slack (default 100 = shaping.queue_ms's default;
#                        negative control LAB_ROUTER_ARGS=queue_ms=0)
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
#                        wan_mode=pppoe pppoe_user=leatos pppoe_pass=lab-secret
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
#                        The ISP offers IPv6CP: the router logs the offer
#                        (rejected with its IPv6 off); with LAB_IPV6=1 it
#                        negotiates it and runs IPv6 over the session
#                        (docs/ipv6.md step 4). Negative control
#                        LAB_PPPOE_IPV6=0 (no offer: the offer check, or
#                        with LAB_IPV6=1 the IPv6CP and IPv6 checks, fail).
#   LAB_WAN_STATIC=1     the ISP runs no DHCP server; the router gets
#                        wan_mode=static wan_ip=203.0.113.60/24
#                        wan_gw=203.0.113.1 wan_dns=203.0.113.1 (LAB_ROUTER_ARGS
#                        win). Checks: the router's static line and the ISP
#                        seeing 203.0.113.60 as the NATed source; all other
#                        checks run through it. Negative control:
#                        LAB_ROUTER_ARGS=wan_mode=dhcp (no address, everything
#                        fails).
#   LAB_GUEST=1          the router boots from a store (tools/leatstore) with a
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
#   LAB_GUEST_IPV6=0     (with LAB_IPV6) the guest network with
#                        `ipv6 = false`: the router reports no IPv6 there,
#                        the client gets no SLAAC address on VLAN 20, and
#                        IPv6 it sends anyway (pings to ff02::2) is dropped
#                        as `unsupported`; the main
#                        LAN's IPv6 checks still pass. Negative control:
#                        LAB_GUEST_IPV6_CONTROL=1 (the store keeps IPv6 on:
#                        all three fail).
#   LAB_MDNS=1           (implies LAB_GUEST=1) mDNS across networks
#                        (docs/mdns.md): the guest zone allows "mdns" and
#                        the rule guest-printers reflects _ipp._tcp from
#                        guest to lan. The client announces a printer
#                        (_ipp._tcp + _ssh._tcp) on VLAN 20; checks: the
#                        router's counters (guest received, lan sent) and,
#                        on the LAN capture, the copy from 192.168.1.1 to
#                        224.0.0.251 with TTL 255 holding _ipp but not
#                        _ssh, plus the router's IGMP joins on both
#                        networks. With LAB_IPV6=1 the same over ff02::fb
#                        (the copy from the router's link-local address,
#                        hop limit 255). Negative control: LAB_MDNS_RULES=0 (the
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
#                        With LAB_IPV6=1 the router's only upstream is
#                        [2001:db8:ffff::1]:853 (DoT over IPv6; negative
#                        control LAB_DOT_V6=0: the ISP's stunnel on IPv4
#                        only).
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
#                        Control: LEATOS_ARCH=x86_64
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
#                        disabled: every check fails). With LAB_IPV6=1 also
#                        lab-behind6 = fd00:30::/64 via the client's ULA:
#                        the router answers fd00:30::5 on the client's
#                        loopback, /api/status routes6 lists it active.
#   LAB_IPV6=1           (or pd; LAB_IPV6=static: step 2b's boot arguments
#                        instead) the ISP VM sends RAs (dnsmasq, ra-only)
#                        and delegates prefixes (Kea, 2001:db8:100::/48 →
#                        /56, renew 10 s); the router gets ipv6=1 only and
#                        learns its default router and prefix (step 3):
#                        status wan_ipv6 from dhcpv6-pd, every check below
#                        through it, then a prefix change (cgi-bin/pd?change:
#                        2001:db8:200::/48): new addresses, the old one
#                        deprecated, traffic through the new one. Negative
#                        control LAB_IPV6_PD=0 (no Kea: no delegated prefix).
#                        Step 5: the router's WAN address from the prefix
#                        (the last /64's ::1) and the default router's
#                        source (ra / ipv6cp) in its status; its own DNS
#                        over IPv6: Kea hands out 2001:db8:ffff::53, an
#                        IPv6-only resolver answering v6dns.isp.example,
#                        resolved with the ISP's IPv4 DNS stopped (negative
#                        control LAB_IPV6_DNS6=0: no servers handed out).
#                        With a store (LAB_GUEST=1): the prefix kept across
#                        a reboot while the ISP's server forgot every lease
#                        and allocates at random (cgi-bin/pd?fresh);
#                        negative control LAB_ROUTER_ARGS=pd_keep=0.
#                        Step 5b, with LAB_GUEST=1: rule v6-pinhole (wan ->
#                        lan tcp 8087, dst_iid = the client's EUI-64 id):
#                        the ISP reaches the client's :8087, not on a second
#                        address with another id, and again after the
#                        prefix change. Negative control
#                        LAB_IPV6_PINHOLE=0.
#                        labclient.lan answers AAAA with the client's
#                        global and ULA addresses (neighbor discovery x
#                        its DHCP lease) and the PTR of the global one;
#                        negative control LAB_ROUTER_ARGS=dns_aaaa=0.
#                        The client's lease in /api/status lists both
#                        addresses (`ipv6`, the Clients page); no run-time
#                        negative control (ipv6=0 skips the section):
#                        checked with a build listing none.
#                        IPv6 on the router's networks (docs/ipv6.md step
#                        1; router ipv6=1): the client gets a SLAAC
#                        address from the main LAN's ULA /64, no default
#                        route (router lifetime 0), pings the router's ULA
#                        and link-local address, resolves router.lan AAAA
#                        over IPv6 and opens the web interface on the ULA;
#                        the router's RA counters; /api/status routes
#                        lists the ULA /64 (with a global prefix also that
#                        /64), ::/0 via the WAN's IPv6 router if it has
#                        one. With LAB_GUEST=1 also
#                        the guest network: its own ULA, DNS over IPv6
#                        allowed, the web interface refused (zone input).
#                        Negative controls: LAB_ROUTER_ARGS=ipv6=0 (every
#                        IPv6 check fails), LAB_GUEST_ZONE=lan (the guest's
#                        web-refused check fails).
#                        The WAN side (step 2b): the ISP VM gets
#                        2001:db8:ffff::1/64 and routes 2001:db8:100::/56 to
#                        the router (wan6_ip=2001:db8:ffff::2/64
#                        wan6_gw=2001:db8:ffff::1 lan6_prefix=...::/56
#                        wan_mtu=1400; the IPv4 big ping becomes 1372). The
#                        client: a global SLAAC address and a default
#                        route, ping6 and HTTP to the ISP, the ISP sees the
#                        client's own address (no NAT), traceroute6 through
#                        the router, inbound refused (cgi-bin/fetch back to
#                        the client's [::]:8086; firewall drops rise), Packet
#                        Too Big (ping6 -s 1452: route cache mtu 1400), a
#                        forged source dropped (spoofed rises); with
#                        LAB_GUEST=1 the guest's global address reaches the
#                        ISP; fragments both ways (ping6 -s 3000, step 2c,
#                        negative control LAB_ROUTER_ARGS=fw_frag=0). Negative controls: LAB_IPV6_OPEN=1 (implies
#                        LAB_GUEST=1; a rule wan -> lan accept: inbound
#                        reaches the client), LAB_ROUTER_ARGS=wan_mtu=1500
#                        (no PTB), LAB_ROUTER_ARGS=lan_antispoof=0 (the
#                        forged source passes).
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
NEIGH="${LAB_NEIGH:-}"
NEIGH_HOSTS="${LAB_NEIGH_HOSTS:-40}"
NEIGH_SECS="${LAB_NEIGH_SECS:-35}"
if [[ -n "$NEIGH" ]]; then
  SHAPE_KBIT="${LAB_SHAPE_KBIT:-0}"
  [[ -z "${LAB_TIMEOUT:-}" ]] && TIMEOUT=$((TIMEOUT + NEIGH_HOSTS * 3 + NEIGH_SECS + 30))
fi
KERNEL_FEATURES=""
case "${LAB_NEIGH_CACHE:-}" in
  "") ;;
  8) KERNEL_FEATURES="--no-default-features" ;;
  *) echo "LAB_NEIGH_CACHE: only 8 (smoltcp's default) is a control" >&2; exit 2 ;;
esac
SHAPE_KBIT="${LAB_SHAPE_KBIT:-${SHAPE_KBIT:-10000}}"
EXPECT_KBIT="${LAB_EXPECT_KBIT:-$SHAPE_KBIT}"
ROUTER_ARGS=""
[[ "$SHAPE_KBIT" != 0 ]] && ROUTER_ARGS="shape_up=$SHAPE_KBIT shape_down=$SHAPE_KBIT"
ACK="${LAB_ACK:-}"
[[ -n "$ACK" && "$SHAPE_KBIT" != 0 ]] && ROUTER_ARGS="shape_up=${LAB_ACK_UP_KBIT:-150} shape_down=$SHAPE_KBIT ack_filter=${LAB_ACK_FILTER:-1}"
SWARM="${LAB_SWARM:-}"
[[ "$SWARM" == 1 ]] && SWARM=256
SWARM_KBIT="${LAB_SWARM_KBIT:-98000}"
if [[ -n "$SWARM" ]]; then
  ROUTER_ARGS="shape_up=${LAB_SWARM_UP_KBIT:-20000} shape_down=$SWARM_KBIT"
  EXPECT_KBIT=0 # no single-download shaping phase
fi
ROUTER_ARGS="$ROUTER_ARGS ${LAB_ROUTER_ARGS:-}"
# A password in every mode: live config changes (LAB_GUEST_LIVE, the recheck
# check) and the web interface's CSRF check need it.
[[ " ${LAB_ROUTER_ARGS:-} " == *" mgmt_pass="* ]] || ROUTER_ARGS="$ROUTER_ARGS mgmt_pass=lab-pass"
[[ -n "$NEIGH" ]] && ROUTER_ARGS="$ROUTER_ARGS neigh_secs=${LAB_NEIGH_LIFETIME:-10}"
# The first ntp= wins: only add the default when the caller sets none.
[[ " ${LAB_ROUTER_ARGS:-} " == *" ntp="* ]] || ROUTER_ARGS="$ROUTER_ARGS ntp=ntp.isp.example"
ISP_VLAN="${LAB_VLAN:-}"
# The router takes the first occurrence of an argument: LAB_ROUTER_ARGS wins.
[[ -n "$ISP_VLAN" ]] && ROUTER_ARGS="$ROUTER_ARGS wan_vlan=$ISP_VLAN"
ISP_PPPOE="${LAB_PPPOE:-}"
[[ "$ISP_PPPOE" == 1 ]] && ISP_PPPOE=pap
ISP_PPPOE_IPV6="${LAB_PPPOE_IPV6:-}"
BIG_PING="${LAB_BIG_PING:-1472}"
if [[ -n "$ISP_PPPOE" ]]; then
  # No user name with LAB_PPPOE=none (or the LAB_PPPOE_ANON=1 control).
  if [[ "$ISP_PPPOE" == none || -n "${LAB_PPPOE_ANON:-}" ]]; then
    ROUTER_ARGS="$ROUTER_ARGS wan_mode=pppoe"
  else
    ROUTER_ARGS="$ROUTER_ARGS wan_mode=pppoe pppoe_user=leatos pppoe_pass=lab-secret"
  fi
  BIG_PING="${LAB_BIG_PING:-1464}"
fi
ISP_STATIC="${LAB_WAN_STATIC:-}"
[[ -n "$ISP_STATIC" ]] && ROUTER_ARGS="$ROUTER_ARGS wan_mode=static wan_ip=203.0.113.60/24 wan_gw=203.0.113.1 wan_dns=203.0.113.1"
# 1 (or pd): the ISP delegates a prefix (DHCPv6-PD, docs/ipv6.md step
# 3); static: the development boot arguments of step 2b.
IPV6="${LAB_IPV6:-}"
IPV6_OPEN="${LAB_IPV6_OPEN:-}"
[[ -n "$IPV6_OPEN" && -z "$IPV6" ]] && IPV6=1
[[ "$IPV6" == 1 ]] && IPV6=pd
ISP_IPV6="$IPV6"
ISP_PD="${LAB_IPV6_PD:-1}"
ISP_DNS6="${LAB_IPV6_DNS6:-1}"
ISP_DOT6="${LAB_DOT_V6:-1}"
if [[ "$IPV6" == static && -n "$ISP_PPPOE" ]]; then
  echo "lab-test: LAB_IPV6=static is for an Ethernet WAN; with LAB_PPPOE use LAB_IPV6=1" >&2
  exit 2
fi
if [[ "$IPV6" == static ]]; then
  ROUTER_ARGS="$ROUTER_ARGS ipv6=1 wan6_ip=2001:db8:ffff::2/64 wan6_gw=2001:db8:ffff::1 lan6_prefix=2001:db8:100::/56 wan_mtu=1400"
elif [[ -n "$IPV6" && -n "$ISP_PPPOE" ]]; then
  # Over PPPoE (step 4): IPv6CP, the session's MTU (1492).
  ROUTER_ARGS="$ROUTER_ARGS ipv6=1"
  export LAB_INITRD_KEA=1
elif [[ -n "$IPV6" ]]; then
  ROUTER_ARGS="$ROUTER_ARGS ipv6=1 wan_mtu=1400"
  export LAB_INITRD_KEA=1 # the ISP's prefix delegation server
fi
[[ -n "$IPV6" && -z "$ISP_PPPOE" ]] && BIG_PING="${LAB_BIG_PING:-1372}"
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
[[ -n "$IPV6_OPEN" ]] && GUEST=1
GUEST_ZONE="${LAB_GUEST_ZONE:-guest}"
GUEST_RULES="${LAB_GUEST_RULES:-1}"
GUEST_REJECT="${LAB_GUEST_REJECT:-reject}"
FORWARD="${LAB_FORWARD:-1}"
FWD_CUT="${LAB_FWD_CUT:-}"
REDIRECT="${LAB_REDIRECT:-1}"
GUEST_DOMAIN="${LAB_GUEST_DOMAIN:-1}"
GUEST_IPV6="${LAB_GUEST_IPV6:-1}"
DOT="${LAB_DOT:-}"
DOT_NAME="${LAB_DOT_NAME:-dns.isp.example}"
DOT_CA="${LAB_DOT_CA:-1}"
LAN_PORT="${LAB_LAN_PORT:-10003}"
WAN_PORT="${LAB_WAN_PORT:-10005}"
LAN1_PORT="${LAB_LAN1_PORT:-10007}"
WORK=$(mktemp -d -t leatos-lab)
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
ARCH="${LEATOS_ARCH:-aarch64}"
cargo build -q -p leatos-kernel --target "$ARCH-unknown-none" $KERNEL_FEATURES
MODLOOP=""
[[ -n "$ISP_VLAN$ISP_PPPOE$GUEST" ]] && MODLOOP=modloop
ALPINE_DIR=$(scripts/lab/fetch-alpine.sh $MODLOOP ${LAB_INITRD_KEA:+kea} | tail -1)
ISP_INITRD=$(scripts/lab/build-initrd.sh isp | tail -1)
CLIENT_INITRD=$(scripts/lab/build-initrd.sh client | tail -1)

if [[ -n "$DOT" ]]; then
  # A CA and the ISP's DoT certificate (RSA under an ECDSA CA), made per run
  # and valid from now; the server's half goes into the ISP's initrd.
  mkdir -p "$WORK/dot/etc/dot"; d="$WORK/dot"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$d/ca.key" -out "$d/ca.pem" -days 30 \
    -subj "/CN=leatos lab CA" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
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
    # With LAB_IPV6: the ISP's IPv6 address only (step 5b: DoT over IPv6;
    # negative control LAB_DOT_V6=0, the ISP listening on IPv4 only).
    if [[ -n "$IPV6" ]]; then
      printf 'tls = true\nupstreams = ["[2001:db8:ffff::1]:853#%s"]\n' "$DOT_NAME"
    else
      printf 'tls = true\nupstreams = ["203.0.113.1#%s"]\n' "$DOT_NAME"
    fi
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
$([[ "$GUEST_IPV6" == 0 && -z "${LAB_GUEST_IPV6_CONTROL:-}" ]] && echo 'ipv6 = false')

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
  # IPv6 pinhole (docs/ipv6.md step 5b): the client's interface
  # identifier, any prefix. Negative control LAB_IPV6_PINHOLE=0.
  [[ -n "$IPV6" && "${LAB_IPV6_PINHOLE:-1}" != 0 ]] && cat >>"$WORK/config.toml" <<'CFG'

[[firewall.rule]]
name = "v6-pinhole"
from = "wan"
to = "lan"
proto = "tcp"
dst_iid = "::5054:ff:fe00:10"
dst_port = 8087
action = "accept"
CFG
  [[ -n "$IPV6_OPEN" ]] && cat >>"$WORK/config.toml" <<'CFG'

[[firewall.rule]]
name = "v6-open"
from = "wan"
to = "lan"
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
  # IPv6 (docs/ipv6.md step 5b): fd00:30::/64 via the client's ULA. The
  # lab router's ULA /48 is derived from its WAN MAC 52:54:00:00:00:01:
  # fd13:34ac:fcc9::/48 (config::ula_prefix), on both architectures.
  [[ -n "$ROUTES" && -n "$IPV6" ]] && cat >>"$WORK/config.toml" <<CFG

[[route]]
name = "lab-behind6"
enabled = $([[ "$ROUTES" == 1 ]] && echo true || echo false)
dst = "fd00:30::/64"
via = "fd13:34ac:fcc9::5054:ff:fe00:10"
CFG
  dns_toml >>"$WORK/config.toml"
  cargo build -q -p leatstore --release
  target/release/leatstore create "$WORK/store.img" --mib 32 >/dev/null
  target/release/leatstore put "$WORK/store.img" config "$WORK/config.toml" >/dev/null
  if [[ -n "$GUEST_LIVE" ]]; then
    # Boot with the main LAN only (everything before the second network);
    # the client adds the rest live.
    awk '/^\[\[network\]\]$/ { n++ } n < 2' "$WORK/config.toml" >"$WORK/boot.toml"
    target/release/leatstore create "$WORK/store.img" --mib 32 >/dev/null
    target/release/leatstore put "$WORK/store.img" config "$WORK/boot.toml" >/dev/null
    # The full config goes into the client's initrd (an extra cpio archive).
    mkdir -p "$WORK/extra"; cp "$WORK/config.toml" "$WORK/extra/guest.toml"
    ( cd "$WORK/extra" && echo guest.toml | cpio -o -H newc 2>/dev/null | gzip -9 ) >"$WORK/extra.cpio.gz"
    cat "$CLIENT_INITRD" "$WORK/extra.cpio.gz" >"$WORK/client-initrd.img"
    CLIENT_INITRD="$WORK/client-initrd.img"
  fi
  ROUTER_STORE="$WORK/store.img"
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
  cargo build -q -p leatstore --release
  target/release/leatstore create "$WORK/store.img" --mib 32 >/dev/null
  target/release/leatstore put "$WORK/store.img" config "$WORK/config.toml" >/dev/null
  ROUTER_STORE="$WORK/store.img"
fi
[[ -n "$DOT" ]] && echo "== router config: DNS over TLS to 203.0.113.1#$DOT_NAME$([[ "$DOT_CA" == 1 ]] && echo ", lab CA trusted" || echo ", Mozilla's roots only")"

echo "== start leatos${ROUTER_ARGS:+ ($(echo "$ROUTER_ARGS" | sed 's/pppoe_pass=[^ ]*/pppoe_pass=***/'))}"
QEMU_STORE="$ROUTER_STORE" QEMU_NET=lab LAB_LAN_PORT="$LAN_PORT" LAB_WAN_PORT="$WAN_PORT" LAB_LAN1_PORT="${PORTS:+$LAN1_PORT}" QEMU_PCAP_DIR="$PCAP_DIR" QEMU_ACCEL="$QEMU_ACCEL" QEMU_APPEND="$ROUTER_ARGS" \
  scripts/qemu-run.sh "target/$ARCH-unknown-none/debug/leatos" >"$WORK/router.log" 2>&1 &
PIDS+=($!)
wait_for "$WORK/router.log" "leatos: boot ok" 40 || { echo "router did not boot:"; cat "$WORK/router.log"; exit 1; }
# When the host sees the router's first SNTP sync (compared with the time
# the router then reports).
( wait_for "$WORK/router.log" "ntp  .*synced to" 90 && date -u +%s >"$WORK/ntp-seen" ) &
PIDS+=($!)

echo "== start client"
VM_DISK="${GUEST:+$ALPINE_DIR/modloop-virt}" \
  VM_NIC2="${PORTS:+52:54:00:00:00:11 $((LAN1_PORT + 1)) $LAN1_PORT}" \
  linux_vm "$CLIENT_INITRD" 52:54:00:00:00:10 $((LAN_PORT + 1)) "$LAN_PORT" "$WORK/client.log" "lab_shape_kbit=$EXPECT_KBIT${NEIGH:+ lab_neigh=1 lab_neigh_hosts=$NEIGH_HOSTS lab_neigh_secs=$NEIGH_SECS}${ACK:+ lab_ack=1}${SWARM:+ lab_swarm=$SWARM lab_swarm_kbit=$SWARM_KBIT lab_swarm_secs=${LAB_SWARM_SECS:-15} lab_swarm_mtu=${LAB_SWARM_MTU:-680} lab_swarm_ovf=${LAB_SWARM_OVF:-10}} lab_big_ping=$BIG_PING${ISP_PPPOE:+ lab_pppoe_kick=${LAB_PPPOE_KICK:-kick}}${GUEST:+ lab_guest=$GUEST_ZONE lab_guest_rules=$GUEST_RULES lab_forward=$FORWARD${FWD_CUT:+ lab_fwd_cut=1} lab_redirect=$REDIRECT lab_guest_domain=$GUEST_DOMAIN lab_guest_v6=$GUEST_IPV6}${GUEST_LIVE:+ lab_guest_live=1}${LAB_MGMT_SAME_SOURCE:+ lab_mgmt_same=1}${MDNS:+ lab_mdns=$MDNS_RULES}${DOT:+ lab_dot=1}${DNS_VIEWS:+ lab_dns_views=$DNS_VIEWS lab_dns_hosts=$DNS_HOSTS}${ROUTES:+ lab_routes=$ROUTES}${PORTS:+ lab_ports=$PORTS_NET}${IPV6:+ lab_ipv6=$IPV6}$([[ "$IPV6" == pd && -n "$ROUTER_STORE" ]] && echo ' lab_pd_keep=1')"
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

# The router's checks read its log up to a reboot (the client's last
# check, LAB_IPV6=1 with a store, reboots it: counters start over).
RLOG="$WORK/router-checks.log"
tr -d '\r' <"$WORK/router.log" | awk '/leatos: boot ok/ { n++ } n < 2' >"$RLOG"

echo "== router"
tr -d '\r' <"$WORK/router.log" | grep -E "dhcp  |lan services|dns-over-tls|rtc  |dns upstreams|net lan0  |net wan0 .*(lease|vlan|PPPoE)|pppoe |net ping|qos |qdisc |cpu  |ntp  |watchdog  |vlan  " | sed 's/^/  /' || true
echo "== results"
tr -d '\r' <"$WORK/client.log" | grep -E "^LAB (PASS|FAIL|INFO|WARN)|^    \|" | sed 's/^/  /' || true

# Per-direction ECN (router side): with ECN on, the AQM marks the client's
# ECN-capable traffic; with it off, it drops and never marks. Upload = WAN
# egress, download = the WAN ingress stage (LAN egress with
# shape_ingress=0).
router_fails=0
# Swarm mode has no upload phase: its check is the client's.
if [[ "$SHAPE_KBIT" != 0 && -z "$SWARM" ]]; then
  bootarg() { echo " $ROUTER_ARGS " | sed -n "s/.* $1=\([0-9]*\) .*/\1/p"; }
  all=$(bootarg ecn)
  up=$(bootarg ecn_up); up=${up:-${all:-0}}
  down=$(bootarg ecn_down); down=${down:-${all:-1}}
  if [[ -n "${LAB_EXPECT_ECN:-}" ]]; then up=${LAB_EXPECT_ECN%%:*}; down=${LAB_EXPECT_ECN##*:}; fi
  downq=ingress
  [[ " $ROUTER_ARGS " == *" shape_ingress=0 "* ]] && downq=lan0
  pairs=("wan0 upload $up" "$downq download $down")
  # ACK mode: no upload phase, so only the download's ECN is checked.
  [[ -n "$ACK" ]] && pairs=("$downq download $down")
  for pair in "${pairs[@]}"; do
    set -- $pair
    line=$(cat "$RLOG" | grep "qdisc $1 " | tail -1)
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
  # Queue limit follows the rate (shaping.queue_ms, docs/bufferbloat-cake.md):
  # the client's UDP burst fills the WAN queue (overflow drops prove it did,
  # else the check is invalid), and the worst delay of a full queue stays
  # near LAB_EXPECT_QUEUE_MS (default 100) + 20 ms. Negative control
  # LAB_ROUTER_ARGS=queue_ms=0 (the fixed 384 packets: ~465 ms at 10 Mbit/s).
  # ACK filter (LAB_ACK=1): the download's ACKs queue on the slow upload;
  # CAKE must drop redundant ones (its "ack drops" counter on wan0), and
  # the client's download check shows TCP still delivered the file whole.
  # Negative control LAB_ACK_FILTER=0: no ACK drops, the check fails.
  if [[ -n "$ACK" ]]; then
    wl=$(cat "$RLOG" | grep "qdisc wan0 " | tail -1)
    ackd=$(echo "$wl" | sed -n 's/.*ack drops \([0-9]*\).*/\1/p')
    sent=$(echo "$wl" | sed -n 's/.*, sent \([0-9]*\),.*/\1/p')
    if [[ -n "$ackd" && "$ackd" -gt 0 ]]; then
      echo "  LAB PASS: ack filter: wan0 dropped $ackd redundant ACKs, sent ${sent:-?}"
    else
      echo "  LAB FAIL: ack filter: wan0 ack drops ${ackd:-?} (sent ${sent:-?})"; router_fails=$((router_fails + 1))
    fi
  fi
  qms=${LAB_EXPECT_QUEUE_MS:-100}
  wq=$(cat "$RLOG" | grep "qdisc wan0 ")
  ovf=$(echo "$wq" | tail -1 | sed -n 's/.*overflow drops \([0-9]*\).*/\1/p')
  worst=$(echo "$wq" | sed -n 's/.*max sojourn \([0-9]*\)\.[0-9]* ms.*/\1/p' | sort -n | tail -1)
  what="wan0 worst sojourn ${worst:-?} ms, overflow drops ${ovf:-?} (expected <= $((qms + 20)) ms)"
  if [[ -n "$ACK" ]]; then
    echo "  LAB INFO: queue limit: not checked in ACK mode (no upload burst)"
  elif [[ -z "$ovf" || -z "$worst" ]]; then
    echo "  LAB FAIL: queue limit: no router counters"; router_fails=$((router_fails + 1))
  elif [[ "$ovf" == 0 ]]; then
    echo "  LAB FAIL: queue limit: INVALID, the burst never filled the queue ($what)"; router_fails=$((router_fails + 1))
  elif [[ "$worst" -le $((qms + 20)) ]]; then
    echo "  LAB PASS: queue limit follows the rate: $what"
  else
    echo "  LAB FAIL: queue limit: $what"; router_fails=$((router_fails + 1))
  fi
fi

# PPPoE: the session came up (MTU 1492, DNS from IPCP) before the client
# ran; the reconnect is the client's check.
if [[ -n "$ISP_PPPOE" ]]; then
  up=$(cat "$RLOG" | grep "pppoe wan0 .*: up," | head -1 || true)
  if echo "$up" | grep -q "203.0.113.50 peer 203.0.113.1 dns \[203.0.113.1\] mtu 1492 (AC isp-ac)"; then
    echo "  LAB PASS: pppoe ($ISP_PPPOE): ${up##*: }"
  else
    echo "  LAB FAIL: pppoe ($ISP_PPPOE): no session (${up:-no 'up' line in the router log})"
    cat "$RLOG" | grep "pppoe " | tail -3 | sed 's/^/    | /'
    router_fails=$((router_fails + 1))
  fi
  if [[ -n "$IPV6" ]]; then
    # IPv6CP negotiated (docs/ipv6.md step 4).
    v6=$(cat "$RLOG" | grep "pppoe wan0 .*: IPv6CP up, fe80::" | head -1 || true)
    if [[ -n "$v6" ]]; then
      echo "  LAB PASS: pppoe ipv6: ${v6##*: }"
    else
      echo "  LAB FAIL: pppoe ipv6: no 'IPv6CP up' in the router log"
      router_fails=$((router_fails + 1))
    fi
  else
    # The ISP's IPv6CP offer is logged (docs/ipv6.md step 0).
    v6=$(cat "$RLOG" | grep "pppoe wan0 .*: the access concentrator offers IPv6 (IPv6CP, interface id " | head -1 || true)
    if [[ -n "$v6" ]]; then
      echo "  LAB PASS: pppoe ipv6 offer: ${v6##*: }"
    else
      echo "  LAB FAIL: pppoe ipv6 offer: no IPv6CP offer in the router log"
      router_fails=$((router_fails + 1))
    fi
  fi
fi

# Static WAN: the router configured its address (no DHCP server at the
# ISP), and the ISP saw it as the NATed source.
if [[ -n "$ISP_STATIC" ]]; then
  st=$(cat "$RLOG" | grep "net wan0 .*: static " | head -1 || true)
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
  # The ISP's IPv4 address, or with LAB_IPV6 its IPv6 one.
  srv="203.0.113.1#"; [[ -n "$IPV6" ]] && srv="[2001:db8:ffff::1]:853#"
  up=$(cat "$RLOG" | grep -F "dns-over-tls    : $srv" | grep " up:" | head -1 || true)
  n=$(tr -d '\r' <"$WORK/isp.log" | grep -c "isp-dot: .*query\[" || true)
  if [[ -n "$up" && "$n" -gt 0 ]]; then
    echo "  LAB PASS: dns over tls: ${up##*: $srv} ($n queries at the ISP's DoT server)"
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
      set_line=$(cat "$RLOG" | grep "rtc  .*: was .* s off, set to" | head -1 || true)
      if [[ -n "$set_line" ]]; then
        echo "  LAB PASS: rtc corrected after SNTP: ${set_line##*: }"
      else
        echo "  LAB FAIL: rtc not corrected after SNTP"; router_fails=$((router_fails + 1))
      fi
    fi
  else
    echo "  LAB FAIL: dns over tls: ${up:-no connection} ($n queries at the ISP's DoT server)"
    cat "$RLOG" | grep "dns-over-tls" | tail -3 | sed 's/^/    | /'
    router_fails=$((router_fails + 1))
  fi
fi

# SNTP: synced, and the time it then reported is the host's (±5 s; the
# ISP VM's clock comes from the host's RTC).
sync=$(cat "$RLOG" | grep "ntp  .*synced to" | head -1 || true)
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
line=$(cat "$RLOG" | grep "  cpu  " | tail -1 || true)
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
  # IPv6 (LAB_IPV6, docs/ipv6.md step 5b): the copy from the router's
  # link-local address to ff02::fb, hop limit 255, _ipp only.
  if [[ -n "$IPV6" ]]; then
    tcpdump -nn -e -v -r "$PCAP_DIR/lan.pcap" 'ip6 and udp port 5353' 2>/dev/null \
      | awk '/^[^ \t]/ { if (l != "") print l; l = $0; next } { l = l " " $0 } END { if (l != "") print l }' >"$WORK/mdns6.txt"
    if ! tr -d '\r' <"$WORK/client.log" | grep -q "LAB MDNS6 SENT"; then
      echo "  LAB FAIL: mdns ipv6 wire: the client's reflection check did not pass"; router_fails=$((router_fails + 1))
    else
      copy=$(grep -v "vlan 20" "$WORK/mdns6.txt" | grep "fe80::5054:ff:fe00:2.5353 > ff02::fb.5353" | grep "labprn._ipp._tcp.local" | head -1 || true)
      if [[ "$copy" == *"hlim 255"* && "$copy" != *"_ssh"* ]]; then
        echo "  LAB PASS: mdns ipv6 wire: copy from fe80::5054:ff:fe00:2 to ff02::fb, hlim 255, _ipp only"
      else
        echo "  LAB FAIL: mdns ipv6 wire: no proper copy on the LAN (${copy:0:300})"; router_fails=$((router_fails + 1))
        grep -v "vlan 20" "$WORK/mdns6.txt" | head -3 | cut -c1-200 | sed 's/^/    | /'
      fi
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
