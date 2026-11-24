# Split-horizon local DNS (design)

Status (2026-11-23): all five steps of §12 done in QEMU; on the apu4
(457cb97, `views = "firewall"`, home config) the DNS page and its "Local
names" card render in Chrome without console errors, and from `lan` the
iot-only override `time.evrythng.com` gets the public answer (NXDOMAIN)
while iot uses 192.168.1.238 (1,725 hits).
- Step 1: `crates/proto-dns` `Zone` has views (`View`, records per
  network, `Lookup::Hidden`, overrides; a newer record takes over only its
  networks from older ones of its source) and `Resolver::handle_query_in`
  takes the asking network (`Stats::hidden`). Host tests, mutation-checked
  (ignoring views fails 7 of them).
- Step 2: `crates/config`: `dns.views`, `[[dns.host]] networks`,
  validation, `Config::name_visibility` (`NameVisibility::seen_by`),
  `local_domains`, `local_hosts` (`crates/config/src/names.rs`). Host
  tests on the home topology, mutation-checked (ignoring the rules or the
  zones fails them).
- Step 3: the kernel (`net/services.rs`): queries answered as the network
  whose DNS socket they came in on, the router's own as `View::ROUTER`;
  reservations, leases and `[[dns.host]]` with their views, rebuilt on
  every config change; `hidden` in `/api/status` `dns` and CLI `status`.
  `dns.host` and `dns.views` are no longer refused.
- Step 4: `LAB_DNS_VIEWS=1 scripts/lab-test.sh` (§10) passes on aarch64
  and x86_64 and with `LAB_GUEST_LIVE=1`; each negative control fails
  exactly its checks. `LAB_DOT=1`, `cli-test`, `store-test` (its
  unsupported example is now a static WAN) pass.
- Step 5: the DNS page has a "Local names" card (`net/mgmt.html`): the
  views switch, a hosts table (rows by index, so validation paths
  `dns.host[i].…` highlight them; networks as checkboxes, gone ones kept
  and marked), warnings for overrides of public names, and local/hidden
  answers in the status table. Checked with Node against a minimal DOM
  (load, edit, remove, warnings) and through the API on a running router
  (saved and applied live, errors with row paths). The CLI sets the list
  as a whole (`config set dns.host = [{ name = …, ip = …, networks =
  [...] }]`) and `dns.views`; host test `dns_views_and_hosts_from_the_cli`.
  `store-test` and `upgrade-test` pass.

## 1. Today (verified in the code, 2026-11-18)
- One resolver and one local zone (`crates/proto-dns` `Zone`) for all
  networks. `Zone::lookup(name, qtype)` does not know who asks.
- Every network's DNS socket reaches it (the zone input policy only decides
  whether a network may query at all; the guest zone may).
- A network's own `domain` only decides where its names live:
  `labclient.guest.home.arpa` is NXDOMAIN, but `labclient.home.arpa` asked from the
  guest network answers the LAN address.
- The reverse zones of all subnets are local, so a guest can PTR-sweep
  `10.10.0.1–254` and list every LAN host name.
- Nothing becomes reachable by this (the forward policy still decides), but
  host names, addresses and device kinds leak to guest and IoT networks.

## 2. Goals
1. **Visibility:** a name is answered only to some networks; the others get
   NXDOMAIN (`nas.home.arpa` on the LAN, not on the guest network).
2. **Different answers per network:** the same name, another address
   (a server with a leg on two VLANs).
3. **Override of a public name inside:** `files.example.com` → an internal
   address on the LAN, the public answer elsewhere (instead of hairpin NAT
   through a port forward).
4. **DHCP and reservation names follow the firewall:** a network that cannot
   reach another one does not resolve its names, forward or reverse.

## 3. Which network asks
The **socket the query arrived on**, not the source address: each network
has its own DNS socket on its own link (smoltcp interface on its VLAN), so
a guest client cannot claim to be on the LAN by forging a LAN source. A
client asking another network's router address is still answered as its
own network. The router's own lookups (`ntp::SELF_CLIENT`) use a `ROUTER`
view that sees everything.

## 4. Visibility from the firewall (`dns.views = "firewall"`)
Network V **sees** a name whose address lies in network N if
1. V and N are in the same zone, or
2. V's zone may forward to N's zone (`Policy::forward`), or
3. an **accept** rule from V's zone (or `any`) to N's zone (or `any`) has
   no `dst`, or a `dst` covering that address.

Drop/reject rules, `src` and `dst_port` are ignored: an over-approximation
(a name is shown wherever some traffic could reach it). Hiding a reachable
name would be the bug; showing one that only part of the traffic reaches is
acceptable.

Why rule 3: the home config (`target/apu4/config-home.toml`) has zone `iot`
with `forward_to = []` and the rule `homeassistant` (iot → 192.168.1.200,
accept). With zones alone the IoT devices would lose Home Assistant's name.
There: `lan` sees everything, `iot` its own names plus `homeassistant`,
`powerstream` its own names only.

## 5. Config (`crates/config`)
```toml
[dns]
views = "firewall"          # "all" (default: today's behaviour) | "firewall"

[[dns.host]]
name = "nas"                # relative → dns.domain; dotted under a local domain = that domain
ip = "192.168.1.10"
networks = ["lan", "iot"]   # optional; omitted = the views decide (like a DHCP name)

[[dns.host]]
name = "files.example.com"  # outside the local domains = override of a public name
ip = "192.168.1.200"
networks = ["lan"]          # required for overrides; other networks: forwarded upstream
```
- `views` defaults to `"all"` (no change until switched on); `"firewall"`
  may become the default in a later release.
- `networks` on a record wins over the views: exactly those networks see it.
- Validation:
  - `networks` entries exist.
  - A name may repeat only with non-overlapping network sets (omitted =
    overlaps everything).
  - A reservation's hostname in the same domain only with `networks`
    (the record takes the name over for those networks).
  - `router` is allowed: it takes `router.<domain>` over for its networks.
  - An override (name outside every local domain) must list `networks`;
    no names under `.arpa` (reverse names come from the records).
  - A name that is a local domain itself is refused. No trailing dot.
  - ≤ 256 records (as today). Paths `dns.host[i].networks[j]`.
- `dns.host` leaves `unsupported()`.
- CLI: list editing in `edit.rs` (`dns.host`, `dns.host[i].networks`).
- The view computation (`dns_views`: per network the mask of networks it
  sees, from zones, `forward_to`, rules and subnets) is a pure function in
  `crates/config` with host tests; `kernel/src/config.rs` calls it.

## 6. Zone (`crates/proto-dns/src/zone.rs`)
- View = `u32` bitmask: bit k = network k (≤ 16 networks), plus `ROUTER`.
- Host label → `Vec<Record { ip, source, seen_by: mask }>`.
- `lookup(name, qtype, view)`:
  - Name in a local domain, no record for the view → **NXDOMAIN, never
    forwarded**.
  - Overrides: a separate map of exact names. In view: A answers, AAAA and
    other types NoData (a dual-stack client must not take the public IPv6
    address). Out of view: `NotLocal`, forwarded as usual.
  - PTR filtered by the same mask: a hidden address answers NXDOMAIN.
- DHCP never takes over a static name within the static record's views.
- `is_local_name` stays view-independent and overrides are **not** local:
  upstream answers for an override name keep rebind protection.

## 7. Resolver (`crates/proto-dns/src/resolver.rs`)
- `handle_query(now, client, view, query)`; only step 1 (local zone) uses
  the view. The cache cannot mix views: local answers are never cached, and
  a view that answers a name locally never reaches the cache for it.
- `Stats.hidden`: answers withheld by a view (`/api/status` `dns`, CLI
  `status`).

## 8. Kernel
- `config.rs`: `dns_views() -> Vec<u32>` (`"all"` = every bit). Each
  record's `seen_by` (DHCP names, reservation names, `[[dns.host]]`) = the
  networks that see its address's network, or its own `networks`.
- `net/services.rs`:
  - `build_zone` takes the masks.
  - The query loop passes network i's bit; SNTP passes `ROUTER`.
  - `apply_dhcp_events` gets the network index, so runtime leases get the
    right mask.
  - `reconfigure` already rebuilds the zone: firewall changes update the
    views live.

## 9. Web interface (`net/mgmt.html`)
On the DNS page:
- "Local names visible across networks": all / by firewall.
- Hosts table: name, IP, networks (multi-select, empty = by views).
- A warning on overrides of public names (DNSSEC-validating clients reject
  them).
- The `hidden` counter in the status table.

## 10. Tests
- `proto-dns`:
  - Two views, two answers.
  - Hidden → NXDOMAIN, not forwarded.
  - Override: in view A + AAAA NoData; out of view forwarded.
  - PTR per view.
  - Rebind protection still applies to upstream answers for override names.
  - DHCP cannot take a static name inside its views.
  - Each with a control (the other view gives the other result).
- `config`:
  - `dns_views` on the home topology (iot sees homeassistant, lan sees all,
    powerstream only its own).
  - Validation errors.
  - Version 1 configs still load.
- Lab, `LAB_GUEST=1 LAB_DNS_VIEWS=1` (router with `views = "firewall"`).
  From `eth0.20` (guest):
  - `labclient.home.arpa` and its PTR → NXDOMAIN.
  - `nas.home.arpa` → resolves (rule `guest-ping-nas`; check the lab config has a
    `nas` reservation, add it if not).
  - `labguest.guest.home.arpa` → resolves.
  - From `eth0`: all resolve.
  - Override `www.isp.example`: internal address on the LAN, the ISP's on
    the guest network.
  - `hidden` counter rises.
  - Negative controls:
    - `LAB_DNS_VIEWS=0` (`all`): the hiding checks fail.
    - `LAB_GUEST_RULES=0`: `nas.home.arpa` fails too.
    - `LAB_DNS_HOSTS=0` (no `[[dns.host]]`): the split and override checks fail.
  - Also with `LAB_GUEST_LIVE=1`, `LAB_DOT=1`, `LEATOS_ARCH=x86_64`,
    `QEMU_ACCEL=tcg`.
- Also `cli-test`, `store-test` (saving the new fields), `cargo test`,
  `clippy`, `kclippy`, `kcheck-x86`.

## 11. Docs
- `config-v2.md`: `[[dns.host]]`, `[dns] views`, the visibility rule,
  overrides; drop `[[dns.host]]` from §4's "not yet" list and item 8.
- CLAUDE.md: the `unsupported()` note, the lab command, a `dns_views=` boot
  argument if one is added for the negative control.
- `roadmap.md` status.

## 12. Order of work
1. `Zone` rework + tests; the resolver's view argument + tests.
2. Config schema, validation, `dns_views` + tests.
3. Kernel wiring; smoke test plus a manual lab check.
4. Lab checks with negative controls.
5. Web UI, CLI, docs.

Estimate: about 400–600 lines plus tests; the `Zone` rework and the lab
checks are the bulk. Risk is low for forwarding: local answers touch
neither the cache nor the datapath. The visibility rule (§4) is the part to
get right; the home-topology test covers it.
