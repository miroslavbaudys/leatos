# Fuzz targets (M9)

libFuzzer targets for the sans-IO crates, through `cargo-fuzz`. This directory
is a Cargo workspace of its own: the main workspace stays on stable and never
builds libFuzzer.

Setup (once): `rustup toolchain install nightly --profile minimal` and
`cargo install cargo-fuzz`.

```sh
cd fuzz
cargo +nightly fuzz list
cargo +nightly fuzz run fwd -- -max_total_time=600 -max_len=4096
cargo +nightly fuzz run fwd -j 8 -- -max_total_time=3600   # 8 jobs
cargo +nightly fuzz run fwd artifacts/fwd/crash-...        # reproduce
cargo +nightly fuzz fmt fwd artifacts/fwd/crash-...        # show the input
```

Corpora (`corpus/`) and crashes (`artifacts/`) are gitignored. A crash that
reveals a bug gets a host regression test in its crate before the fix.

| Target | Code | Exposure | Beyond "no panic" it checks |
|---|---|---|---|
| `fwd` | `crates/fwd` forwarder, conntrack, NAT, firewall, fragments, split | every packet, WAN and LAN | forwarded frames inside the buffer; valid checksums in → valid out (NAT) |
| `pppoe` | `crates/proto-pppoe` client + `wire` | WAN (the ISP's AC, anyone on the segment) | client frames are PPPoE from its MAC; TX queue bounded |
| `dns` | `crates/proto-dns` resolver, cache, zone, `wire` | upstream answers (internet), LAN queries | replies only to clients that asked; queries only to upstreams |
| `sntp` | `crates/proto-sntp` | WAN replies | requests only to configured servers |
| `http` | `crates/proto-http` parser | LAN, before authentication | body ≤ limits and Content-Length; whole and split feeds agree |
| `dhcp` | `crates/proto-dhcp` server, packet, persist | LAN | no shared addresses; pool bounds; persist round trip; emit/parse |
| `mdns` | `crates/proto-mdns` wire + reflector | LAN multicast | rebuild = parse; reflects only along rules, never back |
| `qdisc` | `crates/qdisc` CAKE / FQ-CoDel / CoDel + shaper, ACK filter on and off | every forwarded packet | backlog limits; packet conservation; no duplicates; drains |
| `ack_filter` | `crates/qdisc` ACK filter decision on arbitrary bytes | pure TCP ACKs from the LAN | no panic; never supersedes itself; never mutual |
| `boot_image` | `crates/boot-image` ELF / Multiboot2 | uploaded kernels (authenticated) | plan inside the allowed range; flatten fits |

The stateful targets generate operations rather than bytes: packets built from
fields over the addresses and ports the configuration knows (with correct
checksums, so they reach the logic behind the parsers), replies to what the
code under test just sent (NAT reverse path, the PPPoE AC's answers, upstream
DNS answers to the resolver's own query, SNTP replies with the right cookie),
and damaged or raw variants of all of them. Shared builders are in `src/lib.rs`.
