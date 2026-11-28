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

Corpora (`corpus/`) and crashes (`artifacts/`) are gitignored; `seeds/`
holds committed starting inputs (`seeds/config`: the examples of
docs/config-v2.md), passed as a second corpus directory:
`cargo +nightly fuzz run config corpus/config seeds/config -- -max_len=16384`. A crash that
reveals a bug gets a host regression test in its crate before the fix.

| Target | Code | Exposure | Beyond "no panic" it checks |
|---|---|---|---|
| `fwd` | `crates/fwd` forwarder, conntrack, NAT, firewall, fragments, split; `nd` (ARP / ND answers); `udp` (the router's own datagrams), `echo`, `mcast` | every packet, WAN and LAN | forwarded frames inside the buffer; valid checksums in → valid out (NAT); ARP / NA replies only to requests for our addresses, never to our own MAC, well formed; `udp::parse4` payload inside the frame, `build4` of it parses back; an echo reply goes back to the sender with the request's data |
| `pppoe` | `crates/proto-pppoe` client + `wire` | WAN (the ISP's AC, anyone on the segment) | client frames are PPPoE from its MAC; TX queue bounded |
| `dns` | `crates/proto-dns` resolver, cache, zone, `wire` | upstream answers (internet), LAN queries | replies only to clients that asked; queries only to upstreams |
| `sntp` | `crates/proto-sntp` | WAN replies | requests only to configured servers |
| `http` | `crates/proto-http` parser | LAN, before authentication | body ≤ limits and Content-Length; whole and split feeds agree |
| `dhcp` | `crates/proto-dhcp` server, packet, persist | LAN | no shared addresses; pool bounds; persist round trip; emit/parse |
| `dhcp_client` | `crates/proto-dhcp` `v4::client` (the WAN's client, `net::wan4`) | WAN (the ISP's server, anyone on the segment) | requests from our MAC, from 0.0.0.0 to broadcast unless renewing; a held lease is a host address with a contiguous mask; `Lost` only after `Bound`; deadline never past |
| `mdns` | `crates/proto-mdns` wire + reflector | LAN multicast | rebuild = parse; reflects only along rules, never back |
| `qdisc` | `crates/qdisc` CAKE / FQ-CoDel / CoDel + shaper, ACK filter on and off | every forwarded packet | backlog limits; packet conservation; no duplicates; drains |
| `ack_filter` | `crates/qdisc` ACK filter decision on arbitrary bytes | pure TCP ACKs from the LAN | no panic; never supersedes itself; never mutual |
| `boot_image` | `crates/boot-image` ELF / Multiboot2, the framebuffer tag | uploaded kernels (authenticated) | plan inside the allowed range; flatten fits; a parsed framebuffer tag rebuilt by `build_info` parses back the same |
| `install_image` | `crates/install-image` header, extents, write plan | the installer's boot module (hash-checked) | plan ascending, covers the image once + the GPT tail; `build` round-trips |
| `cli` | `crates/cli` line editor + command parser | the serial console | lines ≤ `MAX_LINE`; whole and split feeds give the same lines |
| `config` | `crates/config` TOML / JSON parse, validation, `with_assignment`, `without`, diffs, secrets | the store at boot, `POST /api/config`, CLI `config set` | a config that parses re-parses from its own TOML and JSON to itself |
| `store` | `crates/config-store` MBR, store header, A/B record slots, write plans | the SD card / disk at boot | header round trip, areas inside the partition; a planned write gives a valid slot that becomes current, the other slot untouched |
| `dns_tcp` | `proto_dns::tcp` DNS-over-TCP framing | LAN clients on port 53 | queries 12..=`MAX_QUERY` and equal to a reference parse; outstanding and output bounds; output = framed answers in order |
| `auth` | `crates/auth` hash strings, sessions, login throttle (PBKDF2 only with ≤ 64 iterations) | stored hashes, any client's tokens and logins | only issued tokens accepted; session and source caps; backoff ≤ `MAX_BLOCK_MS`; hash budget rate |
| `tcp` | `crates/proto-tcp`: segments (checksum good or bad, sequence and ACK numbers absolute or relative to what the stack sent) to a listening and a connecting socket, user calls, time steps | LAN clients on :80 / :53, the WAN for the DoT client's connections | buffers within their sizes; every segment sent parses back with a valid checksum and fits the MSS; a deadline of "now" is followed by a segment (no livelock) |
| `dot` | `crates/proto-dot` crypto provider (key exchange, signatures, AEAD), `verify::validity`, a client on an arbitrary server stream | DoT servers / the path before the certificate check | no all-zero shared secret accepted |

The stateful targets generate operations rather than bytes: packets built from
fields over the addresses and ports the configuration knows (with correct
checksums, so they reach the logic behind the parsers), replies to what the
code under test just sent (NAT reverse path, the PPPoE AC's answers, upstream
DNS answers to the resolver's own query, SNTP replies with the right cookie),
and damaged or raw variants of all of them. Shared builders are in `src/lib.rs`.
