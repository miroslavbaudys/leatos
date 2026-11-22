use crate::*;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

const FULL: &str = r#"
version = 2

[[network]]
name = "lan"
ipv4 = "10.10.0.1/24"

[network.dhcp]
range = ["10.10.0.50", "10.10.0.150"]
lease_secs = 3600

[[network.dhcp.static]]
mac = "52:54:00:00:00:05"
ip = "10.10.0.10"
hostname = "nas"

[[network.dhcp.static]]
mac = "AA:BB:CC:DD:EE:01"
ip = "10.10.0.60"

[dns]
domain = "home.lan"
cache_entries = 1000
rebind_protection = false

[shaping]
up_kbit = 18000
down_kbit = 90000
overhead = 20
ecn_up = true
ecn_down = false
qdisc = "fq_codel"
isolation = "dual-dsthost"

[mgmt]
on_wan = true

[time]
ntp_servers = ["ntp.isp.example", "192.0.2.123"]

[wan]
vlan = 848
vlan_pcp = 1
"#;

fn ip(a: u8, b: u8, c: u8, d: u8) -> core::net::Ipv4Addr {
    core::net::Ipv4Addr::new(a, b, c, d)
}

/// A one-network document (the LAN on `ipv4`), then `rest`.
fn lan_doc(ipv4: &str, rest: &str) -> String {
    alloc::format!("[[network]]\nname = \"lan\"\nipv4 = \"{ipv4}\"\n{rest}")
}

fn paths(e: Error) -> Vec<String> {
    match e {
        Error::Invalid(v) => v.into_iter().map(|i| i.path).collect(),
        other => panic!("expected Invalid, got {other:?}"),
    }
}

/// Issue paths, none if the config is valid.
fn issues(f: impl FnOnce(&mut Config)) -> Vec<String> {
    let mut c = Config::default();
    f(&mut c);
    parse(&c.to_toml()).err().map(paths).unwrap_or_default()
}

fn invalid(f: impl FnOnce(&mut Config)) -> Vec<String> {
    let mut c = Config::default();
    f(&mut c);
    paths(parse(&c.to_toml()).unwrap_err())
}

#[test]
fn full_document_parses() {
    let c = parse(FULL).unwrap();
    assert_eq!(c.networks[0].ipv4, Cidr::new(ip(10, 10, 0, 1), 24));
    assert_eq!(c.dns.domain, "home.lan");
    assert_eq!(c.networks[0].dhcp_range(), (ip(10, 10, 0, 50), ip(10, 10, 0, 150)));
    assert_eq!(c.networks[0].dhcp.lease_secs, 3600);
    assert_eq!(
        c.networks[0].dhcp.statics,
        vec![
            StaticLease {
                mac: Mac([0x52, 0x54, 0, 0, 0, 5]),
                ip: ip(10, 10, 0, 10),
                hostname: Some("nas".into())
            },
            StaticLease {
                mac: Mac([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 1]),
                ip: ip(10, 10, 0, 60),
                hostname: None
            },
        ]
    );
    assert_eq!(
        c.dns,
        Dns {
            cache_entries: 1000,
            rebind_protection: false,
            domain: "home.lan".into(),
            hosts: vec![],
            ..Dns::default()
        }
    );
    assert_eq!(
        c.shaping,
        Shaping {
            up_kbit: Some(18000),
            down_kbit: Some(90000),
            overhead: 20,
            ecn_up: true,
            ecn_down: false,
            qdisc: Qdisc::FqCodel,
            isolation: Isolation::DualDstHost,
            queue_ms: DEFAULT_QUEUE_MS,
            ack_filter: false,
        }
    );
    assert!(c.mgmt.on_wan);
    assert_eq!(c.time.ntp_servers, ["ntp.isp.example", "192.0.2.123"]);
    assert_eq!(
        c.wan,
        Wan {
            vlan: Some(848),
            vlan_pcp: 1,
            ..Wan::default()
        }
    );
}

#[test]
fn round_trips() {
    for c in [Config::default(), parse(FULL).unwrap()] {
        let text = c.to_toml();
        assert!(!text.is_empty());
        assert_eq!(parse(&text).unwrap(), c, "{text}");
    }
    // Canonical form: MACs lower case.
    assert!(
        parse(FULL)
            .unwrap()
            .to_toml()
            .contains("\"aa:bb:cc:dd:ee:01\"")
    );
}

#[test]
fn defaults_are_valid_and_match_the_kernel() {
    let c = Config::default();
    assert_eq!(c.validate(), Ok(()));
    assert_eq!(c.networks[0].ipv4.to_string(), "192.168.1.1/24");
    assert_eq!(
        c.networks[0].dhcp_range(),
        (ip(192, 168, 1, 100), ip(192, 168, 1, 199))
    );
    assert_eq!(c.networks[0].dhcp.lease_secs, 43200);
    assert_eq!((c.shaping.ecn_up, c.shaping.ecn_down), (false, true));
    assert_eq!(
        (c.shaping.qdisc, c.shaping.isolation),
        (Qdisc::Cake, Isolation::Triple)
    );
    assert_eq!(
        c.dns,
        Dns {
            cache_entries: 4096,
            rebind_protection: true,
            domain: "lan".into(),
            hosts: vec![],
            ..Dns::default()
        }
    );
    assert!(!c.mgmt.on_wan);
    assert_eq!(c.time.ntp_servers, ["pool.ntp.org"]);
}

#[test]
fn sparse_files_fill_in_defaults() {
    assert_eq!(parse("").unwrap(), Config::default());
    let c = parse("[shaping]\nup_kbit = 18000\n").unwrap();
    assert_eq!(c.shaping.up_kbit, Some(18000));
    assert_eq!(c.shaping.down_kbit, None);
    assert_eq!(c.networks, Config::default().networks);
    let c = parse(&lan_doc("10.0.0.1/16", "")).unwrap();
    assert_eq!(c.dns.domain, "lan");
    assert_eq!(c.networks[0].dhcp_range(), (ip(10, 0, 0, 100), ip(10, 0, 0, 199)));
}

#[test]
fn derived_range_in_small_subnets() {
    let mut l = Network {
        ipv4: Cidr::new(ip(10, 0, 0, 1), 29), // hosts .1–.6
        ..Network::default()
    };
    assert_eq!(l.dhcp_range(), (ip(10, 0, 0, 2), ip(10, 0, 0, 6)));
    l.ipv4 = Cidr::new(ip(10, 0, 0, 129), 25); // .128/25: hosts .129–.254
    assert_eq!(l.dhcp_range(), (ip(10, 0, 0, 130), ip(10, 0, 0, 254)));
}

#[test]
fn syntax_errors_name_the_line() {
    let e = parse("[[network]]\nipv4 = 10.10.0.1\n").unwrap_err();
    let Error::Syntax(m) = &e else {
        panic!("{e:?}")
    };
    assert!(m.contains("line 2"), "{m}");

    let e = parse(&FULL.replace("domain", "domian")).unwrap_err();
    let m = e.to_string();
    assert!(
        m.contains("unknown field `domian`") && m.contains("line 22"),
        "{m}"
    );

    let e = parse(&lan_doc("10.10.0.1", "")).unwrap_err();
    assert!(e.to_string().contains("expected a.b.c.d/len"), "{e}");
    let e =
        parse(&lan_doc("192.168.1.1/24", "[[network.dhcp.static]]\nmac = \"52:54:00:00:05\"\nip = \"192.168.1.5\"\n")).unwrap_err();
    assert!(e.to_string().contains("six bytes"), "{e}");
    let e = parse("[shaping]\nqdisc = \"pfifo\"\n").unwrap_err();
    assert!(matches!(e, Error::Syntax(_)), "{e:?}");
    // Negative rate: not representable in u64.
    assert!(matches!(
        parse("[shaping]\nup_kbit = -5\n"),
        Err(Error::Syntax(_))
    ));
    // Reservations need mac and ip.
    assert!(matches!(
        parse(&lan_doc("192.168.1.1/24", "[[network.dhcp.static]]\nip = \"192.168.1.5\"\n")),
        Err(Error::Syntax(_))
    ));
}

#[test]
fn size_and_version_limits() {
    let big = "#".repeat(MAX_LEN + 1);
    assert_eq!(parse(&big), Err(Error::TooLarge { len: MAX_LEN + 1 }));
    let max = "#".repeat(MAX_LEN);
    assert!(parse(&max).is_ok());

    // A newer document is reported as newer, even with fields we don't know.
    let newer = "version = 3\n[firewall]\nzones = []\n";
    assert_eq!(parse(newer), Err(Error::NewerVersion(3)));
    assert_eq!(paths(parse("version = 0\n").unwrap_err()), ["version"]);
    // Version 1 is no longer read, with or without its version line.
    assert_eq!(parse("version = 1\n[lan]\nipv4 = \"10.0.0.1/16\"\n"), Err(Error::OldVersion(1)));
    assert_eq!(parse("[lan]\ndomain = \"x\"\n"), Err(Error::OldVersion(1)));
    assert_eq!(parse(&lan_doc("10.0.0.1/24", "")).map(|_| ()).err(), None);
    assert!(parse("version = 1\n").unwrap_err().to_string().contains("[[network]]"));
    assert!(matches!(parse("version = 2\n[lan]\nipv4 = \"10.0.0.1/24\"\n"), Err(Error::Syntax(_))));
    // Missing version = current.
    assert_eq!(
        parse("[dns]\ncache_entries = 100\n").unwrap().version,
        VERSION
    );
}

#[test]
fn lan_checks() {
    assert_eq!(invalid(|c| c.networks[0].ipv4.prefix = 30), ["network.lan.ipv4"]);
    assert_eq!(invalid(|c| c.networks[0].ipv4.prefix = 7), ["network.lan.ipv4"]);
    assert_eq!(
        invalid(|c| c.networks[0].ipv4.addr = ip(192, 168, 1, 0)),
        ["network.lan.ipv4"]
    );
    assert_eq!(
        invalid(|c| c.networks[0].ipv4.addr = ip(192, 168, 1, 255)),
        ["network.lan.ipv4"]
    );
    for bad in [
        "",
        "-lan",
        "lan-",
        "my_lan",
        "a..b",
        "lan.",
        &"x".repeat(64),
    ] {
        assert_eq!(
            invalid(|c| c.dns.domain = bad.into()),
            ["dns.domain"],
            "{bad:?}"
        );
    }
    assert!(parse("[dns]\ndomain = \"home.example-1.lan\"\n").is_ok());
}

#[test]
fn dhcp_checks() {
    let r = |lo, hi| move |c: &mut Config| c.networks[0].dhcp.range = Some([lo, hi]);
    assert_eq!(
        invalid(r(ip(192, 168, 0, 10), ip(192, 168, 1, 20))),
        ["network.lan.dhcp.range[0]"]
    );
    assert_eq!(
        invalid(r(ip(192, 168, 1, 10), ip(192, 168, 1, 255))),
        ["network.lan.dhcp.range[1]"]
    );
    assert_eq!(
        invalid(r(ip(192, 168, 1, 50), ip(192, 168, 1, 40))),
        ["network.lan.dhcp.range"]
    );
    // At most MAX_DHCP_POOL addresses (a /16 network: 4096 fit, 4097 do not).
    let wide = |lo, hi| {
        move |c: &mut Config| {
            c.networks[0].ipv4 = "10.0.0.1/16".parse().unwrap();
            c.networks[0].dhcp.range = Some([lo, hi]);
        }
    };
    assert_eq!(issues(wide(ip(10, 0, 0, 100), ip(10, 0, 16, 99))), Vec::<String>::new());
    assert_eq!(invalid(wide(ip(10, 0, 0, 100), ip(10, 0, 16, 100))), ["network.lan.dhcp.range"]);
    assert_eq!(
        invalid(|c| c.networks[0].dhcp.lease_secs = 59),
        ["network.lan.dhcp.lease_secs"]
    );
    assert_eq!(
        invalid(|c| c.networks[0].dhcp.lease_secs = 31 * 86400),
        ["network.lan.dhcp.lease_secs"]
    );

    // A changed subnet must carry the range along: the derived one does.
    let c = parse(&lan_doc("10.1.2.1/24", "")).unwrap();
    assert_eq!(c.networks[0].dhcp_range().0, ip(10, 1, 2, 100));
}

#[test]
fn reservation_checks() {
    let s = |mac: [u8; 6], ip, name: Option<&str>| StaticLease {
        mac: Mac(mac),
        ip,
        hostname: name.map(Into::into),
    };
    let m1 = [0x52, 0x54, 0, 0, 0, 1];
    let m2 = [0x52, 0x54, 0, 0, 0, 2];
    let with = |v: Vec<StaticLease>| move |c: &mut Config| c.networks[0].dhcp.statics = v;

    // A valid pair, one inside the dynamic range (allowed: the server skips it).
    let mut c = Config::default();
    c.networks[0].dhcp.statics = vec![
        s(m1, ip(192, 168, 1, 10), Some("nas")),
        s(m2, ip(192, 168, 1, 150), Some("tv")),
    ];
    assert_eq!(parse(&c.to_toml()).unwrap(), c);

    assert_eq!(
        invalid(with(vec![s([0; 6], ip(192, 168, 1, 10), None)])),
        ["network.lan.dhcp.static[0].mac"]
    );
    assert_eq!(
        invalid(with(vec![s([1, 0, 0, 0, 0, 1], ip(192, 168, 1, 10), None)])),
        ["network.lan.dhcp.static[0].mac"]
    );
    assert_eq!(
        invalid(with(vec![s(m1, ip(10, 0, 0, 10), None)])),
        ["network.lan.dhcp.static[0].ip"]
    );
    assert_eq!(
        invalid(with(vec![s(m1, ip(192, 168, 1, 1), None)])),
        ["network.lan.dhcp.static[0].ip"]
    );
    assert_eq!(
        invalid(with(vec![s(m1, ip(192, 168, 1, 255), None)])),
        ["network.lan.dhcp.static[0].ip"]
    );
    assert_eq!(
        invalid(with(vec![
            s(m1, ip(192, 168, 1, 10), None),
            s(m1, ip(192, 168, 1, 11), None)
        ])),
        ["network.lan.dhcp.static[1].mac"]
    );
    assert_eq!(
        invalid(with(vec![
            s(m1, ip(192, 168, 1, 10), None),
            s(m2, ip(192, 168, 1, 10), None)
        ])),
        ["network.lan.dhcp.static[1].ip"]
    );
    assert_eq!(
        invalid(with(vec![
            s(m1, ip(192, 168, 1, 10), Some("NAS")),
            s(m2, ip(192, 168, 1, 11), Some("nas"))
        ])),
        ["network.lan.dhcp.static[1].hostname"]
    );
    assert_eq!(
        invalid(with(vec![s(m1, ip(192, 168, 1, 10), Some("my nas"))])),
        ["network.lan.dhcp.static[0].hostname"]
    );
    assert_eq!(
        invalid(with(vec![s(m1, ip(192, 168, 1, 10), Some("nas.lan"))])),
        ["network.lan.dhcp.static[0].hostname"]
    );

    // Too many.
    let many = (0..=validate::MAX_STATICS as u32)
        .map(|i| {
            let b = i.to_be_bytes();
            s(
                [0x02, 0, b[0], b[1], b[2], b[3]],
                ip(10, 0, b[2], b[3]),
                None,
            )
        })
        .collect::<Vec<_>>();
    let mut c = Config::default();
    c.networks[0].ipv4 = Cidr::new(ip(10, 0, 0, 1), 8);
    c.networks[0].dhcp.statics = many;
    let p = c
        .validate()
        .unwrap_err()
        .into_iter()
        .map(|i| i.path)
        .collect::<Vec<_>>();
    assert!(p.contains(&"network".into()), "{p:?}");
}

#[test]
fn shaping_and_dns_checks() {
    assert_eq!(
        invalid(|c| c.shaping.up_kbit = Some(10)),
        ["shaping.up_kbit"]
    );
    assert_eq!(
        invalid(|c| c.shaping.down_kbit = Some(20_000_000)),
        ["shaping.down_kbit"]
    );
    assert_eq!(invalid(|c| c.shaping.overhead = 300), ["shaping.overhead"]);
    assert_eq!(invalid(|c| c.shaping.queue_ms = 5), ["shaping.queue_ms"]);
    assert_eq!(invalid(|c| c.shaping.queue_ms = 1001), ["shaping.queue_ms"]);
    for ok in [0, 10, 1000] {
        let mut c = Config::default();
        c.shaping.queue_ms = ok;
        assert_eq!(c.validate(), Ok(()), "queue_ms {ok}");
    }
    assert_eq!(invalid(|c| c.dns.cache_entries = 0), ["dns.cache_entries"]);
    let c = parse("[shaping]\nqdisc = \"codel\"\nisolation = \"flows\"\n").unwrap();
    assert_eq!(
        (c.shaping.qdisc, c.shaping.isolation),
        (Qdisc::Codel, Isolation::Flows)
    );
}

#[test]
fn dns_prefetch_is_on_by_default() {
    let c = Config::default();
    assert!(c.dns.prefetch);
    assert!(!c.to_toml().contains("prefetch"), "the default is written as nothing");
    let off = parse("version = 2\n[dns]\nprefetch = false\n").unwrap();
    assert!(!off.dns.prefetch);
    let toml = off.to_toml();
    assert!(toml.contains("prefetch = false"), "{toml}");
    assert_eq!(parse(&toml).unwrap(), off);
}

#[test]
fn dns_serve_stale_window() {
    let c = Config::default();
    assert_eq!(c.dns.stale_secs, 86_400);
    assert!(!c.to_toml().contains("stale"), "the default is written as nothing");
    let off = parse("version = 2\n[dns]\nstale_secs = 0\n").unwrap();
    assert_eq!(off.dns.stale_secs, 0);
    assert_eq!(parse(&off.to_toml()).unwrap(), off);
    assert_eq!(invalid(|c| c.dns.stale_secs = 604_801), ["dns.stale_secs"]);
    assert!(issues(|c| c.dns.stale_secs = 604_800).is_empty());
}

#[test]
fn dns_upstreams_and_tls() {
    // Cloudflare over TLS, as written by hand.
    let c = parse(
        "version = 2\n[dns]\ntls = true\nupstreams = [\"1.1.1.1#cloudflare-dns.com\", \"1.0.0.1:853#Cloudflare-DNS.com\"]\n",
    )
    .unwrap();
    let ups = c.dns.upstream_list();
    assert_eq!(ups.len(), 2);
    assert_eq!((ups[0].ip, ups[0].port(true), ups[0].name.as_deref()), (core::net::IpAddr::V4(ip(1, 1, 1, 1)), 853, Some("cloudflare-dns.com")));
    assert_eq!((ups[1].port, ups[1].name.as_deref()), (Some(853), Some("cloudflare-dns.com")), "names lowercased");
    assert_eq!(alloc::format!("{}", ups[1]), "1.0.0.1:853#cloudflare-dns.com");
    assert!(c.unsupported().is_empty(), "implemented: {:?}", c.unsupported());
    assert!(c.to_toml().contains("tls = true"));
    assert_eq!(parse(&c.to_toml()).unwrap(), c, "round trip");
    let json = c.to_json();
    assert_eq!(parse_json(&json).unwrap(), c, "JSON round trip");
    // Plain upstreams: any port, a name allowed (used once TLS is on).
    let plain = parse("version = 2\n[dns]\nupstreams = [\"9.9.9.9\", \"192.168.1.53:5353\", \"8.8.8.8#dns.google\"]\n").unwrap();
    assert_eq!(plain.dns.upstream_list()[1].port(false), 5353);
    assert_eq!(plain.dns.upstream_list()[0].port(false), 53);
    // Defaults: the lease's servers, written as nothing.
    assert!(!Config::default().to_toml().contains("upstreams"));

    let set = |ups: &[&str], tls: bool| {
        issues(|c| {
            c.dns.upstreams = ups.iter().map(|s| String::from(*s)).collect();
            c.dns.tls = tls;
        })
    };
    assert_eq!(set(&["1.1.1.1"], true), ["dns.upstreams[0]"], "TLS needs the certificate name");
    assert_eq!(set(&[], true), ["dns.upstreams"], "TLS needs servers");
    assert_eq!(set(&["1.1.1"], false), ["dns.upstreams[0]"]);
    assert_eq!(set(&["0.0.0.0"], false), ["dns.upstreams[0]"]);
    assert_eq!(set(&["127.0.0.1"], false), ["dns.upstreams[0]"]);
    assert_eq!(set(&["1.1.1.1:0"], false), ["dns.upstreams[0]"]);
    assert_eq!(set(&["1.1.1.1#bad name"], false), ["dns.upstreams[0]"]);
    assert_eq!(set(&["1.1.1.1#a", "1.1.1.1#b"], true), ["dns.upstreams[1]"], "same server twice");
    assert_eq!(set(&["1.1.1.1", "1.1.1.1:53"], false), ["dns.upstreams[1]"], "53 is the default");
    assert_eq!(set(&["1.1.1.1#a", "1.1.1.2#a", "1.1.1.3#a", "1.1.1.4#a", "1.1.1.5#a"], true), ["dns.upstreams"]);
    assert!(set(&["1.1.1.1#1.1.1.1"], true).is_empty(), "an IP certificate name");

    let ca = |pem: &str| issues(|c| c.dns.tls_ca = Some(String::from(pem)));
    assert_eq!(ca("not pem"), ["dns.tls_ca"]);
    assert_eq!(ca("-----BEGIN CERTIFICATE-----\n!!\n-----END CERTIFICATE-----\n"), ["dns.tls_ca"]);
    assert!(ca("-----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----\n").is_empty());
}

#[test]
fn wan_checks() {
    assert_eq!(invalid(|c| c.wan.vlan = Some(0)), ["wan.vlan"]);
    assert_eq!(invalid(|c| c.wan.vlan = Some(4095)), ["wan.vlan"]);
    assert_eq!(invalid(|c| c.wan.vlan_pcp = 8), ["wan.vlan_pcp"]);
    for v in [1, 848, MAX_VLAN_ID] {
        let mut c = Config::default();
        c.wan.vlan = Some(v);
        assert_eq!(parse(&c.to_toml()).unwrap(), c);
    }
    assert!(parse("[wan]\nvlan = 70000\n").is_err(), "beyond u16");
    assert!(parse("[wan]\nvlan_id = 848\n").is_err(), "unknown field");
}

#[test]
fn pppoe_checks() {
    let pppoe = |c: &mut Config| {
        c.wan.mode = WanMode::Pppoe;
        c.wan.pppoe.username = "alice@isp.example".into();
    };
    // No user name: valid (ISPs without PPPoE authentication).
    let mut anon = Config::default();
    anon.wan.mode = WanMode::Pppoe;
    assert_eq!(parse(&anon.to_toml()).unwrap(), anon);
    // Up to 1500 with RFC 4638; above, or below IPv4's minimum for PPPoE use: refused.
    assert_eq!(invalid(|c| {
        pppoe(c);
        c.wan.pppoe.mtu = 1501;
    }), ["wan.pppoe.mtu"]);
    assert_eq!(invalid(|c| {
        pppoe(c);
        c.wan.pppoe.mtu = 1279;
    }), ["wan.pppoe.mtu"]);
    let mut j = Config::default();
    pppoe(&mut j);
    j.wan.pppoe.mtu = 1500;
    assert!(j.validate().is_ok(), "{:?}", j.validate());
    assert_eq!(invalid(|c| {
        pppoe(c);
        c.wan.pppoe.password = Some("x".repeat(256));
    }), ["wan.pppoe.password"]);
    assert_eq!(invalid(|c| {
        pppoe(c);
        c.wan.pppoe.service = "a\nb".into();
    }), ["wan.pppoe.service"]);
    assert_eq!(invalid(|c| {
        pppoe(c);
        c.wan.pppoe.lcp_echo_failure = 0;
    }), ["wan.pppoe.lcp_echo_failure"]);
    let text = r#"
[wan]
vlan = 848
mode = "pppoe"

[wan.pppoe]
username = "alice@isp.example"
password = "s3cret"
"#;
    let c = parse(text).unwrap();
    assert_eq!(c.wan.mode, WanMode::Pppoe);
    assert_eq!(c.wan.pppoe.password.as_deref(), Some("s3cret"));
    assert_eq!((c.wan.pppoe.mtu, c.wan.pppoe.lcp_echo_interval, c.wan.pppoe.lcp_echo_failure), (1492, 10, 5));
    assert_eq!(parse(&c.to_toml()).unwrap(), c, "the store keeps the password");
    assert_eq!(paths(parse("[wan]\nmode = \"static\"\n").unwrap_err()), ["wan.static"]);
    assert!(parse("[wan.pppoe]\nuser = \"x\"\n").is_err(), "unknown field");
}

#[test]
fn pppoe_password_is_a_secret() {
    let mut c = Config::default();
    c.wan.mode = WanMode::Pppoe;
    c.wan.pppoe.username = "alice".into();
    c.wan.pppoe.password = Some("s3cret".into());
    let shown = c.without_secrets();
    for text in [shown.to_toml(), shown.to_json(), flat_lines(&shown).join("\n")] {
        assert!(!text.contains("s3cret"), "{text}");
        assert!(text.contains("alice"));
    }
    assert!(diff_lines(&Config::default(), &shown).iter().all(|l| !l.contains("s3cret")));
    // The form sends the config back without it: the password stays.
    let mut back = parse_json(&shown.to_json()).unwrap();
    back.keep_secrets(&c);
    assert_eq!(back, c);
    // An explicit empty one clears it.
    let mut cleared = shown.with_assignment(r#"wan.pppoe.password = """#).unwrap();
    cleared.keep_secrets(&c);
    assert_eq!(cleared.wan.pppoe.password.as_deref(), Some(""));
}

#[test]
fn static_wan_through_assignments() {
    // The CLI's path: the whole table at once (both fields are required),
    // then single fields; the mode switches separately.
    let c = Config::default();
    let s = c
        .with_assignment(r#"wan.static = { ipv4 = "203.0.113.50/24", gateway = "203.0.113.1" }"#)
        .unwrap();
    assert_eq!(s.wan.static_ip.as_ref().unwrap().gateway, ip(203, 0, 113, 1));
    assert!(c.with_assignment(r#"wan.static.ipv4 = "203.0.113.50/24""#).is_err(), "gateway missing");
    let s = s.with_assignment(r#"wan.static.dns = ["203.0.113.1"]"#).unwrap();
    let s = s.with_assignment(r#"wan.mode = "static""#).unwrap();
    assert!(s.validate().is_ok(), "{:?}", s.validate());
    assert_eq!(s.unsupported(), vec![]);
    let t = s.to_toml();
    assert!(t.contains("mode = \"static\"") && t.contains("[wan.static]"), "{t}");
    assert_eq!(parse(&t).unwrap(), s);
    // Back to DHCP: the static settings stay for later, unused.
    let d = s.with_assignment(r#"wan.mode = "dhcp""#).unwrap();
    assert!(d.validate().is_ok());
    assert!(d.wan.static_ip.is_some());
}

#[test]
fn dhcp_wan_leaves_pppoe_out_of_the_canonical_form() {
    // Kernels from before PPPoE know [wan] with vlan/vlan_pcp only.
    let mut c = Config::default();
    c.wan.vlan = Some(848);
    let t = c.to_toml();
    assert!(!t.contains("mode") && !t.contains("pppoe"), "{t}");
    let p = c.with_assignment(r#"wan.mode = "pppoe""#).unwrap();
    assert!(p.to_toml().contains("mode = \"pppoe\""));
    assert_eq!(p.without("wan.mode").unwrap(), c);
    assert_eq!(c.without("wan.pppoe.mtu").unwrap(), c);
    let u = c.with_assignment(r#"wan.pppoe.username = "bob""#).unwrap();
    assert_eq!(u.wan.pppoe.username, "bob");
    assert_eq!(u.without("wan.pppoe.username").unwrap(), c);
    assert_eq!(u.without("wan.pppoe").unwrap(), c);
}

#[test]
fn untagged_wan_is_left_out_of_the_canonical_form() {
    // Kernels from before `[wan]` reject unknown sections: a config that
    // does not use it must not contain it (rollback after an upgrade).
    let c = Config::default();
    assert!(!c.to_toml().contains("[wan]"), "{}", c.to_toml());
    assert!(!c.to_json().contains("\"wan\""), "{}", c.to_json());
    assert!(!flat_lines(&c).iter().any(|l| l.starts_with("wan.")));
    let t = c.with_assignment("wan.vlan = 848").unwrap();
    assert_eq!(t.wan.vlan, Some(848));
    assert!(t.to_toml().contains("[wan]"));
    assert!(diff_lines(&c, &t).contains(&"+ wan.vlan = 848".to_string()));
    // Unsetting it (or anything in an absent section) gives the default back.
    assert_eq!(t.without("wan.vlan").unwrap(), c);
    assert_eq!(t.without("wan").unwrap(), c);
    assert_eq!(c.without("wan.vlan").unwrap(), c);
    assert_eq!(c.without("wan.vlan_pcp").unwrap(), c);
    assert!(c.without("wan.nosuch").is_err());
    // The web form sends the section with defaults: still the same config.
    assert_eq!(parse_json(r#"{"wan":{"vlan_pcp":0}}"#).unwrap(), c);
}

#[test]
fn time_checks() {
    assert_eq!(
        invalid(|c| c.time.ntp_servers = vec!["a.example".into(); 5]),
        ["time.ntp_servers"]
    );
    assert_eq!(
        invalid(|c| c.time.ntp_servers = vec!["ok.example".into(), "bad name".into(), "".into()]),
        ["time.ntp_servers[1]", "time.ntp_servers[2]"]
    );
    // Empty: no SNTP.
    let c = parse("[time]\nntp_servers = []\n").unwrap();
    assert!(c.time.ntp_servers.is_empty());
    assert!(!c.needs_trial(&Config::default()));
}

#[test]
fn all_issues_are_reported() {
    let p = invalid(|c| {
        c.networks[0].dhcp.lease_secs = 1;
        c.dns.cache_entries = 1;
        c.shaping.overhead = 999;
    });
    assert_eq!(
        p,
        [
            "network.lan.dhcp.lease_secs",
            "dns.cache_entries",
            "shaping.overhead"
        ]
    );
    let e = parse("[dns]\ncache_entries = 1\n").unwrap_err();
    assert_eq!(e.to_string(), "dns.cache_entries: must be 16–65536");
}

#[test]
fn value_types() {
    assert_eq!(
        "10.0.0.1/8".parse::<Cidr>(),
        Ok(Cidr::new(ip(10, 0, 0, 1), 8))
    );
    assert!("10.0.0.1/33".parse::<Cidr>().is_err());
    assert!("10.0.0/8".parse::<Cidr>().is_err());
    assert!("10.0.0.1/".parse::<Cidr>().is_err());
    let c = Cidr::new(ip(192, 168, 7, 77), 22);
    assert_eq!(
        (c.network(), c.broadcast(), c.netmask()),
        (
            ip(192, 168, 4, 0),
            ip(192, 168, 7, 255),
            ip(255, 255, 252, 0)
        )
    );
    assert!(c.contains(ip(192, 168, 5, 1)) && !c.contains(ip(192, 168, 8, 1)));
    assert_eq!(Cidr::new(ip(1, 2, 3, 4), 0).mask(), 0);

    assert_eq!(
        "00:0D:b9:5a:3e:e4".parse::<Mac>().unwrap().to_string(),
        "00:0d:b9:5a:3e:e4"
    );
    for bad in [
        "00:0d:b9:5a:3e",
        "00:0d:b9:5a:3e:e4:00",
        "00-0d-b9-5a-3e-e4",
        "0:0d:b9:5a:3e:e4",
        "00:0d:b9:5a:3e:zz",
        "+0:0d:b9:5a:3e:e4",
    ] {
        assert!(bad.parse::<Mac>().is_err(), "{bad}");
    }
}

#[test]
fn json_round_trips_with_the_same_checks() {
    let mut c = Config::default();
    c.networks[0].dhcp.statics.push(StaticLease {
        mac: Mac([0x52, 0x54, 0, 0, 0, 7]),
        ip: ip(192, 168, 1, 7),
        hostname: Some("printer".into()),
    });
    c.shaping.up_kbit = Some(18000);
    let j = c.to_json();
    assert!(j.contains(r#""ipv4":"192.168.1.1/24""#), "{j}");
    assert!(j.contains(r#""mac":"52:54:00:00:00:07""#), "{j}");
    assert_eq!(parse_json(&j).unwrap(), c);
    // Sparse documents get defaults, as in TOML.
    let s = parse_json(r#"{"network":[{"name":"lan","ipv4":"10.1.0.1/16"}]}"#).unwrap();
    assert_eq!(s.networks[0].ipv4, Cidr::new(ip(10, 1, 0, 1), 16));
    assert_eq!(s.dns, Config::default().dns);
    // Unknown fields, bad values, inconsistencies and newer versions fail.
    assert!(matches!(
        parse_json(r#"{"bogus":1}"#),
        Err(Error::Syntax(_))
    ));
    assert!(matches!(
        parse_json(r#"{"network":[{"name":"lan","ipv4":"10.1.0.1"}]}"#),
        Err(Error::Syntax(_))
    ));
    let e =
        parse_json(r#"{"network":[{"name":"lan","ipv4":"10.1.0.1/24","dhcp":{"range":["10.2.0.1","10.2.0.9"]}}]}"#);
    assert!(
        paths(e.unwrap_err())
            .iter()
            .any(|p| p.starts_with("network.lan.dhcp.range"))
    );
    assert_eq!(parse_json(r#"{"version":3}"#), Err(Error::NewerVersion(3)));
    // Version 1 JSON (an old export) is refused like TOML.
    assert_eq!(parse_json(r#"{"version":1,"lan":{"ipv4":"10.1.0.1/16"}}"#), Err(Error::OldVersion(1)));
    assert_eq!(parse_json(r#"{"lan":{"ipv4":"10.1.0.1/16"}}"#), Err(Error::OldVersion(1)));
    let big = alloc::format!(r#"{{"dns":{{"domain":"{}"}}}}"#, "x".repeat(MAX_LEN));
    assert!(matches!(parse_json(&big), Err(Error::TooLarge { .. })));
}

#[test]
fn trial_for_changes_that_can_lock_the_user_out() {
    let old = Config::default();
    let mut c = old.clone();
    assert!(!c.needs_trial(&old));
    c.dns.cache_entries = 100;
    c.shaping.down_kbit = Some(90000);
    c.dns.domain = "home".into();
    assert!(
        !c.needs_trial(&old),
        "harmless changes apply without a trial"
    );
    let mut lan = old.clone();
    lan.networks[0].ipv4.prefix = 16;
    assert!(lan.needs_trial(&old));
    let mut m = old.clone();
    m.mgmt.on_wan = true;
    assert!(m.needs_trial(&old));
    // The WAN VLAN only matters for access while mgmt is on the WAN.
    let mut w = old.clone();
    w.wan.vlan = Some(848);
    assert!(!w.needs_trial(&old));
    let mut on = m.clone();
    on.wan.vlan = Some(848);
    assert!(on.needs_trial(&m));
}

#[test]
fn assignments_edit_one_setting() {
    let c = Config::default();
    let d = c.with_assignment("dns.cache_entries = 1234").unwrap();
    assert_eq!(d.dns.cache_entries, 1234);
    assert_eq!(d.dns.rebind_protection, c.dns.rebind_protection, "siblings kept");
    let d = d
        .with_assignment(r#"time.ntp_servers = ["a.example", "192.0.2.1"]"#)
        .unwrap()
        .with_assignment("shaping.up_kbit = 18000")
        .unwrap()
        .with_assignment(r#"network.lan.dhcp.static = [{ mac = "52:54:00:00:00:05", ip = "192.168.1.10", hostname = "nas" }]"#)
        .unwrap();
    assert_eq!(d.time.ntp_servers, ["a.example", "192.0.2.1"]);
    assert_eq!(d.shaping.up_kbit, Some(18000));
    assert_eq!(d.networks[0].dhcp.statics[0].hostname.as_deref(), Some("nas"));
    // Whole sections can be given as inline tables, and merge.
    let e = d.with_assignment("shaping = { overhead = 20 }").unwrap();
    assert_eq!((e.shaping.overhead, e.shaping.up_kbit), (20, Some(18000)));
    // Not validated yet: out-of-range values pass, save catches them.
    assert!(c.with_assignment("dns.cache_entries = 5").unwrap().validate().is_err());
}

#[test]
fn assignment_errors() {
    let c = Config::default();
    for bad in [
        "dns.cache_entries",              // no value
        "nosuch.x = 1",                   // unknown section
        "dns.nosuch = 1",                 // unknown field
        "dns.cache_entries = \"many\"",   // wrong type
        "shaping.qdisc = \"pfifo\"",      // unknown variant
        "network.lan.ipv4 = \"10.0.0.1\"",        // bad value
        "version = 1",
        "dns.cache_entries = ",
    ] {
        assert!(
            matches!(c.with_assignment(bad), Err(Error::Syntax(_))),
            "{bad} must fail"
        );
    }
}

#[test]
fn unset_restores_defaults() {
    let c = Config::default()
        .with_assignment("dns.cache_entries = 1234")
        .unwrap()
        .with_assignment("shaping.up_kbit = 18000")
        .unwrap();
    let d = c.without("dns.cache_entries").unwrap().without("shaping.up_kbit").unwrap();
    assert_eq!(d, Config::default());
    assert_eq!(Config::default().without("shaping.down_kbit").unwrap(), Config::default());
    assert!(c.without("dns.nosuch").is_err());
    assert!(c.without("nosuch.x").is_err());
    assert!(c.without("version").is_err());
    assert!(c.without("dns.").is_err());
    // A whole section.
    assert_eq!(c.without("dns").unwrap().dns, Dns::default());
}

#[test]
fn diff_shows_changed_settings() {
    let a = Config::default();
    assert!(diff_lines(&a, &a).is_empty());
    let b = a
        .with_assignment("dns.cache_entries = 1234")
        .unwrap()
        .with_assignment(r#"network.lan.dhcp.static = [{ mac = "52:54:00:00:00:05", ip = "192.168.1.10" }]"#)
        .unwrap();
    let d = diff_lines(&a, &b);
    assert!(d.contains(&"- dns.cache_entries = 4096".to_string()), "{d:?}");
    assert!(d.contains(&"+ dns.cache_entries = 1234".to_string()), "{d:?}");
    assert!(d.contains(&"+ network.lan.dhcp.static[0].ip = \"192.168.1.10\"".to_string()), "{d:?}");
    assert!(!flat_lines(&a).iter().any(|l| l.starts_with("version")));
}

// ---- version 2 ---------------------------------------------------------------

const FULL_V2: &str = r#"
version = 2

[wan]
vlan = 848
mode = "pppoe"
[wan.pppoe]
username = "user@isp.example"

[[network]]
name = "lan"
ipv4 = "10.10.0.1/24"
[network.dhcp]
lease_secs = 3600
[[network.dhcp.static]]
mac = "52:54:00:00:00:05"
ip = "10.10.0.10"
hostname = "nas"

[[network]]
name = "guest"
vlan = 20
ipv4 = "10.20.0.1/24"
zone = "guest"

[[network]]
name = "iot"
ports = ["lan0"]
vlan = 30
ipv4 = "10.30.0.1/24"
zone = "iot"
[network.dhcp]
enabled = false

[[zone]]
name = "guest"
input = "drop"
allow = ["dhcp", "dns", "ping"]

[[zone]]
name = "iot"
input = "reject"
allow = ["dhcp", "dns"]
forward_to = []

[[firewall.rule]]
name = "printer"
from = "guest"
to = "lan"
proto = "tcp"
dst = "10.10.0.20"
dst_port = 9100
action = "accept"

[[firewall.rule]]
name = "no-ssh"
from = "any"
to = "router"
proto = "tcp"
dst_port = "22"
action = "reject"
enabled = false

[[firewall.forward]]
name = "nas-https"
wan_port = 8443
to = "10.10.0.10:443"
src = "198.51.100.0/24"

[[firewall.forward]]
name = "games"
proto = "tcp+udp"
wan_port = "27000-27010"
to = "10.10.0.30"
hairpin = false

[[firewall.redirect]]
name = "ntp"
from = "any"
dst_port = 123
to = "10.10.0.10"

[dns]
domain = "home"
[[dns.host]]
name = "router"
ip = "10.10.0.1"
"#;

#[test]
fn v2_document_parses_and_round_trips() {
    let c = parse(FULL_V2).unwrap();
    assert_eq!(c.networks.len(), 3);
    let g = c.network("guest").unwrap();
    assert_eq!((g.vlan, g.zone.as_str(), g.ports.clone()), (20, "guest", vec![String::from("lan0")]));
    assert!(c.network("iot").is_some_and(|n| !n.dhcp.enabled));
    assert_eq!(c.zone("guest").unwrap().allow, [Service::Dhcp, Service::Dns, Service::Ping]);
    assert_eq!(c.zone("iot").unwrap().forward_to, Vec::<String>::new());
    assert_eq!(c.zone("lan"), Some(Zone::builtin_lan()), "built in");
    assert_eq!(c.zone("wan"), Some(Zone::builtin_wan()));
    let r = &c.firewall.rules;
    assert_eq!(r[0].dst_port, Some(PortRange::one(9100)), "integer port");
    assert_eq!(r[0].dst, Some(AnyNet::V4(Net(Cidr::new(ip(10, 10, 0, 20), 32)))));
    assert!(!r[1].enabled);
    let f = &c.firewall.forwards;
    assert_eq!((f[0].proto, f[0].wan_port, f[0].to), (Proto::Tcp, PortRange::one(8443), Target { ip: ip(10, 10, 0, 10), port: Some(443) }));
    assert_eq!((f[1].proto, f[1].wan_port.span(), f[1].hairpin), (Proto::TcpUdp, 10, false));
    let rd = &c.firewall.redirects[0];
    assert_eq!((rd.from.as_str(), rd.proto, rd.dst_port, rd.to), ("any", Proto::Udp, PortRange::one(123), Target { ip: ip(10, 10, 0, 10), port: None }), "UDP by default");
    assert_eq!(c.dns.domain, "home");

    let text = c.to_toml();
    assert!(text.starts_with("version = 2"), "{text}");
    assert_eq!(parse(&text).unwrap(), c, "{text}");
    assert_eq!(parse_json(&c.to_json()).unwrap(), c);
    // Defaults stay out of the canonical form.
    for absent in ["enabled = true", "hairpin = true", "proto = \"any\"", "proto = \"udp\"", "vlan = 0"] {
        assert!(!text.contains(absent), "{absent} in {text}");
    }
}

#[test]
fn always_written_as_version_2() {
    for c in [Config::default(), parse(FULL).unwrap()] {
        let t = c.to_toml();
        assert!(t.starts_with("version = 2") && t.contains("[[network]]"), "{t}");
        assert_eq!(parse(&t), Ok(c));
    }
    assert!(Config::default().unsupported().is_empty());
}

fn with_v2(f: impl FnOnce(&mut Config)) -> Vec<String> {
    let mut c = parse(FULL_V2).unwrap();
    f(&mut c);
    match c.validate() {
        Ok(()) => Vec::new(),
        Err(v) => v.into_iter().map(|i| i.path).collect(),
    }
}

#[test]
fn network_checks() {
    assert!(with_v2(|_| {}).is_empty());
    assert_eq!(with_v2(|c| c.networks[1].name = "lan".into()), ["network[1].name"]);
    assert_eq!(with_v2(|c| c.networks[1].name = "wan".into()), ["network.wan.name"]);
    assert_eq!(with_v2(|c| c.networks[1].name = "Guest_1".into()), ["network[1].name"]);
    assert_eq!(with_v2(|c| c.networks.clear())[0], "network");
    assert_eq!(with_v2(|c| c.networks[1].ipv4 = Cidr::new(ip(10, 10, 0, 129), 25)), ["network.guest.ipv4"]);
    assert_eq!(with_v2(|c| c.networks[2].vlan = 20), ["network.iot.ports[0]"]);
    assert_eq!(with_v2(|c| c.networks[1].vlan = 0), ["network.guest.ports[0]"], "two untagged on lan0");
    assert_eq!(with_v2(|c| c.networks[1].vlan = 4095), ["network.guest.vlan"]);
    assert_eq!(with_v2(|c| c.networks[1].ports = vec!["wan0".into()]), ["network.guest.ports[0]"]);
    assert_eq!(with_v2(|c| c.networks[1].ports = vec!["lan1".into(), "lan1".into()]), ["network.guest.ports[1]"]);
    assert_eq!(with_v2(|c| c.networks[1].ports.clear()), ["network.guest.ports"]);
    assert_eq!(with_v2(|c| c.networks[1].zone = "nosuch".into()), ["network.guest.zone"]);
    assert_eq!(with_v2(|c| c.networks[1].zone = "wan".into()), ["network.guest.zone"]);
    // The same MAC reserved in two networks.
    assert_eq!(
        with_v2(|c| {
            let mut s = c.networks[0].dhcp.statics[0].clone();
            s.ip = ip(10, 20, 0, 5);
            c.networks[1].dhcp.statics.push(s);
        }),
        ["network.guest.dhcp.static[0].mac"]
    );
    // Another port, the same VLAN: fine (separate segments).
    assert!(with_v2(|c| c.networks[2].ports = vec!["lan1".into()]).is_empty());
    // A static WAN may not overlap a network.
    assert_eq!(
        with_v2(|c| {
            c.wan.mode = WanMode::Static;
            c.wan.static_ip = Some(WanStatic { ipv4: Cidr::new(ip(10, 20, 0, 77), 30), gateway: ip(10, 20, 0, 78), dns: vec![] });
        }),
        ["wan.static.ipv4"]
    );
    assert_eq!(
        with_v2(|c| {
            c.wan.mode = WanMode::Static;
            c.wan.static_ip = Some(WanStatic { ipv4: Cidr::new(ip(203, 0, 113, 2), 30), gateway: ip(203, 0, 113, 3), dns: vec![] });
        }),
        ["wan.static.gateway"],
        "the broadcast address"
    );
}

#[test]
fn zone_rule_and_forward_checks() {
    assert!(with_v2(|c| c.zones.push(Zone { name: "lan".into(), input: Policy::Drop, allow: vec![Service::Mgmt], forward_to: vec!["wan".into()] })).is_empty(), "lan may be redefined");
    assert_eq!(with_v2(|c| c.zones[0].name = "visitors".into()), ["network.guest.zone", "firewall.rule.printer.from"], "references follow names");
    assert!(with_v2(|c| c.zones[0].name = "wan".into()).contains(&"zone.wan.name".into()));
    assert_eq!(with_v2(|c| c.zones[1].forward_to = vec!["iot".into()]), ["zone.iot.forward_to[0]"]);
    assert_eq!(with_v2(|c| c.zones[1].forward_to = vec!["nosuch".into()]), ["zone.iot.forward_to[0]"]);
    assert_eq!(with_v2(|c| c.zones[1].forward_to = vec!["wan".into(), "wan".into()]), ["zone.iot.forward_to[1]"]);
    assert_eq!(with_v2(|c| c.zones[0].input = Policy::Accept), ["zone.guest.allow"]);
    assert_eq!(with_v2(|c| c.zones[0].allow.push(Service::Dns)), ["zone.guest.allow[3]"]);

    assert_eq!(with_v2(|c| c.firewall.rules[0].from = "router".into()), ["firewall.rule.printer.from"]);
    assert_eq!(with_v2(|c| c.firewall.rules[0].to = "nosuch".into()), ["firewall.rule.printer.to"]);
    assert_eq!(with_v2(|c| c.firewall.rules[0].proto = Proto::Icmp), ["firewall.rule.printer.dst_port"]);
    assert_eq!(with_v2(|c| c.firewall.rules[0].src = Some("10.20.0.5/24".parse().unwrap())), ["firewall.rule.printer.src"]);
    assert_eq!(with_v2(|c| c.firewall.rules[1].name = "printer".into()), ["firewall.rule[1].name"]);
    // IPv6 rules (docs/ipv6.md step 5b).
    let v6 = |s: &str| -> Option<AnyNet> { Some(s.parse().unwrap()) };
    assert!(with_v2(|c| { c.firewall.rules[0].src = None; c.firewall.rules[0].dst = v6("2001:db8:100::/56") }).is_empty());
    assert!(with_v2(|c| { c.firewall.rules[0].dst = None; c.firewall.rules[0].dst_iid = Some("::5054:ff:fe00:10".parse().unwrap()) }).is_empty());
    assert_eq!(with_v2(|c| { c.firewall.rules[0].src = None; c.firewall.rules[0].dst = v6("2001:db8:100::5/56") }), ["firewall.rule.printer.dst"], "host bits");
    assert_eq!(with_v2(|c| { c.firewall.rules[0].src = v6("2001:db8::/32"); c.firewall.rules[0].dst = v6("10.10.0.20") }), ["firewall.rule.printer.dst"], "two families");
    assert_eq!(with_v2(|c| { c.firewall.rules[0].dst = None; c.firewall.rules[0].dst_iid = Some("2001:db8::10".parse().unwrap()) }), ["firewall.rule.printer.dst_iid"], "prefix bits");
    assert_eq!(with_v2(|c| { c.firewall.rules[0].dst = None; c.firewall.rules[0].dst_iid = Some("::".parse().unwrap()) }), ["firewall.rule.printer.dst_iid"], "zero");

    let fw = |f: fn(&mut Forward)| with_v2(move |c| f(&mut c.firewall.forwards[0]));
    assert_eq!(fw(|f| f.to.ip = ip(192, 0, 2, 1)), ["firewall.forward.nas-https.to"]);
    assert_eq!(fw(|f| f.to.ip = ip(10, 10, 0, 1)), ["firewall.forward.nas-https.to"], "the router");
    assert_eq!(fw(|f| f.proto = Proto::Icmp), ["firewall.forward.nas-https.proto"]);
    assert_eq!(fw(|f| f.wan_port = PortRange { lo: 27005, hi: 27005 }), ["firewall.forward.games.wan_port"]);
    assert!(fw(|f| { f.proto = Proto::Udp; f.wan_port = PortRange::one(8443) }).is_empty());
    assert_eq!(fw(|f| { f.wan_port = PortRange { lo: 8443, hi: 8450 }; f.to.port = Some(65533); }), ["firewall.forward.nas-https.to"]);
    assert_eq!(fw(|f| f.wan_port = PortRange { lo: 59_990, hi: 60_010 }), ["firewall.forward.nas-https.wan_port"], "the router's ports");
    assert!(fw(|f| f.wan_port = PortRange::one(51_820)).is_empty(), "WireGuard's port is fine");
    assert_eq!(
        with_v2(|c| {
            c.mgmt.on_wan = true;
            c.firewall.forwards[0].wan_port = PortRange { lo: 1, hi: 1024 };
        }),
        ["firewall.forward.nas-https.wan_port"]
    );
    assert!(parse(&FULL_V2.replace("wan_port = 8443", "wan_port = 0")).is_err());
    assert!(parse(&FULL_V2.replace("wan_port = 8443", "wan_port = \"9-8\"")).is_err());
    assert_eq!(with_v2(|c| c.dns.hosts[0].name = "bad name".into()), ["dns.host[0].name"]);
}

#[test]
fn redirect_checks() {
    let rd = |f: fn(&mut Config)| with_v2(f);
    fn ntp(c: &mut Config) -> &mut Redirect {
        &mut c.firewall.redirects[0]
    }
    assert_eq!(rd(|c| ntp(c).from = "wan".into()), ["firewall.redirect.ntp.from"], "not from the WAN");
    assert_eq!(rd(|c| ntp(c).from = "nosuch".into()), ["firewall.redirect.ntp.from"]);
    assert!(rd(|c| ntp(c).from = "guest".into()).is_empty());
    assert!(rd(|c| ntp(c).from = "lan".into()).is_empty(), "the built-in lan zone");
    assert_eq!(rd(|c| ntp(c).proto = Proto::Icmp), ["firewall.redirect.ntp.proto"]);
    assert_eq!(rd(|c| ntp(c).to.ip = ip(192, 0, 2, 1)), ["firewall.redirect.ntp.to"], "outside the networks");
    assert_eq!(rd(|c| ntp(c).to.ip = ip(10, 10, 0, 1)), ["firewall.redirect.ntp.to"], "the router");
    assert_eq!(rd(|c| { ntp(c).dst_port = PortRange { lo: 100, hi: 200 }; ntp(c).to.port = Some(65500) }), ["firewall.redirect.ntp.to"]);
    assert!(rd(|c| ntp(c).to.port = Some(1123)).is_empty());
    // Overlaps: same port from zones that meet.
    let second = |from: &str, proto: Proto| {
        let from = String::from(from);
        with_v2(move |c| {
            let mut r = c.firewall.redirects[0].clone();
            r.name = "ntp2".into();
            r.from = from;
            r.proto = proto;
            c.firewall.redirects.push(r);
        })
    };
    assert_eq!(second("any", Proto::Udp), ["firewall.redirect.ntp2.dst_port"]);
    assert_eq!(second("guest", Proto::TcpUdp), ["firewall.redirect.ntp2.dst_port"], "any covers guest");
    assert!(second("guest", Proto::Tcp).is_empty(), "another protocol");
    assert_eq!(rd(|c| { let r = c.firewall.redirects[0].clone(); c.firewall.redirects.push(r) }), ["firewall.redirect[1].name", "firewall.redirect[1].dst_port"]);
    assert!(parse(&FULL_V2.replace("dst_port = 123\n", "")).is_err(), "dst_port is required");
}

#[test]
fn firewall_entries_with_builtin_zones() {
    // The built-in zones only, but a port forward, redirect or rule.
    for entry in [
        "[[firewall.forward]]\nname = \"web\"\nwan_port = 8080\nto = \"192.168.1.10:80\"\n",
        "[[firewall.redirect]]\nname = \"ntp\"\nfrom = \"any\"\ndst_port = 123\nto = \"192.168.1.10\"\n",
        "[[firewall.rule]]\nname = \"ssh\"\nfrom = \"lan\"\nto = \"router\"\naction = \"drop\"\n",
    ] {
        let c = parse(&alloc::format!("version = 2\n{entry}")).unwrap();
        assert_eq!(c.validate(), Ok(()));
        let text = c.to_toml();
        assert_eq!(parse(&text).unwrap(), c, "kept: {text}");
    }
}

#[test]
fn trials_in_version_2() {
    let old = parse(FULL_V2).unwrap();
    let t = |f: fn(&mut Config)| {
        let mut c = old.clone();
        f(&mut c);
        c.needs_trial(&old)
    };
    assert!(!t(|_| {}));
    // Networks the user cannot be on (zones without mgmt) change freely.
    assert!(!t(|c| c.networks[1].vlan = 21));
    assert!(!t(|c| c.networks.pop().map(drop).unwrap_or(())));
    assert!(!t(|c| c.firewall.forwards.clear()));
    assert!(!t(|c| c.firewall.rules[0].dst_port = Some(PortRange::one(631))));
    assert!(!t(|c| {
        let mut n = c.networks[1].clone();
        n.name = "lab".into();
        n.vlan = 40;
        n.ipv4 = Cidr::new(ip(10, 40, 0, 1), 24);
        n.zone = "lan".into();
        c.networks.push(n);
    }), "a new network");
    // The management network, its zone and rules to the router do not.
    assert!(t(|c| c.networks[0].vlan = 10));
    assert!(t(|c| c.networks[0].zone = "guest".into()));
    assert!(t(|c| c.networks.remove(0).name.clear()));
    assert!(t(|c| c.zones.push(Zone { name: "lan".into(), input: Policy::Drop, allow: vec![Service::Dns], forward_to: vec!["wan".into()] })));
    assert!(t(|c| c.firewall.rules[1].enabled = true));
    // A zone opened to the web interface: its networks count from then on.
    let mut open = old.clone();
    open.zones[0].allow.push(Service::Mgmt);
    let mut moved = open.clone();
    moved.networks[1].vlan = 21;
    assert!(moved.needs_trial(&open));
}

#[test]
fn cli_edits_list_entries_by_name() {
    let c = Config::default();
    let g = c
        .with_assignment(r#"network.guest = { ipv4 = "10.20.0.1/24", vlan = 20, zone = "lan" }"#)
        .unwrap();
    assert_eq!(g.networks.iter().map(|n| n.name.as_str()).collect::<Vec<_>>(), ["lan", "guest"]);
    assert_eq!(g.network("guest").unwrap().ports, ["lan0"], "defaults filled in");
    assert_eq!(g.validate(), Ok(()));
    let g2 = g.with_assignment("network.guest.vlan = 30").unwrap();
    assert_eq!(g2.network("guest").unwrap().vlan, 30);
    assert!(diff_lines(&g, &g2).contains(&"+ network.guest.vlan = 30".to_string()));
    // Entries keep their order; new ones go last.
    let z = g2
        .with_assignment(r#"network.aaa = { ipv4 = "10.50.0.1/24", vlan = 50 }"#)
        .unwrap();
    assert_eq!(z.networks.iter().map(|n| n.name.as_str()).collect::<Vec<_>>(), ["lan", "guest", "aaa"]);
    // lan.… is the first network, lan.domain is dns.domain.
    let l = z.with_assignment(r#"lan.ipv4 = "10.9.0.1/24""#).unwrap();
    assert_eq!(l.networks[0].ipv4, Cidr::new(ip(10, 9, 0, 1), 24));
    let d = l.with_assignment(r#"lan.domain = "home""#).unwrap();
    assert_eq!(d.dns.domain, "home");
    assert_eq!(d.without("lan.domain").unwrap().dns.domain, "lan");
    assert!(l.with_assignment("lan = 5").is_err());
    // Unset: entries go, fields return to their type's default.
    assert_eq!(g2.without("network.guest.vlan").unwrap().network("guest").unwrap().vlan, 0);
    assert_eq!(g2.without("network.guest").unwrap(), c);
    assert!(g2.without("network.nosuch").is_err());
    assert!(g2.without("network.nosuch.vlan").is_err());
    assert!(g2.without("network.guest.nosuch").is_err());
    assert!(c.without("lan").is_err());
    // Rules: required fields, order.
    let r = c
        .with_assignment(r#"firewall.rule.b = { from = "lan", to = "router", action = "drop" }"#)
        .unwrap()
        .with_assignment(r#"firewall.rule.a = { from = "lan", to = "router", proto = "tcp", dst_port = 22, action = "accept" }"#)
        .unwrap();
    assert_eq!(r.firewall.rules.iter().map(|x| x.name.as_str()).collect::<Vec<_>>(), ["b", "a"]);
    assert_eq!(r.without("firewall.rule.a.dst_port").unwrap().firewall.rules[1].dst_port, None);
    assert!(matches!(c.with_assignment(r#"firewall.rule.x = { from = "lan" }"#), Err(Error::Syntax(_))), "missing fields");
    assert_eq!(r.without("firewall").unwrap(), c);
    // Redirects: keyed by name, UDP by default.
    let d = c
        .with_assignment(r#"firewall.redirect.ntp = { from = "any", dst_port = 123, to = "192.168.1.10" }"#)
        .unwrap();
    assert_eq!(d.validate(), Ok(()));
    assert_eq!(d.firewall.redirects[0].proto, Proto::Udp);
    let d2 = d.with_assignment(r#"firewall.redirect.ntp.proto = "tcp+udp""#).unwrap();
    assert_eq!(d2.without("firewall.redirect.ntp.proto").unwrap(), d);
    assert!(diff_lines(&c, &d).contains(&"+ firewall.redirect.ntp.dst_port = \"123\"".to_string()), "{:?}", diff_lines(&c, &d));
    assert_eq!(d.without("firewall.redirect.ntp").unwrap(), c);
    assert_eq!(c.without("zone").unwrap(), c);
}

#[test]
fn v2_value_types() {
    assert_eq!("8000-8100".parse::<PortRange>(), Ok(PortRange { lo: 8000, hi: 8100 }));
    assert_eq!(PortRange { lo: 8000, hi: 8100 }.to_string(), "8000-8100");
    assert_eq!(PortRange::one(22).to_string(), "22");
    for bad in ["0", "65536", "9-8", "a", "1-", ""] {
        assert!(bad.parse::<PortRange>().is_err(), "{bad}");
    }
    assert_eq!("10.0.0.1:443".parse::<Target>().unwrap().to_string(), "10.0.0.1:443");
    assert_eq!("10.0.0.1".parse::<Target>().unwrap().port, None);
    assert!("10.0.0.1:0".parse::<Target>().is_err());
    assert_eq!("10.0.0.1".parse::<Net>().unwrap().to_string(), "10.0.0.1");
    assert_eq!("10.0.0.0/8".parse::<Net>().unwrap().to_string(), "10.0.0.0/8");
    assert!(!"10.0.0.1/8".parse::<Net>().unwrap().is_network());
    assert!(Proto::TcpUdp.overlaps(&Proto::Udp) && !Proto::Tcp.overlaps(&Proto::Udp));
}

#[test]
fn what_the_kernel_supports() {
    // Networks on lan0, VLANs, zones, DHCP off: supported.
    let c = parse(FULL_V2).unwrap();
    assert_eq!(c.unsupported(), vec![]);
    // Routed LAN ports are in; a bridge and unknown port names are not.
    let mut d = c.clone();
    d.networks[1].ports = vec!["lan1".into()];
    assert_eq!(d.unsupported(), vec![]);
    d.networks[1].ports = vec!["lan2".into()];
    assert_eq!(d.unsupported(), vec![]);
    d.networks[1].ports = vec!["lan3".into()];
    assert_eq!(d.unsupported()[0].path, "network.guest.ports");
    d.networks[1].ports = vec!["lan1".into(), "lan2".into()];
    assert_eq!(d.unsupported()[0].path, "network.guest.ports");
    assert!(d.unsupported()[0].msg.contains("bridge"), "{:?}", d.unsupported());
    let mut s = c.clone();
    s.wan.mode = WanMode::Static;
    s.wan.static_ip = Some(WanStatic { ipv4: Cidr::new(ip(203, 0, 113, 50), 24), gateway: ip(203, 0, 113, 1), dns: vec![] });
    assert_eq!(s.unsupported(), vec![]);
    assert!(s.validate().is_ok(), "{:?}", s.validate());
}

#[test]
fn only_bridges_reboot() {
    let old = parse(FULL_V2).unwrap();
    let r = |f: fn(&mut Config)| {
        let mut c = old.clone();
        f(&mut c);
        c.needs_reboot(&old)
    };
    assert!(!r(|_| {}));
    assert!(!r(|c| c.networks[1].dhcp.lease_secs = 600), "DHCP: live");
    assert!(!r(|c| c.zones[0].allow.push(Service::Ntp)), "zone policy: live");
    assert!(!r(|c| c.zones[1].forward_to = vec!["wan".into()]));
    assert!(!r(|c| c.dns.cache_entries = 100));
    // Networks and zones change live now (docs/config-v2.md §7).
    assert!(!r(|c| c.networks[1].vlan = 21));
    assert!(!r(|c| c.networks[1].ipv4.prefix = 16));
    assert!(!r(|c| c.networks[1].zone = "lan".into()));
    assert!(!r(|c| { c.networks.pop(); }));
    assert!(!r(|c| c.zones.push(Zone { name: "lab".into(), ..Zone::builtin_lan() })));
    // Another port: live too (every NIC is up from boot); a bridge would
    // be built at boot.
    assert!(!r(|c| c.networks[1].ports = vec!["lan1".into()]));
    assert!(r(|c| c.networks[1].ports = vec!["lan1".into(), "lan2".into()]));
}

#[test]
fn management_password_is_hashed_and_secret() {
    let mut pool = auth::Pool::new(b"t");
    let mut c = Config::default().with_assignment(r#"mgmt.password = "correct horse""#).unwrap();
    assert_eq!(c.validate(), Ok(()));
    assert!(c.hash_new_password(&mut pool));
    assert!(c.mgmt.password.is_none());
    let h = c.mgmt.password_hash.clone().unwrap();
    assert!(auth::verify("correct horse", &h));
    // Stored, never shown.
    let t = c.to_toml();
    assert!(t.contains("password_hash") && !t.contains("correct horse"), "{t}");
    assert_eq!(parse(&t).unwrap(), c);
    let shown = c.without_secrets();
    for text in [shown.to_toml(), shown.to_json(), flat_lines(&shown).join("\n")] {
        assert!(!text.contains("pbkdf2") && !text.contains("correct horse"), "{text}");
    }
    // A form save without it keeps it; another one replaces it; "" removes it.
    let mut back = parse_json(&shown.to_json()).unwrap();
    back.keep_secrets(&c);
    assert_eq!(back.mgmt.password_hash, c.mgmt.password_hash);
    assert!(!back.hash_new_password(&mut pool));
    let mut cleared = parse_json(r#"{"mgmt":{"password_hash":""}}"#).unwrap();
    cleared.keep_secrets(&c);
    cleared.hash_new_password(&mut pool);
    assert_eq!(cleared.mgmt.password_hash, None);
    // A password change is not a trial (on_wan still is).
    assert!(!c.needs_trial(&Config::default()));
    assert!(c.unsupported().is_empty(), "the kernel supports it");
    // Validation.
    assert_eq!(invalid(|c| c.mgmt.password = Some("short".into())), ["mgmt.password"]);
    assert_eq!(paths(parse("version = 2\n[mgmt]\npassword_hash = \"plain\"\n").unwrap_err()), ["mgmt.password_hash"]);
    assert_eq!(c.without("mgmt.password_hash").unwrap().mgmt.password_hash, None);
}

// ---- mDNS ------------------------------------------------------------------

const MDNS: &str = r#"
[[mdns.reflect]]
name = "iot-to-lan"
from = "iot"
to = ["lan", "guest"]
services = ["_ipp._tcp", "_AirPlay._tcp"]
"#;

/// FULL_V2 with the zones allowing mDNS and [`MDNS`] added.
fn with_mdns() -> Config {
    let text = FULL_V2.replace(r#"allow = ["dhcp", "dns", "ping"]"#, r#"allow = ["dhcp", "dns", "ping", "mdns"]"#)
        .replace(r#"allow = ["dhcp", "dns"]"#, r#"allow = ["dhcp", "dns", "mdns"]"#);
    parse(&(text + MDNS)).unwrap()
}

fn mdns_issues(f: impl FnOnce(&mut Config)) -> Vec<String> {
    let mut c = with_mdns();
    f(&mut c);
    match c.validate() {
        Ok(()) => Vec::new(),
        Err(v) => v.into_iter().map(|i| i.path).collect(),
    }
}

#[test]
fn mdns_parses_and_round_trips() {
    let c = with_mdns();
    let r = &c.mdns.reflect[0];
    assert_eq!((r.name.as_str(), r.from.as_str(), r.enabled), ("iot-to-lan", "iot", true));
    assert_eq!(r.to, ["lan", "guest"]);
    assert_eq!(c.zone("iot").unwrap().allow, [Service::Dhcp, Service::Dns, Service::Mdns]);
    assert_eq!(parse(&c.to_toml()).unwrap(), c);
    assert_eq!(parse_json(&c.to_json()).unwrap(), c);
    // Not written when empty.
    assert!(!Config::default().to_toml().contains("mdns"));
    assert!(parse("version = 2\n[mdns]\nreflector = true\n").is_err(), "unknown field");
}

#[test]
fn mdns_checks() {
    assert!(mdns_issues(|_| {}).is_empty());
    assert_eq!(mdns_issues(|c| c.mdns.reflect[0].from = "dmz".into()), ["mdns.reflect.iot-to-lan.from"]);
    assert_eq!(mdns_issues(|c| c.mdns.reflect[0].to.push("nope".into())), ["mdns.reflect.iot-to-lan.to[2]"]);
    assert_eq!(mdns_issues(|c| c.mdns.reflect[0].to.push("iot".into())), ["mdns.reflect.iot-to-lan.to[2]"], "to itself");
    assert_eq!(mdns_issues(|c| c.mdns.reflect[0].to.push("lan".into())), ["mdns.reflect.iot-to-lan.to[2]"], "twice");
    assert_eq!(mdns_issues(|c| c.mdns.reflect[0].to.clear()), ["mdns.reflect.iot-to-lan.to"]);
    assert_eq!(mdns_issues(|c| c.mdns.reflect[0].services.clear()), ["mdns.reflect.iot-to-lan.services"]);
    for bad in ["ipp._tcp", "_ipp", "_ipp._sctp", "_ipp._tcp.local", "_x y._tcp"] {
        assert_eq!(mdns_issues(|c| c.mdns.reflect[0].services.push(bad.into())), ["mdns.reflect.iot-to-lan.services[2]"], "{bad}");
    }
    assert_eq!(mdns_issues(|c| c.mdns.reflect[0].services.push("_IPP._TCP".into())), ["mdns.reflect.iot-to-lan.services[2]"], "twice, any case");
    // Names: keys, unique.
    assert_eq!(mdns_issues(|c| c.mdns.reflect[0].name = "Bad Name".into()), ["mdns.reflect[0].name"]);
    assert_eq!(
        mdns_issues(|c| c.mdns.reflect.push(c.mdns.reflect[0].clone())),
        ["mdns.reflect[1].name"]
    );
    assert_eq!(mdns_issues(|c| {
        let e = c.mdns.reflect[0].clone();
        c.mdns.reflect = (0..33).map(|i| MdnsReflect { name: alloc::format!("r{i}"), ..e.clone() }).collect();
    }), ["mdns.reflect"]);
}

#[test]
fn mdns_needs_the_zones_to_allow_it() {
    // The iot zone (input = reject) without "mdns": the source is refused.
    let issues = mdns_issues(|c| c.zones.iter_mut().find(|z| z.name == "iot").unwrap().allow.retain(|s| *s != Service::Mdns));
    assert_eq!(issues, ["mdns.reflect.iot-to-lan.from"]);
    // Guest (input = drop) without it: that target is refused.
    let issues = mdns_issues(|c| c.zones.iter_mut().find(|z| z.name == "guest").unwrap().allow.retain(|s| *s != Service::Mdns));
    assert_eq!(issues, ["mdns.reflect.iot-to-lan.to[1]"]);
    // The built-in lan zone accepts everything; redefined as drop it needs it.
    let issues = mdns_issues(|c| c.zones.push(Zone { name: "lan".into(), input: Policy::Drop, allow: vec![Service::Mgmt], forward_to: vec!["wan".into()] }));
    assert_eq!(issues, ["mdns.reflect.iot-to-lan.to[0]"]);
    // Message names the zone and where to fix it.
    let mut c = with_mdns();
    c.zones[0].allow.retain(|s| *s != Service::Mdns);
    let e = c.validate().unwrap_err();
    assert!(e[0].msg.contains("zone \"guest\" must allow \"mdns\""), "{}", e[0].msg);
}

#[test]
fn mdns_too_many_service_types() {
    let issues = mdns_issues(|c| {
        c.mdns.reflect[0].services = (0..proto_mdns::MAX_SERVICES + 1).map(|i| alloc::format!("_s{i}._tcp")).collect();
    });
    assert_eq!(issues, ["mdns.reflect"]);
    // Disabled entries do not count.
    let issues = mdns_issues(|c| {
        c.mdns.reflect[0].services = (0..proto_mdns::MAX_SERVICES + 1).map(|i| alloc::format!("_s{i}._tcp")).collect();
        c.mdns.reflect[0].enabled = false;
    });
    assert!(issues.is_empty());
}

#[test]
fn mdns_is_supported() {
    let mut c = with_mdns();
    c.dns.hosts.clear();
    assert!(c.unsupported().is_empty());
}

#[test]
fn mdns_cli_paths() {
    let c = with_mdns();
    let d = c.with_assignment(r#"mdns.reflect.iot-to-lan.services = ["_ipp._tcp"]"#).unwrap();
    assert_eq!(d.mdns.reflect[0].services, ["_ipp._tcp"]);
    let d = d.with_assignment(r#"mdns.reflect.cast = { from = "guest", to = ["lan"], services = ["_googlecast._tcp"] }"#).unwrap();
    assert_eq!(d.mdns.reflect.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(), ["iot-to-lan", "cast"]);
    assert!(diff_lines(&c, &d).iter().any(|l| l.contains("mdns.reflect.cast")), "{:?}", diff_lines(&c, &d));
    let e = d.without("mdns.reflect.iot-to-lan").unwrap();
    assert_eq!(e.mdns.reflect.len(), 1);
    assert!(e.without("mdns").unwrap().mdns.is_empty());
    assert!(c.with_assignment(r#"mdns.reflect.iot-to-lan.to = ["dmz"]"#).unwrap().validate().is_err(), "checked on save");
}

// ---- per-network DNS domain ------------------------------------------------

#[test]
fn network_domain() {
    let text = FULL_V2.replace("zone = \"guest\"\n\n[[network]]", "zone = \"guest\"\ndomain = \"guest.home\"\n\n[[network]]");
    let c = parse(&text).unwrap();
    assert_eq!(c.networks[0].domain, None);
    assert_eq!(c.networks[0].domain(&c.dns), "home", "falls back to dns.domain");
    assert_eq!(c.networks[1].domain.as_deref(), Some("guest.home"));
    assert_eq!(c.networks[1].domain(&c.dns), "guest.home");
    assert_eq!(parse(&c.to_toml()).unwrap(), c);
    assert_eq!(parse_json(&c.to_json()).unwrap(), c);
    // Not written when unset.
    assert!(!Config::default().to_toml().contains("\ndomain = \"lan\"\n[[network"));
    assert!(!parse(FULL_V2).unwrap().to_toml().contains("guest.home"));
    // Validation and editing by path.
    for bad in ["", "a b", "-x.home", "x..home", "x_y"] {
        assert_eq!(invalid(|c| c.networks[0].domain = Some(bad.into())), ["network.lan.domain"], "{bad:?}");
    }
    let d = c.with_assignment(r#"network.iot.domain = "iot.home""#).unwrap();
    assert_eq!(d.networks[2].domain(&d.dns), "iot.home");
    assert_eq!(d.without("network.iot.domain").unwrap().networks[2].domain, None);
}

// ---- DNS views (docs/dns-views.md) ----

/// The home topology (target/apu4/config-home.toml, trimmed): lan sees
/// everything, iot has no forwarding but a rule to Home Assistant,
/// powerstream forwards to the WAN only.
const HOME_VIEWS: &str = r#"
version = 2

[[network]]
name = "lan"
ipv4 = "192.168.1.1/24"

[[network]]
name = "iot"
vlan = 2
ipv4 = "192.168.2.1/24"
zone = "iot"
domain = "iot.home.arpa"

[[network]]
name = "powerstream"
vlan = 3
ipv4 = "192.168.3.1/24"
zone = "powerstream"
domain = "ps.home.arpa"

[[zone]]
name = "lan"
input = "accept"
forward_to = ["wan", "iot", "powerstream"]

[[zone]]
name = "iot"
input = "drop"
allow = ["dhcp", "dns"]
forward_to = []

[[zone]]
name = "powerstream"
input = "drop"
allow = ["dhcp", "dns"]
forward_to = ["wan"]

[[firewall.rule]]
name = "homeassistant"
from = "iot"
to = "lan"
dst = "192.168.1.200"
action = "accept"

[[firewall.rule]]
name = "no-rfc1918-wan-10"
from = "any"
to = "wan"
dst = "10.0.0.0/8"
action = "reject"

[dns]
domain = "home.arpa"
views = "firewall"
"#;

#[test]
fn dns_views_follow_the_firewall_on_the_home_topology() {
    const LAN: u32 = 1;
    const IOT: u32 = 2;
    const PS: u32 = 4;
    let c = parse(HOME_VIEWS).unwrap();
    assert_eq!(c.unsupported(), vec![]);
    let v = c.name_visibility();
    assert_eq!(v.all_networks(), LAN | IOT | PS);
    assert_eq!(v.seen_by(ip(192, 168, 1, 50)), LAN, "a LAN laptop: lan only");
    assert_eq!(v.seen_by(ip(192, 168, 1, 200)), LAN | IOT, "Home Assistant: the iot rule reaches it");
    assert_eq!(v.seen_by(ip(192, 168, 2, 10)), LAN | IOT, "an iot device: lan forwards to iot");
    assert_eq!(v.seen_by(ip(192, 168, 3, 5)), LAN | PS);
    assert_eq!(v.seen_by(ip(8, 8, 8, 8)), LAN | IOT | PS, "outside every network");
    // Controls: views = all; the rule disabled; a drop rule instead.
    let mut all = c.clone();
    all.dns.views = DnsViews::All;
    assert_eq!(all.name_visibility().seen_by(ip(192, 168, 1, 50)), LAN | IOT | PS);
    assert!(!all.to_toml().contains("views"), "the default is not written");
    let mut off = c.clone();
    off.firewall.rules[0].enabled = false;
    assert_eq!(off.name_visibility().seen_by(ip(192, 168, 1, 200)), LAN);
    let mut drop = c.clone();
    drop.firewall.rules[0].action = Action::Drop;
    assert_eq!(drop.name_visibility().seen_by(ip(192, 168, 1, 200)), LAN);
    // A rule without dst opens the whole network; from/to any.
    let mut wide = c.clone();
    wide.firewall.rules[0].dst = None;
    assert_eq!(wide.name_visibility().seen_by(ip(192, 168, 1, 50)), LAN | IOT);
    wide.firewall.rules[0].from = "any".into();
    assert_eq!(wide.name_visibility().seen_by(ip(192, 168, 1, 50)), LAN | IOT | PS);
    let mut to_any = c.clone();
    to_any.firewall.rules[0].to = "any".into();
    assert_eq!(to_any.name_visibility().seen_by(ip(192, 168, 1, 200)), LAN | IOT);
    assert_eq!(to_any.name_visibility().seen_by(ip(192, 168, 3, 200)), LAN | PS, "dst still limits");
    // Rules to the router reach no names.
    let mut router = c.clone();
    router.firewall.rules[0].to = "router".into();
    router.firewall.rules[0].dst = None;
    assert_eq!(router.name_visibility().seen_by(ip(192, 168, 1, 200)), LAN);
    // JSON keeps it.
    assert_eq!(parse_json(&c.to_json()).unwrap(), c);
}

#[test]
fn dns_host_names_resolve_to_a_domain_or_an_override() {
    let mut c = parse(HOME_VIEWS).unwrap();
    let h = |name: &str, nets: &[&str]| DnsHost {
        name: name.into(),
        ip: ip(192, 168, 1, 10),
        networks: nets.iter().map(|n| String::from(*n)).collect(),
    };
    c.dns.hosts = vec![
        h("nas", &[]),
        h("Boiler.IoT.home.arpa", &["iot", "lan"]),
        h("a.b.home.arpa", &[]),
        h("files.example.com", &["lan"]),
    ];
    assert_eq!(c.local_domains(), ["home.arpa", "iot.home.arpa", "ps.home.arpa"]);
    let local = |d: &str, l: &str| HostName::Local { domain: d.into(), label: l.into() };
    let got: Vec<(HostName, Option<u32>)> = c.local_hosts().into_iter().map(|l| (l.name, l.networks)).collect();
    assert_eq!(
        got,
        [
            (local("home.arpa", "nas"), None),
            (local("iot.home.arpa", "boiler"), Some(3)),
            (local("home.arpa", "a.b"), None),
            (HostName::Override("files.example.com".into()), Some(1)),
        ]
    );
    assert_eq!(c.validate(), Ok(()));
    let t = c.to_toml();
    assert!(t.contains("networks = [\"lan\"]") && parse(&t).unwrap() == c);
    assert_eq!(parse_json(&c.to_json()).unwrap(), c);
}

#[test]
fn dns_host_checks() {
    fn check(hosts: &[(&str, &[&str])]) -> Vec<String> {
        let mut c = parse(HOME_VIEWS).unwrap();
        c.networks[0].dhcp.statics.push(StaticLease {
            mac: "52:54:00:00:00:05".parse().unwrap(),
            ip: ip(192, 168, 1, 10),
            hostname: Some("NAS".into()),
        });
        c.dns.hosts = hosts
            .iter()
            .map(|(n, nets)| DnsHost {
                name: (*n).into(),
                ip: ip(192, 168, 1, 11),
                networks: nets.iter().map(|n| String::from(*n)).collect(),
            })
            .collect();
        match c.validate() {
            Ok(()) => Vec::new(),
            Err(v) => v.into_iter().map(|i| i.path).collect(),
        }
    }
    assert_eq!(check(&[("srv", &[]), ("srv", &["lan"])]), ["dns.host[1].name"], "overlap");
    assert_eq!(check(&[("srv", &["lan"]), ("SRV.home.arpa", &["iot", "lan"])]), ["dns.host[1].name"]);
    assert_eq!(check(&[("srv", &["lan"]), ("srv", &["iot"])]), Vec::<String>::new(), "other answer per network");
    assert_eq!(check(&[("srv", &[]), ("srv.iot.home.arpa", &[])]), Vec::<String>::new(), "other domain");
    assert_eq!(check(&[("srv", &["guest"])]), ["dns.host[0].networks[0]"]);
    assert_eq!(check(&[("srv", &["lan", "lan"])]), ["dns.host[0].networks[1]"]);
    assert_eq!(check(&[("example.com", &[])]), ["dns.host[0].networks"], "override needs networks");
    assert_eq!(check(&[("example.com", &["iot"])]), Vec::<String>::new());
    assert_eq!(check(&[("iot.home.arpa", &[])]), ["dns.host[0].name"], "a domain itself");
    assert_eq!(check(&[("1.1.168.192.in-addr.arpa", &["lan"])]), ["dns.host[0].name"]);
    assert_eq!(check(&[("bad name", &[])]), ["dns.host[0].name"]);
    assert_eq!(check(&[("nas", &[])]), ["dns.host[0].name"], "a reservation's hostname for everyone");
    assert_eq!(check(&[("nas", &["iot"])]), Vec::<String>::new(), "for some networks: takes it over");
    assert_eq!(check(&[("router", &[])]), Vec::<String>::new());
}

#[test]
fn dns_views_and_hosts_from_the_cli() {
    let c = parse(HOME_VIEWS).unwrap();
    let c = c.with_assignment(r#"dns.views = "all""#).unwrap();
    assert_eq!(c.dns.views, DnsViews::All);
    let c = c.with_assignment(r#"dns.views = "firewall""#).unwrap();
    assert_eq!(c.dns.views, DnsViews::Firewall);
    assert!(c.with_assignment(r#"dns.views = "some""#).is_err());
    let c = c
        .with_assignment(r#"dns.host = [{ name = "nas", ip = "192.168.1.10", networks = ["lan"] }, { name = "nas", ip = "192.168.2.10", networks = ["iot"] }]"#)
        .unwrap();
    assert_eq!(c.dns.hosts.len(), 2);
    assert_eq!(c.dns.hosts[1].networks, ["iot"]);
    let d = diff_lines(&parse(HOME_VIEWS).unwrap(), &c);
    assert!(d.iter().any(|l| l.starts_with("+ dns.host[1].networks")), "{d:?}");
    // Validation (at `config save`) refuses an overlapping name.
    let overlap = c.with_assignment(r#"dns.host = [{ name = "nas", ip = "192.168.1.10" }, { name = "nas", ip = "192.168.2.10" }]"#).unwrap();
    assert_eq!(overlap.validate().unwrap_err()[0].path, "dns.host[1].name");
    // Unset: back to none.
    assert!(c.without("dns.host").unwrap().dns.hosts.is_empty());
    assert_eq!(c.without("dns.views").unwrap().dns.views, DnsViews::All);
}

fn route(name: &str, dst: &str, via: core::net::Ipv4Addr) -> Route {
    Route { name: name.into(), enabled: true, dst: dst.parse().unwrap(), via: via.into() }
}

#[test]
fn routes_parse_round_trip_and_feed_option_121() {
    let doc = lan_doc(
        "192.168.1.1/24",
        "[[route]]\nname = \"lab\"\ndst = \"10.20.0.0/24\"\nvia = \"192.168.1.2\"\n\n\
         [[route]]\nname = \"vpn\"\nenabled = false\ndst = \"10.30.0.0/16\"\nvia = \"192.168.1.3\"\n\n\
         [[route]]\nname = \"modem\"\ndst = \"192.168.100.1\"\nvia = \"100.64.0.2\"\n",
    );
    let c = parse(&doc).unwrap();
    assert_eq!(c.routes.len(), 3);
    assert_eq!(c.routes[2].v4().unwrap().0.prefix, 32, "an address is a /32");
    assert_eq!(parse(&c.to_toml()).unwrap(), c, "{}", c.to_toml());
    assert!(!c.to_toml().contains("enabled = true"));
    assert_eq!(c.route_via(&c.routes[0]), RouteVia::Network(&c.networks[0]));
    assert_eq!(c.route_via(&c.routes[2]), RouteVia::Wan);
    // Only enabled routes through this network's routers.
    assert_eq!(c.network_routes("lan"), vec![(ip(10, 20, 0, 0), 24, ip(192, 168, 1, 2))]);
    assert_eq!(c.network_routes("nosuch"), vec![]);
    assert_eq!(parse_json(&c.to_json()).unwrap(), c);
    assert!(!Config::default().to_toml().contains("route"));
}

#[test]
fn route_checks() {
    let gw = ip(192, 168, 1, 2);
    let one = |dst: &'static str, via| issues(move |c| c.routes.push(route("r", dst, via)));
    assert!(one("10.20.0.0/24", gw).is_empty());
    assert!(one("10.0.0.0/8", gw).is_empty());
    assert!(one("192.168.0.0/16", gw).is_empty(), "around the LAN: the LAN is the longer match");
    assert_eq!(one("10.20.0.5/24", gw), ["route.r.dst"], "host bits");
    assert_eq!(one("0.0.0.0/0", gw), ["route.r.dst"], "the default route");
    assert_eq!(one("192.168.1.128/25", gw), ["route.r.dst"], "inside the LAN");
    assert_eq!(one("192.168.1.0/24", gw), ["route.r.dst"], "the LAN itself");
    assert_eq!(one("127.0.0.0/8", gw), ["route.r.dst"]);
    assert_eq!(one("224.0.0.0/4", gw), ["route.r.dst"]);
    assert_eq!(one("10.20.0.0/24", ip(192, 168, 1, 1)), ["route.r.via"], "the router itself");
    assert_eq!(one("10.20.0.0/24", ip(192, 168, 1, 255)), ["route.r.via"], "broadcast");
    // Through the WAN (DHCP): anything unicast, not inside dst.
    assert!(one("10.20.0.0/24", ip(100, 64, 0, 2)).is_empty());
    assert_eq!(one("100.64.0.0/10", ip(100, 64, 0, 2)), ["route.r.via"]);
    assert_eq!(one("10.20.0.0/24", ip(127, 0, 0, 1)), ["route.r.via"]);
    assert_eq!(
        issues(|c| {
            c.wan.mode = WanMode::Pppoe;
            c.routes.push(route("r", "10.20.0.0/24", ip(100, 64, 0, 2)));
        }),
        ["route.r.via"],
        "PPPoE has no other routers"
    );
    assert!(
        issues(|c| {
            c.wan.mode = WanMode::Pppoe;
            c.routes.push(route("r", "10.20.0.0/24", gw));
        })
        .is_empty(),
        "a LAN route with PPPoE"
    );
    // Names, duplicates, the limit.
    assert_eq!(
        issues(|c| {
            c.routes.push(route("a", "10.20.0.0/24", gw));
            c.routes.push(route("b", "10.20.0.0/24", ip(192, 168, 1, 3)));
        }),
        ["route.b.dst"]
    );
    assert_eq!(
        issues(|c| {
            c.routes.push(route("a", "10.20.0.0/24", gw));
            c.routes.push(route("a", "10.21.0.0/24", gw));
        }),
        ["route[1].name"]
    );
    assert_eq!(
        issues(|c| {
            for k in 0..=validate::MAX_ROUTES as u8 {
                c.routes.push(route(&alloc::format!("r{k}"), &alloc::format!("10.{k}.0.0/16"), gw));
            }
        }),
        ["route"]
    );
}

#[test]
fn routes_by_name_on_the_cli() {
    let c = Config::default()
        .with_assignment(r#"route.lab = { dst = "10.20.0.0/24", via = "192.168.1.2" }"#)
        .unwrap();
    assert_eq!(c.routes, vec![route("lab", "10.20.0.0/24", ip(192, 168, 1, 2))]);
    let c = c.with_assignment("route.lab.enabled = false").unwrap();
    assert!(!c.routes[0].enabled);
    let c = c.without("route.lab.enabled").unwrap();
    assert!(c.routes[0].enabled);
    assert!(c.with_assignment(r#"route.lab.via = "192.168.1.1""#).unwrap().validate().is_err());
    assert!(c.without("route.lab").unwrap().routes.is_empty());
}

#[test]
fn routed_subnets_belong_to_their_routers_network_in_dns_views() {
    const LAN: u32 = 1;
    let mut c = parse(HOME_VIEWS).unwrap();
    // Behind a router on the iot network: iot's names.
    let iot = c.networks[1].ipv4.host(2);
    c.routes.push(route("behind-iot", "10.40.0.0/16", iot));
    c.routes.push(route("behind-lan", "10.40.1.0/24", ip(192, 168, 1, 2)));
    c.validate().unwrap();
    let v = c.name_visibility();
    assert_eq!(v.seen_by(ip(10, 40, 9, 9)), v.seen_by(c.networks[1].ipv4.host(10)), "as iot");
    assert_eq!(v.seen_by(ip(10, 40, 1, 9)), LAN, "the longer route wins");
    c.routes[0].enabled = false;
    assert_eq!(c.name_visibility().seen_by(ip(10, 40, 9, 9)), LAN | 2 | 4, "a disabled route: outside");
}

/// `shaping.queue_ms` is left out at its default (older kernels refuse
/// unknown fields), written when set, and read back.
#[test]
fn queue_ms_written_only_when_set() {
    let d = Config::default();
    assert!(!d.to_toml().contains("queue_ms"), "{}", d.to_toml());
    let c = parse("[shaping]\nqueue_ms = 50\n").unwrap();
    assert_eq!(c.shaping.queue_ms, 50);
    assert!(c.to_toml().contains("queue_ms = 50"));
    assert_eq!(parse(&c.to_toml()).unwrap().shaping.queue_ms, 50);
}

/// `shaping.ack_filter` likewise: left out while off.
#[test]
fn ack_filter_written_only_when_on() {
    assert!(!Config::default().to_toml().contains("ack_filter"));
    let c = parse("[shaping]\nack_filter = true\n").unwrap();
    assert!(c.shaping.ack_filter);
    assert!(c.to_toml().contains("ack_filter = true"));
    assert!(parse(&c.to_toml()).unwrap().shaping.ack_filter);
}

#[test]
fn ipv6_section_round_trips_and_validates_the_ula() {
    // Off and unset: not written at all.
    assert!(!Config::default().to_toml().contains("[ipv6]"));
    let c = parse(&lan_doc("10.10.0.1/24", "[ipv6]\nenabled = true\nula_prefix = \"fd12:3456:789a::/48\"\n")).unwrap();
    assert!(c.ipv6.enabled);
    assert_eq!(c.ipv6.ula_prefix.unwrap().to_string(), "fd12:3456:789a::/48");
    assert_eq!(parse(&c.to_toml()).unwrap(), c);
    let ula = |s: &str| {
        invalid(|c| {
            c.ipv6.enabled = true;
            c.ipv6.ula_prefix = Some(s.parse().unwrap());
        })
    };
    for bad in ["2001:db8::/48", "fd12:3456:789a::/56", "fd12:3456:789a:1::/48", "fe80::/48"] {
        assert_eq!(ula(bad), vec![String::from("ipv6.ula_prefix")], "{bad}");
    }
    assert!(issues(|c| c.ipv6.ula_prefix = Some("fc00:1:2::/48".parse().unwrap())).is_empty());
    assert!(parse(&lan_doc("10.10.0.1/24", "[ipv6]\nula_prefix = \"fd::/129\"\n")).is_err());
    assert!(parse(&lan_doc("10.10.0.1/24", "[ipv6]\nbogus = 1\n")).is_err());
}

#[test]
fn network_ipv6_switch() {
    let c = parse(&lan_doc("10.10.0.1/24", "")).unwrap();
    assert!(c.networks[0].ipv6);
    assert!(!c.to_toml().contains("ipv6"), "on by default, not written");
    let mut d = c.clone();
    d.networks[0].ipv6 = false;
    let t = d.to_toml();
    assert!(t.contains("ipv6 = false"), "{t}");
    assert_eq!(parse(&t).unwrap(), d);
    // The CLI: by name and `lan.`, unset = back on.
    let off = c.with_assignment("network.lan.ipv6 = false").unwrap();
    assert_eq!(off, d);
    assert_eq!(c.with_assignment("lan.ipv6 = false").unwrap(), d);
    assert_eq!(off.without("network.lan.ipv6").unwrap(), c);
    assert_eq!(c.without("network.lan.ipv6").unwrap(), c, "already on");
}

#[test]
fn ipv6_prefix_delegation_settings() {
    let c = Config::default();
    assert!(c.ipv6.dhcpv6_pd && c.ipv6.prefix_hint == 56);
    let c = parse(&lan_doc("10.10.0.1/24", "[ipv6]\nenabled = true\ndhcpv6_pd = false\nprefix_hint = 60\n")).unwrap();
    assert!(!c.ipv6.dhcpv6_pd);
    assert_eq!(c.ipv6.prefix_hint, 60);
    assert_eq!(parse(&c.to_toml()).unwrap(), c);
    for bad in [47, 65] {
        assert_eq!(invalid(|c| c.ipv6.prefix_hint = bad), vec![String::from("ipv6.prefix_hint")], "{bad}");
    }
    // Defaults are not written out.
    let mut d = Config::default();
    d.ipv6.enabled = true;
    let t = d.to_toml();
    assert!(!t.contains("dhcpv6_pd") && !t.contains("prefix_hint"), "{t}");
}

#[test]
fn ipv6_rule_fields_roundtrip() {
    let t = r#"
[[firewall.rule]]
name = "qbit6"
from = "wan"
to = "lan"
proto = "tcp+udp"
dst_iid = "::5054:ff:fe00:10"
dst_port = 9524
action = "accept"

[[firewall.rule]]
name = "admin6"
from = "wan"
to = "lan"
src = "2001:db8:9::/48"
dst = "2001:db8:100::10"
action = "accept"
"#;
    let c: Config = toml::from_str(&alloc::format!("version = 2\n{t}")).unwrap();
    let r = &c.firewall.rules;
    assert_eq!(r[0].dst_iid, Some("::5054:ff:fe00:10".parse().unwrap()));
    assert_eq!(r[1].src.unwrap().v6().unwrap().prefix, 48);
    assert_eq!(r[1].dst.unwrap().v6().unwrap().prefix, 128, "a bare address is /128");
    let back = toml::to_string(&c).unwrap();
    assert!(back.contains("dst_iid = \"::5054:ff:fe00:10\""), "{back}");
    assert!(back.contains("dst = \"2001:db8:100::10\""), "{back}");
}

#[test]
fn ipv6_upstreams_ntp_and_routes() {
    use core::net::IpAddr;
    // DNS upstreams: [addr]:port#name, a bare address, the name check.
    let u = Upstream::parse("[2606:4700:4700::1111]:853#cloudflare-dns.com").unwrap();
    assert_eq!((u.ip, u.port, u.name.as_deref()), ("2606:4700:4700::1111".parse::<IpAddr>().unwrap(), Some(853), Some("cloudflare-dns.com")));
    assert_eq!(alloc::format!("{u}"), "[2606:4700:4700::1111]:853#cloudflare-dns.com");
    let u = Upstream::parse("2001:4860:4860::8888").unwrap();
    assert_eq!((u.port, alloc::format!("{u}")), (None, String::from("2001:4860:4860::8888")));
    assert!(Upstream::parse("[2606:4700:4700::1111]853").is_err());
    assert!(Upstream::parse("fe80::1").is_err(), "link-local");
    assert!(Upstream::parse("::1").is_err());
    assert!(Upstream::parse("[2606:4700:4700::1111]:853#2606:4700:4700::1111").is_ok(), "an IP certificate name");
    // NTP: IPv6 literals.
    assert!(issues(|c| c.time.ntp_servers = vec!["2001:db8::123".into()]).is_empty());
    // Routes: IPv6 through a host in network 0's unique local /64.
    let r6 = |dst: &str, via: &str| Route { name: "r6".into(), enabled: true, dst: dst.parse().unwrap(), via: via.parse().unwrap() };
    let one = |r: Route| issues(move |c| c.routes.push(r));
    assert!(one(r6("fd00:30::/64", "fd12:3456:789a::5")).is_empty());
    assert!(one(r6("2001:db8:500::/48", "fd12:3456:789a::5")).is_empty());
    assert_eq!(one(r6("fd00:30::5/64", "fd12:3456:789a::5")), ["route.r6.dst"], "host bits");
    assert_eq!(one(r6("::/0", "fd12:3456:789a::5")), ["route.r6.dst"], "default");
    assert_eq!(one(r6("fe80::/64", "fd12:3456:789a::5")), ["route.r6.dst"], "link-local");
    assert_eq!(one(r6("fd00:30::/64", "2001:db8::5")), ["route.r6.via"], "not unique local");
    assert_eq!(one(r6("fd00:30::/64", "fd12:3456:789a:7::5")), ["route.r6.via"], "no network 7");
    assert_eq!(one(r6("fd00:30::/64", "fd12:3456:789a::1")), ["route.r6.via"], "the router");
    assert_eq!(one(r6("fd00:30::/64", "192.168.1.2")), ["route.r6.via"], "mixed families");
    let off = r6("fd00:30::/64", "fd12:3456:789a::5");
    assert_eq!(issues(move |c| {
        c.networks[0].ipv6 = false;
        c.routes.push(off);
    }), ["route.r6.via"], "network with IPv6 off");
    let c = parse(&lan_doc("192.168.1.1/24", "[[route]]\nname = \"r6\"\ndst = \"fd00:30::/64\"\nvia = \"fd12:3456:789a::5\"\n")).unwrap();
    assert!(c.routes[0].v6().is_some() && c.routes[0].v4().is_none());
    assert_eq!(c.route_via(&c.routes[0]), RouteVia::Network(&c.networks[0]));
    assert!(c.network_routes("lan").is_empty(), "no option 121 for IPv6");
    assert_eq!(parse(&c.to_toml()).unwrap(), c);
}
