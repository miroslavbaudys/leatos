use crate::*;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

const FULL: &str = r#"
version = 1

[lan]
ipv4 = "10.10.0.1/24"
domain = "home.lan"

[lan.dhcp]
range = ["10.10.0.50", "10.10.0.150"]
lease_secs = 3600

[[lan.dhcp.static]]
mac = "52:54:00:00:00:05"
ip = "10.10.0.10"
hostname = "nas"

[[lan.dhcp.static]]
mac = "AA:BB:CC:DD:EE:01"
ip = "10.10.0.60"

[dns]
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

fn paths(e: Error) -> Vec<String> {
    match e {
        Error::Invalid(v) => v.into_iter().map(|i| i.path).collect(),
        other => panic!("expected Invalid, got {other:?}"),
    }
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
    let c = parse("[lan]\nipv4 = \"10.0.0.1/16\"\n").unwrap();
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
    let e = parse("[lan]\nipv4 = 10.10.0.1\n").unwrap_err();
    let Error::Syntax(m) = &e else {
        panic!("{e:?}")
    };
    assert!(m.contains("line 2"), "{m}");

    let e = parse(&FULL.replace("domain", "domian")).unwrap_err();
    let m = e.to_string();
    assert!(
        m.contains("unknown field `domian`") && m.contains("line 6"),
        "{m}"
    );

    let e = parse("[lan]\nipv4 = \"10.10.0.1\"\n").unwrap_err();
    assert!(e.to_string().contains("expected a.b.c.d/len"), "{e}");
    let e =
        parse("[[lan.dhcp.static]]\nmac = \"52:54:00:00:05\"\nip = \"192.168.1.5\"\n").unwrap_err();
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
        parse("[[lan.dhcp.static]]\nip = \"192.168.1.5\"\n"),
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
    assert!(parse("[lan]\ndomain = \"home.example-1.lan\"\n").is_ok());
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
    assert_eq!(
        invalid(|c| c.networks[0].dhcp.lease_secs = 59),
        ["network.lan.dhcp.lease_secs"]
    );
    assert_eq!(
        invalid(|c| c.networks[0].dhcp.lease_secs = 31 * 86400),
        ["network.lan.dhcp.lease_secs"]
    );

    // A changed subnet must carry the range along: the derived one does.
    let c = parse("[lan]\nipv4 = \"10.1.2.1/24\"\n").unwrap();
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
    assert_eq!(invalid(|c| c.dns.cache_entries = 0), ["dns.cache_entries"]);
    let c = parse("[shaping]\nqdisc = \"codel\"\nisolation = \"flows\"\n").unwrap();
    assert_eq!(
        (c.shaping.qdisc, c.shaping.isolation),
        (Qdisc::Codel, Isolation::Flows)
    );
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
    assert_eq!(invalid(|c| c.wan.mode = WanMode::Pppoe), ["wan.pppoe.username"]);
    assert_eq!(invalid(|c| {
        pppoe(c);
        c.wan.pppoe.mtu = 1500;
    }), ["wan.pppoe.mtu"]);
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
    // Version 1 JSON (an old export) is migrated like TOML.
    let old = parse_json(r#"{"version":1,"lan":{"ipv4":"10.1.0.1/16","domain":"home"}}"#).unwrap();
    assert_eq!((old.networks[0].ipv4, old.dns.domain.as_str()), (Cidr::new(ip(10, 1, 0, 1), 16), "home"));
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
    assert_eq!(r[0].dst, Some(Net(Cidr::new(ip(10, 10, 0, 20), 32))));
    assert!(!r[1].enabled);
    let f = &c.firewall.forwards;
    assert_eq!((f[0].proto, f[0].wan_port, f[0].to), (Proto::Tcp, PortRange::one(8443), Target { ip: ip(10, 10, 0, 10), port: Some(443) }));
    assert_eq!((f[1].proto, f[1].wan_port.span(), f[1].hairpin), (Proto::TcpUdp, 10, false));
    assert_eq!(c.dns.domain, "home");
    assert!(!c.fits_v1());

    let text = c.to_toml();
    assert!(text.starts_with("version = 2"), "{text}");
    assert_eq!(parse(&text).unwrap(), c, "{text}");
    assert_eq!(parse_json(&c.to_json()).unwrap(), c);
    // Defaults stay out of the canonical form.
    for absent in ["enabled = true", "hairpin = true", "proto = \"any\"", "vlan = 0"] {
        assert!(!text.contains(absent), "{absent} in {text}");
    }
}

#[test]
fn written_as_version_1_while_it_fits() {
    // Kernels that read only version 1 must still find their LAN.
    let mut c = parse(FULL).unwrap();
    c.dns.domain = "home".into();
    let text = c.to_toml();
    assert!(text.starts_with("version = 1") && text.contains("[lan]"), "{text}");
    let old: v1::Config = toml::from_str(&text).unwrap();
    assert_eq!((old.lan.ipv4, old.lan.domain.as_str()), (c.networks[0].ipv4, "home"));
    assert_eq!(parse(&text).unwrap(), c);

    // Each version 2 feature switches to version 2, with the reason.
    type Case = (&'static str, fn(&mut Config));
    let cases: [Case; 7] = [
        ("network", |c| c.networks.push(Network { name: "guest".into(), vlan: 20, ipv4: Cidr::new(ip(10, 20, 0, 1), 24), ..Network::default() })),
        ("network.lan.vlan", |c| c.networks[0].vlan = 5),
        ("network.lan.dhcp.enabled", |c| c.networks[0].dhcp.enabled = false),
        ("zone", |c| c.zones.push(Zone { name: "guest".into(), ..Zone::builtin_lan() })),
        ("dns.host", |c| c.dns.hosts.push(DnsHost { name: "x".into(), ip: ip(10, 0, 0, 1) })),
        ("wan.static", |c| {
            c.wan.mode = WanMode::Static;
            c.wan.static_ip = Some(WanStatic { ipv4: Cidr::new(ip(203, 0, 113, 2), 30), gateway: ip(203, 0, 113, 1), dns: vec![] });
        }),
        ("network.main.name", |c| c.networks[0].name = "main".into()),
    ];
    for (path, f) in cases {
        let mut d = Config::default();
        f(&mut d);
        assert!(!d.fits_v1(), "{path}");
        let t = d.to_toml();
        assert!(t.starts_with("version = 2"), "{path}: {t}");
        assert_eq!(parse(&t), Ok(d), "{path}");
    }
    assert!(Config::default().unsupported().is_empty());
}

#[test]
fn version_1_is_migrated() {
    let c = parse("version = 1\n[lan]\nipv4 = \"10.0.0.1/16\"\ndomain = \"home\"\n").unwrap();
    assert_eq!(c.version, VERSION);
    assert_eq!(
        c.networks,
        vec![Network { ipv4: Cidr::new(ip(10, 0, 0, 1), 16), ..Network::default() }]
    );
    assert_eq!(c.dns.domain, "home");
    // Without a version line, [lan] means version 1; v2 fields are not
    // accepted in a version 1 document and vice versa.
    assert_eq!(parse("[lan]\ndomain = \"x\"\n").unwrap().dns.domain, "x");
    assert!(matches!(parse("version = 1\n[[network]]\nname = \"lan\"\nipv4 = \"10.0.0.1/24\"\n"), Err(Error::Syntax(_))));
    assert!(matches!(parse("version = 2\n[lan]\nipv4 = \"10.0.0.1/24\"\n"), Err(Error::Syntax(_))));
    assert_eq!(v1::Config::default().lan.ipv4, Config::default().networks[0].ipv4);
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

    let fw = |f: fn(&mut Forward)| with_v2(move |c| f(&mut c.firewall.forwards[0]));
    assert_eq!(fw(|f| f.to.ip = ip(192, 0, 2, 1)), ["firewall.forward.nas-https.to"]);
    assert_eq!(fw(|f| f.to.ip = ip(10, 10, 0, 1)), ["firewall.forward.nas-https.to"], "the router");
    assert_eq!(fw(|f| f.proto = Proto::Icmp), ["firewall.forward.nas-https.proto"]);
    assert_eq!(fw(|f| f.wan_port = PortRange { lo: 27005, hi: 27005 }), ["firewall.forward.games.wan_port"]);
    assert!(fw(|f| { f.proto = Proto::Udp; f.wan_port = PortRange::one(8443) }).is_empty());
    assert_eq!(fw(|f| { f.wan_port = PortRange { lo: 8443, hi: 8450 }; f.to.port = Some(65533); }), ["firewall.forward.nas-https.to"]);
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
    let mut c = parse(FULL_V2).unwrap();
    c.firewall.forwards.clear();
    c.dns.hosts.clear();
    assert_eq!(c.unsupported(), vec![]);
    // Not yet: forwards, DNS hosts, other ports, static WAN (rules are in).
    let p = parse(FULL_V2).unwrap().unsupported().into_iter().map(|i| i.path).collect::<Vec<_>>();
    assert_eq!(p, ["firewall.forward", "dns.host"]);
    let mut d = c.clone();
    d.networks[1].ports = vec!["lan1".into()];
    assert_eq!(d.unsupported()[0].path, "network.guest.ports");
    d.wan.mode = WanMode::Static;
    assert!(d.unsupported().iter().any(|i| i.path == "wan.static"));
}

#[test]
fn network_layout_changes_reboot() {
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
    assert!(r(|c| c.networks[1].vlan = 21));
    assert!(r(|c| c.networks[1].ipv4.prefix = 16));
    assert!(r(|c| c.networks[1].zone = "lan".into()));
    assert!(r(|c| { c.networks.pop(); }));
    assert!(r(|c| c.zones.push(Zone { name: "lab".into(), ..Zone::builtin_lan() })));
}
