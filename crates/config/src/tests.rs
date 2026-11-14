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
    assert_eq!(c.lan.ipv4, Cidr::new(ip(10, 10, 0, 1), 24));
    assert_eq!(c.lan.domain, "home.lan");
    assert_eq!(c.lan.dhcp_range(), (ip(10, 10, 0, 50), ip(10, 10, 0, 150)));
    assert_eq!(c.lan.dhcp.lease_secs, 3600);
    assert_eq!(
        c.lan.dhcp.statics,
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
            rebind_protection: false
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
    assert_eq!(c.lan.ipv4.to_string(), "192.168.1.1/24");
    assert_eq!(
        c.lan.dhcp_range(),
        (ip(192, 168, 1, 100), ip(192, 168, 1, 199))
    );
    assert_eq!(c.lan.dhcp.lease_secs, 43200);
    assert_eq!((c.shaping.ecn_up, c.shaping.ecn_down), (false, true));
    assert_eq!(
        (c.shaping.qdisc, c.shaping.isolation),
        (Qdisc::Cake, Isolation::Triple)
    );
    assert_eq!(
        c.dns,
        Dns {
            cache_entries: 4096,
            rebind_protection: true
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
    assert_eq!(c.lan, Lan::default());
    let c = parse("[lan]\nipv4 = \"10.0.0.1/16\"\n").unwrap();
    assert_eq!(c.lan.domain, "lan");
    assert_eq!(c.lan.dhcp_range(), (ip(10, 0, 0, 100), ip(10, 0, 0, 199)));
}

#[test]
fn derived_range_in_small_subnets() {
    let mut l = Lan {
        ipv4: Cidr::new(ip(10, 0, 0, 1), 29), // hosts .1–.6
        ..Lan::default()
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
    let newer = "version = 2\n[firewall]\nzones = []\n";
    assert_eq!(parse(newer), Err(Error::NewerVersion(2)));
    assert_eq!(paths(parse("version = 0\n").unwrap_err()), ["version"]);
    // Missing version = current.
    assert_eq!(
        parse("[dns]\ncache_entries = 100\n").unwrap().version,
        VERSION
    );
}

#[test]
fn lan_checks() {
    assert_eq!(invalid(|c| c.lan.ipv4.prefix = 30), ["lan.ipv4"]);
    assert_eq!(invalid(|c| c.lan.ipv4.prefix = 7), ["lan.ipv4"]);
    assert_eq!(
        invalid(|c| c.lan.ipv4.addr = ip(192, 168, 1, 0)),
        ["lan.ipv4"]
    );
    assert_eq!(
        invalid(|c| c.lan.ipv4.addr = ip(192, 168, 1, 255)),
        ["lan.ipv4"]
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
            invalid(|c| c.lan.domain = bad.into()),
            ["lan.domain"],
            "{bad:?}"
        );
    }
    assert!(parse("[lan]\ndomain = \"home.example-1.lan\"\n").is_ok());
}

#[test]
fn dhcp_checks() {
    let r = |lo, hi| move |c: &mut Config| c.lan.dhcp.range = Some([lo, hi]);
    assert_eq!(
        invalid(r(ip(192, 168, 0, 10), ip(192, 168, 1, 20))),
        ["lan.dhcp.range[0]"]
    );
    assert_eq!(
        invalid(r(ip(192, 168, 1, 10), ip(192, 168, 1, 255))),
        ["lan.dhcp.range[1]"]
    );
    assert_eq!(
        invalid(r(ip(192, 168, 1, 50), ip(192, 168, 1, 40))),
        ["lan.dhcp.range"]
    );
    assert_eq!(
        invalid(|c| c.lan.dhcp.lease_secs = 59),
        ["lan.dhcp.lease_secs"]
    );
    assert_eq!(
        invalid(|c| c.lan.dhcp.lease_secs = 31 * 86400),
        ["lan.dhcp.lease_secs"]
    );

    // A changed subnet must carry the range along: the derived one does.
    let c = parse("[lan]\nipv4 = \"10.1.2.1/24\"\n").unwrap();
    assert_eq!(c.lan.dhcp_range().0, ip(10, 1, 2, 100));
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
    let with = |v: Vec<StaticLease>| move |c: &mut Config| c.lan.dhcp.statics = v;

    // A valid pair, one inside the dynamic range (allowed: the server skips it).
    let mut c = Config::default();
    c.lan.dhcp.statics = vec![
        s(m1, ip(192, 168, 1, 10), Some("nas")),
        s(m2, ip(192, 168, 1, 150), Some("tv")),
    ];
    assert_eq!(parse(&c.to_toml()).unwrap(), c);

    assert_eq!(
        invalid(with(vec![s([0; 6], ip(192, 168, 1, 10), None)])),
        ["lan.dhcp.static[0].mac"]
    );
    assert_eq!(
        invalid(with(vec![s([1, 0, 0, 0, 0, 1], ip(192, 168, 1, 10), None)])),
        ["lan.dhcp.static[0].mac"]
    );
    assert_eq!(
        invalid(with(vec![s(m1, ip(10, 0, 0, 10), None)])),
        ["lan.dhcp.static[0].ip"]
    );
    assert_eq!(
        invalid(with(vec![s(m1, ip(192, 168, 1, 1), None)])),
        ["lan.dhcp.static[0].ip"]
    );
    assert_eq!(
        invalid(with(vec![s(m1, ip(192, 168, 1, 255), None)])),
        ["lan.dhcp.static[0].ip"]
    );
    assert_eq!(
        invalid(with(vec![
            s(m1, ip(192, 168, 1, 10), None),
            s(m1, ip(192, 168, 1, 11), None)
        ])),
        ["lan.dhcp.static[1].mac"]
    );
    assert_eq!(
        invalid(with(vec![
            s(m1, ip(192, 168, 1, 10), None),
            s(m2, ip(192, 168, 1, 10), None)
        ])),
        ["lan.dhcp.static[1].ip"]
    );
    assert_eq!(
        invalid(with(vec![
            s(m1, ip(192, 168, 1, 10), Some("NAS")),
            s(m2, ip(192, 168, 1, 11), Some("nas"))
        ])),
        ["lan.dhcp.static[1].hostname"]
    );
    assert_eq!(
        invalid(with(vec![s(m1, ip(192, 168, 1, 10), Some("my nas"))])),
        ["lan.dhcp.static[0].hostname"]
    );
    assert_eq!(
        invalid(with(vec![s(m1, ip(192, 168, 1, 10), Some("nas.lan"))])),
        ["lan.dhcp.static[0].hostname"]
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
    c.lan.ipv4 = Cidr::new(ip(10, 0, 0, 1), 8);
    c.lan.dhcp.statics = many;
    let p = c
        .validate()
        .unwrap_err()
        .into_iter()
        .map(|i| i.path)
        .collect::<Vec<_>>();
    assert!(p.contains(&"lan.dhcp.static".into()), "{p:?}");
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
        c.lan.dhcp.lease_secs = 1;
        c.dns.cache_entries = 1;
        c.shaping.overhead = 999;
    });
    assert_eq!(
        p,
        [
            "lan.dhcp.lease_secs",
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
    c.lan.dhcp.statics.push(StaticLease {
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
    let s = parse_json(r#"{"lan":{"ipv4":"10.1.0.1/16"}}"#).unwrap();
    assert_eq!(s.lan.ipv4, Cidr::new(ip(10, 1, 0, 1), 16));
    assert_eq!(s.dns, Config::default().dns);
    // Unknown fields, bad values, inconsistencies and newer versions fail.
    assert!(matches!(
        parse_json(r#"{"bogus":1}"#),
        Err(Error::Syntax(_))
    ));
    assert!(matches!(
        parse_json(r#"{"lan":{"ipv4":"10.1.0.1"}}"#),
        Err(Error::Syntax(_))
    ));
    let e =
        parse_json(r#"{"lan":{"ipv4":"10.1.0.1/24","dhcp":{"range":["10.2.0.1","10.2.0.9"]}}}"#);
    assert!(
        paths(e.unwrap_err())
            .iter()
            .any(|p| p.starts_with("lan.dhcp.range"))
    );
    assert_eq!(parse_json(r#"{"version":2}"#), Err(Error::NewerVersion(2)));
    let big = alloc::format!(r#"{{"lan":{{"domain":"{}"}}}}"#, "x".repeat(MAX_LEN));
    assert!(matches!(parse_json(&big), Err(Error::TooLarge { .. })));
}

#[test]
fn trial_for_changes_that_can_lock_the_user_out() {
    let old = Config::default();
    let mut c = old.clone();
    assert!(!c.needs_trial(&old));
    c.dns.cache_entries = 100;
    c.shaping.down_kbit = Some(90000);
    c.lan.domain = "home".into();
    assert!(
        !c.needs_trial(&old),
        "harmless changes apply without a trial"
    );
    let mut lan = old.clone();
    lan.lan.ipv4.prefix = 16;
    assert!(lan.needs_trial(&old));
    let mut m = old.clone();
    m.mgmt.on_wan = true;
    assert!(m.needs_trial(&old));
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
        .with_assignment(r#"lan.dhcp.static = [{ mac = "52:54:00:00:00:05", ip = "192.168.1.10", hostname = "nas" }]"#)
        .unwrap();
    assert_eq!(d.time.ntp_servers, ["a.example", "192.0.2.1"]);
    assert_eq!(d.shaping.up_kbit, Some(18000));
    assert_eq!(d.lan.dhcp.statics[0].hostname.as_deref(), Some("nas"));
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
        "lan.ipv4 = \"10.0.0.1\"",        // bad value
        "version = 2",
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
        .with_assignment(r#"lan.dhcp.static = [{ mac = "52:54:00:00:00:05", ip = "192.168.1.10" }]"#)
        .unwrap();
    let d = diff_lines(&a, &b);
    assert!(d.contains(&"- dns.cache_entries = 4096".to_string()), "{d:?}");
    assert!(d.contains(&"+ dns.cache_entries = 1234".to_string()), "{d:?}");
    assert!(d.contains(&"+ lan.dhcp.static[0].ip = \"192.168.1.10\"".to_string()), "{d:?}");
    assert!(flat_lines(&a).iter().any(|l| l == "version = 1"));
}
