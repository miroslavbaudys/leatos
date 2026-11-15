//! Editing a [`Config`] one setting at a time (the serial CLI): TOML
//! assignments with dotted paths, back-to-default, and a readable diff.
//!
//! List entries with a name are addressed by it: the config is edited as
//! a table in which `[[network]]`, `[[zone]]`, `[[firewall.rule]]` and
//! `[[firewall.forward]]` are keyed by `name` (`network.guest.vlan = 20`,
//! `firewall.rule.ssh = { from = "wan", to = "router", … }`). The order
//! of existing entries is kept; new ones go last. `lan.…` means the first
//! network (version 1's `[lan]`), `lan.domain` is `dns.domain`.

use crate::{Config, Error, Network, Zone};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use toml::{Table, Value};

/// Lists keyed by `name`, as paths.
const KEYED: [&[&str]; 4] = [&["network"], &["zone"], &["firewall", "rule"], &["firewall", "forward"]];

fn syntax(e: impl ToString) -> Error {
    Error::Syntax(e.to_string())
}

fn get_mut<'a>(t: &'a mut Table, path: &[&str]) -> Option<&'a mut Value> {
    let (last, parents) = path.split_last()?;
    let mut cur = t;
    for p in parents {
        cur = cur.get_mut(*p)?.as_table_mut()?;
    }
    cur.get_mut(*last)
}

/// The config as an editing table (keyed lists as tables).
fn to_table(c: &Config) -> Result<Table, Error> {
    let mut t = Table::try_from(c).map_err(syntax)?;
    t.remove("version");
    for path in KEYED {
        if let Some(v) = get_mut(&mut t, path)
            && let Value::Array(items) = v
        {
            let mut keyed = Table::new();
            for item in core::mem::take(items) {
                if let Value::Table(mut e) = item {
                    let name = match e.remove("name") {
                        Some(Value::String(n)) => n,
                        _ => continue,
                    };
                    keyed.insert(name, Value::Table(e));
                }
            }
            *v = Value::Table(keyed);
        }
    }
    Ok(t)
}

/// Back from an editing table; entries in `order`'s order, new ones last.
fn from_table(mut t: Table, order: &Config) -> Result<Config, Error> {
    let names = |path: &[&str]| -> Vec<String> {
        match path {
            ["network"] => order.networks.iter().map(|n| n.name.clone()).collect(),
            ["zone"] => order.zones.iter().map(|z| z.name.clone()).collect(),
            ["firewall", "rule"] => order.firewall.rules.iter().map(|r| r.name.clone()).collect(),
            _ => order.firewall.forwards.iter().map(|f| f.name.clone()).collect(),
        }
    };
    for path in KEYED {
        let old = names(path);
        if let Some(v) = get_mut(&mut t, path)
            && let Value::Table(keyed) = v
        {
            let mut keyed = core::mem::take(keyed);
            let mut keys: Vec<String> = old.into_iter().filter(|k| keyed.contains_key(k)).collect();
            keys.extend(keyed.keys().filter(|k| !keys.contains(k)).cloned().collect::<Vec<_>>());
            let mut items = Vec::new();
            for k in keys {
                match keyed.remove(&k) {
                    Some(Value::Table(mut e)) => {
                        e.insert("name".into(), Value::String(k));
                        items.push(Value::Table(e));
                    }
                    _ => {
                        return Err(Error::Syntax(format!(
                            "{}.{k} must be a table",
                            path.join(".")
                        )));
                    }
                }
            }
            *v = Value::Array(items);
        }
    }
    t.insert("version".into(), Value::Integer(crate::VERSION.into()));
    t.try_into::<Config>().map_err(syntax)
}

/// Tables merge key by key; anything else (values, arrays) replaces.
fn merge(into: &mut Table, from: Table) {
    for (k, v) in from {
        match (into.get_mut(&k), v) {
            (Some(Value::Table(a)), Value::Table(b)) => merge(a, b),
            (_, v) => {
                into.insert(k, v);
            }
        }
    }
}

fn first_network(c: &Config) -> Result<String, Error> {
    c.lan()
        .map(|n| n.name.clone())
        .ok_or_else(|| Error::Syntax("there is no network".into()))
}

/// `lan.x` → `network.<first>.x`, `lan.domain` → `dns.domain`.
fn alias(c: &Config, path: &str) -> Result<String, Error> {
    match path.strip_prefix("lan.") {
        Some("domain") => Ok("dns.domain".into()),
        Some(rest) => Ok(format!("network.{}.{rest}", first_network(c)?)),
        None if path == "lan" => Err(Error::Syntax(
            "lan is the first network: unset its settings one by one".into(),
        )),
        None => Ok(path.into()),
    }
}

impl Config {
    /// This config with one TOML assignment applied: `dns.cache_entries =
    /// 1000`, `time.ntp_servers = ["a", "b"]`, `network.lan.dhcp.static =
    /// [{ mac = "…", ip = "…" }]`, `network.guest = { ipv4 =
    /// "10.20.0.1/24", vlan = 20 }`. Unknown settings and wrong types are
    /// errors; the cross-field checks ([`Config::validate`]) are not run,
    /// so related changes can be made one after the other.
    pub fn with_assignment(&self, line: &str) -> Result<Config, Error> {
        if !line.contains('=') {
            return Err(Error::Syntax("expected <setting> = <value>".into()));
        }
        let mut snippet: Table = line.parse().map_err(syntax)?;
        if snippet.contains_key("version") {
            return Err(Error::Syntax("version cannot be set".into()));
        }
        if let Some(lan) = snippet.remove("lan") {
            let Value::Table(mut lan) = lan else {
                return Err(Error::Syntax("lan is a section: set lan.<setting>".into()));
            };
            if let Some(d) = lan.remove("domain") {
                let mut dns = Table::new();
                dns.insert("domain".into(), d);
                merge(&mut snippet, Table::from_iter([("dns".into(), Value::Table(dns))]));
            }
            let mut net = Table::new();
            net.insert(first_network(self)?, Value::Table(lan));
            merge(&mut snippet, Table::from_iter([("network".into(), Value::Table(net))]));
        }
        let mut t = to_table(self)?;
        merge(&mut t, snippet);
        from_table(t, self)
    }

    /// This config with `path` (`shaping.up_kbit`) back at its default:
    /// the default value, or no value where the setting is optional. A
    /// list entry (`network.guest`, `firewall.rule.ssh`) is removed.
    pub fn without(&self, path: &str) -> Result<Config, Error> {
        let path = alias(self, path)?;
        let unknown = || Error::Syntax(format!("unknown setting {path}"));
        let parts: Vec<&str> = path.split('.').collect();
        if parts.iter().any(|p| p.is_empty()) || path == "version" {
            return Err(unknown());
        }
        let mut t = to_table(self)?;
        // A whole entry of a keyed list.
        if let Some(list) = KEYED.iter().find(|k| parts.len() == k.len() + 1 && parts.starts_with(k)) {
            let removed = get_mut(&mut t, list)
                .and_then(Value::as_table_mut)
                .and_then(|k| k.remove(parts[list.len()]));
            return match removed {
                Some(_) => from_table(t, self),
                None => Err(Error::Syntax(format!("there is no {path}"))),
            };
        }
        let (last, parents) = parts.split_last().ok_or_else(unknown)?;
        // The path with entry names as `*` (`network.*.vlan`).
        let generic = parts
            .iter()
            .enumerate()
            .map(|(i, p)| {
                if KEYED.iter().any(|k| k.len() == i && parts.starts_with(k)) {
                    "*"
                } else {
                    p
                }
            })
            .collect::<Vec<_>>()
            .join(".");
        let known = optional_known(&generic);
        let defaults = to_table(&Config::default())?;
        let mut cur = &mut t;
        let mut def = Some(defaults);
        for (i, p) in parents.iter().enumerate() {
            let entry = KEYED.iter().find(|k| k.len() == i && parts.starts_with(k));
            def = match entry {
                // Inside a list entry: the defaults of its type.
                Some(list) => template(list),
                None => def.and_then(|d| d.get(*p).and_then(Value::as_table).cloned()),
            };
            cur = match cur.get_mut(*p) {
                Some(Value::Table(x)) => x,
                None if entry.is_some() => {
                    return Err(Error::Syntax(format!("there is no {}", parts[..=i].join("."))));
                }
                // A section left out of the canonical form because it is
                // all defaults (`[wan]`): already unset.
                None if known => return Ok(self.clone()),
                _ => return Err(unknown()),
            };
        }
        match def.as_ref().and_then(|d| d.get(*last)) {
            Some(v) => {
                cur.insert(String::from(*last), v.clone());
            }
            None => {
                if cur.remove(*last).is_none() && !known {
                    return Err(unknown());
                }
            }
        }
        from_table(t, self)
    }
}

/// Default fields of a keyed list's entries.
fn template(list: &[&str]) -> Option<Table> {
    let mut t = match list {
        ["network"] => Table::try_from(Network::default()),
        ["zone"] => Table::try_from(Zone::builtin_lan()),
        _ => return Some(Table::new()), // rules, forwards: required fields only
    }
    .ok()?;
    t.remove("name");
    Some(t)
}

/// Optional settings without a default value (list entry names as `*`):
/// unsetting them is fine even when they are not set.
fn optional_known(path: &str) -> bool {
    matches!(
        path,
        "shaping.up_kbit"
            | "shaping.down_kbit"
            | "network.*.vlan"
            | "network.*.dhcp.enabled"
            | "network.*.dhcp.range"
            | "network.*.dhcp.static"
            | "zone"
            | "zone.*.allow"
            | "firewall"
            | "firewall.rule"
            | "firewall.forward"
            | "firewall.rule.*.enabled"
            | "firewall.rule.*.proto"
            | "firewall.rule.*.src"
            | "firewall.rule.*.dst"
            | "firewall.rule.*.dst_port"
            | "firewall.forward.*.enabled"
            | "firewall.forward.*.proto"
            | "firewall.forward.*.src"
            | "firewall.forward.*.hairpin"
            | "dns.host"
            | "mgmt.password"
            | "mgmt.password_hash"
            | "wan"
            | "wan.port"
            | "wan.vlan"
            | "wan.vlan_pcp"
            | "wan.mode"
            | "wan.static"
            | "wan.pppoe"
            | "wan.pppoe.username"
            | "wan.pppoe.password"
            | "wan.pppoe.service"
            | "wan.pppoe.ac_name"
            | "wan.pppoe.mtu"
            | "wan.pppoe.lcp_echo_interval"
            | "wan.pppoe.lcp_echo_failure"
    )
}

/// One `path = value` line per setting, list entries by name:
/// `dns.cache_entries = 4096`, `network.lan.dhcp.static[0].ip =
/// "10.10.0.10"`.
pub fn flat_lines(c: &Config) -> Vec<String> {
    fn walk(t: &Table, prefix: &str, out: &mut Vec<String>) {
        for (k, v) in t {
            let p = format!("{prefix}{k}");
            match v {
                Value::Table(sub) => walk(sub, &format!("{p}."), out),
                Value::Array(a) if !a.is_empty() && a.iter().all(Value::is_table) => {
                    for (i, e) in a.iter().enumerate() {
                        if let Value::Table(sub) = e {
                            walk(sub, &format!("{p}[{i}]."), out);
                        }
                    }
                }
                v => out.push(format!("{p} = {v}")),
            }
        }
    }
    let mut out = Vec::new();
    if let Ok(t) = to_table(c) {
        walk(&t, "", &mut out);
    }
    out
}

/// What changes from `old` to `new`: `- path = old` / `+ path = new` lines.
pub fn diff_lines(old: &Config, new: &Config) -> Vec<String> {
    let (a, b) = (flat_lines(old), flat_lines(new));
    let mut out: Vec<String> = a
        .iter()
        .filter(|l| !b.contains(l))
        .map(|l| format!("- {l}"))
        .collect();
    out.extend(b.iter().filter(|l| !a.contains(l)).map(|l| format!("+ {l}")));
    out
}
