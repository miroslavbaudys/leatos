//! Editing a [`Config`] one setting at a time (the serial CLI): TOML
//! assignments with dotted paths, back-to-default, and a readable diff.

use crate::{Config, Error};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use toml::{Table, Value};

fn syntax(e: impl ToString) -> Error {
    Error::Syntax(e.to_string())
}

fn to_table(c: &Config) -> Result<Table, Error> {
    Table::try_from(c).map_err(syntax)
}

fn from_table(t: Table) -> Result<Config, Error> {
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

impl Config {
    /// This config with one TOML assignment applied: `dns.cache_entries =
    /// 1000`, `time.ntp_servers = ["a", "b"]`, `lan.dhcp.static = [{ mac =
    /// "…", ip = "…" }]`. Unknown settings and wrong types are errors; the
    /// cross-field checks ([`Config::validate`]) are not run, so related
    /// changes can be made one after the other.
    pub fn with_assignment(&self, line: &str) -> Result<Config, Error> {
        if !line.contains('=') {
            return Err(Error::Syntax("expected <setting> = <value>".into()));
        }
        let snippet: Table = line.parse().map_err(syntax)?;
        if snippet.contains_key("version") {
            return Err(Error::Syntax("version cannot be set".into()));
        }
        let mut t = to_table(self)?;
        merge(&mut t, snippet);
        from_table(t)
    }

    /// This config with `path` (`shaping.up_kbit`) back at its default:
    /// the default value, or no value where the setting is optional.
    pub fn without(&self, path: &str) -> Result<Config, Error> {
        let unknown = || Error::Syntax(format!("unknown setting {path}"));
        let parts: Vec<&str> = path.split('.').collect();
        if parts.iter().any(|p| p.is_empty()) || path == "version" {
            return Err(unknown());
        }
        let (last, parents) = parts.split_last().ok_or_else(unknown)?;
        let mut t = to_table(self)?;
        let defaults = to_table(&Config::default())?;
        let mut cur = &mut t;
        let mut def = Some(&defaults);
        for p in parents {
            def = def.and_then(|d| d.get(*p)).and_then(Value::as_table);
            cur = match cur.get_mut(*p) {
                Some(Value::Table(x)) => x,
                _ => return Err(unknown()),
            };
        }
        match def.and_then(|d| d.get(*last)) {
            Some(v) => {
                cur.insert(String::from(*last), v.clone());
            }
            None => {
                if cur.remove(*last).is_none() && !optional_known(path) {
                    return Err(unknown());
                }
            }
        }
        from_table(t)
    }
}

/// Optional settings without a default value: unsetting them is fine even
/// when they are not set.
fn optional_known(path: &str) -> bool {
    matches!(
        path,
        "shaping.up_kbit" | "shaping.down_kbit" | "lan.dhcp.range" | "lan.dhcp.static"
    )
}

/// The canonical TOML as one `path = value` line per setting:
/// `dns.cache_entries = 4096`, `lan.dhcp.static[0].ip = "10.10.0.10"`.
pub fn flat_lines(c: &Config) -> Vec<String> {
    let mut out = Vec::new();
    let mut prefix = String::new();
    let mut counts: Vec<(String, usize)> = Vec::new();
    for line in c.to_toml().lines() {
        let l = line.trim();
        if l.is_empty() {
            continue;
        }
        if let Some(h) = l.strip_prefix("[[").and_then(|x| x.strip_suffix("]]")) {
            let n = match counts.iter_mut().find(|(k, _)| k == h) {
                Some((_, n)) => {
                    *n += 1;
                    *n - 1
                }
                None => {
                    counts.push((h.into(), 1));
                    0
                }
            };
            prefix = format!("{h}[{n}].");
        } else if let Some(h) = l.strip_prefix('[').and_then(|x| x.strip_suffix(']')) {
            prefix = format!("{h}.");
        } else {
            out.push(format!("{prefix}{l}"));
        }
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
