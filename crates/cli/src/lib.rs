//! The serial console CLI, sans-IO:
//!
//! - [`LineEditor`]: bytes from the UART in, bytes to echo and finished
//!   lines out (backspace, Ctrl-U, Ctrl-C, history with the arrow keys)
//! - [`parse`]: a line → a [`Command`]
//!
//! The kernel (`kernel/src/cli.rs`) runs the commands.
//!
//! `#![no_std]` + `alloc`, no unsafe.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

mod editor;
#[cfg(test)]
mod tests;

pub use editor::{LineEditor, Output, MAX_LINE};

use alloc::string::String;

/// Which config `config show` prints.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Which {
    /// What runs: stored config + boot arguments.
    Running,
    /// What the store holds (or the defaults).
    Stored,
    /// The edit in progress.
    Pending,
}

/// What `log` shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogArg {
    /// The last N lines.
    Last(usize),
    All,
    Clear,
}

/// Lines `log` shows without an argument.
pub const LOG_DEFAULT_LINES: usize = 40;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    Help,
    Status,
    Leases,
    Routes,
    /// `log [N|all|clear]`: the last N lines of the RAM log (`None` = all).
    Log(LogArg),
    Show(Which),
    /// `config set <path> = <value>`: the assignment, verbatim.
    Set(String),
    Unset(String),
    Diff,
    Save,
    Discard,
    Reboot,
}

pub const HELP: &str = "\
commands:
  status                         system, ports, WAN, time, watchdog, CPU
  leases                         DHCP leases
  routes                         routing table
  log [N|all|clear]              messages since boot (default: last 40 lines)
  config show [running|stored|pending]
  config set <setting> = <value> edit (TOML), e.g. config set shaping.up_kbit = 18000
  config unset <setting>         back to the default
  config diff                    pending edit vs stored config
  config save                    check, store and apply the edit
  config discard                 drop the edit
  reboot
keys: Backspace, Ctrl-U clear line, Ctrl-C cancel, Up/Down history";

/// One line → a command. Empty lines are `Ok(None)`.
pub fn parse(line: &str) -> Result<Option<Command>, String> {
    let line = line.trim();
    let mut words = line.split_whitespace();
    let Some(first) = words.next() else {
        return Ok(None);
    };
    let rest: alloc::vec::Vec<&str> = words.collect();
    let bad = |m: &str| Err(String::from(m));
    let cmd = match (first, rest.as_slice()) {
        ("help" | "?", []) => Command::Help,
        ("status", []) => Command::Status,
        ("leases", []) => Command::Leases,
        ("routes", []) => Command::Routes,
        ("log", []) => Command::Log(LogArg::Last(LOG_DEFAULT_LINES)),
        ("log", ["all"]) => Command::Log(LogArg::All),
        ("log", ["clear"]) => Command::Log(LogArg::Clear),
        ("log", [n]) if n.parse::<usize>().is_ok_and(|n| n > 0) => {
            Command::Log(LogArg::Last(n.parse().unwrap_or(LOG_DEFAULT_LINES)))
        }
        ("log", _) => return bad("usage: log [N|all|clear]"),
        ("reboot", []) => Command::Reboot,
        ("config", ["show"] | ["show", "running"]) => Command::Show(Which::Running),
        ("config", ["show", "stored"]) => Command::Show(Which::Stored),
        ("config", ["show", "pending"]) => Command::Show(Which::Pending),
        ("config", ["show", ..]) => return bad("usage: config show [running|stored|pending]"),
        ("config", ["set", ..]) => {
            // The assignment verbatim: values may contain spaces.
            let a = line
                .strip_prefix("config")
                .map(str::trim_start)
                .and_then(|l| l.strip_prefix("set"))
                .map(str::trim)
                .unwrap_or("");
            if !a.contains('=') || a.starts_with('=') {
                return bad("usage: config set <setting> = <value>");
            }
            Command::Set(a.into())
        }
        ("config", ["unset", path]) => Command::Unset((*path).into()),
        ("config", ["unset", ..]) => return bad("usage: config unset <setting>"),
        ("config", ["diff"]) => Command::Diff,
        ("config", ["save"]) => Command::Save,
        ("config", ["discard"]) => Command::Discard,
        ("config", _) => return bad("usage: config show|set|unset|diff|save|discard"),
        (
            "help" | "?" | "status" | "leases" | "routes" | "reboot",
            _,
        ) => return Err(alloc::format!("{first} takes no arguments")),
        _ => return Err(alloc::format!("unknown command: {first} (try help)")),
    };
    Ok(Some(cmd))
}
