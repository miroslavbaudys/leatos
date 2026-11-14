use crate::*;
use alloc::string::ToString;
use alloc::vec::Vec;

fn lines(out: &[Output]) -> Vec<String> {
    out.iter()
        .filter_map(|o| match o {
            Output::Line(l) => Some(l.clone()),
            _ => None,
        })
        .collect()
}

fn echoed(out: &[Output]) -> Vec<u8> {
    out.iter()
        .flat_map(|o| match o {
            Output::Echo(e) => e.clone(),
            _ => Vec::new(),
        })
        .collect()
}

#[test]
fn typing_and_line_endings() {
    let mut e = LineEditor::new();
    let out = e.feed(b"status\r");
    assert_eq!(lines(&out), ["status"]);
    assert_eq!(echoed(&out), b"status\r\n");
    // CRLF is one Enter; LF alone too; split across calls as well.
    let out = e.feed(b"a\r\nb\n");
    assert_eq!(lines(&out), ["a", "b"]);
    assert_eq!(lines(&e.feed(b"c\r")), ["c"]);
    assert_eq!(lines(&e.feed(b"\nd\r")), ["d"]);
    // An empty Enter still ends a (empty) line.
    assert_eq!(lines(&e.feed(b"\r")), [""]);
}

#[test]
fn editing_keys() {
    let mut e = LineEditor::new();
    // Backspace (DEL and BS), at an empty line too.
    let out = e.feed(b"\x7fstatx\x7f\x08tus\r");
    assert_eq!(lines(&out), ["status"]);
    assert!(echoed(&out).windows(3).any(|w| w == b"\x08 \x08"));
    // Ctrl-U clears, Ctrl-C cancels.
    assert_eq!(lines(&e.feed(b"junk\x15help\r")), ["help"]);
    let out = e.feed(b"half\x03");
    assert!(out.contains(&Output::Cancel));
    assert_eq!(e.current(), "");
    // Other control bytes, non-ASCII and unknown escapes are ignored.
    assert_eq!(lines(&e.feed(b"x\x01\xc3\xa9\x1b[Cy\x1b[3~\r")), ["xy"]);
}

#[test]
fn history() {
    let mut e = LineEditor::new();
    e.feed(b"one\rtwo\rtwo\r");
    // Up: two (duplicates kept once), up: one, up: stays at one.
    e.feed(b"\x1b[A");
    assert_eq!(e.current(), "two");
    e.feed(b"\x1b[A\x1b[A");
    assert_eq!(e.current(), "one");
    // Down past the end: back to what was typed before browsing.
    e.feed(b"\x1b[B\x1b[B");
    assert_eq!(e.current(), "");
    e.feed(b"dr\x1b[A\x1b[B");
    assert_eq!(e.current(), "dr");
    // SS3 arrows (application cursor mode) work as well.
    e.feed(b"\x15\x1bOA");
    assert_eq!(e.current(), "two");
    assert_eq!(lines(&e.feed(b"\r")), ["two"]);
}

#[test]
fn long_lines_are_capped() {
    let mut e = LineEditor::new();
    let long = [b'a'; MAX_LINE + 10];
    let out = e.feed(&long);
    assert!(echoed(&out).contains(&0x07));
    assert_eq!(lines(&e.feed(b"\r"))[0].len(), MAX_LINE);
}

#[test]
fn commands() {
    let p = |s: &str| parse(s).unwrap().unwrap();
    assert_eq!(parse("   ").unwrap(), None);
    assert_eq!(p("help"), Command::Help);
    assert_eq!(p("?"), Command::Help);
    assert_eq!(p(" status "), Command::Status);
    assert_eq!(p("leases"), Command::Leases);
    assert_eq!(p("reboot"), Command::Reboot);
    assert_eq!(p("config show"), Command::Show(Which::Running));
    assert_eq!(p("config show stored"), Command::Show(Which::Stored));
    assert_eq!(p("config show pending"), Command::Show(Which::Pending));
    assert_eq!(
        p("config  set time.ntp_servers = [\"a b\", \"c\"]"),
        Command::Set("time.ntp_servers = [\"a b\", \"c\"]".to_string())
    );
    assert_eq!(p("config unset shaping.up_kbit"), Command::Unset("shaping.up_kbit".into()));
    assert_eq!(p("config diff"), Command::Diff);
    assert_eq!(p("config save"), Command::Save);
    assert_eq!(p("config discard"), Command::Discard);
}

#[test]
fn command_errors() {
    for (line, msg) in [
        ("bogus", "unknown command: bogus"),
        ("status now", "status takes no arguments"),
        ("config", "usage: config"),
        ("config show all", "usage: config show"),
        ("config set dns.cache_entries", "usage: config set"),
        ("config set = 5", "usage: config set"),
        ("config unset", "usage: config unset"),
        ("config unset a b", "usage: config unset"),
    ] {
        let e = parse(line).unwrap_err();
        assert!(e.starts_with(msg), "{line}: {e}");
    }
    assert!(HELP.contains("config set"));
}
