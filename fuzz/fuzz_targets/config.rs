//! `config.toml` and its JSON form (`crates/config`): what the store holds
//! at boot (written by an earlier kernel, `leatstore` or the web form),
//! what `POST /api/config` and the CLI's `config set` take. Checks: a
//! config that parses re-parses from its own canonical TOML and JSON to
//! the same config (a saved config always loads again); the derived views
//! (secrets removed, unsupported settings, trials, names, diffs) never
//! panic; CLI assignments and unsets on the default config never panic and
//! give a config whose TOML is readable.
#![no_main]

use config::{Config, diff_lines, flat_lines, parse, parse_json};
use libfuzzer_sys::fuzz_target;

fn views(c: &Config) {
    let base = Config::default();
    let _ = c.without_secrets();
    let _ = c.unsupported();
    let _ = c.needs_trial(&base);
    let _ = base.needs_trial(c);
    let _ = c.name_visibility();
    let _ = c.local_hosts();
    let _ = c.local_domains();
    let _ = flat_lines(c);
    let _ = diff_lines(&base, c);
    let mut kept = c.clone();
    kept.keep_secrets(&base);
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = core::str::from_utf8(data) else { return };
    for (c, how) in [(parse(text), "toml"), (parse_json(text), "json")] {
        let Ok(c) = c else { continue };
        let toml = c.to_toml();
        let back = parse(&toml).unwrap_or_else(|e| panic!("{how}: own TOML refused: {e:?}\n{toml}"));
        assert_eq!(back, c, "{how}: TOML round trip");
        let json = c.to_json();
        let back = parse_json(&json).unwrap_or_else(|e| panic!("{how}: own JSON refused: {e:?}\n{json}"));
        assert_eq!(back, c, "{how}: JSON round trip");
        views(&c);
    }
    let base = Config::default();
    for line in text.lines().take(8) {
        if let Ok(n) = base.with_assignment(line) {
            let _ = n.validate();
            let _ = n.to_toml();
            views(&n);
        }
        if let Ok(n) = base.without(line.trim()) {
            let _ = n.validate();
        }
    }
});
