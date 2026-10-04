//! User-level configuration. It is read ONLY from the user's own config directory or from the
//! environment: never from the project directory. A cloned repository must not be able to ship a file
//! that weakens the guard.

use std::path::PathBuf;

use serde::Deserialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    /// Only the irreversible and sensitive (default).
    High,
    /// Also the important (plain `git push`, installs, config files…).
    Medium,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Let the agent's own permission prompt ask the person, showing why. Where a client cannot
    /// ask from a hook (Codex, Gemini CLI) this degrades to `Deny`.
    Ask,
    /// Block outright.
    Deny,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub level: Level,
    pub mode: Mode,
    /// Exact commands (after trimming) that are never questioned.
    pub allow: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Config { level: Level::High, mode: Mode::Ask, allow: vec![] }
    }
}

#[derive(Deserialize, Default)]
struct File {
    level: Option<String>,
    mode: Option<String>,
    #[serde(default)]
    allow: Vec<String>,
}

fn level_of(s: &str) -> Option<Level> {
    match s.trim().to_ascii_lowercase().as_str() {
        "high" => Some(Level::High),
        "medium" => Some(Level::Medium),
        _ => None,
    }
}

fn mode_of(s: &str) -> Option<Mode> {
    match s.trim().to_ascii_lowercase().as_str() {
        "ask" => Some(Mode::Ask),
        "deny" => Some(Mode::Deny),
        _ => None,
    }
}

pub fn path() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("OLO_GATE_CONFIG") {
        return Some(PathBuf::from(p));
    }
    if cfg!(windows) {
        return std::env::var_os("APPDATA").map(|a| PathBuf::from(a).join("olo-gate").join("config.json"));
    }
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
    Some(base.join("olo-gate").join("config.json"))
}

impl Config {
    /// Defaults, then the user file, then the environment (`OLO_GATE_LEVEL`, `OLO_GATE_MODE`).
    pub fn load() -> Config {
        let mut c = Config::default();
        if let Some(text) = path().and_then(|p| std::fs::read_to_string(p).ok()) {
            if let Ok(f) = serde_json::from_str::<File>(&text) {
                if let Some(l) = f.level.as_deref().and_then(level_of) {
                    c.level = l;
                }
                if let Some(m) = f.mode.as_deref().and_then(mode_of) {
                    c.mode = m;
                }
                c.allow = f.allow.into_iter().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
            }
        }
        if let Some(l) = std::env::var("OLO_GATE_LEVEL").ok().as_deref().and_then(level_of) {
            c.level = l;
        }
        if let Some(m) = std::env::var("OLO_GATE_MODE").ok().as_deref().and_then(mode_of) {
            c.mode = m;
        }
        c
    }
}
