//! Turns a hook payload from an agent into that agent's decision format.
//!
//! Silence is the common case: when an action is not risky the hook prints nothing and the agent
//! carries on with its own permission flow. The hook never *grants* anything: it can only add a
//! question or a block.
//!
//! Status of each client format:
//! - Claude Code: follows the documented `PreToolUse` contract and is covered by the CLI tests.
//! - Cursor, Codex, Gemini CLI: implemented from each tool's documented hook format; not yet verified
//!   against every release. Reports welcome.

use serde_json::{json, Value};

use crate::{
    config::{Config, Level, Mode},
    effect,
    rules::{self, Risk},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Client {
    Claude,
    Codex,
    Cursor,
    Gemini,
}

impl Client {
    pub fn parse(s: &str) -> Option<Client> {
        match s.to_ascii_lowercase().as_str() {
            "claude" | "claude-code" => Some(Client::Claude),
            "codex" => Some(Client::Codex),
            "cursor" => Some(Client::Cursor),
            "gemini" | "gemini-cli" => Some(Client::Gemini),
            _ => None,
        }
    }
}

/// Only these events happen BEFORE the action. Anything else (after-tool, stop, permission prompts the
/// agent already raises itself) is left alone.
fn is_pre_event(ev: &str) -> bool {
    matches!(ev.to_ascii_lowercase().as_str(), "pretooluse" | "beforetool" | "beforeshellexecution")
}

/// The text shown to the person: what, and what it would really do.
pub fn reason(payload: &Value) -> Option<(Risk, String)> {
    let a = rules::assess(payload)?;
    let mut text = format!("olo-gate: {}", a.action);
    if let (Some(cmd), Some(dir)) = (a.command.as_deref(), effect::dir_of(payload)) {
        let e = effect::of_command(cmd, &dir);
        if !e.lines.is_empty() {
            text.push_str(" — ");
            text.push_str(&e.lines.join("; "));
        }
    }
    Some((a.risk, text))
}

/// The stdout the hook must print for this payload, or `None` to stay silent.
pub fn decide(client: Client, payload: &Value, cfg: &Config) -> Option<String> {
    let ev = payload.get("hook_event_name").and_then(Value::as_str).unwrap_or("");
    if !is_pre_event(ev) {
        return None;
    }
    let verdict = rules::assess(payload)
        .filter(|a| a.risk == Risk::High || cfg.level == Level::Medium)
        .filter(|a| !a.command.as_deref().is_some_and(|c| cfg.allow.iter().any(|x| x == c.trim())));
    let Some(_) = verdict else {
        // Cursor treats silence as "no decision" only for some events; answering allow is the safe, explicit form.
        return (client == Client::Cursor).then(|| json!({ "permission": "allow" }).to_string());
    };
    let (_, why) = reason(payload)?;
    // Where the client cannot ask from a hook, asking means blocking.
    let mode = match (cfg.mode, client) {
        (Mode::Ask, Client::Codex | Client::Gemini) => Mode::Deny,
        (m, _) => m,
    };
    let deny_hint = format!("{why}. To allow this exact action, add it to \"allow\" in your olo-gate config.");
    Some(match (client, mode) {
        (Client::Claude | Client::Codex, Mode::Ask) => json!({ "hookSpecificOutput": { "hookEventName": "PreToolUse", "permissionDecision": "ask", "permissionDecisionReason": why } }),
        (Client::Claude | Client::Codex, Mode::Deny) => json!({ "hookSpecificOutput": { "hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": deny_hint } }),
        (Client::Gemini, _) => json!({ "decision": "deny", "reason": deny_hint }),
        (Client::Cursor, Mode::Ask) => json!({ "permission": "ask", "user_message": why, "agent_message": why }),
        (Client::Cursor, Mode::Deny) => json!({ "permission": "deny", "user_message": why, "agent_message": deny_hint }),
    }
    .to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Built at run time so that secret scanners do not flag the fixture.
    const FAKE: &str = concat!("sk-", "ABCDEF1234567890abcdef");

    fn bash(cmd: &str) -> Value {
        json!({ "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": { "command": cmd } })
    }

    fn out(client: Client, p: &Value, cfg: &Config) -> Option<Value> {
        decide(client, p, cfg).map(|s| serde_json::from_str(&s).unwrap())
    }

    #[test]
    fn silent_when_not_risky() {
        assert!(decide(Client::Claude, &bash("ls -la"), &Config::default()).is_none());
        assert!(
            decide(Client::Claude, &bash("git push origin main"), &Config::default()).is_none(),
            "medium is off by default"
        );
    }

    #[test]
    fn claude_asks_with_the_reason_and_can_deny() {
        let p = bash("git push --force origin main");
        let v = out(Client::Claude, &p, &Config::default()).unwrap();
        assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "ask");
        assert!(v["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .contains("Rewrites or deletes remote history"));
        let deny = Config { mode: Mode::Deny, ..Config::default() };
        assert_eq!(out(Client::Claude, &p, &deny).unwrap()["hookSpecificOutput"]["permissionDecision"], "deny");
    }

    #[test]
    fn medium_level_includes_plain_push() {
        let cfg = Config { level: Level::Medium, ..Config::default() };
        assert!(decide(Client::Claude, &bash("git push origin main"), &cfg).is_some());
    }

    #[test]
    fn exact_allow_list_only() {
        let cfg = Config { allow: vec!["npm publish".into()], ..Config::default() };
        assert!(decide(Client::Claude, &bash("npm publish"), &cfg).is_none());
        assert!(
            decide(Client::Claude, &bash("npm publish --tag latest"), &cfg).is_some(),
            "a different action is still questioned"
        );
    }

    #[test]
    fn clients_that_cannot_ask_deny() {
        let p = json!({ "hook_event_name": "BeforeTool", "tool_name": "run_shell_command", "tool_input": { "command": "rm -rf build" } });
        assert_eq!(out(Client::Gemini, &p, &Config::default()).unwrap()["decision"], "deny");
        let c = bash("rm -rf build");
        assert_eq!(
            out(Client::Codex, &c, &Config::default()).unwrap()["hookSpecificOutput"]["permissionDecision"],
            "deny"
        );
    }

    #[test]
    fn cursor_answers_explicitly() {
        let safe = json!({ "hook_event_name": "beforeShellExecution", "command": "ls" });
        assert_eq!(out(Client::Cursor, &safe, &Config::default()).unwrap()["permission"], "allow");
        let risky = json!({ "hook_event_name": "beforeShellExecution", "command": "git reset --hard HEAD~2" });
        assert_eq!(out(Client::Cursor, &risky, &Config::default()).unwrap()["permission"], "ask");
    }

    #[test]
    fn after_events_and_the_agents_own_prompts_are_left_alone() {
        let post =
            json!({ "hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_input": { "command": "rm -rf x" } });
        assert!(decide(Client::Claude, &post, &Config::default()).is_none());
        let perm = json!({ "hook_event_name": "PermissionRequest", "tool_name": "Bash", "tool_input": { "command": "rm -rf x" } });
        assert!(decide(Client::Codex, &perm, &Config::default()).is_none());
    }

    #[test]
    fn the_reason_never_contains_secrets() {
        let p = bash(&format!("curl -X DELETE -H 'Authorization: Bearer {FAKE}' https://api.example.com/items/1"));
        let v = out(Client::Claude, &p, &Config::default()).unwrap();
        assert!(!v.to_string().contains("sk-ABCDEF"));
    }
}
