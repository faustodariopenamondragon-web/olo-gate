use std::{
    io::{Read, Write},
    path::PathBuf,
    process::ExitCode,
};

use olo_gate::{config::Config, effect, hook, rules, Risk};
use serde_json::{json, Value};

const MAX_STDIN: u64 = 256 * 1024;

const HELP: &str = "olo-gate: a tiny guard for AI coding agents

USAGE
  olo-gate hook <claude|codex|cursor|gemini>   run as an agent hook (reads the payload on stdin)
  olo-gate check [--json] [--cwd DIR] <command...>
                                               classify a command; exit 0 safe, 10 medium, 20 high
  olo-gate init <claude|codex|cursor|gemini>   print the hook configuration to add (changes nothing)
  olo-gate redact                              mask secrets in text read from stdin
  olo-gate --version | --help

CONFIG (user-level only; never read from the project): see docs/configuration.md
  OLO_GATE_LEVEL=high|medium   OLO_GATE_MODE=ask|deny   OLO_GATE_CONFIG=/path/to/config.json
";

fn stdin_limited() -> String {
    let mut s = String::new();
    let _ = std::io::stdin().take(MAX_STDIN).read_to_string(&mut s);
    s
}

fn init_snippet(client: hook::Client) -> Value {
    match client {
        hook::Client::Claude => {
            json!({ "hooks": { "PreToolUse": [{ "matcher": "Bash|Write|Edit|MultiEdit|NotebookEdit|mcp__.*", "hooks": [{ "type": "command", "command": "olo-gate hook claude", "timeout": 10 }] }] } })
        }
        hook::Client::Codex => {
            json!({ "hooks": { "PreToolUse": [{ "hooks": [{ "type": "command", "command": "olo-gate hook codex", "timeout": 10 }] }] } })
        }
        hook::Client::Cursor => {
            json!({ "version": 1, "hooks": { "beforeShellExecution": [{ "command": "olo-gate hook cursor", "timeout": 10 }] } })
        }
        hook::Client::Gemini => {
            json!({ "hooks": { "BeforeTool": [{ "hooks": [{ "name": "olo-gate", "type": "command", "command": "olo-gate hook gemini", "timeout": 10000 }] }] } })
        }
    }
}

fn where_to_put(client: hook::Client) -> &'static str {
    match client {
        hook::Client::Claude => "merge into ~/.claude/settings.json",
        hook::Client::Codex => "merge into ~/.codex/hooks.json",
        hook::Client::Cursor => "merge into ~/.cursor/hooks.json",
        hook::Client::Gemini => "merge into ~/.gemini/settings.json",
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    match a.as_slice() {
        ["--version" | "-V"] => println!("olo-gate {}", env!("CARGO_PKG_VERSION")),
        [] | ["--help" | "-h" | "help"] => print!("{HELP}"),
        ["hook", client] => {
            let Some(client) = hook::Client::parse(client) else {
                eprintln!("olo-gate: unknown client '{client}'");
                return ExitCode::from(64);
            };
            // Any internal problem (bad JSON, empty input) means silence: a guard must never wedge the agent.
            if let Ok(payload) = serde_json::from_str::<Value>(&stdin_limited()) {
                if let Some(out) = hook::decide(client, &payload, &Config::load()) {
                    let _ = writeln!(std::io::stdout(), "{out}");
                }
            }
        }
        ["init", client] => {
            let Some(client) = hook::Client::parse(client) else {
                eprintln!("olo-gate: unknown client '{client}'");
                return ExitCode::from(64);
            };
            eprintln!("# {}", where_to_put(client));
            println!("{}", serde_json::to_string_pretty(&init_snippet(client)).unwrap_or_default());
        }
        ["redact"] => println!("{}", rules::redact(&stdin_limited())),
        ["check", rest @ ..] => {
            let mut json_out = false;
            let mut cwd: Option<PathBuf> = None;
            let mut cmd: Vec<&str> = vec![];
            let mut it = rest.iter();
            while let Some(&x) = it.next() {
                match x {
                    "--json" if cmd.is_empty() => json_out = true,
                    "--cwd" if cmd.is_empty() => cwd = it.next().map(|d| PathBuf::from(*d)),
                    other => cmd.push(other),
                }
            }
            if cmd.is_empty() {
                eprintln!("olo-gate check: give a command, e.g. olo-gate check git push --force");
                return ExitCode::from(64);
            }
            let line = cmd.join(" ");
            let payload =
                json!({ "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": { "command": line } });
            let dir = cwd.or_else(|| std::env::current_dir().ok()).unwrap_or_default();
            let fx = effect::of_command(&line, &dir);
            return match rules::assess(&payload) {
                None => {
                    if json_out {
                        println!("{}", json!({ "risk": "none" }))
                    } else {
                        println!("ok    {}", rules::redact(&line))
                    }
                    ExitCode::SUCCESS
                }
                Some(asm) => {
                    if json_out {
                        println!(
                            "{}",
                            json!({ "risk": asm.risk.as_str(), "action": asm.action, "effect": fx.to_json() })
                        );
                    } else {
                        println!("{:<6}{}", asm.risk.as_str().to_uppercase(), asm.action);
                        for l in &fx.lines {
                            println!("      {l}");
                        }
                    }
                    ExitCode::from(if asm.risk == Risk::High { 20 } else { 10 })
                }
            };
        }
        _ => {
            eprint!("{HELP}");
            return ExitCode::from(64);
        }
    }
    ExitCode::SUCCESS
}
