use std::{
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

fn bin() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_olo-gate"));
    // Never read the developer's own config during tests.
    c.env("OLO_GATE_CONFIG", "/nonexistent/olo-gate.json").env_remove("OLO_GATE_LEVEL").env_remove("OLO_GATE_MODE");
    c
}

fn git(dir: &Path, args: &[&str]) {
    let ok = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"])
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .success();
    assert!(ok, "git {args:?}");
}

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("olo-gate-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn check_exit_codes() {
    assert_eq!(bin().args(["check", "ls", "-la"]).output().unwrap().status.code(), Some(0));
    assert_eq!(bin().args(["check", "git", "push", "origin", "main"]).output().unwrap().status.code(), Some(10));
    assert_eq!(bin().args(["check", "rm", "-rf", "build"]).output().unwrap().status.code(), Some(20));
}

#[test]
fn hook_is_silent_on_garbage_and_on_safe_commands() {
    for input in
        ["", "not json", r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}"#]
    {
        let mut ch = bin().args(["hook", "claude"]).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
        ch.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
        let out = ch.wait_with_output().unwrap();
        assert!(out.status.success());
        assert!(out.stdout.is_empty(), "{input}");
    }
}

#[test]
fn hook_asks_for_a_force_push_and_shows_the_real_effect() {
    let root = scratch("effect");
    let (remote, work) = (root.join("remote.git"), root.join("work"));
    std::fs::create_dir_all(&remote).unwrap();
    git(&remote, &["init", "--bare", "-b", "main"]);
    std::fs::create_dir_all(&work).unwrap();
    git(&work, &["init", "-b", "main"]);
    git(&work, &["remote", "add", "origin", remote.to_str().unwrap()]);
    for n in 1..=3 {
        std::fs::write(work.join("f.txt"), format!("v{n}")).unwrap();
        git(&work, &["add", "."]);
        git(&work, &["commit", "-m", &format!("c{n}")]);
    }
    git(&work, &["push", "origin", "main"]);
    git(&work, &["reset", "--hard", "HEAD~2"]); // origin/main now has 2 commits this checkout lacks

    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": work,
        "tool_input": { "command": "git push --force origin main" }
    });
    let mut ch = bin().args(["hook", "claude"]).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    ch.stdin.take().unwrap().write_all(payload.to_string().as_bytes()).unwrap();
    let out = ch.wait_with_output().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "ask");
    let why = v["hookSpecificOutput"]["permissionDecisionReason"].as_str().unwrap();
    assert!(why.contains("Would erase 2 commits of origin/main"), "{why}");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn project_files_cannot_weaken_the_guard() {
    let dir = scratch("cfg");
    std::fs::write(dir.join(".olo-gate.json"), r#"{"allow":["rm -rf build"],"level":"high"}"#).unwrap();
    let payload = serde_json::json!({ "hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": dir, "tool_input": { "command": "rm -rf build" } });
    let mut ch =
        bin().current_dir(&dir).args(["hook", "claude"]).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    ch.stdin.take().unwrap().write_all(payload.to_string().as_bytes()).unwrap();
    let out = ch.wait_with_output().unwrap();
    assert!(!out.stdout.is_empty(), "a config file inside the project must be ignored");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn init_prints_valid_json_and_changes_nothing() {
    for c in ["claude", "codex", "cursor", "gemini"] {
        let out = bin().args(["init", c]).output().unwrap();
        assert!(out.status.success());
        serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap();
    }
}
