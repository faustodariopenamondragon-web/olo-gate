//! The REAL effect of a risky action, computed locally before anyone decides.
//!
//! An agent's own summary ("clean up the branch") says nothing about what is lost. This looks at the
//! repository: "would erase 3 commits of origin/main that you don't have locally".
//!
//! Rules: read-only, no network (never `git fetch`: it compares with what you last fetched and says so),
//! no shell (argv is passed separately, git is hardened), and capped in time and files walked.
//! Counts only: file names are never reported.

use std::{
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use serde_json::{json, Map, Value};

/// Total budget: a person is waiting for the answer.
const BUDGET: Duration = Duration::from_millis(1500);
/// Cap on entries walked when sizing what an `rm -r` would delete.
const WALK_MAX: u64 = 50_000;

#[derive(Default, Debug, PartialEq)]
pub struct Effect {
    pub lines: Vec<String>,
    pub counts: Map<String, Value>,
}

impl Effect {
    fn add(&mut self, line: String, key: &str, n: u64) {
        if self.lines.len() < 6 {
            self.lines.push(line);
        }
        let prev = self.counts.get(key).and_then(Value::as_u64).unwrap_or(0);
        self.counts.insert(key.into(), json!(prev + n));
    }

    pub fn to_json(&self) -> Option<Value> {
        (!self.lines.is_empty()).then(|| json!({ "lines": self.lines, "counts": self.counts }))
    }
}

fn plural(n: u64, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

fn count(out: Option<String>) -> Option<u64> {
    out?.trim().parse().ok()
}

fn lines_of(out: Option<String>, keep: impl Fn(&str) -> bool) -> u64 {
    out.map(|s| s.lines().filter(|l| !l.trim().is_empty() && keep(l)).count() as u64).unwrap_or(0)
}

fn is_flag(a: &str) -> bool {
    a.starts_with('-')
}

fn has_short(args: &[String], c: char) -> bool {
    args.iter().any(|a| {
        !a.starts_with("--")
            && a.starts_with('-')
            && a.len() > 1
            && a[1..].chars().all(|x| x.is_ascii_alphabetic())
            && a.contains(c)
    })
}

fn has_long(args: &[String], l: &str) -> bool {
    args.iter().any(|a| a == l || a.starts_with(&format!("{l}=")))
}

/// Effect of a `git …` command (`-C dir` is honoured).
fn git_effect(mut dir: PathBuf, args: &[String], deadline: Instant, e: &mut Effect) {
    // Global options before the subcommand: -C <dir>, -c k=v, --no-pager…
    let mut i = 0;
    while i < args.len() && is_flag(&args[i]) {
        if (args[i] == "-C" || args[i] == "-c") && i + 1 < args.len() {
            if args[i] == "-C" {
                let p = PathBuf::from(&args[i + 1]);
                dir = if p.is_absolute() { p } else { dir.join(p) };
            }
            i += 2;
        } else {
            i += 1;
        }
    }
    let Some(sub) = args.get(i).map(String::as_str) else { return };
    let rest: Vec<String> = args[i + 1..].to_vec();
    let pos: Vec<&String> = rest.iter().filter(|a| !is_flag(a)).collect();
    let git = |a: &[&str]| git(&dir, a, deadline);
    let current = || {
        git(&["rev-parse", "--abbrev-ref", "HEAD"])
            .map(|s| s.trim().to_string())
            .filter(|b| !b.is_empty() && b != "HEAD")
    };
    let tracked_dirty = || lines_of(git(&["status", "--porcelain=v1", "--untracked-files=no"]), |_| true);
    match sub {
        "push" => {
            let force = has_short(&rest, 'f')
                || has_long(&rest, "--force")
                || has_long(&rest, "--force-with-lease")
                || pos.iter().skip(1).any(|r| r.starts_with('+'));
            let delete =
                has_long(&rest, "--delete") || has_short(&rest, 'd') || pos.iter().skip(1).any(|r| r.starts_with(':'));
            let remote = pos.first().map(|s| s.as_str()).unwrap_or("origin").to_string();
            let refspec = pos.get(1).map(|s| s.trim_start_matches(['+', ':']).to_string());
            let branch = refspec
                .map(|r| r.rsplit(':').next().unwrap_or(&r).trim_start_matches("refs/heads/").to_string())
                .or_else(current);
            let Some(branch) = branch else { return };
            let target = format!("{remote}/{branch}");
            if delete {
                let only_there = count(git(&["rev-list", "--count", &target, "--not", "--branches"])).unwrap_or(0);
                e.add(
                    format!(
                        "Would delete the remote branch {target}{}",
                        if only_there > 0 {
                            format!(
                                ", including {} that you have on no local branch",
                                plural(only_there, "commit", "commits")
                            )
                        } else {
                            String::new()
                        }
                    ),
                    "commits_lost",
                    only_there,
                );
            } else if force {
                match count(git(&["rev-list", "--count", &format!("HEAD..{target}")])) {
                    Some(0) => e.add(format!("Would not erase any commit of {target} (based on what you last fetched; the server may have newer changes)"), "commits_lost", 0),
                    Some(n) => e.add(format!("Would erase {} of {target} that you don't have locally", plural(n, "commit", "commits")), "commits_lost", n),
                    None => e.add(format!("{target} is unknown on this machine: can't tell what would be lost"), "unknown", 1),
                }
            }
        }
        "reset" if has_long(&rest, "--hard") => {
            let n = tracked_dirty();
            if n > 0 {
                e.add(
                    format!("You would lose the uncommitted changes in {}", plural(n, "file", "files")),
                    "files_lost",
                    n,
                );
            }
            if let Some(t) = pos.first() {
                if let Some(c) = count(git(&["rev-list", "--count", &format!("{t}..HEAD")])).filter(|c| *c > 0) {
                    e.add(
                        format!("{} would no longer be on your branch", plural(c, "commit", "commits")),
                        "commits_dropped",
                        c,
                    );
                }
            }
            if e.lines.is_empty() {
                e.add("There are no uncommitted changes to lose".into(), "files_lost", 0);
            }
        }
        "checkout" | "restore"
            if !has_long(&rest, "--staged")
                && (rest.iter().any(|a| a == "--") && pos.iter().any(|p| p.as_str() == ".")
                    || sub == "restore" && pos.iter().any(|p| p.as_str() == ".")) =>
        {
            let n = tracked_dirty();
            e.add(
                if n > 0 {
                    format!("You would lose the uncommitted changes in {}", plural(n, "file", "files"))
                } else {
                    "There are no uncommitted changes to lose".into()
                },
                "files_lost",
                n,
            );
        }
        "clean" if has_short(&rest, 'f') || has_long(&rest, "--force") => {
            let mut a = vec!["clean", "-n"];
            if has_short(&rest, 'd') {
                a.push("-d");
            }
            if has_short(&rest, 'x') {
                a.push("-x");
            } else if has_short(&rest, 'X') {
                a.push("-X");
            }
            let n = lines_of(git(&a), |l| l.starts_with("Would remove"));
            e.add(
                if n > 0 {
                    format!("Would delete {} (untracked, cannot be recovered)", plural(n, "file", "files"))
                } else {
                    "There are no untracked files to delete".into()
                },
                "files_deleted",
                n,
            );
        }
        "branch" if has_short(&rest, 'D') || (has_short(&rest, 'd') && has_short(&rest, 'f')) => {
            for b in pos.iter().take(3) {
                let n = count(git(&["rev-list", "--count", b, "--not", "--remotes"])).unwrap_or(0);
                e.add(
                    if n > 0 {
                        format!("Branch {b} has {} that are on no remote", plural(n, "commit", "commits"))
                    } else {
                        format!("Branch {b} is already on a remote: nothing is lost")
                    },
                    "commits_lost",
                    n,
                );
            }
        }
        "stash" if pos.first().is_some_and(|s| s.as_str() == "clear" || s.as_str() == "drop") => {
            let total = lines_of(git(&["stash", "list"]), |_| true);
            let n = if pos[0].as_str() == "clear" { total } else { total.min(1) };
            e.add(format!("Would delete {} saved with stash", plural(n, "change", "changes")), "stashes_lost", n);
        }
        _ => {}
    }
}

/// Counts files and bytes under `p` (never following links), with entry and time caps.
fn walk(p: &Path, deadline: Instant, files: &mut u64, bytes: &mut u64, seen: &mut u64) -> bool {
    let Ok(meta) = std::fs::symlink_metadata(p) else { return true };
    *seen += 1;
    if *seen > WALK_MAX || Instant::now() > deadline {
        return false;
    }
    if meta.is_dir() {
        let Ok(rd) = std::fs::read_dir(p) else { return true };
        for entry in rd.flatten() {
            if !walk(&entry.path(), deadline, files, bytes, seen) {
                return false;
            }
        }
    } else {
        *files += 1;
        *bytes += meta.len();
    }
    true
}

fn size(b: u64) -> String {
    match b {
        b if b >= 1 << 30 => format!("{:.1} GB", b as f64 / (1u64 << 30) as f64),
        b if b >= 1 << 20 => format!("{:.0} MB", b as f64 / (1u64 << 20) as f64),
        b if b >= 1 << 10 => format!("{:.0} KB", b as f64 / 1024.0),
        b => format!("{b} B"),
    }
}

fn rm_effect(dir: &Path, args: &[String], deadline: Instant, e: &mut Effect) {
    let targets: Vec<&String> = args.iter().filter(|a| !is_flag(a)).collect();
    if targets.iter().any(|t| t.contains(['*', '?', '[', '$', '~'])) {
        e.add("Uses wildcards or variables: can't compute what it would delete".into(), "unknown", 1);
        return;
    }
    let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).map(PathBuf::from);
    let (mut files, mut bytes, mut seen) = (0u64, 0u64, 0u64);
    let mut complete = true;
    for t in targets.iter().take(20) {
        let p = if Path::new(t.as_str()).is_absolute() { PathBuf::from(t.as_str()) } else { dir.join(t.as_str()) };
        if p.parent().is_none() || home.as_deref() == Some(p.as_path()) {
            e.add("Would delete a root folder or your whole home folder".into(), "danger", 1);
            return;
        }
        complete &= walk(&p, deadline, &mut files, &mut bytes, &mut seen);
        if !complete {
            break;
        }
    }
    if files == 0 && complete {
        e.add("Found nothing to delete at those paths".into(), "files_deleted", 0);
    } else {
        let approx = if complete { "" } else { "more than " };
        e.add(
            format!("Would delete {approx}{} ({})", plural(files, "file", "files"), size(bytes)),
            "files_deleted",
            files,
        );
        e.counts.insert("bytes".into(), json!(bytes));
    }
}

/// Effect of a command line run in `dir`.
pub fn of_command(cmd: &str, dir: &Path) -> Effect {
    let deadline = Instant::now() + BUDGET;
    let mut e = Effect::default();
    for seg in crate::rules::segments(cmd).into_iter().take(6) {
        let words: Vec<String> = seg
            .into_iter()
            .skip_while(|w| w.contains('=') && !w.starts_with('-') || w == "sudo" || w == "command" || w == "env")
            .collect();
        let Some((prog, args)) = words.split_first() else { continue };
        let prog = prog.rsplit(['/', '\\']).next().unwrap_or(prog).trim_end_matches(".exe");
        match prog {
            "git" => git_effect(dir.to_path_buf(), args, deadline, &mut e),
            "rm" | "rmdir" => rm_effect(dir, args, deadline, &mut e),
            _ => {}
        }
        if Instant::now() > deadline {
            break;
        }
    }
    e
}

fn git(dir: &Path, args: &[&str], deadline: Instant) -> Option<String> {
    let mut c = Command::new("git");
    // A foreign repo can ask in its config for git to run programs (fsmonitor, diff drivers):
    // those are disabled here, because this git runs by itself, unseen.
    c.arg("-C")
        .arg(dir)
        .args([
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.untrackedCache=false",
            "-c",
            "diff.external=",
            "-c",
            "core.pager=cat",
        ])
        .args(args)
        // Do not take the index lock (`git status` refreshes it if it can) and never prompt for credentials.
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        c.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let mut ch = c.spawn().ok()?;
    let mut out = ch.stdout.take()?;
    let reader = std::thread::spawn(move || {
        let mut v = Vec::new();
        let _ = out.read_to_end(&mut v);
        v.truncate(256 * 1024);
        v
    });
    loop {
        match ch.try_wait() {
            Ok(Some(st)) => {
                let v = reader.join().ok()?;
                return st.success().then(|| String::from_utf8_lossy(&v).into_owned());
            }
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(4)),
            _ => {
                let _ = ch.kill();
                let _ = ch.wait();
                return None;
            }
        }
    }
}

/// Working directory of a hook payload (`cwd`, or the first workspace root), when absolute and existing.
pub fn dir_of(payload: &Value) -> Option<PathBuf> {
    let d = payload.get("cwd").and_then(Value::as_str).or_else(|| {
        payload.get("workspace_roots").and_then(Value::as_array).and_then(|a| a.first()).and_then(Value::as_str)
    })?;
    let p = PathBuf::from(d);
    (p.is_absolute() && p.is_dir()).then_some(p)
}
