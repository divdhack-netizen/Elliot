//! elliot-runner — the tool runner.
//!
//! This is the execution side of Elliot's trust boundary. The agent only ever
//! *proposes* a structured tool call; the runner **validates** that proposal
//! against the catalog entry (the allow-list) and the scope engine, and only
//! then **executes** it — via `argv`, never a shell, so nothing the proposal
//! contains can be reinterpreted by `/bin/sh`.
//!
//! Validation enforces, per the catalog contract:
//! - only allow-listed flags, each argument satisfying its declared type
//!   (`bool`/`int`/`enum`/`string` pattern/`path` confinement);
//! - non-repeatable flags appear at most once;
//! - every target passes the scope engine and must be [`ScopeDecision::InScope`];
//! - path arguments stay inside the project directory;
//! - effective intrusiveness = `max(tool, used flags)`; a `dangerous` effective
//!   level is refused unless the caller passes an explicit manual unlock.
//!
//! [`validate`] produces a [`ValidatedCommand`]; [`ValidatedCommand::execute`]
//! runs it. The human-confirmation step lives above the runner (in the UI); the
//! runner's job is to make sure an approved proposal is *safe to run as given*.

use std::path::{Path, PathBuf};
use std::time::Duration;

use regex::Regex;

use elliot_catalog::{Access, Cardinality, ConfinedTo, FlagType, Intrusiveness, Privilege, ToolEntry};
use elliot_httpraw::{ScopeDecider, ScopeDecision};

/// Runner configuration: the confinement root and the dangerous-unlock switch.
#[derive(Clone, Debug)]
pub struct RunnerConfig {
    /// Root that `path` flags are confined to (`confined_to: project_dir`).
    pub project_dir: PathBuf,
    /// Manual unlock for a `dangerous` effective level. Off by default.
    pub allow_dangerous: bool,
}

impl RunnerConfig {
    pub fn new(project_dir: impl Into<PathBuf>) -> Self {
        Self {
            project_dir: project_dir.into(),
            allow_dangerous: false,
        }
    }
}

/// A structured, already-approved proposal from the agent (or the UI).
#[derive(Clone, Debug, Default)]
pub struct Proposal {
    pub tool_id: String,
    pub flags: Vec<FlagArg>,
    pub targets: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct FlagArg {
    pub name: String,
    pub value: Option<String>,
}

impl FlagArg {
    pub fn switch(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: None,
        }
    }
    pub fn valued(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: Some(value.into()),
        }
    }
}

/// A validated command, ready to run as `argv` (no shell involved).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedCommand {
    pub program: String,
    pub argv: Vec<String>,
    pub effective_intrusiveness: Intrusiveness,
    /// OS capabilities the used flags declared they need (e.g. raw sockets).
    pub required_privileges: Vec<Privilege>,
}

#[derive(Debug, thiserror::Error)]
pub enum RunnerError {
    #[error("proposal is for {proposal:?} but entry is {entry:?}")]
    ToolMismatch { proposal: String, entry: String },
    #[error("flag {0:?} is not in the catalog allow-list")]
    UnknownFlag(String),
    #[error("flag {0:?} is not repeatable")]
    NotRepeatable(String),
    #[error("flag {name:?}: {reason}")]
    BadValue { name: String, reason: String },
    #[error("target {target:?} is not in scope ({decision:?})")]
    OutOfScope {
        target: String,
        decision: ScopeDecision,
    },
    #[error("expected exactly one target, got {0}")]
    CardinalityOne(usize),
    #[error("at least one target is required")]
    CardinalityAtLeastOne,
    #[error("path {path:?} escapes the project directory")]
    PathEscapesProject { path: String },
    #[error("dangerous effective intrusiveness refused (manual unlock required)")]
    DangerousBlocked,
    #[error("binary {0:?} not found on PATH")]
    BinaryNotFound(String),
    #[error("execution failed: {0}")]
    Exec(#[source] std::io::Error),
    #[error("timed out after {0:?}")]
    Timeout(Duration),
}

/// Validate a proposal against its catalog entry, scope and config.
pub fn validate(
    entry: &ToolEntry,
    proposal: &Proposal,
    scope: &dyn ScopeDecider,
    config: &RunnerConfig,
) -> Result<ValidatedCommand, RunnerError> {
    if proposal.tool_id != entry.id {
        return Err(RunnerError::ToolMismatch {
            proposal: proposal.tool_id.clone(),
            entry: entry.id.clone(),
        });
    }

    let mut effective = entry.base_intrusiveness;
    let mut required_privileges = Vec::new();
    let mut argv: Vec<String> = Vec::new();
    let mut seen: std::collections::HashMap<&str, u32> = std::collections::HashMap::new();

    for arg in &proposal.flags {
        let spec = entry
            .flag(&arg.name)
            .ok_or_else(|| RunnerError::UnknownFlag(arg.name.clone()))?;

        let count = seen.entry(spec.name.as_str()).or_insert(0);
        *count += 1;
        if *count > 1 && !spec.repeatable {
            return Err(RunnerError::NotRepeatable(arg.name.clone()));
        }

        validate_flag_value(spec, arg, config)?;

        if let Some(level) = spec.intrusiveness {
            effective = effective.max(level);
        }
        if let Some(priv_) = spec.requires_privilege {
            if !required_privileges.contains(&priv_) {
                required_privileges.push(priv_);
            }
        }

        argv.push(arg.name.clone());
        if let Some(v) = &arg.value {
            argv.push(v.clone());
        }
    }

    // Targets: cardinality + scope.
    match entry.target.cardinality {
        Cardinality::One if proposal.targets.len() != 1 => {
            return Err(RunnerError::CardinalityOne(proposal.targets.len()));
        }
        Cardinality::OneOrMore if proposal.targets.is_empty() => {
            return Err(RunnerError::CardinalityAtLeastOne);
        }
        _ => {}
    }
    for target in &proposal.targets {
        let (scheme, host, port, path) = target_locus(target);
        let decision = scope.decide(scheme, &host, port, path);
        if decision != ScopeDecision::InScope {
            return Err(RunnerError::OutOfScope {
                target: target.clone(),
                decision,
            });
        }
    }
    // Append targets as a flag value or positionals, per the entry.
    for target in &proposal.targets {
        if entry.target.kind == elliot_catalog::TargetKind::Flag {
            if let Some(flag) = &entry.target.flag {
                argv.push(flag.clone());
            }
        }
        argv.push(target.clone());
    }

    if effective == Intrusiveness::Dangerous && !config.allow_dangerous {
        return Err(RunnerError::DangerousBlocked);
    }

    Ok(ValidatedCommand {
        program: entry.binary.clone(),
        argv,
        effective_intrusiveness: effective,
        required_privileges,
    })
}

fn validate_flag_value(
    spec: &elliot_catalog::Flag,
    arg: &FlagArg,
    config: &RunnerConfig,
) -> Result<(), RunnerError> {
    let bad = |reason: String| {
        Err(RunnerError::BadValue {
            name: arg.name.clone(),
            reason,
        })
    };

    match spec.flag_type {
        FlagType::Bool => {
            if arg.value.is_some() {
                return bad("boolean flag takes no value".into());
            }
        }
        FlagType::Int => {
            let raw = arg.value.as_deref().ok_or_else(|| RunnerError::BadValue {
                name: arg.name.clone(),
                reason: "int flag requires a value".into(),
            })?;
            let n: i64 = raw.parse().map_err(|_| RunnerError::BadValue {
                name: arg.name.clone(),
                reason: format!("{raw:?} is not an integer"),
            })?;
            if let Some(min) = spec.min {
                if n < min {
                    return bad(format!("{n} < min {min}"));
                }
            }
            if let Some(max) = spec.max {
                if n > max {
                    return bad(format!("{n} > max {max}"));
                }
            }
        }
        FlagType::Enum => {
            let v = arg.value.as_deref().ok_or_else(|| RunnerError::BadValue {
                name: arg.name.clone(),
                reason: "enum flag requires a value".into(),
            })?;
            let allowed = spec.values.as_deref().unwrap_or(&[]);
            if !allowed.iter().any(|a| a == v) {
                return bad(format!("{v:?} not in {allowed:?}"));
            }
        }
        FlagType::String => {
            let v = arg.value.as_deref().ok_or_else(|| RunnerError::BadValue {
                name: arg.name.clone(),
                reason: "string flag requires a value".into(),
            })?;
            let pattern = spec.pattern.as_deref().unwrap_or("");
            let re = Regex::new(pattern).map_err(|e| RunnerError::BadValue {
                name: arg.name.clone(),
                reason: format!("catalog pattern is invalid: {e}"),
            })?;
            if !re.is_match(v) {
                return bad(format!("{v:?} does not match pattern {pattern:?}"));
            }
        }
        FlagType::Path => {
            let v = arg.value.as_deref().ok_or_else(|| RunnerError::BadValue {
                name: arg.name.clone(),
                reason: "path flag requires a value".into(),
            })?;
            // Only project_dir confinement exists today.
            let ConfinedTo::ProjectDir = spec.confined_to.unwrap_or(ConfinedTo::ProjectDir);
            if !is_within(&config.project_dir, Path::new(v)) {
                return Err(RunnerError::PathEscapesProject {
                    path: v.to_string(),
                });
            }
            // `access` (read/write) is recorded in the catalog; enforcing the
            // filesystem mode is a follow-up when the store owns the project dir.
            let _ = spec.access.unwrap_or(Access::Read);
        }
    }
    Ok(())
}

impl ValidatedCommand {
    /// Verify the binary exists, then run it as argv with no shell. Captures
    /// stdout/stderr and enforces an optional timeout.
    pub async fn execute(&self, timeout: Option<Duration>) -> Result<Output, RunnerError> {
        if find_in_path(&self.program).is_none() {
            return Err(RunnerError::BinaryNotFound(self.program.clone()));
        }

        let mut cmd = tokio::process::Command::new(&self.program);
        cmd.args(&self.argv)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);

        let child = cmd.spawn().map_err(RunnerError::Exec)?;
        let fut = child.wait_with_output();
        let out = match timeout {
            Some(t) => tokio::time::timeout(t, fut)
                .await
                .map_err(|_| RunnerError::Timeout(t))?
                .map_err(RunnerError::Exec)?,
            None => fut.await.map_err(RunnerError::Exec)?,
        };
        Ok(Output {
            status: out.status.code(),
            stdout: out.stdout,
            stderr: out.stderr,
        })
    }
}

/// Captured result of an execution.
#[derive(Clone, Debug)]
pub struct Output {
    pub status: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Derive a (scheme, host, port, path) locus from a target string for the
/// scope check. Best-effort: handles bare hosts, host:port, CIDR (mask
/// stripped) and URLs; a port-range or unparseable token scope-checks as a
/// bare host with no port.
fn target_locus(target: &str) -> (&str, String, u16, &str) {
    // URL form.
    if let Some(rest) = target
        .strip_prefix("http://")
        .map(|r| ("http", r))
        .or_else(|| target.strip_prefix("https://").map(|r| ("https", r)))
    {
        let (scheme, after) = rest;
        let (authority, _path) = after.split_once('/').unwrap_or((after, ""));
        let (host, port) = split_host_port(authority, if scheme == "https" { 443 } else { 80 });
        return (scheme, host, port, "");
    }
    // CIDR: scope-check the network address.
    let host_part = target.split('/').next().unwrap_or(target);
    let (host, port) = split_host_port(host_part, 0);
    ("", host, port, "")
}

fn split_host_port(authority: &str, default_port: u16) -> (String, u16) {
    if let Some(rest) = authority.strip_prefix('[') {
        if let Some((addr, tail)) = rest.split_once(']') {
            let port = tail
                .strip_prefix(':')
                .and_then(|p| p.parse().ok())
                .unwrap_or(default_port);
            return (format!("[{addr}]"), port);
        }
    }
    match authority.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => {
            (h.to_string(), p.parse().unwrap_or(default_port))
        }
        _ => (authority.to_string(), default_port),
    }
}

/// Is `candidate` inside `root` after normalizing `.`/`..` lexically? Rejects
/// traversal without touching the filesystem (the file may not exist yet).
fn is_within(root: &Path, candidate: &Path) -> bool {
    let joined = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        root.join(candidate)
    };
    let root = lexical_normalize(root);
    let joined = lexical_normalize(&joined);
    joined.starts_with(&root)
}

fn lexical_normalize(p: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for comp in p.components() {
        match comp {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Locate `bin` the way the OS would: an explicit path is checked directly,
/// otherwise each `PATH` entry is scanned for an executable file.
fn find_in_path(bin: &str) -> Option<PathBuf> {
    let p = Path::new(bin);
    if p.components().count() > 1 {
        return is_executable(p).then(|| p.to_path_buf());
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).find_map(|dir| {
        let candidate = dir.join(bin);
        is_executable(&candidate).then_some(candidate)
    })
}

#[cfg(unix)]
fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(p: &Path) -> bool {
    p.is_file()
}

#[cfg(test)]
mod tests {
    use super::*;
    use elliot_scope::ScopePolicy;

    fn nmap() -> ToolEntry {
        ToolEntry::load(include_str!("../../../catalog/standard/nmap.yaml")).unwrap()
    }

    fn scope_allow(host: &str) -> ScopePolicy {
        ScopePolicy::host_suffix(host)
    }

    #[test]
    fn builds_argv_in_order_without_shell() {
        let entry = nmap();
        let proposal = Proposal {
            tool_id: "nmap".into(),
            flags: vec![FlagArg::valued("-p", "80,443"), FlagArg::switch("-sV")],
            targets: vec!["scanme.example.com".into()],
        };
        let cmd = validate(
            &entry,
            &proposal,
            &scope_allow("example.com"),
            &RunnerConfig::new("/tmp/project"),
        )
        .unwrap();
        assert_eq!(cmd.program, "nmap");
        assert_eq!(cmd.argv, vec!["-p", "80,443", "-sV", "scanme.example.com"]);
        // base low, -sV low → still low.
        assert_eq!(cmd.effective_intrusiveness, Intrusiveness::Low);
    }

    #[test]
    fn unknown_flag_is_rejected() {
        let proposal = Proposal {
            tool_id: "nmap".into(),
            flags: vec![FlagArg::switch("-oG")],
            targets: vec!["a.example.com".into()],
        };
        let err = validate(&nmap(), &proposal, &scope_allow("example.com"), &RunnerConfig::new("/tmp"))
            .unwrap_err();
        assert!(matches!(err, RunnerError::UnknownFlag(_)));
    }

    #[test]
    fn string_flag_pattern_is_enforced() {
        let proposal = Proposal {
            tool_id: "nmap".into(),
            flags: vec![FlagArg::valued("-p", "80; rm -rf /")],
            targets: vec!["a.example.com".into()],
        };
        let err = validate(&nmap(), &proposal, &scope_allow("example.com"), &RunnerConfig::new("/tmp"))
            .unwrap_err();
        assert!(matches!(err, RunnerError::BadValue { .. }));
    }

    #[test]
    fn enum_flag_rejects_unlisted_value() {
        let proposal = Proposal {
            tool_id: "nmap".into(),
            flags: vec![FlagArg::valued("--script", "exploit")],
            targets: vec!["a.example.com".into()],
        };
        let err = validate(&nmap(), &proposal, &scope_allow("example.com"), &RunnerConfig::new("/tmp"))
            .unwrap_err();
        assert!(matches!(err, RunnerError::BadValue { .. }));
    }

    #[test]
    fn used_flag_raises_effective_intrusiveness() {
        let proposal = Proposal {
            tool_id: "nmap".into(),
            flags: vec![FlagArg::valued("--script", "safe")],
            targets: vec!["a.example.com".into()],
        };
        let cmd = validate(&nmap(), &proposal, &scope_allow("example.com"), &RunnerConfig::new("/tmp"))
            .unwrap();
        assert_eq!(cmd.effective_intrusiveness, Intrusiveness::Intrusive);
    }

    #[test]
    fn syn_scan_reports_required_privilege() {
        let proposal = Proposal {
            tool_id: "nmap".into(),
            flags: vec![FlagArg::switch("-sS")],
            targets: vec!["a.example.com".into()],
        };
        let cmd = validate(&nmap(), &proposal, &scope_allow("example.com"), &RunnerConfig::new("/tmp"))
            .unwrap();
        assert_eq!(cmd.required_privileges, vec![Privilege::RawSocket]);
    }

    #[test]
    fn out_of_scope_target_is_refused() {
        let proposal = Proposal {
            tool_id: "nmap".into(),
            flags: vec![],
            targets: vec!["evil.com".into()],
        };
        let err = validate(&nmap(), &proposal, &scope_allow("example.com"), &RunnerConfig::new("/tmp"))
            .unwrap_err();
        assert!(matches!(err, RunnerError::OutOfScope { .. }));
    }

    #[test]
    fn path_flag_confined_to_project_dir() {
        // Inside is fine.
        let inside = Proposal {
            tool_id: "nmap".into(),
            flags: vec![FlagArg::valued("-oX", "out/scan.xml")],
            targets: vec!["a.example.com".into()],
        };
        assert!(validate(
            &nmap(),
            &inside,
            &scope_allow("example.com"),
            &RunnerConfig::new("/tmp/project")
        )
        .is_ok());

        // Traversal escapes and is rejected.
        let outside = Proposal {
            tool_id: "nmap".into(),
            flags: vec![FlagArg::valued("-oX", "../../etc/passwd")],
            targets: vec!["a.example.com".into()],
        };
        let err = validate(
            &nmap(),
            &outside,
            &scope_allow("example.com"),
            &RunnerConfig::new("/tmp/project"),
        )
        .unwrap_err();
        assert!(matches!(err, RunnerError::PathEscapesProject { .. }));
    }

    #[tokio::test]
    async fn executes_argv_and_captures_status() {
        // A tiny synthetic entry that runs `true` with a positional target.
        let yaml = r#"
id: truecmd
binary: "true"
source: custom
description: always succeeds
base_intrusiveness: passive
target: { kind: positional, type: host, cardinality: one, scope_checked: true }
flags: []
"#;
        let entry = ToolEntry::load(yaml).unwrap();
        let proposal = Proposal {
            tool_id: "truecmd".into(),
            flags: vec![],
            targets: vec!["localhost".into()],
        };
        let cmd = validate(
            &entry,
            &proposal,
            &ScopePolicy::host_suffix("localhost"),
            &RunnerConfig::new("/tmp"),
        )
        .unwrap();
        let out = cmd
            .execute(Some(Duration::from_secs(5)))
            .await
            .expect("true should run");
        assert_eq!(out.status, Some(0));
    }
}
