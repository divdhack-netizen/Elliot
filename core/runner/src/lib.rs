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

use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use regex::Regex;

use elliot_catalog::{
    Access, Cardinality, ConfinedTo, FlagType, Intrusiveness, Privilege, TargetKind, ToolEntry,
};
use elliot_httpraw::{ScopeDecider, ScopeDecision};

mod which;
use which::find_in_path;

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
    #[error("cannot resolve project path {path:?}: {reason}")]
    PathUnresolved { path: String, reason: String },
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
///
/// A thin orchestrator: each rule lives in its own pure helper below, so it can
/// be read — and tested — on its own.
pub fn validate(
    entry: &ToolEntry,
    proposal: &Proposal,
    scope: &dyn ScopeDecider,
    config: &RunnerConfig,
) -> Result<ValidatedCommand, RunnerError> {
    check_tool_match(entry, proposal)?;
    let flags = validate_flags(entry, &proposal.flags, config)?;
    validate_targets(&proposal.targets, entry, scope)?;

    if flags.effective == Intrusiveness::Dangerous && !config.allow_dangerous {
        return Err(RunnerError::DangerousBlocked);
    }

    Ok(ValidatedCommand {
        program: entry.binary.clone(),
        argv: build_argv(entry, flags.argv, &proposal.targets),
        effective_intrusiveness: flags.effective,
        required_privileges: flags.privileges,
    })
}

/// The proposal must name the entry it is validated against.
fn check_tool_match(entry: &ToolEntry, proposal: &Proposal) -> Result<(), RunnerError> {
    if proposal.tool_id != entry.id {
        return Err(RunnerError::ToolMismatch {
            proposal: proposal.tool_id.clone(),
            entry: entry.id.clone(),
        });
    }
    Ok(())
}

/// Result of validating the proposed flags.
struct FlagValidation {
    /// Flag names and values, in proposal order, ready to prefix the argv.
    argv: Vec<String>,
    /// `max(tool base, every used flag)`.
    effective: Intrusiveness,
    /// OS capabilities the used flags declared, deduplicated.
    privileges: Vec<Privilege>,
}

/// Validate every proposed flag against the allow-list and build their argv.
fn validate_flags(
    entry: &ToolEntry,
    args: &[FlagArg],
    config: &RunnerConfig,
) -> Result<FlagValidation, RunnerError> {
    let mut out = FlagValidation {
        argv: Vec::new(),
        effective: entry.base_intrusiveness,
        privileges: Vec::new(),
    };
    let mut seen: HashMap<&str, u32> = HashMap::new();

    for arg in args {
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
            out.effective = out.effective.max(level);
        }
        if let Some(priv_) = spec.requires_privilege {
            if !out.privileges.contains(&priv_) {
                out.privileges.push(priv_);
            }
        }

        out.argv.push(arg.name.clone());
        if let Some(v) = &arg.value {
            out.argv.push(v.clone());
        }
    }
    Ok(out)
}

/// Enforce the target cardinality, then the scope gate: every target must come
/// back [`ScopeDecision::InScope`] or nothing is run.
fn validate_targets(
    targets: &[String],
    entry: &ToolEntry,
    scope: &dyn ScopeDecider,
) -> Result<(), RunnerError> {
    match entry.target.cardinality {
        Cardinality::One if targets.len() != 1 => {
            return Err(RunnerError::CardinalityOne(targets.len()));
        }
        Cardinality::OneOrMore if targets.is_empty() => {
            return Err(RunnerError::CardinalityAtLeastOne);
        }
        _ => {}
    }
    for target in targets {
        let locus = elliot_httpraw::net::target_locus(target);
        let decision = scope.decide(locus.scheme, &locus.host, locus.port, locus.path);
        if decision != ScopeDecision::InScope {
            return Err(RunnerError::OutOfScope {
                target: target.clone(),
                decision,
            });
        }
    }
    Ok(())
}

/// Append the targets to the flag argv, per the entry's target kind.
fn build_argv(entry: &ToolEntry, flag_argv: Vec<String>, targets: &[String]) -> Vec<String> {
    let mut argv = flag_argv;
    for target in targets {
        if entry.target.kind == TargetKind::Flag {
            if let Some(flag) = &entry.target.flag {
                argv.push(flag.clone());
            }
        }
        argv.push(target.clone());
    }
    argv
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
            let root = canonical_project_dir(&config.project_dir)?;
            if !is_within(&root, Path::new(v))? {
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

/// Resolve the confinement root to a real, canonical path. It must exist: every
/// confinement decision is made relative to it, and a path that cannot be
/// resolved gives no honest answer, so this fails loudly instead of guessing.
fn canonical_project_dir(dir: &Path) -> Result<PathBuf, RunnerError> {
    std::fs::canonicalize(dir).map_err(|e| RunnerError::PathUnresolved {
        path: dir.display().to_string(),
        reason: e.to_string(),
    })
}

/// Is `candidate` confined to the (already canonical) `root`?
///
/// Two layers:
/// 1. a purely lexical filter that rejects any `..` component without touching
///    the filesystem;
/// 2. a symlink-aware check: the deepest existing ancestor is canonicalized and
///    the not-yet-existing remainder re-attached, so a link *inside* the project
///    that points outside is caught even though its lexical path looks confined.
///
/// Residual limit (TOCTOU): between this check and the tool opening the path, a
/// process that can already write inside the project directory could swap a
/// component for a symlink. Closing that needs `openat`-style confinement at
/// open time and is out of scope here.
fn is_within(root: &Path, candidate: &Path) -> Result<bool, RunnerError> {
    if candidate
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        return Ok(false);
    }
    let joined = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        root.join(candidate)
    };
    Ok(resolve_existing_ancestor(&joined)?.starts_with(root))
}

/// Canonicalize `path`, tolerating a tail that does not exist yet.
///
/// `std::fs::canonicalize` needs the whole path to exist; an output file usually
/// does not. So walk up to the deepest existing ancestor, canonicalize that
/// (resolving every symlink on the way), and re-attach the missing components.
fn resolve_existing_ancestor(path: &Path) -> Result<PathBuf, RunnerError> {
    let mut missing: Vec<std::ffi::OsString> = Vec::new();
    let mut current = path.to_path_buf();

    loop {
        match std::fs::canonicalize(&current) {
            Ok(mut resolved) => {
                for part in missing.iter().rev() {
                    resolved.push(part);
                }
                return Ok(resolved);
            }
            Err(e) => match (current.file_name(), current.parent()) {
                // Keep the component, then retry with the parent.
                (Some(name), Some(parent)) if !parent.as_os_str().is_empty() => {
                    missing.push(name.to_os_string());
                    current = parent.to_path_buf();
                }
                // Ran out of components without resolving: report, never panic.
                _ => {
                    return Err(RunnerError::PathUnresolved {
                        path: path.display().to_string(),
                        reason: e.to_string(),
                    });
                }
            },
        }
    }
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
        let project = tempfile::tempdir().unwrap();
        let cfg = RunnerConfig::new(project.path());

        // Inside is fine.
        let inside = Proposal {
            tool_id: "nmap".into(),
            flags: vec![FlagArg::valued("-oX", "out/scan.xml")],
            targets: vec!["a.example.com".into()],
        };
        assert!(validate(&nmap(), &inside, &scope_allow("example.com"), &cfg).is_ok());

        // Lexical traversal escapes and is rejected.
        let traversal = Proposal {
            tool_id: "nmap".into(),
            flags: vec![FlagArg::valued("-oX", "../../etc/passwd")],
            targets: vec!["a.example.com".into()],
        };
        let err =
            validate(&nmap(), &traversal, &scope_allow("example.com"), &cfg).unwrap_err();
        assert!(matches!(err, RunnerError::PathEscapesProject { .. }));

        // An absolute path outside the project is rejected too.
        let absolute = Proposal {
            tool_id: "nmap".into(),
            flags: vec![FlagArg::valued("-oX", "/etc/passwd")],
            targets: vec!["a.example.com".into()],
        };
        let err = validate(&nmap(), &absolute, &scope_allow("example.com"), &cfg).unwrap_err();
        assert!(matches!(err, RunnerError::PathEscapesProject { .. }));
    }

    /// A symlink *inside* the project that points outside must not become an
    /// escape hatch: the lexical path looks confined, the resolved one is not.
    #[test]
    #[cfg(unix)]
    fn path_flag_rejects_symlink_escaping_the_project() {
        let project = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), project.path().join("escape")).unwrap();

        let proposal = Proposal {
            tool_id: "nmap".into(),
            flags: vec![FlagArg::valued("-oX", "escape/scan.xml")],
            targets: vec!["a.example.com".into()],
        };
        let err = validate(
            &nmap(),
            &proposal,
            &scope_allow("example.com"),
            &RunnerConfig::new(project.path()),
        )
        .unwrap_err();
        assert!(
            matches!(err, RunnerError::PathEscapesProject { .. }),
            "got {err:?}"
        );
    }

    /// A confinement root that does not exist yields a clear error, not a panic
    /// and not a silently-allowed path.
    #[test]
    fn path_flag_reports_an_unresolvable_project_dir() {
        let proposal = Proposal {
            tool_id: "nmap".into(),
            flags: vec![FlagArg::valued("-oX", "out/scan.xml")],
            targets: vec!["a.example.com".into()],
        };
        let err = validate(
            &nmap(),
            &proposal,
            &scope_allow("example.com"),
            &RunnerConfig::new("/definitely/not/a/real/project/dir"),
        )
        .unwrap_err();
        assert!(
            matches!(err, RunnerError::PathUnresolved { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn is_within_filters_parent_components_without_touching_disk() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        assert!(!is_within(&root, Path::new("../outside")).unwrap());
        assert!(is_within(&root, Path::new("nested/new.xml")).unwrap());
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
