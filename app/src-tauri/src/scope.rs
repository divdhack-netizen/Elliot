//! Project file + scope policy wiring for the Tauri shell.
//!
//! The scope policy is the single source of truth for what Elliot is allowed to
//! intercept, and it lives in the project file. This module owns:
//!
//! - [`ScopeState`]: the live policy (shared with a running proxy) plus the open
//!   project file it is persisted to;
//! - the commands the UI calls to create/open a project and read or edit the
//!   policy;
//! - the glue that keeps the two in sync, so an edit applies to the next request
//!   **and** survives a restart.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use elliot_httpraw::ScopeDecider;
use elliot_scope::{ScopePolicy, SharedPolicy};
use elliot_store::Store;
use serde::Serialize;
use tauri::State;
use tokio::sync::Mutex;

/// Setting key under which the scope policy is stored in the project file.
const SCOPE_KEY: &str = "scope_policy";

/// Default project file name.
pub const PROJECT_FILE: &str = "project.elliot";

/// An open project file.
struct Project {
    store: Store,
    path: PathBuf,
}

/// What the UI needs to know about the project.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectStatus {
    /// Is a project file open (i.e. are scope edits persisted)?
    pub open: bool,
    /// Path of the open project file, when there is one.
    pub path: Option<String>,
    /// Where the UI's "create project" form points by default.
    pub default_path: String,
}

/// Scope + project state held by Tauri.
pub struct ScopeState {
    policy: Arc<SharedPolicy>,
    project: Mutex<Option<Project>>,
    default_path: PathBuf,
}

impl ScopeState {
    pub fn new(default_path: PathBuf) -> Self {
        Self {
            // An empty policy is the safe default: until the user defines a
            // scope, everything is tunnelled and nothing is captured.
            policy: Arc::new(SharedPolicy::default()),
            project: Mutex::new(None),
            default_path,
        }
    }

    /// The decider handed to the proxy. It reads the *current* policy, so an
    /// edit applies to the next request, not to the next proxy start.
    pub fn decider(&self) -> Arc<dyn ScopeDecider> {
        self.policy.decider()
    }

    pub fn policy(&self) -> ScopePolicy {
        self.policy.get()
    }

    pub fn default_path(&self) -> &Path {
        &self.default_path
    }

    pub async fn project_status(&self) -> ProjectStatus {
        let guard = self.project.lock().await;
        self.status_with(guard.as_ref().map(|p| p.path.as_path()))
    }

    /// Create a new project file, seeded with the policy currently in force.
    pub async fn create_project(
        &self,
        path: PathBuf,
        passphrase: &str,
    ) -> Result<ProjectStatus, String> {
        if passphrase.is_empty() {
            return Err("a passphrase is required to encrypt the project".into());
        }
        let mut guard = self.project.lock().await;
        if guard.is_some() {
            return Err("a project is already open; close it first".into());
        }
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("creating {}: {e}", parent.display()))?;
            }
        }
        let store = Store::create(&path, passphrase).map_err(|e| e.to_string())?;

        // Persist the policy in force right now, so creating a project never
        // silently changes what gets captured.
        let encoded = serde_json::to_vec(&self.policy.get())
            .map_err(|e| format!("encoding the scope policy: {e}"))?;
        store
            .set_setting(SCOPE_KEY, &encoded)
            .map_err(|e| e.to_string())?;

        *guard = Some(Project {
            store,
            path: path.clone(),
        });
        Ok(self.status_with(Some(&path)))
    }

    /// Open an existing project file and adopt its stored policy.
    pub async fn open_project(
        &self,
        path: PathBuf,
        passphrase: &str,
    ) -> Result<ProjectStatus, String> {
        let mut guard = self.project.lock().await;
        if guard.is_some() {
            return Err("a project is already open; close it first".into());
        }
        let store = Store::open(&path, passphrase).map_err(|e| e.to_string())?;

        // A policy that cannot be decoded is a hard error: falling back to the
        // default would change what is captured without telling anyone.
        if let Some(bytes) = store.get_setting(SCOPE_KEY).map_err(|e| e.to_string())? {
            let policy: ScopePolicy = serde_json::from_slice(&bytes)
                .map_err(|e| format!("stored scope policy is unreadable: {e}"))?;
            self.policy.set(policy);
        }

        *guard = Some(Project {
            store,
            path: path.clone(),
        });
        Ok(self.status_with(Some(&path)))
    }

    /// Close the project. The live policy is left untouched: closing a project
    /// should not silently change what a running proxy captures.
    pub async fn close_project(&self) -> ProjectStatus {
        *self.project.lock().await = None;
        self.status_with(None)
    }

    /// Replace the live policy, persisting it when a project is open.
    ///
    /// Returns whether it was persisted (`false` = this session only).
    pub async fn set_policy(&self, policy: ScopePolicy) -> Result<bool, String> {
        // Write first: if persistence fails, the live policy stays as it was, so
        // what the proxy enforces still matches what is on disk.
        let guard = self.project.lock().await;
        let persisted = match guard.as_ref() {
            Some(project) => {
                let encoded = serde_json::to_vec(&policy)
                    .map_err(|e| format!("encoding the scope policy: {e}"))?;
                project
                    .store
                    .set_setting(SCOPE_KEY, &encoded)
                    .map_err(|e| e.to_string())?;
                true
            }
            None => false,
        };
        drop(guard);

        self.policy.set(policy);
        Ok(persisted)
    }

    fn status_with(&self, path: Option<&Path>) -> ProjectStatus {
        ProjectStatus {
            open: path.is_some(),
            path: path.map(|p| p.display().to_string()),
            default_path: self.default_path.display().to_string(),
        }
    }
}

/// An explicit path if the UI sent one, otherwise the default project file.
fn resolve_path(state: &ScopeState, path: Option<String>) -> PathBuf {
    match path {
        Some(p) if !p.trim().is_empty() => PathBuf::from(p.trim()),
        _ => state.default_path().to_path_buf(),
    }
}

#[tauri::command]
pub async fn project_status(state: State<'_, ScopeState>) -> Result<ProjectStatus, String> {
    Ok(state.project_status().await)
}

#[tauri::command]
pub async fn project_create(
    state: State<'_, ScopeState>,
    path: Option<String>,
    passphrase: String,
) -> Result<ProjectStatus, String> {
    let path = resolve_path(&state, path);
    state.create_project(path, &passphrase).await
}

#[tauri::command]
pub async fn project_open(
    state: State<'_, ScopeState>,
    path: Option<String>,
    passphrase: String,
) -> Result<ProjectStatus, String> {
    let path = resolve_path(&state, path);
    state.open_project(path, &passphrase).await
}

#[tauri::command]
pub async fn project_close(state: State<'_, ScopeState>) -> Result<ProjectStatus, String> {
    Ok(state.close_project().await)
}

#[tauri::command]
pub async fn scope_get(state: State<'_, ScopeState>) -> Result<ScopePolicy, String> {
    Ok(state.policy())
}

/// Replace the policy. Returns whether it was persisted to the project file.
#[tauri::command]
pub async fn scope_set(
    state: State<'_, ScopeState>,
    policy: ScopePolicy,
) -> Result<bool, String> {
    state.set_policy(policy).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use elliot_httpraw::ScopeDecision;

    fn state_in(dir: &std::path::Path) -> ScopeState {
        ScopeState::new(dir.join("project.elliot"))
    }

    #[tokio::test]
    async fn an_empty_policy_captures_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let state = state_in(dir.path());
        assert_eq!(
            state.decider().decide("https", "example.com", 443, "/"),
            ScopeDecision::Passthrough
        );
        assert!(!state.project_status().await.open);
    }

    #[tokio::test]
    async fn edits_apply_to_the_live_decider_and_survive_a_new_session() {
        let dir = tempfile::tempdir().unwrap();
        let state = state_in(dir.path());
        // The decider is obtained *before* the edits, like the proxy does.
        let decider = state.decider();
        assert_eq!(
            decider.decide("https", "example.com", 443, "/"),
            ScopeDecision::Passthrough
        );

        // Without a project the edit is live but session-only.
        let policy = ScopePolicy::host_suffix("example.com");
        assert!(!state.set_policy(policy.clone()).await.unwrap());
        assert_eq!(
            decider.decide("https", "example.com", 443, "/"),
            ScopeDecision::InScope
        );

        // With a project it is persisted too.
        let path = dir.path().join("project.elliot");
        let status = state.create_project(path.clone(), "correct horse").await.unwrap();
        assert!(status.open);
        assert!(state.set_policy(policy).await.unwrap());

        // A fresh session that opens the same file gets the same policy.
        let reopened = state_in(dir.path());
        reopened.open_project(path, "correct horse").await.unwrap();
        assert_eq!(reopened.policy(), ScopePolicy::host_suffix("example.com"));
        let decider = reopened.decider();
        assert_eq!(
            decider.decide("https", "api.example.com", 443, "/"),
            ScopeDecision::InScope
        );
        assert_eq!(
            decider.decide("https", "evil.com", 443, "/"),
            ScopeDecision::OutOfScope
        );
    }

    #[tokio::test]
    async fn creating_over_an_existing_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("project.elliot");
        state_in(dir.path())
            .create_project(path.clone(), "pw")
            .await
            .unwrap();

        // A different session must not adopt (and clobber) the same file.
        let other = state_in(dir.path());
        let err = other.create_project(path, "pw").await.unwrap_err();
        assert!(err.contains("already exists"), "got {err}");

        // And one session cannot hold two projects.
        let state = state_in(dir.path());
        state
            .create_project(dir.path().join("a.elliot"), "pw")
            .await
            .unwrap();
        assert!(state
            .create_project(dir.path().join("b.elliot"), "pw")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn a_wrong_passphrase_leaves_no_project_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("project.elliot");
        state_in(dir.path())
            .create_project(path.clone(), "right")
            .await
            .unwrap();

        let state = state_in(dir.path());
        assert!(state.open_project(path, "wrong").await.is_err());
        assert!(!state.project_status().await.open);
    }

    #[tokio::test]
    async fn an_empty_passphrase_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let err = state_in(dir.path())
            .create_project(dir.path().join("p.elliot"), "")
            .await
            .unwrap_err();
        assert!(err.contains("passphrase"), "got {err}");
    }
}
