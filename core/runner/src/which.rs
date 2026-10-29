//! Minimal `PATH` lookup, kept in its own module so `lib.rs` stays focused on
//! validation logic.
//!
//! Deliberately not a dependency on a `which` crate: the lookup is a handful of
//! lines, and the execution side of the trust boundary should keep as small a
//! dependency surface as possible.

use std::path::{Path, PathBuf};

/// Locate `bin` the way the OS would: an explicit path is checked directly,
/// otherwise each `PATH` entry is scanned for an executable file.
pub fn find_in_path(bin: &str) -> Option<PathBuf> {
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
