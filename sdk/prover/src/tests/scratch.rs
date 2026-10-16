//! A temporary directory for a test's files. Also compiled into `pico-cli`'s integration tests by
//! path, which cannot reach this crate's test modules.

use std::path::{Path, PathBuf};

/// Removed when dropped by a passing test. A failing one keeps it and says where: the failure
/// message points at its files, and a heavy run is too slow to repeat just to look at them.
pub(super) struct ScratchDir(PathBuf);

impl std::ops::Deref for ScratchDir {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}

impl AsRef<Path> for ScratchDir {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!("kept {} for the failure above", self.0.display());
        } else {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

/// A directory named for the package, `tag` and this process.
pub(super) fn scratch_dir(tag: &str) -> ScratchDir {
    let package = env!("CARGO_PKG_NAME").replace('-', "_");
    let dir = std::env::temp_dir().join(format!("{package}_{tag}_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    ScratchDir(dir)
}
