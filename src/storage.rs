use crate::error::{CrashForgeError, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::Builder;

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct MinimizationStats {
    pub original_size: usize,
    pub minimized_size: usize,
    pub reduction_percent: f64,
    pub minimization_runs: usize,
    pub minimization_ms: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CrashManifest {
    pub id: String,
    pub signal: Option<String>,
    pub crash_kind: String,
    pub fingerprint_strength: String,
    pub original_size: usize,
    pub minimized_size: usize,
    #[serde(default)]
    pub stats: MinimizationStats,
    #[serde(default)]
    pub fingerprint_confidence: Option<String>,
    pub program: PathBuf,
    pub working_directory: PathBuf,
    pub timeout_ms: u64,
    pub status: String,
}

pub fn save_case(
    root: &Path,
    manifest: &CrashManifest,
    original: &[u8],
    minimized: &[u8],
) -> Result<PathBuf> {
    validate_id(&manifest.id)?;
    let crashes = root.join("crashes");
    fs::create_dir_all(&crashes)?;

    let temporary = Builder::new().prefix(".case-").tempdir_in(&crashes)?;
    fs::write(temporary.path().join("original.txt"), original)?;
    fs::write(temporary.path().join("minimized.txt"), minimized)?;
    fs::write(
        temporary.path().join("crash.json"),
        serde_json::to_vec_pretty(manifest)?,
    )?;
    let script = reproduce_script(manifest);
    fs::write(temporary.path().join("reproduce.sh"), script)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(temporary.path().join("reproduce.sh"))?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(temporary.path().join("reproduce.sh"), permissions)?;
    }

    let destination = crashes.join(&manifest.id);
    if let Err(error) = rename_directory_no_replace(temporary.path(), &destination) {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            return Err(CrashForgeError::Collision(destination));
        }
        return Err(error.into());
    }

    Ok(destination)
}

pub fn load_case(root: &Path, id: &str) -> Result<CrashManifest> {
    validate_id(id)?;
    let path = root.join("crashes").join(id).join("crash.json");
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

pub fn list_cases(root: &Path) -> Result<Vec<CrashManifest>> {
    let crashes = root.join("crashes");
    if !crashes.exists() {
        return Ok(Vec::new());
    }

    let mut cases = Vec::new();
    for entry in fs::read_dir(crashes)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            let manifest_path = entry.path().join("crash.json");
            if manifest_path.exists() {
                cases.push(serde_json::from_slice(&fs::read(manifest_path)?)?);
            }
        }
    }
    cases.sort_by(|left: &CrashManifest, right: &CrashManifest| left.id.cmp(&right.id));
    Ok(cases)
}

pub fn case_directory(root: &Path, id: &str) -> Result<PathBuf> {
    validate_id(id)?;
    Ok(root.join("crashes").join(id))
}

fn validate_id(id: &str) -> Result<()> {
    if id.starts_with("CF-")
        && id.len() == 11
        && id[3..]
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        Ok(())
    } else {
        Err(crate::error::message(format!("invalid crash id: {id}")))
    }
}

fn reproduce_script(manifest: &CrashManifest) -> String {
    format!(
        "#!/bin/sh\nset -eu\nCASE_DIR=$(CDPATH= cd -- \"$(dirname -- \"$0\")\" && pwd)\ncd -- {}\nexec {} \"$CASE_DIR/minimized.txt\"\n",
        shell_quote(&manifest.working_directory.display().to_string()),
        shell_quote(&manifest.program.display().to_string()),
    )
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn rename_directory_no_replace(source: &Path, destination: &Path) -> std::io::Result<()> {
    let source = c_path(source)?;
    let destination = c_path(destination)?;

    #[cfg(target_os = "linux")]
    let status = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };

    #[cfg(target_os = "macos")]
    let status =
        unsafe { libc::renamex_np(source.as_ptr(), destination.as_ptr(), libc::RENAME_EXCL) };

    if status == 0 {
        Ok(())
    } else {
        Err(collision_or_io(std::io::Error::last_os_error()))
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn c_path(path: &Path) -> std::io::Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;

    std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn collision_or_io(error: std::io::Error) -> std::io::Error {
    match error.raw_os_error() {
        Some(libc::EEXIST | libc::ENOTEMPTY) => {
            std::io::Error::new(std::io::ErrorKind::AlreadyExists, error)
        }
        _ => error,
    }
}

#[cfg(test)]
mod tests {
    use super::rename_directory_no_replace;
    use std::fs;
    use std::io::ErrorKind;
    use tempfile::tempdir;

    #[test]
    fn exclusive_directory_rename_preserves_an_existing_populated_destination() {
        let root = tempdir().unwrap();
        let source = root.path().join("source");
        let destination = root.path().join("destination");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("source.txt"), b"source").unwrap();
        fs::create_dir(&destination).unwrap();
        fs::write(destination.join("destination.txt"), b"destination").unwrap();

        let error = rename_directory_no_replace(&source, &destination).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::AlreadyExists);
        assert_eq!(fs::read(source.join("source.txt")).unwrap(), b"source");
        assert_eq!(
            fs::read(destination.join("destination.txt")).unwrap(),
            b"destination"
        );
    }

    #[test]
    fn exclusive_directory_rename_preserves_an_existing_empty_destination() {
        let root = tempdir().unwrap();
        let source = root.path().join("source");
        let destination = root.path().join("destination");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("source.txt"), b"source").unwrap();
        fs::create_dir(&destination).unwrap();

        let error = rename_directory_no_replace(&source, &destination).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::AlreadyExists);
        assert_eq!(fs::read(source.join("source.txt")).unwrap(), b"source");
        assert!(destination.is_dir());
        assert_eq!(fs::read_dir(&destination).unwrap().count(), 0);
    }
}
