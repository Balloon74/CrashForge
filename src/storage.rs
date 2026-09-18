use crate::error::{CrashForgeError, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::Builder;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CrashManifest {
    pub id: String,
    pub signal: Option<String>,
    pub crash_kind: String,
    pub fingerprint_strength: String,
    pub original_size: usize,
    pub minimized_size: usize,
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
    match fs::create_dir(&destination) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(CrashForgeError::Collision(destination));
        }
        Err(error) => return Err(error.into()),
    }

    for filename in [
        "original.txt",
        "minimized.txt",
        "crash.json",
        "reproduce.sh",
    ] {
        fs::rename(temporary.path().join(filename), destination.join(filename))?;
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
