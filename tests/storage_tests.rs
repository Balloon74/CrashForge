use crashforge::storage::{list_cases, load_case, save_case, CrashManifest};
use std::path::PathBuf;
use tempfile::tempdir;

fn manifest() -> CrashManifest {
    CrashManifest {
        id: "CF-deadbeef".into(),
        signal: Some("SIGSEGV".into()),
        crash_kind: "signal".into(),
        fingerprint_strength: "SignalFallback".into(),
        original_size: 10,
        minimized_size: 4,
        program: PathBuf::from("/tmp/program"),
        working_directory: PathBuf::from("/tmp"),
        timeout_ms: 5000,
        status: "active".into(),
    }
}

#[test]
fn saves_and_loads_a_case_without_overwriting_it() {
    let root = tempdir().unwrap();
    let manifest = manifest();
    let case_path = save_case(root.path(), &manifest, b"original", b"mini").unwrap();

    assert_eq!(
        std::fs::read(case_path.join("original.txt")).unwrap(),
        b"original"
    );
    assert_eq!(load_case(root.path(), &manifest.id).unwrap(), manifest);
    assert_eq!(list_cases(root.path()).unwrap(), vec![manifest.clone()]);
    assert!(save_case(root.path(), &manifest, b"new", b"new").is_err());
}
