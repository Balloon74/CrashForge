use crashforge::storage::{list_cases, load_case, save_case, CrashManifest, MinimizationStats};
use std::collections::BTreeSet;
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
        stats: MinimizationStats {
            original_size: 10,
            minimized_size: 4,
            reduction_percent: 60.0,
            minimization_runs: 7,
            minimization_ms: 42,
        },
        fingerprint_confidence: Some("high".into()),
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
    let names = std::fs::read_dir(&case_path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        names,
        BTreeSet::from([
            "crash.json".to_string(),
            "minimized.txt".to_string(),
            "original.txt".to_string(),
            "reproduce.sh".to_string(),
        ])
    );
    assert!(std::fs::read_dir(root.path().join("crashes"))
        .unwrap()
        .all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".case-")));
    assert_eq!(load_case(root.path(), &manifest.id).unwrap(), manifest);
    assert_eq!(list_cases(root.path()).unwrap(), vec![manifest.clone()]);
    assert!(save_case(root.path(), &manifest, b"new", b"new").is_err());
    assert_eq!(
        std::fs::read(case_path.join("original.txt")).unwrap(),
        b"original"
    );
}

#[test]
fn deserializes_v0_1_manifest_with_default_statistics_and_confidence() {
    let manifest: CrashManifest = serde_json::from_str(
        r#"{
            "id": "CF-deadbeef",
            "signal": "SIGSEGV",
            "crash_kind": "signal",
            "fingerprint_strength": "SignalFallback",
            "original_size": 10,
            "minimized_size": 4,
            "program": "/tmp/program",
            "working_directory": "/tmp",
            "timeout_ms": 5000,
            "status": "active"
        }"#,
    )
    .unwrap();

    assert_eq!(manifest.stats, MinimizationStats::default());
    assert_eq!(manifest.fingerprint_confidence, None);
}
