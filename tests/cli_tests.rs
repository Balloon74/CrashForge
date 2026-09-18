use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn help_lists_the_required_commands() {
    let output = Command::new(env!("CARGO_BIN_EXE_crashforge"))
        .arg("--help")
        .output()
        .unwrap();

    assert!(output.status.success());
    let help = String::from_utf8_lossy(&output.stdout);
    for command in ["run", "test", "inspect", "reproduce", "list"] {
        assert!(help.contains(command), "missing {command} in help: {help}");
    }
}

#[test]
fn runs_minimizes_stores_and_reproduces_a_c_crash() {
    let workspace = tempdir().unwrap();
    let program = workspace.path().join("segfault");
    let source = format!(
        "{}/examples/vulnerable-programs/segfault.c",
        env!("CARGO_MANIFEST_DIR")
    );
    let compile = Command::new("cc")
        .args(["-std=c11", "-O0", &source, "-o"])
        .arg(&program)
        .output()
        .unwrap();
    assert!(
        compile.status.success(),
        "{}",
        String::from_utf8_lossy(&compile.stderr)
    );

    let input = workspace.path().join("crash.txt");
    let contents = format!("{}CRASH\n{}", "noise\n".repeat(20), "tail\n".repeat(20));
    fs::write(&input, contents.as_bytes()).unwrap();
    let binary = env!("CARGO_BIN_EXE_crashforge");

    let run = Command::new(binary)
        .args(["run", "--max-runs", "1000"])
        .arg(&program)
        .arg(&input)
        .current_dir(workspace.path())
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let output = String::from_utf8_lossy(&run.stdout);
    for marker in ["CrashForge", "Confidence:", "executions", "Saved:"] {
        assert!(
            output.contains(marker),
            "missing {marker} in output: {output}"
        );
    }
    for marker in ["Verified:", "Saved:"] {
        assert!(
            output.lines().any(|line| line.starts_with(marker)),
            "missing marker-first {marker} line in output: {output}"
        );
    }
    let id = output
        .lines()
        .find_map(|line| line.strip_prefix("Fingerprint: "))
        .unwrap()
        .trim()
        .to_string();
    let case = workspace.path().join(".crashforge/crashes").join(&id);
    let minimized = fs::read(case.join("minimized.txt")).unwrap();
    assert!(minimized.len() < contents.len());
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(case.join("crash.json")).unwrap()).unwrap();
    assert_eq!(
        manifest["original_size"],
        manifest["stats"]["original_size"]
    );
    assert_eq!(
        manifest["minimized_size"],
        manifest["stats"]["minimized_size"]
    );
    assert!(manifest["stats"]["minimization_runs"].as_u64().unwrap() > 0);
    assert!(manifest["stats"]["minimization_ms"].is_number());

    for arguments in [
        vec!["reproduce".into(), id.clone()],
        vec!["inspect".into(), id.clone()],
        vec!["list".into()],
        vec!["test".into()],
    ] {
        let command = Command::new(binary)
            .args(arguments)
            .current_dir(workspace.path())
            .output()
            .unwrap();
        assert!(
            command.status.success(),
            "command failed: {}",
            String::from_utf8_lossy(&command.stderr)
        );
    }
}

#[test]
fn rejects_a_target_that_does_not_fail() {
    let workspace = tempdir().unwrap();
    let input = workspace.path().join("input.txt");
    fs::write(&input, b"safe").unwrap();

    let command = Command::new(env!("CARGO_BIN_EXE_crashforge"))
        .args(["run", "/bin/cat"])
        .arg(&input)
        .current_dir(workspace.path())
        .output()
        .unwrap();
    assert!(!command.status.success());
    assert!(String::from_utf8_lossy(&command.stderr).contains("did not produce a crash"));
}

#[test]
fn reproduces_v0_1_signal_cases_and_selects_the_algorithm_from_manifest_metadata() {
    use crashforge::runner::{run, RunOptions, Target};
    use std::time::Duration;

    let workspace = tempdir().unwrap();
    let program = workspace.path().join("segfault");
    let compile = Command::new("cc")
        .args(["-std=c11", "-O0"])
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/examples/vulnerable-programs/segfault.c"
        ))
        .arg("-o")
        .arg(&program)
        .output()
        .unwrap();
    assert!(
        compile.status.success(),
        "{}",
        String::from_utf8_lossy(&compile.stderr)
    );

    // v0.1 SHA-256 canonical bytes: "signal:SIGSEGV:11\nsignal=SIGSEGV\n".
    // A literal historical ID ensures the test cannot mirror today's implementation.
    let id = "CF-1057a891";
    let case = workspace.path().join(".crashforge/crashes").join(id);
    fs::create_dir_all(&case).unwrap();
    fs::write(case.join("minimized.txt"), b"CRASH").unwrap();
    fs::write(case.join("original.txt"), b"CRASH").unwrap();
    let execution = run(
        &Target {
            program: program.clone(),
            input: case.join("minimized.txt"),
            working_dir: workspace.path().to_path_buf(),
        },
        &RunOptions {
            timeout: Duration::from_secs(1),
        },
    )
    .unwrap();
    assert_eq!(execution.signal, Some(11));
    assert!(execution.stderr.is_empty());

    let mut manifest = serde_json::json!({
        "id": id,
        "signal": "SIGSEGV",
        "crash_kind": "signal",
        "fingerprint_strength": "SignalFallback",
        "original_size": 5,
        "minimized_size": 5,
        "program": program,
        "working_directory": workspace.path(),
        "timeout_ms": 5000,
        "status": "active"
    });
    for (strength, confidence, succeeds) in [
        ("SignalFallback", None, true),
        ("Diagnostic", None, true),
        ("SignalFallback", Some("Low"), false),
        ("Diagnostic", Some("High"), false),
        ("Low", None, false),
    ] {
        manifest["fingerprint_strength"] = strength.into();
        manifest
            .as_object_mut()
            .unwrap()
            .remove("fingerprint_confidence");
        if let Some(confidence) = confidence {
            manifest["fingerprint_confidence"] = confidence.into();
        }
        fs::write(
            case.join("crash.json"),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        for arguments in [vec!["reproduce", id], vec!["test"]] {
            let output = Command::new(env!("CARGO_BIN_EXE_crashforge"))
                .args(&arguments)
                .current_dir(workspace.path())
                .output()
                .unwrap();
            assert_eq!(output.status.success(), succeeds,
                "{arguments:?} strength={strength} confidence={confidence:?}\nstdout: {}\nstderr: {}",
                String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
        }
    }
}
