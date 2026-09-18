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
    let id = output
        .lines()
        .find_map(|line| line.strip_prefix("Fingerprint: "))
        .unwrap()
        .trim()
        .to_string();
    let case = workspace.path().join(".crashforge/crashes").join(&id);
    let minimized = fs::read(case.join("minimized.txt")).unwrap();
    assert!(minimized.len() < contents.len());

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
