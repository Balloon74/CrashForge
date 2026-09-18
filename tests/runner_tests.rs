use crashforge::runner::{run, RunOptions, Target};
use std::fs;
use std::process::Command;
use std::time::Duration;
use tempfile::tempdir;

#[test]
fn captures_output_and_exit_code() {
    let directory = tempdir().unwrap();
    let input = directory.path().join("input.txt");
    fs::write(&input, b"hello\n").unwrap();

    let result = run(
        &Target {
            program: "/bin/cat".into(),
            input,
            working_dir: directory.path().to_path_buf(),
        },
        &RunOptions {
            timeout: Duration::from_secs(1),
        },
    )
    .unwrap();

    assert_eq!(result.exit_code, Some(0));
    assert_eq!(result.signal, None);
    assert_eq!(result.stdout, b"hello\n");
    assert!(!result.timed_out);
}

#[test]
fn kills_a_timed_out_process() {
    let directory = tempdir().unwrap();
    let input = directory.path().join("input.txt");
    fs::write(&input, b"sleep 10\n").unwrap();

    let result = run(
        &Target {
            program: "/bin/sh".into(),
            input,
            working_dir: directory.path().to_path_buf(),
        },
        &RunOptions {
            timeout: Duration::from_millis(20),
        },
    )
    .unwrap();

    assert!(result.timed_out);
    assert!(result.duration < Duration::from_secs(1));
}

#[test]
fn decodes_a_signal_from_a_native_target() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("crash.c");
    let program = directory.path().join("crash");
    let input = directory.path().join("input.txt");
    fs::write(
        &source,
        b"int main(void) { *(volatile int *)0 = 1; return 0; }\n",
    )
    .unwrap();
    fs::write(&input, b"input").unwrap();
    let compile = Command::new("cc")
        .arg(&source)
        .arg("-o")
        .arg(&program)
        .output()
        .unwrap();
    assert!(
        compile.status.success(),
        "{}",
        String::from_utf8_lossy(&compile.stderr)
    );

    let result = run(
        &Target {
            program,
            input,
            working_dir: directory.path().to_path_buf(),
        },
        &RunOptions {
            timeout: Duration::from_secs(1),
        },
    )
    .unwrap();

    assert_eq!(result.signal, Some(11));
    assert_eq!(result.exit_code, None);
}
