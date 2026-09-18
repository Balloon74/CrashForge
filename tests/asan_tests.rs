use crashforge::crash::{classify, FingerprintConfidence};
use crashforge::fingerprint::fingerprint;
use crashforge::runner::{run, RunOptions, Target};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;
use tempfile::tempdir;

fn repository() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn compile(source: &Path, program: &Path, asan: bool) -> Output {
    let mut command = Command::new("cc");
    command
        .arg("-std=c11")
        .arg("-Wall")
        .arg("-Wextra")
        .arg("-O0");
    if asan {
        command
            .arg("-fsanitize=address")
            .arg("-fno-omit-frame-pointer")
            .arg("-g");
    }
    command.arg(source).arg("-o").arg(program).output().unwrap()
}

fn run_fixture(
    program: PathBuf,
    input: PathBuf,
    working_dir: PathBuf,
) -> crashforge::runner::ExecutionResult {
    run(
        &Target {
            program,
            input,
            working_dir,
        },
        &RunOptions {
            timeout: Duration::from_secs(1),
        },
    )
    .unwrap()
}

fn asan_supported(directory: &Path) -> bool {
    let source = directory.join("asan-capability-probe.c");
    let program = directory.join("asan-capability-probe");
    fs::write(&source, "int main(void) { return 0; }\n").unwrap();
    let output = compile(&source, &program, true);
    if output.status.success() {
        true
    } else {
        eprintln!(
            "SKIP: cc rejected -fsanitize=address; AddressSanitizer coverage is unavailable on this toolchain:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        false
    }
}

fn assert_fixture_compiled(fixture: &str, output: &Output) {
    assert!(
        output.status.success(),
        "{fixture} did not compile with AddressSanitizer:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn asan_capability_probe_is_independent_of_fixture_compilation_errors() {
    let directory = tempdir().unwrap();
    let invalid_fixture = directory.path().join("invalid-fixture.c");
    fs::write(&invalid_fixture, "#error simulated fixture failure\n").unwrap();
    let fixture_output = compile(
        &invalid_fixture,
        &directory.path().join("invalid-fixture"),
        true,
    );
    assert!(!fixture_output.status.success());

    let valid_probe = directory.path().join("valid-probe.c");
    fs::write(&valid_probe, "int main(void) { return 0; }\n").unwrap();
    let probe_output = compile(&valid_probe, &directory.path().join("valid-probe"), true);
    if !probe_output.status.success() {
        eprintln!(
            "SKIP: cc rejected -fsanitize=address; AddressSanitizer coverage is unavailable on this toolchain:\n{}",
            String::from_utf8_lossy(&probe_output.stderr)
        );
        return;
    }

    assert!(
        asan_supported(directory.path()),
        "a fixture compilation error must not make AddressSanitizer coverage skip"
    );
}

#[test]
fn asan_observations_are_high_confidence_and_stable_across_runs() {
    let repository = repository();
    let directory = tempdir().unwrap();
    if !asan_supported(directory.path()) {
        return;
    }
    let fixtures = [
        ("buffer_overflow", "buffer_overflow.txt"),
        ("use_after_free", "use_after_free.txt"),
    ];

    for (fixture, input) in fixtures {
        let source = repository
            .join("examples/vulnerable-programs")
            .join(format!("{fixture}.c"));
        let program = directory.path().join(fixture);
        let compilation = compile(&source, &program, true);
        assert_fixture_compiled(fixture, &compilation);

        let input = repository
            .join("examples/vulnerable-programs/inputs")
            .join(input);
        let first_result = run_fixture(
            program.clone(),
            input.clone(),
            directory.path().to_path_buf(),
        );
        let second_result = run_fixture(program, input, directory.path().to_path_buf());
        let first_observation = classify(&first_result)
            .unwrap_or_else(|| panic!("{fixture} did not produce a crash observation"));
        let second_observation = classify(&second_result)
            .unwrap_or_else(|| panic!("{fixture} did not produce a crash observation"));

        assert_eq!(first_observation.kind, second_observation.kind);
        assert_eq!(first_observation.confidence, FingerprintConfidence::High);
        assert_eq!(
            fingerprint(&first_observation),
            fingerprint(&second_observation)
        );
    }
}

#[test]
fn examples_asan_target_builds_sanitizer_fixtures() {
    let repository = repository();
    let directory = tempdir().unwrap();
    if !asan_supported(directory.path()) {
        return;
    }

    let programs = [
        repository.join("target/examples-asan/buffer_overflow"),
        repository.join("target/examples-asan/use_after_free"),
    ];
    for program in &programs {
        match fs::remove_file(program) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("could not remove {}: {error}", program.display()),
        }
    }

    let build = Command::new("make")
        .arg("examples-asan")
        .current_dir(&repository)
        .output()
        .unwrap();
    assert!(
        build.status.success(),
        "make examples-asan failed:\n{}",
        String::from_utf8_lossy(&build.stderr)
    );
    for program in programs {
        assert!(
            program.is_file(),
            "make examples-asan did not create {}",
            program.display()
        );
    }
}

#[test]
fn adversarial_fixtures_crash_only_for_the_documented_byte_relationships() {
    let repository = repository();
    let directory = tempdir().unwrap();
    let fixtures = [
        (
            "relational_crash",
            "relational.txt",
            b"RIGHT LEFT".as_slice(),
        ),
        ("binary_crash", "binary.bin", b"CF!\0".as_slice()),
    ];

    for (fixture, trigger_input, non_trigger_input) in fixtures {
        let source = repository
            .join("examples/vulnerable-programs")
            .join(format!("{fixture}.c"));
        let program = directory.path().join(fixture);
        let compilation = compile(&source, &program, false);
        assert!(
            compilation.status.success(),
            "{fixture} did not compile:\n{}",
            String::from_utf8_lossy(&compilation.stderr)
        );

        let trigger_result = run_fixture(
            program.clone(),
            repository
                .join("examples/vulnerable-programs/inputs")
                .join(trigger_input),
            directory.path().to_path_buf(),
        );
        assert_eq!(trigger_result.signal, Some(6), "{fixture} did not abort");

        let non_trigger_path = directory.path().join(format!("{fixture}-non-trigger"));
        std::fs::write(&non_trigger_path, non_trigger_input).unwrap();
        let non_trigger_result =
            run_fixture(program, non_trigger_path, directory.path().to_path_buf());
        assert_eq!(
            non_trigger_result.exit_code,
            Some(0),
            "{fixture} crashed without its documented byte relationship"
        );
    }
}
