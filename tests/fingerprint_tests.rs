use crashforge::crash::{classify, FingerprintStrength};
use crashforge::fingerprint::fingerprint;
use crashforge::runner::ExecutionResult;
use std::time::Duration;

fn result(stderr: &[u8], signal: Option<i32>, exit_code: Option<i32>) -> ExecutionResult {
    ExecutionResult {
        stdout: Vec::new(),
        stderr: stderr.to_vec(),
        exit_code,
        signal,
        timed_out: false,
        duration: Duration::from_millis(1),
    }
}

#[test]
fn normalizes_addresses_in_asan_fingerprints() {
    let first = result(
        b"ERROR: AddressSanitizer: heap-use-after-free\n#0 0x1234 in parse /tmp/a/parser.c:42\n",
        Some(11),
        None,
    );
    let second = result(
        b"ERROR: AddressSanitizer: heap-use-after-free\n#0 0xabcd in parse /other/path/parser.c:42\n",
        Some(11),
        None,
    );

    let first_observation = classify(&first).unwrap();
    let second_observation = classify(&second).unwrap();
    assert_eq!(first_observation.strength, FingerprintStrength::Diagnostic);
    assert_eq!(
        fingerprint(&first_observation),
        fingerprint(&second_observation)
    );
}

#[test]
fn distinguishes_different_signals() {
    let segv = classify(&result(b"", Some(11), None)).unwrap();
    let abort = classify(&result(b"", Some(6), None)).unwrap();
    assert_ne!(fingerprint(&segv), fingerprint(&abort));
}
