use crashforge::crash::{classify, FingerprintConfidence};
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
    assert_eq!(first_observation.confidence, FingerprintConfidence::High);
    assert_eq!(
        fingerprint(&first_observation),
        fingerprint(&second_observation)
    );
}

#[test]
fn asan_type_and_stable_frames_are_high_confidence_and_address_independent() {
    let first = result(
        b"ERROR: AddressSanitizer: heap-use-after-free\n#0 0x1234 in parse /tmp/a/parser.c:42\n#1 0x5678 in main /tmp/a/main.c:10\n",
        Some(11),
        None,
    );
    let second = result(
        b"runtime note\nERROR: AddressSanitizer: heap-use-after-free\n#0 0xabcd in parse /other/parser.c:99\n#1 0xef01 in main /other/main.c:20\n",
        Some(11),
        None,
    );

    let first_observation = classify(&first).unwrap();
    let second_observation = classify(&second).unwrap();

    assert_eq!(first_observation.confidence, FingerprintConfidence::High);
    assert_eq!(second_observation.confidence, FingerprintConfidence::High);
    assert_eq!(
        fingerprint(&first_observation),
        fingerprint(&second_observation)
    );
}

#[test]
fn same_signal_with_stable_frames_is_medium_and_prose_independent() {
    let first = result(
        b"first prose\n#0 0x1234 in parse /tmp/a/parser.c:42\n#1 0x5678 in main /tmp/a/main.c:10\n",
        Some(11),
        None,
    );
    let second = result(
        b"different prose\n#0 0xabcd in parse /other/parser.c:99\n#1 0xef01 in main /other/main.c:20\n",
        Some(11),
        None,
    );

    let first_observation = classify(&first).unwrap();
    let second_observation = classify(&second).unwrap();

    assert_eq!(first_observation.confidence, FingerprintConfidence::Medium);
    assert_eq!(second_observation.confidence, FingerprintConfidence::Medium);
    assert_eq!(
        fingerprint(&first_observation),
        fingerprint(&second_observation)
    );
}

#[test]
fn signal_only_is_low_and_ignores_stderr() {
    let first_observation = classify(&result(b"one diagnostic", Some(11), None)).unwrap();
    let second_observation = classify(&result(b"another diagnostic", Some(11), None)).unwrap();

    assert_eq!(first_observation.confidence, FingerprintConfidence::Low);
    assert_eq!(second_observation.confidence, FingerprintConfidence::Low);
    assert_eq!(
        fingerprint(&first_observation),
        fingerprint(&second_observation)
    );
}

#[test]
fn different_stable_frame_sequences_have_different_fingerprints() {
    let first = classify(&result(
        b"#0 0x1234 in parse /tmp/parser.c:42\n",
        Some(11),
        None,
    ))
    .unwrap();
    let second = classify(&result(
        b"#0 0x1234 in render /tmp/parser.c:42\n",
        Some(11),
        None,
    ))
    .unwrap();

    assert_ne!(fingerprint(&first), fingerprint(&second));
}

#[test]
fn sanitizer_without_stable_frames_uses_signal_as_low_confidence_identity() {
    let first = classify(&result(
        b"ERROR: AddressSanitizer: heap-use-after-free\nfirst detail\n",
        Some(11),
        None,
    ))
    .unwrap();
    let second = classify(&result(
        b"ERROR: AddressSanitizer: stack-use-after-return\nsecond detail\n",
        Some(11),
        None,
    ))
    .unwrap();

    assert_eq!(first.confidence, FingerprintConfidence::Low);
    assert_eq!(second.confidence, FingerprintConfidence::Low);
    assert_eq!(fingerprint(&first), fingerprint(&second));
}

#[test]
fn stable_frames_beyond_the_first_thirty_two_still_affect_fingerprint() {
    let mut first_stderr = String::new();
    let mut second_stderr = String::new();
    for frame in 0..34 {
        let first_function = if frame == 33 { "first" } else { "same" };
        let second_function = if frame == 33 { "second" } else { "same" };
        first_stderr.push_str(&format!("#{frame} in {first_function} /tmp/parser.c:42\n"));
        second_stderr.push_str(&format!("#{frame} in {second_function} /tmp/parser.c:42\n"));
    }

    let first = classify(&result(first_stderr.as_bytes(), Some(11), None)).unwrap();
    let second = classify(&result(second_stderr.as_bytes(), Some(11), None)).unwrap();

    assert_ne!(fingerprint(&first), fingerprint(&second));
}

#[test]
fn punctuation_adjacent_instruction_addresses_are_ignored() {
    let first = classify(&result(
        b"#0 0x1234, in parse /tmp/parser.c:42\n",
        Some(11),
        None,
    ))
    .unwrap();
    let second = classify(&result(
        b"#0 0xabcd, in parse /tmp/parser.c:42\n",
        Some(11),
        None,
    ))
    .unwrap();

    assert_eq!(fingerprint(&first), fingerprint(&second));
}

#[test]
fn distinguishes_different_signals() {
    let segv = classify(&result(b"", Some(11), None)).unwrap();
    let abort = classify(&result(b"", Some(6), None)).unwrap();
    assert_ne!(fingerprint(&segv), fingerprint(&abort));
}
