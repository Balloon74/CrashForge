use crashforge::crash::{classify, FingerprintConfidence};
use crashforge::fingerprint::{fingerprint, legacy_fingerprint};
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

#[test]
fn frameless_asan_without_a_signal_ignores_signal_prose() {
    let observe = |details: &str| {
        classify(&result(
            format!("ERROR: AddressSanitizer: heap-use-after-free\n{details}\n").as_bytes(),
            None,
            Some(1),
        ))
        .unwrap()
    };
    let first = observe("signal=SIGSEGV:11 arbitrary prose");
    let second = observe("signal=SIGABRT:6 unrelated prose");
    assert_eq!(first.confidence, FingerprintConfidence::Low);
    assert_eq!(fingerprint(&first), fingerprint(&second));
    assert_eq!(fingerprint(&first), fingerprint(&observe("no signal text")));
    let other_kind = classify(&result(
        b"ERROR: AddressSanitizer: stack-use-after-return\nsignal=SIGSEGV:11\n",
        None,
        Some(1),
    ))
    .unwrap();
    assert_ne!(fingerprint(&first), fingerprint(&other_kind));
}

#[test]
fn sanitizer_details_retain_the_v0_1_normalization_without_a_synthetic_signal_prefix() {
    let observation = classify(&result(
        b"ERROR: AddressSanitizer: heap-use-after-free\n",
        Some(11),
        None,
    ))
    .unwrap();
    assert_eq!(
        observation.normalized_details,
        "ERROR: AddressSanitizer: heap-use-after-free"
    );
}

#[test]
fn frameless_asan_uses_the_observed_signal_even_if_details_are_replaced() {
    for signal in [6, 11] {
        let mut observation = classify(&result(
            b"ERROR: AddressSanitizer: heap-use-after-free\nsignal=SIGILL:4\n",
            Some(signal),
            None,
        ))
        .unwrap();
        observation.normalized_details = "signal=SIGBUS:7\nother text".into();
        let signal_only = classify(&result(b"", Some(signal), None)).unwrap();
        assert_eq!(fingerprint(&observation), fingerprint(&signal_only));
    }
}

#[test]
fn stable_frames_preserve_complete_distinct_cpp_operator_symbols() {
    let observe = |symbol: &str| {
        classify(&result(
            format!("#0 0x1234 in {symbol} /tmp/parser.cpp:42:7\n").as_bytes(),
            Some(11),
            None,
        ))
        .unwrap()
    };
    let first = observe("A::operator/(int)");
    let second = observe("B::operator/(int)");
    assert_ne!(fingerprint(&first), fingerprint(&second));
    assert_eq!(
        first.stable_frames,
        ["frame:0 in A::operator/(int) parser.cpp"]
    );
    assert_ne!(
        fingerprint(&first),
        fingerprint(&observe("A::operator/=(int)"))
    );
    assert_ne!(
        fingerprint(&first),
        fingerprint(&observe("A::operator*(int)"))
    );
}

#[test]
fn relocated_source_and_module_paths_with_spaces_have_stable_identities() {
    for (first, second, expected) in [
        (
            "#0 0x1234 in parse(int) /tmp/build one/src/parser file.cpp:42:7",
            "#0 0xabcd in parse(int) /other/checkout two/src/parser file.cpp:90:2",
            "frame:0 in parse(int) parser file.cpp",
        ),
        (
            "#0 0x1234 (/tmp/build one/my program+0x123)",
            "#0 0xabcd (/other/checkout two/my program+0x123)",
            "frame:0 my program+0x123",
        ),
        (
            "#0 0x1234 in A::operator/(int) build one/src/parser file.cpp:42:7",
            "#0 0xabcd in A::operator/(int) checkout two/src/parser file.cpp:90:2",
            "frame:0 in A::operator/(int) parser file.cpp",
        ),
        (
            "#0 0x1234 in parse src/parser.cpp:42:7",
            "#0 0xabcd in parse other/parser.cpp:90:2",
            "frame:0 in parse parser.cpp",
        ),
    ] {
        let first = classify(&result(first.as_bytes(), Some(11), None)).unwrap();
        let second = classify(&result(second.as_bytes(), Some(11), None)).unwrap();
        assert_eq!(fingerprint(&first), fingerprint(&second));
        assert_eq!(first.stable_frames, [expected]);
    }
}

#[test]
fn relative_source_paths_with_spaces_do_not_change_the_fingerprint() {
    let first = classify(&result(
        b"#0 0x1234 in parse build one/src/parser file.cpp:42:7\n",
        Some(11),
        None,
    ))
    .unwrap();
    let second = classify(&result(
        b"#0 0xabcd in parse checkout two/src/parser file.cpp:90:2\n",
        Some(11),
        None,
    ))
    .unwrap();

    assert_eq!(fingerprint(&first), fingerprint(&second));
    assert_eq!(first.stable_frames, ["frame:0 in parse parser file.cpp"]);
}

#[test]
fn relative_module_function_qualifiers_remain_part_of_the_identity() {
    let observe = |qualifier: &str| {
        classify(&result(
            format!("#0 0x1234 in {qualifier} source tree/parser.cpp:42:7\n").as_bytes(),
            Some(11),
            None,
        ))
        .unwrap()
    };

    let frontend = observe("./frontend/parse");
    let backend = observe("./backend/parse");
    let relocated_frontend = classify(&result(
        b"#0 0xabcd in ./frontend/parse checkout tree/parser.cpp:90:2\n",
        Some(11),
        None,
    ))
    .unwrap();

    assert_eq!(fingerprint(&frontend), fingerprint(&relocated_frontend));
    assert_ne!(fingerprint(&frontend), fingerprint(&backend));
    assert_eq!(
        frontend.stable_frames,
        ["frame:0 in ./frontend/parse parser.cpp"]
    );
}

#[test]
fn legacy_fingerprints_match_v0_1_golden_ids_for_each_crash_kind() {
    // SHA-256 vectors derived from v0.1 (b495ae1), not from the helper under test.
    for (stderr, signal, exit_code, expected) in [
        ("", Some(11), None, "CF-1057a891"),
        (
            "ERROR: AddressSanitizer: heap-use-after-free\n",
            Some(11),
            None,
            "CF-f503dd6f",
        ),
        ("message", None, Some(2), "CF-a4bcbb78"),
    ] {
        let observation = classify(&result(stderr.as_bytes(), signal, exit_code)).unwrap();
        assert_eq!(legacy_fingerprint(&observation), expected);
    }
}
