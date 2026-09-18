use crashforge::minimizer::{minimize, MinimizerLimits};
use std::time::Duration;

#[test]
fn reduces_to_the_smallest_line_preserving_the_predicate() {
    let input = b"noise one\nCRASH\nnoise two\n";
    let result = minimize(input, MinimizerLimits { max_runs: 1000 }, |candidate| {
        candidate
            .windows(b"CRASH".len())
            .any(|window| window == b"CRASH")
    });

    assert!(result.complete);
    assert_eq!(result.bytes, b"CRASH");
    assert!(result.bytes.len() < input.len());
}

#[test]
fn observes_the_execution_budget() {
    let result = minimize(b"abcdef", MinimizerLimits { max_runs: 1 }, |_| false);

    assert!(!result.complete);
    assert_eq!(result.runs, 1);
}

#[test]
fn reports_elapsed_time_and_preserves_a_required_prefix_and_suffix() {
    let result = minimize(
        b"noise-HEAD-middle-TAIL-noise",
        MinimizerLimits { max_runs: 1000 },
        |candidate| {
            candidate
                .windows(b"HEAD".len())
                .any(|window| window == b"HEAD")
                && candidate
                    .windows(b"TAIL".len())
                    .any(|window| window == b"TAIL")
        },
    );

    assert!(result.complete);
    assert_eq!(result.bytes, b"HEADTAIL");
    assert!(result.elapsed >= Duration::ZERO);
}

#[test]
fn preserves_ordered_bytes_at_a_required_offset() {
    let result = minimize(
        b"xxx012345-suffix",
        MinimizerLimits { max_runs: 1000 },
        |candidate| candidate.get(3..9) == Some(b"012345"),
    );

    assert!(result.complete);
    assert_eq!(result.bytes, b"xxx012345");
}

#[test]
fn preserves_multiple_required_lines() {
    let result = minimize(
        b"noise one\nKEEP ONE\nnoise two\nKEEP TWO\nnoise three\n",
        MinimizerLimits { max_runs: 1000 },
        |candidate| {
            candidate
                .windows(b"KEEP ONE\nKEEP TWO\n".len())
                .any(|window| window == b"KEEP ONE\nKEEP TWO\n")
        },
    );

    assert!(result.complete);
    assert_eq!(result.bytes, b"KEEP ONE\nKEEP TWO\n");
}

#[test]
fn preserves_embedded_nul_bytes() {
    let result = minimize(
        b"noise\0\0REQUIRED\0tail",
        MinimizerLimits { max_runs: 1000 },
        |candidate| {
            candidate
                .windows(b"\0\0REQUIRED\0".len())
                .any(|window| window == b"\0\0REQUIRED\0")
        },
    );

    assert!(result.complete);
    assert_eq!(result.bytes, b"\0\0REQUIRED\0");
}

#[test]
fn minimizes_a_large_input_to_its_required_region() {
    let mut input = vec![b'x'; 1024 * 1024];
    let required_start = 500_000;
    let required = b"0123456789abcdefghij";
    input[required_start..required_start + required.len()].copy_from_slice(required);

    let result = minimize(&input, MinimizerLimits { max_runs: 5000 }, |candidate| {
        candidate
            .windows(required.len())
            .any(|window| window == required)
    });

    assert!(result.complete);
    assert_eq!(result.bytes, required);
}
