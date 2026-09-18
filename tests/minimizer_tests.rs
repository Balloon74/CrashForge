use crashforge::minimizer::{minimize, MinimizerLimits};
use std::time::{Duration, Instant};

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
    // Exercise the early line-phase return and exhaustion in the byte phase.
    for input in [b"abcdef".as_slice(), b"abcdef\n".as_slice()] {
        let mut predicate_elapsed = Duration::ZERO;
        let result = minimize(input, MinimizerLimits { max_runs: 1 }, |_| {
            let started = Instant::now();
            std::thread::sleep(Duration::from_millis(2));
            predicate_elapsed += started.elapsed();
            false
        });

        assert!(!result.complete);
        assert_eq!(result.runs, 1);
        assert_eq!(result.bytes, input);
        assert!(predicate_elapsed > Duration::ZERO);
        assert!(result.elapsed >= predicate_elapsed);
    }
}

#[test]
fn reports_elapsed_time_and_preserves_a_required_prefix_and_suffix() {
    let input = b"HEAD-middle-TAIL";
    let preserves =
        |candidate: &[u8]| candidate.starts_with(b"HEAD") && candidate.ends_with(b"TAIL");
    assert!(preserves(input));
    let mut predicate_elapsed = Duration::ZERO;
    let result = minimize(input, MinimizerLimits { max_runs: 1000 }, |candidate| {
        let started = Instant::now();
        std::thread::sleep(Duration::from_millis(1));
        let accepted = preserves(candidate);
        predicate_elapsed += started.elapsed();
        accepted
    });

    assert!(result.complete);
    assert_eq!(result.bytes, b"HEADTAIL");
    assert!(predicate_elapsed > Duration::ZERO);
    assert!(result.elapsed >= predicate_elapsed);
}

#[test]
fn changing_outcomes_preserve_deterministic_candidates_results_and_budget() {
    // The same "cd" candidate first fails, then succeeds on its second visit.
    let candidates: &[&[u8]] = &[b"cd", b"ab", b"bcd", b"cd", b"d"];
    let outcomes = [false, false, true, true, false];
    for _ in 0..3 {
        for (budget, expected) in [(3, b"bcd".as_slice()), (5, b"cd".as_slice())] {
            let mut visited = Vec::new();
            let result = minimize(b"abcd", MinimizerLimits { max_runs: budget }, |candidate| {
                let index = visited.len();
                assert!(index < budget, "predicate exceeded run budget");
                assert_eq!(candidate, candidates[index]);
                visited.push(candidate.to_vec());
                outcomes[index]
            });
            assert_eq!(visited, candidates[..budget]);
            assert_eq!(result.bytes, expected);
            assert_eq!(result.runs, budget);
            assert!(!result.complete);
        }
    }
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
