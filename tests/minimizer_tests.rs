use crashforge::minimizer::{minimize, MinimizerLimits};

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
