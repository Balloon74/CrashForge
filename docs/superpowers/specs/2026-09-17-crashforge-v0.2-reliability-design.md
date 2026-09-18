# CrashForge v0.2 Reliability and Performance Design

## Goal

Make CrashForge's crash identity trustworthy enough for minimization and regression storage, while improving minimization performance, observability, fixture coverage, and persistence reliability without changing the v0.1 command model.

## Scope

This release covers eight connected improvements:

1. Confidence-aware crash fingerprints that do not hash arbitrary unsanitized stderr into a low-confidence signal identity.
2. Stable diagnostic/frame extraction for AddressSanitizer and unsanitized stack-bearing diagnostics.
3. Deterministic minimization statistics and lower-overhead candidate removal.
4. Adversarial minimization coverage, including binary/NUL and large-input cases.
5. ASan example builds and integration coverage for UAF and buffer-overflow diagnostics.
6. Persisted minimization statistics and compatibility with existing v0.1 manifests.
7. Atomic case-directory publication.
8. Compiler-style CLI reporting for detection, minimization, verification, and storage.

The release does not add debugger integration, parallel candidate execution, fuzzing, AI assistance, network services, GitHub Actions, or a new command-line workflow.

## Design

### Confidence-aware fingerprinting

`CrashObservation` will carry a confidence enum with three serialized/displayed values: `High`, `Medium`, and `Low`.

- High: an AddressSanitizer error type plus one or more normalized stable stack frames.
- Medium: a signal plus one or more normalized stable stack frames.
- Low: a signal-only identity, or an abnormal exit without stable diagnostic frames.

The classifier will continue to reject timeouts. It will parse AddressSanitizer's error type from the diagnostic and extract stack-frame identities from diagnostic lines beginning with a frame number such as `#0`. Normalization will remove ANSI escapes, process addresses, source-path prefixes, and volatile source line/column suffixes while retaining stable function/module/file identity. Arbitrary stderr lines will not participate in a Low-confidence fingerprint.

The canonical fingerprint input will be structured from the crash kind, confidence-relevant error identity, and normalized stable frames. It will not include the complete normalized stderr. This makes two signal-only SIGSEGV executions intentionally collide as a known low-confidence fallback, while changing diagnostic prose cannot split the same low-confidence crash into multiple IDs. High- and Medium-confidence fingerprints will distinguish separate bugs when their sanitizer type or stable frames differ.

Existing public Rust names will be changed only where needed for the new semantics. The CLI will render the confidence value, and stored manifests will use `High`, `Medium`, or `Low` for new cases. Existing `Diagnostic` and `SignalFallback` manifest values remain readable and are displayed as-is for backward compatibility.

### Minimizer and statistics

The deterministic two-phase ddmin algorithm remains the minimization algorithm: line units when the input contains a newline, followed by byte units. The candidate-removal helper will use contiguous ranges or slice copying so it does not perform `Vec::contains` for every unit.

`MinimizationResult` will include the existing bytes, run count, and completeness plus elapsed minimization duration. The timer covers candidate evaluation and algorithm overhead, beginning immediately before the first ddmin phase.

The CLI will print original size, minimized size, reduction percentage, execution count, elapsed time, and whether the budget completed. A final verification execution remains separate from the minimization run count.

### Test fixtures and ASan

The existing marker fixtures remain useful for deterministic CI. Additional minimizer tests will cover predicates requiring:

- a prefix and suffix together;
- exact byte ordering and offsets;
- multiple lines together;
- embedded NUL bytes;
- a large input with a small relevant region;
- a flaky predicate, proving the deterministic budget/return behavior without claiming nondeterministic correctness.

The C examples will include harder relational and binary-input cases where appropriate. The Makefile will retain `examples` and add `examples-asan`, compiling sanitizer-capable examples with `-fsanitize=address -fno-omit-frame-pointer -g`. ASan integration tests will run only when a POSIX C compiler is available, as the current native-fixture tests do, and will verify that repeated UAF and overflow executions classify as sanitizer crashes with stable fingerprints despite changing runtime addresses.

### Manifest and compatibility

`CrashManifest` will gain a nested `stats` object containing:

- `original_size`;
- `minimized_size`;
- `reduction_percent`;
- `minimization_runs`;
- `minimization_ms`.

The concrete types are `usize` for both sizes and run count, `f64` for reduction percentage, and `u64` for elapsed milliseconds. The existing top-level size fields remain for v0.1 compatibility and are written consistently with the nested stats. The new stats field uses serde defaults so old `crash.json` files load successfully. A `fingerprint_confidence: Option<String>` field will be added alongside the existing `fingerprint_strength`; old manifests without it remain loadable, and new manifests record the three-level confidence vocabulary. No migration command is required.

### Atomic persistence

`save_case` will write all files, set reproduction-script permissions, and then rename the completed temporary directory directly to `.crashforge/crashes/CF-xxxxxxxx`. The destination directory will not be created in advance. A pre-existing destination returns the existing collision error, and a failure before publication is cleaned up by the temporary-directory guard. The operation relies on same-filesystem directory rename, which is guaranteed because the temporary directory is created under the crashes directory.

### CLI reporting

The `run` command will retain its current stdout markers used by integration tests (`Fingerprint:`, `Verified:`, and `Saved:`) while adding concise status lines:

```text
CrashForge 0.2
✓ Crash detected: SIGSEGV
✓ Fingerprinted: CF-a82f091c [Low confidence]
→ Minimizing
  482,910 B → 184 B · 241 executions · 4.81s · 99.996% reduction
✓ Verified: CF-a82f091c
✓ Saved: .crashforge/crashes/CF-a82f091c
```

`inspect` will remain pretty-printed JSON for script compatibility, with confidence and nested stats included for new cases. `list` will add reduction and run columns without removing the existing ID, kind, original, or minimized columns.

## Data flow

```text
ExecutionResult
    -> classify
       -> CrashObservation { kind, stable_frames, confidence }
          -> fingerprint
             -> baseline ID
                -> minimize (run/classify/fingerprint candidates)
                   -> MinimizationResult { bytes, runs, elapsed, complete }
                      -> verify
                         -> CrashManifest + stats
                            -> atomic save_case
```

Candidate acceptance continues to require the candidate fingerprint to equal the baseline fingerprint. This is important for high/medium identities and preserves the known conservative behavior of low-confidence signal-only cases.

## Error handling

- A timeout is not a crash and cannot satisfy the minimizer predicate.
- A candidate execution or file write error aborts the run and is returned to the CLI.
- A zero timeout or zero run budget remains a CLI validation error.
- A failed final verification aborts before persistence.
- A fingerprint mismatch during final verification is reported with expected and observed IDs.
- Existing case IDs are never overwritten.
- Old manifests without new fields load through serde defaults.

## Testing strategy

Unit tests will cover confidence classification, stable-frame normalization, signal-only stderr independence, minimizer edge cases, timing/run accounting, and manifest serde compatibility. Integration tests will cover native signal crashes, ASan diagnostics when `cc` supports ASan, the end-to-end CLI stats/reporting path, atomic case layout, and reproduction of stored cases. `make check` remains the primary Rust verification command; `make examples-asan` is an explicit fixture-build check.

## Non-goals and follow-ups

Parallel candidate evaluation, LLDB/GDB stack capture, flaky-crash quorum policies, and real open-source crash benchmarks are deliberately deferred. They become the next evaluation milestone after this release has trustworthy confidence labels, persisted statistics, and adversarial fixture coverage.
