# CrashForge v0.2 Reliability and Performance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make CrashForge crash identities confidence-aware and stable, make deterministic minimization faster and measurable, and preserve complete regression cases atomically with adversarial and ASan coverage.

**Architecture:** Keep the v0.1 execution/classification/minimization/storage pipeline and file-input CLI. Replace diagnostic-wide fingerprinting with structured stable-frame identities, thread minimization timing/statistics through the CLI into a backward-compatible manifest, optimize contiguous candidate removal, and publish complete case directories with one same-filesystem rename.

**Tech Stack:** Rust 2021, Cargo, `serde`/`serde_json`, `sha2`, `tempfile`, Clap 4, POSIX C compiler, AddressSanitizer where available.

**Spec:** `docs/superpowers/specs/2026-09-17-crashforge-v0.2-reliability-design.md`

## Global Constraints

- Preserve the existing `run`, `test`, `inspect`, `reproduce`, and `list` commands and their current required output markers: `Fingerprint:`, `Verified:`, and `Saved:`.
- Keep deterministic two-phase ddmin; do not add parallel candidate execution or debugger integration.
- New fingerprints use `High`, `Medium`, or `Low`; old `Diagnostic` and `SignalFallback` manifest values remain deserializable.
- Low-confidence identities must not include arbitrary normalized stderr.
- Existing top-level `original_size` and `minimized_size` manifest fields remain present and consistent with nested stats.
- Old manifests missing new fields must deserialize successfully through serde defaults.
- Candidate execution/file errors and final verification mismatches remain fatal before persistence.
- Do not edit unrelated user changes; the starting worktree is clean except for the approved spec and this plan.

---

### Task 1: Add confidence-aware stable-frame classification and fingerprints

**Files:**
- Modify: `src/crash.rs`
- Modify: `src/fingerprint.rs`
- Modify: `src/lib.rs` only if a new public type needs re-exporting (the existing module exports are otherwise sufficient)
- Test: `tests/fingerprint_tests.rs`

**Interfaces:**
- `crash::FingerprintConfidence` exposes `High`, `Medium`, and `Low`.
- `crash::CrashObservation` exposes the crash kind, normalized diagnostic details needed for descriptions, a `Vec<String>` of stable frame identities, and the new confidence.
- `crash::classify(&ExecutionResult) -> Option<CrashObservation>` continues to reject timeouts.
- `fingerprint::fingerprint(&CrashObservation) -> String` hashes only confidence-relevant canonical identity fields.

- [ ] **Step 1: Write failing confidence and stability tests**

Add tests in `tests/fingerprint_tests.rs` for:

```rust
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
    assert_eq!(fingerprint(&first_observation), fingerprint(&second_observation));
}
```

Also add tests that same-signal executions with stable frames are `Medium` and equal despite changing prose/addresses, that signal-only executions are `Low` and equal despite different stderr, and that two different stable frame sequences produce different fingerprints. Retain the existing different-signal assertion.

- [ ] **Step 2: Run the focused tests and verify the expected red failure**

Run:

```bash
cargo test --test fingerprint_tests
```

Expected: compilation/test failure because `FingerprintConfidence`/`confidence`/stable-frame identity are not implemented and the current fingerprint still depends on normalized stderr.

- [ ] **Step 3: Implement structured classification**

In `src/crash.rs`:

1. Replace `FingerprintStrength` with `FingerprintConfidence` and add the three variants.
2. Add `stable_frames: Vec<String>` and `confidence: FingerprintConfidence` to `CrashObservation`.
3. Extract frame identities only from diagnostic lines whose trimmed form begins with `#` followed by decimal digits. Normalize each frame by removing ANSI escapes, the instruction address, source path prefixes, and trailing `:line[:column]` suffixes while retaining the function/module/file identity.
4. Return `High` for an AddressSanitizer error type with at least one stable frame.
5. Return `Medium` for a signal with at least one stable frame.
6. Return `Low` for signal-only observations and abnormal exits without stable frames. Keep timeout rejection and existing crash-kind detection.

In `src/fingerprint.rs`:

1. Keep diagnostic normalization available for display/debug details, but add a stable-frame normalization helper used by classification.
2. Build canonical input from the crash kind plus sanitizer error type or signal/exit identity, then append stable frames only when present. For a sanitizer observation without stable frames but with a signal, use the signal identity as the Low-confidence fallback and do not use the sanitizer diagnostic text as identity.
3. Do not append complete normalized stderr for Low-confidence observations.
4. Keep the `CF-` plus eight lowercase hexadecimal character format.

- [ ] **Step 4: Run the focused tests and verify green**

Run:

```bash
cargo test --test fingerprint_tests
```

Expected: all fingerprint tests pass, including the new confidence and stderr-independence assertions.

- [ ] **Step 5: Run the full Rust test suite before moving on**

Run:

```bash
cargo test
```

Expected: the full existing suite passes; any compile failures from old `FingerprintStrength` references are fixed in tests and downstream code before continuing.

### Task 2: Make ddmin candidate removal range-based and record elapsed time

**Files:**
- Modify: `src/minimizer.rs`
- Test: `tests/minimizer_tests.rs`

**Interfaces:**
- `MinimizerLimits { max_runs }` remains unchanged.
- `MinimizationResult` gains `elapsed: Duration` while retaining `bytes`, `runs`, and `complete`.
- `minimize(input, limits, preserves_crash)` retains its generic predicate API.

- [ ] **Step 1: Add failing timing and adversarial minimizer tests**

Extend `tests/minimizer_tests.rs` with tests for:

```rust
#[test]
fn reports_elapsed_time_and_preserves_a_required_prefix_and_suffix() {
    let result = minimize(
        b"noise-HEAD-middle-TAIL-noise",
        MinimizerLimits { max_runs: 1000 },
        |candidate| candidate.starts_with(b"HEAD") && candidate.ends_with(b"TAIL"),
    );

    assert!(result.complete);
    assert_eq!(result.bytes, b"HEADTAIL");
    assert!(result.elapsed >= std::time::Duration::ZERO);
}
```

Add separate tests for ordered bytes at a required offset, multiple required lines, embedded NUL bytes, and a 1 MiB input whose predicate requires a 20-byte region. Keep the budget test and assert that a one-run budget reports exactly one run and a non-complete result.

- [ ] **Step 2: Run the minimizer tests and verify the expected red failure**

Run:

```bash
cargo test --test minimizer_tests
```

Expected: compilation failure for the missing `elapsed` field, or assertion failure for the new required behaviors if the old algorithm cannot yet satisfy them.

- [ ] **Step 3: Implement range-based removal and timing**

In `src/minimizer.rs`:

1. Import `std::ops::Range` and `std::time::{Duration, Instant}`.
2. Start an `Instant` at the beginning of `minimize` and return `started.elapsed()` in every `MinimizationResult`, including the budget-exhausted early return.
3. Change `split_groups` to return non-empty `Range<usize>` values.
4. Change `without_group` to copy `units[..group.start]` and `units[group.end..]`, cloning only retained units; never call `group.contains(index)`.
5. Preserve partition progression, run-budget checks, line-vs-byte phases, and deterministic output exactly otherwise.

- [ ] **Step 4: Run the minimizer tests and verify green**

Run:

```bash
cargo test --test minimizer_tests
```

Expected: all minimizer tests pass, including binary/NUL, large-input, timing, and budget cases.

- [ ] **Step 5: Run formatting and the full test suite**

Run:

```bash
cargo fmt --all -- --check
cargo test
```

Expected: both commands exit successfully.

### Task 3: Add backward-compatible manifest statistics and atomic case publication

**Files:**
- Modify: `src/storage.rs`
- Modify: `tests/storage_tests.rs`

**Interfaces:**
- Add `storage::MinimizationStats` with `original_size: usize`, `minimized_size: usize`, `reduction_percent: f64`, `minimization_runs: usize`, and `minimization_ms: u64`.
- Add `CrashManifest::stats: MinimizationStats` with serde default behavior for old manifests; if `Default` is used, its values must be deterministic zeros.
- Add `CrashManifest::fingerprint_confidence: Option<String>` with serde default behavior.
- Keep `CrashManifest::original_size`, `minimized_size`, and all existing fields unchanged.
- `save_case` continues returning the final case directory or `CrashForgeError::Collision`.

- [ ] **Step 1: Add failing manifest compatibility and atomic-layout tests**

In `tests/storage_tests.rs`:

1. Update the helper manifest with new stats and confidence values.
2. Add a test that deserializes a v0.1 JSON string with no `stats` or `fingerprint_confidence` and asserts loading succeeds with default stats and `None` confidence.
3. Extend the save test to assert the final directory contains exactly `original.txt`, `minimized.txt`, `crash.json`, and `reproduce.sh`, and that no `.case-*` directory remains under `crashes`.
4. Keep the collision/no-overwrite assertion.

- [ ] **Step 2: Run the storage tests and verify the expected red failure**

Run:

```bash
cargo test --test storage_tests
```

Expected: compilation failure for the missing manifest fields or deserialization failure for the missing-default test.

- [ ] **Step 3: Implement the manifest types and atomic rename**

In `src/storage.rs`:

1. Define `MinimizationStats` with `Clone`, `Debug`, `Default`, `Deserialize`, `PartialEq`, and `Serialize`; remove `Eq` from types that contain `f64` if necessary.
2. Mark new manifest fields with `#[serde(default)]` and use `Option<String>` for `fingerprint_confidence`.
3. In `save_case`, write all four files and reproduction permissions into the `tempdir` created under `crashes`.
4. Compute the destination path and return `CrashForgeError::Collision` if it already exists.
5. Rename the temporary directory itself to the destination with `fs::rename(temporary.path(), &destination)`; do not create the destination directory first and do not rename individual files.
6. Keep ID validation, shell quoting, load/list behavior, and reproduction-script contents unchanged.

- [ ] **Step 4: Run storage tests and verify green**

Run:

```bash
cargo test --test storage_tests
```

Expected: all storage tests pass, including old-manifest deserialization and atomic-layout assertions.

- [ ] **Step 5: Run all Rust tests**

Run:

```bash
cargo test
```

Expected: all tests pass; update any test fixture construction that now needs `stats` while retaining the old JSON compatibility test.

### Task 4: Thread confidence and minimization statistics through the CLI

**Files:**
- Modify: `src/cli.rs`
- Modify: `tests/cli_tests.rs`
- Modify: `src/storage.rs` only if a constructor/helper is needed to keep manifest assembly focused

**Interfaces:**
- `run_command` continues accepting program, input, timeout, and max-run values.
- New manifests use `fingerprint_confidence` and `MinimizationStats` from the baseline observation and `MinimizationResult`.
- `inspect` remains pretty-printed JSON; `list` keeps existing columns and adds reduction/run information.

- [ ] **Step 1: Add failing CLI assertions for confidence and stats**

Extend `runs_minimizes_stores_and_reproduces_a_c_crash` to assert stdout contains `CrashForge`, a confidence label, `executions`, and `Saved:`. Parse `crash.json` and assert:

```rust
assert_eq!(manifest["original_size"], manifest["stats"]["original_size"]);
assert_eq!(manifest["minimized_size"], manifest["stats"]["minimized_size"]);
assert!(manifest["stats"]["minimization_runs"].as_u64().unwrap() > 0);
assert!(manifest["stats"]["minimization_ms"].is_number());
```

The signal-only stderr-independence rule is covered by the focused fingerprint unit test; the CLI test remains focused on reporting, persistence, and reproduction.

- [ ] **Step 2: Run the CLI tests and verify the expected red failure**

Run:

```bash
cargo test --test cli_tests
```

Expected: failure because the current output and manifest do not include the new confidence/stat fields.

- [ ] **Step 3: Implement CLI metadata and compiler-style reporting**

In `src/cli.rs`:

1. Replace `FingerprintStrength` imports/helpers with `FingerprintConfidence` and a display helper returning `High`, `Medium`, or `Low`.
2. Start timing immediately before calling `minimize`; use `MinimizationResult::elapsed` as the authoritative minimization duration.
3. Compute reduction percent as `0.0` when the original is empty, otherwise `100.0 * (original.len() - minimized.len()) as f64 / original.len() as f64`.
4. Keep the exact `Fingerprint: {id}` line for integration parsing.
5. Print concise detected/fingerprinted/minimizing/verified/saved lines while preserving existing useful wording and markers.
6. Build `CrashManifest` with consistent top-level sizes, nested stats, and `fingerprint_confidence: Some(...)`.
7. Print run count, duration, reduction, and incomplete-budget status after minimization.
8. Update `list_command` to include reduction and run columns while retaining ID/kind/original/minimized.
9. Keep `inspect_command` as `serde_json::to_string_pretty` so existing JSON consumers continue to work.

- [ ] **Step 4: Run CLI tests and verify green**

Run:

```bash
cargo test --test cli_tests
```

Expected: all CLI tests pass, including end-to-end storage/reproduction and the new report/manifest assertions.

- [ ] **Step 5: Run formatting, lint, and all tests**

Run:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

Expected: all commands exit successfully with no warnings promoted to errors.

### Task 5: Add adversarial C fixtures and ASan build/test coverage

**Files:**
- Create: `examples/vulnerable-programs/relational_crash.c`
- Create: `examples/vulnerable-programs/binary_crash.c`
- Create: `examples/vulnerable-programs/inputs/relational.txt`
- Create: `examples/vulnerable-programs/inputs/binary.bin`
- Modify: `Makefile`
- Create: `tests/asan_tests.rs`

**Interfaces:**
- `make examples` continues compiling the four existing normal fixtures.
- `make examples-asan` compiles the sanitizer-relevant examples with `-fsanitize=address -fno-omit-frame-pointer -g` into `target/examples-asan`.
- The ASan integration test runs a real fixture multiple times and compares `classify`/`fingerprint` results.

- [ ] **Step 1: Add failing fixture/build/test expectations**

Add a test that attempts to compile `use_after_free.c` and `buffer_overflow.c` with the ASan flags, runs each against its trigger input, and asserts:

```rust
assert_eq!(first_observation.kind, second_observation.kind);
assert_eq!(first_observation.confidence, FingerprintConfidence::High);
assert_eq!(fingerprint(&first_observation), fingerprint(&second_observation));
```

If the compiler rejects `-fsanitize=address`, print a clear skip message and return from the test so unsupported toolchains do not fail the portable suite. The normal native tests continue to require only the existing C compiler.

Add adversarial C fixtures with explicit byte/ordering relationships and a binary fixture that reads bytes without treating NUL as string termination. Their inputs must trigger only when the documented relationship is present.

- [ ] **Step 2: Run the new focused test and verify the expected red failure**

Run:

```bash
cargo test --test asan_tests
```

Expected: failure because the new test file/fixture/build target is not implemented yet.

- [ ] **Step 3: Implement fixtures and Makefile targets**

1. Add C programs that read the file argument in binary mode and trigger a deterministic crash only for relational/ordered/binary conditions; avoid undefined behavior in the non-triggering path.
2. Add matching inputs under `examples/vulnerable-programs/inputs/`.
3. Add `examples-asan` to `.PHONY` and compile `buffer_overflow.c` and `use_after_free.c` with `-std=c11 -Wall -Wextra -O0 -fsanitize=address -fno-omit-frame-pointer -g` into `target/examples-asan`.
4. Keep ordinary `examples` output and flags unchanged.
5. Place ASan test helpers in one test module, use `tempdir`, compile with `cc`, run through `runner::run`, and compare stable fingerprints across two executions.

- [ ] **Step 4: Run ASan/fixture verification**

Run:

```bash
make examples
make examples-asan
cargo test --test asan_tests -- --nocapture
```

Expected: normal examples build; ASan examples build on an ASan-capable compiler; the ASan test passes or clearly reports a supported-toolchain skip; no generated binaries are added to git.

- [ ] **Step 5: Run the complete project verification**

Run:

```bash
make check
git diff --check
git status --short
```

Expected: formatting, clippy, and all Rust tests pass; the diff has no whitespace errors; only intended source, fixture, Makefile, spec, and plan files are present. Report any ASan/toolchain limitation explicitly rather than claiming an ASan run that did not occur.

## Plan Self-Review

- Confidence requirements map to Task 1 and its focused tests.
- Minimizer optimization, elapsed timing, adversarial inputs, and budget behavior map to Task 2.
- Nested statistics, old-manifest defaults, and directory-level atomic publication map to Task 3.
- CLI output and manifest assembly map to Task 4.
- Real C fixtures, ASan compilation, and repeated runtime fingerprints map to Task 5.
- Every production change has a preceding failing-test step, and every task ends with a fresh verification command.
- No placeholder steps or undefined later interfaces remain; unsupported ASan toolchains are an explicit test skip and are reported as such.
