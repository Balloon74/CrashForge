# CrashForge 0.2.0 real-world validation — Test 2

Date: 2026-09-17

## Target

- Target: `test2_partial_bulk_sync.c`
- Input: `test2_partial_bulk_sync.txt`
- Sanitizer build: `cc -std=c11 -Wall -Wextra -O0 -fsanitize=address -fno-omit-frame-pointer -g`
- Memory error: ASan heap-buffer-overflow, writing 48 bytes into a 32-byte heap allocation in `decode_legacy_bulk_patch`.
- The path requires all of `"schema":"sync-manifest/4"`, `"mode":"legacy-bulk-patch"`, and `CF_TRIGGER_BULK_PATCH_V2`. Three no-marker controls all exited 0.
- Intentional instability is isolated to `compatibility_gate_opens()`, which opens when `target_entropy() % 10 < 8`. The entropy uses only fresh-process time, PID, and stack-address variation; CrashForge is not involved.

## Results

| Measurement | Result |
|---|---:|
| Original input size | 8,487 B |
| Minimized input size | 99 B |
| Reduction | 98.834% |
| Minimization executions | 437 |
| Minimization time | 6,175 ms |
| CrashForge fingerprint | `CF-e3a0425b` |
| Fingerprint confidence | High |
| Original direct crash rate | 74/100 = 74.0% |
| Minimized direct crash rate | 78/100 = 78.0% |
| `crashforge reproduce` success rate | 20/25 = 80.0% |

CrashForge’s first `run` attempt detected the crash, generated `CF-e3a0425b`, completed minimization, verified the fingerprint, and stored the case. The stored manifest records the same sizes, reduction, execution count, time, fingerprint, and High confidence.

## Fingerprint and reproduction assessment

Fingerprints remained stable. All 20 successful `reproduce` executions reported `Fingerprint match`; the five failures were `stored case did not fail`, and there were zero fingerprint mismatches. The minimized input preserved the same underlying ASan heap-buffer-overflow and the same stable `decode_legacy_bulk_patch`/`main` crash path.

The 74.0% original rate, 78.0% minimized rate, and 80.0% reproduction rate are consistent with the deliberate 8/10 target-side gate. No instability was introduced by CrashForge. `crashforge reproduce` and `crashforge test` are single-shot operations, so they correctly report failure when this intentionally nondeterministic target happens to take its non-crashing branch.

## Regression checks

- `crashforge test`: 9/10 complete command runs passed both stored cases. The one failure was `CF-e3a0425b    FAIL (stored case did not fail)`; Test 1’s deterministic `CF-d4e942ab` passed in all 10 runs.
- `cargo test`: all 40 Rust tests passed.
- Tracked CrashForge source diff: empty. `git diff --name-only` and `git diff --stat` returned no tracked changes; `git status --short` showed only the pre-existing/new untracked `validation/` tree.

## Suspicious or incorrect behavior

No incorrect CrashForge behavior was observed. The only noteworthy behavior is expected: a single-shot replay or regression run can fail on the target’s intentional gate miss and reports `stored case did not fail`, rather than a fingerprint mismatch. Apple’s ASan runtime emitted local symbolizer warnings, but CrashForge still produced High confidence from stable sanitizer frames and maintained the same fingerprint.

Raw evidence is preserved in `test2-evidence/`, including direct-rate logs, the successful CrashForge run, the 25 reproduction outcomes, success/failure transcripts, ten regression-test runs, control-input results, and the Rust test output.
