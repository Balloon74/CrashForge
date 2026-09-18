# CrashForge

CrashForge turns software crashes into permanent, minimal, reproducible regression tests.

## Status

Version 0.2.0 targets C and C++ command-line programs on Linux and macOS. The workflow accepts an input file as the target's only argument:

```bash
crashforge run ./parser bad.json
crashforge reproduce CF-a82f091c
crashforge test
crashforge inspect CF-a82f091c
crashforge list
```

CrashForge reports fingerprint confidence using stable sanitizer and stack-frame identities, with a signal-only fallback when frames are unavailable. Candidate inputs are minimized with deterministic delta debugging, with execution and timing statistics recorded in atomically published cases below `.crashforge/crashes/`. Existing v0.1 manifests remain readable and reproducible using their original fingerprint algorithm.

## Development

```bash
make check
make demo
```

Rust stable and a POSIX C compiler are required.
