# CrashForge

CrashForge turns software crashes into permanent, minimal, reproducible regression tests.

## Status

Version 0.1 targets C and C++ command-line programs on Linux and macOS. The v0.1 workflow accepts an input file as the target's only argument:

```bash
crashforge run ./parser bad.json
crashforge reproduce CF-a82f091c
crashforge test
crashforge inspect CF-a82f091c
crashforge list
```

CrashForge fingerprints sanitizer diagnostics when available and falls back to signal identity for unsanitized programs. Candidate inputs are minimized with deterministic delta debugging and stored below `.crashforge/crashes/`.

## Development

```bash
make check
make demo
```

Rust stable and a POSIX C compiler are required.

