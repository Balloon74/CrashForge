# CrashForge v0.1 Project Specification

CrashForge automates the workflow:

```text
Crash -> Identify -> Fingerprint -> Minimize -> Verify -> Preserve -> Retest
```

The first release is a native Rust CLI for C/C++ command-line programs on Linux and macOS. It runs a target with a file argument, captures process results, detects signal and sanitizer failures, fingerprints normalized diagnostics, minimizes the input with deterministic delta debugging, and stores a filesystem regression case.

Stored cases contain the original input, minimized input, JSON metadata, and a POSIX reproduction script. No database, web service, debugger, cloud infrastructure, or AI dependency is required.

