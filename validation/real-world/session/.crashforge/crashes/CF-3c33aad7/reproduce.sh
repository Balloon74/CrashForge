#!/bin/sh
set -eu
CASE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd -- '/Users/mouryakummithi/CrashForge - GH opensource/validation/real-world/session'
exec '/Users/mouryakummithi/CrashForge - GH opensource/validation/real-world/bin/asan_import_parser' "$CASE_DIR/minimized.txt"
