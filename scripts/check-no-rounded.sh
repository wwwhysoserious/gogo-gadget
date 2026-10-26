#!/usr/bin/env bash
# Fails if any rounded-shape API appears in app/src/main (the UI must be square).
set -u
root="$(cd "$(dirname "$0")/.." && pwd)"
if grep -rnE 'RoundedCornerShape|CircleShape|ButtonDefaults\.shape' "$root/app/src/main"; then
    echo "FAIL: rounded shapes found" >&2
    exit 1
fi
echo "OK: no rounded shapes"
