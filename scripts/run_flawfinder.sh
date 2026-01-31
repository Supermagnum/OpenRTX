#!/bin/bash
# Run flawfinder on OpenRTX source trees that use UTF-8.
# Excludes platform/mcu/CMSIS (vendor headers with non-UTF-8 bytes) which
# cause flawfinder to fail with a decode error on the full tree.
# Usage: from repo root, run: scripts/run_flawfinder.sh [flawfinder options]
# Example: scripts/run_flawfinder.sh --html --context --minlevel=1

set -e
cd "$(dirname "$0")/.."
DIRS="openrtx lib platform/drivers platform/targets"
if ! command -v flawfinder >/dev/null 2>&1; then
    echo "flawfinder not found. Install with: pip install flawfinder or apt install flawfinder"
    exit 1
fi
exec flawfinder "$@" $DIRS
