#!/bin/bash
# Run valgrind on the Linux OpenRTX build.
# Requires: meson (or .venv/bin/meson), ninja, valgrind, SDL2 (libsdl2-dev).
# Build: meson setup build && ninja -C build openrtx_linux
# Usage: scripts/run_valgrind.sh [valgrind options]
# Example: scripts/run_valgrind.sh --leak-check=full

set -e
cd "$(dirname "$0")/.."
BIN="build/openrtx_linux"
if [ ! -x "$BIN" ]; then
    echo "Binary not found: $BIN"
    echo "Install deps (e.g. libsdl2-dev), then:"
    echo "  meson setup build && ninja -C build openrtx_linux"
    exit 1
fi
if [ $# -eq 0 ]; then
    set -- --leak-check=full --show-leak-kinds=all
fi
exec valgrind "$@" "$BIN"
