#!/bin/bash
# Run available analysis tools for problematic code and memory leaks.
# See scripts/ANALYSIS_TOOLS.md for full list and how to run sanitizers/fuzzing.
# Usage: from repo root, run: scripts/run_analysis.sh [--no-cppcheck] [--no-flawfinder]

set -e
cd "$(dirname "$0")/.."
REPORTS="${REPORTS:-analysis_reports}"
mkdir -p "$REPORTS"

run_cppcheck() {
    if ! command -v cppcheck >/dev/null 2>&1; then
        echo "cppcheck not found; install with: apt install cppcheck"
        return 1
    fi
    echo "Running cppcheck (openrtx, lib, platform/drivers, platform/targets)..."
    cppcheck --enable=warning,style,performance,portability --inconclusive \
             --suppress=missingIncludeSystem --suppress=unusedFunction \
             --std=c++14 -q \
             openrtx lib platform/drivers platform/targets \
             -i platform/mcu/CMSIS \
             --output-file="$REPORTS/cppcheck.txt" 2>"$REPORTS/cppcheck_stderr.txt" || true
    echo "  output: $REPORTS/cppcheck.txt"
}

run_flawfinder() {
    if [ -x scripts/run_flawfinder.sh ]; then
        echo "Running flawfinder..."
        scripts/run_flawfinder.sh --quiet 2>&1 | tee "$REPORTS/flawfinder.txt" || true
        echo "  output: $REPORTS/flawfinder.txt"
    else
        echo "scripts/run_flawfinder.sh not found or not executable"
        return 1
    fi
}

valgrind_hint() {
    if [ -x build/openrtx_linux ] && command -v valgrind >/dev/null 2>&1; then
        echo "  Valgrind: ./scripts/run_valgrind.sh"
    else
        echo "  Valgrind: build openrtx_linux, then ./scripts/run_valgrind.sh"
    fi
}

do_cppcheck=1
do_flawfinder=1
for arg in "$@"; do
    case "$arg" in
        --no-cppcheck) do_cppcheck=0 ;;
        --no-flawfinder) do_flawfinder=0 ;;
    esac
done

echo "Analysis reports directory: $REPORTS"
echo ""

if [ "$do_cppcheck" -eq 1 ]; then
    run_cppcheck
    echo ""
fi

if [ "$do_flawfinder" -eq 1 ]; then
    run_flawfinder
    echo ""
fi

echo "Runtime / sanitizers:"
valgrind_hint
echo "  ASan (buffer overflows, use-after-free): meson setup build -Dasan=true && ninja -C build openrtx_linux && ./build/openrtx_linux"
echo "  UBSan (undefined behaviour): meson setup build -Dubsan=true && ninja -C build openrtx_linux && ./build/openrtx_linux"
echo ""
echo "Full list: scripts/ANALYSIS_TOOLS.md"
