# Analysis tools for problematic code and memory leaks

Tools that can find bugs, memory errors, and security issues in OpenRTX (C/C++ and Python). Use alongside existing: flawfinder, bandit, black, valgrind.

---

## Memory and runtime errors

| Tool | What it finds | How to run (OpenRTX) |
|------|----------------|----------------------|
| **Valgrind Memcheck** | Leaks, use-after-free, invalid read/write, uninitialised memory | `./scripts/run_valgrind.sh` (build openrtx_linux first) |
| **AddressSanitizer (ASan)** | Buffer overflows, use-after-free, double-free at runtime | `meson setup build -Dasan=true` then `ninja -C build openrtx_linux` and run the binary. Crashes with a report on first bad access. |
| **UndefinedBehaviourSanitizer (UBSan)** | Undefined behaviour (signed overflow, null deref, etc.) at runtime | `meson setup build -Dubsan=true` then build and run. Prints a report when UB is hit. |
| **LeakSanitizer (LSan)** | Leaks at exit; often enabled with ASan | Same build as ASan; set `ASAN_OPTIONS=detect_leaks=1` (default with -fsanitize=address). Standalone: `-fsanitize=leak` (no ASan). |
| **ThreadSanitizer (TSan)** | Data races | Build with `-fsanitize=thread` (add to linux_c_args in meson if needed). Run binary; reports races. |

---

## Static analysis (no run required)

| Tool | What it finds | How to run (OpenRTX) |
|------|----------------|----------------------|
| **Flawfinder** | Dangerous C/C++ functions (strcpy, sprintf, etc.), security patterns | `./scripts/run_flawfinder.sh` or `flawfinder openrtx lib platform/drivers platform/targets` (avoid full tree: CMSIS header encoding). |
| **Cppcheck** | Bugs, style, performance, some leaks; C/C++ | `cppcheck --enable=all --inconclusive -I openrtx/include -I platform openrtx platform/drivers platform/targets lib 2>&1` or use `run_security_analysis.sh` (writes to security_reports/). |
| **clang-tidy** | Modern C++, bugprone, performance, readability; needs compile_commands.json | `meson compile -C build -t compile_commands` then `clang-tidy -p build FILE.cpp` or use run-clang-tidy. Checks: `clang-tidy --checks='-*,bugprone-*,performance-*,readability-*' -p build openrtx/src/...`. |
| **PVS-Studio** | Bugs and security (commercial; free for some FOSS) | Install PVS-Studio, generate compile_commands, run analyzer. |
| **Coverity** | Deep static analysis (commercial; free tier for FOSS) | Upload build to Coverity Connect; run analysis in the cloud. |

---

## Python

| Tool | What it finds | How to run |
|------|----------------|-------------|
| **Bandit** | Security issues (assert, eval, hardcoded secrets, etc.) | `bandit -r scripts/ -f txt` |
| **Black** | Formatting | `black scripts/` or `black --check scripts/` |
| **Pylint / Ruff** | Bugs, style, imports | `pylint scripts/*.py` or `ruff check scripts/` |

---

## Fuzzing (find crashes and edge cases)

| Tool | What it finds | How to run (concept) |
|------|----------------|----------------------|
| **AFL++** | Crashes and hangs via mutation; needs harness | Build with afl-clang-fast, run afl-fuzz with a small corpus and a harness that reads stdin/file and calls parser/codec. |
| **libFuzzer** | Same idea; in-process, single binary | Build with `-fsanitize=fuzzer,address,undefined`, link a LLVMFuzzerTestOneInput harness, run the binary; it fuzzes until stopped. |

---

## Already wired in OpenRTX

- **run_valgrind.sh** – Valgrind on `build/openrtx_linux`.
- **run_flawfinder.sh** – Flawfinder on openrtx, lib, platform (no CMSIS).
- **run_security_analysis.sh** – Cppcheck, flawfinder, grep-based patterns; writes to `security_reports/`.
- **Meson options** – `-Dasan=true`, `-Dubsan=true` for sanitizer builds.

---

## Suggested order

1. **Static (no run):** flawfinder, cppcheck, bandit, black.
2. **Runtime (linux build):** valgrind (normal build), then ASan build and run, then UBSan build and run.
3. **Optional:** clang-tidy on changed files; fuzzing if you add a harness.
