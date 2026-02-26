# Fuzzing OpenRTX with libFuzzer

This project can be built with **libFuzzer** (LLVM's in-process, coverage-guided fuzzer) to find bugs in protocol decoders and parsers across the codebase.

## Requirements

- **Clang** (libFuzzer is part of the compiler-rt runtime; use a recent LLVM/Clang).
- Meson build configured with the fuzzing option.

## Building fuzz targets

Configure and build with the `fuzzing` option:

```bash
# Use clang explicitly (recommended)
export CC=clang
export CXX=clang++

meson setup build -Dfuzzing=true
ninja -C build fuzz_horse_frame fuzz_ldpc_horse fuzz_m17_golay fuzz_m17_callsign fuzz_m17_frame fuzz_minmea
```

Building only the fuzz executables (recommended to avoid building the full firmware) is sufficient. This produces:

| Target | Input | Code under test |
|--------|--------|------------------|
| `fuzz_horse_frame` | 48 bytes | Horse protocol frame decoder (LSF, voice, EOT) |
| `fuzz_ldpc_horse` | 46 bytes | Horse LDPC voice decoder |
| `fuzz_m17_golay` | 4 bytes | M17 Golay(24,12) decode |
| `fuzz_m17_callsign` | 6 bytes | M17 callsign decode (base-40 to string) |
| `fuzz_m17_frame` | 48 bytes | M17 protocol frame decoder (LSF, stream) |
| `fuzz_minmea` | up to 256 bytes | minmea NMEA sentence parser (GGA, RMC, etc.) |

## Running the fuzzers

Run a single fuzz target with no arguments for continuous fuzzing:

```bash
./build/fuzz_horse_frame
```

To use a **corpus** directory (recommended) and save **crashes/hangs**:

```bash
./build/fuzz_horse_frame corpus_dir artifacts_dir
```

### Run all fuzzers for 3 hours (parallel, nohup)

To run every fuzz target **in parallel** for **3 hours** each with corpus and artifacts:

```bash
python3 scripts/gen_fuzz_corpus.py
./scripts/run_all_fuzzers_3h.sh build
```

Each fuzzer runs in the background via `nohup`; logs go to `fuzz_artifacts/logs/<name>.log`. The script waits for all to finish. To run the script itself in the background (e.g. over SSH):

```bash
nohup ./scripts/run_all_fuzzers_3h.sh build > fuzz_artifacts/logs/master.log 2>&1 &
```

Corpus: `tests/fuzz/corpus/<fuzzer_name>/`. Artifacts (crashes/hangs): `fuzz_artifacts/<fuzzer_name>/`.

### 120-second smoke test

To verify all fuzzers run and that coverage rises during a short run:

```bash
./scripts/run_fuzz_smoke_test.sh build 120
```

This runs each fuzzer for 120 seconds and prints start/end coverage (cov, ft). For a 120-second total quick smoke (20s per fuzzer), use:

```bash
./scripts/run_fuzz_smoke_test.sh build 20
```

### Seed corpus

Generate minimal seed corpus for all fuzzers:

```bash
python3 scripts/gen_fuzz_corpus.py
```

This creates `tests/fuzz/corpus/fuzz_<name>/` with at least one seed file per target (Horse frames, LDPC 46-byte, M17 Golay 4-byte, callsign 6-byte, M17 frame 48-byte, and a sample NMEA line for minmea).

## Interpreting results

- **Crashes** (e.g. SIGSEGV, ASan reports) are written to the artifacts directory (or to the current directory if you did not specify one). Inspect them with a debug build or by re-running the fuzzer with the crashing input.
- **Hangs** (if detected) are also stored when you pass an artifacts directory.
- Fix any found bug, add a regression test if appropriate, and re-run the fuzzer to confirm the fix.

## Performance tips

- Use a **corpus** directory and let the fuzzer run for a while to build a diverse corpus.
- For **reproducible** runs, set `LLVM_FUZZER_SEED` (e.g. `LLVM_FUZZER_SEED=1`).
- Execution speed (exec/s) is reported by libFuzzer; aim for at least hundreds of exec/s. If it is too low, consider reducing the size of the code under test or simplifying the harness.
