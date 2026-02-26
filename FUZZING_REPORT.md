# Fuzzing Report

Summary of libFuzzer-based fuzzing of OpenRTX protocol decoders and parsers.

## Setup

- **Tool:** libFuzzer (Clang), with AddressSanitizer and UndefinedBehaviorSanitizer.
- **Build:** `CC=clang CXX=clang++ meson setup build -Dfuzzing=true` then build fuzz targets only (see [FUZZING.md](./FUZZING.md)).
- **Corpus:** Seed corpus under `tests/fuzz/corpus/<target>/`; generated with `python3 scripts/gen_fuzz_corpus.py`. Frame fuzzers use dictionary `tests/fuzz/dict/frame_sync_words.dict`.
- **Run:** `./scripts/run_all_fuzzers_3h.sh build` for a 3-hour parallel run; logs in `fuzz_artifacts/logs/`.

## Fuzz Targets

| Target | Input | Code under test |
|--------|------|------------------|
| fuzz_horse_frame | 48 B (strides) | Horse frame decoder (LSF, voice, EOT) |
| fuzz_ldpc_horse | 46 B | Horse LDPC voice decode/encode |
| fuzz_m17_golay | 4 B | M17 Golay(24,12) |
| fuzz_m17_callsign | up to 15 B | M17 callsign (base-40) |
| fuzz_m17_frame | 48 B (strides) | M17 frame decoder (LSF, stream) |
| fuzz_minmea | up to 256 B | minmea NMEA parser (GGA, RMC, etc.) |

## Bugs Found and Fixed

All issues were in the **minmea** NMEA parsing library (`lib/minmea/`), triggered by `fuzz_minmea`.

1. **FPE in `minmea_tocoord`** (`lib/minmea/include/minmea.h`)  
   Division by zero when `f->scale * 100` overflowed to zero (e.g. large `scale`) or when the denominator `60 * f->scale` was zero.  
   **Fix:** Use 64-bit intermediate for `scale * 100`; return NAN when the result is zero or out of range; guard the float denominator.

2. **Signed integer overflow in fractional parser** (`lib/minmea/minmea.c`)  
   `scale *= 10` could overflow for inputs with many decimal digits.  
   **Fix:** Guard with `scale > INT_LEAST32_MAX / 10` and break (truncate) instead of multiplying.

3. **Signed integer overflow in `minmea_rescale`** (`lib/minmea/include/minmea.h`)  
   - Addition overflow: `f->value + rounding_term` (e.g. 1983698719 + 500000000).  
   - Multiplication overflow: `f->value * (new_scale/f->scale)` (e.g. 3510687 * 1000).  
   **Fix:** Perform arithmetic in `int_least64_t` and clamp the result to `INT32_MIN`..`INT32_MAX` before returning.

## Campaign Summary

- Fuzzers were run in parallel with corpus, dict (for frame targets), and `-max_len` per target.
- **fuzz_horse_frame**, **fuzz_ldpc_horse**, **fuzz_m17_golay**, **fuzz_m17_callsign**, **fuzz_m17_frame** reached coverage plateau (no new edges/features) within the run; only **fuzz_minmea** continued to find new coverage until it too plateaued.
- No crashes or hangs remained after the minmea fixes; the above bugs were fixed and re-tested with the fuzz harness.

## How to Reproduce

1. Build: `CC=clang CXX=clang++ meson setup build -Dfuzzing=true && ninja -C build fuzz_minmea fuzz_horse_frame fuzz_ldpc_horse fuzz_m17_golay fuzz_m17_callsign fuzz_m17_frame`
2. Generate corpus: `python3 scripts/gen_fuzz_corpus.py`
3. Run: `./scripts/run_all_fuzzers_3h.sh build` (or run a single target, e.g. `./build/fuzz_minmea tests/fuzz/corpus/fuzz_minmea fuzz_artifacts/fuzz_minmea`)

See [FUZZING.md](./FUZZING.md) for full instructions.
