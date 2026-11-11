# Upstream issue: UBSan left shift of negative value in `dsp_dcBlockFilter`

**Status: fixed upstream.** OpenRTX/OpenRTX#564 merged as `f403de9d`
(2026-11-11). Upstream `dsp_dcBlockFilter` now scales with
`static_cast<int32_t>(sample) * 32768` instead of a left shift.

Until this fork rebases onto post-564 `upstream/master`, the local
workaround `-fno-sanitize=shift` (`83e4a806`) may still be present.
Drop it on the next rebase; do not keep a fork-only `dsp.cpp` patch.

## Originally reproduced on

- Tree: `upstream/master` at `34052ea7` (OpenRTX version 0.4.5)
- Worktree: clean checkout, no Horse patches
- Host: Ubuntu, gcc 13.3.0
- Command:

```bash
meson setup build_asan -Db_sanitize=address,undefined
meson compile -C build_asan m17_demodulator_test
meson test -C build_asan "M17 Demodulator Test" --print-errorlogs
```

Without sanitizers the same test was green. With UBSan it aborted.

## Sanitizer trace (verbatim, pre-fix)

```
../openrtx/src/core/dsp.cpp:19:48: runtime error: left shift of negative value -60
    #0 ... in dsp_dcBlockFilter ../openrtx/src/core/dsp.cpp:19
    #1 ... in M17::Demodulator::sample(short, bool) ../openrtx/src/protocols/M17/Demodulator.cpp:217
    #2 ... in CATCH2_INTERNAL_TEST_16 ../tests/unit/M17_demodulator.cpp:264

SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior ../openrtx/src/core/dsp.cpp:19:48 in
```

## Pre-fix failing line

```c
dcb->prevIn = static_cast<int32_t>(sample) << 15;
```

`sample` is an `int16_t`. A left shift of a negative signed value is
undefined behaviour before C++20. Upstream now uses the multiply form.

---

## M17 `syncUpdateState` reads the swapped-out `demodFrame`

Do not change M17 code in this fork. This item is separate from the
DC-block UB and remains an upstream M17 note.

- Tree: `upstream/master` at `34052ea7` (OpenRTX version 0.4.5), retained
  in `upstream-sync`.
- Files:
  - `openrtx/src/protocols/M17/Demodulator.cpp:413-415` (`lockedState`):
    `std::swap(readyFrame, demodFrame)` then `demodState = SYNC_UPDATE`.
  - `openrtx/src/protocols/M17/Demodulator.cpp:424-430` (`syncUpdateState`):
    `compareSyncwords(demodFrame->data(), ...)` for LSF, stream, packet,
    and EOT.

After the swap, `demodFrame` is the buffer that will be filled next
(empty / previous contents), and `readyFrame` holds the frame that just
completed. The Hamming/sync check therefore inspects the wrong buffer.
Horse now checks `readyFrame` (`HorseDemodulator.cpp` `syncUpdateState`).
M17 is unchanged.
