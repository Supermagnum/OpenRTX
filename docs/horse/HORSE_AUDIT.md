# Horse code audit

Date: 2026-10-05
Branch: `upstream-sync` (after merge of OpenRTX `v0.4.5`)
Spec: `horse.md` (the implementation claim)

This document is a read-of-the-path audit. Nothing in this file is a
security guarantee. Findings marked **confirmed** were traced end to end.
Fuzzing was not run (cancelled by the owner).

Linux Horse enablement is commit `7a2d775f`. This document is also the
work list. All confirmed software findings are closed except C21.
Finding status:

| Id | Status |
|----|--------|
| C1 voice MAC not session-keyed | fixed in `4e789cbf` / `16a5b677` (k_tag from ECDH); test `horse_crypto_test` |
| C2 TX cleartext fallback | fixed in `c6bdad06` (refuse TX; UI `horseError`); test `horse_tx_fail_test` |
| C3 demod correlator not Horse sync | fixed in `c6337821` / `4d301939`; test `horse_loopback_test` |
| C4 signature chunk overflow | fixed in `c3f68754`; packing `13ac0cef` (5x12+4); test `horse_frame_test` |
| C5 20 ms DMA vs 40 ms codec | fixed in `8b965e29`; test `horse_codec_test` |
| C6 FN / nonce layout | fixed in `08e6c3cb` / `4e789cbf`; test `horse_crypto_test` |
| C7 Argon2 RAM / PBKDF2 | fixed: 16 KiB Argon2id; no PBKDF2; `horse_heap` peak vs 53248 B budget (`horse_heap_test`) |
| C8 passphrase in `settings_t` | fixed in `4015daa2` (RAM-only); empty/short rejected (`HORSE_PASSPHRASE_MIN` 8); test `horse_keystore_test` |
| C9 `contact_t` growth | fixed in `1b79bbdb` (sidecar peers); `contact_t` 39 B / `settings_t` 84 B match upstream (`cps_layout_test`, `horse_settings_upstream.py`) |
| C10 Ed25519 seed padded to 64 | fixed in `80404ce2`; test `horse_host_interop_test` |
| C11 keyring hex/JSON | fixed in `80404ce2` / `31495ec7` (XDG files; `show` publics only) |
| C12 encrypted RX without session | fixed in `c6bdad06`; test `horse_session_modem` / loopback negatives |
| C13 MD-3x0 C5000 TX enable | fixed: driver `OPMODE_HORSE` LINE_IN path; RF check remains HARDWARE_TEST_PLAN step 3 |
| C14 RTX 512 B stack | fixed: sodium on 16 KiB worker; `scripts/check_horse_stack_usage.py` enforced in ARM CI build |
| C15 keystore race / oversized hdr / unauth provision | fixed: mutex `fb86c4ed`; oversized `hdr->len` resets; `MSG_SEND_IDENTITY` only in menu provision mode + fingerprint confirm + 120 s timeout (`horse_provision_sock_test`) |
| C16 `horseInfo_t` garbage on mode switch | fixed in `1ca16357`; test `horse_info_test` |
| C17 LDPC name vs repeat-2 | fixed in v2: M17 option-C voice `0de39b89`; `ldpc_horse` removed |
| C18 tests vs claims | fixed: `horse_test_opmode_buffer_e2e` (encrypt/sign/combined via OpMode); `horse_session_modem` / loopback |
| C19 `sodium_memzero` | fixed in `c6bdad06` / `fb86c4ed` |
| C20 LSF has no FEC and no checksum | fixed in v2: three M17-coded opening frames + CRC-16 `4003bcf2`; fragments `d2e4405d` |
| C21 MD-3x0 Horse BW 12.5 vs M17 25 kHz | open; analysis below; no code change without measurement; HARDWARE_TEST_PLAN step 10 |
| M17 `dsp.cpp:19` UBSan | fixed upstream: OpenRTX/OpenRTX#564 (`f403de9d`); drop fork `-fno-sanitize=shift` on rebase |
| `horse_keytool.py` | fixed: removed (`31495ec7`); use `scripts/horse_provision.py` |
| LSF bind / channel flags | fixed: `b1f207f5` |
| False-lock Hamming 0 + tag drop | fixed: `b9f6331c`; NCC floor removed `18a4d420` |
| Native meson test vs ARM firmware | fixed: reverted `a5fc2f08`; procedure in `AGENTS.md` (`--no-rebuild`) |
| Sanitizer Horse timeouts / `-fno-sanitize=shift` | fixed upstream with #564; remove fork workaround on rebase onto post-564 master |
| ECIES dead code | fixed: `c18faa08` |
| Python/C identity interop | fixed: `3bb7439a`; test `horse_host_interop_test` |

---

Linux Horse enablement (Task 2 compile-only) was committed as `7a2d775f`.

---

## Linux compile (previously never built on the host)

`CONFIG_HORSE` and `horse_src` were only on the MD-3x0 target. That
matches the known issue: the emulator did not compile Horse even though
`horse.md` and `README.md` describe emulator encrypt/sign, `/tmp/horse_output.raw`
and the provisioning Unix socket.

Enabling Horse for Linux (`linux_def` `CONFIG_HORSE`, `linux_src += horse_src`)
produced these **errors** (gcc 13.3, then remaining after include fixes):

1. `HorseModulator.cpp:9` / `HorseDemodulator.cpp:8-9`:
   `#include "protocols/M17/M17DSP.hpp"` and `M17Utils.hpp` -- those
   headers were renamed upstream to `DSP.hpp` and `Utils.hpp`.
2. `HorseDemodulator.hpp` including `Synchronizer.hpp` without `<cmath>`:
   `std::abs` is not a member of `std` (error originates in
   `Synchronizer.hpp:75`).
3. `HorseDemodulator.cpp:22`:
   `streamSync({{+1, +3, ...}})` is an ambiguous `Synchronizer` constructor
   after the upstream API change (move-from `std::array` vs copy ctor).
4. `OpMode_Horse.cpp:315-316, 438-439`:
   `M17::decode_callsign` / `M17::encode_callsign` no longer exist; the
   API is `M17::Callsign`.
5. `OpMode_Horse.cpp` (rxState, originally 368/379/385/387):
   `break` not within a loop or switch. Ill-formed C++. Confirmed by the
   compiler. Replaced with a `drop_voice` flag so the file compiles; the
   intended skip-voice control flow is unchanged.
6. Link error: `HorseDemodulator::sfNum` / `sfDen` ODR-used as
   `static constexpr` members (C++14) without out-of-line definitions.

**Warnings** on the successful Linux link:

- `horse_keystore.c:89`: `-Wformat-truncation` (`%s/horse_identity.bin`
  into a 256-byte buffer).
- `OpMode_Horse.cpp` constructor: `-Wreorder` (`txSigSent` vs `rxSigChunks`).
- `OpMode_Horse.cpp:121,453`: `-Wmissing-field-initializers` on
  `contact_t contact = {0}`.
- Linker: missing `.note.GNU-stack` on `voicePromptData.S` (pre-existing
  on all Linux targets, not Horse-specific).

After those compile-only fixes, `meson compile -C build openrtx_linux`
succeeds and `OpMode_Horse.cpp` is part of the emulator binary.

---

## Confirmed bugs

### C1. Voice MAC is not keyed by the session key -- fixed

- **Was:** BLAKE2b keyed with the public string `"HVOICETAG"`, no FN
  bind; tag forgeable.
- **Fix:** Session `k_tag` from ECDH (`4e789cbf` / `16a5b677`); keyed
  MAC over direction, FN, and payload. Test: `horse_crypto_test`
  rejects a forged `"HVOICETAG"` tag.

### C2. TX fails open to cleartext -- fixed

- **Was:** Missing crypto/keystore/contact still allowed cleartext TX.
- **Fix:** `c6bdad06` refuses TX (`opStatus = OFF`, UI `horseError`)
  when encrypt/sign is required and crypto is not ready. Test:
  `horse_tx_fail_test`.

### C3. Demodulator acquisition sync is not a Horse sync word -- fixed

- **Was:** Correlator template did not match Horse LSF/voice/EOT
  symbols from `byteToSymbols`.
- **Fix:** `c6337821` / `4d301939` acquire and track Horse sync words.
  Test: `horse_loopback_test`.

### C4. Signature chunk 5 reads/writes past a 64-byte signature -- fixed

- **Was:** Six 12-byte slots over a 64-byte Ed25519 signature overflowed
  on chunk 5 (ASan `stack-buffer-overflow`).
- **Fix:** `c3f68754`; packing `13ac0cef` (5x12+4). Test:
  `horse_frame_test`.

### C5. Codec DMA is 20 ms; encode/decode assume 40 ms -- fixed

- **Was:** Stream started at 320 samples; DMA returned 20 ms halves
  while MELPe path assumed 40 ms.
- **Fix:** `8b965e29` matches the double-buffer contract. Test:
  `horse_codec_test`.

### C6. Frame-number space collides; XChaCha20 nonce is only those 16 bits -- fixed

- **Was:** Signature FN range overlapped voice FN; nonce was only 16-bit
  FN.
- **Fix:** `08e6c3cb` / `4e789cbf` separate layout and stop TX before
  wrap. Test: `horse_crypto_test`.

### C7. Argon2id moderate (~256 MiB) vs STM32F405 -- fixed

- **Fix:** Argon2id `opslimit=2` / `memlimit=16384`. No PBKDF2. Host
  tracker `horse_heap_peak()` notes Argon2 + worker stack; budget
  `HORSE_HEAP_BUDGET_BYTES` (53248) derived from MD-3x0 heap 89600 B.
  Test: `horse_heap_test`. Optional on-radio HWM check is
  HARDWARE_TEST_PLAN step 1 (not an open software bug).

### C8. Passphrase stored in plaintext `settings_t` -- fixed

- **Was:** `char horse_passphrase[33]` persisted in NVM via
  `settings_t`.
- **Fix:** `4015daa2` keeps the passphrase RAM-only; empty/short
  rejected (`HORSE_PASSPHRASE_MIN` 8). Test: `horse_keystore_test`.

### C9. `contact_t` / `settings_t` layout change -- fixed

- **Fix:** Horse peers are a sidecar (`struct horse_peer`); `contact_t`
  remains 39 B. Passphrase is RAM-only; `settings_t` remains 84 B and
  matches upstream (`tests/unit/horse_settings_upstream.py`).
  `horseInfo_t` (4 B) fits the existing channel union.
  `cps_layout_test` asserts packed sizes/offsets.

### C10. Provisioning packs a 32-byte Ed25519 seed into a 64-byte field -- fixed

- **Was:** PyNaCl 32-byte seed null-padded to 64; libsodium expects
  `seed || pk`.
- **Fix:** `80404ce2` packs seed plus verify key. Test:
  `horse_host_interop_test`.

### C11. Kernel keyring round-trip is broken; `show` prints secret material -- fixed

- **Was:** kernel keyring store used `payload.hex()` then `json.loads`
  without `unhexlify`; `show` printed secret-key hex.
- **Fix:** `31495ec7` / `80404ce2` replaced the keyring with XDG state
  files (`horse_identity_*.bin` mode 0600). `show` prints public keys
  and fingerprint only.

### C12. Encrypted RX without a session still starts audio -- fixed

- **Was:** Encrypted LSF without a valid session still opened RX audio.
- **Fix:** `c6bdad06` drops encrypted voice when `!sessionValid`.
  Tests: `horse_session_modem` / loopback negatives.

### C13. Horse TX never enables RF TX on MD-3x0 -- fixed

- **Was:** `radio_enableTx()` had no `OPMODE_HORSE` case; PA keyed
  without `C5000.startAnalogTx()`.
- **Fix:** `#ifdef CONFIG_HORSE` `case OPMODE_HORSE:` starts analog TX
  from `LINE_IN` with `FmConfig::BW_12p5kHz`, matching
  `radio_setOpmode` BW_12_5 / mod factor `0x1E`. Abort/EOT still goes
  through `radio_disableRtx()`. On-air check is HARDWARE_TEST_PLAN
  step 3. Bandwidth vs M17 25 kHz remains C21 (open).

### C14. RTX stack 512 B vs Horse work -- fixed

- **Fix:** Voice coding is M17 option-C on existing encoder/Viterbi;
  libsodium runs on a dedicated 16 KiB worker. RTX Horse functions must
  stay under `RTX_THREAD_STKSIZE - 64`; worker deepest path under
  `CODEC2_THREAD_STKSIZE - 2048`. Enforced by
  `scripts/check_horse_stack_usage.py` on ARM `.su` files in the CI
  `build` job after `openrtx_md3x0`.

### C15. Provision parser / keystore / unauthenticated identity -- fixed

- **Fix:** `hdr->len` above the remaining 320-byte buffer clears
  `rx_len`. Keystore mutex in `fb86c4ed`. `MSG_SEND_IDENTITY` is
  accepted only while Settings > Horse Prov has opened a 120 s window;
  the radio shows the public fingerprint and stores only after ENTER
  (`horse_provision_confirm`). Host tests: `horse_provision_sock_test`.

### C16. Mode cycle leaves garbage in `horseInfo_t` -- fixed

- **Was:** Mode switch left FM/M17 bits in the Horse channel union.
- **Fix:** `1ca16357` zeros `channel.horse` on switch to Horse. Test:
  `horse_info_test`.

### C17. LDPC / MELPe names vs reality -- fixed (protocol v2)

- **Was:** `ldpc_horse.c` repeat-2 misnamed as LDPC; fragile voice FEC.
- **Fix:** Option-C M17 convolutional coding via existing
  `ConvolutionalEncoder` / `DATA_PUNCTURE` / interleaver / decorrelator /
  `HardViterbi` (`0de39b89`). `ldpc_horse.*` removed. Codec remains
  CODEC2 2400 (`melpe_horse.c` name kept for path continuity).
- **Normative:** `docs/horse/HORSE_FEC_V2.md` option C / section 7b.

### C20. LSF has no FEC and no checksum -- fixed (protocol v2)

- **Was:** single uncoded 46-byte LSF; reception limit on analog
  loopback (121/200 intact at sigma 10000).
- **Fix:** three M17-coded opening frames covering 46 B + `crc_m17`
  (`4003bcf2`); cycle-10 spare fragments with majority combine
  (`d2e4405d`); late entry on voice sync (`b1ceb6b0`); version byte 2
  and new sync words (`dc8c906a`).
- **Normative:** `docs/horse/HORSE_FEC_V2.md` section 7b.

### C18. Tests do not cover the claims -- fixed

Host analog loopback (`tests/unit/horse_loopback.cpp`) covers layers a–d.
Session-keyed voice MAC (C1) is covered by `tests/unit/horse_crypto.cpp`.
Three-mode modem loopback is in `horse_session_modem.cpp`.
`horse_test_opmode_buffer_e2e` drives `OpMode_Horse::sendTxVoiceFrame`
for encrypt, sign, and combined (cleartext TX refused by C2). Optional
RF / C5000 on-air checks stay in HARDWARE_TEST_PLAN steps 3–6 (not open
software bugs).

### Cost figures (host, protocol v2)

| Item | Value |
|------|------:|
| Hard Viterbi decode (m17_hard, noise 0, n=5000) | 82.4 us/frame |
| Hard Viterbi decode (noise 10000, n=2000) | 82.2 us/frame |
| `sizeof(HorseFrameDecoder)` | 454 B (fragCopy 360 B of that) |
| `sizeof(HorseFrameEncoder)` | 116 B |
| `sizeof(HorseDemodulator)` | 416 B |
| `sizeof(M17::HardViterbi)` | 2032 B |
| `voice_decode` stack (`-Wstack-usage`, host g++) | 2208 B |

Gate for decode time is <= 5 ms/frame (section 16); host meets it.
Static RAM added vs pre-fragment decoder is dominated by `fragCopy`
(~360 B) plus small counters. On MD-3x0, `voice_decode` is 16 B
(`-Wstack-usage`); `SoftViterbi::decodePunctured` 88 B; `txState`
128 B on the 512 B RTX stack. libsodium runs on the 16 KiB worker.

### MD-3x0 link with libsodium 1.0.20 (estimates marked)

Seed tarball sha256
`ebb65ef6ca439333c2bb41a0c1990587288da07f6c7fd07cb3a18cc18d30ce19`.
Autotools: `--disable-shared --enable-static --disable-ssp --disable-pie
--disable-asm --disable-blocking-random`, CFLAGS `-Os` Cortex-M4 hard
float, `RANDOMBYTES_CUSTOM_IMPLEMENTATION`. Not `--enable-minimal`
(drops `crypto_stream_xchacha20`). Unused objects dropped by
`--gc-sections`. Randomness: STM32F405 HASH_RNG (PLL48 / PLL_Q=7),
Horse `horse_randombytes` (not `rng_get`): SECS/CECS/SEIS/CEIS on every
read, discard first word after enable, reject consecutive identical
words, pthread mutex for the crypto worker. Failure is sticky;
`HORSE_ERR_RNG` and no TX. Mocked in `horse_randombytes_test`. Platform
`rng.c` is unchanged so non-Horse radios can match `upstream/master`.

| Region | Before sodium | After sodium |
|--------|--------------:|-------------:|
| flash (848 KiB) | 240896 B (27.74%) | 350000 B (40.31%) |
| CCM smallram (64 KiB) | 29328 B (44.75%) | 30800 B (47.00%) |
| largeram (130560 B) | 40 KiB framebuffer | 40 KiB framebuffer |
| ELF text/data/bss | 239120 / 1776 / 68512 | 347096 / 2904 / 68856 |
| heap (`_end` 0x2000a200 to `_heap_end` 0x20020000) | 89600 B | 89600 B |

Heap 89600 B vs Argon2id 16384 + worker stack 16384 + codec stack 16384
= 49152 B. Remainder ~40 KiB for other mallocs. **Runtime heap HWM
unverified on the radio.**

ARM `-Wstack-usage` / `.su` (bytes, static):

| Path | Stack |
|------|------:|
| `OpMode_Horse::txState` (RTX) | 128 |
| `OpMode_Horse::rxState` | 72 |
| `sendTxVoiceFrame` | 72 |
| `SoftViterbi::decodePunctured` voice | 88 |
| `melpe_horse_encode_20ms` (codec thread) | 664 |
| worker `generate_addresses` (Argon2id) | 4120 |
| worker `ge25519_scalarmult` | 4048 |
| worker `ge25519_double_scalarmult_vartime` (verify) | 2344 |
| worker `crypto_scalarmult_curve25519_ref10` | 440 |
| `sodium_stackzero` | unbounded warning; Horse does not call it |

Timing **estimates** (not DWT traces). 168 MHz. C ref10, `-Os`, no asm.
Published Cortex-M4 C curve25519/ed25519 figures scaled to this clock;
Viterbi from host 82 us scaled by ~3 GHz/168 MHz.

| Op | Estimate |
|----|----------|
| X25519 scalarmult or keypair | ~8e6 cycles, ~48 ms |
| Ed25519 sign | ~6e6 cycles, ~36 ms |
| Ed25519 verify | ~10e6 cycles, ~60 ms |
| Argon2id m=16384 t=2 (unlock, not PTT) | ~15 ms |
| Soft Viterbi / voice frame | ~1.5 ms (host 82 us) |
| PTT to `radio_enableTx`, encrypt | ~96 ms (keypair + derive) |
| PTT to key, signed or both | ~132 ms (keypair + sign + derive) |

TX encrypt failure now encodes EOT, unkeys, `HORSE_ERR_TX_CRYPTO`
(host test `horse_tx_fail_test`).

Non-Horse `openrtx_mduv3x0` / `openrtx_gd77` vs `upstream/master`
v0.4.5 (`34052ea7`) with the same `GIT_VERSION` string `v0.4.5`
(`-Dgit_version=v0.4.5` on this branch; `git describe` on master):
flash images are byte-identical (`objcopy -O binary`). `rtxStatus_t`
Horse overlay and `horseInfo_t` are behind `CONFIG_HORSE`. ELF
relocatable objects can still differ in DWARF compile directories.
Sodium is not linked on those radios.

GitHub CI on this fork: clang-format on Horse files that the format
script checks; unit tests with junit extra args; Cortex-M4 meson setup
must not require a successful sodium prebuild. Crypto tests skip
without a host libsodium package.

First failing layer before the demod fix was **c**. Commits:

| Commit | Change |
|--------|--------|
| `b425dbf3` | RRC always on host; `setSymbol` inverse; TX RRC reset |
| `2e3bbe98` | `CORR_SYNC_SCALE` 18 for mixed `±1`/`±3` sync words |
| `f9cac93d` | lock at correlator peak, not M17 falling edge |
| `09ff4e7f` | peak-abs slicing so LSF inner symbols stay inner |
| `12dea76f` | correlator window aligned with `convolve()`; loopback first pass; `should_fail` removed |
| `4d301939` | acquire/track LSF, voice and EOT; Hamming 0 lock / 2 track; `readyFrame` after swap |
| `af1704cf` | DC-block loopback variant |

Acquisition uses Hamming 0. Tracking uses Hamming 2 and checks
`readyFrame` after the swap (M17 still inspects the emptied `demodFrame`;
see `UPSTREAM_ISSUE_dsp.md`).

**Baseband regression baselines** (payload must match; not RF sensitivity):

| Impairment | Pass | Fail |
|------------|------|------|
| Uniform noise amplitude vs outer ~21861 | 12500 | 17000 (v2 sync E2=64 + 3-frame opening; gate >=13000); post-v2 remeasure `first_noise_fail=17000` |
| Sample-rate offset | 400 ppm | 450 ppm; post-v2 `first_ppm_fail=450` |
| Polarity invert without `invertPhase` | 0/3 frames | -- |
| Polarity invert with `invertPhase` | 3/3 | -- |
| DC offset 500 | 3/3 | -- |
| Gain 0.25 | 3/3 | -- |
| Drop first TX frame | 3/3 | -- |

Host coverage for C1/C4/C18 is in the status table. On-air MD-3x0 TX/RX
remains HARDWARE_TEST_PLAN (not an open software finding).

### C19. Keys not wiped with `sodium_memzero` -- fixed

- **Was:** wrap key left on the stack after unlock; `memset` on
  `sessionKey` / `eph_sk` (compiler may drop).
- **Fix:** `c6bdad06` / `fb86c4ed` use `sodium_memzero` on wrap keys,
  eph_sk, session_key, and identity copies.

### C21. Horse MD-3x0 channel bandwidth 12.5 kHz vs M17 25 kHz -- open

- **Where:** `radio_MD3x0.cpp` `radio_setOpmode`: M17 calls
  `_setBandwidth(BW_25)` (WN_SW set, `setModFactor(0x3C)`) with the
  comment "for proper deviation"; Horse calls `_setBandwidth(BW_12_5)`
  (WN_SW clear, `setModFactor(0x1E)`). `radio_enableTx` passes
  `FmConfig::BW_25kHz` for M17 and `FmConfig::BW_12p5kHz` for Horse
  into `C5000.startAnalogTx` (register 0x34 bit 4).
- **Analysis (no meter):** Horse is the same 4800 sym/s 4-FSK outer
  constellation as M17. Halving the FM modulation factor from `0x3C`
  to `0x1E` is expected to roughly halve TX deviation for the same
  LINE_IN level. M17 deliberately used 25 kHz for deviation, not for
  a 25 kHz regulatory channel claim alone. A ±2.4 kHz-class 4-FSK
  signal fits inside a 12.5 kHz channel filter in theory, but if TX
  deviation is half of what the demodulator / correlator was tuned
  for under M17 levels, acquire and SER can degrade. The RX path uses
  the same WN_SW setting as TX for the selected opmode.
- **Decision:** Do **not** change Horse to BW_25 without a deviation
  meter or SDR capture comparing both settings. Measurement steps are
  in `HARDWARE_TEST_PLAN.md`. Untested on hardware.

---

## Suspicions (resolved)

- `HORSE_IDENTITY_NVM_OFFSET 0x00FE0000`: last 128 KiB of the 16 MiB
  W25Qx (`nvmem_MDx.c` area 0 size `0x1000000`). Calib is in security
  registers; OpenRTX settings are internal flash sector 11 at
  `0x080E0000`. Documented in `horse_keystore.c`. Device write still
  needs hardware (HARDWARE_TEST_PLAN step 1).
- Linux provisioning socket: host tests cover path/mode/SIGPIPE;
  menu confirm is in `horse_provision_sock_test`. Emulator headless
  E2E with `openrtx_linux` + `horse_provision.py` is possible
  (`SDL_VIDEODRIVER=dummy` works; shell `key` can open Settings >
  Horse Prov) but is not automated in meson yet because menu index
  depends on `CONFIG_*` feature set; socket-level tests cover the
  protocol. Manual: `PROVISIONING.md`.
- Identity fingerprint: BLAKE2b keyed `"HORSE-IDFP"` over public keys
  only (intentional).
- OpenPGP: unchanged; see `PROVISIONING.md` / `TEST_RESULTS.md`.
- MDx `data[1024]` overlay vs 128 KB sector 11: **pre-existing
  upstream** in `nvmem_settings_MDx.c` (same layout on
  `upstream/master`). Not a Horse regression; Horse no longer grows
  `settings_t`. Tracked as upstream structural risk, not a Horse bug.
- `horse_identity_store_t`: packed; `static_assert` on size 290 and
  field offsets matching Python (`horse_keystore.c`).

---

## ASan / UBSan

Early ASan run caught C4 (`Horse Frame` stack-buffer-overflow) and
UBSan on upstream `dsp_dcBlockFilter` (`dsp.cpp:19`). C4 is fixed
(`c3f68754` / packing `13ac0cef`). The DC-block UB was fixed upstream
in OpenRTX/OpenRTX#564 (`f403de9d`, multiply instead of left shift).
After rebasing onto that commit, drop the fork
`-fno-sanitize=shift` workaround (`83e4a806`).

Unsanitized `meson test -C build_linux` covers Horse Frame, Loopback,
and OpMode buffer E2E. Fuzz targets were not run.

---

## What matches `horse.md`

Frame size 192 symbols / 48 bytes, sync **bytes**, LSF 46-byte layout,
flags `0x01`/`0x02`, TX order LSF then six signature frames then voice
then EOT (when `signTx` is set). Symbol LUT on TX. Linux dump path
`/tmp/horse_output.raw`. ECIES wrap APIs exist and are unused on the
live path, as documented.
