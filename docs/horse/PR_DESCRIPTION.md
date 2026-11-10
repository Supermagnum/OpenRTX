# Horse upstream submission (draft)

Series based on upstream `master`, tip `horse/pr-07-openpgp`.
OpenPGP (`pr-07`) is optional and can follow later.

## PR stack

| PR | Branch | Contents |
|----|--------|----------|
| 01 | `horse/pr-01-build-libsodium` | Optional libsodium, empty `horse_src` |
| 02 | `horse/pr-02-frames` | Frames, MELPe glue, frame/codec tests |
| 03 | `horse/pr-03-modem` | Modulator/demodulator (no FEC v2 research) |
| 04 | `horse/pr-04-crypto` | Crypto, keystore, peers, heap, loopback tests |
| 05 | `horse/pr-05-rtx-ui` | OpMode, MD-3x0, UI, CONFIG_HORSE, CI |
| 06 | `horse/pr-06-provision` | Provisioning protocol and host tool |
| 07 | `horse/pr-07-openpgp` | Optional OpenPGP helper (possible later PR) |

FEC v2 design-time simulations live on fork-only `horse/research-fec-v2`.
This docs/fuzz branch is fork-only support material, not an upstream PR.

## CI notes (Part 1)

Fork pushes to an open upstream PR branch spend upstream CI minutes
(about three workflows per push). Prefer enabling Actions on the fork and
validating there before any push to a branch with an open upstream PR.

Hardware RF remains untested (C21 open).
