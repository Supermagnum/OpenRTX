## Horse digital voice mode (experimental)

Horse is an **experimental encrypted digital voice mode** implemented in this fork for the TYT MD‑3x0 family.  
It reuses large parts of the M17 DSP chain but defines its own framing and (planned) cryptography.

> Important: The current implementation contains **stub cryptography** only.  
> It does not provide real confidentiality yet and must not be relied on for secure communication.

---

## On‑air waveform and framing

- **Symbol rate:** `4800` symbols/s (`SYMBOL_RATE` in `HorseConstants.hpp`).
- **Frame length:** `192` symbols per frame (`FRAME_SYMBOLS`), i.e. `48` bytes (`FRAME_BYTES`).
- **Sync words:**
  - Link Setup Frame (LSF): `LSF_SYNC_WORD = {0x5A, 0xA7}`
  - Voice frame: `VOICE_SYNC_WORD = {0x7E, 0x9B}`
  - End‑of‑Transmission (EOT): `EOT_SYNC_WORD = {0x3C, 0xD8}`
- **Voice payload structure (per frame):**
  - `96` bits MELPe‑2400 voice (`VOICE_MELPE_BITS`)
  - `16`‑bit frame counter (`VOICE_FRAME_COUNTER_BITS`)
  - `32`‑bit authentication/tag field (`VOICE_TAG_BITS`)

Modulation is generated in `HorseModulator`:

- Symbol stream is produced as small integer levels (4‑level symbols) and written into a 48 kHz baseband buffer.
- A **root‑raised cosine (RRC)** filter from the existing M17 DSP (`M17::rrc_48k`) shapes the symbols.
- On RF, the same constant‑envelope 4‑FSK path used by M17 is reused, so Horse occupies a standard 12.5 kHz channel with M17‑compatible RF characteristics.

For Linux builds, baseband samples are written to `/tmp/horse_output.raw` for analysis.

---

## Encryption and keying (design)

Horse is designed to use modern authenticated encryption with per‑session keys:

- **Long‑term identity keys:** stored as GnuPG (OpenPGP) keys on the operator’s workstation.
- **Session keys:** 32‑byte symmetric keys generated per call (`HORSE_SESSION_KEY_BYTES`).
- **Public‑key encryption (ECIES):**
  - Curve: **BrainpoolP256r1** (elliptic‑curve Diffie‑Hellman).
  - API in `horse_crypto.h`:
    - `horse_crypto_ecies_encrypt_session_key(...)`
    - `horse_crypto_ecies_decrypt_session_key(...)`
  - Intended flow:
    1. On transmit, a fresh 32‑byte session key is generated.
    2. The session key is encrypted to the peer’s public key using ECIES.
    3. The resulting ephemeral public key + ciphertext + tag are carried in the Horse link setup signalling.
- **Voice encryption (ChaCha20‑Poly1305):**
  - API in `horse_crypto_voice_encrypt(...)` / `horse_crypto_voice_decrypt(...)`.
  - Algorithm: **ChaCha20‑Poly1305 AEAD** with a 96‑bit nonce.
  - A truncated **32‑bit authentication tag** (`HORSE_VOICE_TAG_BYTES`) is carried alongside each encrypted voice frame.
- **Passphrase‑based key derivation (Argon2id):**
  - API in `horse_crypto_argon2id_derive(...)`.
  - Intended use: derive a symmetric key from a user passphrase to unlock stored private keys.

At present, all of these functions are **placeholders**:

- ECIES functions do not perform real elliptic‑curve operations yet.
- Voice encrypt/decrypt currently copy plaintext/ciphertext buffers without applying ChaCha20‑Poly1305.
- Argon2id‑based derivation is not wired to a real Argon2id implementation.

Until real cryptographic implementations are integrated, Horse behaves effectively as **cleartext over an encrypted signalling design**, suitable only for testing.

---

## Codeplug integration and GnuPG key handling

Horse adds minimal, forward‑compatible fields to the existing codeplug structures in `openrtx/include/core/cps.h`.

### Horse channels

Horse‑specific per‑channel information:

- `horseInfo_t`:
  - `rxCan` / `txCan` (4‑bit each): logical **channel IDs** for receive/transmit.
  - `contact_index` (16‑bit): index into the global contact table, pointing to the Horse contact for this channel.

Each `channel_t` in the codeplug contains a `mode` (FM/DMR/M17/Horse) and a tagged union of mode‑specific data.  
For Horse, the `horse` field of that union is populated with `horseInfo_t`.

### Horse contacts

Horse extends the generic `contact_t` structure with a Horse‑specific view:

- `contact_t`:
  - `name[32]`: human‑readable contact name.
  - `mode`: which mode the contact is for (DMR, M17, Horse, …).
  - `info.horse` (`horseContact_t` when `mode == OPMODE_HORSE`):
    - `address[6]`: Horse address encoded in the same base‑40 scheme used for M17 callsigns.

The current codeplug layout stores:

- A **symbolic identity** (name and base‑40 address) for each Horse contact.
- A **reference** from each Horse channel to a Horse contact via `contact_index`.

### How GnuPG keys fit into this design

GnuPG/OpenPGP keys are **not stored directly** in the codeplug. Instead, the intended model is:

1. Long‑term identity keys are managed by the operator’s normal **GnuPG keyring** on a PC.
2. An external **codeplug generation tool**:
   - Reads the operator’s GnuPG public keys.
   - Extracts or derives the corresponding **elliptic‑curve public keys** suitable for Horse (BrainpoolP256r1).
   - Writes a compact representation of those public keys and identifiers into a Horse‑specific key store (either as an extension to the codeplug format or an associated blob).
   - Fills in `contact_t` entries with:
     - `name` and Horse `address` (base‑40 callsign).
     - A stable mapping between `contact_index` and the derived Horse public key record.
3. At runtime, when transmitting to a Horse contact:
   - The firmware uses `contact_index` to resolve the Horse contact.
   - The associated Horse public key is retrieved from the key store.
   - `horse_crypto_ecies_encrypt_session_key(...)` is called with that public key to encrypt the fresh session key.

Private keys and passphrases **never live in the radio codeplug**:

- The radio stores only:
  - Public keys (or identifiers/indices to them).
  - Derived session keys in RAM for the lifetime of a call.
- Private keys remain on the operator’s secure workstation or a separate secure element.
- If a future implementation adds on‑device private keys, they are intended to be:
  - Encrypted at rest.
  - Unlocked via a passphrase processed through `horse_crypto_argon2id_derive(...)` / `horse_crypto_unlock_private_key(...)`.

At the current stage of development, the Horse codeplug fields are fully defined, but:

- The external toolchain that integrates with GnuPG to populate Horse keys is **not yet implemented**.
- The firmware uses Horse contacts and channels structurally, but does not yet perform real public‑key encryption.

---

## Developer reference

- **Protocol types and framing:**
  - `openrtx/include/protocols/horse/HorseDatatypes.hpp`
  - `openrtx/include/protocols/horse/HorseConstants.hpp`
- **DSP / modulation path:**
  - `openrtx/src/protocols/horse/HorseModulator.cpp`
- **Cryptography API (stubs):**
  - `openrtx/include/protocols/horse/horse_crypto.h`
  - `openrtx/src/protocols/horse/horse_crypto.c`
- **Codeplug integration:**
  - `openrtx/include/core/cps.h` (`horseInfo_t`, `horseContact_t`, and `channel_t` / `contact_t` unions)

This document describes the **intended design** of Horse as implemented in this fork.  
Until the cryptographic primitives are fully implemented and reviewed, Horse must be treated as an experimental feature for development and interoperability testing only.

