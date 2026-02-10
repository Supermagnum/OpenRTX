## Horse digital voice mode (experimental)

Horse is an **experimental encrypted digital voice mode** implemented in this fork for the TYT MD‑3x0 family.  
It reuses large parts of the M17 DSP chain but defines its own framing and cryptography.

> Important: Horse is experimental and under active development.  
> Cryptographic implementations use libsodium where available (Linux builds), but embedded targets may use fallback implementations.  
> This mode should not be relied upon for production secure communication until fully audited.

### Why is it named "Horse"?

Horse mode uses **4‑FSK (4‑level Frequency Shift Keying)** modulation, so it has "4 legs" — hence the name "Horse".

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

### Modulation details

Horse uses **4‑FSK (4‑level Frequency Shift Keying)** modulation:

- **Type:** 4‑FSK (4‑level FSK)
- **Symbol rate:** 4800 symbols/s
- **Symbol mapping:** Each byte maps to 4 symbols via a lookup table:
  - `00` → `+1`
  - `01` → `+3`
  - `10` → `-1`
  - `11` → `-3`
- **Filtering:** Root‑raised cosine (RRC) filter from M17 DSP (`M17::rrc_48k`) at 48 kHz sample rate
- **RF characteristics:**
  - Constant‑envelope 4‑FSK (same RF path as M17)
  - Occupies a standard 12.5 kHz channel
  - M17‑compatible RF characteristics

Modulation is generated in `HorseModulator`:

- Symbol stream is produced as small integer levels (4‑level symbols) and written into a 48 kHz baseband buffer.
- A **root‑raised cosine (RRC)** filter from the existing M17 DSP (`M17::rrc_48k`) shapes the symbols.
- On RF, the same constant‑envelope 4‑FSK path used by M17 is reused, so Horse occupies a standard 12.5 kHz channel with M17‑compatible RF characteristics.

For Linux builds, baseband samples are written to `/tmp/horse_output.raw` for analysis.

---

## Encryption, signing, and keying

Horse uses modern cryptographic primitives with per‑session keys and optional signing:

- **Long‑term identity keys:** Ed25519/X25519 keypairs stored in `horse_identity_keys_t` structure:
  - **Ed25519** (32‑byte public, 64‑byte secret): used for digital signatures
  - **X25519** (32‑byte public, 32‑byte secret): used for key exchange
  - Keys are provisioned to the radio via `horse_provision.py` and stored encrypted with a user passphrase
- **Session keys:** 32‑byte symmetric keys generated per call (`HORSE_SESSION_KEY_BYTES`).
- **Public‑key encryption (ECIES‑style):**
  - Curve: **X25519** (elliptic‑curve Diffie‑Hellman).
  - API in `horse_crypto.h`:
    - `horse_crypto_ecies_encrypt_session_key(...)` — wraps session key using X25519 ECDH + XChaCha20‑Poly1305
    - `horse_crypto_ecies_decrypt_session_key(...)` — unwraps session key using recipient's X25519 secret key
  - Flow:
    1. On transmit, a fresh 32‑byte session key is generated.
    2. An ephemeral X25519 keypair is generated.
    3. ECDH is performed: `shared = ephemeral_sk * recipient_x25519_pk`
    4. AEAD key and nonce are derived from the shared secret via BLAKE2b.
    5. Session key is encrypted with XChaCha20‑Poly1305 (detached tag).
    6. Ephemeral public key + ciphertext + tag are carried in Horse link setup signalling.
- **Voice encryption (XChaCha20 + BLAKE2b MAC):**
  - API in `horse_crypto_voice_encrypt(...)` / `horse_crypto_voice_decrypt(...)`.
  - Algorithm: **XChaCha20 stream cipher** with a 96‑bit nonce expanded to 192 bits and a **BLAKE2b‑derived 32‑bit MAC** carried in the `VOICE_TAG_BITS` field.
- **Digital signatures (Ed25519):**
  - API in `horse_crypto.h`:
    - `horse_crypto_sign(...)` — sign data with Ed25519 secret key
    - `horse_crypto_verify(...)` — verify Ed25519 signature with public key
  - Use case: Sign voice frames or control messages **without encryption** for authentication and non‑repudiation.
  - Signatures are 64 bytes (`HORSE_ED25519_SIGNATURE_BYTES`) and can be carried alongside voice payload or in link setup frames.
- **Passphrase‑based key derivation (Argon2id):**
  - API in `horse_crypto_argon2id_derive(...)`.
  - Implemented via libsodium’s `crypto_pwhash` API where available, with a PBKDF2 fallback on platforms that do not ship libsodium.
  - Used to derive encryption keys from user passphrases for protecting stored private keys.

**Implementation status:**

- **ECIES session key wrapping:** Fully implemented with libsodium (X25519 + XChaCha20‑Poly1305) on Linux builds.
- **Voice encryption:** Fully implemented with libsodium (XChaCha20 + BLAKE2b MAC) on Linux builds.
- **Digital signatures:** Fully implemented with libsodium (Ed25519) on Linux builds.
- **Argon2id:** Implemented via libsodium where available, PBKDF2 fallback otherwise.
- **Embedded targets:** Fall back to placeholder implementations when libsodium is not available (cleartext mode).

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

### How identity keys fit into this design

Horse identity keys use **Ed25519/X25519** (not GnuPG/OpenPGP directly). The workflow is:

1. **Key generation:** Use `horse_provision.py generate <label>` on a desktop system:
   - Generates Ed25519/X25519 keypairs using libsodium (PyNaCl).
   - Stores the identity in the Linux kernel keyring for secure intermediate storage.
2. **Provisioning to radio:** Use `horse_provision.py provision <label> [--port DEVICE]`:
   - Exports the identity from the kernel keyring.
   - Sends it to the radio over USB‑CDC serial.
   - Radio stores it encrypted with a user passphrase (via `horse_crypto_argon2id_derive`).
3. **At runtime:**
   - Radio unlocks stored identity keys using the user's passphrase.
   - For encrypted transmission: uses X25519 public key from contact to wrap session keys.
   - For signed transmission: uses Ed25519 secret key to sign voice frames or control messages.
   - Contact public keys are stored in the codeplug or a separate key store, referenced via `contact_index`.

**Key storage model:**

- **Desktop side:** Keys stored in Linux kernel keyring (`@user` keyring) with label `openrtx:horse:<label>`.
- **Radio side:** Private keys are stored encrypted in flash, wrapped with a key derived from the user's Horse passphrase.
- **Codeplug:** Stores contact public keys (Ed25519/X25519) or references to them, not private keys.

**Current implementation status:**

- `horse_provision.py` provides full key generation and provisioning workflow.
- Firmware crypto functions are implemented with libsodium on Linux builds.
- Embedded targets (STM32/MK22) use fallback implementations until libsodium is ported.

---

## Provisioning and key management tools

This fork includes two tools for Horse key management:

### `horse_provision.py` – identity generation and provisioning

- **Location:** `scripts/horse_provision.py`  
- **Purpose:** Generate Ed25519/X25519 identities and provision them to radios.
- **Dependencies:** `pynacl`, `pyserial`, `keyutils` (for kernel keyring access).

**Commands:**

- `generate <label>` — Generate a new Horse identity and store it in the kernel keyring.
- `list` — List all stored identities in the keyring.
- `show <label>` — Display identity details (public keys, fingerprints).
- `provision <label> [--port DEVICE]` — Send identity to radio over USB‑CDC serial.

**Example workflow:**

```bash
# Generate identity for operator "M0ABC"
python3 scripts/horse_provision.py generate M0ABC

# List stored identities
python3 scripts/horse_provision.py list

# Provision identity to radio (auto-detects USB serial port)
python3 scripts/horse_provision.py provision M0ABC

# Or specify port manually
python3 scripts/horse_provision.py provision M0ABC --port /dev/ttyACM0
```

### `horse_keytool.py` – collecting Horse public keys from GnuPG

- **Location:** `scripts/horse_keytool.py`  
- **Purpose:** Collect public keys for Horse contacts from:
  - OpenPGP key files (`.asc`, `.pgp`), and
  - keys already present in the user’s GnuPG keyring (including smartcards / Nitrokey),
  and write them into a single JSON mapping file for later use by codeplug tooling.

### Inputs

The tool is a command‑line program that accepts one or more `--contact` arguments:

- `--contact NAME:KEYREF`
  - **NAME**: human‑readable contact name or callsign (e.g. `M0ABC`).
  - **KEYREF**:
    - a path to an ASCII‑armored `.asc` or binary `.pgp` key file, **or**
    - any key reference that `gpg --export` understands (fingerprint, key ID, email, etc.).

Because it uses the standard `gpg` command, keys backed by **Nitrokey** or other smartcards, and keys cached in the **kernel keyring** via GnuPG, are handled transparently as long as GnuPG can export them.

### Output

- `--output / -o PATH` selects an output file, typically `horse_keys.json`.
- The JSON file has the structure:
  - `version`: schema version (integer).
  - `generated_at`: ISO‑8601 UTC timestamp.
  - `entries`: array of objects, each with:
    - `name`: contact name/callsign.
    - `key_ref`: original reference (file path or GnuPG spec).
    - `source`: `"file"` or `"gpg"`.
    - `format`: `"ascii"`, `"text"`, or `"binary"`.
    - `public_key`: the exported public key:
      - ASCII‑armored text for keys coming from GnuPG or `.asc` files.
      - Hex‑encoded binary for `.pgp` files.

### Example usage

From the repository root:

```bash
python3 scripts/horse_keytool.py \
  --output horse_keys.json \
  --contact M0ABC:/path/to/m0abc.asc \
  --contact M0DEF:/path/to/m0def.pgp \
  --contact M0GHI:0xDEADBEEFCAFEBABE
```

This command will:

- Read the `.asc` and `.pgp` files directly.
- Ask `gpg --export --armor 0xDEADBEEFCAFEBABE` for the third contact.
- Write a combined `horse_keys.json` containing public‑key material for all three Horse contacts.

---

## Developer reference

- **Protocol types and framing:**
  - `openrtx/include/protocols/horse/HorseDatatypes.hpp`
  - `openrtx/include/protocols/horse/HorseConstants.hpp`
- **DSP / modulation path:**
  - `openrtx/src/protocols/horse/HorseModulator.cpp`
- **Cryptography API:**
  - `openrtx/include/protocols/horse/horse_crypto.h` — API definitions
  - `openrtx/src/protocols/horse/horse_crypto.c` — Implementation (libsodium on Linux, fallbacks on embedded)
  - Functions:
    - `horse_crypto_ecies_encrypt_session_key()` / `horse_crypto_ecies_decrypt_session_key()` — Session key wrapping (X25519 + XChaCha20‑Poly1305)
    - `horse_crypto_voice_encrypt()` / `horse_crypto_voice_decrypt()` — Voice frame encryption (XChaCha20 + BLAKE2b MAC)
    - `horse_crypto_sign()` / `horse_crypto_verify()` — Digital signatures (Ed25519)
    - `horse_crypto_argon2id_derive()` — Passphrase‑based key derivation
- **Codeplug integration:**
  - `openrtx/include/core/cps.h` (`horseInfo_t`, `horseContact_t`, and `channel_t` / `contact_t` unions)

## Usage modes

Horse supports two operational modes:

1. **Encrypted mode:** Voice frames are encrypted with XChaCha20 using a session key wrapped via X25519 ECDH. Provides confidentiality and authentication (via MAC).

2. **Signed mode:** Voice frames are sent in cleartext but signed with Ed25519. Provides authentication and non‑repudiation without encryption. Use `horse_crypto_sign()` to sign frames and `horse_crypto_verify()` to verify received signatures.

Both modes can be used independently or combined (encrypted + signed frames).

---

This document describes the **current implementation** of Horse as implemented in this fork.  
Horse is experimental and under active development. Cryptographic implementations use audited libraries (libsodium) where available, but should be reviewed before production use.

