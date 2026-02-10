/*
 * SPDX-FileCopyrightText: Copyright 2020-2026 OpenRTX Contributors
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Horse crypto API.
 *
 * Current implementation uses libsodium where available:
 *  - XChaCha20 stream cipher + BLAKE2b-based 32-bit MAC for voice frames
 *  - X25519 ECDH + XChaCha20-Poly1305 for session key wrapping (ECIES-style)
 *  - Ed25519 for digital signatures (without encryption)
 *  - Argon2id (via crypto_pwhash) for passphrase-based key derivation
 *
 * All functions have fallback implementations for platforms without libsodium.
 */

#ifndef HORSE_CRYPTO_H
#define HORSE_CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HORSE_SESSION_KEY_BYTES  32
#define HORSE_VOICE_TAG_BYTES    4

/* Horse identity keys (libsodium-native sizes). */
#define HORSE_ED25519_PUBLICKEY_BYTES  32
#define HORSE_ED25519_SECRETKEY_BYTES  64
#define HORSE_X25519_PUBLICKEY_BYTES   32
#define HORSE_X25519_SECRETKEY_BYTES   32

/* AEAD used for session key wrapping (XChaCha20-Poly1305). */
#define HORSE_AEAD_XCHACHA20_NONCE_BYTES 24
#define HORSE_AEAD_TAG_BYTES             16

/* Ed25519 signature sizes. */
#define HORSE_ED25519_SIGNATURE_BYTES    64

/* Identity key bundle stored/provisioned to the radio. */
typedef struct
{
    uint8_t version; /* must be 1 */
    uint8_t reserved[3];

    uint8_t ed25519_pk[HORSE_ED25519_PUBLICKEY_BYTES];
    uint8_t ed25519_sk[HORSE_ED25519_SECRETKEY_BYTES];

    uint8_t x25519_pk[HORSE_X25519_PUBLICKEY_BYTES];
    uint8_t x25519_sk[HORSE_X25519_SECRETKEY_BYTES];
} __attribute__((packed)) horse_identity_keys_t;

/* Session key wrap (ECIES-like):
 * - X25519 ECDH (ephemeral_sk * recipient_pk)
 * - Derive AEAD key via BLAKE2b generichash
 * - Encrypt session key with XChaCha20-Poly1305 (detached tag)
 *
 * Out:
 *  - ephemeral_pubkey_out[32]
 *  - ciphertext_out[32]
 *  - tag_out[16]
 */
bool horse_crypto_ecies_encrypt_session_key(
    const uint8_t *recipient_x25519_pubkey,
    const uint8_t *session_key,
    uint8_t *ephemeral_pubkey_out,
    uint8_t *ciphertext_out,
    uint8_t *tag_out);

/* Session key unwrap, see horse_crypto_ecies_encrypt_session_key().
 * Input:
 *  - recipient_x25519_seckey[32]
 */
bool horse_crypto_ecies_decrypt_session_key(
    const uint8_t *ephemeral_pubkey,
    const uint8_t *ciphertext,
    const uint8_t *tag,
    const uint8_t *recipient_x25519_seckey,
    uint8_t *session_key_out);

/* Voice frame encrypt: XChaCha20 stream cipher + 32-bit BLAKE2b MAC. */
void horse_crypto_voice_encrypt(
    const uint8_t *session_key,
    const uint8_t *nonce_96bit,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t *ciphertext_out,
    uint8_t *tag_truncated_32bit);

/* Voice frame decrypt with MAC verification. */
bool horse_crypto_voice_decrypt(
    const uint8_t *session_key,
    const uint8_t *nonce_96bit,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t *tag_truncated_32bit,
    uint8_t *plaintext_out);

/* Derive key from passphrase (Argon2id where libsodium is available, PBKDF2 fallback otherwise). */
bool horse_crypto_argon2id_derive(
    const char *passphrase,
    size_t passphrase_len,
    const uint8_t *salt,
    size_t salt_len,
    uint8_t *key_out,
    size_t key_len);

/* Unlock stored private key with passphrase. Placeholder: not implemented. */
bool horse_crypto_unlock_private_key(const char *passphrase, size_t len);

/* Sign data with Ed25519 (without encryption).
 * Input:
 *  - ed25519_secretkey[64]: signing key from horse_identity_keys_t
 *  - message: data to sign
 *  - message_len: length of message
 * Output:
 *  - signature_out[64]: Ed25519 signature
 * Returns true on success, false on failure.
 */
bool horse_crypto_sign(
    const uint8_t *ed25519_secretkey,
    const uint8_t *message,
    size_t message_len,
    uint8_t *signature_out);

/* Verify Ed25519 signature (without decryption).
 * Input:
 *  - ed25519_publickey[32]: verification key from horse_identity_keys_t
 *  - message: signed data
 *  - message_len: length of message
 *  - signature[64]: Ed25519 signature to verify
 * Returns true if signature is valid, false otherwise.
 */
bool horse_crypto_verify(
    const uint8_t *ed25519_publickey,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *signature);

#ifdef __cplusplus
}
#endif

#endif
