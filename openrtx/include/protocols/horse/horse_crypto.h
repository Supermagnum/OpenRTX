/*
 * SPDX-FileCopyrightText: Copyright 2020-2026 OpenRTX Contributors
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Horse crypto API: ECIES (BrainpoolP256r1), ChaCha20-Poly1305, Argon2id.
 * LSF and voice are unencrypted until real implementations are wired;
 * key/passphrase handling is for a later phase.
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
#define HORSE_VOICE_TAG_BYTES   4
#define HORSE_PUBKEY_BYTES      65

/* Session key encrypt (ECIES): encrypt 32-byte session key for recipient pubkey.
 * Out: ephemeral_pubkey[65], ciphertext[32+16], tag[16]. Placeholder: no-op. */
bool horse_crypto_ecies_encrypt_session_key(
    const uint8_t *recipient_pubkey,
    const uint8_t *session_key,
    uint8_t *ephemeral_pubkey_out,
    uint8_t *ciphertext_out,
    uint8_t *tag_out);

/* Session key decrypt (ECIES): decrypt session key using private key. Placeholder: no-op. */
bool horse_crypto_ecies_decrypt_session_key(
    const uint8_t *ephemeral_pubkey,
    const uint8_t *ciphertext,
    const uint8_t *tag,
    uint8_t *session_key_out);

/* Voice frame encrypt: ChaCha20-Poly1305. Placeholder: copy plaintext to ciphertext. */
void horse_crypto_voice_encrypt(
    const uint8_t *session_key,
    const uint8_t *nonce_96bit,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t *ciphertext_out,
    uint8_t *tag_truncated_32bit);

/* Voice frame decrypt. Placeholder: copy ciphertext to plaintext. */
bool horse_crypto_voice_decrypt(
    const uint8_t *session_key,
    const uint8_t *nonce_96bit,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t *tag_truncated_32bit,
    uint8_t *plaintext_out);

/* Derive key from passphrase (Argon2id). Placeholder: use PBKDF2. */
bool horse_crypto_argon2id_derive(
    const char *passphrase,
    size_t passphrase_len,
    const uint8_t *salt,
    size_t salt_len,
    uint8_t *key_out,
    size_t key_len);

/* Unlock stored private key with passphrase. Placeholder: not implemented. */
bool horse_crypto_unlock_private_key(const char *passphrase, size_t len);

#ifdef __cplusplus
}
#endif

#endif
