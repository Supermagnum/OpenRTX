/*
 * SPDX-FileCopyrightText: Copyright 2020-2026 OpenRTX Contributors
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Horse crypto stubs: LSF and voice unencrypted; key/passphrase for later.
 * Replace with ECIES (BrainpoolP256r1), ChaCha20-Poly1305, Argon2id when ready.
 */

#include "protocols/horse/horse_crypto.h"
#include "core/crypto_utils.h"
#include <string.h>

bool horse_crypto_ecies_encrypt_session_key(
    const uint8_t *recipient_pubkey,
    const uint8_t *session_key,
    uint8_t *ephemeral_pubkey_out,
    uint8_t *ciphertext_out,
    uint8_t *tag_out)
{
    (void)recipient_pubkey;
    (void)ephemeral_pubkey_out;
    memcpy(ciphertext_out, session_key, HORSE_SESSION_KEY_BYTES);
    if (tag_out)
        memset(tag_out, 0, 16);
    return true;
}

bool horse_crypto_ecies_decrypt_session_key(
    const uint8_t *ephemeral_pubkey,
    const uint8_t *ciphertext,
    const uint8_t *tag,
    uint8_t *session_key_out)
{
    (void)ephemeral_pubkey;
    (void)tag;
    memcpy(session_key_out, ciphertext, HORSE_SESSION_KEY_BYTES);
    return true;
}

void horse_crypto_voice_encrypt(
    const uint8_t *session_key,
    const uint8_t *nonce_96bit,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t *ciphertext_out,
    uint8_t *tag_truncated_32bit)
{
    (void)session_key;
    (void)nonce_96bit;
    memcpy(ciphertext_out, plaintext, plaintext_len);
    if (tag_truncated_32bit)
        memset(tag_truncated_32bit, 0, HORSE_VOICE_TAG_BYTES);
}

bool horse_crypto_voice_decrypt(
    const uint8_t *session_key,
    const uint8_t *nonce_96bit,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t *tag_truncated_32bit,
    uint8_t *plaintext_out)
{
    (void)session_key;
    (void)nonce_96bit;
    (void)tag_truncated_32bit;
    memcpy(plaintext_out, ciphertext, ciphertext_len);
    return true;
}

bool horse_crypto_argon2id_derive(
    const char *passphrase,
    size_t passphrase_len,
    const uint8_t *salt,
    size_t salt_len,
    uint8_t *key_out,
    size_t key_len)
{
    if (passphrase == NULL || salt == NULL || key_out == NULL)
        return false;
    return crypto_pbkdf2(passphrase, passphrase_len, salt, salt_len,
                         10000, key_out, key_len) == 0;
}

bool horse_crypto_unlock_private_key(const char *passphrase, size_t len)
{
    (void)passphrase;
    (void)len;
    return false;
}
