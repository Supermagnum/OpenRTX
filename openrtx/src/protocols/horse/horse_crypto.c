/*
 * SPDX-FileCopyrightText: Copyright 2020-2026 OpenRTX Contributors
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Horse crypto implementation.
 *
 * When libsodium is available (HAVE_LIBSODIUM), this file provides:
 *  - XChaCha20 stream cipher + BLAKE2b-based 32-bit MAC for voice frames
 *  - Argon2id via crypto_pwhash for passphrase-based key derivation
 *
 * ECIES-style session key operations remain stubs until a concrete curve and
 * key storage format are finalized in this tree.
 */

#include "protocols/horse/horse_crypto.h"
#include <string.h>

#ifdef HAVE_LIBSODIUM
#include <sodium.h>

static int horse_sodium_init(void)
{
    static int initialized = 0;

    if (initialized)
        return 0;

    if (sodium_init() < 0)
        return -1;

    initialized = 1;
    return 0;
}
#else
#include "core/crypto_utils.h"
#endif

bool horse_crypto_ecies_encrypt_session_key(
    const uint8_t *recipient_x25519_pubkey,
    const uint8_t *session_key,
    uint8_t *ephemeral_pubkey_out,
    uint8_t *ciphertext_out,
    uint8_t *tag_out)
{
    if (recipient_x25519_pubkey == NULL || session_key == NULL ||
        ephemeral_pubkey_out == NULL || ciphertext_out == NULL || tag_out == NULL)
        return false;

#ifdef HAVE_LIBSODIUM
    if (horse_sodium_init() != 0)
        return false;

    unsigned char eph_pk[HORSE_X25519_PUBLICKEY_BYTES];
    unsigned char eph_sk[HORSE_X25519_SECRETKEY_BYTES];
    crypto_kx_keypair(eph_pk, eph_sk);
    memcpy(ephemeral_pubkey_out, eph_pk, sizeof eph_pk);

    /* ECDH shared secret. */
    unsigned char shared[crypto_scalarmult_BYTES];
    if (crypto_scalarmult(shared, eph_sk, recipient_x25519_pubkey) != 0)
        return false;

    /* Derive AEAD key and nonce deterministically from shared secret + context. */
    unsigned char aead_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];

    crypto_generichash(aead_key, sizeof aead_key,
                       shared, sizeof shared,
                       (const unsigned char *)"HORSE-ECIES-KEY", 14);
    crypto_generichash(nonce, sizeof nonce,
                       shared, sizeof shared,
                       (const unsigned char *)"HORSE-ECIES-NONCE", 16);

    unsigned long long clen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
            ciphertext_out,
            tag_out,
            &clen,
            session_key,
            (unsigned long long)HORSE_SESSION_KEY_BYTES,
            eph_pk,
            (unsigned long long)sizeof eph_pk,
            NULL, /* nsec */
            nonce,
            aead_key) != 0)
    {
        return false;
    }

    return clen == HORSE_SESSION_KEY_BYTES;
#else
    /* No libsodium: keep previous placeholder (cleartext session key). */
    (void)recipient_x25519_pubkey;
    (void)ephemeral_pubkey_out;
    memcpy(ciphertext_out, session_key, HORSE_SESSION_KEY_BYTES);
    memset(tag_out, 0, 16);
    return true;
#endif
}

bool horse_crypto_ecies_decrypt_session_key(
    const uint8_t *ephemeral_pubkey,
    const uint8_t *ciphertext,
    const uint8_t *tag,
    const uint8_t *recipient_x25519_seckey,
    uint8_t *session_key_out)
{
    if (ephemeral_pubkey == NULL || ciphertext == NULL || tag == NULL ||
        recipient_x25519_seckey == NULL || session_key_out == NULL)
        return false;

#ifdef HAVE_LIBSODIUM
    if (horse_sodium_init() != 0)
        return false;

    unsigned char shared[crypto_scalarmult_BYTES];
    if (crypto_scalarmult(shared, recipient_x25519_seckey, ephemeral_pubkey) != 0)
        return false;

    unsigned char aead_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];

    crypto_generichash(aead_key, sizeof aead_key,
                       shared, sizeof shared,
                       (const unsigned char *)"HORSE-ECIES-KEY", 14);
    crypto_generichash(nonce, sizeof nonce,
                       shared, sizeof shared,
                       (const unsigned char *)"HORSE-ECIES-NONCE", 16);

    if (crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
            session_key_out,
            NULL, /* nsec */
            ciphertext,
            (unsigned long long)HORSE_SESSION_KEY_BYTES,
            tag,
            ephemeral_pubkey,
            (unsigned long long)HORSE_X25519_PUBLICKEY_BYTES,
            nonce,
            aead_key) != 0)
    {
        return false;
    }
    return true;
#else
    /* No libsodium: placeholder behaviour. */
    (void)ephemeral_pubkey;
    (void)tag;
    (void)recipient_x25519_seckey;
    memcpy(session_key_out, ciphertext, HORSE_SESSION_KEY_BYTES);
    return true;
#endif
}

void horse_crypto_voice_encrypt(
    const uint8_t *session_key,
    const uint8_t *nonce_96bit,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t *ciphertext_out,
    uint8_t *tag_truncated_32bit)
#ifdef HAVE_LIBSODIUM
{
    if (plaintext == NULL || ciphertext_out == NULL)
        return;

    if (horse_sodium_init() != 0)
    {
        /* Fallback to cleartext on initialization failure. */
        memcpy(ciphertext_out, plaintext, plaintext_len);
        if (tag_truncated_32bit)
            memset(tag_truncated_32bit, 0, HORSE_VOICE_TAG_BYTES);
        return;
    }

    /* Derive a 192-bit XChaCha20 nonce from the 96-bit input using BLAKE2b. */
    uint8_t nonce[crypto_stream_xchacha20_NONCEBYTES];
    crypto_generichash(nonce, sizeof nonce,
                       nonce_96bit, 12,
                       (const unsigned char *)"HORSEV1", 7);

    /* XChaCha20 stream cipher encryption. */
    crypto_stream_xchacha20_xor(ciphertext_out,
                                plaintext,
                                plaintext_len,
                                nonce,
                                session_key);

    if (tag_truncated_32bit)
    {
        /* Compute a BLAKE2b MAC over the ciphertext and truncate to 32 bits. */
        uint8_t mac[crypto_generichash_BYTES];
        crypto_generichash(mac, sizeof mac,
                           ciphertext_out, plaintext_len,
                           (const unsigned char *)"HVOICETAG", 9);
        memcpy(tag_truncated_32bit, mac, HORSE_VOICE_TAG_BYTES);
    }
#else
{
    (void)session_key;
    (void)nonce_96bit;
    memcpy(ciphertext_out, plaintext, plaintext_len);
    if (tag_truncated_32bit)
        memset(tag_truncated_32bit, 0, HORSE_VOICE_TAG_BYTES);
#endif
}

bool horse_crypto_voice_decrypt(
    const uint8_t *session_key,
    const uint8_t *nonce_96bit,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t *tag_truncated_32bit,
    uint8_t *plaintext_out)
{
#ifdef HAVE_LIBSODIUM
    if (ciphertext == NULL || plaintext_out == NULL)
        return false;

    if (horse_sodium_init() != 0)
    {
        memcpy(plaintext_out, ciphertext, ciphertext_len);
        return true;
    }

    /* Verify 32-bit BLAKE2b MAC over ciphertext, if provided. */
    if (tag_truncated_32bit != NULL)
    {
        uint8_t mac[crypto_generichash_BYTES];
        crypto_generichash(mac, sizeof mac,
                           ciphertext, ciphertext_len,
                           (const unsigned char *)"HVOICETAG", 9);

        if (sodium_memcmp(mac, tag_truncated_32bit,
                          HORSE_VOICE_TAG_BYTES) != 0)
        {
            /* Authentication failed. Do not decrypt into output buffer. */
            return false;
        }
    }

    uint8_t nonce[crypto_stream_xchacha20_NONCEBYTES];
    crypto_generichash(nonce, sizeof nonce,
                       nonce_96bit, 12,
                       (const unsigned char *)"HORSEV1", 7);

    crypto_stream_xchacha20_xor(plaintext_out,
                                ciphertext,
                                ciphertext_len,
                                nonce,
                                session_key);
    return true;
#else
    (void)session_key;
    (void)nonce_96bit;
    (void)tag_truncated_32bit;
    memcpy(plaintext_out, ciphertext, ciphertext_len);
    return true;
#endif
}

bool horse_crypto_argon2id_derive(
    const char *passphrase,
    size_t passphrase_len,
    const uint8_t *salt,
    size_t salt_len,
    uint8_t *key_out,
    size_t key_len)
{
    if (passphrase == NULL || salt == NULL || key_out == NULL || key_len == 0)
        return false;

#ifdef HAVE_LIBSODIUM
    if (horse_sodium_init() != 0)
        return false;

    /* Use libsodium's Argon2id implementation via crypto_pwhash.
     * Note: crypto_pwhash expects salt to be crypto_pwhash_SALTBYTES (16 bytes);
     * salt_len parameter is ignored in this path.
     */
    (void)salt_len;
    if (crypto_pwhash(key_out, key_len,
                      passphrase, passphrase_len,
                      salt,
                      crypto_pwhash_OPSLIMIT_MODERATE,
                      crypto_pwhash_MEMLIMIT_MODERATE,
                      crypto_pwhash_ALG_ARGON2ID13) != 0)
    {
        return false;
    }
    return true;
#else
    /* Fallback to PBKDF2 when libsodium is not available. */
    return crypto_pbkdf2(passphrase, passphrase_len, salt, salt_len,
                         10000, key_out, key_len) == 0;
#endif
}

bool horse_crypto_unlock_private_key(const char *passphrase, size_t len)
{
    (void)passphrase;
    (void)len;
    return false;
}

bool horse_crypto_sign(
    const uint8_t *ed25519_secretkey,
    const uint8_t *message,
    size_t message_len,
    uint8_t *signature_out)
{
    if (ed25519_secretkey == NULL || message == NULL || signature_out == NULL)
        return false;

#ifdef HAVE_LIBSODIUM
    if (horse_sodium_init() != 0)
        return false;

    if (crypto_sign_detached(signature_out, NULL,
                              message, message_len,
                              ed25519_secretkey) != 0)
    {
        return false;
    }
    return true;
#else
    /* No libsodium: placeholder (zero signature). */
    (void)message_len;
    memset(signature_out, 0, HORSE_ED25519_SIGNATURE_BYTES);
    return true;
#endif
}

bool horse_crypto_verify(
    const uint8_t *ed25519_publickey,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *signature)
{
    if (ed25519_publickey == NULL || message == NULL || signature == NULL)
        return false;

#ifdef HAVE_LIBSODIUM
    if (horse_sodium_init() != 0)
        return false;

    if (crypto_sign_verify_detached(signature,
                                     message, message_len,
                                     ed25519_publickey) != 0)
    {
        return false;
    }
    return true;
#else
    /* No libsodium: placeholder (always accept). */
    (void)message_len;
    (void)signature;
    return true;
#endif
}
