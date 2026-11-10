/*
 * SPDX-FileCopyrightText: Copyright 2020-2026 OpenRTX Contributors
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Horse identity keystore: encrypted storage and runtime unlock.
 */

#ifndef HORSE_KEYSTORE_H
#define HORSE_KEYSTORE_H

#include "protocols/horse/horse_crypto.h"
#include <stddef.h>
#include <stdbool.h>
#include <errno.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Initialise the identity keystore (call once at boot). */
void horse_keystore_init(void);
/** Lock and wipe runtime identity state. */
void horse_keystore_terminate(void);

/** @return true when an identity is unlocked in RAM. */
bool horse_keystore_is_unlocked(void);
/**
 * Copy the unlocked identity.
 * @return 0 on success, -ENOENT if locked.
 */
int horse_keystore_copy_identity(struct horse_identity_keys *out);

/**
 * Unlock the store with a passphrase.
 * @return 0 on success, negative errno on failure.
 */
int horse_keystore_unlock(const char *passphrase, size_t passphrase_len);
/**
 * Hold a passphrase for a later unlock/store (UI entry).
 * @return 0 on success, -EINVAL if length is out of range.
 */
int horse_keystore_hold_passphrase(const char *passphrase,
                                   size_t passphrase_len);
/** Unlock using the held passphrase. @return 0 or negative errno. */
int horse_keystore_unlock_held(void);
/** @return true when a passphrase is held. */
bool horse_keystore_has_passphrase(void);
/** Lock the identity and wipe the held passphrase. */
void horse_keystore_lock(void);

/**
 * Encrypt and persist an identity with the given passphrase.
 * @return 0 on success, negative errno on failure.
 */
int horse_keystore_store_plaintext(const struct horse_identity_keys *identity,
                                   const char *passphrase,
                                   size_t passphrase_len);
/** Store using the held passphrase. @return 0 or negative errno. */
int horse_keystore_store_with_held(const struct horse_identity_keys *identity);

/**
 * Fingerprint of the unlocked identity.
 * @return 0 on success, -ENOENT if locked.
 */
int horse_keystore_fingerprint(uint8_t fp_out[32]);

#ifdef __cplusplus
}
#endif

#endif
