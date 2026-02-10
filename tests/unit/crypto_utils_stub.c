/*
 * SPDX-FileCopyrightText: Copyright 2020-2026 OpenRTX Contributors
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Minimal stub for crypto_utils functions needed by horse_crypto tests.
 */

#include "core/crypto_utils.h"
#include <string.h>

int crypto_pbkdf2(const char *password, size_t password_len,
                  const uint8_t *salt, size_t salt_len,
                  uint32_t iterations, uint8_t *key, size_t key_len)
{
    /* Minimal stub - not used in tests when libsodium is available. */
    (void)password;
    (void)password_len;
    (void)salt;
    (void)salt_len;
    (void)iterations;
    (void)key;
    (void)key_len;
    return -1; /* Not implemented in stub. */
}
