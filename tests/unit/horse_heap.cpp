/*
 * SPDX-FileCopyrightText: Copyright 2020-2026 OpenRTX Contributors
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * C7: Horse-attributable heap peak must stay under the MD-3x0 budget.
 * state.heap_usage does not exist; device Info menu uses
 * getHeapSize() - getCurrentFreeHeap(). This host test measures the
 * Horse tracker across unlock (Argon2id) and crypto-worker start.
 */

#include "protocols/horse/horse_heap.h"
#include "protocols/horse/horse_crypto.h"
#include "protocols/horse/horse_crypto_worker.h"
#include "protocols/horse/horse_keystore.h"
#include "core/threads.h"
#include <cstdio>
#include <cstring>

#ifdef HAVE_LIBSODIUM
#include <sodium.h>
#endif

int main(void)
{
    size_t budget_claim;

    /* Static budget check: Argon2 + worker + codec stacks. */
    budget_claim = (size_t)HORSE_ARGON2ID_MEMLIMIT
                 + (size_t)CODEC2_THREAD_STKSIZE
                 + (size_t)CODEC2_THREAD_STKSIZE;
    if (budget_claim > HORSE_HEAP_BUDGET_BYTES) {
        std::printf("horse_heap: static claim %zu > budget %u\n", budget_claim,
                    HORSE_HEAP_BUDGET_BYTES);
        return 1;
    }
    if (HORSE_HEAP_BUDGET_BYTES > HORSE_MD3X0_HEAP_BYTES) {
        std::printf("horse_heap: budget exceeds MD-3x0 heap\n");
        return 1;
    }

#ifndef HAVE_LIBSODIUM
    std::printf("horse_heap: skipped runtime (no libsodium)\n");
    return 77;
#else
    struct horse_identity_keys id;
    const char *pass = "heap-test-passphrase";
    uint8_t salt[HORSE_KDF_SALT_BYTES];
    uint8_t key[32];

    if (sodium_init() < 0)
        return 1;

    horse_heap_reset_peak();
    horse_crypto_worker_init();

    memset(&id, 0, sizeof id);
    id.version = 1;
    crypto_sign_ed25519_keypair(id.ed25519_pk, id.ed25519_sk);
    crypto_kx_keypair(id.x25519_pk, id.x25519_sk);
    randombytes_buf(salt, sizeof salt);

    if (!horse_crypto_argon2id_derive(pass, strlen(pass), salt, sizeof salt,
                                      key, sizeof key)) {
        std::printf("horse_heap: argon2id_derive failed\n");
        return 1;
    }

    /* Worker stack remains live; Argon2 was acquire/release. */
    if (horse_heap_peak() > HORSE_HEAP_BUDGET_BYTES) {
        std::printf("horse_heap: peak %zu exceeds budget %u\n",
                    horse_heap_peak(), HORSE_HEAP_BUDGET_BYTES);
        return 1;
    }
    if (horse_heap_peak() < HORSE_ARGON2ID_MEMLIMIT) {
        std::printf("horse_heap: peak %zu below Argon2 memlimit\n",
                    horse_heap_peak());
        return 1;
    }

    horse_crypto_worker_terminate();
    horse_crypto_memzero(&id, sizeof id);
    horse_crypto_memzero(key, sizeof key);
    std::printf("horse_heap: peak %zu / budget %u (MD-3x0 heap %u)\n",
                horse_heap_peak(), HORSE_HEAP_BUDGET_BYTES,
                HORSE_MD3X0_HEAP_BYTES);
    return 0;
#endif
}
