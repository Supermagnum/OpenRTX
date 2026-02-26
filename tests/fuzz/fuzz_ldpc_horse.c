/*
 * SPDX-FileCopyrightText: Copyright 2020-2026 OpenRTX Contributors
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * LibFuzzer harness for Horse LDPC voice decoder.
 * Input: 46 bytes (LDPC_VOICE_ENCODED_BYTES); output: 23 bytes payload.
 */

#include "protocols/horse/ldpc_horse.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define LDPC_IN_LEN 46

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < LDPC_IN_LEN)
        return 0;

    uint8_t encoded[LDPC_IN_LEN];
    uint8_t payload[LDPC_VOICE_PAYLOAD_BYTES];

    memcpy(encoded, data, LDPC_IN_LEN);
    ldpc_horse_decode_voice(encoded, payload);

    return 0;
}
