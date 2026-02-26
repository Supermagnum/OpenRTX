/*
 * SPDX-FileCopyrightText: Copyright 2020-2026 OpenRTX Contributors
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * LibFuzzer harness for M17 Golay(24,12) decode.
 * Input: 4 bytes (codeword as uint32_t).
 */

#include "protocols/M17/M17Golay.hpp"
#include <cstdint>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 4)
        return 0;

    uint32_t codeword;
    memcpy(&codeword, data, 4);
    (void)M17::golay24_decode(codeword);

    return 0;
}
