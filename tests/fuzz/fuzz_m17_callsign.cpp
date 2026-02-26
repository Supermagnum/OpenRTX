/*
 * SPDX-FileCopyrightText: Copyright 2020-2026 OpenRTX Contributors
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * LibFuzzer harness for M17 callsign decode (6-byte encoded call_t to string).
 */

#include "protocols/M17/Callsign.hpp"
#include "protocols/M17/M17Datatypes.hpp"
#include <cstdint>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 6)
        return 0;

    M17::call_t encoded;
    std::memcpy(encoded.data(), data, 6);

    M17::Callsign cs(encoded);
    (void)static_cast<const char *>(cs);
    (void)static_cast<std::string>(cs);

    return 0;
}
