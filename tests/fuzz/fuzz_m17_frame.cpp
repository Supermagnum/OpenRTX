/*
 * SPDX-FileCopyrightText: Copyright 2020-2026 OpenRTX Contributors
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * LibFuzzer harness for M17 protocol frame decoder.
 * Input: 48 bytes (one M17 frame including sync word).
 */

#include "protocols/M17/FrameDecoder.hpp"
#include "protocols/M17/Datatypes.hpp"
#include <cstdint>
#include <cstring>

using namespace M17;

static constexpr size_t FRAME_LEN = 48;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < FRAME_LEN)
        return 0;

    FrameDecoder dec;
    frame_t frame;
    std::memcpy(frame.data(), data, FRAME_LEN);

    FrameType type = dec.decodeFrame(frame);

    if (type == FrameType::LINK_SETUP)
        (void)dec.getLsf();
    else if (type == FrameType::STREAM)
        (void)dec.getStreamFrame();

    return 0;
}
