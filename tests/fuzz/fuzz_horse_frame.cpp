/*
 * SPDX-FileCopyrightText: Copyright 2020-2026 OpenRTX Contributors
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * LibFuzzer harness for Horse protocol frame decoder.
 * Feed raw bytes (minimum 48 bytes per frame) to exercise decodeFrame and payload extraction.
 */

#include "protocols/horse/HorseFrameDecoder.hpp"
#include "protocols/horse/HorseConstants.hpp"
#include <cstdint>
#include <cstring>

using namespace horse;

static constexpr size_t FRAME_LEN = 48;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < FRAME_LEN)
        return 0;

    HorseFrameDecoder dec;
    frame_t frame;
    std::memcpy(frame.data(), data, FRAME_LEN);

    HorseFrameType type = dec.decodeFrame(frame);

    switch (type)
    {
    case HorseFrameType::LINK_SETUP:
    {
        call_t src, dst;
        dec.getLsfCallsigns(src, dst);
        (void)src;
        (void)dst;
        break;
    }
    case HorseFrameType::VOICE:
    {
        uint8_t melpe[12];
        uint8_t tag[4];
        uint16_t frameNum = 0;
        dec.getVoicePayload(frame, melpe, tag, &frameNum);
        (void)frameNum;
        break;
    }
    case HorseFrameType::EOT:
    case HorseFrameType::UNKNOWN:
        break;
    }

    return 0;
}
