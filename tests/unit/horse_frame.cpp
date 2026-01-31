/*
 * SPDX-FileCopyrightText: Copyright 2020-2026 OpenRTX Contributors
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Unit test for Horse protocol frame encode/decode round-trip.
 */

#include "protocols/horse/HorseFrameEncoder.hpp"
#include "protocols/horse/HorseFrameDecoder.hpp"
#include "protocols/horse/HorseConstants.hpp"
#include "protocols/horse/ldpc_horse.h"
#include <cstdio>
#include <cstring>
#include <cstdint>

using namespace horse;

static int test_lsf_roundtrip()
{
    HorseFrameEncoder enc;
    HorseFrameDecoder dec;
    call_t src = {{'A', 'B', '1', '2', '3', '4'}};
    call_t dst = {{'C', 'D', '5', '6', '7', '8'}};
    frame_t frame;

    enc.encodeLsf(src, dst, frame);
    HorseFrameType type = dec.decodeFrame(frame);
    if (type != HorseFrameType::LINK_SETUP)
    {
        std::printf("horse_frame_test: LSF decode type fail (got %u)\n", static_cast<unsigned>(type));
        return -1;
    }
    call_t outSrc, outDst;
    dec.getLsfCallsigns(outSrc, outDst);
    if (outSrc != src || outDst != dst)
    {
        std::printf("horse_frame_test: LSF callsign round-trip fail\n");
        return -1;
    }
    return 0;
}

static int test_voice_roundtrip()
{
    HorseFrameEncoder enc;
    HorseFrameDecoder dec;
    uint8_t melpe[12] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x11, 0x22, 0x33, 0x44};
    uint8_t tag[4]   = {0xAA, 0xBB, 0xCC, 0xDD};
    frame_t frame;

    enc.encodeVoiceFrame(melpe, tag, frame, false);
    HorseFrameType type = dec.decodeFrame(frame);
    if (type != HorseFrameType::VOICE)
    {
        std::printf("horse_frame_test: voice decode type fail (got %u)\n", static_cast<unsigned>(type));
        return -1;
    }
    uint8_t outMelpe[12], outTag[4];
    uint16_t outFn = 0;
    dec.getVoicePayload(frame, outMelpe, outTag, &outFn);
    if (std::memcmp(outMelpe, melpe, 12) != 0 || std::memcmp(outTag, tag, 4) != 0)
    {
        std::printf("horse_frame_test: voice payload round-trip fail\n");
        return -1;
    }
    if (outFn != 0)
    {
        std::printf("horse_frame_test: voice frame number fail (got %u)\n", outFn);
        return -1;
    }
    return 0;
}

static int test_eot_detect()
{
    HorseFrameEncoder enc;
    HorseFrameDecoder dec;
    frame_t frame;

    enc.encodeEotFrame(frame);
    HorseFrameType type = dec.decodeFrame(frame);
    if (type != HorseFrameType::EOT)
    {
        std::printf("horse_frame_test: EOT decode type fail (got %u)\n", static_cast<unsigned>(type));
        return -1;
    }
    return 0;
}

static int test_voice_frame_number()
{
    HorseFrameEncoder enc;
    HorseFrameDecoder dec;
    uint8_t melpe[12] = {0};
    uint8_t tag[4]    = {0};
    frame_t frame;

    enc.reset();
    enc.encodeVoiceFrame(melpe, tag, frame, false);
    dec.decodeFrame(frame);
    uint16_t fn0 = 0;
    dec.getVoicePayload(frame, nullptr, nullptr, &fn0);

    enc.encodeVoiceFrame(melpe, tag, frame, false);
    dec.decodeFrame(frame);
    uint16_t fn1 = 0;
    dec.getVoicePayload(frame, nullptr, nullptr, &fn1);

    if (fn0 != 0 || fn1 != 1)
    {
        std::printf("horse_frame_test: voice frame number sequence fail (fn0=%u fn1=%u)\n", fn0, fn1);
        return -1;
    }
    return 0;
}

int main()
{
    if (test_lsf_roundtrip() != 0) return -1;
    if (test_voice_roundtrip() != 0) return -1;
    if (test_eot_detect() != 0) return -1;
    if (test_voice_frame_number() != 0) return -1;
    std::printf("horse_frame_test: all tests passed\n");
    return 0;
}
