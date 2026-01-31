/*
 * SPDX-FileCopyrightText: Copyright 2020-2026 OpenRTX Contributors
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef HORSE_FRAME_ENCODER_H
#define HORSE_FRAME_ENCODER_H

#include "HorseDatatypes.hpp"
#include "HorseConstants.hpp"
#include <cstdint>

#ifndef __cplusplus
#error This header is C++ only!
#endif

namespace horse
{

class HorseFrameEncoder
{
public:
    HorseFrameEncoder();
    ~HorseFrameEncoder();

    void reset();

    void encodeLsf(const call_t& src, const call_t& dst, frame_t& output);

    uint16_t encodeVoiceFrame(const uint8_t* melpe96bits, const uint8_t* tag32bits,
                              frame_t& output, bool isLast = false);

    void encodeEotFrame(frame_t& output);

private:
    uint16_t voiceFrameNumber;
};

}  // namespace horse

#endif  // HORSE_FRAME_ENCODER_H
