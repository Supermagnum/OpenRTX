/*
 * SPDX-FileCopyrightText: Copyright 2020-2026 OpenRTX Contributors
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef OPMODE_HORSE_H
#define OPMODE_HORSE_H

#include "protocols/horse/HorseFrameDecoder.hpp"
#include "protocols/horse/HorseFrameEncoder.hpp"
#include "protocols/horse/HorseDemodulator.hpp"
#include "protocols/horse/HorseModulator.hpp"
#include "core/audio_path.h"
#include "OpMode.hpp"

#ifndef __cplusplus
#error This header is C++ only!
#endif

class OpMode_Horse : public OpMode
{
public:
    OpMode_Horse();
    ~OpMode_Horse();

    virtual void enable() override;
    virtual void disable() override;
    virtual void update(rtxStatus_t* const status, const bool newCfg) override;
    virtual opmode getID() override { return OPMODE_HORSE; }
    virtual bool rxSquelchOpen() override { return dataValid; }

private:
    void offState(rtxStatus_t* const status);
    void rxState(rtxStatus_t* const status);
    void txState(rtxStatus_t* const status);

    bool startRx;
    bool startTx;
    bool locked;
    bool dataValid;
    bool invertTxPhase;
    bool invertRxPhase;
    pathId rxAudioPath;
    pathId txAudioPath;
    horse::HorseModulator modulator;
    horse::HorseDemodulator demodulator;
    horse::HorseFrameDecoder decoder;
    horse::HorseFrameEncoder encoder;
};

#endif  // OPMODE_HORSE_H
