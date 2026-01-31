/*
 * SPDX-FileCopyrightText: Copyright 2020-2026 OpenRTX Contributors
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "interfaces/platform.h"
#include "interfaces/delays.h"
#include "interfaces/audio.h"
#include "interfaces/radio.h"
#include "protocols/M17/M17Callsign.hpp"
#include "protocols/horse/HorseDatatypes.hpp"
#include "rtx/OpMode_Horse.hpp"
#include "core/audio_codec.h"
#include "core/horse_codec.h"
#include "core/state.h"
#include "rtx/rtx.h"
#include <cstring>

#ifdef PLATFORM_MOD17
#include "calibration/calibInfo_Mod17.h"
#endif

#if defined(PLATFORM_MD3x0) || defined(PLATFORM_MDUV3x0)
#include "interfaces/platform.h"
#endif

using namespace horse;

OpMode_Horse::OpMode_Horse()
    : startRx(false),
      startTx(false),
      locked(false),
      dataValid(false),
      invertTxPhase(false),
      invertRxPhase(false),
      rxAudioPath(-1),
      txAudioPath(-1)
{
}

OpMode_Horse::~OpMode_Horse()
{
    disable();
}

void OpMode_Horse::enable()
{
    codec_init();
    horse_codec_init();
    modulator.init();
    demodulator.init();
    locked    = false;
    dataValid = false;
    startRx   = true;
    startTx   = false;
#if defined(PLATFORM_MD3x0) || defined(PLATFORM_MDUV3x0)
    invertTxPhase = true;
    if (platform_getHwInfo()->vhf_band == 1)
        invertRxPhase = true;
    else
        invertRxPhase = false;
#elif defined(PLATFORM_MOD17)
    extern mod17Calib_t mod17CalData;
    invertTxPhase = (mod17CalData.bb_tx_invert == 1);
    invertRxPhase = (mod17CalData.bb_rx_invert == 1);
#else
    invertTxPhase = true;
    invertRxPhase = false;
#endif
}

void OpMode_Horse::disable()
{
    startRx = false;
    startTx = false;
    platform_ledOff(GREEN);
    platform_ledOff(RED);
    horse_codec_stop(rxAudioPath);
    horse_codec_stop(txAudioPath);
    audioPath_release(rxAudioPath);
    audioPath_release(txAudioPath);
    horse_codec_terminate();
    codec_terminate();
    radio_disableRtx();
    modulator.terminate();
    demodulator.terminate();
}

void OpMode_Horse::update(rtxStatus_t* const status, const bool newCfg)
{
    (void)newCfg;
    switch (status->opStatus)
    {
    case OFF:
        offState(status);
        break;
    case RX:
        rxState(status);
        break;
    case TX:
        txState(status);
        break;
    default:
        break;
    }
    switch (status->opStatus)
    {
    case RX:
        if (dataValid)
            platform_ledOn(GREEN);
        else
            platform_ledOff(GREEN);
        break;
    case TX:
        platform_ledOff(GREEN);
        platform_ledOn(RED);
        break;
    default:
        platform_ledOff(GREEN);
        platform_ledOff(RED);
        break;
    }
}

void OpMode_Horse::offState(rtxStatus_t* const status)
{
    radio_disableRtx();
    codec_stop(txAudioPath);
    audioPath_release(txAudioPath);
    if (startRx)
    {
        status->opStatus = RX;
        return;
    }
    if (platform_getPttStatus() && (status->txDisable == 0))
    {
        startTx          = true;
        status->opStatus = TX;
        return;
    }
    sleepFor(0, 30);
}

void OpMode_Horse::rxState(rtxStatus_t* const status)
{
    if (startRx)
    {
        demodulator.startBasebandSampling();
        radio_enableRx();
        startRx = false;
    }
    bool newData = demodulator.update(invertRxPhase);
    bool lock    = demodulator.isLocked();
    if (lock && !locked)
    {
        decoder.reset();
        locked = lock;
    }
    if (locked)
    {
        if (newData)
        {
            const frame_t& frame = demodulator.getFrame();
            HorseFrameType type  = decoder.decodeFrame(frame);
            status->horseLsfOk  = (type == HorseFrameType::LINK_SETUP);
            if (status->horseLsfOk)
            {
                dataValid = true;
                horse::call_t srcCall, dstCall;
                decoder.getLsfCallsigns(srcCall, dstCall);
                std::string srcStr = M17::decode_callsign(srcCall);
                std::string dstStr = M17::decode_callsign(dstCall);
                strncpy(status->horse_src, srcStr.c_str(), 9);
                status->horse_src[9] = '\0';
                strncpy(status->horse_dst, dstStr.c_str(), 9);
                status->horse_dst[9] = '\0';
                if (rxAudioPath < 0)
                {
                    rxAudioPath = audioPath_request(SOURCE_MCU, SINK_SPK, PRIO_RX);
                    if (rxAudioPath >= 0 && audioPath_getStatus(rxAudioPath) == PATH_OPEN)
                        horse_codec_startDecode(rxAudioPath);
                }
            }
            if (type == HorseFrameType::VOICE)
            {
                uint8_t melpe[HORSE_CODEC_FRAME_BYTES];
                uint8_t tag[4];
                uint16_t fn;
                decoder.getVoicePayload(frame, melpe, tag, &fn);
                if (rxAudioPath >= 0 && horse_codec_running())
                    horse_codec_pushFrame(melpe, false);
            }
        }
    }
    locked = lock;
    if (platform_getPttStatus())
    {
        demodulator.stopBasebandSampling();
        locked = false;
        status->opStatus = OFF;
    }
    if (!locked)
    {
        status->horseLsfOk = false;
        dataValid          = false;
        status->horse_dst[0] = '\0';
        status->horse_src[0] = '\0';
        if (rxAudioPath >= 0)
        {
            horse_codec_stop(rxAudioPath);
            audioPath_release(rxAudioPath);
            rxAudioPath = -1;
        }
    }
}

void OpMode_Horse::txState(rtxStatus_t* const status)
{
    horse::frame_t outFrame;
    if (startTx)
    {
        startTx = false;
        txAudioPath = audioPath_request(SOURCE_MIC, SINK_RTX, PRIO_TX);
        if (txAudioPath < 0)
            return;
        if (!horse_codec_startEncode(txAudioPath))
        {
            audioPath_release(txAudioPath);
            return;
        }
        horse::call_t srcCall, dstCall;
        M17::encode_callsign(status->source_address, srcCall, false);
        M17::encode_callsign(status->destination_address, dstCall, false);
        encoder.reset();
        encoder.encodeLsf(srcCall, dstCall, outFrame);
        modulator.invertPhase(invertTxPhase);
        if (!modulator.start())
            return;
        modulator.sendPreamble();
        modulator.sendFrame(outFrame);
    }

    uint8_t melpeBuf[HORSE_CODEC_FRAME_BYTES];
    uint8_t tagZero[4] = {0};
    if (horse_codec_popFrame(melpeBuf, true) == 0)
        encoder.encodeVoiceFrame(melpeBuf, tagZero, outFrame, false);
    else
    {
        memset(melpeBuf, 0, sizeof(melpeBuf));
        encoder.encodeVoiceFrame(melpeBuf, tagZero, outFrame, false);
    }
    modulator.sendFrame(outFrame);
    sleepFor(0u, 40u);

    if (!platform_getPttStatus())
    {
        if (horse_codec_popFrame(melpeBuf, false) != 0)
            memset(melpeBuf, 0, sizeof(melpeBuf));
        encoder.encodeVoiceFrame(melpeBuf, tagZero, outFrame, true);
        modulator.sendFrame(outFrame);
        encoder.encodeEotFrame(outFrame);
        modulator.sendFrame(outFrame);
        modulator.stop();
        horse_codec_stop(txAudioPath);
        audioPath_release(txAudioPath);
        status->opStatus = OFF;
    }
}
