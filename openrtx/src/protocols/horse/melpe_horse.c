/*
 * SPDX-FileCopyrightText: Copyright 2020-2026 OpenRTX Contributors
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * MELPe 2400 placeholder: 96 bits per 40ms. Encode produces zeros;
 * decode produces silence until a real MELPe 2400 implementation is integrated.
 */

#include "protocols/horse/melpe_horse.h"
#include <string.h>

void melpe_horse_encoder_init(void)
{
}

void melpe_horse_encoder_terminate(void)
{
}

void melpe_horse_encode(const int16_t *pcm, size_t n_samples, uint8_t *bits_96)
{
    (void)pcm;
    (void)n_samples;
    memset(bits_96, 0, MELPE_HORSE_BYTES);
}

void melpe_horse_decoder_init(void)
{
}

void melpe_horse_decoder_terminate(void)
{
}

void melpe_horse_decode(const uint8_t *bits_96, int16_t *pcm, size_t *n_samples_out)
{
    (void)bits_96;
    memset(pcm, 0, MELPE_HORSE_SAMPLES_40MS * sizeof(int16_t));
    if (n_samples_out)
        *n_samples_out = MELPE_HORSE_SAMPLES_40MS;
}
