/*
 * SPDX-FileCopyrightText: Copyright 2020-2026 OpenRTX Contributors
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * LibFuzzer harness for minmea NMEA sentence parser.
 * Input: raw bytes (copied into null-terminated buffer, max 256 bytes).
 */

#include <minmea.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define MAX_SENTENCE 256

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0 || size > MAX_SENTENCE)
        return 0;

    char buf[MAX_SENTENCE + 1];
    memcpy(buf, data, size);
    buf[size] = '\0';

    (void)minmea_checksum(buf);
    (void)minmea_check(buf, false);
    (void)minmea_check(buf, true);

    char talker[3];
    (void)minmea_talker_id(talker, buf);

    (void)minmea_sentence_id(buf, false);
    (void)minmea_sentence_id(buf, true);

    struct minmea_sentence_rmc rmc;
    struct minmea_sentence_gga gga;
    struct minmea_sentence_gsa gsa;
    struct minmea_sentence_gll gll;
    struct minmea_sentence_gst gst;
    struct minmea_sentence_gsv gsv;
    struct minmea_sentence_vtg vtg;
    struct minmea_sentence_zda zda;

    (void)minmea_parse_rmc(&rmc, buf);
    (void)minmea_parse_gga(&gga, buf);
    (void)minmea_parse_gsa(&gsa, buf);
    (void)minmea_parse_gll(&gll, buf);
    (void)minmea_parse_gst(&gst, buf);
    (void)minmea_parse_gsv(&gsv, buf);
    (void)minmea_parse_vtg(&vtg, buf);
    (void)minmea_parse_zda(&zda, buf);

    return 0;
}
