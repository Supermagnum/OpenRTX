#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: Copyright 2020-2026 OpenRTX Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Generate minimal seed corpus for all libFuzzer targets.
# Writes into tests/fuzz/corpus/<fuzzer_name>/ by default.
#

import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CORPUS_BASE = os.path.join(SCRIPT_DIR, "..", "tests", "fuzz", "corpus")

# Horse frame sync words (HorseConstants.hpp)
LSF_SYNC = bytes([0x5A, 0xA7])
VOICE_SYNC = bytes([0x7E, 0x9B])
EOT_SYNC = bytes([0x3C, 0xD8])


def write_horse_frame(base):
    d = os.path.join(base, "fuzz_horse_frame")
    os.makedirs(d, exist_ok=True)
    for name, sync in [("seed_lsf.bin", LSF_SYNC), ("seed_voice.bin", VOICE_SYNC), ("seed_eot.bin", EOT_SYNC)]:
        with open(os.path.join(d, name), "wb") as f:
            f.write(sync + bytes(46))
        print("Wrote", os.path.join(d, name))


def write_ldpc_horse(base):
    d = os.path.join(base, "fuzz_ldpc_horse")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "seed_46.bin"), "wb") as f:
        f.write(bytes(46))
    print("Wrote", os.path.join(d, "seed_46.bin"))


def write_m17_golay(base):
    d = os.path.join(base, "fuzz_m17_golay")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "seed_4.bin"), "wb") as f:
        f.write(bytes(4))
    print("Wrote", os.path.join(d, "seed_4.bin"))


def write_m17_callsign(base):
    d = os.path.join(base, "fuzz_m17_callsign")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "seed_6.bin"), "wb") as f:
        f.write(bytes(6))
    print("Wrote", os.path.join(d, "seed_6.bin"))


def write_m17_frame(base):
    d = os.path.join(base, "fuzz_m17_frame")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "seed_48.bin"), "wb") as f:
        f.write(bytes(48))
    print("Wrote", os.path.join(d, "seed_48.bin"))


def write_minmea(base):
    d = os.path.join(base, "fuzz_minmea")
    os.makedirs(d, exist_ok=True)
    nmea = b"$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*47\n"
    with open(os.path.join(d, "seed_gga.txt"), "wb") as f:
        f.write(nmea)
    print("Wrote", os.path.join(d, "seed_gga.txt"))


def main():
    base = sys.argv[1] if len(sys.argv) > 1 else CORPUS_BASE
    os.makedirs(base, exist_ok=True)
    write_horse_frame(base)
    write_ldpc_horse(base)
    write_m17_golay(base)
    write_m17_callsign(base)
    write_m17_frame(base)
    write_minmea(base)
    print("Corpus generation done.")


if __name__ == "__main__":
    main()
