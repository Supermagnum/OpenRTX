#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright 2020-2026 OpenRTX Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Enforce Horse -fstack-usage limits from ARM .su files (C14).

RTX thread stack is RTX_THREAD_STKSIZE (512 B). Crypto runs on a
CODEC2_THREAD_STKSIZE (16384 B) worker. Limits leave a small margin.

Usage:
  python3 scripts/check_horse_stack_usage.py BUILD_DIR
  python3 scripts/check_horse_stack_usage.py --print-limits
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

# Bytes. Must match openrtx/include/core/threads.h and HORSE_AUDIT.md.
RTX_STACK = 512
WORKER_STACK = 16384
RTX_MARGIN = 64
WORKER_MARGIN = 2048

# Substrings matched against the .su function column (mangled or demangled).
RTX_LIMITS = {
    "OpMode_Horse::txState": RTX_STACK - RTX_MARGIN,
    "OpMode_Horse::rxState": RTX_STACK - RTX_MARGIN,
    "OpMode_Horse::sendTxVoiceFrame": RTX_STACK - RTX_MARGIN,
    "OpMode_Horse::update": RTX_STACK - RTX_MARGIN,
    "OpMode_Horse::offState": RTX_STACK - RTX_MARGIN,
}

WORKER_LIMIT = WORKER_STACK - WORKER_MARGIN

SU_LINE = re.compile(
    r"^(?P<file>[^\t]+)\t(?P<func>[^\t]+)\t(?P<bytes>\d+)\t(?P<qual>\S+)"
)


def parse_su(path: Path) -> list[tuple[str, str, int, str]]:
    rows = []
    text = path.read_text(errors="replace")
    for line in text.splitlines():
        m = SU_LINE.match(line.strip())
        if not m:
            continue
        rows.append(
            (
                m.group("file"),
                m.group("func"),
                int(m.group("bytes")),
                m.group("qual"),
            )
        )
    return rows


def matches(func: str, needle: str) -> bool:
    return needle in func


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "build_dir",
        nargs="?",
        help="Meson build directory containing .su files",
    )
    ap.add_argument(
        "--print-limits",
        action="store_true",
        help="Print limits and exit",
    )
    args = ap.parse_args()

    if args.print_limits:
        print("Horse stack-usage limits (bytes)")
        print(f"  RTX stack total: {RTX_STACK}")
        print(f"  Worker stack total: {WORKER_STACK}")
        for name, lim in sorted(RTX_LIMITS.items()):
            print(f"  RTX {name}: <= {lim}")
        print(f"  Worker deepest path: <= {WORKER_LIMIT}")
        return 0

    if not args.build_dir:
        ap.error("BUILD_DIR required unless --print-limits")

    root = Path(args.build_dir)
    if not root.is_dir():
        print(f"Error: {root} is not a directory", file=sys.stderr)
        return 2

    su_files = list(root.rglob("*.su"))
    if not su_files:
        print(f"Error: no .su files under {root}", file=sys.stderr)
        return 2

    failures = []
    seen_rtx = {k: False for k in RTX_LIMITS}
    worker_max = 0
    worker_who = ""

    for su in su_files:
        for _file, func, nbytes, _qual in parse_su(su):
            for name, lim in RTX_LIMITS.items():
                if matches(func, name):
                    seen_rtx[name] = True
                    if nbytes > lim:
                        failures.append(
                            f"{su}: {func} uses {nbytes} B > RTX limit {lim}"
                        )
            # libsodium / Horse worker paths: deepest static use.
            if any(
                x in func
                for x in (
                    "generate_addresses",
                    "ge25519_",
                    "crypto_scalarmult",
                    "argon2",
                    "crypto_pwhash",
                    "horse_crypto",
                )
            ):
                if nbytes > worker_max:
                    worker_max = nbytes
                    worker_who = f"{su}:{func}"

    if worker_max > WORKER_LIMIT:
        failures.append(
            f"worker deepest {worker_who} uses {worker_max} B "
            f"> limit {WORKER_LIMIT}"
        )

    missing = [n for n, ok in seen_rtx.items() if not ok]
    if missing:
        # Soft: .su names may be mangled differently across gcc versions.
        print(
            "Warning: RTX Horse symbols not found in .su: "
            + ", ".join(missing),
            file=sys.stderr,
        )

    if failures:
        for f in failures:
            print(f"Error: {f}", file=sys.stderr)
        return 1

    print(
        f"check_horse_stack_usage: ok "
        f"({len(su_files)} .su files, worker_max={worker_max})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
