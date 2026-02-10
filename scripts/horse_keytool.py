#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: Copyright 2020-2026 OpenRTX Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Helper tool for Horse mode key handling.
#
# This script collects public keys for Horse contacts from:
#   - ASCII-armored (.asc) OpenPGP key files
#   - Binary (.pgp) OpenPGP key files
#   - Existing keys in the user's GnuPG keyring (including smartcard / Nitrokey)
#
# and writes a consolidated JSON mapping file that can later be consumed
# by codeplug tooling or other utilities.
#
# The script does not parse OpenPGP packets itself; it either:
#   - stores the raw file contents (for .asc / .pgp), or
#   - asks gpg to export a public key in ASCII-armored form.

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple


def run_gpg_export(key_ref: str) -> str:
    """Export a public key from the user's GnuPG keyring in ASCII armor."""
    try:
        completed = subprocess.run(
            ["gpg", "--batch", "--yes", "--export", "--armor", key_ref],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError:
        raise RuntimeError("gpg not found in PATH; please install GnuPG") from None

    if completed.returncode != 0 or not completed.stdout:
        msg = completed.stderr.decode(errors="ignore").strip()
        raise RuntimeError(
            f"gpg --export failed for key reference '{key_ref}'. "
            f"GnuPG output: {msg or 'no additional details'}"
        )

    return completed.stdout.decode("utf-8", errors="ignore")


def read_key_file(path: Path) -> Tuple[str, str]:
    """Read a .asc or .pgp key file and return (format, content)."""
    if not path.is_file():
        raise FileNotFoundError(f"Key file not found: {path}")

    data = path.read_bytes()

    # Heuristic: if it looks like ASCII armor, treat as text, otherwise keep as binary.
    try:
        text = data.decode("utf-8")
        if "BEGIN PGP PUBLIC KEY BLOCK" in text:
            return ("ascii", text)
        # Even if it is text but not obviously armored, keep it as text for transparency.
        return ("text", text)
    except UnicodeDecodeError:
        # Binary .pgp or similar
        return ("binary", data.hex())


def parse_contact_arg(arg: str) -> Tuple[str, str]:
    """
    Parse a --contact argument of the form NAME:KEYREF.

    NAME is typically a callsign or human-readable contact name.
    KEYREF is either:
      - a filesystem path to a .asc or .pgp file, or
      - a GnuPG key reference (fingerprint, key ID, email, etc.)
    """
    if ":" not in arg:
        raise ValueError(
            f"Invalid contact specification '{arg}'. "
            "Expected format: NAME:KEYREF (e.g. CALLSIGN:/path/to/key.asc or CALLSIGN:0xDEADBEEF)."
        )
    name, key_ref = arg.split(":", 1)
    name = name.strip()
    key_ref = key_ref.strip()
    if not name or not key_ref:
        raise ValueError(
            f"Invalid contact specification '{arg}'. "
            "Both NAME and KEYREF must be non-empty."
        )
    return name, key_ref


def build_mapping(contacts: List[Tuple[str, str]]) -> Dict:
    """
    Build a JSON-serializable mapping structure from a list of (name, key_ref) pairs.

    For each contact:
      - If key_ref is an existing file path, store its contents.
      - Otherwise, ask gpg to export the public key in ASCII armor.
    """
    entries = []

    for name, key_ref in contacts:
        path = Path(key_ref)
        if path.exists():
            fmt, content = read_key_file(path)
            entry = {
                "name": name,
                "key_ref": str(path),
                "source": "file",
                "format": fmt,
                "public_key": content,
            }
        else:
            armor = run_gpg_export(key_ref)
            entry = {
                "name": name,
                "key_ref": key_ref,
                "source": "gpg",
                "format": "ascii",
                "public_key": armor,
            }

        entries.append(entry)

    return {
        "version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "entries": entries,
    }


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Collect Horse contact public keys from .asc/.pgp files and/or "
            "the local GnuPG keyring, producing a JSON mapping file."
        )
    )
    parser.add_argument(
        "--output",
        "-o",
        required=True,
        help="Output JSON file to write (e.g. horse_keys.json).",
    )
    parser.add_argument(
        "--contact",
        "-c",
        action="append",
        default=[],
        help=(
            "Contact specification in the form NAME:KEYREF. "
            "KEYREF may be a path to a .asc/.pgp file or a GnuPG key ID / fingerprint. "
            "May be provided multiple times."
        ),
    )
    return parser.parse_args(argv)


def main(argv: List[str]) -> int:
    args = parse_args(argv)

    if not args.contact:
        print(
            "No contacts provided. Use --contact NAME:KEYREF at least once.",
            file=sys.stderr,
        )
        return 1

    try:
        contacts = [parse_contact_arg(c) for c in args.contact]
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    try:
        mapping = build_mapping(contacts)
    except (FileNotFoundError, RuntimeError) as exc:
        print(str(exc), file=sys.stderr)
        return 1

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(mapping, f, indent=2, sort_keys=True)

    print(f"Wrote {len(mapping['entries'])} contact entries to {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

