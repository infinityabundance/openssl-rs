#!/usr/bin/env python3
"""openssl-rs — forbidden-dependency gate.

`docs/CUSTODIAN_CONTRACT.md` §3 forbids using any existing cryptographic
implementation as the product's backend. That rule is worthless if it is only
prose, so it is enforced here and wired into the release gates.

Checks:
  1. `[dependencies]` / `[build-dependencies]` / `[dev-dependencies]` in
     Cargo.toml;
  2. every package name in Cargo.lock, including transitive dependencies.

Run inside the court:

    python3 forensics/tools/check_forbidden_dependencies.py

Exit 0 if clean, 1 if a forbidden dependency is present.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# Crate names (normalised: lowercase, '-' == '_') that must never appear as a
# dependency of the product. Independent implementations may exist in the court
# as *test authorities*, but never as a backend.
FORBIDDEN = {
    "openssl",
    "openssl_sys",
    "openssl_src",
    "rustls",
    "rustls_ffi",
    "rustls_pemfile",
    "aws_lc_rs",
    "aws_lc_sys",
    "aws_lc",
    "boringssl",
    "boring",
    "boring_sys",
    "libressl",
    "ring",
    "mbedtls",
    "wolfssl",
    "sodiumoxide",
    "libsodium_sys",
}

SECTION_RE = re.compile(r"^\s*\[([^\]]+)\]\s*$")
KEY_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*=")
LOCK_NAME_RE = re.compile(r'^\s*name\s*=\s*"([^"]+)"\s*$')


def normalise(name: str) -> str:
    return name.strip().lower().replace("-", "_")


def check_manifest(path: Path) -> list[str]:
    if not path.exists():
        return []
    offenders = []
    section = ""
    for line in path.read_text().splitlines():
        m = SECTION_RE.match(line)
        if m:
            section = m.group(1)
            continue
        if section.endswith("dependencies"):
            k = KEY_RE.match(line)
            if k and normalise(k.group(1)) in FORBIDDEN:
                offenders.append(f"{path.name}: [{section}] {k.group(1)}")
    return offenders


def check_lock(path: Path) -> list[str]:
    if not path.exists():
        return []
    offenders = []
    for line in path.read_text().splitlines():
        m = LOCK_NAME_RE.match(line)
        if m and normalise(m.group(1)) in FORBIDDEN:
            offenders.append(f"{path.name}: package {m.group(1)}")
    return offenders


def main() -> int:
    offenders = check_manifest(REPO_ROOT / "Cargo.toml")
    offenders += check_lock(REPO_ROOT / "Cargo.lock")
    if offenders:
        print("FORBIDDEN DEPENDENCIES PRESENT:", file=sys.stderr)
        for o in offenders:
            print(f"  {o}", file=sys.stderr)
        print(
            "\nThe product must not use an existing cryptographic implementation "
            "as a backend (docs/CUSTODIAN_CONTRACT.md §3).",
            file=sys.stderr,
        )
        return 1
    print("forbidden-dependency gate: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
