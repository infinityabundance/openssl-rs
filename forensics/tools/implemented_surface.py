#!/usr/bin/env python3
"""openssl-rs — derive the *candidate implemented surface* from the built crate.

Why this tool exists
--------------------
`docs/CUSTODIAN_CONTRACT.md` §5 lets the ABI shell carry SCAFFOLDED definitions
for obligations that are not implemented yet, and requires that a scaffold
"cannot count as parity". That rule only has teeth if the shell generator knows
*which* symbols are implemented, because a scaffold and an implementation of the
same symbol cannot both be defined in one link.

The honest source for "what does the crate implement" is **the crate's own
compiled output**, not a list someone maintains by hand. So this tool:

  1. requires the built crate archive (`libopenssl_rs.a`);
  2. reads the authority's measured DSO export inventory (the same plane the
     ABI-SYMBOL court uses);
  3. intersects them with the symbols the archive actually **defines**;
  4. writes `forensics/atlas/implemented-surface.json` — content-addressed,
     with the counts per library.

The result is deliberately *not* a parity claim. It says "the crate defines a
symbol with this name". Whether that definition is ABI-compatible, semantically
compatible, ownership-compatible and so on is decided by the courts, dimension
by dimension, exactly as `docs/PARITY_MODEL.md` requires. A symbol that appears
here is at most `IMPLEMENTED`; it is never `PARITY_VERIFIED` by this tool.

Symbols the crate defines that are *not* in the authority's export set (for
example `openssl_rs_err_set_error`, the internal callback the C-variadic
adapters call) are recorded separately as `internal_symbols`. They are hidden by
the version script's `local: *;` and are not part of the ABI.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    PRODUCTION_AUTHORITY,
    REPO_ROOT,
    InputRef,
    content_hash,
    envelope,
    rel,
    resolve_authority,
    sha256_file,
    write_json,
    authority_atlas_dir,
)

# The distribution artifacts and the symbol namespaces they carry. Kept here
# rather than parameterised because the *separation* (libcrypto vs libssl as two
# namespaces) is a contract fact, not a build option.
LIBRARIES = ("libcrypto", "libssl")

DEFAULT_ARCHIVE = REPO_ROOT / "target" / "release" / "libopenssl_rs.a"
OUT = REPO_ROOT / "forensics" / "atlas" / "implemented-surface.json"


def defined_symbols(archive: Path) -> set[str]:
    """Global symbols *defined* by an archive or object, via `nm`.

    `--defined-only --extern-only` is the right filter: a scaffold and an
    implementation differ precisely in whether the symbol is defined here.
    """
    if not archive.is_file():
        raise SystemExit(
            f"implemented_surface: {rel(archive)} does not exist.\n"
            f"  Build the crate first:  cargo build --release"
        )
    out = subprocess.run(
        ["nm", "--defined-only", "--extern-only", str(archive)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    names: set[str] = set()
    for line in out.splitlines():
        parts = line.split()
        # nm format: "<addr> <type> <name>" (or "<type> <name>" for undefined).
        if len(parts) >= 3:
            names.add(parts[2])
        elif len(parts) == 2:
            names.add(parts[1])
    return names


def authority_exports(authority_id: str, lib: str) -> list[dict]:
    """The authority DSO's actual exports for one library (plane C)."""
    doc = json.loads((authority_atlas_dir(authority_id) / f"symbols-{lib}.json").read_text())
    out = []
    for rec in doc["body"]["records"]:
        dso = rec.get("dso") or {}
        if dso.get("present"):
            out.append(
                {
                    "symbol": rec["symbol"],
                    "version": dso.get("version"),
                    "type": dso.get("type"),
                    "bind": dso.get("bind"),
                }
            )
    return out


def build(authority_id: str, archive: Path, extra_objects: list[Path]) -> dict:
    auth = resolve_authority(authority_id)
    defined = defined_symbols(archive)
    for obj in extra_objects:
        defined |= defined_symbols(obj)

    per_lib: dict[str, dict] = {}
    claimed: set[str] = set()
    for lib in LIBRARIES:
        exports = authority_exports(authority_id, lib)
        exported_names = {e["symbol"] for e in exports}
        implemented = sorted(exported_names & defined)
        claimed |= exported_names
        per_lib[lib] = {
            "authority_exports": len(exported_names),
            "implemented": len(implemented),
            "scaffolded": len(exported_names) - len(implemented),
            "implemented_symbols": implemented,
        }

    internal = sorted(defined - claimed)

    body = {
        "authority": auth.id,
        "authority_version": auth.version,
        "archive": rel(archive),
        "libraries": per_lib,
        "totals": {
            "authority_exports": sum(v["authority_exports"] for v in per_lib.values()),
            "implemented": sum(v["implemented"] for v in per_lib.values()),
            "scaffolded": sum(v["scaffolded"] for v in per_lib.values()),
        },
        "internal_symbols": internal,
        "claim": (
            "IMPLEMENTED means only: the crate's compiled output defines a symbol "
            "with this name in this library's namespace. It is NOT a parity claim. "
            "Parity is promoted only by courts, dimension by dimension "
            "(docs/PARITY_MODEL.md)."
        ),
    }

    inputs = [InputRef(name="crate-archive", path=archive)]
    for obj in extra_objects:
        inputs.append(InputRef(name="extra-object", path=obj))
    inputs.append(
        InputRef(
            name="authority-exports",
            path=authority_atlas_dir(authority_id) / "symbols-libcrypto.json",
        )
    )
    inputs.append(
        InputRef(
            name="authority-exports",
            path=authority_atlas_dir(authority_id) / "symbols-libssl.json",
        )
    )

    doc = envelope(
        "implemented-surface",
        "forensics/tools/implemented_surface.py",
        inputs,
        body,
        authority=auth.id,
    )
    doc["body_hash"] = content_hash(body)
    return doc


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Derive the candidate implemented surface.")
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    ap.add_argument("--archive", type=Path, default=DEFAULT_ARCHIVE)
    ap.add_argument("--object", type=Path, action="append", default=[],
                    help="additional object file whose defined symbols count as implemented")
    ap.add_argument("--out", type=Path, default=OUT)
    args = ap.parse_args(argv)

    doc = build(args.authority, args.archive, args.object)
    write_json(args.out, doc)

    t = doc["body"]["totals"]
    print(f"[implemented-surface] {doc['authority']}")
    for lib, v in doc["body"]["libraries"].items():
        print(f"  {lib:<10} exports={v['authority_exports']:<6} "
              f"implemented={v['implemented']:<6} scaffolded={v['scaffolded']}")
    print(f"  {'total':<10} exports={t['authority_exports']:<6} "
          f"implemented={t['implemented']:<6} scaffolded={t['scaffolded']}")
    print(f"  internal symbols (not ABI): {len(doc['body']['internal_symbols'])}")
    print(f"  -> {rel(args.out)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
