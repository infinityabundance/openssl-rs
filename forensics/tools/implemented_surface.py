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

`internal_symbols` is split, and the split matters. Most of what the archive
defines is compiler output: Rust manglings and LLVM-internalised anonymous data
whose names are literally `anon.<hash>.<n>.llvm.<hash>`. Those hashes are a
function of the *build*, not of the source, so the names cannot be evidence and
are not recorded as names. What is recorded and compared exactly is the subset a
consumer's own symbols could actually collide with: plain C identifiers. The
compiler-emitted population is kept only as a declared build-product count, which
`evidence_determinism.py` normalises and reports (docs/DECISIONS.md D30).

The symbol tables are read by `elf_symbols.py` rather than by `nm`, because a
host's `nm` may read Rust's LLVM bitcode and report symbols the object does not
define natively -- a reader-dependent symbol set, which is what made CI and the
court disagree (docs/DECISIONS.md D33).
"""

from __future__ import annotations

import argparse
import json
import re
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
from elf_symbols import defined_external_symbols  # noqa: E402

# The distribution artifacts and the symbol namespaces they carry. Kept here
# rather than parameterised because the *separation* (libcrypto vs libssl as two
# namespaces) is a contract fact, not a build option.
LIBRARIES = ("libcrypto", "libssl")

DEFAULT_ARCHIVE = REPO_ROOT / "target" / "release" / "libopenssl_rs.a"
# The crate archive's location. It is deliberately the repository's `target/`
# rather than anything environment-dependent: the court purges host-written
# dev-profile artifacts before running (D62), so the release archive this reads
# is always the court's own, and the path recorded in the artefact stays the
# same string in every environment that regenerates it.
DEFAULT_ARCHIVE = REPO_ROOT / "target" / "release" / "libopenssl_rs.a"

OUT = REPO_ROOT / "forensics" / "atlas" / "implemented-surface.json"

# --- symbol tables -----------------------------------------------------------
#
# Read via `elf_symbols.py`, never via `nm`. See that module's header: a host's
# binfmt plugin may read Rust's LLVM bitcode, so `nm` reports more symbols on one
# machine than another for the *same* archive. The native `.symtab` is what the
# shell must reason about, and it is a function of the archive alone.
#
# A name a C consumer could collide with: a plain C identifier that is not a
# Rust mangling (legacy `_ZN...` or v0 `_R...`).
C_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
RUST_MANGLED_RE = re.compile(r"_(R|ZN)")


def is_c_style(name: str) -> bool:
    """True for the stable, collision-relevant part of the internal symbol set."""
    return bool(C_IDENT_RE.match(name)) and not RUST_MANGLED_RE.match(name)


def defined_symbols(path: Path) -> set[str]:
    """Global symbols *defined* by an archive or object.

    Defined-but-external is the right filter: a scaffold and an implementation
    differ precisely in whether the symbol is defined here.
    """
    if not path.is_file():
        raise SystemExit(
            f"implemented_surface: {rel(path)} does not exist.\n"
            f"  Build the crate first:  cargo build --release"
        )
    return defined_external_symbols(path)


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
    c_style = [s for s in internal if is_c_style(s)]
    compiler_emitted = [s for s in internal if not is_c_style(s)]

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
        # Split deliberately (docs/DECISIONS.md D30). `c_style` is stable across
        # builds and is compared exactly: these are the names a consumer's own
        # symbols could collide with, and they are what `local: *;` must hide.
        # `compiler_emitted_count` covers Rust manglings and LLVM-internalised
        # anonymous data, whose `anon.<hash>.<n>.llvm.<hash>` names change from
        # build to build; the names are a build product, so only the count is
        # recorded, and evidence_determinism.py normalises and reports it.
        "internal_symbols": {
            "status": "build-product observation, not contract evidence",
            "definition": (
                "global symbols defined by the crate's static archive that are not "
                "authority exports; the version script's `local: *;` hides them from "
                "the DSO, so they are not part of the ABI"
            ),
            "c_style": c_style,
            "compiler_emitted_count": len(compiler_emitted),
            "note": (
                "`c_style` is compared exactly: these are the names a consumer's "
                "own symbols could collide with. `compiler_emitted_count` is a "
                "property of the toolchain (its codegen), not of the source, so "
                "it is recorded as a count and evidence_determinism.py normalises "
                "and reports it. It is excluded from body_hash for the same "
                "reason. The symbol tables are read by elf_symbols.py rather than "
                "by `nm`, so the set does not depend on the host's binutils."
            ),
        },
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
    doc["body_hash"] = content_hash(evidence_body(body))
    doc["body_hash_note"] = (
        "hashed over the evidence subset of `body`; `internal_symbols` is excluded "
        "because it carries build-product counts (docs/DECISIONS.md D30). Ledgers "
        "bind this digest rather than the file digest, so the build product cannot "
        "propagate into them."
    )
    return doc


def evidence_body(body: dict) -> dict:
    """`body` without the fields that are build products rather than evidence."""
    return {k: v for k, v in body.items() if k != "internal_symbols"}


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
    internal = doc["body"]["internal_symbols"]
    print(f"  internal symbols (not ABI): c_style={len(internal['c_style'])} "
          f"compiler_emitted={internal['compiler_emitted_count']}")
    print(f"    c_style: {', '.join(internal['c_style'])}")
    print(f"  -> {rel(args.out)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
