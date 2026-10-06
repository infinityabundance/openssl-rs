#!/usr/bin/env python3
"""openssl-rs — the parameterized archaeology atlas (Phase 23.3).

Why this exists
---------------
Phase 1 and Phase 22 mined the *production* authority (OpenSSL 3.6.4) into a per-authority
atlas. Phase 23.3 generalizes that into **one generator parameterized by authority identity**
rather than a `phase1_old.py` per version: the same code path serves an admitted court authority
and a built historical authority, and an older authority produces a **measured absence** -- a real
counted zero with provenance -- where a modern plane does not exist for it, rather than an empty
modern assumption (no Providers, no Provider registrations, no QUIC, ...).

Two things make this reproducible without the (uncommitted) authority trees:

  * each authority's identity and its source manifest are read from committed records
    (`forensics/authorities/AUTHORITIES.json`, `forensics/multitrack/historical-acquisition.json`)
    and the committed manifest `SOURCE_MANIFEST.<version>.json` is the evidence plane; and
  * every plane is a *counted predicate over that manifest's own file list*, so an absence is
    evidence (`0 paths match`) rather than an assertion.

The default authority is selected through the committed alias
`forensics/multitrack/default-authority.json` (never the catalogue's `latest-stable`, never the
newest build). `--authority <id>` selects explicitly; a historical authority is resolved through
the same atlas_common path as a court one.

Outputs
-------
  forensics/atlas/parameterization-receipt.json              the parameterization proof
  forensics/atlas/<historical-id>/plane-census.json          a non-default authority's census

The **default** authority's census is carried inside the receipt rather than written beside its
committed atlas, so the committed `forensics/atlas/openssl-3.6.4-production/**` plane is not
perturbed. The receipt's `byte_identity` block binds that plane: it records the sha256 of every
committed file and names the pre-existing, disclosed drift of the parity reconciliation plane.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    ATLAS,
    AUTH_ROOT,
    REPO_ROOT,
    InputRef,
    all_authority_ids,
    authority_atlas_dir,
    default_authority_id,
    envelope,
    historical_authority_ids,
    load_registry,
    rel,
    sha256_file,
    write_json,
)

import multitrack_schemas  # noqa: E402

GENERATOR = "forensics/tools/atlas_authority.py"
RECEIPT = ATLAS / "parameterization-receipt.json"
MANIFEST_DIR = AUTH_ROOT
HISTORICAL_ACQUISITION = REPO_ROOT / "forensics" / "multitrack" / "historical-acquisition.json"

# The archaeology generators an authority-parameterized regeneration runs. They are the Phase-1
# planes that take `--authority` and reproduce their committed bytes; the court re-runs them through
# `--authority` for the proof. `atlas_parity.py` is deliberately **not** here: its committed output
# has a pre-existing drift (below), so it is disclosed rather than claimed.
REGENERATORS = [
    "forensics/tools/atlas_symbols.py",
    "forensics/tools/atlas_api.py",
    "forensics/tools/atlas_runtime.py",
    "forensics/tools/atlas_abi.py",
    "forensics/tools/render_atlas.py",
]

# The derived artefacts whose committed bytes do not currently reproduce: the committed
# `parity-obligations.json` and the rendered `ATLAS.md` predate the CLI option grammar that
# `cli-commands.json` gained at p16 (commit 0db42154), and neither was regenerated after it, so
# re-deriving moves each command's `option_count` from the stale 0 to the measured value. It is a
# *pre-existing* staleness unrelated to authority parameterization; it is named here, measured by
# the court, and never silently applied (the committed atlas is left byte-identical).
KNOWN_STALE = (
    {
        "path": "forensics/atlas/openssl-3.6.4-production/parity-obligations.json",
        "generator": "forensics/tools/atlas_parity.py",
        "reason": (
            "the committed parity-obligations.json predates the CLI option grammar added to "
            "cli-commands.json at commit 0db42154 (p16) and was never regenerated, so re-deriving "
            "moves each command's option_count from the stale 0 to the measured value"
        ),
    },
    {
        "path": "forensics/atlas/openssl-3.6.4-production/ATLAS.md",
        "generator": "forensics/tools/render_atlas.py",
        "reason": (
            "the committed ATLAS.md is the Markdown projection of the same p16-stale cli-commands "
            "data, so its command/option table shows the stale 0; re-rendering moves it"
        ),
    },
)
KNOWN_STALE_PATHS = frozenset(e["path"] for e in KNOWN_STALE)


# ---------------------------------------------------------------------------
# plane definitions: a counted predicate over the authority's own source manifest
# ---------------------------------------------------------------------------

def _under(*prefixes: str):
    return lambda files: [f for f in files if any(f.startswith(p) for p in prefixes)]


def _suffix(suffix: str):
    return lambda files: [f for f in files if f.endswith(suffix)]


def _under_and_suffix(prefix: str, suffix: str):
    return lambda files: [f for f in files if f.startswith(prefix) and f.endswith(suffix)]


def _exact(path: str):
    return lambda files: [f for f in files if f == path]


def _quic(files: list[str]) -> list[str]:
    return [f for f in files if f.startswith("ssl/quic/") or f == "include/openssl/quic.h"]


# `(plane, epoch-introduced, what, predicate)`, in a fixed order so the census is deterministic.
# `epoch` is None for the always-present planes; for a feature plane it is the release that
# introduced it, used only to say whether an absence is *expected chronology* or not -- it is never
# a compatibility claim (docs/PARITY_TRACK / multitrack_schemas).
PLANES: tuple[tuple[str, object, str, object], ...] = (
    ("source-tree", None, "the release's own committed source file inventory",
     lambda files: list(files)),
    ("source-headers", None, "C headers in the source tree",
     _suffix(".h")),
    ("cli-apps", None, "the `openssl` command units under `apps/`",
     _under_and_suffix("apps/", ".c")),
    ("test-suite", None, "the upstream test recipes under `test/`",
     _under("test/")),
    ("man-pages", None, "the documentation under `doc/`",
     _under("doc/")),
    ("symbol-ordinal-inventory", None, "ordinal inventories (`*.num`)",
     _suffix(".num")),
    ("engines", "0.9.7", "the ENGINE implementation under `crypto/engine/`",
     _under("crypto/engine/")),
    ("engine-registry", "1.0.0", "the ENGINE registration inventory (`util/engines.num`)",
     _exact("util/engines.num")),
    ("providers", "3.0.0", "the provider implementation under `providers/`",
     _under("providers/")),
    ("provider-registrations", "3.0.0", "the provider registration inventory "
     "(`util/providers.num`)",
     _exact("util/providers.num")),
    ("fips-provider", "3.0.0", "the FIPS provider source under `providers/fips/`",
     _under("providers/fips/")),
    ("provider-capabilities", "3.0.0", "the default provider's capability tables (`*prov.c`)",
     _under_and_suffix("providers/", "prov.c")),
    ("store-api", "3.0.0", "the OSSL_STORE API (`crypto/store/store_meth.c`)",
     _exact("crypto/store/store_meth.c")),
    ("encoder-decoder-api", "3.0.0", "the encoder/decoder API under `crypto/encode_decode/`",
     _under("crypto/encode_decode/")),
    ("quic", "3.2.0", "the QUIC implementation (`ssl/quic/` and `include/openssl/quic.h`)",
     _quic),
    ("symbol-versioning", "1.1.0", "the modern versioned symbol inventory (`util/libcrypto.num`)",
     _exact("util/libcrypto.num")),
)

# Planes whose presence is the conjunction of two others rather than a path prefix. Recorded
# separately so the conjunction is explicit rather than a second, drifting predicate.
CONJUNCT_PLANES = {
    "engine-vs-provider-registry": {
        "epoch": "3.0.0",
        "what": "the ENGINE-versus-Provider registration comparison plane",
        "parts": ("engine-registry", "provider-registrations"),
    },
}

PLANE_ORDER = [p[0] for p in PLANES] + ["engine-vs-provider-registry"]


# ---------------------------------------------------------------------------
# authority identity, read from committed records
# ---------------------------------------------------------------------------

def authority_identity(authority_id: str) -> dict:
    """`(version, role, venue, manifest relpath, manifest filename)` for an authority.

    Reads the admitted-authority registry first, then the historical acquisition registry. The
    manifest is committed, so a census is a pure function of committed inputs; the (uncommitted)
    source tree is never required.
    """
    reg = load_registry()
    for a in reg["authorities"]:
        if a["id"] == authority_id:
            return {
                "authority_id": a["id"],
                "version": a["version"],
                "role": a["role"],
                "venue": "court",
                "manifest": f"forensics/authorities/{a['source_tree']['manifest']}",
                "manifest_root_hash": a["source_tree"]["root_hash"],
                "source_file_count": a["source_tree"]["file_count"],
            }
    if HISTORICAL_ACQUISITION.is_file():
        doc = json.loads(HISTORICAL_ACQUISITION.read_text(encoding="utf-8"))
        for a in doc.get("acquisitions", []):
            if a.get("id") == authority_id:
                return {
                    "authority_id": a["id"],
                    "version": a["version"],
                    "role": a.get("role", "historical"),
                    "venue": "historical",
                    "manifest": f"forensics/authorities/{a['source_tree']['manifest']}",
                    "manifest_root_hash": a["source_tree"]["root_hash"],
                    "source_file_count": a["source_tree"]["file_count"],
                }
    raise SystemExit(f"atlas-authority: no admitted or acquired authority {authority_id!r}")


def manifest_files(manifest_relpath: str) -> list[str]:
    """The sorted source-relative paths of a committed source manifest."""
    p = REPO_ROOT / manifest_relpath
    if not p.is_file():
        raise SystemExit(f"atlas-authority: source manifest {manifest_relpath} is absent")
    doc = json.loads(p.read_text(encoding="utf-8"))
    return sorted(entry["path"] for entry in doc.get("files", []))


# ---------------------------------------------------------------------------
# the census
# ---------------------------------------------------------------------------

def _chronology(version: str, epoch: object) -> str:
    """Whether `version` predates `epoch`, read through the shared version parser.

    Chronology only: it says whether an absence is the release predating a feature epoch, and it
    is never a compatibility claim (`multitrack_schemas` D535).
    """
    if epoch is None:
        return "n/a"
    if multitrack_schemas.chronological_order(str(version), str(epoch)) < 0:
        return "predates"
    return "at_or_after"


def build_census(authority_id: str) -> dict:
    """The plane census for one authority: every plane produced, or a measured absence.

    A plane is `produced` when its predicate matches at least one path in the authority's own
    source manifest, and `measured_absence` when it matches **zero** -- the zero is the evidence,
    and the row carries the epoch and whether the release's own version predates it.
    """
    identity = authority_identity(authority_id)
    files = manifest_files(identity["manifest"])
    rows: list[dict] = []
    matched_by_plane: dict[str, list[str]] = {}

    for plane, epoch, what, predicate in PLANES:
        matches = predicate(files)
        matched_by_plane[plane] = matches
        rows.append(_plane_row(identity, plane, epoch, what, matches))

    for plane, spec in CONJUNCT_PLANES.items():
        parts = spec["parts"]
        matches = [p for part in parts for p in matched_by_plane.get(part, [])]
        rows.append(_plane_row(identity, plane, spec["epoch"], spec["what"], matches,
                               parts=parts))

    produced = sum(1 for r in rows if r["status"] == "produced")
    absent = sum(1 for r in rows if r["status"] == "measured_absence")
    return {
        "authority_id": identity["authority_id"],
        "version": identity["version"],
        "role": identity["role"],
        "venue": identity["venue"],
        "manifest": identity["manifest"],
        "manifest_root_hash": identity["manifest_root_hash"],
        "source_file_count": identity["source_file_count"],
        "plane_order": PLANE_ORDER,
        "planes": rows,
        "counts": {
            "planes": len(rows),
            "produced": produced,
            "measured_absence": absent,
        },
        "note": (
            "one census per authority from the same parameterized generator: a `produced` plane is "
            "a nonzero count over the authority's own committed source manifest, and a "
            "`measured_absence` is a counted zero with its epoch and chronology as provenance, "
            "never an empty modern assumption. A plane here is a *source* plane: it says the "
            "release's tree carries the implementation, not that the built profile enabled it."
        ),
    }


def _plane_row(identity: dict, plane: str, epoch: object, what: str, matches: list[str],
               *, parts: tuple[str, ...] = ()) -> dict:
    count = len(matches)
    chronology = _chronology(identity["version"], epoch)
    if count:
        detail = f"{count} path(s) under the plane's predicate in {identity['manifest']}"
    else:
        pred = " and ".join(parts) if parts else plane
        if chronology == "predates":
            detail = (f"{identity['version']} predates the {epoch} epoch ({pred}): zero paths in "
                      f"{identity['manifest']} is the measured absence")
        else:
            detail = (f"{identity['version']} is at or after the {epoch} epoch but the plane's "
                      f"predicate ({pred}) matches zero paths in {identity['manifest']}")
    return {
        "plane": plane,
        "epoch_introduced": epoch,
        "status": "produced" if count else "measured_absence",
        "count": count,
        "evidence": {
            "manifest": identity["manifest"],
            "manifest_paths_matched": count,
            "sample": sorted(matches)[:6],
            "chronology": chronology,
            "detail": detail,
        },
    }


# ---------------------------------------------------------------------------
# the receipt and its byte-identity binding
# ---------------------------------------------------------------------------

def _atlas_dir(authority_id: str) -> Path:
    return authority_atlas_dir(authority_id)


def byte_identity_block(authority_id: str) -> dict:
    """The committed atlas files of the default authority, with their sha256 and status.

    The default authority's plane must not move: this block is the receipt's proof that every
    committed file is named and hashed, that the authority-parameterized generators reproduce
    them, and that the one disclosed pre-existing drift is named rather than hidden.
    """
    atlas_dir = _atlas_dir(authority_id)
    files = sorted(p for p in atlas_dir.glob("*") if p.is_file())
    out = []
    for p in files:
        out.append({
            "path": rel(p),
            "sha256": sha256_file(p),
            "reproduces": rel(p) not in KNOWN_STALE_PATHS,
        })
    return {
        "authority_id": authority_id,
        "atlas_dir": rel(atlas_dir),
        "regenerators": list(REGENERATORS),
        "files": out,
        "not_reproduced": [dict(entry) for entry in KNOWN_STALE],
        "note": (
            "the authority-parameterized generators above are re-run by the "
            "RT-ATLAS-PARAMETERIZATION court for this authority and must reproduce every committed "
            "JSON byte; the `not_reproduced` entries are a pre-existing staleness that is "
            "disclosed, measured live by the court, and **not** applied, so the committed plane "
            "stays byte-identical"
        ),
    }


def build_receipt(authority_ids: list[str]) -> dict:
    default_id = default_authority_id()
    censuses = {aid: build_census(aid) for aid in authority_ids}
    if default_id not in censuses:
        censuses[default_id] = build_census(default_id)
    absent = {aid: [r["plane"] for r in c["planes"] if r["status"] == "measured_absence"]
              for aid, c in censuses.items()}
    body = {
        "receipt_id": f"PARAM-{default_id}",
        "default_authority": default_id,
        "default_alias": "forensics/multitrack/default-authority.json",
        "plane_order": PLANE_ORDER,
        "selection": (
            "the default authority is read from the committed alias, never from the catalogue's "
            "`latest-stable` (openssl-4.0.3) and never from a version sort; an explicit "
            "`--authority` overrides it"
        ),
        "same_code_path": {
            "generator": GENERATOR,
            "plane_order": PLANE_ORDER,
            "authorities": sorted(censuses),
            "note": (
                "one generator and one plane set serve every authority; each census differs only "
                "in what that authority's own committed manifest measures, so an older authority "
                "produces a measured absence instead of an empty modern assumption"
            ),
        },
        "byte_identity": byte_identity_block(default_id),
        "censuses": {aid: censuses[aid] for aid in sorted(censuses)},
        "measured_absences": {aid: sorted(v) for aid, v in sorted(absent.items())},
        "note": (
            "Phase 23.3's parameterization proof. The 3.6.4 production authority is the pivot: its "
            "plane is byte-identical after the refactor, and the historical authority "
            "openssl-0.9.8zh-historical is produced through the same code path, with every plane "
            "the release does not have recorded as a measured absence (a counted zero with its "
            "manifest and epoch as provenance)."
        ),
    }
    inputs = [
        InputRef(name="default-authority", path=REPO_ROOT / "forensics" / "multitrack"
                 / "default-authority.json"),
        InputRef(name="authority-registry", path=AUTH_ROOT / "AUTHORITIES.json"),
        InputRef(name="historical-acquisition", path=HISTORICAL_ACQUISITION),
    ]
    for c in censuses.values():
        inputs.append(InputRef(name=f"source-manifest:{c['authority_id']}",
                               path=REPO_ROOT / c["manifest"]))
    doc = envelope(kind="parameterization-receipt", generator=GENERATOR, inputs=inputs,
                   body=body, authority=default_id)
    return doc


def _default_targets() -> list[str]:
    """The authorities the no-argument run covers: the default plus every built historical one."""
    ids = [default_authority_id(), *historical_authority_ids()]
    return sorted(set(ids))


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", action="append", default=[],
                    help="authority id to census (repeatable)")
    ap.add_argument("--all-court", action="store_true",
                    help="census every admitted court authority as well")
    ap.add_argument("--list", action="store_true", help="print the plane set and exit")
    args = ap.parse_args(argv)

    if args.list:
        for plane in PLANE_ORDER:
            print(plane)
        return 0

    if args.authority:
        targets = sorted(set(args.authority))
    else:
        targets = _default_targets()
        if args.all_court:
            targets = sorted(set(targets) | set(all_authority_ids()))

    default_id = default_authority_id()

    # A census beside the authority's atlas, except for the default authority whose committed plane
    # must not be perturbed -- its census is carried in the receipt instead.
    for aid in targets:
        if aid == default_id:
            continue
        census = build_census(aid)
        outdir = _atlas_dir(aid)
        doc = envelope(kind="plane-census", generator=GENERATOR,
                       inputs=[InputRef(name="source-manifest", path=REPO_ROOT / census["manifest"])],
                       body=census, authority=aid)
        write_json(outdir / "plane-census.json", doc)
        print(f"[atlas-authority] {rel(outdir / 'plane-census.json')} "
              f"({census['counts']['produced']} produced, "
              f"{census['counts']['measured_absence']} measured absence)")

    receipt = build_receipt(targets)
    write_json(RECEIPT, receipt)
    c = receipt["body"]["censuses"][default_id]["counts"]
    print(f"[atlas-authority] {rel(RECEIPT)} "
          f"(default={default_id}: {c['produced']} produced, {c['measured_absence']} absent over "
          f"{c['planes']} planes)")
    for aid in sorted(receipt["body"]["measured_absences"]):
        if aid == default_id:
            continue
        print(f"  {aid}: measured absences = "
              f"{', '.join(receipt['body']['measured_absences'][aid])}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
