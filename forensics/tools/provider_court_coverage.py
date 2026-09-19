#!/usr/bin/env python3
"""openssl-rs — the provider-row court-coverage atlas.

Why this exists
---------------
The export court-coverage atlas (`court_coverage.py`, D199/D236) proves that every implemented
*export* is observed by a court. The provider census (D237) introduced a second universe of things
that can be implemented: **algorithm registration rows**, which are not symbols at all. The same
hole therefore exists one level down, and the same invariant is owed:

    every provider row the census calls `implemented`
        =
      directly courted by a court that covers its stratum
    + declared with a named path through a court
    + declared unobservable, with a reason

and no unmatched row. Without this, `provider-algorithms.json` says `implemented` because a row
exists in a candidate table, and nothing proves any observation touches it. That is exactly the
weakness D236 removed for exports: a fetch-only claim is not an observation.

The measured gap this was written against
-----------------------------------------
Of the 82 implemented `OSSL_OP_CIPHER` rows, **39 were named nowhere in any probe** -- every AES and
Camellia non-128 variant in ECB/OFB/CFB/CFB1/CFB8/CTR, and the 3DES EDE/EDE3 counterparts. The
census called them implemented and no observation touched them. They are now fetched and measured by
`rt_cipher_probe.c`'s `rt_deflt_row_census` arm, and this generator is what keeps that true: it
compares the arm's name list against the census in both directions, so a row landed without a probe
line and a probe line for a row the census does not call implemented are each a failure.

What is derived and what is authored
------------------------------------
Derived: the required set (every `implemented` row), the court that names a row (a probe source
containing one of the row's aliases as a C string literal), and the probe's own name list.
Authored: nothing. A row no probe names is a **finding**, not an entry in a table somebody has to
remember to extend -- which is the whole difference between this and a hand-kept coverage list.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import ATLAS, REPO_ROOT, InputRef, envelope, rel, write_json  # noqa: E402

GENERATOR = "forensics/tools/provider_court_coverage.py"
PROVIDERS = ATLAS / "provider-algorithms.json"
OUT = ATLAS / "provider-court-coverage.json"

# The differential courts whose probes can name a provider row, and the file each is written in.
# A row is `direct` when one of its aliases appears as a C string literal in one of these; the
# mapping from probe file to court name mirrors `phase8_courts.py`'s `COURTS`.
COURT_PROBES: list[tuple[str, str, int]] = [
    ("RT-DIGEST", "courts/phase8/rt_digest_probe.c", 8),
    ("RT-CIPHER", "courts/phase8/rt_cipher_probe.c", 8),
]

# The arm whose name list must equal the census's implemented cipher rows. A static list in a probe
# is the one place a hand-kept set can go stale, so it is checked rather than trusted.
ROW_CENSUS_ARM = "courts/phase8/rt_cipher_probe.c"
ROW_CENSUS_ANCHOR = "static void rt_deflt_row_census(void)"

CLAIM = (
    "Every provider algorithm registration row that `provider-algorithms.json` records as "
    "`implemented` is either named as a C string literal by a probe belonging to a differential "
    "court, or declared with a reason. The required set is derived from the census and the provided "
    "set from the probe sources, so a row that becomes implemented without an observation is a "
    "failure on the commit that lands it rather than at a stratum's seal."
)


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def load_census() -> tuple[list[dict], str]:
    doc = json.loads(read(PROVIDERS))
    return doc["body"]["rows"], doc.get("authority", "unknown")


def arm_names(text: str) -> list[str]:
    """The names `rt_deflt_row_census` fetches, in order.

    Anchored on the function and then on its own `rows[]` initialiser, so the parser cannot pick up
    string literals from anywhere else in the probe.
    """
    at = text.index(ROW_CENSUS_ANCHOR)
    body = text[at:]
    start = body.index("static const char *rows[] = {")
    end = body.index("};", start)
    return re.findall(r'"([^"]*)"', body[start:end])


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    args = ap.parse_args(argv)
    del args

    rows, authority = load_census()
    implemented = [r for r in rows if r["implementation_state"] == "implemented"]

    probes: list[tuple[str, int, str]] = []
    for court, relpath, phase in COURT_PROBES:
        path = REPO_ROOT / relpath
        if not path.is_file():
            print(f"[provider-court-coverage] fatal: {relpath} is absent", file=sys.stderr)
            return 1
        probes.append((court, phase, read(path)))

    covered: list[dict] = []
    unmatched: list[dict] = []
    for row in implemented:
        naming = [
            court
            for court, _phase, text in probes
            if any(f'"{alias}"' in text for alias in row["aliases"])
        ]
        record = {
            "provider": row["provider"],
            "operation": row["operation"],
            "algorithm_names": row["algorithm_names"],
            "aliases": row["aliases"],
            "owning_phase": row["owning_phase"],
            "courts": naming,
        }
        if naming:
            record["coverage"] = "direct"
            covered.append(record)
        else:
            record["coverage"] = "unmatched"
            unmatched.append(record)

    # The probe's own list, against the census, in both directions. A corpus row the arm fetches and
    # the census does not call implemented is as much a staleness as the reverse.
    text = read(REPO_ROOT / ROW_CENSUS_ARM)
    listed = arm_names(text)
    expected = [
        r["algorithm_names"]
        for r in implemented
        if r["operation"] == "OSSL_OP_CIPHER"
    ]
    problems: list[str] = []
    if listed != expected:
        missing = [n for n in expected if n not in listed]
        extra = [n for n in listed if n not in expected]
        problems.append(
            f"{ROW_CENSUS_ARM}'s row census lists {len(listed)} row(s) for {len(expected)} "
            f"implemented cipher row(s); not listed: {missing or 'none'}; listed but not "
            f"implemented: {extra or 'none'}"
        )
    if unmatched:
        problems.append(
            f"{len(unmatched)} implemented provider row(s) are named by no probe: "
            + ", ".join(sorted(r["algorithm_names"] for r in unmatched)[:8])
        )

    per_phase: dict[str, dict[str, int]] = {}
    for record in covered + unmatched:
        bucket = per_phase.setdefault(
            str(record["owning_phase"]), {"implemented": 0, "unmatched": 0}
        )
        bucket["implemented"] += 1
        if not record["courts"]:
            bucket["unmatched"] += 1

    body = {
        "claim": CLAIM,
        "courts": [
            {"court": court, "phase": phase, "probe": probe_rel}
            for court, probe_rel, phase in COURT_PROBES
        ],
        "implemented_rows": len(implemented),
        "directly_courted": len(covered),
        "unmatched": len(unmatched),
        "by_phase": {k: per_phase[k] for k in sorted(per_phase)},
        "rows": sorted(
            covered + unmatched,
            key=lambda r: (r["provider"], r["operation"], r["algorithm_names"]),
        ),
    }

    inputs = [
        InputRef(name="census", path=PROVIDERS),
        *[
            InputRef(name=f"court:{court}", path=REPO_ROOT / probe_rel)
            for court, probe_rel, _phase in COURT_PROBES
        ],
    ]
    doc = envelope(
        kind="provider-court-coverage", generator=GENERATOR, inputs=inputs, body=body,
        authority=authority,
    )
    write_json(OUT, doc)

    print(f"[provider-court-coverage] implemented provider rows: {len(implemented)}")
    print(f"  directly courted: {len(covered)}")
    print(f"  unmatched:        {len(unmatched)}")
    for phase in sorted(per_phase):
        counts = per_phase[phase]
        print(f"  phase {phase}: {counts['implemented']} implemented, {counts['unmatched']} unmatched")
    if problems:
        for p in problems:
            print(f"[provider-court-coverage] finding: {p}", file=sys.stderr)
        print(f"[provider-court-coverage] {len(problems)} finding(s)", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
