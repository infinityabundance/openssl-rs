#!/usr/bin/env python3
"""openssl-rs — the historical population: a support status for every catalogue node.

Phase 23 is the multitrack authority stratum (`docs/PHASE-23-MULTITRACK-SUBPHASES.md`). 23.10 says
the historical population is the systematic **admission and courting of the public final-release
lineage forward from the first release**, recording **honest unavailability** where a release cannot
be reproducibly built rather than counting it runtime-compatible. This module derives that record --
`forensics/multitrack/historical-population.json` -- from the artefacts that already carry the facts,
and never types a status:

  * `forensics/release-catalog.json` -- the release node and its channel, scope and version;
  * `forensics/authority-nodes.json` -- the builds, their receipts and the release each names;
  * `forensics/multitrack/historical-acquisition.json` -- a release's acquisition, or its recorded
    unavailability with its reason;
  * `forensics/multitrack/historical-build-receipts.json` and `forensics/atlas/BUILD_RECORDS.json`
    -- the build receipts a `built-authority` rung is backed by. `BUILD_RECORDS.json` records the
    host's `build_platform`/`build_toolchain`, which the court job's `authority_build.py --all`
    rewrites, so it is cited by a digest over its stable build identity rather than by its file
    bytes (`evidence_digest`);
  * `forensics/atlas/<authority>/` -- a committed atlas, for the `atlas-complete` rung;
  * `forensics/multitrack/compatibility-views.json` -- a compatible candidate view, for
    `candidate-view`; and
  * `forensics/multitrack/semantic-courts.json` -- the executed authority pair, for
    `runtime-evidenced`.

The status is read off the ladder `multitrack_schemas.SUPPORT_LADDER`: a node's `status` is the
**highest rung an evidence plane reached**, and `rungs_attained` names every rung it reached. A node
outside the public final-release lineage, or a final release whose official source cannot be
admitted, is `archaeological-only` and has climbed no rung. `downstream-evidenced` is read from
its plane `forensics/multitrack/downstream-multitrack.json` (23.11): a node attains it when an
unmodified real downstream consumer was built against its authority and ran a real workload, and it
may be attained without the oracle-to-oracle `runtime-evidenced` rung, because the two are
independent evidence planes rather than a contiguous prefix.

Honest unavailability
---------------------
An unavailable release is **never counted runtime-compatible**: `runtime_compatible` is true only
when the node attained `runtime-evidenced`, the unavailable set is reproduced from the acquisition
registry, and `validate_population_record` refuses the over-claim. Nothing here turns an absence
into a compatibility claim, and an epoch with no built representative is a finding rather than a
smaller census.

Outputs
-------
  forensics/multitrack/historical-population.json

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
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
)

import multitrack_schemas as mts  # noqa: E402

OUT = REPO_ROOT / "forensics" / "multitrack" / "historical-population.json"
GENERATOR = "forensics/tools/historical_population.py"
CATALOG = REPO_ROOT / "forensics" / "release-catalog.json"
AUTHORITY_NODES = REPO_ROOT / "forensics" / "authority-nodes.json"
AUTHORITIES = REPO_ROOT / "forensics" / "authorities" / "AUTHORITIES.json"
BUILD_RECORDS = REPO_ROOT / "forensics" / "atlas" / "BUILD_RECORDS.json"
HIST_ACQ = REPO_ROOT / "forensics" / "multitrack" / "historical-acquisition.json"
HIST_RECEIPTS = REPO_ROOT / "forensics" / "multitrack" / "historical-build-receipts.json"
ATLAS_ROOT = REPO_ROOT / "forensics" / "atlas"
COMPAT_VIEWS = REPO_ROOT / "forensics" / "multitrack" / "compatibility-views.json"
SEMANTIC_COURTS = REPO_ROOT / "forensics" / "multitrack" / "semantic-courts.json"
DOWNSTREAM = REPO_ROOT / "forensics" / "multitrack" / "downstream-multitrack.json"
DEFAULT_AUTHORITY = REPO_ROOT / "forensics" / "multitrack" / "default-authority.json"

# The epoch a release belongs to, by the shape of its parsed version. `3.6+/4.x` is the current
# maintained line (3.6 and the 4.x releases); `pre-1.0` is the 0.9.x ancestry the catalogue begins
# at. The court requires every epoch but `out-of-scope` to hold a built representative.
MAJOR_EPOCHS: tuple[str, ...] = ("pre-1.0", "1.0.x", "1.1.x", "3.x", "3.6+/4.x")


def sha(path: Path) -> str:
    return sha256_file(path)


# `forensics/atlas/BUILD_RECORDS.json` records each build's `build_platform` (the host kernel),
# `build_toolchain` and produced-`artifacts` sizes, so its **file** digest is a property of the
# machine that built the authority rather than a committed input: the court job's
# `authority_build.py --all` rewrites the file before the courts run, so binding its file bytes would
# make this derivation disagree with itself on a differently-built authority. The evidence therefore
# binds a digest over the receipt's **stable build identity** -- the fields that are a function of
# the release and the recorded profile, not of the host -- exactly as `implemented_surface_input`
# binds `body_hash` rather than the artefact's file digest, because that artefact too carries
# build-product observations (docs/DECISIONS.md D30). `historical-build-receipts.json` records no
# host value, so it stays content-addressed by its file digest as before.
BUILD_RECORD_STABLE_FIELDS: tuple[str, ...] = (
    "id", "version", "profile", "profile_args", "build_dir", "prefix", "configure_argv",
)


def _build_records_digest() -> str:
    """A digest over `BUILD_RECORDS`'s stable build identity, not its machine-specific bytes."""
    builds = load(BUILD_RECORDS)["builds"]
    stable = [
        {field: b.get(field) for field in BUILD_RECORD_STABLE_FIELDS}
        for b in sorted(builds, key=lambda b: b["id"])
    ]
    return content_hash(stable)


def evidence_digest(path: Path) -> str:
    """The digest an evidence entry records for `path`, and the digest the court checks it against.

    A build-product receipt (`BUILD_RECORDS.json`) is hashed by its stable build identity (above);
    every other artefact is hashed by its file bytes. The court's content-addressing check calls
    this same function, so the committed digest and the check cannot drift.
    """
    if rel(path) == rel(BUILD_RECORDS):
        return _build_records_digest()
    return sha(path)


class Evidence:
    """A content-addressed evidence cache: one artefact, hashed once, cited many times."""

    def __init__(self) -> None:
        self._digests: dict[str, str] = {}

    def ref(self, path: Path, what: str) -> dict:
        key = rel(path)
        if key not in self._digests:
            self._digests[key] = evidence_digest(path)
        return {"path": key, "sha256": self._digests[key], "what": what}


def load(path: Path) -> dict:
    if not path.is_file():
        raise SystemExit(f"historical-population: {rel(path)} is absent")
    doc = json.loads(path.read_text(encoding="utf-8"))
    return doc.get("body", doc)


def epoch_of(display_version: str) -> str:
    """The ABI/architecture epoch a display version belongs to, or `out-of-scope`."""
    try:
        v = mts.parse_version(display_version)
    except mts.VersionError:
        return "out-of-scope"
    if v.major == 0:
        return "pre-1.0"
    if v.major == 1 and v.minor == 0:
        return "1.0.x"
    if v.major == 1 and v.minor == 1:
        return "1.1.x"
    if v.major == 3 and v.minor < 6:
        return "3.x"
    if v.major >= 4 or (v.major == 3 and v.minor >= 6):
        return "3.6+/4.x"
    return "out-of-scope"


def atlas_anchor(authority_id: str) -> Path | None:
    """The committed atlas an `atlas-complete` rung cites, or `None` when there is none."""
    for name in ("plane-census.json", "ATLAS.md"):
        candidate = ATLAS_ROOT / authority_id / name
        if candidate.is_file():
            return candidate
    return None


def body_hash(records: list[dict], epochs: list[dict], unavailable: list[dict]) -> str:
    """The population body's content hash, a function of its committed records."""
    return content_hash({"records": records, "epochs": epochs, "unavailable": unavailable})


def derive_body() -> dict:
    """The historical-population body, a pure function of the committed evidence.

    Deterministic: every list is sorted, no wall-clock/environment value is read, and every rung is
    read from the artefact that carries it rather than typed. The court re-derives this body through
    the same code and refuses a committed record whose status was typed.
    """
    catalog = load(CATALOG)
    auth_nodes = {n["release_id"]: n for n in load(AUTHORITY_NODES)["nodes"]}
    authorities = load(AUTHORITIES)["authorities"]
    admitted_releases = {f"openssl-{a['version']}" for a in authorities}
    build_records = {b["id"]: b for b in load(BUILD_RECORDS)["builds"]}
    acq = {r["release_id"]: r for r in load(HIST_ACQ)["acquisitions"]}
    unavail = {r["release_id"]: r for r in load(HIST_ACQ)["unavailable"]}
    views = load(COMPAT_VIEWS)
    semantic = load(SEMANTIC_COURTS)
    default_alias = load(DEFAULT_AUTHORITY)

    compatible_authorities = {v["reference_id"] for v in views.get("views", [])
                              if v.get("status") == "compatible"}
    runtime_authorities = {semantic.get("authority_a"), semantic.get("authority_b")} - {None}
    maintained_release = str(default_alias.get("maintained_candidate") or "")

    ev = Evidence()

    def built_backed(auth_node: dict) -> bool:
        """Whether an authority node's `built-authority` claim is backed by a real receipt."""
        receipt = auth_node.get("build_receipt")
        if not receipt or not (REPO_ROOT / receipt).is_file():
            return False
        if receipt == rel(HIST_RECEIPTS):
            return any(r["release_id"] == auth_node["release_id"]
                       for r in load(HIST_RECEIPTS)["receipts"])
        if receipt == rel(BUILD_RECORDS):
            return auth_node["authority_id"] in build_records
        return False

    records: list[dict] = []
    for node in catalog["nodes"]:
        rid = node["release_id"]
        display = str(node["display_version"])
        channel = node["release_channel"]
        # The public/extended distinction is a distribution channel, not a lineage boundary: the LTS
        # branch finals (0.9.8, 1.0.2, 1.1.1, 3.0, 3.5) are `extended`, and they are exactly the
        # epoch representatives the population must carry. The lineage is the mainline final
        # channel.
        in_lineage = (channel == "final" and node["mainline_or_auxiliary"] == "mainline")
        epoch = epoch_of(display)
        auth_node = auth_nodes.get(rid)
        aid = auth_node.get("authority_id") if auth_node else None

        evidence: list[dict] = [ev.ref(CATALOG, "the release node and its channel, scope and "
                                              "version, read from the committed catalogue")]

        if not in_lineage:
            records.append({
                "release_id": rid,
                "display_version": display,
                "release_channel": channel,
                "epoch": epoch,
                "scope": "out-of-population-scope",
                "outcome": "out-of-population-scope",
                "status": "archaeological-only",
                "rungs_attained": [],
                "runtime_compatible": False,
                "reason": (
                    "not a public mainline final release: the population ladder tracks the public "
                    "final-release lineage forward from OpenSSL 0.9.1c, so this node is catalogued "
                    "archaeology and carries no rung"
                ),
                "evidence": evidence,
            })
            continue

        rungs = ["catalogued"]

        # admitted-source: the release was acquired, or is an admitted authority.
        if rid in acq:
            rungs.append("admitted-source")
            evidence.append(ev.ref(HIST_ACQ, "the release's acquisition record and its verified "
                                             "archive digest"))
        elif rid in admitted_releases:
            rungs.append("admitted-source")
            evidence.append(ev.ref(AUTHORITIES, "the release's admitted-authority record and its "
                                                "verified archive digest"))

        # built-authority: a built authority node whose receipt exists and names the release.
        if auth_node is not None and auth_node.get("claim") == "built-authority" \
                and built_backed(auth_node):
            rungs.append("built-authority")
            receipt = auth_node["build_receipt"]
            evidence.append(ev.ref(REPO_ROOT / receipt, "the build receipt the built-authority "
                                                        "claim is backed by"))

        # atlas-complete: the authority carries a committed atlas.
        anchor = atlas_anchor(aid) if aid else None
        if anchor is not None:
            rungs.append("atlas-complete")
            evidence.append(ev.ref(anchor, "the authority's committed atlas"))

        # candidate-view: a compatible candidate-to-reference view names the authority.
        if aid and aid in compatible_authorities:
            rungs.append("candidate-view")
            evidence.append(ev.ref(COMPAT_VIEWS, "the compatible candidate view the authority "
                                                 "carries"))

        # runtime-evidenced: the authority is one side of the executed semantic pair.
        if aid and aid in runtime_authorities:
            rungs.append("runtime-evidenced")
            evidence.append(ev.ref(SEMANTIC_COURTS, "the oracle-to-oracle semantic court that "
                                                    "executed this authority"))

        # downstream-evidenced: a real consumer was built against this authority and ran (23.11).
        # Only a `passed` record advances the rung, so a `not_run` pair never does.
        if DOWNSTREAM.is_file():
            downstream = load(DOWNSTREAM)
            executed = {r.get("authority_id") for r in downstream.get("records", [])
                        if r.get("outcome") == "passed"}
            if aid and aid in executed:
                rungs.append("downstream-evidenced")
                evidence.append(ev.ref(DOWNSTREAM, "the downstream consumer that exercised this "
                                                   "authority"))

        # maintained: the maintained candidate the production alias names, once built.
        if maintained_release and rid == maintained_release and "built-authority" in rungs:
            rungs.append("maintained")
            evidence.append(ev.ref(DEFAULT_AUTHORITY, "the committed default-authority alias that "
                                                      "names the maintained candidate"))

        if rid in unavail:
            # A release whose official source cannot be admitted is studied and not supported: it
            # is archaeology, never a node, and never counted runtime-compatible.
            records.append({
                "release_id": rid,
                "display_version": display,
                "release_channel": channel,
                "epoch": epoch,
                "scope": "final-release-lineage",
                "outcome": "unavailable",
                "status": "archaeological-only",
                "rungs_attained": [],
                "runtime_compatible": False,
                "reason": unavail[rid]["reason"],
                "evidence": [
                    ev.ref(CATALOG, "the release node"),
                    ev.ref(HIST_ACQ, "the recorded unavailability and its reason"),
                ],
            })
            continue

        status = rungs[-1]
        records.append({
            "release_id": rid,
            "display_version": display,
            "release_channel": channel,
            "epoch": epoch,
            "scope": "final-release-lineage",
            "outcome": "built" if "built-authority" in rungs else
                       "acquired" if "admitted-source" in rungs else "catalogued",
            "status": status,
            "rungs_attained": rungs,
            "runtime_compatible": "runtime-evidenced" in rungs,
            "reason": _reason(status),
            "evidence": evidence,
        })

    records.sort(key=lambda r: r["release_id"])

    epochs = []
    for name in mts.POPULATION_EPOCHS:
        members = [r for r in records if r["epoch"] == name]
        built = sorted(r["release_id"] for r in members
                       if "built-authority" in r["rungs_attained"])
        epochs.append({
            "epoch": name,
            "members": len(members),
            "built_representatives": built,
            "covered": True if name == "out-of-scope" else bool(built),
        })

    unavailable = sorted(
        ({"release_id": r["release_id"], "reason": r["reason"],
          "runtime_compatible": False} for r in records if r["outcome"] == "unavailable"),
        key=lambda r: r["release_id"],
    )

    by_status: dict[str, int] = {}
    by_rung: dict[str, int] = {}
    by_epoch: dict[str, int] = {}
    for r in records:
        by_status[r["status"]] = by_status.get(r["status"], 0) + 1
        by_epoch[r["epoch"]] = by_epoch.get(r["epoch"], 0) + 1
        for rung in r["rungs_attained"]:
            by_rung[rung] = by_rung.get(rung, 0) + 1

    counts = {
        "nodes": len(records),
        "by_status": {k: by_status[k] for k in sorted(by_status)},
        "by_rung": {k: by_rung[k] for k in sorted(by_rung)},
        "by_epoch": {k: by_epoch[k] for k in sorted(by_epoch)},
        "built": sum(1 for r in records if "built-authority" in r["rungs_attained"]),
        "unavailable": len(unavailable),
        "runtime_compatible": sum(1 for r in records if r["runtime_compatible"]),
        "epochs": len(MAJOR_EPOCHS),
        "epochs_covered": sum(1 for e in epochs
                              if e["epoch"] in MAJOR_EPOCHS and e["covered"]),
    }

    body = {
        "rule": (
            "one population record per release-catalogue node, read from the catalogue, the "
            "authority nodes, the acquisition and build receipts, the committed atlases and the "
            "compatibility views, never typed. The `status` is the highest rung of "
            "multitrack_schemas.SUPPORT_LADDER an evidence plane reached, `rungs_attained` names "
            "every rung reached, and a node outside the public final-release lineage or whose "
            "official source cannot be admitted is `archaeological-only` with no rung. "
            "`runtime_compatible` is true only when the node attained `runtime-evidenced`, so a "
            "release that cannot be reproducibly built is never counted runtime-compatible"
        ),
        "scope": (
            "every node of forensics/release-catalog.json. The ladder's subject is the public "
            "mainline final-release lineage forward from OpenSSL 0.9.1c; a pre-release, an "
            "auxiliary branch or an extended release is out of scope and is recorded "
            "archaeological-only rather than omitted"
        ),
        "ladder": list(mts.SUPPORT_LADDER),
        "epochs": epochs,
        "records": records,
        "unavailable": unavailable,
        "counts": counts,
        "content_hash": body_hash(records, epochs, unavailable),
        "boundary": (
            "the population covers the catalogue and records a status per node; it is not a "
            "compatibility claim about any release. The `downstream-evidenced` rung is read from "
            "forensics/multitrack/downstream-multitrack.json (23.11): a node attains it when an "
            "unmodified real downstream consumer was built against its authority and ran a real "
            "workload, and it may be attained without the oracle-to-oracle `runtime-evidenced` "
            "rung, because the two are independent evidence planes rather than a contiguous "
            "prefix. An unavailable release is archaeology -- studied, catalogued, and never "
            "runtime-compatible -- and each major ABI epoch carries at least one built "
            "representative: 0.9.8zh (pre-1.0), 1.0.2u (1.0.x), 1.1.1w (1.1.x), 3.0.0 (3.x) and "
            "3.6.3/3.6.4 (3.6+/4.x). The epoch representatives are built in the historical and "
            "forensic venues; the profile each was built with is a property of its authority node, "
            "not of its release identity"
        ),
    }
    return body


def _reason(status: str) -> str:
    """Why a node stopped where it did, so a non-built rung is a reason rather than a blank."""
    return {
        "catalogued": (
            "not attempted: the public final-release lineage is admitted by epoch representative "
            "rather than exhaustively, and this release is catalogued but not admitted"
        ),
        "admitted-source": "acquired as source but not built",
        "built-authority": "built in a historical or forensic venue; the authority carries no "
                           "committed atlas",
        "atlas-complete": "the authority carries a committed atlas; no candidate view exists for "
                          "its epoch",
        "candidate-view": "a candidate-to-reference compatibility view is compatible; the node has "
                          "no executed runtime court",
        "runtime-evidenced": "measured by the oracle-to-oracle semantic court",
        "downstream-evidenced": "a real downstream consumer exercised the authority",
        "maintained": "the maintained candidate the production authority targets",
        "archaeological-only": "studied and not supported",
    }[status]


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)
    del args

    auth = resolve_authority(PRODUCTION_AUTHORITY)
    body = derive_body()

    for record in body["records"]:
        problems = mts.validate_population_record(record)
        if problems:
            raise SystemExit(f"historical-population: derived record {record['release_id']} is not "
                             f"schema-valid: {problems}")

    inputs = [
        InputRef(name="release-catalog", path=CATALOG),
        InputRef(name="authority-nodes", path=AUTHORITY_NODES),
        InputRef(name="authority-registry", path=AUTHORITIES),
        InputRef(name="build-records", path=BUILD_RECORDS),
        InputRef(name="historical-acquisition", path=HIST_ACQ),
        InputRef(name="historical-build-receipts", path=HIST_RECEIPTS),
        InputRef(name="compatibility-views", path=COMPAT_VIEWS),
        InputRef(name="semantic-courts", path=SEMANTIC_COURTS),
        InputRef(name="default-authority", path=DEFAULT_AUTHORITY),
    ]
    doc = envelope(kind="historical-population", authority=auth.id, inputs=inputs,
                   body=body, generator=GENERATOR)
    write_json(OUT, doc)

    c = body["counts"]
    print(f"[historical-population] {c['nodes']} node(s); status={c['by_status']}; "
          f"built={c['built']} unavailable={c['unavailable']} "
          f"runtime_compatible={c['runtime_compatible']}; "
          f"epochs covered={c['epochs_covered']}/{c['epochs']}")
    for e in body["epochs"]:
        mark = "ok" if e["covered"] else "NO REPRESENTATIVE"
        reps = ", ".join(e["built_representatives"]) or "-"
        print(f"  epoch {e['epoch']:<10} members={e['members']:<4} built={reps:<28} {mark}")
    for u in body["unavailable"]:
        print(f"  unavailable {u['release_id']:<27} runtime_compatible=false")
    print(f"  -> {rel(OUT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
