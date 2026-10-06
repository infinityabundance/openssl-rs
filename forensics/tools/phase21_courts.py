#!/usr/bin/env python3
"""openssl-rs — Phase 21 courts: the maintenance delta machinery courts.

Each court is an instrument that makes the delta procedure of `docs/RELEASE_GATES.md` section 8
mechanical over two authorities that are already admitted, not a differential probe over a symbol
set. This stratum owns no exported symbol: it re-measures the implementation the strata before it
completed, so its evidence is about *the delta* — the identity and profile of the two authorities,
the added / removed / changed obligations between them across the atlas planes, the disposition of
every delta row, the courts the delta reaches, and what the stratum explicitly does not claim. The
method is Phases 3 through 20's where an artefact carries the expectation: each court reads the
artefact that holds its subject rather than typing the expectation beside it, so the two cannot
disagree, and a court whose control is not honest is `fail` rather than `pass`.

`RT-AUTHORITY-ADMISSION`, and what it admits
-------------------------------------------
21.1's court. Its subject is the **delta input pair**: the two authorities a maintenance delta runs
between, whose identity and build profile must be established *before* any movement is computed. It
stages no probe — this stratum owns no exported symbol — and reads the committed records that carry
the identities rather than typing a version, a checksum or a root hash:

  * `forensics/authorities/AUTHORITIES.json`, the admitted authority set;
  * the two `forensics/authorities/SOURCE_MANIFEST.{3.6.3,3.6.4}.json` source identities;
  * `forensics/atlas/BUILD_RECORDS.json`, the build profile each authority was built with; and
  * `forensics/atlas/differential/openssl-3.6.3-historical-vs-openssl-3.6.4-production.json`,
    whose `from_authority` / `to_authority` name the pair and whose direction `docs/
    SECURITY_DIVERGENCE_POLICY.md` section 1 fixes (historical -> production, never the reverse).

For each authority in the pair it records `{id, role, version, profile, manifest, checksum,
admitted}` plus the manifest root hash that binds the identity, read from those artefacts rather
than typed. It **fails** the stratum when an authority is named as a delta input but is not
admitted, or when its identity disagrees between `AUTHORITIES.json` and its source manifest: a
manifest whose file count, byte count, root hash or per-file digests do not reproduce the
registry's record, an artifact whose checksum is not the published one, or a manifest name that
does not carry the registry's version. `docs/AUTHORITY_POLICY.md` sections 1 and 3 are the
authority for the admitted set and for profile dependence.

The instrument sensitivity control
----------------------------------
Section 3.2's rule: a control that cannot fail is not evidence. Beside the real admission the court
derives two **synthetic views** and requires the admission to detect each — a differential that
names an authority no registry admits, and a manifest whose root hash has drifted from the
registry's. The control is honest only when the real pair yields **zero findings** (specificity)
*and* both injections are caught; otherwise a court that cannot tell an admitted authority from an
unadmitted one, or an identity from its forgery, would pass vacuously.

`RT-ATLAS-DELTA`, and what it compares
--------------------------------------
21.2's court. Its subject is the **movement between the two authorities**, computed across the
atlas planes `docs/PHASE-21-SUBPHASES.md` section 2 names:

  * **exports** — the per-authority symbol atlases (`symbols-libcrypto.json`, `symbols-libssl.json`)
    and the declared-surface planes (`functions`, `typedefs`, `structs`, `enums`, `variables`,
    `macros`), read from `forensics/atlas/openssl-3.6.3-historical` and
    `forensics/atlas/openssl-3.6.4-production` and keyed exactly as
    `forensics/tools/atlas_differential.py` keys them. **Measured**: it is the plane whose two sides
    are both committed, and the committed differential is a second record of the same movement, so
    the court recomputes the delta and requires the two to agree.
  * **provider registration rows** — the procedure names
    `forensics/atlas/provider-algorithms.json`, the openssl-rs census of the production authority's
    provider tables. A historical counterpart is not committed and `atlas_differential.py` does not
    compare it, so the named authority-to-authority registration-row delta is **`not-measured`**
    with that reason. The differential *does* compare the per-authority `provider-inventory.json`
    (the algorithm names the built `openssl` publishes) under its own `provider_algorithms` key;
    the court measures that **adjacent** plane and records it as adjacent, never as the named one.
  * **prerequisite units** — the procedure names `forensics/prerequisites.json`, the openssl-rs
    prerequisite plane. It is a single-authority artefact with no historical counterpart and no
    committed differential tool, so the plane is **`not-measured`** with that reason.

A plane the court cannot compare is named `not-measured` with its reason rather than counted as
motionless (section 3.3). The two synthetic rows the control injects are the instrument-sensitivity
proof that the comparison can see an added and a removed row at all, and that an unchanged plane
reports no motion.

`RT-DELTA-DISPOSITION`, and what it dispositions
-----------------------------------------------
21.3's court. Its subject is the **disposition of every delta row** the atlas-delta court computed,
together with every plane and axis it recorded `not-measured`:

  * a measured `added` / `removed` / `changed` row is `implemented` **only when the candidate's own
    installed surface carries the declaration** -- verified from
    `artifacts/phase2/install/include/openssl/`, the distribution prefix the downstream consumers
    link against, and never from the authority's atlas -- and is otherwise **un-dispositioned**,
    which is a `fail` rather than a silent addition (`docs/PHASE-21-SUBPHASES.md` section 2);
  * a plane or axis `RT-ATLAS-DELTA` recorded `not-measured` -- the provider registration-row and
    prerequisite-unit planes and the declaration-body `changed` axis -- is dispositioned `boundary`:
    a recorded boundary, never counted motionless;
  * a `removed` / `changed` row whose disposition would be `implemented` re-adopts the historical
    behaviour the fixed authority moved away from, so `docs/SECURITY_DIVERGENCE_POLICY.md` section 3
    makes it a **finding, not a disposition**, and the court `fail`s rather than record it.

The instrument sensitivity control
----------------------------------
Section 3.2's rule. Beside the real disposition the court derives synthetic target lists and requires
each to react as it must: a measured row the candidate carries in no header (un-dispositioned) and a
`removed` row the candidate carries (a prohibited re-adoption) are both caught, while an `added` row
the candidate carries produces no finding. The control is honest only when the real disposition
carries **zero findings** (specificity) *and* both injections are caught *and* the benign injection
stays clean.

The pending courts
------------------
Two of the five courts the plan names are not runnable yet. `PENDING_COURTS` names each with the
subphase that lands its instrument:

  * `RT-AFFECTED-COURT-SELECTION` (21.4) — the derivation of which courts a delta touches, recorded
    with the selection derivation, so the selected courts are re-run or re-derived;
  * `MAINTENANCE-BOUNDARY-REGISTER` (21.5) — the register that records the explicit non-claims
    (OpenSSL 4.x is a new compatibility profile, a 3.x receipt is never silently reinterpreted as
    evidence for 4, only the exercised delta is claimed, unknown stays unknown), and that fails the
    stratum if a recorded boundary drifts from its evidence.

There is no version-universality claim anywhere in this stratum; a passing court is an instrument
and a bounded measurement of the movement between the two authorities it names, and the property it
names may still carry findings. `docs/NON_CLAIMS.md` and `docs/SECURITY_DIVERGENCE_POLICY.md` are
the authorities on the explicit non-claims and on the fixed direction of the trajectory.

The runner reads no obligations ledger: the ledger's contract-unit states are measured from this
registry, so the edge runs ledger -> courts and binding it back would form a digest cycle neither
artefact could reproduce. `docs/PHASE-21-SUBPHASES.md` section 4.2 is the precondition. No court is
registered in `gen_frf_courts.py`: that registry is the stratum's seal.

SPDX-License-Identifier: Apache-2.0"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    HISTORICAL_AUTHORITY,
    PRODUCTION_AUTHORITY,
    REPO_ROOT,
    InputRef,
    content_hash,
    envelope,
    rel,
    resolve_authority,
    write_json,
)

# The differential tool is imported rather than re-implemented: the court keys the per-authority
# atlases exactly as `atlas_differential.py` keys them (`SET_PLANES`) and diffs the same record
# sets, so "the planes the procedure names" cannot drift from the tool that computes them.
import atlas_differential as differential_tool  # noqa: E402

OUT = REPO_ROOT / "artifacts" / "phase21" / "COURTS.json"
GENERATOR = "forensics/tools/phase21_courts.py"
PLAN = REPO_ROOT / "docs" / "PHASE-21-SUBPHASES.md"
ATLAS = REPO_ROOT / "forensics" / "atlas"

# The committed records the authority-admission court reads. Each is content-addressed through the
# envelope's `inputs`, so the court's evidence binds the exact bytes it read.
AUTHORITIES = REPO_ROOT / "forensics" / "authorities" / "AUTHORITIES.json"
BUILD_RECORDS = REPO_ROOT / "forensics" / "atlas" / "BUILD_RECORDS.json"
AUTHORITY_POLICY_DOC = REPO_ROOT / "docs" / "AUTHORITY_POLICY.md"
SECURITY_POLICY_DOC = REPO_ROOT / "docs" / "SECURITY_DIVERGENCE_POLICY.md"
# The pair's differential, located by the two authorities `atlas_common` names. The court reads the
# pair *identity* from it (`from_authority` / `to_authority`), never the movement, which is 21.2's
# subject.
DIFFERENTIAL = (
    REPO_ROOT / "forensics" / "atlas" / "differential"
    / f"{HISTORICAL_AUTHORITY}-vs-{PRODUCTION_AUTHORITY}.json"
)

# The source-manifest root-hash algorithm `forensics/tools/authority_acquire.py` writes: SHA-256
# over the newline-joined, path-sorted lines `<file-sha256>  <repo-relative-path>`.
ROOT_HASH_ALGORITHM = "sha256(<sha256>  <path>\\n, lexicographic)"

# The two named provider / prerequisite planes, and the differential tool's own provider plane
# (which compares the per-authority `provider-inventory.json`, a *different* artefact).
PROVIDER_CENSUS = ATLAS / "provider-algorithms.json"
PREREQUISITES = REPO_ROOT / "forensics" / "prerequisites.json"

# The synthetic rows the atlas-delta sensitivity control injects -- names no authority atlas carries,
# so their appearance in the recomputed delta is unambiguous evidence the comparison saw them.
CONTROL_ADDED_ROW = "RT-ATLAS-DELTA-SYNTHETIC-ADDED-ROW"
CONTROL_REMOVED_ROW = "RT-ATLAS-DELTA-SYNTHETIC-REMOVED-ROW"

# The candidate's installed declaration surface -- the headers `build_phase2.sh` installs under the
# distribution prefix and Phase 17's consumers link against. A delta row is `implemented` only when
# *this* surface carries the declaration, verified rather than asserted; the authority's atlas
# carrying it says the authority moved, not that the candidate followed.
INSTALL_INCLUDE = REPO_ROOT / "artifacts" / "phase2" / "install" / "include" / "openssl"

# The synthetic targets the delta-disposition sensitivity control injects: a measured row the
# candidate carries in no header (un-dispositioned), a `removed` row the candidate carries (a
# prohibited re-adoption of the historical behaviour), and an ordinary `added` row the candidate
# carries (which must produce no finding, so specificity is proven).
CONTROL_UNDISPOSITIONED_ROW = "RT-DELTA-DISPOSITION-SYNTHETIC-UNDISPOSITIONED-ROW"
CONTROL_REINTRODUCED_ROW = "RT-DELTA-DISPOSITION-SYNTHETIC-REINTRODUCED-ROW"
CONTROL_BENIGN_ADDED_ROW = "RT-DELTA-DISPOSITION-SYNTHETIC-BENIGN-ADDED-ROW"

AUTHORITY_ADMISSION = "RT-AUTHORITY-ADMISSION"
ATLAS_DELTA = "RT-ATLAS-DELTA"
DELTA_DISPOSITION = "RT-DELTA-DISPOSITION"

# The courts, in the order they land. `(name, probe filename)`, and the probe is declared in the
# same commit as the entry, so a runner that names a probe which does not exist cannot be
# committed. A court that stages no probe names `""`: `RT-AUTHORITY-ADMISSION`, `RT-ATLAS-DELTA`
# and `RT-DELTA-DISPOSITION` derive their evidence from committed records, so they have no staged
# transcript to read back.
COURTS: list[tuple[str, str]] = [
    (AUTHORITY_ADMISSION, ""),
    (ATLAS_DELTA, ""),
    (DELTA_DISPOSITION, ""),
]

# A court the plan names and this stratum cannot run yet. Each entry names the subphase that lands
# the instrument and what the court will drive, so "nothing registered" is a stated distance rather
# than a court quietly dropped.
PENDING_COURTS: dict[str, str] = {
    "RT-AFFECTED-COURT-SELECTION": (
        "21.4 lands the affected-court selection; it derives which courts a delta touches, records "
        "the selection derivation, and re-runs or re-derives exactly those courts, so a delta "
        "reaches the courts its obligations do and no more"
    ),
    "MAINTENANCE-BOUNDARY-REGISTER": (
        "21.5 lands the register; it records the explicit non-claims — OpenSSL 4.x is a new "
        "compatibility profile and a 3.x receipt is never silently reinterpreted as evidence for "
        "4, only the exercised delta is claimed, and unknown stays unknown — and checks that every "
        "recorded boundary still matches the evidence that establishes it"
    ),
}


# --------------------------------------------------------------------------------------------
# the authority-admission court: reading the pair, and proving it admissible and well-identified
# --------------------------------------------------------------------------------------------

def read_view() -> dict:
    """The committed records the admission reads, as one view.

    A *view* is the triplet of artefacts the admission is a pure function of -- the admitted
    registry, the per-authority source manifests and build records, and the pair's differential --
    so the sensitivity control can mutate a copy and re-run the same derivation without touching
    the tree.
    """
    registry = json.loads(AUTHORITIES.read_text(encoding="utf-8"))
    builds_doc = json.loads(BUILD_RECORDS.read_text(encoding="utf-8"))
    builds = {b.get("id"): b for b in builds_doc.get("builds") or []}
    manifests: dict[str, dict | None] = {}
    for rec in registry.get("authorities") or []:
        name = (rec.get("source_tree") or {}).get("manifest")
        path = AUTHORITIES.parent / str(name) if name else None
        manifests[rec.get("id")] = (
            json.loads(path.read_text(encoding="utf-8")) if path and path.is_file() else None
        )
    differential = json.loads(DIFFERENTIAL.read_text(encoding="utf-8"))
    return {
        "registry": registry,
        "builds": builds,
        "manifests": manifests,
        "differential": differential.get("body", differential),
        "differential_body_hash": differential.get("body_hash"),
    }


def recompute_root(manifest: dict) -> str:
    """The manifest's root hash recomputed from its own per-file digests.

    `forensics/tools/authority_acquire.py` walks the source tree with `sorted(root.rglob("*"))`
    and joins `<sha256>  <path>\\n` in that order, so the manifest's `files` list already carries
    the order the root hash was taken over. The entries are consumed in their recorded order and
    **not** re-sorted: `pathlib` orders by path *parts*, which differs from a lexicographic order
    of the POSIX strings (e.g. `a.b` sorts before `a/b` as strings, after as parts), so re-sorting
    would recompute a different hash. Reproducing the recorded order is what makes an *internally*
    inconsistent manifest -- one whose recorded root hash its own file rows do not reproduce -- a
    finding rather than a number the court trusts.
    """
    lines = [f"{e.get('sha256')}  {e.get('path')}\n" for e in manifest.get("files") or []]
    return hashlib.sha256("".join(lines).encode("utf-8")).hexdigest()


def authority_identity_findings(aid: str, rec: dict, view: dict) -> list[str]:
    """Every way one admitted authority's identity disagrees with its source manifest.

    The registry and the manifest are two records of the same source tree; the manifest name must
    carry the registry's version, and the manifest's file count, byte count and root hash must
    reproduce the registry's `source_tree` block. The manifest's own per-file digests must
    reproduce its recorded root hash, and the artifact checksum must be the published one.
    """
    findings: list[str] = []
    st = rec.get("source_tree") or {}
    art = rec.get("artifact") or {}
    expected_name = f"SOURCE_MANIFEST.{rec.get('version')}.json"
    if st.get("manifest") != expected_name:
        findings.append(
            f"{aid}: the registry names manifest {st.get('manifest')!r} but its version "
            f"{rec.get('version')!r} requires {expected_name!r}"
        )
    manifest = (view.get("manifests") or {}).get(aid)
    if manifest is None:
        findings.append(
            f"{aid}: source manifest {st.get('manifest')!r} is absent, so its identity cannot be "
            f"established"
        )
    else:
        if manifest.get("file_count") != st.get("file_count"):
            findings.append(
                f"{aid}: manifest file_count {manifest.get('file_count')!r} != registry "
                f"{st.get('file_count')!r}"
            )
        if manifest.get("total_bytes") != st.get("total_bytes"):
            findings.append(
                f"{aid}: manifest total_bytes {manifest.get('total_bytes')!r} != registry "
                f"{st.get('total_bytes')!r}"
            )
        if manifest.get("root_hash") != st.get("root_hash"):
            findings.append(
                f"{aid}: manifest root_hash {manifest.get('root_hash')!r} != registry "
                f"{st.get('root_hash')!r}"
            )
        recomputed = recompute_root(manifest)
        if recomputed != manifest.get("root_hash"):
            findings.append(
                f"{aid}: the manifest's per-file digests do not reproduce its root hash: "
                f"recomputed {recomputed!r} != recorded {manifest.get('root_hash')!r}"
            )
        if manifest.get("root_hash_algorithm") != ROOT_HASH_ALGORITHM:
            findings.append(
                f"{aid}: manifest root_hash_algorithm {manifest.get('root_hash_algorithm')!r} != "
                f"{ROOT_HASH_ALGORITHM!r}"
            )
    if not art.get("checksum_verified"):
        findings.append(f"{aid}: the artifact checksum is not verified")
    if art.get("sha256") != art.get("published_sha256"):
        findings.append(
            f"{aid}: artifact sha256 {art.get('sha256')!r} != published "
            f"{art.get('published_sha256')!r}"
        )
    build = (view.get("builds") or {}).get(aid)
    if not build or not build.get("profile"):
        findings.append(
            f"{aid}: no build profile is recorded in forensics/atlas/BUILD_RECORDS.json"
        )
    return findings


def admission_findings(view: dict) -> list[str]:
    """Every way the delta input pair fails to be an admitted, well-identified pair.

    A pure function of its view, so the sensitivity control mutates a copy and re-runs it without
    touching the tree. The pair is the differential's `from_authority` / `to_authority`; an
    authority it names must be admitted, and an admitted one must agree with its manifest.
    """
    registry = {a.get("id"): a for a in view.get("registry", {}).get("authorities") or []}
    dif = view.get("differential") or {}
    findings: list[str] = []
    for side, aid in (("from", dif.get("from_authority")), ("to", dif.get("to_authority"))):
        if not aid:
            findings.append(
                f"the differential names no {side} authority, so the delta input pair is not "
                f"identified"
            )
            continue
        rec = registry.get(aid)
        if rec is None:
            findings.append(
                f"delta input {side} authority {aid!r} is not admitted by "
                f"forensics/authorities/AUTHORITIES.json"
            )
            continue
        findings += authority_identity_findings(aid, rec, view)
    if not dif.get("direction"):
        findings.append("the differential records no `direction`, so the trajectory is unfixed")
    return findings


def authority_record(aid: str | None, view: dict) -> dict:
    """One authority's identity and build profile, read from the committed records.

    The keys are the admission's subject (`docs/PHASE-21-SUBPHASES.md` section 3.4): the court
    records them rather than typing a version, a checksum or a root hash. An authority the registry
    does not admit is recorded with `admitted: false` and no identity, so a failing admission still
    names the authority it refused.
    """
    registry = {a.get("id"): a for a in view.get("registry", {}).get("authorities") or []}
    rec = registry.get(aid) if aid else None
    if rec is None:
        return {"id": aid, "role": None, "version": None, "profile": None, "manifest": None,
                "checksum": None, "admitted": False, "root_hash": None}
    st = rec.get("source_tree") or {}
    art = rec.get("artifact") or {}
    build = (view.get("builds") or {}).get(aid) or {}
    return {
        "id": aid,
        "role": rec.get("role"),
        "version": rec.get("version"),
        "profile": build.get("profile"),
        "manifest": st.get("manifest"),
        "checksum": art.get("sha256"),
        "admitted": True,
        "root_hash": st.get("root_hash"),
    }


def admission_sensitivity_control(view: dict) -> dict:
    """Prove the admission can fail: inject an unadmitted authority and a drifted manifest.

    Two synthetic views are derived beside the real one -- the differential retargeted at an
    authority no registry admits, and a manifest's root hash moved off the registry's -- and each
    must be detected. The control is honest only when the real pair shows **zero findings**
    (specificity) *and* both injections are caught; otherwise a court that cannot tell an admitted
    authority from an unadmitted one, or an identity from its forgery, would pass vacuously.
    """
    base = admission_findings(view)
    specificity = not base

    unadmitted = copy.deepcopy(view)
    (unadmitted.get("differential") or {})["from_authority"] = "openssl-0.0.0-unadmitted"
    unadmitted_findings = admission_findings(unadmitted)
    caught_unadmitted = any("is not admitted" in f for f in unadmitted_findings)

    drifted = copy.deepcopy(view)
    dif = drifted.get("differential") or {}
    manifests = drifted.get("manifests") or {}
    mut_id = next(
        (aid for aid in (dif.get("to_authority"), dif.get("from_authority"))
         if aid in manifests and manifests[aid] is not None),
        None,
    )
    if mut_id is not None:
        manifests[mut_id]["root_hash"] = "0" * 64
    drifted_findings = admission_findings(drifted)
    caught_drift = any("root_hash" in f for f in drifted_findings)

    return {
        "baseline_findings": len(base),
        "injected_unadmitted_authority": "openssl-0.0.0-unadmitted",
        "injected_unadmitted_findings": len(unadmitted_findings),
        "injected_identity_authority": mut_id,
        "injected_identity_findings": len(drifted_findings),
        "specificity_holds": specificity,
        "caught_unadmitted_authority": caught_unadmitted,
        "caught_identity_drift": caught_drift,
        "honest": bool(specificity and caught_unadmitted and caught_drift),
    }


def authority_admission_court(name: str) -> dict:
    """`RT-AUTHORITY-ADMISSION`: admit the delta input pair and record its identity and profile.

    Stages no probe. It reads `forensics/authorities/AUTHORITIES.json` and the two
    `SOURCE_MANIFEST.{3.6.3,3.6.4}.json` files, the build records that carry each authority's
    profile and the differential that names the pair, records `{id, role, version, profile,
    manifest, checksum, admitted}` per authority, and fails when an authority named as a delta input
    is not admitted or its identity disagrees with its manifest. A passing admission is the pair's
    *identity*, not the delta between them: `docs/SECURITY_DIVERGENCE_POLICY.md` section 1 fixes the
    direction and `docs/AUTHORITY_POLICY.md` section 3 makes the profile part of the claim.
    """
    view = read_view()
    findings = admission_findings(view)
    control = admission_sensitivity_control(view)
    dif = view.get("differential") or {}

    problems: list[str] = []
    if not DIFFERENTIAL.is_file():
        problems.append(f"the differential {rel(DIFFERENTIAL)} is absent")
    if not AUTHORITIES.is_file():
        problems.append(f"the authority registry {rel(AUTHORITIES)} is absent")

    pair = {
        "from": authority_record(dif.get("from_authority"), view),
        "to": authority_record(dif.get("to_authority"), view),
        "identity": {
            "from_authority": dif.get("from_authority"),
            "to_authority": dif.get("to_authority"),
            "direction": dif.get("direction"),
            "differential": rel(DIFFERENTIAL),
            "differential_body_hash": view.get("differential_body_hash"),
        },
    }

    verdict = "pass" if (not findings and not problems and control["honest"]) else "fail"
    return {
        "court": name,
        "probe": "",
        "method": (
            "stages no probe: it reads the committed authority records -- "
            "forensics/authorities/AUTHORITIES.json and the two "
            "SOURCE_MANIFEST.{3.6.3,3.6.4}.json source identities -- the build records that carry "
            "each authority's profile, and the differential that names the pair, and records "
            "`{id, role, version, profile, manifest, checksum, admitted}` per authority in the "
            "delta input pair. It fails when an authority the differential names is not admitted, "
            "or when its identity disagrees between the registry and its manifest (a manifest name "
            "that does not carry the registry's version, a file count, byte count or root hash the "
            "registry does not record, per-file digests that do not reproduce the manifest root "
            "hash, or an artifact checksum that is not the published one). A synthetic view with an "
            "unadmitted authority in the pair and one with a manifest root hash drifted from the "
            "registry's are both detected (docs/PHASE-21-SUBPHASES.md section 3.2)."
        ),
        "frf_declarable": False,
        "frf_exclusion": (
            "the admission court reads committed authority records and stages no "
            "artifacts/phase21/probes/ pair, so it takes no transcript to diff and carries no FRF "
            "declaration"
        ),
        "admission_authority": rel(AUTHORITY_POLICY_DOC),
        "divergence_authority": rel(SECURITY_POLICY_DOC),
        "pair": pair,
        "findings": findings,
        "control": control,
        "problems": problems,
        "verdict": verdict,
    }


# --------------------------------------------------------------------------------------------
# the atlas-delta court: the added / removed / changed delta across the named atlas planes
# --------------------------------------------------------------------------------------------

def _records_by_key(doc: dict, keyfn) -> dict:
    """One authority atlas's records keyed as `atlas_differential.py` keys them."""
    return {keyfn(r): r for r in (doc.get("body") or {}).get("records") or []}


def read_delta_view() -> dict:
    """The two authorities' export-plane records and the committed differential, as one view.

    A *view* is the pure-function input of the delta derivation: per authority, the symbol atlases
    (`symbols-libcrypto.json`, `symbols-libssl.json`) and the declared-surface atlases
    (`functions`/`typedefs`/`structs`/`enums`/`variables`/`macros`) keyed exactly as
    `forensics/tools/atlas_differential.py` keys them -- the key functions are imported from that
    tool, not re-typed -- plus the differential that names the pair. The sensitivity control mutates
    a copy and re-runs the same derivation without touching the tree.
    """
    declarations: dict[str, dict] = {}
    for plane, fname, keyfn in differential_tool.SET_PLANES:
        sides: dict[str, dict] = {}
        for side, aid in (("from", HISTORICAL_AUTHORITY), ("to", PRODUCTION_AUTHORITY)):
            p = ATLAS / aid / fname
            sides[side] = _records_by_key(json.loads(p.read_text()), keyfn) if p.is_file() else {}
        declarations[plane] = sides
    symbols: dict[str, dict] = {}
    for lib in ("libcrypto", "libssl"):
        sides = {}
        for side, aid in (("from", HISTORICAL_AUTHORITY), ("to", PRODUCTION_AUTHORITY)):
            p = ATLAS / aid / f"symbols-{lib}.json"
            sides[side] = (
                {r.get("symbol"): r
                 for r in (json.loads(p.read_text()).get("body") or {}).get("records") or []}
                if p.is_file() else {}
            )
        symbols[lib] = sides
    differential = json.loads(DIFFERENTIAL.read_text(encoding="utf-8"))
    return {
        "declarations": declarations,
        "symbols": symbols,
        "differential": differential.get("body", differential),
        "differential_body_hash": differential.get("body_hash"),
    }


def export_delta(view: dict) -> dict:
    """The added / removed / changed rows across the export plane, from a view.

    A pure function of its view, so the sensitivity control mutates a copy and re-runs it. The
    symbol sub-planes are set-diffed by symbol name and their `changed` axis is the DSO version the
    differential records; the declared-surface sub-planes are set-diffed by their own key (the key
    function is `atlas_differential.SET_PLANES`'s). The committed differential compares declaration
    *membership* by key and not declaration bodies, so a declaration whose body changed without its
    name changing is not detected: that axis is recorded `not-measured` rather than asserted zero.
    """
    added: list[dict] = []
    removed: list[dict] = []
    changed: list[dict] = []
    subplanes: dict[str, dict] = {}
    for lib, sides in sorted((view.get("symbols") or {}).items()):
        oa, ob = sides.get("from") or {}, sides.get("to") or {}
        a, r = sorted(set(ob) - set(oa)), sorted(set(oa) - set(ob))
        c = sorted(
            s for s in (set(oa) & set(ob))
            if (oa[s].get("dso") or {}).get("version") != (ob[s].get("dso") or {}).get("version")
        )
        subplanes[f"symbols.{lib}"] = {
            "added": a, "removed": r, "changed": c, "changed_measured": True,
            "from_count": len(oa), "to_count": len(ob),
        }
        added += [{"plane": f"symbols.{lib}", "kind": "symbol", "key": s} for s in a]
        removed += [{"plane": f"symbols.{lib}", "kind": "symbol", "key": s} for s in r]
        changed += [
            {"plane": f"symbols.{lib}", "kind": "symbol", "key": s,
             "from": (oa[s].get("dso") or {}).get("version"),
             "to": (ob[s].get("dso") or {}).get("version")}
            for s in c
        ]
    for plane, sides in sorted((view.get("declarations") or {}).items()):
        oa, ob = sides.get("from") or {}, sides.get("to") or {}
        a, r = sorted(set(ob) - set(oa)), sorted(set(oa) - set(ob))
        subplanes[f"declarations.{plane}"] = {
            "added": a, "removed": r, "changed": None, "changed_measured": False,
            "from_count": len(oa), "to_count": len(ob),
        }
        added += [{"plane": f"declarations.{plane}", "kind": "declaration", "key": s} for s in a]
        removed += [{"plane": f"declarations.{plane}", "kind": "declaration", "key": s} for s in r]
    return {
        "added": added,
        "removed": removed,
        "changed": changed,
        "counts": {"added": len(added), "removed": len(removed), "changed": len(changed)},
        "subplanes": subplanes,
    }


def atlas_delta_findings(view: dict, recomputed: dict) -> list[str]:
    """Every way the committed differential and the per-authority atlases disagree.

    The delta is recomputed from the per-authority atlases, and the committed differential is a
    second record of the same movement; a differential that no longer matches its authorities is a
    `fail`, not a number the court trusts (`docs/PHASE-21-SUBPHASES.md` section 3.4). The
    differential's own `body_hash` is recomputed for the same reason.
    """
    findings: list[str] = []
    body = view.get("differential") or {}
    recorded_hash = view.get("differential_body_hash")
    if recorded_hash and content_hash(body) != recorded_hash:
        findings.append(
            f"the differential's recorded body_hash {recorded_hash!r} does not reproduce its body"
        )
    planes = body.get("planes") or {}
    for plane, _fname, _keyfn in differential_tool.SET_PLANES:
        dp = planes.get(plane)
        if not isinstance(dp, dict):
            findings.append(f"the differential records no `{plane}` declared-surface plane")
            continue
        sub = (recomputed.get("subplanes") or {}).get(f"declarations.{plane}") or {}
        for axis in ("added", "removed"):
            committed = sorted(dp.get(f"{axis}_in_to") or [])
            fresh = sorted(sub.get(axis) or [])
            if committed != fresh:
                findings.append(
                    f"declarations.{plane}.{axis}: the committed differential records "
                    f"{committed!r} but the per-authority atlases yield {fresh!r}"
                )
    for lib in ("libcrypto", "libssl"):
        dp = (planes.get("symbols") or {}).get(lib)
        if not isinstance(dp, dict):
            findings.append(f"the differential records no `symbols.{lib}` plane")
            continue
        sub = (recomputed.get("subplanes") or {}).get(f"symbols.{lib}") or {}
        for axis in ("added", "removed"):
            committed = sorted(dp.get(f"{axis}_in_to") or [])
            fresh = sorted(sub.get(axis) or [])
            if committed != fresh:
                findings.append(
                    f"symbols.{lib}.{axis}: the committed differential records {committed!r} but "
                    f"the per-authority atlases yield {fresh!r}"
                )
        committed_changed = sorted(c.get("symbol") for c in dp.get("version_changed") or [])
        if committed_changed != sorted(sub.get("changed") or []):
            findings.append(
                f"symbols.{lib}.changed: the committed differential records {committed_changed!r} "
                f"but the per-authority atlases yield {sorted(sub.get('changed') or [])!r}"
            )
    return findings


def _provider_classes(aid: str) -> dict:
    p = ATLAS / aid / "provider-inventory.json"
    if not p.is_file():
        return {}
    return (json.loads(p.read_text()).get("body") or {}).get("algorithm_classes") or {}


def _provider_entry_names(info: dict, cls: str) -> set[str]:
    """The entry names of one provider class, exactly as `atlas_differential.plane_providers` reads."""
    entries = info.get("entries") or []
    if cls == "disabled":
        return {e for e in entries if isinstance(e, str)}
    return {e["name"] for e in entries if isinstance(e, dict)}


def provider_inventory_delta() -> dict:
    """The per-authority provider *inventory* movement -- an adjacent measurement, not the named plane.

    `atlas_differential.py` compares the two authorities' `provider-inventory.json` (the algorithm
    names the built `openssl` publishes) under its own `provider_algorithms` key. That is a
    *different* artefact from the named provider registration-row census
    `forensics/atlas/provider-algorithms.json`, which exists only for the production authority. It
    is computed so the reader sees it was measured rather than overlooked, and is recorded as
    adjacent, never as the named plane.
    """
    a, b = _provider_classes(HISTORICAL_AUTHORITY), _provider_classes(PRODUCTION_AUTHORITY)
    classes: dict[str, dict] = {}
    added = removed = 0
    for cls in sorted(set(a) | set(b)):
        ea = _provider_entry_names(a.get(cls) or {}, cls)
        eb = _provider_entry_names(b.get(cls) or {}, cls)
        if ea != eb:
            classes[cls] = {"added": sorted(eb - ea), "removed": sorted(ea - eb)}
            added += len(eb - ea)
            removed += len(ea - eb)
    return {"added": added, "removed": removed, "classes": classes}


def prerequisite_shape() -> dict:
    """The named prerequisite plane's shape, read for context -- it is not a delta."""
    if not PREREQUISITES.is_file():
        return {"units": None, "deferrals": None, "divergences": None}
    body = (json.loads(PREREQUISITES.read_text()).get("body") or {})
    return {
        "units": len(body.get("units") or []),
        "deferrals": len(body.get("deferrals") or []),
        "divergences": len(body.get("divergences") or []),
    }


def atlas_delta_sensitivity_control(view: dict, recomputed: dict) -> dict:
    """Prove the atlas delta can fail: inject an added and a removed row, require both caught.

    Two synthetic views are derived beside the real one -- a declaration the `to` authority carries
    and the `from` authority does not, and one the `from` authority carries and the `to` does not --
    and the recomputed delta must report the first as `added` and the second as `removed`. The
    control is honest only when the real derivation carries neither synthetic row (specificity),
    both injections are caught, and the unchanged plane (the symbol sub-plane, which neither
    injection touches) reports **no** motion; otherwise a court that cannot see an added or a removed
    row would pass vacuously.
    """
    caught_added_view = copy.deepcopy(view)
    caught_added_view["declarations"]["macros"]["to"][CONTROL_ADDED_ROW] = {"name": CONTROL_ADDED_ROW}
    added_delta = export_delta(caught_added_view)
    caught_added = any(r["key"] == CONTROL_ADDED_ROW for r in added_delta["added"])

    caught_removed_view = copy.deepcopy(view)
    caught_removed_view["declarations"]["functions"]["from"][CONTROL_REMOVED_ROW] = {
        "name": CONTROL_REMOVED_ROW
    }
    removed_delta = export_delta(caught_removed_view)
    caught_removed = any(r["key"] == CONTROL_REMOVED_ROW for r in removed_delta["removed"])

    synthetic = {CONTROL_ADDED_ROW, CONTROL_REMOVED_ROW}
    honest_clean = not any(
        r["key"] in synthetic for r in (recomputed["added"] + recomputed["removed"])
    )
    # The unchanged plane: neither injection touches the symbol sub-planes, so a comparison that
    # reports motion there has lost specificity.
    unchanged_plane_clean = not (
        [r for r in added_delta["added"] if r["plane"].startswith("symbols.")]
        or [r for r in removed_delta["removed"] if r["plane"].startswith("symbols.")]
    )
    specificity = honest_clean and unchanged_plane_clean
    return {
        "baseline_counts": recomputed["counts"],
        "injected_added_row": CONTROL_ADDED_ROW,
        "injected_added_counts": added_delta["counts"],
        "injected_removed_row": CONTROL_REMOVED_ROW,
        "injected_removed_counts": removed_delta["counts"],
        "caught_added": bool(caught_added),
        "caught_removed": bool(caught_removed),
        "specificity_holds": bool(specificity),
        "honest": bool(caught_added and caught_removed and specificity),
    }


def atlas_delta_court(name: str) -> dict:
    """`RT-ATLAS-DELTA`: the added / removed / changed delta across the named atlas planes.

    Stages no probe. It recomputes the export-plane delta from the per-authority symbol and
    declared-surface atlases and requires the committed differential to agree; it names the provider
    registration-row and prerequisite-unit planes `not-measured` with their reasons rather than
    counting them motionless; and it records the adjacent provider-inventory measurement beside the
    named provider plane so nothing measured is hidden and nothing unmeasured is counted.
    """
    view = read_delta_view()
    recomputed = export_delta(view)
    findings = atlas_delta_findings(view, recomputed)
    control = atlas_delta_sensitivity_control(view, recomputed)
    adjacent = provider_inventory_delta()

    problems: list[str] = []
    for p in (DIFFERENTIAL, PROVIDER_CENSUS, PREREQUISITES):
        if not p.is_file():
            problems.append(f"{rel(p)} is absent, so its plane cannot be named")
    for aid in (HISTORICAL_AUTHORITY, PRODUCTION_AUTHORITY):
        for fname in ("symbols-libcrypto.json", "symbols-libssl.json",
                      *[f for _p, f, _k in differential_tool.SET_PLANES]):
            if not (ATLAS / aid / fname).is_file():
                problems.append(f"forensics/atlas/{aid}/{fname} is absent")

    exports = {
        "plane": "exports",
        "state": "measured",
        "named_source": (
            "the per-authority symbol atlases (symbols-libcrypto.json, symbols-libssl.json) and "
            "the declared-surface planes (functions, typedefs, structs, enums, variables, macros) "
            "under forensics/atlas/openssl-3.6.3-historical and forensics/atlas/openssl-3.6.4-production"
        ),
        "sources": [
            f"forensics/atlas/{aid}/{fname}"
            for aid in (HISTORICAL_AUTHORITY, PRODUCTION_AUTHORITY)
            for fname in ("symbols-libcrypto.json", "symbols-libssl.json",
                          *[f for _p, f, _k in differential_tool.SET_PLANES])
        ],
        "added": recomputed["added"],
        "removed": recomputed["removed"],
        "changed": recomputed["changed"],
        "counts": recomputed["counts"],
        "subplanes": recomputed["subplanes"],
        "not_measured_axes": [
            {
                "axis": "declarations.*.changed",
                "reason": (
                    "the committed differential compares declared-surface membership by key and "
                    "not declaration bodies, so a declaration whose body changed without its name "
                    "changing is not detected; `changed` is measured for the ABI symbols (their DSO "
                    "version) and not for the declared declarations"
                ),
            }
        ],
    }
    provider = {
        "plane": "provider-registration-rows",
        "state": "not-measured",
        "named_source": rel(PROVIDER_CENSUS),
        "reason": (
            "the named census forensics/atlas/provider-algorithms.json is generated for the "
            "production authority only, so no committed historical counterpart exists and "
            "atlas_differential.py does not compare it; the named authority-to-authority "
            "registration-row delta therefore cannot be computed from committed data. What would be "
            "needed is a second provider-algorithms.json census generated over the historical "
            "authority's provider tables. The differential does compare the per-authority "
            "provider-inventory.json (the algorithm names the built openssl publishes) under its own "
            "provider_algorithms key, and that adjacent plane is measured below -- it is not this "
            "named plane, and the not-measured plane carries no counts"
        ),
    }
    prerequisites = {
        "plane": "prerequisite-units",
        "state": "not-measured",
        "named_source": rel(PREREQUISITES),
        "reason": (
            "the named plane forensics/prerequisites.json is a single-authority openssl-rs artefact "
            "(the prerequisite/divergence units of the implementation, not of an authority), with no "
            "committed historical counterpart and no differential tool that compares it; the "
            "authority-to-authority prerequisite-unit delta therefore cannot be computed from "
            "committed data. The named artefact's shape is recorded for context, but it is not a "
            "delta and this plane carries no counts"
        ),
        "named_source_shape": prerequisite_shape(),
    }
    planes = [exports, provider, prerequisites]

    verdict = "pass" if (not findings and not problems and control["honest"]) else "fail"
    return {
        "court": name,
        "probe": "",
        "method": (
            "stages no probe: it recomputes the added / removed / changed delta across the atlas "
            "planes docs/PHASE-21-SUBPHASES.md section 2 names, from the per-authority atlases "
            "under forensics/atlas/openssl-3.6.3-historical and forensics/atlas/openssl-3.6.4-production "
            "keyed exactly as forensics/tools/atlas_differential.py keys them, and requires the "
            "committed differential to agree with what it recomputes (a differential that no longer "
            "matches its authorities is a fail). The exports plane is measured (it is the plane whose "
            "two sides are both committed); the provider registration-row plane and the prerequisite "
            "unit plane are named `not-measured` with their reasons, because the artefacts the "
            "procedure names (forensics/atlas/provider-algorithms.json, forensics/prerequisites.json) "
            "are single-authority and no committed differential compares them -- an unmeasured plane is "
            "never counted motionless. The adjacent provider-inventory plane the differential does "
            "compare is measured and recorded as adjacent, not as the named plane. The instrument "
            "sensitivity control injects an added and a removed declaration row into a synthetic view "
            "and requires both to be caught with the unchanged symbol plane reporting no motion "
            "(docs/PHASE-21-SUBPHASES.md sections 3.2, 3.3 and 3.4)"
        ),
        "frf_declarable": False,
        "frf_exclusion": (
            "the atlas-delta court reads committed atlases and stages no artifacts/phase21/probes/ "
            "pair, so it takes no transcript to diff and carries no FRF declaration"
        ),
        "divergence_authority": rel(SECURITY_POLICY_DOC),
        "planes": planes,
        "adjacent_measurements": [
            {
                "plane": "provider-inventory",
                "note": (
                    "adjacent, NOT the named provider-registration-rows plane: the differential's "
                    "provider_algorithms key, computed from the per-authority provider-inventory.json"
                ),
                "sources": [
                    f"forensics/atlas/{aid}/provider-inventory.json"
                    for aid in (HISTORICAL_AUTHORITY, PRODUCTION_AUTHORITY)
                ],
                "added": adjacent["added"],
                "removed": adjacent["removed"],
                "changed": None,
                "classes": adjacent["classes"],
            }
        ],
        "counts": {
            "planes_named": len(planes),
            "planes_measured": sum(1 for p in planes if p["state"] == "measured"),
            "planes_not_measured": sum(1 for p in planes if p["state"] == "not-measured"),
            "added": recomputed["counts"]["added"],
            "removed": recomputed["counts"]["removed"],
            "changed": recomputed["counts"]["changed"],
        },
        "findings": findings,
        "control": control,
        "problems": problems,
        "verdict": verdict,
    }


# --------------------------------------------------------------------------------------------
# the delta-disposition court: every delta row dispositioned, with zero unexplained
# --------------------------------------------------------------------------------------------

def candidate_declaration(name: str, defined_in: list, plane: str, expected_value) -> dict:
    """Whether the candidate's **own installed surface** carries one delta declaration.

    A delta row is `implemented` only when the candidate's installed headers carry the declaration,
    not because the authority's atlas carries it (`docs/PHASE-21-SUBPHASES.md` section 3.3). The
    authority's macro/declaration atlas records `defined_in` -- the header basename under
    `include/openssl/` -- so the installed header is located beside it in the candidate's
    distribution prefix. A macro's value is compared with the authority's when both are present, so
    a declaration carried under a different value is not counted as carried. Returns
    `{carried, source, value}`; `carried` false with no source is a declaration the candidate does
    not carry at all, which makes the row un-dispositioned.
    """
    for header in defined_in or []:
        p = INSTALL_INCLUDE / header
        if not p.is_file():
            nested = sorted(INSTALL_INCLUDE.rglob(header))
            p = nested[0] if nested else p
        if not p.is_file():
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        if plane == "declarations.macros":
            m = re.search(rf"^#\s*define\s+{re.escape(name)}\s+(\S.*?)\s*$", text, re.M)
            if not m:
                continue
            value = re.split(r"/\*", m.group(1))[0].strip()
            carried = expected_value is None or value == str(expected_value)
            return {"carried": carried, "source": rel(p), "value": value}
        if re.search(rf"\b{re.escape(name)}\b", text):
            return {"carried": True, "source": rel(p), "value": None}
    return {"carried": False, "source": None, "value": None}


def delta_disposition_targets() -> list[dict]:
    """Every delta row and every `not-measured` surface, as a disposition target.

    The delta is the one `RT-ATLAS-DELTA` computed -- its own recorded planes, not a second list --
    so the two courts cannot disagree about what moved. A measured row's `carried` is read from the
    candidate's installed headers; a plane or axis recorded `not-measured` is a boundary target
    (`docs/PHASE-21-SUBPHASES.md` sections 3.3 and 4.6).
    """
    view = read_delta_view()
    delta = atlas_delta_court(ATLAS_DELTA)
    targets: list[dict] = []
    for plane in delta.get("planes") or []:
        if plane.get("state") == "measured":
            for axis in ("added", "removed", "changed"):
                for row in plane.get(axis) or []:
                    subplane = row["plane"].split(".", 1)[1]
                    sides = (view.get("declarations") or {}).get(subplane) or {}
                    rec = ((sides.get("to") or {}).get(row["key"])
                           or (sides.get("from") or {}).get(row["key"]) or {})
                    carried = candidate_declaration(
                        row["key"], rec.get("defined_in") or [], row["plane"], rec.get("value"))
                    targets.append({
                        "id": f"{row['plane']}:{axis}:{row['key']}",
                        "plane": row["plane"],
                        "kind": row["kind"],
                        "axis": axis,
                        "key": row["key"],
                        "state": "measured",
                        "carried": bool(carried["carried"]),
                        "candidate_source": carried.get("source"),
                        "candidate_value": carried.get("value"),
                        "authority_value": rec.get("value"),
                    })
            for ax in plane.get("not_measured_axes") or []:
                targets.append({
                    "id": ax["axis"],
                    "plane": plane["plane"],
                    "kind": "axis",
                    "axis": "not-measured-axis",
                    "key": ax["axis"],
                    "state": "not-measured",
                    "carried": None,
                    "reason": ax.get("reason"),
                })
        else:
            targets.append({
                "id": plane["plane"],
                "plane": plane["plane"],
                "kind": "plane",
                "axis": "not-measured-plane",
                "key": plane["plane"],
                "state": "not-measured",
                "carried": None,
                "reason": plane.get("reason"),
            })
    return targets


def derive_dispositions(targets: list[dict]) -> dict:
    """The disposition of every target, and the findings a real gap produces.

    A pure function of the target list, so the sensitivity control injects a target and re-derives.
    `implemented` is recorded only for a measured row the candidate carries; a `not-measured` plane
    or axis is recorded `boundary`. A measured row the candidate does not carry is
    **un-dispositioned** -- no value in `implemented`/`deferred`/`not-in-profile`/`boundary` is
    honest for it -- and is a finding, because every un-dispositioned delta row is a `fail`
    (`docs/PHASE-21-SUBPHASES.md` section 2). A `removed`/`changed` row the candidate carries would
    re-adopt the historical behaviour the fixed authority moved away from, so
    `docs/SECURITY_DIVERGENCE_POLICY.md` section 3 makes it a finding and not a disposition. A
    non-empty findings list is a `fail`, not a verdict the court talks itself out of.
    """
    rows: list[dict] = []
    findings: list[str] = []
    for target in targets:
        row = dict(target)
        if row["state"] == "not-measured":
            row["disposition"] = "boundary"
        elif row.get("carried"):
            row["disposition"] = "implemented"
        else:
            row["disposition"] = None
        prohibited = row["axis"] in ("removed", "changed") \
            and row["disposition"] == "implemented"
        row["prohibited"] = bool(prohibited)
        if row["disposition"] is None:
            findings.append(
                f"delta row {row['id']} is measured but the candidate's installed surface "
                f"({rel(INSTALL_INCLUDE)}) does not carry it, so it is un-dispositioned: none of "
                f"`implemented`/`deferred`/`not-in-profile`/`boundary` is honest for it, and an "
                f"un-dispositioned delta row is a `fail` rather than a silent addition "
                f"(docs/PHASE-21-SUBPHASES.md section 2, docs/PARITY_MODEL.md section 1)"
            )
        if prohibited:
            findings.append(
                f"delta row {row['id']} is on the `{row['axis']}` axis -- the trajectory "
                f"{HISTORICAL_AUTHORITY} -> {PRODUCTION_AUTHORITY} moved away from it -- but the "
                f"candidate's installed surface carries it, so dispositioning it `implemented` "
                f"would re-adopt the historical behaviour the fixed authority removed; "
                f"docs/SECURITY_DIVERGENCE_POLICY.md section 3 prohibits reintroducing a security "
                f"regression to match a historical authority, so this is a finding and not a "
                f"disposition and the court `fail`s"
            )
        rows.append(row)
    counts = {
        "targets": len(rows),
        "measured": sum(1 for r in rows if r["state"] == "measured"),
        "not_measured": sum(1 for r in rows if r["state"] == "not-measured"),
        "implemented": sum(1 for r in rows if r["disposition"] == "implemented"),
        "boundary": sum(1 for r in rows if r["disposition"] == "boundary"),
        "deferred": sum(1 for r in rows if r["disposition"] == "deferred"),
        "not_in_profile": sum(1 for r in rows if r["disposition"] == "not-in-profile"),
        "unexplained": sum(1 for r in rows if r["disposition"] is None),
        "prohibited": sum(1 for r in rows if r["prohibited"]),
        "findings": len(findings),
    }
    return {"rows": rows, "counts": counts, "findings": findings}


def delta_disposition_problems(derived: dict) -> list[str]:
    """Internal consistency of the disposition itself, distinct from its findings.

    The findings are real gaps in the delta; these are defects in the read or the derivation, which
    make the verdict `fail` on their own account rather than letting an incomplete read pass.
    """
    problems: list[str] = []
    counts = derived["counts"]
    if counts["targets"] == 0:
        problems.append(
            "the delta carries no row and no not-measured plane, so the disposition is vacuous: an "
            "empty target set is a read that measured nothing rather than a complete disposition"
        )
    accounted = (counts["implemented"] + counts["boundary"] + counts["deferred"]
                 + counts["not_in_profile"] + counts["unexplained"])
    if counts["targets"] != accounted:
        problems.append(
            f"the disposition does not account for every target: {counts['targets']} != "
            f"implemented {counts['implemented']} + boundary {counts['boundary']} + deferred "
            f"{counts['deferred']} + not-in-profile {counts['not_in_profile']} + unexplained "
            f"{counts['unexplained']}"
        )
    if not INSTALL_INCLUDE.is_dir():
        problems.append(
            f"the candidate install prefix {rel(INSTALL_INCLUDE)} is absent, so no delta row's "
            f"declaration can be verified against the candidate's own surface"
        )
    return problems


def disposition_sensitivity_control(targets: list[dict]) -> dict:
    """Prove the disposition can fail: inject an un-dispositioned and a re-adopted row.

    Three synthetic target lists are derived beside the real one -- a measured row the candidate
    carries in no header (un-dispositioned), a `removed` row the candidate carries (a prohibited
    re-adoption of the historical behaviour), and an ordinary `added` row the candidate carries --
    and each must behave as it must. The control is honest only when the real disposition carries
    zero findings (specificity), both injections are caught, and the benign injection stays clean;
    otherwise a court that cannot tell a carried row from an absent one, or a fixed-authority row
    from a re-adopted one, would pass vacuously (`docs/PHASE-21-SUBPHASES.md` section 3.2).
    """
    base = derive_dispositions(targets)
    specificity = not base["findings"]

    def synthetic(cid: str, axis: str, carried: bool) -> dict:
        return {
            "id": cid, "plane": "synthetic", "kind": "declaration", "axis": axis,
            "key": cid, "state": "measured", "carried": carried,
            "candidate_source": None, "candidate_value": None, "authority_value": None,
        }

    un = derive_dispositions(
        targets + [synthetic(CONTROL_UNDISPOSITIONED_ROW, "added", False)])
    re_adopted = derive_dispositions(
        targets + [synthetic(CONTROL_REINTRODUCED_ROW, "removed", True)])
    benign = derive_dispositions(
        targets + [synthetic(CONTROL_BENIGN_ADDED_ROW, "added", True)])

    caught_un = any("un-dispositioned" in f for f in un["findings"])
    caught_re = any("re-adopt the historical behaviour" in f for f in re_adopted["findings"])
    benign_clean = not benign["findings"]
    return {
        "baseline_targets": base["counts"]["targets"],
        "baseline_findings": len(base["findings"]),
        "baseline_unexplained": base["counts"]["unexplained"],
        "injected_un_dispositioned_row": CONTROL_UNDISPOSITIONED_ROW,
        "injected_un_dispositioned_findings": len(un["findings"]),
        "injected_reintroduced_row": CONTROL_REINTRODUCED_ROW,
        "injected_reintroduced_findings": len(re_adopted["findings"]),
        "injected_benign_added_row": CONTROL_BENIGN_ADDED_ROW,
        "injected_benign_added_findings": len(benign["findings"]),
        "caught_un_dispositioned": bool(caught_un),
        "caught_security_reintroduction": bool(caught_re),
        "specificity_holds": bool(specificity and benign_clean),
        "honest": bool(specificity and benign_clean and caught_un and caught_re),
    }


def delta_disposition_court(name: str) -> dict:
    """`RT-DELTA-DISPOSITION`: disposition every delta row, and fail on an un-dispositioned one.

    Stages no probe. It reads the delta `RT-ATLAS-DELTA` computed and the candidate's installed
    headers, dispositions every measured row (`implemented` only when the candidate carries the
    declaration) and every `not-measured` plane or axis (`boundary`), and records no value that
    would re-adopt a historical behaviour against a fixed authority. The verdict is `pass` only when
    every row is dispositioned, no row re-adopts, the arithmetic is consistent, and the control is
    honest; a real gap is a `finding` and a `fail`.
    """
    targets = delta_disposition_targets()
    derived = derive_dispositions(targets)
    control = disposition_sensitivity_control(targets)
    problems = delta_disposition_problems(derived)

    verdict = "pass" if (
        not problems and control["honest"] and not derived["findings"]
    ) else "fail"
    return {
        "court": name,
        "probe": "",
        "method": (
            "stages no probe: it dispositions every delta row RT-ATLAS-DELTA computed and every "
            "plane or axis it recorded `not-measured`, reading the delta from that court's own "
            "record rather than a second list. A measured `added`/`removed`/`changed` row is "
            "`implemented` only when the candidate's installed surface "
            "(artifacts/phase2/install/include/openssl/) carries the declaration with the "
            "authority's value -- verified, not asserted -- and is otherwise un-dispositioned, "
            "which is a fail; a `not-measured` plane or axis is dispositioned `boundary`, a "
            "recorded boundary rather than motionless. A `removed`/`changed` row the candidate "
            "carries would re-adopt the historical behaviour the fixed authority moved away from, "
            "which docs/SECURITY_DIVERGENCE_POLICY.md section 3 makes a finding and not a "
            "disposition. The instrument sensitivity control injects an un-dispositioned row and "
            "a re-adopted `removed` row and requires both caught while an ordinary carried `added` "
            "row produces no finding (docs/PHASE-21-SUBPHASES.md sections 2, 3.2 and 3.5)"
        ),
        "frf_declarable": False,
        "frf_exclusion": (
            "the delta-disposition court reads committed atlases and the candidate's installed "
            "headers and stages no artifacts/phase21/probes/ pair, so it takes no transcript to "
            "diff and carries no FRF declaration"
        ),
        "disposition_authority": [rel(SECURITY_POLICY_DOC), rel(PLAN)],
        "dispositions": derived["rows"],
        "counts": derived["counts"],
        "findings": derived["findings"],
        "control": control,
        "problems": problems,
        "verdict": verdict,
    }


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)
    del args

    auth = resolve_authority(PRODUCTION_AUTHORITY)
    work = REPO_ROOT / "court" / "phase21"
    work.mkdir(parents=True, exist_ok=True)

    records: list[dict] = []
    for name, filename in COURTS:
        # 21.1's, 21.2's and 21.3's courts stage no probe: their subjects are the pair's committed
        # identity, the movement between the two admitted authorities, and the disposition of that
        # movement, so each is computed here rather than read back from disk and no digest cycle
        # forms. This stratum owns no export, so no differential probe over a symbol set is its
        # evidence.
        if name == AUTHORITY_ADMISSION:
            records.append(authority_admission_court(name))
            continue
        if name == ATLAS_DELTA:
            records.append(atlas_delta_court(name))
            continue
        if name == DELTA_DISPOSITION:
            records.append(delta_disposition_court(name))
            continue
        src = REPO_ROOT / "courts" / "phase21" / str(filename)
        records.append({"court": name, "verdict": "fail", "stage": "probe-missing",
                        "detail": rel(src)})

    passed = sum(1 for r in records if r["verdict"] == "pass")
    failed = sum(1 for r in records if r["verdict"] == "fail")
    body = {
        "all_pass": failed == 0 and len(records) == len(COURTS),
        "authority": auth.id,
        "courts": records,
        "summary": {"total": len(records), "pass": passed, "fail": failed},
        "pending_courts": PENDING_COURTS,
        "claim": (
            "`RT-AUTHORITY-ADMISSION` is 21.1's court: it stages no probe and admits the delta's "
            "input pair, recording each authority's identity and build profile as "
            "`{id, role, version, profile, manifest, checksum, admitted}` from "
            "forensics/authorities/AUTHORITIES.json, the two SOURCE_MANIFEST.{3.6.3,3.6.4}.json "
            "source identities, the build records and the differential that names the pair — "
            "`openssl-3.6.3-historical` versus `openssl-3.6.4-production`. It fails when an "
            "authority named as a delta input is not admitted, or when its identity disagrees "
            "between the registry and its manifest, and a synthetic view with an unadmitted "
            "authority in the pair and one with a manifest root hash drifted from the registry's "
            "are both detected. It records the pair's identity, not the delta between them. "
            "`RT-ATLAS-DELTA` is 21.2's: it stages no probe and recomputes the added / removed / "
            "changed obligation delta between the two authorities across the atlas planes the "
            "procedure names, from the per-authority atlases under "
            "forensics/atlas/openssl-3.6.3-historical and forensics/atlas/openssl-3.6.4-production "
            "keyed exactly as the differential tool keys them, requiring the committed differential "
            "to agree with what it recomputes. The exports plane is measured; the provider "
            "registration-row and prerequisite-unit planes are named `not-measured` with their "
            "reasons, because the artefacts the procedure names are single-authority and no "
            "committed differential compares them — an unmeasured plane is never counted motionless. "
            "A synthetic view with an injected added and an injected removed declaration row detects "
            "both, with the unchanged symbol plane reporting no motion. `RT-DELTA-DISPOSITION` is "
            "21.3's: it dispositions every delta row against the candidate's own installed surface "
            "-- a measured row is `implemented` only when that surface carries it, a `not-measured` "
            "plane or axis is `boundary`, and a `removed`/`changed` row the candidate carries "
            "re-adopts the historical behaviour the fixed authority moved away from and is a "
            "finding -- with zero unexplained, so an un-dispositioned row is a `fail`. "
            "`RT-AFFECTED-COURT-SELECTION` is 21.4's: the derivation of which courts a delta "
            "touches, recorded with the selection derivation. `MAINTENANCE-BOUNDARY-REGISTER` is "
            "21.5's: the register of the explicit non-claims. This stratum owns no exported "
            "symbol, so no differential probe over a symbol set is its evidence: the subject is "
            "the delta between two admitted authorities, with no version-universality claim — "
            "OpenSSL 4.x is a new compatibility profile and a 3.x receipt is never silently "
            "reinterpreted as evidence for 4 — only the exercised delta claimed, and unknown left "
            "unknown. A 3.6.3 behaviour that corresponds to an upstream security fix is not "
            "reintroduced. docs/PHASE-21-SUBPHASES.md sections 1, 3 and 4 record the measurement "
            "and the courts."
        ),
    }

    view = read_view()
    manifest_inputs = [
        InputRef(name=f"source-manifest-{rec.get('version')}",
                 path=AUTHORITIES.parent / str((rec.get("source_tree") or {}).get("manifest")))
        for rec in view.get("registry", {}).get("authorities") or []
        if (rec.get("source_tree") or {}).get("manifest")
    ]
    inputs = [
        InputRef(name="phase-21-plan", path=PLAN),
        InputRef(name="authority-registry", path=AUTHORITIES),
        InputRef(name="build-records", path=BUILD_RECORDS),
        *manifest_inputs,
        InputRef(name="differential", path=DIFFERENTIAL),
        InputRef(name="authority-policy", path=AUTHORITY_POLICY_DOC),
        InputRef(name="security-divergence-policy", path=SECURITY_POLICY_DOC),
        # The 21.2 atlas-delta court's per-authority inputs: the symbol and declared-surface atlases
        # it recomputes the export-plane delta from, the named provider census and prerequisite
        # plane, and the per-authority provider inventories it measures as the adjacent plane.
        *[
            InputRef(name=f"{aid}-{fname}", path=ATLAS / aid / fname)
            for aid in (HISTORICAL_AUTHORITY, PRODUCTION_AUTHORITY)
            for fname in ("symbols-libcrypto.json", "symbols-libssl.json",
                          *[f for _p, f, _k in differential_tool.SET_PLANES])
            if (ATLAS / aid / fname).is_file()
        ],
        *[
            InputRef(name=f"{aid}-provider-inventory", path=ATLAS / aid / "provider-inventory.json")
            for aid in (HISTORICAL_AUTHORITY, PRODUCTION_AUTHORITY)
            if (ATLAS / aid / "provider-inventory.json").is_file()
        ],
        InputRef(name="provider-algorithms", path=PROVIDER_CENSUS),
        InputRef(name="prerequisites", path=PREREQUISITES),
        # The 21.3 delta-disposition court's candidate-surface inputs: the installed headers it
        # verified the committed delta's declarations against. They are read from the court's own
        # recorded `candidate_source`s, so the evidence binds the exact bytes it read.
        *[
            InputRef(name=f"candidate-{Path(src).name}", path=REPO_ROOT / src)
            for src in sorted({
                str(r["candidate_source"])
                for rec in records if rec.get("court") == DELTA_DISPOSITION
                for r in (rec.get("dispositions") or [])
                if r.get("candidate_source")
            })
        ],
    ]
    doc = envelope(kind="phase21-courts", authority=auth.id, inputs=inputs,
                   body=body, generator=GENERATOR)
    write_json(OUT, doc)

    for r in records:
        if r["verdict"] == "pass" and r["court"] == AUTHORITY_ADMISSION:
            c = r["control"]
            pair = r["pair"]
            frm, to = pair["from"], pair["to"]
            print(f"  {r['court']:<32} pass   (no probe, pair {frm['id']} -> {to['id']}, "
                  f"profiles {frm['profile']!r} = {to['profile']!r}, "
                  f"{len(r['findings'])} finding(s); control honest={c['honest']} "
                  f"specificity={c['specificity_holds']} "
                  f"injected-unadmitted->{c['injected_unadmitted_findings']} finding(s) "
                  f"injected-identity-drift->{c['injected_identity_findings']} finding(s))")
            for f in r["findings"]:
                print(f"      finding: {f}")
        elif r["verdict"] == "pass" and r["court"] == ATLAS_DELTA:
            c = r["control"]
            counts = r["counts"]
            print(f"  {r['court']:<32} pass   (no probe, {counts['planes_measured']} measured / "
                  f"{counts['planes_not_measured']} not-measured plane(s), "
                  f"delta added={counts['added']} removed={counts['removed']} "
                  f"changed={counts['changed']}; control honest={c['honest']} "
                  f"specificity={c['specificity_holds']} "
                  f"injected-added->{c['injected_added_counts']['added']} row(s) "
                  f"injected-removed->{c['injected_removed_counts']['removed']} row(s))")
            for row in r["planes"]:
                tag = "measured" if row["state"] == "measured" else "not-measured"
                extra = ""
                if row["state"] == "measured":
                    extra = (f" added={row['counts']['added']} removed={row['counts']['removed']} "
                             f"changed={row['counts']['changed']}")
                print(f"      plane {row['plane']:<26} {tag}{extra}")
            for f in r["findings"]:
                print(f"      finding: {f}")
        elif r["verdict"] == "pass" and r["court"] == DELTA_DISPOSITION:
            c = r["control"]
            counts = r["counts"]
            print(f"  {r['court']:<32} pass   (no probe, {counts['targets']} target(s): "
                  f"{counts['implemented']} implemented / {counts['boundary']} boundary / "
                  f"{counts['deferred']} deferred / {counts['not_in_profile']} not-in-profile / "
                  f"{counts['unexplained']} unexplained; {counts['findings']} finding(s); "
                  f"control honest={c['honest']} specificity={c['specificity_holds']} "
                  f"injected-un-dispositioned->{c['injected_un_dispositioned_findings']} finding(s) "
                  f"injected-reintroduced->{c['injected_reintroduced_findings']} finding(s) "
                  f"injected-benign->{c['injected_benign_added_findings']} finding(s))")
            for row in r["dispositions"]:
                tag = "un-dispositioned" if row["disposition"] is None else row["disposition"]
                if row.get("prohibited"):
                    tag += " (prohibited)"
                source = row.get("candidate_source") or ""
                print(f"      row {row['id']:<68} {tag}"
                      + (f"  ({source})" if source else ""))
            for f in r["findings"]:
                print(f"      finding: {f}")
        elif r["verdict"] != "pass":
            print(f"  {r['court']:<32} FAIL   stage={r.get('stage', 'derive')}")
            for p in (r.get("problems") or [])[:12]:
                print(f"      {p}")
            for f in (r.get("findings") or [])[:12]:
                print(f"      finding: {f}")
    for cname, needs in PENDING_COURTS.items():
        print(f"  {cname:<32} PENDING (not registered as passing) -- {needs}")
    print(f"  -> {rel(OUT)} all_pass={body['all_pass']} over {len(records)} court(s)")
    return 0 if body["all_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
