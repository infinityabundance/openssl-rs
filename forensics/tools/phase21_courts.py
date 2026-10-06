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

The pending courts
------------------
Four of the five courts the plan names are not runnable yet. `PENDING_COURTS` names each with the
subphase that lands its instrument:

  * `RT-ATLAS-DELTA` (21.2) — the added / removed / changed obligation delta between the two
    authorities across the atlas planes (exports, provider rows, prerequisite units), computed
    mechanically from committed artefacts;
  * `RT-DELTA-DISPOSITION` (21.3) — the disposition of every delta row (`implemented` / `deferred`
    / `not-in-profile` / `boundary`), requiring zero unexplained, so a newly discovered
    un-dispositioned delta row is a `fail` rather than a silent addition;
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
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    HISTORICAL_AUTHORITY,
    PRODUCTION_AUTHORITY,
    REPO_ROOT,
    InputRef,
    envelope,
    rel,
    resolve_authority,
    write_json,
)

OUT = REPO_ROOT / "artifacts" / "phase21" / "COURTS.json"
GENERATOR = "forensics/tools/phase21_courts.py"
PLAN = REPO_ROOT / "docs" / "PHASE-21-SUBPHASES.md"

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

AUTHORITY_ADMISSION = "RT-AUTHORITY-ADMISSION"

# The courts, in the order they land. `(name, probe filename)`, and the probe is declared in the
# same commit as the entry, so a runner that names a probe which does not exist cannot be
# committed. A court that stages no probe names `""`: `RT-AUTHORITY-ADMISSION` derives its
# evidence from committed records, so it has no staged transcript to read back.
COURTS: list[tuple[str, str]] = [
    (AUTHORITY_ADMISSION, ""),
]

# A court the plan names and this stratum cannot run yet. Each entry names the subphase that lands
# the instrument and what the court will drive, so "nothing registered" is a stated distance rather
# than a court quietly dropped.
PENDING_COURTS: dict[str, str] = {
    "RT-ATLAS-DELTA": (
        "21.2 lands the atlas delta; it computes the added / removed / changed obligations between "
        "the two authorities across the atlas planes the procedure names — exports, provider "
        "registration rows and prerequisite units — from the committed differential and the "
        "per-authority atlases, never hand-listed, and names a plane it cannot yet compare "
        "`not-measured` rather than counting it as motionless"
    ),
    "RT-DELTA-DISPOSITION": (
        "21.3 lands the delta disposition; it requires every delta row to be dispositioned "
        "(`implemented` / `deferred` / `not-in-profile` / `boundary`) with zero unexplained, so a "
        "newly discovered un-dispositioned delta row is a `fail`. A row whose disposition would "
        "re-adopt a historical behaviour against a security fix is a finding, not a disposition"
    ),
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
        # 21.1's authority-admission court stages no probe: its subject is the pair's committed
        # identity, so it is computed here rather than read back from disk and no digest cycle
        # forms. This stratum owns no export, so no differential probe over a symbol set is its
        # evidence.
        if name == AUTHORITY_ADMISSION:
            records.append(authority_admission_court(name))
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
            "`RT-ATLAS-DELTA` is 21.2's: the added / removed / changed obligation delta between "
            "the two authorities across the atlas planes (exports, provider rows, prerequisite "
            "units), computed mechanically from committed artefacts. `RT-DELTA-DISPOSITION` is "
            "21.3's: the disposition of every delta row with zero unexplained. "
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
