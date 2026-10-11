#!/usr/bin/env python3
"""openssl-rs — the Phase-18 fuzz crosswalk (Phase 25.13).

Phase 25 is the memory-safety stratum (`docs/RELEASE_GATES.md` section 1,
`docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md`). 25.1 enumerates the compiler-derived unsafe
operations, 25.2 records the non-Rust trusted computing base, 25.3 gives every site an
obligation, 25.4 models the ownership/allocation/callback machinery, 25.5 maps every site to
the Phase-22 reachability roots that reach it, 25.6 to the Phase-24 downstream population and
25.7 classifies every site's exposure and records the attacker-input routes. This subphase is
25.13: it **crosswalks the memory-safety census to the Phase-18 hostile-fuzz courts**, so a
discovered memory-safety failure is a preserved Phase-18 record rather than a discarded run.

The rule, and the authority it reads
------------------------------------
    census unsafe site -> its 25.7 attacker-input route (a parser the site's module/authority
       unit is) -> the Phase-18 hostile-fuzz target whose corpus drives that input route

Each step is a fact a committed plane measured, and none of it is typed here:

  * the **attacker-input routes** and the sites on them are the 25.7 exposure classification's
    own (`artifacts/phase25/exposure.json`, `body.attacker_routes`): a route is a rule over the
    committed parser identities, and a site is on a route when its committed module or authority
    unit is the parser the route names, so the route -> site map is the exposure court's answer
    rather than a second, typed one;
  * the **Phase-18 hostile-fuzz targets** are the courts the committed hostile-boundary register
    records (`artifacts/phase18/hostile-boundary-register.json`): the surface groups that drive
    an attacker-input corpus (`hostile-tls`, `hostile-x509`). A target's sites are the sites on
    the exposure routes its surfaces' inputs drive, and the input-route correspondence is the
    rule this plane records (`rule.group_routes`), keyed on the register's own group vocabulary;
  * the **evidence** is the register's per-surface court evidence (its verdict, its corpus size
    and its candidate crash/OOM/timeout findings) and the Phase-18 courts registry
    (`artifacts/phase18/COURTS.json`) and the bounded mutational screen
    (`artifacts/phase18/fuzz-hostile-corpus.json`); no finding, verdict or corpus size is typed.

The join is the Phase-18 measurement's answer
---------------------------------------------
For every Phase-18 hostile-fuzz target this plane asks the committed exposure routes which
census sites the target's input classes reach. It reads no source, runs no compiler and drives
no corpus: the routes are the 25.7 classification's, the verdicts and corpus sizes are the
Phase-18 register's, and a target the register does not record is not invented to fill a gap.
A target that produced a finding carries it here rather than having it dropped with the run.

Partial joins and coverage gaps are residuals, never zeros or guesses
---------------------------------------------------------------------
Where the join cannot be closed it is recorded rather than defaulted:

  * an **attacker-input route no Phase-18 hostile-fuzz corpus drives** is a recorded
    `evidence_missing` residual, with the sites on it, so an unfuzzed input class is preserved
    rather than read as covered;
  * a **register group that is not a hostile-input fuzz target** (constant-time, memory
    hardening, the explicit non-claims) is a recorded `out_of_scope` residual, so nothing in
    the register is silently dropped;
  * the **census sites no attacker-input route reaches** are a recorded `out_of_scope`
    residual: they are not externally reachable buffer operations, so no fuzz target is
    expected to exercise them, and this is said rather than zeroed.

A pure derivation, so it executes nothing
-----------------------------------------
It reads committed planes and writes a derived plane; it runs no compiler, no tool and no
probe, so `forensics/memory-safety/container.json` lists it `metadata_only` and the Docker-only
guard admits it on any host (it still calls the guard first, so the rule is never optional).

Outputs
-------
  artifacts/phase25/phase18-fuzz-crosswalk.json

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter, defaultdict
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
)

# The Docker-only execution guard, called first. This tool executes nothing -- it derives a plane
# from committed planes -- so the manifest lists it `metadata_only` and the guard admits it on any
# host exactly as `ms_exposure.py`/`ms_phase24_crosswalk.py` are.
import phase25_guard  # noqa: E402

# The fuzz-crosswalk schema and the closed vocabularies. Imported, never restated.
import memory_safety_schemas as schemas  # noqa: E402

# The census (for the site universe and its ordered id lists) and the lossless columnar codec.
import ms_census  # noqa: E402
import ms_codec  # noqa: E402

OUT = REPO_ROOT / "artifacts" / "phase25" / "phase18-fuzz-crosswalk.json"
GENERATOR = "forensics/tools/ms_phase18_fuzz_crosswalk.py"
TOOL = REPO_ROOT / "forensics" / "tools" / "ms_phase18_fuzz_crosswalk.py"
SCHEMAS = REPO_ROOT / "forensics" / "tools" / "memory_safety_schemas.py"
GUARD = REPO_ROOT / "forensics" / "tools" / "phase25_guard.py"
PLAN = REPO_ROOT / "docs" / "PHASE-25-MEMORY-SAFETY-SUBPHASES.md"
MANIFEST = REPO_ROOT / "forensics" / "memory-safety" / "container.json"

# 25.1's compiler-backed source census: the site universe.
CENSUS = REPO_ROOT / "artifacts" / "phase25" / "source-census.json"
# 25.7's exposure classification: the attacker-input routes and the sites on them.
EXPOSURE = REPO_ROOT / "artifacts" / "phase25" / "exposure.json"

# The committed Phase-18 hostile evidence: the register of surfaces and their court evidence, the
# courts registry and the bounded mutational screen over the hostile-X.509 corpus.
P18_REGISTER = REPO_ROOT / "artifacts" / "phase18" / "hostile-boundary-register.json"
P18_COURTS = REPO_ROOT / "artifacts" / "phase18" / "COURTS.json"
P18_FUZZ_CORPUS = REPO_ROOT / "artifacts" / "phase18" / "fuzz-hostile-corpus.json"

CENSUS_REL = rel(CENSUS)
EXPOSURE_REL = rel(EXPOSURE)
P18_REGISTER_REL = rel(P18_REGISTER)
P18_COURTS_REL = rel(P18_COURTS)
P18_FUZZ_CORPUS_REL = rel(P18_FUZZ_CORPUS)

# The Phase-18 hostile-fuzz **groups**: each names the corpus it drives, and the 25.7
# attacker-input routes its inputs are parsed by. The correspondence is this plane's rule, keyed
# on the register's own group vocabulary; the routes are the 25.7 route vocabulary, so a group
# that names a route the exposure plane does not carry is recorded rather than silently ignored.
GROUP_ROUTES: dict[str, tuple[str, ...]] = {
    "hostile-tls": ("TLS_RECORD", "TLS_CLIENT_STATE"),
    "hostile-x509": ("DER", "PEM", "X509_CERTIFICATE"),
}

GROUPS: tuple[str, ...] = tuple(sorted(GROUP_ROUTES))

# The site dispositions. `NOT_FUZZED` is a recorded state with a reason, never an omission.
STATES: tuple[str, ...] = ("FUZZED", "NOT_FUZZED")

# Why a routed site is `NOT_FUZZED`: the closed reasons, so an unfuzzed site is explained rather
# than merely counted.
NOT_FUZZED_REASONS: tuple[str, ...] = (
    "route_not_driven_by_a_phase18_fuzz_target",
)

# The Phase-18 surface verdicts -> the schema's tool states. `UNSUPPORTED` is never `PASS`.
TOOL_STATE_BY_VERDICT: dict[str, str] = {
    "pass": "PASS",
    "fail": "FAIL",
    "not-reachable": "NOT_REACHABLE",
    "unsupported": "UNSUPPORTED",
}

# The residual class for a route no Phase-18 corpus drives: the input class has no hostile-fuzz
# evidence. It is a member of the schema's residual vocabulary.
UNFUZZED_RESIDUAL_CLASS = "evidence_missing"
# The residual class for a register group that is not a hostile-input fuzz target, and for the
# census sites no attacker-input route reaches: both are outside what a fuzz target exercises.
OUT_OF_SCOPE_RESIDUAL_CLASS = "out_of_scope"

NON_CLAIMS = (
    "a fuzzed site is on an attacker-input route a Phase-18 hostile-fuzz corpus drives, which is "
    "a bounded differential or property result over the corpus it drove: it is not a coverage "
    "claim about every input to the parser and not a memory-safety proof, so a site under a "
    "passing corpus is exercised by that corpus's classes, not proven safe",
    "a Phase-18 verdict is about the corpus, not the site: a `PASS` says the corpus produced the "
    "observations it recorded (no crash, no OOM, no timeout over the entries it drove), never "
    "that a reachable unsafe site's contract holds",
    "an unfuzzed site is recorded, not zeroed: a route no Phase-18 corpus drives carries an "
    "`evidence_missing` residual with its sites, and the census sites no attacker-input route "
    "reaches are `out_of_scope` because no fuzz target is expected to exercise them -- neither "
    "is a claim that the site is safe",
    "the corpus is a fixed enumeration, not a coverage-guided fuzzer: the Phase-18 corpora and the "
    "bounded mutational screen are deterministic enumerations, so the absence of a finding is the "
    "absence of a finding over those bytes, never evidence that no input produces one",
)


# --------------------------------------------------------------------------------------------
# small pure helpers
# --------------------------------------------------------------------------------------------

def _load(path: Path) -> dict:
    if not path.is_file():
        raise SystemExit(f"[ms-phase18-fuzz-crosswalk] {rel(path)} is absent")
    return json.loads(path.read_text(encoding="utf-8"))


def load_authority() -> dict:
    """The committed planes this plane reads, loaded once so the generator and the court share bytes.

    The census and the 25.7 exposure classification are columnar artefacts from this stratum, so
    their bodies are decoded here (the census supplies the ordered id lists the exposure plane
    references by index); the Phase-18 atlases are not this stratum's encoding and are used as
    loaded.
    """
    census_doc = _load(CENSUS)
    census_body = ms_census.decode_body(census_doc.get("body", census_doc))
    refs = ms_codec.refs_from_census(census_body)
    exp_doc = _load(EXPOSURE)
    return {
        "census": {**census_doc, "body": census_body},
        "exposure": {**exp_doc,
                     "body": ms_codec.decode_body(exp_doc.get("body", exp_doc), refs)},
        "p18_register": _load(P18_REGISTER),
        "p18_courts": _load(P18_COURTS),
        "p18_fuzz": _load(P18_FUZZ_CORPUS),
    }


def _route_sites(exposure_body: dict) -> dict:
    """`route -> [site_id]` from the 25.7 exposure classification's own attacker routes."""
    routes = exposure_body.get("attacker_routes") or {}
    return {str(r): list((routes[r] or {}).get("sites") or []) for r in routes}


def _court_records(authority: dict) -> dict:
    """`court -> its committed Phase-18 courts-registry record`."""
    body = authority["p18_courts"].get("body", authority["p18_courts"])
    return {str(c.get("court")): c for c in (body.get("courts") or [])}


def _probe_stem(value: str) -> str:
    """The probe's file stem, so a `..._probe.c` court and a `..._probe.candidate` screen match."""
    name = str(value or "").split("/")[-1]
    for suffix in (".candidate", ".authority", ".bin", ".c"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
    return name


# --------------------------------------------------------------------------------------------
# the derivation
# --------------------------------------------------------------------------------------------

_DERIVE_CACHE: dict = {}


def derive_cached(census_body: dict, authority: dict) -> dict:
    """`derive` memoised by the identity of its two arguments (pure and deterministic)."""
    key = (id(census_body), id(authority))
    if key not in _DERIVE_CACHE:
        _DERIVE_CACHE[key] = derive(census_body, authority)
    return _DERIVE_CACHE[key]


def derive(census_body: dict, authority: dict) -> dict:
    """The whole crosswalk, derived: targets, the inverse view, counts and residuals."""
    census_ids = [str(s["site_id"]) for s in (census_body.get("sites") or [])]
    census_set = set(census_ids)
    exp = authority["exposure"].get("body", authority["exposure"])
    route_sites = _route_sites(exp)
    route_vocab = sorted(route_sites)

    reg = authority["p18_register"]
    surfaces = reg.get("surfaces") or []
    courts = _court_records(authority)
    fuzz = authority["p18_fuzz"]
    fuzz_stem = _probe_stem(fuzz.get("probe"))

    # The Phase-18 hostile-fuzz targets: the courts whose register surfaces drive a hostile input
    # corpus (`group` in the group vocabulary), derived from the register, never typed.
    court_groups: dict = defaultdict(set)
    court_surfaces: dict = defaultdict(list)
    for s in surfaces:
        g = s.get("group")
        court = str(s.get("court"))
        if g in GROUP_ROUTES:
            court_groups[court].add(str(g))
            court_surfaces[court].append(s)
    targets = sorted(court_groups)

    # The register groups that are not hostile-input fuzz targets: recorded, never dropped.
    all_groups = sorted({str(s.get("group")) for s in surfaces})

    # The target's input routes, and the sites they reach (their intersection with the census).
    target_routes: dict = {}
    target_sites: dict = {}
    missing_route: dict = {}
    for t in targets:
        routes = sorted({r for g in court_groups[t] for r in GROUP_ROUTES[g]})
        good = [r for r in routes if r in route_sites]
        missing = [r for r in routes if r not in route_sites]
        if missing:
            missing_route[t] = missing
        target_routes[t] = good
        sites: set = set()
        for r in good:
            sites |= set(route_sites[r])
        target_sites[t] = sorted(sites & census_set)

    # The per-surface court evidence: the verdict, the corpus size and the candidate findings.
    # A court's surfaces repeat the same corpus totals, so the sizes are the maximum recorded and
    # a disagreement is a surface-level fact, not a sum.
    target_evidence: dict = {}
    for t in targets:
        verdicts: set = set()
        entries = 0
        total_bytes = 0
        findings = {"crash": 0, "oom": 0, "timeout": 0}
        surface_ids: list = []
        for s in court_surfaces[t]:
            surface_ids.append(str(s.get("id")))
            e = s.get("evidence") or {}
            if e.get("verdict"):
                verdicts.add(str(e["verdict"]))
            entries = max(entries, int(e.get("corpus_entries") or 0))
            total_bytes = max(total_bytes, int(e.get("corpus_total_bytes") or 0))
            cf = e.get("candidate_findings") or {}
            for k in findings:
                findings[k] = max(findings[k], int(cf.get(k) or 0))
        tool_state = (TOOL_STATE_BY_VERDICT[sorted(verdicts)[0]]
                      if len(verdicts) == 1 and sorted(verdicts)[0] in TOOL_STATE_BY_VERDICT
                      else "UNSUPPORTED")
        target_evidence[t] = {
            "verdicts": sorted(verdicts),
            "tool_state": tool_state,
            "corpus_entries": entries,
            "corpus_total_bytes": total_bytes,
            "findings_by_class": dict(sorted(findings.items())),
            "surface_ids": sorted(surface_ids),
        }

    # The forward target records, keyed by the Phase-18 target (the schema's `fuzz_crosswalk` row).
    target_records: dict = {}
    for t in targets:
        ev = target_evidence[t]
        sites = target_sites[t]
        rec = {
            "crosswalk_id": "fw-" + t.lower(),
            "phase18_target": t,
            "unsafe_site_ids": sites,
            "covered": bool(sites),
            "tool_state": ev["tool_state"],
            "evidence": [P18_REGISTER_REL, P18_COURTS_REL, P18_FUZZ_CORPUS_REL,
                         EXPOSURE_REL, CENSUS_REL],
            "group": sorted(court_groups[t]),
            "routes": target_routes[t],
            "surface_ids": ev["surface_ids"],
            "corpus_entries": ev["corpus_entries"],
            "corpus_total_bytes": ev["corpus_total_bytes"],
            "findings_by_class": ev["findings_by_class"],
            "unsafe_site_count": len(sites),
        }
        # The bounded mutational screen drives the hostile corpus of the court whose probe it uses.
        court_rec = courts.get(t) or {}
        if court_rec and _probe_stem(court_rec.get("probe")) == fuzz_stem:
            rec["mutational_screen"] = {
                "tool": str(fuzz.get("tool") or ""),
                "corpus": str(fuzz.get("corpus") or ""),
                "cases_requested": int(fuzz.get("cases_requested") or 0),
                "cases_driven": int(fuzz.get("cases_driven") or 0),
                "finding_count": int(fuzz.get("finding_count") or 0),
                "classes": dict(sorted((fuzz.get("classes") or {}).items())),
                "note": str(fuzz.get("note") or ""),
            }
        target_records[t] = rec

    # The inverse site view: per routed site, the targets that exercise it, its routes and its
    # state. Every count is recomputed from the forward map above, never typed.
    routed: set = set()
    site_routes: dict = defaultdict(list)
    for r in route_vocab:
        for sid in route_sites[r]:
            if sid in census_set:
                routed.add(sid)
                site_routes[sid].append(r)
    forward: dict = defaultdict(list)
    for t in targets:
        for sid in target_sites[t]:
            forward[sid].append(t)
    sites: dict = {}
    for sid in sorted(routed):
        tg = sorted(forward.get(sid, []))
        rs = sorted(set(site_routes.get(sid, [])))
        if tg:
            sites[sid] = {"state": "FUZZED", "targets": tg, "routes": rs}
        else:
            sites[sid] = {"state": "NOT_FUZZED", "targets": [], "routes": rs,
                          "reason": "route_not_driven_by_a_phase18_fuzz_target"}

    driven_routes = sorted({r for t in targets for r in target_routes[t]})
    undriven_routes = sorted(set(route_vocab) - set(driven_routes))
    non_fuzz_groups = sorted(set(all_groups) - set(GROUPS))
    not_routed = sorted(census_set - routed)

    # The residuals. A partial join or a coverage gap is recorded, never zeroed or guessed.
    residuals: list = []
    for r in undriven_routes:
        rec = exp["attacker_routes"].get(r) or {}
        residuals.append({
            "residual_id": "rx:" + hashlib.sha256(
                f"{UNFUZZED_RESIDUAL_CLASS}|route|{r}".encode("utf-8")).hexdigest()[:16],
            "subject": r,
            "class": UNFUZZED_RESIDUAL_CLASS,
            "disposition": "open",
            "detail": ("the attacker-input route names a parser no Phase-18 hostile-fuzz corpus "
                       "drives, so the sites on it carry no Phase-18 fuzz evidence; preserved "
                       "rather than read as covered"),
            "evidence": [P18_REGISTER_REL, EXPOSURE_REL],
            "route": r,
            "input": str(rec.get("input") or ""),
            "transport": str(rec.get("transport") or ""),
            "site_count": len(route_sites[r]),
        })
    for g in non_fuzz_groups:
        residuals.append({
            "residual_id": "rx:" + hashlib.sha256(
                f"{OUT_OF_SCOPE_RESIDUAL_CLASS}|group|{g}".encode("utf-8")).hexdigest()[:16],
            "subject": "phase18-group:" + g,
            "class": OUT_OF_SCOPE_RESIDUAL_CLASS,
            "disposition": "open",
            "detail": ("the committed hostile-boundary register records this Phase-18 group, but it "
                       "is not a hostile-input fuzz target (its corpus drives no attacker-input "
                       "route), so it is outside this crosswalk rather than silently dropped"),
            "evidence": [P18_REGISTER_REL],
            "group": g,
            "surface_count": sum(1 for s in surfaces if str(s.get("group")) == g),
        })
    if not_routed:
        residuals.append({
            "residual_id": "rx:" + hashlib.sha256(
                f"{OUT_OF_SCOPE_RESIDUAL_CLASS}|no-attacker-route".encode("utf-8")).hexdigest()[:16],
            "subject": "census sites on no attacker-input route",
            "class": OUT_OF_SCOPE_RESIDUAL_CLASS,
            "disposition": "open",
            "detail": ("the census sites no committed attacker-input route reaches are not "
                       "externally reachable buffer operations, so no Phase-18 fuzz target is "
                       "expected to exercise them; recorded rather than dropped and never "
                       "defaulted to a fuzz target"),
            "evidence": [EXPOSURE_REL, CENSUS_REL],
            "site_count": len(not_routed),
        })
    for t in sorted(missing_route):
        residuals.append({
            "residual_id": "rx:" + hashlib.sha256(
                f"{UNFUZZED_RESIDUAL_CLASS}|missing-route|{t}".encode("utf-8")).hexdigest()[:16],
            "subject": "phase18-target:" + t,
            "class": UNFUZZED_RESIDUAL_CLASS,
            "disposition": "open",
            "detail": ("the Phase-18 target's input group names an attacker-input route the 25.7 "
                       "exposure plane does not carry, so the route's sites cannot be joined and "
                       "are recorded rather than guessed"),
            "evidence": [P18_REGISTER_REL, EXPOSURE_REL],
            "phase18_target": t,
            "missing_routes": missing_route[t],
        })
    for t in targets:
        if t not in courts:
            residuals.append({
                "residual_id": "rx:" + hashlib.sha256(
                    f"evidence_missing|court|{t}".encode("utf-8")).hexdigest()[:16],
                "subject": "phase18-court:" + t,
                "class": "evidence_missing",
                "disposition": "open",
                "detail": ("the Phase-18 target has no record in the committed Phase-18 courts "
                           "registry, so its verdict is missing evidence; recorded rather than "
                           "assumed to have passed"),
                "evidence": [P18_COURTS_REL],
                "phase18_target": t,
            })

    fuzzed = sum(1 for e in sites.values() if e["state"] == "FUZZED")
    not_fuzzed = sum(1 for e in sites.values() if e["state"] == "NOT_FUZZED")
    findings_total = sum(sum(r["findings_by_class"].values()) for r in target_records.values())
    screen_findings = sum(r.get("mutational_screen", {}).get("finding_count", 0)
                          for r in target_records.values())
    counts = {
        "census_sites": len(census_ids),
        "attacker_routes": len(route_vocab),
        "routed_sites": len(routed),
        "sites_on_a_fuzzed_route": fuzzed,
        "sites_not_fuzzed": not_fuzzed,
        "not_fuzzed_by_reason": dict(sorted(Counter(
            e["reason"] for e in sites.values() if e["state"] == "NOT_FUZZED").items())),
        "sites_on_no_attacker_route": len(not_routed),
        "phase18_fuzz_targets": len(targets),
        "targets_covered": sum(1 for r in target_records.values() if r["covered"]),
        "routes_driven_by_phase18": len(driven_routes),
        "routes_not_driven_by_phase18": len(undriven_routes),
        "phase18_groups": len(all_groups),
        "phase18_groups_not_fuzz_targets": len(non_fuzz_groups),
        "fuzzed_sites_by_target": {t: len(target_records[t]["unsafe_site_ids"]) for t in targets},
        "corpus_entries": sum(r["corpus_entries"] for r in target_records.values()),
        "findings": findings_total,
        "mutational_screen_findings": screen_findings,
        "residuals": len(residuals),
        "states": sorted(STATES),
    }

    return {
        "targets": target_records,
        "sites": sites,
        "counts": counts,
        "residuals": residuals,
        "driven_routes": driven_routes,
        "undriven_routes": undriven_routes,
        "non_fuzz_groups": non_fuzz_groups,
        "not_routed_count": len(not_routed),
        "target_sites": target_sites,
        "missing_route": missing_route,
    }


def _rule(authority: dict) -> dict:
    reg = authority["p18_register"]
    return {
        "authority": {
            "kind": "phase18-hostile-fuzz-evidence",
            "paths": [P18_REGISTER_REL, P18_COURTS_REL, P18_FUZZ_CORPUS_REL],
            "declaration": (
                "the committed Phase-18 hostile-boundary register is the authority this plane "
                "reads: its surfaces name the hostile-fuzz courts, their corpus sizes and their "
                "candidate findings, the courts registry records the verdicts and the bounded "
                "mutational screen records the Phase-18 fuzz evidence; no verdict, corpus size or "
                "finding is typed here"
            ),
            "register_rule": str(reg.get("rule") or "")[:400],
        },
        "mapping_rule": (
            "census unsafe site -> its 25.7 attacker-input route (the parser its committed module "
            "or authority unit is) -> the Phase-18 hostile-fuzz target whose surface group drives "
            "that input route"
        ),
        "group_routes": {g: list(GROUP_ROUTES[g]) for g in GROUPS},
        "route_authority": {
            "rule": (
                "the attacker-input routes and the sites on them are the 25.7 exposure "
                "classification's own attacker_routes: a site is on a route when its committed "
                "module or authority unit is the parser the route names"
            ),
            "input": EXPOSURE_REL,
        },
        "target_disposition": (
            "every Phase-18 hostile-fuzz target is present in `.targets`: a target carries the "
            "sites on the routes its inputs drive, whether it is `covered`, its tool state (from "
            "the register verdict), its corpus size and its candidate findings; a target the "
            "register does not record is not invented"
        ),
        "site_disposition": (
            "every routed census site is present in `.sites`: a `FUZZED` site names the Phase-18 "
            "targets that exercise it and its routes, and a `NOT_FUZZED` site names its routes and "
            "a closed reason; a site is never dropped"
        ),
        "partial_join": (
            "a partial join or a coverage gap is a residual, never a zero or a guess: an "
            "attacker-input route no Phase-18 corpus drives is `evidence_missing`, a register "
            "group that is not a fuzz target and the sites no attacker route reaches are "
            "`out_of_scope`, and a missing court record is `evidence_missing`"
        ),
        "sort_key": ("targets by name; sites by id; residuals by id; every list sorted"),
    }


def _property_findings(d: dict) -> list:
    c = d["counts"]
    per_target = ", ".join(f"{t}={n}" for t, n in sorted(c["fuzzed_sites_by_target"].items()))
    return [
        f"{c['sites_on_a_fuzzed_route']} of {c['routed_sites']} externally reachable "
        f"buffer-operation site(s) are on a Phase-18 hostile-fuzz route across "
        f"{c['phase18_fuzz_targets']} hostile-fuzz target(s) ({per_target}); "
        f"{c['sites_not_fuzzed']} are on an attacker-input route no Phase-18 corpus drives and are "
        f"recorded as `evidence_missing` residuals, never zeroed",
        f"the {c['phase18_fuzz_targets']} Phase-18 hostile-fuzz target(s) carry "
        f"{c['corpus_entries']} corpus entr(ies) and {c['findings']} crash/OOM/timeout finding(s) "
        f"(the bounded mutational screen adds {c['mutational_screen_findings']}); a finding is "
        f"carried here rather than dropped with the run",
        f"{c['routes_driven_by_phase18']} of {c['attacker_routes']} attacker-input route(s) are "
        f"driven by a Phase-18 hostile-fuzz target and {c['routes_not_driven_by_phase18']} are not; "
        f"{c['phase18_groups_not_fuzz_targets']} of {c['phase18_groups']} register group(s) are "
        f"not hostile-input fuzz targets and are `out_of_scope`",
        f"{c['sites_on_no_attacker_route']} census site(s) are on no attacker-input route: they "
        f"are not externally reachable buffer operations, so no fuzz target is expected to "
        f"exercise them, and this is said rather than read as covered",
        "a Phase-18 `PASS` is a bounded result over the corpus it drove, not a coverage or "
        "memory-safety claim: a site under a passing corpus is exercised by that corpus's classes, "
        "never proven safe",
    ]


def build_body(census_body: dict, authority: dict) -> dict:
    """The crosswalk body: the rule, the targets, the inverse view, counts, residuals and findings."""
    d = derive_cached(census_body, authority)
    return {
        "rule": _rule(authority),
        "targets": d["targets"],
        "sites": d["sites"],
        "counts": d["counts"],
        "residuals": d["residuals"],
        "findings": _property_findings(d),
        "non_claims": list(NON_CLAIMS),
    }


# --------------------------------------------------------------------------------------------
# the pure checks: what the court runs over the committed artefact
# --------------------------------------------------------------------------------------------

def crosswalk_findings(body: dict, census_body: dict, authority: dict) -> list:
    """Every way the committed crosswalk contradicts the census or the Phase-18 evidence.

    Pure over `body`, the census and the authority (the 25.7 exposure classification and the
    Phase-18 register/courts/screen): it is what the `MS-PHASE18-FUZZ-CROSSWALK` court runs. It
    checks that every Phase-18 target is present with its Phase-18 evidence; that its sites are
    exactly the sites on the routes its inputs drive (so a site is neither dropped nor added);
    that a covered target names its Phase-18 evidence; that the inverse site view reproduces from
    the forward map; that the targets, the site view, the counts and the residuals equal their
    derivation; that every coverage gap is a residual; and that the plane reads the committed
    Phase-18 evidence and the committed 25.7 routes rather than a typed set.
    """
    problems: list = []
    # The committed crosswalk is columnar on disk; re-derive the views the checks read (a fresh
    # measurement passes the views, for which decoding is a no-op).
    census_body = ms_census.decode_body(census_body)
    refs = ms_codec.refs_from_census(census_body)
    body = ms_codec.decode_body(body, refs)
    d = derive_cached(census_body, authority)

    census_ids = [str(s["site_id"]) for s in (census_body.get("sites") or [])]
    census_set = set(census_ids)
    targets = body.get("targets") or {}
    sites = body.get("sites") or {}

    # 1. The census site ids are unique.
    if len(census_set) != len(census_ids):
        problems.append("the census carries a duplicate site_id, so a fuzz disposition is ambiguous")

    # 2. Every derived Phase-18 target is present, and every present target is a derived one.
    for t in sorted(set(d["targets"]) - set(targets)):
        problems.append(f"the Phase-18 hostile-fuzz target {t} has no crosswalk record (dropped)")
    for t in sorted(set(targets) - set(d["targets"])):
        problems.append(f"the crosswalk records the target {t}, which no Phase-18 surface drives")

    # 3. Every target's sites are exactly the sites on the routes its inputs drive, and its
    #    evidence, tool state and corpus size equal the derivation.
    for t in sorted(set(d["targets"]) & set(targets)):
        rec = targets[t]
        want = d["target_sites"][t]
        got = list(rec.get("unsafe_site_ids") or [])
        if len(set(got)) != len(got):
            problems.append(f"{t}: `unsafe_site_ids` carries a duplicate site")
        for sid in sorted(set(got) - census_set):
            problems.append(f"{t}: names {sid}, which is not a census site")
        if sorted(got) != want:
            missing = sorted(set(want) - set(got))
            extra = sorted(set(got) - set(want))
            problems.append(
                f"{t}: its sites are not the sites on its routes "
                f"(missing {missing[:4]}, extra {extra[:4]})"
            )
        # A covered target must name its Phase-18 evidence: the register/courts/screen.
        if rec.get("covered"):
            if not rec.get("evidence"):
                problems.append(f"{t}: is covered but names no Phase-18 evidence")
            elif not any(P18_REGISTER_REL == e or P18_COURTS_REL == e
                         or P18_FUZZ_CORPUS_REL == e for e in rec.get("evidence") or []):
                problems.append(
                    f"{t}: is covered but names no committed Phase-18 hostile-fuzz evidence"
                )
        # `covered` is exactly "the target drives routes that reach census sites".
        if bool(rec.get("covered")) != bool(want):
            problems.append(f"{t}: `covered`={rec.get('covered')!r} disagrees with its site set")
        # The tool state and the corpus size are the register's, never typed.
        ev = d["targets"][t]
        if rec.get("tool_state") != ev["tool_state"]:
            problems.append(
                f"{t}: the tool state {rec.get('tool_state')!r} is not the register's "
                f"{ev['tool_state']!r}"
            )
        if rec.get("tool_state") not in schemas.TOOL_STATES:
            problems.append(f"{t}: the tool state {rec.get('tool_state')!r} is not a tool state")
        if rec.get("corpus_entries") != ev["corpus_entries"]:
            problems.append(f"{t}: the corpus size is not the register's")
        if rec.get("findings_by_class") != ev["findings_by_class"]:
            problems.append(f"{t}: the findings are not the register's")
        # The record validates against the fuzz-crosswalk schema.
        problems += [f"{t}: schema: {p}" for p in schemas.validate("fuzz_crosswalk", rec)]

    # 4. The inverse site view reproduces from the forward map.
    routed = set()
    for r, ids in _route_sites(
            authority["exposure"].get("body", authority["exposure"])).items():
        routed |= {sid for sid in ids if sid in census_set}
    for sid in sorted(routed - set(sites)):
        problems.append(f"the routed census site {sid} has no crosswalk disposition (dropped)")
    for sid in sorted(set(sites) - routed):
        problems.append(f"the crosswalk maps {sid}, which is not on an attacker-input route")
    forward: dict = defaultdict(list)
    for t in d["targets"]:
        for sid in d["target_sites"][t]:
            forward[sid].append(t)
    for sid in sorted(set(sites) & routed):
        e = sites[sid]
        want_targets = sorted(forward.get(sid, []))
        got_targets = sorted(e.get("targets") or [])
        if got_targets != want_targets:
            problems.append(
                f"{sid}: the inverse view names targets {got_targets}, the forward map has "
                f"{want_targets}"
            )
        if e.get("state") not in STATES:
            problems.append(f"{sid}: the state {e.get('state')!r} is not a fuzz disposition")
            continue
        if e["state"] == "FUZZED" and not want_targets:
            problems.append(f"{sid}: is FUZZED but no Phase-18 target exercises it")
        if e["state"] == "NOT_FUZZED":
            if want_targets:
                problems.append(f"{sid}: is NOT_FUZZED but the target(s) {want_targets} reach it")
            if e.get("reason") not in NOT_FUZZED_REASONS:
                problems.append(f"{sid}: NOT_FUZZED without a closed reason")

    # 5. Every coverage gap is a residual: each undriven route, each non-fuzz group.
    residual_routes = {r.get("route") for r in (body.get("residuals") or []) if r.get("route")}
    for r in d["undriven_routes"]:
        if r not in residual_routes:
            problems.append(f"the attacker-input route {r} is driven by no Phase-18 corpus and has "
                            f"no residual")
    residual_groups = {r.get("group") for r in (body.get("residuals") or []) if r.get("group")}
    for g in d["non_fuzz_groups"]:
        if g not in residual_groups:
            problems.append(f"the Phase-18 group {g} is not a fuzz target and has no residual")
    if d["not_routed_count"] and not any(
            r.get("class") == OUT_OF_SCOPE_RESIDUAL_CLASS and "no attacker-input route" in
            str(r.get("subject")) for r in (body.get("residuals") or [])):
        problems.append("the census sites on no attacker-input route have no residual")
    if d.get("missing_route"):
        for t in d["missing_route"]:
            if t not in {r.get("phase18_target") for r in (body.get("residuals") or [])
                         if r.get("missing_routes")}:
                problems.append(f"{t}: names a route the exposure plane does not carry and has no "
                                f"residual")

    # 6. Every plane equals its derivation.
    for key in ("targets", "sites", "counts", "residuals"):
        if body.get(key) != d[key]:
            problems.append(f"the committed `{key}` is not the derived `{key}`")

    # 7. The rule names the committed Phase-18 evidence and the committed 25.7 routes.
    rule_authority = (body.get("rule") or {}).get("authority") or {}
    paths = rule_authority.get("paths") or []
    if P18_REGISTER_REL not in paths or P18_COURTS_REL not in paths:
        problems.append(
            f"the mapping rule does not name the committed Phase-18 evidence "
            f"({P18_REGISTER_REL}, {P18_COURTS_REL}) as its authority"
        )
    if (body.get("rule") or {}).get("route_authority", {}).get("input") != EXPOSURE_REL:
        problems.append("the rule does not name the committed 25.7 exposure routes as its join")

    # 8. Every residual validates against the residual schema.
    for r in body.get("residuals") or []:
        problems += [f"residual[{r.get('residual_id')}]: {p}" for p in schemas.validate("residual", r)]

    return problems


def crosswalk_sensitivity_control(body: dict, census_body: dict, authority: dict) -> dict:
    """Seed six mutations and require each caught, with specificity holding.

    Each is a distinct way the crosswalk could lie: a site silently dropped from a target; a
    covered target whose Phase-18 evidence is gone; the inverse view disagreeing with the forward
    map; a typed count; a coverage gap with no residual; and a tool state that is not the
    register's.
    """
    # The committed crosswalk is columnar on disk; the mutations below index its records, so decode
    # once (a fresh measurement passes the views, for which decoding is a no-op).
    census_body = ms_census.decode_body(census_body)
    refs = ms_codec.refs_from_census(census_body)
    body = ms_codec.decode_body(body, refs)
    baseline = crosswalk_findings(body, census_body, authority)
    result: dict = {"baseline_findings": len(baseline), "honest": not baseline,
                    "specificity_holds": False, "mutations": {}}

    def check(label: str, mutated: dict, marker: str) -> bool:
        found = crosswalk_findings(mutated, census_body, authority)
        caught = any(marker in f for f in found)
        result["mutations"][label] = {"caught": caught, "findings": len(found),
                                      "delta": len(found) - len(baseline), "marker": marker}
        return caught

    def clone() -> dict:
        return json.loads(json.dumps(body))

    target_names = sorted(t for t in body["targets"] if body["targets"][t]["unsafe_site_ids"])
    routed = sorted(body["sites"])
    fuzzed = sorted(sid for sid in body["sites"] if body["sites"][sid]["state"] == "FUZZED")
    not_fuzzed = sorted(sid for sid in body["sites"] if body["sites"][sid]["state"] == "NOT_FUZZED")

    # m1: a site silently dropped from a Phase-18 target.
    def drop_site() -> dict:
        b = clone()
        b["targets"][target_names[0]]["unsafe_site_ids"].pop()
        return b

    m1 = check("site_dropped", drop_site(), "its sites are not the sites on its routes")

    # m2: a covered target whose Phase-18 evidence is gone.
    def covered_without_evidence() -> dict:
        b = clone()
        b["targets"][target_names[0]]["evidence"] = []
        return b

    m2 = check("covered_without_evidence", covered_without_evidence(),
               "is covered but names no Phase-18 evidence")

    # m3: the inverse view disagreeing with the forward map.
    def inverse_disagrees() -> dict:
        b = clone()
        sid = not_fuzzed[0] if not_fuzzed else routed[0]
        b["sites"][sid]["state"] = "FUZZED"
        b["sites"][sid]["targets"] = [target_names[0]]
        return b

    m3 = check("inverse_view_disagrees", inverse_disagrees(), ": the inverse view names targets")

    # m4: a typed count (a count not derived from the site map).
    def typed_count() -> dict:
        b = clone()
        b["counts"]["sites_on_a_fuzzed_route"] += 1
        return b

    m4 = check("typed_count", typed_count(), "not the derived `counts`")

    # m5: a coverage gap with no residual (an undriven route's residual removed).
    def residual_omitted() -> dict:
        b = clone()
        b["residuals"] = [r for r in b["residuals"] if not r.get("route")]
        return b

    m5 = check("residual_omitted", residual_omitted(),
               "is driven by no Phase-18 corpus and has no residual")

    # m6: a tool state that is not the register's (a typed verdict).
    def typed_verdict() -> dict:
        b = clone()
        b["targets"][target_names[0]]["tool_state"] = "FAIL"
        return b

    m6 = check("typed_verdict", typed_verdict(), "is not the register's")

    result["specificity_holds"] = bool(m1 and m2 and m3 and m4 and m5 and m6 and not baseline)
    result["caught"] = sum(1 for v in result["mutations"].values() if v["caught"])
    result["seeded"] = len(result["mutations"])
    return result


# --------------------------------------------------------------------------------------------
# self-test
# --------------------------------------------------------------------------------------------

def _synth_authority() -> dict:
    """A tiny, self-consistent set of Phase-18 and 25.7 planes: two fuzz targets, five routes."""
    exposure = {"body": {
        "attacker_routes": {
            "TLS_RECORD": {"input": "TLS record bytes", "transport": "NETWORK_SERVER",
                           "sites": ["us-s1", "us-s2"]},
            "X509_CERTIFICATE": {"input": "X.509 certificate/CRL", "transport": "LOCAL_FILE",
                                 "sites": ["us-s3", "us-s4"]},
            "DER": {"input": "DER-encoded ASN.1", "transport": "LOCAL_FILE",
                    "sites": ["us-s4", "us-s5"]},
            "PEM": {"input": "PEM text", "transport": "LOCAL_FILE", "sites": ["us-s5"]},
            "PKCS7": {"input": "PKCS#7 input", "transport": "LOCAL_FILE", "sites": ["us-s6"]},
        },
    }}
    register = {
        "schema": "openssl-rs/hostile-boundary-register/v1",
        "rule": "the register is authored; a surface is hardened, measured or not-claimed",
        "surfaces": [
            {"id": "tls-records", "group": "hostile-tls", "court": "RT-HOSTILE-TLS",
             "classification": "measured",
             "evidence": {"verdict": "pass", "corpus_entries": 10, "corpus_total_bytes": 100,
                          "candidate_findings": {"crash": 0, "oom": 0, "timeout": 0}}},
            {"id": "x509-der", "group": "hostile-x509", "court": "RT-HOSTILE-X509",
             "classification": "measured",
             "evidence": {"verdict": "pass", "corpus_entries": 20, "corpus_total_bytes": 200,
                          "candidate_findings": {"crash": 0, "oom": 0, "timeout": 0}}},
            {"id": "ct-bn", "group": "constant-time", "court": "CT-PRIMITIVES",
             "classification": "measured", "evidence": {"verdict": "pass"}},
            {"id": "nc-parity", "group": "not-claimed", "court": None,
             "classification": "not-claimed"},
        ],
    }
    courts = {"body": {"courts": [
        {"court": "RT-HOSTILE-TLS", "probe": "courts/phase18/rt_hostile_tls_probe.c"},
        {"court": "RT-HOSTILE-X509", "probe": "courts/phase18/rt_hostile_x509_probe.c"},
    ]}}
    fuzz = {
        "probe": "artifacts/phase18/probes/rt_hostile_x509_probe.candidate",
        "corpus": "courts/phase18/fixtures/hostile-x509", "cases_requested": 100,
        "cases_driven": 100, "finding_count": 0, "findings": [], "classes": {"parse": 100},
        "tool": "forensics/tools/fuzz_hostile_corpus.py", "note": "a bounded mutational screen",
    }
    return {
        "census": None,
        "exposure": exposure,
        "p18_register": register,
        "p18_courts": courts,
        "p18_fuzz": fuzz,
    }


def _synth_census() -> dict:
    return {"sites": [{"site_id": f"us-s{i}"} for i in range(1, 7)]}


def self_test() -> int:
    """Prove the metadata-only admission holds, the derivation is clean and the control is honest."""
    failures: list = []

    admission = phase25_guard.evaluate(entry_point="ms_phase18_fuzz_crosswalk.py", env={},
                                       dockerenv=False)
    if not admission["admitted"] or admission["venue"] != "metadata-only":
        failures.append("ms_phase18_fuzz_crosswalk.py is not admitted as a metadata-only "
                        "generator on a host")

    census = _synth_census()
    authority = _synth_authority()
    body = build_body(census, authority)
    baseline = crosswalk_findings(body, census, authority)
    if baseline:
        failures.append(f"the synthetic crosswalk body is not clean: {baseline[:4]}")
    c = body["counts"]
    if (c["phase18_fuzz_targets"], c["sites_on_a_fuzzed_route"], c["sites_not_fuzzed"]) != (2, 5, 1):
        failures.append(f"the synthetic disposition counts are wrong: {c}")
    if c["routed_sites"] != 6 or c["sites_on_no_attacker_route"] != 0:
        failures.append(f"the synthetic routed counts are wrong: {c}")
    if c["routes_driven_by_phase18"] != 4 or c["routes_not_driven_by_phase18"] != 1:
        failures.append(f"the synthetic route counts are wrong: {c}")
    # The synthetic must exercise both residual classes and the mutational screen.
    classes = {r["class"] for r in body["residuals"]}
    if UNFUZZED_RESIDUAL_CLASS not in classes or OUT_OF_SCOPE_RESIDUAL_CLASS not in classes:
        failures.append(f"the synthetic residuals do not carry both classes: {sorted(classes)}")
    if not any("mutational_screen" in r for r in body["targets"].values()):
        failures.append("the synthetic crosswalk does not carry the mutational screen")
    control = crosswalk_sensitivity_control(body, census, authority)
    if not control["specificity_holds"] or control["caught"] != control["seeded"]:
        failures.append(f"the sensitivity control is not honest: {control}")

    if failures:
        print("[ms-phase18-fuzz-crosswalk] self-test FAILED")
        for f in failures:
            print(f"  {f}")
        return 1
    print("[ms-phase18-fuzz-crosswalk] self-test ok: the guard admits it as metadata-only; the "
          "synthetic crosswalk body is clean (2 hostile-fuzz targets, 5 fuzzed sites, 1 routed but "
          "unfuzzed site, 4 driven routes, a `evidence_missing` and an `out_of_scope` residual and "
          "a mutational screen); and all six seeded mutations (a dropped site, a covered target "
          "with no evidence, an inverse view that disagrees, a typed count, a coverage gap with no "
          "residual and a typed tool state) are caught with specificity holding")
    return 0


# --------------------------------------------------------------------------------------------
# entry points
# --------------------------------------------------------------------------------------------

def _write_planes(path: Path, doc: dict) -> None:
    """Write the plane compactly, key-sorted and deterministic.

    The plane carries thousands of sites, so pretty-printing would multiply the file without
    adding evidence; determinism is preserved (sorted keys, fixed separators) and `body_hash`
    covers the body.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    path.write_text(text, encoding="utf-8")


def _inputs() -> list:
    return [
        InputRef(name="phase-25-plan", path=PLAN),
        InputRef(name="memory-safety-schemas", path=SCHEMAS),
        InputRef(name="phase25-guard", path=GUARD),
        InputRef(name="phase25-container-manifest", path=MANIFEST),
        InputRef(name="ms-phase18-fuzz-crosswalk-tool", path=TOOL),
        InputRef(name="source-census", path=CENSUS),
        InputRef(name="exposure-classification", path=EXPOSURE),
        InputRef(name="phase18-hostile-boundary-register", path=P18_REGISTER),
        InputRef(name="phase18-courts", path=P18_COURTS),
        InputRef(name="phase18-fuzz-hostile-corpus", path=P18_FUZZ_CORPUS),
    ]


def _measure() -> int:
    """Derive the crosswalk from the committed census, routes and Phase-18 evidence, and write it."""
    census_body = ms_census.decode_body(_load(CENSUS).get("body", {}))
    refs = ms_codec.refs_from_census(census_body)
    authority = load_authority()
    body = build_body(census_body, authority)
    problems = crosswalk_findings(body, census_body, authority)

    auth = resolve_authority(PRODUCTION_AUTHORITY)
    encoded = ms_codec.encode_body(body, refs)
    doc = envelope(kind="phase25-phase18-fuzz-crosswalk", authority=auth.id, inputs=_inputs(),
                   body=encoded, generator=GENERATOR)
    doc["body_hash"] = content_hash(encoded)
    _write_planes(OUT, doc)

    c = body["counts"]
    print(f"[ms-phase18-fuzz-crosswalk] {c['sites_on_a_fuzzed_route']} fuzzed site(s), "
          f"{c['sites_not_fuzzed']} routed-but-unfuzzed, {c['sites_on_no_attacker_route']} on no "
          f"route, over {c['phase18_fuzz_targets']} Phase-18 target(s)")
    print("  fuzzed sites by target: "
          + ", ".join(f"{t}={n}" for t, n in sorted(c["fuzzed_sites_by_target"].items())))
    print(f"  routes driven: {c['routes_driven_by_phase18']}/{c['attacker_routes']}; "
          f"corpus entries: {c['corpus_entries']}; findings: {c['findings']}; "
          f"residuals: {len(body['residuals'])}")
    print(f"  -> {rel(OUT)} all_pass={not problems} (findings={len(body['findings'])})")
    if problems:
        for p in problems[:24]:
            print(f"    {p}")
    return 0 if not problems else 1


def _check() -> int:
    """Re-run the pure checks over the committed crosswalk, without a compiler."""
    if not OUT.is_file():
        print(f"[ms-phase18-fuzz-crosswalk] {rel(OUT)} is absent; run --measure")
        return 1
    census_body = ms_census.decode_body(_load(CENSUS).get("body", {}))
    body = _load(OUT).get("body", {})
    authority = load_authority()
    problems = crosswalk_findings(body, census_body, authority)
    if problems:
        print(f"[ms-phase18-fuzz-crosswalk] check FAILED: {len(problems)} problem(s)")
        for p in problems[:24]:
            print(f"  {p}")
        return 1
    c = derive_cached(census_body, authority)["counts"]
    print(f"[ms-phase18-fuzz-crosswalk] check ok: {c['sites_on_a_fuzzed_route']} fuzzed, "
          f"{c['sites_not_fuzzed']} routed-but-unfuzzed, {c['phase18_fuzz_targets']} target(s); "
          f"every check holds")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--measure", action="store_true",
                    help="derive artifacts/phase25/phase18-fuzz-crosswalk.json from the committed "
                         "inputs")
    ap.add_argument("--check", action="store_true",
                    help="re-run the pure checks over the committed crosswalk")
    ap.add_argument("--self-test", action="store_true",
                    help="prove the metadata-only admission and the control is honest")
    args = ap.parse_args(argv)

    # The Docker-only execution guard, called first. This tool executes nothing, so the manifest
    # lists it `metadata_only` and the guard admits it on any host.
    phase25_guard.require_admitted()

    if args.self_test:
        return self_test()
    if args.check:
        return _check()
    # The default action is the derivation (and `--measure` names it): `evidence_determinism.py`
    # regenerates every generator with no flags and compares the bytes.
    return _measure()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
