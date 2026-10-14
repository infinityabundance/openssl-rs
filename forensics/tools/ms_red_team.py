#!/usr/bin/env python3
"""Phase 25.18 -- the red team.

Attacks the atlas's own claims about the memory-safety profile and records, for each attempt, the
hypothesis it attacked, the method it reasoned with, the outcome and the evidence. Its subject is
the bounded claim the Phase-25 courts carry -- that the memory-safety-relevant trusted computing
base of the exact admitted candidate has been exhaustively inventoried, with unsafe operations
mapped to their safety contracts, their Phase-22 reachability, their Phase-24 downstream usage and
the available dynamic/formal evidence, and with no unexplained reachable unsafe site -- and it tries
to falsify it the way an adversary would:

  * a **reachable unsafe site the atlas left unexplained, UNKNOWN or unreachable**;
  * a **claimed-safe site that is in fact reachable** (a non-externally-reachable classification the
    committed Phase-22 typed edges reach from a public root);
  * an **`UNREACHABLE_PROFILE` / `NOT_REACHABLE` classification with no justified exclusion
    witness**;
  * a **claimed-eliminated mechanism** whose operation survives, an **unpreserved discovered
    failure**, or a **reachable site dropped** from a plane.

The method is **static reachability reasoning over the committed Phase-22 typed edges**, the
per-plane **witness / join audits**, and the committed **hostile corpus** -- never a second graph, a
re-typed edge or a fresh measurement. Each attempt's outcome is one of the closed vocabulary
`FOUND_GAP` / `NO_GAP` / `INCONCLUSIVE`:

  * `FOUND_GAP` -- the committed evidence contradicts the atlas's claim; it becomes a property
    finding **and** a residual (class `unexplained_reachable_unsafe`), never suppressed;
  * `INCONCLUSIVE` -- the method cannot settle the question from the committed evidence (e.g. a
    reachability grounded in an authored parser route the committed typed edges carry no edge for);
    it is recorded `inconclusive` with its reason and a residual (class `evidence_missing`), never a
    pass;
  * `NO_GAP` -- the committed evidence is consistent with the claim **under this method**; it is
    recorded as "no gap found under method X" and **is never proof of absence**.

Honesty is structural, not prose. A plane that asserts the absence of gaps from a **single** method,
that presents an **unreachable classification with no witness**, or that records a **gap with no
residual** is refused by name, and the sensitivity control seeds each such lie and requires it
caught. A passing red-team court therefore records that the attacks ran and their controls were
honest; it is not, and never is read as, a proof that the atlas is complete.

It is a **pure derivation**: it reads only committed planes -- the 25.7 exposure classification (the
classes, the justifications and the exclusion witnesses), the committed Phase-22 whole-program atlas
through 25.5's crosswalk, the 25.8 reduction axis, the 25.13 Phase-18 fuzz crosswalk and its hostile
corpus, the 25.14 downstream safety coverage, the 25.17 mechanism reconciliation, the 25.9-25.12
evidence planes (Miri, ASan/MSan, TSan, Kani) and the 25.16 replay index -- and it executes
nothing: no compiler, no tool, no probe. It is therefore **metadata-only** (the manifest lists it
and the guard admits it on any host).

Usage:
  python3 forensics/tools/ms_red_team.py --measure     # derive and write the plane
  python3 forensics/tools/ms_red_team.py --check       # re-run the pure checks
  python3 forensics/tools/ms_red_team.py --self-test   # metadata-only + control
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
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

# The Docker-only execution guard, called first. This tool executes nothing, so the manifest lists
# it `metadata_only` and the guard admits it on any host.
import phase25_guard  # noqa: E402

import memory_safety_schemas as schemas  # noqa: E402

import ms_census  # noqa: E402
import ms_codec  # noqa: E402

OUT = REPO_ROOT / "artifacts" / "phase25" / "red-team.json"
GENERATOR = "forensics/tools/ms_red_team.py"
TOOL = REPO_ROOT / "forensics" / "tools" / "ms_red_team.py"
SCHEMAS = REPO_ROOT / "forensics" / "tools" / "memory_safety_schemas.py"
GUARD = REPO_ROOT / "forensics" / "tools" / "phase25_guard.py"
PLAN = REPO_ROOT / "docs" / "PHASE-25-MEMORY-SAFETY-SUBPHASES.md"
MANIFEST = REPO_ROOT / "forensics" / "memory-safety" / "container.json"

# The committed planes the red team reads.
SOURCE_CENSUS = REPO_ROOT / "artifacts" / "phase25" / "source-census.json"
PHASE22_CROSSWALK = REPO_ROOT / "artifacts" / "phase25" / "phase22-crosswalk.json"
EXPOSURE = REPO_ROOT / "artifacts" / "phase25" / "exposure.json"
UNSAFE_REDUCTION = REPO_ROOT / "artifacts" / "phase25" / "unsafe-reduction.json"
PHASE18_FUZZ_CROSSWALK = REPO_ROOT / "artifacts" / "phase25" / "phase18-fuzz-crosswalk.json"
PHASE24_SAFETY_COVERAGE = REPO_ROOT / "artifacts" / "phase25" / "phase24-safety-coverage.json"
MECHANISMS = REPO_ROOT / "artifacts" / "phase25" / "mechanisms.json"
MIRI = REPO_ROOT / "artifacts" / "phase25" / "miri.json"
ASAN_MSAN = REPO_ROOT / "artifacts" / "phase25" / "asan-msan.json"
TSAN = REPO_ROOT / "artifacts" / "phase25" / "tsan.json"
KANI = REPO_ROOT / "artifacts" / "phase25" / "kani.json"
CVE_REPLAY_INDEX = REPO_ROOT / "artifacts" / "phase25" / "cve-replay" / "index.json"

SOURCE_CENSUS_REL = rel(SOURCE_CENSUS)
PHASE22_CROSSWALK_REL = rel(PHASE22_CROSSWALK)
EXPOSURE_REL = rel(EXPOSURE)
UNSAFE_REDUCTION_REL = rel(UNSAFE_REDUCTION)
PHASE18_FUZZ_CROSSWALK_REL = rel(PHASE18_FUZZ_CROSSWALK)
PHASE24_SAFETY_COVERAGE_REL = rel(PHASE24_SAFETY_COVERAGE)
MECHANISMS_REL = rel(MECHANISMS)
MIRI_REL = rel(MIRI)
ASAN_MSAN_REL = rel(ASAN_MSAN)
TSAN_REL = rel(TSAN)
KANI_REL = rel(KANI)
CVE_REPLAY_INDEX_REL = rel(CVE_REPLAY_INDEX)

# The closed method vocabulary: the ways an attack reasons over the committed evidence, and nothing
# else. `phase22_typed_edges` is the static reachability reasoning the plan names; the rest are the
# per-plane witness/join audits and the committed hostile corpus.
ATTACK_METHODS: tuple[str, ...] = (
    "phase22_typed_edges",
    "exposure_witness",
    "tool_witness",
    "reduction_join",
    "coverage_join",
    "fuzz_corpus",
    "mechanism_witness",
)

# The closed outcome vocabulary. An attack either contradicts the atlas (`FOUND_GAP`), is consistent
# with it under the method (`NO_GAP` -- "no gap found under method X", never proof of absence), or
# cannot be settled from the committed evidence (`INCONCLUSIVE`, with its reason).
OUTCOMES: tuple[str, ...] = ("FOUND_GAP", "NO_GAP", "INCONCLUSIVE")

# A red-team result may assert the absence of gaps only when it is grounded in more than one method:
# a single method -- however clean -- is a single way to be wrong, and "the red team that reasoned
# one way found nothing" is not "there is nothing".
MIN_METHODS_FOR_ABSENCE = 2

# The residual a genuine gap becomes: the reachable unsafe site the atlas left unexplained. An
# inconclusive attempt records the missing evidence instead.
RESIDUAL_CLASS_FOR_GAP = "unexplained_reachable_unsafe"
RESIDUAL_CLASS_FOR_INCONCLUSIVE = "evidence_missing"
# A tool's NOT_REACHABLE classification with no reason witness is a different leftover.
RESIDUAL_CLASS_FOR_UNWITNESSED_TOOL = "tool_not_reachable"

# The 25.16 replay states that demonstrate a memory-corruption path is present (a discovered
# failure a red team must find preserved rather than dropped).
REPLAY_MEMORY_FAULT_STATES = frozenset({
    "CANDIDATE_REPRODUCES_MEMORY_FAULT",
    "CANDIDATE_UNSAFE_PATH_REMAINS",
    "UPSTREAM_VULNERABLE_REPRODUCED",
})

# The mechanism-disposition vocabulary 25.17 uses, restated so the red team refuses a disposition
# outside it without reading 25.17's module.
MECHANISM_DISPOSITIONS = frozenset({
    "ELIMINATED", "RELOCATED_TO_BOUNDARY", "HIDDEN", "PRESENT", "UNRESOLVED",
})

# The committed evidence planes an attack may cite.
ALLOWED_EVIDENCE = frozenset({
    SOURCE_CENSUS_REL, PHASE22_CROSSWALK_REL, EXPOSURE_REL, UNSAFE_REDUCTION_REL,
    PHASE18_FUZZ_CROSSWALK_REL, PHASE24_SAFETY_COVERAGE_REL, MECHANISMS_REL,
    MIRI_REL, ASAN_MSAN_REL, TSAN_REL, KANI_REL, CVE_REPLAY_INDEX_REL,
})

# The witness audit classifications: the unreachable and not-reachable classes a reader could
# mistake for a clean result, each of which must carry a reason the committed plane recorded.
AUDITED_CLASSES: tuple[tuple[str, str], ...] = (
    ("MIRI_NOT_REACHABLE", MIRI_REL),
    ("ASAN_NOT_REACHABLE", ASAN_MSAN_REL),
    ("TSAN_NOT_REACHABLE", TSAN_REL),
)

NON_CLAIMS = (
    "a red-team outcome of `NO_GAP` is 'no gap found under this method', never proof that the "
    "atlas is complete: a method the red team did not run, a route the committed typed edges "
    "cannot witness, and a future input can each still conceal a gap, so absence of a found gap is "
    "not absence of a gap",
    "the red team reasons over the committed planes -- the Phase-22 typed edges and the per-plane "
    "witnesses and joins -- and never re-types an edge, builds a second call graph or stages a "
    "probe: a static attack can neither execute the candidate nor observe a race a schedule did "
    "not take, so it can refute a claim but never confirm a property",
    "`INCONCLUSIVE` is not `NO_GAP`: where the method cannot settle the question (a reachability "
    "grounded in an authored parser route the typed edges carry no edge for) the attempt is "
    "recorded inconclusive with its reason and an open residual, never read as a pass",
    "a passing `MS-RED-TEAM` court records that the attacks ran and that its controls were honest; "
    "it is an instrument, not a memory-safety property, and a pass is never 'the candidate is "
    "memory safe'",
    "the red team attacks the atlas's claims and the evidence a reader would take as those claims; "
    "it does not attack the candidate at runtime itself, which is the 25.9-25.16 evidence's job",
)


# --------------------------------------------------------------------------------------------
# small pure helpers
# --------------------------------------------------------------------------------------------

def _load(path: Path) -> dict:
    if not path.is_file():
        raise SystemExit(f"[ms-red-team] {rel(path)} is absent")
    return json.loads(path.read_text(encoding="utf-8"))


def _body(doc: dict) -> dict:
    return doc.get("body", doc)


def load_authority() -> dict:
    """The committed planes the red team reads, loaded once so the generator and court share bytes.

    Every columnar artefact is decoded through the one codec against the committed census's
    reference lists, so a plane is read the same way in the generator and in the court.
    """
    census_doc = _load(SOURCE_CENSUS)
    census_body = ms_census.decode_body(census_doc.get("body", census_doc))
    refs = ms_codec.refs_from_census(census_body)

    def dec(path: Path) -> dict:
        return ms_codec.decode_body(_body(_load(path)), refs)

    return {
        "source_census": census_body,
        "phase22_crosswalk": dec(PHASE22_CROSSWALK),
        "exposure": dec(EXPOSURE),
        "reduction": dec(UNSAFE_REDUCTION),
        "fuzz": dec(PHASE18_FUZZ_CROSSWALK),
        "coverage": dec(PHASE24_SAFETY_COVERAGE),
        "mechanisms": dec(MECHANISMS),
        "tools": {"miri": dec(MIRI), "asan": dec(ASAN_MSAN), "tsan": dec(TSAN), "kani": dec(KANI)},
        "cve_replay": dec(CVE_REPLAY_INDEX),
    }


def _sample(ids: list, n: int = 8) -> list:
    return [str(i) for i in ids[:n]]


# --------------------------------------------------------------------------------------------
# the witness audit: every unreachable/not-reachable classification and its witness
# --------------------------------------------------------------------------------------------

def witness_audit(authority: dict) -> list:
    """Every unreachable-classification and its committed witness.

    A reader could take `UNREACHABLE_PROFILE` or a tool's `NOT_REACHABLE` as a clean result; each
    entry records the sites that carry it, the sites that carry it with **no** committed witness,
    and the witness the committed plane recorded. An entry with sites and no witness is a gap, not
    a pass, and the court refuses the plane that presents one as such.
    """
    audit: list = []
    exp = authority["exposure"]
    esites = exp["sites"]
    unreachable = sorted(sid for sid, e in esites.items() if e.get("e") == "UNREACHABLE_PROFILE")
    unwit = [sid for sid in unreachable if not esites[sid].get("j")]
    kinds = exp.get("rule", {}).get("exclusion_witness_kinds") or []
    audit.append({
        "classification": "UNREACHABLE_PROFILE",
        "plane": EXPOSURE_REL,
        "count": len(unreachable),
        "unwitnessed": len(unwit),
        "witness": (", ".join(str(k) for k in kinds) if unreachable else
                    "no site carries the class in the committed profile"),
        "gap": bool(unwit),
    })
    for label, plane_rel in AUDITED_CLASSES:
        plane = next((authority["tools"][k] for k, r in
                      (("miri", MIRI_REL), ("asan", ASAN_MSAN_REL), ("tsan", TSAN_REL))
                      if r == plane_rel), {})
        sites = plane.get("sites") or {}
        nr = [s for s in sites.values() if str(s.get("state") or "").endswith("NOT_REACHABLE")]
        reasons = sorted({str(s.get("reason") or "") for s in nr if str(s.get("reason") or "")})
        unwit_n = [s for s in nr if not str(s.get("reason") or "")]
        audit.append({
            "classification": label,
            "plane": plane_rel,
            "count": len(nr),
            "unwitnessed": len(unwit_n),
            "witness": (", ".join(reasons) if reasons
                        else ("no site carries the classification" if not nr else "")),
            "gap": bool(unwit_n),
        })
    return audit


# --------------------------------------------------------------------------------------------
# the derivation
# --------------------------------------------------------------------------------------------

_DERIVE_CACHE: dict = {}


def derive_cached(authority: dict) -> dict:
    """`derive` memoised by the identity of its argument (pure and deterministic)."""
    key = id(authority)
    if key not in _DERIVE_CACHE:
        _DERIVE_CACHE[key] = derive(authority)
    return _DERIVE_CACHE[key]


def derive(authority: dict) -> dict:
    """The whole red team, derived: the attacks, the residuals, the witness audit and the counts."""
    exp = authority["exposure"]
    px = authority["phase22_crosswalk"]
    cov = authority["coverage"]
    red = authority["reduction"]
    fuzz = authority["fuzz"]
    mech = authority["mechanisms"]
    tools = authority["tools"]
    replay = authority["cve_replay"]

    esites = exp["sites"]
    psites = px["sites"]
    csites = cov["sites"]
    justs = exp.get("justifications") or {}
    ext = sorted(sid for sid, e in esites.items()
                 if e.get("e") in schemas.EXTERNALLY_REACHABLE_EXPOSURE)
    ext_set = set(ext)

    attacks: list = []
    residuals: list = []

    def add(attack_id, method, hypothesis, target, outcome, detail, evidence,
            site_count, witness=None, samples=None, amount=None):
        rec = {
            "attack_id": attack_id,
            "method": method,
            "hypothesis": hypothesis,
            "target": target,
            "outcome": outcome,
            "detail": detail,
            "evidence": list(evidence),
            "site_count": int(site_count),
        }
        if witness is not None:
            rec["witness"] = witness
        if samples:
            rec["sample_site_ids"] = _sample(samples)
        if amount is not None:
            rec["amount"] = int(amount)
        if outcome in ("FOUND_GAP", "INCONCLUSIVE"):
            klass = (RESIDUAL_CLASS_FOR_GAP if outcome == "FOUND_GAP"
                     else RESIDUAL_CLASS_FOR_INCONCLUSIVE)
            resid = {
                "residual_id": f"rt-res-{attack_id}",
                "subject": attack_id,
                "class": klass,
                "disposition": "open",
                "detail": detail,
                "evidence": list(evidence),
            }
            if amount is not None:
                resid["site_count"] = int(amount)
            residuals.append(resid)
            rec["residual_id"] = resid["residual_id"]
        attacks.append(rec)

    # -- exposure_witness: the exposure plane's own reachability claims ----------------------
    unreachable = sorted(sid for sid, e in esites.items() if e.get("e") == "UNREACHABLE_PROFILE")
    unwit_unreachable = [sid for sid in unreachable if not esites[sid].get("j")]
    add(
        "rt-exposure-unreachable-witness", "exposure_witness",
        "no site is classified UNREACHABLE_PROFILE without a justified exclusion witness recorded "
        "on it",
        f"{EXPOSURE_REL}#UNREACHABLE_PROFILE",
        "FOUND_GAP" if unwit_unreachable else "NO_GAP",
        (f"{len(unreachable)} site(s) carry UNREACHABLE_PROFILE and {len(unwit_unreachable)} carry "
         f"it with no justification; "
         + ("the class is vacuous -- no site carries it in the committed profile -- so the claim "
            "holds vacuously, which is not evidence that no site could" if not unreachable else
            "a site the atlas calls unreachable with no witness is a gap")),
        [EXPOSURE_REL, PHASE22_CROSSWALK_REL], len(unreachable),
        witness=", ".join(str(k) for k in (exp.get("rule", {}).get("exclusion_witness_kinds") or [])),
        samples=unwit_unreachable, amount=len(unwit_unreachable) or None,
    )

    unknown = sorted(sid for sid, e in esites.items() if e.get("e") == "UNKNOWN_REACHABILITY")
    cov_unknown_observed = [sid for sid, s in csites.items()
                            if s.get("exposure") == "UNKNOWN_REACHABILITY"
                            and s.get("state") == "DOWNSTREAM_OBSERVED"]
    named_unknown = "UNKNOWN_REACHABILITY" in (cov["counts"].get("not_reachable_by_exposure") or {})
    add(
        "rt-exposure-unknown-not-read-safe", "exposure_witness",
        "no UNKNOWN_REACHABILITY site is read as non-reachable or as observed downstream, so an "
        "unknown is never presented as a clean result",
        f"{EXPOSURE_REL}#UNKNOWN_REACHABILITY",
        "FOUND_GAP" if (cov_unknown_observed or not named_unknown) else "NO_GAP",
        (f"{len(unknown)} site(s) are UNKNOWN_REACHABILITY; the 25.14 coverage plane names them "
         f"separately among the not-reachable-by-exposure ({named_unknown}) and "
         f"{len(cov_unknown_observed)} of them is read as observed downstream"),
        [EXPOSURE_REL, PHASE24_SAFETY_COVERAGE_REL], len(unknown),
        samples=cov_unknown_observed, amount=len(cov_unknown_observed) or None,
    )

    ungrounded = [sid for sid in ext
                  if not (psites.get(sid) or {}).get("roots")
                  and not (psites.get(sid) or {}).get("residual")]
    add(
        "rt-exposure-external-ungrounded", "exposure_witness",
        "every externally reachable site is grounded in committed evidence -- a Phase-22 reachable "
        "root or a recorded unresolved/exclusion residual -- and none is claimed external with no "
        "grounding at all",
        f"{EXPOSURE_REL}#EXTERNALLY_REACHABLE",
        "FOUND_GAP" if ungrounded else "NO_GAP",
        (f"{len(ext)} site(s) are externally reachable and {len(ungrounded)} carries neither a "
         f"Phase-22 reachable root nor a committed residual, so its reachability would be asserted "
         f"with no committed grounding"),
        [EXPOSURE_REL, PHASE22_CROSSWALK_REL], len(ext),
        samples=ungrounded, amount=len(ungrounded) or None,
    )

    # -- phase22_typed_edges: static reachability reasoning over the committed typed edges ----
    overstated = [sid for sid, e in esites.items()
                  if e.get("e") not in schemas.EXTERNALLY_REACHABLE_EXPOSURE
                  and (psites.get(sid) or {}).get("roots")]
    add(
        "rt-phase22-overstated-nonreachable", "phase22_typed_edges",
        "no non-externally-reachable site is reached by a public Phase-22 root, so no claimed-safe "
        "site is in fact reachable through the committed typed edges",
        f"{PHASE22_CROSSWALK_REL}#roots",
        "FOUND_GAP" if overstated else "NO_GAP",
        (f"{len(esites)} site(s) audited; {len(overstated)} carries a public reachable root yet a "
         f"non-externally-reachable exposure class, which would be a claimed-safe site the typed "
         f"edges reach"),
        [EXPOSURE_REL, PHASE22_CROSSWALK_REL], len(esites),
        samples=overstated, amount=len(overstated) or None,
    )

    unwitnessed_ext = [sid for sid in ext if not (psites.get(sid) or {}).get("roots")]
    justified = {sid: (esites[sid].get("j") in justs) for sid in unwitnessed_ext}
    all_justified = all(justified.values())
    add(
        "rt-phase22-unwitnessed-external", "phase22_typed_edges",
        "every externally reachable site's reachability is witnessed by a committed Phase-22 typed "
        "edge from a public root",
        f"{PHASE22_CROSSWALK_REL}#roots vs {EXPOSURE_REL}#justifications",
        ("NO_GAP" if not unwitnessed_ext
         else ("INCONCLUSIVE" if all_justified else "FOUND_GAP")),
        (f"{len(ext)} site(s) are externally reachable and {len(unwitnessed_ext)} has no Phase-22 "
         f"reachable root; "
         + ("each is nevertheless grounded in a committed parser-route justification, and the "
            "committed typed edges carry no edge for a local-file route, so the typed-edge method "
            "can neither witness nor refute it -- recorded inconclusive, not a pass"
            if all_justified else
            "at least one is grounded in no committed evidence at all, which is a gap")),
        [PHASE22_CROSSWALK_REL, EXPOSURE_REL], len(ext),
        witness=("parser-route justification" if all_justified else None),
        samples=unwitnessed_ext, amount=len(unwitnessed_ext) or None,
    )

    # -- coverage_join: the 25.14 downstream safety coverage ----------------------------------
    no_cov = [sid for sid in ext if sid not in csites]
    add(
        "rt-coverage-unexplained-reachable", "coverage_join",
        "every externally reachable site carries a 25.14 coverage row, so no reachable unsafe site "
        "is left with no downstream disposition at all",
        f"{PHASE24_SAFETY_COVERAGE_REL}#sites",
        "FOUND_GAP" if no_cov else "NO_GAP",
        (f"{len(ext)} externally reachable site(s); {len(no_cov)} has no coverage row, so its "
         f"absence from every downstream run would be an omission rather than a recorded "
         f"REACHABLE_UNOBSERVED state"),
        [PHASE24_SAFETY_COVERAGE_REL, EXPOSURE_REL], len(ext),
        samples=no_cov, amount=len(no_cov) or None,
    )

    bad_cov = [sid for sid, s in csites.items()
               if (s.get("state") == "REACHABLE_UNOBSERVED" and (s.get("observed_by") or []))
               or (s.get("state") == "DOWNSTREAM_OBSERVED" and not (s.get("observed_by") or []))]
    add(
        "rt-coverage-state-contradiction", "coverage_join",
        "no coverage row's state contradicts its observed_by list -- an unobserved site is not "
        "presented as observed and an observed site is not presented as unobserved",
        f"{PHASE24_SAFETY_COVERAGE_REL}#sites",
        "FOUND_GAP" if bad_cov else "NO_GAP",
        (f"{len(csites)} coverage row(s) audited; {len(bad_cov)} contradicts its own observed_by "
         f"list, so a site would be read as exercised or not against its own record"),
        [PHASE24_SAFETY_COVERAGE_REL], len(csites),
        samples=bad_cov, amount=len(bad_cov) or None,
    )

    # -- reduction_join: the 25.8 reduction axis ---------------------------------------------
    census_sites = len(authority["source_census"].get("sites") or [])
    red_after = int(red.get("counts", {}).get("reachable_after") or 0)
    worklist_ids = [str(i) for entry in (red.get("worklist") or [])
                    for i in ((entry.get("sites") or {}).get("sample_site_ids") or [])]
    fabricated = [sid for sid in worklist_ids if sid not in esites]
    dropped = (red_after != len(ext)) or bool(fabricated)
    add(
        "rt-reduction-dropped-reachable", "reduction_join",
        "the reduction axis drops no reachable unsafe site from the shipped profile and names no "
        "site the census does not carry -- a reachable site removed by a reconstruction is "
        "classified, never silently dropped",
        f"{UNSAFE_REDUCTION_REL}#counts",
        "FOUND_GAP" if dropped else "NO_GAP",
        (f"the reconstruction's post-axis reachable count is {red_after} and the exposure plane's "
         f"externally reachable count is {len(ext)} (the shipped census carries {census_sites} "
         f"sites); {len(fabricated)} worklist sample id(s) are not census sites"),
        [UNSAFE_REDUCTION_REL, EXPOSURE_REL, SOURCE_CENSUS_REL], census_sites,
        samples=fabricated, amount=1 if dropped else None,
    )

    # -- fuzz_corpus: the committed hostile corpus and the discovered failures -----------------
    failures = []
    for key, plane in tools.items():
        for sid, s in (plane.get("sites") or {}).items():
            if str(s.get("state") or "").endswith("FAIL"):
                failures.append((key, str(sid), s))
    memfault = [r for r in (replay.get("replays") or [])
                if r.get("state") in REPLAY_MEMORY_FAULT_STATES]
    unpreserved = [(k, sid) for k, sid, s in failures if not str(s.get("disposition") or "").strip()]
    add(
        "rt-fuzz-unpreserved-failure", "fuzz_corpus",
        "every memory-safety failure the committed evidence discovered -- a Miri/ASan/TSan FAIL or "
        "a 25.16 replay memory fault -- is preserved with a disposition, never dropped",
        f"{MIRI_REL}#sites",
        "FOUND_GAP" if (unpreserved or any(not r.get("residuals") for r in memfault)) else "NO_GAP",
        (f"{len(failures)} tool FAIL site(s) and {len(memfault)} replay memory-fault record(s) "
         f"audited; {len(unpreserved)} FAIL site(s) carry no disposition and {len(memfault)} "
         f"memory-fault record(s) are present as preserved replay records"),
        [MIRI_REL, ASAN_MSAN_REL, TSAN_REL, CVE_REPLAY_INDEX_REL], len(failures),
        samples=[sid for _k, sid in unpreserved], amount=len(unpreserved) or None,
    )

    fuzz_sites = fuzz.get("sites") or {}
    misread = [sid for sid, s in fuzz_sites.items()
               if s.get("state") == "FUZZED" and not (s.get("targets") or [])]
    add(
        "rt-fuzz-untargeted-site-misread", "fuzz_corpus",
        "no site is recorded FUZZED without a Phase-18 target -- a site on an attacker route no "
        "target drives is recorded NOT_FUZZED with its reason, never read as fuzzed",
        f"{PHASE18_FUZZ_CROSSWALK_REL}#sites",
        "FOUND_GAP" if (misread or int(fuzz.get("counts", {}).get("findings") or 0) != 0) else "NO_GAP",
        (f"{len(fuzz_sites)} site(s) carry a fuzz state; {len(misread)} is FUZZED with no target; "
         f"the committed hostile corpus reports "
         f"{int(fuzz.get('counts', {}).get('findings') or 0)} finding(s) and "
         f"{int(fuzz.get('counts', {}).get('mutational_screen_findings') or 0)} mutational-screen "
         f"finding(s)"),
        [PHASE18_FUZZ_CROSSWALK_REL, EXPOSURE_REL], len(fuzz_sites),
        samples=misread, amount=len(misread) or None,
    )

    # -- mechanism_witness: the 25.17 mechanism reconciliation --------------------------------
    mechanisms = mech.get("mechanisms") or []
    res_ids = {str(r.get("residual_id")) for r in (mech.get("residuals") or [])}
    not_extinct_no_resid = [m.get("mechanism_id") for m in mechanisms
                            if m.get("disposition") != "ELIMINATED"
                            and f"res-mech-{m.get('mechanism_id')}" not in res_ids]
    add(
        "rt-mechanism-nonextinct-no-residual", "mechanism_witness",
        "every non-extinct mechanism carries an open residual, so a surviving operation is never "
        "read as extinct without a recorded leftover",
        f"{MECHANISMS_REL}#mechanisms",
        "FOUND_GAP" if not_extinct_no_resid else "NO_GAP",
        (f"{len(mechanisms)} mechanism(s) reconciled; "
         f"{len(not_extinct_no_resid)} is non-extinct with no residual"),
        [MECHANISMS_REL, UNSAFE_REDUCTION_REL], len(mechanisms),
        samples=not_extinct_no_resid, amount=len(not_extinct_no_resid) or None,
    )

    outside_disp = [m.get("mechanism_id") for m in mechanisms
                    if m.get("disposition") not in MECHANISM_DISPOSITIONS]
    add(
        "rt-mechanism-disposition-vocabulary", "mechanism_witness",
        "every mechanism disposition is in the closed vocabulary, so no mechanism is described "
        "outside the classes the reconciliation can mean",
        f"{MECHANISMS_REL}#mechanisms",
        "FOUND_GAP" if outside_disp else "NO_GAP",
        (f"{len(mechanisms)} mechanism(s) reconciled; {len(outside_disp)} carries a disposition "
         f"outside {sorted(MECHANISM_DISPOSITIONS)}"),
        [MECHANISMS_REL], len(mechanisms),
        samples=outside_disp, amount=len(outside_disp) or None,
    )

    # -- tool_witness: the dynamic planes' NOT_REACHABLE classifications ----------------------
    audit = witness_audit(authority)
    tool_unwit = [a for a in audit
                  if a["classification"] != "UNREACHABLE_PROFILE" and a["unwitnessed"] > 0]
    nr_total = sum(a["count"] for a in audit if a["classification"] != "UNREACHABLE_PROFILE")
    add(
        "rt-tool-not-reachable-witness", "tool_witness",
        "no tool NOT_REACHABLE classification lacks a committed reason witness, so a site the "
        "instrument did not reach is recorded with why rather than read as clean",
        f"{MIRI_REL}#sites",
        "FOUND_GAP" if tool_unwit else "NO_GAP",
        (f"{nr_total} tool NOT_REACHABLE classification(s) audited across Miri/ASan/TSan; "
         f"{sum(a['unwitnessed'] for a in tool_unwit)} carries no reason witness"),
        [MIRI_REL, ASAN_MSAN_REL, TSAN_REL], nr_total,
        witness=", ".join(a["classification"] for a in audit
                          if a["classification"] != "UNREACHABLE_PROFILE"),
        samples=[a["classification"] for a in tool_unwit], amount=len(tool_unwit) or None,
    )

    attacks.sort(key=lambda a: a["attack_id"])
    residuals.sort(key=lambda r: r["residual_id"])
    return {"attacks": attacks, "residuals": residuals, "witness_audit": audit}


def _counts(d: dict) -> dict:
    attacks = d["attacks"]
    by_outcome = Counter(a["outcome"] for a in attacks)
    by_method = Counter(a["method"] for a in attacks)
    return {
        "attacks": len(attacks),
        "methods": len(by_method),
        "by_outcome": {k: by_outcome[k] for k in OUTCOMES if by_outcome[k]},
        "by_method": dict(sorted(by_method.items())),
        "found_gap": by_outcome.get("FOUND_GAP", 0),
        "no_gap": by_outcome.get("NO_GAP", 0),
        "inconclusive": by_outcome.get("INCONCLUSIVE", 0),
        "sites_attacked": sum(int(a.get("site_count") or 0) for a in attacks),
        "residuals": len(d["residuals"]),
        "witness_audit_entries": len(d["witness_audit"]),
        "unwitnessed_classifications": sum(int(a.get("unwitnessed") or 0) for a in d["witness_audit"]),
    }


def _absence_claim(d: dict) -> dict:
    attacks = d["attacks"]
    methods = sorted({a["method"] for a in attacks})
    gaps = [a["attack_id"] for a in attacks if a["outcome"] == "FOUND_GAP"]
    asserted = not gaps
    by_outcome = Counter(a["outcome"] for a in attacks)
    return {
        "asserted": asserted,
        "methods": methods,
        "min_methods": MIN_METHODS_FOR_ABSENCE,
        "found_gap": len(gaps),
        "statement": (
            "the red team found no genuine gap across "
            f"{len(methods)} method(s) over {len(attacks)} attack(s) "
            f"({', '.join(f'{k}={by_outcome[k]}' for k in OUTCOMES if by_outcome[k])}); "
            "an inconclusive attack is not a pass, and this is not proof of the atlas's "
            "completeness: no single method can establish it, and an unexercised method or a route "
            "the committed typed edges cannot witness may still conceal a gap"
        ),
    }


def _property_findings(d: dict) -> list:
    c = _counts(d)
    by_outcome = ", ".join(f"{k}={v}" for k, v in sorted(c["by_outcome"].items()))
    by_method = ", ".join(f"{k}={v}" for k, v in sorted(c["by_method"].items()))
    inconcl = [a["attack_id"] for a in d["attacks"] if a["outcome"] == "INCONCLUSIVE"]
    gaps = [a["attack_id"] for a in d["attacks"] if a["outcome"] == "FOUND_GAP"]
    return [
        f"{c['attacks']} red-team attack(s) were run across {c['methods']} method(s) over "
        f"{c['sites_attacked']} site(s): by outcome {by_outcome}; by method {by_method}",
        f"{c['found_gap']} genuine gap(s) were found and {c['inconclusive']} attack(s) are "
        f"inconclusive; the attacks that found nothing are recorded as 'no gap found under method "
        f"X', which is never proof of absence",
        ("the inconclusive attack(s) are named rather than smoothed over: "
         + (", ".join(sorted(inconcl)) if inconcl else "none")),
        ("a genuine gap is a property finding and a residual, never suppressed: "
         + (", ".join(sorted(gaps)) if gaps else
            "none was found, so no residual is owed to a gap")),
        f"every unreachable/not-reachable classification was audited for a committed witness "
        f"({c['witness_audit_entries']} classification(s), {c['unwitnessed_classifications']} "
        f"unwitnessed site(s)), so an unreachable classification without a witness is a finding",
        "a passing red-team court records that the attacks ran and their controls were honest; it "
        "is an instrument, not a memory-safety property, and its clean result is not read as 'the "
        "atlas is complete' or 'the candidate is memory safe'",
    ]


def build_body(authority: dict) -> dict:
    """The red-team body: the rule, the attacks, the witness audit, the counts and the residuals."""
    d = derive_cached(authority)
    return {
        "rule": _rule(),
        "attacks": d["attacks"],
        "witness_audit": d["witness_audit"],
        "counts": _counts(d),
        "absence_claim": _absence_claim(d),
        "residuals": d["residuals"],
        "findings": _property_findings(d),
        "non_claims": list(NON_CLAIMS),
    }


def _rule() -> dict:
    return {
        "attacker_model": (
            "the red team tries to falsify the atlas's bounded claim -- no unexplained reachable "
            "unsafe site -- by hunting a reachable site the atlas left unexplained, UNKNOWN or "
            "unreachable; a claimed-safe site the committed Phase-22 typed edges reach from a "
            "public root; an UNREACHABLE_PROFILE or NOT_REACHABLE classification with no witness; "
            "an unpreserved discovered failure; or a reachable site dropped from a plane"
        ),
        "methods": list(ATTACK_METHODS),
        "outcomes": list(OUTCOMES),
        "method_rule": (
            "an attack reasons only over the committed planes -- the Phase-22 typed edges (static "
            "reachability), the per-plane witnesses and joins, and the committed hostile corpus -- "
            "and never re-types an edge, builds a second graph or stages a probe"
        ),
        "outcome_rule": (
            "FOUND_GAP contradicts the atlas and owes a finding and a residual; INCONCLUSIVE cannot "
            "be settled from the committed evidence and is recorded with its reason; NO_GAP is 'no "
            "gap found under this method' and is never proof of absence"
        ),
        "absence_rule": (
            f"the plane may assert the absence of gaps only with at least {MIN_METHODS_FOR_ABSENCE} "
            f"distinct methods and no FOUND_GAP attack; a single-method absence claim is refused"
        ),
        "witness_rule": (
            "an UNREACHABLE_PROFILE or tool NOT_REACHABLE classification with sites and no "
            "committed witness is a gap, not a pass, and is refused by name"
        ),
        "residual_rule": (
            f"a FOUND_GAP becomes a residual of class `{RESIDUAL_CLASS_FOR_GAP}`; an INCONCLUSIVE "
            f"attempt a residual of class `{RESIDUAL_CLASS_FOR_INCONCLUSIVE}`; an unwitnessed tool "
            f"classification of class `{RESIDUAL_CLASS_FOR_UNWITNESSED_TOOL}`"
        ),
        "sort_key": "attacks by attack_id; residuals by residual_id; witness_audit by classification",
        "evidence": sorted(ALLOWED_EVIDENCE),
    }


# --------------------------------------------------------------------------------------------
# the pure checks: what the court runs over the committed artefact
# --------------------------------------------------------------------------------------------

def red_team_findings(body: dict, authority: dict) -> list:
    """Every way the committed red-team plane contradicts the committed evidence.

    Pure over `body` and the authority (the 25.7 exposure classification, the committed Phase-22
    atlas through 25.5's crosswalk, the 25.8 reduction axis, the 25.13 fuzz crosswalk, the 25.14
    coverage, the 25.17 mechanisms, the 25.9-25.12 evidence planes and the 25.16 replay index): it
    is what the `MS-RED-TEAM` court runs. It establishes that every attack is in the closed method
    and outcome vocabulary with committed evidence; that a genuine gap is a finding **and** a
    residual and an inconclusive attempt carries its residual; that the absence claim rests on more
    than one method and never coexists with a gap; that no unreachable classification is presented
    without a witness; that the witness audit, the counts and the whole plane equal their
    derivation; and that the plane never asserts the atlas is complete.
    """
    problems: list = []
    d = derive_cached(authority)
    attacks = body.get("attacks")
    if not isinstance(attacks, list):
        return ["the red-team plane's `attacks` is not a list"]

    ids = [str(a.get("attack_id")) for a in attacks]
    if len(set(ids)) != len(ids):
        problems.append("the plane carries a duplicate attack_id, so an outcome is ambiguous")

    for a in attacks:
        aid = str(a.get("attack_id"))
        for field in ("attack_id", "method", "hypothesis", "target", "outcome", "detail", "evidence"):
            if not a.get(field):
                problems.append(f"{aid}: missing required field {field!r}")
        if a.get("method") not in ATTACK_METHODS:
            problems.append(f"{aid}: method {a.get('method')!r} is not in the closed red-team method "
                            f"vocabulary")
        if a.get("outcome") not in OUTCOMES:
            problems.append(f"{aid}: outcome {a.get('outcome')!r} is not in the closed red-team "
                            f"outcome vocabulary")
        ev = a.get("evidence") or []
        if not ev:
            problems.append(f"{aid}: the attack cites no committed evidence")
        for e in ev:
            if str(e) not in ALLOWED_EVIDENCE:
                problems.append(f"{aid}: the cited evidence {e!r} is not a committed evidence plane")

    # A genuine gap is a residual, and an inconclusive attempt is a residual; neither is dropped.
    residuals = body.get("residuals") or []
    by_subject = {}
    for r in residuals:
        by_subject.setdefault(str(r.get("subject")), []).append(r)
    for a in attacks:
        aid = str(a.get("attack_id"))
        owed = (RESIDUAL_CLASS_FOR_GAP if a.get("outcome") == "FOUND_GAP"
                else RESIDUAL_CLASS_FOR_INCONCLUSIVE if a.get("outcome") == "INCONCLUSIVE" else None)
        if owed is None:
            continue
        mine = by_subject.get(aid, [])
        if not mine:
            problems.append(f"{aid}: a {a.get('outcome')} attack with no residual (a gap is never "
                            f"suppressed and an inconclusive attempt is never read as a pass)")
        elif not any(str(r.get("class")) == owed for r in mine):
            problems.append(f"{aid}: a {a.get('outcome')} attack whose residual is not of class "
                            f"{owed!r}")
    for r in residuals:
        problems += [f"residual[{r.get('residual_id')}]: {p}"
                     for p in schemas.validate("residual", r)]

    # The witness audit: an unreachable/not-reachable classification with sites needs a witness.
    audit = body.get("witness_audit") or []
    for e in audit:
        c = int(e.get("count") or 0)
        w = str(e.get("witness") or "").strip()
        if c > 0 and not w and not e.get("gap"):
            problems.append(f"{e.get('classification')}: an unreachable classification with {c} "
                            f"site(s) and no committed witness is presented as a clean result")
        if int(e.get("unwitnessed") or 0) > c:
            problems.append(f"{e.get('classification')}: the unwitnessed count exceeds the count")

    # The absence claim: never from a single method, never alongside a gap.
    claim = body.get("absence_claim") or {}
    if claim.get("asserted"):
        methods = claim.get("methods") or []
        if len(set(methods)) < MIN_METHODS_FOR_ABSENCE:
            problems.append(f"the plane claims the absence of gaps from {len(set(methods))} "
                            f"method(s); a single-method absence claim is refused")
        if any(a.get("outcome") == "FOUND_GAP" for a in attacks):
            problems.append("the plane asserts the absence of gaps while a FOUND_GAP attack is "
                            "recorded")
    if body.get("atlas_complete") or body.get("complete"):
        problems.append("the plane asserts the atlas is complete, which a red team can never do")
    if not body.get("non_claims"):
        problems.append("the plane records no non-claim, so a clean result could be read as "
                        "completeness")

    # The whole plane is the derivation.
    if attacks != d["attacks"]:
        derived_ids = {str(x["attack_id"]) for x in d["attacks"]}
        for aid in sorted(derived_ids - set(ids)):
            problems.append(f"the plane omits the derived attack {aid} (dropped)")
        for aid in sorted(set(ids) - derived_ids):
            problems.append(f"the plane records the attack {aid}, which the committed evidence does "
                            f"not derive")
        if (set(ids) == derived_ids):
            problems.append("the plane's attacks are not the derived attacks (a field was typed)")
    if audit != d["witness_audit"]:
        problems.append("the committed witness audit is not the derived witness audit")
    if (body.get("counts") or {}) != _counts(d):
        problems.append("the committed `counts` is not the derived `counts`")
    if (body.get("absence_claim") or {}) != _absence_claim(d):
        problems.append("the committed `absence_claim` is not the derived `absence_claim`")
    if (body.get("residuals") or []) != d["residuals"]:
        problems.append("the committed `residuals` is not the derived `residuals`")
    return problems


def red_team_sensitivity_control(body: dict, authority: dict) -> dict:
    """Seed eight mutations and require each caught, with specificity holding.

    Each is a distinct way a red team could lie about its own honesty: a gap with no residual; an
    absence claim from a single method; an unreachable classification with no witness; a typed
    count; an outcome outside the vocabulary; a dropped attack; an absence claim that coexists
    with a gap; and a method outside the vocabulary.
    """
    baseline = red_team_findings(body, authority)
    result: dict = {"baseline_findings": len(baseline), "honest": not baseline,
                    "specificity_holds": False, "mutations": {}}

    def clone() -> dict:
        return json.loads(json.dumps(body))

    def check(label: str, mutated: dict, marker: str) -> bool:
        found = red_team_findings(mutated, authority)
        caught = any(marker in f for f in found)
        result["mutations"][label] = {"caught": caught, "findings": len(found),
                                      "delta": len(found) - len(baseline), "marker": marker}
        return caught

    # m1: a genuine gap with no residual (a FOUND_GAP attack injected with no residual owed).
    def gap_without_residual() -> dict:
        b = clone()
        b["attacks"].append({
            "attack_id": "rt-injected-gap", "method": "phase22_typed_edges",
            "hypothesis": "an injected gap", "target": PHASE22_CROSSWALK_REL,
            "outcome": "FOUND_GAP", "detail": "an injected reachable site", "evidence": [EXPOSURE_REL],
            "site_count": 1,
        })
        return b

    m1 = check("gap_without_residual", gap_without_residual(), "with no residual")

    # m2: an absence claim from a single method.
    def single_method_absence() -> dict:
        b = clone()
        b["absence_claim"]["asserted"] = True
        b["absence_claim"]["methods"] = ["phase22_typed_edges"]
        return b

    m2 = check("absence_from_single_method", single_method_absence(),
               "single-method absence claim")

    # m3: an unreachable classification with no witness.
    def unreachable_without_witness() -> dict:
        b = clone()
        entry = next((e for e in b["witness_audit"] if int(e.get("count") or 0) > 0),
                     b["witness_audit"][-1])
        entry["witness"] = ""
        entry["gap"] = False
        return b

    m3 = check("unreachable_without_witness", unreachable_without_witness(),
               "no committed witness")

    # m4: a typed count.
    def typed_count() -> dict:
        b = clone()
        b["counts"]["attacks"] = int(b["counts"].get("attacks", 0)) + 1
        return b

    m4 = check("typed_count", typed_count(), "not the derived `counts`")

    # m5: an outcome outside the closed vocabulary.
    def outside_outcome() -> dict:
        b = clone()
        b["attacks"][0]["outcome"] = "MAGIC"
        return b

    m5 = check("outcome_outside_vocabulary", outside_outcome(),
               "not in the closed red-team outcome vocabulary")

    # m6: a derived attack silently dropped.
    def drop_attack() -> dict:
        b = clone()
        b["attacks"] = b["attacks"][1:]
        return b

    m6 = check("attack_dropped", drop_attack(), "omits the derived attack")

    # m7: an absence claim that coexists with a gap.
    def absence_with_gap() -> dict:
        b = clone()
        b["attacks"].append({
            "attack_id": "rt-injected-gap", "method": "phase22_typed_edges",
            "hypothesis": "an injected gap", "target": PHASE22_CROSSWALK_REL,
            "outcome": "FOUND_GAP", "detail": "an injected reachable site", "evidence": [EXPOSURE_REL],
            "site_count": 1, "residual_id": "rt-res-rt-injected-gap",
        })
        b["residuals"].append({
            "residual_id": "rt-res-rt-injected-gap", "subject": "rt-injected-gap",
            "class": RESIDUAL_CLASS_FOR_GAP, "disposition": "open",
            "detail": "an injected gap", "evidence": [EXPOSURE_REL],
        })
        b["absence_claim"]["asserted"] = True
        return b

    m7 = check("absence_with_gap", absence_with_gap(),
               "asserts the absence of gaps while a FOUND_GAP")

    # m8: a method outside the closed vocabulary.
    def outside_method() -> dict:
        b = clone()
        b["attacks"][0]["method"] = "magic"
        return b

    m8 = check("method_outside_vocabulary", outside_method(),
               "not in the closed red-team method vocabulary")

    result["specificity_holds"] = bool(
        m1 and m2 and m3 and m4 and m5 and m6 and m7 and m8 and not baseline)
    result["caught"] = sum(1 for v in result["mutations"].values() if v["caught"])
    result["seeded"] = len(result["mutations"])
    return result


# --------------------------------------------------------------------------------------------
# writing and reading the plane
# --------------------------------------------------------------------------------------------

def _write_plane(path: Path, doc: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    path.write_text(text, encoding="utf-8")


def _inputs() -> list:
    return [
        InputRef(name="phase-25-plan", path=PLAN),
        InputRef(name="memory-safety-schemas", path=SCHEMAS),
        InputRef(name="phase25-guard", path=GUARD),
        InputRef(name="phase25-container-manifest", path=MANIFEST),
        InputRef(name="ms-red-team-tool", path=TOOL),
        InputRef(name="source-census", path=SOURCE_CENSUS),
        InputRef(name="phase22-crosswalk", path=PHASE22_CROSSWALK),
        InputRef(name="exposure", path=EXPOSURE),
        InputRef(name="unsafe-reduction", path=UNSAFE_REDUCTION),
        InputRef(name="phase18-fuzz-crosswalk", path=PHASE18_FUZZ_CROSSWALK),
        InputRef(name="phase24-safety-coverage", path=PHASE24_SAFETY_COVERAGE),
        InputRef(name="mechanisms", path=MECHANISMS),
        InputRef(name="miri", path=MIRI),
        InputRef(name="asan-msan", path=ASAN_MSAN),
        InputRef(name="tsan", path=TSAN),
        InputRef(name="kani", path=KANI),
        InputRef(name="cve-replay", path=CVE_REPLAY_INDEX),
    ]


def _measure() -> int:
    """Derive the red team from the committed planes, and write it."""
    authority = load_authority()
    body = build_body(authority)
    problems = red_team_findings(body, authority)
    control = red_team_sensitivity_control(body, authority)

    auth = resolve_authority(PRODUCTION_AUTHORITY)
    doc = envelope(kind="phase25-red-team", authority=auth.id, inputs=_inputs(),
                   body=body, generator=GENERATOR)
    doc["body_hash"] = content_hash(body)
    _write_plane(OUT, doc)

    c = body["counts"]
    print(f"[ms-red-team] {rel(OUT)} -- {c['attacks']} attack(s) over {c['methods']} method(s); "
          f"found_gap={c['found_gap']} inconclusive={c['inconclusive']} no_gap={c['no_gap']}")
    for a in body["attacks"]:
        print(f"  {a['attack_id']:<40} {a['method']:<22} {a['outcome']:<13} "
              f"sites={a['site_count']}")
    print("  by outcome: " + ", ".join(f"{k}={v}" for k, v in sorted(c["by_outcome"].items())))
    print(f"  residuals={c['residuals']} witness_audit={c['witness_audit_entries']} "
          f"unwitnessed={c['unwitnessed_classifications']}")
    print(f"  absence_claim asserted={body['absence_claim']['asserted']} "
          f"methods={len(body['absence_claim']['methods'])}")
    print(f"  -> body_hash={doc['body_hash'][:16]} all_checks={not problems} "
          f"control honest={control['honest']} specificity={control['specificity_holds']}")
    for p in problems[:24]:
        print(f"    {p}")
    return 0 if not problems else 1


def _check() -> int:
    """Re-run the pure checks over the committed plane, without reading a compiler."""
    if not OUT.is_file():
        print(f"[ms-red-team] {rel(OUT)} is absent; run --measure")
        return 1
    body = _body(_load(OUT))
    authority = load_authority()
    problems = red_team_findings(body, authority)
    control = red_team_sensitivity_control(body, authority)
    if problems or not control["honest"]:
        print(f"[ms-red-team] check FAILED: {len(problems)} problem(s)")
        for p in problems[:24]:
            print(f"  {p}")
        return 1
    c = body["counts"]
    print(f"[ms-red-team] check ok: {c['attacks']} attack(s) over {c['methods']} method(s); "
          f"found_gap={c['found_gap']} inconclusive={c['inconclusive']}; "
          f"{len(body['residuals'])} residual(s); every check holds")
    return 0


# --------------------------------------------------------------------------------------------
# self-test
# --------------------------------------------------------------------------------------------

def _synth_authority() -> dict:
    """A tiny, self-consistent set of planes exercising all three outcomes."""
    # The synthetic exercises all three outcomes: E1 finds a gap (us-unreach is UNREACHABLE_PROFILE
    # with no witness), T2 is inconclusive (us-ext is externally reachable with no typed-edge root
    # but a committed parser-route justification), and the rest are no-gap.
    exposure = {"sites": {
        "us-ext": {"e": "LOCAL_FILE_INPUT_REACHABLE", "j": "j:lf", "r": "S1"},
        "us-root": {"e": "CLI_INPUT_REACHABLE", "j": "j:cli", "r": "S1"},
        "us-safe": {"e": "INTERNAL_REACHABLE", "r": "S0"},
        "us-unk": {"e": "UNKNOWN_REACHABILITY", "r": "SU"},
        "us-unreach": {"e": "UNREACHABLE_PROFILE", "r": "S0"},
    }, "justifications": {"j:lf": {"class": "LOCAL_FILE_INPUT_REACHABLE"}, "j:cli": {"class": "CLI_INPUT_REACHABLE"}},
        "rule": {"exclusion_witness_kinds": ["committed_exclusion_residual", "no_reachable_root"],
                 "exclusion_residuals": ["out_of_scope"]},
        "residuals": [], "counts": {}}
    crosswalk = {"sites": {
        "us-ext": {"roots": [], "residual": "evidence_missing"},
        "us-root": {"roots": ["cli"]},
        "us-safe": {"roots": []},
        "us-unk": {"roots": [], "residual": "evidence_missing"},
    }}
    coverage = {"sites": {
        "us-ext": {"exposure": "LOCAL_FILE_INPUT_REACHABLE", "state": "REACHABLE_UNOBSERVED", "observed_by": []},
        "us-root": {"exposure": "CLI_INPUT_REACHABLE", "state": "DOWNSTREAM_OBSERVED", "observed_by": ["curl"]},
    }, "counts": {"not_reachable_by_exposure": {"UNKNOWN_REACHABILITY": 1}}}
    reduction = {"counts": {"reachable_after": 2}, "worklist": [
        {"pattern": "P", "sites": {"count": 2, "sample_site_ids": ["us-ext", "us-root"]}}]}
    fuzz = {"sites": {"us-ext": {"state": "NOT_FUZZED", "reason": "route_not_driven", "targets": []},
                      "us-root": {"state": "FUZZED", "targets": ["RT-HOSTILE-X509"]}},
            "counts": {"findings": 0, "mutational_screen_findings": 0}}
    mechanisms = {"mechanisms": [
        {"mechanism_id": "vm-a", "disposition": "ELIMINATED"},
        {"mechanism_id": "vm-b", "disposition": "HIDDEN"},
    ], "residuals": [{"residual_id": "res-mech-vm-b", "subject": "vm-b", "class": "mechanism_unreconciled",
                      "disposition": "open", "detail": "survives", "evidence": ["x"]}],
        "counts": {}}
    miri = {"sites": {"us-root": {"state": "MIRI_NOT_REACHABLE", "reason": "NO_COMMITTED_HARNESS_EXECUTED"},
                      "us-safe": {"state": "MIRI_PASS"}}}
    empty_tool = {"sites": {}}
    replay = {"replays": []}
    return {
        "source_census": {"sites": [{"site_id": k} for k in
                                    ("us-ext", "us-root", "us-safe", "us-unk", "us-unreach")]},
        "phase22_crosswalk": crosswalk,
        "exposure": exposure,
        "reduction": reduction,
        "fuzz": fuzz,
        "coverage": coverage,
        "mechanisms": mechanisms,
        "tools": {"miri": miri, "asan": empty_tool, "tsan": empty_tool, "kani": empty_tool},
        "cve_replay": replay,
    }


def self_test() -> int:
    """Prove the metadata-only admission holds, the derivation runs and the control is honest."""
    failures: list = []

    admission = phase25_guard.evaluate(entry_point="ms_red_team.py", env={}, dockerenv=False)
    if not admission["admitted"] or admission["venue"] != "metadata-only":
        failures.append("ms_red_team.py is not admitted as a metadata-only generator on a host")

    authority = _synth_authority()
    body = build_body(authority)
    baseline = red_team_findings(body, authority)
    if baseline:
        failures.append(f"the synthetic red-team body is not clean: {baseline[:4]}")
    c = body["counts"]
    # The synthetic must exercise all three outcomes: one justified typed-edge inconclusive, one
    # ungrounded typed-edge gap, and the rest no-gap.
    if c["found_gap"] < 1 or c["inconclusive"] < 1 or c["no_gap"] < 1:
        failures.append(f"the synthetic does not exercise all three outcomes: {c['by_outcome']}")
    if c["methods"] < 2:
        failures.append(f"the synthetic exercises too few methods: {c['methods']}")
    if not body["absence_claim"]["asserted"]:
        # A gap is present, so the derived claim must NOT assert absence.
        pass
    else:
        failures.append("the synthetic carries a gap but still asserts the absence of gaps")

    control = red_team_sensitivity_control(body, authority)
    if not control["specificity_holds"] or control["caught"] != control["seeded"]:
        failures.append(f"the sensitivity control is not honest: {control}")

    if failures:
        print("[ms-red-team] self-test FAILED")
        for f in failures:
            print(f"  {f}")
        return 1
    print("[ms-red-team] self-test ok: the guard admits it as metadata-only; the synthetic attack "
          f"plane is clean ({c['attacks']} attack(s) over {c['methods']} method(s): "
          f"found_gap={c['found_gap']}, inconclusive={c['inconclusive']}, no_gap={c['no_gap']}, "
          f"absence_claim asserted={body['absence_claim']['asserted']}); and all eight seeded "
          "mutations (a gap with no residual, an absence claim from a single method, an unreachable "
          "classification with no witness, a typed count, an outcome outside the vocabulary, a "
          "dropped attack, an absence claim with a gap and a method outside the vocabulary) are "
          "caught with specificity holding")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--measure", action="store_true",
                    help="derive artifacts/phase25/red-team.json from the committed inputs")
    ap.add_argument("--check", action="store_true",
                    help="re-run the pure checks over the committed plane")
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
