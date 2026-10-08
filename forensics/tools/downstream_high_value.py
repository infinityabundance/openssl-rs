#!/usr/bin/env python3
"""openssl-rs — Phase-24.9 high-value deep tier: the families that depend on OpenSSL most deeply,
measured past the shallow levels to the functional level where they can be.

Phase 24 measures whether `openssl-rs` survives the ways real software depends on OpenSSL, over the
frozen P1000 (`forensics/downstream/family-freeze.json`). 24.3 recorded, for a bounded census cohort,
the **usage fingerprints** -- the actual imported OpenSSL symbols, the OpenSSL headers the pristine
source includes, and the linkage proof -- of the handful of families whose OpenSSL dependence the
authority could measure deeply. 24.6 built and linked every family that had a pristine-source recipe;
24.7 loaded and drove a real local workload for the ones that reached `L4-linked`; 24.8 classified,
preserved and minimized the failures. This module is the **high-value deep tier**: the deepest
families by that committed depth evidence, plus the genuinely deep consumers the 24.x catalogue does
not yet carry (Git and CPython, admitted by the committed Phase-17 downstream precedent), taken
**past the shallow levels to the functional level** under both subjects.

The frozen depth rule, and it reads no candidate result
-------------------------------------------------------
The tier is selected by a rule recorded **verbatim** in the artefact and re-derived by the court from
committed evidence only. A family's OpenSSL dependence **depth** is ordered by, in order:

  1. distinct imported OpenSSL symbols (descending) — from the 24.3 usage fingerprints;
  2. distinct OpenSSL API-family breadth (descending) — the count of distinct tokens before the first
     `_` of each imported symbol (`EVP`, `BIO`, `X509`, `SSL`, ...), derived from the same list;
  3. distinct OpenSSL headers (descending) — from the same fingerprints;
  4. `direct` before `transitive` linkage (the two are different evidence and are never summed);
  5. `canonical_name`, then `family_id`, ascending — the total tiebreak.

The rule consults the committed 24.3 fingerprints and the committed families; it **never** reads a
candidate row, so a family cannot enter the tier by what the candidate happened to pass. A family the
committed fingerprints do not cover is admitted only by the **precedent** clause below, never by a
result.

Tier A: the deepest families with an admitted specimen and a functional workload
--------------------------------------------------------------------------------
**Tier A** is the bounded, deterministic set of families the rule selects:

  * every family with a committed 24.3 usage fingerprint whose committed authority-applicable
    baseline (24.7) reached `L5-loaded` and which has an admitted pristine-source recipe and a local
    functional workload — the deepest families that *can* be driven to the functional level; and
  * the **precedented deep consumers**: a family named by a committed Phase-17 downstream harness
    (`courts/phase17/downstream/<program>/build.sh`) whose family node is a direct consumer the 24.3
    fingerprints do not cover and the 24.6/24.7 recipe catalogue does not already measure. The
    Phase-17 harnesses are the committed precedent that these are deep consumers, so their admission
    is committed evidence and not a candidate result.

Where a genuinely deep consumer is missing from the 24.6/24.7 catalogue the catalogue is **extended**
here: the committed Phase-17 `build.sh` for Git and CPython is run against each subject's OpenSSL
prefix (exactly the pristine upstream release, the exact flags that harness pins), and the built
program is loaded and driven by the 24.7 workload machinery. Git links the subject's `libcrypto`
directly (its SHA-1/SHA-256 object hashing routes through OpenSSL); CPython's `_ssl` extension links
the subject's `libssl`/`libcrypto`, so its load proof is taken on that module rather than the
interpreter (which links neither), recorded honestly.

Carried where already measured, measured where new
-------------------------------------------------
A tier member the 24.7 runtime/functional atlas **already** measured at the functional level is
**carried**: its committed row is copied with a `carried_from` pointer that names the 24.7 `run_id`,
and the court re-checks that the cited 24.7 row really exists and agrees on its level and transcript
hash. Six programs are not rebuilt to re-derive a measurement the stratum already has, so the run is
bounded. A tier member 24.7 did not measure (a precedented deep consumer) is **measured fresh** with
the same workload machinery.

Every P1000 family is accounted for
-----------------------------------
The artefact carries one **accounting row per frozen P1000 family**: a tier member reads
`tier_measured`, every other family reads `not_selected` with a reason. A tier member outside the
P1000 (a precedented deep consumer the counted population does not carry) is recorded in the tier and
is **not** folded into the population — which is why the stratum's non-claims gain the fifth one: *a
deep tier of a selected population is not a proof about consumers outside it*.

Deterministic transcript normalisation, and the Docker-only guard
----------------------------------------------------------------
Every measured row carries a `transcript_sha256` over its normalised transcript, and the **same**
normaliser 24.7 uses is applied to both subjects; it replaces only genuinely nondeterministic and
contract-irrelevant values (absolute paths, ports, PIDs, timestamps, addresses) and **never** a return
code, an error class, a certificate decision, or a protocol/algorithm choice (the brief's section 46).
This tool fetches, compiles and runs downstream projects, so `phase24_guard.require_admitted()` is the
first statement of `main` and a host invocation is refused (`docs/REPRODUCIBILITY.md` section 1).

Why this artefact is not in `evidence_determinism.py`'s `GENERATORS` or `COMPARED`
----------------------------------------------------------------------------------
It is **measurement**, not a pure function of committed inputs: it fetches, compiles and loads real
downstream releases inside the court container, so the level a run reaches and its normalised
transcript are a function of the court's toolchain and of the network, not of committed inputs — the
same precedent as 24.6's build/link atlas, 24.7's runtime/functional atlas and the Phase-17 measured
corpus. Regenerating it needs a compiler, a prefix and the committed Phase-17 harnesses, none of which
a host CI runner has, and the Docker-only guard refuses a host invocation before it builds anything.
The court `RT-HIGH-VALUE-TIER` re-runs only this module's **pure** functions over the committed
artefact and never rebuilds.

Outputs
-------
  forensics/downstream/high-value-tier.json   the tier, the accounting rows and the runs, both subjects

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import shutil
import sys
import time
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
    write_json,
)

# The Docker-only execution guard. Its call is the first statement of `main`: this tool fetches,
# compiles and runs, so it is an execution entry point and a host invocation is refused.
import phase24_guard  # noqa: E402

# The record schemas the rows are validated against, imported rather than restated so the vocabulary
# cannot drift from the module the court checks it with.
import downstream_schemas  # noqa: E402

# The 24.3 census primitives (fetch/extract/run/ELF inspection/resource limits) are reused.
import downstream_census as census  # noqa: E402

# The 24.6 build/link atlas: its recipe catalogue, its specimen/variant/run constructors and its
# source-root hash are reused, so the tier builds and records a run the same way the atlas does.
import downstream_build_link as bl  # noqa: E402

# The 24.7 runtime/functional atlas: its workload helpers (the PKI fixture, the peer s_client, the
# load proof), its normaliser and its `run` construction are **imported and reused**, so a tier run is
# the exact workload machinery 24.7 measured with (one code path, not two that can drift).
import downstream_runtime as rt  # noqa: E402

# The stratum's four non-claims, imported from 24.4 so the tier and the freeze cannot drift.
from downstream_freeze import NON_CLAIMS as STRATUM_NON_CLAIMS  # noqa: E402

FAMILIES = REPO_ROOT / "forensics" / "downstream" / "families.json"
FAMILY_FREEZE = REPO_ROOT / "forensics" / "downstream" / "family-freeze.json"
USAGE_FINGERPRINTS = REPO_ROOT / "forensics" / "downstream" / "usage-fingerprints.json"
BUILD_LINK_ATLAS = REPO_ROOT / "forensics" / "downstream" / "build-link-atlas.json"
RUNTIME_FUNCTIONAL_ATLAS = REPO_ROOT / "forensics" / "downstream" / "runtime-functional-atlas.json"
OUT = REPO_ROOT / "forensics" / "downstream" / "high-value-tier.json"

# The committed Phase-17 downstream harnesses: the precedent that a program is a deep OpenSSL
# consumer, and the build recipe that compiles it against a subject prefix.
PHASE17_DOWNSTREAM = REPO_ROOT / "courts" / "phase17" / "downstream"

CANDIDATE_PREFIX = bl.CANDIDATE_PREFIX

# Scratch is kept under `/work/court` (never `/tmp` or the container's `/`) and removed after the
# measurement; only the small committed artefact persists in the tree.
SCRATCH = REPO_ROOT / "court" / "phase24-high-value"
SHARED_DL = SCRATCH / "dl"

GENERATOR = "forensics/tools/downstream_high_value.py"
PARSER_VERSION = "downstream-high-value-tier/1"

L0 = "L0-catalogued"
L4 = "L4-linked"
L5 = "L5-loaded"
L6 = "L6-runtime"
L7 = "L7-functional"
RANK = downstream_schemas.EXECUTION_LEVEL_RANK

STEP_TIMEOUT = census.STEP_TIMEOUT
FETCH_TIMEOUT = census.FETCH_TIMEOUT
LAUNCH_TIMEOUT = census.LAUNCH_TIMEOUT
MAKE_JOBS = census.MAKE_JOBS
# The Phase-17 build.sh compiles a whole dependency (a shared libcurl for Git, or all of CPython), so
# its single wall-clock bound is larger than one configure/make step. Bounded, not unlimited.
BUILD_TIMEOUT = 1800

SUBJECTS = ("authority", "candidate")

# The same normalisation categories 24.7 uses: only genuinely nondeterministic and contract-irrelevant
# values. Everything else -- return codes, error classes, certificate decisions, protocol/algorithm
# choices -- is evidence and is never normalised (the brief's section 46).
NORMALISATION_TAG = rt.NORMALISATION_TAG
NORMALISATION_ALLOWED = rt.NORMALISATION_ALLOWED
NORMALISATION_NEVER = rt.NORMALISATION_NEVER

# The stratum's four non-claims (imported from 24.4 so the two cannot drift) plus the one this
# subphase's measurement adds: a deep tier of a selected population is not a proof about consumers
# outside it.
NON_CLAIMS: list[str] = list(STRATUM_NON_CLAIMS) + [
    "a deep tier of a selected population is not a proof about consumers outside it: the tier is the "
    "families the committed depth evidence and the frozen precedent select, and its functional passes "
    "say nothing about a consumer the atlas does not measure",
]


# ---------------------------------------------------------------------------------------------------
# the frozen rule: the depth order, the tier selection, the carry policy, the local-only and
# normalisation policy. Recorded verbatim in the artefact and re-derived by the court.
# ---------------------------------------------------------------------------------------------------

# The depth-order key, in order. Recorded as data so the court can re-derive the ordering from it and
# a reader can recompute it; it is derived only from the 24.3 usage fingerprints and the committed
# families, and it reads no candidate result.
DEPTH_KEY: list[str] = [
    "distinct_imported_openssl_symbols:descending",
    "distinct_openssl_api_families:descending",
    "distinct_openssl_headers:descending",
    "openssl_linkage:direct-before-transitive",
    "canonical_name:ascending",
    "family_id:ascending",
]

RULE: dict = {
    "id": "downstream-high-value-tier/1",
    "name": "the high-value deep tier",
    "depth_rule": {
        "source": rel(USAGE_FINGERPRINTS),
        "key": DEPTH_KEY,
        "api_family": (
            "the token before the first `_` of an imported OpenSSL symbol (EVP, BIO, X509, SSL, ...); "
            "the API-family breadth is the count of distinct such tokens in a family's imported "
            "symbol list"
        ),
        "candidate_blind": (
            "the depth order is derived only from the committed 24.3 usage fingerprints and the "
            "committed families; it reads no candidate row, so a family cannot enter the tier by what "
            "the candidate happened to pass"
        ),
    },
    "tier_rule": (
        "Tier A is (a) every family with a committed 24.3 usage fingerprint whose committed "
        "authority-applicable baseline (24.7) reached L5-loaded and which has an admitted "
        "pristine-source recipe and a local functional workload -- the deepest families that can be "
        "driven to the functional level -- plus (b) the precedented deep consumers: a family named by "
        "a committed Phase-17 downstream harness whose family node is a direct consumer the 24.3 "
        "fingerprints do not cover and the 24.6/24.7 recipe catalogue does not already measure. The "
        "tier is bounded (no family outside these two clauses) and deterministic"
    ),
    "carry_policy": (
        "a tier member the 24.7 runtime/functional atlas already measured at the functional level is "
        "carried: its committed row is copied with a `carried_from` pointer naming the 24.7 run_id, "
        "and the court re-checks that the cited row exists and agrees on its level and transcript "
        "hash; a tier member 24.7 did not measure is measured fresh with the same workload machinery"
    ),
    "levels": [L5, L6, L7],
    "subjects": list(SUBJECTS),
    "authority_applicable_baseline": (
        "a tier member's authority-applicable baseline is the highest level its authority runs "
        "reached; a candidate run reaches it when its own level rank is at least that rank, and a "
        "candidate row never claims a level above it"
    ),
    "local_only": (
        "every L6/L7 workload runs against local peers only -- the admitted authority's own openssl "
        "CLI and the subject-linked program, on loopback; no run touches the public internet. The "
        "network is used only to acquire a pinned pristine source"
    ),
    "workload_policy": (
        "only a workload meaningful to the program is driven, never a manufactured one; where a "
        "program's workload needs a peer or dependency this venue does not admit, the exclusion is "
        "recorded with a reason and the level reached is stated honestly rather than faked"
    ),
    "normalisation": {
        "tag": NORMALISATION_TAG,
        "normalises": list(NORMALISATION_ALLOWED),
        "never": list(NORMALISATION_NEVER),
        "policy": (
            "the same normaliser is applied to both subjects; it replaces only absolute paths, "
            "ports, PIDs, timestamps and addresses, and never a return code, an error class, a "
            "certificate decision, or a protocol/algorithm choice"
        ),
    },
    "accounting": (
        "one accounting row per frozen P1000 family: a tier member reads `tier_measured`, every other "
        "family reads `not_selected` with a reason, never omitted. A tier member outside the P1000 is "
        "recorded in the tier and is not folded into the counted population"
    ),
    "confinement": (
        "each fetch, build and run runs inside the admitted court container under its cgroup caps and "
        "this tool's own wall-clock bounds; scratch is under /work/court and removed afterwards"
    ),
    "constants": {"make_jobs": MAKE_JOBS, "step_timeout_seconds": STEP_TIMEOUT,
                  "build_timeout_seconds": BUILD_TIMEOUT, "launch_timeout_seconds": LAUNCH_TIMEOUT},
}


# ---------------------------------------------------------------------------------------------------
# the committed Phase-17 precedent: the deep consumers the 24.x catalogue does not yet carry
# ---------------------------------------------------------------------------------------------------
#
# Each entry is a committed `courts/phase17/downstream/<harness>/build.sh` that configures and builds
# the pristine upstream release against a subject prefix, plus the version and the pinned digest that
# build.sh itself carries. The tool runs the committed build.sh (never a re-typed recipe) with
# CANDIDATE=<subject prefix>, so the build is exactly the Phase-17 precedent.
#
# The family node each harness builds: the Git SCM project is the P1000 family `git-core` (Fedora's
# `git-core` package node) and CPython is the committed family `python` (Homebrew's `python@3.x`).
# The mapping is committed and the court checks each maps to a real committed direct-consumer family.
PRECEDENT_FAMILY: dict[str, str] = {
    "git": "family:git-core",
    "python": "family:python",
}

PRECEDENT_CONSUMERS: dict[str, dict] = {
    "git": {
        "family_id": "family:git-core",
        "harness": "git",
        "version": "2.56.0",
        "url": "https://mirrors.edge.kernel.org/pub/software/scm/git/git-2.56.0.tar.xz",
        "sha256": "26c56c296b38c0695b26fa95f475f1d01704d2d38e73465ca30b0b2f5dc789d3",
        "archive": "git-2.56.0.tar.xz",
        "source_root": "git-2.56.0",
        "program": "git-2.56.0/git",
        "launch": ["--version"],
        "version_re": r"git version",
        "deps": [("curl", "curl-8.22.0.tar.gz",
                  "https://curl.se/download/curl-8.22.0.tar.gz",
                  "d54dd598bf05927a726deb38df31c6a255ba83ff1de57c5d1464dac3ed8f44a1")],
    },
    "python": {
        "family_id": "family:python",
        "harness": "python",
        "version": "3.12.15",
        "url": "https://www.python.org/ftp/python/3.12.15/Python-3.12.15.tar.xz",
        "sha256": "c2c4321961fab0fb999d66e0cecf521c2ab3994c7992873ea99e306c1094fd5a",
        "archive": "Python-3.12.15.tar.xz",
        "source_root": "Python-3.12.15",
        "program": "Python-3.12.15/python",
        "launch": ["-V"],
        "version_re": r"Python 3",
        "deps": [],
    },
}

# A local cache for the pinned Phase-17 tarballs (a same-host venue may already have fetched them), so
# a flaky network does not make the tier unmeasurable. The candidate is always verified against the
# pinned digest by the build.sh, so a cached copy cannot be a different source.
_TARBALL_CACHES: dict[str, list[Path]] = {
    "git-2.56.0.tar.xz": [REPO_ROOT / "court" / "phase18-asan" / "consumers" / "git" / "dl"
                          / "git-2.56.0.tar.xz"],
    "curl-8.22.0.tar.gz": [REPO_ROOT / "court" / "phase18-asan" / "consumers" / "git" / "dl"
                           / "curl-8.22.0.tar.gz"],
    "Python-3.12.15.tar.xz": [REPO_ROOT / "court" / "phase18-asan" / "consumers" / "python" / "dl"
                              / "Python-3.12.15.tar.xz"],
}


def _acquire(url: str, dest: Path, name: str) -> dict:
    """Fetch a pinned tarball to `dest`, falling back to a same-host cache on fetch failure."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.is_file():
        return {"ok": True, "exit_code": 0, "source": "present", "argv": ["cache"],
                "stdout": "", "stderr": "", "elapsed_seconds": 0.0}
    res = census._fetch(url, dest)
    if res["ok"] and dest.is_file():
        res = dict(res, source="fetched")
        return res
    for cand in _TARBALL_CACHES.get(name, []):
        if cand.is_file():
            shutil.copy2(cand, dest)
            return {"ok": True, "exit_code": 0, "source": f"cache:{rel(cand)}",
                    "argv": ["cp"], "stdout": "", "stderr": res.get("stderr", ""),
                    "elapsed_seconds": 0.0}
    return dict(res, source="fetch-failed")


# ---------------------------------------------------------------------------------------------------
# the depth order and the tier derivation (pure over committed evidence; reads no candidate row)
# ---------------------------------------------------------------------------------------------------

def _api_family(symbol: str) -> str:
    return symbol.split("_", 1)[0] if symbol else ""


def depth_entry(fingerprint: dict, families_by_id: dict) -> dict:
    """One family's dependence depth, derived from its 24.3 usage fingerprint alone."""
    syms = [str(s) for s in (fingerprint.get("imported_openssl_symbols") or [])]
    headers = [str(h) for h in (fingerprint.get("openssl_headers") or [])]
    fam = families_by_id.get(str(fingerprint.get("family_id"))) or {}
    return {
        "canonical_name": str(fingerprint.get("canonical_name")),
        "family_id": str(fingerprint.get("family_id")),
        "distinct_imported_symbols": len(syms),
        "distinct_api_families": len({_api_family(s) for s in syms if s}),
        "distinct_headers": len(headers),
        "openssl_linkage": str(fam.get("openssl_linkage") or "direct"),
    }


def depth_key(entry: dict) -> tuple:
    return (
        -int(entry["distinct_imported_symbols"]),
        -int(entry["distinct_api_families"]),
        -int(entry["distinct_headers"]),
        0 if entry["openssl_linkage"] == "direct" else 1,
        entry["canonical_name"],
        entry["family_id"],
    )


def _authority_baseline(runtime_body: dict) -> dict[str, str]:
    """The committed 24.7 authority-applicable level per family, from the authority rows only."""
    out: dict[str, str] = {}
    for row in runtime_body.get("runs") or []:
        if row.get("subject") != "authority":
            continue
        fid = str(row.get("family_id"))
        lv = str(row.get("level"))
        if RANK.get(lv, -1) > RANK.get(out.get(fid, L0), -1):
            out[fid] = lv
    return out


def precedent_members(families_body: dict, recipe_families: set[str],
                      fingerprint_names: set[str]) -> list[dict]:
    """The precedented deep consumers, derived from the committed Phase-17 harness set.

    A harness qualifies when its `build.sh` is committed, its family node is a real committed direct
    consumer, the 24.3 fingerprints do not cover that family, and the 24.6/24.7 recipe catalogue does
    not already measure it. Derived from committed evidence, never typed.
    """
    by_id = {str(f.get("family_id")): f for f in (families_body.get("families") or [])}
    by_name = {str(f.get("canonical_name")): str(f.get("family_id"))
               for f in (families_body.get("families") or [])}
    out: list[dict] = []
    if not PHASE17_DOWNSTREAM.is_dir():
        return out
    for harness_dir in sorted(PHASE17_DOWNSTREAM.iterdir()):
        if not (harness_dir / "build.sh").is_file():
            continue
        harness = harness_dir.name
        fid = by_name.get(harness) or PRECEDENT_FAMILY.get(harness)
        if fid is None:
            continue
        fam = by_id.get(fid)
        if fam is None or str(fam.get("openssl_linkage")) != "direct":
            continue
        name = str(fam.get("canonical_name"))
        if name in fingerprint_names or name in recipe_families:
            continue
        out.append({
            "canonical_name": name,
            "family_id": fid,
            "harness": harness,
            "harness_path": rel(harness_dir / "build.sh"),
        })
    out.sort(key=lambda m: (m["canonical_name"], m["family_id"]))
    return out


def _has_functional_workload(name: str) -> bool:
    """Whether a local functional workload is admitted for a program (24.7's runner catalogue)."""
    return name in rt.RUNNERS


def derive_tier(fingerprints_body: dict, runtime_body: dict, families_body: dict,
                recipe_families: set[str]) -> list[dict]:
    """The frozen depth rule applied to committed evidence: the ordered, bounded Tier A.

    Reads the committed 24.3 fingerprints, the committed families and the committed 24.7 authority
    rows, and the committed recipe/workload catalogue. It reads **no candidate row**.
    """
    by_id = {str(f.get("family_id")): f for f in (families_body.get("families") or [])}
    entries = [depth_entry(fp, by_id) for fp in (fingerprints_body.get("fingerprints") or [])]
    ranked = sorted(entries, key=depth_key)
    fp_names = {e["canonical_name"] for e in entries}
    baselines = _authority_baseline(runtime_body)

    members: list[dict] = []
    for rank, e in enumerate(ranked, 1):
        name, fid = e["canonical_name"], e["family_id"]
        base = baselines.get(fid, L0)
        if name not in recipe_families or not _has_functional_workload(name):
            continue
        if RANK.get(base, -1) < RANK[L5]:
            continue
        members.append({
            "family_id": fid,
            "canonical_name": name,
            "source": "fingerprint",
            "depth_rank": rank,
            "depth": e,
            "authority_applicable_baseline": base,
            "admission": ("the deepest families by the committed 24.3 usage fingerprint; an admitted "
                          "pristine-source recipe and a local functional workload"),
        })

    for pre in precedent_members(families_body, recipe_families, fp_names):
        spec = PRECEDENT_CONSUMERS.get(pre["harness"])
        if spec is None:
            continue
        members.append({
            "family_id": pre["family_id"],
            "canonical_name": pre["canonical_name"],
            "source": "precedent",
            "depth_rank": None,
            "depth": None,
            "harness": pre["harness"],
            "harness_path": pre["harness_path"],
            "authority_applicable_baseline": None,
            "admission": (f"a precedented deep consumer: the committed Phase-17 downstream harness "
                          f"{pre['harness_path']} builds it against the subject prefix and it is a "
                          f"direct consumer the 24.3 fingerprints and the 24.6/24.7 catalogue do not "
                          f"cover"),
        })

    members.sort(key=lambda m: (m["source"] != "fingerprint",
                                m["depth_rank"] if m["depth_rank"] is not None else 10 ** 6,
                                m["canonical_name"], m["family_id"]))
    return members


# ---------------------------------------------------------------------------------------------------
# building and measuring a precedented deep consumer (both subjects)
# ---------------------------------------------------------------------------------------------------

def _precedent_recipe(spec: dict) -> dict:
    return {
        "recipe_id": f"recipe:{spec['harness']}:{spec['version']}:phase17-precedent",
        "version": spec["version"],
        "url": spec["url"],
        "sha256": spec["sha256"],
        "archive": spec["archive"],
        "build_system": "phase17-harness",
        "artifact": spec["program"],
        "launch": list(spec["launch"]),
    }


def _build_precedent(spec: dict, prefix: Path, work: Path) -> dict:
    """Run the committed Phase-17 build.sh against one subject's prefix, bounded.

    The pinned tarballs are acquired into `work/dl` first, so the harness's own fetch is skipped; the
    harness still verifies every digest against its pinned value before it builds.
    """
    dl = work / "dl"
    dl.mkdir(parents=True, exist_ok=True)
    acquired: list[dict] = []
    for _label, name, url, _sha in spec.get("deps", []) + [("main", spec["archive"], spec["url"],
                                                             spec["sha256"])]:
        res = _acquire(url, dl / name, name)
        acquired.append({"name": name, "source": res.get("source"), "ok": bool(res.get("ok"))})
        if not res["ok"]:
            return {"ok": False, "exit_code": res.get("exit_code", 1),
                    "stdout": "", "stderr": f"acquiring {name} failed: {census._error_line(res)}",
                    "argv": ["acquire", name], "elapsed_seconds": 0.0, "acquired": acquired}
    # Only `CANDIDATE` (the subject prefix the harness reads) and `WORK`/`JOBS` are passed. The
    # harness's `DEPS`/`INSTALL` are deliberately **not** exported: they are the harness's own shell
    # variables, and exporting `INSTALL` would override `make`'s `$(INSTALL)` install program and
    # break the recursive install.
    env = dict(os.environ, CANDIDATE=str(prefix), WORK=str(work), JOBS="8")
    res = census._run(["bash", str(PHASE17_DOWNSTREAM / spec["harness"] / "build.sh")],
                      cwd=work, env=env, timeout=BUILD_TIMEOUT)
    res["acquired"] = acquired
    return res


def _find_ssl_module(work: Path) -> Path | None:
    found = [p for p in work.rglob("_ssl*.so") if p.is_file()]
    if not found:
        return None
    # the in-tree build/lib.* module the interpreter imports, preferred over the build-tree copy
    found.sort(key=lambda p: (0 if "build/lib" in p.as_posix() else 1, p.as_posix()))
    return found[0]


def _python_load_proof(work: Path, prefix: Path, authority_prefix: Path, program: Path,
                       env: dict) -> dict:
    """Prove CPython's `_ssl` extension loads the subject's libssl/libcrypto, not the authority's.

    The interpreter itself links neither, so the load proof is taken on the extension module that
    actually consumes OpenSSL: its `ldd` resolution of every OpenSSL soname must be under the subject
    prefix (and, for a candidate row, never the authority's), and the interpreter must import `ssl`
    and report a version with the subject library present on the load path.
    """
    module = _find_ssl_module(work)
    is_authority = os.path.realpath(str(prefix)) == os.path.realpath(str(authority_prefix))
    proof: dict = {"proven": False, "all_under_prefix": False, "resolved_under_authority": False,
                   "sonames": {}, "dynamic_load_trace": [], "ldd_exit": None, "trace_exit": None,
                   "artifact": rel(module) if module else None}
    if module is None:
        return proof
    ldd = rt._run_captured(["ldd", str(module)], env=env, timeout=60)
    any_lib = False
    all_under = True
    under_authority = False
    for line in (ldd["stdout"] or "").splitlines():
        left = line.split("=>")[0].strip()
        if not (left == "libssl.so" or left.startswith("libssl.so.") or left == "libcrypto.so"
                or left.startswith("libcrypto.so.")):
            continue
        resolved = line.split("=>", 1)[1].strip().split(" (")[0].strip() if "=>" in line else ""
        under = bool(resolved) and census._under(resolved, prefix)
        under_auth = bool(resolved) and census._under(resolved, authority_prefix)
        proof["sonames"][left] = {
            "resolved": f"prefix:{left}" if under else (resolved or "unresolved"),
            "under_prefix": under, "under_authority": under_auth,
        }
        any_lib = True
        all_under = all_under and under
        under_authority = under_authority or under_auth
    trace = rt._run_captured([str(program), "-c",
                              "import ssl,hashlib;print(ssl.OPENSSL_VERSION)"],
                             env=dict(env, LD_DEBUG="libs"), timeout=LAUNCH_TIMEOUT)
    trace_lines = [ln.strip() for ln in ((trace["stderr"] or "") + "\n" +
                                         (trace["stdout"] or "")).splitlines()
                   if ("libssl" in ln or "libcrypto" in ln) and str(prefix) in ln]
    proof.update({
        "proven": any_lib and all_under and (is_authority or not under_authority),
        "all_under_prefix": all_under,
        "resolved_under_authority": under_authority,
        "dynamic_load_trace": trace_lines[:8],
        "ldd_exit": ldd["exit_code"],
        "trace_exit": trace["exit_code"],
    })
    return proof


# ---------------------------------------------------------------------------------------------------
# the workloads: real, deterministic, local OpenSSL exercises for the precedented deep consumers
# ---------------------------------------------------------------------------------------------------

def _git_blob_sha(hexdigest: str, content: bytes) -> str:
    """The object id Git must print: an independent oracle, so a wrong subject digest is visible."""
    header = f"blob {len(content)}\0".encode("ascii")
    h = hashlib.new(hexdigest)
    h.update(header)
    h.update(content)
    return h.hexdigest()


def _wl_git(ctx: dict) -> dict:
    """Git's SHA-1 and SHA-256 object hashing, routed through the subject's libcrypto.

    With `OPENSSL_SHA1`/`OPENSSL_SHA256` Git hashes objects with the subject's `libcrypto`; a wrong
    digest is visible because the object id is compared against an independent oracle (Python's own
    hashlib), so this is a functional proof of the subject's digest path and not a self-consistency
    check.
    """
    prog, d, env = ctx["program"], ctx["workdir"], ctx["env"]
    content = b"phase24 high-value git fixture\n"
    blob = d / "blob.txt"
    blob.write_bytes(content)
    notes: list[dict] = []

    def run(argv: list[str]) -> dict:
        res = rt._run_captured([str(prog)] + argv, cwd=d, env=env, timeout=40)
        notes.append(res)
        return res

    sha1_repo = d / "repo1"
    init1 = run(["init", "--quiet", str(sha1_repo)])
    hash1 = run(["-C", str(sha1_repo), "hash-object", "-w", str(blob)])
    got1 = (hash1["stdout"] or "").strip()
    want1 = _git_blob_sha("sha1", content)

    sha256_repo = d / "repo2"
    init2 = run(["init", "--quiet", "--object-format=sha256", str(sha256_repo)])
    hash2 = run(["-C", str(sha256_repo), "hash-object", "-w", str(blob)])
    got2 = (hash2["stdout"] or "").strip()
    want2 = _git_blob_sha("sha256", content)

    runtime_ok = (init1["ok"] and hash1["ok"] and bool(got1)
                  and init2["ok"] and hash2["ok"] and bool(got2))
    functional_ok = runtime_ok and got1 == want1 and got2 == want2
    reason = None
    if not functional_ok:
        reason = ("the SHA-1 object id did not match the independent oracle"
                  if runtime_ok and got1 != want1 else
                  "the SHA-256 object id did not match the independent oracle" if runtime_ok else
                  "git did not hash an object")
    transcript = rt._transcript(
        ("git init (sha1)", init1), ("git hash-object (sha1)", hash1),
        ("git init (sha256)", init2), ("git hash-object (sha256)", hash2),
        ("oracle", {"exit_code": 0, "stdout": f"sha1={want1}\nsha256={want2}\n"}))
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if runtime_ok else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if runtime_ok else
                                                      "runtime-failure"),
            "reason": reason, "transcript": transcript,
            "workload": "git: libcrypto SHA-1/SHA-256 object hashing vs an independent oracle",
            "local_only": True}


_PY_TLS_PROBE = r'''
import socket, ssl, sys
port = int(sys.argv[1])
ca = sys.argv[2]
other = sys.argv[3]
ctx = ssl.create_default_context(cafile=ca)
with socket.create_connection(("127.0.0.1", port), timeout=15) as raw:
    with ctx.wrap_socket(raw, server_hostname="127.0.0.1") as s:
        print("handshake_ok=1")
        print("ver=%s" % s.version())
        s.sendall(b"GET / HTTP/1.0\r\nConnection: close\r\n\r\n")
        body = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            body += chunk
        print("http200=%d" % (1 if b" 200 " in body.replace(b"\r", b" ").replace(b"\n", b" ")
                               else 0))
print("openssl=%s" % ssl.OPENSSL_VERSION)
bad = ssl.create_default_context(cafile=other)
try:
    with socket.create_connection(("127.0.0.1", port), timeout=15) as raw2:
        with bad.wrap_socket(raw2, server_hostname="127.0.0.1"):
            print("unrelated_rejected=0")
except ssl.SSLError:
    print("unrelated_rejected=1")
'''


def _wl_python(ctx: dict) -> dict:
    """A verified TLS 1.3 client fetch from CPython against the authority's s_server.

    The subject's `_ssl` extension drives the handshake (the load proof takes the resolution on that
    module); a verified fetch must return 200 and an unrelated CA must be rejected, which is the
    certificate-verification behaviour the workload exists to prove.
    """
    ap, port, d = ctx["authority_prefix"], ctx["port"], ctx["workdir"]
    pki = rt._gen_pki(ap, d)
    probe = d / "tls_probe.py"
    probe.write_text(_PY_TLS_PROBE, encoding="utf-8")
    srv, of, ef = rt._spawn([str(rt._auth_ossl(ap)), "s_server", "-accept", str(port), "-cert",
                             str(pki["srv_crt"]), "-key", str(pki["srv_key"]), "-tls1_3", "-www"],
                            d, rt._auth_env(ap), d / "srv.out", d / "srv.err")
    try:
        if not rt._wait_tcp("127.0.0.1", port):
            return rt._wl_fail([], "python: the authority s_server did not listen", None, d)
        res = rt._run_captured([str(ctx["program"]), str(probe), str(port), str(pki["ca_crt"]),
                                str(pki["other_crt"])], env=ctx["env"], timeout=60)
    finally:
        rt._stop(srv)
        of.close()
        ef.close()
    out = res["stdout"] or ""
    runtime_ok = res["ok"] and "handshake_ok=1" in out and "ver=TLSv1.3" in out
    functional_ok = runtime_ok and "http200=1" in out and "unrelated_rejected=1" in out
    reason = None
    if not functional_ok:
        reason = ("the verified TLS 1.3 fetch did not return 200" if runtime_ok and
                  "http200=1" not in out else
                  "the unrelated CA was not rejected, so the fetch does not verify" if runtime_ok
                  else "CPython's _ssl did not complete a TLS 1.3 handshake")
    transcript = rt._transcript(("python _ssl TLS1.3 client", res),
                                ("s_server", {"exit_code": 0, "stdout": rt._read(d / "srv.err")}))
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if runtime_ok else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if runtime_ok else
                                                      "runtime-failure"),
            "reason": reason, "transcript": transcript,
            "workload": "python: verified TLS1.3 fetch + unrelated-CA reject (CPython _ssl)",
            "local_only": True}


PRECEDENT_RUNNERS: dict[str, object] = {"git": _wl_git, "python": _wl_python}


# ---------------------------------------------------------------------------------------------------
# measuring one precedented deep consumer under one subject
# ---------------------------------------------------------------------------------------------------

def _measure_precedent_subject(member: dict, spec: dict, recipe: dict, subject: str, prefix: Path,
                               authority_prefix: Path, limits: dict, build: dict) -> dict:
    """Load and drive one subject's built deep consumer; return its tier run row (reusing 24.7)."""
    name = str(member["canonical_name"])
    work = SCRATCH / name / subject
    root = work / spec["source_root"]
    program = work / spec["program"]
    spec_id = f"specimen:{name}:{spec['version']}"
    variant_id = f"variant:{name}:{spec['version']}:pristine"
    fam = {"family_id": member["family_id"], "canonical_name": name, "openssl_linkage": "direct",
           "directness_class": "DIRECT_OPENSSL_CONSUMER", "_rank": member.get("p1000_rank")}
    source_root_hash = bl._source_root_hash(root) if root.is_dir() else None
    evidence = [f"family:{member['family_id']}", f"harness:{member['harness_path']}",
                f"recipe:{recipe['recipe_id']}", f"artifact:{spec['program']}",
                "local_only:loopback"]

    if not build.get("ok") or not program.is_file():
        return rt._runtime_row(
            fam, recipe, subject, level=L0, outcome="not_attempted", residual="unbuildable",
            failure_class="candidate-build-failure" if subject == "candidate"
            else "authority-build-failure",
            reason=(f"the committed Phase-17 build for {spec['harness']} failed: "
                    f"{census._error_line(build)}"),
            specimen_id=spec_id, variant_id=variant_id, source_sha256=spec["sha256"],
            evidence=evidence, canvas=None, limits=limits, prefix=prefix,
            source_root_hash=source_root_hash, launch=None, workload=None, transcript="",
            local_only=True)

    workdir = SCRATCH / "run" / name / subject
    if workdir.exists():
        shutil.rmtree(workdir, ignore_errors=True)
    workdir.mkdir(parents=True, exist_ok=True)
    lib_paths = [str(prefix / "lib")]
    env = dict(os.environ, LD_LIBRARY_PATH=os.pathsep.join(lib_paths))
    launch = rt._run_captured([str(program)] + list(spec["launch"]), cwd=program.parent, env=env,
                              timeout=LAUNCH_TIMEOUT)
    version_ok = (re.search(spec["version_re"], launch["stdout"] + launch["stderr"],
                            re.IGNORECASE) is not None
                  and "error while loading shared libraries" not in launch["stderr"])
    if member["harness"] == "python":
        proof = _python_load_proof(work, prefix, authority_prefix, program, env)
    else:
        proof = rt.load_proof(program, prefix, authority_prefix, spec["launch"], env)
    base_canvas = {"load_proof": proof, "linkage_proven": proof["proven"],
                   "resolved_under_authority": proof["resolved_under_authority"],
                   "link": {"all_under_prefix": proof["all_under_prefix"],
                            "sonames": proof["sonames"]}}
    if not version_ok or not proof["proven"]:
        reason = ("the program did not start and report its version" if not version_ok else
                  "the subject's libssl/libcrypto were not loaded by the dynamic loader")
        return rt._runtime_row(
            fam, recipe, subject, level=L4, outcome="failed", residual="runtime-failure",
            failure_class="load-failure", reason=reason, specimen_id=spec_id, variant_id=variant_id,
            source_sha256=spec["sha256"], evidence=evidence, canvas=base_canvas, limits=limits,
            prefix=prefix, source_root_hash=source_root_hash, launch=list(spec["launch"]),
            workload=None, transcript=rt._transcript(("launch", launch)), local_only=True)

    runner = PRECEDENT_RUNNERS[member["harness"]]
    ctx = {"family": name, "subject": subject, "program": program, "root": work, "prefix": prefix,
           "authority_prefix": authority_prefix, "workdir": workdir, "port": rt._free_port(),
           "env": env}
    try:
        result = runner(ctx)
    except Exception as exc:  # noqa: BLE001 — a fixture failure is recorded, never raised
        result = {"runtime_ok": False, "functional_ok": False, "failure_class": "harness-failure",
                  "residual": "out-of-scope", "reason": f"the local workload fixture failed: {exc}",
                  "transcript": "", "workload": "harness-failure", "local_only": True}
    raw = rt._transcript(("launch", launch), ("workload", {"exit_code": 0,
                                                          "stdout": result.get("transcript", "")}))
    normalised = rt.normalise_transcript(raw, prefix, authority_prefix, workdir, ctx["port"])
    extra = {"workload_result": {"name": result.get("workload"), "runtime_ok": result["runtime_ok"],
                                 "functional_ok": result["functional_ok"],
                                 "local_only": result.get("local_only", True)}}
    if result.get("note"):
        extra["note"] = result["note"]
    if result["functional_ok"]:
        level, outcome, residual, failure_class, reason = L7, "reached", "none", None, None
    elif result["runtime_ok"]:
        level = L6
        outcome = "failed" if result.get("failure_class") else "reached"
        residual = result.get("residual") or "functional-divergence"
        failure_class = result.get("failure_class")
        reason = result.get("reason") or result.get("note") or (
            "the workload reached its runtime level but no functional level was driven")
    else:
        level, outcome = L5, "failed"
        residual = result.get("residual") or "runtime-failure"
        failure_class = result.get("failure_class") or "runtime-failure"
        reason = result.get("reason") or "the local workload did not complete"
    return rt._runtime_row(
        fam, recipe, subject, level=level, outcome=outcome, residual=residual,
        failure_class=failure_class, reason=reason, specimen_id=spec_id, variant_id=variant_id,
        source_sha256=spec["sha256"], evidence=evidence, canvas=base_canvas, limits=limits,
        prefix=prefix, source_root_hash=source_root_hash, launch=list(spec["launch"]),
        workload=str(result.get("workload")), transcript=normalised,
        local_only=bool(result.get("local_only", True)), extra=extra)


# ---------------------------------------------------------------------------------------------------
# carrying a tier member the 24.7 atlas already measured
# ---------------------------------------------------------------------------------------------------

def _carry_row(row: dict, carried_from: str) -> dict:
    """A tier row carried from the committed 24.7 atlas: the same measurement, honestly cited."""
    out = copy.deepcopy(row)
    out["run_id"] = f"run:high-value:{out.get('subject')}:{out.get('canonical_name')}"
    out["carried_from"] = carried_from
    out["evidence"] = list(out.get("evidence") or []) + [f"carried_from:{carried_from}"]
    return out


# ---------------------------------------------------------------------------------------------------
# the tier body: selection, runs, accounting
# ---------------------------------------------------------------------------------------------------

def _p1000(freeze_body: dict) -> list[dict]:
    return list(freeze_body.get("p1000") or [])


def _p1000_rank(freeze_body: dict, family_id: str) -> int | None:
    for e in _p1000(freeze_body):
        if str(e.get("family_id")) == family_id:
            return e.get("p1000_rank")
    return None


def derive_tier_body(fingerprints_body: dict, runtime_body: dict, families_body: dict,
                     freeze_body: dict, authority_id: str) -> dict:
    """Build the whole tier artefact body: measure the new consumers, carry the measured ones."""
    auth_prefix = resolve_authority(authority_id).prefix
    if not (CANDIDATE_PREFIX / "lib" / "libssl.so.3").is_file():
        raise SystemExit(f"[downstream-high-value] the candidate install prefix "
                         f"{rel(CANDIDATE_PREFIX)} holds no lib/libssl.so.3")
    limits = census.resource_limits()
    recipe_families = {r["family"] for r in bl.RECIPES}
    tier = derive_tier(fingerprints_body, runtime_body, families_body, recipe_families)
    for m in tier:
        m["p1000_rank"] = _p1000_rank(freeze_body, m["family_id"])

    rt_rows: dict[tuple[str, str], dict] = {
        (str(r.get("family_id")), str(r.get("subject"))): r for r in (runtime_body.get("runs") or [])
    }

    rows: list[dict] = []
    specimens: dict[str, dict] = {}
    variants: dict[str, dict] = {}
    SCRATCH.mkdir(parents=True, exist_ok=True)
    try:
        for m in tier:
            name = m["canonical_name"]
            if m["source"] == "fingerprint":
                for subject in SUBJECTS:
                    src = rt_rows.get((m["family_id"], subject))
                    if src is not None:
                        rows.append(_carry_row(src, str(src.get("run_id"))))
                continue
            spec = PRECEDENT_CONSUMERS[m["harness"]]
            recipe = _precedent_recipe(spec)
            for subject, prefix in (("authority", auth_prefix), ("candidate", CANDIDATE_PREFIX)):
                work = SCRATCH / name / subject
                if work.exists():
                    shutil.rmtree(work, ignore_errors=True)
                work.mkdir(parents=True, exist_ok=True)
                build = _build_precedent(spec, prefix, work)
                row = _measure_precedent_subject(m, spec, recipe, subject, prefix, auth_prefix,
                                                 limits, build)
                root = work / spec["source_root"]
                specimen = bl._specimen(
                    {"family_id": m["family_id"], "canonical_name": name}, recipe,
                    spec["sha256"], row.get("source_root_hash"))
                variant = bl._variant({"family_id": m["family_id"], "canonical_name": name}, recipe)
                specimens[specimen["specimen_id"]] = specimen
                variants[variant["variant_id"]] = variant
                rows.append(row)
                print(f"  [tier] {name:<10} {subject:<9} {row['level']:<16} "
                      f"{str(row.get('reason') or '')[:60]}"[:150], flush=True)
    finally:
        census._cleanup(SCRATCH)

    rt._apply_baseline(rows)
    # the carried authority baseline is the committed one; the measured members get theirs derived.
    for m in tier:
        auth_rows = [r for r in rows if r["family_id"] == m["family_id"]
                     and r["subject"] == "authority"]
        if auth_rows:
            best = max(auth_rows, key=lambda r: RANK.get(str(r.get("level")), -1))
            m["authority_applicable_baseline"] = str(best.get("level"))
    rows.sort(key=lambda r: (str(r.get("family_id")), str(r.get("subject"))))

    accounting = _accounting(freeze_body, tier)
    counts = _counts(tier, rows, accounting)
    body = {
        "rule": RULE,
        "authority": authority_id,
        "authority_prefix": rel(auth_prefix),
        "candidate_identity": bl.candidate_identity(),
        "tier": tier,
        "precedent_consumers": [
            {"harness": h, "family_id": s["family_id"], "version": s["version"], "url": s["url"],
             "sha256": s["sha256"], "harness_path": rel(PHASE17_DOWNSTREAM / h / "build.sh"),
             "program": s["program"]}
            for h, s in sorted(PRECEDENT_CONSUMERS.items())
        ],
        "specimens": sorted(specimens.values(), key=lambda s: str(s["specimen_id"])),
        "variants": sorted(variants.values(), key=lambda v: str(v["variant_id"])),
        "runs": rows,
        "accounting": accounting,
        "counts": counts,
        "resource_limits": limits,
        "non_claims": NON_CLAIMS,
    }
    return body


def _accounting(freeze_body: dict, tier: list[dict]) -> list[dict]:
    """One accounting row per frozen P1000 family -- a tier member measured, the rest with a reason."""
    tier_ids = {m["family_id"] for m in tier}
    by_id = {m["family_id"]: m for m in tier}
    out: list[dict] = []
    for e in _p1000(freeze_body):
        fid = str(e.get("family_id"))
        if fid in tier_ids:
            out.append({"family_id": fid, "canonical_name": e.get("canonical_name"),
                        "p1000_rank": e.get("p1000_rank"), "selection": "tier_measured",
                        "tier_source": by_id[fid]["source"], "reason": None})
        else:
            out.append({"family_id": fid, "canonical_name": e.get("canonical_name"),
                        "p1000_rank": e.get("p1000_rank"), "selection": "not_selected",
                        "tier_source": None,
                        "reason": ("not in the frozen deep tier: no committed 24.3 OpenSSL usage "
                                   "fingerprint reaching the functional level and no committed "
                                   "Phase-17 deep-consumer precedent")})
    out.sort(key=lambda r: (int(r["p1000_rank"]) if r.get("p1000_rank") is not None else 10 ** 9,
                            str(r["family_id"])))
    return out


def _counts(tier: list[dict], rows: list[dict], accounting: list[dict]) -> dict:
    """Every count, computed from the tier, the rows and the accounting -- never typed."""
    def levels(subject: str, rung: str) -> int:
        return sum(1 for r in rows if r.get("subject") == subject
                   and RANK.get(str(r.get("level")), -1) >= RANK[rung])

    def outcomes(subject: str, outcome: str) -> int:
        return sum(1 for r in rows if r.get("subject") == subject and r.get("outcome") == outcome)

    baseline: dict[str, str] = {}
    for r in rows:
        if r.get("subject") == "authority":
            fid = str(r.get("family_id"))
            if RANK.get(str(r.get("level")), -1) > RANK.get(baseline.get(fid, L0), -1):
                baseline[fid] = str(r.get("level"))

    cand_rows = {str(r.get("family_id")): r for r in rows if r.get("subject") == "candidate"}
    reaches = 0
    for m in tier:
        base = baseline.get(m["family_id"], L0)
        cand = cand_rows.get(m["family_id"])
        cand_rank = RANK.get(str(cand.get("level")), -1) if cand else -1
        if cand_rank >= RANK.get(base, -1):
            reaches += 1

    failure_histogram: dict[str, int] = {}
    for r in rows:
        if r.get("subject") == "candidate" and r.get("outcome") in ("failed", "not_attempted"):
            fc = r.get("failure_class")
            if fc:
                failure_histogram[fc] = failure_histogram.get(fc, 0) + 1

    not_measured = []
    for m in tier:
        auth = next((r for r in rows if r["family_id"] == m["family_id"]
                     and r["subject"] == "authority"), None)
        cand = cand_rows.get(m["family_id"])
        if (auth is None or RANK.get(str(auth.get("level")), -1) < RANK[L5]
                or cand is None or RANK.get(str(cand.get("level")), -1) < RANK[L5]):
            not_measured.append({
                "family": m["canonical_name"], "family_id": m["family_id"],
                "reason": ((auth or {}).get("reason") or (cand or {}).get("reason")
                           or "no run reached L5-loaded under both subjects")})

    sel = {"tier_measured": 0, "not_selected": 0}
    for r in accounting:
        sel[str(r.get("selection"))] = sel.get(str(r.get("selection")), 0) + 1

    return {
        "tier_size": len(tier),
        "tier_fingerprint": sum(1 for m in tier if m["source"] == "fingerprint"),
        "tier_precedent": sum(1 for m in tier if m["source"] == "precedent"),
        "tier_in_p1000": sum(1 for m in tier if m.get("p1000_rank") is not None),
        "tier_outside_p1000": sum(1 for m in tier if m.get("p1000_rank") is None),
        "rows": len(rows),
        "p1000_accounted": len(accounting),
        "p1000": len(accounting),
        "accounting": {"tier_measured": sel.get("tier_measured", 0),
                       "not_selected": sel.get("not_selected", 0)},
        "by_subject": {
            subject: {
                "loaded": levels(subject, L5),
                "runtime": levels(subject, L6),
                "functional": levels(subject, L7),
                "failed": outcomes(subject, "failed"),
                "not_attempted": outcomes(subject, "not_attempted"),
            }
            for subject in SUBJECTS
        },
        "authority_applicable_level": baseline,
        "candidate_reaches_baseline": reaches,
        "candidate_failures": failure_histogram,
        "tier_not_measured": not_measured,
        "candidate_specific_patch_count": sum(
            int(r.get("candidate_specific_patch_count") or 0) for r in rows),
    }


# ---------------------------------------------------------------------------------------------------
# the artefact
# ---------------------------------------------------------------------------------------------------

def write_outputs(body: dict, authority_id: str) -> None:
    inputs = [
        InputRef(name="family-freeze", path=FAMILY_FREEZE),
        InputRef(name="families", path=FAMILIES),
        InputRef(name="usage-fingerprints", path=USAGE_FINGERPRINTS),
        InputRef(name="runtime-functional-atlas", path=RUNTIME_FUNCTIONAL_ATLAS),
        InputRef(name="build-link-atlas", path=BUILD_LINK_ATLAS),
        InputRef(name="downstream-high-value",
                 path=REPO_ROOT / "forensics" / "tools" / "downstream_high_value.py"),
        InputRef(name="downstream-runtime",
                 path=REPO_ROOT / "forensics" / "tools" / "downstream_runtime.py"),
        InputRef(name="downstream-build-link",
                 path=REPO_ROOT / "forensics" / "tools" / "downstream_build_link.py"),
        InputRef(name="downstream-census",
                 path=REPO_ROOT / "forensics" / "tools" / "downstream_census.py"),
        InputRef(name="downstream-schemas",
                 path=REPO_ROOT / "forensics" / "tools" / "downstream_schemas.py"),
        InputRef(name="phase24-guard",
                 path=REPO_ROOT / "forensics" / "tools" / "phase24_guard.py"),
        InputRef(name="phase-24-plan",
                 path=REPO_ROOT / "docs" / "PHASE-24-DOWNSTREAM-1000-SUBPHASES.md"),
    ]
    for h in sorted(PRECEDENT_CONSUMERS):
        p = PHASE17_DOWNSTREAM / h / "build.sh"
        if p.is_file():
            inputs.append(InputRef(name=f"phase17-harness/{h}", path=p))
    doc = envelope(kind="downstream-high-value-tier", authority=authority_id,
                   inputs=inputs, body=body, generator=GENERATOR)
    doc["body_hash"] = content_hash(body)
    write_json(OUT, doc)


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8")).get("body", {})


# ---------------------------------------------------------------------------------------------------
# the checks the court re-runs over the committed artefact (pure; never rebuilding)
# ---------------------------------------------------------------------------------------------------

def _derive_recipe_families() -> set[str]:
    return {r["family"] for r in bl.RECIPES}


def high_value_findings(fingerprints_body: dict, runtime_body: dict, families_body: dict,
                        freeze_body: dict, tier_body: dict) -> list[str]:
    """Every way the recorded high-value deep tier fails its own subject.

    Pure over the committed 24.3 fingerprints, the committed families, the committed frozen P1000 and
    the committed 24.7 runtime/functional atlas, so the court re-runs it without rebuilding and the
    sensitivity control can mutate an in-memory copy. Every check is a re-derivation: the tier
    reproduces from the frozen depth rule; every tier member has both-subject runs; a candidate row
    never claims a level above the authority-applicable baseline; an `L5+` row is backed by a real
    load/linkage proof; an `L6`/`L7` row has a non-empty normalised transcript hash and a normalisation
    that erases no evidence; a carried row cites a committed 24.7 row that agrees on its level and
    transcript hash; every non-selected P1000 family carries a reason; the counts are read not typed;
    and `candidate_specific_patch_count` is 0.
    """
    findings: list[str] = []
    p1000 = _p1000(freeze_body)
    p1000_ids = {str(e.get("family_id")) for e in p1000}

    derived = derive_tier(fingerprints_body, runtime_body, families_body, _derive_recipe_families())
    derived_key = [(m["family_id"], m["source"], m["depth_rank"]) for m in derived]
    recorded = tier_body.get("tier") or []
    recorded_key = [(str(m.get("family_id")), str(m.get("source")), m.get("depth_rank"))
                    for m in recorded]
    if recorded_key != derived_key:
        findings.append("the recorded tier does not reproduce from the frozen depth rule: the derived "
                        f"members are {derived_key} but the artefact records {recorded_key}")

    # The depth order is the frozen rule's order, checked independently on the fingerprint members.
    by_id = {str(f.get("family_id")): f for f in (families_body.get("families") or [])}
    entries = [depth_entry(fp, by_id) for fp in (fingerprints_body.get("fingerprints") or [])]
    derived_ranks = {e["family_id"]: i for i, e in enumerate(sorted(entries, key=depth_key), 1)}
    for m in recorded:
        if m.get("source") == "fingerprint":
            if m.get("depth_rank") != derived_ranks.get(str(m.get("family_id"))):
                findings.append(f"{m.get('canonical_name')}: depth_rank {m.get('depth_rank')!r} is not "
                                f"the frozen rule's rank "
                                f"{derived_ranks.get(str(m.get('family_id')))!r}")

    tier_ids = {str(m.get("family_id")) for m in recorded}
    tier_names = {str(m.get("canonical_name")) for m in recorded}

    # Every tier member maps to a real committed direct-consumer family.
    for m in recorded:
        fam = by_id.get(str(m.get("family_id")))
        if fam is None:
            findings.append(f"{m.get('canonical_name')}: tier member is not a committed family")
        elif str(fam.get("openssl_linkage")) != "direct":
            findings.append(f"{m.get('canonical_name')}: tier member is not a direct consumer")
        if m.get("source") == "precedent":
            hp = m.get("harness_path")
            if not (hp and (REPO_ROOT / str(hp)).is_file()):
                findings.append(f"{m.get('canonical_name')}: a precedented tier member names no "
                                f"committed Phase-17 harness")

    runs = tier_body.get("runs") or []
    if not runs:
        return findings + ["the tier records no run"]

    rt_rows: dict[str, dict] = {str(r.get("run_id")): r for r in (runtime_body.get("runs") or [])}
    by_fs: dict[tuple[str, str], dict] = {}
    seen_ids: set[str] = set()
    for row in runs:
        fid = str(row.get("family_id"))
        subject = str(row.get("subject"))
        name = str(row.get("canonical_name"))
        findings += [f"{name}/{subject}: {p}" for p in downstream_schemas.validate_run(row)]
        rid = str(row.get("run_id"))
        if rid in seen_ids:
            findings.append(f"two tier rows share run_id {rid!r}")
        seen_ids.add(rid)
        if fid not in tier_ids:
            findings.append(f"{name}: a run row is not a tier member -- a family cannot enter the "
                            f"tier by a result rather than the depth rule")
        by_fs[(fid, subject)] = row

        if int(row.get("candidate_specific_patch_count") or 0) != 0:
            findings.append(f"{name}/{subject}: candidate_specific_patch_count is "
                            f"{row.get('candidate_specific_patch_count')!r}, not 0")

        carried = row.get("carried_from")
        if carried:
            src = rt_rows.get(str(carried))
            if src is None:
                findings.append(f"{name}/{subject}: carried_from {carried!r} is not a committed 24.7 "
                                f"run")
            elif (str(src.get("level")) != str(row.get("level"))
                  or str(src.get("transcript_sha256")) != str(row.get("transcript_sha256"))):
                findings.append(f"{name}/{subject}: the carried row disagrees with the committed 24.7 "
                                f"row it cites ({carried!r})")

        level_rank = RANK.get(str(row.get("level")), -1)
        if level_rank >= RANK[L5]:
            if not row.get("linkage_proven"):
                findings.append(f"{name}/{subject}: claims {row.get('level')} but its load/linkage is "
                                f"not proven")
            proof = row.get("load_proof") or {}
            if proof.get("proven") is not True:
                findings.append(f"{name}/{subject}: a {row.get('level')} row carries no proven load "
                                f"proof")
            link = row.get("link") or {}
            if link.get("all_under_prefix") is not True:
                findings.append(f"{name}/{subject}: a {row.get('level')} row does not resolve every "
                                f"OpenSSL soname under the subject prefix")
            if subject == "candidate" and (row.get("resolved_under_authority")
                                           or link.get("resolved_under_authority")):
                findings.append(f"{name}/{subject}: a candidate {row.get('level')} row resolves the "
                                f"authority prefix")
        if level_rank >= RANK[L6]:
            ts = str(row.get("transcript_sha256") or "")
            if len(ts) != 64:
                findings.append(f"{name}/{subject}: a {row.get('level')} row has no non-empty "
                                f"transcript hash")
            norm = row.get("normalisation") or {}
            if not norm.get("tag"):
                findings.append(f"{name}/{subject}: a {row.get('level')} row carries no normalisation "
                                f"tag")
            bad = [c for c in (norm.get("normalises") or []) if c not in NORMALISATION_ALLOWED]
            if bad:
                findings.append(f"{name}/{subject}: the normalisation erases evidence ({sorted(bad)})")
        if not row.get("local_only"):
            findings.append(f"{name}/{subject}: a tier row is not marked local-only")
        outcome = row.get("outcome")
        if outcome in ("failed", "not_attempted", "unavailable"):
            if not row.get("reason"):
                findings.append(f"{name}/{subject}: a {outcome} row carries no reason")
            if not row.get("failure_class"):
                findings.append(f"{name}/{subject}: a {outcome} row carries no failure class")
            elif row["failure_class"] not in downstream_schemas.FAILURE_CLASSES:
                findings.append(f"{name}/{subject}: failure class {row['failure_class']!r} is outside "
                                f"the taxonomy")

    # Every tier member has both-subject runs.
    for m in recorded:
        for subject in SUBJECTS:
            if (m["family_id"], subject) not in by_fs:
                findings.append(f"{m.get('canonical_name')}: no {subject} tier run")

    # The candidate never claims a level above the authority-applicable baseline.
    baseline: dict[str, str] = {}
    for row in runs:
        if row.get("subject") == "authority":
            fid = str(row.get("family_id"))
            if RANK.get(str(row.get("level")), -1) > RANK.get(baseline.get(fid, L0), -1):
                baseline[fid] = str(row.get("level"))
    for row in runs:
        if row.get("subject") != "candidate":
            continue
        fid = str(row.get("family_id"))
        base = baseline.get(fid, L0)
        if str(row.get("authority_applicable_level")) != base:
            findings.append(f"{row.get('canonical_name')}/candidate: records "
                            f"authority_applicable_level {row.get('authority_applicable_level')!r}, "
                            f"but the authority rows reached {base!r}")
        cand_rank = RANK.get(str(row.get("level")), -1)
        if cand_rank > RANK.get(base, -1):
            findings.append(f"{row.get('canonical_name')}/candidate: claims {row.get('level')}, above "
                            f"the authority-applicable baseline {base!r} the authority reached")
        want_reach = cand_rank >= RANK.get(base, -1)
        if bool(row.get("reaches_baseline")) != want_reach:
            findings.append(f"{row.get('canonical_name')}/candidate: reaches_baseline is "
                            f"{row.get('reaches_baseline')!r}, but {row.get('level')!r} against "
                            f"{base!r} is {want_reach}")

    # Every non-selected P1000 family carries a reason; the accounting covers every P1000 family.
    accounting = tier_body.get("accounting") or []
    acc_ids = [str(r.get("family_id")) for r in accounting]
    if len(set(acc_ids)) != len(acc_ids):
        findings.append("the accounting covers a P1000 family more than once")
    missing = [fid for fid in p1000_ids if fid not in set(acc_ids)]
    if missing:
        findings.append(f"{len(missing)} frozen P1000 family(ies) have no accounting row "
                        f"(e.g. {sorted(missing)[:3]})")
    extra = [fid for fid in set(acc_ids) if fid not in p1000_ids]
    if extra:
        findings.append(f"the accounting carries a family outside the frozen P1000 "
                        f"(e.g. {sorted(extra)[:3]})")
    for r in accounting:
        sel = str(r.get("selection"))
        if sel == "not_selected" and not r.get("reason"):
            findings.append(f"{r.get('canonical_name')}: a not_selected P1000 family carries no reason")
        if sel == "tier_measured" and str(r.get("family_id")) not in tier_ids:
            findings.append(f"{r.get('canonical_name')}: a family is tier_measured but is not a tier "
                            f"member")
        if sel not in ("tier_measured", "not_selected"):
            findings.append(f"{r.get('canonical_name')}: accounting selection {sel!r} is not "
                            f"tier_measured/not_selected")

    # The recorded rule and non-claims are the frozen ones.
    if tier_body.get("rule") != RULE:
        findings.append("the recorded tier rule is not the frozen rule")
    if tier_body.get("non_claims") != NON_CLAIMS:
        findings.append("the recorded non_claims are not the stratum's four plus the deep-tier "
                        "non-claim")

    # Counts are read, not typed.
    derived_counts = _counts(recorded, runs, accounting)
    recorded_counts = tier_body.get("counts") or {}
    for key in ("tier_size", "tier_fingerprint", "tier_precedent", "tier_in_p1000",
                "tier_outside_p1000", "rows", "p1000_accounted", "p1000",
                "candidate_reaches_baseline", "candidate_specific_patch_count"):
        if recorded_counts.get(key) != derived_counts[key]:
            findings.append(f"counts.{key} {recorded_counts.get(key)!r} disagrees with the derived "
                            f"{derived_counts[key]!r}")
    if recorded_counts.get("accounting") != derived_counts["accounting"]:
        findings.append("counts.accounting disagrees with the derived accounting")
    for subject in SUBJECTS:
        for rung in ("loaded", "runtime", "functional", "failed", "not_attempted"):
            got = (recorded_counts.get("by_subject") or {}).get(subject, {}).get(rung)
            want = derived_counts["by_subject"][subject][rung]
            if got != want:
                findings.append(f"counts.by_subject.{subject}.{rung} {got!r} disagrees with the "
                                f"derived {want!r}")
    if recorded_counts.get("authority_applicable_level") != derived_counts["authority_applicable_level"]:
        findings.append("counts.authority_applicable_level disagrees with the derived baseline map")
    if (recorded_counts.get("candidate_failures") or {}) != derived_counts["candidate_failures"]:
        findings.append("counts.candidate_failures disagrees with the derived histogram")
    if (recorded_counts.get("tier_not_measured") or []) != derived_counts["tier_not_measured"]:
        findings.append("counts.tier_not_measured disagrees with the derived not-measured list")
    return findings


def _mutations(tier_body: dict, fingerprints_body: dict, runtime_body: dict) -> list[tuple[str, str,
                                                                                          dict]]:
    """`(name, needle, mutated_body)` for each seeded mutation."""
    del fingerprints_body, runtime_body
    out: list[tuple[str, str, dict]] = []
    runs = tier_body.get("runs") or []

    # a tier member dropped.
    m1 = copy.deepcopy(tier_body)
    if m1["tier"]:
        drop = m1["tier"][0]["family_id"]
        m1["tier"] = [m for m in m1["tier"] if m["family_id"] != drop]
        m1["runs"] = [r for r in m1["runs"] if r.get("family_id") != drop]
    out.append(("tier_member_dropped", "does not reproduce from the frozen depth rule", m1))

    # a family added to the tier by a candidate result rather than the depth rule.
    m2 = copy.deepcopy(tier_body)
    acc = next((r for r in m2.get("accounting") or [] if r.get("selection") == "not_selected"), None)
    if acc is not None:
        m2["tier"] = list(m2["tier"]) + [{"family_id": acc["family_id"],
                                          "canonical_name": acc["canonical_name"],
                                          "source": "fingerprint", "depth_rank": 99,
                                          "depth": None, "authority_applicable_baseline": L7,
                                          "admission": "added by a candidate result"}]
    out.append(("family_added_by_candidate_result",
                "does not reproduce from the frozen depth rule", m2))

    # a candidate run claiming a level above the authority-applicable baseline it was normalized
    # against (the authority reached a lower level), marked pass.
    m3 = copy.deepcopy(tier_body)
    base: dict[str, int] = {}
    for r in m3["runs"]:
        if r.get("subject") == "authority":
            fid = str(r.get("family_id"))
            base[fid] = max(base.get(fid, -1), RANK.get(str(r.get("level")), -1))
    cand = next((r for r in m3["runs"] if r.get("subject") == "candidate"
                 and base.get(str(r.get("family_id")), -1) < RANK["L8-authority-equivalent"]), None)
    if cand is not None:
        cand["level"] = "L8-authority-equivalent"
        cand["outcome"] = "reached"
        cand["residual_class"] = "none"
    out.append(("candidate_level_above_authority_baseline",
                "above the authority-applicable baseline", m3))

    # an L5 row with no load proof.
    m4 = copy.deepcopy(tier_body)
    loaded = next((r for r in m4["runs"] if RANK.get(str(r.get("level")), -1) >= RANK[L5]), None)
    if loaded is not None:
        loaded["linkage_proven"] = False
        loaded["load_proof"] = {"proven": False}
    out.append(("loaded_row_without_proof", "load/linkage is not proven", m4))

    # an empty transcript at L6.
    m5 = copy.deepcopy(tier_body)
    runtime = next((r for r in m5["runs"] if RANK.get(str(r.get("level")), -1) >= RANK[L6]), None)
    if runtime is not None:
        runtime["transcript_sha256"] = ""
    out.append(("runtime_row_without_transcript", "no non-empty transcript hash", m5))

    # a not_selected P1000 family with its reason removed.
    m6 = copy.deepcopy(tier_body)
    ns = next((r for r in m6.get("accounting") or [] if r.get("selection") == "not_selected"), None)
    if ns is not None:
        ns["reason"] = None
    out.append(("non_selected_family_without_reason", "carries no reason", m6))
    return out


def high_value_sensitivity_control(fingerprints_body: dict, runtime_body: dict, families_body: dict,
                                   freeze_body: dict, tier_body: dict) -> dict:
    """Prove the court can fail: seed six mutations and require each caught with specificity holding.

    The honest tier must yield **zero** findings (specificity), and each seeded mutation -- a tier
    member dropped, a family added to the tier by a candidate result, a candidate `L7` where the
    authority reached `L5` marked pass, an `L5` row with no load proof, an empty transcript at `L6`,
    and a not-selected P1000 family with no reason -- must be caught with a finding naming it.
    """
    base = high_value_findings(fingerprints_body, runtime_body, families_body, freeze_body, tier_body)
    control: dict = {"baseline_findings": len(base), "specificity_holds": not base}
    honest = not base
    for name, needle, mutated in _mutations(tier_body, fingerprints_body, runtime_body):
        caught = any(needle in f for f in
                     high_value_findings(fingerprints_body, runtime_body, families_body, freeze_body,
                                         mutated))
        control[f"injected_{name}"] = name
        control[f"caught_{name}"] = caught
        honest = honest and caught
    control["honest"] = bool(honest)
    return control


# ---------------------------------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------------------------------

def _load_inputs() -> tuple[dict, dict, dict, dict]:
    for path, what, sub in ((USAGE_FINGERPRINTS, "usage fingerprints", "24.3"),
                            (RUNTIME_FUNCTIONAL_ATLAS, "runtime/functional atlas", "24.7"),
                            (FAMILY_FREEZE, "frozen P1000", "24.4")):
        if not path.is_file():
            raise SystemExit(f"[downstream-high-value] {rel(path)} is absent; run {sub} first")
    fps = _load_json(USAGE_FINGERPRINTS)
    runtime = _load_json(RUNTIME_FUNCTIONAL_ATLAS)
    freeze = _load_json(FAMILY_FREEZE)
    families = _load_json(FAMILIES) if FAMILIES.is_file() else {}
    return fps, runtime, families, freeze


def cmd_measure(authority_id: str) -> int:
    fps, runtime, families, freeze = _load_inputs()
    if len(_p1000(freeze)) != 1000:
        print(f"[downstream-high-value] the frozen P1000 carries {len(_p1000(freeze))} family(ies), "
              f"not 1000")
        return 1
    print(f"[downstream-high-value] measuring the high-value deep tier against both subjects "
          f"(authority {authority_id} + candidate {rel(CANDIDATE_PREFIX)})")
    started = time.monotonic()
    body = derive_tier_body(fps, runtime, families, freeze, authority_id)
    findings = high_value_findings(fps, runtime, families, freeze, body)
    control = high_value_sensitivity_control(fps, runtime, families, freeze, body)
    if findings or not control["honest"]:
        print("[downstream-high-value] the measured tier fails its own checks:")
        for f in findings:
            print(f"  - {f}")
        if not control["honest"]:
            print(f"  - the sensitivity control is not honest: {control}")
        return 1
    write_outputs(body, authority_id)
    c = body["counts"]
    print(f"[downstream-high-value] elapsed={time.monotonic() - started:.0f}s tier={c['tier_size']} "
          f"(fingerprint={c['tier_fingerprint']} precedent={c['tier_precedent']}) "
          f"in_p1000={c['tier_in_p1000']} outside={c['tier_outside_p1000']}")
    for subject in SUBJECTS:
        s = c["by_subject"][subject]
        print(f"  {subject:<9} loaded={s['loaded']} runtime={s['runtime']} "
              f"functional={s['functional']} failed={s['failed']} "
              f"not_attempted={s['not_attempted']}")
    print(f"  candidate_reaches_baseline={c['candidate_reaches_baseline']} "
          f"candidate_failures={c['candidate_failures']} accounting={c['accounting']}")
    print(f"  -> {rel(OUT)}")
    return 0


def cmd_check(authority_id: str) -> int:
    del authority_id
    if not OUT.is_file():
        print(f"[downstream-high-value] {rel(OUT)} is absent")
        return 1
    fps, runtime, families, freeze = _load_inputs()
    body = _load_json(OUT)
    findings = high_value_findings(fps, runtime, families, freeze, body)
    control = high_value_sensitivity_control(fps, runtime, families, freeze, body)
    if findings:
        print(f"[downstream-high-value] {len(findings)} finding(s):")
        for f in findings:
            print(f"  - {f}")
    c = body.get("counts") or {}
    by = c.get("by_subject") or {}
    print(f"[downstream-high-value] tier={c.get('tier_size')} "
          f"cand_functional={(by.get('candidate') or {}).get('functional')} "
          f"reaches_baseline={c.get('candidate_reaches_baseline')} findings={len(findings)} "
          f"control honest={control['honest']}")
    return 0 if (not findings and control["honest"]) else 1


def self_test() -> int:
    """Prove the guard refuses a host invocation and the pure functions behave over committed data."""
    failures: list[str] = []

    # 1. The guard refuses a host invocation of this tool, naming the marker and the opt-in flag.
    refusal = phase24_guard.host_refusal_reasons("downstream_high_value.py")
    if not refusal:
        failures.append("the guard admitted a host invocation of downstream_high_value.py")
    else:
        manifest = phase24_guard.load_manifest()
        joined = " ".join(refusal)
        if str(manifest.get("marker")) not in joined:
            failures.append("the host refusal does not name the container marker")
        if str(manifest.get("env_flag")) not in joined:
            failures.append("the host refusal does not name the opt-in flag")

    # 2. The precedented deep-consumer specs match the committed Phase-17 harnesses.
    for harness, spec in PRECEDENT_CONSUMERS.items():
        build_sh = PHASE17_DOWNSTREAM / harness / "build.sh"
        if not build_sh.is_file():
            failures.append(f"the Phase-17 harness {rel(build_sh)} is absent")
            continue
        text = build_sh.read_text(encoding="utf-8", errors="ignore")
        if spec["version"] not in text:
            failures.append(f"the {harness} harness does not name version {spec['version']}")

    # 3. The depth order is candidate-blind and the API-family breadth is derived.
    if _api_family("EVP_DigestInit_ex") != "EVP" or _api_family("SSL_new") != "SSL":
        failures.append("the API-family breadcrumb is not the token before the first '_'")

    # 4. The pure functions behave over the committed evidence.
    if not (USAGE_FINGERPRINTS.is_file() and RUNTIME_FUNCTIONAL_ATLAS.is_file()
            and FAMILY_FREEZE.is_file()):
        failures.append(f"{rel(USAGE_FINGERPRINTS)}, {rel(RUNTIME_FUNCTIONAL_ATLAS)} or "
                        f"{rel(FAMILY_FREEZE)} is absent")
    else:
        fps, runtime, families, freeze = _load_inputs()
        if len(_p1000(freeze)) != 1000:
            failures.append("the frozen P1000 does not carry 1000 family(ies)")
        derived = derive_tier(fps, runtime, families, _derive_recipe_families())
        if not derived:
            failures.append("the frozen depth rule selected no tier member")
        if not OUT.is_file():
            failures.append(f"{rel(OUT)} is absent; run --measure")
        else:
            body = _load_json(OUT)
            findings = high_value_findings(fps, runtime, families, freeze, body)
            if findings:
                failures.append(f"the committed tier has findings: {findings[:3]}")
            control = high_value_sensitivity_control(fps, runtime, families, freeze, body)
            if not control["honest"]:
                failures.append(f"the sensitivity control is not honest: {control}")

    if failures:
        print("[downstream-high-value] self-test FAILED")
        for f in failures:
            print(f"  {f}")
        return 1
    print("[downstream-high-value] self-test ok: the guard refuses a host invocation of this tool "
          "(marker and flag both named), the precedented specs match the committed Phase-17 harnesses, "
          "the depth order is candidate-blind, the committed tier reproduces with zero findings, and "
          "every seeded mutation (a tier member dropped, a family added by a candidate result, a "
          "candidate L7 above the authority baseline, an L5 row with no proof, an empty transcript at "
          "L6, a not-selected family with no reason) is caught with specificity holding")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    ap.add_argument("--measure", action="store_true",
                    help="run the real builds and workloads and write the tier (in-container)")
    ap.add_argument("--check", action="store_true",
                    help="validate the committed tier without rebuilding (in-container)")
    ap.add_argument("--self-test", action="store_true",
                    help="prove the pure functions over the committed evidence")
    args = ap.parse_args(argv)

    # The Docker-only execution guard, called first. This tool fetches, compiles and runs, so it is an
    # execution entry point and a host invocation is refused.
    phase24_guard.require_admitted()

    if args.self_test:
        return self_test()
    if args.check:
        return cmd_check(args.authority)
    return cmd_measure(args.authority)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
