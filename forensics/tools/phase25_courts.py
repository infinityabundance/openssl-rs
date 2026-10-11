#!/usr/bin/env python3
"""openssl-rs — Phase 25 courts: the memory-safety, unsafe-TCB and CVE-extinction courts.

Each court is an instrument that makes the memory-safety model of `docs/RELEASE_GATES.md` section 1
mechanical over the exact admitted candidate's shipped first-party source/build surface, not a
differential probe over a symbol set. This stratum owns no exported symbol: it inventories the
memory-safety-relevant trusted computing base, maps compiler-derived unsafe operations to their
safety contracts, their Phase-22 reachability, their Phase-24 downstream usage and the available
dynamic/formal evidence, and reconciles the historical OpenSSL CVEs against the candidate's
structure. The method is Phases 3 through 24's where an artefact carries the expectation: each
court reads the artefact that holds its subject rather than typing the expectation beside it, so the
two cannot disagree, and a court whose control is not honest is `fail` rather than `pass`.

**25.0 registers `MS-CONSTITUTION`, 25.1 registers the compiler-backed census, 25.2 registers the
non-Rust trusted computing base, 25.3 registers the safety obligations, 25.4 registers the
ownership/allocation/callback planes, 25.5 registers the Phase-22 reachability crosswalk, 25.6
registers the Phase-24 downstream crosswalk and 25.7 registers the exposure/data-flow
classification.** The
stratum's
obligations are not exports, so its courts read committed evidence rather than diffing a staged
probe pair, and `run_courts.py` would refuse a stratum in `in-progress` with no runner at all -- so
this runner landed at activation with an empty registry, naming the twenty-two courts it stages
each with the subphase that lands it. **25.0 registers `MS-CONSTITUTION`**, the constitution gate
over the plan, schemas, guard, venue manifest, ledger and the frozen safety lint policy.
**25.1 registers `MS-SOURCE-CENSUS`**, the compiler-backed source census: it reads the committed
`artifacts/phase25/source-census.json` and re-runs the 25.1 pure checks (`ms_census.census_findings`,
`ms_census.census_sensitivity_control`) over it without a compiler, so the census's own measurement
is the court's subject. **25.2 registers `MS-NON-RUST-TCB`**, the non-Rust trusted computing base: it
reads the committed `artifacts/phase25/non-rust-tcb.json` and re-runs the 25.2 pure checks
(`ms_non_rust_tcb.non_rust_findings`, `ms_non_rust_tcb.non_rust_sensitivity_control`) over it and the
on-disk file universe, so the inventory of the first-party C, the generated C scaffolds, the
`core::arch` assembly surface and the FFI boundaries is the court's subject. **25.3 registers
`MS-SAFETY-OBLIGATIONS`**, the safety obligations: it reads the committed
`artifacts/phase25/safety-obligations.json` and re-runs the 25.3 pure checks
(`ms_obligations.obligation_findings`, `ms_obligations.obligation_sensitivity_control`) over it, the
committed census it is derived from and the committed TCB it cross-references, so one obligation set
per compiler-derived unsafe site -- every census site bound, every census context represented, no
`discharged` without a source-stated contract and a discharging proof -- is the court's subject.
court's subject. **25.4 registers `MS-OWNERSHIP-PLANES`**, the ownership/allocation/callback planes: it reads the
committed `artifacts/phase25/ownership-planes.json` and re-runs the 25.4 pure checks
(`ms_ownership_planes.ownership_findings`, `ms_ownership_planes.ownership_sensitivity_control`) over
it, the committed census, the committed TCB and the committed source tree, so the allocation/
deallocation associations, the ownership edges across the Rust/C boundary, the callback lifetimes,
the unsafe `Send`/`Sync` impls, the global/static state and the panic/unwind boundaries are the
court's subject. **25.5 registers `MS-PHASE22-CROSSWALK`**, the Phase-22 reachability crosswalk: it
reads the committed `artifacts/phase25/phase22-crosswalk.json` and re-runs the 25.5 pure checks
(`ms_phase22_crosswalk.crosswalk_findings`, `ms_phase22_crosswalk.crosswalk_sensitivity_control`)
over it, the committed census and the committed Phase-22 whole-program atlas, so every unsafe site's
reachability is the Phase-22 authority's answer (mapped to a public root or an explicit unresolved
residual) rather than a second, typed one. **25.6 registers `MS-PHASE24-CROSSWALK`**, the Phase-24
downstream crosswalk: it reads the committed `artifacts/phase25/phase24-crosswalk.json` and re-runs
the 25.6 pure checks (`ms_phase24_crosswalk.crosswalk_findings`,
`ms_phase24_crosswalk.crosswalk_sensitivity_control`) over it, the committed census and the committed
Phase-24 downstream measurement, so every unsafe site's downstream usage is the Phase-24
measurement's answer (a measured consumer that imports the site's public surface, or an explicit
not-observed disposition with a reason) rather than a typed one. **25.7 registers
`MS-EXPOSURE-CLASSIFICATION`**, the exposure/data-flow classification: it reads the committed
`artifacts/phase25/exposure.json` and re-runs the 25.7 pure checks (`ms_exposure.exposure_findings`,
`ms_exposure.exposure_sensitivity_control`) over it, the committed census, the committed 25.5 and
25.6 crosswalks and the committed 25.4 ownership planes, so every unsafe site's exposure class and
the attacker-input routes that reach its memory operations are the committed evidence's answer
rather than a typed one. The
registry is the file
`run_courts.py` checks is reproduced, so a court
silently dropped is a finding rather than a smaller green run. This is the reverse of Phase 16's
edge: the ledger's contract-unit states are measured from this registry, so this runner does
**not** bind the obligations ledger as an input.

**Every entry point calls the Docker-only execution guard first.** Phase 25's whole subject is
executing tools -- a compiler-backed census, Miri, ASan/MSan, TSan, Kani, the CVE replays -- and
`docs/REPRODUCIBILITY.md` section 1 says nothing executes on the host, so
`phase25_guard.require_admitted()` is the first statement of `main`. `--self-test` proves a host
invocation is refused by handing the guard the shape of a host invocation.

The record kinds these courts will populate are defined and self-tested in
`forensics/tools/memory_safety_schemas.py`; the registry records that schema inventory, and the
closed vocabularies (the unsafe-operation kinds, the obligation dimensions, the exposure classes,
the tool states, the CVE taxonomy, the CVE replay states, the risk tiers and the panic/unwind
classes), so the record kinds are a file the evidence points at rather than prose the plan would
have to restate.

The twenty-two courts, and the subphase that lands each
-------------------------------------------------------
  * `MS-CONSTITUTION` -- 25.0, the constitution.
  * `MS-SOURCE-CENSUS` -- 25.1, the compiler-backed census.
  * `MS-NON-RUST-TCB` -- 25.2, the non-Rust TCB.
  * `MS-SAFETY-OBLIGATIONS` -- 25.3, the safety obligations.
  * `MS-OWNERSHIP-PLANES` -- 25.4, the ownership/allocation/callback planes.
  * `MS-PHASE22-CROSSWALK` -- 25.5, the Phase-22 crosswalk.
  * `MS-PHASE24-CROSSWALK` -- 25.6, the Phase-24 crosswalk.
  * `MS-EXPOSURE-CLASSIFICATION` -- 25.7, the exposure/data-flow classification.
  * `MS-UNSAFE-REDUCTION` -- 25.8, the unsafe reduction.
  * `MS-MIRI` -- 25.9, Miri.
  * `MS-ASAN-MSMAN` -- 25.10, ASan/MSan.
  * `MS-TSAN` -- 25.11, TSan.
  * `MS-KANI` -- 25.12, Kani.
  * `MS-PHASE18-FUZZ-CROSSWALK` -- 25.13, the Phase-18 fuzz crosswalk.
  * `MS-PHASE24-SAFETY-COVERAGE` -- 25.14, the Phase-24 downstream safety coverage.
  * `MS-HISTORICAL-CVE` -- 25.15, the historical CVE census.
  * `MS-CVE-REPLAY` -- 25.16, the historical CVE replay.
  * `MS-MECHANISM-RECONCILIATION` -- 25.17, the vulnerability-mechanism reconciliation.
  * `MS-RED-TEAM` -- 25.18, the red team.
  * `MS-CLEAN-REGEN` -- 25.19, the full clean regeneration.
  * `MS-FRF-CLOSURE` -- 25.20, the FRF/Gemel closure.
  * `MS-SEAL` -- 25.21, the seal.

Every one is `pending` at activation and each becomes a registered, re-derivable court as the
subphase that lands its instrument commits. A passing court is an instrument, not a property claim,
and this stratum makes no claim beyond its bounded one: safe Rust does not prove protocol
correctness, unsafe Rust is not inherently vulnerable, unsafe LOC is not a vulnerability count,
Miri/ASan/TSan are not exhaustive, Kani does not prove unsupported or concurrent whole-program
behaviour, and historical CVE extinction does not predict a future CVE count.

The runner reads no obligations ledger: the ledger's contract-unit states are measured from this
registry, so the edge runs ledger -> courts and binding it back would form a digest cycle neither
artefact could reproduce. `docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md` section 4 is the precondition.
No court is registered in `gen_frf_courts.py`: that registry is the stratum's seal.

SPDX-License-Identifier: Apache-2.0
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
    envelope,
    rel,
    resolve_authority,
    write_json,
)

# The Docker-only execution guard. Its call is the first statement of `main`, and `--self-test`
# proves a host invocation is refused.
import phase25_guard  # noqa: E402

# The schemas the later subphases validate their records against. Imported rather than restated, so
# the registry's inventory cannot drift from the module the evidence is checked with.
import memory_safety_schemas  # noqa: E402

# 25.1's census tool and the artefact it writes. The court re-runs the tool's pure
# `census_findings` / `census_sensitivity_control` over the committed artefact; it does **not** run
# the compiler (the measurement that produced the artefact is the `ms_census.py --measure` run).
import ms_census  # noqa: E402

# 25.2's non-Rust trusted computing base (C, generated C, assembly and the FFI boundaries) and the
# tool that measures it. The court re-runs the tool's pure `non_rust_findings` /
# `non_rust_sensitivity_control` over the committed artefact and the on-disk file universe.
import ms_non_rust_tcb  # noqa: E402

# 25.3's safety obligations (one obligation set per compiler-derived unsafe site) and the tool that
# derives it from the committed 25.1 census and 25.2 TCB. The court re-runs the tool's pure
# `obligation_findings` / `obligation_sensitivity_control` over the committed artefact and the
# census it is derived from.
import ms_obligations  # noqa: E402

# 25.4's ownership, allocation and callback planes and the tool that derives them from the committed
# census, the committed TCB and the committed source text. The court re-runs the tool's pure
# `ownership_findings` / `ownership_sensitivity_control` over the committed artefact, the census, the
# TCB and the source context it classifies.
import ms_ownership_planes  # noqa: E402

# 25.5's Phase-22 reachability crosswalk and the tool that derives it from the committed census and
# the committed Phase-22 whole-program atlas. The court re-runs the tool's pure
# `crosswalk_findings` / `crosswalk_sensitivity_control` over the committed artefact, the census and
# the committed Phase-22 closure, its entity plane and the module -> authority-unit correspondence.
import ms_phase22_crosswalk  # noqa: E402

# 25.6's Phase-24 downstream crosswalk and the tool that derives it from the committed census, the
# committed 25.5 crosswalk and the committed Phase-24 downstream measurement. The court re-runs the
# tool's pure `crosswalk_findings` / `crosswalk_sensitivity_control` over the committed artefact, the
# census and the committed Phase-24 planes (the usage fingerprints, the runtime/build-link atlases,
# the reconciliation clusters and the family freeze) it joins to.
import ms_phase24_crosswalk  # noqa: E402

# 25.7's exposure/data-flow classification and the tool that derives it from the committed census, the
# committed 25.5 crosswalk, the committed 25.6 crosswalk and the committed 25.4 ownership planes. The
# court re-runs the tool's pure `exposure_findings` / `exposure_sensitivity_control` over the
# committed artefact and those planes.
import ms_exposure  # noqa: E402

# 25.8's unsafe reduction and the tool that derives its worklist from the committed census, the
# committed exposure classification and the committed source spans the census names. The court
# re-runs the tool's pure `reduction_findings` / `reduction_sensitivity_control` over the committed
# artefact, the census and the exposure classification.
import ms_reduction  # noqa: E402

# 25.9's Miri results and the tool that records them. The court re-runs the tool's pure
# `miri_findings` / `miri_sensitivity_control` over the committed plane and the committed census.
import ms_miri  # noqa: E402

# 25.10's ASan/MSan results and the tool that records them. The court re-runs the tool's pure
# `asan_findings` / `asan_sensitivity_control` over the committed plane and the committed census.
import ms_asan  # noqa: E402

# 25.11's TSan results and the tool that records them. The court re-runs the tool's pure
# `tsan_findings` / `tsan_sensitivity_control` over the committed plane, the committed census and
# the committed 25.3 obligation rule that defines the concurrency-relevant surface.
import ms_tsan  # noqa: E402

# The lossless columnar codec the Phase-25 artefacts are stored in. Every court decodes the
# committed artefact through `decode_body` before reading its records, so one implementation of the
# scheme serves the generator, the court and every cross-reader; the scheme is named by
# `body.encoding`.
import ms_codec  # noqa: E402

OUT = REPO_ROOT / "artifacts" / "phase25" / "COURTS.json"
GENERATOR = "forensics/tools/phase25_courts.py"
PLAN = REPO_ROOT / "docs" / "PHASE-25-MEMORY-SAFETY-SUBPHASES.md"
SCHEMAS = REPO_ROOT / "forensics" / "tools" / "memory_safety_schemas.py"
GUARD = REPO_ROOT / "forensics" / "tools" / "phase25_guard.py"
MANIFEST = REPO_ROOT / "forensics" / "memory-safety" / "container.json"
# 25.1's compiler-backed source census.
SOURCE_CENSUS = REPO_ROOT / "artifacts" / "phase25" / "source-census.json"
MS_CENSUS_TOOL = REPO_ROOT / "forensics" / "tools" / "ms_census.py"
SOURCE_CENSUS_COURT = "MS-SOURCE-CENSUS"

# The census artefact's size budget, in bytes. The measurement artefacts repeat a file path, a
# module, a kind, a method and a commit per record; written one object per record the census is
# 120 MB, over GitHub's 100 MB pre-receive limit, so it is stored as a lossless columnar body
# (see `ms_codec`) and this court fails if it exceeds the budget recorded in the plan's section 4.
# The budget is comfortably under the 100 MB hook (20 MiB) and well above the ~14 MiB the columnar
# form actually needs, so a real regression is caught and a legitimate growth has headroom.
SOURCE_CENSUS_BUDGET_BYTES = 20 * 1024 * 1024


def _census_view() -> tuple[dict, "ms_codec.Refs"]:
    """The committed census as a decoded record view and the ordered id lists it references."""
    doc = json.loads(SOURCE_CENSUS.read_text(encoding="utf-8"))
    view = ms_census.decode_body(doc.get("body", doc))
    return view, ms_codec.refs_from_census(view)


def _decoded_body(path: Path, refs: "ms_codec.Refs") -> dict:
    """A committed Phase-25 artefact's body, decoded through the columnar codec."""
    doc = json.loads(path.read_text(encoding="utf-8"))
    return ms_codec.decode_body(doc.get("body", doc), refs)

# 25.2's non-Rust trusted computing base and the tool that measures it.
NON_RUST_TCB = REPO_ROOT / "artifacts" / "phase25" / "non-rust-tcb.json"
MS_NON_RUST_TOOL = REPO_ROOT / "forensics" / "tools" / "ms_non_rust_tcb.py"
NON_RUST_TCB_COURT = "MS-NON-RUST-TCB"

# 25.3's safety obligations and the pure tool that derives them from the committed census and TCB.
SAFETY_OBLIGATIONS = REPO_ROOT / "artifacts" / "phase25" / "safety-obligations.json"
MS_OBLIGATIONS_TOOL = REPO_ROOT / "forensics" / "tools" / "ms_obligations.py"
SAFETY_OBLIGATIONS_COURT = "MS-SAFETY-OBLIGATIONS"

# 25.4's ownership/allocation/callback planes and the pure tool that derives them from the committed
# census, TCB and source text.
OWNERSHIP_PLANES = REPO_ROOT / "artifacts" / "phase25" / "ownership-planes.json"
MS_OWNERSHIP_TOOL = REPO_ROOT / "forensics" / "tools" / "ms_ownership_planes.py"
OWNERSHIP_PLANES_COURT = "MS-OWNERSHIP-PLANES"

# 25.5's Phase-22 reachability crosswalk and the pure tool that derives it from the committed
# census and the committed Phase-22 whole-program atlas.
PHASE22_CROSSWALK = REPO_ROOT / "artifacts" / "phase25" / "phase22-crosswalk.json"
MS_PHASE22_CROSSWALK_TOOL = REPO_ROOT / "forensics" / "tools" / "ms_phase22_crosswalk.py"
PHASE22_CROSSWALK_COURT = "MS-PHASE22-CROSSWALK"
PHASE22_CLOSURE = REPO_ROOT / "forensics" / "atlas" / "phase22" / "compatibility-closure.json"
PHASE22_RECONCILIATION = REPO_ROOT / "forensics" / "atlas" / "phase22" / "reconciliation.json"
TRANSCRIPTION_EDGES = REPO_ROOT / "forensics" / "atlas" / "transcription-edges.json"
INTERNAL_SYMBOLS = REPO_ROOT / "forensics" / "atlas" / "internal-symbols.json"
EXPORT_DEFINING_UNITS = REPO_ROOT / "forensics" / "atlas" / "export-defining-units.json"

# 25.6's Phase-24 downstream crosswalk, the pure tool that derives it from the committed census, the
# committed 25.5 crosswalk and the committed Phase-24 downstream measurement, and the Phase-24 planes
# it reads.
PHASE24_CROSSWALK = REPO_ROOT / "artifacts" / "phase25" / "phase24-crosswalk.json"
MS_PHASE24_CROSSWALK_TOOL = REPO_ROOT / "forensics" / "tools" / "ms_phase24_crosswalk.py"
PHASE24_CROSSWALK_COURT = "MS-PHASE24-CROSSWALK"
DOWNSTREAM_USAGE_FINGERPRINTS = (REPO_ROOT / "forensics" / "downstream"
                                / "usage-fingerprints.json")
DOWNSTREAM_RECONCILIATION = REPO_ROOT / "forensics" / "downstream" / "reconciliation.json"
DOWNSTREAM_RUNTIME_ATLAS = (REPO_ROOT / "forensics" / "downstream"
                            / "runtime-functional-atlas.json")
DOWNSTREAM_BUILD_LINK_ATLAS = REPO_ROOT / "forensics" / "downstream" / "build-link-atlas.json"
DOWNSTREAM_P1000_RUN = REPO_ROOT / "forensics" / "downstream" / "p1000-run.json"
DOWNSTREAM_FAMILY_FREEZE = REPO_ROOT / "forensics" / "downstream" / "family-freeze.json"

# 25.7's exposure/data-flow classification and the pure tool that derives it from the committed
# census, the committed 25.5 and 25.6 crosswalks and the committed 25.4 ownership planes.
EXPOSURE = REPO_ROOT / "artifacts" / "phase25" / "exposure.json"
MS_EXPOSURE_TOOL = REPO_ROOT / "forensics" / "tools" / "ms_exposure.py"
EXPOSURE_COURT = "MS-EXPOSURE-CLASSIFICATION"

# 25.8's unsafe reduction and the pure tool that derives it from the committed census, the committed
# exposure classification and the committed source spans the census names.
UNSAFE_REDUCTION = REPO_ROOT / "artifacts" / "phase25" / "unsafe-reduction.json"
MS_REDUCTION_TOOL = REPO_ROOT / "forensics" / "tools" / "ms_reduction.py"
UNSAFE_REDUCTION_COURT = "MS-UNSAFE-REDUCTION"

# 25.9's Miri plane and the tool that records it. The plane is a measurement (it runs Miri), so the
# tool is not a metadata-only generator; the court re-runs only the pure checks over the committed
# artefact and the committed census.
MIRI = REPO_ROOT / "artifacts" / "phase25" / "miri.json"
MS_MIRI_TOOL = REPO_ROOT / "forensics" / "tools" / "ms_miri.py"
MIRI_COURT = "MS-MIRI"
PHASE18_MIRI_SUITE = REPO_ROOT / "forensics" / "miri-tcb-suite.json"
MIRI_HARNESS_SOURCE = REPO_ROOT / "src" / "runtime" / "miri_tcb.rs"

# 25.10's ASan/MSan plane and the tool that records it. The plane is a measurement (it builds and runs
# the ASan-instrumented candidate), so the tool is not a metadata-only generator; the court re-runs
# only the pure checks over the committed artefact and the committed census.
ASAN_MSAN = REPO_ROOT / "artifacts" / "phase25" / "asan-msan.json"
MS_ASAN_TOOL = REPO_ROOT / "forensics" / "tools" / "ms_asan.py"
ASAN_MSAN_COURT = "MS-ASAN-MSMAN"
ASAN_CANARY_SOURCE = REPO_ROOT / "forensics" / "tools" / "asan_canary.c"
ASAN_HARNESS_SOURCE = REPO_ROOT / "src" / "aes.rs"

# 25.11's TSan plane and the tool that records it. The plane is a measurement (it builds and runs the
# TSan-instrumented candidate), so the tool is not a metadata-only generator; the court re-runs only
# the pure checks over the committed artefact, the committed census and the committed 25.3 obligation
# rule that defines the concurrency-relevant surface.
TSAN = REPO_ROOT / "artifacts" / "phase25" / "tsan.json"
MS_TSAN_TOOL = REPO_ROOT / "forensics" / "tools" / "ms_tsan.py"
TSAN_COURT = "MS-TSAN"
TSAN_CANARY_SOURCE = REPO_ROOT / "forensics" / "tools" / "tsan_canary.c"
TSAN_CANARY_RUST_SOURCE = REPO_ROOT / "forensics" / "tools" / "tsan_canary.rs"
TSAN_HARNESS_SOURCE = REPO_ROOT / "src" / "runtime" / "thread.rs"

# 25.0's constitution court and the constitution artefacts it re-derives.
CONSTITUTION_COURT = "MS-CONSTITUTION"
LEDGER = REPO_ROOT / "forensics" / "phase25-obligations.json"
CARGO_TOML = REPO_ROOT / "Cargo.toml"
LIB_RS = REPO_ROOT / "src" / "lib.rs"
# The safety lint policy 25.0 froze. No Phase-25 tool may weaken it.
LINT_SETTINGS: tuple[tuple[str, str], ...] = (
    ("unsafe_op_in_unsafe_fn", "deny"),
    ("undocumented_unsafe_blocks", "deny"),
    ("missing_safety_doc", "deny"),
)
PLANNED_UNITS = 22

# The courts this stratum stages. **25.1 registers `MS-SOURCE-CENSUS`**, the compiler-backed source
# census, and each later subphase appends its court here in the commit that lands its instrument;
# **25.0 registers `MS-CONSTITUTION`**, the constitution gate over the plan, schemas, guard,
# manifest, ledger and lint policy. A court removed from the table leaves the registry and fails
# `run_courts.py`.
COURTS: list[tuple[str, str]] = [
    (CONSTITUTION_COURT, "_ms_constitution_court"),
    (SOURCE_CENSUS_COURT, "_ms_source_census_court"),
    (NON_RUST_TCB_COURT, "_ms_non_rust_tcb_court"),
    (SAFETY_OBLIGATIONS_COURT, "_ms_safety_obligations_court"),
    (OWNERSHIP_PLANES_COURT, "_ms_ownership_planes_court"),
    (PHASE22_CROSSWALK_COURT, "_ms_phase22_crosswalk_court"),
    (PHASE24_CROSSWALK_COURT, "_ms_phase24_crosswalk_court"),
    (EXPOSURE_COURT, "_ms_exposure_classification_court"),
    (UNSAFE_REDUCTION_COURT, "_ms_unsafe_reduction_court"),
    (MIRI_COURT, "_ms_miri_court"),
    (ASAN_MSAN_COURT, "_ms_asan_msan_court"),
    (TSAN_COURT, "_ms_tsan_court"),
]

# The remaining courts the plan names, each pending with the subphase that lands it. 25.1 removed
# `MS-SOURCE-CENSUS`, 25.2 removed `MS-NON-RUST-TCB`, 25.3 removed `MS-SAFETY-OBLIGATIONS`, 25.4
# removed `MS-OWNERSHIP-PLANES`, 25.5 removed `MS-PHASE22-CROSSWALK`, 25.6 removed
# `MS-PHASE24-CROSSWALK`, 25.7 removed `MS-EXPOSURE-CLASSIFICATION`, 25.8 removed
# `MS-UNSAFE-REDUCTION`, 25.9 removed `MS-MIRI`, 25.10 removed `MS-ASAN-MSMAN` and 25.11 removed
# `MS-TSAN`, so ten remain. Ordered as the plan orders them.
PENDING_COURTS: dict[str, str] = {
    "MS-KANI": "25.12 -- Kani",
    "MS-PHASE18-FUZZ-CROSSWALK": "25.13 -- the Phase-18 fuzz crosswalk",
    "MS-PHASE24-SAFETY-COVERAGE": "25.14 -- the Phase-24 downstream safety coverage",
    "MS-HISTORICAL-CVE": "25.15 -- the historical CVE census",
    "MS-CVE-REPLAY": "25.16 -- the historical CVE replay",
    "MS-MECHANISM-RECONCILIATION": "25.17 -- the vulnerability-mechanism reconciliation",
    "MS-RED-TEAM": "25.18 -- the red team",
    "MS-CLEAN-REGEN": "25.19 -- the full clean regeneration",
    "MS-FRF-CLOSURE": "25.20 -- the FRF/Gemel closure",
    "MS-SEAL": "25.21 -- the memory-safety seal",
}


def _plan_units(plan_text: str) -> list[tuple[int, str]]:
    """The `(subphase number, court)` rows of the plan's section-2 table, in file order."""
    out: list[tuple[int, str]] = []
    for line in plan_text.splitlines():
        m = re.match(r"^\|\s*25\.(\d+)\s*\|", line)
        if not m:
            continue
        courts = [c for c in re.findall(r"`([A-Z][A-Z0-9-]+)`", line) if c.startswith("MS-")]
        if courts:
            out.append((int(m.group(1)), courts[-1]))
    return out


def _lint_findings(cargo: str, lib_rs: str) -> list[str]:
    """Every way the frozen safety lint policy has been weakened."""
    problems: list[str] = []
    for lint, want in LINT_SETTINGS:
        if f'{lint} = "{want}"' not in cargo:
            problems.append(f"Cargo.toml does not declare {lint} = \"{want}\"")
        for weak in ("allow", "warn"):
            if f'{lint} = "{weak}"' in cargo:
                problems.append(f"Cargo.toml weakens {lint} to \"{weak}\"")
    if 'unsafe_code = "allow"' in cargo:
        problems.append("Cargo.toml allows unsafe_code")
    if "#![deny(unsafe_op_in_unsafe_fn)]" not in lib_rs:
        problems.append("src/lib.rs does not deny unsafe_op_in_unsafe_fn")
    return problems


def _constitution_findings(plan_text: str, manifest: dict, ledger_body: dict, cargo: str,
                           lib_rs: str, names: list[str]) -> list[str]:
    """Every way the constitution fails to hold. Pure over its inputs, so the control can mutate."""
    problems: list[str] = []
    units = _plan_units(plan_text)
    if [n for n, _c in units] != list(range(PLANNED_UNITS)):
        problems.append(
            f"the plan's section-2 table does not name exactly the {PLANNED_UNITS} subphases "
            f"25.0-25.21 with a court each (found {[n for n, _c in units][:4]}...)"
        )
    plan_courts = [c for _n, c in units]
    if sorted(plan_courts) != sorted(names):
        plan_only = sorted(set(plan_courts) - set(names))
        runner_only = sorted(set(names) - set(plan_courts))
        problems.append("the plan's courts disagree with the runner's registry "
                        f"(plan-only {plan_only}, runner-only {runner_only})")
    if len(set(plan_courts)) != len(plan_courts):
        problems.append("the plan names a court twice")

    ledger_units = ledger_body.get("contract_units") or []
    if len(ledger_units) != PLANNED_UNITS:
        problems.append(f"the ledger carries {len(ledger_units)} contract unit(s), not "
                        f"{PLANNED_UNITS}")
    counts = ledger_body.get("counts") or {}
    if counts.get("owned") != PLANNED_UNITS:
        problems.append(f"the ledger's owned count {counts.get('owned')!r} disagrees with the "
                        f"{PLANNED_UNITS} planned unit(s)")
    if counts.get("atlas_owned") or counts.get("provider_rows_owned"):
        problems.append("the ownership atlas or the provider census assigns this stratum a symbol "
                        "row, but it owns no export")

    if not phase25_guard.host_refusal_reasons("phase25_courts.py"):
        problems.append("the guard admits a host invocation of the runner")
    for key in ("image", "platform", "marker", "env_flag"):
        if not manifest.get(key):
            problems.append(f"the venue manifest does not name {key}")
    metadata_only = list(manifest.get("metadata_only") or [])
    if not metadata_only:
        problems.append("the manifest declares no metadata-only generator")
    for ep in metadata_only:
        if not phase25_guard.evaluate(entry_point=str(ep), env={}, dockerenv=False)["admitted"]:
            problems.append(f"the manifest's metadata-only entry {ep} is not admitted in the shape "
                            f"of a host invocation")
    problems += _lint_findings(cargo, lib_rs)
    return problems


def _constitution_control(plan_text: str, manifest: dict, ledger_body: dict, cargo: str,
                          lib_rs: str, names: list[str]) -> dict:
    """Seed five mutations and require each caught with specificity holding."""
    base = _constitution_findings(plan_text, manifest, ledger_body, cargo, lib_rs, names)
    mutated: list[tuple[str, list[str]]] = []

    # (1) a subphase row dropped from the plan table.
    lines = [ln for ln in plan_text.splitlines() if not re.match(r"^\|\s*25\.7\s*\|", ln)]
    mutated.append(("subphase_dropped",
                    _constitution_findings("\n".join(lines), manifest, ledger_body, cargo, lib_rs,
                                           names)))
    # (2) a schema kind removed -- modelled here as a plan court renamed away from the registry.
    mutated.append(("plan_court_renamed",
                    _constitution_findings(plan_text.replace("`MS-MIRI`", "`MS-MIRI-X`"), manifest,
                                           ledger_body, cargo, lib_rs, names)))
    # (3) a lint weakened to allow.
    mutated.append(("lint_weakened",
                    _constitution_findings(plan_text, manifest, ledger_body,
                                           cargo.replace('unsafe_op_in_unsafe_fn = "deny"',
                                                         'unsafe_op_in_unsafe_fn = "allow"'),
                                           lib_rs, names)))
    # (4) the metadata-only set widened to a real execution entry point.
    widened = dict(manifest, metadata_only=["ms_census.py"])
    mutated.append(("metadata_only_widened",
                    _constitution_findings(plan_text, widened, ledger_body, cargo, lib_rs, names)))
    # (5) a unit dropped from the ledger.
    short = dict(ledger_body, contract_units=(ledger_body.get("contract_units") or [])[:-1])
    mutated.append(("unit_dropped",
                    _constitution_findings(plan_text, manifest, short, cargo, lib_rs, names)))

    control: dict = {"baseline_findings": len(base), "specificity_holds": not base}
    for label, found in mutated:
        control[f"caught_{label}"] = len(found)
        control[f"seed_{label}"] = bool(found)
    control["honest"] = (not base) and all(control[f"seed_{label}"] for label, _f in mutated)
    return control


def _ms_constitution_court(name: str) -> dict:
    """`MS-CONSTITUTION`: 25.0's court, the constitution gate.

    Stages no probe. It re-derives the constitution from the artefacts that *are* the stratum's
    constitution -- the plan's section-2 table, the schema inventory, the Docker-only guard, the
    venue manifest, the obligation ledger and the frozen safety lint policy -- and fails if any of
    them has drifted. It is the court that makes `MS-CONSTITUTION` a real unit rather than a name
    nothing registers. Five seeded mutations (a dropped subphase, a renamed plan court, a lint
    weakened to allow, a widened metadata-only set, a dropped ledger unit) are each caught.
    """
    plan_text = PLAN.read_text(encoding="utf-8") if PLAN.is_file() else ""
    if not plan_text:
        return {"court": name, "probe": "", "verdict": "fail", "stage": "plan-missing",
                "problems": [f"the plan {rel(PLAN)} is absent"], "findings": [], "control": {}}
    manifest = phase25_guard.load_manifest()
    ledger_body = (json.loads(LEDGER.read_text(encoding="utf-8")).get("body", {})
                   if LEDGER.is_file() else {})
    cargo = CARGO_TOML.read_text(encoding="utf-8") if CARGO_TOML.is_file() else ""
    lib_rs = LIB_RS.read_text(encoding="utf-8") if LIB_RS.is_file() else ""
    names = [c for c, _h in COURTS] + list(PENDING_COURTS)

    problems = _constitution_findings(plan_text, manifest, ledger_body, cargo, lib_rs, names)
    control = _constitution_control(plan_text, manifest, ledger_body, cargo, lib_rs, names)
    units = _plan_units(plan_text)
    inventory = memory_safety_schemas.inventory()
    if not inventory:
        problems.append("the schema inventory is empty")

    verdict = "pass" if (not problems and control.get("honest")) else "fail"
    return {
        "court": name,
        "probe": "",
        "method": (
            "stages no probe: it re-derives the constitution from the plan's section-2 table (the 22 "
            "subphases and their courts), the schema inventory, the Docker-only guard, the venue "
            "manifest, the obligation ledger and the frozen safety lint policy, and fails if any has "
            "drifted -- including if a Phase-25 tool has weakened unsafe_op_in_unsafe_fn, "
            "undocumented_unsafe_blocks or missing_safety_doc. Five seeded mutations are each caught "
            "with specificity holding (docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md sections 2, 3)."
        ),
        "frf_declarable": False,
        "frf_exclusion": (
            "the constitution court reads committed authored artefacts and re-derives their claims, "
            "so it stages no artifacts/phase25/probes/ pair and carries no FRF declaration"
        ),
        "counts": {
            "planned_units": len(units),
            "registered_or_pending_courts": len(names),
            "schema_kinds": len(inventory),
            "ledger_units": len(ledger_body.get("contract_units") or []),
        },
        "findings": [],
        "control": control,
        "problems": problems,
        "verdict": verdict,
    }


def _ms_source_census_court(name: str) -> dict:
    """`MS-SOURCE-CENSUS`: 25.1's court, the compiler-backed source census.

    Stages no probe. It reads the committed `artifacts/phase25/source-census.json` and re-runs the
    25.1 pure checks `ms_census.census_findings` and `ms_census.census_sensitivity_control` over the
    committed artefact -- no compiler, no clippy, no nightly; the measurement that produced the
    census is `ms_census.py --measure`, and this court only re-derives from what it wrote. It
    establishes that every shipped first-party file is accounted for with a matching digest; that
    every site is compiler-derived and resolves to a compiler-identified context; that site and
    context ids are stable and unique; that the context/site back-references are consistent; that
    the per-file counts, the counts block and the LOC arithmetic are derived rather than typed; and
    that every cross-check disagreement is recorded as a classified residual. Five seeded
    mutations -- a fabricated raw dereference, an unsafe operation hidden by dropping its
    macro-generated context, a removed safety contract, a site forged as safe, and a dropped file
    -- are each caught with specificity holding. It is an **instrument**: it can pass while the
    census records real property findings (contexts with no source-stated contract, contexts that
    hold no classified operation, and the cross-check residuals), which are recorded as the row's
    `findings` so a passing census is never read as a memory-safety claim.
    """
    if not SOURCE_CENSUS.is_file():
        return {"court": name, "probe": "", "verdict": "fail", "stage": "source-missing",
                "problems": [f"the source census {rel(SOURCE_CENSUS)} is absent"],
                "findings": [], "control": {}}

    doc = json.loads(SOURCE_CENSUS.read_text(encoding="utf-8"))
    body = ms_census.decode_body(doc.get("body", doc))
    # The size budget: the artefact is stored in a lossless columnar form precisely because the
    # record-per-object form exceeded GitHub's 100 MB pre-receive limit (the plan's section 4 records
    # the correction). The court fails if the columnar artefact grows past the committed budget, so
    # a regression here is a failed court rather than a rejected push.
    size_bytes = SOURCE_CENSUS.stat().st_size
    problems = ms_census.census_findings(body)
    if size_bytes > SOURCE_CENSUS_BUDGET_BYTES:
        problems = [f"the source census {rel(SOURCE_CENSUS)} is {size_bytes} bytes, over the "
                    f"committed {SOURCE_CENSUS_BUDGET_BYTES}-byte budget (the columnar form is "
                    f"lossless and must stay well under GitHub's 100 MB pre-receive limit)"] + problems
    control = ms_census.census_sensitivity_control(body)

    counts = body.get("counts") or {}
    loc = body.get("loc") or {}
    cross = body.get("crosschecks") or {}
    toolchain = body.get("toolchain") or {}
    residuals = body.get("residuals") or []

    # Property findings: what the census observes that is not a defect of the instrument. They are
    # recorded so a passing court is never read as the property it does not claim.
    findings = [
        f"{counts.get('uncontracted_contexts', 0)} compiler-identified unsafe context(s) carry no "
        f"source-stated SAFETY contract (recorded open; 25.3 owns the obligations)",
        f"{counts.get('contexts_without_site', 0)} unsafe context(s) hold no classified operation "
        f"(a declaration, not an operation)",
        f"{len(residuals)} cross-check residual(s): "
        + "; ".join(f"{r.get('source')}/{r.get('class')}" for r in residuals),
    ]

    verdict = "pass" if (not problems and control.get("honest")
                         and control.get("specificity_holds")) else "fail"
    return {
        "court": name,
        "probe": "",
        "method": (
            "stages no probe: it reads the committed artifacts/phase25/source-census.json and "
            "re-runs the 25.1 pure checks (ms_census.census_findings and "
            "ms_census.census_sensitivity_control) over it, without a compiler. The census was "
            "derived by one clippy run with the built-in `unsafe_code` lint (the enumerating "
            "authority) plus the three named documentation lints, --message-format=json, and the "
            "macro-expanded source from a pinned nightly. It establishes file coverage, "
            "compiler-derivedness of every site, stable/unique ids, consistent back-references, "
            "derived counts and the LOC split, and that every cross-check disagreement is a "
            "classified residual; five seeded mutations are each caught with specificity holding "
            "(docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md sections 2, 3.1, 3.2)."
        ),
        "frf_declarable": False,
        "frf_exclusion": (
            "the census court reads the committed census and re-derives only its pure checks, so "
            "it stages no artifacts/phase25/probes/ pair and carries no FRF declaration"
        ),
        "toolchain": toolchain,
        "counts": {
            "files": counts.get("files", 0),
            "unsafe_contexts": counts.get("unsafe_contexts", 0),
            "sites": counts.get("sites", 0),
            "generated_files": counts.get("generated_files", 0),
            "uncontracted_contexts": counts.get("uncontracted_contexts", 0),
            "contexts_without_site": counts.get("contexts_without_site", 0),
            "residuals": len(residuals),
        },
        "sites_by_kind": counts.get("sites_by_kind") or {},
        "contexts_by_kind": counts.get("contexts_by_kind") or {},
        "loc": loc,
        "encoding": ms_codec.ENCODING,
        "size_bytes": size_bytes,
        "size_budget_bytes": SOURCE_CENSUS_BUDGET_BYTES,
        "crosschecks": {
            "geiger": (cross.get("geiger") or {}).get("status"),
            "lexical_unsafe_keywords": (cross.get("lexical") or {}).get(
                "unsafe_keyword_occurrences"),
            "residual_count": cross.get("residual_count"),
        },
        "findings": findings,
        "control": control,
        "problems": problems,
        "verdict": verdict,
    }


def _ms_non_rust_tcb_court(name: str) -> dict:
    """`MS-NON-RUST-TCB`: 25.2's court, the non-Rust trusted computing base.

    Stages no probe. It reads the committed `artifacts/phase25/non-rust-tcb.json` and re-runs the
    25.2 pure checks `ms_non_rust_tcb.non_rust_findings` and
    `ms_non_rust_tcb.non_rust_sensitivity_control` over it together with the on-disk file universe
    (the shipped `src` non-Rust files, the Phase-2 generated scaffolds, the `build.rs` C list and
    the 25.1 census's FFI sites) -- no compiler and no `nm`; the measurement that produced the
    inventory is `ms_non_rust_tcb.py --measure`, and this court only re-derives from what it wrote.
    It establishes that every shipped/generated non-Rust file is accounted for with a matching
    digest in both directions; that the C adapters are exactly the C `build.rs` compiles; that each
    adapter names its reason and its variadic-or-layout role; that every export has a boundary
    record and every census FFI site is cross-referenced; that the counts are derived, not typed;
    and that every strict compile is reported honestly. Five seeded mutations -- a dropped C file, a
    fabricated C file, a removed reason, a forged compile-clean result and a dropped export
    boundary -- are each caught with specificity holding. It is an **instrument**: it can pass while
    the inventory records real property findings (the census's macro-collapsed FFI_EXPORT sites, its
    missing plain-extern and C-variadic coverage, and the strict-compile diagnostics), which are
    recorded as the row's `findings` so a passing court is never read as a memory-safety claim.
    """
    if not NON_RUST_TCB.is_file():
        return {"court": name, "probe": "", "verdict": "fail", "stage": "inventory-missing",
                "problems": [f"the non-Rust TCB inventory {rel(NON_RUST_TCB)} is absent"],
                "findings": [], "control": {}}

    doc = json.loads(NON_RUST_TCB.read_text(encoding="utf-8"))
    ctx = ms_non_rust_tcb.build_context()
    body = ms_codec.decode_body(doc.get("body", doc), ctx["refs"])
    problems = ms_non_rust_tcb.non_rust_findings(body, ctx)
    control = ms_non_rust_tcb.non_rust_sensitivity_control(body, ctx)

    counts = body.get("counts") or {}
    residuals = body.get("residuals") or []

    findings = [
        f"{counts.get('warnings', 0)} strict-compile diagnostic(s) recorded across the first-party "
        f"C adapters and the generated scaffolds (a warning/error is a recorded fact, not a pass)",
        f"{counts.get('variadic_boundaries', 0)} C-variadic boundary/-ies (the C adapters' variadic "
        f"exports plus the C-variadic foreign functions the crate imports; 25.1's census reports "
        f"zero C_VARIADIC_BOUNDARY sites)",
        f"{len(residuals)} residual(s): "
        + "; ".join(f"{r.get('source')}/{r.get('class')}" for r in residuals),
    ]

    verdict = "pass" if (not problems and control.get("honest")
                         and control.get("specificity_holds")) else "fail"
    return {
        "court": name,
        "probe": "",
        "method": (
            "stages no probe: it reads the committed artifacts/phase25/non-rust-tcb.json and "
            "re-runs the 25.2 pure checks (ms_non_rust_tcb.non_rust_findings and "
            "ms_non_rust_tcb.non_rust_sensitivity_control) over it and the on-disk file universe, "
            "without a compiler. The inventory was derived by compiling every first-party C adapter "
            "under -std=c11 -Wall -Wextra -Werror (recording every diagnostic), running nm for the "
            "defined/undefined symbol sets, scanning src for the extern blocks and the core::arch "
            "intrinsics, and cross-referencing the 25.1 census's FFI_EXPORT and "
            "EXTERN_FUNCTION_CALL sites rather than re-deriving them. It establishes file coverage "
            "in both directions, the build.rs correspondence, per-adapter reason/role, the "
            "export-to-boundary and census cross-references, derived counts and honest compile "
            "outcomes; five seeded mutations are each caught with specificity holding "
            "(docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md sections 2, 3.1, 3.2)."
        ),
        "frf_declarable": False,
        "frf_exclusion": (
            "the non-Rust TCB court reads the committed inventory and re-derives only its pure "
            "checks, so it stages no artifacts/phase25/probes/ pair and carries no FRF declaration"
        ),
        "counts": {
            "c_files": counts.get("c_files", 0),
            "c_loc": counts.get("c_loc", 0),
            "generated_c_files": counts.get("generated_c_files", 0),
            "asm_sites": counts.get("asm_sites", 0),
            "arch_intrinsic_sites": counts.get("arch_intrinsic_sites", 0),
            "exported_ffi": counts.get("exported_ffi", 0),
            "imported_ffi": counts.get("imported_ffi", 0),
            "variadic_boundaries": counts.get("variadic_boundaries", 0),
            "warnings": counts.get("warnings", 0),
            "residuals": len(residuals),
        },
        "findings": findings,
        "control": control,
        "problems": problems,
        "verdict": verdict,
    }


def _ms_safety_obligations_court(name: str) -> dict:
    """`MS-SAFETY-OBLIGATIONS`: 25.3's court, the safety obligations per unsafe site.

    Stages no probe. It reads the committed `artifacts/phase25/safety-obligations.json` and re-runs
    the 25.3 pure checks `ms_obligations.obligation_findings` and
    `ms_obligations.obligation_sensitivity_control` over it together with the committed 25.1 census
    it is derived from and the 25.2 TCB it cross-references -- no compiler, no clippy; the
    derivation that produced the plane is `ms_obligations.py --measure`, and this court only
    re-derives from what it wrote. It establishes that every census site is bound exactly once and
    every census context represented; that each site's grouped contract reproduces from the census
    and the recorded kind -> dimension rule; that no obligation is `discharged` without a
    source-stated contract and a discharging proof (a `// SAFETY:` comment is a statement, so naming
    a dimension makes it `stated`, never `discharged`); that the cross-check against the non-Rust
    TCB reproduces; and that every count is derived. Five seeded mutations -- a removed contract, a
    forged discharge, a dropped obligation, a forged dimension set and forged named dimensions --
    are each caught with specificity holding. It is an **instrument**: it can pass while the plane
    records real property findings (the open obligations, the sites whose contract escapes to a
    caller, and the recorded discharge gap), which are recorded as the row's `findings` so a
    passing obligations court is never read as a memory-safety claim.
    """
    if not SAFETY_OBLIGATIONS.is_file():
        return {"court": name, "probe": "", "verdict": "fail", "stage": "obligations-missing",
                "problems": [f"the safety obligations plane {rel(SAFETY_OBLIGATIONS)} is absent"],
                "findings": [], "control": {}}
    if not SOURCE_CENSUS.is_file():
        return {"court": name, "probe": "", "verdict": "fail", "stage": "census-missing",
                "problems": [f"the source census {rel(SOURCE_CENSUS)} is absent"],
                "findings": [], "control": {}}

    census_body, refs = _census_view()
    body = _decoded_body(SAFETY_OBLIGATIONS, refs)
    tcb_body = (_decoded_body(NON_RUST_TCB, refs) if NON_RUST_TCB.is_file() else {})
    problems = ms_obligations.obligation_findings(body, census_body, tcb_body)
    control = ms_obligations.obligation_sensitivity_control(body, census_body, tcb_body)

    counts = body.get("counts") or {}
    findings = list(body.get("findings") or [])

    verdict = "pass" if (not problems and control.get("honest")
                         and control.get("specificity_holds")) else "fail"
    return {
        "court": name,
        "probe": "",
        "method": (
            "stages no probe: it reads the committed artifacts/phase25/safety-obligations.json and "
            "re-runs the 25.3 pure checks (ms_obligations.obligation_findings and "
            "ms_obligations.obligation_sensitivity_control) over it, the committed 25.1 census it "
            "is derived from and the committed 25.2 non-Rust TCB it cross-references, without a "
            "compiler. The plane is a pure derivation: each census site is bound once by "
            "reference to a grouped contract whose per-dimension obligations follow from the "
            "recorded operation-kind -> dimension rule and the source-stated contract. It "
            "establishes site and context completeness, contract reproduction, the no-discharge "
            "invariant and derived counts; five seeded mutations are each caught with specificity "
            "holding (docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md sections 2, 3.1, 3.8)."
        ),
        "frf_declarable": False,
        "frf_exclusion": (
            "the obligations court reads the committed plane and re-derives only its pure checks, "
            "so it stages no artifacts/phase25/probes/ pair and carries no FRF declaration"
        ),
        "counts": {
            "census_sites": counts.get("census_sites", 0),
            "census_contexts": counts.get("census_contexts", 0),
            "sites_bound": counts.get("sites_bound", 0),
            "contexts_represented": counts.get("contexts_represented", 0),
            "contexts_without_site": counts.get("contexts_without_site", 0),
            "contracts": counts.get("contracts", 0),
            "obligations": counts.get("obligations", 0),
            "discharged": counts.get("discharged", 0),
            "stated": counts.get("stated", 0),
            "open": counts.get("open", 0),
            "escaping_sites": counts.get("escaping_sites", 0),
            "escaping_obligations": counts.get("escaping_obligations", 0),
            "uncontracted_sites": counts.get("uncontracted_sites", 0),
            "uncontracted_contexts": counts.get("uncontracted_contexts", 0),
            "high_risk_sites": counts.get("high_risk_sites", 0),
        },
        "crosschecks": body.get("crosschecks") or {},
        "findings": findings,
        "control": control,
        "problems": problems,
        "verdict": verdict,
    }


def _ms_ownership_planes_court(name: str) -> dict:
    """`MS-OWNERSHIP-PLANES`: 25.4's court, the ownership/allocation/callback planes.

    Stages no probe. It reads the committed `artifacts/phase25/ownership-planes.json` and re-runs the
    25.4 pure checks `ms_ownership_planes.ownership_findings` and
    `ms_ownership_planes.ownership_sensitivity_control` over it together with the committed 25.1
    census it classifies, the committed 25.2 TCB whose boundaries it panic-classifies, and the
    committed source tree it scans -- no compiler, no tool; the derivation that produced the plane is
    `ms_ownership_planes.py --measure`, and this court only re-derives from what it wrote. It
    establishes that every plane equals its derivation; that every record validates against its
    schema; that every allocation site names an allocator provenance; that every `FREES` edge has a
    matching `ALLOCATES`/`RETURNS_OWNERSHIP` edge or a recorded finding; that every callback has a
    stored-lifetime classification; that every manual `Send`/`Sync` has a justification; that every
    export has a panic/unwind class and none is `UNKNOWN` without a finding; and that every count is
    derived. Four seeded mutations -- a `FREES` with no allocation, a `Send`/`Sync` impl with no
    justification, a hidden `UNKNOWN` panic class and a refcount decrement with no increment -- are
    each caught with specificity holding. It is an **instrument**: it can pass while the plane
    records real property findings (the unequalized frees, the unmatched refcount decrements, the
    double-free-possible contexts, the unjustified impls, the uncontracted globals and the
    `UNKNOWN` panic boundaries), which are recorded as the row's `findings` so a passing ownership
    court is never read as a memory-safety claim.
    """
    if not OWNERSHIP_PLANES.is_file():
        return {"court": name, "probe": "", "verdict": "fail", "stage": "plane-missing",
                "problems": [f"the ownership planes {rel(OWNERSHIP_PLANES)} are absent"],
                "findings": [], "control": {}}
    if not SOURCE_CENSUS.is_file():
        return {"court": name, "probe": "", "verdict": "fail", "stage": "census-missing",
                "problems": [f"the source census {rel(SOURCE_CENSUS)} is absent"],
                "findings": [], "control": {}}

    census_body, refs = _census_view()
    body = _decoded_body(OWNERSHIP_PLANES, refs)
    tcb_body = (_decoded_body(NON_RUST_TCB, refs) if NON_RUST_TCB.is_file() else {})
    ctx = ms_ownership_planes.build_context()
    problems = ms_ownership_planes.ownership_findings(body, census_body, tcb_body, ctx)
    control = ms_ownership_planes.ownership_sensitivity_control(body, census_body, tcb_body, ctx)

    counts = body.get("counts") or {}
    findings = list(body.get("findings") or [])

    verdict = "pass" if (not problems and control.get("honest")
                         and control.get("specificity_holds")) else "fail"
    return {
        "court": name,
        "probe": "",
        "method": (
            "stages no probe: it reads the committed artifacts/phase25/ownership-planes.json and "
            "re-runs the 25.4 pure checks (ms_ownership_planes.ownership_findings and "
            "ms_ownership_planes.ownership_sensitivity_control) over it, the committed 25.1 census, "
            "the committed 25.2 non-Rust TCB and the committed source tree, without a compiler. The "
            "plane is a pure derivation: each compiler-derived site is classified from its own "
            "comment-stripped context text against the recorded allocation/convention tables, and "
            "the panic boundary is classified from the exported body. It establishes that every "
            "plane equals the derivation, that every record validates, that every FREES edge is "
            "matched or found, that every callback has a lifetime, that every unsafe Send/Sync has "
            "a justification, that no UNKNOWN panic class is hidden, and that every count is "
            "derived; four seeded mutations are each caught with specificity holding "
            "(docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md sections 2, 3.1, 3.8)."
        ),
        "frf_declarable": False,
        "frf_exclusion": (
            "the ownership-planes court reads the committed plane and re-derives only its pure "
            "checks, so it stages no artifacts/phase25/probes/ pair and carries no FRF declaration"
        ),
        "counts": {
            "allocation_sites": counts.get("allocation_sites", 0),
            "ownership_edges": counts.get("ownership_edges", 0),
            "ownership_edges_by_kind": counts.get("ownership_edges_by_kind") or {},
            "unmatched_frees": counts.get("unmatched_frees", 0),
            "unmatched_refcount_decrements": counts.get("unmatched_refcount_decrements", 0),
            "double_free_contexts": counts.get("double_free_contexts", 0),
            "unpaired_allocations": counts.get("unpaired_allocations", 0),
            "callback_lifetimes": counts.get("callback_lifetimes", 0),
            "callbacks_that_may_outlive": counts.get("callbacks_that_may_outlive", 0),
            "send_sync": counts.get("send_sync", 0),
            "send_sync_without_source_justification":
                counts.get("send_sync_without_source_justification", 0),
            "globals": counts.get("globals", 0),
            "globals_without_source_contract": counts.get("globals_without_source_contract", 0),
            "panic_boundaries": counts.get("panic_boundaries", 0),
            "panic_by_class": counts.get("panic_by_class") or {},
            "panic_unknown": counts.get("panic_unknown", 0),
        },
        "findings": findings,
        "control": control,
        "problems": problems,
        "verdict": verdict,
    }


def _ms_phase22_crosswalk_court(name: str) -> dict:
    """`MS-PHASE22-CROSSWALK`: 25.5's court, the Phase-22 reachability crosswalk.

    Stages no probe. It reads the committed `artifacts/phase25/phase22-crosswalk.json` and re-runs
    the 25.5 pure checks `ms_phase22_crosswalk.crosswalk_findings` and
    `ms_phase22_crosswalk.crosswalk_sensitivity_control` over it together with the committed 25.1
    census it maps and the committed Phase-22 whole-program atlas it reads -- the reachability
    closure `compatibility-closure.json`, its entity plane `reconciliation.json` and the module ->
    authority-unit correspondence (`transcription-edges.json`, `internal-symbols.json`,
    `export-defining-units.json`) -- no compiler, no tool; the derivation that produced the plane is
    `ms_phase22_crosswalk.py --measure`, and this court only re-derives from what it wrote. It
    establishes that every census site has a disposition (mapped to at least one public root, or an
    explicit unresolved residual with a reason); that the site map, the unit map, the inverse root
    view, the counts and the residuals equal their derivation; that the inverse view reproduces from
    the site map; that the reachability is the atlas's own answer (the walk over its committed typed
    edges equals its committed `by_root`, so a site hidden behind a callback slot, a provider
    dispatch slot or a relocation is still reached and recorded with that edge kind); and that the
    mapping rule names the compatibility-closure atlas rather than a re-derived graph. Five seeded
    mutations -- a site silently dropped, a site mapped to a root the atlas does not reach, an
    inverse view that disagrees with the forward map, an unresolved site defaulted to a root and the
    authority re-pointed away from the atlas -- are each caught with specificity holding. It is an
    **instrument**: it can pass while the crosswalk records real property findings (the sites whose
    module transcribes no authority unit and are preserved as unresolved residuals, the
    `distribution` root that reaches no site, and the graph-reachability-not-execution non-claim),
    which are recorded as the row's `findings` so a passing crosswalk court is never read as a
    memory-safety claim.
    """
    if not PHASE22_CROSSWALK.is_file():
        return {"court": name, "probe": "", "verdict": "fail", "stage": "crosswalk-missing",
                "problems": [f"the Phase-22 crosswalk {rel(PHASE22_CROSSWALK)} is absent"],
                "findings": [], "control": {}}
    if not SOURCE_CENSUS.is_file():
        return {"court": name, "probe": "", "verdict": "fail", "stage": "census-missing",
                "problems": [f"the source census {rel(SOURCE_CENSUS)} is absent"],
                "findings": [], "control": {}}
    if not PHASE22_CLOSURE.is_file():
        return {"court": name, "probe": "", "verdict": "fail", "stage": "atlas-missing",
                "problems": [f"the Phase-22 reachability atlas {rel(PHASE22_CLOSURE)} is absent"],
                "findings": [], "control": {}}

    census_body, refs = _census_view()
    body = _decoded_body(PHASE22_CROSSWALK, refs)
    authority = ms_phase22_crosswalk.load_authority()
    problems = ms_phase22_crosswalk.crosswalk_findings(body, census_body, authority)
    control = ms_phase22_crosswalk.crosswalk_sensitivity_control(body, census_body, authority)

    counts = body.get("counts") or {}
    findings = list(body.get("findings") or [])

    verdict = "pass" if (not problems and control.get("honest")
                         and control.get("specificity_holds")) else "fail"
    return {
        "court": name,
        "probe": "",
        "method": (
            "stages no probe: it reads the committed artifacts/phase25/phase22-crosswalk.json and "
            "re-runs the 25.5 pure checks (ms_phase22_crosswalk.crosswalk_findings and "
            "ms_phase22_crosswalk.crosswalk_sensitivity_control) over it, the committed 25.1 census "
            "it maps and the committed Phase-22 whole-program atlas it reads, without a compiler. "
            "The plane is a pure derivation: each census site's module is resolved to the authority "
            "translation unit the transcription atlas measures it transcribes, that unit's authority "
            "symbols are canonicalised to their Phase-22 entity keys, and the public roots are read "
            "from the closure's own committed `by_root` reachability (corroborated by walking its "
            "typed edges and naming the witness kinds). It establishes site-disposition completeness, "
            "the site/unit/inverse/counts reproduction, the inverse/forward agreement, the atlas' "
            "own reachability and that no competing graph is derived; five seeded mutations are each "
            "caught with specificity holding (docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md sections 2, "
            "3.1, 3.8)."
        ),
        "frf_declarable": False,
        "frf_exclusion": (
            "the Phase-22 crosswalk court reads the committed crosswalk and re-derives only its pure "
            "checks, so it stages no artifacts/phase25/probes/ pair and carries no FRF declaration"
        ),
        "counts": {
            "census_sites": counts.get("census_sites", 0),
            "sites_mapped": counts.get("sites_mapped", 0),
            "sites_unresolved": counts.get("sites_unresolved", 0),
            "unresolved_by_class": counts.get("unresolved_by_class") or {},
            "public_roots": counts.get("public_roots", 0),
            "roots_with_sites": counts.get("roots_with_sites", 0),
            "authority_units": counts.get("authority_units", 0),
            "authority_entities": counts.get("authority_entities", 0),
            "transcription_modules": counts.get("transcription_modules", 0),
            "edge_kinds": counts.get("edge_kinds") or {},
        },
        "sites_by_root": {f: (body.get("roots") or {}).get(f, {}).get("sites", 0)
                          for f in sorted(body.get("roots") or {})},
        "findings": findings,
        "control": control,
        "problems": problems,
        "verdict": verdict,
    }


def _ms_phase24_crosswalk_court(name: str) -> dict:
    """`MS-PHASE24-CROSSWALK`: 25.6's court, the Phase-24 downstream crosswalk.

    Stages no probe. It reads the committed `artifacts/phase25/phase24-crosswalk.json` and re-runs
    the 25.6 pure checks `ms_phase24_crosswalk.crosswalk_findings` and
    `ms_phase24_crosswalk.crosswalk_sensitivity_control` over it together with the committed 25.1
    census it maps and the committed Phase-24 downstream measurement it joins to -- the 24.3 usage
    fingerprints, the 24.12 reconciliation clusters, the 24.9 runtime atlas, the 24.6 build/link
    atlas, the 24.11 drop-in run and the family freeze -- no compiler, no tool; the derivation that
    produced the plane is `ms_phase24_crosswalk.py --measure`, and this court only re-derives from
    what it wrote. It establishes that every census site has a disposition (observed with the
    measured consumers that reach its surface, or `NOT_OBSERVED` with a closed reason); that a
    runtime-observed site has a runtime-observed consumer; that the inverse consumer view reproduces
    from the forward site map; that the site map, the consumer view, the counts and the residuals
    equal their derivation; that every partial join is a residual; and that the mapping rule names
    the committed Phase-24 measurement rather than a typed consumer. Five seeded mutations -- a site
    silently dropped, a site marked runtime-observed with no runtime row, an inverse view that
    disagrees with the forward map, a typed consumer count and a partial join with no residual -- are
    each caught with specificity holding. It is an **instrument**: it can pass while the crosswalk
    records real property findings (the sites no measured consumer reaches, the families without a
    usage fingerprint that cannot be attributed, the imported symbols with no clean entity mapping
    and the import-not-execution non-claim), which are recorded as the row's `findings` so a passing
    crosswalk court is never read as a memory-safety claim.
    """
    if not PHASE24_CROSSWALK.is_file():
        return {"court": name, "probe": "", "verdict": "fail", "stage": "crosswalk-missing",
                "problems": [f"the Phase-24 crosswalk {rel(PHASE24_CROSSWALK)} is absent"],
                "findings": [], "control": {}}
    if not SOURCE_CENSUS.is_file():
        return {"court": name, "probe": "", "verdict": "fail", "stage": "census-missing",
                "problems": [f"the source census {rel(SOURCE_CENSUS)} is absent"],
                "findings": [], "control": {}}
    if not DOWNSTREAM_USAGE_FINGERPRINTS.is_file():
        return {"court": name, "probe": "", "verdict": "fail", "stage": "measurement-missing",
                "problems": [f"the Phase-24 usage fingerprints "
                             f"{rel(DOWNSTREAM_USAGE_FINGERPRINTS)} are absent"],
                "findings": [], "control": {}}

    census_body, refs = _census_view()
    body = _decoded_body(PHASE24_CROSSWALK, refs)
    authority = ms_phase24_crosswalk.load_authority()
    problems = ms_phase24_crosswalk.crosswalk_findings(body, census_body, authority)
    control = ms_phase24_crosswalk.crosswalk_sensitivity_control(body, census_body, authority)

    counts = body.get("counts") or {}
    findings = list(body.get("findings") or [])

    verdict = "pass" if (not problems and control.get("honest")
                         and control.get("specificity_holds")) else "fail"
    return {
        "court": name,
        "probe": "",
        "method": (
            "stages no probe: it reads the committed artifacts/phase25/phase24-crosswalk.json and "
            "re-runs the 25.6 pure checks (ms_phase24_crosswalk.crosswalk_findings and "
            "ms_phase24_crosswalk.crosswalk_sensitivity_control) over it, the committed 25.1 census "
            "and the committed Phase-24 downstream measurement it joins to, without a compiler. The "
            "plane is a pure derivation: each census site's authority unit (the 25.5 resolution) "
            "names a set of Phase-22 authority entities, and the measured consumers whose imported "
            "OpenSSL symbols canonicalise to those entity keys reach the site; the runtime atlas "
            "decides whether the reaching consumer was observed functionally, and the reconciliation "
            "clusters are read. It establishes site-disposition completeness, the runtime/import "
            "split, the site/consumer/counts/residuals reproduction, the inverse/forward agreement "
            "and that every partial join is a residual; five seeded mutations are each caught with "
            "specificity holding (docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md sections 2, 3.1, 3.8)."
        ),
        "frf_declarable": False,
        "frf_exclusion": (
            "the Phase-24 crosswalk court reads the committed crosswalk and re-derives only its pure "
            "checks, so it stages no artifacts/phase25/probes/ pair and carries no FRF declaration"
        ),
        "counts": {
            "census_sites": counts.get("census_sites", 0),
            "sites_runtime_observed": counts.get("sites_runtime_observed", 0),
            "sites_import_observed": counts.get("sites_import_observed", 0),
            "sites_not_observed": counts.get("sites_not_observed", 0),
            "not_observed_by_reason": counts.get("not_observed_by_reason") or {},
            "consumers": counts.get("consumers", 0),
            "consumers_runtime_observed": counts.get("consumers_runtime_observed", 0),
            "counted_families": counts.get("counted_families", 0),
            "usage_clusters": counts.get("usage_clusters", 0),
            "imported_symbols": counts.get("imported_symbols", 0),
            "imported_symbols_unmapped": counts.get("imported_symbols_unmapped", 0),
            "runtime_families_without_a_fingerprint":
                counts.get("runtime_families_without_a_fingerprint", 0),
            "reachable_sites": counts.get("reachable_sites", 0),
            "residuals": len(body.get("residuals") or []),
        },
        "sites_by_consumer": {n: (body.get("consumers") or {}).get(n, {}).get("reachable_sites", 0)
                              for n in sorted(body.get("consumers") or {})},
        "findings": findings,
        "control": control,
        "problems": problems,
        "verdict": verdict,
    }


def _ms_exposure_classification_court(name: str) -> dict:
    """`MS-EXPOSURE-CLASSIFICATION`: 25.7's court, the exposure/data-flow classification.

    Stages no probe. It reads the committed `artifacts/phase25/exposure.json` and re-runs the 25.7
    pure checks `ms_exposure.exposure_findings` and `ms_exposure.exposure_sensitivity_control` over it
    together with the committed 25.1 census it classifies, the committed 25.5 Phase-22 crosswalk it
    reads for the authority unit and public roots, the committed 25.6 Phase-24 crosswalk it reads for
    the downstream state and the committed 25.4 ownership planes it reads for the manual allocation
    sites -- no compiler, no tool; the derivation that produced the plane is `ms_exposure.py
    --measure`, and this court only re-derives from what it wrote. It establishes that every census
    site has exactly one class from the closed vocabulary; that every externally reachable site has a
    justification (a network class one that names a network route, so a remote class with no
    justification is caught); that every attacker route's sites are named and equal the derivation;
    that the inverse exposure view and the buffer-operation census reproduce; that the
    length-boundary plan is marked unexecuted; and that the sites, justifications, counts and
    residuals equal their derivation. It also establishes the risk-tier disposition: a site classed
    `UNKNOWN_REACHABILITY` is tier `SU` (unknown exposure), not `S0`, so an unknown is never read as a
    non-exposed site or the lowest priority. Nine seeded mutations -- a remote class with no
    justification, an attacker route with no path, an inverse view that disagrees, a boundary plan
    marked executed, a dropped site, a typed count, an unresolved site promoted to `UNREACHABLE_PROFILE`
    with no witness, an unresolved site promoted to an external class and an unknown-reachability site
    assigned tier S0 -- are each caught with
    specificity holding. It is an
    **instrument**: it can pass while the classification records real property findings (the sites no
    authority unit reaches, the routes that carry no attributable operation, the buffer-operation
    fields the census does not measure and the network classes grounded in a parser role rather than
    the unpopulated Phase-22 `protocol` family), which are recorded as the row's `findings` so a
    passing classification court is never read as a memory-safety claim.
    """
    if not EXPOSURE.is_file():
        return {"court": name, "probe": "", "verdict": "fail", "stage": "exposure-missing",
                "problems": [f"the exposure classification {rel(EXPOSURE)} is absent"],
                "findings": [], "control": {}}
    if not SOURCE_CENSUS.is_file():
        return {"court": name, "probe": "", "verdict": "fail", "stage": "census-missing",
                "problems": [f"the source census {rel(SOURCE_CENSUS)} is absent"],
                "findings": [], "control": {}}

    census_body, refs = _census_view()
    body = _decoded_body(EXPOSURE, refs)
    authority = ms_exposure.load_authority()
    problems = ms_exposure.exposure_findings(body, census_body, authority)
    control = ms_exposure.exposure_sensitivity_control(body, census_body, authority)

    counts = body.get("counts") or {}
    findings = list(body.get("findings") or [])

    verdict = "pass" if (not problems and control.get("honest")
                         and control.get("specificity_holds")) else "fail"
    return {
        "court": name,
        "probe": "",
        "method": (
            "stages no probe: it reads the committed artifacts/phase25/exposure.json and re-runs the "
            "25.7 pure checks (ms_exposure.exposure_findings and "
            "ms_exposure.exposure_sensitivity_control) over it, the committed 25.1 census, the "
            "committed 25.5 Phase-22 crosswalk, the committed 25.6 Phase-24 crosswalk and the "
            "committed 25.4 ownership planes, without a compiler. The plane is a pure derivation: "
            "each census site gets one class from the closed vocabulary by the recorded precedence "
            "(a wire-parser route, a config/local-file parser, the cli root, the 25.6 downstream "
            "the 25.6 downstream state, the api roots, the callbacks root, or `UNKNOWN_REACHABILITY` "
            "when the 25.5 mapping is missing); a network class needs a "
            "justified entry semantics, never a static edge, and `UNREACHABLE_PROFILE` needs a "
            "justified exclusion witness. An unknown-reachability site is risk tier SU (unknown "
            "exposure), never S0. It establishes site-class completeness, "
            "the justification of every externally reachable site, the attacker-route and "
            "buffer-operation reproduction, the unexecuted boundary plan and the inverse view; nine "
            "seeded mutations are each caught with specificity holding "
            "(docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md sections 2, 3.1, 3.8, 4.5)."
        ),
        "frf_declarable": False,
        "frf_exclusion": (
            "the exposure court reads the committed classification and re-derives only its pure "
            "checks, so it stages no artifacts/phase25/probes/ pair and carries no FRF declaration"
        ),
        "counts": {
            "census_sites": counts.get("census_sites", 0),
            "sites_classified": counts.get("sites_classified", 0),
            "externally_reachable": counts.get("externally_reachable", 0),
            "network_reachable": counts.get("network_reachable", 0),
            "unreachable_profile": counts.get("unreachable_profile", 0),
            "sites_unknown_reachability": counts.get("sites_unknown_reachability", 0),
            "routed_sites": counts.get("routed_sites", 0),
            "attacker_routes": counts.get("attacker_routes", 0),
            "attacker_routes_with_sites": counts.get("attacker_routes_with_sites", 0),
            "buffer_operations": counts.get("buffer_operations", 0),
            "justifications": counts.get("justifications", 0),
            "residuals": len(body.get("residuals") or []),
        },
        "sites_by_exposure": counts.get("sites_by_exposure") or {},
        "sites_by_risk_tier": counts.get("sites_by_risk_tier") or {},
        "routes_by_count": {r: (body.get("attacker_routes") or {}).get(r, {}).get("count", 0)
                            for r in sorted(body.get("attacker_routes") or {})},
        "findings": findings,
        "control": control,
        "problems": problems,
        "verdict": verdict,
    }


def _ms_unsafe_reduction_court(name: str) -> dict:
    """`MS-UNSAFE-REDUCTION`: 25.8's court, the unsafe reduction.

    Stages no probe. It reads the committed `artifacts/phase25/unsafe-reduction.json` and re-runs the
    25.8 pure checks `ms_reduction.reduction_findings` and
    `ms_reduction.reduction_sensitivity_control` over it together with the committed 25.1 census it
    reduces and the committed 25.7 exposure classification it reads for reachability -- no compiler,
    no tool; the derivation that produced the worklist is `ms_reduction.py --measure`, and this court
    only re-derives from what it wrote. It establishes that every applied reduction cites its
    before/after sites, its passing tests and its evidence; that no reduction changes a lint or the
    ABI and every named before site is gone from the live census; that the worklist accounts for
    exactly the reachable sites not reduced; that the counts are derived, not typed; that the frozen
    census matches the live census (its body hash and its bytes); and that the frozen lint policy is
    untouched. It also reads the 25.8 **differential artefact**
    (`forensics/memory-safety/sparse-array-differential.json`) and refuses an allocator divergence
    that is not adjudicated, a differential harness that did not run, a missing callback
    re-entrancy obligation and a missing residual unsafe boundary. Fifteen seeded mutations -- a
    reduction with no test evidence, a weakened lint, a reduced site still present, a frozen census
    that disagrees, a worklist that omits a class, a typed count, a HIDDEN classification, a removed
    site still present, a changed downstream verdict, a relocation with no boundary operation, a
    differential harness that did not run, an unadjudicated allocator divergence, a missing
    re-entrancy obligation, a count increase labelled a reduction and a dropped negative result --
    are each caught with specificity holding. It also records the
    reconstruction campaign's **negative result** and its **axis**: a conversion of the EVP operation
    cache was implemented, differentially tested against `openssl-3.6.4` with every behavioural field
    matching, and reverted because the census showed it is **not a reduction** (the subsystem rose 287
    -> 313 and the crate 172072 -> 172139), since the owned representation's allocator seam, Deref/Drop,
    slice construction and re-entrancy test cost more than a linear cache's interior unsafe is worth --
    an `attempted_conversions` entry with the verdict `REVERTED_NOT_A_REDUCTION`. The axis is what a
    conversion is judged on besides the net: dangerous operations ELIMINATED, a smaller auditable
    residual boundary, and HIDDEN=0, and a net site-count increase is never labelled a reduction. The
    worklist is a
    re-entrancy obligation -- are each caught with specificity holding. It also records the
    reconstruction campaign's **negative result** and its **axis**: a conversion of the EVP operation
    cache was implemented, differentially tested against `openssl-3.6.4` with every behavioural field
    matching, and reverted because the census showed it is **not a reduction** (the subsystem rose 287
    -> 313 and the crate 172072 -> 172139), since the owned representation's allocator seam, Deref/Drop,
    slice construction and re-entrancy test cost more than a linear cache's interior unsafe is worth --
    an `attempted_conversions` entry with the verdict `REVERTED_NOT_A_REDUCTION`. The axis is what a
    conversion is judged on besides the net: dangerous operations ELIMINATED, a smaller auditable
    residual boundary, and HIDDEN=0, and a net site-count increase is never labelled a reduction. The
    worklist is a
    **local-replacement feasibility census**, not an impossibility result: it records that none of the
    operations screened against the ten local-substitution patterns was locally replaceable without
    changing the public surface or behaviour, which is not a claim that the rest of the core is
    irreducible; a structural (representation-level) reconstruction is a separate campaign, recorded
    in `forensics/memory-safety/unsafe-reconstruction.json`. It is an **instrument**: it
    can pass while the reduction records property findings (the reachable sites no admissible safe
    intrinsic removes), which are recorded as the row's `findings` so a passing reduction court is
    never read as a memory-safety claim, and a smaller unsafe count is never read as memory safety.
    """
    if not UNSAFE_REDUCTION.is_file():
        return {"court": name, "probe": "", "verdict": "fail", "stage": "reduction-missing",
                "problems": [f"the unsafe reduction {rel(UNSAFE_REDUCTION)} is absent"],
                "findings": [], "control": {}}
    if not SOURCE_CENSUS.is_file():
        return {"court": name, "probe": "", "verdict": "fail", "stage": "census-missing",
                "problems": [f"the source census {rel(SOURCE_CENSUS)} is absent"],
                "findings": [], "control": {}}
    if not EXPOSURE.is_file():
        return {"court": name, "probe": "", "verdict": "fail", "stage": "exposure-missing",
                "problems": [f"the exposure classification {rel(EXPOSURE)} is absent"],
                "findings": [], "control": {}}

    census_body, refs = _census_view()
    body = _decoded_body(UNSAFE_REDUCTION, refs)
    authority = ms_reduction.load_authority()
    problems = ms_reduction.reduction_findings(body, census_body, authority)
    control = ms_reduction.reduction_sensitivity_control(body, census_body, authority)

    # The frozen census also binds the bytes on disk, so a census edited without re-deriving the
    # reduction is a failure rather than a frozen hash that silently tracks a hand edit.
    frozen = body.get("frozen_census") or {}
    live_sha = ms_reduction.live_census_sha256()
    if frozen.get("sha256") != live_sha:
        problems.append("the frozen census sha256 does not bind the census artefact on disk")

    counts = body.get("counts") or {}
    findings = list(body.get("findings") or [])
    rec = body.get("reconstruction") or {}

    verdict = "pass" if (not problems and control.get("honest")
                         and control.get("specificity_holds")) else "fail"
    return {
        "court": name,
        "probe": "",
        "method": (
            "stages no probe: it reads the committed artifacts/phase25/unsafe-reduction.json and "
            "re-runs the 25.8 pure checks (ms_reduction.reduction_findings and "
            "ms_reduction.reduction_sensitivity_control) over it, the committed 25.1 census it "
            "reduces, the committed 25.7 exposure classification it reads for reachability, the "
            "committed reconstruction declaration and the committed Phase-24 downstream "
            "measurement -- no compiler. Two parts. (1) The **reduction worklist**: each reachable "
            "compiler-derived site is assigned one candidate class by a total function of its "
            "operation kind and committed span, and the class records the proposed safe-intrinsic "
            "replacement or the reason it is not behaviour-preserving. The worklist is a "
            "local-replacement feasibility census, not an impossibility result: none of the "
            "operations screened against the ten local-substitution patterns was locally replaceable "
            "without changing the public surface or behaviour, which is not a claim that the rest of "
            "the core is irreducible, and a structural (representation-level) reconstruction is a "
            "separate campaign recorded in forensics/memory-safety/unsafe-reconstruction.json. "
            "(2) The **safe-core "
            "reconstruction**: it re-derives the subsystem's before/after counts (`after + the "
            "ELIMINATED set`), classifies every removed operation ELIMINATED or "
            "RELOCATED_TO_BOUNDARY, and refuses a HIDDEN claim (a wrapper), a 'removed' site still "
            "present in the live census, a relocation with no boundary operation, a typed count, a "
            "weakened lint and a **changed downstream verdict** (the Phase-24 DROP_IN_PASS count, "
            "ladder and eight functional workloads are re-read from the committed measurement and "
            "required to match the frozen baseline). It also reads the committed differential "
            "artefact and refuses an unadjudicated allocator divergence, a harness that did not run, "
            "a missing re-entrancy obligation and a missing residual unsafe boundary. Fifteen "
            "seeded mutations are each caught with specificity holding (docs/PHASE-25-MEMORY-SAFETY-"
            "SUBPHASES.md sections 2, 3.4)."
        ),
        "frf_declarable": False,
        "frf_exclusion": (
            "the unsafe-reduction court reads the committed worklist and re-derives only its pure "
            "checks, so it stages no artifacts/phase25/probes/ pair and carries no FRF declaration"
        ),
        "counts": {
            "census_sites": counts.get("sites_after", 0),
            "reachable_sites": counts.get("reachable_after", 0),
            "candidate_classes": counts.get("patterns", 0),
            "candidates": counts.get("candidates", 0),
            "applied": counts.get("applied", 0),
            "reduced": counts.get("reduced", 0),
            "rejected": counts.get("rejected", 0),
            "residuals": len(body.get("residuals") or []),
        },
        "reconstruction": {
            "subsystem": (rec.get("subsystem") or {}).get("id"),
            "sites_before": ((rec.get("counts") or {}).get("before") or {}).get("sites"),
            "sites_after": ((rec.get("counts") or {}).get("after") or {}).get("sites"),
            "net_reduced": (rec.get("counts") or {}).get("net_reduced"),
            "relocated_to_boundary": (rec.get("counts") or {}).get("relocated_to_boundary"),
            "test_only_sites": (rec.get("boundary") or {}).get("test_only_sites"),
            "operations": rec.get("operations"),
            "tests": rec.get("tests"),
            "downstream": rec.get("downstream"),
            "hidden": (rec.get("conservation") or {}).get("hidden"),
            "axis": rec.get("axis"),
            "attempted_conversions": [
                {"id": c.get("id"), "verdict": c.get("verdict"),
                 "subsystem_before": (c.get("counts") or {}).get("subsystem_before"),
                 "subsystem_after": (c.get("counts") or {}).get("subsystem_after"),
                 "crate_before": (c.get("counts") or {}).get("crate_before"),
                 "crate_after": (c.get("counts") or {}).get("crate_after"),
                 "hidden": (c.get("classification") or {}).get("HIDDEN")}
                for c in (rec.get("attempted_conversions") or [])],
            "next_targets": [
                {"id": t.get("id"), "subsystem": t.get("subsystem"),
                 "interior_operations": t.get("interior_operations")}
                for t in (rec.get("next_targets") or [])],
        },
        "worklist": {e.get("pattern"): (e.get("sites") or {}).get("count", 0)
                     for e in sorted(body.get("worklist") or [],
                                     key=lambda e: str(e.get("pattern")))},
        "findings": findings,
        "control": control,
        "problems": problems,
        "verdict": verdict,
    }


def _ms_miri_court(name: str) -> dict:
    """`MS-MIRI`: 25.9's court, the Miri results over the claimed profile.

    Stages no probe. It reads the committed `artifacts/phase25/miri.json` and re-runs the 25.9 pure
    checks `ms_miri.miri_findings` and `ms_miri.miri_sensitivity_control` over it together with the
    committed 25.1 census it classifies -- no Miri, no nightly, no compiler; the measurement that
    produced the plane is `ms_miri.py --measure` (it runs Miri), and this court only re-derives from
    what it wrote. It establishes that every census site has exactly one Miri state from the closed
    vocabulary; that an `UNSUPPORTED` site carries its reason; that a `PASS`/`FAIL` cites a real run
    with a matching outcome and command hash; that no `UNSUPPORTED` site is recorded `PASS` (they are
    refused by their specific message); that a `FAIL` run's finding is preserved; that the counts are
    derived, not typed; and that the crate-level unsupported case is recorded. Five seeded mutations
    -- an `UNSUPPORTED` marked `PASS`, a `PASS` with no run, a dropped finding, a coverage claim with
    no harness and a typed count -- are each caught with specificity holding. It is an **instrument**:
    it can pass while the plane records property findings (the Miri undefined-behaviour findings and
    the aliasing-model disagreement), which are recorded as the row's `findings` so a passing Miri
    court is never read as 'the candidate is memory safe'.
    """
    if not MIRI.is_file():
        return {"court": name, "probe": "", "verdict": "fail", "stage": "miri-missing",
                "problems": [f"the Miri plane {rel(MIRI)} is absent"], "findings": [],
                "control": {}}
    if not SOURCE_CENSUS.is_file():
        return {"court": name, "probe": "", "verdict": "fail", "stage": "census-missing",
                "problems": [f"the source census {rel(SOURCE_CENSUS)} is absent"],
                "findings": [], "control": {}}

    census_body, refs = _census_view()
    body = _decoded_body(MIRI, refs)
    problems = ms_miri.miri_findings(body, census_body)
    control = ms_miri.miri_sensitivity_control(body, census_body)

    counts = body.get("counts") or {}
    verdict = "pass" if (not problems and control.get("honest")
                         and control.get("specificity_holds")) else "fail"
    return {
        "court": name,
        "probe": "",
        "method": (
            "stages no probe: it reads the committed artifacts/phase25/miri.json and re-runs the 25.9 "
            "pure checks (ms_miri.miri_findings and ms_miri.miri_sensitivity_control) over it and the "
            "committed 25.1 census it classifies -- no Miri, no nightly, no compiler. The plane records "
            "a per-census-site Miri state (MIRI_PASS / MIRI_FAIL / MIRI_NOT_REACHABLE / "
            "MIRI_UNSUPPORTED), the runs (command hash, aliasing model, outcome), the findings, each "
            "finding's disposition (FIXED / ADJUDICATED / OPEN) and the residuals. Every MIRI_FAIL "
            "site carries a disposition; a FIXED disposition cites the targeted harness(es) now green "
            "and the source files the fix is bound to, and the court recomputes those digests and "
            "refuses a FIXED whose targeted run is absent or not PASS or whose bound source has "
            "drifted. Miri is an interpreter: it executes Rust's MIR and refuses a foreign function "
            "it cannot interpret, so the crate's first-party C adapters and raw FFI are UNSUPPORTED, "
            "recorded with the precise reason; an unsupported site is never read as a pass. The "
            "crate-wide harness aborts at its first undefined-behaviour finding, so most sites are "
            "NOT_REACHABLE rather than clean, and the two aliasing models (Stacked Borrows and Tree "
            "Borrows) are run wherever practical -- a disagreement is a preserved review item, never "
            "averaged away. Seven seeded mutations are each caught with specificity holding "
            "(docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md sections 2, 3.6)."
        ),
        "frf_declarable": False,
        "frf_exclusion": (
            "the Miri court re-derives only the plane's pure checks, so it stages no "
            "artifacts/phase25/probes/ pair and carries no FRF declaration"
        ),
        "counts": {
            "sites": counts.get("sites", 0),
            "pass": counts.get("pass", 0),
            "fail": counts.get("fail", 0),
            "not_reachable": counts.get("not_reachable", 0),
            "unsupported": counts.get("unsupported", 0),
            "runs": len(body.get("runs") or []),
            "findings": len(body.get("findings") or []),
            "dispositions": len(body.get("dispositions") or []),
            "residuals": len(body.get("residuals") or []),
        },
        "runs": [
            {"run_id": r.get("run_id"), "aliasing_model": r.get("aliasing_model"),
             "outcome": r.get("outcome"), "command_sha256": str(r.get("command_sha256"))[:16]}
            for r in body.get("runs") or []
        ],
        "findings": list(body.get("findings") or []),
        "dispositions": list(body.get("dispositions") or []),
        "control": control,
        "problems": problems,
        "verdict": verdict,
    }


def _ms_asan_msan_court(name: str) -> dict:
    """`MS-ASAN-MSMAN`: 25.10's court, the ASan/MSan results over the claimed profile.

    Stages no probe. It reads the committed `artifacts/phase25/asan-msan.json` and re-runs the 25.10
    pure checks `ms_asan.asan_findings` and `ms_asan.asan_sensitivity_control` over it together with
    the committed 25.1 census it classifies -- no ASan, no nightly, no compiler; the measurement that
    produced the plane is `ms_asan.py --measure` (it builds and runs the instrumented candidate), and
    this court only re-derives from what it wrote. It establishes that every census site has exactly
    one ASan state from the closed vocabulary; that an `UNSUPPORTED` site carries its reason; that a
    `PASS`/`FAIL` cites a real run with a matching outcome and command hash and that a `PASS` covers
    the site's file; that no `UNSUPPORTED` site and no site with a finding at it is recorded `PASS`;
    that a `FAIL` run's finding is preserved; that the sanitizer_result records validate and both
    sanitizers are represented; that the counts are derived, not typed; that every ASan result states
    its file coverage granularity and the plane carries its `pass_semantics`; that the MSan result is
    never recorded `PASS` (the venue links uninstrumented libc and carries no MSan positive control);
    and that the venue, the canary and the crate-level case are recorded. Seeded mutations -- a `PASS`
    with no run, a `PASS` with a finding at it, a dropped site, an `UNSUPPORTED` marked `PASS`, a typed
    count, an `UNSUPPORTED` run with no reason and the MSan result marked `PASS` -- are each caught
    with specificity holding. It is an
    **instrument**: it can pass while the plane records property findings (the ASan findings), which
    are recorded as the row's `findings` so a passing sanitizer court is never read as 'the candidate
    is memory safe'.
    """
    if not ASAN_MSAN.is_file():
        return {"court": name, "probe": "", "verdict": "fail", "stage": "asan-missing",
                "problems": [f"the ASan/MSan plane {rel(ASAN_MSAN)} is absent"], "findings": [],
                "control": {}}
    if not SOURCE_CENSUS.is_file():
        return {"court": name, "probe": "", "verdict": "fail", "stage": "census-missing",
                "problems": [f"the source census {rel(SOURCE_CENSUS)} is absent"],
                "findings": [], "control": {}}

    census_body, refs = _census_view()
    body = _decoded_body(ASAN_MSAN, refs)
    problems = ms_asan.asan_findings(body, census_body)
    control = ms_asan.asan_sensitivity_control(body, census_body)

    counts = body.get("counts") or {}
    verdict = "pass" if (not problems and control.get("honest")
                         and control.get("specificity_holds")) else "fail"
    cl = (body.get("rule") or {}).get("crate_level") or {}
    return {
        "court": name,
        "probe": "",
        "method": (
            "stages no probe: it reads the committed artifacts/phase25/asan-msan.json and re-runs the "
            "25.10 pure checks (ms_asan.asan_findings and ms_asan.asan_sensitivity_control) over it "
            "and the committed 25.1 census it classifies -- no ASan, no nightly, no compiler. The "
            "plane records a per-census-site ASan state (ASAN_PASS / ASAN_FAIL / ASAN_NOT_REACHABLE "
            "/ ASAN_UNSUPPORTED), the runs (command hash, outcome, executed tests), the findings, the "
            "sanitizer_result records and the residuals. ASan instruments the Rust crate, `std` "
            "(rebuilt with -Zbuild-std), the first-party C adapters and the interceptable libc; it "
            "cannot instrument a module loaded at run time (src/dso/dlfcn.rs) or see through an "
            "opaque operation, and a site the instrument cannot reach or instrument is "
            "NOT_REACHABLE/UNSUPPORTED, never silently clean. A zero-findings result is trusted only "
            "because the deliberate use-after-free canary is known to fire. The ASan environment is "
            "the admitted court image with the venue's documented OPENSSL_RS_COURT_DATA override "
            "(ASan's shadow is MAP_NORESERVE virtual address space); the crate-level state records "
            "ASAN_RAN or ASAN_UNSUPPORTED. Every ASAN_PASS is a file-granular claim -- the site's "
            "source FILE was instrumented and a passing run covered it, not a per-operation proof "
            "that the specific operation executed (the plane's top-level `pass_semantics` and each "
            "ASan result's `coverage_granularity: file` state this). MSan's result is recorded "
            "UNSUPPORTED, never PASS: the venue links the uninstrumented system glibc/libc++ and the "
            "plane carries no MSan positive control, so its libc-interception boundary is recorded as "
            "the reason. Seven "
            "seeded mutations are each caught with specificity holding "
            "(docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md sections 2, 3.6)."
        ),
        "frf_declarable": False,
        "frf_exclusion": (
            "the ASan/MSan court re-derives only the plane's pure checks, so it stages no "
            "artifacts/phase25/probes/ pair and carries no FRF declaration"
        ),
        "counts": {
            "sites": counts.get("sites", 0),
            "pass": counts.get("pass", 0),
            "fail": counts.get("fail", 0),
            "not_reachable": counts.get("not_reachable", 0),
            "unsupported": counts.get("unsupported", 0),
            "runs": len(body.get("runs") or []),
            "findings": len(body.get("findings") or []),
            "results": len(body.get("results") or []),
            "residuals": len(body.get("residuals") or []),
            "crate_ran": 1 if cl.get("state") == "ASAN_RAN" else 0,
        },
        "runs": [
            {"run_id": r.get("run_id"), "outcome": r.get("outcome"),
             "tests_passed": r.get("tests_passed"), "tests_run": r.get("tests_run"),
             "command_sha256": str(r.get("command_sha256"))[:16]}
            for r in body.get("runs") or []
        ],
        "findings": list(body.get("findings") or []),
        "control": control,
        "problems": problems,
        "verdict": verdict,
    }


def _ms_tsan_court(name: str) -> dict:
    """`MS-TSAN`: 25.11's court, the TSan results over the concurrency-relevant surface.

    Stages no probe. It reads the committed `artifacts/phase25/tsan.json` and re-runs the 25.11 pure
    checks `ms_tsan.tsan_findings` and `ms_tsan.tsan_sensitivity_control` over it, together with the
    committed 25.1 census and the committed 25.3 obligation rule that defines the concurrency-
    relevant surface -- no TSan, no nightly, no compiler; the measurement that produced the plane is
    `ms_tsan.py --measure` (it builds and runs the instrumented candidate), and this court only
    re-derives from what it wrote. It establishes that the plane carries exactly one TSan state for
    every site of the derived concurrency-relevant surface and no other census site; that an
    `UNSUPPORTED` site carries its reason; that a `PASS`/`FAIL` cites a real run with a matching
    outcome and command hash and that a `PASS` covers the site's file; that no `UNSUPPORTED` site and
    no site with a finding at it is recorded `PASS`; that a `FAIL` run's finding is preserved; that
    the sanitizer_result records validate and every result states its file coverage granularity; that
    the counts are derived, not typed; that no `PASS` is recorded while the data-race positive control
    did not fire; that the schedule is recorded; and that the venue, the canary and the crate-level
    case are recorded. Seeded mutations -- a `PASS` with no run, a `PASS` with a finding at it, a
    dropped site, an `UNSUPPORTED` marked `PASS`, a typed count, an `UNSUPPORTED` run with no reason
    and a `PASS` with no positive control -- are each caught with specificity holding. It is an
    **instrument**: it can pass while the plane records property findings (the TSan findings), which
    are recorded as the row's `findings` so a passing sanitizer court is never read as 'the candidate
    is race-free'.
    """
    if not TSAN.is_file():
        return {"court": name, "probe": "", "verdict": "fail", "stage": "tsan-missing",
                "problems": [f"the TSan plane {rel(TSAN)} is absent"], "findings": [],
                "control": {}}
    if not SOURCE_CENSUS.is_file():
        return {"court": name, "probe": "", "verdict": "fail", "stage": "census-missing",
                "problems": [f"the source census {rel(SOURCE_CENSUS)} is absent"],
                "findings": [], "control": {}}

    census_body, refs = _census_view()
    body = _decoded_body(TSAN, refs)
    problems = ms_tsan.tsan_findings(body, census_body)
    control = ms_tsan.tsan_sensitivity_control(body, census_body)

    counts = body.get("counts") or {}
    verdict = "pass" if (not problems and control.get("honest")
                         and control.get("specificity_holds")) else "fail"
    cl = (body.get("rule") or {}).get("crate_level") or {}
    return {
        "court": name,
        "probe": "",
        "method": (
            "stages no probe: it reads the committed artifacts/phase25/tsan.json and re-runs the "
            "25.11 pure checks (ms_tsan.tsan_findings and ms_tsan.tsan_sensitivity_control) over it, "
            "the committed 25.1 census and the committed 25.3 obligation rule that defines the "
            "concurrency-relevant surface -- no TSan, no nightly, no compiler. The plane records a "
            "per-surface-site TSan state (TSAN_PASS / TSAN_FAIL / TSAN_NOT_REACHABLE / "
            "TSAN_UNSUPPORTED) over the census sites whose operation kind requires a concurrency "
            "obligation (thread-affinity, Send/Sync or init-once), the runs (schedule, command hash, "
            "outcome, executed tests), the findings, the sanitizer_result records and the residuals. "
            "The runs pin the libtest schedule to one thread (--test-threads=1, the deterministic "
            "schedule docs/CONCURRENCY_MODEL.md section 6 fixes for reproducibility), so a race the "
            "crate's own thread tests did not exercise under that schedule is not read as absent. "
            "TSan instruments the Rust crate, `std` (rebuilt with -Zbuild-std), the first-party C "
            "adapters and the interceptable libc; it cannot instrument a module loaded at run time "
            "(src/dso/dlfcn.rs) or see through an opaque operation, and a site the instrument cannot "
            "reach or instrument is NOT_REACHABLE/UNSUPPORTED, never silently clean. A no-race "
            "result is trusted only because the deliberate data-race canary is known to fire. The "
            "TSan environment is the admitted court image with the venue's documented "
            "OPENSSL_RS_COURT_DATA override (TSan's ~35.1 TB shadow is MAP_NORESERVE virtual "
            "address space); the crate-level state records TSAN_RAN or TSAN_UNSUPPORTED. Every "
            "TSAN_PASS is a file-granular claim under the recorded schedule -- the site's source "
            "FILE was instrumented and a passing run covered it, not a per-operation proof that the "
            "specific operation executed race-free (the plane's top-level `pass_semantics` and each "
            "result's `coverage_granularity: file` state this). Seven seeded mutations are each "
            "caught with specificity holding "
            "(docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md sections 2, 3.6)."
        ),
        "frf_declarable": False,
        "frf_exclusion": (
            "the TSan court re-derives only the plane's pure checks, so it stages no "
            "artifacts/phase25/probes/ pair and carries no FRF declaration"
        ),
        "counts": {
            "sites": counts.get("sites", 0),
            "pass": counts.get("pass", 0),
            "fail": counts.get("fail", 0),
            "not_reachable": counts.get("not_reachable", 0),
            "unsupported": counts.get("unsupported", 0),
            "runs": len(body.get("runs") or []),
            "findings": len(body.get("findings") or []),
            "results": len(body.get("results") or []),
            "residuals": len(body.get("residuals") or []),
            "crate_ran": 1 if cl.get("state") == "TSAN_RAN" else 0,
        },
        "runs": [
            {"run_id": r.get("run_id"), "outcome": r.get("outcome"),
             "tests_passed": r.get("tests_passed"), "tests_run": r.get("tests_run"),
             "command_sha256": str(r.get("command_sha256"))[:16]}
            for r in body.get("runs") or []
        ],
        "findings": list(body.get("findings") or []),
        "control": control,
        "problems": problems,
        "verdict": verdict,
    }


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    ap.add_argument("--self-test", action="store_true",
                    help="prove a host invocation of this runner is refused by the guard")
    args = ap.parse_args(argv)

    # The Docker-only execution guard, called first. The runner is an execution entry point (its
    # later courts compile the census, run the sanitizers, the proof harnesses and the CVE replays),
    # so the manifest does not list it `metadata_only` and a host invocation is refused.
    phase25_guard.require_admitted()

    if args.self_test:
        # Prove the guard refuses a host invocation of this runner, without running on a host.
        refusal = phase25_guard.host_refusal_reasons("phase25_courts.py")
        if not refusal:
            print("[phase25-courts] self-test FAILED: the guard admitted a host invocation of "
                  "the runner")
            return 1
        marker = phase25_guard.load_manifest().get("marker")
        flag = phase25_guard.load_manifest().get("env_flag")
        joined = " ".join(refusal)
        if str(marker) not in joined or str(flag) not in joined:
            print("[phase25-courts] self-test FAILED: the refusal does not name the marker and "
                  "the opt-in flag")
            return 1
        print(f"[phase25-courts] self-test ok: the guard refuses a host invocation of the runner "
              f"({len(refusal)} reason(s), naming the marker and the opt-in flag)")
        return 0

    auth = resolve_authority(PRODUCTION_AUTHORITY)

    records: list[dict] = []
    for name, handler in COURTS:
        # Each registered court stages no probe -- this stratum owns no exported symbol, so no
        # differential probe over a symbol set is its evidence -- and each is computed here rather
        # than read back from disk, so no digest cycle forms. The handler is named in the table and
        # resolved here, so a court added to COURTS without a function is a loud failure.
        fn = globals().get(str(handler))
        if fn is None:
            records.append({"court": name, "verdict": "fail", "stage": "handler-missing",
                            "detail": str(handler)})
            continue
        records.append(fn(name))

    passed = sum(1 for r in records if r["verdict"] == "pass")
    failed = sum(1 for r in records if r["verdict"] == "fail")
    body = {
        "all_pass": failed == 0 and len(records) == len(COURTS),
        "authority": auth.id,
        "courts": records,
        "summary": {"total": len(records), "pass": passed, "fail": failed},
        "pending_courts": PENDING_COURTS,
        "schemas": memory_safety_schemas.inventory(),
        "unsafe_operation_kinds": list(memory_safety_schemas.UNSAFE_OPERATION_KINDS),
        "obligation_dimensions": list(memory_safety_schemas.OBLIGATION_DIMENSIONS),
        "exposure_classes": list(memory_safety_schemas.EXPOSURE_CLASSES),
        "externally_reachable_exposure": sorted(memory_safety_schemas.EXTERNALLY_REACHABLE_EXPOSURE),
        "tool_states": list(memory_safety_schemas.TOOL_STATES),
        "cve_taxonomy": list(memory_safety_schemas.CVE_TAXONOMY),
        "cve_replay_states": list(memory_safety_schemas.CVE_REPLAY_STATES),
        "risk_tiers": list(memory_safety_schemas.RISK_TIERS),
        "panic_unwind_classes": list(memory_safety_schemas.PANIC_UNWIND_CLASSES),
        "claim": (
            "**25.0 registers `MS-CONSTITUTION`**, the constitution gate over the plan, schemas, "
            "guard, venue manifest, obligation ledger and the frozen safety lint policy, "
            "**25.1 registers `MS-SOURCE-CENSUS`**, the compiler-backed source census, "
            "**25.2 registers `MS-NON-RUST-TCB`**, the non-Rust trusted computing base, "
            "**25.3 registers `MS-SAFETY-OBLIGATIONS`**, the safety obligations per compiler-derived "
            "unsafe site, "
            "**25.4 registers `MS-OWNERSHIP-PLANES`**, the ownership/allocation/callback planes, and "
            "**25.5 registers `MS-PHASE22-CROSSWALK`**, the crosswalk from each unsafe site to the "
            "Phase-22 whole-program reachability atlas, and "
            "**25.6 registers `MS-PHASE24-CROSSWALK`**, the crosswalk from each unsafe site to the "
            "Phase-24 downstream-1000 measurement, and "
            "**25.7 registers `MS-EXPOSURE-CLASSIFICATION`**, the exposure/data-flow classification "
            "that gives every unsafe site exactly one exposure class and records the attacker-input "
            "routes and the buffer-operation census, and "
            "**25.8 registers `MS-UNSAFE-REDUCTION`**, the reduction worklist over the reachable "
            "compiler-derived sites that records each candidate safe-intrinsic replacement, the sites "
            "that remain named rather than dropped, and the frozen post-reduction census, and is a "
            "local-replacement feasibility census rather than an impossibility result, and "
            "**25.9 registers `MS-MIRI`**, the Miri results over the claimed profile, each with its "
            "tool state and its unsupported reason where Miri could not express the question, so an "
            "unsupported site is never read as a pass, and "
            "**25.10 registers `MS-ASAN-MSMAN`**, the ASan/MSan results over the claimed profile, "
            "each with its tool state and its unsupported reason where a sanitizer could not "
            "instrument or reach a target, so a site the instrument cannot reach or instrument is "
            "recorded rather than counted clean, and "
            "**25.11 registers `MS-TSAN`**, the TSan results over the concurrency-relevant surface, "
            "each with its tool state and its unsupported reason, so a race the tool could not "
            "observe under the recorded schedule is not read as absent. "
            "Phase 25 owns "
            "no exported symbol, so no differential probe over a symbol set is its evidence; the "
            "remaining ten of its twenty-two courts -- "
            "MS-KANI, MS-PHASE18-FUZZ-CROSSWALK, MS-PHASE24-SAFETY-COVERAGE, MS-HISTORICAL-CVE, "
            "MS-CVE-REPLAY, MS-MECHANISM-RECONCILIATION, MS-RED-TEAM, MS-CLEAN-REGEN, "
            "MS-FRF-CLOSURE and MS-SEAL -- are pending with the subphases that land them (25.12 "
            "through 25.21). The stratum's record kinds are defined and self-tested in "
            "forensics/tools/memory_safety_schemas.py, whose inventory this registry records: the "
            "source-census row, the compiler-derived unsafe site, the unsafe context, the safety "
            "obligation, the FFI boundary, the C adapter, the allocation site, the ownership edge, "
            "the callback lifetime, the unsafe Send/Sync impl, the global state, the panic "
            "boundary, the Miri/ASan/MSan/TSan/Kani results, the Phase-18 fuzz crosswalk, the "
            "coverage row, the historical CVE, the CVE replay, the vulnerability mechanism, the "
            "residual and the seal-class summary. The **primary unit is a compiler-derived unsafe "
            "operation**, and lines of unsafe code are a secondary projection, never the security "
            "claim. Every entry point calls the Docker-only execution guard "
            "(forensics/tools/phase25_guard.py) first, so nothing in this stratum executes on the "
            "host. A tool state of UNSUPPORTED is never PASS, and a CANDIDATE_STRUCTURALLY_EXCLUDED "
            "CVE replay must cite its evidence. The bounded claim is that the memory-safety-"
            "relevant trusted computing base of the exact admitted candidate has been exhaustively "
            "inventoried over its first-party shipped source/build surface, with unsafe operations "
            "mapped to their safety contracts, Phase-22 reachability, Phase-24 downstream usage and "
            "available dynamic/formal evidence, and with no unexplained reachable unsafe site in "
            "the claimed profile. It is not 'no memory-safety bug can exist' and not '100% memory "
            "safe'; docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md sections 0, 1, 2 and 4 record the "
            "measurement and the precondition."
        ),
    }

    inputs = [
        InputRef(name="phase-25-plan", path=PLAN),
        InputRef(name="memory-safety-schemas", path=SCHEMAS),
        InputRef(name="phase25-guard", path=GUARD),
        InputRef(name="phase25-container-manifest", path=MANIFEST),
        # The obligation ledger is deliberately **not** bound. The edge runs ledger -> courts (the
        # ledger's contract-unit states are measured from this registry), and binding it back would
        # embed each artefact's digest in the other -- a digest cycle neither could reproduce, which
        # is exactly what this runner's own docstring and every other stratum's runner record. The
        # constitution court reads the ledger directly, so nothing here needs its digest.
        InputRef(name="cargo-toml", path=CARGO_TOML),
        InputRef(name="lib-rs", path=LIB_RS),
        InputRef(name="source-census", path=SOURCE_CENSUS),
        InputRef(name="ms-census-tool", path=MS_CENSUS_TOOL),
        InputRef(name="non-rust-tcb", path=NON_RUST_TCB),
        InputRef(name="ms-non-rust-tcb-tool", path=MS_NON_RUST_TOOL),
        InputRef(name="safety-obligations", path=SAFETY_OBLIGATIONS),
        InputRef(name="ms-obligations-tool", path=MS_OBLIGATIONS_TOOL),
        InputRef(name="ownership-planes", path=OWNERSHIP_PLANES),
        InputRef(name="ms-ownership-planes-tool", path=MS_OWNERSHIP_TOOL),
        InputRef(name="phase22-crosswalk", path=PHASE22_CROSSWALK),
        InputRef(name="ms-phase22-crosswalk-tool", path=MS_PHASE22_CROSSWALK_TOOL),
        InputRef(name="phase22-compatibility-closure", path=PHASE22_CLOSURE),
        InputRef(name="phase22-reconciliation", path=PHASE22_RECONCILIATION),
        InputRef(name="transcription-edges", path=TRANSCRIPTION_EDGES),
        InputRef(name="internal-symbols", path=INTERNAL_SYMBOLS),
        InputRef(name="export-defining-units", path=EXPORT_DEFINING_UNITS),
        InputRef(name="phase24-crosswalk", path=PHASE24_CROSSWALK),
        InputRef(name="ms-phase24-crosswalk-tool", path=MS_PHASE24_CROSSWALK_TOOL),
        InputRef(name="downstream-usage-fingerprints", path=DOWNSTREAM_USAGE_FINGERPRINTS),
        InputRef(name="downstream-reconciliation", path=DOWNSTREAM_RECONCILIATION),
        InputRef(name="downstream-runtime-functional-atlas", path=DOWNSTREAM_RUNTIME_ATLAS),
        InputRef(name="downstream-build-link-atlas", path=DOWNSTREAM_BUILD_LINK_ATLAS),
        InputRef(name="downstream-p1000-run", path=DOWNSTREAM_P1000_RUN),
        InputRef(name="downstream-family-freeze", path=DOWNSTREAM_FAMILY_FREEZE),
        InputRef(name="exposure", path=EXPOSURE),
        InputRef(name="ms-exposure-tool", path=MS_EXPOSURE_TOOL),
        InputRef(name="unsafe-reduction", path=UNSAFE_REDUCTION),
        InputRef(name="ms-reduction-tool", path=MS_REDUCTION_TOOL),
        InputRef(name="miri", path=MIRI),
        InputRef(name="ms-miri-tool", path=MS_MIRI_TOOL),
        InputRef(name="miri-tcb-suite-manifest", path=PHASE18_MIRI_SUITE),
        InputRef(name="miri-harness-source", path=MIRI_HARNESS_SOURCE),
        InputRef(name="asan-msan", path=ASAN_MSAN),
        InputRef(name="ms-asan-tool", path=MS_ASAN_TOOL),
        InputRef(name="asan-canary-source", path=ASAN_CANARY_SOURCE),
        InputRef(name="asan-harness-source", path=ASAN_HARNESS_SOURCE),
        InputRef(name="tsan", path=TSAN),
        InputRef(name="ms-tsan-tool", path=MS_TSAN_TOOL),
        InputRef(name="tsan-canary-source", path=TSAN_CANARY_SOURCE),
        InputRef(name="tsan-canary-rust-source", path=TSAN_CANARY_RUST_SOURCE),
        InputRef(name="tsan-harness-source", path=TSAN_HARNESS_SOURCE),
    ]
    doc = envelope(kind="phase25-courts", authority=auth.id, inputs=inputs,
                   body=body, generator=GENERATOR)
    write_json(OUT, doc)

    for r in records:
        if r["verdict"] == "pass":
            c = r.get("counts") or {}
            ctrl = r.get("control") or {}
            pairs = ", ".join(f"{k}={v}" for k, v in sorted(c.items()))
            print(f"  {r['court']:<32} pass   (no probe, {pairs}; "
                  f"{len(r.get('findings') or [])} finding(s); control honest={ctrl.get('honest')} "
                  f"specificity={ctrl.get('specificity_holds')})")
    for cname, needs in PENDING_COURTS.items():
        print(f"  {cname:<32} PENDING (not registered as passing) -- {needs}")
    print(f"  schema inventory: {len(body['schemas'])} record kind(s)")
    print(f"  unsafe-operation kinds: {len(body['unsafe_operation_kinds'])}; "
          f"obligation dimensions: {len(body['obligation_dimensions'])}; "
          f"exposure classes: {len(body['exposure_classes'])}; "
          f"tool states: {len(body['tool_states'])}")
    print(f"  CVE taxonomy: {len(body['cve_taxonomy'])} class(es); "
          f"CVE replay states: {len(body['cve_replay_states'])}; "
          f"risk tiers: {len(body['risk_tiers'])}; "
          f"panic/unwind classes: {len(body['panic_unwind_classes'])}")
    print(f"  -> {rel(OUT)} all_pass={body['all_pass']} over {len(records)} court(s)")
    return 0 if body["all_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
