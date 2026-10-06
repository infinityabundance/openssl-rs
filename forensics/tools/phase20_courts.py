#!/usr/bin/env python3
"""openssl-rs — Phase 20 courts: the 3.6.4 custodian seal courts.

Each court is an instrument that compiles the custodian claim over the finished implementation,
not a differential probe over a symbol set. This stratum owns no exported symbol: it measures the
library the strata before it completed, so its evidence is about *the claim* -- the maturity level
the committed evidence supports, whether every closed obligation joins to an FRF receipt and the
store compiles the parity claim with zero blockers, whether every residual is dispositioned with no
`UNKNOWN` intersecting the claimed production profile, whether an authority-built binary runs
unmodified against the candidate over the machine-owned downstream corpus, and what the stratum
explicitly does not claim. The method is Phases 3 through 19's where an artefact carries the
expectation: each court reads the artefact that holds its subject rather than typing the expectation
beside it, so the two cannot disagree, and a court whose control is not honest is `fail` rather than
`pass`.

`RT-CUSTODIAN-MATURITY`, and what it derives
------------------------------------------
20.1's court. Its subject is the **L0-L9 maturity ladder** of `docs/RELEASE_GATES.md` section 3,
derived for `libcrypto` and `libssl` from committed evidence, and it is the closest analogue of
Phase 19's `PERFORMANCE-BOUNDARY-REGISTER`: it stages no probe, reads the artefacts that establish
each level, and fails the stratum if a level is named whose evidence is absent. The ladder's
authority is `docs/RELEASE_GATES.md` section 3 (the level names) and section 4 (the court families),
and each level is bound to the strata and machine-owned artefacts that establish it:

  * **L0 `archaeology complete`** -- the Phase 1 seal and `forensics/atlas/phase1-completeness.json`;
  * **L1 `source / API shell`** and **L2 `ABI-load compatible`** -- the Phase 2 seal and the
    `ABI-SYMBOL` / `ABI-VERSION` / `ABI-LOAD` / `ABI-LINK` / `ABI-LAYOUT` / `ABI-DYNAMIC` /
    `ABI-SUBSTITUTION` courts in `artifacts/phase2/COURTS.json`;
  * **L3 `libcrypto core semantic parity`** -- strata 3-5 (the `RT-MEM`/`RT-ERR`/`RT-BN`/`RT-ASN1`/
    `RT-PEM` families);
  * **L4 `provider / EVP parity`** -- strata 6-7 plus the provider census
    (`forensics/atlas/provider-algorithms.json`) and the provider-row coverage join
    (`forensics/atlas/provider-court-coverage.json`);
  * **L5 `complete libcrypto claimed surface`** -- strata 8, 9, 10, 11, 12, 13 and 22, the
    provider census, and the export court-coverage join (`forensics/atlas/court-coverage.json`);
  * **L6 `libssl protocol parity`** -- strata 14-15 (the `RT-SSL-*`/`RT-DTLS`/`RT-QUIC` families);
  * **L7 `CLI / distribution parity`** -- stratum 16 (`RT-CLI`/`RT-CONFIG`);
  * **L8 `downstream custodian court`** -- stratum 17 and the Phase-17 machine-owned corpus
    (`forensics/atlas/downstream-corpus.json`), whose every program must link and run unmodified
    against the candidate;
  * **L9 `high-assurance custodian seal`** -- strata 18-20 and the Phase-20 custodian seal
    `docs/PHASE-20-CUSTODIAN-SEAL.md` 20.6 lands.

The ladder is **cumulative**: level `Ln` is present only when its own evidence and every level
below it are. So a missing prerequisite at any rung makes every rung above it absent, which is what
lets the court record a *gap* rather than a level the seal might otherwise name.

**The two axes diverge here, by design.** On the current tree the derivation reaches **L8** for
both `libcrypto` and `libssl`, and **L9 is absent**: it is the level Phase 20 itself is
establishing, and `docs/PHASE-20-SUBPHASES.md` section 4.2 is the precondition. The court is `pass`
as an **instrument** -- it derived the ladder, its evidence is committed, and its control is honest
-- while recording the L9 gap as a `finding`, so the ledger's `custodian-maturity` property reads
`NOT_CLAIMED` with `findings_present`. **A passing `RT-CUSTODIAN-MATURITY` must never be read as
"L9 custodian seal achieved".** A level whose evidence is absent is never named as reached: the
court records only the highest level the committed evidence establishes, and a level claimed without
its evidence is `fail`, not a stronger verdict.

The derivation reads `forensics/phase-state.json` for the strata states as a **cross-check**, not as
a dependency: it is downstream of this court (it consumes the Phase-20 ledger, which consumes this
registry), so binding it would close the ledger -> courts -> ledger digest cycle
`docs/PHASE-20-SUBPHASES.md` section 4.2 forbids. Every level's presence is derived instead from the
strata's own seals and court registries -- the same committed artefacts `phase_state.py` derives
`complete` from -- and a stratum whose state disagrees with its seal or registry is a `problem`.

The instrument sensitivity control
----------------------------------
Section 3.2's rule is mechanical here: a control that cannot fail is not evidence. Beside the real
derivation the court derives a **synthetic evidence view with a level's prerequisite removed** and
requires the ladder to detect the gap -- once by making a mid-stratum (5, a prerequisite of L3)
incomplete, which must collapse the ladder to L2, and once by making the downstream stratum (17,
L8's own) incomplete, which must leave L7 but drop L8 and L9. The control is honest only when the
baseline reaches L8 with L9 absent *and* both injected views detect their gap; otherwise the verdict
is `fail`, never a vacuous `pass`.

`RT-RECEIPT-CLOSURE`, and what it joins
---------------------------------------
20.2's court. Its subject is the **receipt closure**: every obligation a stratum recorded
`implemented` or closed must join to the FRF receipt that proves it, and the `sensitivity-backed`
claim the FRF store compiled over the receipts must carry **zero blockers**. `docs/CUSTODIAN_CONTRACT.md`
section 6 makes custodian compatibility conditional on machine-verifiable evidence and section 9's
success definition names FRF compiling the parity claim from immutable receipts; this court is where
that join is executed rather than asserted. It reads the registers the earlier strata and the FRF
store write and maintains no list of its own:

  * the **per-stratum obligation ledgers** `forensics/phase<N>-obligations.json`, for the
    `implemented` sets (the export strata's symbols and the contract strata's contract units);
  * the **court-coverage join** `forensics/atlas/court-coverage.json`, which binds each implemented
    export to the courts that court it, and the authored `reference_probes` set in
    `forensics/atlas/court-coverage-rows.json`, which names the courts whose evidence is an
    address-taking probe rather than a transcript;
  * the **FRF declarations** `forensics/frf/courts/<court>/manifest.yaml`, the **receipts**
    `.frf/receipts/*.json` (each read through its own `court.id`), the **challenges**
    `.frf/challenges/*.json`, and the compiled **claims** `.frf/claims/*.json`; and
  * the **Gemel checkpoint projection** `forensics/GEMEL_TRAJECTORY.md`.

The join is per stratum, because the FRF chain is per stratum: a stratum's obligations are proven by
the receipts of the FRF-declarable courts it ran, so the court requires, for every such court, a
declaration, a receipt, two adjudicated challenges (`saw_defect` and `specificity_clean`, both
operators) and a `sensitivity-backed` claim of **zero blockers** that covers the court's receipt and
records the current candidate identity -- the same five clauses `forensics/tools/phase_state.py`'s
`frf_gemel_blocking_reason` derives a stratum's blocking reason from. It additionally joins each
implemented **export** to its courts through the court-coverage atlas, so an obligation courted by no
court at all is a gap rather than a silent omission.

**The two evidence classes, kept apart.** An export whose courts include one with an FRF receipt joins
to that receipt; the reference-basis exports -- whose only courts are the `-REF` probes that take an
address and print non-NULL rather than diffing a transcript (D199) -- join to that reference basis,
which is a recorded evidence class, not a receipt and not a gap. Both are joined; the court records
the two counts separately rather than letting one stand in for the other.

**Honesty.** A stratum whose chain is incomplete, an export courted by no court, or a covering claim
carrying a blocker is the court's `finding`, and the verdict is `fail` -- the court is not weakened to
pass. On the current tree the closure is complete: every in-scope stratum's chain is complete, the
covering claims carry zero blockers, and the court records **zero findings**. A passing
`RT-RECEIPT-CLOSURE` is an instrument plus this join; it is a join over the finite receipts the store
carries, not a universal-parity claim, and the three non-claims of section 0 still bound it.

The instrument sensitivity control
----------------------------------
Section 3.2's rule again: a control that cannot fail is not evidence. Beside the real join the court
derives three **synthetic evidence views**, each with one premise removed, and requires the join to
detect each: a required court's receipt deleted from the store view, a covering claim given a
non-zero blocker, and a covering claim's recorded candidate identity moved off the current release.
The control is honest only when the real join is complete *and* all three injections are detected;
otherwise a join that cannot tell evidence from its absence would pass vacuously.

`RT-CUSTODIAN-RESIDUALS`, and what it dispositions
-----------------------------------------------
20.3's court. Its subject is the **residual disposition**: every residual the earlier strata and
the FRF store record must carry a disposition, and **no `UNKNOWN` residual may intersect the
claimed production profile**. `docs/CUSTODIAN_CONTRACT.md` section 6 makes custodian compatibility
conditional on "no unresolved residual intersecting the claimed scope", section 8 keeps `UNKNOWN`
an honest result rather than a resting state, and `docs/PARITY_MODEL.md` section 1 defines the two
states that must never be papered over; this court is where that discipline is executed over the
registers rather than asserted. Like the two courts above it stages no probe and maintains no list
of its own: it reads the residual sources the earlier strata write, so a residual added without a
disposition is visible as a `fail` rather than a silent addition. The sources are bound to
the committed registers that carry them:

  * the **Phase-22 cross-plane residual census** `forensics/atlas/phase22/reconciliation.json`
    (every reachable entity's residual class and disposition) and the closure
    `forensics/atlas/phase22/compatibility-closure.json` (`unknown_intersecting_root_keys`, the
    register's own computation of which `UNKNOWN` residual reaches a declared compatibility root)
    and the checkpoint `forensics/atlas/phase22/gemel-checkpoint.json` (the `UNKNOWN` sets, named);
  * the **Phase-1 archaeology completeness** `forensics/atlas/phase1-completeness.json` (the
    residual-disposition classes, the open-`UNKNOWN` set, the missing set and the deferred planes)
    and the **symbol reconciliation** `forensics/atlas/openssl-3.6.4-production/
    surface-reconciliation.json` (the five hard-residual classes per library);
  * the **divergence obligations** `forensics/divergence-obligations.json`, the **ownership
    transitions** `forensics/ownership-transitions.json` and the **prerequisite plane**
    `forensics/prerequisites.json` (its divergences, deferrals and classification rows);
  * the **Phase-18 hostile-boundary register** and the **Phase-19 performance-boundary register**,
    the Phase-18 hostile-court residual counts, the **CT-primitives** `bn-modexp`/`bn-inverse`
    findings, the **ASan** closure and the **Miri** TCB receipts;
  * the **unsafe-footprint growth ceiling** `forensics/atlas/unsafe-footprint.json` against
    `artifacts/phase18/unsafe-bounds.json`;
  * the **FRF store's residuals** `.frf/residuals/*.token.json`.

Each source is recorded with its residual records, each record the shape `{source, id,
`disposition`, intersects_production_profile, state}` — where a residual the register carries only as
a set is held as one record with its `count`, and every `UNKNOWN` residual is held individually so
the intersection discipline is visible per name. The `state` names how the residual bears
evidence (`dispositioned`, `unknown`, `un_dispositioned`, `bounded`, `divergence`,
`sensitivity-mutant`, ...).

**Honesty.** The court fails exactly two ways: a residual with **no disposition**, and an
`UNKNOWN` residual that **intersects the claimed production profile**. On the current tree there are
334 `UNKNOWN` residual records — the 167 `POD_NAME_NOT_IN_ATLAS` names the pod-contract plane
carries, re-projected by two registers (the Phase-22 cross-plane census and the checkpoint's named
`UNKNOWN` sets) — and the closure records that **zero of them intersect** a declared compatibility
root, so the court records **zero findings** and says so precisely. An `UNKNOWN` that merely does not intersect is not resolved by
this court: it is recorded, and `UNKNOWN` remains a result rather than a resting state. A real
un-dispositioned or `UNKNOWN`-intersecting residual would be a finding and a `fail`, not a verdict
the court talks itself out of.

The instrument sensitivity control
----------------------------------
Section 3.2's rule again: a control that cannot fail is not evidence. Beside the real derivation the
court derives three **synthetic evidence views** and requires the disposition to react to each: a
residual given **no disposition** must surface as an un-dispositioned finding, a residual recorded
`UNKNOWN` and flagged as **intersecting the profile** must surface as an `UNKNOWN`-intersecting
finding, and a residual recorded `UNKNOWN` but **not intersecting** must surface **no** finding. The
control is honest only when the real view is closed (zero findings) *and* all three injections behave
as required; otherwise a court that cannot tell a dispositioned residual from an absent one, or an
intersecting `UNKNOWN` from a harmless one, would pass vacuously.

`RT-SUBSTITUTION-WITNESS`, and what it witnesses
-----------------------------------------------
20.4's court. Its subject is the **substitution witness chain**: the ABI-substitution witnesses -- a
binary built against one library set that runs unmodified against the other -- and the
**machine-owned downstream corpus witness chain** of the Phase-17 corpus, the six unmodified
upstream programs built against the candidate distribution shell and exercised by the harness
`courts/phase17/downstream/run_all.sh`. `docs/PHASE-20-SUBPHASES.md` section 3.5 makes the witness a
machine-owned chain: the court records, per witness, **the binary it was built against, the run that
exercised it and the observation it produced**, so a witness that is not reproduced by the run is a
finding rather than a remembered result. It maintains no list of its own; it reads the artefacts the
earlier strata wrote:

  * the **Phase-2 ABI-substitution family** `artifacts/phase2/courts/ABI-SUBSTITUTION.json`,
    `ABI-LOAD.json` and `ABI-LINK.json`, cross-checked against the sealed registry
    `artifacts/phase2/COURTS.json`. `ABI-SUBSTITUTION` is the literal witness: one executable,
    compiled once against the admitted authority's headers and libraries, run against the authority
    and then run **unmodified** against the candidate install with `LD_LIBRARY_PATH` pointed at
    `artifacts/phase2/install/lib`; `ABI-LOAD` resolves the authority's declared symbol/version set
    in the candidate DSO with `dlvsym`; `ABI-LINK` is a consumer linked against the candidate
    distribution shell. The three are held apart rather than one standing in for the others.
  * the **Phase-17 machine-owned downstream corpus** `forensics/atlas/downstream-corpus.json`,
    aggregated from `courts/phase17/downstream/<program>/result.json` (curl, git, haproxy, nginx,
    openssh, python), which the court re-establishes as current and functional rather than assuming:
    for each program it re-derives the record's required fields, its `functional` verdict and its
    `candidate` identity against the current release `Cargo.toml` names, and re-checks that the
    aggregate entry still equals the per-program record. The six harnesses include multi-minute
    builds and live TLS servers and `courts/phase17/downstream/run_all.sh` has no cheap
    verify/currency mode -- it re-runs the programs -- so the court does **not** re-run them in the
    gate path: it re-derives currency and functional status from the machine-owned records and
    proves currency by candidate identity, and says exactly that in its `reestablishment` block.

**Honesty.** A witness is a `finding` when it is not functional, when its candidate identity is not
the current release, when its record is absent or has drifted from the aggregate, or when a required
field is missing. On the current tree every witness is current and functional, so the court records
**zero findings**; a stale or non-functional witness is a finding and a `fail`, not a verdict the
court talks itself out of. A passing `RT-SUBSTITUTION-WITNESS` is an instrument plus this re-derived
chain: it is not a re-run of the harnesses, and the three non-claims of section 0 still bound it.

The instrument sensitivity control
----------------------------------
Section 3.2's rule again: a control that cannot fail is not evidence. Beside the real derivation the
court derives three **synthetic evidence views** and requires the witness derivation to react to
each: a downstream witness whose `candidate` identity is moved off the current release must surface
as a stale finding, a downstream witness whose `functional` verdict is set `FAIL` must surface as a
non-functional finding, and an ABI-substitution witness whose verdict is set `fail` must surface as
a non-functional finding. The control is honest only when the real view is closed (every witness
current and functional) *and* all three injections are detected; otherwise a court that cannot tell
a current, functional witness from a stale or failed one would pass vacuously.

`CUSTODIAN-BOUNDARY-REGISTER`, and what it binds
-----------------------------------------------
20.5's court, and the stratum's own answer to `docs/NON_CLAIMS.md`. It stages no probe: its subject
is `artifacts/phase20/custodian-boundary-register.json`, the authored register that records, per
surface, whether it is **claimed** (a passing court covers it) or **bounded** (explicitly outside
this stratum -- including **no FIPS validation**, **no universal parity from finite evidence** and
**memory safety measured, not established**). The court re-reads both sides and fails the stratum if
a recorded boundary has drifted from the evidence that establishes it:

  * the **claimed side** is the four passing custodian courts' own records computed above it in this
    one run -- `RT-CUSTODIAN-MATURITY`, `RT-RECEIPT-CLOSURE`, `RT-CUSTODIAN-RESIDUALS` and
    `RT-SUBSTITUTION-WITNESS` -- so a claimed row whose court no longer passes, or no longer covers
    the surface its `surface_keys` name, is a finding; and
  * the **bounded side** is the constitution/limitations artefacts: `docs/NON_CLAIMS.md` (the
    no-universal-parity and scope rules), `docs/FIPS_CLAIMS.md` (the `NOT FIPS VALIDATED` label and
    the formal/external separation), `docs/UNSAFE.md` (unsafe measured, not asserted, and not a
    memory-safety claim), and the `forensics/atlas/unsafe-footprint.json` measurement against its
    `artifacts/phase18/unsafe-bounds.json` growth ceiling. A bounded row whose cited evidence no
    longer supports it -- a missing non-claim, a moved footprint or a moved ceiling -- is a finding.

The court is mechanical: each row names its `surface`, its `verdict` (`claimed`/`bounded`) and the
evidence that establishes it, and the court re-derives that evidence and compares it exactly. The
instrument-sensitivity control injects a claimed row whose court is not passing and a bounded row
whose cited evidence has drifted, and requires each to be detected; beside them a real view with no
defect yields **zero findings** (specificity), because a control that cannot fail is not evidence.
There is no claim stronger than `docs/CUSTODIAN_CONTRACT.md` section 6's anywhere in this stratum; a
passing court is an instrument and a bounded measurement, and the property it names may still carry
findings. `docs/NON_CLAIMS.md` is the authority on the explicit non-claims.

The runner reads no obligations ledger: the ledger's contract-unit states are measured from this
registry, so the edge runs ledger -> courts and binding it back would form a digest cycle neither
artefact could reproduce. `docs/PHASE-20-SUBPHASES.md` section 4.2 is the precondition. No court is
registered in `gen_frf_courts.py`: that registry is the stratum's seal.

SPDX-License-Identifier: Apache-2.0"""

from __future__ import annotations

import argparse
import collections
import copy
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    PRODUCTION_AUTHORITY,
    REPO_ROOT,
    SEAL_DOCS,
    InputRef,
    envelope,
    rel,
    resolve_authority,
    sha256_file,
    write_json,
)

# The FRF court registry, read as the set of *declared* courts and as the source of the candidate
# version. `phase_state.py` reads the same table for the same reason: the registry (D58) is what a
# generated declaration must satisfy, so the closure court checks the receipts against the same
# requirement the FRF chain rule does rather than a second, drifting one.
import gen_frf_courts  # noqa: E402

OUT = REPO_ROOT / "artifacts" / "phase20" / "COURTS.json"
GENERATOR = "forensics/tools/phase20_courts.py"
PLAN = REPO_ROOT / "docs" / "PHASE-20-SUBPHASES.md"

# The ladder's authority, and the machine-owned artefacts the distinctive levels rest on. Bound by
# the record rather than typed: RELEASE_GATES is where the level names come from, the downstream
# corpus is L8's machine-owned evidence, and the two census joins are what L4 and L5 measure.
LEVELS_DOC = REPO_ROOT / "docs" / "RELEASE_GATES.md"
PHASE1_COMPLETENESS = REPO_ROOT / "forensics" / "atlas" / "phase1-completeness.json"
PROVIDERS = REPO_ROOT / "forensics" / "atlas" / "provider-algorithms.json"
PROVIDER_COVERAGE = REPO_ROOT / "forensics" / "atlas" / "provider-court-coverage.json"
COURT_COVERAGE = REPO_ROOT / "forensics" / "atlas" / "court-coverage.json"
DOWNSTREAM = REPO_ROOT / "forensics" / "atlas" / "downstream-corpus.json"
PHASE2_COURTS = REPO_ROOT / "artifacts" / "phase2" / "COURTS.json"
PHASE17_COURTS = REPO_ROOT / "artifacts" / "phase17" / "COURTS.json"

# The FRF store and the registers the receipt closure joins. The obligations, the court-coverage
# join, the declarations, the receipts, the challenges and the claims are the artefacts that carry
# the join's two sides; none is a list this court maintains.
FRF_RECEIPTS = REPO_ROOT / ".frf" / "receipts"
FRF_CHALLENGES = REPO_ROOT / ".frf" / "challenges"
FRF_CLAIMS = REPO_ROOT / ".frf" / "claims"
FRF_DECLARATIONS = REPO_ROOT / "forensics" / "frf" / "courts"
COURT_COVERAGE_ROWS = REPO_ROOT / "forensics" / "atlas" / "court-coverage-rows.json"
GEMEL_TRAJECTORY = REPO_ROOT / "forensics" / "GEMEL_TRAJECTORY.md"
FRF_README = REPO_ROOT / "forensics" / "frf" / "README.md"
CUSTODIAN_CONTRACT = REPO_ROOT / "docs" / "CUSTODIAN_CONTRACT.md"
PARITY_MODEL = REPO_ROOT / "docs" / "PARITY_MODEL.md"
GEN_FRF_COURTS_SRC = REPO_ROOT / "forensics" / "tools" / "gen_frf_courts.py"

# The registers the residual disposition reads. The Phase-22 census carries the cross-plane
# residual rows and the closure carries the register's own computation of which `UNKNOWN` residual
# reaches a declared compatibility root; the checkpoint names the `UNKNOWN` sets. The Phase-1 and
# symbol reconciliations, the divergence/prerequisite planes, the two Phase-18/19 boundary registers
# and the Phase-18 hostile/CT/ASan/Miri receipts, the unsafe-footprint ceiling and the FRF store's
# own residuals are the other registers the earlier strata write. None is a list this court keeps.
PHASE22_RECONCILIATION = REPO_ROOT / "forensics" / "atlas" / "phase22" / "reconciliation.json"
PHASE22_CLOSURE = REPO_ROOT / "forensics" / "atlas" / "phase22" / "compatibility-closure.json"
PHASE22_GEMEL = REPO_ROOT / "forensics" / "atlas" / "phase22" / "gemel-checkpoint.json"
SURFACE_RECONCILIATION = (REPO_ROOT / "forensics" / "atlas" / "openssl-3.6.4-production"
                          / "surface-reconciliation.json")
DIVERGENCE_OBLIGATIONS = REPO_ROOT / "forensics" / "divergence-obligations.json"
PREREQUISITES = REPO_ROOT / "forensics" / "prerequisites.json"
HOSTILE_BOUNDARY_REGISTER = REPO_ROOT / "artifacts" / "phase18" / "hostile-boundary-register.json"
PERFORMANCE_BOUNDARY_REGISTER = (REPO_ROOT / "artifacts" / "phase19"
                                 / "performance-boundary-register.json")
# 20.5's authored register and the constitution/limitations artefacts it binds. The register is
# authored rather than derived; the court re-reads it and the artefacts it cites, so it is an input
# to the runner rather than an output of it.
CUSTODIAN_BOUNDARY_REGISTER = (REPO_ROOT / "artifacts" / "phase20"
                               / "custodian-boundary-register.json")
CUSTODIAN_BOUNDARY_REGISTER_SCHEMA = "openssl-rs/custodian-boundary-register/v1"
NON_CLAIMS_DOC = REPO_ROOT / "docs" / "NON_CLAIMS.md"
FIPS_CLAIMS_DOC = REPO_ROOT / "docs" / "FIPS_CLAIMS.md"
UNSAFE_DOC = REPO_ROOT / "docs" / "UNSAFE.md"
CUSTODIAN_SEAL_DOC = REPO_ROOT / "docs" / "PHASE-20-CUSTODIAN-SEAL.md"
PHASE18_COURTS = REPO_ROOT / "artifacts" / "phase18" / "COURTS.json"
ASAN_CLOSURE = REPO_ROOT / "artifacts" / "phase18" / "asan.json"
MIRI_TCB = REPO_ROOT / "artifacts" / "phase18" / "miri-tcb.json"
UNSAFE_FOOTPRINT = REPO_ROOT / "forensics" / "atlas" / "unsafe-footprint.json"
UNSAFE_BOUNDS = REPO_ROOT / "artifacts" / "phase18" / "unsafe-bounds.json"
FRF_RESIDUALS = REPO_ROOT / ".frf" / "residuals"

# The substitution witnesses. The Phase-2 ABI-substitution family carries the witnesses a binary
# built against one library set runs unmodified against the other; the Phase-17 machine-owned corpus
# carries the six unmodified upstream programs. None is a list this court keeps: both are read from
# the artefacts the earlier strata wrote. `CANDIDATE_INSTALL` is the candidate distribution shell the
# downstream programs are built against and the ABI-SUBSTITUTION probe is run against.
PHASE2_COURT_DIR = REPO_ROOT / "artifacts" / "phase2" / "courts"
DOWNSTREAM_DIR = REPO_ROOT / "courts" / "phase17" / "downstream"
DOWNSTREAM_RUNNER = DOWNSTREAM_DIR / "run_all.sh"
DOWNSTREAM_README = DOWNSTREAM_DIR / "README.md"
CANDIDATE_INSTALL = REPO_ROOT / "artifacts" / "phase2" / "install"

# The Phase-2 ABI-substitution family and what each witness was built against. `ABI-SUBSTITUTION`
# is compiled against the admitted authority and run unmodified against the candidate install;
# `ABI-LOAD` resolves the authority's declared symbol/version set in the candidate DSO; `ABI-LINK`
# is a consumer linked against the candidate distribution shell. `(court, built_against)`.
ABI_WITNESSES: tuple[tuple[str, str], ...] = (
    ("ABI-SUBSTITUTION", PRODUCTION_AUTHORITY),
    ("ABI-LOAD", PRODUCTION_AUTHORITY),
    ("ABI-LINK", "artifacts/phase2 (the candidate distribution shell)"),
)

# The six programs of the Phase-17 machine-owned corpus, and the fields `RT-DOWNSTREAM-CORPUS`
# requires each record to carry. The list is typed because a program dropped from the corpus must be
# a finding rather than a silent shrink of the witness set; the fields mirror
# `forensics/tools/phase17_courts.py`'s `DOWNSTREAM_REQUIRED_FIELDS`, which is the register's own
# requirement.
WITNESS_PROGRAMS: tuple[str, ...] = ("curl", "git", "haproxy", "nginx", "openssh", "python")
WITNESS_REQUIRED_FIELDS: tuple[str, ...] = (
    "program", "version", "source_url", "source_sha256", "candidate", "authority",
    "build", "link", "start", "functional", "concurrency", "known_residuals",
    "historical_failures",
)

# The two witness chains, named so a row can be read without joining its source.
ABI_CHAIN = "abi-substitution"
DOWNSTREAM_CHAIN = "downstream-corpus"

# The two axes every runtime court declares and challenges; the same pair the FRF chain rule reads.
FRF_CHALLENGE_OPERATORS = ("stdout-first-line", "exit-class")

# The strata whose Gemel checkpoints predate the phrase the checkpoint clause reads. Carried so the
# closure court's requirement is identical to `phase_state.py`'s (the alternative is a stratum the
# chain rule calls complete and the closure court calls incomplete, or vice versa).
FRF_CHAIN_CHECKPOINT_EXEMPT = frozenset({3, 4, 5, 6, 7})

# The strata whose receipt closure this court joins. Phase 20 is this stratum's own (its obligations
# are the contract units this very registry measures, so joining them would be circular) and Phase 22
# is an atlas stratum with no export courts, exactly as the FRF chain rule scopes both out.
CLOSURE_PHASES: tuple[int, ...] = tuple(range(3, 20))

CUSTODIAN_MATURITY = "RT-CUSTODIAN-MATURITY"
RECEIPT_CLOSURE = "RT-RECEIPT-CLOSURE"
CUSTODIAN_RESIDUALS = "RT-CUSTODIAN-RESIDUALS"
SUBSTITUTION_WITNESS = "RT-SUBSTITUTION-WITNESS"
BOUNDARY_REGISTER = "CUSTODIAN-BOUNDARY-REGISTER"

# The register's two verdicts. `claimed` needs a passing court that covers the surface; `bounded`
# is explicitly outside this stratum and names no court.
REGISTER_VERDICTS: tuple[str, ...] = ("claimed", "bounded")

# The courts, in the order they land. `(name, probe filename)`, and the probe is declared in the
# same commit as the entry, so a runner that names a probe which does not exist cannot be
# committed. `RT-CUSTODIAN-MATURITY`, `RT-RECEIPT-CLOSURE`, `RT-CUSTODIAN-RESIDUALS`,
# `RT-SUBSTITUTION-WITNESS` and `CUSTODIAN-BOUNDARY-REGISTER` stage no probe -- their subjects are
# committed evidence, not transcript pairs -- so their probes are `None`, exactly as Phase 19's
# register court is. **Complete at 20.5**: all five custodian courts are registered and passing.
COURTS: list[tuple[str, str | None]] = [
    (CUSTODIAN_MATURITY, None),
    (RECEIPT_CLOSURE, None),
    (CUSTODIAN_RESIDUALS, None),
    (SUBSTITUTION_WITNESS, None),
    (BOUNDARY_REGISTER, None),
]

# A court the plan names and this stratum cannot run yet. It is empty: `RT-CUSTODIAN-MATURITY` left
# this table when 20.1 landed its derivation, `RT-RECEIPT-CLOSURE` when 20.2 landed its join,
# `RT-CUSTODIAN-RESIDUALS` when 20.3 landed its disposition, `RT-SUBSTITUTION-WITNESS` when 20.4
# landed its witness chain, and `CUSTODIAN-BOUNDARY-REGISTER` when 20.5 landed its register.
PENDING_COURTS: dict[str, str] = {}

# The libraries the ladder is derived for. Both are built from the one crate the strata before this
# completed, so a level's evidence is a property of the distribution; each level records which
# library its subject concerns (`libcrypto`, `libssl`, or both) as `applies_to`.
LIBCRYPTO = "libcrypto"
LIBSSL = "libssl"
LIBRARIES: tuple[str, ...] = (LIBCRYPTO, LIBSSL)

# The level whose evidence this stratum is establishing. `RT-CUSTODIAN-MATURITY` records the gap to
# this level as a finding until 20.6's seal lands; it never names the level itself.
SEAL_TARGET = "L9"


@dataclass(frozen=True)
class Level:
    """One rung of `docs/RELEASE_GATES.md` section 3, bound to the evidence that establishes it.

    `strata` are the phases whose completion the level rests on; `courts` are the named court rows
    that must be present and passing in those strata's registries; `court_families` are the section
    4 taxonomy names the level's strata court, recorded for traceability; `artifacts` are the
    committed artefacts the level's distinctive evidence lives in. `registry` is false only for L0,
    whose archaeology stratum (Phase 1) published no differential court registry.
    """

    level: str
    requirement: str
    libraries: tuple[str, ...]
    strata: tuple[int, ...]
    courts: tuple[str, ...]
    court_families: tuple[str, ...]
    artifacts: tuple[str, ...] = ()
    registry: bool = True
    provider_census: bool = False
    provider_coverage: bool = False
    court_coverage: bool = False
    downstream_corpus: bool = False
    # The level is the stratum's own claim rather than prior evidence: its evidence is the
    # completion of this stratum and the seal it writes, so a court running inside the stratum
    # records the gap to it as a finding instead of reading it as committed evidence (L9).
    self_established: bool = False


# The ladder, in order. Each level's `requirement` is the section 3 name verbatim, and the evidence
# is the phase(s) and machine-owned artefact that establish it -- read from the tree at run time,
# never typed as present here.
LEVELS: tuple[Level, ...] = (
    Level("L0", "archaeology complete", LIBRARIES, (1,), (),
          ("API-HEADER",), ("forensics/atlas/phase1-completeness.json",), registry=False),
    Level("L1", "source / API shell", LIBRARIES, (2,),
          ("ABI-SYMBOL", "ABI-VERSION"),
          ("API-HEADER", "ABI-SYMBOL", "ABI-VERSION"),
          ("artifacts/phase2/COURTS.json",)),
    Level("L2", "ABI-load compatible", LIBRARIES, (2,),
          ("ABI-LOAD", "ABI-LINK", "ABI-LAYOUT", "ABI-DYNAMIC", "ABI-SUBSTITUTION"),
          ("ABI-LOAD", "ABI-LINK", "ABI-LAYOUT", "ABI-DYNAMIC", "ABI-SUBSTITUTION"),
          ("artifacts/phase2/COURTS.json",)),
    Level("L3", "libcrypto core semantic parity", (LIBCRYPTO,), (3, 4, 5),
          ("RT-MEM", "RT-ERR", "RT-BN", "RT-ASN1", "RT-PEM"),
          ("MEM-OWNERSHIP", "ERR-QUEUE", "THREAD-STATE", "BIO-STATE", "CONF", "OBJ-NID", "BN",
           "ASN1", "DER", "PEM")),
    Level("L4", "provider / EVP parity", (LIBCRYPTO,), (6, 7),
          ("RT-PROVIDER", "RT-FETCH", "RT-EVP-CIPHER", "RT-EVP-SKEY"),
          ("LIBCTX", "PROVIDER-LOAD", "PROVIDER-DISPATCH", "FETCH-PROPERTY", "EVP-DIGEST",
           "EVP-CIPHER", "EVP-MAC", "EVP-KDF", "EVP-RAND", "EVP-KEYMGMT", "EVP-SIGNATURE",
           "EVP-KEX", "EVP-KEM"),
          (),
          provider_census=True, provider_coverage=True),
    Level("L5", "complete libcrypto claimed surface", (LIBCRYPTO,), (8, 9, 10, 11, 12, 13, 22),
          ("RT-DIGEST", "RT-CIPHER", "RT-RSA", "RT-DRBG", "RT-X509", "RT-CMS", "RT-OCSP", "RT-CMP",
           "RT-STORE"),
          ("X509", "X509-PATH", "PKCS", "CMS", "OCSP", "CMP", "STORE", "ENCODER", "DECODER"),
          ("forensics/atlas/provider-algorithms.json", "forensics/atlas/court-coverage.json"),
          provider_census=True, provider_coverage=True, court_coverage=True),
    Level("L6", "libssl protocol parity", (LIBSSL,), (14, 15),
          ("RT-SSL-OBJECT", "RT-DTLS", "RT-QUIC"),
          ("SSL-STATE", "SSL-WIRE", "SSL-CALLBACK", "DTLS", "QUIC")),
    Level("L7", "CLI / distribution parity", LIBRARIES, (16,),
          ("RT-CLI", "RT-CONFIG"),
          ("CONFIG", "CLI", "BUILD-MATRIX")),
    Level("L8", "downstream custodian court", LIBRARIES, (17,),
          ("RT-DOWNSTREAM-CORPUS", "RT-DOWNSTREAM-CONSUMER"),
          ("DOWNSTREAM",),
          ("artifacts/phase17/COURTS.json", "forensics/atlas/downstream-corpus.json"),
          downstream_corpus=True),
    Level("L9", "high-assurance custodian seal", LIBRARIES, (18, 19, 20), (), (),
          ("docs/PHASE-20-CUSTODIAN-SEAL.md",), self_established=True),
)

LEVEL_BY_NAME: dict[str, Level] = {lv.level: lv for lv in LEVELS}


# --------------------------------------------------------------------------------------------
# reading the evidence
# --------------------------------------------------------------------------------------------

def read_json(relpath: str) -> dict | None:
    """Read a committed JSON artefact, or `None` when it is absent.

    Absence is a fact about the tree -- an un-laddered level -- rather than a fatal read error:
    a missing artefact makes its level absent, which the derivation records, rather than aborting
    the court.
    """
    p = REPO_ROOT / relpath
    if not p.is_file():
        return None
    return json.loads(p.read_text(encoding="utf-8"))


def read_phase_states() -> dict[int, str]:
    """The derived stratum states, as `phase_state.py` writes them. `{}` when the file is absent."""
    doc = read_json("forensics/phase-state.json")
    if not doc:
        return {}
    return {int(r["phase"]): str(r["state"]) for r in doc["body"]["phases"]}


def read_courts(phase: int) -> dict[str, str] | None:
    """A stratum's court registry as `{court: verdict}`, or `None` when no registry exists."""
    doc = read_json(f"artifacts/phase{phase}/COURTS.json")
    if not doc:
        return None
    return {str(c["court"]): str(c["verdict"]) for c in doc["body"].get("courts", [])}


def read_provider_counts() -> tuple[int, int]:
    """`(rows, unimplemented)` over the provider census."""
    doc = read_json("forensics/atlas/provider-algorithms.json")
    if not doc:
        return 0, 0
    rows = doc["body"].get("rows", [])
    unimplemented = sum(1 for r in rows if r.get("implementation_state") != "implemented")
    return len(rows), unimplemented


def read_provider_unmatched() -> int:
    doc = read_json("forensics/atlas/provider-court-coverage.json")
    if not doc:
        return -1
    return int(doc["body"].get("unmatched", -1))


def read_court_unmatched() -> int:
    """Implemented exports named by no court, from the export court-coverage join.

    Returns `-1` when the atlas is absent, so a missing join is a failed check rather than a
    vacuous zero.
    """
    doc = read_json("forensics/atlas/court-coverage.json")
    if not doc:
        return -1
    totals = doc["body"].get("totals", {})
    implemented = int(totals.get("implemented", 0))
    covered = int(totals.get("directly_courted", 0)) + int(totals.get("indirectly_courted", 0))
    return implemented - covered


def read_downstream_bad() -> int:
    """Programs in the Phase-17 corpus that are not fully current and functional.

    A program is good only when it links and starts, its functional check passes and its
    concurrency check is complete -- the same facts `RT-DOWNSTREAM-CORPUS` records.
    """
    doc = read_json("forensics/atlas/downstream-corpus.json")
    if not doc:
        return -1
    bad = 0
    for prog in doc.get("programs", []):
        link = (prog.get("link") or {}).get("ok")
        build = (prog.get("build") or {}).get("ok")
        functional = (prog.get("functional") or {}).get("ok")
        conc = prog.get("concurrency") or {}
        conc_ok = conc.get("ok") == conc.get("total")
        if not (link and build and functional and conc_ok):
            bad += 1
    return bad


def read_evidence() -> dict:
    """The committed evidence view the ladder is derived from.

    A plain dict so the sensitivity control can deep-copy it and inject a missing prerequisite
    without touching the tree. Every value is read from an artefact, none is typed as present.
    """
    courts = {str(p): read_courts(p) for p in range(2, 23)}
    provider_rows, provider_unimplemented = read_provider_counts()
    # Every artefact a level names, plus the ones the derivation reads directly, so a level's
    # artefact check reads the same tree the rest of the court does.
    artifact_paths = sorted(
        {a for lv in LEVELS for a in lv.artifacts}
        | {
            "forensics/atlas/phase1-completeness.json",
            "artifacts/phase2/COURTS.json",
            "artifacts/phase17/COURTS.json",
            "forensics/atlas/downstream-corpus.json",
            "docs/PHASE-20-CUSTODIAN-SEAL.md",
        }
    )
    return {
        "strata": {str(p): s for p, s in read_phase_states().items()},
        "seals": {str(p): (REPO_ROOT / d).is_file() for p, d in SEAL_DOCS.items()},
        "courts": courts,
        "artifacts": {a: (REPO_ROOT / a).is_file() for a in artifact_paths},
        "provider_rows": provider_rows,
        "provider_unimplemented": provider_unimplemented,
        "provider_unmatched": read_provider_unmatched(),
        "court_unmatched": read_court_unmatched(),
        "downstream_bad": read_downstream_bad(),
    }


def court_table(ev: dict) -> dict[str, str]:
    """Every court row the evidence view carries, flattened, for the required-court checks."""
    table: dict[str, str] = {}
    for rows in (ev.get("courts") or {}).values():
        table.update(rows or {})
    return table


def level_sources(lv: Level) -> list[str]:
    """The committed artefacts that establish one level, for the per-level `source_artifacts`."""
    out = ["forensics/phase-state.json"]
    for p in lv.strata:
        if p in SEAL_DOCS:
            out.append(SEAL_DOCS[p])
        if lv.registry and p != 20:
            out.append(f"artifacts/phase{p}/COURTS.json")
    out += list(lv.artifacts)
    if lv.provider_census:
        out.append("forensics/atlas/provider-algorithms.json")
    if lv.provider_coverage:
        out.append("forensics/atlas/provider-court-coverage.json")
    if lv.court_coverage:
        out.append("forensics/atlas/court-coverage.json")
    return sorted(set(out))


def level_own_present(lv: Level, ev: dict) -> tuple[bool, list[str]]:
    """Whether one level's own evidence is present, and every reason it is not.

    A level's own evidence is present when every stratum it rests on has sealed and so is
    `complete`, every named court row is present and passing, every named artefact exists, and the
    census joins the level leans on are clean. Read from the evidence view, never from a table of
    expected booleans.
    """
    missing: list[str] = []
    if lv.self_established:
        # The seal target is the stratum's own claim, not prior evidence. Its evidence -- the
        # completion of stratum 20 and the seal document the stratum writes -- is the seal the
        # instrument belongs to, so reading it as committed evidence here would make the court's
        # own pass its precondition. The instrument records the gap to this level as the finding
        # instead of deriving the level present (docs/PHASE-20-SUBPHASES.md sections 1, 3.2 and
        # 3.3; `SEAL_GAP_UNITS` in forensics/tools/phase20_obligations.py is the same rule).
        missing.append(
            f"{lv.level} is this stratum's own claim rather than prior evidence the instrument "
            f"can certify; its evidence -- the completion of stratum 20 and "
            f"{rel(CUSTODIAN_SEAL_DOC)} -- is the seal this instrument belongs to"
        )
        return False, missing
    for p in lv.strata:
        state = (ev.get("strata") or {}).get(str(p))
        if state != "complete":
            missing.append(f"stratum {p} is {state!r}, not `complete`")
            continue
        if p == 20:
            # The custodian seal is this stratum's own output: its evidence is the seal document,
            # named in the level's artefacts, not a registry this run is writing.
            continue
        if not (ev.get("seals") or {}).get(str(p)):
            missing.append(f"stratum {p} is `complete` but its seal {SEAL_DOCS.get(p)} is absent")
        registry = (ev.get("courts") or {}).get(str(p))
        if lv.registry and not registry:
            missing.append(f"stratum {p} is `complete` but has no court registry")
        elif registry and any(v != "pass" for v in registry.values()):
            failed = sorted(c for c, v in registry.items() if v != "pass")
            missing.append(f"stratum {p} has non-passing court(s): {failed}")
    table = court_table(ev)
    for c in lv.courts:
        verdict = table.get(c)
        if verdict != "pass":
            missing.append(f"court {c} is {verdict!r}, not `pass`")
    for a in lv.artifacts:
        if not (ev.get("artifacts") or {}).get(a):
            missing.append(f"artefact {a} is absent")
    if lv.provider_census and ev.get("provider_unimplemented"):
        missing.append(f"{ev['provider_unimplemented']} provider registration row(s) unimplemented")
    if lv.provider_coverage and ev.get("provider_unmatched") != 0:
        missing.append(
            f"the provider-row coverage join has {ev.get('provider_unmatched')} unmatched row(s)")
    if lv.court_coverage and ev.get("court_unmatched") != 0:
        missing.append(
            f"the export court-coverage join has {ev.get('court_unmatched')} unmatched export(s)")
    if lv.downstream_corpus and ev.get("downstream_bad") != 0:
        missing.append(f"{ev.get('downstream_bad')} downstream corpus program(s) are not current")
    return (not missing), missing


def derive_ladder(ev: dict) -> tuple[dict[str, dict], str | None]:
    """The cumulative ladder over an evidence view: per level, its own and cumulative presence.

    `evidence_present` is cumulative -- a level is present only when its own evidence and every
    level below it are -- so a missing prerequisite at any rung makes every rung above it absent.
    Returns the per-level rows and the highest level whose cumulative evidence is present.
    """
    rows: dict[str, dict] = {}
    previous = True
    for lv in LEVELS:
        own, missing = level_own_present(lv, ev)
        cumulative = own and previous
        previous = cumulative
        rows[lv.level] = {
            "level": lv.level,
            "requirement": lv.requirement,
            "courts": list(lv.courts),
            "court_families": list(lv.court_families),
            "own_evidence_present": own,
            "evidence_present": cumulative,
            "missing": missing,
            "source_artifacts": level_sources(lv),
        }
    present = [lv.level for lv in LEVELS if rows[lv.level]["evidence_present"]]
    highest = max(present, key=lambda s: int(s[1:])) if present else None
    return rows, highest


def per_library(ev: dict, rows: dict[str, dict]) -> dict[str, dict]:
    """The ladder projected per library, plus each library's highest present level.

    `applies_to` records whether a level's subject concerns the library; a level that does not
    apply is not part of that library's chain, so the highest present level is taken over the
    applicable levels. `evidence_present` is the same global derivation for both, because the
    evidence is a property of the one distribution both libraries are built from.
    """
    out: dict[str, dict] = {}
    for lib in LIBRARIES:
        levels = []
        highest: str | None = None
        for lv in LEVELS:
            row = rows[lv.level]
            applies = lib in lv.libraries
            levels.append({
                "level": lv.level,
                "requirement": lv.requirement,
                "applies_to": applies,
                "evidence_present": row["evidence_present"],
                "source_artifacts": row["source_artifacts"],
            })
            if applies and row["evidence_present"]:
                highest = lv.level
        out[lib] = {
            "highest_present": highest,
            "levels": levels,
        }
    return out


def sensitivity_control(ev: dict) -> dict:
    """Prove the derivation can fail: inject a missing prerequisite and require the gap.

    Section 3.2's rule, mechanically. Two synthetic views are derived beside the real one -- a
    mid-stratum (`5`, a prerequisite of L3) made incomplete, which must collapse the ladder to L2,
    and the downstream stratum (`17`, L8's own) made incomplete, which must leave L7 but drop L8
    and L9. The control is honest only when the real view reaches L8 with L9 absent *and* both
    injections detect their gap; otherwise a ladder that cannot tell evidence from its absence
    would pass vacuously.
    """
    base_rows, base_highest = derive_ladder(ev)

    core = copy.deepcopy(ev)
    (core.get("strata") or {})["5"] = "in-progress"
    core_rows, core_highest = derive_ladder(core)

    downstream = copy.deepcopy(ev)
    (downstream.get("strata") or {})["17"] = "in-progress"
    down_rows, down_highest = derive_ladder(downstream)

    base_l9 = base_rows["L9"]["evidence_present"]
    baseline = (base_highest == "L8") and not base_l9
    core_caught = (
        not core_rows["L3"]["evidence_present"]
        and not core_rows["L8"]["evidence_present"]
        and core_highest == "L2"
    )
    downstream_caught = (
        down_rows["L7"]["evidence_present"]
        and not down_rows["L8"]["evidence_present"]
        and not down_rows["L9"]["evidence_present"]
        and down_highest == "L7"
    )
    return {
        "baseline_highest": base_highest,
        "baseline_l9_present": base_l9,
        "injected_core_stratum": 5,
        "injected_core_highest": core_highest,
        "injected_core_l3_present": core_rows["L3"]["evidence_present"],
        "injected_downstream_stratum": 17,
        "injected_downstream_highest": down_highest,
        "injected_downstream_l8_present": down_rows["L8"]["evidence_present"],
        "baseline_holds": baseline,
        "caught_mid_stratum": core_caught,
        "caught_downstream": downstream_caught,
        "honest": bool(baseline and core_caught and downstream_caught),
    }


def consistency_problems(ev: dict) -> list[str]:
    """Strata whose derived state disagrees with their own seal or court registry.

    `phase-state.json` is a cross-check, not a dependency: a stratum it calls `complete` must have
    a seal and a passing registry, and a stratum it calls not-`complete` must not have both, or the
    state and the evidence that establishes it disagree.
    """
    problems: list[str] = []
    seen: set[int] = set()
    registry_required = {p for lv in LEVELS if lv.registry for p in lv.strata}
    for lv in LEVELS:
        for p in lv.strata:
            if p == 20 or p in seen:
                continue
            seen.add(p)
            state = (ev.get("strata") or {}).get(str(p))
            sealed = bool((ev.get("seals") or {}).get(str(p)))
            registry = (ev.get("courts") or {}).get(str(p))
            passing = bool(registry) and all(v == "pass" for v in registry.values())
            complete = sealed and (passing if p in registry_required else True)
            if state == "complete" and not complete:
                problems.append(
                    f"stratum {p} is `complete` but seal present={sealed}, registry passing="
                    f"{passing}")
    return problems


# --------------------------------------------------------------------------------------------
# the court
# --------------------------------------------------------------------------------------------

def custodian_maturity_court(name: str) -> dict:
    """`RT-CUSTODIAN-MATURITY`: derive the L0-L9 ladder from committed evidence.

    Stages no probe. It reads the strata's seals and court registries, the provider census and its
    coverage join, the export court-coverage join and the Phase-17 downstream corpus, derives the
    cumulative ladder for `libcrypto` and `libssl`, and records the highest level the committed
    evidence establishes. The verdict is `pass` when the derivation is complete for both libraries,
    the control is honest, and any gap between the highest present level and the seal's target is
    recorded as a finding -- **not** when the ladder reaches L9. A level whose evidence is absent is
    never named as reached; the seal may not name it.
    """
    ev = read_evidence()
    rows, highest = derive_ladder(ev)
    libraries = per_library(ev, rows)
    control = sensitivity_control(ev)

    problems = consistency_problems(ev)

    # A ladder that names a level without its evidence is `fail`: every level recorded present must
    # have every source it cites present, and the cumulative chain must be monotone.
    for lv in LEVELS:
        row = rows[lv.level]
        if row["evidence_present"] and row["missing"]:
            problems.append(
                f"{lv.level} is recorded present but its evidence is not: {row['missing']}")
    seen_absent = False
    for lv in LEVELS:
        present = rows[lv.level]["evidence_present"]
        if not present:
            seen_absent = True
        elif seen_absent:
            problems.append(
                f"{lv.level} is present below an absent level, so the ladder is not cumulative")

    for lib, block in libraries.items():
        if block["highest_present"] is None:
            problems.append(f"{lib} reaches no level, so the derivation establishes nothing")
        for row in block["levels"]:
            if row["applies_to"] and row["evidence_present"] and row["level"] > (
                    block["highest_present"] or "L0"):
                problems.append(
                    f"{lib} records {row['level']} present above its highest "
                    f"{block['highest_present']}")

    # The finding is the gap between the highest level the evidence establishes and the level the
    # seal names. On the current tree that is L9, the level this stratum is establishing.
    findings: list[str] = []
    if highest != SEAL_TARGET:
        gap = rows[SEAL_TARGET]["missing"]
        findings.append(
            f"the committed evidence establishes {highest} for {' and '.join(LIBRARIES)}, not the "
            f"{SEAL_TARGET} {LEVEL_BY_NAME[SEAL_TARGET].requirement} the seal names: "
            + "; ".join(gap)
            + ". L9 is the level Phase 20 itself is establishing (docs/PHASE-20-SUBPHASES.md "
              "section 4.2); a passing RT-CUSTODIAN-MATURITY is an instrument plus this "
              "derivation and must never be read as 'L9 custodian seal achieved'."
        )

    verdict = "pass" if (not problems and control["honest"] and findings) else "fail"
    return {
        "court": name,
        "probe": "",
        "method": (
            "stages no probe: it derives the L0-L9 maturity ladder of docs/RELEASE_GATES.md "
            "sections 3 and 4 for libcrypto and libssl from committed evidence -- each stratum's "
            "seal and court registry, the provider census and its coverage join, the export "
            "court-coverage join and the Phase-17 downstream corpus -- and records the highest "
            "level whose cumulative evidence is present. It reads forensics/phase-state.json as a "
            "cross-check rather than a dependency, because it is downstream of this court "
            "(docs/PHASE-20-SUBPHASES.md section 4.2): binding it would close the ledger -> courts "
            "-> ledger digest cycle. A level whose evidence is absent is never named as reached. "
            "The court is pass when the derivation is complete for both libraries, a synthetic "
            "evidence view with a prerequisite removed detects the gap (section 3.2), and the gap "
            "to the seal's target is recorded as a finding -- not when the ladder reaches L9."
        ),
        "frf_declarable": False,
        "frf_exclusion": (
            "the maturity court reads committed evidence artefacts and stages no "
            "artifacts/phase20/probes/ pair, so it takes no transcript to diff and carries no FRF "
            "declaration"
        ),
        "ladder_authority": rel(LEVELS_DOC),
        "seal_target_level": SEAL_TARGET,
        "highest_present": highest,
        "evidence_sources": sorted({
            "docs/RELEASE_GATES.md",
            "forensics/phase-state.json",
            "forensics/atlas/provider-algorithms.json",
            "forensics/atlas/provider-court-coverage.json",
            "forensics/atlas/court-coverage.json",
            "forensics/atlas/downstream-corpus.json",
            *[d for p, d in SEAL_DOCS.items() if any(p in lv.strata for lv in LEVELS)],
            *[f"artifacts/phase{p}/COURTS.json" for p in range(2, 20)],
            "artifacts/phase22/COURTS.json",
        }),
        "strata": (ev.get("strata") or {}),
        "libraries": libraries,
        "findings": findings,
        "control": control,
        "problems": problems,
        "verdict": verdict,
    }


# --------------------------------------------------------------------------------------------
# the receipt closure: reading the FRF chain, and joining the obligations to it
# --------------------------------------------------------------------------------------------

def read_reference_probes() -> frozenset[str]:
    """The authored reference-basis probe names, from the court-coverage rows.

    A court named here contributes evidence by taking an address and printing whether it is non-NULL
    rather than by diffing a transcript (D199), so it is the one class of court the FRF chain does
    not require a receipt for. The set is authored data, not a name convention, so the closure court
    reads it rather than guessing.
    """
    doc = read_json("forensics/atlas/court-coverage-rows.json")
    if not doc:
        return frozenset()
    return frozenset(str(x) for x in (doc.get("reference_probes") or []))


def read_obligations() -> dict[str, dict]:
    """Every in-scope stratum's implemented obligation set, from its own ledger.

    A ledger whose unit is not an export -- Phases 16 through 19 -- records its obligations as
    `contract_units` with their state; an export stratum records them as its `implemented` list.
    Phase 20 is this stratum's own (its obligations are the contract units this registry measures,
    so joining them would be circular) and Phase 22 is an atlas stratum; both are out of scope,
    exactly as the FRF chain rule scopes them out.
    """
    out: dict[str, dict] = {}
    for p in sorted(REPO_ROOT.glob("forensics/phase*-obligations.json")):
        m = re.fullmatch(r"phase(\d+)-obligations\.json", p.name)
        if not m:
            continue
        phase = int(m.group(1))
        if phase not in CLOSURE_PHASES:
            continue
        try:
            body = (json.loads(p.read_text(encoding="utf-8")) or {}).get("body") or {}
        except (OSError, json.JSONDecodeError):
            continue
        units = body.get("contract_units") or []
        if units:
            impl = [str(u.get("unit")) for u in units if u.get("state") == "implemented"]
            unit = str(body.get("unit")) if body.get("unit") is not None else None
        else:
            impl = [str(s) for s in (body.get("implemented") or [])]
            unit = None
        out[str(phase)] = {
            "unit": unit,
            "implemented": impl,
            "closed": bool(body.get("complete")),
        }
    return out


def read_symbol_courts() -> dict[str, dict[str, list[str]]]:
    """Each implemented export's courts, from the export court-coverage join.

    A `directly_courted` entry carries its courts in `courts`; an `indirectly_courted` or
    `non_observable` entry names one court in `court`. Both are the atlas's statement of which court
    observes the symbol, so the join uses the atlas rather than a table of its own.
    """
    doc = read_json("forensics/atlas/court-coverage.json")
    if not doc:
        return {}
    out: dict[str, dict[str, list[str]]] = {}
    for s in doc["body"].get("strata", []):
        cov: dict[str, list[str]] = {}
        for e in s.get("directly_courted", []):
            cov.setdefault(str(e.get("symbol")), []).extend(str(c) for c in e.get("courts", []))
        for e in s.get("indirectly_courted", []):
            if e.get("court"):
                cov.setdefault(str(e.get("symbol")), []).append(str(e["court"]))
        for e in s.get("non_observable", []):
            if e.get("court"):
                cov.setdefault(str(e.get("symbol")), []).append(str(e["court"]))
        out[str(s.get("phase"))] = cov
    return out


def read_frf_receipts() -> dict[str, list[str]]:
    """Every receipt in the FRF store, keyed by the court id each names.

    Read through each receipt's own `court.id`, so the closure court maintains no list of receipts:
    the store is the record. Each value is a list of receipt ids (a receipt's file stem is its own
    id, which is what a compiled claim's `requires` names).
    """
    out: dict[str, list[str]] = {}
    if not FRF_RECEIPTS.is_dir():
        return out
    for p in sorted(FRF_RECEIPTS.glob("*.json")):
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        cid = (doc.get("court") or {}).get("id")
        if cid:
            out.setdefault(str(cid), []).append(p.stem)
    return out


def read_frf_challenges() -> dict[str, list[dict]]:
    """Every challenge record in the FRF store, keyed by the court id each names."""
    out: dict[str, list[dict]] = {}
    if not FRF_CHALLENGES.is_dir():
        return out
    for p in sorted(FRF_CHALLENGES.glob("*.json")):
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        cid = doc.get("court")
        if cid:
            out.setdefault(str(cid), []).append(doc)
    return out


def read_frf_claims() -> dict[str, dict]:
    """Every compiled claim in the FRF store, keyed by its own id."""
    out: dict[str, dict] = {}
    if not FRF_CLAIMS.is_dir():
        return out
    for p in sorted(FRF_CLAIMS.glob("*.json")):
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        cid = doc.get("id")
        if cid:
            out[str(cid)] = doc
    return out


def read_frf_declarations() -> set[str]:
    """The court ids that have a generated declaration manifest in the registry directory."""
    if not FRF_DECLARATIONS.is_dir():
        return set()
    return {p.name for p in FRF_DECLARATIONS.iterdir() if (p / "manifest.yaml").is_file()}


def declared_candidate(court: str) -> tuple[str | None, str | None]:
    """`(version_or_commit, artifact_sha256)` the declaration for `court` binds.

    The parser mirrors `phase_state.py`'s, so the closure court's identity clause reads the same fact
    the FRF chain rule conditions on: a compiled claim records its candidate as `version_or_commit`
    plus `identity_hash`, and `identity_hash` is the hash of the candidate reference object the
    declaration names. `(None, None)` when either is absent, so the clause cannot manufacture a
    match it did not measure.
    """
    path = FRF_DECLARATIONS / court / "manifest.yaml"
    if not path.is_file():
        return None, None
    version = cpath = None
    in_candidate = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if re.match(r"^  candidate:\s*$", line):
            in_candidate = True
            continue
        if not in_candidate:
            continue
        m = re.match(r'^    version_or_commit:\s*"?([^"]+?)"?\s*$', line)
        if m:
            version = m.group(1)
            continue
        m = re.match(r"^    path:\s*(\S+)\s*$", line)
        if m:
            cpath = m.group(1)
            continue
        if line and not line.startswith("    "):
            in_candidate = False
    artifact = None
    if cpath:
        ref = REPO_ROOT / cpath
        if ref.is_file():
            artifact = sha256_file(ref)
    return version, artifact


def read_gemel_checkpoints() -> list[list[str]]:
    """`[name, summary]` for every checkpoint in the Git-tracked projection.

    The same shape `phase_state.py` reads, so the checkpoint clause is identical to the FRF chain
    rule's rather than a second phrasing of it.
    """
    if not GEMEL_TRAJECTORY.exists():
        return []
    out: list[list[str]] = []
    for line in GEMEL_TRAJECTORY.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^\* `(K\d+)` — `checkpoint\.[0-9a-f]+`$", line)
        if m:
            out.append([m.group(1), ""])
        elif out and line.startswith("  - "):
            name, summary = out[-1]
            out[-1] = [name, f"{summary} {line[4:]}".strip()]
    return out


def read_required_courts(phase: int, reference_probes: frozenset[str]) -> list[str]:
    """The FRF-declarable courts `artifacts/phase<N>/COURTS.json` records, by FRF court id.

    The classification is `phase_state.py`'s: a row's own `frf_declarable` is authoritative when the
    runner emitted it, and otherwise an authored reference-basis probe or a `CT-` court is not
    declarable. Keeping the rule identical is the point -- a court the chain rule requires a receipt
    for is a court this join requires one for.
    """
    doc = read_json(f"artifacts/phase{phase}/COURTS.json")
    if not doc:
        return []
    out: list[str] = []
    for row in doc["body"].get("courts", []):
        name = str(row.get("court"))
        declarable = row.get("frf_declarable")
        if declarable is None:
            declarable = name not in reference_probes and not name.startswith("CT-")
        if declarable:
            out.append("openssl-rs-" + name.lower())
    return out


def read_closure_evidence() -> dict:
    """The committed evidence view the receipt closure is derived from.

    A plain dict so the sensitivity control can deep-copy it and remove a premise without touching
    the tree. Every value is read from an artefact -- the ledgers, the court-coverage join, the FRF
    declarations, receipts, challenges and claims, and the Gemel projection -- and none is typed as
    present.
    """
    refs = read_reference_probes()
    required = {str(p): read_required_courts(p, refs) for p in CLOSURE_PHASES}
    declared: dict[str, list[str]] = {}
    for name, phase, _probe, _desc in gen_frf_courts.COURTS:
        declared.setdefault(str(phase), []).append("openssl-rs-" + name)
    candidates: dict[str, list] = {}
    for court in sorted({c for cs in required.values() for c in cs}):
        version, artifact = declared_candidate(court)
        candidates[court] = [version, artifact]
    return {
        "candidate_version": gen_frf_courts.CANDIDATE_VERSION,
        "obligations": read_obligations(),
        "symbol_courts": read_symbol_courts(),
        "required_courts": required,
        "declared_courts": declared,
        "declarations": read_frf_declarations(),
        "receipts": read_frf_receipts(),
        "challenges": read_frf_challenges(),
        "claims": read_frf_claims(),
        "declared_candidates": candidates,
        "reference_probes": refs,
        "checkpoints": read_gemel_checkpoints(),
        "checkpoint_exempt": sorted(FRF_CHAIN_CHECKPOINT_EXEMPT),
    }


def court_join(ev: dict, phase: str, symbol: str) -> str:
    """How one implemented export joins: `receipt`, `reference`, or `no_court`.

    `receipt` when a court the atlas names for the symbol has a receipt in the store; `reference`
    when none does but a named court is an authored reference-basis probe (its evidence is the
    address-taking probe, D199); `no_court` otherwise -- a gap rather than a weaker verdict.
    """
    courts = (ev["symbol_courts"].get(phase) or {}).get(symbol)
    if not courts:
        return "no_court"
    ids = ["openssl-rs-" + c.lower() for c in courts]
    if any(ev["receipts"].get(i) for i in ids):
        return "receipt"
    if any(c in ev["reference_probes"] for c in courts):
        return "reference"
    return "no_court"


def covering_claims(ev: dict, required: list[str],
                    receipts_for: dict[str, list[str]]) -> list[dict]:
    """Every `sensitivity-backed` claim whose `requires` cover a receipt of each required court."""
    if not required:
        return []
    out: list[dict] = []
    for cl in ev["claims"].values():
        if cl.get("policy") != "sensitivity-backed":
            continue
        reqs = set(cl.get("requires") or ())
        if all(set(receipts_for.get(c) or []) & reqs for c in required):
            out.append(cl)
    return out


def derive_closure(ev: dict) -> dict:
    """The join over an evidence view: per stratum, whether its obligations close to receipts.

    A pure function of the evidence view, so the sensitivity control can inject a missing premise and
    re-derive. Returns the per-stratum rows, the totals and the findings -- the findings are the
    closure's gaps, and a non-empty list is a `fail`, not a verdict the court talks itself out of.
    """
    rows: list[dict] = []
    findings: list[str] = []
    totals = {
        "strata": 0, "strata_joined": 0,
        "export_obligations": 0, "contract_obligations": 0, "obligations": 0,
        "obligations_joined": 0,
        "obligations_to_receipt": 0, "obligations_to_reference_basis": 0,
        "obligations_to_no_court": 0,
        "receipts": 0, "blockers": 0, "store_blockers": 0, "gaps": 0,
    }
    current_version = ev.get("candidate_version")
    for phase in sorted(ev["obligations"], key=int):
        ob = ev["obligations"][phase]
        required = list(ev["required_courts"].get(phase) or [])
        declared = set(ev["declared_courts"].get(phase) or [])
        missing: list[str] = []
        receipts_for: dict[str, list[str]] = {}
        for c in required:
            if c not in declared:
                missing.append(
                    f"court {c} is FRF-declarable but the registry declares no row for it")
            if c not in ev["declarations"]:
                missing.append(f"court {c} has no FRF declaration manifest")
            rids = list(ev["receipts"].get(c) or [])
            if not rids:
                missing.append(f"court {c} has no receipt in the FRF store")
            receipts_for[c] = rids
        for c in required:
            adjudicated = [
                ch for ch in ev["challenges"].get(c, [])
                if ch.get("saw_defect") and ch.get("specificity_clean")
            ]
            operators = {ch.get("operator") for ch in adjudicated}
            if len(adjudicated) < 2 or not set(FRF_CHALLENGE_OPERATORS).issubset(operators):
                missing.append(
                    f"court {c} lacks two adjudicated challenges over "
                    f"{list(FRF_CHALLENGE_OPERATORS)}")
        claims = covering_claims(ev, required, receipts_for)
        blockers = sum(len(cl.get("blockers") or []) for cl in claims)
        current_artifact = None
        if required:
            current_artifact = (ev["declared_candidates"].get(required[0]) or [None, None])[1]
        covering_id = None
        if required and not claims:
            missing.append(
                f"no `sensitivity-backed` claim covers a receipt of every one of the "
                f"{len(required)} required court(s)")
        else:
            for cl in claims:
                if cl.get("blockers"):
                    missing.append(
                        f"claim {cl.get('id')} carries {len(cl['blockers'])} blocker(s)")
            current = []
            for cl in claims:
                if cl.get("blockers"):
                    continue
                cand = cl.get("candidate") or {}
                if cand.get("version_or_commit") != current_version:
                    continue
                recorded = cand.get("identity_hash")
                if current_artifact is not None and recorded is not None \
                        and recorded != current_artifact:
                    continue
                current.append(cl)
            covering_id = current[0].get("id") if current else None
            if not current:
                missing.append(
                    f"no zero-blocker `sensitivity-backed` claim records the current candidate "
                    f"identity (version_or_commit={current_version!r})")
        if int(phase) not in ev["checkpoint_exempt"] and not any(
                f"Phase {phase}" in s and "FRF chain" in s for _n, s in ev["checkpoints"]):
            missing.append(f"no Gemel checkpoint names Phase {phase} and the FRF chain")

        joined = not missing
        # The per-obligation join. An export joins through the court-coverage edge; a contract unit
        # joins through its stratum's chain, which is the only court evidence it has.
        if ob.get("unit") is None:
            classes = [court_join(ev, phase, s) for s in ob["implemented"]]
            receipt_n = classes.count("receipt")
            reference_n = classes.count("reference")
            nocourt_n = classes.count("no_court")
            if joined:
                for s, k in zip(ob["implemented"], classes):
                    if k == "no_court":
                        findings.append(
                            f"phase {phase}: implemented obligation `{s}` is courted by no court "
                            f"in the export court-coverage join")
        else:
            receipt_n = len(ob["implemented"]) if joined else 0
            reference_n = nocourt_n = 0
        obligations_n = len(ob["implemented"])
        joined_n = obligations_n if joined else 0
        receipts = sorted({r for rids in receipts_for.values() for r in rids})
        if not joined:
            findings.append(
                f"phase {phase} ({ob.get('unit') or 'exports'}) records {obligations_n} "
                f"implemented obligation(s) that do not join to the FRF chain: "
                + "; ".join(missing))
        rows.append({
            "phase": int(phase),
            "unit": ob.get("unit"),
            "closed": ob.get("closed"),
            "obligations": obligations_n,
            "required_courts": required,
            "receipts": len(receipts),
            "covering_claim": covering_id,
            "blockers": blockers,
            "missing": missing,
            "joined": joined,
        })
        totals["strata"] += 1
        totals["strata_joined"] += 1 if joined else 0
        if ob.get("unit") is None:
            totals["export_obligations"] += obligations_n
        else:
            totals["contract_obligations"] += obligations_n
        totals["obligations"] += obligations_n
        totals["obligations_joined"] += joined_n
        totals["obligations_to_receipt"] += receipt_n
        totals["obligations_to_reference_basis"] += reference_n
        totals["obligations_to_no_court"] += nocourt_n
        totals["receipts"] += len(receipts)
        totals["blockers"] += blockers
        totals["gaps"] += (obligations_n - joined_n) + (nocourt_n if joined else 0)

    # **The store's compiled parity claim must carry zero blockers**, every sensitivity-backed one,
    # not only the claim that covers a joined stratum: a blocked claim is not evidence whatever its
    # scope. The obligation ledgers are Phases 3 through 19, so the ABI, CLI and baseline claims are
    # outside the join's receipts -- but their blockers are still the store's, and this records
    # them rather than letting a claim that was never joined carry one silently.
    blocked_claims = [cl for cl in ev["claims"].values() if cl.get("blockers")]
    totals["store_blockers"] = sum(len(cl["blockers"]) for cl in blocked_claims)
    for cl in blocked_claims:
        findings.append(
            f"the FRF store's compiled claim {cl.get('id')} carries {len(cl['blockers'])} "
            f"blocker(s)")
    return {"strata": rows, "totals": totals, "findings": findings}


def closure_problems(ev: dict, derived: dict) -> list[str]:
    """Internal consistency of the join itself, distinct from the closure's findings.

    The findings are gaps in the evidence; these are defects in the derivation, which make the
    verdict `fail` on its own account rather than letting an inconsistent join read as complete.
    """
    problems: list[str] = []
    totals = derived["totals"]
    if totals["strata"] != len(ev["obligations"]):
        problems.append(
            f"the derivation covered {totals['strata']} stratum(s) but the ledgers hold "
            f"{len(ev['obligations'])}")
    if totals["obligations"] != totals["export_obligations"] + totals["contract_obligations"]:
        problems.append(
            "the obligation total is not its export and contract parts: "
            f"{totals['obligations']} != {totals['export_obligations']} + "
            f"{totals['contract_obligations']}")
    expected_gaps = (totals["obligations"] - totals["obligations_joined"]
                     + totals["obligations_to_no_court"])
    if totals["gaps"] != expected_gaps:
        problems.append(
            f"the gap count {totals['gaps']} is not the unjoined obligations plus the "
            f"court-less ones ({expected_gaps})")
    return problems


def closure_sensitivity_control(ev: dict) -> dict:
    """Prove the join can fail: remove one premise at a time and require the gap.

    Three synthetic evidence views are derived beside the real one -- a required court's receipt
    deleted, a covering claim given a non-zero blocker, and a covering claim's recorded candidate
    identity moved off the current release. The control is honest only when the real join is complete
    *and* all three injections are detected; otherwise a join that cannot tell evidence from its
    absence would pass vacuously.
    """
    base = derive_closure(ev)
    base_complete = (base["totals"]["gaps"] == 0 and base["totals"]["blockers"] == 0
                     and base["totals"]["store_blockers"] == 0 and not base["findings"])

    first_phase = sorted(ev["obligations"], key=int)[0] if ev["obligations"] else None
    victim_court = None
    claim_id = None
    if first_phase is not None:
        required = ev["required_courts"].get(first_phase) or []
        victim_court = required[0] if required else None
        row = next((r for r in base["strata"] if str(r["phase"]) == first_phase), None)
        claim_id = row.get("covering_claim") if row else None
    if victim_court is None:
        victim_court = sorted(ev["receipts"])[0] if ev["receipts"] else None
    if claim_id is None:
        claim_id = sorted(ev["claims"])[0] if ev["claims"] else None

    missing_ev = copy.deepcopy(ev)
    if victim_court is not None:
        missing_ev["receipts"][victim_court] = []
    missing_row = derive_closure(missing_ev)
    caught_missing = missing_row["totals"]["gaps"] > 0 and any(
        "has no receipt" in f for f in missing_row["findings"])

    blocked_ev = copy.deepcopy(ev)
    if claim_id is not None and claim_id in blocked_ev["claims"]:
        blocked_ev["claims"][claim_id]["blockers"] = ["injected blocker"]
    blocked_row = derive_closure(blocked_ev)
    caught_blocker = blocked_row["totals"]["blockers"] > 0 and any(
        "blocker" in f for f in blocked_row["findings"])

    stale_ev = copy.deepcopy(ev)
    if claim_id is not None and claim_id in stale_ev["claims"]:
        stale_ev["claims"][claim_id].setdefault("candidate", {})["version_or_commit"] = \
            "0.0.0-injected"
    stale_row = derive_closure(stale_ev)
    caught_stale = any(
        "current candidate identity" in f for f in stale_row["findings"])

    return {
        "baseline_joined": base["totals"]["obligations_joined"],
        "baseline_gaps": base["totals"]["gaps"],
        "baseline_blockers": base["totals"]["blockers"],
        "injected_missing_receipt_court": victim_court,
        "injected_missing_receipt_gaps": missing_row["totals"]["gaps"],
        "injected_blocker_claim": claim_id,
        "injected_blocker_count": blocked_row["totals"]["blockers"],
        "injected_stale_claim": claim_id,
        "baseline_complete": base_complete,
        "caught_missing_receipt": caught_missing,
        "caught_nonzero_blocker": caught_blocker,
        "caught_stale_identity": caught_stale,
        "honest": bool(base_complete and caught_missing and caught_blocker and caught_stale),
    }


def receipt_closure_court(name: str) -> dict:
    """`RT-RECEIPT-CLOSURE`: join every implemented obligation to its FRF receipt.

    Stages no probe. It reads the obligation ledgers, the export court-coverage join, the FRF
    declarations, receipts, challenges and claims, and the Gemel projection, joins each in-scope
    stratum's implemented obligations to its FRF chain, and records whether every obligation joined
    and whether the covering claims carry zero blockers. The verdict is `pass` only when the closure
    is complete for every stratum and the control is honest; a real gap is a `finding` and a `fail`.
    """
    ev = read_closure_evidence()
    derived = derive_closure(ev)
    control = closure_sensitivity_control(ev)
    problems = closure_problems(ev, derived)

    findings = list(derived["findings"])
    totals = derived["totals"]
    verdict = "pass" if (
        not problems
        and control["honest"]
        and not findings
        and totals["gaps"] == 0
        and totals["blockers"] == 0
        and totals["store_blockers"] == 0
    ) else "fail"
    return {
        "court": name,
        "probe": "",
        "method": (
            "stages no probe: it joins every obligation the in-scope strata recorded "
            "`implemented` or closed to the FRF receipt that proves it. It reads the per-stratum "
            "obligation ledgers, the export court-coverage join and its authored `reference_probes` "
            "set, the FRF declarations, receipts, challenges and claims in .frf/, and the Gemel "
            "checkpoint projection -- the registers the earlier strata and the FRF store write, "
            "maintaining no list of its own (docs/PHASE-20-SUBPHASES.md section 3.4). For every "
            "FRF-declarable court each stratum ran it requires a declaration, a receipt, two "
            "adjudicated challenges and a `sensitivity-backed` claim of zero blockers covering the "
            "receipt and recording the current candidate identity, the five clauses "
            "forensics/tools/phase_state.py's frf_gemel_blocking_reason derives a stratum's blocking "
            "reason from, and it joins each implemented export to its courts through the atlas. It "
            "is pass only when the closure is complete for every stratum and a synthetic evidence "
            "view with a receipt removed, a claim blocker injected or a stale candidate identity "
            "detects the gap (section 3.2, docs/CUSTODIAN_CONTRACT.md section 6)."
        ),
        "frf_declarable": False,
        "frf_exclusion": (
            "the receipt-closure court reads the FRF store's own receipts and claims and stages no "
            "artifacts/phase20/probes/ pair, so it takes no transcript to diff and carries no FRF "
            "declaration"
        ),
        "closure_authority": [rel(CUSTODIAN_CONTRACT), rel(LEVELS_DOC), rel(PARITY_MODEL)],
        "candidate_version": ev["candidate_version"],
        "strata": derived["strata"],
        "totals": totals,
        "findings": findings,
        "control": control,
        "problems": problems,
        "verdict": verdict,
    }


# --------------------------------------------------------------------------------------------
# the residual disposition: reading the registers, and dispositioning every residual
# --------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class ResidualSource:
    """One committed register the residual disposition reads, bound to the artefact that carries it.

    `path` is the repository-relative register; `what` is the one-line statement of what residual
    class it carries. The court maintains no residual of its own -- every record it dispositions is
    read from one of these registers, so a residual added without a disposition is visible rather
    than absorbed.
    """

    name: str
    path: str
    what: str


# The residual registers, in the order they are reported. They are the registers the earlier strata
# and the FRF store write: the Phase-22 cross-plane census and its closure/checkpoint, the Phase-1
# completeness and the symbol reconciliation, the divergence, ownership-transition and prerequisite
# planes, the two boundary registers, the Phase-18 hostile/CT/ASan/Miri receipts, the
# unsafe-footprint ceiling and the FRF store itself.
RESIDUAL_SOURCES: tuple[ResidualSource, ...] = (
    ResidualSource(
        "phase22-reconciliation", "forensics/atlas/phase22/reconciliation.json",
        "the cross-plane residual census: every reachable entity's residual class and disposition, "
        "with each `UNKNOWN` residual named individually and tested against the closure"),
    ResidualSource(
        "phase22-closure", "forensics/atlas/phase22/compatibility-closure.json",
        "the reachability closure's own `unknown_intersecting_root_keys`: the `UNKNOWN` residuals "
        "that reach a declared compatibility root, which the Phase-22 seal requires to be zero"),
    ResidualSource(
        "phase22-gemel-checkpoint", "forensics/atlas/phase22/gemel-checkpoint.json",
        "the checkpoint's residual census and its named `UNKNOWN` sets, with the intersection key"),
    ResidualSource(
        "phase1-completeness", "forensics/atlas/phase1-completeness.json",
        "the archaeology completeness residual-disposition classes, the open-`UNKNOWN` set, the "
        "missing set and the deferred planes"),
    ResidualSource(
        "symbol-reconciliation",
        "forensics/atlas/openssl-3.6.4-production/surface-reconciliation.json",
        "the five hard-residual classes per library over the four symbol planes"),
    ResidualSource(
        "divergence-obligations", "forensics/divergence-obligations.json",
        "the machine-readable divergence register: every obligation's disposition and blocking state"),
    ResidualSource(
        "ownership-transitions", "forensics/ownership-transitions.json",
        "the approved obligation-ledger universe changes and downward phase-state corrections, each "
        "with its recorded reason"),
    ResidualSource(
        "prerequisites", "forensics/prerequisites.json",
        "the prerequisite plane's deferrals, deliberate divergences and authority-unit classes"),
    ResidualSource(
        "hostile-boundary-register", "artifacts/phase18/hostile-boundary-register.json",
        "the Phase-18 hostile-boundary register's `not-claimed` surfaces"),
    ResidualSource(
        "performance-boundary-register", "artifacts/phase19/performance-boundary-register.json",
        "the Phase-19 performance-boundary register's `not-claimed` and `not-measured` surfaces"),
    ResidualSource(
        "hostile-courts", "artifacts/phase18/COURTS.json",
        "the Phase-18 hostile courts' residual and recorded-divergence counts (the hostile residual "
        "count is the one that must be zero)"),
    ResidualSource(
        "ct-primitives", "artifacts/phase18/COURTS.json",
        "the CT-primitives `separated` findings (`bn-modexp`, `bn-inverse`)"),
    ResidualSource(
        "asan", "artifacts/phase18/asan.json",
        "the ASan closure's layer findings and its `not_reached` instruments"),
    ResidualSource(
        "miri", "artifacts/phase18/miri-tcb.json",
        "the Miri TCB suite's unsupported tests and its problems"),
    ResidualSource(
        "unsafe-footprint", "artifacts/phase18/unsafe-bounds.json",
        "the UNSAFE-FOOTPRINT growth check: a core module above its recorded ceiling is a residual"),
    ResidualSource(
        "frf-store", ".frf/residuals",
        "the FRF store's own residual tokens, the sensitivity mutants each challenge injects"),
)


# The profile a residual can intersect. The claimed production profile is the exact build the
# candidate is measured under and the declared compatibility-root families the closure observes;
# the register's own `unknown_intersecting_root_keys` is read, never re-derived here.
def read_residual_profile(closure: dict | None) -> dict:
    """The claimed production profile, read from the closure and the FRF candidate identity."""
    body = (closure or {}).get("body") or {}
    counts = body.get("counts") or {}
    unpopulated = body.get("unpopulated") or []
    return {
        "authority": str((closure or {}).get("authority") or ""),
        "candidate_version": gen_frf_courts.CANDIDATE_VERSION,
        "build_profile": gen_frf_courts.BUILD_PROFILE,
        "observable_roots": sorted(str(r) for r in (body.get("roots") or {})),
        "roots_declared": int(counts.get("roots_declared", 0)),
        "roots_observed": int(counts.get("roots", 0)),
        "unpopulated_families": sorted(str(u.get("family")) for u in unpopulated),
        "unknown_intersecting_keys": sorted(
            str(k) for k in (body.get("unknown_intersecting_root_keys") or [])),
    }


def residual_record(id: str, disposition: str | None, intersects: bool, state: str,
                    count: int = 1, cls: str | None = None) -> dict:
    """One normalized residual record, at the granularity the source register carries it.

    `count` is the number of residuals the record stands for: a residual set the register records
    only in aggregate is held as one record with its count, while an individually named residual
    (every `UNKNOWN` one) is held with `count` 1 so the intersection discipline is visible per name.
    """
    rec = {
        "id": id,
        "disposition": disposition,
        "intersects_production_profile": bool(intersects),
        "state": state,
        "count": int(count),
    }
    if cls is not None:
        rec["class"] = cls
    return rec


def read_census_residuals(unknown_keys: frozenset[str]) -> tuple[list[dict], int]:
    """The Phase-22 cross-plane census: non-`UNKNOWN` residuals grouped, `UNKNOWN` ones named.

    The register records 60k+ residuals, so a residual set whose disposition is not `UNKNOWN` is
    held as one record per `(class, disposition)` with its count -- the disposition is uniform over
    the set, so the aggregate is exact. Every `UNKNOWN` residual is held individually and its
    intersection is read from the closure's `unknown_intersecting_root_keys`, so the fact the seal
    turns on is visible per name rather than buried in a count.
    """
    doc = read_json("forensics/atlas/phase22/reconciliation.json")
    if not doc:
        return [], 0
    rows = (doc["body"].get("residuals") or [])
    groups: dict[tuple[str, str], int] = {}
    unknown: list[dict] = []
    for r in rows:
        cls = str(r.get("class"))
        disp = str(r.get("disposition"))
        if disp == "UNKNOWN":
            key = str(r.get("key"))
            unknown.append(residual_record(key, "UNKNOWN", key in unknown_keys, "unknown", 1, cls))
        else:
            groups[(cls, disp)] = groups.get((cls, disp), 0) + 1
    out = [residual_record(f"{cls}/{disp}", disp, disp == "REQUIRED_COMPATIBILITY",
                           "dispositioned", n, cls)
           for (cls, disp), n in sorted(groups.items())]
    out += sorted(unknown, key=lambda rec: rec["id"])
    return out, len(rows)


def read_closure_residuals(unknown_keys: frozenset[str]) -> tuple[list[dict], int]:
    """The closure's own blocking set: the `UNKNOWN` residuals that reach a declared root.

    Zero on the current tree -- the Phase-22 seal's "zero UNKNOWN residuals intersect the claimed
    production profile" holds -- so an empty list is the measured answer and not an omission.
    """
    doc = read_json("forensics/atlas/phase22/compatibility-closure.json")
    if not doc:
        return [], 0
    return ([residual_record(k, "UNKNOWN", True, "unknown-intersecting", 1, "compatibility-root")
             for k in sorted(unknown_keys)], len(unknown_keys))


def read_gemel_residuals() -> tuple[list[dict], int]:
    """The checkpoint's residual census: the named `UNKNOWN` sets and the intersection key."""
    doc = read_json("forensics/atlas/phase22/gemel-checkpoint.json")
    if not doc:
        return [], 0
    census = doc["body"].get("residual_census") or {}
    inter = bool(census.get("intersecting_root_keys"))
    sets = census.get("unknown_sets") or {}
    out = [residual_record(cls, "UNKNOWN", inter, "unknown", len(keys or []), cls)
           for cls, keys in sorted(sets.items())]
    return out, len(sets)


def read_phase1_residuals() -> tuple[list[dict], int]:
    """Phase-1 completeness: the residual-disposition classes, unknowns, missing and deferred."""
    doc = read_json("forensics/atlas/phase1-completeness.json")
    if not doc:
        return [], 0
    body = doc["body"]
    out: list[dict] = []
    for r in (body.get("residual_dispositions") or []):
        cls = str(r.get("class"))
        closed = bool(r.get("closed"))
        public = bool(r.get("source_public") or r.get("binary_public") or r.get("must_export"))
        out.append(residual_record(cls, "closed" if closed else "open", public,
                                   "dispositioned" if closed else "open",
                                   int(r.get("count", 1)), cls))
    for u in (body.get("open_unknowns") or []):
        out.append(residual_record(str(u), "UNKNOWN", False, "unknown", 1, "open_unknown"))
    for m in (body.get("missing") or []):
        out.append(residual_record(str(m), None, True, "un_dispositioned", 1, "missing"))
    for d in (body.get("deferred") or []):
        out.append(residual_record(str(d.get("plane")), "deferred", False, "deferred", 1, "deferred"))
    return out, (len(body.get("residual_dispositions") or [])
                 + len(body.get("open_unknowns") or []) + len(body.get("missing") or [])
                 + len(body.get("deferred") or []))


def read_symbol_residuals() -> tuple[list[dict], int]:
    """The symbol reconciliation's five hard-residual classes per library.

    A class is a residual only when it holds an entry; all ten are empty on the current tree, which
    is the `docs/PARITY_MODEL.md` section 4 "zero hard residuals" measurement. The `checked` count
    is the number of classes examined, so an empty result is a stated measurement, not silence.
    """
    doc = read_json("forensics/atlas/openssl-3.6.4-production/surface-reconciliation.json")
    if not doc:
        return [], 0
    hard = (doc["body"].get("symbol_hard_residuals") or {})
    out: list[dict] = []
    checked = 0
    for lib, classes in sorted(hard.items()):
        for cls, entries in sorted((classes or {}).items()):
            checked += 1
            for e in (entries or []):
                name = e.get("symbol") if isinstance(e, dict) else e
                out.append(residual_record(f"{lib}/{cls}:{name}", None, True,
                                           "un_dispositioned", 1, cls))
    return out, checked


def read_divergence_residuals() -> tuple[list[dict], int]:
    """The divergence register: each obligation's disposition and its own blocking flag."""
    doc = read_json("forensics/divergence-obligations.json")
    if not doc:
        return [], 0
    rows = doc["body"].get("rows") or []
    out = [residual_record(str(r.get("id")), str(r.get("disposition")) or None,
                           bool(r.get("blocking")),
                           "blocking" if r.get("blocking") else "dispositioned",
                           1, str(r.get("class") or ""))
           for r in rows]
    return out, len(rows)


def read_ownership_transition_residuals() -> tuple[list[dict], int]:
    """The ownership-transition register: approved ledger-universe and phase-state corrections.

    These are not unresolved residuals -- they are the approved changes to a ledger's universe and
    the approved downward corrections to a derived phase state, each carrying the reason and
    evidence that justify it -- so each is dispositioned `approved-transition`. An entry with no
    recorded reason would be an un-dispositioned residual and a finding.
    """
    doc = read_json("forensics/ownership-transitions.json")
    if not doc:
        return [], 0
    out: list[dict] = []
    checked = 0
    for key, kind in (("transitions", "universe-transition"),
                      ("phase_state_transitions", "state-correction"),
                      ("prerequisite_transitions", "metric-correction")):
        entries = doc.get(key) or []
        checked += len(entries)
        for e in entries:
            reason = e.get("reason")
            ident = f"{kind}:{e.get('phase', e.get('metric', '?'))}"
            out.append(residual_record(ident, "approved-transition" if reason else None, True,
                                       "approved" if reason else "un_dispositioned", 1, kind))
    return out, checked


def read_prerequisite_residuals() -> tuple[list[dict], int]:
    """The prerequisite plane: deferrals, deliberate divergences and unit-class dispositions."""
    doc = read_json("forensics/prerequisites.json")
    if not doc:
        return [], 0
    body = doc["body"]
    out: list[dict] = []
    for d in (body.get("deferrals") or []):
        name = d.get("symbol") or d.get("authority_unit") or "deferral"
        out.append(residual_record(f"deferral:{name}", "deferred", False, "deferred", 1,
                                   "deferral"))
    for d in (body.get("divergences") or []):
        cls = str(d.get("class"))
        name = d.get("owner_module") or "divergence"
        out.append(residual_record(f"divergence:{name}", cls, False, "divergence", 1, cls))
    groups = collections.Counter(str(u.get("class")) for u in (body.get("units") or []))
    for cls, n in sorted(groups.items()):
        reached = cls == "reached_by_a_named_construct"
        out.append(residual_record(f"unit-class:{cls}", cls, reached,
                                   "reached" if reached else "bounded", n, cls))
    return out, (len(body.get("deferrals") or []) + len(body.get("divergences") or [])
                 + len(body.get("units") or []))


def read_register_residuals(path: str, classes: tuple[str, ...]) -> tuple[list[dict], int]:
    """The `not-claimed`/`not-measured` surfaces of a Phase-18/19 boundary register.

    A boundary surface is the register's explicit non-claim: it is bounded rather than measured, so
    it carries the register's classification as its disposition and is not an `UNKNOWN`.
    """
    doc = read_json(path)
    if not doc:
        return [], 0
    surfaces = doc.get("surfaces") or []
    out = [residual_record(str(s.get("id")), str(s.get("classification")), False, "bounded", 1,
                           str(s.get("classification")))
           for s in surfaces if str(s.get("classification")) in classes]
    return out, len(surfaces)


def read_hostile_court_residuals() -> tuple[list[dict], int]:
    """The Phase-18 hostile courts' residual counts.

    A hostile residual -- a crash, OOM or timeout the candidate produced on hostile input where the
    authority did not -- is an un-dispositioned defect and would fail the court. The recorded
    divergences are the courts' classified value differences and carry their own disposition.
    """
    doc = read_json("artifacts/phase18/COURTS.json")
    if not doc:
        return [], 0
    out: list[dict] = []
    checked = 0
    for c in (doc["body"].get("courts") or []):
        if c.get("hostile_residual_count") is None and c.get("recorded_divergence_count") is None:
            continue
        checked += 1
        name = str(c.get("court"))
        hostile = int(c.get("hostile_residual_count") or 0)
        recorded = int(c.get("recorded_divergence_count") or 0)
        if hostile:
            out.append(residual_record(f"{name}:hostile", None, True, "un_dispositioned",
                                       hostile, "hostile-residual"))
        if recorded:
            out.append(residual_record(f"{name}:recorded-divergence", "recorded-divergence", True,
                                       "recorded-divergence", recorded, "recorded-divergence"))
    return out, checked


def read_ct_residuals() -> tuple[list[dict], int]:
    """CT-primitives' `separated` findings -- dispositioned, and explicitly NOT_CLAIMED."""
    doc = read_json("artifacts/phase18/COURTS.json")
    if not doc:
        return [], 0
    row = next((c for c in doc["body"].get("courts", [])
                if c.get("court") == "CT-PRIMITIVES"), None)
    if row is None:
        return [], 0
    findings = row.get("findings") or []
    paths = row.get("paths") or []
    out = [residual_record(str(f), "separated", True, "not-claimed-finding", 1, "ct")
           for f in findings]
    return out, len(paths) or len(findings)


def read_asan_residuals() -> tuple[list[dict], int]:
    """The ASan closure: layer findings (un-dispositioned defects) and the `not_reached` set."""
    doc = read_json("artifacts/phase18/asan.json")
    if not doc:
        return [], 0
    out: list[dict] = []
    layers = doc.get("layers") or []
    for layer in layers:
        for f in (layer.get("findings") or []):
            out.append(residual_record(f"{layer.get('layer')}:{f}", None, True,
                                       "un_dispositioned", 1, "asan-layer-finding"))
    for r in (doc.get("not_reached") or []):
        out.append(residual_record(str(r), "not-reached", False, "bounded", 1, "not-reached"))
    return out, len(layers)


def read_miri_residuals() -> tuple[list[dict], int]:
    """The Miri TCB suite: the tests Miri cannot interpret (bounded) and any problems (defects)."""
    doc = read_json("artifacts/phase18/miri-tcb.json")
    if not doc:
        return [], 0
    out: list[dict] = []
    for u in (doc.get("unsupported") or []):
        out.append(residual_record(str(u.get("test")), "unsupported-foreign-function", False,
                                   "bounded", 1, "miri-unsupported"))
    for p in (doc.get("problems") or []):
        out.append(residual_record(str(p), None, True, "un_dispositioned", 1, "miri-problem"))
    results = doc.get("results") or {}
    return out, len(results) + len(out)


def read_unsafe_residuals() -> tuple[list[dict], int]:
    """The UNSAFE-FOOTPRINT growth check: a core module above its recorded ceiling is a residual.

    The boundary layer (ffi, runtime, dso, engine, async, context) is allowed to grow; a core
    module's `unsafe_sites`/`extern_c_fns` above `artifacts/phase18/unsafe-bounds.json` is a
    footprint regression and is un-dispositioned, exactly as the Phase-18 register court reads it.
    """
    fp = read_json("forensics/atlas/unsafe-footprint.json")
    bounds = read_json("artifacts/phase18/unsafe-bounds.json")
    if not fp or not bounds:
        return [], 0
    default = bounds.get("default") or {}
    ceiling = bounds.get("bounds") or {}
    modules = fp["body"].get("modules") or []
    out: list[dict] = []
    for m in modules:
        if str(m.get("classification")) != "core":
            continue
        b = ceiling.get(str(m.get("module")), default)
        over = [metric for metric in ("unsafe_sites", "extern_c_fns")
                if int(m.get(metric, 0)) > int(b.get(metric, 0))]
        if over:
            out.append(residual_record(f"{m.get('module')}:{'+'.join(over)}", None, True,
                                       "un_dispositioned", 1, "unsafe-growth"))
    return out, len(modules)


def read_frf_residuals() -> tuple[list[dict], int]:
    """The FRF store's residual tokens -- the sensitivity mutants each challenge injects.

    These are control residuals, not candidate defects: a challenge's mutant perturbs the observed
    axis precisely so the court detects it (`saw_defect`), and a residual produced is the challenge
    succeeding. The register that says whether one blocks the candidate claim is the compiled claim
    store: a residual intersects the profile only when a `sensitivity-backed` claim blocks on it, so
    the intersection is read from `.frf/claims/` rather than assumed.
    """
    if not FRF_RESIDUALS.is_dir():
        return [], 0
    tokens: list[dict] = []
    for p in sorted(FRF_RESIDUALS.glob("*.token.json")):
        try:
            tokens.append(json.loads(p.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError):
            continue
    if not tokens:
        return [], 0
    blocked: set[str] = set()
    for claim in read_frf_claims().values():
        for b in (claim.get("blockers") or []):
            blocked.add(b if isinstance(b, str) else json.dumps(b, sort_keys=True))
    by_disp = collections.Counter()
    blocking = collections.Counter()
    for t in tokens:
        disp = str(t.get("disposition") or "")
        by_disp[disp] += 1
        if str(t.get("residual_id")) in blocked:
            blocking[disp] += 1
    out = [residual_record(f"frf-mutant:{disp or 'none'}", disp or None, blocking[disp] > 0,
                           "sensitivity-mutant", n, "frf-sensitivity-mutant")
           for disp, n in sorted(by_disp.items())]
    return out, len(tokens)


# The reader for each source, keyed by name. A reader returns `(records, checked)`; `checked` is the
# number of register rows examined, so a source that legitimately carries zero residuals states a
# measurement rather than falling silent. The Phase-22 readers take the closure's own blocking set.
RESIDUAL_READERS: dict[str, object] = {
    "phase22-reconciliation": read_census_residuals,
    "phase22-closure": read_closure_residuals,
    "phase22-gemel-checkpoint": lambda keys: read_gemel_residuals(),
    "phase1-completeness": lambda keys: read_phase1_residuals(),
    "symbol-reconciliation": lambda keys: read_symbol_residuals(),
    "divergence-obligations": lambda keys: read_divergence_residuals(),
    "ownership-transitions": lambda keys: read_ownership_transition_residuals(),
    "prerequisites": lambda keys: read_prerequisite_residuals(),
    "hostile-boundary-register": lambda keys: read_register_residuals(
        "artifacts/phase18/hostile-boundary-register.json", ("not-claimed", "not-measured")),
    "performance-boundary-register": lambda keys: read_register_residuals(
        "artifacts/phase19/performance-boundary-register.json", ("not-claimed", "not-measured")),
    "hostile-courts": lambda keys: read_hostile_court_residuals(),
    "ct-primitives": lambda keys: read_ct_residuals(),
    "asan": lambda keys: read_asan_residuals(),
    "miri": lambda keys: read_miri_residuals(),
    "unsafe-footprint": lambda keys: read_unsafe_residuals(),
    "frf-store": lambda keys: read_frf_residuals(),
}


def read_residual_evidence() -> dict:
    """The committed residual evidence view the disposition is derived from.

    A plain dict so the sensitivity control can deep-copy it and inject a residual without touching
    the tree. Every record is read from a register; none is typed as present. `unknown_intersection`
    is the closure's own blocking set, and each source records whether its register was present so
    an absent register is a stated problem rather than a silently empty source.
    """
    closure = read_json("forensics/atlas/phase22/compatibility-closure.json")
    unknown_keys = frozenset(
        str(k) for k in ((closure or {}).get("body", {}).get("unknown_intersecting_root_keys")
                        or []))
    sources: dict[str, dict] = {}
    for spec in RESIDUAL_SOURCES:
        reader = RESIDUAL_READERS[spec.name]
        records, checked = reader(unknown_keys)
        sources[spec.name] = {
            "present": (REPO_ROOT / spec.path).exists(),
            "checked": checked,
            "residuals": records,
        }
    return {
        "profile": read_residual_profile(closure),
        "unknown_intersecting_keys": sorted(unknown_keys),
        "sources": sources,
    }


def residual_finding(source: str, rec: dict) -> str:
    """The finding text for one residual that is un-dispositioned or `UNKNOWN`-intersecting."""
    if not rec.get("disposition"):
        return (f"residual {rec['id']!r} from {source} carries no disposition, so it is an "
                "un-dispositioned residual a custodian claim cannot exclude "
                "(docs/PARITY_MODEL.md section 5, docs/CUSTODIAN_CONTRACT.md section 6)")
    return (f"residual {rec['id']!r} from {source} is `UNKNOWN` and intersects the claimed "
            "production profile, so docs/CUSTODIAN_CONTRACT.md section 6's no-unresolved-residual-"
            "intersecting-the-claimed-scope condition is not satisfied")


def derive_residuals(ev: dict) -> dict:
    """The disposition over an evidence view: per source, and the findings a real gap produces.

    A pure function of the evidence view, so the sensitivity control can inject a residual and
    re-derive. The findings are exactly two classes -- a residual with no disposition, and an
    `UNKNOWN` residual that intersects the profile -- and a non-empty list is a `fail`, not a
    verdict the court talks itself out of.
    """
    sources_out: list[dict] = []
    residuals: list[dict] = []
    findings: list[str] = []
    totals = {
        "sources": 0, "sources_present": 0, "checked": 0, "residuals": 0,
        "dispositioned": 0, "un_dispositioned": 0, "unknown": 0,
        "unknown_intersecting": 0, "intersecting": 0, "bounded": 0, "findings": 0,
    }
    for spec in RESIDUAL_SOURCES:
        block = (ev.get("sources") or {}).get(spec.name)
        recs = list((block or {}).get("residuals") or [])
        state = "closed" if (block and block.get("present")) else "absent"
        disp_counts: collections.Counter = collections.Counter()
        n_res = n_disp = n_un = n_unk = n_unk_inter = n_inter = n_bounded = 0
        for rec in recs:
            count = int(rec.get("count", 1))
            n_res += count
            disp = rec.get("disposition")
            if disp:
                n_disp += count
                disp_counts[str(disp)] += count
            else:
                n_un += count
            if str(disp) == "UNKNOWN":
                n_unk += count
                if rec.get("intersects_production_profile"):
                    n_unk_inter += count
            if rec.get("intersects_production_profile"):
                n_inter += count
            if rec.get("state") == "bounded":
                n_bounded += count
            if not disp or (str(disp) == "UNKNOWN" and rec.get("intersects_production_profile")):
                findings.append(residual_finding(spec.name, rec))
                state = "open"
        totals["sources"] += 1
        totals["sources_present"] += 1 if (block and block.get("present")) else 0
        totals["checked"] += int((block or {}).get("checked", 0))
        totals["residuals"] += n_res
        totals["dispositioned"] += n_disp
        totals["un_dispositioned"] += n_un
        totals["unknown"] += n_unk
        totals["unknown_intersecting"] += n_unk_inter
        totals["intersecting"] += n_inter
        totals["bounded"] += n_bounded
        sources_out.append({
            "source": spec.name,
            "path": spec.path,
            "what": spec.what,
            "checked": int((block or {}).get("checked", 0)),
            "residuals": n_res,
            "dispositioned": n_disp,
            "un_dispositioned": n_un,
            "unknown": n_unk,
            "unknown_intersecting": n_unk_inter,
            "intersecting": n_inter,
            "dispositions": dict(sorted(disp_counts.items())),
            "state": state,
        })
        for rec in recs:
            row = {
                "source": spec.name,
                "id": rec["id"],
                "disposition": rec.get("disposition"),
                "intersects_production_profile": bool(rec.get("intersects_production_profile")),
                "state": rec.get("state"),
            }
            if int(rec.get("count", 1)) != 1:
                row["count"] = int(rec.get("count"))
            if rec.get("class") is not None:
                row["class"] = rec.get("class")
            residuals.append(row)
    totals["findings"] = len(findings)
    residuals.sort(key=lambda r: (r["source"], r["id"]))
    return {
        "profile": ev.get("profile") or {},
        "sources": sources_out,
        "residuals": residuals,
        "totals": totals,
        "findings": findings,
    }


def residuals_problems(ev: dict, derived: dict) -> list[str]:
    """Internal consistency of the disposition itself, distinct from its findings.

    The findings are real residual gaps; these are defects in the derivation or the evidence view,
    which make the verdict `fail` on their own account rather than letting an incomplete read pass.
    """
    problems: list[str] = []
    for spec in RESIDUAL_SOURCES:
        block = (ev.get("sources") or {}).get(spec.name)
        if block is None or not block.get("present"):
            problems.append(
                f"the residual source {spec.name} ({spec.path}) is absent, so its residuals were "
                f"not read and the disposition is incomplete")
    totals = derived["totals"]
    if totals["residuals"] != totals["dispositioned"] + totals["un_dispositioned"]:
        problems.append(
            "the residual total is not its dispositioned and un-dispositioned parts: "
            f"{totals['residuals']} != {totals['dispositioned']} + {totals['un_dispositioned']}")
    if totals["unknown_intersecting"] > totals["unknown"]:
        problems.append(
            f"the UNKNOWN-intersecting count {totals['unknown_intersecting']} exceeds the UNKNOWN "
            f"count {totals['unknown']}")
    return problems


def residuals_sensitivity_control(ev: dict) -> dict:
    """Prove the disposition can fail: inject an un-dispositioned and an intersecting `UNKNOWN`.

    Three synthetic evidence views are derived beside the real one: a residual given no disposition,
    a residual recorded `UNKNOWN` and flagged as intersecting the profile, and a residual recorded
    `UNKNOWN` but *not* intersecting. The control is honest only when the real view is closed (zero
    findings) *and* the first two injections are detected *and* the third produces no finding -- so a
    court that cannot tell a dispositioned residual from an absent one, or an intersecting `UNKNOWN`
    from a harmless one, cannot pass.
    """
    base = derive_residuals(ev)
    base_closed = (not base["findings"] and base["totals"]["un_dispositioned"] == 0
                   and base["totals"]["unknown_intersecting"] == 0)

    victim = next((spec.name for spec in RESIDUAL_SOURCES
                   if (ev.get("sources") or {}).get(spec.name, {}).get("present")), RESIDUAL_SOURCES[0].name)

    def injected(record: dict) -> dict:
        view = copy.deepcopy(ev)
        view["sources"][victim]["residuals"] = \
            list(view["sources"][victim].get("residuals") or []) + [record]
        return derive_residuals(view)

    d_un = injected(residual_record("injected-un-dispositioned", None, True, "un_dispositioned"))
    d_inter = injected(residual_record("injected-unknown-intersecting", "UNKNOWN", True, "unknown"))
    d_clean = injected(residual_record("injected-unknown-not-intersecting", "UNKNOWN", False,
                                       "unknown"))
    caught_un = any("no disposition" in f for f in d_un["findings"])
    caught_inter = any("intersects the claimed" in f for f in d_inter["findings"])
    specificity = not d_clean["findings"]
    return {
        "baseline_closed": base_closed,
        "baseline_residuals": base["totals"]["residuals"],
        "baseline_unknown": base["totals"]["unknown"],
        "baseline_unknown_intersecting": base["totals"]["unknown_intersecting"],
        "injected_source": victim,
        "injected_un_dispositioned_findings": len(d_un["findings"]),
        "injected_unknown_intersecting_findings": len(d_inter["findings"]),
        "injected_unknown_not_intersecting_findings": len(d_clean["findings"]),
        "caught_un_dispositioned": caught_un,
        "caught_unknown_intersecting": caught_inter,
        "specificity_holds": specificity,
        "honest": bool(base_closed and caught_un and caught_inter and specificity),
    }


def residual_court(name: str) -> dict:
    """`RT-CUSTODIAN-RESIDUALS`: disposition every residual, and fail on an `UNKNOWN`-intersecting one.

    Stages no probe. It reads the residual registers the earlier strata and the FRF store write --
    the Phase-22 census and its closure, the Phase-1 completeness and symbol reconciliation, the
    divergence, ownership-transition and prerequisite planes, the two boundary registers, the
    hostile/CT/ASan/Miri receipts and the unsafe-footprint ceiling -- and records, per source, every
    residual with its disposition and whether it intersects the claimed production profile. The
    verdict is `pass` only when every register was read, every residual carries a disposition, no
    `UNKNOWN` intersects the profile, and the control is honest; a real gap is a `finding` and a
    `fail`.
    """
    ev = read_residual_evidence()
    derived = derive_residuals(ev)
    control = residuals_sensitivity_control(ev)
    problems = residuals_problems(ev, derived)

    findings = list(derived["findings"])
    totals = derived["totals"]
    verdict = "pass" if (
        not problems and control["honest"] and not findings
        and totals["un_dispositioned"] == 0 and totals["unknown_intersecting"] == 0
    ) else "fail"
    return {
        "court": name,
        "probe": "",
        "method": (
            "stages no probe: it dispositions every residual the earlier strata and the FRF store "
            "record. It reads the registers that carry them -- the Phase-22 cross-plane residual "
            "census and the closure's `unknown_intersecting_root_keys`, the Phase-22 checkpoint's "
            "named `UNKNOWN` sets, the Phase-1 archaeology completeness and the symbol "
            "reconciliation, the divergence, ownership-transition and prerequisite planes, the "
            "Phase-18 hostile-boundary and Phase-19 performance-boundary registers, the Phase-18 "
            "court residual counts, the CT-primitives `separated` findings, the ASan closure and "
            "the Miri TCB receipts, the UNSAFE-FOOTPRINT growth ceiling and the FRF store's own "
            "residual tokens -- maintaining no list of its own (docs/PHASE-20-SUBPHASES.md section "
            "3.4). For each residual it records `{source, id, disposition, "
            "intersects_production_profile, state}`; every residual must carry a disposition and "
            "no `UNKNOWN` residual may intersect the claimed production profile "
            "(docs/CUSTODIAN_CONTRACT.md sections 6 and 8, docs/PARITY_MODEL.md section 1). The "
            "court is pass only when every register was read, the disposition is complete, and a "
            "synthetic view with an un-dispositioned residual and one with an `UNKNOWN`-intersecting "
            "residual each detects the gap while an `UNKNOWN` that does not intersect does not "
            "(section 3.2)."
        ),
        "frf_declarable": False,
        "frf_exclusion": (
            "the residual-disposition court reads the registers the earlier strata and the FRF "
            "store write and stages no artifacts/phase20/probes/ pair, so it takes no transcript to "
            "diff and carries no FRF declaration"
        ),
        "residual_authority": [rel(CUSTODIAN_CONTRACT), rel(PARITY_MODEL),
                               rel(REPO_ROOT / "docs" / "PHASE-22-SUBPHASES.md")],
        "production_profile": derived["profile"],
        "sources": derived["sources"],
        "residuals": derived["residuals"],
        "totals": totals,
        "findings": findings,
        "control": control,
        "problems": problems,
        "verdict": verdict,
    }


# --------------------------------------------------------------------------------------------
# the substitution-witness court
# --------------------------------------------------------------------------------------------


def read_witness_evidence() -> dict:
    """The committed witness evidence view the substitution chain is derived from.

    A plain dict so the sensitivity control can deep-copy it and inject a stale or non-functional
    witness without touching the tree. Every witness is read from a register the earlier strata
    wrote; none is typed as present. `corpus.present` and `phase2.present` record whether the
    registers existed, so an absent register is a stated problem rather than a silently empty
    chain.
    """
    corpus = read_json("forensics/atlas/downstream-corpus.json")
    programs = (corpus or {}).get("programs") or []
    per_program: dict[str, dict | None] = {
        prog: read_json(f"courts/phase17/downstream/{prog}/result.json")
        for prog in WITNESS_PROGRAMS
    }
    registry = read_json("artifacts/phase2/COURTS.json")
    registry_body = (registry or {}).get("body", registry or {})
    verdicts = {str(c["court"]): str(c["verdict"])
                for c in registry_body.get("courts", [])}
    abi: dict[str, dict | None] = {
        court: read_json(f"artifacts/phase2/courts/{court}.json")
        for court, _built_against in ABI_WITNESSES
    }
    return {
        "candidate": gen_frf_courts.CANDIDATE_VERSION,
        "authority": PRODUCTION_AUTHORITY,
        "install": rel(CANDIDATE_INSTALL),
        "corpus": {"present": corpus is not None, "programs": programs},
        "per_program": per_program,
        "phase2": {"present": registry is not None, "registry": verdicts, "courts": abi},
    }


def witness_abi_functional(court: str, rec: dict) -> bool:
    """Whether an ABI-substitution witness's recorded run succeeded.

    Read from the court's own recorded fields, per court: `ABI-SUBSTITUTION` requires both runs to
    exit 0 *and* the substitution to have taken effect (the candidate libraries resolved, not the
    authority's); `ABI-LOAD` requires every library's `dlvsym` resolution to have exited 0;
    `ABI-LINK` requires the linked consumer's run to have exited 0.
    """
    if not rec:
        return False
    if court == "ABI-SUBSTITUTION":
        return bool(rec.get("verdict") == "pass"
                    and int(rec.get("authority_run_exit", 1)) == 0
                    and int(rec.get("candidate_run_exit", 1)) == 0
                    and rec.get("substitution_took_effect"))
    if court == "ABI-LOAD":
        libs = rec.get("libraries") or {}
        return bool(rec.get("verdict") == "pass" and libs and all(
            (lib or {}).get("verdict") == "pass" and int((lib or {}).get("exit", 1)) == 0
            for lib in libs.values()))
    detail = rec.get("detail") or {}
    return bool(rec.get("verdict") == "pass" and int(detail.get("exit", 1)) == 0)


def witness_abi_observation(court: str, rec: dict) -> str:
    """The observation an ABI-substitution witness produced, as its own record carries it."""
    if not rec:
        return ""
    if court == "ABI-SUBSTITUTION":
        run = "; ".join(str(x) for x in (rec.get("candidate_run_output") or []))
        closure = " -> ".join(
            str(x) for x in (rec.get("dynamic_closure_under_substitution") or []))
        return f"candidate run: {run}; closure: {closure}"
    if court == "ABI-LOAD":
        libs = rec.get("libraries") or {}
        return "; ".join(
            f"{name}: " + "; ".join(str(x) for x in ((libs.get(name) or {}).get("output") or []))
            for name in sorted(libs))
    return "; ".join(str(x) for x in ((rec.get("detail") or {}).get("output") or []))


def witness_downstream_functional(rec: dict | None) -> bool:
    """Whether a downstream witness's record says the program built, linked, started and ran.

    The same facts `RT-DOWNSTREAM-CORPUS` reads: `build`, `link`, `start` and `functional` all true
    and the concurrency shape well formed.
    """
    if not rec:
        return False
    conc = rec.get("concurrency") or {}
    return bool((rec.get("functional") or {}).get("ok") is True
                and (rec.get("build") or {}).get("ok") is True
                and (rec.get("link") or {}).get("ok") is True
                and (rec.get("start") or {}).get("ok") is True
                and isinstance(conc.get("ok"), int) and isinstance(conc.get("total"), int)
                and conc["total"] >= 1 and conc["ok"] <= conc["total"])


def witness_downstream_observation(rec: dict | None) -> str:
    """The observation a downstream witness produced, as its own record carries it."""
    if not rec:
        return ""
    func = rec.get("functional") or {}
    detail = str(func.get("detail") or "")
    evidence = "; ".join(str(x) for x in (func.get("evidence") or []))
    return f"{detail} [{evidence}]" if evidence else detail


def witness_install_prefix(path: str) -> str:
    """The candidate distribution prefix a witness path names, repository-relative.

    A container path like `/work/artifacts/phase2/install/lib/libssl.so.3` -- and the load address
    `ldd` prints beside it -- reduces to `artifacts/phase2/install`, so the ABI-substitution
    witness's closure is joined to the same candidate distribution the corpus links against.
    """
    p = path.strip().split(" (", 1)[0].rstrip(":").strip()
    for soname in ("libssl.so.3", "libcrypto.so.3", "libssl.so", "libcrypto.so"):
        if p.endswith("/" + soname):
            p = p[: -(len(soname) + 1)]
            break
    if p.endswith("/lib"):
        p = p[:-4]
    if p.startswith("/work/"):
        p = p[len("/work/"):]
    return p


def witness_abi_target(court: str, rec: dict) -> str | None:
    """The candidate distribution an ABI-substitution witness's record shows it ran against.

    `None` for a witness whose record carries no resolved path (`ABI-LINK` records only that the
    consumer linked and ran), which is read as authority-anchored rather than asserted current.
    """
    if not rec:
        return None
    if court == "ABI-SUBSTITUTION":
        for line in rec.get("dynamic_closure_under_substitution") or []:
            if "=>" in line:
                return witness_install_prefix(line.split("=>", 1)[1])
        return None
    if court == "ABI-LOAD":
        for lib in (rec.get("libraries") or {}).values():
            for line in (lib or {}).get("output") or []:
                if str(line).startswith("load-probe "):
                    return witness_install_prefix(str(line).split(" ", 2)[1])
        return None
    return None


def witness_corpus_prefixes(rows: dict[str, dict]) -> set[str]:
    """The candidate distribution prefixes the downstream records link against.

    Read from each record's `link.detail` (`libssl.so.3 -> <path>`), so the corpus's own target is
    the join the ABI-substitution witness's recorded closure is measured against rather than a
    value typed beside it.
    """
    prefixes: set[str] = set()
    for prog in WITNESS_PROGRAMS:
        detail = str(((rows.get(prog) or {}).get("link") or {}).get("detail") or "")
        if "->" in detail:
            prefixes.add(witness_install_prefix(detail.split("->", 1)[1]))
    return prefixes


def derive_witnesses(ev: dict) -> dict:
    """The witness chain over an evidence view: per witness, build, run, observation and verdict.

    A pure function of the evidence view, so the sensitivity control can inject a stale or
    non-functional witness and re-derive. A witness is a `finding` when it is not functional, when
    its candidate identity is not the current release, or when its record is absent, has drifted
    from the aggregate or is missing a required field; a non-empty list is a `fail`, not a verdict
    the court talks itself out of.
    """
    current = str(ev.get("candidate") or "")
    install = str(ev.get("install") or rel(CANDIDATE_INSTALL))
    witnesses: list[dict] = []
    findings: list[str] = []
    totals = {
        "chains": 2, "witnesses": 0, "abi": 0, "downstream": 0,
        "functional": 0, "current": 0, "findings": 0,
    }

    # Chain B's records are read first, so the candidate distribution they link against is the join
    # chain A's recorded substitution target is measured against rather than a value typed here.
    corpus = ev.get("corpus") or {}
    rows = {str(r.get("program")): r for r in (corpus.get("programs") or [])}
    corpus_prefixes = witness_corpus_prefixes(rows)

    # Chain A -- the Phase-2 ABI-substitution family, read from the committed per-court records and
    # cross-checked against the sealed registry. A witness is current only when the distribution its
    # record shows it ran against is the candidate distribution the corpus links against (or the
    # shell root above it); a witness whose record carries no resolved path is authority-anchored.
    phase2 = ev.get("phase2") or {}
    registry = phase2.get("registry") or {}
    shell_roots = {p.rsplit("/", 1)[0] for p in corpus_prefixes}
    for court, built_against in ABI_WITNESSES:
        rec = (phase2.get("courts") or {}).get(court) or {}
        functional = witness_abi_functional(court, rec)
        observation = witness_abi_observation(court, rec)
        target = witness_abi_target(court, rec)
        is_current = (target is None or target in corpus_prefixes or target in shell_roots
                      or not corpus_prefixes)
        if target is None:
            currency = ("authority-anchored; the record carries no resolved path, and the "
                        "candidate distribution the corpus links against is "
                        f"{sorted(corpus_prefixes)}")
        else:
            currency = ("current" if is_current
                        else f"stale: target {target!r} != the corpus candidate distribution "
                             f"{sorted(corpus_prefixes)}")
        witnesses.append({
            "chain": ABI_CHAIN,
            "witness": court,
            "built_against": built_against,
            "run_id_or_mode": f"phase2-courts.py {court} (recorded; re-derived, not re-run)",
            "observation": observation,
            "functional": bool(functional),
            "candidate": None,
            "target": target,
            "current": bool(is_current),
            "currency": currency,
            "source": f"artifacts/phase2/courts/{court}.json",
        })
        totals["abi"] += 1
        if not rec:
            findings.append(
                f"the ABI-substitution witness {court!r} has no committed record under "
                f"artifacts/phase2/courts/, so its build, run and observation were not read")
            continue
        if registry and court in registry and registry[court] != "pass":
            findings.append(
                f"the ABI-substitution witness {court!r} is recorded {registry[court]!r} in "
                f"artifacts/phase2/COURTS.json, not `pass`")
        if not functional:
            findings.append(
                f"the ABI-substitution witness {court!r} is not functional: {observation!r}")
        if not is_current:
            findings.append(
                f"the ABI-substitution witness {court!r} targets {target!r}, not the candidate "
                f"distribution the corpus links against {sorted(corpus_prefixes)}")

    # Chain B -- the Phase-17 machine-owned downstream corpus, re-established current and functional
    # from the records rather than assumed.
    per_program = ev.get("per_program") or {}
    for prog in WITNESS_PROGRAMS:
        rec = rows.get(prog)
        per = per_program.get(prog)
        candidate = str((rec or {}).get("candidate") or "")
        is_current = candidate == current
        functional = witness_downstream_functional(rec)
        observation = witness_downstream_observation(rec)
        witnesses.append({
            "chain": DOWNSTREAM_CHAIN,
            "witness": prog,
            "built_against": f"{install} (the candidate distribution shell)",
            "run_id_or_mode": (f"phase17 downstream harness courts/phase17/downstream/{prog}/ "
                               f"(recorded; re-derived, not re-run)"),
            "observation": observation,
            "functional": bool(functional),
            "candidate": candidate or None,
            "current": bool(is_current),
            "currency": ("current" if is_current
                         else f"stale: candidate {candidate!r} != current {current!r}"),
            "source": f"courts/phase17/downstream/{prog}/result.json",
        })
        totals["downstream"] += 1
        if rec is None:
            findings.append(
                f"the downstream witness {prog!r} is absent from the Phase-17 corpus, so its "
                f"build, run and observation were not read")
        else:
            for field in WITNESS_REQUIRED_FIELDS:
                if field not in rec:
                    findings.append(
                        f"the downstream witness {prog!r} is missing required field {field!r}")
            if per is None:
                findings.append(
                    f"the downstream witness {prog!r} has no per-program record "
                    f"courts/phase17/downstream/{prog}/result.json")
            elif per != rec:
                findings.append(
                    f"the downstream witness {prog!r} has drifted from "
                    f"courts/phase17/downstream/{prog}/result.json")
            if not functional:
                findings.append(
                    f"the downstream witness {prog!r} is not functional: {observation!r}")
            if not is_current:
                findings.append(
                    f"the downstream witness {prog!r} is stale: candidate {candidate!r} != "
                    f"current {current!r}")

    for row in witnesses:
        totals["witnesses"] += 1
        totals["functional"] += 1 if row["functional"] else 0
        totals["current"] += 1 if row["current"] else 0
    totals["findings"] = len(findings)
    return {
        "candidate": current,
        "install": install,
        "witnesses": witnesses,
        "totals": totals,
        "findings": findings,
    }


def witnesses_problems(ev: dict, derived: dict) -> list[str]:
    """Internal consistency of the witness chain itself, distinct from its findings.

    The findings are real stale or non-functional witnesses; these are defects in the derivation or
    the evidence view, which make the verdict `fail` on their own account rather than letting an
    incomplete read pass.
    """
    problems: list[str] = []
    if not (ev.get("phase2") or {}).get("present"):
        problems.append(
            "the Phase-2 court registry artifacts/phase2/COURTS.json is absent, so the "
            "ABI-substitution witnesses were not read")
    if not (ev.get("corpus") or {}).get("present"):
        problems.append(
            "the Phase-17 corpus forensics/atlas/downstream-corpus.json is absent, so the "
            "downstream witnesses were not read")
    totals = derived["totals"]
    if totals["witnesses"] != totals["abi"] + totals["downstream"]:
        problems.append(
            f"the witness total {totals['witnesses']} is not its ABI and downstream parts: "
            f"{totals['abi']} + {totals['downstream']}")
    expected = len(ABI_WITNESSES) + len(WITNESS_PROGRAMS)
    if totals["witnesses"] != expected:
        problems.append(
            f"the witness set is {totals['witnesses']}, not the {expected} the plan names "
            f"({len(ABI_WITNESSES)} ABI-substitution + {len(WITNESS_PROGRAMS)} downstream)")
    return problems


def witnesses_sensitivity_control(ev: dict) -> dict:
    """Prove the witness chain can fail: inject a stale and two non-functional witnesses.

    Three synthetic evidence views are derived beside the real one: a downstream witness whose
    `candidate` identity is moved off the current release, a downstream witness whose `functional`
    verdict is set `FAIL`, and an ABI-substitution witness whose verdict is set `fail`. The control
    is honest only when the real view is closed (every witness current and functional) *and* all
    three injections are detected; otherwise a court that cannot tell a current, functional witness
    from a stale or failed one cannot pass.
    """
    base = derive_witnesses(ev)
    baseline = (not base["findings"] and base["totals"]["witnesses"] > 0
                and base["totals"]["functional"] == base["totals"]["witnesses"]
                and base["totals"]["current"] == base["totals"]["witnesses"])

    def injected_downstream(mutate) -> dict:
        view = copy.deepcopy(ev)
        programs = (view.get("corpus") or {}).get("programs") or []
        victim = next(r for r in programs if r.get("program") in WITNESS_PROGRAMS)
        mutate(victim)
        # Mutate the per-program record too, so the injection is exactly the defect the control
        # means to inject: a targeted change, not a targeted change plus an aggregate drift.
        per = (view.get("per_program") or {}).get(victim.get("program"))
        if per is not None:
            mutate(per)
        return derive_witnesses(view)

    def injected_abi(mutate) -> dict:
        view = copy.deepcopy(ev)
        victim = ((view.get("phase2") or {}).get("courts") or {}).get("ABI-SUBSTITUTION")
        mutate(victim)
        return derive_witnesses(view)

    def make_stale(rec: dict) -> None:
        rec["candidate"] = "0.0.0"

    def break_functional(rec: dict) -> None:
        rec.setdefault("functional", {})["ok"] = False

    def break_abi(rec: dict) -> None:
        rec["verdict"] = "fail"

    d_stale = injected_downstream(make_stale)
    d_nonfunc = injected_downstream(break_functional)
    d_abi = injected_abi(break_abi)
    caught_stale = any("is stale" in f for f in d_stale["findings"])
    caught_nonfunc = any("is not functional" in f for f in d_nonfunc["findings"])
    caught_abi = any("ABI-substitution" in f and "not functional" in f for f in d_abi["findings"])
    return {
        "baseline_witnesses": base["totals"]["witnesses"],
        "baseline_functional": base["totals"]["functional"],
        "baseline_current": base["totals"]["current"],
        "injected_stale_findings": len(d_stale["findings"]),
        "injected_nonfunctional_findings": len(d_nonfunc["findings"]),
        "injected_abi_fail_findings": len(d_abi["findings"]),
        "caught_stale": caught_stale,
        "caught_nonfunctional": caught_nonfunc,
        "caught_abi_fail": caught_abi,
        "baseline_holds": baseline,
        "honest": bool(baseline and caught_stale and caught_nonfunc and caught_abi),
    }


def substitution_witness_court(name: str) -> dict:
    """`RT-SUBSTITUTION-WITNESS`: record every witness's build, run and observation.

    Stages no probe. It reads the Phase-2 ABI-substitution family -- the one-binary-two-providers
    witness, the `dlvsym` resolution of the authority's declared symbol/version set and the linked
    consumer -- and the Phase-17 machine-owned downstream corpus, re-establishing each program as
    current and functional from its record rather than assuming it. The verdict is `pass` only when
    every witness was read, every witness is functional and current, and the control is honest; a
    stale or non-functional witness is a `finding` and a `fail`.
    """
    ev = read_witness_evidence()
    derived = derive_witnesses(ev)
    control = witnesses_sensitivity_control(ev)
    problems = witnesses_problems(ev, derived)
    findings = list(derived["findings"])
    totals = derived["totals"]
    verdict = "pass" if (
        not problems and control["honest"] and not findings
        and totals["functional"] == totals["witnesses"]
        and totals["current"] == totals["witnesses"]
    ) else "fail"
    return {
        "court": name,
        "probe": "",
        "method": (
            "stages no probe: it records the ABI-substitution witness chain and the machine-owned "
            "downstream corpus witness chain. It reads the Phase-2 ABI-substitution family "
            "(artifacts/phase2/courts/ABI-SUBSTITUTION.json, ABI-LOAD.json and ABI-LINK.json, "
            "cross-checked against the sealed registry artifacts/phase2/COURTS.json) and the "
            "Phase-17 machine-owned corpus (forensics/atlas/downstream-corpus.json, aggregated "
            "from courts/phase17/downstream/<program>/result.json), maintaining no list of its "
            "own (docs/PHASE-20-SUBPHASES.md section 3.5). For each witness it records "
            "`{witness, built_against, run_id_or_mode, observation, functional}`; the court "
            "re-establishes the corpus as current and functional rather than assuming it, "
            "re-deriving each program's required fields, `functional` verdict and `candidate` "
            "identity against the current release and re-checking the aggregate against the "
            "per-program record. The Phase-17 driver has no cheap verify/currency mode -- it "
            "re-runs multi-minute builds and live TLS servers -- so the court re-derives rather "
            "than re-runs and proves currency by candidate identity, which it says in its "
            "`reestablishment` block. The court is pass only when every witness is current and "
            "functional and a synthetic view with a stale witness and one with a non-functional "
            "witness are both detected (section 3.2)."
        ),
        "frf_declarable": False,
        "frf_exclusion": (
            "the substitution-witness court reads the Phase-2 ABI courts' committed records and "
            "the Phase-17 machine-owned corpus and stages no artifacts/phase20/probes/ pair, so it "
            "takes no transcript to diff and carries no FRF declaration"
        ),
        "witness_authority": [rel(PLAN), rel(DOWNSTREAM_README)],
        "candidate_version": derived["candidate"],
        "candidate_install": derived["install"],
        "reestablishment": {
            "mode": "re-derived from the machine-owned records",
            "re_ran": [],
            "harness": rel(DOWNSTREAM_RUNNER),
            "why": (
                "courts/phase17/downstream/run_all.sh has no cheap verify/currency mode: without "
                "--build it still drives each program's version, ldd, live-TLS probe and test "
                "suite, and with --build it also recompiles them. The court therefore does not "
                "re-run the corpus in the gate path; it re-establishes currency and functional "
                "status from the machine-owned records and proves currency by candidate "
                "identity, exactly as docs/PHASE-20-SUBPHASES.md section 3.5 permits."
            ),
        },
        "witnesses": derived["witnesses"],
        "totals": totals,
        "findings": findings,
        "control": control,
        "problems": problems,
        "verdict": verdict,
    }


# ---------------------------------------------------------------------------
# `CUSTODIAN-BOUNDARY-REGISTER` -- the stratum's own non-claims, bound to the courts
# ---------------------------------------------------------------------------

def read_doc(path: Path) -> str:
    """A committed document's text, or `""` when it is absent.

    The bounded side of the register is read as text and interrogated for the non-claim it states;
    a missing document is `""`, so the row that cites it drifts rather than the court aborting.
    """
    return path.read_text(encoding="utf-8") if path.is_file() else ""


def _l9_present(record: dict) -> bool | None:
    """Whether the maturity record's libcrypto ladder records the seal target present."""
    library = (record.get("libraries") or {}).get(LIBCRYPTO) or {}
    for row in library.get("levels") or []:
        if row.get("level") == SEAL_TARGET:
            return row.get("evidence_present")
    return None


def bounded_evidence() -> dict:
    """The bounded side's evidence, read from the constitution/limitations artefacts.

    Every value is a fact about a committed artefact -- a stated non-claim, the measured unsafe
    footprint, the growth-ceiling schema or the seal document's presence -- so the register's
    `bounded` rows can be compared exactly and a document that stopped stating its non-claim, or a
    footprint that moved, is a drift rather than a register that silently describes the previous
    generation.
    """
    non_claims = read_doc(NON_CLAIMS_DOC)
    fips = read_doc(FIPS_CLAIMS_DOC)
    unsafe = read_doc(UNSAFE_DOC)
    plan = read_doc(PLAN)
    footprint = read_json("forensics/atlas/unsafe-footprint.json") or {}
    totals = (footprint.get("body") or {}).get("totals") or {}
    by_class = totals.get("by_class") or {}
    bounds = read_json("artifacts/phase18/unsafe-bounds.json") or {}
    return {
        "non_claims_present": NON_CLAIMS_DOC.is_file(),
        "non_claims_universal_section": "No universal claims from finite evidence" in non_claims,
        "non_claims_scope_adjacent":
            "authority / version / build profile / platform scope" in non_claims,
        "fips_claims_present": FIPS_CLAIMS_DOC.is_file(),
        "fips_label_present": "NOT FIPS VALIDATED" in fips,
        "fips_validation_external": "external certification process" in fips,
        "unsafe_doc_present": UNSAFE_DOC.is_file(),
        "unsafe_measured_not_asserted": "measured, not asserted" in unsafe,
        "unsafe_not_a_memory_safety_claim": "not a memory-safety claim" in unsafe,
        "unsafe_footprint_present": UNSAFE_FOOTPRINT.is_file(),
        "unsafe_footprint_sites": totals.get("unsafe_sites"),
        "unsafe_footprint_extern_c": totals.get("extern_c_fns"),
        "unsafe_core_sites": (by_class.get("core") or {}).get("unsafe_sites"),
        "unsafe_boundary_sites": (by_class.get("boundary") or {}).get("unsafe_sites"),
        "unsafe_bounds_present": UNSAFE_BOUNDS.is_file(),
        "unsafe_bounds_schema": bounds.get("schema"),
        "unsafe_bounds_core_modules": len(bounds.get("bounds") or {}),
        "plan_present": PLAN.is_file(),
        "plan_names_l9_seal": "L9 high-assurance custodian seal" in plan,
        "seal_doc_present": CUSTODIAN_SEAL_DOC.is_file(),
    }


def court_coverage(record: dict) -> set[str]:
    """The surface keys a court covers, from its own record -- and only when it passed.

    A non-`pass` court covers nothing: its row is still in the registry but no surface may lean on
    it. That is what makes "a claimed row whose court no longer covers it" detectable -- the
    coverage set for that court goes empty (or loses the key).
    """
    if record.get("verdict") != "pass":
        return set()
    court = record.get("court")
    if court == CUSTODIAN_MATURITY:
        return {"custodian.maturity.ladder"} if record.get("highest_present") else set()
    if court == RECEIPT_CLOSURE:
        return {"custodian.closure.join"}
    if court == CUSTODIAN_RESIDUALS:
        return {"custodian.residuals.disposition"}
    if court == SUBSTITUTION_WITNESS:
        keys: set[str] = set()
        totals = record.get("totals") or {}
        if totals.get("abi"):
            keys.add("custodian.witness.abi")
        if totals.get("downstream"):
            keys.add("custodian.witness.downstream")
        return keys
    return set()


def register_evidence(record: dict) -> dict:
    """The court record's classification evidence, as the flat vocabulary the register cites.

    The register's `evidence` block is a dict of `{key: expected}` over this view, and the court
    compares them exactly, so a stated count or evidence value that moves is a failure rather than a
    register that silently describes the previous generation.
    """
    court = record.get("court")
    ev: dict = {"verdict": record.get("verdict")}
    if court == CUSTODIAN_MATURITY:
        ev["highest_present"] = record.get("highest_present")
        ev["seal_target_level"] = record.get("seal_target_level")
        ev["seal_target_present"] = _l9_present(record)
        ev["findings_count"] = len(record.get("findings") or [])
    elif court == RECEIPT_CLOSURE:
        totals = record.get("totals") or {}
        ev["obligations"] = totals.get("obligations")
        ev["obligations_joined"] = totals.get("obligations_joined")
        ev["gaps"] = totals.get("gaps")
        ev["blockers"] = totals.get("blockers")
        ev["findings_count"] = len(record.get("findings") or [])
    elif court == CUSTODIAN_RESIDUALS:
        totals = record.get("totals") or {}
        ev["residuals"] = totals.get("residuals")
        ev["un_dispositioned"] = totals.get("un_dispositioned")
        ev["unknown_intersecting"] = totals.get("unknown_intersecting")
        ev["findings_count"] = len(record.get("findings") or [])
    elif court == SUBSTITUTION_WITNESS:
        totals = record.get("totals") or {}
        ev["witnesses"] = totals.get("witnesses")
        ev["functional"] = totals.get("functional")
        ev["current"] = totals.get("current")
        ev["findings_count"] = len(record.get("findings") or [])
    return ev


def verify_register_surface(row: dict, registry: dict[str, dict], coverage: dict[str, set[str]],
                            covered_any: set[str], bounded: dict) -> list[str]:
    """Every way one register row drifts from the evidence that establishes it.

    A `claimed` row whose court is not registered or no longer passes, or that no longer covers a
    surface key it names, is a drift. A `bounded` row that names a court, or that a passing court
    now covers, is a drift. And a row -- either verdict -- whose cited evidence no longer equals the
    value the artefact shows is a drift; for a `claimed` row the artefact is the court record, for
    a `bounded` row it is the constitution/limitations view. This is the register's whole subject.
    """
    findings: list[str] = []
    sid = row.get("id", "<unnamed>")
    verdict = row.get("verdict")
    keys = row.get("surface_keys") or []
    court = row.get("court")
    if verdict not in REGISTER_VERDICTS:
        findings.append(f"{sid}: verdict {verdict!r} is not one of {list(REGISTER_VERDICTS)}")
        return findings
    if verdict == "bounded":
        if court is not None:
            findings.append(f"{sid}: a bounded row must name no court (got {court!r})")
        for key in keys:
            if key in covered_any:
                findings.append(
                    f"{sid}: recorded bounded but a passing court now covers {key!r}")
        for key, expected in (row.get("evidence") or {}).items():
            if key not in bounded:
                findings.append(f"{sid}: evidence key {key!r} has no value in the bounded view")
            elif bounded[key] != expected:
                findings.append(
                    f"{sid}: evidence {key} = {expected!r} but the bounded view shows "
                    f"{bounded[key]!r}")
        return findings
    rec = registry.get(court)
    if rec is None:
        findings.append(f"{sid}: cites court {court!r} which is not registered")
        return findings
    if rec.get("verdict") != "pass":
        findings.append(f"{sid}: recorded claimed but its court {court} is {rec.get('verdict')}")
    not_covered = sorted(k for k in keys if k not in coverage.get(court, set()))
    if not_covered:
        findings.append(f"{sid}: recorded claimed but {court} does not cover {not_covered}")
    evidence = register_evidence(rec)
    for key, expected in (row.get("evidence") or {}).items():
        if key not in evidence:
            findings.append(f"{sid}: evidence key {key!r} has no value in the {court} record")
        elif evidence[key] != expected:
            findings.append(
                f"{sid}: evidence {key} = {expected!r} but {court} shows {evidence[key]!r}")
    return findings


def register_findings(doc: dict, records: list[dict], bounded: dict) -> list[str]:
    """Every drift finding a register document shows against a court registry and the bounded view.

    A pure function of its three inputs, so the sensitivity control can mutate a copy and re-run it
    without touching the tree.
    """
    registry = {r.get("court"): r for r in records}
    coverage = {r.get("court"): court_coverage(r) for r in records}
    covered_any: set[str] = set()
    for keys in coverage.values():
        covered_any |= keys
    findings: list[str] = []
    for row in doc.get("surfaces") or []:
        findings += verify_register_surface(row, registry, coverage, covered_any, bounded)
    return findings


def register_sensitivity_control(doc: dict, records: list[dict], bounded: dict) -> dict:
    """Prove the register can fail: inject a non-passing court and a drifted boundary.

    Two synthetic views are derived beside the real one -- a claimed row's court turned non-passing,
    and a bounded row's cited evidence moved off the value its artefact shows -- and each must be
    detected. The control is honest only when the real register shows **zero findings** (specificity)
    *and* both injections are caught; otherwise a court that cannot tell a passing court from a
    failed one, or evidence from its absence, would pass vacuously.
    """
    base = register_findings(doc, records, bounded)
    specificity = not base

    claimed = next((r for r in doc.get("surfaces") or [] if r.get("verdict") == "claimed"), None)
    injected_records = copy.deepcopy(records)
    for rec in injected_records:
        if claimed is not None and rec.get("court") == claimed.get("court"):
            rec["verdict"] = "fail"
    caught_claimed = any("is fail" in f or "does not cover" in f
                         for f in register_findings(doc, injected_records, bounded))

    drifted = copy.deepcopy(doc)
    bounded_row = next(
        (r for r in drifted.get("surfaces") or []
         if r.get("verdict") == "bounded" and r.get("evidence")),
        None,
    )
    if bounded_row is not None:
        key = next(iter(bounded_row["evidence"]))
        value = bounded_row["evidence"][key]
        if isinstance(value, bool):
            bounded_row["evidence"][key] = not value
        elif isinstance(value, int):
            bounded_row["evidence"][key] = value + 1
        else:
            bounded_row["evidence"][key] = f"{value}-drifted"
    caught_bounded = any("bounded view shows" in f
                         for f in register_findings(drifted, records, bounded))

    return {
        "baseline_findings": len(base),
        "injected_claimed_court": None if claimed is None else claimed.get("court"),
        "injected_claimed_findings": len(register_findings(doc, injected_records, bounded)),
        "injected_bounded_row": None if bounded_row is None else bounded_row.get("id"),
        "injected_bounded_findings": len(register_findings(drifted, records, bounded)),
        "specificity_holds": specificity,
        "caught_claimed_court": caught_claimed,
        "caught_bounded_drift": caught_bounded,
        "honest": bool(specificity and caught_claimed and caught_bounded),
    }


def register_court(name: str, records: list[dict]) -> dict:
    """`CUSTODIAN-BOUNDARY-REGISTER`: bind the authored register to the live courts registry.

    Reads the four already-computed probe-court records, the authored register and the
    constitution/limitations artefacts, re-derives each row's expected evidence and reports every
    drift. A non-empty `findings` or `problems` is `fail`.
    """
    if not CUSTODIAN_BOUNDARY_REGISTER.is_file():
        return {"court": name, "probe": "", "verdict": "fail", "stage": "register-missing",
                "frf_declarable": False,
                "frf_exclusion": "the register court re-reads the courts registry; it stages no "
                                  "probe pair",
                "detail": rel(CUSTODIAN_BOUNDARY_REGISTER)}
    doc = json.loads(CUSTODIAN_BOUNDARY_REGISTER.read_text(encoding="utf-8"))
    surfaces = doc.get("surfaces") or []
    bounded = bounded_evidence()
    findings = register_findings(doc, records, bounded)
    problems: list[str] = []
    if doc.get("schema") != CUSTODIAN_BOUNDARY_REGISTER_SCHEMA:
        problems.append(
            f"schema {doc.get('schema')!r} != {CUSTODIAN_BOUNDARY_REGISTER_SCHEMA!r}")
    coverage = {r.get("court"): court_coverage(r) for r in records}
    cited = {r.get("court") for r in surfaces if r.get("verdict") == "claimed"}
    for court, keys in coverage.items():
        if keys and court not in cited:
            problems.append(
                f"court {court} passes and covers {len(keys)} surface(s) but no claimed "
                f"register row cites it")
    counts = {verdict: 0 for verdict in REGISTER_VERDICTS}
    for row in surfaces:
        if row.get("verdict") in counts:
            counts[row["verdict"]] += 1
    declared = doc.get("verdicts") or {}
    for verdict in REGISTER_VERDICTS:
        if declared.get(verdict) != counts[verdict]:
            problems.append(
                f"declared {verdict} count {declared.get(verdict)!r} but the register has "
                f"{counts[verdict]} row(s)")
    if declared.get("total") != len(surfaces):
        problems.append(f"declared total {declared.get('total')!r} but the register has "
                        f"{len(surfaces)} row(s)")
    control = register_sensitivity_control(doc, records, bounded)
    verdict = "pass" if (not problems and not findings and control["honest"]) else "fail"
    return {
        "court": name,
        "probe": "",
        "method": (
            "stages no probe: it re-reads the live courts registry (the four custodian courts "
            "above) and the authored register artifacts/phase20/custodian-boundary-register.json, "
            "and fails the stratum if any recorded claimed/bounded verdict, surface key or cited "
            "evidence value has drifted from what the courts and the constitution/limitations "
            "artefacts show (docs/PHASE-20-SUBPHASES.md section 3.6). A claimed row whose court no "
            "longer passes or no longer covers the surface, a bounded row a passing court now "
            "covers, and a bounded row whose cited evidence no longer matches docs/NON_CLAIMS.md, "
            "docs/FIPS_CLAIMS.md, docs/UNSAFE.md or the unsafe-footprint growth ceiling are all "
            "findings. It is the stratum's own answer to docs/NON_CLAIMS.md: no FIPS validation, "
            "no universal parity from finite evidence, and memory safety measured rather than "
            "established."
        ),
        "frf_declarable": False,
        "frf_exclusion": (
            "the register re-reads the courts registry and the constitution/limitations artefacts "
            "and stages no artifacts/phase20/probes/ pair, so it takes no transcript to diff and "
            "carries no FRF declaration"
        ),
        "register": {
            "path": rel(CUSTODIAN_BOUNDARY_REGISTER),
            "schema": doc.get("schema"),
            "sha256": sha256_file(CUSTODIAN_BOUNDARY_REGISTER),
            "counts": counts,
            "total": len(surfaces),
        },
        "surfaces": [
            {"id": r.get("id"), "verdict": r.get("verdict"), "court": r.get("court"),
             "surface_keys": r.get("surface_keys") or []}
            for r in surfaces
        ],
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
    work = REPO_ROOT / "court" / "phase20"
    work.mkdir(parents=True, exist_ok=True)

    records: list[dict] = []
    for name, filename in COURTS:
        # 20.1's maturity court, 20.2's receipt-closure court, 20.3's residual-disposition court,
        # 20.4's substitution-witness court and 20.5's boundary register stage no probe: their
        # subjects are committed evidence, so they are computed here rather than read back from
        # disk, and no digest cycle forms. The register is handed the four records computed above it
        # in this one run, so it re-reads the claimed side without the registry embedding itself.
        # Phase 20 owns no export, so no differential probe over a symbol set is its evidence.
        if name == CUSTODIAN_MATURITY:
            records.append(custodian_maturity_court(name))
            continue
        if name == RECEIPT_CLOSURE:
            records.append(receipt_closure_court(name))
            continue
        if name == CUSTODIAN_RESIDUALS:
            records.append(residual_court(name))
            continue
        if name == SUBSTITUTION_WITNESS:
            records.append(substitution_witness_court(name))
            continue
        if name == BOUNDARY_REGISTER:
            records.append(register_court(name, records))
            continue
        src = REPO_ROOT / "courts" / "phase20" / str(filename)
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
            "`RT-CUSTODIAN-MATURITY` is 20.1's court: it stages no probe and derives the L0-L9 "
            "maturity ladder of docs/RELEASE_GATES.md section 3 for libcrypto and libssl from "
            "committed evidence -- each stratum's seal and court registry, the provider census "
            "and its coverage join, the export court-coverage join and the Phase-17 downstream "
            "corpus. It records, per level per library, `{level, evidence_present, "
            "source_artifacts}`, and names only the highest level whose cumulative evidence is "
            "present. On the current tree that is L8 (downstream custodian court) for both "
            "libraries; L9 (high-assurance custodian seal) is absent because it is the level "
            "Phase 20 itself is establishing, and the gap is recorded as a finding, so the "
            "ledger's `custodian-maturity` property reads NOT_CLAIMED with findings_present. The "
            "court is pass as an instrument -- it derived the ladder, its evidence is committed, "
            "and a synthetic evidence view with a prerequisite removed detects the gap -- NOT "
            "because the ladder reaches L9. A passing RT-CUSTODIAN-MATURITY must never be read as "
            "'L9 custodian seal achieved'. `RT-RECEIPT-CLOSURE` is 20.2's court: it stages no probe "
            "and joins every obligation the in-scope strata recorded `implemented` or closed to the "
            "FRF receipt that proves it, requiring a receipt, two adjudicated challenges and a "
            "zero-blocker `sensitivity-backed` claim at the current candidate identity for every "
            "FRF-declarable court each stratum ran, and joining each implemented export to its "
            "courts through the court-coverage atlas. On the current tree the closure is complete "
            "-- every stratum's chain is complete, the covering claims carry zero blockers and no "
            "export is courted by no court -- so it records zero findings; a real gap would be a "
            "finding and a `fail`, and a synthetic evidence view with a receipt removed, a claim "
            "blocker injected or a stale candidate identity detects the gap. `RT-CUSTODIAN-RESIDUALS` "
            "is 20.3's court: it stages no probe and dispositions every residual the earlier strata "
            "and the FRF store record -- the Phase-22 cross-plane census and the closure's "
            "`unknown_intersecting_root_keys`, the Phase-1 completeness and symbol reconciliation, "
            "the divergence, ownership-transition and prerequisite planes, the two boundary "
            "registers, the "
            "hostile/CT/ASan/Miri receipts, the unsafe-footprint ceiling and the FRF store's own "
            "residuals. For each residual it records `{source, id, disposition, "
            "intersects_production_profile, state}`; every residual must carry a disposition and no "
            "`UNKNOWN` residual may intersect the claimed production profile. On the current tree "
            "there are 334 `UNKNOWN` residual records -- the 167 POD_NAME_NOT_IN_ATLAS names the "
            "pod-contract plane carries, re-projected by two registers (the Phase-22 cross-plane "
            "census and the checkpoint's named `UNKNOWN` sets) -- and the closure records that "
            "zero of them intersect a declared compatibility root, so the court records zero "
            "findings and says so precisely; a real un-dispositioned "
            "or `UNKNOWN`-intersecting residual would be a finding and a `fail`, and a synthetic "
            "evidence view with an un-dispositioned residual and one with an `UNKNOWN`-intersecting "
            "residual detects the gap while an `UNKNOWN` that does not intersect does not. "
            "`RT-SUBSTITUTION-WITNESS` is 20.4's court: it stages no probe and records the "
            "ABI-substitution witness chain and the machine-owned downstream corpus witness chain "
            "-- the Phase-2 ABI-substitution family (ABI-SUBSTITUTION, ABI-LOAD and ABI-LINK, read "
            "from artifacts/phase2/courts/ and cross-checked against artifacts/phase2/COURTS.json) "
            "and the six Phase-17 downstream programs (curl, git, haproxy, nginx, openssh and "
            "python), which it re-establishes as current and functional rather than assuming. For "
            "each witness it records `{witness, built_against, run_id_or_mode, observation, "
            "functional}`; on the current tree all nine witnesses are current and functional "
            "(candidate 0.0.24), so the court records zero findings. The Phase-17 driver has no "
            "cheap verify/currency mode, so the court re-derives currency and functional status "
            "from the machine-owned records and proves currency by candidate identity rather than "
            "re-running the harnesses, and says exactly that in its `reestablishment` block; a "
            "stale or non-functional witness would be a finding and a `fail`, and synthetic views "
            "with a stale witness and with non-functional downstream and ABI witnesses are all "
            "detected. `CUSTODIAN-BOUNDARY-REGISTER` is 20.5's court: it stages no probe and binds "
            "the authored register artifacts/phase20/custodian-boundary-register.json, which "
            "records, per surface, whether it is `claimed` (a passing court covers it) or `bounded` "
            "(explicitly outside this stratum). It re-reads the four custodian courts' records (the "
            "claimed side) and the constitution/limitations artefacts -- docs/NON_CLAIMS.md, "
            "docs/FIPS_CLAIMS.md, docs/UNSAFE.md and the unsafe-footprint growth ceiling (the "
            "bounded side) -- and fails the stratum if a recorded boundary has drifted from its "
            "evidence. The three load-bearing non-claims are carried as bounded rows: no FIPS "
            "validation, no universal parity from finite evidence, and memory safety measured "
            "rather than established. On the current tree the register records zero findings "
            "(specificity), and a synthetic view with a claimed row's court turned non-passing and "
            "one with a bounded row's cited evidence drifted are both detected. This is the last of "
            "the five units, so no court is `pending`. "
            "This stratum owns no "
            "exported symbol, so no differential probe over a symbol set is its evidence: the "
            "subject is the custodian claim over a finished implementation, with no FIPS "
            "validation, no universal-parity claim from finite evidence and no claim that memory "
            "safety is established. docs/PHASE-20-SUBPHASES.md sections 1, 3 and 4 record the "
            "measurement and the courts."
        ),
    }

    inputs = [
        InputRef(name="phase-20-plan", path=PLAN),
        InputRef(name="release-gates", path=LEVELS_DOC),
        InputRef(name="custodian-contract", path=CUSTODIAN_CONTRACT),
        InputRef(name="parity-model", path=PARITY_MODEL),
        InputRef(name="phase1-completeness", path=PHASE1_COMPLETENESS),
        InputRef(name="phase2-courts", path=PHASE2_COURTS),
        InputRef(name="phase17-courts", path=PHASE17_COURTS),
        InputRef(name="phase18-courts", path=PHASE18_COURTS),
        InputRef(name="downstream-corpus", path=DOWNSTREAM),
        InputRef(name="downstream-runner", path=DOWNSTREAM_RUNNER),
        InputRef(name="downstream-readme", path=DOWNSTREAM_README),
        InputRef(name="phase2-abi-substitution", path=PHASE2_COURT_DIR / "ABI-SUBSTITUTION.json"),
        InputRef(name="phase2-abi-load", path=PHASE2_COURT_DIR / "ABI-LOAD.json"),
        InputRef(name="phase2-abi-link", path=PHASE2_COURT_DIR / "ABI-LINK.json"),
        InputRef(name="provider-algorithms", path=PROVIDERS),
        InputRef(name="provider-court-coverage", path=PROVIDER_COVERAGE),
        InputRef(name="court-coverage", path=COURT_COVERAGE),
        InputRef(name="court-coverage-rows", path=COURT_COVERAGE_ROWS),
        InputRef(name="divergence-obligations", path=DIVERGENCE_OBLIGATIONS),
        InputRef(name="prerequisites", path=PREREQUISITES),
        InputRef(name="phase22-reconciliation", path=PHASE22_RECONCILIATION),
        InputRef(name="phase22-closure", path=PHASE22_CLOSURE),
        InputRef(name="phase22-gemel", path=PHASE22_GEMEL),
        InputRef(name="surface-reconciliation", path=SURFACE_RECONCILIATION),
        InputRef(name="hostile-boundary-register", path=HOSTILE_BOUNDARY_REGISTER),
        InputRef(name="performance-boundary-register", path=PERFORMANCE_BOUNDARY_REGISTER),
        InputRef(name="custodian-boundary-register", path=CUSTODIAN_BOUNDARY_REGISTER),
        InputRef(name="non-claims", path=NON_CLAIMS_DOC),
        InputRef(name="fips-claims", path=FIPS_CLAIMS_DOC),
        InputRef(name="unsafe-policy", path=UNSAFE_DOC),
        InputRef(name="asan-closure", path=ASAN_CLOSURE),
        InputRef(name="miri-tcb", path=MIRI_TCB),
        InputRef(name="unsafe-footprint", path=UNSAFE_FOOTPRINT),
        InputRef(name="unsafe-bounds", path=UNSAFE_BOUNDS),
        InputRef(name="gen-frf-courts", path=GEN_FRF_COURTS_SRC),
        InputRef(name="frf-readme", path=FRF_README),
        InputRef(name="gemel-trajectory", path=GEMEL_TRAJECTORY),
    ]
    doc = envelope(kind="phase20-courts", authority=auth.id, inputs=inputs,
                   body=body, generator=GENERATOR)
    write_json(OUT, doc)

    for r in records:
        if r["verdict"] == "pass" and r["court"] == CUSTODIAN_MATURITY:
            c = r["control"]
            print(f"  {r['court']:<32} pass   (no probe, ladder -> {r['highest_present']} "
                  f"[seal target {r['seal_target_level']} absent], "
                  f"{len(r['findings'])} finding(s); control honest={c['honest']} "
                  f"baseline={c['baseline_highest']} "
                  f"injected-core->{c['injected_core_highest']} "
                  f"injected-downstream->{c['injected_downstream_highest']})")
            for f in r["findings"]:
                print(f"      finding: {f}")
        elif r["verdict"] == "pass" and r["court"] == RECEIPT_CLOSURE:
            c = r["control"]
            t = r["totals"]
            print(f"  {r['court']:<32} pass   (no probe, closure: "
                  f"{t['obligations_joined']}/{t['obligations']} obligation(s) joined "
                  f"({t['obligations_to_receipt']} to a receipt, "
                  f"{t['obligations_to_reference_basis']} to the reference basis), "
                  f"{t['receipts']} receipt(s), {t['blockers']} blocker(s) "
                  f"({t['store_blockers']} in the whole store), "
                  f"{t['gaps']} gap(s), {len(r['findings'])} finding(s); "
                  f"control honest={c['honest']} "
                  f"injected-missing-receipt->{c['injected_missing_receipt_gaps']} gap(s) "
                  f"injected-blocker->{c['injected_blocker_count']})")
            for f in r["findings"]:
                print(f"      finding: {f}")
        elif r["verdict"] == "pass" and r["court"] == CUSTODIAN_RESIDUALS:
            c = r["control"]
            t = r["totals"]
            print(f"  {r['court']:<32} pass   (no probe, disposition: "
                  f"{t['sources_present']}/{t['sources']} source(s) read, "
                  f"{t['residuals']} residual record(s) across the sources "
                  f"({t['un_dispositioned']} un-dispositioned, {t['unknown']} UNKNOWN, "
                  f"{t['unknown_intersecting']} UNKNOWN intersecting), "
                  f"{len(r['findings'])} finding(s); control honest={c['honest']} "
                  f"injected-un-dispositioned->{c['injected_un_dispositioned_findings']} finding(s) "
                  f"injected-unknown-intersecting->{c['injected_unknown_intersecting_findings']} "
                  f"finding(s) injected-unknown-clean->"
                  f"{c['injected_unknown_not_intersecting_findings']} finding(s))")
            for f in r["findings"]:
                print(f"      finding: {f}")
        elif r["verdict"] == "pass" and r["court"] == SUBSTITUTION_WITNESS:
            c = r["control"]
            t = r["totals"]
            print(f"  {r['court']:<32} pass   (no probe, witnesses: "
                  f"{t['witnesses']} ({t['abi']} ABI-substitution + {t['downstream']} downstream), "
                  f"{t['functional']} functional, {t['current']} current, "
                  f"{len(r['findings'])} finding(s); control honest={c['honest']} "
                  f"injected-stale->{c['injected_stale_findings']} finding(s) "
                  f"injected-nonfunctional->{c['injected_nonfunctional_findings']} finding(s) "
                  f"injected-abi-fail->{c['injected_abi_fail_findings']} finding(s))")
            for f in r["findings"]:
                print(f"      finding: {f}")
        elif r["verdict"] == "pass" and r["court"] == BOUNDARY_REGISTER:
            c = r["control"]
            counts = r["register"]["counts"]
            print(f"  {r['court']:<32} pass   (no probe, register: "
                  f"{counts['claimed']} claimed + {counts['bounded']} bounded = "
                  f"{r['register']['total']} surface(s), {len(r['findings'])} finding(s); "
                  f"control honest={c['honest']} specificity={c['specificity_holds']} "
                  f"injected-claimed-court->{c['injected_claimed_findings']} finding(s) "
                  f"injected-bounded-drift->{c['injected_bounded_findings']} finding(s))")
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
