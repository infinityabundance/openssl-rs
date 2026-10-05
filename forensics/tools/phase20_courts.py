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

The pending courts
------------------
The other three courts the plan names are not runnable yet; each is registered in `PENDING_COURTS`
with the subphase that lands its instrument and what it will drive, so "nothing registered" is a
stated distance rather than a court quietly dropped:

  * `RT-CUSTODIAN-RESIDUALS` (20.3) — the disposition of every residual, requiring zero `UNKNOWN`
    intersecting the claimed production profile, so a newly discovered un-dispositioned residual is
    a `fail` rather than a silent addition;
  * `RT-SUBSTITUTION-WITNESS` (20.4) — the ABI-substitution witness chain and the machine-owned
    downstream corpus witness chain: binaries built against the admitted authority run unmodified
    against the candidate, over the Phase-17 corpus the court re-establishes as current and
    functional;
  * `CUSTODIAN-BOUNDARY-REGISTER` (20.5) — the register that records what is claimed, what is
    bounded, and the explicit non-claims (no FIPS validation, no universal parity from finite
    evidence, memory safety measured-not-established), and that fails the stratum if a recorded
    boundary drifts from its evidence.

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

# The courts, in the order they land. `(name, probe filename)`, and the probe is declared in the
# same commit as the entry, so a runner that names a probe which does not exist cannot be
# committed. `RT-CUSTODIAN-MATURITY` and `RT-RECEIPT-CLOSURE` stage no probe -- their subjects are
# committed evidence, not transcript pairs -- so their probes are `None`, exactly as Phase 19's
# register court is. **Empty of later courts at 20.2**: 20.3 through 20.5 land the other three
# instruments and add their rows.
COURTS: list[tuple[str, str | None]] = [
    (CUSTODIAN_MATURITY, None),
    (RECEIPT_CLOSURE, None),
]

# A court the plan names and this stratum cannot run yet. Each entry names the subphase that lands
# the instrument and what the court will drive, so "nothing registered" is a stated distance rather
# than a court quietly dropped. `RT-CUSTODIAN-MATURITY` left this table when 20.1 landed its
# derivation and `RT-RECEIPT-CLOSURE` when 20.2 landed its join.
PENDING_COURTS: dict[str, str] = {
    "RT-CUSTODIAN-RESIDUALS": (
        "20.3 lands the residual disposition; it requires every residual to be dispositioned and "
        "zero `UNKNOWN` to intersect the claimed production profile, so a newly discovered "
        "un-dispositioned residual is a `fail`"
    ),
    "RT-SUBSTITUTION-WITNESS": (
        "20.4 lands the substitution witness; it runs binaries built against the admitted "
        "authority unmodified against the candidate over the machine-owned Phase-17 downstream "
        "corpus, which it re-establishes as current and functional, and records each witness's "
        "build, run and observation"
    ),
    "CUSTODIAN-BOUNDARY-REGISTER": (
        "20.5 lands the register; it records what is claimed, what is bounded, and the explicit "
        "non-claims (no FIPS validation, no universal parity from finite evidence, memory safety "
        "measured-not-established), and checks that every recorded boundary still matches the "
        "evidence that establishes it"
    ),
}

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
          ("docs/PHASE-20-CUSTODIAN-SEAL.md",)),
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
        # 20.1's maturity court and 20.2's receipt-closure court stage no probe: their subjects are
        # committed evidence, so they are computed here rather than read back from disk, and no
        # digest cycle forms. Phase 20 owns no export, so no differential probe over a symbol set is
        # its evidence.
        if name == CUSTODIAN_MATURITY:
            records.append(custodian_maturity_court(name))
            continue
        if name == RECEIPT_CLOSURE:
            records.append(receipt_closure_court(name))
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
            "blocker injected or a stale candidate identity detects the gap. The other three courts "
            "(`RT-CUSTODIAN-RESIDUALS` 20.3, `RT-SUBSTITUTION-WITNESS` 20.4 and "
            "`CUSTODIAN-BOUNDARY-REGISTER` 20.5) are named and `pending`. This stratum owns no "
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
        InputRef(name="downstream-corpus", path=DOWNSTREAM),
        InputRef(name="provider-algorithms", path=PROVIDERS),
        InputRef(name="provider-court-coverage", path=PROVIDER_COVERAGE),
        InputRef(name="court-coverage", path=COURT_COVERAGE),
        InputRef(name="court-coverage-rows", path=COURT_COVERAGE_ROWS),
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
