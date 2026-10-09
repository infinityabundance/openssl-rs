#!/usr/bin/env python3
"""openssl-rs — Phase 25.8, the unsafe reduction.

Phase 25 is the memory-safety stratum (`docs/RELEASE_GATES.md` section 1,
`docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md`). This module is 25.8's instrument, in two parts.

Part one: the reduction worklist
--------------------------------
Over the reachable, compiler-derived unsafe sites of the exact admitted candidate, it records per
candidate class the proposed safe replacement, the argument that it would preserve behaviour, the
risk that it touches the ABI, and why the venue cannot apply it. A candidate the venue cannot prove
safe stays on the worklist with its reason -- the merging of blocks or the consolidation of pointers
into one helper is never a reduction, and a worklist with zero applied reductions is acceptable.

The worklist is a **local-replacement feasibility census**, not an impossibility result: it records,
for each of the ten local-substitution patterns, that **none of the operations screened against it
was locally replaceable without changing the public surface or behaviour**. That is **not** a claim
that the rest of the core is irreducible -- the sparse-array reconstruction (part two below) showed a
subsystem the local patterns could not touch was reducible by a representation-level reconstruction.
A structural (representation-level) reconstruction is a **separate campaign**, recorded in
`forensics/memory-safety/unsafe-reconstruction.json`.

Part two: the safe-core reconstruction
--------------------------------------
A **proof-by-construction** that a significant, genuinely internal unsafe mechanism has been
replaced with safe Rust while the observable OpenSSL behaviour is conserved. A reconstruction is
admissible only if it is **ELIMINATED** (the dangerous operation is gone from the census) or
**RELOCATED_TO_BOUNDARY** (it survives only in an unavoidable, isolated FFI boundary, and the site
that disappeared named the interior mechanism); it is **HIDDEN** -- and refused -- when a claimed
reduction is a mere wrapper that leaves the dangerous operation where it was. So the tool reads a
committed **reconstruction declaration** (`forensics/memory-safety/unsafe-reconstruction.json`, the
authored record of which sites the reconstruction removed and how each is classified), re-derives the
before/after counts from the live census plus the removed set, and refuses:

  * any operation classified `HIDDEN` (a wrapper), or any "removed" site still present in the live
    census (the operation was not removed at all);
  * any claimed count that is not `after + removed` (a typed count);
  * any downstream verdict that moved: the Phase-24 headline -- the DROP_IN_PASS verdicts, the
    `p1000-run.json` ladder and the eight functional workloads -- is re-derived from the committed
    Phase-24 measurement and compared with the frozen baseline, so a reconstruction that changed what
    downstream observes is inadmissible;
  * a weakened safety lint (the frozen policy is read and checked);
  * a record that **conflates a count increase with a reduction**, or that **drops the negative
    result**: an attempted conversion whose measured operation count rose must be recorded (with its
    before/after counts and the verdict `REVERTED_NOT_A_REDUCTION`), never omitted and never labelled
    a reduction. The campaign's success **axis** -- dangerous operations ELIMINATED, a smaller
    auditable residual boundary, and HIDDEN=0 -- is not the total operation count, and the two are
    stated side by side and never conflated.

So 25.8 is a **pure function of committed inputs**: the committed 25.1 census, the committed 25.7
exposure classification, the committed reconstruction declaration, the committed Phase-24 downstream
measurement, the committed source spans and the frozen lint policy. It compiles nothing -- no
compiler, no clippy, no nightly -- so `forensics/memory-safety/container.json` lists it
`metadata_only` and the guard admits it on any host, and `evidence_determinism.py` byte-compares
`artifacts/phase25/unsafe-reduction.json` like the other Phase-25 derivations. The census itself is
the 25.1 measurement's output and was re-run when the reconstruction landed.

Outputs
-------
  artifacts/phase25/unsafe-reduction.json

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import re
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
    sha256_file,
)

# The Docker-only execution guard, called first. This tool executes nothing -- it derives a plane from
# committed artefacts and the committed source spans the census names -- so the manifest lists it
# `metadata_only` and the guard admits it on any host exactly as `ms_exposure.py` is.
import phase25_guard  # noqa: E402

# The schema and its closed vocabularies. Imported, never restated.
import memory_safety_schemas as schemas  # noqa: E402

# The census (for the site universe and its ordered id lists) and the lossless columnar codec.
import ms_census  # noqa: E402
import ms_codec  # noqa: E402

OUT = REPO_ROOT / "artifacts" / "phase25" / "unsafe-reduction.json"
GENERATOR = "forensics/tools/ms_reduction.py"
TOOL = REPO_ROOT / "forensics" / "tools" / "ms_reduction.py"
SCHEMAS = REPO_ROOT / "forensics" / "tools" / "memory_safety_schemas.py"
GUARD = REPO_ROOT / "forensics" / "tools" / "phase25_guard.py"
PLAN = REPO_ROOT / "docs" / "PHASE-25-MEMORY-SAFETY-SUBPHASES.md"
MANIFEST = REPO_ROOT / "forensics" / "memory-safety" / "container.json"
CARGO_TOML = REPO_ROOT / "Cargo.toml"
LIB_RS = REPO_ROOT / "src" / "lib.rs"

# 25.1's compiler-backed source census: the primary unit (the compiler-derived unsafe site).
CENSUS = REPO_ROOT / "artifacts" / "phase25" / "source-census.json"

# 25.7's exposure/data-flow classification: the authority for which sites are reachable in the
# claimed profile. The census carries a placeholder exposure class; the classification is here.
EXPOSURE = REPO_ROOT / "artifacts" / "phase25" / "exposure.json"

# The committed reconstruction declaration: the authored record of which sites the reconstruction
# removed from the subsystem, how each operation is classified (ELIMINATED or
# RELOCATED_TO_BOUNDARY), the tests that passed and the downstream baseline it froze. The tool
# re-derives the counts from the live census plus this removed set, so the record is checked, not
# merely asserted.
RECONSTRUCTION = REPO_ROOT / "forensics" / "memory-safety" / "unsafe-reconstruction.json"

# 25.8's differential court artefact: the machine-readable comparison of the authority and the
# crate under a caller-installed allocator, the adjudicated allocator divergence, the re-entrancy
# obligation and its evidence, and the residual unsafe boundary. It is produced by
# `forensics/tools/ms_sparse_array_court.py --measure`, which compiles and runs, so it is a
# measurement artefact (like `miri.json`) and is read here rather than regenerated.
SPARSE_ARRAY_DIFFERENTIAL = REPO_ROOT / "forensics" / "memory-safety" / "sparse-array-differential.json"

# The committed Phase-24 downstream measurement the conservation check re-reads: the DROP_IN_PASS
# verdicts and the ladder from the final P1000 run, and the eight functional workloads of the
# runtime atlas. Both are measurement artefacts, never regenerated here.
DOWNSTREAM_P1000 = REPO_ROOT / "forensics" / "downstream" / "p1000-run.json"
DOWNSTREAM_RUNTIME = REPO_ROOT / "forensics" / "downstream" / "runtime-functional-atlas.json"

CENSUS_REL = rel(CENSUS)
EXPOSURE_REL = rel(EXPOSURE)
PLAN_REL = rel(PLAN)
SCHEMAS_REL = rel(SCHEMAS)
TOOL_REL = rel(TOOL)
RECONSTRUCTION_REL = rel(RECONSTRUCTION)
DIFFERENTIAL_REL = rel(SPARSE_ARRAY_DIFFERENTIAL)

# The two admissible classes a removed operation may carry. `HIDDEN` -- a mere wrapper that leaves
# the dangerous operation in place -- is the third, forbidden name, and a declaration that uses it
# is refused rather than silently accepted.
RECONSTRUCTION_CLASSES: tuple[str, ...] = ("ELIMINATED", "RELOCATED_TO_BOUNDARY")
FORBIDDEN_CLASS = "HIDDEN"

# The one verdict an attempted conversion whose measured operation count ROSE may carry. Any other
# verdict on such a conversion is the conflation -- a net count increase labelled a reduction -- that
# `attempted_conversion_findings` refuses. The success axis (dangerous operations ELIMINATED, a
# smaller auditable residual boundary, HIDDEN=0) is recorded per conversion and is never conflated
# with the net count: a conversion can score well on the axis and still not be a reduction.
NOT_A_REDUCTION = "REVERTED_NOT_A_REDUCTION"


# --------------------------------------------------------------------------------------------
# the closed candidate table: the classes a reachable site is classified into, and what each
# proposed transformation would be
# --------------------------------------------------------------------------------------------

# The membership precondition a reduction must satisfy, recorded once and cited by every candidate.
ADMISSIBILITY = (
    "a reduction is admissible only if (1) it replaces a compiler-derived unsafe operation with a "
    "real safe intrinsic or a checked wrapper; (2) it changes no function signature, no public "
    "surface and no foreign ABI; (3) it silences no lint -- the frozen safety lint policy "
    "(unsafe_op_in_unsafe_fn, undocumented_unsafe_blocks, missing_safety_doc) is untouched; "
    "(4) it does not merge blocks or consolidate pointers/reads into a helper merely to move the "
    "count; (5) the crate's own tests pass and every Phase-25 court and run_courts.py still pass; "
    "and (6) its behaviour-preservation argument holds for every input the authority's contract "
    "admits"
)

# Every candidate class, in classification order. `_classify` returns the first that matches, so the
# order is part of the rule, not an implementation detail. Each `rejection` is this venue's measured
# reason the class is not reduced; `admissible` is false for all of them, and the worklist records
# the reason rather than dropping the sites.
PATTERNS: tuple[dict, ...] = (
    {
        "pattern": "FROM_RAW_PARTS_OVER_SLICE",
        "transform": ("replace `core::slice::from_raw_parts(x.as_ptr(), n)` with the safe slice "
                      "constructor `&x[..n]` (or `x`, when `n` is the array length) where `x` is a "
                      "Rust slice or array and `n` is a bound already established at the site"),
        "preserves": ("the pointer is a Rust slice/array element pointer, `n` is validated by an "
                      "explicit check or a compile-time constant equal to the array length, and the "
                      "element type is unchanged: the same `n` elements are named and no foreign "
                      "provenance is crossed"),
        "abi_risk": ("none when the source is genuinely a Rust slice; the risk is that a member is "
                     "not -- a field of a raw `*const` C object, or a `&[c_char]` reinterpreted as "
                     "`&[u8]`"),
        "rejection": (
            "not applied: every reachable member fails the precondition. The members that read a "
            "field of a raw `*const` C object have their census site on the enclosing raw "
            "dereference -- the site the census establishes is `(*p).field.as_ptr()`, not the "
            "`from_raw_parts` call -- so replacing the call removes no site and leaves the block "
            "unsafe; and the member over a `&[c_char]` needs a `c_char`->`u8` reinterpretation that "
            "has no stable safe form, so the replacement would retain an unsafe operation. Neither "
            "is a reduction."),
        "admissible": False,
    },
    {
        "pattern": "FUNCTION_POINTER_TRANSMUTE",
        "transform": ("replace `core::mem::transmute::<A, B>(x)` between function-pointer shapes "
                      "with a typed `as` cast or a typed wrapper"),
        "preserves": ("the source and target are equal-size function-pointer types and the "
                      "conversion is a pure type erasure over an already-valid pointer"),
        "abi_risk": ("the whole class is the FFI type-erasure boundary -- a dynamically resolved "
                     "`dlsym`/DSO/ENGINE symbol, a callback registered as an untyped `*mut c_void`, "
                     "or the `ASN1_AUX` const-ification -- where the target type is known only at "
                     "run time"),
        "rejection": (
            "not applied: the transmute erases the type of a run-time-resolved symbol; Rust has no "
            "safe conversion for a pointer whose target type is not known to the caller, and "
            "changing the signature to carry the type would change the public/foreign surface."),
        "admissible": False,
    },
    {
        "pattern": "CASTED_POINTER_READ_WRITE",
        "transform": ("replace `p.cast::<T>().read()` / `.write(v)` with a safe dereference `*p` "
                      "when `p` is already a typed Rust pointer"),
        "preserves": ("the pointer is already typed and aligned for `T` and lives across the read, "
                      "so `*p` names the same value"),
        "abi_risk": ("the reachable members are untyped foreign `*const c_void`: `OSSL_PARAM.data`, "
                     "a callback argument, or a list element whose pointee type and validity are the "
                     "C caller's contract"),
        "rejection": (
            "not applied: the pointee type and validity are carried by the C caller and are not "
            "visible to the Rust side, so a safe dereference would have to assume a type the ABI "
            "does not state -- a behaviour change, not a reduction."),
        "admissible": False,
    },
    {
        "pattern": "RAW_POINTER_ARITHMETIC",
        "transform": ("replace `p.add(k)` / `p.offset(k)` raw pointer arithmetic over a buffer with "
                      "safe slice indexing (`&buf[a..b]`) when `p` is the base of a Rust slice"),
        "preserves": ("`p` is `buf.as_ptr()` for a Rust slice `buf` and every computed offset is in "
                      "`0..=buf.len()`"),
        "abi_risk": ("the reachable members walk foreign C buffers -- BIGNUM limbs, ASN.1 content, "
                     "cipher key material -- whose length the authority states as a precondition, "
                     "not as a Rust slice bound"),
        "rejection": (
            "not applied: the walk's extent is a documented precondition over a foreign C buffer, "
            "not a Rust slice bound; turning it into safe indexing would require the slice and the "
            "length -- a signature change at the ABI boundary -- and would introduce a panic where "
            "the authority states undefined behaviour."),
        "admissible": False,
    },
    {
        "pattern": "UNCHECKED_SLICE_ACCESS",
        "transform": ("replace an unchecked access (`get_unchecked`, `set_len`, "
                      "`unreachable_unchecked`) with its checked intrinsic"),
        "preserves": "the index/length is already known in bounds at the site",
        "abi_risk": "none -- a checked intrinsic has the same signature",
        "rejection": (
            "not applied: the checked form adds a panic path where the authority's contract is a "
            "precondition (undefined behaviour on violation), so it is not behaviour-preserving for "
            "the inputs the contract leaves undefined."),
        "admissible": False,
    },
    {
        "pattern": "RAW_POINTER_DEREFERENCE",
        "transform": ("replace `unsafe { *p }` / `(*p).field` with a safe reference when `p` is "
                      "already a Rust reference or a `Box`-derived pointer"),
        "preserves": "the pointer is a Rust reference or an owning Rust pointer and lives across the use",
        "abi_risk": ("the reachable members dereference a foreign `*const`/`*mut` C object whose "
                     "liveness, alignment and initialisation are the caller's contract"),
        "rejection": (
            "not applied: the pointer is a foreign C object crossing the ABI, and the safe form "
            "would require a Rust reference the boundary does not produce -- a signature change."),
        "admissible": False,
    },
    {
        "pattern": "UNSAFE_CALL",
        "transform": ("replace a call to a foreign or contract-carrying `unsafe fn` with a safe "
                      "wrapper that validates the contract at one site"),
        "preserves": "the wrapper accepts exactly the inputs the callee's contract admits and rejects the rest",
        "abi_risk": ("the call is the ABI boundary itself -- a foreign `unsafe extern \"C\"` callee "
                     "or an internal `unsafe fn` whose contract is a raw-pointer precondition"),
        "rejection": (
            "not applied: a wrapper would have to decide the raw-pointer precondition at run time "
            "and would either panic (a behaviour change) or reproduce the same unsafe call. "
            "Repeated calls behind one validated length cannot be folded into a single helper "
            "without consolidating pointers, which section 3.4 and the brief forbid as metric "
            "gaming."),
        "admissible": False,
    },
    {
        "pattern": "FFI_EXPORT",
        "transform": ("remove `unsafe` from a `#[no_mangle] pub unsafe extern \"C\" fn` whose body "
                      "needs no unsafe operation"),
        "preserves": "the machine-level ABI is unchanged; only the Rust-side unsafety marker moves",
        "abi_risk": ("the declaration is the exported symbol the custodian contract fixes; its "
                     "`unsafe` marker is part of the public Rust surface, and the body is unsafe "
                     "precisely because it dereferences its C arguments"),
        "rejection": (
            "not applied: dropping `unsafe` changes the public Rust surface, which section 3.4 "
            "forbids, and the body's unsafe operations remain because they dereference the C "
            "arguments -- the marker is not the operation."),
        "admissible": False,
    },
    {
        "pattern": "STATIC_MUT",
        "transform": ("replace a `static mut` access with a synchronised cell (an atomic or a "
                      "`SyncUnsafeCell`)"),
        "preserves": "the access is already serialised by the program's single-threaded initialisation discipline",
        "abi_risk": ("the `static mut` is the authority's global state (`X509`/provider registries, "
                     "the error stack) whose layout and initialisation the C side also reads"),
        "rejection": (
            "not applied: a synchronised cell still needs an unsafe accessor, changes the global's "
            "type and layout across the ABI, and would add synchronisation the authority's "
            "single-threaded initialisation does not have -- a behaviour change, not a reduction."),
        "admissible": False,
    },
    {
        "pattern": "UNSAFE_IMPL",
        "transform": "replace an `unsafe impl Send`/`Sync` with a safe impl",
        "preserves": "the type is genuinely `Send`/`Sync` by its structure",
        "abi_risk": "none at the machine level, but the impl is a claim about the type, not an operation",
        "rejection": (
            "not applied: the site is a claim (`unsafe impl Send`/`Sync`), not an unsafe operation "
            "with a safe intrinsic; replacing it is a soundness argument owned by 25.4's ownership "
            "planes, not a reduction."),
        "admissible": False,
    },
    {
        "pattern": "UNCLASSIFIED",
        "transform": "none identified",
        "preserves": "n/a",
        "abi_risk": ("the residual class is an `unsafe extern \"C\"` declaration -- an inbound FFI "
                     "symbol binding"),
        "rejection": (
            "not applied: the site is an `unsafe extern \"C\" { ... }` declaration; its unsafety is "
            "the ABI itself, and no safe replacement exists for a binding to a foreign symbol."),
        "admissible": False,
    },
)
PATTERN_BY_ID: dict[str, dict] = {p["pattern"]: p for p in PATTERNS}

# The frozen safety lint policy 25.0 fixed. No Phase-25 tool may weaken it; this instrument reads it
# so a weakened lint is a finding rather than a silent change beside a smaller count.
LINT_SETTINGS: tuple[tuple[str, str], ...] = (
    ("unsafe_op_in_unsafe_fn", "deny"),
    ("undocumented_unsafe_blocks", "deny"),
    ("missing_safety_doc", "deny"),
)

# The required non-claims. The first is the one the brief names for this subphase.
NON_CLAIMS: tuple[str, ...] = (
    "a smaller unsafe count is not a memory-safety claim; the ABI and the lints are unchanged",
    "safe Rust does not prove protocol correctness: memory safety is not behavioural correctness",
    "unsafe Rust is not inherently vulnerable: an unsafe operation with a discharged contract is a "
    "sound operation",
    "unsafe LOC is not a vulnerability count: a line count is a secondary projection of the "
    "compiler-derived census",
    "an unreduced reachable unsafe site is inventoried, not proven: the worklist's rejection is a "
    "statement about the availability of a local safe substitution, not about the site's soundness, "
    "and the worklist is a local-replacement feasibility census, not an impossibility result about "
    "the rest of the core",
    "behaviour preservation is stated for the inputs the authority's contract admits; the "
    "authority's undefined-behaviour cases are not transferred to a defined panic",
    "the campaign's success axis is not the total operation count alone: a conversion is judged on "
    "(a) dangerous operations ELIMINATED, (b) a smaller, auditable residual boundary, and (c) "
    "HIDDEN=0, so a conversion that replaces a large unsafe interior with a small explicit boundary "
    "can be architecturally safer even when its raw site count rises -- and a net site-count "
    "increase is still never labelled a reduction; the axis and the net are separate facts, stated "
    "side by side",
)


# --------------------------------------------------------------------------------------------
# the derivation
# --------------------------------------------------------------------------------------------

_LINE_CACHE: dict[str, list[str]] = {}

# A whole-word match for the unchecked-access hints, so `offset_len` (which contains the substring
# `set_len`) is not misread as a `set_len` call.
_UNCHECKED_HINT = re.compile(r"\b(get_unchecked|set_len)\b")


def _load(path: Path) -> dict:
    if not path.is_file():
        raise SystemExit(f"[ms-reduction] {rel(path)} is absent")
    return json.loads(path.read_text(encoding="utf-8"))


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8") if path.is_file() else ""


def _body(doc: dict) -> dict:
    return doc.get("body", doc)


def _line_text(file: str, line: int) -> str:
    """The source text of one census site, read from the committed file it names (cached)."""
    lines = _LINE_CACHE.get(file)
    if lines is None:
        try:
            lines = (REPO_ROOT / file).read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            lines = []
        _LINE_CACHE[file] = lines
    return lines[line - 1] if 0 <= line - 1 < len(lines) else ""


def load_authority() -> dict:
    """The committed planes and source this plane reads, loaded once so the generator and the court
    share bytes. The exposure classification is the reachability authority; the two lint files are
    read so a weakened lint is a finding; the reconstruction declaration and the committed Phase-24
    downstream measurement are read for the conservation check. The exposure body is decoded here
    (the census supplies the ordered id lists it references by index)."""
    census_doc = _load(CENSUS) if CENSUS.is_file() else {"body": {}}
    census_body = ms_census.decode_body(census_doc.get("body", census_doc))
    refs = ms_codec.refs_from_census(census_body)
    exposure_doc = _load(EXPOSURE) if EXPOSURE.is_file() else {"body": {}}
    reconstruction = _load(RECONSTRUCTION) if RECONSTRUCTION.is_file() else {}
    differential = _load(SPARSE_ARRAY_DIFFERENTIAL) if SPARSE_ARRAY_DIFFERENTIAL.is_file() else {}
    p1000 = _load(DOWNSTREAM_P1000) if DOWNSTREAM_P1000.is_file() else {}
    runtime = _load(DOWNSTREAM_RUNTIME) if DOWNSTREAM_RUNTIME.is_file() else {}
    return {
        "exposure": {**exposure_doc,
                     "body": ms_codec.decode_body(exposure_doc.get("body", exposure_doc), refs)},
        "reconstruction": reconstruction,
        "differential": differential,
        "downstream": {"p1000": p1000, "runtime": runtime},
        "lint_policy": {"cargo_toml": _read(CARGO_TOML), "lib_rs": _read(LIB_RS)},
        "census_sha256": sha256_file(CENSUS) if CENSUS.is_file() else "unknown",
    }


def _classify(kind: str, text: str) -> str:
    """The candidate class of one compiler-derived site.

    The **unit** is the compiler-derived site (its id and operation kind); the source span text is
    read only to name the operation the site is and therefore the candidate transformation. The
    classification is a total function of `(operation_kind, span text)`, so every reachable site has
    exactly one class and the partition is reproducible.
    """
    if "from_raw_parts" in text and (".as_ptr()" in text or ".as_mut_ptr()" in text):
        return "FROM_RAW_PARTS_OVER_SLICE"
    if "transmute" in text or kind == "TRANSMUTE":
        return "FUNCTION_POINTER_TRANSMUTE"
    if ".cast::<" in text and any(m in text for m in (
            ".read(", ".write(", ".read_unaligned(", ".write_unaligned(",
            ".read_volatile(", ".write_volatile(")):
        return "CASTED_POINTER_READ_WRITE"
    if any(m in text for m in (".add(", ".sub(", ".offset(", "wrapping_add", "wrapping_sub")):
        return "RAW_POINTER_ARITHMETIC"
    if (_UNCHECKED_HINT.search(text) is not None or "unreachable_unchecked" in text
            or "assert_unchecked" in text):
        return "UNCHECKED_SLICE_ACCESS"
    if kind in ("RAW_POINTER_DEREFERENCE", "RAW_POINTER_READ", "RAW_POINTER_WRITE"):
        return "RAW_POINTER_DEREFERENCE"
    if kind == "STATIC_MUT_ACCESS":
        return "STATIC_MUT"
    if kind == "UNSAFE_IMPL":
        return "UNSAFE_IMPL"
    if kind in ("UNSAFE_FUNCTION_CALL", "UNSAFE_METHOD_CALL"):
        return "UNSAFE_CALL"
    if kind == "FFI_EXPORT":
        return "FFI_EXPORT"
    return "UNCLASSIFIED"


def _reachable(census_body: dict, exposure_body: dict) -> list[str]:
    """The externally reachable compiler-derived site ids, in census order (the 25.7 authority)."""
    esites = exposure_body.get("sites") or {}
    out: list[str] = []
    for s in census_body.get("sites") or []:
        sid = str(s.get("site_id"))
        e = (esites.get(sid) or {}).get("e")
        if e in schemas.EXTERNALLY_REACHABLE_EXPOSURE:
            out.append(sid)
    return out


def _kind_counts(kinds: object) -> dict:
    """An operation-kind -> count map, key-sorted, so a derived count is byte-stable."""
    return {k: int(v) for k, v in sorted(Counter(kinds).items())}


def _derive_downstream(authority: dict) -> dict:
    """The Phase-24 downstream headline, re-derived from the committed measurement.

    The DROP_IN_PASS verdicts, the counted families, the ladder and the eight functional workloads
    are read from the committed `p1000-run.json` and `runtime-functional-atlas.json`, never typed. A
    reconstruction that moved any of them is inadmissible, and this is the value the frozen baseline
    is compared against.
    """
    ds = authority.get("downstream") or {}
    p1000 = _body(ds.get("p1000") or {})
    runtime = _body(ds.get("runtime") or {})
    counts = p1000.get("counts") or {}
    ladder = p1000.get("ladder") or {}
    verdicts = counts.get("verdicts") or {}
    levels = ladder.get("levels") or {}
    specimens = runtime.get("specimens") or []
    return {
        "drop_in_pass": int(verdicts.get("DROP_IN_PASS", 0)),
        "measurable_families": int(counts.get("measurable_families",
                                             ladder.get("measurable_families", 0))),
        "families": int(counts.get("families", ladder.get("families", 0))),
        "functional_workloads": len(specimens),
        "p1000_ladder_levels": {k: int(v) for k, v in sorted(levels.items())},
        "verdicts": {k: int(v) for k, v in sorted(verdicts.items())},
        "sources": [rel(DOWNSTREAM_P1000), rel(DOWNSTREAM_RUNTIME)],
    }


def _differential(authority: dict) -> dict:
    """The 25.8 differential, read from the committed court artefact.

    The artefact is the machine-readable comparison of the authority and the crate under a
    caller-installed allocator -- the harness result, the adjudicated allocator divergence, the
    re-entrancy obligation with its evidence and the residual unsafe boundary. It is a
    *measurement* (the tool compiles and runs both sides), so it is read here, and its hash is
    frozen into the record so a swapped artefact is visible.
    """
    d = _body(authority.get("differential") or {})
    cmp_ = d.get("comparison") or {}
    divs = cmp_.get("divergences") or []
    ob = d.get("reentrancy_obligation") or {}
    boundary = d.get("residual_unsafe_boundary") or []
    return {
        "artifact": DIFFERENTIAL_REL,
        "artifact_sha256": (sha256_file(SPARSE_ARRAY_DIFFERENTIAL)
                            if SPARSE_ARRAY_DIFFERENTIAL.is_file() else "unknown"),
        "ran": bool((d.get("authority") or {}).get("transcript"))
               and bool((d.get("candidate") or {}).get("transcript")),
        "authority_impl": (d.get("authority") or {}).get("impl"),
        "candidate_impl": (d.get("candidate") or {}).get("impl"),
        "all_match": bool(cmp_.get("all_match")),
        "divergences": [{"class": str(x.get("class")), "adjudication": str(x.get("adjudication")),
                         "field": str(x.get("field"))}
                        for x in divs],
        "unadjudicated": len(cmp_.get("unadjudicated") or []),
        "reentrancy_obligation": {
            "caller": str(ob.get("caller", "")),
            "sites": [str(s) for s in (ob.get("wrapper_sites") or [])],
            "evidence": [str(e) for e in (ob.get("evidence") or [])],
            "disposition": bool(str(ob.get("disposition", "")).strip()),
        },
        "residual_unsafe_boundary": [
            {"boundary": str(b.get("boundary", "")), "operation": str(b.get("operation", ""))}
            for b in boundary
        ],
    }


def differential_findings(body: dict, authority: dict) -> list[str]:
    """Every way the committed differential is inadmissible.

    It refuses an allocator divergence that is not adjudicated, a harness that did not run (no
    authority or candidate transcript), a re-entrancy obligation with no evidence or disposition,
    and a missing residual unsafe boundary. These are the three gaps 25.8's `Fix A` had to close.
    """
    problems: list[str] = []
    d = _body(authority.get("differential") or {})
    if not d:
        problems.append(f"the differential artefact {DIFFERENTIAL_REL} is absent or empty, so the "
                        "differential harness did not run")
        return problems
    if not (d.get("authority") or {}).get("transcript") \
            or not (d.get("candidate") or {}).get("transcript"):
        problems.append("the differential harness did not run: an authority or candidate "
                        "transcript is missing")
    cmp_ = d.get("comparison") or {}
    unadj = cmp_.get("unadjudicated") or []
    divs = cmp_.get("divergences") or []
    for x in divs:
        if x.get("adjudication") not in ("closed", "accepted") or not x.get("reason"):
            problems.append(f"the differential carries an unadjudicated allocator divergence: "
                            f"{x.get('field')} ({x.get('class')})")
    if unadj:
        problems.append(f"the differential carries {len(unadj)} unadjudicated divergence(s)")
    ob = d.get("reentrancy_obligation") or {}
    if not ob.get("evidence"):
        problems.append("the callback re-entrancy obligation is missing its evidence")
    if not str(ob.get("disposition", "")).strip():
        problems.append("the callback re-entrancy obligation states no disposition")
    if not d.get("residual_unsafe_boundary"):
        problems.append("the residual unsafe boundary is not recorded")
    return problems


def _axis(decl: dict) -> dict:
    """The campaign's success axis, carried from the declaration.

    The axis is what a conversion is judged on **besides** the net count: the operations it
    ELIMINATED, the operations it RELOCATED_TO_BOUNDARY, the HIDDEN count (which must be 0) and the
    residual boundary set and its size. It is stated per conversion in `attempted_conversions`, and
    the `never_conflated` sentence is the rule that a net site-count increase is never labelled a
    reduction.
    """
    a = decl.get("axis") or {}
    return {
        "statement": str(a.get("statement", "")),
        "per_conversion_fields": [str(x) for x in (a.get("per_conversion_fields") or [])],
        "never_conflated": str(a.get("never_conflated", "")),
    }


def _attempted_conversions(decl: dict) -> list[dict]:
    """The attempted conversions, normalized from the declaration.

    A conversion that was tried and reverted is a measured negative result, not a reduction: it
    carries its subsystem, its measured before/after counts (subsystem and crate), the differential
    outcome (whether the harness ran and which fields matched), the classification in the closed
    vocabulary (ELIMINATED / RELOCATED_TO_BOUNDARY / HIDDEN, with HIDDEN recorded as 0), the residual
    boundary set and its size, and the verdict. The per-class counts are normalized as they are
    declared -- a reverted conversion may record them as not separately measured rather than invent a
    split -- so the record can express the axis without a fabricated figure.
    """
    out: list[dict] = []
    for a in (decl.get("attempted_conversions") or []):
        counts = a.get("counts") or {}
        cls = a.get("classification") or {}
        diff = a.get("differential") or {}
        rb = a.get("residual_boundary") or {}
        out.append({
            "id": str(a.get("id", "")),
            "subsystem": str(a.get("subsystem", "")),
            "files": [str(f) for f in (a.get("files") or [])],
            "mechanism": str(a.get("mechanism", "")),
            "counts": {
                "subsystem_before": int(counts.get("subsystem_before", 0)),
                "subsystem_after": int(counts.get("subsystem_after", 0)),
                "crate_before": int(counts.get("crate_before", 0)),
                "crate_after": int(counts.get("crate_after", 0)),
            },
            "differential": {
                "ran": bool(diff.get("ran")),
                "authority": str(diff.get("authority", "")),
                "candidate": str(diff.get("candidate", "")),
                "fields_matched": [str(m) for m in (diff.get("fields_matched") or [])],
                "divergence": str(diff.get("divergence", "")),
            },
            "classification": {
                "ELIMINATED": cls.get("ELIMINATED"),
                "RELOCATED_TO_BOUNDARY": cls.get("RELOCATED_TO_BOUNDARY"),
                "HIDDEN": int(cls.get("HIDDEN", 0)),
            },
            "residual_boundary": {
                "set": [str(x) for x in (rb.get("set") or [])],
                "size": rb.get("size"),
            },
            "verdict": str(a.get("verdict", "")),
            "obstruction": str(a.get("obstruction", "")),
        })
    return out


def _next_targets(decl: dict) -> list[dict]:
    """The campaign worklist: the next conversions to attempt, and why.

    A plan, not a claim: each names a subsystem, its measured interior operation count (and its
    breakdown), why it is the next target and why it is tractable, the risk to be proven, and --
    where relevant -- the larger mechanism that was considered and rejected because its interior is
    algorithmic rather than structural and so would not net-reduce.
    """
    out: list[dict] = []
    for t in (decl.get("next_targets") or []):
        out.append({
            "id": str(t.get("id", "")),
            "subsystem": str(t.get("subsystem", "")),
            "files": [str(f) for f in (t.get("files") or [])],
            "interior_operations": int(t.get("interior_operations", 0)),
            "interior_by_kind": {str(k): int(v)
                                 for k, v in (t.get("interior_by_kind") or {}).items()},
            "why_next": str(t.get("why_next", "")),
            "why_tractable": str(t.get("why_tractable", "")),
            "risk": str(t.get("risk", "")),
            "not_chosen": str(t.get("not_chosen", "")),
        })
    return out


def derive_reconstruction(census_body: dict, authority: dict) -> dict:
    """The reconstruction record, derived from the declaration, the live census and the committed
    downstream measurement.

    The **after** counts are the live census's own counts over the subsystem's files; the **before**
    counts are `after + the removed set`, so a typed count cannot survive the check. The per-operation
    classification is the declaration's, tallied; the downstream headline is re-derived from the
    committed Phase-24 files.
    """
    decl = authority.get("reconstruction") or {}
    subsys = decl.get("subsystem") or {}
    ops = decl.get("operations") or []
    files = [str(f) for f in (subsys.get("files") or [])]
    sites = census_body.get("sites") or []

    after_kind = Counter(str(s.get("operation_kind"))
                         for s in sites if str(s.get("file")) in set(files))
    after_sites = sum(after_kind.values())

    by_class: Counter = Counter()
    by_class_kind: dict[str, Counter] = {c: Counter() for c in RECONSTRUCTION_CLASSES}
    for o in ops:
        cls = str(o.get("classification"))
        by_class[cls] += 1
        by_class_kind.setdefault(cls, Counter())[str(o.get("operation_kind"))] += 1

    # An ELIMINATED operation is gone (net -1 site); a RELOCATED_TO_BOUNDARY operation moved to a
    # thin boundary wrapper, so it is one removed site and one introduced boundary site (net 0). The
    # crate/sub-system before count is therefore `after + the ELIMINATED set`, and the relocated set
    # is the boundary operation count that replaced them.
    eliminated_kind = by_class_kind.get("ELIMINATED", Counter())
    before_kind = Counter(after_kind)
    for kind, n in eliminated_kind.items():
        before_kind[kind] += n
    eliminated = int(by_class.get("ELIMINATED", 0))
    relocated = int(by_class.get("RELOCATED_TO_BOUNDARY", 0))
    ids = sorted(str(o.get("site_id")) for o in ops)
    return {
        "subsystem": {
            "id": str(subsys.get("id", "")),
            "files": files,
            "mechanism": str(subsys.get("mechanism", "")),
            "why_internal": str(subsys.get("why_internal", "")),
        },
        "operations": {
            "count": len(ops),
            "by_class": {c: int(by_class.get(c, 0)) for c in sorted(by_class)},
            "by_class_kind": {c: _kind_counts(by_class_kind.get(c, Counter()))
                              for c in sorted(by_class_kind)},
            "removed_site_ids_sha256": content_hash(ids),
            "sample_site_ids": ids[:8],
        },
        "axis": _axis(decl),
        "attempted_conversions": _attempted_conversions(decl),
        "next_targets": _next_targets(decl),
        "counts": {
            "before": {"sites": after_sites + eliminated,
                       "sites_by_kind": _kind_counts(before_kind)},
            "after": {"sites": after_sites, "sites_by_kind": _kind_counts(after_kind)},
            "net_reduced": eliminated,
            "relocated_to_boundary": relocated,
        },
        "boundary": {
            "kinds_present": _kind_counts(after_kind),
            "introduced": relocated,
            # The file's sites the reconstruction did not touch at all: `after_kind` counts every
            # site the live census finds in the subsystem's files, and the declaration's non-test
            # remainder is exactly the relocated set, so the difference is the `#[cfg(test)]`
            # module's own calls into the entry points and its leaf callbacks. They are identical
            # before and after (the tests were rewritten against the same signatures), so they add
            # to neither the removed nor the introduced count -- leaving them unnamed would let the
            # kinds_present total look like it contained undeclared boundary operations.
            "test_only_sites": after_sites - relocated,
            "note": (f"of the {after_sites} operations the census still finds in the file, the "
                     f"{relocated} non-test ones are exactly the thin entry-point wrappers that "
                     f"turn the opaque handle into a reference, call the caller's leaf function "
                     f"pointer and release the header; the other {after_sites - relocated} are the "
                     f"`#[cfg(test)]` module's own calls into those entry points and its leaf "
                     f"callbacks, unchanged across the reconstruction"),
        },
        "tests": [str(t) for t in (decl.get("tests") or [])],
        "differential": _differential(authority),
        "residual_unsafe_boundary": {
            "subsystem": str(subsys.get("id", "")),
            "sites": after_sites,
            "sites_by_kind": _kind_counts(after_kind),
            # The explicit, auditable boundary: the artefact names the seam the reconstruction
            # crosses by construction, and the live census above counts every operation that
            # remains in the subsystem, so a reader can recompute the surface rather than trust a
            # prose list.
            "declared_boundaries": [
                {"boundary": str(b.get("boundary", "")),
                 "operation": str(b.get("operation", ""))}
                for b in (_body(authority.get("differential") or {})
                          .get("residual_unsafe_boundary") or [])
            ],
        },
        "downstream": _derive_downstream(authority),
        "conservation": {
            "hidden": 0,
            "abi_unchanged": True,
            "lint_unchanged": True,
            "downstream_unchanged": True,
            "admissible": True,
        },
    }


def attempted_conversion_findings(rec: dict) -> list[str]:
    """Every way the attempted-conversion record is inadmissible.

    Two invariants, and only two, both about the **honesty** of the negative result:

      * the negative result must not be **dropped** -- at least one attempted conversion must be
        recorded, and at least one must carry the non-reduction verdict `REVERTED_NOT_A_REDUCTION`,
        so a record that quietly forgets a conversion which raised the count is refused; and
      * a conversion whose measured count **rose** must not be labelled a reduction -- `after >
        before` with any verdict but `REVERTED_NOT_A_REDUCTION` is exactly the conflation of a count
        increase with a reduction that this refuses.

    It also refuses a conversion that hides an operation (`HIDDEN != 0`) and one that states no
    obstruction, because a negative result is only useful when it says *why* the conversion was not a
    reduction. It does **not** compare the attempted conversion's counts to the live census: a
    reverted conversion's counts are the measurement of a candidate that no longer exists, so they
    are recorded from the attempt and checked for internal consistency rather than re-derived.
    """
    problems: list[str] = []
    convs = rec.get("attempted_conversions") or []
    if not convs:
        problems.append("the reconstruction records no attempted conversion, so the negative result "
                        "is dropped: a conversion whose count rose must be recorded, not omitted")
        return problems
    if not any(c.get("verdict") == NOT_A_REDUCTION for c in convs):
        problems.append(f"the reconstruction records no attempted conversion with verdict "
                        f"{NOT_A_REDUCTION!r}, so the negative result is dropped")
    for c in convs:
        cid = str(c.get("id", ""))
        counts = c.get("counts") or {}
        before = int(counts.get("subsystem_before", 0))
        after = int(counts.get("subsystem_after", 0))
        verdict = str(c.get("verdict", ""))
        cls = c.get("classification") or {}
        if int(cls.get("HIDDEN", 0)) != 0:
            problems.append(f"attempted conversion {cid} hides {cls.get('HIDDEN')} operation(s): a "
                            f"HIDDEN classification is a wrapper, not a conversion")
        if after > before and verdict != NOT_A_REDUCTION:
            problems.append(f"attempted conversion {cid} conflates a count increase with a "
                            f"reduction: it rose {before} -> {after} (+{after - before}) but carries "
                            f"verdict {verdict!r}, not {NOT_A_REDUCTION!r}")
        if not str(c.get("obstruction", "")).strip():
            problems.append(f"attempted conversion {cid} states no obstruction, so its negative "
                            f"result says nothing about why the conversion was not a reduction")
    return problems


def reconstruction_findings(body: dict, census_body: dict, authority: dict) -> list[str]:
    """Every way the committed reconstruction contradicts the census, the declaration or the
    committed downstream measurement.

    It refuses a **HIDDEN** claim (a classified reduction that is not in the admissible vocabulary,
    or a "removed" site still present in the live census), a relocation with no boundary operation of
    that kind, a typed count (the committed record is not the derived one), a reconstruction with no
    passing test, and a **changed downstream verdict** (the Phase-24 headline no longer matches the
    frozen baseline).
    """
    problems: list[str] = []
    decl = authority.get("reconstruction") or {}
    ops = decl.get("operations") or []
    derived = derive_reconstruction(census_body, authority)
    if body.get("reconstruction") != derived:
        problems.append("the committed reconstruction record is not the derived reconstruction record")
    problems += attempted_conversion_findings(derived)

    census_ids = {str(s.get("site_id")) for s in (census_body.get("sites") or [])}
    files = set(str(f) for f in ((decl.get("subsystem") or {}).get("files") or []))
    after_kind = Counter(str(s.get("operation_kind"))
                         for s in (census_body.get("sites") or [])
                         if str(s.get("file")) in files)
    seen: set[str] = set()
    for o in ops:
        sid = str(o.get("site_id"))
        cls = str(o.get("classification"))
        kind = str(o.get("operation_kind"))
        if cls not in RECONSTRUCTION_CLASSES:
            problems.append(f"reconstruction op {sid} carries the class {cls!r}; a HIDDEN (or "
                            f"unknown) reduction is a wrapper, not a reduction")
            continue
        if sid in seen:
            problems.append(f"reconstruction names {sid} twice, so its class is ambiguous")
        seen.add(sid)
        if sid in census_ids:
            problems.append(f"the reconstruction claims {sid} removed, but it is still present in "
                            f"the live census (HIDDEN)")
        if cls == "RELOCATED_TO_BOUNDARY" and after_kind.get(kind, 0) == 0:
            problems.append(f"reconstruction calls {sid} RELOCATED_TO_BOUNDARY, but no {kind} "
                            f"operation remains at the subsystem boundary")
    if not derived["tests"]:
        problems.append("the reconstruction cites no passing test")

    baseline = decl.get("downstream_baseline") or {}
    live = derived["downstream"]
    for key in ("drop_in_pass", "measurable_families", "families", "functional_workloads"):
        if key in baseline and int(baseline[key]) != int(live.get(key, -1)):
            problems.append(f"a downstream verdict changed: the Phase-24 {key} is {live.get(key)}, "
                            f"not the frozen {baseline[key]}")
    if "p1000_ladder_levels" in baseline:
        want = {k: int(v) for k, v in baseline["p1000_ladder_levels"].items()}
        if want != live["p1000_ladder_levels"]:
            problems.append("a downstream verdict changed: the p1000-run.json ladder no longer "
                            "matches the frozen baseline")
    if "verdicts" in baseline:
        want = {k: int(v) for k, v in baseline["verdicts"].items()}
        if want != live["verdicts"]:
            problems.append("a downstream verdict changed: the p1000-run.json verdict histogram "
                            "no longer matches the frozen baseline")
    return problems


def derive(census_body: dict, authority: dict) -> dict:
    """The candidate classes over the reachable sites, plus the residual and finding sets."""
    exposure_body = _body(authority["exposure"])
    reachable = _reachable(census_body, exposure_body)
    by_pattern: dict[str, list[str]] = defaultdict(list)
    reachable_by_exposure: Counter = Counter()
    esites = exposure_body.get("sites") or {}
    kinds = {str(s.get("site_id")): str(s.get("operation_kind"))
             for s in census_body.get("sites") or []}
    spans = {str(s.get("site_id")): (str(s.get("file")), int(s.get("line") or 0))
             for s in census_body.get("sites") or []}
    for sid in reachable:
        reachable_by_exposure[str((esites.get(sid) or {}).get("e"))] += 1
        file_, line = spans.get(sid, ("", 0))
        by_pattern[_classify(kinds.get(sid, ""), _line_text(file_, line))].append(sid)

    worklist: list[dict] = []
    residuals: list[dict] = []
    for pid in sorted(by_pattern):
        ids = sorted(by_pattern[pid])
        p = PATTERN_BY_ID[pid]
        worklist.append({
            "pattern": pid,
            "sites": {
                "count": len(ids),
                "site_ids_sha256": content_hash(ids),
                "sample_site_ids": ids[:12],
            },
            "proposed_transformation": p["transform"],
            "behaviour_preserving_when": p["preserves"],
            "abi_risk": p["abi_risk"],
            "admissible": False,
            "rejection": p["rejection"],
        })
        residuals.append({
            "residual_id": f"rr-{pid.lower()}",
            "subject": pid,
            "class": "out_of_scope",
            "disposition": "preserved",
            "detail": (f"{len(ids)} externally reachable compiler-derived site(s) in the `{pid}` "
                       f"candidate class are preserved in the census rather than reduced: "
                       f"{p['rejection']}"),
            "evidence": [CENSUS_REL, EXPOSURE_REL] + ids[:3],
        })

    findings = [
        f"{len(reachable)} externally reachable compiler-derived unsafe site(s) carry exactly one "
        f"candidate class across {len(by_pattern)} pattern(s); **0 were reduced on the worklist**, "
        f"so the reachable count is unchanged",
        "every candidate replacement would change a function signature or the foreign ABI, turn a "
        "documented precondition the authority states into a defined panic, or remove no site "
        "because the census site is the enclosing raw dereference; consolidating repeated reads "
        "into one helper is forbidden by section 3.4 and the brief. This is a local-replacement "
        "feasibility census, not an impossibility result: of the reachable operations screened "
        "against the ten local-substitution patterns none was locally replaceable without changing "
        "the public surface or behaviour, which is not a claim that the rest of the core is "
        "irreducible -- a structural (representation-level) reconstruction is a separate campaign, "
        "recorded in forensics/memory-safety/unsafe-reconstruction.json",
        "the safe-core reconstruction is separate from the worklist: it replaced the internal "
        "unsafe mechanism of one subsystem --- recorded below with its per-operation "
        "classification --- so the crate's total operation count moved while the externally "
        "reachable count, the ABI and the lints are unchanged",
    ]
    return {
        "worklist": worklist,
        "reachable": reachable,
        "by_pattern": {pid: sorted(ids) for pid, ids in by_pattern.items()},
        "reachable_by_exposure": {k: reachable_by_exposure[k]
                                  for k in sorted(reachable_by_exposure)},
        "residuals": residuals,
        "findings": findings,
    }


def _counts(census_body: dict, authority: dict, applied: list) -> dict:
    """The before/after counts, derived from the census and the applied reductions.

    The **before** side is `after + everything removed`: the worklist's applied reductions (none) and
    the reconstruction's removed set (the declaration's operations). So the crate's before/after is a
    derivation, never a typed figure.
    """
    exposure_body = _body(authority["exposure"])
    sites = census_body.get("sites") or []
    by_kind = Counter(str(s.get("operation_kind")) for s in sites)
    rec_ops = (authority.get("reconstruction") or {}).get("operations") or []
    # An ELIMINATED operation is a net -1 site; a RELOCATED_TO_BOUNDARY operation is one removed
    # site and one introduced boundary site, so it cancels. The before/all-crate count is therefore
    # `after + the ELIMINATED set`.
    rec_elim = [o for o in rec_ops if str(o.get("classification")) == "ELIMINATED"]
    rec_elim_kind = Counter(str(o.get("operation_kind")) for o in rec_elim)
    before_by_kind = Counter(by_kind)
    for kind, n in rec_elim_kind.items():
        before_by_kind[kind] += n
    reachable = _reachable(census_body, exposure_body)
    reachable_set = set(reachable)
    by_exp: Counter = Counter()
    esites = exposure_body.get("sites") or {}
    for sid in reachable:
        by_exp[str((esites.get(sid) or {}).get("e"))] += 1
    reduced_wl = sum(len(a.get("before_site_ids") or []) - len(a.get("after_site_ids") or [])
                     for a in applied)
    rec_reduced = len(rec_elim)
    return {
        "sites_before": len(sites) + reduced_wl + rec_reduced,
        "sites_after": len(sites),
        "reduced": reduced_wl + rec_reduced,
        "reconstruction_reduced": rec_reduced,
        "sites_by_kind_before": dict(sorted(before_by_kind.items())),
        "sites_by_kind_after": dict(sorted(by_kind.items())),
        "reachable_before": len(reachable) + reduced_wl + rec_reduced,
        "reachable_after": len(reachable),
        "reachable_reduced": reduced_wl + rec_reduced,
        "patterns": len({_classify(str(s.get("operation_kind")),
                                   _line_text(str(s.get("file")), int(s.get("line") or 0)))
                         for s in sites
                         if str(s.get("site_id")) in reachable_set}),
        "candidates": len(reachable),
        "applied": len(applied),
        "rejected": len(reachable) - reduced_wl,
        "reachable_by_exposure": {k: by_exp[k] for k in sorted(by_exp)},
    }


def _rule() -> dict:
    return {
        "authority": {
            "kind": "committed-phase25-planes",
            "paths": [CENSUS_REL, EXPOSURE_REL, RECONSTRUCTION_REL, DIFFERENTIAL_REL, PLAN_REL,
                      SCHEMAS_REL, TOOL_REL, rel(DOWNSTREAM_P1000), rel(DOWNSTREAM_RUNTIME)],
            "declaration": (
                "the committed 25.1 census is the compiler-derived primary unit, the committed 25.7 "
                "exposure classification is the reachability authority (the census carries a "
                "placeholder class), the committed reconstruction declaration is the authored "
                "record of the removed sites and their classification, the committed Phase-24 "
                "measurement is the downstream authority, and the committed source spans the census "
                "names are read only to name the candidate transformation -- a site is never derived "
                "from a text scan"),
        },
        "classification": (
            "each reachable compiler-derived site is assigned exactly one candidate class by a "
            "total function of its operation kind and its committed source span text; the class "
            "names the proposed safe-intrinsic (local-substitution) replacement, not a new unit, and "
            "the worklist is a local-replacement feasibility census, not an impossibility result"
        ),
        "reconstruction": (
            "a genuinely internal unsafe mechanism -- the subsystem the reconstruction declaration "
            "names -- is replaced with safe Rust. Every removed operation is ELIMINATED (gone from "
            "the census) or RELOCATED_TO_BOUNDARY (it survives only in an isolated, unavoidable "
            "boundary), never HIDDEN; the counts are `after + removed`, and the Phase-24 downstream "
            "headline is re-read from the committed measurement and required unchanged"),
        "admissibility": ADMISSIBILITY,
        "axis": (
            "the campaign's success axis is not the total operation count alone. A conversion is "
            "judged on (a) dangerous operations ELIMINATED, (b) a smaller, auditable residual "
            "boundary, and (c) HIDDEN=0 -- the axis can improve even when a conversion's raw site "
            "count rises, when it replaces a large unsafe interior with a small explicit boundary. "
            "The record states that axis per conversion (the ELIMINATED count, the relocated count, "
            "the HIDDEN count, and the residual boundary set and its size) beside the net "
            "before/after counts, and the two are never conflated: a conversion whose count rose is "
            "recorded with the verdict REVERTED_NOT_A_REDUCTION, never as a reduction"
        ),
        "census_changed": True,
        "no_reduction_reason": (
            "the worklist is a local-replacement feasibility census, not an impossibility result: of "
            "the reachable operations screened against the ten local-substitution patterns, none was "
            "locally replaceable without changing the public surface or behaviour -- each candidate "
            "replacement would change a signature or the foreign ABI, turn a documented precondition "
            "the authority states into a defined panic, or remove no site at all, and consolidating "
            "repeated reads into one helper is forbidden by section 3.4. This is not a claim that the "
            "rest of the core is irreducible: a structural (representation-level) reconstruction is a "
            "separate campaign, recorded in forensics/memory-safety/unsafe-reconstruction.json and "
            "applied in the reconstruction below"
        ),
    }


def _frozen_census(census_body: dict, counts_after: dict, authority: dict) -> dict:
    return {
        "path": CENSUS_REL,
        "sha256": str(authority.get("census_sha256") or "unknown"),
        "body_hash": content_hash(census_body),
        "counts": {
            "sites": counts_after["sites_after"],
            "sites_by_kind": counts_after["sites_by_kind_after"],
            "reachable": counts_after["reachable_after"],
            "reachable_by_exposure": counts_after["reachable_by_exposure"],
        },
        "frozen": True,
        "note": ("the post-reconstruction baseline later subphases work against: the committed "
                 "census is the re-run 25.1 census after the reconstruction, and the frozen hashes "
                 "bind it"),
    }


def build_body(census_body: dict, authority: dict) -> dict:
    """The reduction body: the rule, the worklist, the (empty) applied set, the reconstruction
    record, the frozen census and the counts."""
    d = derive(census_body, authority)
    applied: list = []
    counts = _counts(census_body, authority, applied)
    return {
        "rule": _rule(),
        "worklist": d["worklist"],
        "applied": applied,
        "reconstruction": derive_reconstruction(census_body, authority),
        "frozen_census": _frozen_census(census_body, counts, authority),
        "counts": counts,
        "residuals": d["residuals"],
        "findings": d["findings"],
        "non_claims": list(NON_CLAIMS),
    }


# --------------------------------------------------------------------------------------------
# the pure checks: what the court runs over the committed artefact
# --------------------------------------------------------------------------------------------

def _lint_findings(cargo: str, lib_rs: str) -> list[str]:
    """Every way the frozen safety lint policy has been weakened (the same check the constitution
    court runs), so a reduction path cannot silence a lint to shrink the count."""
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


def reduction_findings(body: dict, census_body: dict, authority: dict) -> list[str]:
    """Every way the committed reduction contradicts the census, the exposure classification or the
    lint policy.

    Pure over `body`, the committed census and the committed planes: it checks that the frozen
    census agrees with the live census; that every applied reduction cites its before/after sites,
    its passing tests and its evidence, changes no lint and no ABI, and names a before site the live
    census no longer contains; that the worklist accounts for exactly the reachable sites not
    reduced; that the counts are derived rather than typed; that the lint policy is untouched; and
    that the rule names its committed authority.
    """
    problems: list[str] = []
    # The committed reduction is columnar on disk; re-derive the views the checks read (a fresh
    # measurement passes the views, for which decoding is a no-op).
    census_body = ms_census.decode_body(census_body)
    refs = ms_codec.refs_from_census(census_body)
    body = ms_codec.decode_body(body, refs)
    d = derive(census_body, authority)
    sites = census_body.get("sites") or []
    census_ids = [str(s.get("site_id")) for s in sites]
    census_set = set(census_ids)
    if len(census_set) != len(census_ids):
        problems.append("the census carries a duplicate site_id, so a class is ambiguous")

    # 0. The safe-core reconstruction: the per-operation classification, the derived counts and the
    #    unchanged downstream headline. A HIDDEN claim, a still-present "removed" site, a typed
    #    count or a moved Phase-24 verdict is a finding here.
    problems += reconstruction_findings(body, census_body, authority)

    # 0b. The differential: an allocator divergence that is not adjudicated, a harness that did not
    #     run, a missing re-entrancy obligation or a missing residual boundary is a finding.
    problems += differential_findings(body, authority)

    applied = body.get("applied") or []
    expected_counts = _counts(census_body, authority, applied)

    # 1. The frozen census agrees with the live census (the frozen baseline is the live artefact).
    frozen = body.get("frozen_census") or {}
    if frozen.get("body_hash") != content_hash(census_body):
        problems.append("the frozen census disagrees with the live census (body_hash)")
    want_frozen = {
        "sites": expected_counts["sites_after"],
        "sites_by_kind": expected_counts["sites_by_kind_after"],
        "reachable": expected_counts["reachable_after"],
        "reachable_by_exposure": expected_counts["reachable_by_exposure"],
    }
    if frozen.get("counts") != want_frozen:
        problems.append("the frozen census counts disagree with the live census")

    # 2. The counts are derived, not typed.
    if body.get("counts") != expected_counts:
        problems.append("the committed `counts` is not the derived `counts`")

    # 3. The worklist accounts for exactly the reachable sites not reduced.
    committed = body.get("worklist") or []
    if [e.get("pattern") for e in committed] != [e["pattern"] for e in d["worklist"]]:
        problems.append("the worklist pattern set is not the derived pattern set")
    union: set[str] = set()
    reduced_ids: set[str] = set()
    for a in applied:
        reduced_ids |= {str(x) for x in a.get("before_site_ids") or []}
    for e in committed:
        pid = e.get("pattern")
        ids = d["by_pattern"].get(str(pid), [])
        union |= set(ids)
        cited = set(ids) - reduced_ids
        entry = e.get("sites") or {}
        if entry.get("count") != len(cited):
            problems.append(f"the worklist class {pid!r} records {entry.get('count')!r} site(s), "
                            f"the derivation has {len(cited)}")
        if entry.get("site_ids_sha256") != content_hash(sorted(cited)):
            problems.append(f"the worklist class {pid!r} names a different site set than the "
                            f"derivation")
        if not e.get("admissible") and not e.get("rejection"):
            problems.append(f"the worklist class {pid!r} is not admissible but states no rejection")
    if union != set(d["reachable"]):
        problems.append("the worklist does not account for exactly the reachable sites")

    # 4. Every applied reduction cites its before/after sites, its passing tests and its evidence,
    #    changes no lint and no ABI, and names a before site the live census no longer contains.
    for a in applied:
        pid = str(a.get("pattern"))
        before = [str(x) for x in a.get("before_site_ids") or []]
        after = [str(x) for x in a.get("after_site_ids") or []]
        if not before:
            problems.append(f"the applied reduction {pid!r} names no before site")
        if not a.get("tests"):
            problems.append(f"the applied reduction {pid!r} cites no passing test")
        if not a.get("evidence"):
            problems.append(f"the applied reduction {pid!r} cites no evidence")
        if a.get("abi_change"):
            problems.append(f"the applied reduction {pid!r} declares an ABI change")
        if a.get("lint_change"):
            problems.append(f"the applied reduction {pid!r} declares a lint change")
        for sid in before:
            if sid in census_set:
                problems.append(f"the applied reduction {pid!r} names {sid} as reduced, but it is "
                                f"still present in the live census")
        for sid in after:
            if sid not in census_set:
                problems.append(f"the applied reduction {pid!r} names {sid} as introduced, but the "
                                f"live census does not contain it")

    # 5. No lint was weakened and the non-claim the brief names is present.
    lint = authority.get("lint_policy") or {}
    problems += _lint_findings(str(lint.get("cargo_toml", "")), str(lint.get("lib_rs", "")))
    if "a smaller unsafe count is not a memory-safety claim; the ABI and the lints are unchanged" \
            not in (body.get("non_claims") or []):
        problems.append("the reduction does not carry the required non-claim")

    # 6. The rule names its committed authority.
    paths = ((body.get("rule") or {}).get("authority") or {}).get("paths") or []
    for want in (CENSUS_REL, EXPOSURE_REL):
        if want not in paths:
            problems.append(f"the reduction rule does not name its committed authority {want}")

    # 7. Every residual validates against the residual schema.
    for r in body.get("residuals") or []:
        problems += [f"residual[{r.get('residual_id')}]: {p}" for p in schemas.validate("residual", r)]

    return problems


def reduction_sensitivity_control(body: dict, census_body: dict, authority: dict) -> dict:
    """Seed the mutations and require each caught, with specificity holding.

    Each is a distinct way the reduction could lie: a reduction claiming no test evidence; a
    weakened safety lint; a 'reduced' site that is still present in the live census; the frozen
    census disagreeing with the live census; a worklist that omits a candidate class; a typed
    count; a HIDDEN classification; a removed site still present; a changed downstream verdict; a
    relocation with no boundary operation; a differential harness that did not run; an unadjudicated
    allocator divergence; a missing re-entrancy obligation; an attempted conversion whose count rose
    but is labelled a reduction (the axis conflated with the net); and a dropped negative result
    (the attempted-conversion record emptied).
    """
    # The committed reduction is columnar on disk; the mutations below index its records, so decode
    # once (a fresh measurement passes the views, for which decoding is a no-op).
    census_body = ms_census.decode_body(census_body)
    refs = ms_codec.refs_from_census(census_body)
    body = ms_codec.decode_body(body, refs)
    baseline = reduction_findings(body, census_body, authority)
    result: dict = {"baseline_findings": len(baseline), "honest": not baseline,
                    "specificity_holds": False, "mutations": {}}

    def check(label: str, mutated: dict, mutated_authority: dict, marker: str) -> bool:
        found = reduction_findings(mutated, census_body, mutated_authority)
        caught = any(marker in f for f in found)
        result["mutations"][label] = {"caught": caught, "findings": len(found),
                                      "delta": len(found) - len(baseline), "marker": marker}
        return caught

    def clone() -> dict:
        return json.loads(json.dumps(body))

    reachable = sorted(derive(census_body, authority)["reachable"])
    any_site = reachable[0]

    def applied(with_tests: bool) -> dict:
        entry = {
            "pattern": "FUNCTION_POINTER_TRANSMUTE",
            "before_site_ids": [any_site],
            "after_site_ids": [],
            "tests": ["cargo test"] if with_tests else [],
            "evidence": ["artifacts/phase25/source-census.json"],
            "abi_change": False,
            "lint_change": False,
        }
        return entry

    # m1: a reduction with no test evidence.
    def no_evidence() -> dict:
        b = clone()
        b["applied"] = [applied(with_tests=False)]
        b["counts"] = _counts(census_body, authority, b["applied"])
        return b

    m1 = check("reduction_without_test_evidence", no_evidence(), authority,
               "cites no passing test")

    # m2: a weakened safety lint.
    def weakened_lint() -> tuple[dict, dict]:
        a = dict(authority)
        lp = dict(authority.get("lint_policy") or {})
        lp["cargo_toml"] = lp.get("cargo_toml", "").replace(
            'unsafe_op_in_unsafe_fn = "deny"', 'unsafe_op_in_unsafe_fn = "allow"')
        a["lint_policy"] = lp
        return clone(), a

    b2, a2 = weakened_lint()
    m2 = check("lint_weakened", b2, a2, "weakens unsafe_op_in_unsafe_fn")

    # m3: a 'reduced' site that is still present in the live census.
    def still_present() -> dict:
        b = clone()
        b["applied"] = [applied(with_tests=True)]
        b["counts"] = _counts(census_body, authority, b["applied"])
        return b

    m3 = check("reduced_site_still_present", still_present(), authority, "still present")

    # m4: the frozen census disagreeing with the live census.
    def frozen_disagrees() -> dict:
        b = clone()
        b["frozen_census"]["body_hash"] = "0" * 64
        return b

    m4 = check("frozen_census_disagrees", frozen_disagrees(), authority, "disagrees")

    # m5: a worklist that omits a candidate class.
    def worklist_incomplete() -> dict:
        b = clone()
        b["worklist"] = b["worklist"][:-1]
        return b

    m5 = check("worklist_omits_a_class", worklist_incomplete(), authority,
               "does not account for exactly the reachable sites")

    # m6: a typed count.
    def typed_count() -> dict:
        b = clone()
        b["counts"]["sites_after"] += 1
        return b

    m6 = check("typed_count", typed_count(), authority, "not the derived `counts`")

    # m7: a reduction classified HIDDEN (a mere wrapper that leaves the operation in place).
    def hidden_class() -> tuple[dict, dict]:
        a = json.loads(json.dumps(authority))
        a.setdefault("reconstruction", {}).setdefault("operations", []).append(
            {"site_id": "us-hidden-mutation", "operation_kind": "RAW_POINTER_DEREFERENCE",
             "classification": "HIDDEN"})
        b = clone()
        b["reconstruction"] = derive_reconstruction(census_body, a)
        b["counts"] = _counts(census_body, a, b["applied"])
        return b, a

    b7, a7 = hidden_class()
    m7 = check("reduction_classified_hidden", b7, a7, "HIDDEN")

    # m8: a 'removed' site that is still present in the live census.
    def removed_site_still_present() -> tuple[dict, dict]:
        a = json.loads(json.dumps(authority))
        files = set((a["reconstruction"]["subsystem"]).get("files") or [])
        present = next(s for s in (census_body.get("sites") or [])
                       if str(s.get("file")) in files)
        a["reconstruction"]["operations"][0]["site_id"] = str(present["site_id"])
        a["reconstruction"]["operations"][0]["operation_kind"] = str(present["operation_kind"])
        b = clone()
        b["reconstruction"] = derive_reconstruction(census_body, a)
        b["counts"] = _counts(census_body, a, b["applied"])
        return b, a

    b8, a8 = removed_site_still_present()
    m8 = check("removed_site_still_present", b8, a8, "still present")

    # m9: a changed downstream verdict.
    def downstream_changed() -> tuple[dict, dict]:
        a = json.loads(json.dumps(authority))
        a["reconstruction"].setdefault("downstream_baseline", {})["drop_in_pass"] = 32
        b = clone()
        b["reconstruction"] = derive_reconstruction(census_body, a)
        return b, a

    b9, a9 = downstream_changed()
    m9 = check("downstream_verdict_changed", b9, a9, "downstream verdict changed")

    # m10: a relocation claimed for a kind with no boundary operation remaining.
    def relocation_without_boundary() -> tuple[dict, dict]:
        a = json.loads(json.dumps(authority))
        files = set((a["reconstruction"]["subsystem"]).get("files") or [])
        after = Counter(str(s.get("operation_kind")) for s in (census_body.get("sites") or [])
                        if str(s.get("file")) in files)
        absent = next((k for k in ("STATIC_MUT_ACCESS", "FFI_EXPORT", "INLINE_ASM",
                                   "UNSAFE_IMPL", "CASTED_POINTER")
                       if after.get(k, 0) == 0), "NO_SUCH_KIND")
        a["reconstruction"]["operations"].append(
            {"site_id": "us-reloc-mutation", "operation_kind": absent,
             "classification": "RELOCATED_TO_BOUNDARY"})
        b = clone()
        b["reconstruction"] = derive_reconstruction(census_body, a)
        b["counts"] = _counts(census_body, a, b["applied"])
        return b, a

    b10, a10 = relocation_without_boundary()
    m10 = check("relocation_without_boundary", b10, a10,
                "RELOCATED_TO_BOUNDARY, but no")

    # m11: a differential harness that did not run (no candidate transcript).
    def harness_did_not_run() -> tuple[dict, dict]:
        a = json.loads(json.dumps(authority))
        a.setdefault("differential", {}).setdefault("body", {})["candidate"] = {}
        return clone(), a

    b11, a11 = harness_did_not_run()
    m11 = check("differential_harness_did_not_run", b11, a11, "did not run")

    # m12: an unadjudicated allocator divergence.
    def unadjudicated_divergence() -> tuple[dict, dict]:
        a = json.loads(json.dumps(authority))
        cmp_ = a.setdefault("differential", {}).setdefault("body", {})
        cmp_.setdefault("comparison", {})["divergences"] = [
            {"field": "alloc.sizes", "class": "NODE_BLOCK_SIZE", "adjudication": "unadjudicated",
             "reason": ""}]
        cmp_["comparison"]["unadjudicated"] = [{"field": "alloc.sizes"}]
        return clone(), a

    b12, a12 = unadjudicated_divergence()
    m12 = check("unadjudicated_allocator_divergence", b12, a12, "unadjudicated")

    # m13: a missing re-entrancy obligation (no evidence).
    def missing_reentrancy() -> tuple[dict, dict]:
        a = json.loads(json.dumps(authority))
        ob = a.setdefault("differential", {}).setdefault("body", {}).setdefault(
            "reentrancy_obligation", {})
        ob["evidence"] = []
        return clone(), a

    b13, a13 = missing_reentrancy()
    m13 = check("missing_reentrancy_obligation", b13, a13, "re-entrancy obligation")

    # m14: a conversion whose measured count rose, labelled a reduction -- the axis conflated with
    # the net. The verdict is flipped from REVERTED_NOT_A_REDUCTION to a reduction word while the
    # recorded before/after counts still show the rise.
    def count_increase_labelled_reduction() -> tuple[dict, dict]:
        a = json.loads(json.dumps(authority))
        convs = a.setdefault("reconstruction", {}).get("attempted_conversions") or []
        if convs:
            convs[0]["verdict"] = "REDUCED"
        b = clone()
        b["reconstruction"] = derive_reconstruction(census_body, a)
        return b, a

    b14, a14 = count_increase_labelled_reduction()
    m14 = check("count_increase_labelled_reduction", b14, a14, "conflates")

    # m15: the negative result dropped -- the attempted-conversion record emptied, so the conversion
    # that raised the count is silently forgotten.
    def negative_result_dropped() -> tuple[dict, dict]:
        a = json.loads(json.dumps(authority))
        a.setdefault("reconstruction", {})["attempted_conversions"] = []
        b = clone()
        b["reconstruction"] = derive_reconstruction(census_body, a)
        return b, a

    b15, a15 = negative_result_dropped()
    m15 = check("negative_result_dropped", b15, a15, "negative result")

    result["specificity_holds"] = bool(m1 and m2 and m3 and m4 and m5 and m6 and m7 and m8
                                      and m9 and m10 and m11 and m12 and m13 and m14 and m15
                                      and not baseline)
    result["caught"] = sum(1 for v in result["mutations"].values() if v["caught"])
    result["seeded"] = len(result["mutations"])
    return result


# --------------------------------------------------------------------------------------------
# self-test
# --------------------------------------------------------------------------------------------

def _synth_authority() -> dict:
    """A tiny, self-consistent plane: four reachable sites and one unreachable, and the lint policy."""
    census = {"sites": [
        {"site_id": "us-tls-1", "file": "src/ssl/record/rec.rs", "line": 10,
         "operation_kind": "RAW_POINTER_READ"},
        {"site_id": "us-tls-2", "file": "src/ssl/record/rec.rs", "line": 20,
         "operation_kind": "RAW_POINTER_DEREFERENCE"},
        {"site_id": "us-api-1", "file": "src/bn/bn_lib.rs", "line": 40,
         "operation_kind": "UNSAFE_FUNCTION_CALL"},
        {"site_id": "us-exp-1", "file": "src/ssl/ssl_lib.rs", "line": 50,
         "operation_kind": "FFI_EXPORT"},
        {"site_id": "us-test-1", "file": "src/tests/x.rs", "line": 60,
         "operation_kind": "RAW_POINTER_READ"},
    ]}
    exposure = {"body": {"sites": {
        "us-tls-1": {"e": "NETWORK_SERVER_REACHABLE", "r": "S1"},
        "us-tls-2": {"e": "CLI_INPUT_REACHABLE", "r": "S1"},
        "us-api-1": {"e": "LOCAL_API_REACHABLE", "r": "S2"},
        "us-exp-1": {"e": "CLI_INPUT_REACHABLE", "r": "S3"},
        "us-test-1": {"e": "TEST_ONLY", "r": "S4"},
    }}}
    return {
        "census": census,
        "exposure": exposure,
        "reconstruction": {
            "subsystem": {"id": "runtime/synthetic", "files": ["src/bn/bn_lib.rs"],
                          "mechanism": "synthetic", "why_internal": "synthetic"},
            "operations": [{"site_id": "us-gone-1", "operation_kind": "RAW_POINTER_READ",
                            "classification": "ELIMINATED"}],
            "axis": {
                "statement": "synthetic axis",
                "per_conversion_fields": ["ELIMINATED", "RELOCATED_TO_BOUNDARY", "HIDDEN"],
                "never_conflated": "synthetic",
            },
            "attempted_conversions": [{
                "id": "synthetic-attempt",
                "subsystem": "synthetic",
                "files": ["src/bn/bn_lib.rs"],
                "mechanism": "synthetic",
                "counts": {"subsystem_before": 10, "subsystem_after": 12,
                           "crate_before": 100, "crate_after": 102},
                "differential": {"ran": True, "authority": "synthetic",
                                 "candidate": "synthetic", "fields_matched": ["synthetic"],
                                 "divergence": "synthetic"},
                "classification": {"ELIMINATED": None, "RELOCATED_TO_BOUNDARY": None,
                                   "HIDDEN": 0},
                "residual_boundary": {"set": ["synthetic"], "size": None},
                "verdict": "REVERTED_NOT_A_REDUCTION",
                "obstruction": "synthetic",
            }],
            "next_targets": [{
                "id": "synthetic-target", "subsystem": "synthetic",
                "files": ["src/bn/bn_lib.rs"], "interior_operations": 1,
                "interior_by_kind": {"RAW_POINTER_READ": 1},
                "why_next": "synthetic", "why_tractable": "synthetic",
                "risk": "synthetic", "not_chosen": "synthetic",
            }],
            "tests": ["cargo test --lib"],
        },
        "downstream": {},
        "differential": {"body": {
            "authority": {"impl": "openssl-3.6.4", "transcript": {"num": 1}},
            "candidate": {"impl": "openssl-rs", "transcript": {"num": 1}},
            "comparison": {"all_match": True, "divergences": [], "unadjudicated": []},
            "reentrancy_obligation": {"caller": "synthetic", "wrapper_sites": ["synthetic"],
                                     "evidence": ["synthetic"], "disposition": "synthetic"},
            "residual_unsafe_boundary": [{"boundary": "synthetic", "operation": "synthetic"}],
        }},
        "lint_policy": {"cargo_toml": _read(CARGO_TOML), "lib_rs": _read(LIB_RS)},
        "census_sha256": "0" * 64,
    }


def self_test() -> int:
    """Prove the metadata-only admission holds, the derivation is clean and the control is honest."""
    failures: list = []

    admission = phase25_guard.evaluate(entry_point="ms_reduction.py", env={}, dockerenv=False)
    if not admission["admitted"] or admission["venue"] != "metadata-only":
        failures.append("ms_reduction.py is not admitted as a metadata-only generator on a host")

    authority = _synth_authority()
    census = authority.pop("census")
    body = build_body(census, authority)
    baseline = reduction_findings(body, census, authority)
    if baseline:
        failures.append(f"the synthetic reduction body is not clean: {baseline[:4]}")
    c = body["counts"]
    if c["reachable_after"] != 4:
        failures.append(f"the synthetic reachable count is wrong: {c}")
    if c["reduced"] != 1 or c["reconstruction_reduced"] != 1 or c["reachable_reduced"] != 1 \
            or c["applied"] != 0 or c["rejected"] != 4:
        failures.append(f"the synthetic reduction counts are wrong: {c}")
    if body["applied"]:
        failures.append("the synthetic reduction applied a worklist reduction")
    rec = body["reconstruction"]
    if rec["operations"]["by_class"] != {"ELIMINATED": 1} or rec["counts"]["after"]["sites"] != 1:
        failures.append(f"the synthetic reconstruction counts are wrong: {rec['counts']}")
    if body["frozen_census"]["body_hash"] != content_hash(census):
        failures.append("the synthetic frozen census does not bind the census body")
    control = reduction_sensitivity_control(body, census, authority)
    if not control["specificity_holds"] or control["caught"] != control["seeded"]:
        failures.append(f"the sensitivity control is not honest: {control}")

    if failures:
        print("[ms-reduction] self-test FAILED")
        for f in failures:
            print(f"  {f}")
        return 1
    print("[ms-reduction] self-test ok: the guard admits it as metadata-only; the synthetic "
          "reduction is clean (4 reachable sites over the closed candidate table, 0 worklist "
          "applications, one reconstructed subsystem); and every seeded mutation (a reduction "
          "with no test evidence, a weakened lint, a reduced site still present, a frozen census "
          "that disagrees, a worklist that omits a class, a typed count, a HIDDEN classification, "
          "a removed site still present, a changed downstream verdict, a relocation with no "
          "boundary operation, a differential harness that did not run, an unadjudicated "
          "allocator divergence, a missing re-entrancy obligation, a count increase labelled a "
          "reduction and a dropped negative result) is caught with specificity holding")
    return 0


# --------------------------------------------------------------------------------------------
# entry points
# --------------------------------------------------------------------------------------------

def _write_plane(path: Path, doc: dict) -> None:
    """Write the plane compactly, key-sorted and deterministic."""
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    path.write_text(text, encoding="utf-8")


def _inputs() -> list:
    return [
        InputRef(name="phase-25-plan", path=PLAN),
        InputRef(name="memory-safety-schemas", path=SCHEMAS),
        InputRef(name="phase25-guard", path=GUARD),
        InputRef(name="phase25-container-manifest", path=MANIFEST),
        InputRef(name="ms-reduction-tool", path=TOOL),
        InputRef(name="source-census", path=CENSUS),
        InputRef(name="exposure", path=EXPOSURE),
        InputRef(name="unsafe-reconstruction", path=RECONSTRUCTION),
        InputRef(name="sparse-array-differential", path=SPARSE_ARRAY_DIFFERENTIAL),
        InputRef(name="downstream-p1000-run", path=DOWNSTREAM_P1000),
        InputRef(name="downstream-runtime-functional-atlas", path=DOWNSTREAM_RUNTIME),
        InputRef(name="cargo-toml", path=CARGO_TOML),
        InputRef(name="lib-rs", path=LIB_RS),
    ]


def live_census_sha256() -> str:
    """The sha256 of the committed census file, so a court can bind the frozen census to the bytes
    on disk (this is the one frozen-census check that is not a pure function of the census body)."""
    return sha256_file(CENSUS) if CENSUS.is_file() else "unknown"


def _measure() -> int:
    """Derive the reduction worklist from the committed planes and write it."""
    census_body = ms_census.decode_body(_body(_load(CENSUS)))
    refs = ms_codec.refs_from_census(census_body)
    authority = load_authority()
    body = build_body(census_body, authority)
    problems = reduction_findings(body, census_body, authority)

    auth = resolve_authority(PRODUCTION_AUTHORITY)
    encoded = ms_codec.encode_body(body, refs)
    doc = envelope(kind="phase25-unsafe-reduction", authority=auth.id, inputs=_inputs(),
                   body=encoded, generator=GENERATOR)
    doc["body_hash"] = content_hash(encoded)
    _write_plane(OUT, doc)

    c = body["counts"]
    print(f"[ms-reduction] {c['reachable_after']} externally reachable site(s) over "
          f"{c['patterns']} candidate class(es); worklist reductions: {c['applied']} applied, "
          f"{c['rejected']} preserved")
    r = body["reconstruction"]
    print(f"  reconstruction: {r['subsystem']['id']} -- {r['operations']['count']} operation(s) "
          f"removed ({r['operations']['by_class']}); subsystem {r['counts']['before']['sites']} -> "
          f"{r['counts']['after']['sites']}, crate {c['sites_before']} -> {c['sites_after']}; "
          f"downstream drop_in_pass={r['downstream']['drop_in_pass']}, "
          f"workloads={r['downstream']['functional_workloads']}")
    print(f"  census: {c['sites_after']} compiler-derived site(s); frozen sha256 "
          f"{body['frozen_census']['sha256'][:16]}; body_hash "
          f"{body['frozen_census']['body_hash'][:16]}")
    for e in body["worklist"]:
        print(f"  {e['sites']['count']:7d}  {e['pattern']}")
    print(f"  -> {rel(OUT)} all_pass={not problems} (findings={len(body['findings'])}, "
          f"residuals={len(body['residuals'])})")
    if problems:
        for p in problems[:24]:
            print(f"    {p}")
    return 0 if not problems else 1


def _check() -> int:
    """Re-run the pure checks over the committed reduction, without a compiler."""
    if not OUT.is_file():
        print(f"[ms-reduction] {rel(OUT)} is absent; run --measure")
        return 1
    body = _body(_load(OUT))
    census_body = ms_census.decode_body(_body(_load(CENSUS)))
    refs = ms_codec.refs_from_census(census_body)
    body = ms_codec.decode_body(body, refs)
    authority = load_authority()
    problems = reduction_findings(body, census_body, authority)
    if problems:
        print(f"[ms-reduction] check FAILED: {len(problems)} problem(s)")
        for p in problems[:24]:
            print(f"  {p}")
        return 1
    c = body["counts"]
    r = body.get("reconstruction") or {}
    rc = r.get("counts") or {"after": {"sites": 0}}
    print(f"[ms-reduction] check ok: {c['reachable_after']} reachable site(s) over "
          f"{c['patterns']} candidate class(es), {c['applied']} worklist reduction(s); the "
          f"reconstruction removed {r.get('operations', {}).get('count', 0)} operation(s) from "
          f"{r.get('subsystem', {}).get('id', '')} and the downstream headline is unchanged; the "
          f"frozen census matches the live census; {len(body['residuals'])} residual(s); every "
          f"check holds")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--measure", action="store_true",
                    help="derive artifacts/phase25/unsafe-reduction.json from the committed inputs")
    ap.add_argument("--check", action="store_true",
                    help="re-run the pure checks over the committed reduction")
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
