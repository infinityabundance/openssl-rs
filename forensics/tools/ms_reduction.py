#!/usr/bin/env python3
"""openssl-rs — Phase 25.8, the unsafe reduction.

Phase 25 is the memory-safety stratum (`docs/RELEASE_GATES.md` section 1,
`docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md`). This module is 25.8's instrument: it derives the
**reduction worklist** over the reachable, compiler-derived unsafe sites of the exact admitted
candidate -- the sites a safe intrinsic or a checked wrapper could remove -- and records, per
candidate class, the proposed transformation, the argument that it would preserve behaviour, the
risk that it touches the ABI or observable behaviour, and whether the venue can prove it.

The honesty rule this subphase is built around
----------------------------------------------
Section 3.4 of the plan and the brief's sections 39 and 40 fix what a reduction may never be: it is
never a lint silenced to make a site disappear, never a change to the public surface or the foreign
ABI, and never the merging of blocks or the consolidation of pointers into one helper merely to move
the count. A reduction is admissible only when it replaces an unsafe operation with a real safe
intrinsic or a checked wrapper **and** can be shown behaviour-preserving **and** leaves the crate's
tests and every court passing. A candidate the venue cannot prove safe stays on the worklist with its
reason -- that is the honest outcome, and a worklist with zero applied reductions is acceptable.

The measured outcome of this venue is **zero applied reductions**, and the reason is structural
rather than a shortcut: every reachable unsafe site in the claimed profile is a C-ABI-boundary
operation (a dereference of a foreign `*const`/`*mut` C object, a call to a foreign `unsafe fn`, a
type-erasure `transmute` at a dynamically resolved symbol, a `#[no_mangle] pub unsafe extern "C"`
export, a `static mut` access, or a `from_raw_parts` over a field of a raw C object). Replacing any
of them with a safe intrinsic would either change a function signature or the foreign ABI, or turn a
documented precondition the authority states into a defined panic, or remove no site at all because
the census site is the enclosing raw dereference rather than the call. None is a behaviour-preserving
reduction, so none is applied and all are preserved on the worklist.

Why the tool needs no compiler
------------------------------
25.1's census (`forensics/tools/ms_census.py`) is the compiler-backed measurement and is a
measurement-precedent tool that `evidence_determinism.py` does not regenerate. Because this venue
applies no reduction, the census is unchanged, and 25.8 is a **pure function of committed inputs**:
the committed 25.1 census, the committed 25.7 exposure classification and the committed source spans
the census names. It compiles nothing -- no compiler, no clippy, no nightly -- so
`forensics/memory-safety/container.json` lists it `metadata_only` and the guard admits it on any host,
and `evidence_determinism.py` byte-compares `artifacts/phase25/unsafe-reduction.json` like the other
Phase-25 derivations. Had a reduction been applied, re-running the compiler census would have been
required and this tool would have followed the measurement precedent instead.

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

CENSUS_REL = rel(CENSUS)
EXPOSURE_REL = rel(EXPOSURE)
PLAN_REL = rel(PLAN)
SCHEMAS_REL = rel(SCHEMAS)
TOOL_REL = rel(TOOL)


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
    "statement about the availability of a safe intrinsic, not about the site's soundness",
    "behaviour preservation is stated for the inputs the authority's contract admits; the "
    "authority's undefined-behaviour cases are not transferred to a defined panic",
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
    read so a weakened lint is a finding. The exposure body is decoded here (the census supplies the
    ordered id lists it references by index)."""
    census_doc = _load(CENSUS) if CENSUS.is_file() else {"body": {}}
    census_body = ms_census.decode_body(census_doc.get("body", census_doc))
    refs = ms_codec.refs_from_census(census_body)
    exposure_doc = _load(EXPOSURE) if EXPOSURE.is_file() else {"body": {}}
    return {
        "exposure": {**exposure_doc,
                     "body": ms_codec.decode_body(exposure_doc.get("body", exposure_doc), refs)},
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
        f"candidate class across {len(by_pattern)} pattern(s); **0 were reduced**, so the reachable "
        f"count is unchanged",
        "every candidate replacement would change a function signature or the foreign ABI, turn a "
        "documented precondition the authority states into a defined panic, or remove no site "
        "because the census site is the enclosing raw dereference; consolidating repeated reads "
        "into one helper is forbidden by section 3.4 and the brief, so no candidate was applied",
        "the compiler-derived site count is unchanged and the operation-kind mix is unchanged; a "
        "smaller unsafe count would not be a memory-safety claim and the ABI and the lints are "
        "unchanged",
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
    """The before/after counts, derived from the census and the applied reductions."""
    exposure_body = _body(authority["exposure"])
    sites = census_body.get("sites") or []
    by_kind = Counter(str(s.get("operation_kind")) for s in sites)
    reachable = _reachable(census_body, exposure_body)
    reachable_set = set(reachable)
    by_exp: Counter = Counter()
    esites = exposure_body.get("sites") or {}
    for sid in reachable:
        by_exp[str((esites.get(sid) or {}).get("e"))] += 1
    reduced = sum(len(a.get("before_site_ids") or []) - len(a.get("after_site_ids") or [])
                  for a in applied)
    return {
        "sites_before": len(sites) + reduced,
        "sites_after": len(sites),
        "reduced": reduced,
        "sites_by_kind_before": dict(sorted(by_kind.items())),
        "sites_by_kind_after": dict(sorted(by_kind.items())),
        "reachable_before": len(reachable) + reduced,
        "reachable_after": len(reachable),
        "reachable_reduced": reduced,
        "patterns": len({_classify(str(s.get("operation_kind")),
                                   _line_text(str(s.get("file")), int(s.get("line") or 0)))
                         for s in sites
                         if str(s.get("site_id")) in reachable_set}),
        "candidates": len(reachable),
        "applied": len(applied),
        "rejected": len(reachable) - reduced,
        "reachable_by_exposure": {k: by_exp[k] for k in sorted(by_exp)},
    }


def _rule() -> dict:
    return {
        "authority": {
            "kind": "committed-phase25-planes",
            "paths": [CENSUS_REL, EXPOSURE_REL, PLAN_REL, SCHEMAS_REL, TOOL_REL],
            "declaration": (
                "the committed 25.1 census is the compiler-derived primary unit, the committed 25.7 "
                "exposure classification is the reachability authority (the census carries a "
                "placeholder class), and the committed source spans the census names are read only "
                "to name the candidate transformation -- a site is never derived from a text scan"),
        },
        "classification": (
            "each reachable compiler-derived site is assigned exactly one candidate class by a "
            "total function of its operation kind and its committed source span text; the class "
            "names the proposed safe-intrinsic replacement, not a new unit"),
        "admissibility": ADMISSIBILITY,
        "census_changed": False,
        "no_reduction_reason": (
            "no reduction was applied because no candidate can be shown behaviour-preserving: every "
            "reachable site is a C-ABI-boundary operation whose safe replacement would change a "
            "signature or the foreign ABI, or introduce a panic where the authority states a "
            "precondition, or remove no site at all"),
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
        "note": ("the post-reduction baseline later subphases work against: because this venue "
                 "applies no reduction, it is the committed 25.1 census unchanged, and the frozen "
                 "hashes bind it"),
    }


def build_body(census_body: dict, authority: dict) -> dict:
    """The reduction body: the rule, the worklist, the (empty) applied set, the frozen census and
    the counts."""
    d = derive(census_body, authority)
    applied: list = []
    counts = _counts(census_body, authority, applied)
    return {
        "rule": _rule(),
        "worklist": d["worklist"],
        "applied": applied,
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
    census disagreeing with the live census; a worklist that omits a candidate class; and a typed
    count.
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

    result["specificity_holds"] = bool(m1 and m2 and m3 and m4 and m5 and m6 and not baseline)
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
    if c["reduced"] != 0 or c["applied"] != 0 or c["rejected"] != 4:
        failures.append(f"the synthetic reduction counts are wrong: {c}")
    if body["applied"]:
        failures.append("the synthetic reduction applied a reduction")
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
          "reduction is clean (4 reachable sites over the closed candidate table, 0 applied); and "
          "every seeded mutation (a reduction with no test evidence, a weakened lint, a reduced "
          "site still present, a frozen census that disagrees, a worklist that omits a class and a "
          "typed count) is caught with specificity holding")
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
          f"{c['patterns']} candidate class(es); reduced: {c['reduced']} ({c['applied']} "
          f"applied, {c['rejected']} preserved on the worklist)")
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
    census_body = _body(_load(CENSUS))
    authority = load_authority()
    problems = reduction_findings(body, census_body, authority)
    if problems:
        print(f"[ms-reduction] check FAILED: {len(problems)} problem(s)")
        for p in problems[:24]:
            print(f"  {p}")
        return 1
    c = body["counts"]
    print(f"[ms-reduction] check ok: {c['reachable_after']} reachable site(s) over "
          f"{c['patterns']} candidate class(es), {c['reduced']} reduced; the frozen census matches "
          f"the live census; {len(body['residuals'])} residual(s); every check holds")
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
