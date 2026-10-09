#!/usr/bin/env python3
"""openssl-rs — the safety obligations per compiler-derived unsafe site (Phase 25.3).

Phase 25 is the memory-safety stratum (`docs/RELEASE_GATES.md` section 1,
`docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md`). Its primary unit is a **compiler-derived unsafe
operation**; 25.1's census enumerates those operations and their enclosing unsafe contexts, and
25.2's non-Rust TCB records the C/asm/FFI part. This subphase is 25.3: it gives every census site an
explicit soundness contract along the closed `OBLIGATION_DIMENSIONS`, so **no reachable unsafe site
is left unexplained**.

The obligation is a dimension, not a confidence
----------------------------------------------
An unsafe operation is sound only if the properties it requires are established. Those properties
are the closed `memory_safety_schemas.OBLIGATION_DIMENSIONS` (nullability, lifetime, aliasing,
alignment, initialization, bounds, ownership, refcount, thread affinity, ABI, unwind, type validity,
send/sync, panic safety, pointer provenance, init-once and validity). A **deterministic
operation-kind → dimension mapping** — recorded in the artefact's `rule`, so the court can reproduce
it rather than trust it — names the dimensions each compiler-derived operation kind requires: a raw
write needs alignment/initialization/bounds (and nullability/aliasing/provenance), a `from_raw_parts`
call needs lifetime/alignment/bounds, an allocation/free needs ownership/provenance, a callback cast
needs lifetime/function-pointer-validity, an FFI export needs ABI/unwind, and so on.

Three classifications, and a comment is never a discharge
--------------------------------------------------------
Each required dimension of a site is classified from the **source-stated contract** the site's
context carries (its `// SAFETY:` comment or `# Safety` doc section, indexed here as
`safety_comment_present`, its span, and the dimension codes it names):

  * `discharged` — a source-stated contract names the dimension **and** the caller chain establishes
    it. A `// SAFETY:` comment is the *author's statement*, not the caller chain's establishment, so
    naming a dimension in one is **never** a discharge: this stratum records that establishment as
    not measured (the Phase-22 reachability crosswalk is 25.5's, the dynamic/formal evidence is
    25.9–25.12's). The tool never upgrades `stated`/`open` to `discharged`.
  * `stated` — a source-stated contract names the dimension but nothing verifies it.
  * `open` — no source-stated contract names the dimension.

A high-risk site whose contract **escapes to its caller** (an unsafe `fn`, an unsafe `impl`, an
extern block, an FFI export, or a block whose contract says "the caller's contract") carries its
obligation to a caller this stratum cannot show establishes it; that is recorded as a **finding**,
never as a discharge.

Compact by reference, re-derivable in full
------------------------------------------
The artefact binds each site **once**, by reference to a grouped contract (one per distinct
`(operation_kind, basis, escape, named-dimension set)`), so identical contracts are recorded once and
every site's obligation set is re-derived from the census plus the bound `rule`. The court
(`MS-SAFETY-OBLIGATIONS`) re-derives every site's obligations from the committed census and the
artefact and refuses a site that is unbound, an open obligation that is hidden, a `discharged`
without a source-stated contract and a discharging proof, a dimension set the mapping does not
reproduce, and a count that was typed rather than derived.

A pure derivation, so it executes nothing
-----------------------------------------
It reads the committed `source-census.json` and `non-rust-tcb.json` and writes a derived plane; it
runs no compiler, no tool and no probe, so `forensics/memory-safety/container.json` lists it
`metadata_only` and the Docker-only guard admits it on any host (it still calls the guard first).

Outputs
-------
  artifacts/phase25/safety-obligations.json

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import re
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
    sha256_bytes,
)

# The Docker-only execution guard, called first. This tool executes nothing -- it derives a plane
# from committed artefacts -- so the manifest lists it `metadata_only` and the guard admits it on any
# host exactly as `phase25_obligations.py` is; the call is still first so the rule is never optional.
import phase25_guard  # noqa: E402

# The record kind and its closed vocabularies. Imported, never restated, so the obligations cannot
# drift from the schema the court validates them against.
import memory_safety_schemas as schemas  # noqa: E402

# The census (for the site universe and its ordered id lists) and the lossless columnar codec both
# the census and this plane are stored in. One implementation of the scheme serves every reader.
import ms_census  # noqa: E402
import ms_codec  # noqa: E402

OUT = REPO_ROOT / "artifacts" / "phase25" / "safety-obligations.json"
GENERATOR = "forensics/tools/ms_obligations.py"
TOOL = REPO_ROOT / "forensics/tools" / "ms_obligations.py"
SCHEMAS = REPO_ROOT / "forensics" / "tools" / "memory_safety_schemas.py"
GUARD = REPO_ROOT / "forensics" / "tools" / "phase25_guard.py"
PLAN = REPO_ROOT / "docs" / "PHASE-25-MEMORY-SAFETY-SUBPHASES.md"
MANIFEST = REPO_ROOT / "forensics" / "memory-safety" / "container.json"
CENSUS = REPO_ROOT / "artifacts" / "phase25" / "source-census.json"
TCB = REPO_ROOT / "artifacts" / "phase25" / "non-rust-tcb.json"

DIMENSIONS = list(schemas.OBLIGATION_DIMENSIONS)
OPERATION_KINDS = list(schemas.UNSAFE_OPERATION_KINDS)

# The compact dimension codes the site bindings carry, one per closed dimension. Kept short because
# the binding is the compact half of the artefact: 57,663 sites each name their dimension set as a
# code string, and the court decodes it back to dimensions via the same table in `rule`.
DIMENSION_CODES: dict[str, str] = {
    "NULLABILITY": "NU", "LIFETIME": "LI", "ALIASING": "AI", "ALIGNMENT": "AG",
    "INITIALIZATION": "IN", "BOUNDS": "BO", "OWNERSHIP": "OW", "REFCOUNT": "RC",
    "THREAD_AFFINITY": "TA", "ABI": "AB", "UNWIND": "UW", "TYPE_VALIDITY": "TV",
    "SEND_SYNC": "SS", "PANIC_SAFETY": "PS", "POINTER_PROVENANCE": "PP",
    "INIT_ONCE": "IO", "VALIDITY": "VA",
}
CODE_DIMENSIONS: dict[str, str] = {c: d for d, c in DIMENSION_CODES.items()}

# The deterministic operation-kind -> dimension mapping. The dimensions a compiler-derived operation
# kind requires for soundness, over the closed vocabulary. **This is the rule the artefact records
# and the court reproduces**; the dimensions are canonicalised into `OBLIGATION_DIMENSIONS` order, so
# a code string is a stable function of the kind alone. The mapping is by operation kind, because the
# census classifies each site's operation and does not name the callee; hence `from_raw_parts` is a
# `UNSAFE_FUNCTION_CALL` here and the allocation/free/callback cases are the function/method calls.
KIND_DIMENSIONS: dict[str, list[str]] = {
    # raw memory access: the pointer must be non-null, live, aligned, initialised, in bounds and
    # point into a live allocation; a write additionally requires no aliasing reader/writer.
    "RAW_POINTER_DEREFERENCE": ["NULLABILITY", "LIFETIME", "ALIGNMENT", "INITIALIZATION", "BOUNDS",
                                "POINTER_PROVENANCE"],
    "RAW_POINTER_READ": ["NULLABILITY", "LIFETIME", "ALIGNMENT", "INITIALIZATION", "BOUNDS",
                         "POINTER_PROVENANCE"],
    "RAW_POINTER_WRITE": ["NULLABILITY", "LIFETIME", "ALIASING", "ALIGNMENT", "INITIALIZATION",
                          "BOUNDS", "POINTER_PROVENANCE"],
    "UNALIGNED_ACCESS": ["ALIGNMENT", "INITIALIZATION", "BOUNDS", "POINTER_PROVENANCE"],
    # an unsafe function/method call requires the callee's preconditions: its arguments must be
    # valid, live, non-null, unaliased and point into the allocation the callee expects (this is the
    # `from_raw_parts`, allocation and free surface too, which the census does not name separately).
    "UNSAFE_FUNCTION_CALL": ["NULLABILITY", "LIFETIME", "ALIASING", "POINTER_PROVENANCE", "VALIDITY"],
    "UNSAFE_METHOD_CALL": ["NULLABILITY", "LIFETIME", "ALIASING", "POINTER_PROVENANCE", "VALIDITY"],
    "UNSAFE_TRAIT_METHOD": ["LIFETIME", "ALIASING", "TYPE_VALIDITY", "VALIDITY"],
    # an unsafe impl (Send/Sync and friends) carries the trait's invariant to every user.
    "UNSAFE_IMPL": ["ALIASING", "THREAD_AFFINITY", "SEND_SYNC", "VALIDITY"],
    # an extern call is an ABI/unwind boundary: the call must use the declared ABI and not let a
    # panic unwind across it.
    "EXTERN_FUNCTION_CALL": ["NULLABILITY", "ABI", "UNWIND", "VALIDITY"],
    "UNION_FIELD_ACCESS": ["ALIGNMENT", "INITIALIZATION", "TYPE_VALIDITY", "VALIDITY"],
    "TRANSMUTE": ["ALIGNMENT", "LIFETIME", "TYPE_VALIDITY", "VALIDITY"],
    "UNSAFE_CAST": ["ALIGNMENT", "POINTER_PROVENANCE", "TYPE_VALIDITY", "VALIDITY"],
    "INLINE_ASM": ["ABI", "UNWIND", "POINTER_PROVENANCE", "VALIDITY"],
    # an FFI export is the ABI/unwind boundary the C side calls.
    "FFI_EXPORT": ["NULLABILITY", "ABI", "UNWIND", "VALIDITY"],
    "C_VARIADIC_BOUNDARY": ["ABI", "BOUNDS", "VALIDITY"],
    "STATIC_MUT_ACCESS": ["LIFETIME", "ALIASING", "INITIALIZATION", "THREAD_AFFINITY"],
    "ASSERT_UNCHECKED": ["BOUNDS", "VALIDITY"],
}

# The unsafe contexts whose contract **escapes to the caller**: an unsafe `fn`/`impl`/trait, an
# extern block and an FFI export all state a precondition the caller must uphold, so the obligation
# is carried outward rather than established at the site. An unsafe block is local unless its own
# contract says otherwise (the escape *token* below).
ESCAPING_CONTEXT_KINDS: frozenset[str] = frozenset({
    "UNSAFE_FN", "UNSAFE_IMPL", "UNSAFE_TRAIT", "EXTERN_BLOCK", "FFI_EXPORT_FN",
})
ESCAPE_TOKEN = "caller"

# The high-risk operation kinds whose enclosing function and caller-escape are recorded as a finding.
HIGH_RISK_KINDS: frozenset[str] = frozenset({
    "RAW_POINTER_DEREFERENCE", "RAW_POINTER_WRITE", "TRANSMUTE", "UNION_FIELD_ACCESS",
    "UNSAFE_IMPL", "FFI_EXPORT", "EXTERN_FUNCTION_CALL", "STATIC_MUT_ACCESS", "INLINE_ASM",
    "UNALIGNED_ACCESS", "C_VARIADIC_BOUNDARY",
})

# The proofs that would *discharge* a dimension. `DOCUMENTED_PRECONDITION` is deliberately absent: a
# `// SAFETY:` comment is a documented precondition, i.e. a statement, so naming a dimension in one
# can never be a discharge. Nothing in this stratum supplies one of these witnesses, so no obligation
# is `discharged`; the court refuses a `DISCHARGED` record whose proof is not on this list.
DISCHARGING_PROOFS: frozenset[str] = frozenset({
    "PROOF", "RUNTIME_CHECK", "TYPE_SYSTEM", "TEST", "TOOL_EVIDENCE",
})

# The keyword table the source-stated contract is indexed with: a dimension is *named* when any of
# its patterns matches the contract text, case-insensitively. This is a deterministic classification
# over the comment (like 25.1's operation kind over the span), recorded in `rule` so the court can
# reproduce it; it is a secondary label on a source-stated contract, not a compiler fact.
NAMED_KEYWORDS: dict[str, tuple[str, ...]] = {
    "NULLABILITY": (r"\bnon-null\b", r"\bnull\b", r"\bnul\b", r"nul-terminated"),
    "LIFETIME": (r"\blive\b", r"lifetime", r"outliv", r"dangling", r"\bstatic\b"),
    "ALIASING": (r"alias", r"uniqu", r"exclusive", r"no other"),
    "ALIGNMENT": (r"\balign",),
    "INITIALIZATION": (r"initializ", r"\buninit", r"compile-time-constant", r"compiled-in",
                       r"static literal"),
    "BOUNDS": (r"in bounds", r"out of bounds", r"\bwithin\b", r"\blength\b", r"readable for",
               r"writable for", r"\bbytes\b", r"multiple of", r"\bsized?\b", r"capacity", r"in range"),
    "OWNERSHIP": (r"\bown", r"\bfree", r"dealloc", r"\bdrop", r"allocation"),
    "REFCOUNT": (r"refcount", r"reference count", r"ref count"),
    "THREAD_AFFINITY": (r"\bthread",),
    "ABI": (r"\babi\b", r"calling convention", r"repr\(c\)", r'extern "c"'),
    "UNWIND": (r"unwind",),
    "TYPE_VALIDITY": (r"\btype\b", r"\brepr\b", r"discriminant", r"bit pattern"),
    "SEND_SYNC": (r"\bsend\b", r"\bsync\b"),
    "PANIC_SAFETY": (r"\bpanic",),
    "POINTER_PROVENANCE": (r"provenance", r"points into", r"same allocation", r"derived from"),
    "INIT_ONCE": (r"\bonce\b",),
    "VALIDITY": (r"\bvalid",),
}
_NAMED_PATTERNS: dict[str, list[re.Pattern]] = {
    d: [re.compile(p, re.IGNORECASE) for p in pats] for d, pats in NAMED_KEYWORDS.items()
}

# The non-claims every Phase-25 artefact carries. Verbatim from
# docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md section 0.
NON_CLAIMS = (
    "safe Rust does not prove protocol correctness: memory safety is not behavioural correctness",
    "unsafe Rust is not inherently vulnerable: an unsafe operation with a discharged contract is "
    "sound, so an unsafe site is not a defect",
    "unsafe LOC is not a vulnerability count: lines of unsafe code are a secondary projection of "
    "the compiler-derived census, and a count is not a risk",
    "a `// SAFETY:` comment is a source-stated contract, i.e. the author's statement, not the "
    "caller chain's establishment; naming a dimension makes it stated, never discharged, so this "
    "stratum records no discharge and never upgrades a statement to one",
    "the operation-kind -> dimension mapping and the contract keyword index are deterministic "
    "classifications over the census and its comments, recorded in `rule`; they are labels on "
    "compiler-established units, not compiler facts",
    "the per-dimension classification records what the source states, not that the site is sound: "
    "an open or stated obligation is a recorded gap, and its establishment is later evidence's "
    "measurement (25.4, 25.5, 25.9-25.12), not this subphase's claim",
)


def _canon(dims) -> list[str]:
    """The dimensions in `OBLIGATION_DIMENSIONS` order, de-duplicated."""
    return sorted(set(dims), key=DIMENSIONS.index)


def _codes(dims) -> str:
    """The compact, canonical code string for a dimension set."""
    return "".join(DIMENSION_CODES[d] for d in _canon(dims))


def _decode_codes(codes: str) -> list[str]:
    """The dimensions a code string names, in order."""
    return [CODE_DIMENSIONS[codes[i:i + 2]] for i in range(0, len(codes), 2)]


def _named_by(dimension: str, text: str) -> str | None:
    """The first keyword of `dimension` the contract text matches, or None."""
    for pattern in _NAMED_PATTERNS[dimension]:
        if pattern.search(text):
            return pattern.pattern
    return None


def _named_dimensions(text: str) -> set[str]:
    """Every dimension the source-stated contract text names."""
    return {d for d in DIMENSIONS if _named_by(d, text) is not None}


def _escapes(context_kind: str, text: str) -> bool:
    """Whether the context's contract is carried to a caller rather than established at the site."""
    return context_kind in ESCAPING_CONTEXT_KINDS or ESCAPE_TOKEN in text.lower()


def _classification(named: bool) -> tuple[str, str, str]:
    """`(classification, status, discharged_by)` for a dimension that is (not) named.

    A named dimension is `stated` -- a source-stated contract is a statement, not a caller-chain
    establishment -- and never `discharged`; an unnamed one is `open`. There is deliberately no path
    to `discharged` from a contract alone: that would be the upgrade this stratum refuses.
    """
    if not named:
        return "open", "OPEN", "UNKNOWN"
    return "stated", "UNKNOWN", "DOCUMENTED_PRECONDITION"


def _dimension_records(operation_kind: str, basis: str, named_dims, escaping: bool) -> list[dict]:
    """The per-dimension obligation records of a contract, derived from the rule alone."""
    named = set(named_dims)
    out: list[dict] = []
    for dim in _canon(KIND_DIMENSIONS[operation_kind]):
        is_named = dim in named
        classification, status, proof = _classification(is_named)
        if is_named:
            evidence = [f"named by the source-stated contract (keyword index of {dim})"]
        else:
            evidence = [f"no source-stated contract dimension names {dim}"]
        if escaping and classification == "stated":
            evidence.append("the contract escapes to a caller; this stratum does not establish it")
        rec = {
            "dimension": dim,
            "code": DIMENSION_CODES[dim],
            "classification": classification,
            "status": status,
            "discharged_by": proof,
            "evidence": evidence,
        }
        if basis == "UNSTATED":
            rec["basis_note"] = "the context states no contract; this dimension is open"
        out.append(rec)
    return out


def _contract_id(operation_kind: str, basis: str, escaping: bool, named_dims) -> str:
    key = f"{operation_kind}\0{basis}\0{int(escaping)}\0{'|'.join(_canon(named_dims))}"
    return "obc-" + sha256_bytes(key.encode("utf-8"))[:16]


def _index(census_body: dict) -> tuple[dict, dict, list]:
    """`(context_by_id, site_by_id, sites)` from a census body, failing closed on a bad link."""
    ctx_by_id = {c.get("context_id"): c for c in census_body.get("unsafe_contexts") or []}
    sites = census_body.get("sites") or []
    site_by_id = {s.get("site_id"): s for s in sites}
    return ctx_by_id, site_by_id, sites


def derive(census_body: dict) -> dict:
    """Every site's binding and every grouped contract, re-derived from the census alone.

    Pure over the census body: no compiler, no disk. `build_body` and `obligation_findings` share
    it, so the artefact's content and the court's re-derivation cannot be two different rules.
    """
    ctx_by_id, site_by_id, sites = _index(census_body)
    bindings: list[dict] = []
    contracts: dict[str, dict] = {}
    absent: list[dict] = []
    named_by_site: dict[str, list[str]] = {}

    for ctx in census_body.get("unsafe_contexts") or []:
        if not ctx.get("site_ids"):
            basis = str(ctx.get("contract_state") or "UNSTATED")
            absent.append({
                "context_id": ctx.get("context_id"),
                "comment_present": basis == "STATED",
                "stated_codes": "",
                "reason": "NO_CLASSIFIED_OPERATION",
            })
    absent.sort(key=lambda r: str(r["context_id"]))

    for site in sites:
        site_id = site.get("site_id")
        ctx = ctx_by_id.get(site.get("context_id"))
        op = site.get("operation_kind")
        if ctx is None or op not in KIND_DIMENSIONS:
            continue
        basis = str(ctx.get("contract_state") or "UNSTATED")
        text = ctx.get("safety_contract") or ""
        required = _canon(KIND_DIMENSIONS[op])
        if basis == "STATED":
            named = [d for d in required if d in _named_dimensions(text)]
        else:
            named = []
        named = _canon(named)
        escaping = _escapes(str(ctx.get("kind") or ""), text)
        cid = _contract_id(op, basis, escaping, named)
        contracts.setdefault(cid, {
            "contract_id": cid,
            "operation_kind": op,
            "basis": basis,
            "escaping": escaping,
            "named_dimensions": named,
            "dimensions": _dimension_records(op, basis, named, escaping),
        })
        bindings.append({
            "site_id": site_id,
            "context_id": site.get("context_id"),
            "contract_id": cid,
            "codes": _codes(required),
            "comment_present": basis == "STATED",
            "stated_codes": _codes(named),
            "function": str(site.get("function") or ""),
        })
        named_by_site[site_id] = named

    bindings.sort(key=lambda b: str(b["site_id"]))
    contract_list = sorted(contracts.values(), key=lambda c: str(c["contract_id"]))
    return {
        "ctx_by_id": ctx_by_id,
        "site_by_id": site_by_id,
        "bindings": bindings,
        "by_site": {b["site_id"]: b for b in bindings},
        "contracts": contract_list,
        "by_contract": {c["contract_id"]: c for c in contract_list},
        "absent": absent,
        "named_by_site": named_by_site,
    }


def _counts(census_body: dict, d: dict, body: dict | None = None) -> dict:
    """The counts, derived from the census and the artefact's own records -- never typed."""
    ctx_by_id, _site_by_id, sites = _index(census_body)
    contracts = (body or {}).get("contracts")
    contracts = contracts if contracts is not None else d["contracts"]
    bindings = (body or {}).get("site_obligations")
    bindings = bindings if bindings is not None else d["bindings"]
    absent = (body or {}).get("site_absent_contexts")
    absent = absent if absent is not None else d["absent"]
    by_contract = {c.get("contract_id"): c for c in contracts}

    classification = Counter()
    obligations_by_dimension: Counter = Counter()
    stated_by_dimension: Counter = Counter()
    escaping_sites = 0
    escaping_obligations = 0
    uncontracted_sites = 0
    high_risk_sites = 0
    obligations = 0
    for b in bindings:
        contract = by_contract.get(b.get("contract_id")) or {}
        dims = {r.get("dimension"): r for r in contract.get("dimensions") or []}
        escaping = bool(contract.get("escaping"))
        if escaping:
            escaping_sites += 1
        if not b.get("comment_present"):
            uncontracted_sites += 1
        op = contract.get("operation_kind")
        if op in HIGH_RISK_KINDS:
            high_risk_sites += 1
        for dim in _decode_codes(str(b.get("codes") or "")):
            obligations += 1
            obligations_by_dimension[dim] += 1
            rec = dims.get(dim) or {}
            cls = rec.get("classification")
            classification[cls] += 1
            if cls == "stated":
                stated_by_dimension[dim] += 1
            if escaping and cls == "stated":
                escaping_obligations += 1

    represented = {b.get("context_id") for b in bindings} | {r.get("context_id") for r in absent}
    return {
        "census_sites": len(sites),
        "census_contexts": len(ctx_by_id),
        "sites_bound": len(bindings),
        "contexts_represented": len(represented),
        "contexts_without_site": len(absent),
        "contracts": len(contracts),
        "obligations": obligations,
        "discharged": classification["discharged"],
        "stated": classification["stated"],
        "open": classification["open"],
        "escaping_sites": escaping_sites,
        "escaping_obligations": escaping_obligations,
        "uncontracted_sites": uncontracted_sites,
        "uncontracted_contexts": sum(
            1 for c in ctx_by_id.values() if c.get("contract_state") != "STATED"),
        "high_risk_sites": high_risk_sites,
        "obligations_by_dimension": {d: obligations_by_dimension[d] for d in DIMENSIONS
                                     if obligations_by_dimension[d]},
        "named_by_dimension": {d: stated_by_dimension[d] for d in DIMENSIONS
                               if stated_by_dimension[d]},
    }


def _crosschecks(census_body: dict, tcb_body: dict) -> tuple[dict, list]:
    """The 25.2 cross-reference: every census FFI export must have a TCB boundary record."""
    _ctx, _site, sites = _index(census_body)
    boundaries = tcb_body.get("ffi_boundaries") or []
    inbound = {b.get("census_site") for b in boundaries
               if b.get("direction") == "INBOUND" and b.get("census_site")}
    ffi_sites = [s for s in sites if s.get("operation_kind") == "FFI_EXPORT"]
    extern_sites = [s for s in sites if s.get("operation_kind") == "EXTERN_FUNCTION_CALL"]
    covered = sum(1 for s in ffi_sites if s.get("site_id") in inbound)
    tcb_counts = tcb_body.get("counts") or {}
    residuals: list[dict] = []
    if covered != len(ffi_sites):
        residuals.append({
            "source": "non-rust-tcb", "class": "evidence_missing",
            "detail": (f"{len(ffi_sites) - covered} census FFI_EXPORT site(s) have no inbound "
                       f"boundary record in the non-Rust TCB inventory"),
        })
    crosschecks = {
        "tcb_boundary_records": len(boundaries),
        "census_ffi_export_sites": len(ffi_sites),
        "ffi_export_sites_with_boundary": covered,
        "census_extern_function_calls": len(extern_sites),
        "tcb_variadic_boundaries": int(tcb_counts.get("variadic_boundaries") or 0),
        "census_c_variadic_sites": sum(
            1 for s in sites if s.get("operation_kind") == "C_VARIADIC_BOUNDARY"),
    }
    return crosschecks, residuals


def _property_findings(counts: dict) -> list[str]:
    """The findings the artefact records: the gaps the instrument passes while naming."""
    return [
        f"{counts['open']} obligation dimension(s) are open: no source-stated SAFETY contract names "
        f"them ({counts['uncontracted_sites']} unsafe site(s) state no contract at all), recorded "
        f"open rather than hidden -- their establishment is later evidence's measurement, not this "
        f"subphase's claim",
        f"{counts['escaping_sites']} unsafe site(s) carry their contract to a caller "
        f"(escapes_to_caller): the {counts['escaping_obligations']} named dimension(s) on them are "
        f"the caller's obligation, and this stratum records the escape without establishing the "
        f"caller chain (the Phase-22 reachability crosswalk is 25.5's measurement), so they are "
        f"findings, never discharges",
        f"{counts['discharged']} obligation dimension(s) are classified discharged: a `// SAFETY:` "
        f"comment is a source-stated contract, so naming a dimension makes it stated, never "
        f"discharged, and this stratum never upgrades a statement to a discharge",
    ]


def build_body(census_body: dict, tcb_body: dict) -> dict:
    """The obligations body: the rule, the grouped contracts, the per-site bindings and the counts."""
    d = derive(census_body)
    crosschecks, residuals = _crosschecks(census_body, tcb_body)
    body = {
        "rule": {
            "authority": (
                "the compiler is the authority for unsafe operations, and 25.1's census is the "
                "authority for the sites: this plane assigns obligations to the compiler-derived "
                "unsafe operations 25.1 enumerated, and types no site"
            ),
            "dimension_source": (
                "the closed memory_safety_schemas.OBLIGATION_DIMENSIONS; every obligation names "
                "exactly one"
            ),
            "kind_dimensions": {k: _canon(v) for k, v in KIND_DIMENSIONS.items()},
            "dimension_codes": dict(DIMENSION_CODES),
            "named_dimension_keywords": {d: list(v) for d, v in NAMED_KEYWORDS.items()},
            "classification": {
                "discharged": (
                    "a source-stated contract names the dimension AND the caller chain establishes "
                    "it; nothing in this stratum measures the caller chain, so this records no "
                    "discharge"
                ),
                "stated": (
                    "a source-stated contract names the dimension but nothing verifies it; a "
                    "`// SAFETY:`/`# Safety` comment is a statement, so naming makes it stated"
                ),
                "open": "no source-stated contract names the dimension",
            },
            "escaping_context_kinds": sorted(ESCAPING_CONTEXT_KINDS),
            "escape_token": ESCAPE_TOKEN,
            "discharging_proofs": sorted(DISCHARGING_PROOFS),
            "obligation_id_scheme": "ob:<site_id>:<dimension_code>",
            "high_risk_kinds": sorted(HIGH_RISK_KINDS),
            "binding": (
                "each site is bound once, by reference to a grouped contract: the binding carries "
                "the site's dimension-code set, whether its context states a contract, the "
                "dimension codes the contract names, and the enclosing function; the court "
                "re-derives every site's obligation set from the census plus this rule"
            ),
        },
        "contracts": d["contracts"],
        "site_obligations": d["bindings"],
        "site_absent_contexts": d["absent"],
        "crosschecks": crosschecks,
        "counts": {},
        "findings": [],
        "residuals": residuals,
        "non_claims": list(NON_CLAIMS),
    }
    body["counts"] = _counts(census_body, d, body)
    body["findings"] = _property_findings(body["counts"])
    return body


# --------------------------------------------------------------------------------------------
# the pure checks: what the court runs over the committed artefact
# --------------------------------------------------------------------------------------------

def obligation_findings(body: dict, census_body: dict, tcb_body: dict) -> list[str]:
    """Every way the committed obligations plane contradicts the census or the rule.

    Pure over `body`, the census and the TCB (no compiler, no disk except the caller's reads): it is
    what the `MS-SAFETY-OBLIGATIONS` court runs. It checks that every census site is bound exactly
    once and every census context represented; that every contract's dimension set, named dimensions,
    basis and escape flag reproduce from the census and the `rule`; that no `discharged` appears
    without a source-stated contract and a discharging proof; that the kind -> dimension mapping
    reproduces; and that every count is derived, not typed.
    """
    problems: list[str] = []

    # The committed planes are columnar on disk; re-derive the views the checks read (a fresh
    # measurement passes the views, for which decoding is a no-op). The census supplies the ordered
    # site/context id lists the plane references by index.
    census_body = ms_census.decode_body(census_body)
    refs = ms_codec.refs_from_census(census_body)
    tcb_body = ms_codec.decode_body(tcb_body, refs)
    body = ms_codec.decode_body(body, refs)
    d = derive(census_body)
    expected_by_site = d["by_site"]
    expected_contracts = d["by_contract"]
    census_site_ids = {s.get("site_id") for s in census_body.get("sites") or []}
    census_ctx_ids = {c.get("context_id") for c in census_body.get("unsafe_contexts") or []}

    # 1. Every census site is bound exactly once; no binding names a non-site.
    bindings = body.get("site_obligations") or []
    by_site: dict[str, dict] = {}
    for b in bindings:
        sid = b.get("site_id")
        if sid in by_site:
            problems.append(f"the census site {sid} is bound more than once")
        by_site[sid] = b
    for sid in sorted(census_site_ids):
        if sid not in by_site:
            problems.append(f"the census site {sid} is not bound to any obligation")
    for sid in sorted(by_site):
        if sid not in census_site_ids:
            problems.append(f"the obligations plane binds {sid}, which is not a census site")

    # 2. Every census context is represented: by a binding or as a site-absent declaration.
    absent = body.get("site_absent_contexts") or []
    absent_by_id = {r.get("context_id"): r for r in absent}
    represented = {b.get("context_id") for b in bindings} | set(absent_by_id)
    for cid in sorted(census_ctx_ids):
        if cid not in represented:
            problems.append(f"the census context {cid} is not represented in the obligations plane")
    for cid in sorted(represented):
        if cid not in census_ctx_ids:
            problems.append(f"the obligations plane represents {cid}, which is not a census context")
    for cid in sorted({r.get("context_id") for r in d["absent"]} - set(absent_by_id)):
        problems.append(f"the site-absent context {cid} is not recorded as represented")

    contracts = body.get("contracts") or []
    by_contract = {c.get("contract_id"): c for c in contracts}

    # 3. Every binding reproduces from the census and the rule.
    for sid, b in sorted(by_site.items()):
        site = d["site_by_id"].get(sid)
        if site is None:
            continue
        op = site.get("operation_kind")
        if op not in KIND_DIMENSIONS:
            problems.append(f"the binding for site {sid} has no derivable obligation (operation "
                            f"kind {op!r} is not in the rule)")
            continue
        ctx = d["ctx_by_id"].get(site.get("context_id")) or {}
        basis = str(ctx.get("contract_state") or "UNSTATED")
        text = ctx.get("safety_contract") or ""
        required = _canon(KIND_DIMENSIONS[op])
        named = (_canon([x for x in required if x in _named_dimensions(text)])
                 if basis == "STATED" else [])
        escaping = _escapes(str(ctx.get("kind") or ""), text)
        exp = expected_by_site.get(sid)
        contract = by_contract.get(b.get("contract_id"))
        if contract is None:
            problems.append(f"the binding for site {sid} names contract "
                            f"{b.get('contract_id')!r}, which is absent")
            continue
        if contract.get("operation_kind") != op:
            problems.append(f"the contract of site {sid} names operation_kind "
                            f"{contract.get('operation_kind')!r}, not the site's {op!r}")
        if b.get("codes") != _codes(required):
            problems.append(f"the binding for site {sid} records dimension codes {b.get('codes')!r}"
                            f", which do not reproduce the operation-kind dimension set "
                            f"{_codes(required)!r}")
        if bool(b.get("comment_present")) != (basis == "STATED"):
            problems.append(f"the binding for site {sid} records comment_present="
                            f"{b.get('comment_present')!r}, which does not match the source "
                            f"contract state")
        if b.get("stated_codes") != _codes(named):
            problems.append(f"the binding for site {sid} records stated codes {b.get('stated_codes')!r}"
                            f", which do not match the source-stated contract")
        if contract.get("basis") != basis:
            problems.append(f"the contract of site {sid} records basis {contract.get('basis')!r}, "
                            f"which does not match the source contract state {basis!r}")
        if _canon(contract.get("named_dimensions") or []) != named:
            problems.append(f"the contract of site {sid} names dimensions that do not match the "
                            f"source-stated contract")
        if bool(contract.get("escaping")) != bool(escaping):
            problems.append(f"the contract of site {sid} records escape "
                            f"{contract.get('escaping')!r}, which does not match the source")
        if exp is not None and exp.get("function") != b.get("function"):
            problems.append(f"the binding for site {sid} records function {b.get('function')!r}, "
                            f"not the census site's {exp.get('function')!r}")

    # 4. Every contract is referenced, and its dimensions reproduce and validate.
    referenced = {b.get("contract_id") for b in bindings}
    for cid in sorted(set(by_contract) - referenced):
        problems.append(f"the contract {cid} is not referenced by any site")
    for cid in sorted(set(expected_contracts) - set(by_contract)):
        problems.append(f"the derived contract {cid} is not recorded")
    for c in contracts:
        cid = c.get("contract_id")
        op = c.get("operation_kind")
        if op not in KIND_DIMENSIONS:
            problems.append(f"the contract {cid} names operation kind {op!r}, not a closed "
                            f"operation kind")
            continue
        named = c.get("named_dimensions") or []
        derived = _dimension_records(op, str(c.get("basis")), named, bool(c.get("escaping")))
        got = c.get("dimensions") or []
        if [r.get("dimension") for r in got] != [r["dimension"] for r in derived]:
            problems.append(f"the contract {cid} dimension set is not the derived dimension set "
                            f"for its operation kind")
            continue
        for rec, want in zip(got, derived):
            for field in ("classification", "status", "discharged_by", "code"):
                if rec.get(field) != want[field]:
                    problems.append(f"the contract {cid} dimension {rec.get('dimension')} "
                                    f"{field}={rec.get(field)!r} is not the derived "
                                    f"{want[field]!r}")
            flat = {
                "obligation_id": f"{cid}:{rec.get('code')}",
                "site_id": f"contract:{cid}",
                "dimension": rec.get("dimension"),
                "discharged_by": rec.get("discharged_by"),
                "status": rec.get("status"),
                "evidence": rec.get("evidence") or [],
            }
            problems += [f"contracts[{cid}].{rec.get('dimension')}: {p}"
                         for p in schemas.validate_safety_obligation(flat)]
            # A discharge requires both a source-stated contract naming the dimension and a
            # discharging proof with evidence. A `// SAFETY:` comment is a statement.
            if rec.get("status") == "DISCHARGED":
                named_here = rec.get("dimension") in named
                witness = rec.get("discharged_by") in DISCHARGING_PROOFS and bool(rec.get("evidence"))
                if not (named_here and witness):
                    problems.append(
                        f"the contract {cid} dimension {rec.get('dimension')} is DISCHARGED "
                        f"without a source-stated contract and a discharging proof, so a statement "
                        f"was upgraded to a discharge")

    # 5. The kind -> dimension mapping reproduces.
    rule = body.get("rule") or {}
    recorded = rule.get("kind_dimensions") or {}
    want = {k: _canon(v) for k, v in KIND_DIMENSIONS.items()}
    if set(recorded) != set(want):
        problems.append("the rule's operation-kind mapping does not cover exactly the closed "
                        f"operation kinds (missing {sorted(set(want) - set(recorded))}, extra "
                        f"{sorted(set(recorded) - set(want))})")
    for kind in sorted(set(recorded) & set(want)):
        if _canon(recorded[kind]) != want[kind]:
            problems.append(f"the rule's mapping for {kind} is not the derived dimension set")
    if (rule.get("dimension_codes") or {}) != DIMENSION_CODES:
        problems.append("the rule's dimension codes are not the derived code table")

    # 6. The counts are derived, not typed.
    derived_counts = _counts(census_body, d, body)
    counts = body.get("counts") or {}
    for key, val in derived_counts.items():
        if counts.get(key) != val:
            problems.append(f"counts.{key}={counts.get(key)!r} is not the derived {val!r}")

    # 7. The cross-check against the non-Rust TCB reproduces.
    want_cross, want_residuals = _crosschecks(census_body, tcb_body)
    if (body.get("crosschecks") or {}) != want_cross:
        problems.append("the cross-check block against the non-Rust TCB is not the derived "
                        "cross-check")
    for r in body.get("residuals") or []:
        if r.get("class") not in schemas.RESIDUAL_CLASSES:
            problems.append(f"residual {r.get('source')!r} has class {r.get('class')!r}, not a "
                            f"closed residual class")

    # 8. The property findings are recorded (the artefact does not hide the gaps).
    findings = body.get("findings") or []
    if not any("open" in f for f in findings):
        problems.append("the artefact records no finding about its open obligations, which hides "
                        "the gap rather than recording it")
    return problems


def obligation_sensitivity_control(body: dict, census_body: dict, tcb_body: dict) -> dict:
    """Seed five mutations and require each caught, with specificity holding.

    Each mutation is a distinct way the obligations plane could lie: a source-stated contract
    removed, a stated obligation forged as discharged, a site's obligation dropped, a site's
    dimension set forged, and a contract's named dimensions forged. The baseline must be clean and
    each mutation must produce its own finding, so a control that "caught" everything
    indiscriminately would not pass.
    """
    # The committed planes are columnar on disk; the mutations below index their records, so decode
    # once (a fresh measurement passes the views, for which decoding is a no-op).
    census_body = ms_census.decode_body(census_body)
    refs = ms_codec.refs_from_census(census_body)
    tcb_body = ms_codec.decode_body(tcb_body, refs)
    body = ms_codec.decode_body(body, refs)
    baseline = obligation_findings(body, census_body, tcb_body)
    result: dict = {"baseline_findings": len(baseline), "honest": not baseline,
                    "specificity_holds": False, "mutations": {}}

    def check(label: str, mutated_body: dict, mutated_census: dict, marker: str) -> bool:
        found = obligation_findings(mutated_body, mutated_census, tcb_body)
        caught = any(marker in f for f in found)
        result["mutations"][label] = {
            "caught": caught, "findings": len(found),
            "delta": len(found) - len(baseline), "marker": marker,
        }
        return caught

    # m1: remove a source-stated contract from a context that has a site -- the site becomes open.
    def remove_contract() -> dict:
        ctxs = [dict(c) for c in census_body.get("unsafe_contexts") or []]
        for i, c in enumerate(ctxs):
            if c.get("contract_state") == "STATED" and c.get("site_ids"):
                c["contract_state"] = "UNSTATED"
                c["safety_contract"] = "(no SAFETY contract in source; recorded open for 25.3)"
                ctxs[i] = c
                break
        return {**census_body, "unsafe_contexts": ctxs}

    m1 = check("remove_safety_contract", body, remove_contract(),
               "does not match the source contract state")

    # m2: forge a stated obligation as discharged (keeping its documented-precondition proof).
    def forge_discharge() -> dict:
        contracts = []
        for c in body.get("contracts") or []:
            c = dict(c)
            dims = [dict(r) for r in c.get("dimensions") or []]
            for r in dims:
                if r.get("classification") == "stated":
                    r["status"] = "DISCHARGED"
                    r["classification"] = "discharged"
                    break
            c["dimensions"] = dims
            contracts.append(c)
        return {**body, "contracts": contracts}

    m2 = check("forge_discharge", forge_discharge(), census_body, "DISCHARGED")

    # m3: drop a site's obligation (its binding).
    def drop_binding() -> dict:
        sites = list(body.get("site_obligations") or [])
        return {**body, "site_obligations": sites[1:]}

    m3 = check("drop_site_obligation", drop_binding(), census_body, "is not bound")

    # m4: forge a site's dimension set.
    def forge_dimension_set() -> dict:
        sites = [dict(b) for b in body.get("site_obligations") or []]
        if sites:
            codes = str(sites[0].get("codes") or "")
            sites[0]["codes"] = codes[:-2] or "NU"
        return {**body, "site_obligations": sites}

    m4 = check("forge_dimension_set", forge_dimension_set(), census_body, "dimension set")

    # m5: forge a contract's named dimensions.
    def forge_named_dimensions() -> dict:
        contracts = [dict(c) for c in body.get("contracts") or []]
        for c in contracts:
            if c.get("named_dimensions"):
                c["named_dimensions"] = []
                break
        return {**body, "contracts": contracts}

    m5 = check("forge_named_dimensions", forge_named_dimensions(), census_body,
               "do not match the source-stated contract")

    result["specificity_holds"] = bool(m1 and m2 and m3 and m4 and m5 and not baseline)
    result["caught"] = sum(1 for v in result["mutations"].values() if v["caught"])
    result["seeded"] = len(result["mutations"])
    return result


# --------------------------------------------------------------------------------------------
# self-test
# --------------------------------------------------------------------------------------------

def _synthetic_census() -> dict:
    """A tiny well-formed census, built without a compiler, for the self-test."""
    def ctx(cid, kind, line, state, contract, site_ids):
        return {"context_id": cid, "kind": kind, "file": "src/synthetic.rs", "line": line,
                "span": [0, 10, line, 1], "safety_contract": contract, "contract_state": state,
                "site_ids": site_ids, "evidence": []}

    def site(sid, cid, kind, line, fn):
        return {"site_id": sid, "file": "src/synthetic.rs", "line": line, "column": 1,
                "operation_kind": kind, "context_id": cid, "compiler": "synthetic",
                "compiler_derived": True, "exposure_class": "INTERNAL_REACHABLE",
                "risk_tier": "S4", "safety_obligation_ids": [], "evidence": [],
                "function": fn, "module": "synthetic"}

    return {
        "unsafe_contexts": [
            ctx("uc-a", "UNSAFE_BLOCK", 10, "STATED", "SAFETY: p is live and non-null.", ["us-a"]),
            ctx("uc-b", "FFI_EXPORT_FN", 20, "STATED", "# Safety\n/// out writable for n bytes.",
                ["us-b"]),
            ctx("uc-c", "UNSAFE_BLOCK", 30, "UNSTATED",
                "(no SAFETY contract in source; recorded open for 25.3)", ["us-c"]),
            ctx("uc-d", "UNSAFE_FN", 40, "STATED",
                "# Safety\n/// The caller must pass a live pointer.", []),
        ],
        "sites": [
            site("us-a", "uc-a", "RAW_POINTER_DEREFERENCE", 10, "f"),
            site("us-b", "uc-b", "FFI_EXPORT", 20, "g"),
            site("us-c", "uc-c", "RAW_POINTER_WRITE", 30, "h"),
        ],
    }


def _synthetic_tcb() -> dict:
    return {"ffi_boundaries": [{"boundary_id": "fb-b", "direction": "INBOUND",
                                "census_site": "us-b"}], "counts": {"variadic_boundaries": 0}}


def self_test() -> int:
    """Prove the metadata-only admission holds and the sensitivity control is honest."""
    failures: list[str] = []

    admission = phase25_guard.evaluate(entry_point="ms_obligations.py", env={}, dockerenv=False)
    if not admission["admitted"] or admission["venue"] != "metadata-only":
        failures.append("ms_obligations.py is not admitted as a metadata-only generator on a host")

    census = _synthetic_census()
    tcb = _synthetic_tcb()
    body = build_body(census, tcb)
    baseline = obligation_findings(body, census, tcb)
    if baseline:
        failures.append(f"the synthetic obligations body is not clean: {baseline[:4]}")
    if body["counts"]["discharged"] != 0:
        failures.append("the synthetic body records a discharge, which no source-stated contract "
                        "can establish")
    control = obligation_sensitivity_control(body, census, tcb)
    if not control["specificity_holds"] or control["caught"] != control["seeded"]:
        failures.append(f"the sensitivity control is not honest: {control}")

    if failures:
        print("[ms-obligations] self-test FAILED")
        for f in failures:
            print(f"  {f}")
        return 1
    print("[ms-obligations] self-test ok: the guard admits it as metadata-only; the synthetic "
          "obligations body is clean and records no discharge; and all five seeded mutations "
          "(removed contract, forged discharge, dropped obligation, forged dimension set, forged "
          "named dimensions) are caught with specificity holding")
    return 0


# --------------------------------------------------------------------------------------------
# entry points
# --------------------------------------------------------------------------------------------

def _load(path: Path) -> dict:
    if not path.is_file():
        raise SystemExit(f"[ms-obligations] {rel(path)} is absent")
    return json.loads(path.read_text(encoding="utf-8"))


def _write_obligations(path: Path, doc: dict) -> None:
    """Write the plane compactly, key-sorted and deterministic.

    A deliberate deviation from `atlas_common.write_json`'s `indent=2`: the plane carries ~64,000
    records, and pretty-printing multiplies the file without adding evidence. Determinism is
    preserved (sorted keys, fixed separators) and `body_hash` covers the body.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    path.write_text(text, encoding="utf-8")


def _inputs() -> list[InputRef]:
    return [
        InputRef(name="phase-25-plan", path=PLAN),
        InputRef(name="memory-safety-schemas", path=SCHEMAS),
        InputRef(name="phase25-guard", path=GUARD),
        InputRef(name="phase25-container-manifest", path=MANIFEST),
        InputRef(name="ms-obligations-tool", path=TOOL),
        InputRef(name="source-census", path=CENSUS),
        InputRef(name="non-rust-tcb", path=TCB),
    ]


def _measure() -> int:
    """Derive the obligations plane from the committed census and TCB, and write it."""
    census_body = ms_census.decode_body(_load(CENSUS).get("body", {}))
    tcb_body = ms_codec.decode_body(_load(TCB).get("body", {}),
                                    ms_codec.refs_from_census(census_body))
    body = build_body(census_body, tcb_body)
    problems = obligation_findings(body, census_body, tcb_body)

    auth = resolve_authority(PRODUCTION_AUTHORITY)
    encoded = ms_codec.encode_body(body, ms_codec.refs_from_census(census_body))
    doc = envelope(kind="phase25-safety-obligations", authority=auth.id, inputs=_inputs(),
                   body=encoded, generator=GENERATOR)
    doc["body_hash"] = content_hash(encoded)
    _write_obligations(OUT, doc)

    c = body["counts"]
    print(f"[ms-obligations] {c['sites_bound']} site(s) bound to {c['contracts']} grouped "
          f"contract(s); {c['obligations']} obligation dimension(s)")
    print(f"  classification: discharged={c['discharged']} stated={c['stated']} open={c['open']}")
    print(f"  contexts represented={c['contexts_represented']}/{c['census_contexts']} "
          f"(site-absent={c['contexts_without_site']}); uncontracted sites={c['uncontracted_sites']}")
    print(f"  escaping sites={c['escaping_sites']} over {c['escaping_obligations']} named "
          f"obligation(s); high-risk sites={c['high_risk_sites']}")
    print(f"  crosscheck: census FFI_EXPORT sites with a TCB boundary="
          f"{body['crosschecks']['ffi_export_sites_with_boundary']}/"
          f"{body['crosschecks']['census_ffi_export_sites']}")
    print(f"  -> {rel(OUT)} all_pass={not problems} (findings={len(body['findings'])})")
    if problems:
        for p in problems[:24]:
            print(f"    {p}")
    return 0 if not problems else 1


def _check() -> int:
    """Re-run the pure checks over the committed plane, without a compiler."""
    if not OUT.is_file():
        print(f"[ms-obligations] {rel(OUT)} is absent; run --measure")
        return 1
    body = _load(OUT).get("body", {})
    census_body = _load(CENSUS).get("body", {})
    tcb_body = _load(TCB).get("body", {})
    problems = obligation_findings(body, census_body, tcb_body)
    if problems:
        print(f"[ms-obligations] check FAILED: {len(problems)} problem(s)")
        for p in problems[:24]:
            print(f"  {p}")
        return 1
    c = body["counts"]
    print(f"[ms-obligations] check ok: {c['sites_bound']} site(s), {c['obligations']} "
          f"obligation(s); discharged={c['discharged']} stated={c['stated']} open={c['open']}; "
          f"every check holds")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--measure", action="store_true",
                    help="derive artifacts/phase25/safety-obligations.json from the committed census")
    ap.add_argument("--check", action="store_true",
                    help="re-run the pure checks over the committed obligations plane")
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
    # regenerates every generator with no flags and compares the bytes, so a generator that only
    # wrote behind a flag would fail there rather than reproduce.
    return _measure()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
