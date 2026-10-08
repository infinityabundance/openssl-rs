#!/usr/bin/env python3
"""openssl-rs — the memory-safety record schemas, and the unsafe/exposure vocabularies.

Phase 25 is the memory-safety stratum (`docs/RELEASE_GATES.md` section 1,
`docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md`). Like Phases 16 through 24 it owns no exported symbol:
its unit is the authored non-export `memory-safety contract`, and its working set is twenty-two
contract units, one per subphase 25.0 through 25.21. This module is 25.0's own half of that work: it
**defines and validates** the record kinds those subphases will emit, fixes the closed vocabularies
the atlas is queryable by, and closes the class lists the brief names (the unsafe-operation kinds,
the obligation dimensions, the exposure classes, the tool states, the CVE taxonomy, the CVE replay
states, the risk tiers and the panic/unwind classes).

The primary unit is a compiler-derived unsafe operation
------------------------------------------------------
A memory-safety census is only evidence if its unit is a fact the compiler establishes. Each
`unsafe_site` record therefore carries `compiler` (the exact toolchain that produced the unsafe
operation) and `compiler_derived` (which **must** be true), and `validate_unsafe_site` refuses a
site that is not compiler-derived: a regular-expression scan or a text grep is a *projection* of
the source, not the source's unsafe operations, and a metric built on it would move when a comment
moves. Lines of unsafe code (`unsafe LOC`) are a **secondary projection** only -- this module never
treats a LOC ratio as the security claim.

Tool states are four-valued, and `UNSUPPORTED` is never a pass
-------------------------------------------------------------
Every dynamic/formal evidence record names a `tool_state` from `TOOL_STATES`
(`PASS`, `FAIL`, `NOT_REACHABLE`, `UNSUPPORTED`). `UNSUPPORTED` records that the tool **could not
express** the question, not that the target is safe; `validate_summary` refuses a seal-class record
that marks an externally reachable unsafe site's tool state `UNSUPPORTED` as a pass, and the
tool-result validators refuse an `UNSUPPORTED` record with no `unsupported_reason`.

A `STRUCTURALLY_EXCLUDED` CVE replay cites its evidence
------------------------------------------------------
A historical CVE is `STRUCTURALLY_EXCLUDED` only if the candidate's structure **cannot** express the
mechanism. That is a claim about a mechanism, so it needs evidence: `validate_cve_replay` refuses a
`CANDIDATE_STRUCTURALLY_EXCLUDED` state with no `evidence`, so "we do not have this bug" cannot be
asserted without naming the structure that makes it inexpressible.

Outputs
-------
  (none) — this module writes no artefact; it is imported by the Phase-25 ledger and runner, and
  run with `--self-test` / `--check` / `--list` / `--vocabulary`.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import re
import sys

# --------------------------------------------------------------------------------------------
# the closed vocabularies: every value a record may carry comes from one of these
# --------------------------------------------------------------------------------------------

# The kinds of first-party shipped source/build file the census covers. A census row is one file of
# this surface, so the `source_census` record's `kind` names which.
SOURCE_KINDS: tuple[str, ...] = (
    "RUST_SOURCE",
    "C_SOURCE",
    "C_HEADER",
    "ASM_SOURCE",
    "BUILD_SCRIPT",
    "GENERATED_BINDING",
    "CONFIG",
    "OTHER",
)

# Where a file came from. `FIRST_PARTY` is the shipped source/build surface the bounded claim covers;
# `VENDORED` and `GENERATED` are recorded so the boundary of the claim is auditable rather than
# implied. A vendored dependency is **not** part of the claimed first-party TCB.
SOURCE_ORIGINS: tuple[str, ...] = ("FIRST_PARTY", "VENDORED", "GENERATED")

# The unsafe-operation kinds (brief section 2). The primary unit is one of these, derived from the
# compiler, never from a regex. `INLINE_ASM` and `C_VARIADIC_BOUNDARY` are here because the unsafe
# trusted computing base is not only Rust: first-party C shims, exported FFI and inline assembly are
# part of the same census.
UNSAFE_OPERATION_KINDS: tuple[str, ...] = (
    "RAW_POINTER_DEREFERENCE",
    "RAW_POINTER_READ",
    "RAW_POINTER_WRITE",
    "UNSAFE_FUNCTION_CALL",
    "UNSAFE_METHOD_CALL",
    "UNSAFE_TRAIT_METHOD",
    "UNSAFE_IMPL",
    "EXTERN_FUNCTION_CALL",
    "UNION_FIELD_ACCESS",
    "TRANSMUTE",
    "UNSAFE_CAST",
    "INLINE_ASM",
    "FFI_EXPORT",
    "C_VARIADIC_BOUNDARY",
    "STATIC_MUT_ACCESS",
    "UNALIGNED_ACCESS",
    "ASSERT_UNCHECKED",
)

# The kind of enclosing unsafe context a site lives in. A context is where a safety contract is
# stated; a site is what the contract covers.
UNSAFE_CONTEXT_KINDS: tuple[str, ...] = (
    "UNSAFE_BLOCK",
    "UNSAFE_FN",
    "UNSAFE_IMPL",
    "UNSAFE_TRAIT",
    "EXTERN_BLOCK",
    "FFI_EXPORT_FN",
    "INLINE_ASM_BLOCK",
    "OTHER",
)

# The obligation dimensions (brief section 3). Each is a property an unsafe site must establish for
# its operation to be sound, and each safety obligation names exactly one.
OBLIGATION_DIMENSIONS: tuple[str, ...] = (
    "NULLABILITY",
    "LIFETIME",
    "ALIASING",
    "ALIGNMENT",
    "INITIALIZATION",
    "BOUNDS",
    "OWNERSHIP",
    "REFCOUNT",
    "THREAD_AFFINITY",
    "ABI",
    "UNWIND",
    "TYPE_VALIDITY",
    "SEND_SYNC",
    "PANIC_SAFETY",
    "POINTER_PROVENANCE",
    "INIT_ONCE",
    "VALIDITY",
)

# How an obligation is discharged. `UNKNOWN` is a recorded state, never traded for confidence.
OBLIGATION_PROOFS: tuple[str, ...] = (
    "PROOF",
    "RUNTIME_CHECK",
    "TYPE_SYSTEM",
    "DOCUMENTED_PRECONDITION",
    "TEST",
    "TOOL_EVIDENCE",
    "UNKNOWN",
)
OBLIGATION_STATES: tuple[str, ...] = ("DISCHARGED", "OPEN", "UNKNOWN")

# The exposure classes (brief section 7): whether a person, a configuration, a CLI input, a network
# peer or a downstream program can reach the site. `UNREACHABLE_PROFILE` and `TEST_ONLY` are the
# two classes that are not reachable in the claimed profile.
EXPOSURE_CLASSES: tuple[str, ...] = (
    "UNREACHABLE_PROFILE",
    "TEST_ONLY",
    "INTERNAL_REACHABLE",
    "LOCAL_API_REACHABLE",
    "CONFIG_REACHABLE",
    "CLI_INPUT_REACHABLE",
    "NETWORK_CLIENT_REACHABLE",
    "NETWORK_SERVER_REACHABLE",
    "DOWNSTREAM_RUNTIME_OBSERVED",
)

# The exposure classes that name a site **externally** reachable in the claimed profile: a caller,
# a configuration, a CLI input, a network peer or a downstream program can reach it. A seal-class
# record may not report a pass while one of these carries tool state `UNSUPPORTED`.
EXTERNALLY_REACHABLE_EXPOSURE: frozenset[str] = frozenset({
    "LOCAL_API_REACHABLE",
    "CONFIG_REACHABLE",
    "CLI_INPUT_REACHABLE",
    "NETWORK_CLIENT_REACHABLE",
    "NETWORK_SERVER_REACHABLE",
    "DOWNSTREAM_RUNTIME_OBSERVED",
})

# The tool-result states (brief section: tool states). `UNSUPPORTED` is **never** `PASS`: it records
# that the tool could not express the question, not that the target is safe.
TOOL_STATES: tuple[str, ...] = ("PASS", "FAIL", "NOT_REACHABLE", "UNSUPPORTED")

# The sanitizers Phase 25 derives an environment for. Kept as a closed vocabulary so a result row
# names which one it is.
SANITIZERS: tuple[str, ...] = ("ASAN", "MSAN", "TSAN")

# The FFI directions and ABIs a boundary record names.
FFI_DIRECTIONS: tuple[str, ...] = ("INBOUND", "OUTBOUND")
FFI_ABIS: tuple[str, ...] = ("C", "SYSTEM", "CDECL", "STDCALL", "WIN64", "OTHER")

# The ownership-edge kinds (brief section 4): how a value or a pointer crosses the Rust/C boundary
# and how its lifetime is managed. The vocabulary is owned by 25.4, the subphase that measures the
# ownership plane: an allocation, a borrowed reference, an ownership transfer in either direction,
# a reference-count increment or decrement, and a release. 25.0's earlier placeholder
# (MOVE/BORROW/TRANSFER_*/REFCOUNT_*/RETURN/OTHER) named the boundary crossing but not the
# allocation/release half, so it could not express the plane's pairing rule; 25.4 refined it in the
# commit that landed the plane.
OWNERSHIP_KINDS: tuple[str, ...] = (
    "ALLOCATES",
    "RETURNS_OWNERSHIP",
    "BORROWS",
    "TRANSFERS_OWNERSHIP",
    "INCREMENTS_REFCOUNT",
    "DECREMENTS_REFCOUNT",
    "FREES",
)

SEND_SYNC_TRAITS: tuple[str, ...] = ("SEND", "SYNC")

# A global's mutability discipline. `MUTABLE_UNSYNCHRONIZED` must state a safety contract.
GLOBAL_MUTABILITY: tuple[str, ...] = (
    "IMMUTABLE",
    "MUTABLE_UNSYNCHRONIZED",
    "MUTABLE_SYNCHRONIZED",
    "THREAD_LOCAL",
)

# The panic/unwind classes (brief section: panic/unwind classes). `UNKNOWN` is a recorded class.
PANIC_UNWIND_CLASSES: tuple[str, ...] = (
    "CATCHES_PANIC",
    "CANNOT_PANIC_BY_CONSTRUCTION",
    "C_UNWIND_EXPLICIT",
    "UNKNOWN",
)

# The risk tiers S0-S4: an ordering aid for the exposure ranking, never a vulnerability count.
RISK_TIERS: tuple[str, ...] = ("S0", "S1", "S2", "S3", "S4")

# The CVE taxonomy (brief section 15): a closed vocabulary, so a historical CVE is classified rather
# than described. `OTHER` is the recorded last resort, never a substitute for classification.
CVE_TAXONOMY: tuple[str, ...] = (
    "HEAP_OOB_READ",
    "HEAP_OOB_WRITE",
    "STACK_OOB_READ",
    "STACK_OOB_WRITE",
    "USE_AFTER_FREE",
    "DOUBLE_FREE",
    "NULL_DEREFERENCE",
    "UNINITIALIZED_READ",
    "INTEGER_OVERFLOW",
    "INTEGER_UNDERFLOW",
    "TYPE_CONFUSION",
    "UNALIGNED_ACCESS",
    "RACE_CONDITION",
    "DATA_RACE",
    "BUFFER_OVERFLOW",
    "MEMORY_LEAK",
    "IMPROPER_FREE",
    "SIDE_CHANNEL",
    "PROTOCOL_LOGIC",
    "ALGORITHM_COMPLEXITY",
    "OTHER",
)

# The CVE replay states (brief section 16): the candidate's disposition for one historical CVE.
# `CANDIDATE_STRUCTURALLY_EXCLUDED` requires evidence -- the structure that makes the mechanism
# inexpressible -- and `CANDIDATE_UNSAFE_PATH_REMAINS` is the honest residual.
CVE_REPLAY_STATES: tuple[str, ...] = (
    "UPSTREAM_VULNERABLE_REPRODUCED",
    "CANDIDATE_STRUCTURALLY_EXCLUDED",
    "CANDIDATE_SAFE_REJECTION",
    "CANDIDATE_NO_MEMORY_FAULT_OBSERVED",
    "CANDIDATE_UNSAFE_PATH_REMAINS",
    "CANDIDATE_REPRODUCES_MEMORY_FAULT",
    "CANDIDATE_FEATURE_NOT_APPLICABLE",
    "UNKNOWN",
)

# The residual classes (brief section: residual). A leftover is classified rather than described.
# `join_evidence_missing` was added by 25.6: a crosswalk whose join is only partial (an imported
# symbol with no clean entity mapping, or a runtime-observed family with no usage fingerprint)
# records the partial join rather than a zero or a guess. See
# docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md section 4.5.
RESIDUAL_CLASSES: tuple[str, ...] = (
    "none",
    "unclassified_unsafe_site",
    "unexplained_reachable_unsafe",
    "tool_unsupported",
    "tool_not_reachable",
    "evidence_missing",
    "join_evidence_missing",
    "historical_cve_unreplayed",
    "mechanism_unreconciled",
    "out_of_scope",
    "unknown",
)
RESIDUAL_DISPOSITIONS: tuple[str, ...] = (
    "none", "classified", "preserved", "open", "unknown",
)

# A CVE identifier shape. A row that is not a CVE id is a row that is not a historical CVE.
_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


# --------------------------------------------------------------------------------------------
# the helpers every validator shares
# --------------------------------------------------------------------------------------------

def _missing(rec: dict, fields: tuple[str, ...]) -> list[str]:
    return [f"missing required field {f!r}" for f in fields if f not in rec]


def _enum(rec: dict, field: str, allowed: tuple[str, ...]) -> list[str]:
    if field not in rec:
        return []
    if rec[field] not in allowed:
        return [f"{field}={rec[field]!r} is not one of {sorted(allowed)}"]
    return []


def _nonempty(rec: dict, field: str) -> list[str]:
    if field not in rec:
        return []
    if not rec[field]:
        return [f"{field} must be non-empty"]
    return []


def _isin(rec: dict, field: str, allowed: frozenset[str]) -> list[str]:
    if field not in rec:
        return []
    if rec[field] not in allowed:
        return [f"{field}={rec[field]!r} is not one of {sorted(allowed)}"]
    return []


def _unknownable_hash(rec: dict, field: str) -> list[str]:
    if field not in rec:
        return []
    value = rec[field]
    if value == "unknown":
        return []
    if not isinstance(value, str) or not _HEX64.match(value):
        return [f"{field} must be a 64-hex digest or the literal `unknown`"]
    return []


def _bool(rec: dict, field: str) -> list[str]:
    if field not in rec:
        return []
    if not isinstance(rec[field], bool):
        return [f"{field} must be a boolean"]
    return []


def _int(rec: dict, field: str) -> list[str]:
    if field not in rec:
        return []
    if not isinstance(rec[field], int) or isinstance(rec[field], bool):
        return [f"{field} must be an integer"]
    return []


def _list(rec: dict, field: str) -> list[str]:
    if field not in rec:
        return []
    if not isinstance(rec[field], list):
        return [f"{field} must be a list"]
    return []


# --------------------------------------------------------------------------------------------
# the validators: each returns a list of problems, empty when the record is well-formed
# --------------------------------------------------------------------------------------------

def validate_source_census(rec: dict) -> list[str]:
    """A source-census row: one shipped first-party source/build file.

    The census is over the first-party shipped surface; a `VENDORED` file is recorded but is not
    part of the claimed TCB. `file_sha256` may be `unknown` only where the content is genuinely not
    established, and `unsafe_operations` is a count of compiler-derived operations, never a LOC.
    """
    fields = ("census_id", "path", "kind", "language", "origin", "shipped", "file_sha256",
              "unsafe_operations", "evidence")
    problems = _missing(rec, fields)
    problems += _nonempty(rec, "census_id")
    problems += _nonempty(rec, "path")
    problems += _enum(rec, "kind", SOURCE_KINDS)
    problems += _enum(rec, "origin", SOURCE_ORIGINS)
    problems += _bool(rec, "shipped")
    problems += _unknownable_hash(rec, "file_sha256")
    problems += _int(rec, "unsafe_operations")
    problems += _list(rec, "evidence")
    return problems


def validate_unsafe_site(rec: dict) -> list[str]:
    """A compiler-derived unsafe operation: the primary unit of the census.

    `compiler_derived` **must** be true and `compiler` must name the toolchain that established the
    operation: a regex or a text scan is not the authority for unsafe operations, so a site that is
    not compiler-derived is refused. `line` and `column` are one-based positions in `file`.
    """
    fields = ("site_id", "file", "line", "column", "operation_kind", "context_id", "compiler",
              "compiler_derived", "exposure_class", "risk_tier", "safety_obligation_ids",
              "evidence")
    problems = _missing(rec, fields)
    problems += _nonempty(rec, "site_id")
    problems += _nonempty(rec, "file")
    problems += _nonempty(rec, "context_id")
    problems += _nonempty(rec, "compiler")
    problems += _int(rec, "line")
    problems += _int(rec, "column")
    problems += _enum(rec, "operation_kind", UNSAFE_OPERATION_KINDS)
    problems += _enum(rec, "exposure_class", EXPOSURE_CLASSES)
    problems += _enum(rec, "risk_tier", RISK_TIERS)
    problems += _bool(rec, "compiler_derived")
    problems += _list(rec, "safety_obligation_ids")
    problems += _list(rec, "evidence")
    if rec.get("compiler_derived") is not True:
        problems.append(
            "an unsafe site must be compiler-derived (compiler_derived=true): the compiler is the "
            "authority for unsafe operations, never a regex or a text scan, and a LOC projection "
            "is never the unit"
        )
    return problems


def validate_unsafe_context(rec: dict) -> list[str]:
    """An enclosing unsafe context, where a safety contract is stated.

    A context with sites and no safety contract is exactly the unexplained site the bounded claim
    forbids, so it is refused rather than passed.
    """
    fields = ("context_id", "kind", "file", "line", "safety_contract", "site_ids", "evidence")
    problems = _missing(rec, fields)
    problems += _nonempty(rec, "context_id")
    problems += _nonempty(rec, "file")
    problems += _int(rec, "line")
    problems += _enum(rec, "kind", UNSAFE_CONTEXT_KINDS)
    problems += _list(rec, "site_ids")
    problems += _list(rec, "evidence")
    if rec.get("site_ids") and not rec.get("safety_contract"):
        problems.append(
            "an unsafe context with sites must state its safety contract (safety_contract); an "
            "unsafe block with no contract is the unexplained site the claim forbids"
        )
    return problems


def validate_safety_obligation(rec: dict) -> list[str]:
    """One obligation an unsafe site must discharge, along its dimension."""
    fields = ("obligation_id", "site_id", "dimension", "discharged_by", "status", "evidence")
    problems = _missing(rec, fields)
    problems += _nonempty(rec, "obligation_id")
    problems += _nonempty(rec, "site_id")
    problems += _enum(rec, "dimension", OBLIGATION_DIMENSIONS)
    problems += _enum(rec, "discharged_by", OBLIGATION_PROOFS)
    problems += _enum(rec, "status", OBLIGATION_STATES)
    problems += _list(rec, "evidence")
    return problems


def validate_ffi_boundary(rec: dict) -> list[str]:
    """A first-party FFI boundary: an exported symbol or an inbound extern call."""
    fields = ("boundary_id", "symbol", "direction", "abi", "c_variadic", "unwind", "sites",
              "evidence")
    problems = _missing(rec, fields)
    problems += _nonempty(rec, "boundary_id")
    problems += _nonempty(rec, "symbol")
    problems += _enum(rec, "direction", FFI_DIRECTIONS)
    problems += _enum(rec, "abi", FFI_ABIS)
    problems += _bool(rec, "c_variadic")
    problems += _enum(rec, "unwind", PANIC_UNWIND_CLASSES)
    problems += _list(rec, "sites")
    problems += _list(rec, "evidence")
    return problems


def validate_c_adapter(rec: dict) -> list[str]:
    """A first-party C shim/adapter: part of the unsafe TCB even though it is not Rust."""
    fields = ("adapter_id", "path", "purpose", "exported_symbols", "memory_operations", "evidence")
    problems = _missing(rec, fields)
    problems += _nonempty(rec, "adapter_id")
    problems += _nonempty(rec, "path")
    problems += _nonempty(rec, "purpose")
    problems += _list(rec, "exported_symbols")
    problems += _list(rec, "memory_operations")
    problems += _list(rec, "evidence")
    return problems


def validate_allocation_site(rec: dict) -> list[str]:
    """An allocation/deallocation association.

    A `paired` allocation must name what frees it: an allocation whose deallocation is not named is
    not a paired record, it is a leak or an unknown, and either is recorded honestly.
    """
    fields = ("allocation_id", "site_id", "allocator", "size_expr", "freed_by", "paired",
              "evidence")
    problems = _missing(rec, fields)
    problems += _nonempty(rec, "allocation_id")
    problems += _nonempty(rec, "site_id")
    problems += _nonempty(rec, "allocator")
    problems += _nonempty(rec, "size_expr")
    problems += _bool(rec, "paired")
    problems += _list(rec, "evidence")
    if rec.get("paired") is True and not rec.get("freed_by"):
        problems.append(
            "a paired allocation must name what frees it (freed_by); an allocation with no named "
            "deallocation is recorded unpaired or unknown"
        )
    return problems


def validate_ownership_edge(rec: dict) -> list[str]:
    """A ownership edge: how a value or pointer crosses the Rust/C boundary."""
    fields = ("edge_id", "from_site", "to_site", "kind", "evidence")
    problems = _missing(rec, fields)
    problems += _nonempty(rec, "edge_id")
    problems += _nonempty(rec, "from_site")
    problems += _nonempty(rec, "to_site")
    problems += _enum(rec, "kind", OWNERSHIP_KINDS)
    problems += _list(rec, "evidence")
    return problems


def validate_callback_lifetime(rec: dict) -> list[str]:
    """A callback/function-pointer lifetime contract: who invokes it, and for how long it lives."""
    fields = ("callback_id", "registered_at", "invoked_by", "lifetime", "may_outlive", "evidence")
    problems = _missing(rec, fields)
    problems += _nonempty(rec, "callback_id")
    problems += _nonempty(rec, "registered_at")
    problems += _nonempty(rec, "invoked_by")
    problems += _nonempty(rec, "lifetime")
    problems += _bool(rec, "may_outlive")
    problems += _list(rec, "evidence")
    return problems


def validate_send_sync_impl(rec: dict) -> list[str]:
    """An unsafe `impl Send`/`impl Sync`; refused without its justification."""
    fields = ("impl_id", "type", "trait", "justification", "evidence")
    problems = _missing(rec, fields)
    problems += _nonempty(rec, "impl_id")
    problems += _nonempty(rec, "type")
    problems += _enum(rec, "trait", SEND_SYNC_TRAITS)
    problems += _list(rec, "evidence")
    if not rec.get("justification"):
        problems.append(
            "an unsafe Send/Sync impl must state its justification; an unjustified unsafe impl is "
            "an unexplained reachable unsoundness"
        )
    return problems


def validate_global_state(rec: dict) -> list[str]:
    """A global/static state; an unsynchronized mutable one must state a safety contract."""
    fields = ("global_id", "name", "mutability", "initialization", "safety_contract", "evidence")
    problems = _missing(rec, fields)
    problems += _nonempty(rec, "global_id")
    problems += _nonempty(rec, "name")
    problems += _enum(rec, "mutability", GLOBAL_MUTABILITY)
    problems += _nonempty(rec, "initialization")
    problems += _list(rec, "evidence")
    if rec.get("mutability") == "MUTABLE_UNSYNCHRONIZED" and not rec.get("safety_contract"):
        problems.append(
            "a MUTABLE_UNSYNCHRONIZED global must state its safety contract; an unsynchronized "
            "mutable global with no contract is an unexplained reachable data race"
        )
    return problems


def validate_panic_boundary(rec: dict) -> list[str]:
    """A panic/unwinding boundary between Rust and C, classified from the closed vocabulary."""
    fields = ("panic_id", "site_id", "class", "caught_at", "evidence")
    problems = _missing(rec, fields)
    problems += _nonempty(rec, "panic_id")
    problems += _nonempty(rec, "site_id")
    problems += _enum(rec, "class", PANIC_UNWIND_CLASSES)
    problems += _list(rec, "evidence")
    if rec.get("class") == "CATCHES_PANIC" and not rec.get("caught_at"):
        problems.append("a CATCHES_PANIC boundary must name where the panic is caught (caught_at)")
    return problems


def _tool_state_problems(rec: dict) -> list[str]:
    """The shared rule for every tool-result kind: `UNSUPPORTED` names its reason."""
    problems = _enum(rec, "tool_state", TOOL_STATES)
    problems += _list(rec, "findings")
    if rec.get("tool_state") == "UNSUPPORTED" and not rec.get("unsupported_reason"):
        problems.append(
            "an UNSUPPORTED tool state must name its unsupported_reason; UNSUPPORTED is not PASS, "
            "and refusing to say why is refusing the evidence"
        )
    return problems


def validate_miri_result(rec: dict) -> list[str]:
    """A Miri result over a target, with its tool state and version."""
    fields = ("result_id", "target", "tool_state", "tool_version", "findings",
              "unsupported_reason", "evidence")
    problems = _missing(rec, fields)
    problems += _nonempty(rec, "result_id")
    problems += _nonempty(rec, "target")
    problems += _nonempty(rec, "tool_version")
    problems += _tool_state_problems(rec)
    problems += _list(rec, "evidence")
    return problems


def validate_sanitizer_result(rec: dict) -> list[str]:
    """An ASan/MSan/TSan result over a target, with its tool state."""
    fields = ("result_id", "sanitizer", "target", "tool_state", "findings",
              "unsupported_reason", "evidence")
    problems = _missing(rec, fields)
    problems += _nonempty(rec, "result_id")
    problems += _enum(rec, "sanitizer", SANITIZERS)
    problems += _nonempty(rec, "target")
    problems += _tool_state_problems(rec)
    problems += _list(rec, "evidence")
    return problems


def validate_kani_result(rec: dict) -> list[str]:
    """A Kani harness result over a target, with its tool state."""
    fields = ("result_id", "harness", "target", "tool_state", "findings",
              "unsupported_reason", "evidence")
    problems = _missing(rec, fields)
    problems += _nonempty(rec, "result_id")
    problems += _nonempty(rec, "harness")
    problems += _nonempty(rec, "target")
    problems += _tool_state_problems(rec)
    problems += _list(rec, "evidence")
    return problems


def validate_fuzz_crosswalk(rec: dict) -> list[str]:
    """A crosswalk from a Phase-18 fuzz target to the unsafe sites it exercises."""
    fields = ("crosswalk_id", "phase18_target", "unsafe_site_ids", "covered", "tool_state",
              "evidence")
    problems = _missing(rec, fields)
    problems += _nonempty(rec, "crosswalk_id")
    problems += _nonempty(rec, "phase18_target")
    problems += _list(rec, "unsafe_site_ids")
    problems += _bool(rec, "covered")
    problems += _enum(rec, "tool_state", TOOL_STATES)
    problems += _list(rec, "evidence")
    return problems


def validate_coverage(rec: dict) -> list[str]:
    """The coverage of the unsafe sites by one tool over one profile."""
    fields = ("coverage_id", "profile", "tool", "covered_sites", "uncovered_sites", "tool_state",
              "evidence")
    problems = _missing(rec, fields)
    problems += _nonempty(rec, "coverage_id")
    problems += _nonempty(rec, "profile")
    problems += _nonempty(rec, "tool")
    problems += _list(rec, "covered_sites")
    problems += _list(rec, "uncovered_sites")
    problems += _enum(rec, "tool_state", TOOL_STATES)
    problems += _list(rec, "evidence")
    return problems


def validate_historical_cve(rec: dict) -> list[str]:
    """A historical OpenSSL CVE, classified from the CVE taxonomy.

    The id must be a CVE identifier: a row that is not a CVE is a row that is not a historical CVE.
    """
    fields = ("cve_id", "taxonomy", "affected_versions", "fix_commit", "memory_safety", "evidence")
    problems = _missing(rec, fields)
    problems += _enum(rec, "taxonomy", CVE_TAXONOMY)
    problems += _list(rec, "affected_versions")
    problems += _bool(rec, "memory_safety")
    problems += _list(rec, "evidence")
    if "cve_id" in rec and not _CVE_ID.match(str(rec["cve_id"])):
        problems.append(f"cve_id={rec.get('cve_id')!r} is not a CVE identifier")
    return problems


def validate_cve_replay(rec: dict) -> list[str]:
    """The candidate's disposition for one historical CVE.

    `CANDIDATE_STRUCTURALLY_EXCLUDED` is a claim about a mechanism, so it **requires evidence**: the
    structure that makes the mechanism inexpressible. A structurally-excluded replay with no
    evidence is refused by name.
    """
    fields = ("replay_id", "cve_id", "state", "candidate_identity", "evidence")
    problems = _missing(rec, fields)
    problems += _nonempty(rec, "replay_id")
    problems += _nonempty(rec, "candidate_identity")
    problems += _enum(rec, "state", CVE_REPLAY_STATES)
    problems += _list(rec, "evidence")
    if "cve_id" in rec and not _CVE_ID.match(str(rec["cve_id"])):
        problems.append(f"cve_id={rec.get('cve_id')!r} is not a CVE identifier")
    if rec.get("state") == "CANDIDATE_STRUCTURALLY_EXCLUDED" and not rec.get("evidence"):
        problems.append(
            "a CANDIDATE_STRUCTURALLY_EXCLUDED replay must cite its evidence; structural exclusion "
            "is a claim about a mechanism, not an assertion"
        )
    return problems


def validate_vulnerability_mechanism(rec: dict) -> list[str]:
    """The reconciliation of a vulnerability mechanism, never a CVE count.

    A structural-immunity claim must state its reason, and `cve_ids` names the historical CVEs whose
    mechanism the row reconciles; a row reconciles a *mechanism*, not a count.
    """
    fields = ("mechanism_id", "taxonomy", "class_present", "candidate_structurally_immune",
              "reason", "cve_ids", "evidence")
    problems = _missing(rec, fields)
    problems += _nonempty(rec, "mechanism_id")
    problems += _enum(rec, "taxonomy", CVE_TAXONOMY)
    problems += _bool(rec, "class_present")
    problems += _bool(rec, "candidate_structurally_immune")
    problems += _list(rec, "cve_ids")
    problems += _list(rec, "evidence")
    if rec.get("candidate_structurally_immune") and not rec.get("reason"):
        problems.append(
            "a candidate_structurally_immune mechanism must state its reason; immunity is a claim "
            "about structure and cannot be asserted bare"
        )
    return problems


def validate_residual(rec: dict) -> list[str]:
    """A classified leftover: a residual class from the closed vocabulary, with its disposition."""
    fields = ("residual_id", "subject", "class", "disposition", "detail", "evidence")
    problems = _missing(rec, fields)
    problems += _nonempty(rec, "residual_id")
    problems += _nonempty(rec, "subject")
    problems += _enum(rec, "class", RESIDUAL_CLASSES)
    problems += _enum(rec, "disposition", RESIDUAL_DISPOSITIONS)
    problems += _nonempty(rec, "detail")
    problems += _list(rec, "evidence")
    return problems


def validate_summary(rec: dict) -> list[str]:
    """The seal-class summary: the census's closure record, and its two refusals.

    This is the record a reader would take as "the stratum passed", so it is where the tool-state
    rule is enforced hardest. For every externally reachable unsafe site the summary carries, an
    `UNSUPPORTED` tool state may **not** be presented as a pass -- neither per row (`claimed_pass`)
    nor in the overall `passed` flag. A seal-class record that does either is refused by name,
    because `UNSUPPORTED` records that the tool could not express the question, not that the target
    is safe.
    """
    fields = ("summary_id", "profile", "candidate_identity", "counts", "reachable_unsafe_sites",
              "bounded_claim", "non_claims", "passed", "evidence")
    problems = _missing(rec, fields)
    problems += _nonempty(rec, "summary_id")
    problems += _nonempty(rec, "profile")
    problems += _nonempty(rec, "candidate_identity")
    problems += _nonempty(rec, "bounded_claim")
    problems += _list(rec, "non_claims")
    problems += _bool(rec, "passed")
    problems += _list(rec, "evidence")
    if "counts" in rec and not isinstance(rec["counts"], dict):
        problems.append("counts must be an object")
    sites = rec.get("reachable_unsafe_sites")
    if sites is not None and not isinstance(sites, list):
        problems.append("reachable_unsafe_sites must be a list")
        return problems
    externally_reachable_unsupported: list[str] = []
    for i, row in enumerate(sites or []):
        if not isinstance(row, dict):
            problems.append(f"reachable_unsafe_sites[{i}] must be an object")
            continue
        row_fields = ("unsafe_site_id", "exposure_class", "tool_state", "claimed_pass",
                      "explanation")
        problems += [f"reachable_unsafe_sites[{i}]: {p}" for p in _missing(row, row_fields)]
        problems += [f"reachable_unsafe_sites[{i}]: {p}"
                     for p in _enum(row, "exposure_class", EXPOSURE_CLASSES)]
        problems += [f"reachable_unsafe_sites[{i}]: {p}"
                     for p in _enum(row, "tool_state", TOOL_STATES)]
        problems += [f"reachable_unsafe_sites[{i}]: {p}" for p in _bool(row, "claimed_pass")]
        if row.get("claimed_pass") is True and row.get("tool_state") != "PASS":
            problems.append(
                f"reachable_unsafe_sites[{i}] marks tool_state={row.get('tool_state')!r} as a pass; "
                f"only a PASS tool state may be claimed as a pass"
            )
        if (row.get("exposure_class") in EXTERNALLY_REACHABLE_EXPOSURE
                and row.get("tool_state") == "UNSUPPORTED"):
            externally_reachable_unsupported.append(str(row.get("unsafe_site_id")))
            if row.get("claimed_pass") is True:
                problems.append(
                    f"reachable_unsafe_sites[{i}] ({row.get('unsafe_site_id')}) is externally "
                    f"reachable and its tool state is UNSUPPORTED, which is never a pass"
                )
    if rec.get("passed") is True and externally_reachable_unsupported:
        problems.append(
            "a seal-class summary cannot report passed=true while an externally reachable unsafe "
            "site carries tool state UNSUPPORTED ("
            + ", ".join(externally_reachable_unsupported) + "); UNSUPPORTED is never a pass"
        )
    return problems


# The registries the ledger, the runner and the later subphases read. `SCHEMAS` names each record
# kind and its validator; `REQUIRED_FIELDS` is what the inventory publishes.
REQUIRED_FIELDS: dict[str, tuple[str, ...]] = {
    "source_census": ("census_id", "path", "kind", "language", "origin", "shipped", "file_sha256",
                      "unsafe_operations", "evidence"),
    "unsafe_site": ("site_id", "file", "line", "column", "operation_kind", "context_id",
                    "compiler", "compiler_derived", "exposure_class", "risk_tier",
                    "safety_obligation_ids", "evidence"),
    "unsafe_context": ("context_id", "kind", "file", "line", "safety_contract", "site_ids",
                       "evidence"),
    "safety_obligation": ("obligation_id", "site_id", "dimension", "discharged_by", "status",
                          "evidence"),
    "ffi_boundary": ("boundary_id", "symbol", "direction", "abi", "c_variadic", "unwind", "sites",
                     "evidence"),
    "c_adapter": ("adapter_id", "path", "purpose", "exported_symbols", "memory_operations",
                  "evidence"),
    "allocation_site": ("allocation_id", "site_id", "allocator", "size_expr", "freed_by", "paired",
                        "evidence"),
    "ownership_edge": ("edge_id", "from_site", "to_site", "kind", "evidence"),
    "callback_lifetime": ("callback_id", "registered_at", "invoked_by", "lifetime", "may_outlive",
                          "evidence"),
    "send_sync_impl": ("impl_id", "type", "trait", "justification", "evidence"),
    "global_state": ("global_id", "name", "mutability", "initialization", "safety_contract",
                     "evidence"),
    "panic_boundary": ("panic_id", "site_id", "class", "caught_at", "evidence"),
    "miri_result": ("result_id", "target", "tool_state", "tool_version", "findings",
                    "unsupported_reason", "evidence"),
    "sanitizer_result": ("result_id", "sanitizer", "target", "tool_state", "findings",
                         "unsupported_reason", "evidence"),
    "kani_result": ("result_id", "harness", "target", "tool_state", "findings",
                    "unsupported_reason", "evidence"),
    "fuzz_crosswalk": ("crosswalk_id", "phase18_target", "unsafe_site_ids", "covered", "tool_state",
                       "evidence"),
    "coverage": ("coverage_id", "profile", "tool", "covered_sites", "uncovered_sites", "tool_state",
                 "evidence"),
    "historical_cve": ("cve_id", "taxonomy", "affected_versions", "fix_commit", "memory_safety",
                       "evidence"),
    "cve_replay": ("replay_id", "cve_id", "state", "candidate_identity", "evidence"),
    "vulnerability_mechanism": ("mechanism_id", "taxonomy", "class_present",
                                "candidate_structurally_immune", "reason", "cve_ids", "evidence"),
    "residual": ("residual_id", "subject", "class", "disposition", "detail", "evidence"),
    "summary": ("summary_id", "profile", "candidate_identity", "counts", "reachable_unsafe_sites",
                "bounded_claim", "non_claims", "passed", "evidence"),
}

SCHEMAS = {
    "source_census": validate_source_census,
    "unsafe_site": validate_unsafe_site,
    "unsafe_context": validate_unsafe_context,
    "safety_obligation": validate_safety_obligation,
    "ffi_boundary": validate_ffi_boundary,
    "c_adapter": validate_c_adapter,
    "allocation_site": validate_allocation_site,
    "ownership_edge": validate_ownership_edge,
    "callback_lifetime": validate_callback_lifetime,
    "send_sync_impl": validate_send_sync_impl,
    "global_state": validate_global_state,
    "panic_boundary": validate_panic_boundary,
    "miri_result": validate_miri_result,
    "sanitizer_result": validate_sanitizer_result,
    "kani_result": validate_kani_result,
    "fuzz_crosswalk": validate_fuzz_crosswalk,
    "coverage": validate_coverage,
    "historical_cve": validate_historical_cve,
    "cve_replay": validate_cve_replay,
    "vulnerability_mechanism": validate_vulnerability_mechanism,
    "residual": validate_residual,
    "summary": validate_summary,
}


def validate(kind: str, rec: dict) -> list[str]:
    """Validate one record against a named schema, or report the unknown schema."""
    fn = SCHEMAS.get(kind)
    if fn is None:
        return [f"unknown record kind {kind!r}; known: {sorted(SCHEMAS)}"]
    return fn(rec)


def inventory() -> dict:
    """The schema inventory: each record kind and the fields it requires, deterministically."""
    return {
        kind: {"fields": list(REQUIRED_FIELDS[kind]), "valid": SCHEMAS[kind].__name__}
        for kind in sorted(SCHEMAS)
    }


# --------------------------------------------------------------------------------------------
# the self-test: every validator accepts a documented-good record and rejects a documented-bad one
# --------------------------------------------------------------------------------------------

_DIGEST = "0" * 64
_GOOD: dict[str, dict] = {
    "source_census": {
        "census_id": "sc-src-runtime-alloc",
        "path": "src/runtime/alloc.rs",
        "kind": "RUST_SOURCE",
        "language": "rust",
        "origin": "FIRST_PARTY",
        "shipped": True,
        "file_sha256": _DIGEST,
        "unsafe_operations": 12,
        "evidence": ["artifacts/phase25/source-census.json"],
    },
    "unsafe_site": {
        "site_id": "us-runtime-alloc-40",
        "file": "src/runtime/alloc.rs",
        "line": 40,
        "column": 9,
        "operation_kind": "RAW_POINTER_DEREFERENCE",
        "context_id": "uc-runtime-alloc-drop",
        "compiler": "rustc 1.98.1",
        "compiler_derived": True,
        "exposure_class": "INTERNAL_REACHABLE",
        "risk_tier": "S2",
        "safety_obligation_ids": ["ob-alloc-nonnull"],
        "evidence": ["artifacts/phase25/unsafe-sites.json"],
    },
    "unsafe_context": {
        "context_id": "uc-runtime-alloc-drop",
        "kind": "UNSAFE_FN",
        "file": "src/runtime/alloc.rs",
        "line": 36,
        "safety_contract": "the caller guarantees `ptr` is a live allocation from `allocator`",
        "site_ids": ["us-runtime-alloc-40"],
        "evidence": ["artifacts/phase25/unsafe-sites.json"],
    },
    "safety_obligation": {
        "obligation_id": "ob-alloc-nonnull",
        "site_id": "us-runtime-alloc-40",
        "dimension": "NULLABILITY",
        "discharged_by": "RUNTIME_CHECK",
        "status": "DISCHARGED",
        "evidence": ["artifacts/phase25/safety-obligations.json"],
    },
    "ffi_boundary": {
        "boundary_id": "ffi-crypto-lib-ctx-new",
        "symbol": "CRYPTO_malloc",
        "direction": "OUTBOUND",
        "abi": "C",
        "c_variadic": False,
        "unwind": "CANNOT_PANIC_BY_CONSTRUCTION",
        "sites": ["us-runtime-alloc-40"],
        "evidence": ["artifacts/phase25/ffi-boundaries.json"],
    },
    "c_adapter": {
        "adapter_id": "ca-shim-openssl",
        "path": "csrc/shim.c",
        "purpose": "expose the authority C ABI to the crate",
        "exported_symbols": ["OSSL_shim_init"],
        "memory_operations": ["malloc", "free"],
        "evidence": ["artifacts/phase25/c-adapters.json"],
    },
    "allocation_site": {
        "allocation_id": "alloc-lib-ctx",
        "site_id": "us-runtime-alloc-40",
        "allocator": "CRYPTO_malloc",
        "size_expr": "size_of::<LibCtx>()",
        "freed_by": "CRYPTO_free",
        "paired": True,
        "evidence": ["artifacts/phase25/allocations.json"],
    },
    "ownership_edge": {
        "edge_id": "oe-lib-ctx-to-c",
        "from_site": "us-runtime-alloc-40",
        "to_site": "us-ffi-register-12",
        "kind": "TRANSFERS_OWNERSHIP",
        "evidence": ["artifacts/phase25/ownership.json"],
    },
    "callback_lifetime": {
        "callback_id": "cb-verify",
        "registered_at": "us-ffi-register-12",
        "invoked_by": "authority X509_verify_cert",
        "lifetime": "until the X509_STORE_CTX is freed",
        "may_outlive": False,
        "evidence": ["artifacts/phase25/callbacks.json"],
    },
    "send_sync_impl": {
        "impl_id": "ss-lib-ctx",
        "type": "LibCtx",
        "trait": "SEND",
        "justification": "the authority serialises access to the context internally",
        "evidence": ["artifacts/phase25/send-sync.json"],
    },
    "global_state": {
        "global_id": "gs-error-queue",
        "name": "ERR_STATE",
        "mutability": "THREAD_LOCAL",
        "initialization": "lazy thread-local init",
        "safety_contract": "",
        "evidence": ["artifacts/phase25/globals.json"],
    },
    "panic_boundary": {
        "panic_id": "pb-ffi-export",
        "site_id": "us-ffi-register-12",
        "class": "CATCHES_PANIC",
        "caught_at": "catch_unwind in the exported wrapper",
        "evidence": ["artifacts/phase25/panic-boundaries.json"],
    },
    "miri_result": {
        "result_id": "miri-runtime-alloc",
        "target": "src/runtime",
        "tool_state": "PASS",
        "tool_version": "miri 1.98.1",
        "findings": [],
        "unsupported_reason": "",
        "evidence": ["artifacts/phase25/miri.json"],
    },
    "sanitizer_result": {
        "result_id": "asan-phase17-corpus",
        "sanitizer": "ASAN",
        "target": "phase17 downstream corpus",
        "tool_state": "PASS",
        "findings": [],
        "unsupported_reason": "",
        "evidence": ["artifacts/phase25/asan.json"],
    },
    "kani_result": {
        "result_id": "kani-alloc-drop",
        "harness": "alloc_drop_is_sound",
        "target": "src/runtime/alloc.rs",
        "tool_state": "PASS",
        "findings": [],
        "unsupported_reason": "",
        "evidence": ["artifacts/phase25/kani.json"],
    },
    "fuzz_crosswalk": {
        "crosswalk_id": "fw-hostile-tls",
        "phase18_target": "RT-HOSTILE-TLS",
        "unsafe_site_ids": ["us-runtime-alloc-40"],
        "covered": True,
        "tool_state": "PASS",
        "evidence": ["artifacts/phase25/fuzz-crosswalk.json"],
    },
    "coverage": {
        "coverage_id": "cov-miri-claimed-profile",
        "profile": "default-linux-x86_64",
        "tool": "miri",
        "covered_sites": ["us-runtime-alloc-40"],
        "uncovered_sites": [],
        "tool_state": "PASS",
        "evidence": ["artifacts/phase25/coverage.json"],
    },
    "historical_cve": {
        "cve_id": "CVE-2022-3602",
        "taxonomy": "STACK_OOB_WRITE",
        "affected_versions": ["3.0.0", "3.0.6"],
        "fix_commit": "ab5c0c1",
        "memory_safety": True,
        "evidence": ["artifacts/phase25/historical-cves.json"],
    },
    "cve_replay": {
        "replay_id": "replay-CVE-2022-3602",
        "cve_id": "CVE-2022-3602",
        "state": "CANDIDATE_STRUCTURALLY_EXCLUDED",
        "candidate_identity": "openssl-rs 0.0.27",
        "evidence": ["artifacts/phase25/cve-replay/CVE-2022-3602.json"],
    },
    "vulnerability_mechanism": {
        "mechanism_id": "vm-punycode-overflow",
        "taxonomy": "BUFFER_OVERFLOW",
        "class_present": False,
        "candidate_structurally_immune": True,
        "reason": "the punycode decoder is a slice-indexed safe-Rust transcription",
        "cve_ids": ["CVE-2022-3602"],
        "evidence": ["artifacts/phase25/mechanisms.json"],
    },
    "residual": {
        "residual_id": "res-unsupported-tsan",
        "subject": "src/net",
        "class": "tool_unsupported",
        "disposition": "classified",
        "detail": "TSan cannot instrument the FFI shim's inline asm",
        "evidence": ["artifacts/phase25/residuals.json"],
    },
    "summary": {
        "summary_id": "summary-default-profile",
        "profile": "default-linux-x86_64",
        "candidate_identity": "openssl-rs 0.0.27",
        "counts": {"unsafe_sites": 1, "externally_reachable": 0},
        "reachable_unsafe_sites": [
            {
                "unsafe_site_id": "us-runtime-alloc-40",
                "exposure_class": "INTERNAL_REACHABLE",
                "tool_state": "PASS",
                "claimed_pass": True,
                "explanation": "covered by miri and asan",
            }
        ],
        "bounded_claim": "the memory-safety-relevant TCB has been inventoried",
        "non_claims": ["safe Rust does not prove protocol correctness"],
        "passed": True,
        "evidence": ["artifacts/phase25/summary.json"],
    },
}


def _bad(kind: str) -> dict:
    """A documented-bad record for each kind: the mutation and why it must be refused."""
    import copy

    rec = copy.deepcopy(_GOOD[kind])
    if kind == "source_census":
        rec["kind"] = "MARKDOWN"  # not a shipped source/build kind
    elif kind == "unsafe_site":
        rec["compiler_derived"] = False  # the compiler is the authority, never a regex
    elif kind == "unsafe_context":
        rec["safety_contract"] = ""  # a context with sites must state its contract
    elif kind == "safety_obligation":
        rec["dimension"] = "VIBES"  # not one of the obligation dimensions
    elif kind == "ffi_boundary":
        rec["abi"] = "MAGIC"  # not one of the FFI ABIs
    elif kind == "c_adapter":
        rec["purpose"] = ""  # an adapter with no purpose is not a record
    elif kind == "allocation_site":
        rec["freed_by"] = ""  # a paired allocation must name what frees it
    elif kind == "ownership_edge":
        rec["kind"] = "TELEPORT"  # not one of the ownership kinds
    elif kind == "callback_lifetime":
        rec["lifetime"] = ""  # a callback with no lifetime is not a contract
    elif kind == "send_sync_impl":
        rec["justification"] = ""  # an unjustified unsafe impl is refused
    elif kind == "global_state":
        rec["mutability"] = "MUTABLE_UNSYNCHRONIZED"  # now needs a safety contract
    elif kind == "panic_boundary":
        rec["class"] = "PROBABLY_FINE"  # not one of the panic/unwind classes
    elif kind == "miri_result":
        rec["tool_state"] = "UNSUPPORTED"  # now needs an unsupported_reason
    elif kind == "sanitizer_result":
        rec["sanitizer"] = "UBSAN"  # not one of the admitted sanitizers
    elif kind == "kani_result":
        rec["tool_state"] = "MAYBE"  # not one of the tool states
    elif kind == "fuzz_crosswalk":
        rec["covered"] = "yes"  # must be a boolean
    elif kind == "coverage":
        rec["tool_state"] = "SORT_OF"  # not one of the tool states
    elif kind == "historical_cve":
        rec["cve_id"] = "2022-3602"  # not a CVE identifier
    elif kind == "cve_replay":
        rec["state"] = "CANDIDATE_STRUCTURALLY_EXCLUDED"
        rec["evidence"] = []  # structurally excluded with no evidence is refused
    elif kind == "vulnerability_mechanism":
        rec["candidate_structurally_immune"] = True
        rec["reason"] = ""  # immunity with no reason is refused
    elif kind == "residual":
        rec["class"] = "mysterious"  # not one of the residual classes
    elif kind == "summary":
        # An externally reachable unsafe site whose tool state is UNSUPPORTED, marked as a pass.
        rec["reachable_unsafe_sites"][0]["exposure_class"] = "NETWORK_SERVER_REACHABLE"
        rec["reachable_unsafe_sites"][0]["tool_state"] = "UNSUPPORTED"
        rec["reachable_unsafe_sites"][0]["claimed_pass"] = True
    else:
        raise AssertionError(f"no bad case for {kind}")
    return rec


def self_test() -> int:
    """Prove every validator accepts a documented-good record and rejects a documented-bad one."""
    failures: list[str] = []

    # --- the vocabularies are closed and non-empty -------------------------------------------------
    for label, values in (
        ("unsafe_operation_kinds", UNSAFE_OPERATION_KINDS),
        ("obligation_dimensions", OBLIGATION_DIMENSIONS),
        ("exposure_classes", EXPOSURE_CLASSES),
        ("tool_states", TOOL_STATES),
        ("cve_taxonomy", CVE_TAXONOMY),
        ("cve_replay_states", CVE_REPLAY_STATES),
        ("risk_tiers", RISK_TIERS),
        ("panic_unwind_classes", PANIC_UNWIND_CLASSES),
    ):
        if not values:
            failures.append(f"the {label} vocabulary is empty")
        if len(set(values)) != len(values):
            failures.append(f"the {label} vocabulary has a duplicate member")
    if list(RISK_TIERS) != ["S0", "S1", "S2", "S3", "S4"]:
        failures.append("the risk tiers are not the ordered S0-S4")
    if "UNSUPPORTED" not in TOOL_STATES:
        failures.append("the tool states do not carry UNSUPPORTED")
    if not EXTERNALLY_REACHABLE_EXPOSURE <= set(EXPOSURE_CLASSES):
        failures.append("an externally reachable exposure class is not in the exposure vocabulary")

    # --- every validator, both directions ----------------------------------------------------------
    for kind in sorted(SCHEMAS):
        good = validate(kind, _GOOD[kind])
        if good:
            failures.append(f"{kind}: a documented-good record was refused: {good}")
        bad = validate(kind, _bad(kind))
        if not bad:
            failures.append(f"{kind}: a documented-bad record was accepted")

    # --- the named refusals, by name ---------------------------------------------------------------
    import copy

    seal = copy.deepcopy(_GOOD["summary"])
    seal["reachable_unsafe_sites"][0]["exposure_class"] = "NETWORK_SERVER_REACHABLE"
    seal["reachable_unsafe_sites"][0]["tool_state"] = "UNSUPPORTED"
    seal["reachable_unsafe_sites"][0]["claimed_pass"] = False
    problems = validate_summary(seal)
    if not problems:
        failures.append("validate_summary accepted a passed seal with an externally reachable "
                        "UNSUPPORTED tool state")
    elif "UNSUPPORTED" not in " ".join(problems):
        failures.append("the externally-reachable-UNSUPPORTED refusal does not name UNSUPPORTED")

    excluded = copy.deepcopy(_GOOD["cve_replay"])
    excluded["evidence"] = []
    problems = validate_cve_replay(excluded)
    if not problems:
        failures.append("validate_cve_replay accepted a STRUCTURALLY_EXCLUDED replay with no "
                        "evidence")
    elif "evidence" not in " ".join(problems):
        failures.append("the structurally-excluded refusal does not name evidence")

    if failures:
        print("[memory-safety-schemas] self-test FAILED")
        for f in failures:
            print(f"  {f}")
        return 1
    print(f"[memory-safety-schemas] self-test ok: {len(SCHEMAS)} record kind(s) accept the "
          f"documented-good record and refuse the documented-bad one; "
          f"{len(UNSAFE_OPERATION_KINDS)} unsafe-operation kinds, "
          f"{len(OBLIGATION_DIMENSIONS)} obligation dimensions, "
          f"{len(EXPOSURE_CLASSES)} exposure classes, {len(TOOL_STATES)} tool states, "
          f"{len(CVE_TAXONOMY)} CVE taxonomy classes, {len(CVE_REPLAY_STATES)} CVE replay states, "
          f"{len(RISK_TIERS)} risk tiers and {len(PANIC_UNWIND_CLASSES)} panic/unwind classes are "
          f"closed; a seal-class summary with an externally reachable UNSUPPORTED tool state and a "
          f"STRUCTURALLY_EXCLUDED replay with no evidence are both refused")
    return 0


def check() -> int:
    """The vocabulary invariants `--check` asserts, before the self-test."""
    problems: list[str] = []
    inv = inventory()
    if set(inv) != set(REQUIRED_FIELDS) or set(inv) != set(SCHEMAS):
        problems.append("the inventory, REQUIRED_FIELDS and SCHEMAS disagree about the record kinds")
    for kind, fn in SCHEMAS.items():
        if fn.__name__ != f"validate_{kind}":
            problems.append(f"{kind}'s validator is named {fn.__name__}, not validate_{kind}")
    if not EXTERNALLY_REACHABLE_EXPOSURE <= set(EXPOSURE_CLASSES):
        problems.append("EXTERNALLY_REACHABLE_EXPOSURE is not a subset of EXPOSURE_CLASSES")
    if "UNSUPPORTED" not in TOOL_STATES:
        problems.append("TOOL_STATES does not carry UNSUPPORTED")
    if problems:
        print("[memory-safety-schemas] check FAILED")
        for p in problems:
            print(f"  {p}")
        return 1
    print(f"[memory-safety-schemas] check ok: {len(SCHEMAS)} record kinds, "
          f"{len(EXTERNALLY_REACHABLE_EXPOSURE)} externally reachable exposure class(es), "
          f"{len(TOOL_STATES)} tool states; every validator is named and the closed vocabularies "
          f"are subsets of each other as declared")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--self-test", action="store_true",
                    help="prove every validator accepts good and refuses bad records")
    ap.add_argument("--check", action="store_true",
                    help="assert the vocabulary and registry invariants")
    ap.add_argument("--list", action="store_true", help="print the schema inventory")
    ap.add_argument("--vocabulary", action="store_true",
                    help="print the closed vocabularies")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()
    if args.check:
        rc = check()
        if rc:
            return rc
        return self_test()

    if args.vocabulary:
        for label, values in (
            ("unsafe_operation_kinds", UNSAFE_OPERATION_KINDS),
            ("obligation_dimensions", OBLIGATION_DIMENSIONS),
            ("exposure_classes", EXPOSURE_CLASSES),
            ("tool_states", TOOL_STATES),
            ("cve_taxonomy", CVE_TAXONOMY),
            ("cve_replay_states", CVE_REPLAY_STATES),
            ("risk_tiers", RISK_TIERS),
            ("panic_unwind_classes", PANIC_UNWIND_CLASSES),
        ):
            print(f"{label}: {', '.join(values)}")
        return 0

    inv = inventory()
    if args.list:
        for kind in sorted(inv):
            print(f"{kind}: {', '.join(inv[kind]['fields'])}")
        return 0

    print(f"[memory-safety-schemas] {len(inv)} record kind(s): {', '.join(sorted(inv))}")
    print("  run --self-test to prove each accepts a documented-good record and refuses a "
          "documented-bad one; run --check for the vocabulary invariants")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
