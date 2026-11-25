#!/usr/bin/env python3
"""transparency_model.py -- check the transparency-policy invariants in a small model.

Why this tool exists
--------------------
`docs/ETP-ADDENDUM-B.md` section B.23 states twelve transparency-policy
invariants in prose.  Prose is not a checked property, and B.23 itself says the
abstract model must stay small, independently reviewable, and related to the
production machinery without being presented as that machinery.

This tool does the honest middle thing:

  1. the invariants are taken **verbatim** from B.23 and recorded with an
     identifier in ``evidence/b7/MODEL.json``; a clause that is not found in the
     authority is refused (``BM_REFUSED_INVARIANT_UNSOURCED``);
  2. a finite state ``(origin, leaves, issued, acceptedCheckpoints, version,
     verdict, published, witnesses)`` with a fourteen-operation alphabet is
     defined, and a step function changes it;
  3. the reachable state graph is enumerated **exhaustively** to a declared
     sequence bound.  The state is complete and the step is deterministic, so
     every sequence up to the bound maps to a path in the explored graph and no
     sequence's outcome is missed;
  4. a checker flags each invariant on every reached state.  The expected result
     is zero violations, and a **deliberately broken model** for each invariant
     shows that the checker can fail (the canary);
  5. the same small sequences are driven through the **real modules**
     (``tlog``, ``monitor``, ``corrections``, ``thresholds``, ``publication``)
     and the accept/reject vector and the resulting state are compared.  A
     disagreement is a defect, recorded and never repaired by editing the model.

What this does and does not establish
-------------------------------------
A model theorem is not a proof about the binary or the service (Earned Trust
Article 7).  The enumeration is finite and sequence-bounded.  The model and the
implementation share an author, so agreement is a shared reading, not
independent verification (Article 5).  These limits are recorded in
``evidence/b7/REFINEMENT.json`` and in ``docs/TRANSPARENCY-FORMAL-ASSURANCE.md``
beside the result, not after it.

The model does not import the implementation.  ``root_of``, the step function
and the checker are implemented from the model text alone; the real modules are
imported **inside** the differential driver, after the model has decided.  A
structural test refuses a model function whose globals resolve an implementation
module.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass, replace
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping, Sequence

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = "forensics/tools/transparency_model.py"
ADDENDUM_PATH = REPO_ROOT / "docs/ETP-ADDENDUM-B.md"
MODEL_PATH = REPO_ROOT / "evidence/b7/MODEL.json"
ENUMERATION_PATH = REPO_ROOT / "evidence/b7/ENUMERATION.json"
REFINEMENT_PATH = REPO_ROOT / "evidence/b7/REFINEMENT.json"
CONTROLS_PATH = REPO_ROOT / "evidence/b7/CONTROLS.json"
DOCUMENT_PATH = REPO_ROOT / "docs/TRANSPARENCY-FORMAL-ASSURANCE.md"

SCHEMA_MODEL = "openssl-rs/b7/model/1"
SCHEMA_ENUMERATION = "openssl-rs/b7/enumeration/1"
SCHEMA_REFINEMENT = "openssl-rs/b7/refinement/1"
SCHEMA_CONTROLS = "openssl-rs/b7/controls/1"

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_USAGE = 2

CODE_OK = "BM_OK"
CODE_USAGE = "BM_REFUSED_USAGE"

#: Stable refusal vocabulary.  Each names the wrong conclusion it prevents.
#: ``docs/TRANSPARENCY-FORMAL-ASSURANCE.md`` names every code and the test that
#: fires it; ``evidence/b7/CONTROLS.json`` has one control per code.
REFUSALS: dict[str, str] = {
    "BM_REFUSED_INVARIANT_VIOLATED": (
        "a reachable state of the model violates a stated invariant"
    ),
    "BM_REFUSED_MODEL_INCOMPLETE": (
        "the model record omits a state field, an operation, an alphabet member "
        "or a required invariant field"
    ),
    "BM_REFUSED_INVARIANT_UNSOURCED": (
        "an invariant's clause is not found verbatim in the authority section"
    ),
    "BM_REFUSED_ENUMERATION_TRUNCATED": (
        "the enumeration did not reach the declared bound, or its reported "
        "sequence space is not the declared alphabet's"
    ),
    "BM_REFUSED_CANARY_NOT_DETECTED": (
        "a deliberately broken model did not violate the invariant it targets, "
        "so the checker has not been shown able to fail"
    ),
    "BM_REFUSED_REFINEMENT_UNSTATED": (
        "a refinement status, a gap, or a gap's source is unstated or contradictory"
    ),
    "BM_REFUSED_DIFFERENTIAL_DISAGREEMENT": (
        "the model and the real modules differ in accept/reject or resulting "
        "state on a sequence they both ran"
    ),
    "BM_REFUSED_NOT_RUN_AS_VERIFIED": (
        "a NOT_RUN sequence is counted as compared, or a matched status has no "
        "executed sequence behind it"
    ),
    "BM_REFUSED_USAGE": "the command line was used incorrectly",
}
REFUSAL_CODES = tuple(REFUSALS)

#: Model step outcomes.  These are not tool refusal codes; they are the model's
#: own vocabulary for a refused operation, and the document lists them so a
#: reader can tell an operational refusal from an invariant violation.
STEP_CODES = (
    "BM_STEP_OK",
    "BM_STEP_NO_NOTE",
    "BM_STEP_UNSIGNED",
    "BM_STEP_FOREIGN",
    "BM_STEP_FALSE_PROOF",
    "BM_STEP_SPLIT",
    "BM_STEP_ROLLBACK",
    "BM_STEP_INCONSISTENT",
    "BM_STEP_CORRECTED",
    "BM_STEP_PRIVATE",
    "BM_STEP_NOTHING_TO_ALIAS",
)


class ToolError(Exception):
    """An invocation or record error that is not a policy refusal."""


class Refusal(Exception):
    """A stable refusal code and the conclusion it prevents."""

    def __init__(self, code: str, message: str) -> None:
        if code not in REFUSALS:
            raise ValueError(f"unknown refusal code {code!r}")
        super().__init__(message)
        self.code = code
        self.message = message

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


def _fail(code: str, message: str) -> None:
    raise Refusal(code, message)


# ---------------------------------------------------------------------------
# Canonical bytes and digests
# ---------------------------------------------------------------------------


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def pretty(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode(
        "utf-8"
    )


def record_digest(document: Mapping[str, Any]) -> str:
    body = {key: value for key, value in document.items() if key != "digest"}
    return digest(body)


# ---------------------------------------------------------------------------
# The authority: B.23's clauses, verbatim
# ---------------------------------------------------------------------------


def authority_clauses() -> list[str]:
    """The bullet clauses of section B.23, in order, verbatim from the file."""
    try:
        text = ADDENDUM_PATH.read_text(encoding="utf-8")
    except OSError as error:
        _fail("BM_REFUSED_INVARIANT_UNSOURCED", f"the authority is unreadable: {error}")
    start = text.find("## B.23.")
    end = text.find("## B.24.")
    if start < 0 or end < 0 or end <= start:
        _fail(
            "BM_REFUSED_INVARIANT_UNSOURCED",
            "section B.23 is not delimited in docs/ETP-ADDENDUM-B.md",
        )
    block = text[start:end]
    clauses = []
    for line in block.splitlines():
        stripped = line.strip()
        if stripped.startswith("- "):
            clauses.append(stripped[2:])
    if not clauses:
        _fail("BM_REFUSED_INVARIANT_UNSOURCED", "section B.23 states no bullet clause")
    return clauses


def assert_sourced(clause: str, authority: Sequence[str]) -> None:
    if clause not in authority:
        _fail(
            "BM_REFUSED_INVARIANT_UNSOURCED",
            f"the clause {clause!r} is not a verbatim B.23 bullet",
        )


# ---------------------------------------------------------------------------
# The model's alphabet and state
# ---------------------------------------------------------------------------

BOUND = 5
MAX_BOUND = 8

OPERATIONS = (
    "append_claim",
    "append_other",
    "issue_checkpoint",
    "observe_head",
    "observe_stale",
    "observe_split",
    "observe_unsigned",
    "observe_foreign",
    "correct_subject",
    "use_claim",
    "publish_public",
    "publish_private",
    "witness_distinct",
    "witness_alias",
)
ALPHABET = OPERATIONS
ALPHABET_SIZE = len(ALPHABET)

ORIGIN = "log-a"
FOREIGN_ORIGIN = "log-b"
INITIAL_LEAF = "claim-0"
PUBLIC_PATH = "evidence/a9/STATEMENTS/a8-shard-000.json"
PRIVATE_PATH = "keys/release.pem"
PUBLIC_PATHS = (PUBLIC_PATH,)
PRIVATE_PATHS = (PRIVATE_PATH,)

VERDICT_ACTIVE = "ACTIVE"
VERDICT_CORRECTED = "CORRECTED"

#: A state field the checker reads.  A model record that omits one is incomplete.
STATE_FIELDS = (
    "origin",
    "leaves",
    "issued",
    "accepted",
    "version",
    "versionFloor",
    "verdict",
    "correctedAt",
    "lastUseVersion",
    "published",
    "witnessLabels",
    "witnessDomains",
    "quorum",
)


@dataclass(frozen=True)
class Accepted:
    """One accepted checkpoint and the leaf sequence it commits to.

    ``committed`` is the model's stand-in for the tiles an RFC 6962 verifier
    would read.  A checkpoint the log itself produced commits the true prefix;
    a deliberately equivocating checkpoint (``observe_split``) commits a
    different list, which is how the split-view rule is expressible without the
    model knowing which one the log "really" meant.
    """

    origin: str
    size: int
    root: str
    signed: bool
    committed: tuple[str, ...]


@dataclass(frozen=True)
class State:
    origin: str
    leaves: tuple[str, ...]
    issued: tuple[tuple[str, int, str, tuple[str, ...]], ...]
    accepted: tuple[Accepted, ...]
    version: int
    versionFloor: int
    verdict: str
    correctedAt: int | None
    lastUseVersion: int | None
    published: tuple[str, ...]
    witnessLabels: int
    witnessDomains: int
    quorum: int


INITIAL_STATE = State(
    origin=ORIGIN,
    leaves=(INITIAL_LEAF,),
    issued=(),
    accepted=(),
    version=1,
    versionFloor=1,
    verdict=VERDICT_ACTIVE,
    correctedAt=None,
    lastUseVersion=None,
    published=(),
    witnessLabels=0,
    witnessDomains=0,
    quorum=0,
)


# ---------------------------------------------------------------------------
# RFC 6962 geometry, implemented from the model text (not imported from tlog)
# ---------------------------------------------------------------------------

HASH_BYTES = 32
LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"
EMPTY_ROOT = hashlib.sha256(b"").digest()


def _leaf_hash(entry: str) -> bytes:
    return hashlib.sha256(LEAF_PREFIX + entry.encode("utf-8")).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def _largest_power_of_two_less_than(n: int) -> int:
    return 1 << ((n - 1).bit_length() - 1)


def _mth(hashes: Sequence[bytes], start: int, end: int) -> bytes:
    count = end - start
    if count == 0:
        return EMPTY_ROOT
    if count == 1:
        return hashes[start]
    k = _largest_power_of_two_less_than(count)
    return _node_hash(_mth(hashes, start, start + k), _mth(hashes, start + k, end))


@lru_cache(maxsize=None)
def root_of(committed: tuple[str, ...]) -> str:
    """The RFC 6962 root over a committed leaf sequence, as lower-case hex."""
    hashes = [_leaf_hash(item) for item in committed]
    if not hashes:
        return EMPTY_ROOT.hex()
    return _mth(hashes, 0, len(hashes)).hex()


def _path(hashes: Sequence[bytes], start: int, count: int, m: int) -> list[bytes]:
    if count == 1:
        return []
    k = _largest_power_of_two_less_than(count)
    if m < k:
        return _path(hashes, start, k, m) + [_mth(hashes, start + k, start + count)]
    return _path(hashes, start + k, count - k, m - k) + [_mth(hashes, start, start + k)]


def _inclusion_path(committed: tuple[str, ...], index: int) -> list[bytes]:
    hashes = [_leaf_hash(item) for item in committed]
    return _path(hashes, 0, len(hashes), index)


def _verify_inclusion(
    committed: tuple[str, ...], index: int, proof: Sequence[bytes], root: bytes
) -> bool:
    """The RFC 6962 section 2.1.3 node accumulation, from the model text."""
    size = len(committed)
    if not 0 <= index < size:
        return False
    fn, sn = index, size - 1
    r = _leaf_hash(committed[index])
    for sibling in proof:
        if len(sibling) != HASH_BYTES:
            return False
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = _node_hash(sibling, r)
            if not (fn & 1):
                while fn != 0 and not (fn & 1):
                    fn >>= 1
                    sn >>= 1
        else:
            r = _node_hash(r, sibling)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def inclusion_holds(committed: tuple[str, ...], index: int, root_hex: str) -> bool:
    return _verify_inclusion(
        committed, index, _inclusion_path(committed, index), bytes.fromhex(root_hex)
    )


def inclusion_rejects_a_lie(committed: tuple[str, ...], index: int, root_hex: str) -> bool:
    """A mutated proof (or leaf) does not verify against the same root."""
    proof = _inclusion_path(committed, index)
    if proof:
        mutated = list(proof)
        last = bytearray(mutated[-1])
        last[0] ^= 0x01
        mutated[-1] = bytes(last)
        return not _verify_inclusion(
            committed, index, mutated, bytes.fromhex(root_hex)
        )
    if len(committed) != 1 or index != 0:
        return False
    lie = ("forged-leaf",)
    return not _verify_inclusion(lie, 0, [], bytes.fromhex(root_hex))


# ---------------------------------------------------------------------------
# The step function
# ---------------------------------------------------------------------------


def _corrupt(root_hex: str) -> str:
    return ("0" if root_hex[0] != "0" else "1") + root_hex[1:]


def _admit(
    state: State,
    origin: str,
    committed: tuple[str, ...],
    root_hex: str,
    signed: bool,
    fault: str | None,
) -> tuple[State, bool, str]:
    """The acceptance rule for one observed checkpoint."""
    if not signed and fault != "unsigned-accepted":
        return state, False, "BM_STEP_UNSIGNED"
    if origin != state.origin and fault != "foreign-accepted":
        return state, False, "BM_STEP_FOREIGN"
    if root_hex != root_of(committed) and fault != "root-ignored":
        return state, False, "BM_STEP_FALSE_PROOF"
    size = len(committed)
    for accepted in state.accepted:
        if (
            accepted.size == size
            and accepted.root != root_hex
            and fault != "split-accepted"
        ):
            return state, False, "BM_STEP_SPLIT"
    if state.accepted:
        top = max(state.accepted, key=lambda item: item.size)
        if size < top.size:
            if fault != "rollback-accepted":
                return state, False, "BM_STEP_ROLLBACK"
        elif size > top.size:
            if committed[: top.size] != top.committed:
                return state, False, "BM_STEP_INCONSISTENT"
    entry = Accepted(origin, size, root_hex, signed, committed)
    return replace(state, accepted=state.accepted + (entry,)), True, "BM_STEP_OK"


def step(state: State, operation: str, fault: str | None = None) -> tuple[State, bool, str]:
    """Apply one operation; return ``(state, accepted, step_code)``.

    A refused operation returns the *same* state: a refusal never partially
    mutates the model, which is the model's whole point.
    """
    if operation not in OPERATIONS:
        _fail("BM_REFUSED_MODEL_INCOMPLETE", f"unknown operation {operation!r}")

    if operation == "append_claim":
        return replace(state, leaves=state.leaves + (f"claim-{len(state.leaves)}",)), True, "BM_STEP_OK"
    if operation == "append_other":
        return replace(state, leaves=state.leaves + (f"other-{len(state.leaves)}",)), True, "BM_STEP_OK"

    if operation == "issue_checkpoint":
        committed = state.leaves
        root_hex = root_of(committed)
        if fault == "root-ignored":
            root_hex = _corrupt(root_hex)
        entry = (state.origin, len(committed), root_hex, committed)
        first = state.issued[0] if state.issued else entry
        return replace(state, issued=(first, entry)), True, "BM_STEP_OK"

    if operation in ("observe_head", "observe_stale", "observe_split",
                     "observe_unsigned", "observe_foreign"):
        if not state.issued:
            return state, False, "BM_STEP_NO_NOTE"
        chosen = state.issued[-1] if operation != "observe_stale" else state.issued[0]
        origin, size, root_hex, committed = chosen
        if operation == "observe_split":
            committed = tuple(
                "fork" if position == 0 else committed[position]
                for position in range(size)
            )
            origin, root_hex = state.origin, root_of(committed)
            return _admit(state, origin, committed, root_hex, True, fault)
        if operation == "observe_unsigned":
            return _admit(state, origin, committed, root_hex, False, fault)
        if operation == "observe_foreign":
            return _admit(state, FOREIGN_ORIGIN, committed, root_hex, True, fault)
        return _admit(state, origin, committed, root_hex, True, fault)

    if operation == "correct_subject":
        version = state.version - 1 if fault == "version-decrease" else state.version + 1
        return (
            replace(
                state,
                version=version,
                versionFloor=max(state.versionFloor, version),
                verdict=VERDICT_CORRECTED,
                correctedAt=version,
            ),
            True,
            "BM_STEP_OK",
        )

    if operation == "use_claim":
        if state.verdict == VERDICT_CORRECTED and fault != "withdrawn-current":
            return state, False, "BM_STEP_CORRECTED"
        return replace(state, lastUseVersion=state.version), True, "BM_STEP_OK"

    if operation == "publish_public":
        if PUBLIC_PATH in state.published:
            return state, True, "BM_STEP_OK"
        return replace(state, published=state.published + (PUBLIC_PATH,)), True, "BM_STEP_OK"
    if operation == "publish_private":
        if fault != "publish-private":
            return state, False, "BM_STEP_PRIVATE"
        return replace(state, published=state.published + (PRIVATE_PATH,)), True, "BM_STEP_OK"

    if operation == "witness_distinct":
        labels = state.witnessLabels + 1
        domains = state.witnessDomains + 1
        quorum = labels if fault == "witness-labels" else domains
        return (
            replace(
                state,
                witnessLabels=labels,
                witnessDomains=domains,
                quorum=quorum,
            ),
            True,
            "BM_STEP_OK",
        )
    if operation == "witness_alias":
        if state.witnessDomains == 0:
            return state, False, "BM_STEP_NOTHING_TO_ALIAS"
        labels = state.witnessLabels + 1
        quorum = labels if fault == "witness-labels" else state.witnessDomains
        return (
            replace(
                state,
                witnessLabels=labels,
                witnessDomains=state.witnessDomains,
                quorum=quorum,
            ),
            True,
            "BM_STEP_OK",
        )

    raise AssertionError("unreachable")


# ---------------------------------------------------------------------------
# The invariants
# ---------------------------------------------------------------------------

#: The eight modelled invariants.  ``clause`` is copied verbatim from B.23 and
#: checked against the authority by ``validate_model``; ``statement`` is the
#: modelled reading, which is *narrower* than the clause and never replaces it.
INVARIANTS: tuple[dict[str, Any], ...] = (
    {
        "id": "BM-I1",
        "name": "checkpoint-signature",
        "clause": "an unauthenticated checkpoint cannot authorise an accepted tree root;",
        "operations": [
            "issue_checkpoint",
            "observe_head",
            "observe_stale",
            "observe_split",
            "observe_unsigned",
            "observe_foreign",
        ],
        "statement": (
            "No checkpoint enters acceptedCheckpoints without a signature over its "
            "exact note bytes. Every observation carries a signature-valid flag; an "
            "unsigned observation is refused and leaves the state unchanged."
        ),
        "assumption": (
            "signatures are unforgeable and cover the exact note bytes; the model "
            "represents 'verified' as a boolean supplied by a signer/verifier pair it "
            "does not implement"
        ),
        "check": "no accepted checkpoint has signed == false",
        "brokenBy": "unsigned-accepted",
    },
    {
        "id": "BM-I2",
        "name": "tree-size-monotone",
        "clause": "a smaller checkpoint cannot silently roll back accepted state;",
        "operations": ["observe_head", "observe_stale", "observe_split"],
        "statement": (
            "The tree sizes of accepted checkpoints never decrease: a checkpoint "
            "smaller than the largest accepted size is refused, not applied."
        ),
        "assumption": (
            "a checkpoint's tree size is the length of the leaf sequence it commits; "
            "leaf bytes are atomic"
        ),
        "check": "the accepted sizes are non-decreasing",
        "brokenBy": "rollback-accepted",
    },
    {
        "id": "BM-I3",
        "name": "one-root-per-origin-size",
        "clause": "equal-size conflicting authenticated roots produce an incident;",
        "operations": ["observe_head", "observe_stale", "observe_split"],
        "statement": (
            "For one origin and one tree size there is at most one accepted root; a "
            "second authenticated root at that size is refused as an incident."
        ),
        "assumption": "origins are atomic labels; the log is the only producer of its own checkpoints",
        "check": "no (origin, size) key maps to two roots among accepted checkpoints",
        "brokenBy": "split-accepted",
    },
    {
        "id": "BM-I4",
        "name": "inclusion-persistence",
        "clause": "a false inclusion proof cannot satisfy inclusion verification;",
        "operations": [
            "append_claim",
            "append_other",
            "issue_checkpoint",
            "observe_head",
            "observe_stale",
            "observe_split",
            "use_claim",
        ],
        "statement": (
            "Every accepted checkpoint's root is the RFC 6962 root over the leaf "
            "sequence it commits; a leaf committed at size n is committed at the same "
            "index by every later accepted checkpoint; and the model's inclusion "
            "verifier accepts the true path and rejects a mutated one."
        ),
        "assumption": "leaf bytes are atomic; the RFC 6962 hash geometry is part of the model, not imported",
        "check": (
            "root == root_of(committed); committed lengths agree; earlier committed "
            "prefixes persist; a mutated inclusion path fails"
        ),
        "brokenBy": "root-ignored",
    },
    {
        "id": "BM-I5",
        "name": "withdrawn-is-not-current",
        "clause": "a revoked claim cannot satisfy a sufficiently fresh current-state policy;",
        "operations": ["correct_subject", "use_claim", "issue_checkpoint", "observe_head"],
        "statement": (
            "Once a subject is corrected or withdrawn, no present-tense use is "
            "accepted at that version or any later version, while the claim leaf's "
            "original inclusion at its index remains valid in every honest accepted "
            "checkpoint."
        ),
        "assumption": "the corrected value is a new state version; the claim leaf's position is atomic",
        "check": (
            "after a correction, lastUseVersion < correctedAt; the claim leaf is still "
            "at index 0; every honest checkpoint that committed it still does"
        ),
        "brokenBy": "withdrawn-current",
    },
    {
        "id": "BM-I6",
        "name": "witness-distinct-domains",
        "clause": "duplicate witness credentials cannot satisfy independence thresholds;",
        "operations": ["witness_distinct", "witness_alias"],
        "statement": (
            "A witness quorum counts distinct operator domains, not labels: an alias "
            "of an established domain adds a label and does not raise the quorum."
        ),
        "assumption": "a domain is identified by its establishment record (path, sha256), not by its label",
        "check": "quorum == the number of distinct domains and never exceeds the label count",
        "brokenBy": "witness-labels",
    },
    {
        "id": "BM-I7",
        "name": "state-version-monotone",
        "clause": "a smaller checkpoint cannot silently roll back accepted state;",
        "operations": ["correct_subject", "use_claim"],
        "statement": (
            "The current-state version never decreases: a correction advances it and "
            "no operation lowers it below the highest version the model has reached."
        ),
        "assumption": "the B6 current-state version is the number of covered correction events",
        "check": "version >= versionFloor",
        "brokenBy": "version-decrease",
    },
    {
        "id": "BM-I8",
        "name": "published-is-classified",
        "clause": "a publication failure cannot masquerade as transparent acceptance.",
        "operations": ["publish_public", "publish_private"],
        "statement": (
            "The published set contains only members the classification policy calls "
            "publishable; publishing a private member is refused, not recorded."
        ),
        "assumption": "the classification policy is the B4 policy and a member's class is atomic",
        "check": "every published path is in PUBLIC_PATHS",
        "brokenBy": "publish-private",
    },
)

INVARIANT_IDS = tuple(item["id"] for item in INVARIANTS)
INVARIANT_BY_ID = {item["id"]: item for item in INVARIANTS}

#: B.23 bullets that the model does not express, recorded rather than dropped.
UNMODELLED_CLAUSES = (
    {
        "clause": "an unrelated log entry cannot authenticate a DSSE statement;",
        "reason": (
            "the model's leaves are opaque bytes; DSSE statements, payload types and "
            "the A9/A10 binding are outside it (A23 and A9/A10 own them)"
        ),
    },
    {
        "clause": "unrelated log shards cannot satisfy a same-tree consistency obligation;",
        "reason": (
            "the model has one origin and no shard transitions; cross-shard proof "
            "substitution is a tlog/monitor property, exercised by B5's controls"
        ),
    },
    {
        "clause": "an omitted required campaign activity cannot permit promotion;",
        "reason": (
            "campaign opening, amendment and closure are A19/B3 machinery and have no "
            "representation in this state"
        ),
    },
    {
        "clause": "missing timestamp evidence cannot satisfy a timestamp-dependent claim;",
        "reason": (
            "the model records an observation instant but has no trusted-time authority "
            "or RFC 3161 evidence; B2 records no authority in this venue"
        ),
    },
    {
        "clause": "unavailable evidence cannot satisfy reconstruction requirements;",
        "reason": (
            "archival reconstruction is B6's archive reader; the model has no archive "
            "members and no IO"
        ),
    },
)

#: The frozen state fields, restated in the record so a reader sees the finite state.
STATE_DESCRIPTION = (
    "origin is one atomic label; leaves is an append-only sequence of opaque leaf "
    "strings; issued is the first and last checkpoint the log signed; accepted is "
    "the sequence of accepted checkpoints with the leaf sequence each commits; "
    "version/versionFloor are current-state counters; verdict/correctedAt/"
    "lastUseVersion are the subject's current state; published is the set of "
    "published members; witnessLabels/witnessDomains/quorum are the witness counts."
)

ASSUMPTIONS = (
    {
        "id": "BM-A1",
        "statement": "signatures are unforgeable and cover the exact note bytes",
        "source": "docs/ETP-ADDENDUM-B.md section B.23 (unauthenticated checkpoint clause); docs/LOCAL-TRANSPARENCY.md (the test-only HMAC key)",
        "consequence": "the model's signed flag is an oracle; the differential signs with a test-only HMAC-SHA256 key",
    },
    {
        "id": "BM-A2",
        "statement": "leaf bytes are atomic and are not parsed",
        "source": "docs/ETP-ADDENDUM-B.md section B.23 (model paragraph); docs/ARCHIVAL-REVOCATION.md section 2 (byte-identified members)",
        "consequence": "no DSSE, ASN.1, tile or statement binding is modelled; B.23 bullet 3 is NOT_MODELLED",
    },
    {
        "id": "BM-A3",
        "statement": "time is the recorded observation instant, not a clock",
        "source": "docs/TRANSPARENCY-MONITORING.md section 5 (the monitor's observation time is its own record, not a trusted timestamp); evidence/b5/RECEIPT.md",
        "consequence": "backdating is a comparison of recorded instants; clock skew, trusted time and RFC 3161 are NOT_RUN",
    },
    {
        "id": "BM-A4",
        "statement": "origins are atomic labels and one log is modelled",
        "source": "docs/ETP-ADDENDUM-B.md section B.23 (unrelated shards clause); docs/LOCAL-TRANSPARENCY.md",
        "consequence": "cross-origin substitution is modelled as a refused origin; shard transitions are NOT_MODELLED",
    },
    {
        "id": "BM-A5",
        "statement": "process failure, IO, retries, partial writes and concurrency are not modelled",
        "source": "docs/ETP-ADDENDUM-B.md section B.23 (the crash-recovery and partial-write sentence)",
        "consequence": "B.23 requires these to be modelled; this model does not, and says so in the refinement record",
    },
    {
        "id": "BM-A6",
        "statement": "the enumeration is finite and sequence-bounded",
        "source": "docs/ETP-ADDENDUM-B.md section B.23 (the abstract model paragraph); docs/ETP-ADDENDUM-B.md section B.23 ('bounded model checkers')",
        "consequence": "no theorem about sequences longer than the bound or about the binary (Article 7)",
    },
)


# ---------------------------------------------------------------------------
# The checker
# ---------------------------------------------------------------------------


def check(state: State) -> list[dict[str, str]]:
    """Every invariant violation on one reachable state."""
    violations: list[dict[str, str]] = []

    def flag(identifier: str, detail: str) -> None:
        violations.append({"invariant": identifier, "detail": detail})

    # BM-I1: signature on everything accepted.
    for accepted in state.accepted:
        if not accepted.signed:
            flag("BM-I1", f"accepted checkpoint at size {accepted.size} is unsigned")

    # BM-I2: accepted sizes never decrease.
    sizes = [accepted.size for accepted in state.accepted]
    for previous, following in zip(sizes, sizes[1:]):
        if following < previous:
            flag("BM-I2", f"accepted size decreases {previous} -> {following}")

    # BM-I3: one root per (origin, size).
    roots: dict[tuple[str, int], str] = {}
    for accepted in state.accepted:
        key = (accepted.origin, accepted.size)
        if key in roots and roots[key] != accepted.root:
            flag(
                "BM-I3",
                f"origin {accepted.origin!r} size {accepted.size} has two roots "
                f"{roots[key]} and {accepted.root}",
            )
        roots.setdefault(key, accepted.root)

    # BM-I4: root soundness, persistence and inclusion.
    for accepted in state.accepted:
        if len(accepted.committed) != accepted.size:
            flag(
                "BM-I4",
                f"a checkpoint commits {len(accepted.committed)} leaves but claims size "
                f"{accepted.size}",
            )
        if accepted.root != root_of(accepted.committed):
            flag(
                "BM-I4",
                f"the root at size {accepted.size} is not the root over its committed "
                "leaves (a false proof was accepted)",
            )
        if accepted.size > 0:
            for index in sorted({0, accepted.size - 1}):
                if not inclusion_holds(accepted.committed, index, accepted.root):
                    flag(
                        "BM-I4",
                        f"index {index} at size {accepted.size} does not verify against "
                        "its own root",
                    )
                if not inclusion_rejects_a_lie(accepted.committed, index, accepted.root):
                    flag(
                        "BM-I4",
                        f"a mutated inclusion proof for index {index} at size "
                        f"{accepted.size} was accepted",
                    )
    for position, first in enumerate(state.accepted):
        for second in state.accepted[position + 1 :]:
            if first.size <= second.size and first.committed != second.committed[: first.size]:
                flag(
                    "BM-I4",
                    f"the leaves committed at size {first.size} are not the prefix of "
                    f"the leaves committed at size {second.size} (persistence)",
                )

    # BM-I5: a corrected claim is never current and its inclusion survives.
    if state.verdict == VERDICT_CORRECTED:
        if state.lastUseVersion is not None and not (
            state.lastUseVersion < (state.correctedAt or 0)
        ):
            flag(
                "BM-I5",
                f"a present-tense use at version {state.lastUseVersion} was accepted "
                f"after the correction at version {state.correctedAt}",
            )
        if state.leaves and state.leaves[0] != INITIAL_LEAF:
            flag("BM-I5", "the claim leaf is no longer at index 0")
        for accepted in state.accepted:
            if accepted.size > 0 and accepted.committed == state.leaves[: accepted.size]:
                if accepted.committed[0] != INITIAL_LEAF:
                    flag(
                        "BM-I5",
                        f"the honest checkpoint at size {accepted.size} no longer commits "
                        "the claim at index 0",
                    )
                if not inclusion_holds(accepted.committed, 0, accepted.root):
                    flag(
                        "BM-I5",
                        f"the claim's original inclusion at size {accepted.size} does not "
                        "verify",
                    )

    # BM-I6: the quorum counts distinct domains, not labels.
    if state.quorum != state.witnessDomains:
        flag(
            "BM-I6",
            f"the quorum {state.quorum} is not the {state.witnessDomains} distinct "
            "witness domain(s)",
        )
    if state.witnessDomains > state.witnessLabels:
        flag(
            "BM-I6",
            f"{state.witnessDomains} domains exceed the {state.witnessLabels} label(s)",
        )

    # BM-I7: the current-state version never decreases.
    if state.version < state.versionFloor:
        flag(
            "BM-I7",
            f"state version {state.version} is below the reached {state.versionFloor}",
        )

    # BM-I8: only classified public members are published.
    for path in state.published:
        if path not in PUBLIC_PATHS:
            flag("BM-I8", f"published member {path!r} is not classified public")

    return violations


def violations_by_invariant(violations: Sequence[Mapping[str, str]]) -> dict[str, int]:
    counts = {identifier: 0 for identifier in INVARIANT_IDS}
    for violation in violations:
        counts[str(violation["invariant"])] += 1
    return counts


# ---------------------------------------------------------------------------
# Exhaustive enumeration of the reachable state graph
# ---------------------------------------------------------------------------

#: One deliberately broken model per invariant.  The same checker must catch it.
CANARIES: dict[str, dict[str, str]] = {
    "unsigned-accepted": {
        "invariant": "BM-I1",
        "description": "accept an unsigned checkpoint, as if a signature were not required",
    },
    "rollback-accepted": {
        "invariant": "BM-I2",
        "description": "accept a checkpoint smaller than the largest accepted size",
    },
    "split-accepted": {
        "invariant": "BM-I3",
        "description": "accept a second, conflicting root at an accepted size",
    },
    "root-ignored": {
        "invariant": "BM-I4",
        "description": "issue and accept a checkpoint whose root is not the root over its leaves",
    },
    "withdrawn-current": {
        "invariant": "BM-I5",
        "description": "accept a present-tense use after the subject was corrected",
    },
    "witness-labels": {
        "invariant": "BM-I6",
        "description": "count witness labels rather than distinct operator domains",
    },
    "version-decrease": {
        "invariant": "BM-I7",
        "description": "lower the current-state version below the reached version",
    },
    "publish-private": {
        "invariant": "BM-I8",
        "description": "publish a member classified private",
    },
}

CANARY_BY_INVARIANT = {row["invariant"]: fault for fault, row in CANARIES.items()}


def sequence_space(bound: int, alphabet_size: int = ALPHABET_SIZE) -> int:
    """Every sequence of length 0..bound over the alphabet."""
    if not isinstance(bound, int) or isinstance(bound, bool) or bound < 0:
        _fail("BM_REFUSED_ENUMERATION_TRUNCATED", f"bound {bound!r} is not a length")
    return sum(alphabet_size**length for length in range(bound + 1))


def enumerate_model(
    bound: int = BOUND,
    *,
    fault: str | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    """Explore the reachable state graph to ``bound``, checking every state.

    The state is complete and the step deterministic, so exploring each distinct
    (state, operation) edge once covers every sequence up to the bound.  The
    reported ``sequences`` is the combinatorial size of the sequence space; the
    reported ``transitionsExplored`` is the number of edges actually executed.
    """
    if not isinstance(bound, int) or isinstance(bound, bool) or bound < 0:
        _fail("BM_REFUSED_ENUMERATION_TRUNCATED", f"bound {bound!r} is not a length")
    if bound > MAX_BOUND:
        _fail(
            "BM_REFUSED_USAGE",
            f"bound {bound} exceeds the declared maximum {MAX_BOUND}",
        )
    if limit is not None and limit < bound:
        _fail(
            "BM_REFUSED_ENUMERATION_TRUNCATED",
            f"the limit {limit} stops below the declared bound {bound}",
        )

    initial_violations = check(INITIAL_STATE)
    violations: list[dict[str, Any]] = []
    for violation in initial_violations:
        violations.append({"depth": 0, "sequence": [], **violation})

    visited: dict[State, int] = {INITIAL_STATE: 0}
    paths: dict[State, tuple[str, ...]] = {INITIAL_STATE: ()}
    frontier = [INITIAL_STATE]
    transitions = 0
    expanded = 0
    refusals: dict[str, int] = {}
    max_depth = 0
    checked = 1
    for depth in range(bound):
        following: list[State] = []
        for state in frontier:
            expanded += 1
            for operation in OPERATIONS:
                transitions += 1
                produced, accepted, code = step(state, operation, fault)
                if not accepted:
                    refusals[code] = refusals.get(code, 0) + 1
                if produced not in visited:
                    visited[produced] = depth + 1
                    paths[produced] = paths[state] + (operation,)
                    max_depth = max(max_depth, depth + 1)
                    following.append(produced)
                    checked += 1
                    for violation in check(produced):
                        violations.append(
                            {
                                "depth": depth + 1,
                                "sequence": list(paths[produced]),
                                "previous": _state_identity(state),
                                **violation,
                            }
                        )
        frontier = following
        if not frontier:
            break

    counts = violations_by_invariant(violations)
    return {
        "schema": SCHEMA_ENUMERATION,
        "code": CODE_OK if not violations else "BM_REFUSED_INVARIANT_VIOLATED",
        "bound": bound,
        "fault": fault,
        "alphabet": list(OPERATIONS),
        "alphabetSize": ALPHABET_SIZE,
        "sequenceSpace": sequence_space(bound),
        "sequences": sequence_space(bound),
        "statesReached": len(visited),
        "statesExpanded": expanded,
        "statesChecked": checked,
        "transitionsExplored": transitions,
        "maxDepthReached": max_depth,
        "refusalsByCode": dict(sorted(refusals.items())),
        "invariants": [
            {"id": identifier, "checked": checked, "violations": counts[identifier]}
            for identifier in INVARIANT_IDS
        ],
        "violations": violations[:20],
        "violationCount": len(violations),
        "deterministic": True,
    }


def _state_identity(state: State) -> dict[str, Any]:
    return {
        "leaves": list(state.leaves),
        "acceptedSizes": [item.size for item in state.accepted],
        "version": state.version,
        "verdict": state.verdict,
        "published": list(state.published),
        "quorum": state.quorum,
    }


def run_canaries(bound: int = BOUND) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for fault, meta in CANARIES.items():
        record = enumerate_model(bound, fault=fault)
        target = meta["invariant"]
        counts = violations_by_invariant(record["violations"])
        detected = counts.get(target, 0) > 0
        rows.append(
            {
                "id": fault,
                "targetInvariant": target,
                "description": meta["description"],
                "violations": record["violationCount"],
                "targetViolations": counts.get(target, 0),
                "detected": detected,
                "firstWitness": record["violations"][0] if record["violations"] else None,
            }
        )
    return {
        "canaries": rows,
        "allDetected": all(row["detected"] for row in rows),
        "targets": {row["targetInvariant"]: row["id"] for row in rows},
    }


# ---------------------------------------------------------------------------
# The differential: the model and the real modules over the same sequences
# ---------------------------------------------------------------------------


def default_sequences() -> list[list[str]]:
    """Every sequence of length 1..2, plus one per invariant (length 3..5)."""
    sequences: list[list[str]] = []
    for operation in OPERATIONS:
        sequences.append([operation])
    for first in OPERATIONS:
        for second in OPERATIONS:
            sequences.append([first, second])
    sequences.extend(
        [
            ["issue_checkpoint", "observe_unsigned", "observe_head"],
            [
                "issue_checkpoint",
                "append_other",
                "issue_checkpoint",
                "observe_head",
                "observe_stale",
            ],
            ["issue_checkpoint", "observe_head", "issue_checkpoint", "observe_split"],
            ["issue_checkpoint", "append_claim", "issue_checkpoint", "observe_head"],
            [
                "issue_checkpoint",
                "observe_head",
                "correct_subject",
                "use_claim",
            ],
            ["witness_distinct", "witness_alias", "witness_distinct"],
            ["correct_subject", "correct_subject", "correct_subject"],
            ["publish_public", "publish_private", "publish_public"],
            [
                "issue_checkpoint",
                "observe_head",
                "append_other",
                "issue_checkpoint",
                "observe_head",
            ],
        ]
    )
    return sequences


def _projection(state: State) -> dict[str, Any]:
    return {
        "sizes": [item.size for item in state.accepted],
        "roots": [item.root for item in state.accepted],
        "version": state.version,
        "verdict": state.verdict,
        "published": list(state.published),
        "quorum": state.quorum,
        "lastUseVersion": state.lastUseVersion,
    }


def run_model(sequence: Sequence[str]) -> dict[str, Any]:
    state = INITIAL_STATE
    accepted: list[bool] = []
    codes: list[str] = []
    for operation in sequence:
        state, ok, code = step(state, operation)
        accepted.append(ok)
        codes.append(code)
    return {"accepted": accepted, "codes": codes, "state": _projection(state)}


class _ImplementationDriver:
    """Drive the real modules with the same operations.

    The implementation modules are imported **here**, inside the driver, so the
    model functions' globals never resolve them (the structural guard).
    """

    def __init__(self) -> None:
        tools = str(REPO_ROOT / "forensics" / "tools")
        if tools not in sys.path:
            sys.path.insert(0, tools)
        import corrections as corrections_module
        import monitor as monitor_module
        import publication as publication_module
        import thresholds as thresholds_module
        import tlog as tlog_module

        self.tlog = tlog_module
        self.monitor = monitor_module
        self.corrections = corrections_module
        self.thresholds = thresholds_module
        self.publication = publication_module

        self.origin = ORIGIN
        self.key_name = "b7-test-only"
        self.key = b"b7-test-only-key"
        self.leaves: list[str] = [INITIAL_LEAF]
        self.issued: list[tuple[str, int, str, tuple[str, ...]]] = []
        self.store = monitor_module.CheckpointStore([])
        self.accepted: list[tuple[str, int, str, tuple[str, ...]]] = []
        self.clock = 0
        self.last_use: int | None = None
        self.published: list[str] = []
        self.witness_labels = 0
        self.witness_domains = 0
        self.approvals: list[dict[str, Any]] = []
        self.domains: list[dict[str, Any]] = []
        self.policy = publication_module.load_policy()
        self.assignments = {
            "producer": {"b7-producer"},
            "revocation_authority": {"b7-revoker"},
        }
        self.log = corrections_module.append(
            corrections_module.new_log(),
            corrections_module.sign_event(self._assertion()),
            assignments=self.assignments,
        )

    # -- shared helpers ---------------------------------------------------
    def _value(self, number: int) -> dict[str, Any]:
        body = {"v": number}
        return {
            "value": body,
            "digest": self.corrections.value_digest(body),
            "citation": "b7 model differential",
            "record": None,
        }

    def _assertion(self) -> dict[str, Any]:
        return {
            "schema": self.corrections.EVENT_SCHEMA,
            "eventId": "B7-E1",
            "kind": "assert",
            "subject": "claim-1",
            "supersedes": None,
            "reason": "b7 differential fixture",
            "oldValue": None,
            "newValue": self._value(1),
            "recordedAt": "2026-11-24T00:00:00Z",
            "recordedBy": {"role": "producer", "identity": "b7-producer"},
            "evidence": ["control-only"],
            "authentication": {
                "status": "SELF_ISSUED",
                "authenticated": False,
                "original": "control-only",
            },
        }

    def _leaf_bytes(self, committed: Sequence[str]) -> list[bytes]:
        return [item.encode("utf-8") for item in committed]

    def _root(self, committed: Sequence[str]) -> bytes:
        return self.tlog.root_from_entries(self._leaf_bytes(committed))

    def _note(
        self, origin: str, committed: Sequence[str], *, signed: bool = True
    ) -> bytes:
        text = self.tlog.checkpoint_text(origin, len(committed), self._root(committed))
        return self.tlog.sign_checkpoint(text, self.key_name, self.key) if signed else text

    def _observe(
        self,
        note: bytes,
        committed: Sequence[str],
        *,
        expected_origin: str | None,
    ) -> tuple[bool, str]:
        head = self.store.head
        proof = None
        if head is not None and len(committed) > head["treeSize"]:
            hashes = [self.tlog.leaf_hash(item) for item in self._leaf_bytes(committed)]
            proof = self.tlog.consistency_path(hashes, head["treeSize"], len(committed))
        self.clock += 1
        observed_at = f"2026-01-01T00:00:{self.clock:02d}Z"
        try:
            result = self.monitor.observe(
                self.store,
                note,
                key_name=self.key_name,
                key=self.key,
                observed_at=observed_at,
                source="b7-model",
                consistency_proof=proof,
                expected_origin=expected_origin,
            )
        except (self.monitor.Refusal, self.tlog.Refusal) as refusal:
            return False, getattr(refusal, "code", "REFUSED")
        self.accepted.append(
            (
                result["origin"],
                result["treeSize"],
                result["rootHash"],
                tuple(committed),
            )
        )
        return True, "BM_STEP_OK"

    # -- the operations ---------------------------------------------------
    def step(self, operation: str) -> tuple[bool, str]:
        if operation == "append_claim":
            self.leaves.append(f"claim-{len(self.leaves)}")
            return True, "BM_STEP_OK"
        if operation == "append_other":
            self.leaves.append(f"other-{len(self.leaves)}")
            return True, "BM_STEP_OK"
        if operation == "issue_checkpoint":
            committed = tuple(self.leaves)
            entry = (self.origin, len(committed), self._root(committed).hex(), committed)
            self.issued.append(entry)
            return True, "BM_STEP_OK"
        if operation in (
            "observe_head",
            "observe_stale",
            "observe_split",
            "observe_unsigned",
            "observe_foreign",
        ):
            if not self.issued:
                return False, "BM_STEP_NO_NOTE"
            chosen = self.issued[-1] if operation != "observe_stale" else self.issued[0]
            origin, size, _root_hex, committed = chosen
            if operation == "observe_split":
                committed = tuple(
                    "fork" if position == 0 else committed[position]
                    for position in range(size)
                )
                return self._observe(
                    self._note(self.origin, committed),
                    committed,
                    expected_origin=self.origin,
                )
            if operation == "observe_unsigned":
                return self._observe(
                    self._note(origin, committed, signed=False),
                    committed,
                    expected_origin=self.origin,
                )
            if operation == "observe_foreign":
                return self._observe(
                    self._note(FOREIGN_ORIGIN, committed),
                    committed,
                    expected_origin=self.origin,
                )
            return self._observe(
                self._note(origin, committed), committed, expected_origin=self.origin
            )
        if operation == "correct_subject":
            outcome = self.corrections.current(
                self.log, "claim-1", assignments=self.assignments
            )
            tip = outcome["history"][-1]
            number = len(self.log["events"]) + 1
            event = {
                "schema": self.corrections.EVENT_SCHEMA,
                "eventId": f"B7-C{number}",
                "kind": "correct",
                "subject": "claim-1",
                "supersedes": {
                    "previousEventId": tip["eventId"],
                    "previousDigest": self.corrections.event_digest(tip),
                },
                "reason": "b7 differential correction",
                "oldValue": tip["newValue"],
                "newValue": self._value(number),
                "recordedAt": "2026-11-24T00:00:00Z",
                "recordedBy": {"role": "producer", "identity": "b7-producer"},
                "evidence": ["control-only"],
                "authentication": {
                    "status": "SELF_ISSUED",
                    "authenticated": False,
                    "original": "control-only",
                },
            }
            try:
                self.log = self.corrections.append(
                    self.log,
                    self.corrections.sign_event(event),
                    assignments=self.assignments,
                )
            except self.corrections.Refusal as refusal:
                return False, refusal.code
            return True, "BM_STEP_OK"
        if operation == "use_claim":
            outcome = self.corrections.current(
                self.log, "claim-1", assignments=self.assignments
            )["outcome"]
            if outcome != self.corrections.OUTCOME_CURRENT:
                return False, "BM_STEP_CORRECTED"
            self.last_use = len(self.log["events"])
            return True, "BM_STEP_OK"
        if operation in ("publish_public", "publish_private"):
            path = PUBLIC_PATH if operation == "publish_public" else PRIVATE_PATH
            klass, _rule, _reason = self.publication.classify_path(self.policy, path)
            if klass not in self.publication.PUBLISHABLE:
                return False, "BM_STEP_PRIVATE"
            if path not in self.published:
                self.published.append(path)
            return True, "BM_STEP_OK"
        if operation == "witness_distinct":
            self.witness_labels += 1
            number = self.witness_domains + 1
            record = {
                "path": f"records/domain-{number}.json",
                "sha256": f"{number:064x}",
            }
            self.approvals.append(
                {"identity": f"operator-{number}", "domainId": f"w{number}",
                 "role": "witness", "verified": True, "approvedAt": "2026-11-01",
                 "expiresAt": "2026-12-01"}
            )
            self.domains.append(
                {"domainId": f"w{number}", "kind": "external",
                 "independentOfCandidate": True, "establishedBy": record}
            )
            self.witness_domains = self._distinct()
            return True, "BM_STEP_OK"
        if operation == "witness_alias":
            if self.witness_domains == 0:
                return False, "BM_STEP_NOTHING_TO_ALIAS"
            self.witness_labels += 1
            number = self.witness_labels
            first = self.domains[0]["establishedBy"]
            self.approvals.append(
                {"identity": f"operator-a{number}", "domainId": f"wa{number}",
                 "role": "witness", "verified": True, "approvedAt": "2026-11-01",
                 "expiresAt": "2026-12-01"}
            )
            self.domains.append(
                {"domainId": f"wa{number}", "kind": "external",
                 "independentOfCandidate": True, "establishedBy": dict(first)}
            )
            self.witness_domains = self._distinct()
            return True, "BM_STEP_OK"
        raise AssertionError(f"unreachable operation {operation!r}")

    def _distinct(self) -> int:
        return int(
            self.thresholds.distinct_domains(
                self.approvals,
                {"candidateDomain": "openssl-rs", "domains": self.domains},
            )["count"]
        )

    def projection(self) -> dict[str, Any]:
        return {
            "sizes": [item[1] for item in self.accepted],
            "roots": [item[2] for item in self.accepted],
            "version": len(self.log["events"]),
            "verdict": (
                "ACTIVE"
                if self.corrections.current(
                    self.log, "claim-1", assignments=self.assignments
                )["outcome"]
                == self.corrections.OUTCOME_CURRENT
                else "CORRECTED"
            ),
            "published": list(self.published),
            "quorum": self.witness_domains,
            "lastUseVersion": self.last_use,
        }


def run_implementation(sequence: Sequence[str]) -> tuple[dict[str, Any], str | None]:
    """Run the real modules; return ``(row, not_run_reason)``."""
    try:
        driver = _ImplementationDriver()
    except Exception as error:  # a missing module is NOT_RUN, never a pass
        return {}, f"the implementation driver could not be constructed: {error}"
    accepted: list[bool] = []
    codes: list[str] = []
    try:
        for operation in sequence:
            ok, code = driver.step(operation)
            accepted.append(ok)
            codes.append(code)
    except Exception as error:
        return {}, f"the implementation driver raised {type(error).__name__}: {error}"
    return {"accepted": accepted, "codes": codes, "state": driver.projection()}, None


def differential(
    sequences: Sequence[Sequence[str]] | None = None,
    *,
    force_not_run: Mapping[int, str] | None = None,
) -> dict[str, Any]:
    """Drive the model and the real modules over the same small sequences.

    ``force_not_run`` exists for the control that proves a ``NOT_RUN`` row is
    labelled rather than counted; the default run forces nothing.  No modelled
    operation requires a service, so the default ``notRun`` list is empty.
    """
    if sequences is None:
        sequences = default_sequences()
    force = dict(force_not_run or {})
    rows: list[dict[str, Any]] = []
    disagreements: list[dict[str, Any]] = []
    not_run: list[dict[str, Any]] = []
    for index, sequence in enumerate(sequences):
        identifier = f"S{index:03d}"
        if index in force:
            row = {
                "id": identifier,
                "sequence": list(sequence),
                "outcome": "NOT_RUN",
                "reason": force[index],
            }
            rows.append(row)
            not_run.append({"id": identifier, "sequence": list(sequence),
                            "reason": force[index]})
            continue
        model = run_model(sequence)
        implementation, reason = run_implementation(sequence)
        if reason is not None:
            row = {
                "id": identifier,
                "sequence": list(sequence),
                "outcome": "NOT_RUN",
                "reason": reason,
            }
            rows.append(row)
            not_run.append(
                {"id": identifier, "sequence": list(sequence), "reason": reason}
            )
            continue
        agreed = (
            model["accepted"] == implementation["accepted"]
            and model["state"] == implementation["state"]
        )
        row = {
            "id": identifier,
            "sequence": list(sequence),
            "outcome": "AGREED" if agreed else "DISAGREED",
            "model": model,
            "implementation": implementation,
        }
        rows.append(row)
        if not agreed:
            disagreements.append(
                {
                    "id": identifier,
                    "sequence": list(sequence),
                    "model": model,
                    "implementation": implementation,
                }
            )
    return {
        "schema": "openssl-rs/b7/differential/1",
        "code": CODE_OK if not disagreements else "BM_REFUSED_DIFFERENTIAL_DISAGREEMENT",
        "sequences": len(sequences),
        "compared": len(sequences) - len(not_run),
        "agreed": len(sequences) - len(not_run) - len(disagreements),
        "disagreementCount": len(disagreements),
        "notRunCount": len(not_run),
        "disagreements": disagreements,
        "notRun": not_run,
        "serviceRequirements": {
            operation: None for operation in OPERATIONS
        },
        "rows": rows,
    }


def _differential_row(differential_record: Mapping[str, Any], identifier: str) -> Mapping[str, Any]:
    for row in differential_record["rows"]:
        if row["id"] == identifier:
            return row
    raise ToolError(f"no differential row {identifier!r}")


# ---------------------------------------------------------------------------
# Refinement
# ---------------------------------------------------------------------------


def refinement_status(
    invariant: Mapping[str, Any],
    enumeration: Mapping[str, Any],
    differential_record: Mapping[str, Any],
) -> dict[str, Any]:
    identifier = invariant["id"]
    matching = [
        row["id"]
        for row in differential_record["rows"]
        if row["outcome"] == "AGREED"
        and any(operation in invariant["operations"] for operation in row["sequence"])
    ]
    not_run = [
        row["id"]
        for row in differential_record["rows"]
        if row["outcome"] == "NOT_RUN"
        and any(operation in invariant["operations"] for operation in row["sequence"])
    ]
    if matching:
        status = "MODEL_AND_MATCHED"
    elif not_run:
        status = "MODEL_ONLY"
    else:
        status = "NOT_MATCHED"
    return {
        "id": identifier,
        "status": status,
        "model": "PASS" if counts_for(enumeration, identifier) == 0 else "FAIL",
        "differential": "MATCHED" if matching else ("NOT_RUN" if not_run else "NO_SEQUENCE"),
        "sequences": matching[:8],
        "notRun": not_run,
        "note": (
            "the model's checker reports no violation and the model and the real "
            "modules agree on the accept/reject vector and the resulting state for "
            "the named sequences"
            if status == "MODEL_AND_MATCHED"
            else "stated, not matched"
        ),
    }


def counts_for(enumeration: Mapping[str, Any], identifier: str) -> int:
    for row in enumeration["invariants"]:
        if row["id"] == identifier:
            return int(row["violations"])
    raise ToolError(f"the enumeration has no row for {identifier!r}")


REFINEMENT_GAPS = (
    {
        "id": "BM-G1",
        "gap": "DER and signature cryptography are assumed unforgeable",
        "assumption": "the model's signed flag is an oracle and the note bytes are the signed bytes",
        "source": "docs/ETP-ADDENDUM-B.md section B.23 (unauthenticated checkpoint clause); docs/LOCAL-TRANSPARENCY.md (test-only HMAC key)",
        "consequence": "no claim is made about signature verification, key binding or DER parsing; the differential uses a test-only HMAC-SHA256 key",
    },
    {
        "id": "BM-G2",
        "gap": "time is the recorded instant, not a clock",
        "assumption": "each observation carries a monotonically increasing recorded instant",
        "source": "docs/TRANSPARENCY-MONITORING.md section 5; evidence/b5/RECEIPT.md",
        "consequence": "backdating is a comparison of records; trusted time, clock skew and RFC 3161 are NOT_RUN",
    },
    {
        "id": "BM-G3",
        "gap": "the model's leaves are opaque bytes",
        "assumption": "a leaf is its bytes; no parsing, DSSE payload or tile structure exists",
        "source": "docs/ETP-ADDENDUM-B.md section B.23 (model paragraph); docs/ARCHIVAL-REVOCATION.md section 2",
        "consequence": "B.23's unrelated-entry, shard, campaign, timestamp and reconstruction clauses are NOT_MODELLED",
    },
    {
        "id": "BM-G4",
        "gap": "the model does not model process failure, IO or concurrency",
        "assumption": "an operation either takes effect atomically or is refused with the state unchanged",
        "source": "docs/ETP-ADDENDUM-B.md section B.23 (crash recovery, retries, partial writes, concurrent publication and shard transitions are modelled)",
        "consequence": "the B.23 requirement to model crash recovery, retries, partial writes and concurrency is not met; those properties are NOT_RUN",
    },
    {
        "id": "BM-G5",
        "gap": "the enumeration is finite and sequence-bounded",
        "assumption": "bound = 5; the reachable state graph is explored, not every sequence executed",
        "source": "docs/ETP-ADDENDUM-B.md section B.23 (bounded model checkers; the abstract model stays small)",
        "consequence": "no claim about a sequence longer than the bound or an alphabet larger than the fourteen operations",
    },
    {
        "id": "BM-G6",
        "gap": "the model, the checker and the driver share an author",
        "assumption": "the model is written from B.23 and the B4/B5/B6 documents, not from the modules",
        "source": "docs/EARNED-TRUST.md Article 5; docs/ETP-ADDENDUM-B.md section B.23 (a verified abstract state machine is not a verified implementation)",
        "consequence": "agreement is a shared reading, not independent verification; a model theorem is not a proof about the binary (Article 7)",
    },
)


def build_refinement(
    enumeration: Mapping[str, Any], differential_record: Mapping[str, Any]
) -> dict[str, Any]:
    invariants = [
        refinement_status(invariant, enumeration, differential_record)
        for invariant in INVARIANTS
    ]
    unmodelled = [
        {
            "clause": row["clause"],
            "status": "NOT_MODELLED",
            "model": "NOT_MODELLED",
            "differential": "NOT_MODELLED",
            "reason": row["reason"],
        }
        for row in UNMODELLED_CLAUSES
    ]
    return {
        "schema": SCHEMA_REFINEMENT,
        "bound": enumeration["bound"],
        "invariants": invariants,
        "unmodelled": unmodelled,
        "gaps": [dict(gap) for gap in REFINEMENT_GAPS],
        "notRun": [
            {
                "id": "BM-NR1",
                "item": "an admitted public transparency log",
                "reason": "no admitted service, log key or client exists in this venue (B0/B1 record a fixture)",
            },
            {
                "id": "BM-NR2",
                "item": "a witness cosignature admitted from an independent operator",
                "reason": "B5 records 0 witnesses; the model's witness op counts distinct domains from a local fixture",
            },
            {
                "id": "BM-NR3",
                "item": "a trusted RFC 3161 timestamp",
                "reason": "B2 records no timestamp authority in this venue",
            },
            {
                "id": "BM-NR4",
                "item": "crash recovery, retries, partial writes and concurrent publication",
                "reason": "not modelled; B.23 requires them and this item does not claim them",
            },
            {
                "id": "BM-NR5",
                "item": "a machine-checked proof (TLA+, Coq, Lean, Kani) and a source-to-binary refinement edge",
                "reason": "no such tool ran; a model theorem is not a proof about the binary (Article 7)",
            },
            {
                "id": "BM-NR6",
                "item": "an independent reviewer or a distinct trust domain",
                "reason": "the model, the checker and the driver share an author (Article 5)",
            },
        ],
        "limits": [
            "The enumeration is finite: the sequence space is bounded at "
            f"{enumeration['bound']} operations over {ALPHABET_SIZE} operations.",
            "The state graph is explored, not every sequence executed; the state is "
            "complete and the step deterministic, so no sequence's outcome is missed.",
            "A model theorem is not a proof about the binary or the service.",
            "The model shares an author with the implementation.",
        ],
    }


# ---------------------------------------------------------------------------
# Record validation
# ---------------------------------------------------------------------------


def validate_model(record: Mapping[str, Any]) -> None:
    required = (
        "schema",
        "stateFields",
        "operations",
        "alphabet",
        "bound",
        "invariants",
        "clauses",
        "assumptions",
    )
    for field in required:
        if field not in record:
            _fail("BM_REFUSED_MODEL_INCOMPLETE", f"the model record has no {field!r}")
    if record["schema"] != SCHEMA_MODEL:
        _fail("BM_REFUSED_MODEL_INCOMPLETE", f"foreign schema {record['schema']!r}")
    for field in STATE_FIELDS:
        if field not in record["stateFields"]:
            _fail("BM_REFUSED_MODEL_INCOMPLETE", f"the state omits {field!r}")
    if list(record["alphabet"]) != list(OPERATIONS):
        _fail(
            "BM_REFUSED_MODEL_INCOMPLETE",
            "the alphabet is not the declared fourteen operations",
        )
    if list(record["operations"]) != list(OPERATIONS):
        _fail(
            "BM_REFUSED_MODEL_INCOMPLETE",
            "the operation list and the alphabet disagree",
        )
    if record["bound"] != BOUND:
        _fail(
            "BM_REFUSED_MODEL_INCOMPLETE",
            f"the bound {record['bound']!r} is not the declared {BOUND}",
        )
    authority = authority_clauses()
    seen_ids = set()
    for invariant in record["invariants"]:
        for field in ("id", "name", "clause", "operations", "assumption", "check", "brokenBy"):
            if field not in invariant or invariant[field] in (None, "", []):
                _fail(
                    "BM_REFUSED_MODEL_INCOMPLETE",
                    f"invariant {invariant.get('id')!r} has no {field!r}",
                )
        assert_sourced(invariant["clause"], authority)
        for operation in invariant["operations"]:
            if operation not in OPERATIONS:
                _fail(
                    "BM_REFUSED_MODEL_INCOMPLETE",
                    f"invariant {invariant['id']} names unknown operation {operation!r}",
                )
        seen_ids.add(invariant["id"])
    if seen_ids != set(INVARIANT_IDS):
        _fail(
            "BM_REFUSED_MODEL_INCOMPLETE",
            f"the modelled invariant ids are {sorted(seen_ids)!r}, not {list(INVARIANT_IDS)!r}",
        )
    sources = {row["clause"] for row in record["clauses"]}
    if sources != set(authority):
        _fail(
            "BM_REFUSED_INVARIANT_UNSOURCED",
            "the clause list is not exactly the twelve B.23 bullets",
        )
    for clause in record["clauses"]:
        assert_sourced(clause["clause"], authority)
        if clause["modelled"] and not clause.get("invariants"):
            _fail(
                "BM_REFUSED_MODEL_INCOMPLETE",
                f"the modelled clause {clause['id']!r} names no invariant",
            )
    if not record["assumptions"]:
        _fail("BM_REFUSED_MODEL_INCOMPLETE", "the model states no assumption")


def validate_enumeration(
    record: Mapping[str, Any],
    model: Mapping[str, Any],
    canaries: Mapping[str, Any],
) -> None:
    bound = int(model["bound"])
    expected = sequence_space(bound)
    if record.get("bound") != bound:
        _fail(
            "BM_REFUSED_ENUMERATION_TRUNCATED",
            f"the enumeration bound {record.get('bound')!r} is not {bound}",
        )
    if record.get("sequences") != expected or record.get("sequenceSpace") != expected:
        _fail(
            "BM_REFUSED_ENUMERATION_TRUNCATED",
            f"the enumeration reports {record.get('sequences')!r} sequences, not {expected}",
        )
    if record.get("maxDepthReached") != bound:
        _fail(
            "BM_REFUSED_ENUMERATION_TRUNCATED",
            f"the enumeration reached depth {record.get('maxDepthReached')!r}, not {bound}",
        )
    if int(record.get("violationCount", -1)) != 0:
        first = record.get("violations") or [{}]
        _fail(
            "BM_REFUSED_INVARIANT_VIOLATED",
            f"{record.get('violationCount')} violation(s); first is {first[0]}",
        )
    if not canaries.get("allDetected"):
        missed = [row["id"] for row in canaries.get("canaries", []) if not row["detected"]]
        _fail(
            "BM_REFUSED_CANARY_NOT_DETECTED",
            f"these deliberately broken models were not caught: {missed}",
        )
    for row in canaries.get("canaries", []):
        if not row["detected"]:
            _fail(
                "BM_REFUSED_CANARY_NOT_DETECTED",
                f"the canary {row['id']!r} did not violate {row['targetInvariant']}",
            )


def validate_refinement(
    record: Mapping[str, Any], differential_record: Mapping[str, Any]
) -> None:
    statuses = {
        "MODEL_AND_MATCHED",
        "MODEL_ONLY",
        "NOT_MATCHED",
        "NOT_MODELLED",
    }
    rows = {row["id"]: row for row in record.get("invariants", [])}
    if set(rows) != set(INVARIANT_IDS):
        _fail(
            "BM_REFUSED_REFINEMENT_UNSTATED",
            "the refinement record does not state a status for every modelled invariant",
        )
    for identifier, row in rows.items():
        if row.get("status") not in statuses:
            _fail(
                "BM_REFUSED_REFINEMENT_UNSTATED",
                f"{identifier} has status {row.get('status')!r}",
            )
        if row["status"] == "MODEL_AND_MATCHED":
            executed = [
                item
                for item in differential_record["rows"]
                if item["outcome"] == "AGREED"
                and any(
                    operation in INVARIANT_BY_ID[identifier]["operations"]
                    for operation in item["sequence"]
                )
            ]
            if not executed:
                _fail(
                    "BM_REFUSED_NOT_RUN_AS_VERIFIED",
                    f"{identifier} is MODEL_AND_MATCHED with no agreed sequence",
                )
        if row["status"] == "MODEL_ONLY" and not row.get("notRun"):
            _fail(
                "BM_REFUSED_NOT_RUN_AS_VERIFIED",
                f"{identifier} is MODEL_ONLY but names no NOT_RUN sequence",
            )
    for gap in record.get("gaps", []):
        for field in ("id", "gap", "assumption", "source", "consequence"):
            if not gap.get(field):
                _fail(
                    "BM_REFUSED_REFINEMENT_UNSTATED",
                    f"gap {gap.get('id')!r} has no {field!r}",
                )
    for row in record.get("notRun", []):
        if not row.get("reason"):
            _fail(
                "BM_REFUSED_REFINEMENT_UNSTATED",
                f"NOT_RUN {row.get('id')!r} states no reason",
            )


def assert_differential(record: Mapping[str, Any]) -> None:
    if int(record.get("disagreementCount", 0)) != 0:
        first = record["disagreements"][0]
        _fail(
            "BM_REFUSED_DIFFERENTIAL_DISAGREEMENT",
            f"{record['disagreementCount']} disagreement(s); first is {first['id']} on "
            f"{first['sequence']}: model {first['model']['accepted']} vs implementation "
            f"{first['implementation']['accepted']}",
        )
    for row in record.get("rows", []):
        if row.get("outcome") == "NOT_RUN" and not row.get("reason"):
            _fail(
                "BM_REFUSED_NOT_RUN_AS_VERIFIED",
                f"the NOT_RUN row {row.get('id')!r} states no reason",
            )


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


def model_record() -> dict[str, Any]:
    authority = authority_clauses()
    invariants_for_clause: dict[str, list[str]] = {clause: [] for clause in authority}
    for invariant in INVARIANTS:
        invariants_for_clause[invariant["clause"]].append(invariant["id"])
    modelled = {item["clause"] for item in INVARIANTS}
    clauses = []
    for index, clause in enumerate(authority, 1):
        identifier = f"BM-C{index}"
        if clause in modelled:
            clauses.append(
                {
                    "id": identifier,
                    "clause": clause,
                    "modelled": True,
                    "invariants": invariants_for_clause[clause],
                }
            )
        else:
            reason = next(
                (row["reason"] for row in UNMODELLED_CLAUSES if row["clause"] == clause),
                "the model does not express this clause",
            )
            clauses.append(
                {
                    "id": identifier,
                    "clause": clause,
                    "modelled": False,
                    "invariants": [],
                    "reason": reason,
                }
            )
    record: dict[str, Any] = {
        "schema": SCHEMA_MODEL,
        "item": (
            "B7 of docs/ETP-TODO.md: the transparency-policy invariants of "
            "docs/ETP-ADDENDUM-B.md section B.23, checked in a small model"
        ),
        "authority": "docs/ETP-ADDENDUM-B.md section B.23",
        "document": "docs/TRANSPARENCY-FORMAL-ASSURANCE.md",
        "tool": TOOL_PATH,
        "bound": BOUND,
        "alphabet": list(OPERATIONS),
        "alphabetSize": ALPHABET_SIZE,
        "sequenceSpace": sequence_space(BOUND),
        "operations": list(OPERATIONS),
        "stateFields": list(STATE_FIELDS),
        "state": STATE_DESCRIPTION,
        "initialState": {
            "origin": ORIGIN,
            "leaves": [INITIAL_LEAF],
            "version": 1,
            "verdict": VERDICT_ACTIVE,
        },
        "invariants": [dict(item) for item in INVARIANTS],
        "clauses": clauses,
        "assumptions": [dict(item) for item in ASSUMPTIONS],
        "checker": {
            "function": "check",
            "result": "0 violations on every reachable state of the unbroken model",
            "canaries": {fault: meta["invariant"] for fault, meta in CANARIES.items()},
        },
    }
    record["digest"] = record_digest(record)
    return record


def controls() -> list[dict[str, Any]]:
    """One control per refusal code, each proving the check can fail."""
    rows: list[dict[str, Any]] = []

    # 1. INVARIANT_VIOLATED: a broken model the checker catches.
    broken = enumerate_model(BOUND, fault="rollback-accepted")
    observed = None
    try:
        validate_enumeration(broken, model_record(), run_canaries(BOUND))
    except Refusal as refusal:
        observed = refusal.code
    rows.append({
        "id": "rollback-accepted-invariant-violated",
        "controlOnly": True,
        "expectedCode": "BM_REFUSED_INVARIANT_VIOLATED",
        "observedCode": observed,
        "detail": f"the broken model reached {broken['violationCount']} violation(s)",
    })

    # 2. MODEL_INCOMPLETE: a model record that drops an operation.
    incomplete = model_record()
    incomplete["alphabet"] = incomplete["alphabet"][:-1]
    observed = None
    try:
        validate_model(incomplete)
    except Refusal as refusal:
        observed = refusal.code
    rows.append({
        "id": "alphabet-short",
        "controlOnly": True,
        "expectedCode": "BM_REFUSED_MODEL_INCOMPLETE",
        "observedCode": observed,
        "detail": "the alphabet omits witness_alias",
    })

    # 3. INVARIANT_UNSOURCED: a clause that B.23 does not state.
    unsourced = model_record()
    unsourced["invariants"][0]["clause"] = "a checkpoint is always accepted;"
    observed = None
    try:
        validate_model(unsourced)
    except Refusal as refusal:
        observed = refusal.code
    rows.append({
        "id": "fabricated-clause",
        "controlOnly": True,
        "expectedCode": "BM_REFUSED_INVARIANT_UNSOURCED",
        "observedCode": observed,
        "detail": "BM-I1's clause is replaced by a sentence B.23 does not contain",
    })

    # 4. ENUMERATION_TRUNCATED: a limit below the declared bound.
    observed = None
    try:
        enumerate_model(BOUND, limit=BOUND - 1)
    except Refusal as refusal:
        observed = refusal.code
    rows.append({
        "id": "limit-below-bound",
        "controlOnly": True,
        "expectedCode": "BM_REFUSED_ENUMERATION_TRUNCATED",
        "observedCode": observed,
        "detail": f"a limit of {BOUND - 1} stops below bound {BOUND}",
    })

    # 5. CANARY_NOT_DETECTED: a broken model with its fault removed.
    missed = run_canaries(BOUND)
    for row in missed["canaries"]:
        row["detected"] = False
    missed["allDetected"] = False
    observed = None
    try:
        validate_enumeration(enumerate_model(BOUND), model_record(), missed)
    except Refusal as refusal:
        observed = refusal.code
    rows.append({
        "id": "canary-not-detected",
        "controlOnly": True,
        "expectedCode": "BM_REFUSED_CANARY_NOT_DETECTED",
        "observedCode": observed,
        "detail": "every canary row is rewritten to detected = false",
    })

    # 6. REFINEMENT_UNSTATED: a gap with no source.
    unstated = build_refinement(enumerate_model(BOUND), differential())
    unstated["gaps"][0]["source"] = ""
    observed = None
    try:
        validate_refinement(unstated, differential())
    except Refusal as refusal:
        observed = refusal.code
    rows.append({
        "id": "gap-without-source",
        "controlOnly": True,
        "expectedCode": "BM_REFUSED_REFINEMENT_UNSTATED",
        "observedCode": observed,
        "detail": "BM-G1's source is erased",
    })

    # 7. DIFFERENTIAL_DISAGREEMENT: a driver whose accept vector differs.
    sequence = ["issue_checkpoint", "observe_head"]
    model = run_model(sequence)
    implementation = {"accepted": [not value for value in model["accepted"]],
                      "codes": [], "state": model["state"]}
    tampered = {
        "schema": "openssl-rs/b7/differential/1",
        "disagreementCount": 1,
        "disagreements": [
            {"id": "S000", "sequence": sequence, "model": model,
             "implementation": implementation}
        ],
        "rows": [{"id": "S000", "sequence": sequence, "outcome": "DISAGREED",
                  "model": model, "implementation": implementation}],
    }
    observed = None
    try:
        assert_differential(tampered)
    except Refusal as refusal:
        observed = refusal.code
    rows.append({
        "id": "driver-differs",
        "controlOnly": True,
        "expectedCode": "BM_REFUSED_DIFFERENTIAL_DISAGREEMENT",
        "observedCode": observed,
        "detail": "one implementation accept vector is inverted",
    })

    # 8. NOT_RUN_AS_VERIFIED: a matched status with only NOT_RUN rows.
    forced = differential(
        [["issue_checkpoint", "observe_head"]],
        force_not_run={0: "no admitted log service in this venue"},
    )
    unbacked = build_refinement(enumerate_model(BOUND), differential())
    observed = None
    try:
        validate_refinement(unbacked, forced)
    except Refusal as refusal:
        observed = refusal.code
    rows.append({
        "id": "not-run-counted",
        "controlOnly": True,
        "expectedCode": "BM_REFUSED_NOT_RUN_AS_VERIFIED",
        "observedCode": observed,
        "detail": "the differential's only row is NOT_RUN, so no matched status has a run behind it",
    })

    rows.append({
        "id": "not-run-labelled",
        "controlOnly": True,
        "expectedCode": "BM_OK",
        "observedCode": (
            "BM_OK"
            if forced["notRunCount"] == 1 and forced["compared"] == 0
            and forced["notRun"][0]["reason"]
            else "UNLABELLED"
        ),
        "detail": "a forced NOT_RUN row carries its reason and is excluded from compared",
    })

    # 9. USAGE: a bound above the declared maximum.
    observed = None
    try:
        enumerate_model(MAX_BOUND + 1)
    except Refusal as refusal:
        observed = refusal.code
    rows.append({
        "id": "bound-above-maximum",
        "controlOnly": True,
        "expectedCode": "BM_REFUSED_USAGE",
        "observedCode": observed,
        "detail": f"a bound of {MAX_BOUND + 1} exceeds the declared maximum {MAX_BOUND}",
    })
    return rows


def assert_controls(rows: Sequence[Mapping[str, Any]]) -> None:
    covered = {row["expectedCode"] for row in rows}
    if not set(REFUSAL_CODES).issubset(covered):
        missing = sorted(set(REFUSAL_CODES) - covered)
        _fail("BM_REFUSED_MODEL_INCOMPLETE", f"these codes lack a control: {missing}")
    for row in rows:
        if not row.get("controlOnly"):
            _fail("BM_REFUSED_MODEL_INCOMPLETE", f"{row['id']} is not controlOnly")
        if row["observedCode"] != row["expectedCode"]:
            _fail(
                "BM_REFUSED_MODEL_INCOMPLETE",
                f"{row['id']} observed {row['observedCode']}, expected "
                f"{row['expectedCode']}",
            )


def controls_record() -> dict[str, Any]:
    rows = controls()
    return {
        "schema": SCHEMA_CONTROLS,
        "code": CODE_OK,
        "controls": rows,
        "codesCovered": sorted({row["expectedCode"] for row in rows}),
        "coversEveryCode": set(REFUSAL_CODES).issubset(
            {row["expectedCode"] for row in rows}
        ),
    }


# ---------------------------------------------------------------------------
# Printing and command line
# ---------------------------------------------------------------------------


def _print_summary(**fields: Any) -> None:
    print(" ".join(f"{key}={value}" for key, value in fields.items()))


def _command_model(_: argparse.Namespace) -> int:
    try:
        record = json.loads(MODEL_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        _fail("BM_REFUSED_MODEL_INCOMPLETE", f"the model record is unreadable: {error}")
    validate_model(record)
    _print_summary(
        code=CODE_OK,
        model=record["schema"],
        invariants=len(record["invariants"]),
        clauses=len(record["clauses"]),
        bound=record["bound"],
        alphabet=record["alphabetSize"],
    )
    return EXIT_OK


def _command_enumerate(args: argparse.Namespace) -> int:
    enumeration = enumerate_model(args.bound)
    canaries = run_canaries(args.bound)
    validate_enumeration(enumeration, model_record(), canaries)
    for row in enumeration["invariants"]:
        print(
            f"bm: invariant {row['id']} checked={row['checked']} "
            f"violations={row['violations']}"
        )
    for row in canaries["canaries"]:
        print(
            f"bm: canary {row['id']} target={row['targetInvariant']} "
            f"violations={row['targetViolations']} detected={str(row['detected']).lower()}"
        )
    _print_summary(
        code=CODE_OK,
        bound=enumeration["bound"],
        sequences=enumeration["sequences"],
        states=enumeration["statesReached"],
        transitions=enumeration["transitionsExplored"],
        violations=enumeration["violationCount"],
        canaries=len(canaries["canaries"]),
        allDetected=str(canaries["allDetected"]).lower(),
    )
    return EXIT_OK


def _command_differential(args: argparse.Namespace) -> int:
    record = differential()
    assert_differential(record)
    _print_summary(
        code=CODE_OK,
        sequences=record["sequences"],
        compared=record["compared"],
        agreed=record["agreed"],
        disagreements=record["disagreementCount"],
        notRun=record["notRunCount"],
    )
    return EXIT_OK


def _command_refinement(args: argparse.Namespace) -> int:
    record = build_refinement(enumerate_model(args.bound), differential())
    validate_refinement(record, differential())
    for row in record["invariants"]:
        print(f"bm: refinement {row['id']} status={row['status']}")
    _print_summary(code=CODE_OK, gaps=len(record["gaps"]),
                   notRun=len(record["notRun"]))
    return EXIT_OK


def _command_controls(_: argparse.Namespace) -> int:
    record = controls_record()
    assert_controls(record["controls"])
    for row in record["controls"]:
        print(
            f"bm: control {row['id']} expected={row['expectedCode']} "
            f"observed={row['observedCode']}"
        )
    _print_summary(code=CODE_OK, controls=len(record["controls"]),
                   codes=len(record["codesCovered"]))
    return EXIT_OK


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="transparency_model.py",
        description="Check the B.23 transparency invariants in a small model.",
    )
    parser.add_argument("--bound", type=int, default=BOUND,
                        help=f"sequence bound (default {BOUND}, maximum {MAX_BOUND})")
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("model", help="validate and print the model record")
    subparsers.add_parser("enumerate", help="enumerate and check the reachable states")
    subparsers.add_parser("differential", help="drive the model and the real modules")
    subparsers.add_parser("refinement", help="print the refinement record")
    subparsers.add_parser("controls", help="run one control per refusal code")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    arguments = parser.parse_args(list(argv) if argv is not None else sys.argv[1:])
    if arguments.command is None:
        _print_summary(code=CODE_USAGE, usage="model|enumerate|differential|refinement|controls")
        return EXIT_USAGE
    handlers = {
        "model": _command_model,
        "enumerate": _command_enumerate,
        "differential": _command_differential,
        "refinement": _command_refinement,
        "controls": _command_controls,
    }
    try:
        return handlers[arguments.command](arguments)
    except Refusal as refusal:
        _print_summary(code=refusal.code, detail=refusal.message)
        return EXIT_REFUSED
    except ToolError as error:
        _print_summary(code=CODE_USAGE, detail=str(error))
        return EXIT_USAGE


if __name__ == "__main__":
    raise SystemExit(main())
