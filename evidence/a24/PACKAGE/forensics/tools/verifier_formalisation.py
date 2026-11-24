#!/usr/bin/env python3
"""verifier_formalisation.py -- write the verifier's rules down, then measure the gap.

Why this tool exists
--------------------
A specification written by reading the implementation cannot find an implementation
defect: it inherits whatever the code does, including the defect.  A specification
that *restates* the code is therefore worthless as a check (Earned Trust Article 6),
and a finite enumeration of test vectors is not a theorem about the rule (Article 7).
This tool does the honest middle thing, and states its two limits:

  1. the rules are written first, in ``evidence/a23/SPEC.json`` and
     ``docs/VERIFIER-FORMALISATION.md``, in terms a reader can implement without
     seeing the module;
  2. an **independent reference evaluator** is implemented from that text -- it
     does not import the implementation, and a structural test refuses it if it
     ever does;
  3. the relation between reference and implementation is established by
     **exhaustive enumeration over a stated finite domain** plus invariants;
  4. a disagreement is a **counterexample**, reported with both outputs and the
     rule it violates, and it exits non-zero.  The specification is never edited
     to match the implementation.

What the enumeration does and does not establish
------------------------------------------------
The decision function over an n-obligation policy has exactly ``4**n`` input
states, so for the real eight-obligation policy ``4**8 = 65,536`` vectors is the
*whole* input space of that function, and the differential over it is exhaustive
for that function -- not a sample.  It is still not a theorem: the enumeration is
finite, it covers a decision function and not the tool that produces states from
records, and the reference shares an author with the implementation, so agreement
is evidence of a shared reading, not independent verification (Article 5).  The
threshold and correction domains are *declared finite models*, smaller than their
implementations' inputs; their sizes are stated and their limits recorded.

Reference independence
----------------------
``reference_decide``, ``reference_threshold_count`` and
``reference_chain_admissible`` read ``SPEC.json`` but never import
``policy_engine``, ``thresholds`` or ``corrections``.  The implementation adapters
import those modules *inside* the adapter functions, so the reference functions'
``__globals__`` never contain an implementation name.
``assert_reference_independent`` checks both the globals and the source text, and
the control suite proves the check fires.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib
import inspect
import itertools
import json
import sys
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Mapping, Sequence

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS_DIR = REPO_ROOT / "forensics" / "tools"
TOOL_PATH = "forensics/tools/verifier_formalisation.py"
SPEC_PATH = REPO_ROOT / "evidence/a23/SPEC.json"
SYNTHETIC_POLICY_PATH = "evidence/a23/SYNTHETIC-POLICY.json"

SCHEMA_SPEC = "openssl-rs/a23/verifier-formalisation-spec/1"
SCHEMA_DIFFERENTIAL = "openssl-rs/a23/differential/1"
SCHEMA_PROPERTIES = "openssl-rs/a23/properties/1"
SCHEMA_CONTROLS = "openssl-rs/a23/controls/1"

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_USAGE = 2
CODE_OK = "VF_OK"
CODE_USAGE = "VF_USAGE"

STATES = ("MET", "UNMET", "UNKNOWN", "NOT_APPLICABLE")
STATE_MET = "MET"
STATE_UNKNOWN = "UNKNOWN"
STATE_NOT_APPLICABLE = "NOT_APPLICABLE"
DECISIONS = ("ADMIT", "DENY")
DECISION_ADMIT = "ADMIT"
DECISION_DENY = "DENY"

# Threshold model constants.  They are declared here and restated in SPEC.json;
# the test suite refuses a drift between the two.
THRESHOLD_REQUIRED_ROLES = ("release_authority", "adjudicator")
THRESHOLD_ARTEFACT_DIGEST = "a" * 64
THRESHOLD_MOMENT = "2026-11-15"
THRESHOLD_APPROVED_FRESH = "2026-11-01"
THRESHOLD_EXPIRES_FRESH = "2026-12-01"
THRESHOLD_EXPIRES_STALE = "2026-11-10"
THRESHOLD_DECLARED_AT = "2026-01-01"

# Correction model constants.
CHAIN_SUBJECTS = ("S1", "S2")

# ---------------------------------------------------------------------------
# Refusal codes.  Each names the wrong conclusion it prevents.  The document
# (docs/VERIFIER-FORMALISATION.md) must name every code here, and the test suite
# refuses a code that appears in one and not the other.
# ---------------------------------------------------------------------------

REFUSALS: dict[str, dict[str, str]] = {
    "VF_REFUSED_DISAGREEMENT": {
        "condition": "for some input in an enumerated domain the implementation and "
                     "the reference evaluator return different decisions",
        "prevents": "that a divergence between the written rule and the code is "
                    "reported as agreement, or silently repaired by editing the rule",
    },
    "VF_REFUSED_DOMAIN_INCOMPLETE": {
        "condition": "a claimed domain size is not the full 4**n state space of an "
                     "n-obligation decision function",
        "prevents": "that a partial enumeration is presented as exhaustive",
    },
    "VF_REFUSED_REFERENCE_IMPORTS_IMPLEMENTATION": {
        "condition": "a function declared to be the independent reference resolves an "
                     "implementation module (policy_engine, thresholds, corrections) "
                     "through its globals or its source",
        "prevents": "that the reference is the implementation by another name and the "
                    "agreement it reports is a restatement",
    },
    "VF_REFUSED_PROPERTY_VIOLATED": {
        "condition": "a stated invariant (determinism, monotonicity, UNKNOWN never "
                     "admits, canonical-order independence, no numeric score) fails on "
                     "some input in its stated domain",
        "prevents": "that an invariant is asserted from inspection while a "
                    "counterexample exists in the enumerated domain",
    },
    "VF_REFUSED_SPEC_ABSENT": {
        "condition": "the specification record is absent, unreadable, not of the "
                     "declared schema, or its recorded digest does not match its bytes",
        "prevents": "that a missing or edited specification is still treated as the "
                    "rule the reference implements",
    },
    "VF_REFUSED_UNSPECIFIED_RULE": {
        "condition": "an input lies outside the specification (an unknown obligation "
                     "state, a vector whose length differs from the required set, an "
                     "unknown chain event kind)",
        "prevents": "that an input the rule does not decide is given a decision by "
                    "accident, and that an unknown state reads as a known one",
    },
    "VF_REFUSED_ENUMERATION_TRUNCATED": {
        "condition": "the enumeration was bounded below the declared size, so fewer "
                     "vectors would be compared than the domain contains",
        "prevents": "that a truncated run is reported with the declared domain size",
    },
}
REFUSAL_CODES = tuple(REFUSALS)


class ToolError(Exception):
    """A usage error, reported with exit status 2."""


class Refusal(Exception):
    """A refusal, reported with exit status 1 and a stable code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


def _refuse(code: str, message: str) -> None:
    if code not in REFUSALS:
        raise ToolError(f"unknown refusal code {code!r}")
    raise Refusal(code, message)


# ---------------------------------------------------------------------------
# Canonical form, digests and the specification record
# ---------------------------------------------------------------------------
def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def spec_body(spec: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in spec.items() if key != "digest"}


def spec_digest(spec: Mapping[str, Any]) -> str:
    return digest(spec_body(spec))


_SPEC_CACHE: dict[Path, dict[str, Any]] = {}


def load_spec(path: Path | str | None = None) -> dict[str, Any]:
    """Read and verify the specification record.  Absence is a refusal, not a default."""
    key = Path(SPEC_PATH if path is None else path)
    if key in _SPEC_CACHE:
        return _SPEC_CACHE[key]
    try:
        raw = key.read_bytes()
    except OSError as error:
        _refuse("VF_REFUSED_SPEC_ABSENT", f"the specification {key} is unreadable: {error}")
    try:
        spec = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        _refuse("VF_REFUSED_SPEC_ABSENT", f"the specification {key} is not JSON: {error}")
    if not isinstance(spec, Mapping) or spec.get("schema") != SCHEMA_SPEC:
        _refuse("VF_REFUSED_SPEC_ABSENT", f"the specification {key} is not {SCHEMA_SPEC!r}")
    if not isinstance(spec.get("rules"), list) or not spec["rules"]:
        _refuse("VF_REFUSED_SPEC_ABSENT", f"the specification {key} declares no rules")
    if not isinstance(spec.get("decision"), Mapping):
        _refuse("VF_REFUSED_SPEC_ABSENT", f"the specification {key} declares no decision")
    if spec.get("digest") != spec_digest(spec):
        _refuse("VF_REFUSED_SPEC_ABSENT", f"the specification {key} does not match its digest")
    _SPEC_CACHE[key] = dict(spec)
    return _SPEC_CACHE[key]


def rule_ids(spec: Mapping[str, Any] | None = None) -> list[str]:
    document = spec if spec is not None else load_spec()
    return [rule["id"] for rule in document["rules"]]


# ---------------------------------------------------------------------------
# The reference evaluators.  No implementation module appears in these
# functions' globals; the adapters import lazily, below.
# ---------------------------------------------------------------------------
def reference_decide(
    states: Sequence[str],
    required: Sequence[bool],
    *,
    spec: Mapping[str, Any] | None = None,
) -> str:
    """The decision rule, implemented from the document and SPEC.json.

    Rule VF-R1: the state vocabulary is closed.  Rule VF-R2: ADMIT iff the
    required set is non-empty and every required obligation is MET.  Rule VF-R3:
    UNKNOWN is a refusal whether or not the obligation is required -- an
    unevaluated obligation is a machinery defect, never a MET and never a
    NOT_APPLICABLE.  Rule VF-R5: with no required obligation nothing is admitted.
    """
    document = spec if spec is not None else load_spec()
    vocabulary = tuple(document["states"])
    decision = document["decision"]
    if len(states) != len(required):
        _refuse(
            "VF_REFUSED_UNSPECIFIED_RULE",
            f"the state vector has {len(states)} entries and the required set {len(required)}",
        )
    for index, state in enumerate(states):
        if state not in vocabulary:
            _refuse(
                "VF_REFUSED_UNSPECIFIED_RULE",
                f"obligation {index} has state {state!r}, which the specification does not name",
            )
    if decision["unknown"] in states:
        return decision["deny"]
    required_indices = [index for index, flag in enumerate(required) if bool(flag)]
    if len(required_indices) < int(decision["minimumRequired"]):
        return decision["deny"]
    satisfies = decision["satisfies"]
    for index in required_indices:
        if states[index] != satisfies:
            return decision["deny"]
    return decision["admit"]


def reference_threshold_count(
    approvals: Sequence[Mapping[str, Any]],
    inventory: Mapping[str, Any],
    *,
    required_roles: Sequence[str] = THRESHOLD_REQUIRED_ROLES,
    artefact_digest: str = THRESHOLD_ARTEFACT_DIGEST,
) -> int:
    """The count over distinct established domains, from rule VF-R8.

    An approval counts only if it is verified, its role is required, it is fresh
    and it names the current artefact.  Its domain must be established by a
    record and must not be the candidate's.  Two labels whose domain records
    share the establishment record ``(path, sha256)`` are one domain.  A
    duplicate approval on a counted domain adds nothing, and one identity
    contributes at most one domain: a later approval by the same identity in a
    different domain is dropped.
    """
    domains = inventory.get("domains") if isinstance(inventory, Mapping) else None
    if not isinstance(domains, Mapping):
        _refuse("VF_REFUSED_UNSPECIFIED_RULE", "the inventory has no domains mapping")
    counted: list[tuple[str, str]] = []
    established: dict[Any, tuple[str, str]] = {}
    for approval in approvals:
        if not isinstance(approval, Mapping):
            _refuse("VF_REFUSED_UNSPECIFIED_RULE", "an approval is not an object")
        if approval.get("verified") is not True:
            continue
        if approval.get("role") not in tuple(required_roles):
            continue
        if approval.get("fresh") is not True:
            continue
        if approval.get("digest") != artefact_digest:
            continue
        domain = domains.get(approval.get("domain"))
        if not isinstance(domain, Mapping):
            continue
        establishment = domain.get("establishment")
        if establishment is None:
            continue
        if domain.get("candidate") is True:
            continue
        key = tuple(establishment)
        if len(key) != 2 or not all(isinstance(part, str) for part in key):
            _refuse("VF_REFUSED_UNSPECIFIED_RULE", "an establishment is not (path, sha256)")
        identity = approval.get("identity")
        previous = established.get(identity)
        if previous is not None and previous != key:
            continue
        established.setdefault(identity, key)
        if key not in counted:
            counted.append(key)
    return len(counted)


def reference_chain_admissible(chain: Sequence[Mapping[str, Any]]) -> tuple[bool, str | None]:
    """Chain admissibility from rule VF-R9.

    Returns ``(admissible, violated_rule)``.  The model is the specification's:
    ``kind`` is ``assert`` or ``correct``; ``predecessor`` is an index into the
    chain or ``None``; ``link`` is ``intact`` or ``bad``; ``original`` is
    ``preserved`` or ``modified``.
    """
    by_index = {index: event for index, event in enumerate(chain)}
    roots: dict[str, int] = {}
    successors: dict[int, int] = {}
    for index, event in enumerate(chain):
        if not isinstance(event, Mapping):
            _refuse("VF_REFUSED_UNSPECIFIED_RULE", "a chain event is not an object")
        kind = event.get("kind")
        if kind == "assert":
            if event.get("predecessor") is not None:
                return False, "VF-C8"
            subject = event.get("subject")
            roots[subject] = roots.get(subject, 0) + 1
            continue
        if kind != "correct":
            _refuse("VF_REFUSED_UNSPECIFIED_RULE", f"unknown chain event kind {kind!r}")
        predecessor = event.get("predecessor")
        if predecessor is None or predecessor not in by_index:
            return False, "VF-C1"
        if predecessor >= index:
            return False, "VF-C4"
        if by_index[predecessor].get("subject") != event.get("subject"):
            return False, "VF-C5"
        if event.get("link") != "intact":
            return False, "VF-C2"
        if event.get("original") != "preserved":
            return False, "VF-C7"
        successors[predecessor] = successors.get(predecessor, 0) + 1
    if any(count > 1 for count in roots.values()):
        return False, "VF-C6"
    if any(count > 1 for count in successors.values()):
        return False, "VF-C3"
    return True, None


# ---------------------------------------------------------------------------
# Implementation adapters.  The implementations are imported *here*, so the
# reference functions above never see them.
# ---------------------------------------------------------------------------
_POLICY_CACHE: dict[tuple[int, tuple[bool, ...]], tuple[dict, dict, dict]] = {}


def _implementation(name: str) -> Any:
    if name not in ("policy_engine", "thresholds", "corrections"):
        raise ToolError(f"unknown implementation {name!r}")
    if str(TOOLS_DIR) not in sys.path:
        sys.path.insert(0, str(TOOLS_DIR))
    return importlib.import_module(name)


def _synthetic_policy(
    size: int, required: tuple[bool, ...]
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """A well-formed policy whose obligations can be driven to any of the four states.

    The obligation shape is the engine's own: an object member, a predicate that
    is true iff ``/s`` is ``MET``, and an applicability condition on ``na``.  The
    optional states are reached by serving ``{"s": "OTHER"}`` (UNMET),
    ``{"s": "MET", "na": false}`` (NOT_APPLICABLE), or no record at all
    (UNKNOWN).  The decision function sees only the resulting state vector.
    """
    key = (size, tuple(bool(flag) for flag in required))
    if key in _POLICY_CACHE:
        return copy.deepcopy(_POLICY_CACHE[key])
    engine = _implementation("policy_engine")
    obligations = []
    for index in range(size):
        obligations.append(
            {
                "id": f"O{index:02d}",
                "description": "a synthetic obligation for the A23 state-space enumeration",
                "required": bool(required[index]),
                "source": {
                    "tool": TOOL_PATH,
                    "record": f"vf/obligation-{index:02d}.json",
                    "locator": "",
                },
                "predicate": {"op": "eq", "path": "/s", "value": "MET"},
                "applicableWhen": [{"field": "na", "op": "eq", "value": True}],
            }
        )
    policy = {
        "schema": engine.POLICY_SCHEMA,
        "policyId": "verifier-formalisation-synthetic",
        "version": 1,
        "default": "deny",
        "scores": False,
        "obligations": obligations,
        "provenance": {
            "establishedBy": {"role": "maintainer", "identity": "P-VF-ESTABLISHER"},
            "recordedAt": "2026-11-24",
            "independentOfCandidate": False,
        },
    }
    policy["digest"] = engine.policy_digest(policy)
    pin = {
        "schema": engine.PIN_SCHEMA,
        "policyId": policy["policyId"],
        "policyDigest": policy["digest"],
        "policyPath": SYNTHETIC_POLICY_PATH,
        "pinnedAt": "2026-11-24",
        "pinnedBy": {"role": "maintainer", "identity": "P-VF-PINNER"},
        "candidate": {"commit": "0000000", "producedBy": "P-VF-PRODUCER"},
    }
    candidate = {"commit": "0000000", "producedBy": {"identity": "P-VF-PRODUCER"}}
    _POLICY_CACHE[key] = (policy, pin, candidate)
    return copy.deepcopy((policy, pin, candidate))


def _records_for(states: Sequence[str]) -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    for index, state in enumerate(states):
        name = f"vf/obligation-{index:02d}.json"
        if state == "MET":
            records[name] = {"s": "MET", "na": True}
        elif state == "UNMET":
            records[name] = {"s": "OTHER", "na": True}
        elif state == "NOT_APPLICABLE":
            records[name] = {"s": "MET", "na": False}
        elif state == "UNKNOWN":
            continue
        else:
            _refuse("VF_REFUSED_UNSPECIFIED_RULE", f"cannot materialise state {state!r}")
    return records


def implementation_decide(states: Sequence[str], required: Sequence[bool]) -> str:
    """Run the real policy engine over records that produce the requested states."""
    engine = _implementation("policy_engine")
    policy, pin, candidate = _synthetic_policy(len(states), tuple(required))
    records = _records_for(states)

    def reader(relative: str) -> tuple[bytes | None, str | None]:
        if relative not in records:
            return None, f"{relative!r} is absent"
        return canonical(records[relative]).encode("utf-8"), None

    decision = engine.evaluate(
        policy,
        pin,
        candidate,
        reader=reader,
        root=REPO_ROOT,
        action="release",
        policy_path=SYNTHETIC_POLICY_PATH,
        runs=1,
    )
    return decision["decision"]


def _threshold_documents(
    approvals: Sequence[Mapping[str, Any]],
    inventory: Mapping[str, Any],
    k: int,
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    """Materialise the abstract approval model as the A15 documents."""
    domains: list[dict[str, Any]] = []
    for label, domain in inventory["domains"].items():
        establishment = domain.get("establishment")
        domains.append(
            {
                "domainId": label,
                "kind": "candidate" if domain.get("candidate") else "external",
                "establishedBy": (
                    {"path": establishment[0], "sha256": establishment[1]}
                    if establishment is not None
                    else {}
                ),
                "independentOfCandidate": not bool(domain.get("candidate")),
            }
        )
    domains_document = {"candidateDomain": "openssl-rs", "domains": domains}
    materialised = []
    identities = sorted({item["identity"] for item in approvals})
    for approval in approvals:
        materialised.append(
            {
                "identity": approval["identity"],
                "domainId": approval["domain"],
                "role": approval["role"],
                "signature": {"verified": bool(approval["verified"]), "basis": "control-only"},
                "artefactDigest": approval["digest"],
                "approvedAt": THRESHOLD_APPROVED_FRESH,
                "expiresAt": (
                    THRESHOLD_EXPIRES_FRESH if approval["fresh"] else THRESHOLD_EXPIRES_STALE
                ),
            }
        )
    assignments = []
    for identity in identities:
        for role in THRESHOLD_REQUIRED_ROLES:
            assignments.append(
                {
                    "identity": identity,
                    "party": f"P-VF-{identity}",
                    "role": role,
                    "scope": ["*"],
                    "grantedAt": "2026-01-01",
                    "evidence": "control-only:a23",
                }
            )
        assignments.append(
            {
                "identity": identity,
                "party": f"P-VF-{identity}",
                "role": "auditor",
                "scope": ["*"],
                "grantedAt": "2026-01-01",
                "evidence": "control-only:a23",
            }
        )
    declaration = {
        "id": "vf:threshold",
        "action": "release",
        "k": k,
        "n": max(4, k),
        "requiredRoles": list(THRESHOLD_REQUIRED_ROLES),
        "distinctDomains": True,
        "declaredAt": THRESHOLD_DECLARED_AT,
        "declaredBy": "control-only:a23",
        "artefactDigest": THRESHOLD_ARTEFACT_DIGEST,
        "asOf": THRESHOLD_MOMENT,
        "scope": ["*"],
        "amendments": [],
    }
    return declaration, domains_document, materialised, assignments


def implementation_threshold_count(
    approvals: Sequence[Mapping[str, Any]], inventory: Mapping[str, Any], *, k: int
) -> int:
    thresholds = _implementation("thresholds")
    declaration, domains_document, materialised, assignments = _threshold_documents(
        approvals, inventory, k
    )
    result = thresholds.evaluate(
        declaration,
        materialised,
        domains_document,
        assignments,
        at=THRESHOLD_MOMENT,
        artefact_digest=THRESHOLD_ARTEFACT_DIGEST,
    )
    return int(result["distinctDomains"])


def _value(tag: str) -> dict[str, Any]:
    return {
        "value": tag,
        "digest": (tag.encode("utf-8").hex() * 64)[:64],
        "citation": tag,
        "record": None,
    }


def _chain_events(chain: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Materialise a chain model as corrections.py events with real digests."""
    corrections = _implementation("corrections")
    events: list[dict[str, Any]] = []
    for index, event in enumerate(chain):
        base = {
            "eventId": f"E{index}",
            "reason": "a23 chain model",
            "recordedAt": "2026-11-24",
            "recordedBy": {"role": "maintainer", "identity": "control-only:a23"},
            "evidence": ["control-only:a23"],
        }
        if event["kind"] == "assert":
            events.append(
                {
                    **base,
                    "kind": "assert",
                    "subject": event["subject"],
                    "supersedes": None,
                    "oldValue": None,
                    "newValue": _value(f"assert-{index}"),
                }
            )
            continue
        events.append(
            {
                **base,
                "kind": "correct",
                "subject": event["subject"],
                "supersedes": {"previousEventId": f"E{event['predecessor']}", "previousDigest": "0" * 64},
                "oldValue": {
                    "value": f"old-{index}",
                    "digest": "0" * 64,
                    "citation": f"old-{index}",
                    "record": None,
                },
                "newValue": _value(f"new-{index}"),
            }
        )
    # The accepted value digest: a correct preserves its predecessor's newValue.
    for index, event in enumerate(chain):
        if event["kind"] != "correct":
            continue
        predecessor = event["predecessor"]
        events[index]["oldValue"]["digest"] = (
            events[predecessor]["newValue"]["digest"]
            if event["original"] == "preserved"
            else "f" * 64
        )
    # The recorded predecessor digest, computed in index order so an earlier
    # predecessor's canonical digest is already final.
    for index, event in enumerate(chain):
        if event["kind"] != "correct":
            continue
        predecessor = event["predecessor"]
        events[index]["supersedes"]["previousDigest"] = (
            corrections.event_digest(events[predecessor]) if event["link"] == "intact" else "0" * 64
        )
    return events


def implementation_chain_admissible(
    chain: Sequence[Mapping[str, Any]]
) -> tuple[bool, str | None]:
    """The chain-binding rules, as ``append`` applies them: check, then extend."""
    corrections = _implementation("corrections")
    events = _chain_events(chain)
    log: dict[str, Any] = {"events": []}
    try:
        for event in events:
            corrections._check_binding(log, event)
            log["events"].append(event)
    except corrections.Refusal as refusal:
        return False, refusal.code
    return True, None


def implementation_chain_revalidate(
    chain: Sequence[Mapping[str, Any]]
) -> tuple[bool, str | None]:
    """Re-validate the last event against the whole log (the cycle defence)."""
    corrections = _implementation("corrections")
    events = _chain_events(chain)
    try:
        corrections._check_binding({"events": events}, events[-1])
    except corrections.Refusal as refusal:
        return False, refusal.code
    return True, None


# ---------------------------------------------------------------------------
# The exhaustive domains
# ---------------------------------------------------------------------------
def domain_size(n: int) -> int:
    """The number of state vectors over n obligations: exactly 4**n."""
    if not isinstance(n, int) or isinstance(n, bool) or n < 0:
        _refuse("VF_REFUSED_UNSPECIFIED_RULE", f"an obligation count is a non-negative integer, not {n!r}")
    return 4**n


def enumerate_domain(n: int, *, limit: int | None = None) -> Iterator[tuple[str, ...]]:
    """Every state vector over n obligations, in canonical (lexicographic) order."""
    size = domain_size(n)
    if limit is not None and limit < size:
        _refuse(
            "VF_REFUSED_ENUMERATION_TRUNCATED",
            f"the enumeration was bounded at {limit} of {size} vectors",
        )
    return itertools.product(STATES, repeat=n)


DECISION_SMALL_OBLIGATIONS = 3
DECISION_POLICY_OBLIGATIONS = 8
THRESHOLD_CATALOGUE_SIZE = 12
THRESHOLD_MAX_APPROVALS = 4


def small_decision_domain_size() -> int:
    """n = 0..3, every state vector and every required mask: 585 vectors."""
    return sum(domain_size(size) * (2**size) for size in range(DECISION_SMALL_OBLIGATIONS + 1))


def policy_decision_domain_size() -> int:
    return domain_size(DECISION_POLICY_OBLIGATIONS)


def _decision_differential(
    size: int,
    masks: Iterable[Sequence[bool]],
    *,
    reference: Callable[..., str] = reference_decide,
    implementation: Callable[..., str] = implementation_decide,
    declared_size: int | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    state_space = domain_size(size)
    mask_list = [tuple(bool(flag) for flag in mask) for mask in masks]
    for mask in mask_list:
        if len(mask) != size:
            _refuse(
                "VF_REFUSED_UNSPECIFIED_RULE",
                f"{size} obligations were enumerated with a mask of {len(mask)}",
            )
    expected = state_space * len(mask_list)
    if declared_size is not None and declared_size != expected:
        _refuse(
            "VF_REFUSED_DOMAIN_INCOMPLETE",
            f"the domain was declared {declared_size} and its full space is {expected}",
        )
    compared = 0
    disagreements: list[dict[str, Any]] = []
    for mask in mask_list:
        for states in enumerate_domain(size, limit=limit):
            compared += 1
            got = implementation(states, mask)
            want = reference(states, mask)
            if got != want:
                disagreements.append(
                    {
                        "rule": "VF-R2",
                        "states": list(states),
                        "required": [bool(flag) for flag in mask],
                        "implementation": got,
                        "reference": want,
                    }
                )
    if compared != expected:
        _refuse(
            "VF_REFUSED_ENUMERATION_TRUNCATED",
            f"{compared} vectors were compared and the domain contains {expected}",
        )
    return {
        "declaredSize": expected,
        "stateSpace": state_space,
        "masks": len(mask_list),
        "compared": compared,
        "disagreements": disagreements,
    }


def differential(
    n: int,
    required: Sequence[bool] | None = None,
    *,
    reference: Callable[..., str] = reference_decide,
    implementation: Callable[..., str] = implementation_decide,
    declared_size: int | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    """The decision differential over all ``4**n`` state vectors.

    When ``required`` is omitted, every required mask is enumerated as well, so
    the compared count is ``4**n * 2**n``.  ``declared_size`` refuses a claim
    that does not equal that full space (``VF_REFUSED_DOMAIN_INCOMPLETE``), and
    ``limit`` refuses a bounded run (``VF_REFUSED_ENUMERATION_TRUNCATED``).
    """
    if required is None:
        masks = [
            tuple(bool(mask >> index & 1) for index in range(n)) for mask in range(2**n)
        ]
    else:
        masks = [tuple(bool(flag) for flag in required)]
    return _decision_differential(
        n,
        masks,
        reference=reference,
        implementation=implementation,
        declared_size=declared_size,
        limit=limit,
    )


def _small_decision_differential(
    *,
    reference: Callable[..., str] = reference_decide,
    implementation: Callable[..., str] = implementation_decide,
    declared_size: int | None = None,
) -> dict[str, Any]:
    expected = small_decision_domain_size()
    if declared_size is not None and declared_size != expected:
        _refuse(
            "VF_REFUSED_DOMAIN_INCOMPLETE",
            f"the small domain was declared {declared_size} and contains {expected}",
        )
    compared = 0
    disagreements: list[dict[str, Any]] = []
    state_space = 0
    masks = 0
    for size in range(DECISION_SMALL_OBLIGATIONS + 1):
        mask_list = [
            tuple(bool(mask >> index & 1) for index in range(size)) for mask in range(2**size)
        ]
        record = _decision_differential(
            size, mask_list, reference=reference, implementation=implementation
        )
        compared += record["compared"]
        disagreements.extend(record["disagreements"])
        state_space += record["stateSpace"]
        masks += record["masks"]
    if compared != expected:
        _refuse(
            "VF_REFUSED_ENUMERATION_TRUNCATED",
            f"{compared} vectors were compared and the small domain contains {expected}",
        )
    return {
        "declaredSize": expected,
        "stateSpace": state_space,
        "masks": masks,
        "compared": compared,
        "disagreements": disagreements,
    }


# ---------------------------------------------------------------------------
# The threshold model: 1,820 multisets of 0..4 approvals over 12 archetypes
# ---------------------------------------------------------------------------
def threshold_catalogue() -> list[dict[str, Any]]:
    """Twelve approval archetypes, including an alias, a duplicate domain and an
    identity reused across domains."""
    digest = THRESHOLD_ARTEFACT_DIGEST
    other = "b" * 64
    return [
        {"identity": "vf:i1", "domain": "vf:d1", "verified": True, "role": "release_authority", "fresh": True, "digest": digest},
        {"identity": "vf:i2", "domain": "vf:d2", "verified": True, "role": "adjudicator", "fresh": True, "digest": digest},
        {"identity": "vf:i3", "domain": "vf:d3", "verified": True, "role": "release_authority", "fresh": True, "digest": digest},
        {"identity": "vf:i4", "domain": "vf:d1", "verified": True, "role": "adjudicator", "fresh": True, "digest": digest},
        {"identity": "vf:i5", "domain": "vf:da", "verified": True, "role": "release_authority", "fresh": True, "digest": digest},
        {"identity": "vf:i6", "domain": "vf:cand", "verified": True, "role": "release_authority", "fresh": True, "digest": digest},
        {"identity": "vf:i7", "domain": "vf:self", "verified": True, "role": "release_authority", "fresh": True, "digest": digest},
        {"identity": "vf:i8", "domain": "vf:d2", "verified": False, "role": "release_authority", "fresh": True, "digest": digest},
        {"identity": "vf:i9", "domain": "vf:d1", "verified": True, "role": "auditor", "fresh": True, "digest": digest},
        {"identity": "vf:i10", "domain": "vf:d2", "verified": True, "role": "adjudicator", "fresh": False, "digest": digest},
        {"identity": "vf:i11", "domain": "vf:d3", "verified": True, "role": "release_authority", "fresh": True, "digest": other},
        {"identity": "vf:i1", "domain": "vf:d2", "verified": True, "role": "adjudicator", "fresh": True, "digest": digest},
    ]


def threshold_inventories() -> list[dict[str, Any]]:
    """Two inventories: three distinct establishments, and a third that is an alias."""
    return [
        {
            "domains": {
                "vf:d1": {"establishment": ("control-only/a23/est/d1.json", "1" * 64), "candidate": False},
                "vf:d2": {"establishment": ("control-only/a23/est/d2.json", "2" * 64), "candidate": False},
                "vf:d3": {"establishment": ("control-only/a23/est/d3.json", "3" * 64), "candidate": False},
                "vf:cand": {"establishment": ("control-only/a23/est/cand.json", "c" * 64), "candidate": True},
                "vf:self": {"establishment": None, "candidate": False},
            }
        },
        {
            "domains": {
                "vf:d1": {"establishment": ("control-only/a23/est/d1.json", "1" * 64), "candidate": False},
                "vf:d2": {"establishment": ("control-only/a23/est/d2.json", "2" * 64), "candidate": False},
                "vf:da": {"establishment": ("control-only/a23/est/d1.json", "1" * 64), "candidate": False},
                "vf:cand": {"establishment": ("control-only/a23/est/cand.json", "c" * 64), "candidate": True},
                "vf:self": {"establishment": None, "candidate": False},
            }
        },
    ]


def _threshold_multisets() -> list[list[dict[str, Any]]]:
    catalogue = threshold_catalogue()
    return [
        [catalogue[index] for index in combination]
        for count in range(THRESHOLD_MAX_APPROVALS + 1)
        for combination in itertools.combinations_with_replacement(
            range(len(catalogue)), count
        )
    ]


def inventory_availability(inventory: Mapping[str, Any]) -> int:
    """The distinct establishments an inventory carries (an alias is not a second)."""
    return len(
        {
            tuple(domain["establishment"])
            for domain in inventory["domains"].values()
            if domain["establishment"] is not None and not domain["candidate"]
        }
    )


def threshold_domain_size() -> int:
    """Multisets of 0..4 over 12 archetypes, against the reachable k of both
    inventories: (3 + 2) * 1,820 = 9,100."""
    multisets = sum(
        len(list(itertools.combinations_with_replacement(range(THRESHOLD_CATALOGUE_SIZE), count)))
        for count in range(THRESHOLD_MAX_APPROVALS + 1)
    )
    reachable = sum(
        min(3, inventory_availability(inventory))
        for inventory in threshold_inventories()
    )
    return multisets * reachable


def _threshold_cases() -> Iterator[tuple[dict[str, Any], int, list[dict[str, Any]]]]:
    multisets = _threshold_multisets()
    for inventory in threshold_inventories():
        for k in range(1, min(3, inventory_availability(inventory)) + 1):
            for approvals in multisets:
                yield inventory, k, approvals


def threshold_differential(
    *,
    reference: Callable[..., int] = reference_threshold_count,
    implementation: Callable[..., int] = implementation_threshold_count,
    declared_size: int | None = None,
) -> dict[str, Any]:
    expected = threshold_domain_size()
    if declared_size is not None and declared_size != expected:
        _refuse(
            "VF_REFUSED_DOMAIN_INCOMPLETE",
            f"the threshold domain was declared {declared_size} and contains {expected}",
        )
    compared = 0
    disagreements: list[dict[str, Any]] = []
    for inventory, k, approvals in _threshold_cases():
        compared += 1
        want = reference(approvals, inventory)
        got = implementation(approvals, inventory, k=k)
        if got != want:
            disagreements.append(
                {
                    "rule": "VF-R8",
                    "k": k,
                    "approvals": approvals,
                    "inventory": sorted(inventory["domains"]),
                    "implementation": got,
                    "reference": want,
                }
            )
    if compared != expected:
        _refuse(
            "VF_REFUSED_ENUMERATION_TRUNCATED",
            f"{compared} threshold cases were compared and the domain contains {expected}",
        )
    return {
        "declaredSize": expected,
        "compared": compared,
        "disagreements": disagreements,
    }


# ---------------------------------------------------------------------------
# The correction-chain model: 383 chains of length 0..3, plus cycle witnesses
# ---------------------------------------------------------------------------
def _chain_options(index: int) -> list[dict[str, Any]]:
    options = [
        {"kind": "assert", "subject": subject, "predecessor": None, "link": None, "original": None}
        for subject in CHAIN_SUBJECTS
    ]
    for subject in CHAIN_SUBJECTS:
        for predecessor in range(index):
            for link in ("intact", "bad"):
                for original in ("preserved", "modified"):
                    options.append(
                        {
                            "kind": "correct",
                            "subject": subject,
                            "predecessor": predecessor,
                            "link": link,
                            "original": original,
                        }
                    )
    return options


def chain_domain_size() -> int:
    """All chains of length 0..3 over two subjects with earlier-only predecessors."""
    total = 1
    for length in range(1, 4):
        product = 1
        for index in range(length):
            product *= len(_chain_options(index))
        total += product
    return total


COUNTEREXAMPLES = {
    "VF-C1": "a correction names a predecessor that is not in the chain",
    "VF-C2": "the recorded predecessor digest is not the predecessor's canonical digest",
    "VF-C3": "one predecessor has two successors (a fork)",
    "VF-C4": "the predecessor chain revisits an event (a cycle) or points forward",
    "VF-C5": "a correction names a predecessor about a different subject",
    "VF-C6": "a subject has more than one root assertion",
    "VF-C7": "a correction's oldValue digest is not the predecessor's accepted value",
    "VF-C8": "an assertion supersedes an event",
}


def _chains() -> Iterator[tuple[str, list[dict[str, Any]]]]:
    yield "empty", []
    for length in range(1, 4):
        for combination in itertools.product(
            *[_chain_options(index) for index in range(length)]
        ):
            yield "chain", list(combination)


def cycle_witnesses() -> list[list[dict[str, Any]]]:
    """Hand-built cycles.  Under the digest rule a cycle is unsatisfiable, so both
    sides refuse it; the observed code is recorded rather than asserted."""
    two_cycle = [
        {"kind": "correct", "subject": "S1", "predecessor": 1, "link": "bad", "original": "preserved"},
        {"kind": "correct", "subject": "S1", "predecessor": 0, "link": "bad", "original": "preserved"},
    ]
    self_loop = [
        {"kind": "correct", "subject": "S1", "predecessor": 0, "link": "bad", "original": "preserved"},
    ]
    three_cycle = [
        {"kind": "correct", "subject": "S1", "predecessor": 2, "link": "bad", "original": "preserved"},
        {"kind": "correct", "subject": "S1", "predecessor": 0, "link": "bad", "original": "preserved"},
        {"kind": "correct", "subject": "S1", "predecessor": 1, "link": "bad", "original": "preserved"},
    ]
    return [two_cycle, self_loop, three_cycle]


def correction_domain_size() -> int:
    return chain_domain_size() + len(cycle_witnesses())


def correction_differential(
    *,
    reference: Callable[..., tuple[bool, str | None]] = reference_chain_admissible,
    implementation: Callable[..., tuple[bool, str | None]] = implementation_chain_admissible,
    declared_size: int | None = None,
) -> dict[str, Any]:
    expected = correction_domain_size()
    if declared_size is not None and declared_size != expected:
        _refuse(
            "VF_REFUSED_DOMAIN_INCOMPLETE",
            f"the correction domain was declared {declared_size} and contains {expected}",
        )
    compared = 0
    disagreements: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    for _kind, chain in _chains():
        compared += 1
        want, want_rule = reference(chain)
        got, got_code = implementation(chain)
        if got != want:
            disagreements.append(
                {
                    "rule": want_rule or "VF-R9",
                    "chain": chain,
                    "implementation": got,
                    "reference": want,
                    "implementationCode": got_code,
                }
            )
    for chain in cycle_witnesses():
        compared += 1
        want, want_rule = reference(chain)
        got, got_code = implementation(chain)
        revalidated, revalidated_code = implementation_chain_revalidate(chain)
        observations.append(
            {
                "chain": chain,
                "reference": want,
                "referenceRule": want_rule,
                "appendPath": got,
                "appendPathCode": got_code,
                "revalidated": revalidated,
                "revalidatedCode": revalidated_code,
            }
        )
        if got != want:
            disagreements.append(
                {
                    "rule": want_rule or "VF-R9",
                    "chain": chain,
                    "implementation": got,
                    "reference": want,
                    "implementationCode": got_code,
                }
            )
    if compared != expected:
        _refuse(
            "VF_REFUSED_ENUMERATION_TRUNCATED",
            f"{compared} chains were compared and the domain contains {expected}",
        )
    return {
        "declaredSize": expected,
        "compared": compared,
        "disagreements": disagreements,
        "observations": observations,
    }


# ---------------------------------------------------------------------------
# Invariants
# ---------------------------------------------------------------------------
def _all_cases(
    size: int, required: Sequence[bool] | None
) -> Iterator[tuple[tuple[str, ...], tuple[bool, ...]]]:
    if required is None:
        masks: Iterable[tuple[bool, ...]] = (
            tuple(bool(mask >> index & 1) for index in range(size))
            for mask in range(2**size)
        )
    else:
        masks = (tuple(bool(flag) for flag in required),)
    for flag_set in masks:
        for states in itertools.product(STATES, repeat=size):
            yield states, flag_set


def _memoised(function: Callable[..., str]) -> Callable[..., str]:
    cache: dict[tuple[tuple[str, ...], tuple[bool, ...]], str] = {}

    def call(states: Sequence[str], required: Sequence[bool]) -> str:
        key = (tuple(states), tuple(bool(flag) for flag in required))
        if key not in cache:
            cache[key] = function(states, required)
        return cache[key]

    return call


def properties(
    size: int = DECISION_SMALL_OBLIGATIONS,
    required: Sequence[bool] | None = None,
    *,
    reference: Callable[..., str] = reference_decide,
    implementation: Callable[..., str] = implementation_decide,
) -> dict[str, Any]:
    """The stated invariants over a finite domain, checked on both evaluators."""
    state_space = domain_size(size)
    mask_count = 2**size if required is None else 1
    cases = state_space * mask_count
    domain_text = (
        f"4**{size} = {state_space} state vectors x {mask_count} required "
        f"mask(s) = {cases} cases"
    )

    def run(decide: Callable[..., str], raw: Callable[..., str]) -> dict[str, Any]:
        failures: list[dict[str, Any]] = []

        def fail(property_id: str, witness: Any) -> None:
            failures.append({"property": property_id, "witness": witness})

        # VF-P1 determinism: the same input twice, on the uncached call.
        for states, flags in _all_cases(size, required):
            if raw(states, flags) != raw(states, flags):
                fail("VF-P1", {"states": list(states), "required": list(flags)})
                break

        for states, flags in _all_cases(size, required):
            admitted = decide(states, flags)
            if admitted == DECISION_ADMIT:
                for extra_required in (True, False):
                    if decide(states + ("MET",), flags + (extra_required,)) != DECISION_ADMIT:
                        fail(
                            "VF-P2",
                            {
                                "states": list(states),
                                "required": list(flags),
                                "added": "MET",
                                "addedRequired": extra_required,
                            },
                        )
            if decide(states + ("UNMET",), flags + (True,)) != DECISION_DENY:
                fail("VF-P3", {"states": list(states), "required": list(flags), "added": "UNMET"})
            if STATE_UNKNOWN in states and admitted != DECISION_DENY:
                fail("VF-P4", {"states": list(states), "required": list(flags)})
            if any(
                states[index] == STATE_NOT_APPLICABLE and flags[index]
                for index in range(size)
            ) and admitted != DECISION_DENY:
                fail("VF-P5", {"states": list(states), "required": list(flags)})
            for index in range(size):
                if flags[index]:
                    continue
                if STATE_UNKNOWN in states:
                    # VF-R3 makes an UNKNOWN a refusal whatever its requirement, so
                    # the no-score invariant is stated over vectors with no UNKNOWN.
                    continue
                for replacement in (STATE_MET, "UNMET", STATE_NOT_APPLICABLE):
                    changed = list(states)
                    changed[index] = replacement
                    if decide(tuple(changed), flags) != admitted:
                        fail(
                            "VF-P7",
                            {
                                "states": list(states),
                                "required": list(flags),
                                "changedIndex": index,
                                "replacement": replacement,
                            },
                        )

        for states, flags in _all_cases(size, required):
            baseline = decide(states, flags)
            for order in itertools.permutations(range(size)):
                if (
                    decide(
                        tuple(states[index] for index in order),
                        tuple(flags[index] for index in order),
                    )
                    != baseline
                ):
                    fail(
                        "VF-P6",
                        {"states": list(states), "required": list(flags), "permutation": list(order)},
                    )
                    break

        unique = sorted({item["property"] for item in failures})
        return {
            "total": cases,
            "failures": len(failures),
            "witness": failures[0] if failures else None,
            "result": "PASS" if not failures else "FAIL",
            "violated": unique,
        }

    implementation_result = run(_memoised(implementation), implementation)
    reference_result = run(_memoised(reference), reference)
    catalogue = [
        ("VF-P1", "determinism: the same state vector twice returns the same decision"),
        ("VF-P2", "adding a MET obligation to an admitting vector still admits"),
        ("VF-P3", "adding a required UNMET obligation to any vector denies"),
        ("VF-P4", "UNKNOWN never admits, whether or not the obligation is required"),
        ("VF-P5", "NOT_APPLICABLE on a required obligation denies"),
        ("VF-P6", "permuting the vector and its required flags together changes no decision"),
        ("VF-P7", "with no obligation in UNKNOWN, a non-required obligation in MET, "
                  "UNMET or NOT_APPLICABLE never changes the decision"),
    ]
    rows = []
    for identifier, statement in catalogue:
        violated = set(implementation_result["violated"]) | set(reference_result["violated"])
        rows.append(
            {
                "id": identifier,
                "statement": statement,
                "domain": domain_text,
                "implementation": "FAIL" if identifier in implementation_result["violated"] else "PASS",
                "reference": "FAIL" if identifier in reference_result["violated"] else "PASS",
                "result": "FAIL" if identifier in violated else "PASS",
                "witness": (
                    implementation_result["witness"]
                    if identifier in implementation_result["violated"]
                    else reference_result["witness"]
                    if identifier in reference_result["violated"]
                    else None
                ),
            }
        )
    return {
        "domain": domain_text,
        "size": size,
        "maskCount": mask_count,
        "properties": rows,
        "allHold": all(row["result"] == "PASS" for row in rows),
    }


# ---------------------------------------------------------------------------
# Assertions that turn a record into a refusal
# ---------------------------------------------------------------------------
def assert_agreement(record: Mapping[str, Any], *, domain: str = "the domain") -> None:
    disagreements = record.get("disagreements") or []
    if disagreements:
        first = disagreements[0]
        witness = first.get("states") or first.get("chain") or first.get("approvals")
        _refuse(
            "VF_REFUSED_DISAGREEMENT",
            f"{domain}: {len(disagreements)} disagreement(s); first at "
            f"{canonical(witness)}: implementation {first.get('implementation')!r}, "
            f"reference {first.get('reference')!r}, rule {first.get('rule')!r}",
        )


def assert_properties(record: Mapping[str, Any]) -> None:
    failing = [row for row in record.get("properties") or [] if row.get("result") != "PASS"]
    if failing:
        first = failing[0]
        _refuse(
            "VF_REFUSED_PROPERTY_VIOLATED",
            f"{first['id']} fails: {canonical(first.get('witness'))}",
        )


def assert_reference_independent(function: Callable[..., Any]) -> None:
    banned = ("policy_engine", "thresholds", "corrections")
    globals_ = getattr(function, "__globals__", {}) or {}
    present = sorted(name for name in banned if name in globals_)
    if present:
        _refuse(
            "VF_REFUSED_REFERENCE_IMPORTS_IMPLEMENTATION",
            f"{getattr(function, '__name__', function)!r} resolves {present} through its globals",
        )
    try:
        source = inspect.getsource(function)
    except (OSError, TypeError):
        source = ""
    for name in banned:
        for needle in (f"import {name}", f"from {name}", f"{name}."):
            if needle in source:
                _refuse(
                    "VF_REFUSED_REFERENCE_IMPORTS_IMPLEMENTATION",
                    f"{getattr(function, '__name__', function)!r} names {name!r} in its source",
                )


assert_reference_independent(reference_decide)
assert_reference_independent(reference_threshold_count)
assert_reference_independent(reference_chain_admissible)


# ---------------------------------------------------------------------------
# The run: all domains, then the record
# ---------------------------------------------------------------------------
def run_differential() -> dict[str, Any]:
    small = _small_decision_differential(declared_size=small_decision_domain_size())
    small_record = {
        "id": "decision-small",
        "subject": "the decision function over 0..3 obligations, every state vector "
                   "and every required mask",
        "rules": ["VF-R1", "VF-R2", "VF-R3", "VF-R4", "VF-R5"],
        "declaredSize": small["declaredSize"],
        "compared": small["compared"],
        "disagreements": small["disagreements"],
        "exhaustive": True,
        "note": "4**n state vectors x 2**n required masks for n = 0..3",
    }
    policy = _decision_differential(
        DECISION_POLICY_OBLIGATIONS,
        [[True] * DECISION_POLICY_OBLIGATIONS],
        declared_size=policy_decision_domain_size(),
    )
    policy_record = {
        "id": "decision-policy",
        "subject": "the decision function over the real policy's shape: 8 obligations, "
                   "all required, canonical order",
        "rules": ["VF-R2", "VF-R5", "VF-R6", "VF-R7"],
        "declaredSize": policy["declaredSize"],
        "compared": policy["compared"],
        "disagreements": policy["disagreements"],
        "exhaustive": True,
        "note": "4**8 = 65,536 is the whole state space of an eight-obligation decision function",
    }
    threshold = threshold_differential(declared_size=threshold_domain_size())
    threshold_record = {
        "id": "threshold",
        "subject": "k-of-n over 12 approval archetypes against two inventories "
                   "(three distinct establishments, and one aliased), k in 1..min(3, available)",
        "rules": ["VF-R8"],
        "declaredSize": threshold["declaredSize"],
        "compared": threshold["compared"],
        "disagreements": threshold["disagreements"],
        "exhaustive": False,
        "note": "a declared finite model: multisets of 0..4 approvals over 12 archetypes",
    }
    correction = correction_differential(declared_size=correction_domain_size())
    correction_record = {
        "id": "correction",
        "subject": "chains of length 0..3 over two subjects, earlier-only predecessors, "
                   "with intact/bad digests and preserved/modified originals, plus 3 cycles",
        "rules": ["VF-R9", "VF-C1", "VF-C2", "VF-C3", "VF-C4", "VF-C5", "VF-C6", "VF-C7", "VF-C8"],
        "declaredSize": correction["declaredSize"],
        "compared": correction["compared"],
        "disagreements": correction["disagreements"],
        "observations": correction.get("observations") or [],
        "exhaustive": False,
        "note": "a declared finite model: the cycle witnesses are unsatisfiable under the "
                "digest rule, so they are observations as well as cases",
    }
    domains = [small_record, policy_record, threshold_record, correction_record]
    return {
        "schema": SCHEMA_DIFFERENTIAL,
        "baseCommit": "7c2b5f25fe55e6302b942ed124f4fbec5aff8888",
        "reference": {
            "decision": "forensics/tools/verifier_formalisation.py:reference_decide",
            "threshold": "forensics/tools/verifier_formalisation.py:reference_threshold_count",
            "correction": "forensics/tools/verifier_formalisation.py:reference_chain_admissible",
            "importsImplementation": False,
        },
        "domains": domains,
        "compared": sum(domain["compared"] for domain in domains),
        "disagreements": sum(len(domain["disagreements"]) for domain in domains),
    }


def run_properties() -> dict[str, Any]:
    record = properties(DECISION_SMALL_OBLIGATIONS, None)
    return {
        "schema": SCHEMA_PROPERTIES,
        "baseCommit": "7c2b5f25fe55e6302b942ed124f4fbec5aff8888",
        "domain": record["domain"],
        "properties": record["properties"],
        "allHold": record["allHold"],
    }


# ---------------------------------------------------------------------------
# Controls: deliberately wrong references and one control per refusal code
# ---------------------------------------------------------------------------
def wrong_reference_unknown_as_met(states: Sequence[str], required: Sequence[bool]) -> str:
    """A reference that reads UNKNOWN as MET -- the failure rule VF-R3 prevents."""
    coerced = tuple(STATE_MET if state == STATE_UNKNOWN else state for state in states)
    return reference_decide(coerced, required)


def wrong_reference_not_applicable_as_met(
    states: Sequence[str], required: Sequence[bool]
) -> str:
    """A reference that reads NOT_APPLICABLE as MET -- the failure rule VF-R4 prevents."""
    coerced = tuple(STATE_MET if state == STATE_NOT_APPLICABLE else state for state in states)
    return reference_decide(coerced, required)


def wrong_threshold_count_ignores_aliases(
    approvals: Sequence[Mapping[str, Any]],
    inventory: Mapping[str, Any],
    *,
    required_roles: Sequence[str] = THRESHOLD_REQUIRED_ROLES,
    artefact_digest: str = THRESHOLD_ARTEFACT_DIGEST,
) -> int:
    """Counts establishment records by domain *label*, so an alias is two domains."""
    domains = inventory["domains"]
    labels: set[str] = set()
    for approval in approvals:
        if approval.get("verified") is not True:
            continue
        if approval.get("role") not in tuple(required_roles):
            continue
        if approval.get("fresh") is not True:
            continue
        if approval.get("digest") != artefact_digest:
            continue
        domain = domains.get(approval.get("domain"))
        if not isinstance(domain, Mapping):
            continue
        if domain.get("establishment") is None or domain.get("candidate") is True:
            continue
        labels.add(approval["domain"])
    return len(labels)


def wrong_chain_ignores_digest(chain: Sequence[Mapping[str, Any]]) -> tuple[bool, str | None]:
    """Ignores the predecessor digest, so a mismatch is admitted."""
    admissible, rule = reference_chain_admissible(chain)
    if rule == "VF-C2":
        return True, None
    return admissible, rule


def _stub_reference_importing_implementation() -> Callable[..., str]:
    namespace: dict[str, Any] = {"policy_engine": object()}
    exec("def stub(states, required):\n    return 'ADMIT'\n", namespace)
    return namespace["stub"]


def _capture(action: Callable[[], Any]) -> str:
    try:
        action()
    except Refusal as refusal:
        return refusal.code
    return "VF_OK"


def controls() -> list[dict[str, Any]]:
    """Controls that show each refusal fires.  Every record is ``control-only``."""
    rows: list[dict[str, Any]] = []

    def add(identifier: str, code: str, action: Callable[[], Any], detail: str) -> None:
        rows.append(
            {
                "id": identifier,
                "controlOnly": True,
                "expectedCode": code,
                "observedCode": _capture(action),
                "detail": detail,
            }
        )

    add(
        "wrong-reference-unknown-as-met",
        "VF_REFUSED_DISAGREEMENT",
        lambda: assert_agreement(
            _decision_differential(2, [[True, True]], reference=wrong_reference_unknown_as_met),
            domain="unknown-as-met",
        ),
        "a reference that reads UNKNOWN as MET admits a vector the engine denies",
    )
    add(
        "wrong-reference-not-applicable-as-met",
        "VF_REFUSED_DISAGREEMENT",
        lambda: assert_agreement(
            _decision_differential(
                2, [[True, True]], reference=wrong_reference_not_applicable_as_met
            ),
            domain="not-applicable-as-met",
        ),
        "a reference that reads NOT_APPLICABLE as MET admits a required-inapplicable vector",
    )
    add(
        "wrong-threshold-ignores-aliases",
        "VF_REFUSED_DISAGREEMENT",
        lambda: assert_agreement(
            threshold_differential(reference=wrong_threshold_count_ignores_aliases),
            domain="threshold-aliases",
        ),
        "a count by label reads two aliases of one establishment as two domains",
    )
    add(
        "wrong-chain-ignores-digest",
        "VF_REFUSED_DISAGREEMENT",
        lambda: assert_agreement(
            correction_differential(reference=wrong_chain_ignores_digest),
            domain="chain-digest",
        ),
        "a chain rule that ignores the predecessor digest admits a modified chain",
    )
    add(
        "domain-incomplete",
        "VF_REFUSED_DOMAIN_INCOMPLETE",
        lambda: _decision_differential(2, [[True, True]], declared_size=3),
        "a claimed size of 3 for a 16-vector state space is refused",
    )
    add(
        "enumeration-truncated",
        "VF_REFUSED_ENUMERATION_TRUNCATED",
        lambda: _decision_differential(3, [[True] * 3], limit=10),
        "a bounded enumeration is refused rather than reported with the full size",
    )
    add(
        "reference-imports-implementation",
        "VF_REFUSED_REFERENCE_IMPORTS_IMPLEMENTATION",
        lambda: assert_reference_independent(_stub_reference_importing_implementation()),
        "a reference whose globals resolve policy_engine is refused",
    )
    add(
        "property-violated",
        "VF_REFUSED_PROPERTY_VIOLATED",
        lambda: assert_properties(
            properties(2, [True, True], reference=wrong_reference_unknown_as_met)
        ),
        "the wrong reference violates VF-P4 (UNKNOWN never admits)",
    )
    add(
        "spec-absent",
        "VF_REFUSED_SPEC_ABSENT",
        lambda: load_spec(REPO_ROOT / "evidence/a23/SPEC-ABSENT.json"),
        "a missing specification is refused, not defaulted",
    )
    add(
        "unspecified-rule",
        "VF_REFUSED_UNSPECIFIED_RULE",
        lambda: reference_decide(("MAYBE",), (True,)),
        "a state outside the specification is refused rather than decided",
    )
    return rows


def assert_controls(rows: Sequence[Mapping[str, Any]]) -> None:
    wrong = [row for row in rows if row.get("observedCode") != row.get("expectedCode")]
    if wrong:
        first = wrong[0]
        _refuse(
            "VF_REFUSED_PROPERTY_VIOLATED",
            f"control {first['id']!r} observed {first['observedCode']!r}, "
            f"expected {first['expectedCode']!r}",
        )
    covered = {row["expectedCode"] for row in rows}
    missing = sorted(set(REFUSAL_CODES) - covered)
    if missing:
        _refuse("VF_REFUSED_PROPERTY_VIOLATED", f"no control exercises {missing}")


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------
def _print_differential(record: Mapping[str, Any]) -> None:
    for domain in record["domains"]:
        print(
            f"vf: domain {domain['id']} declared={domain['declaredSize']} "
            f"compared={domain['compared']} disagreements={len(domain['disagreements'])} "
            f"exhaustive={str(domain['exhaustive']).lower()}"
        )
        for disagreement in domain["disagreements"][:5]:
            print(f"vf:   counterexample {canonical(disagreement)}")
    print(
        f"vf: differential domains={len(record['domains'])} compared={record['compared']} "
        f"disagreements={record['disagreements']}"
    )


def _print_properties(record: Mapping[str, Any]) -> None:
    for row in record["properties"]:
        print(
            f"vf: property {row['id']} implementation={row['implementation']} "
            f"reference={row['reference']} result={row['result']}"
        )
    print(
        f"vf: properties domain={record['domain']!r} "
        f"allHold={str(record['allHold']).lower()}"
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="verifier_formalisation.py",
        description="the verifier's written rules, an independent reference, and their gap",
    )
    parser.add_argument("command", nargs="?")
    parser.add_argument("--json", action="store_true", help="emit the record as JSON")
    arguments = parser.parse_args(argv)

    if arguments.command not in ("differential", "properties", "spec", "controls"):
        print("vf: usage verifier_formalisation.py differential|properties|spec|controls [--json]")
        print(f"vf: codes={CODE_USAGE}")
        return EXIT_USAGE

    try:
        if arguments.command == "spec":
            spec = load_spec()
            if arguments.json:
                print(json.dumps(spec, indent=2, sort_keys=True))
            else:
                for rule in spec["rules"]:
                    print(f"vf: rule {rule['id']} {rule['name']}")
                print(f"vf: spec rules={len(spec['rules'])} digest={spec['digest']}")
            print(f"vf: codes={CODE_OK}")
            return EXIT_OK

        if arguments.command == "controls":
            rows = controls()
            assert_controls(rows)
            if arguments.json:
                print(json.dumps(rows, indent=2, sort_keys=True))
            else:
                for row in rows:
                    print(
                        f"vf: control {row['id']} expected={row['expectedCode']} "
                        f"observed={row['observedCode']}"
                    )
                print(f"vf: controls={len(rows)}")
            print(f"vf: codes={CODE_OK}")
            return EXIT_OK

        if arguments.command == "differential":
            record = run_differential()
            if arguments.json:
                print(json.dumps(record, indent=2, sort_keys=True))
            else:
                _print_differential(record)
            assert_agreement(
                {
                    "disagreements": [
                        item for domain in record["domains"] for item in domain["disagreements"]
                    ]
                },
                domain="the declared domains",
            )
            print(f"vf: codes={CODE_OK}")
            return EXIT_OK

        record = run_properties()
        if arguments.json:
            print(json.dumps(record, indent=2, sort_keys=True))
        else:
            _print_properties(record)
        assert_properties(record)
        print(f"vf: codes={CODE_OK}")
        return EXIT_OK
    except Refusal as refusal:
        print(f"vf: refused {refusal.code}: {refusal.message}")
        print(f"vf: codes={refusal.code}")
        return EXIT_REFUSED
    except ToolError as error:
        print(f"vf: usage {error}")
        print(f"vf: codes={CODE_USAGE}")
        return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
