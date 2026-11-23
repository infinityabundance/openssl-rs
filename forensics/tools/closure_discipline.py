#!/usr/bin/env python3
"""Closure discipline for the safe-c33 consumer closures (ETP-T10).

The consumer-closure engine (`forensics/tools/consumer_closure.py`) measures a
reachable set and records, per indirect site, the targets it drops.  A closure
is only as strong as the omissions it admits, so this module audits the
omissions the engine records and the opaque operations it cannot see into:

* every omitted edge (a dropped target, an excluded production operation, an
  excluded enrolment row, an analysis limit) must carry an *independently
  checkable exclusion argument*: the edge named, the reason it cannot affect
  the claim, and a procedure a third party can run against tracked artefacts
  and the recorded candidate identity;
* every opaque external operation (an external provider call, a dispatch
  through an ABI contract, a dynamic name lookup, a call into a shared object
  the analysis does not model) must carry a *scoped contract*: what it is
  assumed to do, the scope of the assumption, and what would falsify it;
* an aggregate that reports a pass while containing a blocked row is refused.

The exclusion bar (five requirements)
------------------------------------
``edge_identity``
    the exact omitted edge is named: a consumer import, a symbol, an indirect
    site plus the dropped target, or a ``file:line:kind`` operation identity.
    A count is not an identity.
``reason``
    the argument states why the omission cannot affect the claim.
``procedure``
    a reproducible check a third party can run.  "Would be checked" is not a
    procedure.
``identity_binding``
    the check is bound to the candidate identity the closure claims (DSO
    digests, source commit, inventory identity), so it cannot be satisfied by
    a different build.
``checkable_result``
    the check's inputs are present in the tracked tree at the recorded
    identity, so the procedure can actually be run (an unavailable input makes
    the argument an assertion), and the receipt records the observed result.

A row missing any requirement fails the bar.  The output is the *count* of
rows that fail; no row is dropped to make a closure look complete.

Aggregation rule
----------------
A summary may not be stronger than its members.  An aggregate document that
reports an overall pass while containing a blocked, unresolved or
not-established row is refused with ``CD_AGGREGATE_PASS_HIDES_BLOCKED_ROW``.
The refusal does not edit the aggregate; it records that the aggregate cannot
be cited as a pass.

Usage
-----
    python3 forensics/tools/closure_discipline.py audit --receipt PATH
    python3 forensics/tools/closure_discipline.py aggregate --name NAME
    python3 forensics/tools/closure_discipline.py emit
    python3 forensics/tools/closure_discipline.py check
    python3 forensics/tools/closure_discipline.py --self-test

Exit status: 0 when the requested check passed, 1 when a refusal fired, 2 for
a usage error.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS = Path(__file__).resolve().parent

EXCLUSIONS_SCHEMA = "openssl-rs/etp-t10/exclusions/1"
OPAQUE_SCHEMA = "openssl-rs/etp-t10/opaque-operations/1"
AGGREGATES_SCHEMA = "openssl-rs/etp-t10/aggregates/1"

EVIDENCE_DIR = REPO_ROOT / "evidence" / "etp-t10"

# Section 1a: the five requirements an exclusion argument must satisfy.
BAR_REQUIREMENTS = {
    "edge_identity": "the exact omitted edge is named, not only a count",
    "reason": "the argument states why the omission cannot affect the claim",
    "procedure": "a reproducible procedure a third party can run is named",
    "identity_binding": "the procedure is bound to the recorded candidate identity",
    "checkable_result": (
        "the procedure's inputs are present at the recorded identity and the "
        "receipt records the observed result"
    ),
}

# Section 1b: a scoped contract must state three things.
CONTRACT_REQUIREMENTS = {
    "assumption": "what the operation is assumed to do",
    "scope": "the scope of the assumption",
    "falsifier": "what would falsify it",
}

CATEGORY_PRODUCTION = "production-operation-exclusions"
CATEGORY_ENROLMENT = "documented-enrolment-exclusions"
CATEGORY_TARGET_DROP = "indirect-target-drops"
CATEGORY_RESIDUAL = "unresolved-indirect-sites"
CATEGORY_ANALYSIS = "analysis-limit-omissions"
EXCLUSION_CATEGORIES = (
    CATEGORY_PRODUCTION,
    CATEGORY_ENROLMENT,
    CATEGORY_TARGET_DROP,
    CATEGORY_RESIDUAL,
    CATEGORY_ANALYSIS,
)

CLOSED_TARGET_SET_PREFIX = "CLOSED_TARGET_SET_"
ABI_CONTRACT_PREFIX = "ABI_CONTRACT_"

DISPOSITION_ARGUMENT = "ARGUMENT"
DISPOSITION_ASSERTION = "ASSERTION"
DISPOSITION_ADMITTED = "ADMITTED_LIMITATION"
DISPOSITION_NON_CLAIM = "NON_CLAIM"

# Section 1c: states an aggregate row may carry.
BLOCKED_STATES = frozenset({
    "BLOCKED",
    "UNKNOWN",
    "NOT_ESTABLISHED",
    "NOT ESTABLISHED",
    "NOT_GRADUATED",
    "NOT RUN",
    "NOT_RUN",
    "REFUSED",
    "CONTRADICTED",
    "FAIL",
    "FAILED",
    "WITHDRAWN",
    "PARTIAL",
})
PASS_STATES = frozenset({
    "PASS",
    "ACCEPTED",
    "SAFE_COMPATIBLE",
    "ESTABLISHED",
    "DISCHARGED",
})

OPENSYM = re.compile(r"^(?:libcrypto|libssl)\.so(?:\.\d+)*$")

# The three exports the closure engine's ABI_CONTRACT_DSO_EXPORT contract names.
_DSO_EXPORT_CONTRACT_NAMES = (
    "ERR_get_state",
    "CRYPTO_malloc",
    "CRYPTO_realloc",
)

_blob_cache: dict[tuple[str, str, str], str | None] = {}
_file_cache: dict[tuple[str, str], str | None] = {}


# --------------------------------------------------------------------------- #
# identities
# --------------------------------------------------------------------------- #

def _git(args, repo: Path) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", "-c", "safe.directory=*", "-c", "core.fsmonitor=false",
         "-C", str(repo), *args],
        capture_output=True,
        check=False,
    )


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_sha256(path: Path) -> str | None:
    if not path.is_file():
        return None
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def blob_sha256(commit: str | None, rel_path: str, repo: Path) -> str | None:
    """The Git blob digest at ``commit``; ``None`` when absent or no commit."""
    if not commit:
        return None
    key = (str(repo), commit, rel_path)
    if key in _blob_cache:
        return _blob_cache[key]
    result = _git(["cat-file", "blob", f"{commit}:{rel_path}"], repo)
    value = sha256_bytes(result.stdout) if result.returncode == 0 else None
    _blob_cache[key] = value
    return value


def blob_exists(commit: str | None, rel_path: str, repo: Path) -> bool:
    return blob_sha256(commit, rel_path, repo) is not None


def identity_sha256(rel_path: str, commit: str | None, repo: Path) -> str | None:
    """Digest at ``commit`` when one is given, else from the worktree."""
    if commit:
        return blob_sha256(commit, rel_path, repo)
    key = (str(repo), rel_path)
    if key not in _file_cache:
        _file_cache[key] = file_sha256(repo / rel_path)
    return _file_cache[key]


def _input_present(rel_path: str, commit: str | None, repo: Path) -> bool:
    if commit:
        return blob_sha256(commit, rel_path, repo) is not None
    return (repo / rel_path).is_file()


# --------------------------------------------------------------------------- #
# the closure engine's contract registry
# --------------------------------------------------------------------------- #

def _closure_engine():
    if str(TOOLS) not in sys.path:
        sys.path.insert(0, str(TOOLS))
    import consumer_closure  # noqa: E402  (deliberate lazy import)
    return consumer_closure


def abi_contracts() -> dict:
    return _closure_engine().ABI_CONTRACTS


def abi_contract_classes() -> frozenset:
    return _closure_engine().ABI_CONTRACT_CLASSES


# --------------------------------------------------------------------------- #
# exclusion rows
# --------------------------------------------------------------------------- #

def _row_id(prefix: str, ordinal: int) -> str:
    return f"{prefix}-{ordinal:04d}"


def _evaluate_bar(edge, reason, check) -> dict:
    missing: list[str] = []
    if not edge:
        missing.append("edge_identity")
    if not reason:
        missing.append("reason")
    if not isinstance(check, dict) or not check.get("procedure"):
        missing.append("procedure")
    else:
        if not check.get("candidate_identity"):
            missing.append("identity_binding")
        if check.get("available") is not True:
            missing.append("checkable_result")
    if not isinstance(check, dict) or check.get("result") is None:
        if "checkable_result" not in missing:
            missing.append("checkable_result")
    if not missing:
        disposition = DISPOSITION_ARGUMENT
    elif edge is None and check is None and not reason:
        # No edge, no reason and no check: a global limitation that offers no
        # exclusion argument at all.  It is recorded as admitted, never as a
        # passing exclusion.  A row that offers a reason but no checkable
        # procedure is an assertion, not a limitation.
        disposition = DISPOSITION_ADMITTED
    else:
        disposition = DISPOSITION_ASSERTION
    return {
        "passes": not missing,
        "missing": sorted(set(missing)),
        "disposition": disposition,
    }


def _check_record(procedure, inputs, candidate_identity, absent) -> dict:
    present = not absent
    return {
        "procedure": procedure,
        "inputs": inputs,
        "candidate_identity": candidate_identity,
        "available": present,
        "absent_inputs": sorted(absent),
        "result": {
            "decision": "excluded",
            "recorded_in": None,
        } if present else None,
    }


def _candidate_identity(receipt: dict) -> dict:
    cand = receipt.get("candidate_identity") or {}
    src = receipt.get("source_identity") or {}
    return {
        "install_prefix": cand.get("install_prefix"),
        "libcrypto_so_3_sha256": cand.get("libcrypto_so_3_sha256"),
        "libssl_so_3_sha256": cand.get("libssl_so_3_sha256"),
        "source_head": src.get("span_source_commit") or src.get("repository_head"),
        "inventory_path": src.get("inventory_path"),
    }


def _install_status(receipt: dict, commit, repo: Path) -> dict:
    """Whether the recorded candidate DSO bytes are available at ``commit``.

    The check is a digest match against the recorded path.  A tracked path whose
    bytes are a *different* candidate is not the recorded identity and does not
    make the procedure runnable.
    """
    cand = receipt.get("candidate_identity") or {}
    prefix = cand.get("install_prefix") or ""
    checks = []
    for name, key in (("libcrypto.so.3", "libcrypto_so_3_sha256"),
                      ("libssl.so.3", "libssl_so_3_sha256")):
        expected = cand.get(key)
        if not expected:
            continue
        rel = f"{prefix}/lib/{name}"
        observed = identity_sha256(rel, commit, repo)
        checks.append({
            "path": rel,
            "expected_sha256": expected,
            "observed_sha256": observed,
            "match": observed == expected,
        })
    return {
        "available": bool(checks) and all(c["match"] for c in checks),
        "checks": checks,
    }


def _inventory_status(receipt: dict, commit, repo: Path) -> dict:
    src = receipt.get("source_identity") or {}
    rel = src.get("inventory_path") or ""
    return {
        "path": rel,
        "available": bool(rel) and _input_present(rel, commit, repo),
    }


def _tool_status(receipt: dict, commit, repo: Path) -> dict:
    src = receipt.get("source_identity") or {}
    commit_for_tool = src.get("span_source_commit")
    rel = "forensics/tools/consumer_closure.py"
    return {
        "path": rel,
        "bound_commit": commit_for_tool,
        "available": bool(commit_for_tool) and blob_exists(
            commit_for_tool, rel, repo),
    }


def _production_rows(receipt, consumer, commit, repo, identity, install) -> list:
    rows = []
    excluded = (receipt.get("closure_scope") or {}).get(
        "excluded_from_upper_bound") or []
    for ordinal, row in enumerate(excluded, 1):
        edge = {
            "kind": "production-operation",
            "identity": f"{row.get('file')}:{row.get('line')}:{row.get('kind')}",
            "file": row.get("file"),
            "line": row.get("line"),
            "operation_kind": row.get("kind"),
        }
        reason = row.get("reason") or ""
        procedure = (
            "recompute the reachable function set of the recorded candidate DSO "
            "with the recorded tool and the recorded inventory, and confirm that "
            "no function whose source is this file is in that set; the exclusion "
            "is admitted only under the same upper bound used for every obligation"
        )
        inputs = [
            f"{identity.get('install_prefix')}/lib/libcrypto.so.3",
            identity.get("inventory_path"),
            "forensics/tools/consumer_closure.py",
        ]
        absent = []
        if not install["available"]:
            absent.append(f"{identity.get('install_prefix')}/lib/libcrypto.so.3")
        if not identity.get("inventory_path"):
            absent.append("inventory")
        rows.append({
            "id": _row_id(f"EX-{consumer.upper()}-PROD", ordinal),
            "consumer": consumer,
            "category": CATEGORY_PRODUCTION,
            "edge": edge,
            "statement": "the production operation is outside the upper bound",
            "reason": reason,
            "check": _check_record(procedure, inputs, identity, absent),
            "source": f"closure_scope.excluded_from_upper_bound[{ordinal - 1}]",
        })
        rows[-1]["check"]["result"] = (
            {"decision": "excluded", "recorded_in": rows[-1]["source"]}
            if not absent else None)
    return rows


def _enrolment_rows(receipt, consumer, commit, repo, identity, inventory) -> list:
    rows = []
    excluded = (receipt.get("documented_enrollment") or {}).get(
        "excluded") or []
    src = receipt.get("source_identity") or {}
    span = src.get("span_source_commit")
    for ordinal, row in enumerate(excluded, 1):
        file = row.get("file")
        edge = {
            "kind": "documented-enrolment",
            "identity": f"{file}:{row.get('line')}:{row.get('kind')}",
            "file": file,
            "line": row.get("line"),
            "operation_kind": row.get("kind"),
        }
        reason = row.get("reason") or ""
        procedure = (
            "read the inventory at the recorded identity and confirm that no "
            "operation with this file, line and kind is enumerated; read the "
            "source blob at the recorded span commit and confirm the operation "
            "is absent there"
        )
        inputs = [identity.get("inventory_path"), f"{span}:{file}"]
        absent = []
        if not inventory["available"]:
            absent.append(identity.get("inventory_path") or "inventory")
        if not span or not blob_exists(span, file, repo):
            absent.append(f"{span}:{file}")
        rows.append({
            "id": _row_id(f"EX-{consumer.upper()}-ENROL", ordinal),
            "consumer": consumer,
            "category": CATEGORY_ENROLMENT,
            "edge": edge,
            "statement": "the documented operation is stale at this identity",
            "reason": reason,
            "check": _check_record(procedure, inputs, identity, absent),
            "source": f"documented_enrollment.excluded[{ordinal - 1}]",
        })
        rows[-1]["check"]["result"] = (
            {"decision": "excluded", "recorded_in": rows[-1]["source"]}
            if not absent else None)
    return rows


def _target_drop_rows(receipt, consumer, commit, repo, identity, install) -> list:
    rows = []
    sample = (receipt.get("edge_provenance") or {}).get("records_sample") or []
    declared = sum(
        ((receipt.get("edge_provenance") or {}).get("exclusion_reasons") or {})
        .values())
    ordinal = 0
    for record in sample:
        edge_id = record.get("edge_id") or "?"
        for drop in record.get("exclusions") or []:
            ordinal += 1
            target = drop.get("target")
            edge = {
                "kind": "indirect-target-drop",
                "identity": f"{edge_id}#target={target}",
                "edge_id": edge_id,
                "target": target,
                "drop_reason": drop.get("reason"),
            }
            procedure = (
                "recompute the site's reachable-caller contribution from the "
                "recorded candidate_source per-call-site witnesses against the "
                "candidate DSO, and confirm the excluded caller is not in the "
                "final upper bound; the validator recomputes the same mapping"
            )
            inputs = [
                f"{identity.get('install_prefix')}/lib/libcrypto.so.3",
                "forensics/tools/consumer_closure.py",
            ]
            absent = [] if install["available"] else [inputs[0]]
            rows.append({
                "id": _row_id(f"EX-{consumer.upper()}-DROP", ordinal),
                "consumer": consumer,
                "category": CATEGORY_TARGET_DROP,
                "edge": edge,
                "statement": "the target is not contributed by a reachable caller",
                "reason": drop.get("reason") or "",
                "check": _check_record(procedure, inputs, identity, absent),
                "source": f"edge_provenance.records_sample[edge_id={edge_id}]",
            })
            rows[-1]["check"]["result"] = (
                {"decision": "dropped", "recorded_in": rows[-1]["source"]}
                if not absent else None)
    if declared > len(rows):
        # The receipt declares more dropped targets than its sample records.
        # An unrecorded drop has no argument at all, so it is counted as a
        # failing row rather than left out of the population.
        rows.append({
            "id": _row_id(f"EX-{consumer.upper()}-DROP", len(rows) + 1),
            "consumer": consumer,
            "category": CATEGORY_TARGET_DROP,
            "edge": None,
            "statement": (
                f"{declared - len(rows)} declared target-drop(s) have no record "
                "in the receipt sample, so no exclusion argument exists for them"),
            "reason": "",
            "check": None,
            "source": (
                "edge_provenance.exclusion_reasons against "
                "edge_provenance.records_sample"),
        })
        rows[-1]["bar"] = _evaluate_bar(None, "", None)
        rows[-1]["bar"]["disposition"] = DISPOSITION_ASSERTION
    return rows, declared


def _analysis_limit_kind(text: str) -> str:
    lowered = text.lower()
    if "inlined callees have no out-of-line function node" in lowered:
        return "inlining"
    if "residual bound" in lowered and "may-bound" in lowered:
        return "residual-may-bound"
    if "analysis identity" in lowered and "not a proof of input completeness" in lowered:
        return "analysis-input-completeness"
    return "non-claim"


def _residual_site_scoped(site_class: str) -> bool:
    """Whether a residual site's target set is bounded by a stated argument.

    A ``CLOSED_TARGET_SET_*`` class is bounded by an enumerated in-image set; an
    ``ABI_CONTRACT_*`` class is bounded by the contract registry.  Any other
    class (``field``, ``materialised`` or an ``ABI_*`` class with no contract)
    has no argument, so it is recorded as failing rather than admitted.
    """
    if site_class.startswith(CLOSED_TARGET_SET_PREFIX):
        return True
    if site_class.startswith(ABI_CONTRACT_PREFIX):
        contract, missing = _contract_record(site_class)
        return contract is not None and not missing
    return False


def _residual_rows(receipt, consumer, identity, install) -> list:
    """Every unresolved reachable indirect site recorded by the receipt."""
    precision = receipt.get("precision") or {}
    sites = precision.get("residual_sites") or []
    rows = []
    dso = f"{identity.get('install_prefix')}/lib/libcrypto.so.3"
    for ordinal, site in enumerate(sites, 1):
        site_class = site.get("class") or "unclassified"
        scoped = _residual_site_scoped(site_class)
        edge = {
            "kind": "unresolved-indirect-site",
            "identity": "%s:%s:%s" % (site.get("dso"), site.get("function"),
                                       site.get("call_site")),
            "dso": site.get("dso"),
            "function": site.get("function"),
            "call_site": site.get("call_site"),
            "site_class": site_class,
            "text": site.get("text"),
        }
        procedure = (
            "recompute the site class and its target set from the recorded "
            "candidate DSO with forensics/tools/consumer_closure.py; for a "
            "contract class confirm the named ABI contract in the registry "
            "covers this call site; for a closed-target-set class re-enumerate "
            "the in-image set")
        inputs = [dso, "forensics/tools/consumer_closure.py"]
        absent = [] if install["available"] else [dso]
        source = f"precision.residual_sites[{ordinal - 1}]"
        row = {
            "id": _row_id(f"EX-{consumer.upper()}-RESID", ordinal),
            "consumer": consumer,
            "category": CATEGORY_RESIDUAL,
            "edge": edge,
            "statement": (
                "the indirect site is bounded by %s" % site_class if scoped
                else "the indirect site has no contract or closed-target-set bound"),
            "reason": site.get("reason") if scoped else "",
            "check": _check_record(procedure, inputs, identity, absent),
            "source": source,
            "site_class": site_class,
        }
        row["check"]["result"] = (
            {"decision": "bounded", "recorded_in": source}
            if (not absent and scoped) else None)
        rows.append(row)
    return rows


def _coverage_rows(receipt, consumer) -> list:
    """Omissions the receipt records as counts or lists rather than per edge."""
    rows = []
    precision = receipt.get("precision") or {}
    totals = precision.get("totals") or {}
    sites = precision.get("residual_sites") or []
    reachable = totals.get("reachable_unresolved_sites")
    ordinal = 0

    def add(statement, source, category=CATEGORY_RESIDUAL):
        nonlocal ordinal
        ordinal += 1
        rows.append({
            "id": _row_id(f"EX-{consumer.upper()}-COV", ordinal),
            "consumer": consumer,
            "category": category,
            "edge": None,
            "statement": statement,
            "reason": "",
            "check": None,
            "source": source,
        })
        rows[-1]["bar"] = _evaluate_bar(None, "", None)
        rows[-1]["bar"]["disposition"] = DISPOSITION_ASSERTION

    if isinstance(reachable, int) and len(sites) < reachable:
        add(
            f"{reachable - len(sites)} of {reachable} reachable unresolved indirect "
            f"site(s) have no per-site record (the receipt records {len(sites)})",
            "precision.residual_sites against precision.totals.reachable_unresolved_sites")
    unclassified = precision.get("unclassified_reachable_sites") or []
    if unclassified:
        add(
            f"{len(unclassified)} reachable indirect site(s) are unclassified",
            "precision.unclassified_reachable_sites")
    boundary = receipt.get("boundary_coverage") or {}
    for index, path in enumerate(boundary.get("reachable_files_without_receipt") or []):
        add(
            f"reachable file {path} has no receipt",
            f"boundary_coverage.reachable_files_without_receipt[{index}]")
    conflicts = receipt.get("disposition_conflicts") or {}
    for key in ("unresolved_obligation_count", "unresolved_edge_count"):
        value = conflicts.get(key)
        if isinstance(value, int) and value > 0:
            add(
                f"{value} unresolved disposition conflict(s) recorded in {key}",
                f"disposition_conflicts.{key}")
    return rows


def _analysis_rows(receipt, consumer) -> list:
    rows = []
    limits = (receipt.get("graph") or {}).get("limits") or []
    for ordinal, text in enumerate(limits, 1):
        kind = _analysis_limit_kind(text)
        if kind == "non-claim":
            continue
        rows.append({
            "id": _row_id(f"EX-{consumer.upper()}-LIMIT", ordinal),
            "consumer": consumer,
            "category": CATEGORY_ANALYSIS,
            "edge": None,
            "statement": text,
            "reason": "",
            "check": None,
            "source": f"graph.limits[{ordinal - 1}]",
            "limit_kind": kind,
        })
        rows[-1]["bar"] = _evaluate_bar(None, "", None)
        rows[-1]["bar"]["disposition"] = DISPOSITION_ADMITTED
    return rows


def audit_receipt_dict(receipt: dict, *, consumer: str, commit=None,
                       repo: Path = REPO_ROOT) -> dict:
    """Audit a closure receipt's omissions against the exclusion bar."""
    identity = _candidate_identity(receipt)
    install = _install_status(receipt, commit, repo)
    inventory = _inventory_status(receipt, commit, repo)
    _tool_status(receipt, commit, repo)

    rows = []
    rows.extend(_production_rows(receipt, consumer, commit, repo, identity, install))
    rows.extend(_enrolment_rows(receipt, consumer, commit, repo, identity, inventory))
    dropped, declared = _target_drop_rows(
        receipt, consumer, commit, repo, identity, install)
    rows.extend(dropped)
    rows.extend(_residual_rows(receipt, consumer, identity, install))
    rows.extend(_coverage_rows(receipt, consumer))
    rows.extend(_analysis_rows(receipt, consumer))

    for row in rows:
        if "bar" not in row:
            row["bar"] = _evaluate_bar(
                row.get("edge"), row.get("reason"), row.get("check"))

    failing = [r for r in rows if not r["bar"]["passes"]]
    categories = {}
    for name in EXCLUSION_CATEGORIES:
        members = [r for r in rows if r["category"] == name]
        categories[name] = {
            "rows": len(members),
            "passing": sum(1 for r in members if r["bar"]["passes"]),
            "failing": sum(1 for r in members if not r["bar"]["passes"]),
        }
    target_drop_rows = [r for r in rows if r["category"] == CATEGORY_TARGET_DROP]
    sampled_target_drops = {
        "rows_in_receipt_sample": len(target_drop_rows),
        "declared_in_exclusion_reasons": declared,
        "complete": len(target_drop_rows) == declared,
    }
    return {
        "consumer": consumer,
        "exclusion_rows": len(rows),
        "exclusions_failing": len(failing),
        "failing_ids": [r["id"] for r in failing],
        "categories": categories,
        "target_drop_sample": sampled_target_drops,
        "candidate_identity": identity,
        "candidate_install": install,
        "inventory_availability": inventory,
        "rows": rows,
    }


def audit_receipt_path(path: Path, *, consumer: str | None = None,
                       commit=None, repo: Path = REPO_ROOT) -> dict:
    receipt = json.loads(Path(path).read_text(encoding="utf-8"))
    if consumer is None:
        consumer = receipt.get("family") or Path(path).stem
    return audit_receipt_dict(receipt, consumer=consumer, commit=commit, repo=repo)


# --------------------------------------------------------------------------- #
# opaque external operations
# --------------------------------------------------------------------------- #

def _contract_record(cls: str) -> tuple[dict | None, list[str]]:
    contracts = abi_contracts()
    contract = contracts.get(cls)
    if not isinstance(contract, dict):
        return None, ["class has no contract in the closure engine registry"]
    missing = []
    if not contract.get("contract"):
        missing.append("assumption")
    if not contract.get("covers"):
        missing.append("scope")
    if not contract.get("does_not_cover"):
        missing.append("falsifier")
    if not contract.get("citation"):
        missing.append("citation")
    return contract, missing


def audit_opaque_dict(receipt: dict, *, consumer: str) -> dict:
    precision = receipt.get("precision") or {}
    element7 = precision.get("predicate_element_7") or {}
    rows = []
    ordinal = 0

    def add(kind, operation, sites, contract, missing, source, **extra):
        nonlocal ordinal
        ordinal += 1
        rows.append({
            "id": f"OP-{consumer.upper()}-{ordinal:04d}",
            "consumer": consumer,
            "kind": kind,
            "operation": operation,
            "sites": sites,
            "scoped_contract": bool(contract) and not missing,
            "contract": contract,
            "contract_missing": sorted(missing),
            "source": source,
            **extra,
        })

    # 1. Sites admitted under a documented ABI contract.
    by_class = element7.get("contract_bounded_by_class") or {}
    for cls, sites in sorted(by_class.items()):
        contract, missing = _contract_record(cls)
        add("contract-bounded-indirect-site", cls, sites, contract, missing,
            f"precision.predicate_element_7.contract_bounded_by_class[{cls}]")

    # 2. Sites whose candidate contract has no per-call-site witness.
    witness_missing = (precision.get("witness_rule") or {}).get(
        "witness_missing") or []
    for index, row in enumerate(witness_missing):
        add("candidate-contract-without-witness",
            row.get("candidate_class") or "unknown", 1, None,
            ["no per-call-site witness"], 
            f"precision.witness_rule.witness_missing[{index}]",
            dso=row.get("dso"), function=row.get("function"),
            call_site=row.get("call_site"), slot=row.get("slot"),
            writer=row.get("writer"), reason=row.get("reason"))

    # 3. dlsym literals not covered by the documented DSO-export contract.
    literals = precision.get("dlsym_literals") or {}
    merged: dict[str, dict] = {}
    for dso, entries in sorted(literals.items()):
        for name in sorted(entries):
            record = merged.setdefault(
                name, {"sites": 0, "dsos": [], "exported": []})
            record["sites"] += entries[name].get("sites", 1)
            record["dsos"].append(dso)
            record["exported"].append(bool(entries[name].get("exported")))
    for name in sorted(merged):
        if name in _DSO_EXPORT_CONTRACT_NAMES:
            continue
        record = merged[name]
        add("dlsym-literal-not-covered", name, record["sites"],
            None, ["no contract names this literal"],
            f"precision.dlsym_literals[{name}]", dsos=record["dsos"],
            exported=record["exported"])

    # 4. Dynamic name lookup: arbitrary module and symbol names.
    special = (receipt.get("graph") or {}).get("special_edges") or {}
    for index, name in enumerate(special.get("dynamic_name_lookup_reachable") or []):
        add("dynamic-name-lookup", name, 1, None,
            ["the resolved module and symbol names are configuration"],
            f"graph.special_edges.dynamic_name_lookup_reachable[{index}]")

    # 5. Shared objects the analysis does not model.
    needed = ((receipt.get("artifact_identity") or {}).get("dynamic") or {}).get(
        "needed") or []
    for soname in needed:
        if OPENSYM.match(soname):
            continue
        add("unmodelled-shared-object", soname, 1, None,
            ["no scoped contract for this dependency"],
            "artifact_identity.dynamic.needed")

    # 6. ABI-named classes outside the contract registry.
    unresolved = precision.get("unresolved_by_class") or {}
    contracts = abi_contracts()
    contract_classes = abi_contract_classes()
    for cls, sites in sorted(unresolved.items()):
        if not cls.startswith("ABI_"):
            continue
        if cls in contract_classes or cls in contracts:
            continue
        add("abi-class-without-contract", cls, sites, None,
            ["class is named ABI_* but the closure engine has no contract for it"],
            f"precision.unresolved_by_class[{cls}]")

    unscoped = [r for r in rows if not r["scoped_contract"]]
    return {
        "consumer": consumer,
        "operations": rows,
        "operation_rows": len(rows),
        "operation_sites": sum(r["sites"] for r in rows),
        "scoped_contract_rows": len(rows) - len(unscoped),
        "unscoped_contract_rows": len(unscoped),
        "unscoped_contract_sites": sum(r["sites"] for r in unscoped),
        "unscoped_ids": [r["id"] for r in unscoped],
    }


# --------------------------------------------------------------------------- #
# aggregate visibility
# --------------------------------------------------------------------------- #

def _load(path: Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _rows_from_claims(doc: dict, source: str) -> list:
    rows = []
    for claim in doc.get("claims") or []:
        verdict = claim.get("verdict") or {}
        state = verdict.get("state") if isinstance(verdict, dict) else verdict
        if not isinstance(state, str):
            state = "UNKNOWN"
        rows.append({
            "id": claim.get("id") or "?",
            "state": state,
            "blocked": state in BLOCKED_STATES,
            "locator": f"{source}#/claims[id={claim.get('id')}]/verdict/state",
        })
    return rows


def _aggregate_freezes() -> dict:
    """A real aggregate that does not report a pass and keeps its rows visible."""
    path = REPO_ROOT / "evidence" / "FREEZE-b85c.json"
    doc = _load(path)
    rows = []
    measured = (doc.get("safe_compatible") or {}).get("measured") or {}
    for family, values in sorted(measured.items()):
        for key in ("BLOCKED", "UNKNOWN"):
            count = values.get(key)
            if isinstance(count, int) and count:
                rows.append({
                    "id": f"{family}.{key}",
                    "state": key,
                    "blocked": True,
                    "locator": f"safe_compatible.measured.{family}.{key}",
                })
    for index, entry in enumerate(doc.get("not_run") or []):
        rows.append({
            "id": f"not_run[{index}]",
            "state": "NOT_RUN",
            "blocked": True,
            "locator": f"not_run[{index}]",
            "detail": entry if isinstance(entry, str) else json.dumps(entry)[:200],
        })
    for index, entry in enumerate((doc.get("safe_compatible") or {}).get(
            "outstanding") or []):
        rows.append({
            "id": f"outstanding[{index}]",
            "state": "NOT_ESTABLISHED",
            "blocked": True,
            "locator": f"safe_compatible.outstanding[{index}]",
            "detail": entry if isinstance(entry, str) else json.dumps(entry)[:200],
        })
    overall = "PASS" if (doc.get("safe_compatible") or {}).get("value") is True else "FAIL"
    return _aggregate("freeze-b85c", path, doc, overall,
                      "safe_compatible.value", rows)


def _aggregate_graduation(path: Path | None = None,
                         name: str = "safe-compatible-openssh-b85c") -> dict:
    """A graduation/risk-acceptance aggregate and its visible dissent.

    The live record is a risk acceptance and reports FAIL, so it is accepted.
    The historical SAFE_COMPATIBLE bytes are audited separately as a control; a
    record that reports PASS while carrying the NOT_ESTABLISHED dissent is
    refused by ``_aggregate``.
    """
    path = path or REPO_ROOT / "evidence" / "SAFE-COMPATIBLE-openssh-b85c.json"
    doc = _load(path)
    rows = []
    verdict = doc.get("verdict") or {}
    state = verdict.get("value") if isinstance(verdict, dict) else verdict
    overall = "PASS" if state in PASS_STATES else "FAIL"
    dissent = doc.get("dissent") or {}
    if isinstance(dissent, dict) and dissent.get("statement"):
        rows.append({
            "id": "dissent",
            "state": "NOT_ESTABLISHED",
            "blocked": True,
            "locator": "dissent.statement",
            "detail": str(dissent.get("statement"))[:300],
        })
    mechanisms = doc.get("mechanism_verdicts") or {}
    if isinstance(mechanisms, dict):
        for mechanism_name, value in sorted(mechanisms.items()):
            if isinstance(value, dict):
                value = value.get("state") or value.get("verdict")
            if isinstance(value, str) and value in BLOCKED_STATES:
                rows.append({
                    "id": f"mechanism[{mechanism_name}]",
                    "state": value,
                    "blocked": True,
                    "locator": f"mechanism_verdicts[{mechanism_name}]",
                })
    elif isinstance(mechanisms, list):
        for index, entry in enumerate(mechanisms):
            if not isinstance(entry, dict):
                continue
            value = entry.get("verdict") or entry.get("state")
            if isinstance(value, str) and value in BLOCKED_STATES:
                rows.append({
                    "id": entry.get("id") or f"mechanism[{index}]",
                    "state": value,
                    "blocked": True,
                    "locator": f"mechanism_verdicts[{index}]",
                })
    retraction = doc.get("retraction") or {}
    if isinstance(retraction, dict) and retraction.get("status") == "RETRACTED":
        # A retraction of a *sub-claim* is not a blocked row of the aggregate.
        # It is recorded as history so it stays visible, but it does not make a
        # graduation pass hide a not-established row.  A retraction that
        # withdraws the aggregate's own verdict would be recorded as
        # ``withdraws_verdict`` by its producer and is handled as blocked.
        withdrawn_claim = str(retraction.get("withdrawn_claim") or "")
        withdraws_verdict = bool(retraction.get("withdraws_verdict")) or (
            "SAFE_COMPATIBLE" in withdrawn_claim.upper())
        rows.append({
            "id": "retraction",
            "state": "WITHDRAWN" if withdraws_verdict else "RETRACTED_SUB_CLAIM",
            "blocked": withdraws_verdict,
            "locator": "retraction.status",
            "detail": withdrawn_claim[:300],
        })
    return _aggregate(name, path, doc, overall,
                      "verdict.value", rows)


def _aggregate_campaign_status() -> dict:
    """The cohort counter and the adjudications it summarises."""
    path = REPO_ROOT / "forensics" / "memory-safety" / "campaign" / "safe-c33" / "CAMPAIGN-STATUS.json"
    doc = _load(path)
    rows = []
    consumers = doc.get("consumers") or {}
    count = consumers.get("safe_compatible")
    overall = "PASS" if isinstance(count, int) and count > 0 else "FAIL"
    for key in ("b85_adjudication", "b85c_adjudication", "b84_adjudication"):
        block = doc.get(key) or {}
        value = block.get("verdict") if isinstance(block, dict) else None
        if isinstance(value, str):
            state = value.split()[0].replace("-", "_")
            rows.append({
                "id": key,
                "state": "NOT_ESTABLISHED" if value.startswith("NOT ESTABLISHED") else state,
                "blocked": value.startswith("NOT ESTABLISHED") or state in BLOCKED_STATES,
                "locator": f"{key}.verdict",
                "detail": value[:200],
            })
    gates = doc.get("gates") or {}
    for name in ("boundary_gate", "seal_gate"):
        gate = gates.get(name) or {}
        state = gate.get("state") if isinstance(gate, dict) else None
        if isinstance(state, str) and state in BLOCKED_STATES:
            rows.append({
                "id": f"gates.{name}",
                "state": state,
                "blocked": True,
                "locator": f"gates.{name}.state",
            })
    return _aggregate("campaign-status", path, doc, overall,
                      "consumers.safe_compatible", rows)


def _aggregate_closure(consumer: str, rel: str) -> dict:
    path = REPO_ROOT / rel
    doc = _load(path)
    rows = []
    counts = doc.get("counts") or {}
    for key in ("BLOCKED", "UNKNOWN"):
        value = counts.get(key)
        if isinstance(value, int):
            rows.append({
                "id": f"counts.{key}",
                "state": key,
                "blocked": value > 0,
                "locator": f"counts.{key}",
            })
    element7 = ((doc.get("precision") or {}).get("predicate_element_7") or {})
    status = element7.get("status")
    if isinstance(status, str):
        rows.append({
            "id": "predicate.element_7",
            "state": status,
            "blocked": status not in PASS_STATES,
            "locator": "precision.predicate_element_7.status",
            "detail": element7.get("why"),
        })
    verdict = doc.get("verdict") or {}
    overall = "PASS" if verdict.get("safe_compatible") is True else "FAIL"
    result = _aggregate(f"closure-{consumer}", path, doc, overall,
                        "verdict.safe_compatible", rows)
    count_rows = [r for r in rows
                  if r["blocked"] and r["locator"].startswith("counts.")]
    other_rows = [r for r in rows
                  if r["blocked"] and not r["locator"].startswith("counts.")]
    result["summary_counts_hide_blocked_rows"] = bool(other_rows) and not count_rows
    return result


def _aggregate(name, path: Path, doc: dict, overall: str, source: str,
               rows: list) -> dict:
    blocked = [r for r in rows if r["blocked"]]
    visible = bool(blocked)
    refusal = None
    if overall == "PASS" and blocked:
        refusal = {
            "code": "CD_AGGREGATE_PASS_HIDES_BLOCKED_ROW",
            "detail": (
                f"aggregate {name} reports an overall pass "
                f"({source}) while containing {len(blocked)} blocked or "
                "not-established row(s)"),
            "blocked_rows": [r["id"] for r in blocked],
        }
    return {
        "aggregate": name,
        "path": str(path.relative_to(REPO_ROOT)),
        "sha256": file_sha256(path),
        "reported_overall_state": overall,
        "reported_state_source": source,
        "rows": rows,
        "blocked_rows": [r["id"] for r in blocked],
        "blocked_rows_visible_in_document": visible,
        "refusal": refusal,
    }


def aggregate_registry() -> list:
    return [
        ("freeze-b85c", _aggregate_freezes),
        ("safe-compatible-openssh-b85c", _aggregate_graduation),
        ("campaign-status", _aggregate_campaign_status),
        ("closure-curl-049", lambda: _aggregate_closure(
            "curl", "evidence/closure-curl-049.json")),
        ("closure-ssh-b85c", lambda: _aggregate_closure(
            "ssh", "evidence/closure-ssh-b85c.json")),
        ("closure-sshd-b85c", lambda: _aggregate_closure(
            "sshd", "evidence/closure-sshd-b85c.json")),
        ("claims-etp", lambda: _aggregate_claims(
            "claims-etp", REPO_ROOT / "evidence" / "etp" / "claims.json")),
        ("claims-etp0", lambda: _aggregate_claims(
            "claims-etp0", REPO_ROOT / "evidence" / "etp0" / "CLAIMS.json")),
    ]


def _aggregate_claims(name: str, path: Path) -> dict:
    doc = _load(path)
    rows = _rows_from_claims(doc, str(path.relative_to(REPO_ROOT)))
    if any(r["state"] in BLOCKED_STATES for r in rows):
        overall = "FAIL"
    elif rows and all(r["state"] in PASS_STATES for r in rows):
        overall = "PASS"
    else:
        overall = "UNDETERMINED"
    return _aggregate(name, path, doc, overall, "claims[].verdict.state", rows)


def audit_aggregates() -> dict:
    results = []
    for name, builder in aggregate_registry():
        results.append(builder())
    refusals = [
        {"aggregate": r["aggregate"], **r["refusal"]}
        for r in results if r["refusal"]
    ]
    return {
        "schema": AGGREGATES_SCHEMA,
        "aggregates": results,
        "aggregate_count": len(results),
        "refusal_count": len(refusals),
        "refusals": refusals,
        "rule": (
            "an aggregate that reports an overall pass while containing a "
            "blocked, unresolved or not-established row is refused with "
            "CD_AGGREGATE_PASS_HIDES_BLOCKED_ROW; the aggregate is not edited"),
    }


# --------------------------------------------------------------------------- #
# documents
# --------------------------------------------------------------------------- #

RECEIPTS = (
    ("curl", "evidence/closure-curl-049.json"),
    ("ssh", "evidence/closure-ssh-b85c.json"),
    ("sshd", "evidence/closure-sshd-b85c.json"),
)


def _check_commit(repo: Path) -> str:
    result = _git(["rev-parse", "HEAD"], repo)
    if result.returncode != 0:
        raise SystemExit("cannot resolve HEAD")
    return result.stdout.decode().strip()


def build_documents(commit: str, repo: Path = REPO_ROOT) -> tuple[dict, dict]:
    exclusions = []
    opaque = []
    per_consumer = {}
    for consumer, rel in RECEIPTS:
        audit = audit_receipt_path(repo / rel, consumer=consumer,
                                   commit=commit, repo=repo)
        exclusions.extend(audit["rows"])
        opaque_audit = audit_opaque_dict(
            _load(repo / rel), consumer=consumer)
        opaque.extend(opaque_audit["operations"])
        per_consumer[consumer] = {
            "receipt": rel,
            "receipt_sha256": identity_sha256(rel, commit, repo),
            "exclusion_rows": audit["exclusion_rows"],
            "exclusions_failing": audit["exclusions_failing"],
            "categories": audit["categories"],
            "target_drop_sample": audit["target_drop_sample"],
            "candidate_install_available": audit["candidate_install"]["available"],
            "inventory_available": audit["inventory_availability"]["available"],
            "opaque_rows": opaque_audit["operation_rows"],
            "opaque_unscoped_rows": opaque_audit["unscoped_contract_rows"],
            "opaque_unscoped_sites": opaque_audit["unscoped_contract_sites"],
        }

    totals = {}
    for name in EXCLUSION_CATEGORIES:
        members = [r for r in exclusions if r["category"] == name]
        totals[name] = {
            "rows": len(members),
            "passing": sum(1 for r in members if r["bar"]["passes"]),
            "failing": sum(1 for r in members if not r["bar"]["passes"]),
        }
    exclusions_doc = {
        "schema": EXCLUSIONS_SCHEMA,
        "item": "ETP-T10 of docs/ETP-TODO.md",
        "identity": {
            "commit": commit,
            "digest_rule": (
                "closure receipts and their procedure inputs are read from the "
                "named commit, never from a later working tree"),
        },
        "bar": {
            "requirements": BAR_REQUIREMENTS,
            "rule": (
                "an exclusion passes only when all five requirements hold; a "
                "row missing any requirement is counted as failing, and the "
                "output is the count of failing rows, never a reduced set"),
        },
        "consumers": per_consumer,
        "totals_by_category": totals,
        "exclusion_rows": len(exclusions),
        "exclusions_passing": sum(1 for r in exclusions if r["bar"]["passes"]),
        "exclusions_failing": sum(1 for r in exclusions if not r["bar"]["passes"]),
        "rows": exclusions,
        "non_claims": [
            "A failing row is not repaired or removed by this record; it names "
            "an omission that must be closed or accepted explicitly.",
            "A passing row establishes that the procedure can be run against the "
            "recorded identity; it does not establish that the procedure was "
            "re-run for this record.",
            "The audit reads closure receipts; it does not re-run the closure "
            "engine or rebuild the candidate.",
        ],
    }

    opaque_totals = {
        "operation_rows": len(opaque),
        "operation_sites": sum(r["sites"] for r in opaque),
        "scoped_contract_rows": sum(1 for r in opaque if r["scoped_contract"]),
        "unscoped_contract_rows": sum(1 for r in opaque if not r["scoped_contract"]),
        "unscoped_contract_sites": sum(
            r["sites"] for r in opaque if not r["scoped_contract"]),
    }
    opaque_doc = {
        "schema": OPAQUE_SCHEMA,
        "item": "ETP-T10 of docs/ETP-TODO.md",
        "identity": {
            "commit": commit,
            "digest_rule": (
                "the operation population is read from the closure receipts at "
                "the named commit"),
        },
        "contract_requirements": CONTRACT_REQUIREMENTS,
        "rule": (
            "an opaque operation is scoped only when the closure engine's "
            "contract registry supplies an assumption, a scope and a falsifier "
            "bound to a documented interface; a site that stays unresolved "
            "without such a contract is listed"),
        "totals": opaque_totals,
        "operations": opaque,
        "non_claims": [
            "A scoped contract bounds what the operation is assumed to do; it "
            "does not establish the behaviour or memory safety of the external "
            "implementation.",
            "An operation listed without a contract is not thereby unsafe; it is "
            "an admission that the closure cannot see into it under a documented "
            "interface.",
        ],
    }
    return exclusions_doc, opaque_doc


def write_documents(commit: str | None = None, repo: Path = REPO_ROOT) -> dict:
    commit = commit or _check_commit(repo)
    exclusions_doc, opaque_doc = build_documents(commit, repo)
    aggregates_doc = audit_aggregates()
    aggregates_doc["identity"] = {"commit": commit}
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    written = {}
    for name, document in (
        ("EXCLUSIONS.json", exclusions_doc),
        ("OPAQUE-OPERATIONS.json", opaque_doc),
        ("AGGREGATES.json", aggregates_doc),
    ):
        path = EVIDENCE_DIR / name
        path.write_text(
            json.dumps(document, indent=2, sort_keys=True) + "\n",
            encoding="utf-8")
        written[name] = {
            "path": str(path.relative_to(REPO_ROOT)),
            "sha256": file_sha256(path),
        }
    return written


# --------------------------------------------------------------------------- #
# refusals used by the claim algebra
# --------------------------------------------------------------------------- #

def closure_receipt_failure(path: Path, *, repo: Path = REPO_ROOT,
                            commit: str | None = None) -> dict:
    """Audit a closure receipt for the SAFE_COMPATIBLE exclusion requirement.

    When ``commit`` is named, the candidate DSO and inventory inputs are
    resolved at that commit, so the audit is bound to the claim's identity
    rather than to whatever the working tree happens to contain.
    """
    audit = audit_receipt_path(path, commit=commit, repo=repo)
    return {
        "path": str(path),
        "bound_commit": commit,
        "exclusions_failing": audit["exclusions_failing"],
        "failing_ids": audit["failing_ids"][:20],
        "failure_total": len(audit["failing_ids"]),
    }


# --------------------------------------------------------------------------- #
# self-test
# --------------------------------------------------------------------------- #

def _synthetic_receipt() -> dict:
    """A minimal receipt-shaped document exercising every refusal."""
    return {
        "family": "synthetic",
        "candidate_identity": {
            "install_prefix": "artifacts/phase2/install",
            "libcrypto_so_3_sha256": "0" * 64,
            "libssl_so_3_sha256": None,
        },
        "source_identity": {
            "span_source_commit": "0" * 40,
            "inventory_path": "does/not/exist.json",
        },
        "closure_scope": {
            "excluded_from_upper_bound": [{
                "file": "src/x.rs", "line": 1, "kind": "UNSAFE_FN_DEF",
                "reason": "file is not in the reachable set",
            }],
        },
        "documented_enrollment": {"excluded": [{
            "file": "src/y.rs", "line": 2, "kind": "UNSAFE_FN_DEF",
            "reason": "stale at this identity",
        }]},
        "edge_provenance": {
            "exclusion_reasons": {"not-contributed-by-reachable-callers": 1},
            "records_sample": [{
                "edge_id": "libcrypto.so.3::f::call::argument-callback::1",
                "exclusions": [{
                    "target": "TARGET", "reason": "not-contributed-by-reachable-callers",
                }],
            }],
        },
        "graph": {"limits": [
            "inlined callees have no out-of-line function node; their code is "
            "attributed to the caller",
            "a dynamic trace proves execution, not unreachability",
        ], "special_edges": {
            "dynamic_name_lookup_reachable": ["DSO_bind_func"],
        }},
        "artifact_identity": {"dynamic": {"needed": [
            "libcrypto.so.3", "libc.so.6"]}},
        "precision": {
            "predicate_element_7": {"contract_bounded_by_class": {
                "ABI_CONTRACT_PROVIDER": 2,
            }},
            "witness_rule": {"witness_missing": [{
                "candidate_class": "ABI_CONTRACT_PROVIDER", "dso": "libcrypto.so.3",
                "function": "f", "call_site": "0x1", "slot": "s",
                "writer": "w", "reason": "no witness",
            }]},
            "dlsym_literals": {
                "libcrypto.so.3": {
                    "ERR_get_state": {"sites": 1, "exported": True},
                    "MYSTERY": {"sites": 1, "exported": True},
                },
            },
            "unresolved_by_class": {"ABI_OPEN_METHOD_TABLE": 3},
        },
    }


def self_test() -> int:
    failures = []

    def check(name, condition, detail=""):
        if not condition:
            failures.append(f"{name}: {detail}")

    # 1. The bar refuses a row with no edge identity.
    bar = _evaluate_bar(None, "reason", None)
    check("bar-no-edge", not bar["passes"] and "edge_identity" in bar["missing"],
          bar)
    check("bar-no-edge-disposition", bar["disposition"] == DISPOSITION_ASSERTION,
          bar)

    # 1b. A limitation with no edge, no reason and no procedure is admitted,
    # never counted as a passing exclusion.
    bar = _evaluate_bar(None, "", None)
    check("bar-admitted-limitation",
          not bar["passes"] and bar["disposition"] == DISPOSITION_ADMITTED, bar)

    # 1c. Each individual bar requirement is load-bearing: a row with every
    # requirement but one must name exactly that requirement.
    for dropped in ("edge_identity", "reason", "procedure",
                    "identity_binding", "checkable_result"):
        edge = {"identity": "x"} if dropped != "edge_identity" else None
        reason = "" if dropped == "reason" else "a stated reason"
        if dropped == "procedure":
            candidate = _check_record("", ["input"], {"x": 1}, [])
        elif dropped == "identity_binding":
            candidate = _check_record("proc", ["input"], {}, [])
        elif dropped == "checkable_result":
            candidate = _check_record("proc", ["input"], {"x": 1}, ["input"])
        else:
            candidate = _check_record("proc", ["input"], {"x": 1}, [])
        bar = _evaluate_bar(edge, reason, candidate)
        check(f"bar-requires-{dropped}", not bar["passes"], bar)
        check(f"bar-names-{dropped}", dropped in bar["missing"], bar)

    # 2. The bar refuses an edge whose procedure inputs are absent.
    absent_check = _check_record("proc", ["input"], {"x": 1}, ["input"])
    bar = _evaluate_bar({"identity": "x"}, "reason", absent_check)
    check("bar-absent-input", not bar["passes"], bar)
    check("bar-absent-input-missing", "checkable_result" in bar["missing"], bar)

    # 3. A complete argument passes.
    good = _check_record("proc", ["input"], {"x": 1}, [])
    bar = _evaluate_bar({"identity": "x"}, "reason", good)
    check("bar-complete", bar["passes"] and bar["disposition"] == DISPOSITION_ARGUMENT,
          bar)

    # 4. A synthetic receipt classifies every category and refuses what it must.
    audit = audit_receipt_dict(_synthetic_receipt(), consumer="synthetic",
                               commit=None, repo=REPO_ROOT)
    check("synthetic-categories",
          set(audit["categories"]) == set(EXCLUSION_CATEGORIES), audit["categories"])
    check("synthetic-fails",
          audit["exclusions_failing"] == 4, audit["exclusions_failing"])
    check("synthetic-analysis-omission",
          audit["categories"][CATEGORY_ANALYSIS]["failing"] == 1,
          audit["categories"][CATEGORY_ANALYSIS])
    check("synthetic-target-drops",
          audit["target_drop_sample"]["complete"] is True,
          audit["target_drop_sample"])

    # 5. Opaque operations: the contract class is scoped, the rest are listed.
    opaque = audit_opaque_dict(_synthetic_receipt(), consumer="synthetic")
    kinds = {r["kind"] for r in opaque["operations"]}
    check("opaque-contract", kinds == {
        "contract-bounded-indirect-site",
        "candidate-contract-without-witness",
        "dlsym-literal-not-covered",
        "dynamic-name-lookup",
        "unmodelled-shared-object",
        "abi-class-without-contract",
    }, sorted(kinds))
    unscoped = [r for r in opaque["operations"] if not r["scoped_contract"]]
    check("opaque-unscoped", len(unscoped) == 5, len(unscoped))
    check("opaque-covered-literal",
          all(r["operation"] != "ERR_get_state" for r in unscoped), [
              r["operation"] for r in unscoped])
    check("opaque-abis",
          any(r["operation"] == "ABI_OPEN_METHOD_TABLE" for r in unscoped),
          [r["operation"] for r in unscoped])

    # 6. Aggregate refusal: a pass containing a blocked row is refused.
    blocked_row = {"id": "cell", "state": "NOT_ESTABLISHED", "blocked": True,
                   "locator": "cell"}
    aggregate = _aggregate("synthetic-pass", Path(__file__).resolve(),
                           {}, "PASS", "verdict.value", [blocked_row])
    check("aggregate-refused",
          (aggregate["refusal"] or {}).get("code")
          == "CD_AGGREGATE_PASS_HIDES_BLOCKED_ROW", aggregate)
    aggregate = _aggregate("synthetic-fail", Path(__file__).resolve(),
                           {}, "FAIL", "verdict.value", [blocked_row])
    check("aggregate-fail-not-refused", aggregate["refusal"] is None, aggregate)

    # 7. Determinism: the real documents are byte-stable over two builds.
    commit = _check_commit(REPO_ROOT)
    first = build_documents(commit)
    second = build_documents(commit)
    first_bytes = tuple(
        json.dumps(doc, indent=2, sort_keys=True).encode() for doc in first)
    second_bytes = tuple(
        json.dumps(doc, indent=2, sort_keys=True).encode() for doc in second)
    check("deterministic", first_bytes == second_bytes, "two builds differ")
    check("deterministic-aggregates",
          json.dumps(audit_aggregates(), sort_keys=True)
          == json.dumps(audit_aggregates(), sort_keys=True),
          "aggregate audits differ")

    if failures:
        for failure in failures:
            print(f"FAIL {failure}", file=sys.stderr)
        return 1
    print(f"closure discipline self-test: {7} control groups passed")
    return 0


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def _emit(payload) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command")

    audit = sub.add_parser("audit")
    audit.add_argument("--receipt", required=True)
    audit.add_argument("--consumer", default=None)
    audit.add_argument("--commit", default=None)

    aggregate = sub.add_parser("aggregate")
    aggregate.add_argument("--name", default=None)

    emit = sub.add_parser("emit")
    emit.add_argument("--commit", default=None)

    check = sub.add_parser("check")
    check.add_argument("--commit", default=None)

    parser.add_argument("--self-test", action="store_true")

    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    if args.command == "audit":
        result = audit_receipt_path(
            Path(args.receipt), consumer=args.consumer, commit=args.commit)
        _emit(result)
        return 0 if result["exclusions_failing"] == 0 else 1

    if args.command == "aggregate":
        aggregates = audit_aggregates()
        if args.name:
            selected = [a for a in aggregates["aggregates"]
                        if a["aggregate"] == args.name]
            if not selected:
                print(f"unknown aggregate {args.name!r}", file=sys.stderr)
                return 2
            _emit(selected[0])
            return 0 if selected[0]["refusal"] is None else 1
        _emit(aggregates)
        return 0 if aggregates["refusal_count"] == 0 else 1

    if args.command == "emit":
        written = write_documents(args.commit)
        exclusions = _load(EVIDENCE_DIR / "EXCLUSIONS.json")
        opaque = _load(EVIDENCE_DIR / "OPAQUE-OPERATIONS.json")
        _emit({
            "written": written,
            "exclusion_rows": exclusions["exclusion_rows"],
            "exclusions_failing": exclusions["exclusions_failing"],
            "opaque_rows": opaque["totals"]["operation_rows"],
            "opaque_unscoped_rows": opaque["totals"]["unscoped_contract_rows"],
        })
        return 0

    if args.command == "check":
        commit = args.commit or _check_commit(REPO_ROOT)
        exclusions_doc, opaque_doc = build_documents(commit)
        aggregates = audit_aggregates()
        summary = {
            "commit": commit,
            "exclusion_rows": exclusions_doc["exclusion_rows"],
            "exclusions_failing": exclusions_doc["exclusions_failing"],
            "exclusions_failing_by_consumer": {
                name: data["exclusions_failing"]
                for name, data in exclusions_doc["consumers"].items()},
            "opaque_unscoped_rows": opaque_doc["totals"]["unscoped_contract_rows"],
            "opaque_unscoped_sites": opaque_doc["totals"]["unscoped_contract_sites"],
            "aggregate_refusals": aggregates["refusals"],
        }
        _emit(summary)
        return 0 if (exclusions_doc["exclusions_failing"] == 0
                     and aggregates["refusal_count"] == 0) else 1

    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
