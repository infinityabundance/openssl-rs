#!/usr/bin/env python3
"""Re-validate committed evidence under the omission-resistance rules.

The ETP-5 probe documents are read exactly as tracked; this tool never rewrites
them. It re-runs the validator over them, then derives four additional typed
documents in memory to show that the new rules fire on the claim shapes the
probes describe:

  * F1: the withdrawn O7 revision and the element-7 triage declare a state that
    cannot support a positive verdict, once the state is copied from the tracked
    artefact into the evidence record.
  * F3: the O7 aggregate names no cell receipt digests and is refused as
    unbound; a cell digest that disagrees with the tracked receipt is refused.
  * F4: the two counter readings are typed from the tracked ledger, and their
    disagreement is refused; the same measures left as free text are refused as
    untyped.

Output is sorted and carries no timestamp, so repeated runs are byte-identical.
Run from any directory with the court's Python 3.11:

    python3 evidence/etp/omission/revalidate.py --out evidence/etp/omission/REVALIDATION.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TOOLS = ROOT / "forensics/tools"
sys.path.insert(0, str(TOOLS))

import etp_claims  # noqa: E402

SCHEMA = etp_claims.load_json(etp_claims.DEFAULT_SCHEMA)
PROBES = ROOT / "evidence/etp5/probes"
CLAIMS = etp_claims.DEFAULT_CLAIMS
WITHDRAWN_CLAIM = PROBES / "p4a-withdrawn-o7-historical-accepted.json"
ELEMENT7_CLAIM = PROBES / "p6-curl-element7-closed.json"
COUNTER_CLAIM = PROBES / "p3c-counter-two-established.json"
O7_AGGREGATE = ROOT / "courts/phase18/interop/RECEIPT-o7.json"
O7_CELLS = {
    "AA": ROOT / "courts/phase18/interop/RECEIPT-o7-AA.json",
    "AB": ROOT / "courts/phase18/interop/RECEIPT-o7-AB.json",
    "BA": ROOT / "courts/phase18/interop/RECEIPT-o7-BA.json",
    "BB": ROOT / "courts/phase18/interop/RECEIPT-o7-BB.json",
}
STATUS = ROOT / "forensics/memory-safety/campaign/safe-c33/CAMPAIGN-STATUS.json"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def summarise(doc: dict) -> dict:
    refusals = etp_claims.validate_document(doc, SCHEMA, repo_root=ROOT)
    by_rule: dict[str, int] = {}
    for refusal in refusals:
        by_rule[refusal["rule"]] = by_rule.get(refusal["rule"], 0) + 1
    return {
        "valid": not refusals,
        "refusal_count": len(refusals),
        "refusals_by_rule": by_rule,
        "refusals": refusals,
    }


def unchanged(doc: dict, expected_rule: str, source: str) -> dict:
    result = summarise(doc)
    return {
        "source": source,
        "expected_rule": expected_rule,
        "fired": expected_rule in result["refusals_by_rule"],
        **result,
    }


def f1_withdrawn() -> dict:
    doc = etp_claims.load_json(WITHDRAWN_CLAIM)
    claim = doc["claims"][0]
    claim["evidence"][0]["state"] = {
        "value": "WITHDRAWN",
        "artefact": "courts/phase18/interop/RECEIPT-o7.json",
        "revision": "cc2e5fa32",
    }
    return unchanged(
        doc,
        "EG_EVIDENCE_CONTRADICTS_VERDICT",
        "evidence/etp5/probes/p4a-withdrawn-o7-historical-accepted.json",
    )


def f1_element7() -> dict:
    doc = etp_claims.load_json(ELEMENT7_CLAIM)
    claim = doc["claims"][0]
    for entry in claim["evidence"]:
        if entry["path"] == "evidence/element7-curl-049-triage.json":
            entry["state"] = {
                "value": "NOT_ESTABLISHED",
                "artefact": "evidence/element7-curl-049-triage.json",
                "revision": "tracked",
            }
    return unchanged(
        doc,
        "EG_EVIDENCE_CONTRADICTS_VERDICT",
        "evidence/etp5/probes/p6-curl-element7-closed.json",
    )


def _counter(value: str) -> dict:
    numerator, denominator = value.split("/")
    return {
        "name": "safe_compatible_counter",
        "counter": {
            "numerator": int(numerator),
            "denominator": int(denominator),
        },
        "aggregation": "forbidden",
    }


def _ledger_readings() -> tuple[list[str], dict]:
    """The two counter readings the tracked ledger itself states.

    `consumers.safe_compatible` is 1, while `consumers.note` says the counter
    remains 0/33. Both readings are copied from the tracked record; neither is
    inferred from a claim.
    """
    ledger = etp_claims.load_json(STATUS)
    consumers = ledger.get("consumers", {})
    total = consumers.get("families_total")
    positive = consumers.get("safe_compatible")
    note = str(consumers.get("note", ""))
    zero = re.search(r"SAFE_COMPATIBLE remains (\d+)\s*/\s*(\d+)", note)
    if not isinstance(total, int) or not isinstance(positive, int) or zero is None:
        raise SystemExit("the tracked ledger no longer states both counter readings")
    return [f"{positive}/{total}", f"{zero.group(1)}/{zero.group(2)}"], {
        "consumers.safe_compatible": positive,
        "consumers.families_total": total,
        "consumers.note": zero.group(0),
    }


def f4_typed() -> dict:
    doc = etp_claims.load_json(COUNTER_CLAIM)
    readings, ledger = _ledger_readings()
    for claim, reading in zip(doc["claims"], readings):
        claim["quantification"]["measure"] = _counter(reading)
    result = unchanged(
        doc,
        "EG_CONTRADICTION_UNRESOLVED",
        "evidence/etp5/probes/p3c-counter-two-established.json",
    )
    result["typed_readings"] = readings
    result["ledger_readings"] = ledger
    result["ledger_path"] = str(STATUS.relative_to(ROOT))
    result["conjoin"] = etp_claims.conjoin(doc["claims"])
    return result


def f4_untyped() -> dict:
    doc = etp_claims.load_json(COUNTER_CLAIM)
    for claim in doc["claims"]:
        measure = claim["quantification"]["measure"]
        claim["quantification"]["measure"] = {
            "name": "safe_compatible_counter",
            "value": measure["value"],
            "aggregation": "forbidden",
        }
    return unchanged(
        doc,
        "EG_MEASURE_UNTYPED",
        "evidence/etp5/probes/p3c-counter-two-established.json",
    )


def _aggregate_doc(cells: list[dict] | None) -> dict:
    doc = etp_claims.load_json(WITHDRAWN_CLAIM)
    claim = doc["claims"][0]
    claim["evidence"][0].pop("state", None)
    aggregate: dict = {"summarises_cells": True}
    if cells is not None:
        aggregate["cells"] = cells
    claim["aggregate_cells"] = aggregate
    return doc


def f3_unbound() -> dict:
    return unchanged(
        _aggregate_doc(None),
        "EG_AGGREGATE_UNBOUND",
        "courts/phase18/interop/RECEIPT-o7.json",
    )


def f3_mismatch() -> dict:
    aggregate = etp_claims.load_json(O7_AGGREGATE)
    aggregate_bb_log = aggregate["cells"]["BB"]["log_sha256"]
    cells = [
        {
            "id": "BB",
            "receipt_path": str(O7_CELLS["BB"].relative_to(ROOT)),
            "receipt_sha256": aggregate_bb_log,
        }
    ]
    return unchanged(
        _aggregate_doc(cells),
        "EG_AGGREGATE_DIGEST_MISMATCH",
        "courts/phase18/interop/RECEIPT-o7.json cells.BB.log_sha256",
    )


def f3_bound() -> dict:
    cells = [
        {
            "id": cell_id,
            "receipt_path": str(path.relative_to(ROOT)),
            "receipt_sha256": digest(path),
        }
        for cell_id, path in sorted(O7_CELLS.items())
    ]
    result = summarise(_aggregate_doc(cells))
    result["cell_receipts"] = {
        cell["id"]: cell["receipt_sha256"] for cell in cells
    }
    return {
        "source": "courts/phase18/interop/RECEIPT-o7-{AA,AB,BA,BB}.json",
        "expected_rule": None,
        "fired": False,
        **result,
    }


def probes() -> dict:
    found: dict[str, dict] = {}
    for path in sorted(PROBES.glob("*.json")):
        result = summarise(etp_claims.load_json(path))
        found[path.name] = {
            "valid": result["valid"],
            "refusal_count": result["refusal_count"],
            "refusals_by_rule": result["refusals_by_rule"],
        }
    return found


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", default=None)
    args = parser.parse_args(argv)

    committed = summarise(etp_claims.load_json(CLAIMS))
    payload = {
        "schema": "openssl-rs/etp/omission/revalidation/v1",
        "validator": "forensics/tools/etp_claims.py",
        "validator_sha256": hashlib.sha256(
            (TOOLS / "etp_claims.py").read_bytes()
        ).hexdigest(),
        "source_identity": {
            "claims_document": "evidence/etp/claims.json",
            "claims_source_commit": etp_claims.load_json(CLAIMS)["source_identity"][
                "commit"
            ],
            "probe_inputs": "evidence/etp5/probes (read-only)",
            "ledger": str(STATUS.relative_to(ROOT)),
        },
        "committed": {
            "document": "evidence/etp/claims.json",
            "claims": len(etp_claims.load_json(CLAIMS)["claims"]),
            "valid": committed["valid"],
            "refusal_count": committed["refusal_count"],
            "refusals_by_rule": committed["refusals_by_rule"],
        },
        "probes": probes(),
        "derived": {
            "F1-withdrawn-o7": f1_withdrawn(),
            "F1-element7-not-established": f1_element7(),
            "F3-aggregate-unbound": f3_unbound(),
            "F3-aggregate-digest-mismatch": f3_mismatch(),
            "F3-aggregate-bound": f3_bound(),
            "F4-counter-typed": f4_typed(),
            "F4-counter-untyped": f4_untyped(),
        },
    }
    text = json.dumps(payload, sort_keys=True, indent=1) + "\n"
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
