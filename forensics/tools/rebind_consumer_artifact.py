#!/usr/bin/env python3
"""Per-artefact ledger binding for a consumer-closure receipt.

The problem this fixes
----------------------
``consumer_closure.py`` binds a closure to one build-link atlas row selected by
``family:<family>``.  Both ``ssh`` and ``sshd`` belong to family ``openssh``,
but that single row records ``linkage.artifact_sha256 = <sha256 of ssh>``.  A
second artefact from the same recipe (``sshd``) therefore cannot match the row,
and its receipt records ``artifact_matches_this_build: false`` even when the
artefact is the one the same freeze built.

This tool performs the honest per-artefact join **after** a closure run.  It
does not re-analyse the binary, re-adjudicate obligations, or change any count,
verdict or refusal: it verifies that the analysed artefact is the exact artefact
the freeze records at the same source and recipe, and then replaces only the
ledger binding.  The original receipt is preserved by writing a new file.

It must refuse rather than guess.  Every check below is a refusal condition.

The output is explicitly marked ``not_a_closure_run``.  A fresh closure run is
still required for final evidence; this only removes the structural
one-row-cannot-bind-two-artefacts defect.
"""
import argparse
import copy
import json
import sys
from pathlib import Path

SCHEMA = "openssl-rs/campaign/safe-c33/consumer-artifact-rebind/v1"


class Refusal(Exception):
    pass


def load(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        raise Refusal(f"{path} does not exist")
    except json.JSONDecodeError as exc:
        raise Refusal(f"{path} is not JSON: {exc}")


def require(condition, message):
    if not condition:
        raise Refusal(message)


def verify(receipt: dict, ledger: dict, freeze: dict) -> dict:
    """Return the check table.  Raise Refusal on the first failed check."""
    checks = {}

    require(str(receipt.get("schema", "")).startswith(
        "openssl-rs/campaign/safe-c33/consumer-closure/"),
        "receipt is not a consumer-closure receipt")
    artifact = receipt.get("artifact_identity") or {}
    artifact_sha = artifact.get("sha256")
    require(artifact_sha, "receipt has no artifact_identity.sha256")
    require(ledger.get("artifact_sha256") == artifact_sha,
            "ledger artifact_sha256 does not match the analysed artefact")
    checks["artifact_sha256_matches"] = True

    require(ledger.get("family_id") == receipt.get("family"),
            "ledger family_id does not match the receipt family")
    checks["family_matches"] = True

    artifact_rel = ledger.get("artifact_rel")
    require(artifact_rel, "ledger has no artifact_rel")
    require(Path(str(artifact.get("path", ""))).name == artifact_rel,
            "artifact_rel does not name the analysed executable")
    checks["artifact_rel_matches"] = True

    files = ((freeze.get("artefacts") or {}).get("files") or {})
    frozen = (files.get(artifact_rel) or {}).get("sha256")
    require(frozen == artifact_sha,
            f"freeze records a different sha256 for {artifact_rel}")
    checks["freeze_artifact_matches"] = True

    install_sha = ledger.get("install_libcrypto_sha256")
    if install_sha:
        require(
            ((freeze.get("candidate_identity") or {}).get("libcrypto_so_3_sha256")
             == install_sha),
            "freeze libcrypto does not match the ledger install")
        checks["freeze_libcrypto_matches"] = True

    source_head = (freeze.get("source") or {}).get("head")
    inventory_head = (receipt.get("source_identity") or {}).get(
        "inventory_source_head")
    if source_head and inventory_head:
        require(source_head == inventory_head,
                "freeze source head does not match the receipt inventory source head")
        checks["freeze_source_matches"] = True

    old = receipt.get("ledger_record") or {}
    for field in ("recipe_id", "source_sha256"):
        if old.get(field) and ledger.get(field):
            require(old[field] == ledger[field],
                    f"ledger {field} differs from the closure's recipe/source")
            checks[f"{field}_matches"] = True

    return checks


def rebind(receipt: dict, ledger: dict, freeze: dict, ledger_path: str) -> dict:
    checks = verify(receipt, ledger, freeze)
    out = copy.deepcopy(receipt)
    old = out.get("ledger_record") or {}
    new = {
        "run_id": ledger.get("run_id"),
        "level": ledger.get("level"),
        "outcome": ledger.get("outcome"),
        "recipe_id": ledger.get("recipe_id"),
        "source_sha256": ledger.get("source_sha256"),
        "source_root_hash": ledger.get("source_root_hash"),
        "source_root_hash_rule": ledger.get("source_root_hash_rule"),
        "source_tree_domain_hash": ledger.get("source_tree_domain_hash"),
        "artifact_rel": ledger.get("artifact_rel"),
        "artifact_sha256_recorded": ledger.get("artifact_sha256"),
        "recorded_candidate_install": ledger.get("recorded_candidate_install"),
        "frozen_install_libcrypto_sha256": ledger.get("install_libcrypto_sha256"),
        "artifact_matches_this_build": True,
        "ledger_source": ledger_path,
    }
    out["ledger_record"] = new
    out["rebind"] = {
        "schema": SCHEMA,
        "not_a_closure_run": True,
        "ledger_source": ledger_path,
        "freeze": ledger.get("freeze"),
        "original_ledger_record": old,
        "checks": checks,
        "witness": ledger.get("witness"),
        "note": ("a per-artefact ledger join: the closure's counts, verdict, refusals "
                 "and obligations are unchanged; only the ledger binding is replaced. "
                 "A fresh closure run is still required for final evidence."),
    }
    return out


def self_test() -> int:
    receipt = {
        "schema": "openssl-rs/campaign/safe-c33/consumer-closure/v2",
        "family": "openssh",
        "source_identity": {"inventory_source_head": "15bebabc9"},
        "artifact_identity": {"path": "/tmp/build/sshd", "sha256": "64e0a4cc"},
        "ledger_record": {"recipe_id": "recipe:openssh:9.9p1",
                          "source_sha256": "b343fbcd"},
        "counts": {"DISCHARGED": 321, "BLOCKED": 2},
        "verdict": {"state": "ACCEPTED", "safe_compatible": False},
    }
    ledger = {
        "family_id": "openssh", "run_id": "run:sshd", "level": "L4-linked",
        "outcome": "reached", "recipe_id": "recipe:openssh:9.9p1",
        "source_sha256": "b343fbcd", "artifact_rel": "sshd",
        "artifact_sha256": "64e0a4cc", "install_libcrypto_sha256": "e8a90ba4",
        "freeze": "FREEZE.json", "witness": "freeze records sshd",
    }
    freeze = {
        "source": {"head": "15bebabc9"},
        "candidate_identity": {"libcrypto_so_3_sha256": "e8a90ba4"},
        "artefacts": {"files": {"sshd": {"sha256": "64e0a4cc"},
                                "ssh": {"sha256": "bff896e3"}}},
    }
    result = rebind(receipt, ledger, freeze, "sidecar.json")
    assert result["ledger_record"]["artifact_matches_this_build"] is True
    assert result["artifact_identity"] == receipt["artifact_identity"]
    assert result["counts"] == receipt["counts"]
    assert result["verdict"] == receipt["verdict"]
    assert result["rebind"]["not_a_closure_run"] is True

    def refuses(label, mutate, expected):
        r = copy.deepcopy(receipt)
        l = copy.deepcopy(ledger)
        f = copy.deepcopy(freeze)
        mutate(r, l, f)
        try:
            verify(r, l, f)
        except Refusal as exc:
            assert expected in str(exc), (label, str(exc))
            return
        raise AssertionError(f"{label} was accepted")

    refuses("wrong artifact hash", lambda r, l, f: l.update(artifact_sha256="deadbeef"),
            "does not match the analysed artefact")
    refuses("wrong family", lambda r, l, f: l.update(family_id="openssl"),
            "does not match the receipt family")
    refuses("wrong rel", lambda r, l, f: l.update(artifact_rel="ssh"),
            "does not name the analysed executable")
    refuses("freeze mismatch", lambda r, l, f: f["artefacts"]["files"]["sshd"].update(
        sha256="deadbeef"), "freeze records a different sha256")
    refuses("libcrypto mismatch", lambda r, l, f: f["candidate_identity"].update(
        libcrypto_so_3_sha256="deadbeef"), "freeze libcrypto does not match")
    refuses("source mismatch", lambda r, l, f: f["source"].update(head="deadbeef"),
            "freeze source head does not match")
    refuses("recipe mismatch", lambda r, l, f: l.update(recipe_id="recipe:other"),
            "differs from the closure's recipe/source")
    refuses("source sha mismatch", lambda r, l, f: l.update(source_sha256="deadbeef"),
            "differs from the closure's recipe/source")
    print("self-test ok: positive binding plus 8 refusal controls")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt")
    parser.add_argument("--artifact-ledger")
    parser.add_argument("--freeze")
    parser.add_argument("--out")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    if not all((args.receipt, args.artifact_ledger, args.freeze, args.out)):
        parser.error("--receipt, --artifact-ledger, --freeze and --out are required")
    try:
        receipt = load(Path(args.receipt))
        ledger = load(Path(args.artifact_ledger))
        freeze = load(Path(args.freeze))
        out = rebind(receipt, ledger, freeze, args.artifact_ledger)
    except Refusal as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2
    dest = Path(args.out)
    if dest.exists() and not args.force:
        print(f"REFUSED: {dest} exists (use --force)", file=sys.stderr)
        return 2
    dest.write_text(json.dumps(out, indent=1) + "\n")
    print(f"wrote {dest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
