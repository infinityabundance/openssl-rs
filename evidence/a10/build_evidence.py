#!/usr/bin/env python3
"""build_evidence.py -- produce the A10 DSSE envelope evidence.

The producer of `evidence/a10/ENVELOPES/`, `evidence/a10/ENVELOPES.json`,
`evidence/a10/CONTROLS.json` and `evidence/a10/PAE-VECTOR.txt`.

For each of the four A9 statements it signs the **exact committed bytes** with the
test-only HMAC-SHA256 signer from `forensics/tools/dsse.py`, writes the envelope,
verifies it against its own PAE over the received bytes, and records the payload,
PAE and envelope digests. Every digest is computed from the bytes; none is typed.

The key is derived from a fixed public seed and is labelled `test-only`. It
establishes framing and PAE only. It is not a trust root, `keyid` is an
unauthenticated hint, and authenticity, identity, authorisation and transparency
are A12/A14/A16/A17's.

The producer also asserts the DSSE specification's PAE vector and builds the
thirteen negative controls, reading every refusal code from the tool.

Usage:
    python3 evidence/a10/build_evidence.py [--source-commit TOKEN] [--out DIR]

Re-running at one source identity reproduces every envelope byte and digest.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS = REPO_ROOT / "forensics" / "tools"
sys.path.insert(0, str(TOOLS))

import dsse as d  # noqa: E402
import intoto  # noqa: E402

OUT_DIR = Path(__file__).resolve().parent

PAYLOAD_TYPE = d.IN_TOTO_PAYLOAD_TYPE

SPEC_VECTOR = {
    "payloadType": "http://example.com/HelloWorld",
    "body": b"hello world",
    "expected": b"DSSEv1 29 http://example.com/HelloWorld 11 hello world",
}

STATEMENTS = (
    ("a1-sarif", "evidence/a9/STATEMENTS/a1-sarif.json"),
    ("a5-admission", "evidence/a9/STATEMENTS/a5-admission.json"),
    ("a7-delta", "evidence/a9/STATEMENTS/a7-delta.json"),
    ("a8-shard-000", "evidence/a9/STATEMENTS/a8-shard-000.json"),
)

INPUTS = tuple(path for _name, path in STATEMENTS) + (
    "forensics/tools/dsse.py",
    "forensics/tools/intoto.py",
)


def _git(repo_root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repo_root), *args], capture_output=True, check=False
    )
    if completed.returncode != 0:
        return ""
    return completed.stdout.decode("utf-8", "replace").strip()


def _recorded_commit(index_path: Path) -> str | None:
    if not index_path.is_file():
        return None
    try:
        document = json.loads(index_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    identity = document.get("sourceIdentity")
    if isinstance(identity, dict) and isinstance(identity.get("commit"), str):
        return identity["commit"]
    return None


def source_identity(repo_root: Path, commit: str) -> dict[str, Any]:
    as_of = _git(repo_root, "show", "-s", "--format=%cs", commit)
    if not as_of:
        raise AssertionError(f"the source commit {commit!r} is not readable")
    inputs = []
    for relative in INPUTS:
        path = repo_root / relative
        if not path.is_file():
            raise AssertionError(f"the measured input {relative} is absent")
        inputs.append({"path": relative, "sha256": d.sha256_bytes(path.read_bytes())})
    return {"asOf": as_of, "commit": commit, "inputs": inputs}


def pae_vector() -> dict[str, Any]:
    payload_type = SPEC_VECTOR["payloadType"]
    body = SPEC_VECTOR["body"]
    expected = SPEC_VECTOR["expected"]
    produced = d.pae(payload_type, body)
    if produced != expected:
        raise AssertionError(f"the PAE vector is {produced!r}, expected {expected!r}")
    parsed_type, parsed_body = d.parse_pae(expected)
    if (parsed_type, parsed_body) != (payload_type, body):
        raise AssertionError("the PAE vector does not parse to its own fields")
    return {
        "payloadType": payload_type,
        "typeLength": len(payload_type.encode("utf-8")),
        "bodyText": body.decode("utf-8"),
        "bodyLength": len(body),
        "expectedText": expected.decode("utf-8"),
        "expectedHex": expected.hex(),
        "sha256": d.sha256_bytes(expected),
        "source": (
            "DSSE specification, Protocol Definition, Pre-Authentication Encoding "
            "example"
        ),
    }


def build_envelopes(repo_root: Path) -> tuple[dict[str, bytes], list[dict[str, Any]]]:
    files: dict[str, bytes] = {}
    entries: list[dict[str, Any]] = []
    signer = d.test_only_signer()
    for name, statement_path in STATEMENTS:
        path = repo_root / statement_path
        if not path.is_file():
            raise AssertionError(f"the A9 statement {statement_path} is absent")
        payload = path.read_bytes()
        document = d.envelope(PAYLOAD_TYPE, payload, signer)
        envelope_bytes = d.encode_envelope(document)
        relative = f"ENVELOPES/{name}.json"
        files[relative] = envelope_bytes
        report = d.verify_pae(
            envelope_bytes,
            d.test_only_verifier(),
            expected_payload_type=PAYLOAD_TYPE,
            require_statement=True,
        )
        if report["payload"] != payload:
            raise AssertionError(f"{name}: verification did not return the received bytes")
        statement = report["statement"]
        if statement is None:
            raise AssertionError(f"{name}: the payload was not decoded as a statement")
        encoded = intoto.encode(statement).encode("utf-8")
        if encoded != payload:
            raise AssertionError(f"{name}: the decoded statement is not the payload")
        entries.append(
            {
                "name": name,
                "statement": statement_path,
                "envelope": relative,
                "payloadType": report["payloadType"],
                "payloadBytes": len(payload),
                "payloadSha256": d.sha256_bytes(payload),
                "paeSha256": report["paeSha256"],
                "envelopeSha256": d.sha256_bytes(envelope_bytes),
                "keyid": report["keyid"],
                "signer": d.TEST_ONLY_SIGNER_LABEL,
                "statementSha256": d.sha256_bytes(encoded),
                "statementMatchesPayload": encoded == payload,
            }
        )
    return files, entries


def _code(action: Callable[[], Any]) -> tuple[str, str]:
    try:
        action()
    except d.Refusal as refusal:
        return refusal.code, refusal.message
    raise AssertionError("the attempt was not refused")


def build_controls(repo_root: Path) -> dict[str, Any]:
    statement = (repo_root / "evidence/a9/STATEMENTS/a1-sarif.json").read_bytes()
    signer = d.test_only_signer()
    verifier = d.test_only_verifier()
    base = d.envelope(PAYLOAD_TYPE, statement, signer)
    base_bytes = d.encode_envelope(base)

    def mutated(**changes: Any) -> bytes:
        document = json.loads(base_bytes)
        document.update(changes)
        return d.encode_envelope(document)

    def without(field: str) -> bytes:
        document = json.loads(base_bytes)
        document.pop(field)
        return d.encode_envelope(document)

    canonical_body = b'{"hello":"world"}'
    pretty_body = b'{"hello": "world"}'
    reserialised = d.envelope(PAYLOAD_TYPE, canonical_body, signer)
    reserialised["payload"] = d.strict_b64encode(pretty_body)
    not_statement = d.envelope(PAYLOAD_TYPE, canonical_body, signer)

    unsigned = d.strict_b64decode(base["signatures"][0]["sig"], "control.sig")
    invalid_signature = bytes([unsigned[0] ^ 0x01]) + unsigned[1:]
    unpadded_envelope = d.envelope(PAYLOAD_TYPE, b"{}", signer)
    unpadded_envelope["payload"] = unpadded_envelope["payload"].rstrip("=")

    controls: list[tuple[str, str, Callable[[], Any]]] = [
        (
            "invalid-envelope",
            d.DS_REFUSED_ENVELOPE_INVALID,
            lambda: d.verify_pae(mutated(payloadType=1), verifier),
        ),
        (
            "duplicate-key",
            d.DS_REFUSED_DUPLICATE_KEY,
            lambda: d.verify_pae(
                b'{"payloadType":"a","payloadType":"b","payload":"e30=",'
                b'"signatures":[{"keyid":"k","sig":"eA=="}]}',
                verifier,
            ),
        ),
        (
            "missing-payload-type",
            d.DS_REFUSED_PAYLOAD_TYPE_MISSING,
            lambda: d.verify_pae(without("payloadType"), verifier),
        ),
        (
            "type-mismatch",
            d.DS_REFUSED_PAYLOAD_TYPE_MISMATCH,
            lambda: d.verify_pae(
                base_bytes,
                verifier,
                expected_payload_type="application/vnd.example.other+json",
            ),
        ),
        (
            "noncanonical-base64",
            d.DS_REFUSED_BASE64_NONCANONICAL,
            lambda: d.verify_pae(d.encode_envelope(unpadded_envelope), verifier),
        ),
        (
            "missing-payload",
            d.DS_REFUSED_PAYLOAD_ABSENT,
            lambda: d.verify_pae(without("payload"), verifier),
        ),
        (
            "missing-signatures",
            d.DS_REFUSED_SIGNATURES_ABSENT,
            lambda: d.verify_pae(without("signatures"), verifier),
        ),
        (
            "bad-signature",
            d.DS_REFUSED_SIGNATURE_INVALID,
            lambda: d.verify_pae(
                mutated(
                    signatures=[
                        {
                            "keyid": base["signatures"][0]["keyid"],
                            "sig": d.strict_b64encode(invalid_signature),
                        }
                    ]
                ),
                verifier,
            ),
        ),
        (
            "reserialised-payload",
            d.DS_REFUSED_PAE_RESERIALISED,
            lambda: d.verify_pae(d.encode_envelope(reserialised), verifier),
        ),
        (
            "wrong-pae-length",
            d.DS_REFUSED_PAE_LENGTH,
            lambda: d.parse_pae(
                b"DSSEv1 29 http://example.com/HelloWorld 12 hello world"
            ),
        ),
        (
            "payload-not-statement",
            d.DS_REFUSED_PAYLOAD_NOT_STATEMENT,
            lambda: d.verify_pae(
                d.encode_envelope(not_statement), verifier, require_statement=True
            ),
        ),
        (
            "trailing-bytes",
            d.DS_REFUSED_TRAILING_BYTES,
            lambda: d.verify_pae(base_bytes + b' {"extra":true}', verifier),
        ),
        (
            "object-supplied",
            d.DS_REFUSED_OBJECT_SUPPLIED,
            lambda: d.verify_pae(json.loads(base_bytes), verifier),
        ),
    ]

    recorded = []
    for name, expected, action in controls:
        observed, message = _code(action)
        if observed != expected:
            raise AssertionError(f"{name}: {observed} fired, expected {expected}")
        recorded.append(
            {
                "control": name,
                "code": observed,
                "prevents": d.REFUSALS[observed]["prevents"],
                "observed": message,
            }
        )
    return {
        "schema": d.CONTROLS_SCHEMA,
        "item": "A10",
        "model": d.MODEL_ID,
        "codes": {code: d.REFUSALS[code] for code in sorted(d.REFUSALS)},
        "controls": recorded,
        "counts": {
            "codes": len(d.REFUSALS),
            "controls": len(recorded),
            "fired": len(recorded),
        },
    }


def build(repo_root: Path, commit: str, out: Path) -> dict[str, Any]:
    files, entries = build_envelopes(repo_root)
    controls = build_controls(repo_root)
    vector = pae_vector()
    index = {
        "schema": d.ENVELOPE_SCHEMA,
        "item": "A10",
        "model": d.MODEL_ID,
        "payloadType": PAYLOAD_TYPE,
        "signer": {
            "label": d.TEST_ONLY_SIGNER_LABEL,
            "keyid": d.test_only_keyid(),
            "seedHex": d.TEST_ONLY_SEED.hex(),
            "establishes": [
                "the envelope frames the exact statement bytes",
                "the PAE is over the decoded bytes as received",
                "a test-only HMAC-SHA256 signature verifies over that PAE",
            ],
            "doesNotEstablish": [
                "authenticity: the key is a fixed public test seed, not a trust root",
                "identity: keyid is an unauthenticated hint",
                "authorisation: role binding is A14",
                "transparency: A17",
                "independent cryptographic verification: A12",
            ],
        },
        "paeVector": vector,
        "envelopes": entries,
        "counts": {
            "statements": len(STATEMENTS),
            "envelopes": len(entries),
            "controls": len(controls["controls"]),
            "refusalCodes": len(d.REFUSALS),
        },
        "sourceIdentity": source_identity(repo_root, commit),
    }
    out.mkdir(parents=True, exist_ok=True)
    (out / "ENVELOPES").mkdir(exist_ok=True)
    for relative, content in files.items():
        (out / relative).write_bytes(content)
    (out / "ENVELOPES.json").write_text(
        json.dumps(index, indent=1, sort_keys=True) + "\n", encoding="utf-8"
    )
    (out / "CONTROLS.json").write_text(
        json.dumps(controls, indent=1, sort_keys=True) + "\n", encoding="utf-8"
    )
    (out / "PAE-VECTOR.txt").write_bytes(vector["expectedHex"].encode("ascii") + b"\n")
    return index


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="build_evidence.py")
    parser.add_argument("--repo-root", default=str(REPO_ROOT))
    parser.add_argument("--out", default=str(OUT_DIR))
    parser.add_argument("--source-commit", default=None)
    parsed = parser.parse_args(argv)
    repo_root = Path(parsed.repo_root)
    out = Path(parsed.out)
    commit = parsed.source_commit or _recorded_commit(out / "ENVELOPES.json")
    if commit is None:
        commit = _git(repo_root, "rev-parse", "--short=9", "HEAD")
    if not commit:
        print("DS_REFUSED_ENVELOPE_INVALID: no source commit", file=sys.stderr)
        return 2
    try:
        index = build(repo_root, commit, out)
    except d.Refusal as refusal:
        print(f"{refusal}", file=sys.stderr)
        return 2
    except AssertionError as error:
        print(f"DS_REFUSED_ENVELOPE_INVALID: {error}", file=sys.stderr)
        return 2
    print(
        "envelopes={envelopes} statements={statements} controls={controls} "
        "codes={refusalCodes} commit={commit}".format(
            commit=commit, **index["counts"]
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
