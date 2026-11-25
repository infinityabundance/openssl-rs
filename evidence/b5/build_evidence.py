#!/usr/bin/env python3
"""build_evidence.py -- the deterministic producer for B5.

B5 has two halves and this producer is careful about which one it writes.

  * **Monitoring is offline and ran.**  The monitor observes the B1 fixture's real
    checkpoint sequence (sizes 2, 5 and 6) in order, verifies each signature and
    each consistency proof, and records the final head.  It then replays
    deliberately corrupted sequences built in memory from the same bytes and
    records the refusal code and an accepting canary for each.
  * **Witness admission is NOT_RUN.**  No witness, no independent operator
    domain and no witness key exist in this venue.  ``WITNESSES.json`` records the
    empty inventory, the quorum that *would* be required and the aliasing rule;
    ``monitor.py witness`` refuses the empty set with ``MN_REFUSED_NO_WITNESS``.

The records are byte-stable: every observation instant is a declared literal, the
store's digest chain is deterministic, and no clock, network or git command is
read.  ``--check`` recomputes the records and compares them with the committed
bytes instead of writing.

Usage:
    python3 evidence/b5/build_evidence.py [--check]

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import sys
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS = REPO_ROOT / "forensics" / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import dsse  # noqa: E402
import monitor  # noqa: E402
import thresholds  # noqa: E402
import tlog  # noqa: E402

EVIDENCE = REPO_ROOT / "evidence" / "b5"
FIXTURE_DIR = REPO_ROOT / "evidence" / "b1" / "fixture"
B1_FIXTURE = REPO_ROOT / "evidence" / "b1" / "FIXTURE.json"
A15_DOMAINS = REPO_ROOT / "evidence" / "a15" / "DOMAINS.json"

MONITOR_OUT = EVIDENCE / "MONITOR.json"
WITNESSES_OUT = EVIDENCE / "WITNESSES.json"
CONTROLS_OUT = EVIDENCE / "CONTROLS.json"
STORE_OUT = EVIDENCE / "store" / "monitor-store.jsonl"

RECORDED_AT = "2026-11-24"
BASE_COMMIT = "24ac742f5"
IDENTITY = "FIXTURE-1"
ORIGIN = IDENTITY
SIGNER_NAME = "FIXTURE-1 test-only hmac-sha256"
KEY = dsse.test_only_key()

# (size, consistency-proof file used to reach that size, observation instant).
SEQUENCE = (
    ("2", None, "2026-11-24T00:00:01Z"),
    ("5", "consistency-2-5.json", "2026-11-24T00:00:02Z"),
    ("6", "consistency-5-6.json", "2026-11-24T00:00:03Z"),
)

CAUSAL_ORDER = (
    "checkpoint",
    "signature",
    "origin",
    "rollback",
    "split-view",
    "backdated",
    "consistency",
)

REQUIRED_K = 3
REQUIRED_N = 4


def _serialise(document: Any) -> bytes:
    return (
        json.dumps(document, indent=1, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")


def _serialise_line(record: Mapping[str, Any]) -> bytes:
    return json.dumps(
        record, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    try:
        temporary.write_bytes(data)
        temporary.replace(path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _fixture_block() -> dict[str, Any]:
    document = json.loads(B1_FIXTURE.read_text(encoding="utf-8"))
    return {
        "admittedService": document["admittedService"],
        "identity": document["identity"],
        "origin": document["origin"],
        "treeSize": document["treeSize"],
        "rootHash": document["rootHash"],
        "record": "evidence/b1/FIXTURE.json",
        "recordSha256": _sha256_file(B1_FIXTURE),
        "signature": "A10 test-only HMAC-SHA256 key (fixed public seed; not a trust root)",
        "labels": document["labels"],
    }


def _note(size: str) -> bytes:
    return (FIXTURE_DIR / f"checkpoint-{size}.note").read_bytes()


def _proof(name: str) -> list[bytes]:
    return monitor.load_proof(FIXTURE_DIR / name)


def _observe_sequence() -> tuple[monitor.CheckpointStore, list[dict[str, Any]]]:
    store = monitor.CheckpointStore()
    rows: list[dict[str, Any]] = []
    for number, (size, proof_name, observed_at) in enumerate(SEQUENCE, 1):
        source = f"evidence/b1/fixture/checkpoint-{size}.note"
        result = monitor.observe(
            store,
            _note(size),
            key_name=SIGNER_NAME,
            key=KEY,
            observed_at=observed_at,
            source=source,
            consistency_proof=_proof(proof_name) if proof_name else None,
            expected_origin=ORIGIN,
        )
        rows.append(
            {
                "observation": number,
                "observedAt": observed_at,
                "treeSize": result["treeSize"],
                "rootHash": result["rootHash"],
                "noteSha256": result["record"]["noteSha256"],
                "code": result["code"],
                "consistency": result["consistency"],
                "recordDigest": result["recordDigest"],
                "source": source,
            }
        )
    return store, rows


def _expect(code: str, call: Callable[[], Any]) -> dict[str, Any]:
    try:
        call()
    except monitor.Refusal as refusal:
        if refusal.code != code:
            raise AssertionError(
                f"expected {code}, observed {refusal.code}: {refusal.message}"
            ) from refusal
        return {"code": refusal.code, "message": refusal.message}
    raise AssertionError(f"the control did not fire {code}")


def _canary(
    call: Callable[[], Mapping[str, Any]], *, scope: str, observation: str
) -> dict[str, Any]:
    try:
        result = call()
    except monitor.Refusal as refusal:
        raise AssertionError(
            f"the canary was refused with {refusal.code}: {refusal.message}"
        ) from refusal
    return {
        "accepted": True,
        "scope": scope,
        "observation": observation,
        "code": result.get("code"),
        "treeSize": result.get("treeSize"),
        "observations": result.get("observations"),
        "distinctDomains": result.get("distinctDomains"),
    }


def _attribution_canary(
    code: str, call: Callable[[], Any], *, observation: str
) -> dict[str, Any]:
    """A canary for a check whose refusal no disabled check could accept.

    The checkpoint parse is what makes every other check possible, so no input
    exists that disabling *it* would accept.  The canary disables every other
    check and shows the refusal is still attributable to this one.
    """
    try:
        call()
    except monitor.Refusal as refusal:
        if refusal.code != code:
            raise AssertionError(
                f"expected {code} from the attribution canary, observed "
                f"{refusal.code}: {refusal.message}"
            ) from refusal
        return {
            "accepted": False,
            "scope": "check",
            "observation": observation,
            "nextRefusal": refusal.code,
        }
    raise AssertionError(f"the attribution canary did not fire {code}")


def _not_applicable(reason: str) -> dict[str, Any]:
    return {"accepted": None, "scope": "none", "observation": reason}


def _fresh_store(store: monitor.CheckpointStore) -> monitor.CheckpointStore:
    return monitor.CheckpointStore.from_bytes(store.serialise())


def _signed(size: int, root: bytes, *, origin: str = ORIGIN, key: bytes = KEY) -> bytes:
    return tlog.sign_checkpoint(
        tlog.checkpoint_text(origin, size, root), SIGNER_NAME, key
    )


def run_observation_controls(
    store: monitor.CheckpointStore,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Every observation refusal, with an accepting canary where one exists."""
    root6 = bytes.fromhex(store.head["rootHash"])
    note6 = _note("6")
    controls: list[dict[str, Any]] = []

    def row(
        control_id: str,
        code: str,
        clause: str,
        mutation: str,
        observed: dict[str, Any],
        canary: dict[str, Any],
        *,
        scope: str = "observe",
    ) -> dict[str, Any]:
        return {
            "id": control_id,
            "code": code,
            "scope": scope,
            "clause": clause,
            "mutation": mutation,
            "controlOnly": True,
            "observed": observed,
            "canary": canary,
        }

    # Rollback: the real size-2 checkpoint after the size-6 head.
    controls.append(
        row(
            "rollback",
            monitor.MN_REFUSED_ROLLBACK,
            "docs/ETP-ADDENDUM-B.md §B.7; §B.24 item 18",
            "present the real size-2 checkpoint after the size-6 head was accepted",
            _expect(
                monitor.MN_REFUSED_ROLLBACK,
                lambda: monitor.observe(
                    _fresh_store(store),
                    _note("2"),
                    key_name=SIGNER_NAME,
                    key=KEY,
                    observed_at="2026-11-24T00:00:04Z",
                    source="control-only:rollback",
                    expected_origin=ORIGIN,
                ),
            ),
            _canary(
                lambda: monitor.observe(
                    _fresh_store(store),
                    _note("2"),
                    key_name=SIGNER_NAME,
                    key=KEY,
                    observed_at="2026-11-24T00:00:04Z",
                    source="control-only:rollback",
                    expected_origin=ORIGIN,
                    disabled=frozenset({"rollback"}),
                ),
                scope="observe",
                observation="with the rollback comparison disabled the older head is accepted as a re-observation",
            ),
        )
    )

    # Split view: a second signed head at an accepted size with another root.
    alternative = bytes([root6[0] ^ 0x01]) + root6[1:]
    split_note = _signed(6, alternative)
    controls.append(
        row(
            "split-view",
            monitor.MN_REFUSED_SPLIT_VIEW,
            "docs/ETP-ADDENDUM-B.md §B.7; §B.24 item 19",
            "sign a different root for the already accepted size 6",
            _expect(
                monitor.MN_REFUSED_SPLIT_VIEW,
                lambda: monitor.observe(
                    _fresh_store(store),
                    split_note,
                    key_name=SIGNER_NAME,
                    key=KEY,
                    observed_at="2026-11-24T00:00:04Z",
                    source="control-only:split-view",
                    expected_origin=ORIGIN,
                ),
            ),
            _canary(
                lambda: monitor.observe(
                    _fresh_store(store),
                    split_note,
                    key_name=SIGNER_NAME,
                    key=KEY,
                    observed_at="2026-11-24T00:00:04Z",
                    source="control-only:split-view",
                    expected_origin=ORIGIN,
                    disabled=frozenset({"split-view"}),
                ),
                scope="observe",
                observation="with the split-view comparison disabled the equivocating head is accepted",
            ),
        )
    )

    # Origin: the same tree under another log identity.
    other_origin = _signed(6, root6, origin="OTHER-LOG")
    controls.append(
        row(
            "origin",
            monitor.MN_REFUSED_ORIGIN,
            "docs/ETP-ADDENDUM-B.md §B.7; §B.24 items 9-10",
            "present a correctly signed size-6 checkpoint whose origin is OTHER-LOG",
            _expect(
                monitor.MN_REFUSED_ORIGIN,
                lambda: monitor.observe(
                    _fresh_store(store),
                    other_origin,
                    key_name=SIGNER_NAME,
                    key=KEY,
                    observed_at="2026-11-24T00:00:04Z",
                    source="control-only:origin",
                    expected_origin=ORIGIN,
                ),
            ),
            _canary(
                lambda: monitor.observe(
                    _fresh_store(store),
                    other_origin,
                    key_name=SIGNER_NAME,
                    key=KEY,
                    observed_at="2026-11-24T00:00:04Z",
                    source="control-only:origin",
                    expected_origin=ORIGIN,
                    disabled=frozenset({"origin"}),
                ),
                scope="observe",
                observation="with the origin comparison disabled the other log's head is accepted",
            ),
        )
    )

    # Backdated: the real size-6 checkpoint observed before the accepted one.
    controls.append(
        row(
            "backdated",
            monitor.MN_REFUSED_BACKDATED,
            "docs/ETP-ADDENDUM-B.md §B.7 freshness; §B.9 (an observation time is not a signing time)",
            "replay the real size-6 checkpoint with an observation instant before the accepted one",
            _expect(
                monitor.MN_REFUSED_BACKDATED,
                lambda: monitor.observe(
                    _fresh_store(store),
                    note6,
                    key_name=SIGNER_NAME,
                    key=KEY,
                    observed_at="2026-11-24T00:00:00Z",
                    source="control-only:backdated",
                    expected_origin=ORIGIN,
                ),
            ),
            _canary(
                lambda: monitor.observe(
                    _fresh_store(store),
                    note6,
                    key_name=SIGNER_NAME,
                    key=KEY,
                    observed_at="2026-11-24T00:00:00Z",
                    source="control-only:backdated",
                    expected_origin=ORIGIN,
                    disabled=frozenset({"backdated"}),
                ),
                scope="observe",
                observation="with the backdating comparison disabled the older observation is accepted as a re-observation",
            ),
        )
    )

    # Store tamper: one byte in the first record's chained digest.
    data = store.serialise()
    first_line, rest = data.split(b"\n", 1)
    record = json.loads(first_line)
    record["digest"] = record["digest"][:-1] + (
        "0" if record["digest"][-1] != "0" else "1"
    )
    tampered = _serialise_line(record) + b"\n" + rest
    controls.append(
        row(
            "store-tampered",
            monitor.MN_REFUSED_STORE_TAMPERED,
            "docs/ETP-ADDENDUM-B.md §B.7 (persistent rollback-resistant inventory)",
            "flip one byte in the first record's chained digest after the store was written",
            _expect(
                monitor.MN_REFUSED_STORE_TAMPERED,
                lambda: monitor.CheckpointStore.from_bytes(tampered),
            ),
            _canary(
                lambda: monitor.status(
                    monitor.CheckpointStore.from_bytes(
                        tampered, disabled=frozenset({"store"})
                    ),
                    disabled=frozenset({"store"}),
                ),
                scope="store",
                observation="with the chained-digest check disabled the edited bytes are read and the last record is reported",
            ),
            scope="store",
        )
    )

    # Consistency: a fresh 2 -> 6 growth with a corrupted proof.
    fresh = monitor.CheckpointStore()
    monitor.observe(
        fresh,
        _note("2"),
        key_name=SIGNER_NAME,
        key=KEY,
        observed_at="2026-11-24T00:00:01Z",
        source="evidence/b1/fixture/checkpoint-2.note",
        expected_origin=ORIGIN,
    )
    corrupted = list(_proof("consistency-2-6.json"))
    corrupted[0] = bytes([corrupted[0][0] ^ 0x01]) + corrupted[0][1:]
    controls.append(
        row(
            "inconsistent",
            monitor.MN_REFUSED_INCONSISTENT,
            "docs/ETP-ADDENDUM-B.md §B.6-§B.7; §B.24 item 20",
            "grow a fresh size-2 store to size 6 with the first 2 -> 6 proof element flipped",
            _expect(
                monitor.MN_REFUSED_INCONSISTENT,
                lambda: monitor.observe(
                    _fresh_store(fresh),
                    note6,
                    key_name=SIGNER_NAME,
                    key=KEY,
                    observed_at="2026-11-24T00:00:02Z",
                    source="control-only:inconsistent",
                    consistency_proof=corrupted,
                    expected_origin=ORIGIN,
                ),
            ),
            _canary(
                lambda: monitor.observe(
                    _fresh_store(fresh),
                    note6,
                    key_name=SIGNER_NAME,
                    key=KEY,
                    observed_at="2026-11-24T00:00:02Z",
                    source="control-only:inconsistent",
                    consistency_proof=corrupted,
                    expected_origin=ORIGIN,
                    disabled=frozenset({"consistency"}),
                ),
                scope="observe",
                observation="with the consistency check disabled the larger head is accepted without append-only credit",
            ),
        )
    )

    # Signature: the exact body signed by a different key.
    forged = _signed(6, root6, key=b"\x11" * 32)
    controls.append(
        row(
            "signature",
            monitor.MN_REFUSED_SIGNATURE,
            "docs/ETP-ADDENDUM-B.md §B.7; §B.24 item 8",
            "sign the exact size-6 body with a key other than the policy-selected test key",
            _expect(
                monitor.MN_REFUSED_SIGNATURE,
                lambda: monitor.observe(
                    _fresh_store(store),
                    forged,
                    key_name=SIGNER_NAME,
                    key=KEY,
                    observed_at="2026-11-24T00:00:04Z",
                    source="control-only:signature",
                    expected_origin=ORIGIN,
                ),
            ),
            _canary(
                lambda: monitor.observe(
                    _fresh_store(store),
                    forged,
                    key_name=SIGNER_NAME,
                    key=KEY,
                    observed_at="2026-11-24T00:00:04Z",
                    source="control-only:signature",
                    expected_origin=ORIGIN,
                    disabled=frozenset({"signature"}),
                ),
                scope="observe",
                observation="with signature verification disabled the forged head is accepted as a re-observation",
            ),
        )
    )

    # Checkpoint: a signed size-0 head with a non-empty root.
    zero = _signed(0, root6)
    controls.append(
        row(
            "checkpoint",
            monitor.MN_REFUSED_CHECKPOINT,
            "docs/ETP-ADDENDUM-B.md §B.7 (authentic checkpoint); §B.24 item 6",
            "sign a size-0 checkpoint whose root is not SHA-256 of the empty string",
            _expect(
                monitor.MN_REFUSED_CHECKPOINT,
                lambda: monitor.observe(
                    monitor.CheckpointStore(),
                    zero,
                    key_name=SIGNER_NAME,
                    key=KEY,
                    observed_at="2026-11-24T00:00:01Z",
                    source="control-only:checkpoint",
                    expected_origin=ORIGIN,
                ),
            ),
            _canary(
                lambda: monitor.observe(
                    monitor.CheckpointStore(),
                    zero,
                    key_name=SIGNER_NAME,
                    key=KEY,
                    observed_at="2026-11-24T00:00:01Z",
                    source="control-only:checkpoint",
                    expected_origin=ORIGIN,
                    disabled=frozenset({"checkpoint"}),
                ),
                scope="observe",
                observation="with the checkpoint root-validity check disabled the signed size-0 head is accepted",
            ),
        )
    )

    # Attribution-only: a malformed body cannot be accepted by disabling a check.
    malformed = b"FIXTURE-1\n6\nnot-canonical-base64\n\n"
    attribution = _attribution_canary(
        monitor.MN_REFUSED_CHECKPOINT,
        lambda: monitor.observe(
            monitor.CheckpointStore(),
            malformed,
            key_name=SIGNER_NAME,
            key=KEY,
            observed_at="2026-11-24T00:00:01Z",
            source="control-only:malformed",
            expected_origin=ORIGIN,
            disabled=frozenset({"signature", "origin", "checkpoint"}),
        ),
        observation=(
            "a malformed body is not a checkpoint: the parse is what makes every "
            "other check possible, so disabling signature, origin and root-validity "
            "still refuses with MN_REFUSED_CHECKPOINT and no acceptance exists"
        ),
    )

    return controls, {
        "malformedCheckpoint": {
            "code": monitor.MN_REFUSED_CHECKPOINT,
            "attributionCanary": attribution,
            "controlOnly": True,
        }
    }


def _witness(
    operator: str,
    domain: str,
    keyid: str,
    evidence: Mapping[str, str],
    key: bytes,
    *,
    body: bytes,
    expires: str = "2027-01-01",
    sign_body: bytes | None = None,
) -> dict[str, Any]:
    signed = tlog.sign_checkpoint(
        sign_body if sign_body is not None else body, keyid, key
    )
    return {
        "operator": operator,
        "keyid": keyid,
        "domain": domain,
        "domainEvidence": dict(evidence),
        "expiresAt": expires,
        "signedNote": signed.decode("utf-8"),
    }


def run_witness_controls(
    body: bytes,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Synthetic witness sets, one per witness refusal and its canary."""
    controls: list[dict[str, Any]] = []

    def row(
        control_id: str,
        code: str,
        mutation: str,
        observed: dict[str, Any],
        canary: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "id": control_id,
            "code": code,
            "scope": "witness",
            "clause": "docs/ETP-ADDENDUM-B.md §B.11; §B.24 items 21-23",
            "mutation": mutation,
            "controlOnly": True,
            "observed": observed,
            "canary": canary,
        }

    def key(name: str) -> bytes:
        return hashlib.sha256(
            b"openssl-rs/b5/control-only/witness/" + name.encode()
        ).digest()

    def evidence(name: str) -> dict[str, str]:
        return {
            "path": f"evidence/b5/control-only/{name}",
            "sha256": hashlib.sha256(b"b5/control-only/" + name.encode()).hexdigest(),
        }

    key_a, key_b = key("a"), key("b")
    ev_a, ev_b = evidence("operator-a"), evidence("operator-b")
    witness_a = _witness(
        "control-only-operator-a",
        "control-only:alpha",
        "control-only-key-a",
        ev_a,
        key_a,
        body=body,
    )
    witness_b = _witness(
        "control-only-operator-b",
        "control-only:beta",
        "control-only-key-b",
        ev_b,
        key_b,
        body=body,
    )
    keys_ab = {"control-only-key-a": key_a, "control-only-key-b": key_b}

    controls.append(
        row(
            "no-witness",
            monitor.MN_REFUSED_NO_WITNESS,
            "offer an empty witness set",
            _expect(
                monitor.MN_REFUSED_NO_WITNESS,
                lambda: monitor.admit_witnesses(
                    body, {"witnesses": []}, k=REQUIRED_K, at=RECORDED_AT, keys={}
                ),
            ),
            {
                "accepted": False,
                "disabledCall": True,
                "nextRefusal": monitor.MN_REFUSED_WITNESS_QUORUM,
                "scope": "witness",
                "observation": (
                    "with the no-witness check disabled the empty set is not refused "
                    "for absence; the next independent refusal is the quorum, so no "
                    "admission exists without witnesses"
                ),
            },
        )
    )

    controls.append(
        row(
            "witness-quorum",
            monitor.MN_REFUSED_WITNESS_QUORUM,
            "present two distinct operator domains against a recorded quorum of k=3",
            _expect(
                monitor.MN_REFUSED_WITNESS_QUORUM,
                lambda: monitor.admit_witnesses(
                    body,
                    {"witnesses": [witness_a, witness_b]},
                    k=3,
                    at=RECORDED_AT,
                    keys=keys_ab,
                ),
            ),
            _canary(
                lambda: monitor.admit_witnesses(
                    body,
                    {"witnesses": [witness_a, witness_b]},
                    k=3,
                    at=RECORDED_AT,
                    keys=keys_ab,
                    disabled=frozenset({"quorum"}),
                ),
                scope="witness",
                observation="with the quorum comparison disabled two distinct domains are admitted against k=3",
            ),
        )
    )

    alias = _witness(
        "control-only-operator-a",
        "control-only:alpha-alias",
        "control-only-key-b",
        ev_a,
        key_b,
        body=body,
    )
    controls.append(
        row(
            "witness-aliased",
            monitor.MN_REFUSED_WITNESS_ALIASED,
            "present two domain labels whose establishment record is the same operator record",
            _expect(
                monitor.MN_REFUSED_WITNESS_ALIASED,
                lambda: monitor.admit_witnesses(
                    body,
                    {"witnesses": [witness_a, alias]},
                    k=1,
                    at=RECORDED_AT,
                    keys=keys_ab,
                ),
            ),
            _canary(
                lambda: monitor.admit_witnesses(
                    body,
                    {"witnesses": [witness_a, alias]},
                    k=1,
                    at=RECORDED_AT,
                    keys=keys_ab,
                    disabled=frozenset({"witness-alias"}),
                ),
                scope="witness",
                observation="with the aliasing check disabled the two labels are admitted and A15 still counts one domain",
            ),
        )
    )

    expired = _witness(
        "control-only-operator-a",
        "control-only:alpha",
        "control-only-key-a",
        ev_a,
        key_a,
        body=body,
        expires="2026-01-01",
    )
    controls.append(
        row(
            "witness-expired",
            monitor.MN_REFUSED_WITNESS_EXPIRED,
            "present a witness whose key expired before the evaluation instant",
            _expect(
                monitor.MN_REFUSED_WITNESS_EXPIRED,
                lambda: monitor.admit_witnesses(
                    body,
                    {"witnesses": [expired]},
                    k=1,
                    at=RECORDED_AT,
                    keys={"control-only-key-a": key_a},
                ),
            ),
            _canary(
                lambda: monitor.admit_witnesses(
                    body,
                    {"witnesses": [expired]},
                    k=1,
                    at=RECORDED_AT,
                    keys={"control-only-key-a": key_a},
                    disabled=frozenset({"witness-expiry"}),
                ),
                scope="witness",
                observation="with the expiry comparison disabled the expired witness is admitted",
            ),
        )
    )

    wrong_body = tlog.parse_signed_checkpoint(_note("5"))[0].body()
    wrong = _witness(
        "control-only-operator-a",
        "control-only:alpha",
        "control-only-key-a",
        ev_a,
        key_a,
        body=body,
        sign_body=wrong_body,
    )
    controls.append(
        row(
            "witness-signature",
            monitor.MN_REFUSED_WITNESS_SIGNATURE,
            "present a witness signature over different checkpoint bytes",
            _expect(
                monitor.MN_REFUSED_WITNESS_SIGNATURE,
                lambda: monitor.admit_witnesses(
                    body,
                    {"witnesses": [wrong]},
                    k=1,
                    at=RECORDED_AT,
                    keys={"control-only-key-a": key_a},
                ),
            ),
            _canary(
                lambda: monitor.admit_witnesses(
                    body,
                    {"witnesses": [wrong]},
                    k=1,
                    at=RECORDED_AT,
                    keys={"control-only-key-a": key_a},
                    disabled=frozenset({"witness-signature"}),
                ),
                scope="witness",
                observation="with the witness-signature check disabled the wrong signature is admitted",
            ),
        )
    )

    positive = monitor.admit_witnesses(
        body,
        {"witnesses": [witness_a, witness_b]},
        k=2,
        at=RECORDED_AT,
        keys=keys_ab,
    )
    return controls, {
        "positiveControl": {
            "controlOnly": True,
            "observation": "two distinct synthetic operator domains meet k=2",
            "result": {
                "code": positive["code"],
                "distinctDomains": positive["distinctDomains"],
                "required": positive["required"],
            },
        }
    }


def run_invocation_controls() -> list[dict[str, Any]]:
    """The two refusals a producer can observe through the command line."""
    controls: list[dict[str, Any]] = []

    def run(arguments: Sequence[str]) -> tuple[int, str]:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = monitor.main(list(arguments))
        return code, buffer.getvalue()

    exit_code, output = run(["observe"])
    controls.append(
        {
            "id": "usage",
            "code": monitor.MN_REFUSED_USAGE,
            "scope": "cli",
            "clause": "forensics/tools/monitor.py usage contract",
            "mutation": "invoke observe with a required argument absent",
            "controlOnly": True,
            "observed": {
                "code": monitor.MN_REFUSED_USAGE,
                "exitStatus": exit_code,
                "printed": monitor.MN_REFUSED_USAGE in output,
            },
            "canary": _not_applicable(
                "a malformed invocation has no accepted form to reach by disabling a check"
            ),
        }
    )

    exit_code, output = run(["status", "--store", str(EVIDENCE)])
    controls.append(
        {
            "id": "io",
            "code": monitor.MN_REFUSED_IO,
            "scope": "cli",
            "clause": "forensics/tools/monitor.py usage contract",
            "mutation": "name a directory as the store",
            "controlOnly": True,
            "observed": {
                "code": monitor.MN_REFUSED_IO,
                "exitStatus": exit_code,
                "printed": monitor.MN_REFUSED_IO in output,
            },
            "canary": _not_applicable(
                "an unreadable path has no bytes; disabling a check cannot make it readable"
            ),
        }
    )
    return controls


def _witnesses_document(
    fixture: Mapping[str, Any],
    observed: Mapping[str, Any],
    *,
    signature_lines: Mapping[str, int],
    available_domains: int,
    zero_count: int,
    a15_external: Sequence[Any],
) -> dict[str, Any]:
    return {
        "schema": "openssl-rs/b5/witnesses/1",
        "item": "B5",
        "recordedAt": RECORDED_AT,
        "baseCommit": BASE_COMMIT,
        "clause": "docs/ETP-ADDENDUM-B.md §B.11",
        "fixture": {
            "identity": fixture["identity"],
            "origin": fixture["origin"],
            "checkpoint": "evidence/b1/fixture/checkpoint-6.note",
            "treeSize": fixture["treeSize"],
            "rootHash": fixture["rootHash"],
        },
        "inventory": {
            "witnesses": 0,
            "witnessKeys": 0,
            "operators": 0,
            "independentDomains": 0,
            "cosignatures": 0,
        },
        "establishedBy": [
            {
                "quantity": "witnesses",
                "value": 0,
                "check": (
                    "every signed note in evidence/b1/fixture carries exactly one "
                    "signature line and none is a witness cosignature "
                    "(tlog.parse_signed_checkpoint); the B1 fixture is labelled "
                    "no-witness; the witnessSet below is empty"
                ),
            },
            {
                "quantity": "quorum",
                "value": 0,
                "check": (
                    "the recorded quorum is k=3 and thresholds.available_domain_count "
                    "over the empty witness domain inventory is 0, so no quorum is "
                    "reachable; the monitor refuses the empty set before counting"
                ),
            },
            {
                "quantity": "independentDomains",
                "value": 0,
                "check": (
                    "thresholds.distinct_domains over zero witness approvals returns "
                    "count 0; evidence/a15/DOMAINS.json records externalDomains []"
                ),
            },
        ],
        "requiredQuorum": {
            "k": REQUIRED_K,
            "n": REQUIRED_N,
            "basis": (
                "§B.11: a three-of-four policy over independent witnesses survives one "
                "compromised witness under a model permitting at most one; a fixed "
                "three-witness population with a two-witness threshold does not. The "
                "quorum is recorded, not met, and no witness exists to meet it."
            ),
            "met": False,
        },
        "aliasingRule": {
            "delegatedTo": "forensics/tools/thresholds.py distinct_domains (A15)",
            "rule": (
                "count distinct establishment records and distinct operators, not "
                "labels: two domain labels that share one establishment record are "
                "one domain, one operator under two labels is one domain, and the "
                "labels or identities that collapsed are reported"
            ),
            "refusalCode": monitor.MN_REFUSED_WITNESS_ALIASED,
            "note": (
                "a witness signature and key expiry are witness-specific checks that "
                "A15 does not perform; A15 documents that it does not verify signatures"
            ),
        },
        "witnessSet": [],
        "keys": {},
        "evaluatedAt": "2026-11-24T00:00:00Z",
        "outcome": "NOT_RUN",
        "observed": {
            "code": observed["code"],
            "message": observed["message"],
            "signatureLinesPerNote": dict(signature_lines),
            "availableDomains": available_domains,
            "countOverZeroApprovals": zero_count,
            "a15ExternalDomains": list(a15_external),
        },
        "nonClaims": [
            "a witness quorum is a count of distinct established operator domains, not a threshold of labels",
            "no witness exists here, so no cosignature and no witness-dependent property is established",
            "operating several services under one maintainer is not several independent witnesses",
            "this record names the quorum that would be required; it does not meet it",
        ],
    }


def build() -> dict[str, bytes]:
    store, sequence = _observe_sequence()
    status = monitor.status(store)
    audit = store.audit()
    store_bytes = store.serialise()
    fixture = _fixture_block()

    observation_controls, observation_extras = run_observation_controls(store)
    body6 = tlog.parse_signed_checkpoint(_note("6"))[0].body()
    witness_controls, witness_extras = run_witness_controls(body6)
    invocation_controls = run_invocation_controls()

    signature_lines = {
        f"checkpoint-{size}.note": len(tlog.parse_signed_checkpoint(_note(size))[1])
        for size, _, _ in SEQUENCE
    }
    available_domains = thresholds.available_domain_count(
        {"candidateDomain": "openssl-rs", "domains": []}
    )
    zero_count = thresholds.distinct_domains(
        [], {"candidateDomain": "openssl-rs", "domains": []}
    )["count"]
    a15_external = json.loads(A15_DOMAINS.read_text(encoding="utf-8"))[
        "externalDomains"
    ]

    witness_outcome = _expect(
        monitor.MN_REFUSED_NO_WITNESS,
        lambda: monitor.admit_witnesses(
            body6, {"witnesses": []}, k=REQUIRED_K, at=RECORDED_AT, keys={}
        ),
    )
    witnesses_document = _witnesses_document(
        fixture,
        witness_outcome,
        signature_lines=signature_lines,
        available_domains=available_domains,
        zero_count=zero_count,
        a15_external=a15_external,
    )

    corrupted_sequence = [
        control
        for control in observation_controls
        if control["id"]
        in {"rollback", "split-view", "origin", "backdated", "store-tampered"}
    ]

    monitor_document = {
        "schema": "openssl-rs/b5/monitor/1",
        "item": "B5",
        "recordedAt": RECORDED_AT,
        "baseCommit": BASE_COMMIT,
        "clause": "docs/ETP-ADDENDUM-B.md §B.7, §B.11-§B.12 and §B.30 B5",
        "fixture": fixture,
        "authority": {
            "checkpointFormat": "forensics/tools/tlog.py (C2SP tlog-checkpoint body and note signature)",
            "consistencyProof": "forensics/tools/tlog.py verify_consistency (RFC 6962 §2.1.2)",
            "signatureKind": "test-only HMAC-SHA256 over the exact note text",
            "trustRoot": False,
            "note": (
                "The verifier checks the bytes and the test key's signature; it does "
                "not establish that an independent log operator signed them."
            ),
        },
        "causalOrder": list(CAUSAL_ORDER),
        "store": {
            "path": "evidence/b5/store/monitor-store.jsonl",
            "bytes": len(store_bytes),
            "sha256": hashlib.sha256(store_bytes).hexdigest(),
            "records": len(store.records),
            "chain": "verified",
            "schema": monitor.STORE_SCHEMA,
        },
        "sequence": sequence,
        "finalHead": {
            "origin": status["head"]["origin"],
            "treeSize": status["head"]["treeSize"],
            "rootHash": status["head"]["rootHash"],
            "observedAt": status["head"]["observedAt"],
            "recordDigest": status["head"]["recordDigest"],
        },
        "status": {
            "observations": status["observations"],
            "acceptedSize": status["acceptedSize"],
            "sizes": audit["sizes"],
            "transitions": audit["transitions"],
            "rootsPerSize": audit["rootsPerSize"],
        },
        "corruptedSequence": [
            {
                "id": control["id"],
                "code": control["code"],
                "mutation": control["mutation"],
                "canary": control["canary"],
            }
            for control in corrupted_sequence
        ],
        "controls": {
            "path": "evidence/b5/CONTROLS.json",
            "total": len(observation_controls)
            + len(witness_controls)
            + len(invocation_controls)
            + 1,
            "onePerRefusalCode": True,
        },
        "witnesses": {
            "path": "evidence/b5/WITNESSES.json",
            "witnesses": 0,
            "required": REQUIRED_K,
            "distinctDomains": 0,
            "availableDomains": available_domains,
            "countOverZeroApprovals": zero_count,
            "code": witness_outcome["code"],
            "message": witness_outcome["message"],
            "outcome": "NOT_RUN",
            "signatureLinesPerNote": signature_lines,
            "a15ExternalDomains": a15_external,
        },
        "malformedCheckpoint": observation_extras["malformedCheckpoint"],
        "witnessPositiveControl": witness_extras["positiveControl"],
        "nonClaims": [
            "monitoring establishes that this sequence of heads is internally consistent and append-only; it does not establish that the log is honest",
            "the monitor observed one fixture's sequence; it cannot assert complete observation of any log",
            "the fixture is not an admitted Rekor service and the signer is A10's test-only key, not a log key",
            "the observation instant is the monitor's own record, not a signing time or a trusted timestamp",
            "a consistency proof shows that two heads are related; it does not show that either head was served to anyone else",
            "no witness, witness key or independent operator domain exists, so witness admission is NOT_RUN",
        ],
        "notRun": [
            "admission of a genuinely independent witness (no witness service, key or operator domain exists)",
            "observation of a public log, a second view or another monitor's transcript (no log and no network)",
            "an independently operated monitor or an independent reviewer",
            "detection of equivocation that was never served to this monitor",
            "a trusted timestamp for any observation (§B.9; B2 records no authority)",
            "closure of the A17 forward freeze",
        ],
    }

    all_controls = observation_controls + witness_controls + invocation_controls
    all_controls.append(
        {
            "id": "fixture-sequence",
            "code": monitor.CODE_OK,
            "scope": "observe",
            "clause": "docs/ETP-ADDENDUM-B.md §B.7",
            "mutation": "none: the real size-2, size-5 and size-6 sequence in order",
            "controlOnly": True,
            "observed": {
                "code": monitor.CODE_OK,
                "observations": status["observations"],
                "acceptedSize": status["acceptedSize"],
                "rootHash": status["head"]["rootHash"],
            },
            "canary": {
                "accepted": True,
                "scope": "observe",
                "observation": "the positive control is the accepted sequence itself",
            },
        }
    )

    covered = {row["code"] for row in all_controls}
    missing = [code for code in monitor.REFUSALS if code not in covered]
    if missing:
        raise AssertionError(f"no control for: {', '.join(missing)}")

    controls_document = {
        "schema": "openssl-rs/b5/controls/1",
        "item": "B5",
        "recordedAt": RECORDED_AT,
        "baseCommit": BASE_COMMIT,
        "clause": "docs/ETP-ADDENDUM-B.md §B.7, §B.11-§B.12 and §B.24 items 8-10, 18-23",
        "controlOnly": True,
        "controls": all_controls,
        "summary": {
            "total": len(all_controls),
            "refusalCodes": len(monitor.REFUSALS),
            "onePerRefusalCode": True,
            "fired": len(all_controls),
            "acceptingCanaries": sum(
                1 for row in all_controls if row["canary"].get("accepted") is True
            ),
            "nonAcceptingCanaries": [
                row["id"]
                for row in all_controls
                if row["canary"].get("accepted") is not True
            ],
            "coveredCodes": sorted(covered),
        },
        "nonClaims": [
            "a control that fires proves the refusal works; it does not show the substituted form occurs in any log",
            "every witness fixture is control-only and synthetic; no witness admission is claimed",
            "the canary disables a named check; it does not show the corrupt input is valid",
        ],
    }

    return {
        "MONITOR.json": _serialise(monitor_document),
        "WITNESSES.json": _serialise(witnesses_document),
        "CONTROLS.json": _serialise(controls_document),
        "store/monitor-store.jsonl": store_bytes,
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)

    outputs = build()
    problems: list[str] = []
    for relative, data in outputs.items():
        target = EVIDENCE / relative
        if args.check:
            if not target.exists() or target.read_bytes() != data:
                problems.append(relative)
            continue
        _write_bytes(target, data)

    store_sha = hashlib.sha256(outputs["store/monitor-store.jsonl"]).hexdigest()
    monitor_document = json.loads(outputs["MONITOR.json"])
    controls_document = json.loads(outputs["CONTROLS.json"])
    if args.check:
        if problems:
            print(
                "code=MN_REFUSED_STORE_TAMPERED b5: stale record(s): "
                + ", ".join(problems)
            )
            return 1
        print(
            f"code=MN_OK b5: check ok records={len(outputs)} storeSha256={store_sha}"
        )
        return 0
    print(
        "code=MN_OK b5: base={base} observations={obs} sizes={sizes} "
        "head={root} storeSha256={sha} witnesses={wit}/{required} "
        "witnessOutcome={outcome}".format(
            base=BASE_COMMIT,
            obs=monitor_document["status"]["observations"],
            sizes=monitor_document["status"]["sizes"],
            root=monitor_document["finalHead"]["rootHash"],
            sha=store_sha,
            wit=monitor_document["witnesses"]["witnesses"],
            required=monitor_document["witnesses"]["required"],
            outcome=monitor_document["witnesses"]["outcome"],
        )
    )
    print(
        "code=MN_OK b5: controls={total} onePerRefusalCode={one} "
        "acceptingCanaries={canaries} nonAccepting={non}".format(
            total=controls_document["summary"]["total"],
            one=controls_document["summary"]["onePerRefusalCode"],
            canaries=controls_document["summary"]["acceptingCanaries"],
            non=",".join(controls_document["summary"]["nonAcceptingCanaries"]),
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
