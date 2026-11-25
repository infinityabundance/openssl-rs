#!/usr/bin/env python3
"""Controls for ``forensics/tools/monitor.py`` and the B5 records.

Every refusal code has one triggering control, and every control that can be
disabled carries a canary showing the same input accepted with that check
disabled.  Three cannot be disabled and say so: the checkpoint parse (nothing
readable survives disabling the parse), an unreadable path, and a malformed
invocation.  The empty witness set is refused for *admission* and does not stop
*observation*: a monitor does not need a witness to record a head.

These are controls, not a conformity result.  A refusal that fires proves the
check works; it does not prove a live log behaves as the fixture does.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
REPO_ROOT = TOOLS.parents[1]
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import dsse  # noqa: E402
import monitor  # noqa: E402
import thresholds  # noqa: E402
import tlog  # noqa: E402

B5 = REPO_ROOT / "evidence/b5"
BUILDER = B5 / "build_evidence.py"
DOCUMENT = REPO_ROOT / "docs/TRANSPARENCY-MONITORING.md"
TOOL = TOOLS / "monitor.py"
STORE = B5 / "store/monitor-store.jsonl"
FIXTURE_DIR = REPO_ROOT / "evidence/b1/fixture"

SIGNER = "FIXTURE-1 test-only hmac-sha256"
KEY = dsse.test_only_key()
ORIGIN = "FIXTURE-1"
ROOT2 = bytes.fromhex(
    "4f91d95745457dbee73edfebe0ac6fa4475a312bdb4ce0545aafe0d4079cb2d8"
)
ROOT5 = bytes.fromhex(
    "106a8e6ea12497c5f0ecd065d34eac15c2b7f9dd45811ce253f700d50d3a2be2"
)
ROOT6 = bytes.fromhex(
    "e9a8ad0126e834c0ec34fed464572772d3f3c2d3501198239a1a5554324c540f"
)
SEQUENCE = (
    ("2", None, "2026-11-24T00:00:01Z"),
    ("5", "consistency-2-5.json", "2026-11-24T00:00:02Z"),
    ("6", "consistency-5-6.json", "2026-11-24T00:00:03Z"),
)


def _builder():
    spec = importlib.util.spec_from_file_location("b5_build_evidence", BUILDER)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _note(size: str) -> bytes:
    return (FIXTURE_DIR / f"checkpoint-{size}.note").read_bytes()


def _proof(name: str) -> list[bytes]:
    return monitor.load_proof(FIXTURE_DIR / name)


def _store() -> monitor.CheckpointStore:
    store = monitor.CheckpointStore()
    for size, proof, at in SEQUENCE:
        monitor.observe(
            store,
            _note(size),
            key_name=SIGNER,
            key=KEY,
            observed_at=at,
            source=f"evidence/b1/fixture/checkpoint-{size}.note",
            consistency_proof=_proof(proof) if proof else None,
            expected_origin=ORIGIN,
        )
    return store


def _fresh(store: monitor.CheckpointStore) -> monitor.CheckpointStore:
    return monitor.CheckpointStore.from_bytes(store.serialise())


def _observe(store: monitor.CheckpointStore, note: bytes, at: str, **kwargs):
    return monitor.observe(
        store,
        note,
        key_name=SIGNER,
        key=KEY,
        observed_at=at,
        source=kwargs.pop("source", "control-only"),
        expected_origin=ORIGIN,
        **kwargs,
    )


def _signed(size: int, root: bytes, *, origin: str = ORIGIN, key: bytes = KEY) -> bytes:
    return tlog.sign_checkpoint(
        tlog.checkpoint_text(origin, size, root), SIGNER, key
    )


def _refused(code: str, call) -> None:
    """Assert ``call`` refuses with exactly ``code``."""
    try:
        call()
    except monitor.Refusal as refusal:
        if refusal.code != code:
            raise AssertionError(
                f"expected {code}, observed {refusal.code}: {refusal.message}"
            ) from refusal
        return
    raise AssertionError(f"no refusal; expected {code}")


def _accepted(call):
    """Assert ``call`` is accepted and return its result."""
    try:
        return call()
    except monitor.Refusal as refusal:
        raise AssertionError(
            f"the canary was refused with {refusal.code}: {refusal.message}"
        ) from refusal


def _body6() -> bytes:
    return tlog.parse_signed_checkpoint(_note("6"))[0].body()


def _witness(operator, domain, keyid, evidence, key, *, expires="2027-01-01",
             body=None, sign_body=None):
    body = _body6() if body is None else body
    signed = tlog.sign_checkpoint(
        sign_body if sign_body is not None else body, keyid, key
    )
    return {
        "operator": operator,
        "keyid": keyid,
        "domain": domain,
        "domainEvidence": evidence,
        "expiresAt": expires,
        "signedNote": signed.decode("utf-8"),
    }


def _evidence(name: str) -> dict[str, str]:
    return {
        "path": f"evidence/b5/control-only/{name}",
        "sha256": hashlib.sha256(b"b5/control-only/" + name.encode()).hexdigest(),
    }


KEY_A = hashlib.sha256(b"b5/control-only/a").digest()
KEY_B = hashlib.sha256(b"b5/control-only/b").digest()
EV_A = _evidence("operator-a")
EV_B = _evidence("operator-b")


def _witness_a(**kwargs):
    return _witness("operator-a", "control-only:alpha", "key-a", EV_A, KEY_A, **kwargs)


def _witness_b(**kwargs):
    return _witness("operator-b", "control-only:beta", "key-b", EV_B, KEY_B, **kwargs)


KEYS_AB = {"key-a": KEY_A, "key-b": KEY_B}


class RefusalCodes(unittest.TestCase):
    """One control per refusal code; a canary wherever a check can be disabled."""

    def test_checkpoint_root_validity_and_canary(self) -> None:
        zero = _signed(0, ROOT6)
        _refused(
            monitor.MN_REFUSED_CHECKPOINT,
            lambda: _observe(monitor.CheckpointStore(), zero, "2026-11-24T00:00:01Z"),
        )
        result = _accepted(
            lambda: _observe(
                monitor.CheckpointStore(),
                zero,
                "2026-11-24T00:00:01Z",
                disabled=frozenset({"checkpoint"}),
            )
        )
        self.assertEqual(result["treeSize"], 0)

    def test_malformed_checkpoint_is_attribution_only(self) -> None:
        malformed = b"FIXTURE-1\n6\nnot-canonical-base64\n\n"
        _refused(
            monitor.MN_REFUSED_CHECKPOINT,
            lambda: _observe(
                monitor.CheckpointStore(),
                malformed,
                "2026-11-24T00:00:01Z",
                disabled=frozenset({"signature", "origin", "checkpoint"}),
            ),
        )

    def test_signature_and_canary(self) -> None:
        forged = _signed(6, ROOT6, key=b"\x11" * 32)
        _refused(
            monitor.MN_REFUSED_SIGNATURE,
            lambda: _observe(_fresh(_store()), forged, "2026-11-24T00:00:04Z"),
        )
        result = _accepted(
            lambda: _observe(
                _fresh(_store()),
                forged,
                "2026-11-24T00:00:04Z",
                disabled=frozenset({"signature"}),
            )
        )
        self.assertEqual(result["treeSize"], 6)

    def test_origin_and_canary(self) -> None:
        other = _signed(6, ROOT6, origin="OTHER-LOG")
        _refused(
            monitor.MN_REFUSED_ORIGIN,
            lambda: _observe(_fresh(_store()), other, "2026-11-24T00:00:04Z"),
        )
        result = _accepted(
            lambda: _observe(
                _fresh(_store()),
                other,
                "2026-11-24T00:00:04Z",
                disabled=frozenset({"origin"}),
            )
        )
        self.assertEqual(result["origin"], "OTHER-LOG")

    def test_rollback_and_canary(self) -> None:
        _refused(
            monitor.MN_REFUSED_ROLLBACK,
            lambda: _observe(_fresh(_store()), _note("2"), "2026-11-24T00:00:04Z"),
        )
        result = _accepted(
            lambda: _observe(
                _fresh(_store()),
                _note("2"),
                "2026-11-24T00:00:04Z",
                disabled=frozenset({"rollback"}),
            )
        )
        self.assertEqual(result["treeSize"], 2)

    def test_split_view_and_canary(self) -> None:
        alternative = bytes([ROOT6[0] ^ 0x01]) + ROOT6[1:]
        split = _signed(6, alternative)
        _refused(
            monitor.MN_REFUSED_SPLIT_VIEW,
            lambda: _observe(_fresh(_store()), split, "2026-11-24T00:00:04Z"),
        )
        result = _accepted(
            lambda: _observe(
                _fresh(_store()),
                split,
                "2026-11-24T00:00:04Z",
                disabled=frozenset({"split-view"}),
            )
        )
        self.assertEqual(result["rootHash"], alternative.hex())

    def test_inconsistent_and_canary(self) -> None:
        fresh = monitor.CheckpointStore()
        monitor.observe(
            fresh,
            _note("2"),
            key_name=SIGNER,
            key=KEY,
            observed_at="2026-11-24T00:00:01Z",
            source="evidence/b1/fixture/checkpoint-2.note",
            expected_origin=ORIGIN,
        )
        corrupted = list(_proof("consistency-2-6.json"))
        corrupted[0] = bytes([corrupted[0][0] ^ 0x01]) + corrupted[0][1:]
        _refused(
            monitor.MN_REFUSED_INCONSISTENT,
            lambda: _observe(
                _fresh(fresh),
                _note("6"),
                "2026-11-24T00:00:02Z",
                consistency_proof=corrupted,
            ),
        )
        result = _accepted(
            lambda: _observe(
                _fresh(fresh),
                _note("6"),
                "2026-11-24T00:00:02Z",
                consistency_proof=corrupted,
                disabled=frozenset({"consistency"}),
            )
        )
        self.assertEqual(result["treeSize"], 6)
        self.assertEqual(result["consistency"]["verified"], False)

    def test_backdated_and_canary(self) -> None:
        _refused(
            monitor.MN_REFUSED_BACKDATED,
            lambda: _observe(_fresh(_store()), _note("6"), "2026-11-24T00:00:00Z"),
        )
        result = _accepted(
            lambda: _observe(
                _fresh(_store()),
                _note("6"),
                "2026-11-24T00:00:00Z",
                disabled=frozenset({"backdated"}),
            )
        )
        self.assertEqual(result["observedAt"], "2026-11-24T00:00:00Z")

    def test_an_unzoned_observation_instant_is_not_an_instant(self) -> None:
        _refused(
            monitor.MN_REFUSED_BACKDATED,
            lambda: _observe(_fresh(_store()), _note("6"), "2026-11-24T00:00:04"),
        )

    def test_store_tampered_digest_and_canary(self) -> None:
        data = _store().serialise()
        first, rest = data.split(b"\n", 1)
        record = json.loads(first)
        record["digest"] = record["digest"][:-1] + (
            "0" if record["digest"][-1] != "0" else "1"
        )
        tampered = (
            json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
            + b"\n"
            + rest
        )
        _refused(
            monitor.MN_REFUSED_STORE_TAMPERED,
            lambda: monitor.CheckpointStore.from_bytes(tampered),
        )
        result = monitor.status(
            monitor.CheckpointStore.from_bytes(
                tampered, disabled=frozenset({"store"})
            ),
            disabled=frozenset({"store"}),
        )
        self.assertEqual(result["acceptedSize"], 6)

    def test_store_tampered_field_is_caught_by_the_digest(self) -> None:
        data = _store().serialise()
        first, rest = data.split(b"\n", 1)
        record = json.loads(first)
        record["treeSize"] = 3
        tampered = (
            json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
            + b"\n"
            + rest
        )
        _refused(
            monitor.MN_REFUSED_STORE_TAMPERED,
            lambda: monitor.CheckpointStore.from_bytes(tampered),
        )

    def test_store_dropped_or_reordered_record_is_refused(self) -> None:
        lines = _store().serialise().splitlines()
        _refused(
            monitor.MN_REFUSED_STORE_TAMPERED,
            lambda: monitor.CheckpointStore.from_bytes(
                lines[0] + b"\n" + lines[2] + b"\n"
            ),
        )
        _refused(
            monitor.MN_REFUSED_STORE_TAMPERED,
            lambda: monitor.CheckpointStore.from_bytes(
                lines[1] + b"\n" + lines[0] + b"\n" + lines[2] + b"\n"
            ),
        )

    def test_no_witness_refuses_and_the_next_check_is_quorum(self) -> None:
        _refused(
            monitor.MN_REFUSED_NO_WITNESS,
            lambda: monitor.admit_witnesses(
                _body6(), {"witnesses": []}, k=1, at="2026-11-24", keys={}
            ),
        )
        _refused(
            monitor.MN_REFUSED_WITNESS_QUORUM,
            lambda: monitor.admit_witnesses(
                _body6(),
                {"witnesses": []},
                k=1,
                at="2026-11-24",
                keys={},
                disabled=frozenset({"no-witness"}),
            ),
        )

    def test_witness_quorum_and_canary(self) -> None:
        witnesses = [_witness_a(), _witness_b()]
        _refused(
            monitor.MN_REFUSED_WITNESS_QUORUM,
            lambda: monitor.admit_witnesses(
                _body6(), {"witnesses": witnesses}, k=3, at="2026-11-24", keys=KEYS_AB
            ),
        )
        result = _accepted(
            lambda: monitor.admit_witnesses(
                _body6(),
                {"witnesses": witnesses},
                k=3,
                at="2026-11-24",
                keys=KEYS_AB,
                disabled=frozenset({"quorum"}),
            )
        )
        self.assertEqual(result["distinctDomains"], 2)

    def test_witness_aliased_and_canary(self) -> None:
        alias = _witness(
            "operator-a", "control-only:alpha-alias", "key-b", EV_A, KEY_B
        )
        _refused(
            monitor.MN_REFUSED_WITNESS_ALIASED,
            lambda: monitor.admit_witnesses(
                _body6(), {"witnesses": [_witness_a(), alias]}, k=1,
                at="2026-11-24", keys=KEYS_AB,
            ),
        )
        result = _accepted(
            lambda: monitor.admit_witnesses(
                _body6(),
                {"witnesses": [_witness_a(), alias]},
                k=1,
                at="2026-11-24",
                keys=KEYS_AB,
                disabled=frozenset({"witness-alias"}),
            )
        )
        self.assertEqual(result["distinctDomains"], 1)

    def test_one_operator_under_two_establishments_is_one_domain(self) -> None:
        second = _witness("operator-a", "control-only:gamma", "key-b", EV_B, KEY_B)
        _refused(
            monitor.MN_REFUSED_WITNESS_ALIASED,
            lambda: monitor.admit_witnesses(
                _body6(), {"witnesses": [_witness_a(), second]}, k=1,
                at="2026-11-24", keys=KEYS_AB,
            ),
        )

    def test_witness_expired_and_canary(self) -> None:
        expired = _witness_a(expires="2026-01-01")
        _refused(
            monitor.MN_REFUSED_WITNESS_EXPIRED,
            lambda: monitor.admit_witnesses(
                _body6(), {"witnesses": [expired]}, k=1, at="2026-11-24",
                keys=KEYS_AB,
            ),
        )
        result = _accepted(
            lambda: monitor.admit_witnesses(
                _body6(),
                {"witnesses": [expired]},
                k=1,
                at="2026-11-24",
                keys=KEYS_AB,
                disabled=frozenset({"witness-expiry"}),
            )
        )
        self.assertEqual(result["code"], monitor.CODE_OK)

    def test_witness_missing_expiry_is_expired(self) -> None:
        no_expiry = _witness_a()
        del no_expiry["expiresAt"]
        _refused(
            monitor.MN_REFUSED_WITNESS_EXPIRED,
            lambda: monitor.admit_witnesses(
                _body6(), {"witnesses": [no_expiry]}, k=1, at="2026-11-24",
                keys=KEYS_AB,
            ),
        )

    def test_witness_signature_and_canary(self) -> None:
        wrong = _witness_a(sign_body=tlog.parse_signed_checkpoint(_note("5"))[0].body())
        _refused(
            monitor.MN_REFUSED_WITNESS_SIGNATURE,
            lambda: monitor.admit_witnesses(
                _body6(), {"witnesses": [wrong]}, k=1, at="2026-11-24",
                keys=KEYS_AB,
            ),
        )
        result = _accepted(
            lambda: monitor.admit_witnesses(
                _body6(),
                {"witnesses": [wrong]},
                k=1,
                at="2026-11-24",
                keys=KEYS_AB,
                disabled=frozenset({"witness-signature"}),
            )
        )
        self.assertEqual(result["code"], monitor.CODE_OK)

    def test_witness_with_no_key_is_not_verified(self) -> None:
        _refused(
            monitor.MN_REFUSED_WITNESS_SIGNATURE,
            lambda: monitor.admit_witnesses(
                _body6(), {"witnesses": [_witness_a()]}, k=1, at="2026-11-24",
                keys={},
            ),
        )

    def test_io(self) -> None:
        _refused(
            monitor.MN_REFUSED_IO,
            lambda: monitor.CheckpointStore.from_path(B5),
        )

    def test_usage(self) -> None:
        with self.assertRaises(monitor.UsageError):
            monitor.admit_witnesses(
                _body6(), {"witnesses": []}, k=0, at="2026-11-24", keys={}
            )


class FixtureSequence(unittest.TestCase):
    def test_the_real_sequence_is_accepted_in_order(self) -> None:
        store = _store()
        self.assertEqual([r["treeSize"] for r in store.records], [2, 5, 6])
        self.assertEqual(
            [r["rootHash"] for r in store.records],
            [ROOT2.hex(), ROOT5.hex(), ROOT6.hex()],
        )
        self.assertEqual(store.head["treeSize"], 6)
        self.assertEqual(store.observations, 3)

    def test_each_growth_records_a_verified_consistency_proof(self) -> None:
        store = monitor.CheckpointStore()
        results = []
        for size, proof, at in SEQUENCE:
            results.append(
                monitor.observe(
                    store,
                    _note(size),
                    key_name=SIGNER,
                    key=KEY,
                    observed_at=at,
                    source="s",
                    consistency_proof=_proof(proof) if proof else None,
                    expected_origin=ORIGIN,
                )
            )
        self.assertIsNone(results[0]["consistency"])
        for index, (previous, current) in enumerate(zip([2, 5], [5, 6]), 1):
            self.assertEqual(results[index]["consistency"]["from"], previous)
            self.assertEqual(results[index]["consistency"]["to"], current)
            self.assertTrue(results[index]["consistency"]["verified"])

    def test_growth_without_a_proof_is_refused(self) -> None:
        fresh = monitor.CheckpointStore()
        monitor.observe(
            fresh,
            _note("2"),
            key_name=SIGNER,
            key=KEY,
            observed_at="2026-11-24T00:00:01Z",
            source="s",
            expected_origin=ORIGIN,
        )
        _refused(
            monitor.MN_REFUSED_INCONSISTENT,
            lambda: _observe(fresh, _note("6"), "2026-11-24T00:00:02Z"),
        )

    def test_status_reports_the_head_and_the_observation_count(self) -> None:
        result = monitor.status(_store())
        self.assertEqual(result["code"], monitor.CODE_OK)
        self.assertEqual(result["observations"], 3)
        self.assertEqual(result["acceptedSize"], 6)
        self.assertEqual(result["head"]["rootHash"], ROOT6.hex())
        self.assertEqual(result["chain"], "verified")

    def test_status_on_an_empty_store_is_not_an_error(self) -> None:
        result = monitor.status(monitor.CheckpointStore())
        self.assertEqual(result["outcome"], "NO_OBSERVATIONS")
        self.assertEqual(result["observations"], 0)
        self.assertIsNone(result["head"])

    def test_audit_reports_two_transitions(self) -> None:
        audit = _store().audit()
        self.assertEqual(audit["transitions"], 2)
        self.assertEqual(audit["sizes"], [2, 5, 6])
        self.assertEqual(audit["origin"], ORIGIN)

    def test_observation_does_not_require_a_witness(self) -> None:
        # The empty witness set is refused for admission and is irrelevant to
        # observation: a monitor records a head without one.
        store = _store()
        self.assertEqual(store.observations, 3)
        _refused(
            monitor.MN_REFUSED_NO_WITNESS,
            lambda: monitor.admit_witnesses(
                _body6(), {"witnesses": []}, k=1, at="2026-11-24", keys={}
            ),
        )

    def test_a_repeated_identical_head_is_a_reobservation(self) -> None:
        result = _observe(_fresh(_store()), _note("6"), "2026-11-24T00:00:04Z")
        self.assertEqual(result["observations"], 4)
        self.assertEqual(result["treeSize"], 6)


class WitnessDelegation(unittest.TestCase):
    def test_aliases_collapse_through_the_a15_rule(self) -> None:
        approvals = [
            {"identity": "operator-a", "domainId": "control-only:alpha"},
            {"identity": "operator-a", "domainId": "control-only:alpha-alias"},
        ]
        domains = {
            "candidateDomain": "openssl-rs",
            "domains": [
                {"domainId": "control-only:alpha", "independentOfCandidate": True,
                 "kind": "external", "establishedBy": EV_A},
                {"domainId": "control-only:alpha-alias", "independentOfCandidate": True,
                 "kind": "external", "establishedBy": EV_A},
            ],
        }
        result = thresholds.distinct_domains(approvals, domains)
        self.assertEqual(result["count"], 1)
        self.assertEqual(len(result["aliases"]), 1)

    def test_no_witness_means_no_independent_domain(self) -> None:
        empty = {"candidateDomain": "openssl-rs", "domains": []}
        self.assertEqual(thresholds.available_domain_count(empty), 0)
        self.assertEqual(thresholds.distinct_domains([], empty)["count"], 0)

    def test_the_inventory_records_zero_witnesses_and_the_quorum(self) -> None:
        document = json.loads((B5 / "WITNESSES.json").read_text(encoding="utf-8"))
        self.assertEqual(document["inventory"]["witnesses"], 0)
        self.assertEqual(document["inventory"]["independentDomains"], 0)
        self.assertEqual(document["requiredQuorum"]["k"], 3)
        self.assertFalse(document["requiredQuorum"]["met"])
        self.assertEqual(document["outcome"], "NOT_RUN")
        self.assertEqual(document["witnessSet"], [])
        self.assertEqual(document["observed"]["code"], monitor.MN_REFUSED_NO_WITNESS)

    def test_two_distinct_synthetic_domains_can_meet_a_control_quorum(self) -> None:
        result = monitor.admit_witnesses(
            _body6(),
            {"witnesses": [_witness_a(), _witness_b()]},
            k=2,
            at="2026-11-24",
            keys=KEYS_AB,
        )
        self.assertEqual(result["distinctDomains"], 2)
        self.assertEqual(result["required"], 2)


class RecordsAndDeterminism(unittest.TestCase):
    def test_the_committed_store_matches_the_committed_monitor_record(self) -> None:
        data = STORE.read_bytes()
        document = json.loads((B5 / "MONITOR.json").read_text(encoding="utf-8"))
        self.assertEqual(hashlib.sha256(data).hexdigest(), document["store"]["sha256"])
        self.assertEqual(len(data.splitlines()), document["store"]["records"])

    def test_the_store_carries_the_six_named_fields(self) -> None:
        for line in STORE.read_bytes().splitlines():
            record = json.loads(line)
            for key in (
                "origin",
                "treeSize",
                "rootHash",
                "signature",
                "observedAt",
                "source",
            ):
                self.assertIn(key, record)

    def test_the_records_are_accepted_after_a_round_trip(self) -> None:
        store = monitor.CheckpointStore.from_path(STORE)
        self.assertEqual(store.observations, 3)
        self.assertEqual(store.head["rootHash"], ROOT6.hex())

    def test_two_builds_are_byte_identical(self) -> None:
        builder = _builder()
        first = builder.build()
        second = builder.build()
        self.assertEqual(first, second)
        for relative, data in first.items():
            self.assertEqual((B5 / relative).read_bytes(), data, relative)

    def test_three_refusal_controls_in_the_record_fire_their_own_code(self) -> None:
        document = json.loads((B5 / "CONTROLS.json").read_text(encoding="utf-8"))
        self.assertTrue(document["controlOnly"])
        self.assertEqual(len(document["controls"]), document["summary"]["total"])
        for row in document["controls"]:
            self.assertTrue(row["controlOnly"], row["id"])
            self.assertIn(row["code"], monitor.ALL_CODES)

    def test_every_refusal_code_has_a_control(self) -> None:
        document = json.loads((B5 / "CONTROLS.json").read_text(encoding="utf-8"))
        codes = {row["code"] for row in document["controls"]}
        for code in monitor.REFUSALS:
            self.assertIn(code, codes)
        self.assertIn(monitor.CODE_OK, codes)

    def test_the_corrupted_sequence_has_five_controls_with_canaries(self) -> None:
        document = json.loads((B5 / "MONITOR.json").read_text(encoding="utf-8"))
        rows = document["corruptedSequence"]
        self.assertEqual(
            [row["id"] for row in rows],
            ["rollback", "split-view", "origin", "backdated", "store-tampered"],
        )
        for row in rows:
            self.assertTrue(row["canary"]["accepted"], row["id"])
        self.assertEqual(
            [row["code"] for row in rows],
            [
                monitor.MN_REFUSED_ROLLBACK,
                monitor.MN_REFUSED_SPLIT_VIEW,
                monitor.MN_REFUSED_ORIGIN,
                monitor.MN_REFUSED_BACKDATED,
                monitor.MN_REFUSED_STORE_TAMPERED,
            ],
        )


class CommandLine(unittest.TestCase):
    def run_tool(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(TOOL), *arguments],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
            check=False,
        )

    def test_status_prints_the_head_and_exits_zero(self) -> None:
        result = self.run_tool("status")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("code=MN_OK", result.stdout)
        self.assertIn("observations=3", result.stdout)
        self.assertIn(ROOT6.hex(), result.stdout)

    def test_monitor_prints_the_sequence_and_exits_zero(self) -> None:
        result = self.run_tool("monitor")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("code=MN_OK", result.stdout)
        self.assertIn("transitions=2", result.stdout)

    def test_witness_refuses_the_real_inventory_with_no_witness(self) -> None:
        result = self.run_tool("witness")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(monitor.MN_REFUSED_NO_WITNESS, result.stdout)

    def test_status_on_a_tampered_store_exits_one(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "store.jsonl"
            first = STORE.read_bytes().split(b"\n", 1)[0]
            first = first[:-1] + (b"0" if not first.endswith(b"0") else b"1")
            target.write_bytes(first + b"\n" + STORE.read_bytes().split(b"\n", 1)[1])
            result = self.run_tool("status", "--store", str(target))
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(monitor.MN_REFUSED_STORE_TAMPERED, result.stdout)

    def test_usage_error_prints_the_code_and_exits_two(self) -> None:
        result = self.run_tool("observe")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn(monitor.MN_REFUSED_USAGE, result.stdout)

    def test_io_error_prints_the_code_and_exits_two(self) -> None:
        result = self.run_tool("status", "--store", str(B5))
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn(monitor.MN_REFUSED_IO, result.stdout)

    def test_observe_writes_a_store_and_refuses_unproven_growth(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = Path(directory) / "store.jsonl"
            common = [
                "--store", str(store),
                "--key-name", SIGNER,
                "--test-only-key",
                "--expected-origin", ORIGIN,
            ]
            first = self.run_tool(
                "observe", "--note", str(FIXTURE_DIR / "checkpoint-2.note"),
                "--observed-at", "2026-11-24T00:00:01Z", "--source", "test", *common,
            )
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertIn("code=MN_OK", first.stdout)
            unproven = self.run_tool(
                "observe", "--note", str(FIXTURE_DIR / "checkpoint-6.note"),
                "--observed-at", "2026-11-24T00:00:02Z", "--source", "test", *common,
            )
            self.assertEqual(unproven.returncode, 1, unproven.stderr)
            self.assertIn(monitor.MN_REFUSED_INCONSISTENT, unproven.stdout)
            proven = self.run_tool(
                "observe", "--note", str(FIXTURE_DIR / "checkpoint-6.note"),
                "--observed-at", "2026-11-24T00:00:03Z", "--source", "test",
                "--proof", str(FIXTURE_DIR / "consistency-2-6.json"), *common,
            )
            self.assertEqual(proven.returncode, 0, proven.stderr)
            status = self.run_tool("status", "--store", str(store))
        self.assertIn("observations=2", status.stdout)

    def test_json_status_is_well_formed(self) -> None:
        result = self.run_tool("status", "--json")
        self.assertEqual(result.returncode, 0, result.stderr)
        document = json.loads(result.stdout)
        self.assertEqual(document["acceptedSize"], 6)


class DocumentSynchronisation(unittest.TestCase):
    def test_the_document_exists_and_names_every_code(self) -> None:
        text = DOCUMENT.read_text(encoding="utf-8")
        for code in monitor.ALL_CODES:
            self.assertIn(code, text, code)

    def test_the_document_quotes_the_real_run(self) -> None:
        text = DOCUMENT.read_text(encoding="utf-8")
        document = json.loads((B5 / "MONITOR.json").read_text(encoding="utf-8"))
        self.assertIn(document["finalHead"]["rootHash"], text)
        self.assertIn("observations: 3", text)
        self.assertIn("witnesses: 0", text)
        self.assertIn("NOT_RUN", text)

    def test_the_document_names_the_store_and_the_delegation(self) -> None:
        text = DOCUMENT.read_text(encoding="utf-8")
        self.assertIn("evidence/b5/store/monitor-store.jsonl", text)
        self.assertIn("forensics/tools/thresholds.py", text)
        self.assertIn("forensics/tools/tlog.py", text)


if __name__ == "__main__":
    unittest.main()
