#!/usr/bin/env python3
"""build_evidence.py -- deterministic producer of the A19 correction records.

It writes four documents and nothing else:

  * ``EVENTS.json``      -- the real correction log: eleven subjects, each with an
    ``assert`` that records what was believed and a bound ``correct`` or
    ``retract``.  Every event is signed with A10's test-only HMAC-SHA256 signer;
    the log carries a digest chain over every event and a DSSE envelope over its
    own canonical bytes.  The label is ``SELF_ISSUED``; no authentication is
    claimed.
  * ``PROPAGATION.json`` -- the dependents of each corrected record, derived from
    the records' own citations of the superseded digest or value, with the
    citation line and the supersession marker that establish each dependency.
  * ``STATUS.json``      -- per subject: the outcome, whether it is
    authenticated, and where the original is preserved.
  * ``CONTROLS.json``    -- one ``control-only`` fixture per refusal code,
    including a fork, a cycle, an edited event, a retraction whose dependent is
    left valid, and a spurious invalidation.

Nothing reads the clock.  The recorded times are declared literals.  Two runs
are byte-identical; the producer reads the real records for their digests and
citations and never rewrites another item's evidence.

Usage:
    python3 evidence/a19/build_evidence.py [--out DIR]

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS = REPO_ROOT / "forensics/tools"
EVIDENCE = REPO_ROOT / "evidence/a19"
sys.path.insert(0, str(TOOLS))

import corrections as cr  # noqa: E402
import dsse  # noqa: E402

BASE_COMMIT = "6bf8c80aa9419addc85998f21a0c3010e697c4b3"
BASE_COMMIT_SHORT = "6bf8c80aa"
ITEM = "A19"
AS_OF = "2026-11-24"

T0 = "2026-11-22T00:00:00Z"
T1 = "2026-11-23T00:00:00Z"
T2 = "2026-11-24T00:00:00Z"

P_CAMPAIGN = "P-CAMPAIGN"

CANDIDATE = {
    "baseCommit": BASE_COMMIT,
    "baseCommitShort": BASE_COMMIT_SHORT,
    "branch": "staging",
    "recordedAt": AS_OF,
}


def write_json(path: Path, document: Mapping[str, Any]) -> None:
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def bound(
    value: Any,
    citation: str,
    *,
    path: str | None = None,
    sha256: str | None = None,
    committed: bool | None = None,
    commit: str | None = None,
) -> dict[str, Any]:
    record: dict[str, Any] | None = None
    if path is not None:
        record = {
            "path": path,
            "sha256": sha256,
            "committed": bool(committed),
        }
        if commit is not None:
            record["commit"] = commit
    return {
        "value": value,
        "digest": cr.value_digest(value),
        "citation": citation,
        "record": record,
    }


# ---------------------------------------------------------------------------
# The real correction events.  Every old value is the value the project
# believed; every record digest is the digest at the stated commit.
# ---------------------------------------------------------------------------


A4_OLD = bound(
    {"byteLength": 165, "byteLengthHex": "0xA5", "observation": "size: 0xA5"},
    "0xA5",
    path="evidence/a4/INSTANCES.json",
    sha256=None,
    committed=False,
    commit="before 5f868b04f",
)
A4_NEW = bound(
    {
        "byteLength": 357,
        "byteLengthHex": "0x165",
        "observation": "size: 0x165",
        "oneBytePast": 358,
    },
    "0x165",
    path="evidence/a4/INSTANCES.json",
    sha256="4887d605e822d67be878dc967d455958c5ab42625ad2ec26e9c52355219f584f",
    committed=True,
    commit="5f868b04f",
)

GATE_OLD = bound(
    {
        "comparedFields": [
            "steps[i].prerequisites[j].detail",
            "steps[i].reason",
            "candidate.untracked_changes",
        ],
        "memAvailable": "read live on every step and run and compared",
        "tmpMaterialisation": "only an argument exactly equal to {tmp} was substituted",
    },
    "MemAvailable 10 GiB",
    path="forensics/tools/verify.py",
    sha256="20e9e125392b5161de218d9541877a3e1a16345d532bf93c37774913632e4334",
    committed=True,
    commit="1efd02cbd^",
)
GATE_NEW = bound(
    {
        "comparedFields": "every top-level field except environment",
        "memAvailable": "sampled once into the declared environment block and excluded",
        "tmpMaterialisation": "{tmp} is substituted wherever it appears",
        "refusal": "environment_declaration_problem; normalised memory echo",
    },
    "declared environment block",
    path="forensics/tools/verify.py",
    sha256="17a9f2ae75614eaff52dd0bd833e30af05721e53a957e6209f68f1fa3fed4fc3",
    committed=True,
    commit="1efd02cbd",
)

A7_OLD_DIGEST = "f2d6e37928a6fd05fa295a06cb54bd64a495336ab0af0a66403bcdbfbb0fe188"
A7_NEW_DIGEST = "2a5a3f863c1ddf7775d0f524e7b36feb9f01a22a6c6569eff1d3c93081ae1cab"
A7_OLD = bound(
    {
        "commit": "1efd02cbd1401c4cffb854b906c021915df94386",
        "asOf": "2026-11-24",
        "branch": "staging",
        "inputs": None,
        "producerRead": "git rev-parse HEAD",
    },
    A7_OLD_DIGEST,
    path="evidence/a7/BASELINES.json",
    sha256=A7_OLD_DIGEST,
    committed=True,
    commit="1efd02cbd",
)
A7_NEW = bound(
    {
        "commit": "1efd02cbd1401c4cffb854b906c021915df94386",
        "asOf": "2026-11-24",
        "inputs": "16 files by repo-relative path and full-length SHA-256",
        "producerRead": "explicit --source-commit; the default is the recorded value",
        "refusal": "BL_REFUSED_INPUT_DIGEST_MISMATCH",
    },
    A7_NEW_DIGEST,
    path="evidence/a7/BASELINES.json",
    sha256=A7_NEW_DIGEST,
    committed=True,
    commit="f1c5047a5",
)

A11_OLD_DIGEST = "9cc6680f1845b3589034f71f2ff5751338fa23efd041fed53d43c2a806e5376e"
A11_NEW_DIGEST = "0307db34a7cbb3e253462b4b0a3ead946b3d698a6a65e8f78ec02da163cb5b5a"
A11_OLD = bound(
    {
        "population": "live glob evidence/*.json over git ls-files, evidence/a11/ excluded",
        "files": 386,
        "schema": "openssl-rs/a11/scan/1",
        "countSource": "the glob plus a fixed files: 386",
    },
    A11_OLD_DIGEST,
    path="evidence/a11/SCAN.json",
    sha256=A11_OLD_DIGEST,
    committed=True,
    commit="f1c1a535d",
)
A11_NEW = bound(
    {
        "population": "explicit frozen 386-member {path, sha256, bytes} list",
        "files": 386,
        "schema": "openssl-rs/a11/scan/2",
        "countSource": "the length of the member list",
        "driftRefusal": "PH_REFUSED_POPULATION_DRIFT",
        "growth": "NEW_SINCE_RECORD",
    },
    A11_NEW_DIGEST,
    path="evidence/a11/SCAN.json",
    sha256=A11_NEW_DIGEST,
    committed=True,
    commit="4e9262bf3",
)

A16_OLD_DIGEST = "b6c06350098bda9227f58defc873b4676113cd54bceb89f4cb82497d18021bf1"
A16_NEW_DIGEST = "a7e200603059828c113ad0704cd3a4b9a6e89feae5cbbd5b8b7e5dbbf03916c2"
A16_OLD = bound(
    {
        "populationFiles": 407,
        "population": "live glob evidence/**/*.json",
        "schema": "openssl-rs/a16/bundle-inventory/1",
        "note": "407 was the 404 evidence JSON files at 67187c39e plus this item's three records",
    },
    A16_OLD_DIGEST,
    path="evidence/a16/INVENTORY.json",
    sha256=A16_OLD_DIGEST,
    committed=True,
    commit="67187c39e",
)
A16_NEW = bound(
    {
        "populationFiles": 404,
        "population": "explicit frozen 404-member {path, sha256, bytes} list",
        "schema": "openssl-rs/a16/bundle-inventory/2",
        "countSource": "the length of the member list",
        "driftRefusal": "PH_REFUSED_POPULATION_DRIFT",
        "growth": "NEW_SINCE_RECORD",
    },
    A16_NEW_DIGEST,
    path="evidence/a16/INVENTORY.json",
    sha256=A16_NEW_DIGEST,
    committed=True,
    commit="2e8e9aa65",
)

KDK_OLD = bound(
    {
        "construction": "SHA-256(decrypted block) keys the synthetic answer",
        "property": "attacker-computable for an attacker-chosen block m and c = m^e mod n",
        "domainSeparation": False,
    },
    "SHA-256(decrypted block)",
)
KDK_NEW = bound(
    {
        "construction": "SHA-256(KEY_LABEL || p || q) with the CRT primes, otherwise a 32-byte RAND_priv_bytes per-key secret",
        "domainSeparation": True,
        "failure": "RNG or allocation failure is the defined refusal; no publicly derivable fallback",
        "residual": "the returned length remains a channel, measured over 2,048 invalid blocks",
    },
    "KEY_LABEL",
    path="evidence/haz-15/KDK-CORRECTION.md",
    sha256="42b61e280c7c85f04b88cea42ab863ee8e5bf5aa2a27909c16079e2f8d451c6c",
    committed=True,
    commit="c28ac7bb9",
)

POSTERIOR_OLD = bound(
    {
        "statement": "P(valid | L=48) = 99.6%",
        "assumption": "equal priors",
        "scope": "quoted unconditionally",
    },
    "99.6%",
)

CLAIMS_OLD_DIGEST = "65d8105b744c80ae01e76af8bf3370c478ab116c7fc9b0f16f63eea5d5c579de"
CLAIMS_NEW_DIGEST = "2968ffd6976f19bd701c58636b51cceed192e42c928dd2116217449a7b85a1bb"
CLAIM_HISTORY = REPO_ROOT / "evidence/etp-t15/history/claims.before-reconciliation.json"
CLAIM_LIVE = REPO_ROOT / "evidence/etp/claims.json"


def load_claim_objects() -> tuple[dict[str, Any], dict[str, Any]]:
    """The exact original and successor claim objects, by claim id.

    The binding is the claim object's own digest, not the digest of the file
    that carries it: a file digest is shared by four claims and by every record
    that cites the claims set as an input, which would make the dependency
    relation meaningless.  The file digest is recorded in ``preservation``.
    """
    old_document = json.loads(CLAIM_HISTORY.read_text(encoding="utf-8"))
    new_document = json.loads(CLAIM_LIVE.read_text(encoding="utf-8"))
    old = {row["id"]: row for row in old_document["claims"]}
    new = {row["id"]: row for row in new_document["claims"]}
    return old, new


def claim_value(claim_id: str, verdict: str, object_sha: str) -> dict[str, Any]:
    return {"claimId": claim_id, "verdict": verdict, "objectSha256": object_sha}


CLAIM_SPECS = [
    {
        "id": "ETP0-CLM-004",
        "old_sha": "63e6c1ee48fc2aadd7518e195c220ccf1816b777db3b58ab389c73384bcf6d28",
        "new_verdict": "SUPERSEDED",
        "new_sha": "dde26d60f432719072d06b34ebe4c2e7271c4f19d5ca0ab70ef4a3c49e0d828a",
        "reason": (
            "the seal prose asserted all_pass true and 5/5 while "
            "artifacts/phase18/COURTS.json records all_pass false, pass 4 / fail 1, "
            "with HOSTILE-BOUNDARY-REGISTER failing on 56 UNSAFE-FOOTPRINT bounds; "
            "the obligation ledger records implemented 4 / open 1. The prose is "
            "the wrong side. The claim is SUPERSEDED by "
            "docs/PHASE-18-HARDENING-SEAL-ERRATUM.md; the measurement stands and "
            "the failing court is not made to pass."
        ),
        "section": "4.1",
    },
    {
        "id": "ETP0-CLM-005",
        "old_sha": "4e86a41696a9b8a9951ac21926561a469a72df521f707faaf9ae1bbc345dbd80",
        "new_verdict": "SUPERSEDED",
        "new_sha": "f429f92a29b643a129ecee4cedebb4c30b56e4e049b85f84da14fe7f7f5d1c5a",
        "reason": (
            "the seal prose was internally inconsistent (110 vs 50 vs 150 "
            "percent); the probe SEP_PCT 150 and the machine field "
            "threshold_percent 150 agree, and the registry's own claim field "
            "still says 50 percent. The measurement is self-consistent; the "
            "prose and the descriptive field are the defect. The claim is "
            "SUPERSEDED; the measurement is not changed and the field defect is "
            "recorded, not repaired."
        ),
        "section": "4.2",
    },
    {
        "id": "ETP0-CLM-030",
        "old_sha": "a826b94005dcf9f0c6264d8971badb7307779d8f578a947ff1b7afb7b13e9e25",
        "new_verdict": "RISK_ACCEPTED",
        "new_sha": "7678946b5d35117f0150e0ffee73af0d18c58168651a78d987566d22f4247e73",
        "reason": (
            "the graduation record issued SAFE_COMPATIBLE while its own closure "
            "receipts record verdict.safe_compatible=false, the freeze records "
            "safe_compatible=false and not_graduated=true, and the adjudication "
            "records NOT ESTABLISHED. It is reclassified RISK_ACCEPTED with the "
            "accepted obligations named; SAFE_COMPATIBLE remains NOT_ESTABLISHED."
        ),
        "section": "4.3",
    },
    {
        "id": "ETP0-CLM-032",
        "old_sha": "3344bd92ecff32f9226338216fde0df83c750a9e9b466f03f868c84f028b171e",
        "new_verdict": "SUPERSEDED",
        "new_sha": "bac28d0afabc4ed35bb1c10eacc145df6331f799b593146f19609d82c5042b89",
        "reason": (
            "CAMPAIGN-STATUS.json recorded consumers.safe_compatible = 1 and a "
            "SAFE_COMPATIBLE verdict while its own note and non_claims said 0/33. "
            "The ledger now records 0 safe_compatible and 1 risk_accepted for "
            "openssh, preserving the previous 1/33 value in its history fields; "
            "the claim is SUPERSEDED and the 1/33 reading is recorded as "
            "inheriting the graduation's error."
        ),
        "section": "4.4",
    },
]


def real_specs() -> list[dict[str, Any]]:
    specs: list[dict[str, Any]] = [
        {
            "subject": "A4/L3-md32-update/byteLength",
            "old": A4_OLD,
            "new": A4_NEW,
            "kind": "correct",
            "assert_at": T2,
            "correct_at": T2,
            "assert_reason": (
                "the record as it stood before the observation control: the "
                "nm --format=posix size field 165 was read as decimal."
            ),
            "correct_reason": (
                "the nm --format=posix size field is hexadecimal. readelf -sW "
                "reports 357 for _RINvNtNtCsfBoMNNx3tZr_10openssl_rs6digest4md32"
                "6updateNtNtB4_3md46Md4CtxEB6_ at 0x1b4d20, and the next update "
                "instantiation begins at 0x1b4e90; 357 ends at 0x1b4e7d with 11 "
                "bytes of alignment padding, while 165 would leave a 203-byte "
                "gap. The repair changed only evidence/a4/{build_instances.py,"
                "CLASSES.json,INSTANCES.json}."
            ),
            "assert_evidence": ["evidence/a4/RECEIPT.md#6", "commit:5f868b04f"],
            "correct_evidence": [
                "evidence/a4/RECEIPT.md#6",
                "readelf -sW _RINvNtNtCsfBoMNNx3tZr_10openssl_rs6digest4md326updateNtNtB4_3md46Md4CtxEB6_ = 357",
                "commit:5f868b04f",
            ],
            "original": "prose-only",
            "recorded_as": "prose-only",
            "preservation": {
                "path": "evidence/a4/RECEIPT.md",
                "section": "§6",
                "commit": "5f868b04f",
                "sha256": "0f35f96b7a1772e4f044e4567d1e9e703c29cc21849f4ebe1146aebad387cb8a",
                "note": "the pre-correction record was not committed; the old value 0xA5 is preserved only in the receipt",
            },
        },
        {
            "subject": "gate-reliability/verify-deterministic-projection",
            "old": GATE_OLD,
            "new": GATE_NEW,
            "kind": "correct",
            "assert_at": T2,
            "correct_at": T2,
            "assert_reason": (
                "the record as it stood before the determinism repair: a live "
                "MemAvailable reading was stored in two compared fields, and a "
                "{tmp} token was substituted only when an argument equalled it "
                "exactly."
            ),
            "correct_reason": (
                "verify.prerequisites read /proc/meminfo on every step and every "
                "run and run_step stored the reading in "
                "steps[i].prerequisites[j].detail and steps[i].reason. The {tmp} "
                "materialisation replaced only an argument exactly equal to {tmp}, "
                "so --out {tmp}/repro passed the literal token; run 1 created an "
                "untracked directory and run 2 read a different untracked count. "
                "The compared projection now excludes a declared environment "
                "block, normalises an echoed MemAvailable, substitutes {tmp} "
                "wherever it appears, and the end-to-end control requires each "
                "run to declare and populate the environment block."
            ),
            "assert_evidence": [
                "evidence/gate-reliability/RECEIPT.md#3",
                "evidence/gate-reliability/RECEIPT.md#4",
            ],
            "correct_evidence": [
                "evidence/gate-reliability/RECEIPT.md#3",
                "evidence/gate-reliability/RECEIPT.md#4",
                "evidence/gate-reliability/RECEIPT.md#5",
                "commit:1efd02cbd",
            ],
            "original": "prose-only",
            "recorded_as": "prose-only",
            "preservation": {
                "path": "evidence/gate-reliability/RECEIPT.md",
                "section": "§3-§5",
                "commit": "1efd02cbd",
                "sha256": "c051be4a89d95d235877ccad9f07abc8b77a0a414e54a87bc37a9e0b3b971689",
                "note": "the failing text and the before/after mechanism are preserved in the receipt; the old verify.py bytes are at 1efd02cbd^",
            },
        },
        {
            "subject": "A7/sourceIdentity",
            "old": A7_OLD,
            "new": A7_NEW,
            "kind": "correct",
            "assert_at": T2,
            "correct_at": T2,
            "assert_reason": (
                "the record as it stood before the repair: sourceIdentity.commit "
                "was the live HEAD at the moment the producer ran."
            ),
            "correct_reason": (
                "sourceIdentity.commit was the live HEAD of the measured source S, "
                "while the record is carried by the evidence commit E; rebuilding "
                "at E recorded E's token, so the committed bytes could never be "
                "reproduced at the commit that carries them. The identity is now "
                "an explicit input (--source-commit, defaulting to the recorded "
                "value) and the record names the 16 input files by path and "
                "SHA-256; verify_input_digests refuses "
                "BL_REFUSED_INPUT_DIGEST_MISMATCH for a changed, removed or newly "
                "read input. The measured content is identical except for "
                "sourceIdentity."
            ),
            "assert_evidence": [
                "evidence/a7/RECEIPT.md#11.1",
                "commit:1efd02cbd",
            ],
            "correct_evidence": [
                "evidence/a7/RECEIPT.md#11.2",
                "evidence/a7/RECEIPT.md#11.3",
                "commit:f1c5047a5",
            ],
            "original": "prose-only",
            "recorded_as": "prose-only",
            "preservation": {
                "path": "evidence/a7/RECEIPT.md",
                "section": "§11",
                "commit": "f1c5047a5",
                "sha256": "8c00cd7aabe8bb1aba0c47981f581fd7aa709452d65fdee66ebd8b88a797efd5",
                "note": "the old and new BASELINES.json digests are preserved in §11.3; the old bytes are at 1efd02cbd",
            },
        },
        {
            "subject": "A11/SCAN.json/population",
            "old": A11_OLD,
            "new": A11_NEW,
            "kind": "correct",
            "assert_at": T2,
            "correct_at": T2,
            "assert_reason": (
                "the record as it stood at f1c1a535d: the population was the live "
                "glob evidence/*.json over git ls-files plus a fixed files: 386."
            ),
            "correct_reason": (
                "the record stored a live glob plus a fixed count, so every item "
                "that added a JSON record under evidence/ changed the glob's "
                "answer while the record still claimed 386; it was valid only at "
                "the commit that produced it. The population is now an explicit "
                "frozen member list of {path, sha256, bytes} at f1c1a535d, "
                "re-hashed on every verification, never a live glob. A removed or "
                "changed member is PH_REFUSED_POPULATION_DRIFT; a new glob match "
                "is NEW_SINCE_RECORD and is not absorbed. The frozen count stays "
                "386, so the record remains byte-stable as later items land."
            ),
            "assert_evidence": [
                "evidence/a11/RECEIPT.md#12",
                "commit:f1c1a535d",
            ],
            "correct_evidence": [
                "evidence/a11/RECEIPT.md#12",
                "commit:4e9262bf3",
            ],
            "original": "prose-only",
            "recorded_as": "prose-only",
            "preservation": {
                "path": "evidence/a11/RECEIPT.md",
                "section": "§12",
                "commit": "4e9262bf3",
                "sha256": "a548c427f9ef5fac1a0e91b1d3612547eb834e2eb8d288e5a2d3d69b207227a4",
                "note": "the old SCAN.json digest 9cc6680f is preserved in §12; the old bytes are at f1c1a535d",
            },
        },
        {
            "subject": "A16/INVENTORY.json/populationFiles",
            "old": A16_OLD,
            "new": A16_NEW,
            "kind": "correct",
            "assert_at": T2,
            "correct_at": T2,
            "assert_reason": (
                "the record as it stood at 67187c39e: populationFiles was 407, "
                "read from the live glob evidence/**/*.json."
            ),
            "correct_reason": (
                "A17's six records made the live count 413, so the committed "
                "record stopped reproducing. The 407 was itself the wrong "
                "population: it was the 404 evidence JSON files at 67187c39e plus "
                "this item's own three records, and a record cannot contain its "
                "own sha256. The population is now the explicit frozen 404-member "
                "list at 67187c39e, re-hashed on every verification; a changed or "
                "removed member is PH_REFUSED_POPULATION_DRIFT and growth is "
                "reported as NEW_SINCE_RECORD, never absorbed."
            ),
            "assert_evidence": [
                "evidence/a16/RECEIPT.md#11",
                "commit:67187c39e",
            ],
            "correct_evidence": [
                "evidence/a16/RECEIPT.md#11",
                "commit:2e8e9aa65",
            ],
            "original": "prose-only",
            "recorded_as": "prose-only",
            "preservation": {
                "path": "evidence/a16/RECEIPT.md",
                "section": "§11",
                "commit": "2e8e9aa65",
                "sha256": "b0d6a67fcc9db58247eedac3686aa693be154baeff5d65ef80a8a3aabf7f73a9",
                "note": "the old INVENTORY.json digest b6c06350 is preserved in §11; the old bytes are at 67187c39e",
            },
        },
        {
            "subject": "HAZ-15/external-key-KDK",
            "old": KDK_OLD,
            "new": KDK_NEW,
            "kind": "correct",
            "assert_at": T0,
            "correct_at": T0,
            "assert_reason": (
                "the earlier construction keyed the external-key synthetic answer "
                "with SHA-256(decrypted block)."
            ),
            "correct_reason": (
                "for an attacker-chosen block m and c = m^e mod n the attacker "
                "knows m, so SHA-256(decrypted block) - and the synthetic answer "
                "it keys - is attacker-computable. The construction is withdrawn. "
                "When the object holds d the existing internal-key path is "
                "unchanged; otherwise the KDK is SHA-256(KEY_LABEL || p || q) when "
                "the CRT primes are present, or a 32-byte secret drawn with "
                "RAND_priv_bytes at first use, every new derivation "
                "domain-separated by its own label. RNG or allocation failure is "
                "the defined refusal, never a fallback to a publicly derivable "
                "value."
            ),
            "assert_evidence": [
                "docs/SECURITY_DIVERGENCE_POLICY.md#D-RSA-EXTKEY-ORACLE-1",
                "commit:c28ac7bb9^",
            ],
            "correct_evidence": [
                "evidence/haz-15/KDK-CORRECTION.md",
                "docs/SECURITY_DIVERGENCE_POLICY.md#D-RSA-EXTKEY-ORACLE-1",
                "commit:c28ac7bb9",
                "commit-subject:rsa: withdraw the unkeyed KDK and key the synthetic answer properly",
            ],
            "original": "prose-only",
            "recorded_as": "prose-only",
            "preservation": {
                "path": "evidence/haz-15/KDK-CORRECTION.md",
                "section": "the whole document",
                "commit": "c28ac7bb9",
                "sha256": "42b61e280c7c85f04b88cea42ab863ee8e5bf5aa2a27909c16079e2f8d451c6c",
                "note": "the retraction is recorded in the KDK-CORRECTION document and the commit message; no signed correction event exists",
            },
        },
        {
            "subject": "HAZ-15/posterior-probability-99.6",
            "old": POSTERIOR_OLD,
            "new": None,
            "kind": "retract",
            "assert_at": T0,
            "correct_at": T0,
            "assert_reason": (
                "an earlier revision of the receipt quoted "
                "P(valid | L=48) = 99.6% unconditionally."
            ),
            "correct_reason": (
                "the 99.6% figure quoted an unconditional posterior and silently "
                "assumed equal priors. The measured quantity is a likelihood: "
                "p_hat = 0.00439 (95% Wilson [0.00231, 0.00833]). The posterior "
                "is pi / (pi + (1-pi)*0.00439): 0.9954 at pi = 0.5, 0.958 at "
                "pi = 0.1, 0.696 at pi = 0.01. The unconditional 99.6% statement "
                "is withdrawn; the conditional formula is what the record states."
            ),
            "assert_evidence": [
                "evidence/haz-15/REENTRANCY-AND-LENGTH.md#5.3",
            ],
            "correct_evidence": [
                "evidence/haz-15/REENTRANCY-AND-LENGTH.md#5.3",
                "commit:4cafcd0ea",
            ],
            "original": "prose-only",
            "recorded_as": "prose-only",
            "preservation": {
                "path": "evidence/haz-15/REENTRANCY-AND-LENGTH.md",
                "section": "§5.3",
                "commit": "4cafcd0ea",
                "sha256": "240165e76eae6a76b98ddaf803f73706384607aa2aaa6427dac04e48d0c1bd37",
                "note": "the earlier revision is not committed; the withdrawal and the conditional formula are preserved in §5.3",
            },
        },
    ]
    old_objects, new_objects = load_claim_objects()
    for spec in CLAIM_SPECS:
        old_object = old_objects[spec["id"]]
        new_object = new_objects[spec["id"]]
        old = bound(
            old_object,
            cr.value_digest(old_object),
            path="evidence/etp-t15/history/claims.before-reconciliation.json",
            sha256=None,
            committed=True,
            commit="e0b727d06",
        )
        new = bound(
            new_object,
            cr.value_digest(new_object),
            path="evidence/etp/claims.json",
            sha256=None,
            committed=True,
            commit="e0b727d06",
        )
        if old["digest"] != spec["old_sha"]:
            raise SystemExit(
                f"{spec['id']}: the history copy's object digest changed "
                f"({old['digest']} != {spec['old_sha']})"
            )
        if new["digest"] != spec["new_sha"]:
            raise SystemExit(
                f"{spec['id']}: the live claim object digest changed "
                f"({new['digest']} != {spec['new_sha']})"
            )
        specs.append(
            {
                "subject": f"{spec['id']}/verdict",
                "old": old,
                "new": new,
                "kind": "retract",
                "assert_at": T0,
                "correct_at": T1,
                "assert_reason": (
                    f"the claim as it was asserted and refused by the release "
                    f"gate: {spec['id']} read CONTRADICTED."
                ),
                "correct_reason": spec["reason"],
                "assert_evidence": [
                    "evidence/etp7/RECEIPT.md#3",
                    f"etp0/claims.before-reconciliation.json#{spec['id']}",
                ],
                "correct_evidence": [
                    "evidence/etp7/RECEIPT.md#3",
                    f"docs/ADJUDICATION-RECONCILIATION.md#{spec['section']}",
                    "evidence/etp/claims.json",
                    "commit:e0b727d06",
                ],
                "original": "machine-readable-unsigned",
                "recorded_as": "machine-readable-unsigned",
                "preservation": {
                    "path": "evidence/etp-t15/history/claims.before-reconciliation.json",
                    "section": f"claims[{spec['id']}]",
                    "commit": "e0b727d06",
                    "sha256": CLAIMS_OLD_DIGEST,
                    "note": "the original claim object is preserved byte-for-byte in the history copy; the live claims.json records the successor verdict",
                },
            }
        )
    return specs


def authentication(original: str) -> dict[str, Any]:
    return {
        "status": "SELF_ISSUED",
        "authenticated": False,
        "original": original,
        "signer": "A10 test-only HMAC-SHA256 (fixed public seed)",
        "keyid": dsse.test_only_keyid(),
        "basis": (
            "the signature is over the canonical event bytes with A10's test-only "
            "HMAC-SHA256 key; it proves byte integrity, not identity or role. A14 "
            "records no declared identity, so the event is not authenticated."
        ),
    }


def make_event(
    event_id: str,
    kind: str,
    subject: str,
    *,
    previous: Mapping[str, Any] | None,
    old: Mapping[str, Any] | None,
    new: Mapping[str, Any] | None,
    reason: str,
    recorded_at: str,
    evidence: Sequence[str],
    original: str,
    role: str | None = None,
) -> dict[str, Any]:
    supersedes = None
    if previous is not None:
        supersedes = {
            "previousEventId": previous["eventId"],
            "previousDigest": cr.event_digest(previous),
        }
    event = {
        "schema": cr.EVENT_SCHEMA,
        "eventId": event_id,
        "kind": kind,
        "subject": subject,
        "supersedes": supersedes,
        "reason": reason,
        "oldValue": old,
        "newValue": new,
        "recordedAt": recorded_at,
        "recordedBy": {
            "role": role or cr.CORRECTING_ROLE[kind],
            "identity": P_CAMPAIGN,
        },
        "evidence": list(evidence),
        "authentication": authentication(original),
    }
    return cr.sign_event(event)


INPUTS = [
    "evidence/a14/ROLES.json",
    "evidence/a4/RECEIPT.md",
    "evidence/a7/RECEIPT.md",
    "evidence/a11/RECEIPT.md",
    "evidence/a16/RECEIPT.md",
    "evidence/gate-reliability/RECEIPT.md",
    "evidence/haz-15/KDK-CORRECTION.md",
    "evidence/haz-15/REENTRANCY-AND-LENGTH.md",
    "evidence/etp/claims.json",
    "evidence/etp-t15/history/claims.before-reconciliation.json",
    "evidence/etp7/RECEIPT.md",
    "docs/ADJUDICATION-RECONCILIATION.md",
    "docs/SECURITY_DIVERGENCE_POLICY.md",
    "forensics/tools/dsse.py",
]


def source_identity() -> dict[str, Any]:
    inputs = []
    for rel in INPUTS:
        path = REPO_ROOT / rel
        if path.is_file():
            inputs.append({"path": rel, "sha256": cr.sha256_file(path)})
    return {
        "item": ITEM,
        "asOf": AS_OF,
        "baseCommit": BASE_COMMIT,
        "baseCommitShort": BASE_COMMIT_SHORT,
        "branch": "staging",
        "tool": cr.tool_identity(),
        "inputs": inputs,
    }


def build_real_log() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    specs = real_specs()
    log = cr.new_log(
        source_identity=source_identity(),
        authentication={
            "status": "SELF_ISSUED",
            "authenticated": False,
            "signer": "A10 test-only HMAC-SHA256 (fixed public seed)",
            "keyid": dsse.test_only_keyid(),
            "note": (
                "the log envelope proves the log bytes have not changed since "
                "signing; it does not establish an independent recorder. Every "
                "real event is a reconstruction of a prose or unsigned record."
            ),
        },
    )
    rows: list[dict[str, Any]] = []
    counter = 0
    for spec in specs:
        counter += 1
        assert_id = f"A19-E{counter:02d}"
        assert_event = make_event(
            assert_id,
            "assert",
            spec["subject"],
            previous=None,
            old=None,
            new=spec["old"],
            reason=spec["assert_reason"],
            recorded_at=spec["assert_at"],
            evidence=spec["assert_evidence"],
            original=spec["original"],
        )
        log = cr.append(log, assert_event)
        counter += 1
        successor_id = f"A19-E{counter:02d}"
        successor = make_event(
            successor_id,
            spec["kind"],
            spec["subject"],
            previous=assert_event,
            old=spec["old"],
            new=spec["new"],
            reason=spec["correct_reason"],
            recorded_at=spec["correct_at"],
            evidence=spec["correct_evidence"],
            original=spec["original"],
        )
        log = cr.append(log, successor)
        rows.append(
            {
                "subject": spec["subject"],
                "assert": assert_event,
                "successor": successor,
                "spec": spec,
            }
        )
    return log, rows


# ---------------------------------------------------------------------------
# Propagation
# ---------------------------------------------------------------------------


def build_propagation(log: Mapping[str, Any]) -> dict[str, Any]:
    dependents = cr.derive_dependents(log, REPO_ROOT)
    report = cr.propagate_report(log, dependents)
    by_digest: dict[str, list[dict[str, Any]]] = {}
    for row in report["dependents"]:
        for digest in row["supersededCites"]:
            by_digest.setdefault(digest, []).append(row)
    events: list[dict[str, Any]] = []
    for event in log["events"]:
        if event["kind"] not in (cr.KIND_CORRECT, cr.KIND_RETRACT):
            continue
        digests = cr.superseded_digests(event)
        rows = sorted(
            {
                row["id"]: row
                for digest in digests
                for row in by_digest.get(digest, [])
            }.values(),
            key=lambda row: row["id"],
        )
        events.append(
            {
                "eventId": event["eventId"],
                "subject": event["subject"],
                "kind": event["kind"],
                "supersededDigests": digests,
                "dependents": rows,
                "summary": {
                    "dependents": len(rows),
                    "invalidated": sum(
                        1 for row in rows if row["state"] == "INVALIDATED"
                    ),
                    "valid": sum(1 for row in rows if row["state"] == "VALID"),
                },
            }
        )
    all_rows = {row["id"]: row for row in report["dependents"]}
    document: dict[str, Any] = {
        "schema": cr.PROPAGATION_SCHEMA,
        "model": cr.MODEL_ID,
        "candidate": CANDIDATE,
        "sourceIdentity": {"baseCommit": BASE_COMMIT, "item": ITEM},
        "method": {
            "supersededDigest": (
                "a correct/retract supersedes its oldValue.digest (the exact "
                "value) and, when present, oldValue.record.sha256 (the exact "
                "record)."
            ),
            "dependentDerivation": (
                "derive_dependents walks evidence/, docs/, forensics/tools/ and "
                "courts/ for the superseded digests and the event's "
                "oldValue.citation; the citation line and the nearest "
                "supersession marker are recorded. No dependent list is "
                "hand-written."
            ),
            "declaredState": (
                "INVALIDATED when the citing record carries a supersession "
                "marker (withdrawn/superseded/old value/correction/...); VALID "
                "otherwise. This is a reported classification, not a proof. Every "
                "citation is recorded so a reviewer can check it."
            ),
        },
        "events": events,
        "dependents": sorted(all_rows.values(), key=lambda row: row["id"]),
        "summary": {
            "corrections": len(events),
            "dependents": len(all_rows),
            "invalidated": sum(
                1 for row in all_rows.values() if row["state"] == "INVALIDATED"
            ),
            "valid": sum(1 for row in all_rows.values() if row["state"] == "VALID"),
            "stale": sum(
                1
                for row in all_rows.values()
                if row["supersededCites"] and row["state"] != "INVALIDATED"
            ),
            "spurious": sum(
                1
                for row in all_rows.values()
                if not row["supersededCites"] and row["state"] == "INVALIDATED"
            ),
        },
        "codes": list(report["codes"]),
        "finding": (
            "every real dependent that cites a superseded digest is INVALIDATED; "
            "no stale dependent and no spurious invalidation was found. The "
            "dependents are the correcting receipts and the records that quote "
            "both the old and the new value; no independent downstream record "
            "cites a superseded digest without also recording the supersession. "
            "An independent consumer that relied on the old value and never "
            "recorded the correction would not be found by a citation scan, which "
            "is a stated limit."
        ),
    }
    if report["code"] != cr.CODE_OK:
        document["refusal"] = report["code"]
    return document


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------


def build_status(
    log: Mapping[str, Any], rows: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    subjects: list[dict[str, Any]] = []
    for row in rows:
        outcome = cr.current(log, row["subject"])
        assert outcome["outcome"] in cr.OUTCOMES
        spec = row["spec"]
        accepted_value = (
            outcome["accepted"]["value"]
            if outcome["accepted"] is not None
            else None
        )
        successor_state = None
        if spec["new"] is not None and isinstance(spec["new"]["value"], Mapping):
            verdict = spec["new"]["value"].get("verdict")
            if isinstance(verdict, Mapping):
                successor_state = verdict.get("state")
            else:
                successor_state = verdict
        subjects.append(
            {
                "subject": row["subject"],
                "outcome": outcome["outcome"],
                "acceptedEventId": outcome["acceptedEventId"],
                "acceptedValue": accepted_value,
                "history": [event["eventId"] for event in outcome["history"]],
                "authenticated": False,
                "authentication": {
                    "status": "SELF_ISSUED",
                    "original": spec["original"],
                    "authenticated": False,
                    "reason": (
                        "the only signer is A10's test-only HMAC-SHA256 key; A14 "
                        "records no declared identity for the producer or the "
                        "revocation authority, so no event is authenticated"
                    ),
                },
                "recordedAs": spec["recorded_as"],
                "originalPreservation": spec["preservation"],
                "successorState": successor_state,
                "reasons": outcome["reasons"],
            }
        )
    outcomes = {
        name: sum(1 for row in subjects if row["outcome"] == name)
        for name in cr.OUTCOMES
    }
    return {
        "schema": cr.STATUS_SCHEMA,
        "model": cr.MODEL_ID,
        "candidate": CANDIDATE,
        "subjects": subjects,
        "summary": {
            "subjects": len(subjects),
            "events": len(log["events"]),
            "outcomes": outcomes,
            "authenticated": sum(1 for row in subjects if row["authenticated"]),
            "proseOnly": sum(
                1 for row in subjects if row["recordedAs"] == "prose-only"
            ),
            "machineReadableUnsigned": sum(
                1
                for row in subjects
                if row["recordedAs"] == "machine-readable-unsigned"
            ),
            "signed": sum(1 for row in subjects if row["recordedAs"] == "signed"),
            "notRecorded": sum(
                1 for row in subjects if row["recordedAs"] == "not-recorded"
            ),
        },
        "finding": (
            "all eleven subjects have a bound successor; six are CORRECTED, five "
            "are RETRACTED, and none is DISPUTED or UNKNOWN. Zero events are "
            "authenticated: seven corrections are recorded in prose only and four "
            "claim retractions are machine-readable but unsigned. The original is "
            "preserved for every subject, but for A4, gate-reliability and the "
            "99.6% posterior the pre-correction record was never committed and "
            "only the correcting receipt preserves it."
        ),
    }


# ---------------------------------------------------------------------------
# Controls.  Every control is synthetic and control-only.
# ---------------------------------------------------------------------------


def control_value(value: Any, citation: str = "control") -> dict[str, Any]:
    return {
        "value": value,
        "digest": cr.value_digest(value),
        "citation": citation,
        "record": None,
    }


def control_event(
    event_id: str,
    kind: str,
    subject: str = "control-subject",
    *,
    previous: Mapping[str, Any] | None = None,
    old: Mapping[str, Any] | None = None,
    new: Mapping[str, Any] | None = None,
    reason: str = "control",
    role: str | None = None,
    identity: str = P_CAMPAIGN,
    signed: bool = True,
) -> dict[str, Any]:
    supersedes = None
    if previous is not None:
        supersedes = {
            "previousEventId": previous["eventId"],
            "previousDigest": cr.event_digest(previous),
        }
    event = {
        "schema": cr.EVENT_SCHEMA,
        "eventId": event_id,
        "kind": kind,
        "subject": subject,
        "supersedes": supersedes,
        "reason": reason,
        "oldValue": old,
        "newValue": new,
        "recordedAt": "2026-11-24T00:00:00Z",
        "recordedBy": {
            "role": role or cr.CORRECTING_ROLE[kind],
            "identity": identity,
        },
        "evidence": ["control-only"],
        "authentication": {
            "status": "SELF_ISSUED",
            "authenticated": False,
            "original": "control-only",
        },
    }
    return cr.sign_event(event) if signed else event


def _chain() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    first = control_event("C1", "assert", new=control_value({"v": 1}))
    log = cr.append(cr.new_log(), first)
    second = control_event(
        "C2",
        "correct",
        previous=first,
        old=first["newValue"],
        new=control_value({"v": 2}),
    )
    log = cr.append(log, second)
    third = control_event(
        "C3",
        "correct",
        previous=second,
        old=second["newValue"],
        new=control_value({"v": 3}),
    )
    log = cr.append(log, third)
    return log, first, second, third


def _observed(fn: Callable[[], Any]) -> dict[str, Any]:
    try:
        result = fn()
    except cr.Refusal as refusal:
        return {"code": refusal.code, "message": refusal.message}
    if isinstance(result, Mapping) and "code" in result:
        return {"code": result["code"]}
    return {"code": cr.CODE_OK}


def build_controls() -> dict[str, Any]:
    controls: list[dict[str, Any]] = []
    positive: list[dict[str, Any]] = []

    def add(
        control_id: str,
        code: str,
        description: str,
        fn: Callable[[], Any],
        *,
        is_positive: bool = False,
    ) -> None:
        observed = _observed(fn)
        expected = cr.CODE_OK if is_positive else code
        if observed["code"] != expected:
            raise SystemExit(
                f"control {control_id}: observed {observed['code']}, expected {expected}"
            )
        row = {
            "id": control_id,
            "controlOnly": True,
            "code": code,
            "description": description,
            "observed": observed,
        }
        (positive if is_positive else controls).append(row)

    # 1. EVENT_INVALID
    add(
        "event-invalid",
        cr.CR_REFUSED_EVENT_INVALID,
        "an event missing its reason is not a correction",
        lambda: cr.validate_event_structure(
            {"eventId": "X", "kind": "assert", "subject": "s"}
        ),
    )
    log, first, second, third = _chain()
    # 2. UNBOUND_CORRECTION
    add(
        "unbound-correction",
        cr.CR_REFUSED_UNBOUND_CORRECTION,
        "a correction names the predecessor id but not its digest",
        lambda: cr.validate_event_structure(
            {
                "eventId": "X",
                "kind": "correct",
                "subject": "control-subject",
                "supersedes": {"previousEventId": "C1"},
                "reason": "r",
                "oldValue": first["newValue"],
                "newValue": control_value({"v": 9}),
                "recordedAt": "2026-11-24T00:00:00Z",
                "recordedBy": {"role": "producer", "identity": P_CAMPAIGN},
                "evidence": ["control-only"],
            }
        ),
    )
    # 3. PREDECESSOR_MISMATCH
    bad_digest = control_event(
        "X",
        "correct",
        previous=first,
        old=first["newValue"],
        new=control_value({"v": 9}),
    )
    bad_digest["supersedes"]["previousDigest"] = "0" * 64
    bad_digest = cr.sign_event(bad_digest)
    add(
        "predecessor-mismatch",
        cr.CR_REFUSED_PREDECESSOR_MISMATCH,
        "supersedes.previousDigest is not the stored predecessor's digest",
        lambda: cr.append(cr.append(cr.new_log(), first), bad_digest),
    )
    # 4. ORIGINAL_MISMATCH
    wrong_original = control_event(
        "X",
        "correct",
        previous=first,
        old=control_value({"v": 999}),
        new=control_value({"v": 9}),
    )
    add(
        "original-mismatch",
        cr.CR_REFUSED_ORIGINAL_MISMATCH,
        "oldValue is not the predecessor's accepted value",
        lambda: cr.append(cr.append(cr.new_log(), first), wrong_original),
    )
    # 5. HISTORY_ERASED
    def erased() -> Any:
        edited = json.loads(json.dumps(log))
        edited["events"][0]["reason"] = "rewritten after the fact"
        cr.check_log(edited)

    add(
        "history-erased",
        cr.CR_REFUSED_HISTORY_ERASED,
        "an event edited after the log was chained is refused",
        erased,
    )
    # 6. FORK
    fork = control_event(
        "F1",
        "correct",
        previous=first,
        old=first["newValue"],
        new=control_value({"v": 10}),
    )
    add(
        "fork",
        cr.CR_REFUSED_FORK,
        "a second direct successor of one predecessor is a fork",
        lambda: cr.append(log, fork),
    )
    # 7. CYCLE
    def cycle() -> Any:
        cyclic = json.loads(json.dumps(log))
        # Make C1 supersede C3.  append verifies the new event, not the stored
        # ones; check_log recomputes the digest chain, which is updated here and
        # the log is re-signed.  The predecessor walk then revisits C1.
        cyclic["events"][0]["supersedes"] = {
            "previousEventId": "C3",
            "previousDigest": cr.event_digest(cyclic["events"][2]),
        }
        cyclic["history"] = [cr._history_entry(event) for event in cyclic["events"]]
        cyclic["logDigest"] = cr.log_digest(cyclic["history"])
        cyclic = cr.sign_log(cyclic)
        follower = control_event(
            "C4",
            "correct",
            previous=cyclic["events"][2],
            old=cyclic["events"][2]["newValue"],
            new=control_value({"v": 11}),
        )
        cr.append(cyclic, follower)

    add(
        "cycle",
        cr.CR_REFUSED_CYCLE,
        "a predecessor chain that revisits an event is a cycle",
        cycle,
    )
    # 8. SUBJECT_CHANGED
    changed = control_event(
        "S1",
        "correct",
        subject="different-subject",
        previous=first,
        old=first["newValue"],
        new=control_value({"v": 12}),
    )
    add(
        "subject-changed",
        cr.CR_REFUSED_SUBJECT_CHANGED,
        "a correction of a different subject is a new assertion",
        lambda: cr.append(cr.append(cr.new_log(), first), changed),
    )
    # 9. RETRACTION_UNBOUND
    ghost = control_event(
        "G1", "assert", subject="never-asserted", new=control_value({"v": 0})
    )
    unbound = control_event(
        "R1",
        "retract",
        subject="never-asserted",
        previous=ghost,
        old=control_value({"v": 0}),
        new=None,
    )
    add(
        "retraction-unbound",
        cr.CR_REFUSED_RETRACTION_UNBOUND,
        "a retraction of a subject with no prior assertion is refused",
        lambda: cr.append(cr.new_log(), unbound),
    )
    # 10. UNSIGNED
    unsigned = control_event(
        "U1", "assert", new=control_value({"v": 1}), signed=False
    )
    add(
        "unsigned",
        cr.CR_REFUSED_UNSIGNED,
        "an unsigned event is not a signed correction",
        lambda: cr.append(cr.new_log(), unsigned),
    )
    # 11. SIGNATURE
    def bad_signature() -> Any:
        tampered = json.loads(json.dumps(first))
        tampered["reason"] = "changed after signing"
        cr.append(cr.new_log(), tampered)

    add(
        "signature",
        cr.CR_REFUSED_SIGNATURE,
        "a signature over different bytes is not this event's signature",
        bad_signature,
    )
    # 12. ROLE
    outsider = control_event(
        "P1",
        "assert",
        new=control_value({"v": 1}),
        identity="P-UNASSIGNED",
    )
    add(
        "role",
        cr.CR_REFUSED_ROLE,
        "an identity with no A14 assignment cannot record the event",
        lambda: cr.append(cr.new_log(), outsider),
    )
    # 13. ASSERTION_EXISTS
    second_assert = control_event("A2", "assert", new=control_value({"v": 2}))
    add(
        "assertion-exists",
        cr.CR_REFUSED_ASSERTION_EXISTS,
        "a second assert for a subject is a correction, not an assertion",
        lambda: cr.append(cr.append(cr.new_log(), first), second_assert),
    )
    # 14. EVENT_ID_REUSED
    duplicate_id = control_event(
        "C1", "assert", subject="another-subject", new=control_value({"v": 3})
    )
    add(
        "event-id-reused",
        cr.CR_REFUSED_EVENT_ID_REUSED,
        "an eventId already in the log cannot name a second event",
        lambda: cr.append(cr.append(cr.new_log(), first), duplicate_id),
    )
    # 15. INVALIDATION_NOT_PROPAGATED (a retraction with a dependent left valid)
    retraction = control_event(
        "RT1",
        "retract",
        subject="control-subject",
        previous=third,
        old=third["newValue"],
        new=None,
    )
    retract_log = cr.append(log, retraction)
    old_digest = third["newValue"]["digest"]
    add(
        "invalidation-not-propagated",
        cr.CR_REFUSED_INVALIDATION_NOT_PROPAGATED,
        "a retraction leaves a dependent that cites the old value marked VALID",
        lambda: cr.propagate(
            retract_log,
            [{"id": "stale-dependent", "cites": [old_digest], "declared": "VALID"}],
        ),
    )
    add(
        "retraction-propagates",
        cr.CODE_OK,
        "the same retraction with the dependent INVALIDATED is accepted",
        lambda: cr.propagate(
            retract_log,
            [{"id": "dependent", "cites": [old_digest], "declared": "INVALIDATED"}],
        ),
        is_positive=True,
    )
    # 16. SPURIOUS_INVALIDATION
    add(
        "spurious-invalidation",
        cr.CR_REFUSED_SPURIOUS_INVALIDATION,
        "a dependent marked INVALIDATED with no superseded citation is refused",
        lambda: cr.propagate(
            retract_log,
            [{"id": "spurious", "cites": ["f" * 64], "declared": "INVALIDATED"}],
        ),
    )
    # Positive: a three-event chain verifies and the tip is CORRECTED.
    def positive_chain() -> Any:
        report = cr.verify_log(log)
        outcome = report["outcomes"]["control-subject"]["outcome"]
        if outcome != cr.OUTCOME_CORRECTED:
            raise AssertionError(f"positive chain outcome {outcome}")
        return {"code": cr.CODE_OK}

    add(
        "positive-chain",
        cr.CODE_OK,
        "assert -> correct -> correct verifies and the accepted event is CORRECTED",
        positive_chain,
        is_positive=True,
    )

    codes = {row["code"] for row in controls}
    if codes != set(cr.REFUSALS):
        missing = sorted(set(cr.REFUSALS) - codes)
        extra = sorted(codes - set(cr.REFUSALS))
        raise SystemExit(f"control coverage: missing={missing} extra={extra}")
    return {
        "schema": cr.CONTROLS_SCHEMA,
        "model": cr.MODEL_ID,
        "candidate": CANDIDATE,
        "controls": controls,
        "positive": positive,
        "coverage": {
            "refusalCodes": len(cr.REFUSALS),
            "controls": len(controls),
            "positive": len(positive),
        },
    }


# ---------------------------------------------------------------------------
# The producer
# ---------------------------------------------------------------------------


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="build_evidence.py",
        description="Deterministic producer of the A19 correction records.",
    )
    parser.add_argument("--out", type=Path, default=EVIDENCE)
    arguments = parser.parse_args(argv)
    output = arguments.out
    output.mkdir(parents=True, exist_ok=True)

    log, rows = build_real_log()
    cr.verify_log(log)
    propagation = build_propagation(log)
    status = build_status(log, rows)
    controls = build_controls()

    write_json(output / "EVENTS.json", log)
    write_json(output / "PROPAGATION.json", propagation)
    write_json(output / "STATUS.json", status)
    write_json(output / "CONTROLS.json", controls)

    outcomes = status["summary"]["outcomes"]
    print(
        f"a19: subjects={status['summary']['subjects']} "
        f"events={status['summary']['events']} "
        f"corrected={outcomes['CORRECTED']} retracted={outcomes['RETRACTED']} "
        f"disputed={outcomes['DISPUTED']} unknown={outcomes['UNKNOWN']} "
        f"authenticated={status['summary']['authenticated']} "
        f"proseOnly={status['summary']['proseOnly']} "
        f"machineReadableUnsigned={status['summary']['machineReadableUnsigned']} "
        f"dependents={propagation['summary']['dependents']} "
        f"invalidated={propagation['summary']['invalidated']} "
        f"stale={propagation['summary']['stale']} "
        f"spurious={propagation['summary']['spurious']} "
        f"controls={controls['coverage']['controls']} "
        f"codes={controls['coverage']['refusalCodes']} "
        f"commit={BASE_COMMIT_SHORT}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
