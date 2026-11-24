#!/usr/bin/env python3
"""build_evidence.py -- the deterministic producer for B1b.

B1 has two halves and this producer is careful about which one it writes.

  * **B1a, the admitted-service slice, is NOT_RUN.**  No Rekor binary, client,
    service, log key, witness or network exists in this venue, and B0 recorded
    that the only pinned digest names the AWS build rather than the POSIX server
    this project uses (``evidence/b0/RECEIPT.md`` §3).  ``PREFLIGHT.json`` records
    that absence, the prerequisites B0 lists, and the commands that would run once
    a pinned instance exists.  Nothing here starts a service or submits an entry.

  * **B1b, the verification half, runs against ``FIXTURE-1``.**  The producer
    builds a six-leaf log from the four real frozen A9 statements plus two
    explicitly synthetic test-only leaves, encodes the C2SP ``tlog-tiles`` layout
    recorded in ``docs/ETP-ADDENDUM-B.md`` §B.3.2, signs checkpoints with A10's
    fixed test-only HMAC key, publishes one real statement, and runs the §B.24
    controls that are decidable offline.

Every record says ``"admittedService": false`` and ``"identity": "FIXTURE-1"``.
The fixture is not ``rekor-tiles``, has no log key, no witness and no production
signature, and does not establish that any admission will succeed.

Two runs write the same bytes: canonical JSON with sorted keys, one-space indent
and a trailing newline, and every field is derived from committed inputs or a
fixed seed.  No clock, environment, network or random source is read.

Usage:
    python3 evidence/b1/build_evidence.py [--check]

``--check`` recomputes the records and the fixture tree and compares them with the
committed bytes instead of writing.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path
from typing import Any, Callable, Sequence

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS = REPO_ROOT / "forensics" / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import dsse  # noqa: E402
import intoto  # noqa: E402
import tlog  # noqa: E402

EVIDENCE = REPO_ROOT / "evidence" / "b1"
FIXTURE_DIR = EVIDENCE / "fixture"
PREFLIGHT_OUT = EVIDENCE / "PREFLIGHT.json"
FIXTURE_OUT = EVIDENCE / "FIXTURE.json"
PUBLICATION_OUT = EVIDENCE / "PUBLICATION.json"
CONTROLS_OUT = EVIDENCE / "CONTROLS.json"

RECORDED_AT = "2026-11-24"
BASE_COMMIT = "54fb5085b"
BASE_COMMIT_FULL = "54fb5085b"
IDENTITY = "FIXTURE-1"
ORIGIN = IDENTITY
SIGNER_NAME = "FIXTURE-1 test-only hmac-sha256"
SEED = b"openssl-rs/b1/fixture-1/seed/v1"
PAYLOAD_TYPE = "application/vnd.in-toto+json"

# The four real frozen A9 statements, in their committed order.  Every leaf below
# index 4 is the exact bytes of one of these files.
STATEMENT_PATHS = (
    "evidence/a9/STATEMENTS/a1-sarif.json",
    "evidence/a9/STATEMENTS/a5-admission.json",
    "evidence/a9/STATEMENTS/a7-delta.json",
    "evidence/a9/STATEMENTS/a8-shard-000.json",
)
PUBLISHED_PATH = "evidence/a9/STATEMENTS/a8-shard-000.json"
ENVELOPE_PATH = "evidence/a10/ENVELOPES/a8-shard-000.json"

# The real leaves are indices 0-3.  Two synthetic leaves make the tree a
# non-perfect shape (a right edge that is not a power of two) and are generated
# from this fixed seed; both are labelled test-only in every record.
SYNTHETIC_COUNT = 2
CHECKPOINT_SIZES = (2, 5, 6)
TREE_SIZE = len(STATEMENT_PATHS) + SYNTHETIC_COUNT
PUBLISHED_INDEX = STATEMENT_PATHS.index(PUBLISHED_PATH)


def _serialise(document: Any) -> bytes:
    return (
        json.dumps(document, indent=1, sort_keys=True, ensure_ascii=False) + "\n"
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


def _write_json(path: Path, document: Any) -> None:
    _write_bytes(path, _serialise(document))


def _synthetic_entry(index: int) -> bytes:
    """A deterministic, explicitly synthetic leaf derived from the fixed seed."""
    token = hashlib.sha256(SEED + b"/entry/" + str(index).encode("ascii")).hexdigest()
    document = {
        "fixture": IDENTITY,
        "index": index,
        "note": "test-only synthetic entry; not an ETP statement, not evidence",
        "seed": SEED.decode("ascii"),
        "seedToken": token,
        "testOnly": True,
    }
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def _real_entries() -> list[dict[str, Any]]:
    rows = []
    for path in STATEMENT_PATHS:
        raw = (REPO_ROOT / path).read_bytes()
        statement = intoto.decode(raw, repo_root=REPO_ROOT)
        subjects = []
        for subject in statement["subject"]:
            subjects.append(
                {
                    "name": subject["name"],
                    "sha256": subject["digest"]["sha256"],
                    "bytes": (REPO_ROOT / subject["name"]).stat().st_size,
                }
            )
        rows.append(
            {
                "index": len(rows),
                "kind": "real-statement",
                "path": path,
                "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "leafHash": tlog.leaf_hash(raw).hex(),
                "subjects": subjects,
                "payload": raw,
            }
        )
    return rows


def _synthetic_rows() -> list[dict[str, Any]]:
    rows = []
    for offset in range(SYNTHETIC_COUNT):
        index = len(STATEMENT_PATHS) + offset
        raw = _synthetic_entry(index)
        rows.append(
            {
                "index": index,
                "kind": "synthetic-test-only",
                "path": None,
                "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "leafHash": tlog.leaf_hash(raw).hex(),
                "subjects": [],
                "payload": raw,
            }
        )
    return rows


def _fixture_files(entries: Sequence[bytes]) -> dict[str, bytes]:
    leaf_hashes = [tlog.leaf_hash(entry) for entry in entries]
    files = {}
    files.update(tlog.build_entry_bundles(entries))
    files.update(tlog.build_hash_tiles(leaf_hashes))
    return files


def _sign(size: int, root: bytes) -> tuple[bytes, bytes]:
    text = tlog.checkpoint_text(ORIGIN, size, root)
    signed = tlog.sign_checkpoint(text, SIGNER_NAME, dsse.test_only_key())
    return text, signed


def _expect(code: str, call: Callable[[], Any]) -> dict[str, Any]:
    try:
        call()
    except tlog.Refusal as refusal:
        if refusal.code != code:
            raise AssertionError(
                f"expected {code}, observed {refusal.code}: {refusal.message}"
            ) from refusal
        return {"code": refusal.code, "message": refusal.message}
    raise AssertionError(f"the control did not fire {code}")


def _canary(call: Callable[[], Any], *, scope: str, observation: str) -> dict[str, Any]:
    try:
        call()
    except tlog.Refusal as refusal:
        raise AssertionError(
            f"the canary was refused with {refusal.code}: {refusal.message}"
        ) from refusal
    return {"accepted": True, "scope": scope, "observation": observation}


def _not_run(item: int, name: str, clause: str, requires: str) -> dict[str, Any]:
    return {
        "item": item,
        "name": name,
        "clause": clause,
        "status": "NOT_RUN",
        "requires": requires,
    }


def _control(
    item: int | None,
    name: str,
    clause: str,
    mutation: str,
    refusal: dict[str, Any],
    canary: dict[str, Any],
) -> dict[str, Any]:
    return {
        "item": item,
        "name": name,
        "clause": clause,
        "mutation": mutation,
        "refusalCode": refusal["code"],
        "refusalMessage": refusal["message"],
        "fired": True,
        "canary": canary,
    }


def run_controls(
    entries: Sequence[bytes],
    leaf_hashes: Sequence[bytes],
    store: tlog.TileStore,
    root6: bytes,
    proof3: Sequence[bytes],
) -> list[dict[str, Any]]:
    """Run every §B.24 control that is decidable offline, with its canary."""
    log6 = tlog.TiledLog(store, TREE_SIZE, root6)
    published = entries[PUBLISHED_INDEX]
    key = dsse.test_only_key()
    controls: list[dict[str, Any]] = []

    # 1. Tampered Merkle leaf.
    tampered = bytearray(published)
    tampered[0] ^= 0x01
    controls.append(
        _control(
            1,
            "tampered Merkle leaves",
            "B.24 item 1",
            "flip the first byte of the published leaf before hashing it",
            _expect(
                tlog.TL_REFUSED_PROOF,
                lambda: tlog.verify_inclusion(
                    bytes(tampered), PUBLISHED_INDEX, TREE_SIZE, proof3, root6
                ),
            ),
            _canary(
                lambda: tlog.verify_inclusion(
                    bytes(tampered),
                    PUBLISHED_INDEX,
                    TREE_SIZE,
                    proof3,
                    root6,
                    disabled=frozenset({"root"}),
                ),
                scope="verifier",
                observation="with the root comparison disabled the mutated leaf is not refused",
            ),
        )
    )

    # 2. Incorrect leaf indices: out of range and in range.
    controls.append(
        _control(
            2,
            "incorrect leaf indices (out of range)",
            "B.24 item 2",
            f"claim leaf index {TREE_SIZE} in a tree of size {TREE_SIZE}",
            _expect(
                tlog.TL_REFUSED_INDEX,
                lambda: tlog.verify_inclusion(
                    published, TREE_SIZE, TREE_SIZE, [], root6
                ),
            ),
            _canary(
                lambda: tlog._checked_index(
                    TREE_SIZE, TREE_SIZE, frozenset({"index"})
                ),
                scope="check",
                observation="the named index check returns the out-of-range index when disabled",
            ),
        )
    )
    controls.append(
        _control(
            2,
            "incorrect leaf indices (wrong index in range)",
            "B.24 item 2",
            "verify the index-3 proof as if it were the proof for index 2",
            _expect(
                tlog.TL_REFUSED_PROOF,
                lambda: tlog.verify_inclusion(
                    published, 2, TREE_SIZE, proof3, root6
                ),
            ),
            _canary(
                lambda: tlog.verify_inclusion(
                    published,
                    2,
                    TREE_SIZE,
                    proof3,
                    root6,
                    disabled=frozenset({"root"}),
                ),
                scope="verifier",
                observation="with the root comparison disabled the wrong index is not refused",
            ),
        )
    )

    # 3. Incorrect sibling order.
    swapped = [proof3[1], proof3[0], *proof3[2:]]
    controls.append(
        _control(
            3,
            "incorrect sibling order",
            "B.24 item 3",
            "swap the first two audit-path siblings",
            _expect(
                tlog.TL_REFUSED_PROOF,
                lambda: tlog.verify_inclusion(
                    published, PUBLISHED_INDEX, TREE_SIZE, swapped, root6
                ),
            ),
            _canary(
                lambda: tlog.verify_inclusion(
                    published,
                    PUBLISHED_INDEX,
                    TREE_SIZE,
                    swapped,
                    root6,
                    disabled=frozenset({"root"}),
                ),
                scope="verifier",
                observation="with the root comparison disabled the reordered proof is not refused",
            ),
        )
    )

    # 4. Truncated inclusion proof.
    truncated = list(proof3[:-1])
    controls.append(
        _control(
            4,
            "truncated inclusion proofs",
            "B.24 item 4",
            "drop the last audit-path element",
            _expect(
                tlog.TL_REFUSED_PROOF,
                lambda: tlog.verify_inclusion(
                    published, PUBLISHED_INDEX, TREE_SIZE, truncated, root6
                ),
            ),
            _canary(
                lambda: tlog.verify_inclusion(
                    published,
                    PUBLISHED_INDEX,
                    TREE_SIZE,
                    truncated,
                    root6,
                    disabled=frozenset({"proof", "root"}),
                ),
                scope="verifier",
                observation=(
                    "with the proof-length and root checks disabled the truncated "
                    "path is not refused; a shorter path cannot reconstruct the root"
                ),
            ),
        )
    )

    # 5. Excess proof elements.
    excess = [*proof3, b"\x00" * tlog.HASH_BYTES]
    controls.append(
        _control(
            5,
            "excess proof elements",
            "B.24 item 5",
            "append one zero hash to a valid audit path",
            _expect(
                tlog.TL_REFUSED_PROOF,
                lambda: tlog.verify_inclusion(
                    published, PUBLISHED_INDEX, TREE_SIZE, excess, root6
                ),
            ),
            _canary(
                lambda: tlog.verify_inclusion(
                    published,
                    PUBLISHED_INDEX,
                    TREE_SIZE,
                    excess,
                    root6,
                    disabled=frozenset({"proof", "root"}),
                ),
                scope="verifier",
                observation="with the proof-length and root checks disabled the excess element is not refused",
            ),
        )
    )

    # 6. Incorrect checkpoint roots.  The body is correctly signed: this is an
    # equivocating operator, not a forger.
    bad_root = bytes([root6[0] ^ 0x01]) + root6[1:]
    _, bad_root_signed = _sign(TREE_SIZE, bad_root)
    controls.append(
        _control(
            6,
            "incorrect checkpoint roots",
            "B.24 item 6",
            "sign a checkpoint whose root is not the root recomputed from the tiles",
            _expect(
                tlog.TL_REFUSED_ROOT,
                lambda: tlog.verify_checkpoint(
                    bad_root_signed,
                    key_name=SIGNER_NAME,
                    key=key,
                    expected_origin=ORIGIN,
                    recomputed_root=root6,
                ),
            ),
            _canary(
                lambda: tlog.verify_checkpoint(
                    bad_root_signed,
                    key_name=SIGNER_NAME,
                    key=key,
                    expected_origin=ORIGIN,
                    recomputed_root=root6,
                    disabled=frozenset({"root"}),
                ),
                scope="verifier",
                observation="with the recomputed-root comparison disabled the signed wrong root is not refused",
            ),
        )
    )

    # 7. Incorrect checkpoint tree sizes.
    _, size7_signed = _sign(TREE_SIZE + 1, root6)
    available = store.available_leaves()
    controls.append(
        _control(
            7,
            "incorrect checkpoint tree sizes",
            "B.24 item 7",
            f"claim tree size {TREE_SIZE + 1} over a store whose entry bundles prove {available} leaves",
            _expect(
                tlog.TL_REFUSED_SIZE,
                lambda: store.root(TREE_SIZE + 1),
            ),
            {
                "accepted": True,
                "scope": "check",
                "observation": (
                    "the named size check returns without refusal when disabled; "
                    "the next independent refusal is TL_REFUSED_TILE for the absent "
                    "leaf, so the size refusal is first and attributable"
                ),
                "nextRefusal": _expect(
                    tlog.TL_REFUSED_TILE,
                    lambda: store.root(TREE_SIZE + 1, disabled=frozenset({"size"})),
                )["code"],
                "disabledCall": _canary(
                    lambda: tlog.check_size_against_tiles(
                        TREE_SIZE + 1, available, frozenset({"size"})
                    ),
                    scope="check",
                    observation="size check disabled",
                )["accepted"],
            },
        )
    )

    # 8. Forged checkpoint signatures.
    text6 = tlog.checkpoint_text(ORIGIN, TREE_SIZE, root6)
    forged = tlog.sign_checkpoint(text6, SIGNER_NAME, b"\x00" * 32)
    controls.append(
        _control(
            8,
            "forged checkpoint signatures",
            "B.24 item 8",
            "sign the exact body with a key other than the policy-selected test key",
            _expect(
                tlog.TL_REFUSED_CHECKPOINT_SIGNATURE,
                lambda: tlog.verify_checkpoint(
                    forged,
                    key_name=SIGNER_NAME,
                    key=key,
                    expected_origin=ORIGIN,
                ),
            ),
            _canary(
                lambda: tlog.verify_checkpoint(
                    forged,
                    key_name=SIGNER_NAME,
                    key=key,
                    expected_origin=ORIGIN,
                    disabled=frozenset({"signature"}),
                ),
                scope="verifier",
                observation="with signature verification disabled the forged checkpoint is not refused",
            ),
        )
    )

    # 9. Cross-log proof substitution.
    other_origin_text = tlog.checkpoint_text("OTHER-LOG", TREE_SIZE, root6)
    cross_log = tlog.sign_checkpoint(other_origin_text, SIGNER_NAME, key)
    controls.append(
        _control(
            9,
            "cross-log proof substitution",
            "B.24 item 9",
            "present a correctly signed checkpoint whose origin is OTHER-LOG",
            _expect(
                tlog.TL_REFUSED_ORIGIN,
                lambda: tlog.verify_checkpoint(
                    cross_log,
                    key_name=SIGNER_NAME,
                    key=key,
                    expected_origin=ORIGIN,
                ),
            ),
            _canary(
                lambda: tlog.verify_checkpoint(
                    cross_log,
                    key_name=SIGNER_NAME,
                    key=key,
                    expected_origin=ORIGIN,
                    disabled=frozenset({"origin"}),
                ),
                scope="verifier",
                observation="with the origin comparison disabled the other log's checkpoint is not refused",
            ),
        )
    )

    # 10. Cross-shard proof substitution.
    shard_text = tlog.checkpoint_text(f"{ORIGIN}-shard-002", TREE_SIZE, root6)
    cross_shard = tlog.sign_checkpoint(shard_text, SIGNER_NAME, key)
    controls.append(
        _control(
            10,
            "cross-shard proof substitution",
            "B.24 item 10",
            "present the same tree under a different shard origin",
            _expect(
                tlog.TL_REFUSED_ORIGIN,
                lambda: tlog.verify_checkpoint(
                    cross_shard,
                    key_name=SIGNER_NAME,
                    key=key,
                    expected_origin=ORIGIN,
                ),
            ),
            _canary(
                lambda: tlog.verify_checkpoint(
                    cross_shard,
                    key_name=SIGNER_NAME,
                    key=key,
                    expected_origin=ORIGIN,
                    disabled=frozenset({"origin"}),
                ),
                scope="verifier",
                observation="with the origin comparison disabled the other shard is not refused",
            ),
        )
    )

    # 11 needs the admitted client's hashedrekord derivation.
    controls.append(
        _not_run(
            11,
            "incorrect DSSE PAE digests",
            "B.24 item 11",
            "the admitted client's exact hashedrekord digest derivation (§B.5, "
            "§B.3.3 T3); no log entry was produced here",
        )
    )

    # 12. A valid entry for an unrelated attestation.
    unrelated = entries[0]
    controls.append(
        _control(
            12,
            "valid log entries for unrelated attestations",
            "B.24 item 12",
            "claim the published statement's index and proof with a different real statement",
            _expect(
                tlog.TL_REFUSED_INCLUSION_OF_ABSENT_LEAF,
                lambda: log6.verify_statement_inclusion(
                    unrelated, PUBLISHED_INDEX, proof3
                ),
            ),
            _canary(
                lambda: log6.verify_statement_inclusion(
                    unrelated,
                    PUBLISHED_INDEX,
                    proof3,
                    disabled=frozenset({"absent-leaf", "root"}),
                ),
                scope="verifier",
                observation=(
                    "with the leaf-binding and root checks disabled the unrelated "
                    "statement is not refused; the proof still cannot bind it to the root"
                ),
            ),
        )
    )

    controls.append(
        _not_run(
            13,
            "unsupported protocol versions",
            "B.24 item 13",
            "the admitted service's version negotiation (§B.5, §B.10); no service exists",
        )
    )

    # 14. Malformed tiles.
    controls.append(
        _control(
            14,
            "malformed tiles",
            "B.24 item 14",
            "a 100-byte hash tile, which is not a multiple of 32",
            _expect(
                tlog.TL_REFUSED_TILE,
                lambda: tlog.decode_hash_tile(b"\x00" * 100),
            ),
            _canary(
                lambda: tlog.decode_hash_tile(b"\x00" * 100, disabled=frozenset({"tile"})),
                scope="check",
                observation="with the tile geometry check disabled the decoder returns three hashes",
            ),
        )
    )

    # 15. Reordered entry bundles.
    reordered_entries = list(entries)
    reordered_entries[PUBLISHED_INDEX], reordered_entries[PUBLISHED_INDEX + 1] = (
        reordered_entries[PUBLISHED_INDEX + 1],
        reordered_entries[PUBLISHED_INDEX],
    )
    reordered_files = _fixture_files(reordered_entries)
    reordered_store = tlog.TileStore(reordered_files)
    reordered_root = reordered_store.root(TREE_SIZE)
    reordered_log = tlog.TiledLog(reordered_store, TREE_SIZE, reordered_root)
    reordered_proof = reordered_log.inclusion_proof(PUBLISHED_INDEX)
    controls.append(
        _control(
            15,
            "reordered entry bundles",
            "B.24 item 15",
            "swap the published leaf with its right neighbour, rebuild the tiles and re-sign the head",
            _expect(
                tlog.TL_REFUSED_INCLUSION_OF_ABSENT_LEAF,
                lambda: reordered_log.verify_statement_inclusion(
                    published, PUBLISHED_INDEX, reordered_proof
                ),
            ),
            _canary(
                lambda: tlog.verify_inclusion(
                    reordered_entries[PUBLISHED_INDEX],
                    PUBLISHED_INDEX,
                    TREE_SIZE,
                    reordered_proof,
                    reordered_root,
                ),
                scope="check",
                observation=(
                    "the reordered log's own leaf at that index is a valid inclusion; "
                    "the binding predicate is what refuses the published statement"
                ),
            ),
        )
    )

    # 16. Incorrect partial-tile boundaries.
    four = b"\x00" * 32 * 4
    controls.append(
        _control(
            16,
            "incorrect partial-tile boundaries",
            "B.24 item 16",
            "a partial hash tile declaring width 3 while carrying 4 hashes",
            _expect(
                tlog.TL_REFUSED_TILE,
                lambda: tlog.decode_hash_tile(four, expected=3),
            ),
            _canary(
                lambda: tlog.decode_hash_tile(four, expected=None),
                scope="check",
                observation="with the declared-width check disabled the four hashes are returned",
            ),
        )
    )

    # 17. Corrupted mirror data.
    corrupt_files = {path: store.read(path) for path in store.paths()}
    level_path = sorted(
        p
        for p in corrupt_files
        if p.startswith("tile/") and not p.startswith("tile/entries/")
    )[-1]
    corrupt = bytearray(corrupt_files[level_path])
    corrupt[0] ^= 0x01
    corrupt_files[level_path] = bytes(corrupt)
    corrupt_store = tlog.TileStore(corrupt_files)
    controls.append(
        _control(
            17,
            "corrupted mirror data",
            "B.24 item 17",
            "flip one byte in a stored hash tile the root reconstruction reads",
            _expect(
                tlog.TL_REFUSED_ROOT,
                lambda: corrupt_store.verify_tiles(TREE_SIZE, root6),
            ),
            _canary(
                lambda: corrupt_store.verify_tiles(
                    TREE_SIZE, root6, disabled=frozenset({"root"})
                ),
                scope="verifier",
                observation=(
                    "with the root comparison disabled the corrupted mirror is not refused"
                ),
            ),
        )
    )

    # 18. Stale checkpoint replay.
    _, size2_signed = _sign(2, store.root(2))
    _, size6_signed = _sign(TREE_SIZE, root6)
    accepted6 = tlog.verify_checkpoint(
        size6_signed,
        key_name=SIGNER_NAME,
        key=key,
        expected_origin=ORIGIN,
    )
    controls.append(
        _control(
            18,
            "stale checkpoint replay",
            "B.24 item 18",
            "present the size-2 checkpoint after the size-6 head was accepted",
            _expect(
                tlog.TL_REFUSED_ROLLBACK,
                lambda: tlog.verify_checkpoint(
                    size2_signed,
                    key_name=SIGNER_NAME,
                    key=key,
                    expected_origin=ORIGIN,
                    previous=accepted6,
                ),
            ),
            _canary(
                lambda: tlog.verify_checkpoint(
                    size2_signed,
                    key_name=SIGNER_NAME,
                    key=key,
                    expected_origin=ORIGIN,
                    previous=accepted6,
                    disabled=frozenset({"rollback"}),
                ),
                scope="verifier",
                observation="with the rollback comparison disabled the older head is not refused",
            ),
        )
    )

    # 19. Same-size conflicting checkpoints.
    other_root = bytes([root6[0] ^ 0x02]) + root6[1:]
    _, conflicting = _sign(TREE_SIZE, other_root)
    controls.append(
        _control(
            19,
            "same-size conflicting checkpoints",
            "B.24 item 19",
            "sign a different root for the already accepted size",
            _expect(
                tlog.TL_REFUSED_SPLIT_VIEW,
                lambda: tlog.verify_checkpoint(
                    conflicting,
                    key_name=SIGNER_NAME,
                    key=key,
                    expected_origin=ORIGIN,
                    previous=accepted6,
                ),
            ),
            _canary(
                lambda: tlog.verify_checkpoint(
                    conflicting,
                    key_name=SIGNER_NAME,
                    key=key,
                    expected_origin=ORIGIN,
                    previous=accepted6,
                    disabled=frozenset({"split-view"}),
                ),
                scope="verifier",
                observation="with the split-view comparison disabled the equivocating head is not refused",
            ),
        )
    )

    # 20. Invalid consistency proofs.
    _, size5_signed = _sign(5, store.root(5))
    accepted5 = tlog.verify_checkpoint(
        size5_signed,
        key_name=SIGNER_NAME,
        key=key,
        expected_origin=ORIGIN,
    )
    valid_growth = tlog.TiledLog(store, TREE_SIZE, root6).consistency_proof(5)
    bad_growth = [
        bytes([valid_growth[0][0] ^ 0x01]) + valid_growth[0][1:],
        *valid_growth[1:],
    ]
    controls.append(
        _control(
            20,
            "invalid consistency proofs",
            "B.24 item 20",
            "flip the first element of the valid 5 -> 6 consistency proof",
            _expect(
                tlog.TL_REFUSED_CONSISTENCY,
                lambda: tlog.verify_checkpoint(
                    size6_signed,
                    key_name=SIGNER_NAME,
                    key=key,
                    expected_origin=ORIGIN,
                    previous=accepted5,
                    consistency_proof=bad_growth,
                ),
            ),
            _canary(
                lambda: tlog.verify_checkpoint(
                    size6_signed,
                    key_name=SIGNER_NAME,
                    key=key,
                    expected_origin=ORIGIN,
                    previous=accepted5,
                    consistency_proof=bad_growth,
                    disabled=frozenset({"consistency"}),
                ),
                scope="verifier",
                observation="with the consistency check disabled the bad proof is not refused",
            ),
        )
    )

    # 21-33 require witness, timestamp, campaign, archival or service state.
    for item, name, clause, requires in (
        (
            21,
            "witness-state rollback",
            "B.24 item 21",
            "a witness with persistent state (§B.11); no witness exists at any n",
        ),
        (
            22,
            "duplicate witness credentials",
            "B.24 item 22",
            "admitted witness keys and an independence policy (§B.11, §B.21)",
        ),
        (
            23,
            "correlated witness populations",
            "B.24 item 23",
            "multiple independent operators (§B.11, §B.21)",
        ),
        (
            24,
            "incorrect timestamp imprints",
            "B.24 item 24",
            "an admitted RFC 3161 token (§B.9), which is B2",
        ),
        (
            25,
            "untrusted timestamp authorities",
            "B.24 item 25",
            "a timestamp trust root and chain (§B.9), which is B2",
        ),
        (
            26,
            "backdated historical submissions",
            "B.24 item 26",
            "a trusted signing time and a publication event (§B.9, §B.2)",
        ),
        (
            27,
            "omitted campaign failures",
            "B.24 item 27",
            "a registered campaign and its closure (§B.13-B.14), which is B3",
        ),
        (
            28,
            "missing archived evidence",
            "B.24 item 28",
            "a durable archive and reconstruction (§B.17), which is B6",
        ),
        (
            29,
            "stale revocation state",
            "B.24 item 29",
            "a revocation authority and current-state policy (§B.19), which is B6",
        ),
        (
            30,
            "incorrect trust-root rotation",
            "B.24 item 30",
            "authenticated SigningConfig and TrustedRoot metadata (§B.10), which is B4",
        ),
        (
            31,
            "interrupted publication",
            "B.24 item 31",
            "a live logging service and a partial-write model (§B.23), which is B1a",
        ),
        (
            32,
            "logging-service unavailability",
            "B.24 item 32",
            "a live logging service (§B.10), which is B1a",
        ),
        (
            33,
            "ambiguous submission retries",
            "B.24 item 33",
            "a live submission endpoint and retry semantics (§B.5, §B.23)",
        ),
    ):
        controls.append(_not_run(item, name, clause, requires))

    # Supplementary controls: the task names a duplicate leaf and the statement
    # binding explicitly, and both have their own stable refusal codes.
    controls.append(
        _control(
            None,
            "duplicate leaf",
            "B.24 control vocabulary; B.19 correction records",
            "append the published statement's exact bytes a second time",
            _expect(
                tlog.TL_REFUSED_DUPLICATE_LEAF,
                lambda: tlog.append_leaf(list(leaf_hashes), published),
            ),
            _canary(
                lambda: tlog.append_leaf(
                    list(leaf_hashes), published, disabled=frozenset({"duplicate"})
                ),
                scope="check",
                observation="with the duplicate check disabled the second append returns an index",
            ),
        )
    )

    statement_document = json.loads(published.decode("utf-8"))
    statement_document["subject"][0]["digest"]["sha256"] = "0" * 64
    # Keep the predicate's record digest consistent with the subject so A9's
    # structural record binding passes; the failure is then the subject file's
    # actual bytes, which is the binding this control is about.
    statement_document["predicate"]["record"]["sha256"] = "0" * 64
    mutated_statement = (
        json.dumps(statement_document, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    controls.append(
        _control(
            None,
            "subject digest binding",
            "B.6 item 10; B.24 item 12",
            "change the statement's subject digest without changing the subject file",
            _expect(
                tlog.TL_REFUSED_BINDING,
                lambda: tlog.verify_subject_binding(mutated_statement, REPO_ROOT),
            ),
            _canary(
                lambda: tlog.verify_subject_binding(
                    mutated_statement, REPO_ROOT, disabled=frozenset({"binding"})
                ),
                scope="check",
                observation=(
                    "with the subject-file binding disabled the canonical mutated "
                    "statement is accepted as a statement, not as a binding"
                ),
            ),
        )
    )

    return controls


def build_fixture() -> dict[str, Any]:
    real = _real_entries()
    synthetic = _synthetic_rows()
    entries = [row["payload"] for row in real + synthetic]
    leaf_hashes = [tlog.leaf_hash(entry) for entry in entries]
    files = _fixture_files(entries)
    store = tlog.TileStore(files)
    roots = {size: store.root(size) for size in CHECKPOINT_SIZES}
    store.verify_tiles(TREE_SIZE, roots[TREE_SIZE])

    checkpoints = {}
    for size in CHECKPOINT_SIZES:
        checkpoints[size] = dict(zip(("text", "signed"), _sign(size, roots[size])))

    accepted = {}
    previous = None
    extras: dict[str, bytes] = {}
    for size in CHECKPOINT_SIZES:
        proof = None
        if previous is not None:
            proof = tlog.TiledLog(store, size, roots[size]).consistency_proof(
                previous.size
            )
            extras[f"consistency-{previous.size}-{size}.json"] = _serialise(
                {"proof": tlog.hex_list(proof)}
            )
        accepted[size] = tlog.verify_checkpoint(
            checkpoints[size]["signed"],
            key_name=SIGNER_NAME,
            key=dsse.test_only_key(),
            expected_origin=ORIGIN,
            previous=previous,
            consistency_proof=proof,
            recomputed_root=roots[size],
        )
        previous = accepted[size]

    log = tlog.TiledLog(store, TREE_SIZE, roots[TREE_SIZE])
    inclusion = log.inclusion_proof(PUBLISHED_INDEX)
    log.verify_statement_inclusion(entries[PUBLISHED_INDEX], PUBLISHED_INDEX, inclusion)

    # An independent 2 -> 6 proof: m is a power of two, unlike 5 -> 6.
    consistency_2_6 = log.consistency_proof(2)
    tlog.verify_consistency(2, TREE_SIZE, consistency_2_6, roots[2], roots[TREE_SIZE])

    extras[f"inclusion-{PUBLISHED_INDEX}-at-{TREE_SIZE}.json"] = _serialise(
        {"proof": tlog.hex_list(inclusion)}
    )
    extras["consistency-2-6.json"] = _serialise(
        {"proof": tlog.hex_list(consistency_2_6)}
    )
    for size, value in checkpoints.items():
        extras[f"checkpoint-{size}.note"] = value["signed"]

    return {
        "real": real,
        "synthetic": synthetic,
        "entries": entries,
        "leaf_hashes": leaf_hashes,
        "files": files,
        "extras": extras,
        "store": store,
        "roots": roots,
        "checkpoints": checkpoints,
        "accepted": accepted,
        "inclusion": inclusion,
        "consistency_2_6": consistency_2_6,
    }


def fixture_document(fixture: dict[str, Any]) -> dict[str, Any]:
    store = fixture["store"]
    leaves = []
    for row in fixture["real"] + fixture["synthetic"]:
        leaves.append(
            {
                "index": row["index"],
                "kind": row["kind"],
                "path": row["path"],
                "bytes": row["bytes"],
                "sha256": row["sha256"],
                "leafHash": row["leafHash"],
                "subjects": row["subjects"],
            }
        )
    checkpoints = []
    for size in CHECKPOINT_SIZES:
        text = fixture["checkpoints"][size]["text"]
        signed = fixture["checkpoints"][size]["signed"]
        checkpoints.append(
            {
                "size": size,
                "rootHash": fixture["roots"][size].hex(),
                "noteText": text.decode("utf-8"),
                "noteTextSha256": hashlib.sha256(text).hexdigest(),
                "signedNote": signed.decode("utf-8"),
                "signedNoteSha256": hashlib.sha256(signed).hexdigest(),
                "signature": {
                    "name": SIGNER_NAME,
                    "keyHash": tlog.note_key_hash(SIGNER_NAME).hex(),
                    "kind": "test-only-hmac-sha256",
                    "notATrustRoot": True,
                },
            }
        )
    return {
        "schema": "openssl-rs/b1/fixture/1",
        "item": "B1b",
        "identity": IDENTITY,
        "admittedService": False,
        "labels": [
            "FIXTURE-1",
            "test-only",
            "not-rekor-tiles",
            "no-log-key",
            "no-witness",
            "no-production-signature",
        ],
        "recordedAt": RECORDED_AT,
        "baseCommit": BASE_COMMIT,
        "origin": ORIGIN,
        "seed": SEED.decode("ascii"),
        "construction": {
            "clause": "RFC 6962 §2.1; docs/ETP-ADDENDUM-B.md §B.3.2",
            "leafHash": "SHA-256(0x00 || leaf)",
            "nodeHash": "SHA-256(0x01 || left || right)",
            "emptyRoot": tlog.empty_tree_root().hex(),
            "hash": "sha256",
            "tileEntries": tlog.TILE_ENTRIES,
            "tileBytes": tlog.TILE_BYTES,
        },
        "treeSize": TREE_SIZE,
        "rootHash": fixture["roots"][TREE_SIZE].hex(),
        "leaves": leaves,
        "checkpoints": checkpoints,
        "tiles": {
            "layout": "<prefix>/tile/<L>/<N>[.p/<W>]; <prefix>/tile/entries/<N>[.p/<W>]",
            "prefix": "evidence/b1/fixture",
            "paths": store.tile_rows(),
        },
        "verification": {
            "tilesReconstructRoot": True,
            "entryBundlesAgreeWithLevel0Hashes": True,
            "treeRoot": fixture["roots"][TREE_SIZE].hex(),
        },
        "nonClaims": [
            "FIXTURE-1 is not rekor-tiles and is not an admitted service",
            "the checkpoint signer is A10's fixed public test key, not a log key",
            "there is no witness, no cosignature and no production signature",
            "the two synthetic leaves are test-only and are not ETP statements",
            "this fixture does not establish that any Rekor admission will succeed",
        ],
    }


def publication_document(fixture: dict[str, Any]) -> dict[str, Any]:
    published_row = fixture["real"][PUBLISHED_INDEX]
    published = published_row["payload"]
    statement = tlog.verify_subject_binding(published, REPO_ROOT)
    envelope_bytes = (REPO_ROOT / ENVELOPE_PATH).read_bytes()
    envelope = dsse.verify_received_bytes(
        envelope_bytes,
        dsse.test_only_verifier(),
        expected_payload_type=PAYLOAD_TYPE,
        require_statement=True,
    )
    if envelope["payload"] != published:
        raise AssertionError("the A10 envelope payload is not the published statement")
    head = fixture["accepted"][TREE_SIZE]
    return {
        "schema": "openssl-rs/b1/publication/1",
        "item": "B1b",
        "identity": IDENTITY,
        "admittedService": False,
        "recordedAt": RECORDED_AT,
        "baseCommit": BASE_COMMIT,
        "statement": {
            "path": PUBLISHED_PATH,
            "bytes": len(published),
            "sha256": hashlib.sha256(published).hexdigest(),
            "leafHash": tlog.leaf_hash(published).hex(),
            "type": statement["_type"],
            "predicateType": statement["predicateType"],
            "subjects": published_row["subjects"],
            "subjectDigestsRecomputed": True,
        },
        "envelope": {
            "path": ENVELOPE_PATH,
            "bytes": len(envelope_bytes),
            "sha256": envelope["envelopeSha256"],
            "paeSha256": envelope["paeSha256"],
            "payloadEqualsStatement": True,
            "note": (
                "recorded for the hashedrekord digest discussion (§B.3.3 T3); no "
                "Rekor log entry, hashedrekord kind or admitted-client derivation "
                "was produced"
            ),
        },
        "binding": {
            "statementToLeaf": "the leaf payload is the exact statement bytes",
            "statementSha256": hashlib.sha256(published).hexdigest(),
            "leafPayloadSha256": hashlib.sha256(published).hexdigest(),
            "leafHash": tlog.leaf_hash(published).hex(),
            "subjectDigest": published_row["subjects"][0]["sha256"],
            "subjectBytesRecomputed": True,
            "verified": True,
        },
        "leaf": {"index": PUBLISHED_INDEX, "leafHash": tlog.leaf_hash(published).hex()},
        "treeSize": TREE_SIZE,
        "rootHash": head.root.hex(),
        "inclusionProof": tlog.hex_list(fixture["inclusion"]),
        "inclusion": {
            "verified": True,
            "refusalCodesObservedOnValidData": [],
            "proofElements": len(fixture["inclusion"]),
        },
        "checkpoint": {
            "size": head.size,
            "rootHash": head.root.hex(),
            "noteTextSha256": hashlib.sha256(head.checkpoint.body()).hexdigest(),
            "signedNoteSha256": hashlib.sha256(head.signed).hexdigest(),
            "signatureName": head.signature.name,
            "signatureKeyHash": head.signature.key_hash.hex(),
            "signatureVerified": True,
            "testOnly": True,
            "notALogKey": True,
        },
        "consistency": {
            "chain": [
                {"from": 2, "to": 5, "verified": True},
                {"from": 5, "to": 6, "verified": True},
            ],
            "independent": [
                {
                    "from": 2,
                    "to": TREE_SIZE,
                    "proofElements": len(fixture["consistency_2_6"]),
                    "verified": True,
                    "note": "m is a power of two; the 5 -> 6 case is not",
                }
            ],
        },
        "hashedrekordPath": {
            "status": "NOT_RUN",
            "clause": "docs/ETP-ADDENDUM-B.md §B.5, §B.3.3 T3, §B.30 B1",
            "requires": (
                "a pinned POSIX-backed rekor-tiles v2 instance and the admitted "
                "client's exact hashedrekord representation and API version"
            ),
            "reason": (
                "the leaf here is the statement bytes in a fixture log, not a Rekor "
                "hashedrekord entry; no submission, log entry or integrated time exists"
            ),
        },
        "nonClaims": [
            "this is not a Rekor publication and carries no Rekor log entry",
            "the checkpoint is signed by the test-only A10 key, not a log key",
            "no trusted signing time exists (§B.9); no RFC 3161 token was requested",
            "inclusion in FIXTURE-1 does not establish inclusion in any admitted log",
        ],
    }


def preflight_document() -> dict[str, Any]:
    checks = [
        {
            "id": "binary-absent",
            "command": "command -v rekor-server rekor-cli rekor-tiles",
            "result": "absent",
            "recordedIn": "evidence/b0/REGISTRY.json#/presenceCheck",
        },
        {
            "id": "cosign-absent",
            "command": "command -v cosign sigstore",
            "result": "absent",
            "recordedIn": "evidence/b0/REGISTRY.json#/presenceCheck",
        },
        {
            "id": "tsa-absent",
            "command": "command -v tsget openssl",
            "result": "only /usr/bin/openssl, which is not a timestamp authority",
            "recordedIn": "evidence/b0/REGISTRY.json#/presenceCheck",
        },
        {
            "id": "endpoint-absent",
            "command": "tracked-path search for a Rekor endpoint or log key",
            "result": "no endpoint or log key outside docs/",
            "recordedIn": "evidence/b0/REGISTRY.json#/presenceCheck",
        },
        {
            "id": "no-network",
            "command": "no network request was made by this item",
            "result": "no service contacted, nothing fetched or installed",
            "recordedIn": "evidence/b1/PREFLIGHT.json",
        },
        {
            "id": "posix-digest-absent",
            "command": "compare the recorded digest with the POSIX server asset",
            "result": (
                "the only recorded digest sha256:3af252cd…61e8a6 names the "
                "linux/amd64 rekor-server-aws asset of v2.4.2, not the POSIX build"
            ),
            "recordedIn": "evidence/b0/RECEIPT.md §3",
        },
        {
            "id": "scf-1",
            "command": "inspect the Sigstore signing_config",
            "result": (
                "SCF-1: the signing_config inspected 2026-10-22 advertised a Rekor "
                "v1 endpoint; a client version does not imply a v2 service"
            ),
            "recordedIn": "evidence/b0/SERVICE-CONFIGURATION.json#/serviceConfigurationFinding",
        },
    ]
    prerequisites = [
        {
            "id": "TA-B1",
            "clause": "§B.21, §B.31 items 1-2",
            "requirement": (
                "a pinned rekor-tiles server binary matching a recorded digest runs "
                "with the POSIX backend and a log key this project controls"
            ),
            "state": "UNMET",
        },
        {
            "id": "B0-digest-gap",
            "clause": "§B.5, §B.3.2",
            "requirement": (
                "record the digest of the exact POSIX server asset installed; the "
                "AWS asset digest may not be reused as its identity"
            ),
            "state": "UNMET",
        },
        {
            "id": "B0-service-metadata",
            "clause": "§B.10",
            "requirement": (
                "read the service metadata actually used and refuse a v1 fallback; "
                "a local slice cannot inherit a v2 endpoint from the client"
            ),
            "state": "UNMET",
        },
        {
            "id": "B0-hashedrekord",
            "clause": "§B.5; §B.3.3 T3",
            "requirement": (
                "use the supported hashedrekord representation, with the API version "
                "read from the admitted client, and derive the digest from the exact "
                "DSSE envelope"
            ),
            "state": "UNMET",
        },
        {
            "id": "TA-B2",
            "clause": "§B.9; §B.31 item 4",
            "requirement": "an admitted RFC 3161 authority for trusted signing time",
            "state": "UNMET",
        },
        {
            "id": "TA-B5",
            "clause": "§B.11; §B.31 item 10",
            "requirement": "an independent witness set with a quorum (not present at any n)",
            "state": "UNMET",
        },
    ]
    planned = [
        {
            "id": "verify-posix-asset",
            "command": (
                "sha256sum <pinned-posix-rekor-server-asset>  # must equal the digest "
                "recorded for that exact asset before execution (§B.3.2)"
            ),
            "runsWhen": "the POSIX asset digest is recorded; NOT_RUN now",
        },
        {
            "id": "read-client-api",
            "command": (
                "<pinned-rekor-server> serve --help; <pinned-client> upload --help  # "
                "read the exact API version and flags from the admitted binary, not "
                "from documentation (§B.5)"
            ),
            "runsWhen": "the pinned binaries exist; NOT_RUN now",
        },
        {
            "id": "start-posix-instance",
            "command": (
                "<pinned-rekor-server> serve --storage posix --posix.path <dir> "
                "--log.key <key> <--hostname and port read from the binary's help>"
            ),
            "runsWhen": "the binary and a log key exist; NOT_RUN now",
        },
        {
            "id": "submit-hashedrekord",
            "command": (
                "<admitted-client> upload --type hashedrekord --artifact "
                "evidence/a9/STATEMENTS/a8-shard-000.json <--signature and "
                "--public-key per the admitted profile> --rekor_server <url>"
            ),
            "runsWhen": "the service, client and signer exist; NOT_RUN now",
        },
        {
            "id": "fetch-and-verify",
            "command": (
                "python3 forensics/tools/tlog.py checkpoint --file <checkpoint> "
                "--origin <origin> --key-name <key> --key-hex <hex> --log <mirror> && "
                "python3 forensics/tools/tlog.py verify-inclusion --log <mirror> "
                "--index <n> --size <n> --leaf evidence/a9/STATEMENTS/a8-shard-000.json "
                "--proof <proof> --checkpoint <checkpoint> --key-name <key> "
                "--key-hex <hex>"
            ),
            "runsWhen": (
                "the service publishes a checkpoint and tiles; the tlog.py invocation "
                "is exact, the service-side placeholders are read at admission"
            ),
        },
    ]
    return {
        "schema": "openssl-rs/b1/preflight/1",
        "item": "B1a",
        "status": "NOT_RUN",
        "identity": "admitted-service-slice",
        "admittedService": False,
        "recordedAt": RECORDED_AT,
        "baseCommit": BASE_COMMIT,
        "baseCommitShort": BASE_COMMIT,
        "clause": "docs/ETP-ADDENDUM-B.md §B.30 B1; §B.21; §B.31",
        "checks": checks,
        "absences": [
            "no rekor-tiles binary or POSIX server asset",
            "no Rekor client, cosign or Sigstore client",
            "no log key and no checkpoint signer under this project's control",
            "no witness, no TSA and no network",
            "no digest for the POSIX server asset (the recorded digest is the AWS asset)",
        ],
        "prerequisites": prerequisites,
        "plannedCommands": planned,
        "whatB1WouldNeed": [
            "a pinned POSIX-backed rekor-tiles v2 instance with the exact asset digest recorded",
            "a log key this project controls and a signed checkpoint from it",
            "the admitted client's hashedrekord representation and API version, read from the binary",
            "the exact DSSE envelope digest the admitted client computes (§B.3.3 T3)",
            "an independent witness before any independence claim is made (§B.11)",
            "a trusted RFC 3161 timestamp for signing time (§B.9), which is B2",
        ],
        "whatWasRunInstead": {
            "item": "B1b",
            "identity": IDENTITY,
            "record": "evidence/b1/PUBLICATION.json",
            "establishes": "the offline verifier refuses the §B.24 corruptions",
            "doesNotEstablish": "that any Rekor admission, submission or witness will succeed",
        },
        "nonClaims": [
            "no component was downloaded, installed, started or configured",
            "no network request was made",
            "a pinned version is not an installed service",
            "the planned commands are not executed and are not evidence",
        ],
    }


def controls_document(controls: Sequence[dict[str, Any]]) -> dict[str, Any]:
    run = [c for c in controls if c.get("status") != "NOT_RUN"]
    not_run = [c for c in controls if c.get("status") == "NOT_RUN"]
    return {
        "schema": "openssl-rs/b1/controls/1",
        "item": "B1b",
        "identity": IDENTITY,
        "admittedService": False,
        "recordedAt": RECORDED_AT,
        "baseCommit": BASE_COMMIT,
        "clause": "docs/ETP-ADDENDUM-B.md §B.24",
        "controls": list(controls),
        "summary": {
            "total": len(controls),
            "runOffline": len(run),
            "notRun": len(not_run),
            "fired": sum(1 for c in run if c.get("fired")),
            "canariesAccepted": sum(
                1 for c in run if c.get("canary", {}).get("accepted")
            ),
            "notRunItems": [c["item"] for c in not_run],
        },
        "nonClaims": [
            "a control that fires offline does not qualify a live Rekor service",
            "the canary disables a named check; it does not show the corrupt input is valid",
            "no witness, timestamp or campaign control was run",
        ],
    }


def build() -> tuple[dict[str, bytes], dict[str, bytes]]:
    """Return ``(records, tree)``; the caller writes or compares them."""
    fixture = build_fixture()
    controls = run_controls(
        fixture["entries"],
        fixture["leaf_hashes"],
        fixture["store"],
        fixture["roots"][TREE_SIZE],
        fixture["inclusion"],
    )
    records = {
        "PREFLIGHT.json": _serialise(preflight_document()),
        "FIXTURE.json": _serialise(fixture_document(fixture)),
        "PUBLICATION.json": _serialise(publication_document(fixture)),
        "CONTROLS.json": _serialise(controls_document(controls)),
    }
    tree = {**fixture["files"], **fixture["extras"]}
    return records, tree


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="produce the B1b fixture and records")
    parser.add_argument("--check", action="store_true", help="compare with the committed bytes")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)

    records, tree = build()

    if args.check:
        bad = []
        for name, data in sorted(records.items()):
            path = EVIDENCE / name
            if not path.is_file() or path.read_bytes() != data:
                bad.append(name)
        for relative, data in sorted(tree.items()):
            path = FIXTURE_DIR / relative
            if not path.is_file() or path.read_bytes() != data:
                bad.append(f"fixture/{relative}")
        if bad:
            for name in bad:
                print(f"b1: differs from the committed build: {name}")
            return 1
        print(
            f"b1: check ok records={len(records)} fixtureFiles={len(tree)} "
            f"identity={IDENTITY} admittedService=false"
        )
        print("b1: codes=NONE")
        return 0

    if FIXTURE_DIR.exists():
        shutil.rmtree(FIXTURE_DIR)
    for relative, data in sorted(tree.items()):
        _write_bytes(FIXTURE_DIR / relative, data)
    for name, data in sorted(records.items()):
        _write_bytes(EVIDENCE / name, data)

    controls = json.loads(records["CONTROLS.json"])
    summary = controls["summary"]
    publication = json.loads(records["PUBLICATION.json"])
    print(
        f"b1: identity={IDENTITY} admittedService=false leaves={TREE_SIZE} "
        f"publishedIndex={PUBLISHED_INDEX} root={publication['rootHash']}"
    )
    print(
        f"b1: controls={summary['total']} runOffline={summary['runOffline']} "
        f"notRun={summary['notRun']} fired={summary['fired']} "
        f"canariesAccepted={summary['canariesAccepted']}"
    )
    print("b1: codes=NONE")
    return 0


if __name__ == "__main__":
    sys.exit(main())
