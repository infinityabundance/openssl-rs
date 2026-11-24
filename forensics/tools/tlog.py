#!/usr/bin/env python3
"""tlog.py -- an offline RFC 6962 / C2SP tiled transparency-log verifier.

Why this tool exists
--------------------
B1 asks for a pinned POSIX-backed Rekor v2 instance.  No Rekor binary, client,
service, log key, witness or network exists in this venue, so the admitted-service
half of B1 is ``NOT_RUN``.  What can be done honestly offline is to implement the
verification rules the addendum names -- and to run those rules against a log
whose identity is *declared* to be a fixture.  This module is that verifier.

It is written from the specification text, not from a third-party transparency
library.  The construction implemented here is the one the pinned C2SP
specifications refer to (``c2sp.org/tlog-tiles`` v1.0.0 and
``c2sp.org/tlog-checkpoint`` v1.1.0, recorded in §B.3.2), which in turn uses
RFC 6962 §2.1 Merkle hashing:

    RFC 6962 §2.1:
      MTH({}) = SHA-256().
      MTH({d(0)}) = SHA-256(0x00 || d(0)).
      For n > 1, let k be the largest power of two smaller than n:
      MTH(D[n]) = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n])).

    RFC 6962 §2.1.1:
      PATH(m, D[n]) = PATH(m, D[0:k]) : MTH(D[k:n]) for m < k
      PATH(m, D[n]) = PATH(m, D[k:n]) : MTH(D[0:k]) for m >= k
      PATH(m, D[1]) = {}

    RFC 6962 §2.1.2:
      PROOF(m, D[n]) = SUBPROOF(m, D[n], true)
      SUBPROOF(m, D[m], true) = {}
      SUBPROOF(m, D[m], false) = {MTH(D[m])}
      For m < n, k = the largest power of two smaller than n:
        SUBPROOF(m, D[n], b) = SUBPROOF(m, D[0:k], b) : MTH(D[k:n]) if m <= k
        SUBPROOF(m, D[n], b) = SUBPROOF(m, D[k:n], false) : MTH(D[0:k]) if m > k

The proof *construction* is quoted above.  The verifier below runs the same
recursion in the same order and additionally requires the reconstructed hash of
the first ``m`` leaves to equal the authenticated ``root_m``: the RFC's
node-accumulation form discharges that obligation by starting from ``root_m``.
Without that equality a proof could reconstruct the larger root from different
leaves and say nothing about the smaller tree.

The checkpoint and tile shapes are quoted from the pinned record in
``docs/ETP-ADDENDUM-B.md`` §B.3.2:

  * "A checkpoint body is exactly three mandatory lines -- origin, tree size as
    ASCII decimal, base64 root hash -- followed by optional extension lines, an
    empty line and one or more note signature lines."
  * "A tile at level ``l``, index ``n`` holds the 256 hashes
    ``MTH(D[(n*256 + i)*256^l : (n*256 + i + 1)*256^l])`` for ``i`` in 0..=255.
    A full tile is exactly 256 hashes, 8,192 bytes."
  * "Tile paths are ``<prefix>/tile/<L>/<N>[.p/<W>]``; ``<N>`` is encoded as
    zero-padded 3-digit path elements of which all but the last begin with ``x``
    (``1234067`` -> ``x001/x234/067``); ``<W>`` is the partial-tile width, 1-255.
    Entry bundles are ``<prefix>/tile/entries/<N>[.p/<W>]`` and are sequences of
    big-endian ``uint16`` length-prefixed entries."

An entry bundle is also called a data tile here: the 256 leaves of a tile,
length-prefixed.  Hash tiles at level 0 hold the leaf hashes; level ``l > 0``
holds complete 256^l-leaf subtree hashes.  A partial right edge is not stored at
a higher level: a node hash is only stored when its whole subtree is inside the
authenticated tree size, so ``floor(size / 2^l)`` nodes exist at level ``l``.

What this tool does not do
--------------------------
It is not Rekor, ``rekor-tiles`` or Tessera.  It does not speak the Rekor HTTP
API, construct a ``hashedrekord`` entry, read a Sigstore bundle, verify a
witness cosignature or contact a service.  It implements no production
signature primitive: the checkpoint signer here is the A10 **test-only**
HMAC-SHA256 key, so a checkpoint it accepts proves the bytes are unchanged and
that the test key signed them -- not that an independent log operator signed
them.  A fixture log is not an admitted service.

The ``disabled`` argument on the verifiers is a qualification seam: the evidence
producer and the tests use it to show that a refusal is attributable to the named
check (the same control is accepted when the check is disabled).  No command-line
flag exposes it, the default is the empty set, and no record is produced with a
check disabled.

Usage
-----
    python3 forensics/tools/tlog.py prove --log DIR --index I --size N [--json]
    python3 forensics/tools/tlog.py verify-inclusion --log DIR --index I --size N \
        --leaf FILE --proof PROOF [--checkpoint NOTE] [--root HEX]
    python3 forensics/tools/tlog.py verify-consistency --log DIR --m M --n N \
        --proof PROOF [--root1 HEX --root2 HEX] [--checkpoint1 NOTE --checkpoint2 NOTE]
    python3 forensics/tools/tlog.py checkpoint --file NOTE --origin ORIGIN \
        [--key-name NAME --key-hex HEX | --test-only-key] [--previous PREV] \
        [--log DIR] [--json]

``--proof`` is a JSON array of lower-case hex hashes.  ``--test-only-key``
explicitly selects A10's fixed public test key and prints that fact; there is no
implicit key selection.

Exit status: 0 when the requested verification succeeds, 1 for a refusal, 2 for a
usage or I/O error.  The code (``TL_OK``, ``TL_REFUSED_*``, ``TL_REFUSED_USAGE``)
is always printed.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import argparse
import base64
import binascii
import hashlib
import hmac
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

TOOL_PATH = "forensics/tools/tlog.py"
MODEL_ID = "b1/tlog/1"

HASH_BYTES = 32
TILE_ENTRIES = 256
TILE_BYTES = TILE_ENTRIES * HASH_BYTES  # 8,192 bytes for a full hash tile
MAX_TREE_SIZE = 1 << 63  # refuse absurd sizes before any arithmetic
LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"
EMPTY_ROOT = hashlib.sha256(b"").digest()

NOTE_SIGNATURE_PREFIX = b"\xe2\x80\x94 "  # U+2014 EM DASH, SPACE
CHECKPOINT_MANDATORY_LINES = 3

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_USAGE = 2

CODE_OK = "TL_OK"
CODE_USAGE = "TL_REFUSED_USAGE"

TL_REFUSED_PROOF = "TL_REFUSED_PROOF"
TL_REFUSED_ROOT = "TL_REFUSED_ROOT"
TL_REFUSED_INDEX = "TL_REFUSED_INDEX"
TL_REFUSED_SIZE = "TL_REFUSED_SIZE"
TL_REFUSED_ORIGIN = "TL_REFUSED_ORIGIN"
TL_REFUSED_CHECKPOINT = "TL_REFUSED_CHECKPOINT"
TL_REFUSED_CHECKPOINT_SIGNATURE = "TL_REFUSED_CHECKPOINT_SIGNATURE"
TL_REFUSED_CONSISTENCY = "TL_REFUSED_CONSISTENCY"
TL_REFUSED_ROLLBACK = "TL_REFUSED_ROLLBACK"
TL_REFUSED_SPLIT_VIEW = "TL_REFUSED_SPLIT_VIEW"
TL_REFUSED_TILE = "TL_REFUSED_TILE"
TL_REFUSED_DUPLICATE_LEAF = "TL_REFUSED_DUPLICATE_LEAF"
TL_REFUSED_INCLUSION_OF_ABSENT_LEAF = "TL_REFUSED_INCLUSION_OF_ABSENT_LEAF"
TL_REFUSED_BINDING = "TL_REFUSED_BINDING"
TL_REFUSED_IO = "TL_REFUSED_IO"

REFUSALS: dict[str, dict[str, str]] = {
    TL_REFUSED_PROOF: {
        "condition": (
            "an inclusion proof is malformed (a non-32-byte element, an excess or "
            "missing element) or reconstructs a root other than the authenticated one"
        ),
        "prevents": (
            "that a leaf is reported included in a tree whose authenticated root it "
            "does not reconstruct"
        ),
    },
    TL_REFUSED_ROOT: {
        "condition": (
            "a root hash is not 32 bytes, a checkpoint's root disagrees with the root "
            "recomputed from the tiles, or a corrupted mirror changes the recomputed root"
        ),
        "prevents": (
            "that an unauthenticated or corrupted root authorises inclusion"
        ),
    },
    TL_REFUSED_INDEX: {
        "condition": "a leaf index is not an integer in ``0 <= index < size``",
        "prevents": (
            "that an out-of-range index is reported as the position of a leaf"
        ),
    },
    TL_REFUSED_SIZE: {
        "condition": (
            "a tree size is negative, non-canonical, above the explicit bound, or "
            "claims more leaves than the authenticated tile store provides"
        ),
        "prevents": (
            "that a size the log cannot have reached is read as an authenticated "
            "tree size"
        ),
    },
    TL_REFUSED_ORIGIN: {
        "condition": (
            "a checkpoint origin is malformed, is not the expected log identity, or "
            "two compared checkpoints name different origins (including two shards)"
        ),
        "prevents": (
            "that a checkpoint or proof from another log or shard is read as this "
            "log's state (cross-log and cross-shard substitution)"
        ),
    },
    TL_REFUSED_CHECKPOINT: {
        "condition": (
            "a checkpoint body is not the pinned three-mandatory-line form with "
            "optional extension lines, a terminating empty line and signature lines"
        ),
        "prevents": (
            "that a truncated, re-spaced or extension-confused document is read as an "
            "authenticated checkpoint"
        ),
    },
    TL_REFUSED_CHECKPOINT_SIGNATURE: {
        "condition": (
            "a checkpoint carries no signature, a malformed signature line, a "
            "signature by another key name, the wrong key hash, or a signature that "
            "does not verify over the exact note text"
        ),
        "prevents": (
            "that an unsigned or differently signed checkpoint is read as signed by "
            "the policy-selected key"
        ),
    },
    TL_REFUSED_CONSISTENCY: {
        "condition": (
            "a consistency proof is missing, malformed, or does not reconstruct the "
            "later root from the earlier authenticated root"
        ),
        "prevents": (
            "that a larger tree is granted append-only credit without a valid "
            "relationship to the previously accepted checkpoint"
        ),
    },
    TL_REFUSED_ROLLBACK: {
        "condition": "a checkpoint's tree size is smaller than the previously accepted size",
        "prevents": (
            "that a smaller tree silently replaces a later accepted checkpoint (a "
            "stale checkpoint replayed as current)"
        ),
    },
    TL_REFUSED_SPLIT_VIEW: {
        "condition": (
            "two authenticated checkpoints have the same tree size and different roots"
        ),
        "prevents": (
            "that an equivocating head is accepted as ordinary append-only growth"
        ),
    },
    TL_REFUSED_TILE: {
        "condition": (
            "a tile path, width or body is malformed: a missing tile, a wrong partial "
            "width, a truncated hash tile, a bad uint16 entry length, or a level-0 "
            "hash tile that disagrees with the entry bundle"
        ),
        "prevents": (
            "that a malformed tile, a reordered bundle or an inconsistent mirror is "
            "read as the authenticated log's data"
        ),
    },
    TL_REFUSED_DUPLICATE_LEAF: {
        "condition": "a publication appends a leaf whose exact bytes are already present",
        "prevents": (
            "that the same statement is counted twice as two independent log entries"
        ),
    },
    TL_REFUSED_INCLUSION_OF_ABSENT_LEAF: {
        "condition": (
            "the leaf stored at the claimed index is not the exact statement being "
            "verified (a valid leaf for another attestation)"
        ),
        "prevents": (
            "that a valid inclusion proof for one entry is read as inclusion of an "
            "unpublished statement"
        ),
    },
    TL_REFUSED_BINDING: {
        "condition": (
            "a statement's subject digest does not match the bytes it names, or the "
            "payload digest does not match the leaf payload"
        ),
        "prevents": (
            "that a statement about one artefact is bound to another artefact's bytes"
        ),
    },
    TL_REFUSED_IO: {
        "condition": "a required file is absent or unreadable",
        "prevents": (
            "that a missing record is treated as an empty record or as agreement"
        ),
    },
}

REFUSAL_CODES = tuple(REFUSALS)
INVOCATION_CODES = (CODE_USAGE, TL_REFUSED_IO)
ALL_CODES = (CODE_OK,) + REFUSAL_CODES + INVOCATION_CODES


class Refusal(Exception):
    """A stable refusal code and the conclusion it prevents."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


def _fail(code: str, message: str) -> None:
    raise Refusal(code, message)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(bytes(data)).hexdigest()


def _as_bytes(data: Any, where: str) -> bytes:
    if isinstance(data, (bytes, bytearray, memoryview)):
        return bytes(data)
    _fail(TL_REFUSED_PROOF, f"{where}: bytes are required, not {type(data).__name__}")


def _as_hex(value: str, *, code: str, where: str) -> bytes:
    if not isinstance(value, str):
        _fail(code, f"{where}: a lower-case hex string is required")
    if len(value) % 2 or any(c not in "0123456789abcdef" for c in value):
        _fail(code, f"{where}: not lower-case hex")
    return bytes.fromhex(value)


def hex_list(hashes: Iterable[bytes]) -> list[str]:
    return [h.hex() for h in hashes]


def parse_hex_list(values: Any, *, code: str, where: str) -> list[bytes]:
    if not isinstance(values, (list, tuple)):
        _fail(code, f"{where}: a list of hex hashes is required")
    out = []
    for index, value in enumerate(values):
        item = _as_hex(value, code=code, where=f"{where}[{index}]")
        if len(item) != HASH_BYTES:
            _fail(code, f"{where}[{index}]: a hash is {HASH_BYTES} bytes")
        out.append(item)
    return out


# ---------------------------------------------------------------------------
# RFC 6962 §2.1 hashing and tree geometry.
# ---------------------------------------------------------------------------


def leaf_hash(entry: bytes) -> bytes:
    """``MTH({d}) = SHA-256(0x00 || d)`` (RFC 6962 §2.1)."""
    return hashlib.sha256(LEAF_PREFIX + bytes(entry)).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    """``MTH(D[n]) = SHA-256(0x01 || MTH(left) || MTH(right))``."""
    left = _as_bytes(left, "left child")
    right = _as_bytes(right, "right child")
    if len(left) != HASH_BYTES or len(right) != HASH_BYTES:
        _fail(
            TL_REFUSED_PROOF,
            f"a node child is {len(left)}/{len(right)} bytes, not {HASH_BYTES}",
        )
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def empty_tree_root() -> bytes:
    """``MTH({}) = SHA-256()``."""
    return EMPTY_ROOT


def largest_power_of_two_less_than(n: int) -> int:
    """The largest ``k = 2^j`` with ``k < n``; ``n`` must be at least 2."""
    if n < 2:
        _fail(TL_REFUSED_SIZE, f"no power of two is smaller than {n}")
    return 1 << ((n - 1).bit_length() - 1)


def _checked_size(size: Any, *, code: str = TL_REFUSED_SIZE) -> int:
    if not isinstance(size, int) or isinstance(size, bool):
        _fail(code, f"a tree size is an integer, not {type(size).__name__}")
    if size < 0 or size > MAX_TREE_SIZE:
        _fail(code, f"tree size {size} is outside 0..={MAX_TREE_SIZE}")
    return size


def _checked_index(index: Any, size: int, disabled: frozenset[str]) -> int:
    if "index" in disabled:
        return int(index) if isinstance(index, int) else 0
    if not isinstance(index, int) or isinstance(index, bool):
        _fail(TL_REFUSED_INDEX, f"a leaf index is an integer, not {type(index).__name__}")
    if index < 0 or index >= size:
        _fail(TL_REFUSED_INDEX, f"leaf index {index} is outside 0..{max(size - 1, -1)}")
    return index


def root_from_leaf_hashes(leaf_hashes: Sequence[bytes]) -> bytes:
    """RFC 6962 §2.1 ``MTH`` over a complete list of leaf hashes."""
    count = len(leaf_hashes)
    if count == 0:
        return empty_tree_root()
    for index, value in enumerate(leaf_hashes):
        if len(value) != HASH_BYTES:
            _fail(TL_REFUSED_ROOT, f"leaf hash {index} is {len(value)} bytes")
    return _mth(leaf_hashes, 0, count)


def _mth(leaf_hashes: Sequence[bytes], start: int, end: int) -> bytes:
    count = end - start
    if count == 0:
        return empty_tree_root()
    if count == 1:
        return leaf_hashes[start]
    k = largest_power_of_two_less_than(count)
    return node_hash(_mth(leaf_hashes, start, start + k), _mth(leaf_hashes, start + k, end))


def root_from_entries(entries: Sequence[bytes]) -> bytes:
    return root_from_leaf_hashes([leaf_hash(entry) for entry in entries])


# ---------------------------------------------------------------------------
# RFC 6962 §2.1.1 inclusion proofs.
# ---------------------------------------------------------------------------


def inclusion_path(leaf_hashes: Sequence[bytes], index: int, size: int | None = None) -> list[bytes]:
    """Generate the RFC 6962 §2.1.1 audit path, bottom-up."""
    size = len(leaf_hashes) if size is None else size
    size = _checked_size(size)
    if size > len(leaf_hashes):
        _fail(TL_REFUSED_SIZE, f"size {size} exceeds the {len(leaf_hashes)} leaves supplied")
    index = _checked_index(index, size, frozenset())
    return _path(leaf_hashes, 0, size, index)


def _path(leaf_hashes: Sequence[bytes], start: int, count: int, m: int) -> list[bytes]:
    if count == 1:
        return []
    k = largest_power_of_two_less_than(count)
    if m < k:
        return _path(leaf_hashes, start, k, m) + [_mth(leaf_hashes, start + k, start + count)]
    return _path(leaf_hashes, start + k, count - k, m - k) + [_mth(leaf_hashes, start, start + k)]


def verify_inclusion(
    leaf: bytes,
    index: int,
    size: int,
    proof: Sequence[bytes],
    root: bytes,
    *,
    disabled: frozenset[str] = frozenset(),
) -> None:
    """Verify an inclusion proof with the RFC 6962 §2.1.3 node accumulation.

    ``leaf`` is the *leaf input* (``d``), not its hash; the caller must have
    obtained it from the statement being verified, never from the untrusted tile
    store.  ``disabled`` names checks the qualification seam may turn off.
    """
    size = _checked_size(size)
    index = _checked_index(index, size, disabled)
    root = _as_bytes(root, "root")
    if "root" not in disabled and len(root) != HASH_BYTES:
        _fail(TL_REFUSED_ROOT, f"the root is {len(root)} bytes, not {HASH_BYTES}")
    proof = list(proof)
    if "proof" not in disabled:
        for position, value in enumerate(proof):
            if len(value) != HASH_BYTES:
                _fail(
                    TL_REFUSED_PROOF,
                    f"proof element {position} is {len(value)} bytes, not {HASH_BYTES}",
                )
        max_elements = size.bit_length() + 1
        if len(proof) > max_elements:
            _fail(
                TL_REFUSED_PROOF,
                f"{len(proof)} proof elements exceed the {max_elements} an RFC 6962 "
                f"path of size {size} can have",
            )
    fn = index
    sn = size - 1
    r = leaf_hash(leaf)
    for position, sibling in enumerate(proof):
        if "proof" not in disabled and sn == 0:
            _fail(
                TL_REFUSED_PROOF,
                f"proof element {position} is excess for leaf {index} in size {size}",
            )
        if fn & 1 or fn == sn:
            r = node_hash(sibling, r)
            if not (fn & 1):
                while fn != 0 and not (fn & 1):
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, sibling)
        fn >>= 1
        sn >>= 1
    if "proof" not in disabled and sn != 0:
        _fail(
            TL_REFUSED_PROOF,
            f"the proof has too few elements: {sn + 1} sibling(s) of the right edge "
            "remain unaccounted for",
        )
    if "root" not in disabled and r != root:
        _fail(
            TL_REFUSED_PROOF,
            f"the proof reconstructs {r.hex()}, not the authenticated root {root.hex()}",
        )


# ---------------------------------------------------------------------------
# RFC 6962 §2.1.2 consistency proofs.
# ---------------------------------------------------------------------------


def consistency_path(
    leaf_hashes: Sequence[bytes], m: int, n: int | None = None
) -> list[bytes]:
    """Generate the RFC 6962 §2.1.2 consistency proof between sizes ``m`` and ``n``."""
    n = len(leaf_hashes) if n is None else n
    n = _checked_size(n)
    m = _checked_size(m)
    if n > len(leaf_hashes):
        _fail(TL_REFUSED_SIZE, f"size {n} exceeds the {len(leaf_hashes)} leaves supplied")
    if m > n:
        _fail(TL_REFUSED_SIZE, f"the earlier size {m} exceeds the later size {n}")
    if m == 0:
        return []
    return _subproof(leaf_hashes, 0, n, m, True)


def _subproof(
    leaf_hashes: Sequence[bytes], start: int, end: int, m: int, complete: bool
) -> list[bytes]:
    count = end - start
    if m == count:
        return [] if complete else [_mth(leaf_hashes, start, end)]
    k = largest_power_of_two_less_than(count)
    if m <= k:
        return _subproof(leaf_hashes, start, start + k, m, complete) + [
            _mth(leaf_hashes, start + k, end)
        ]
    return _subproof(leaf_hashes, start + k, end, m - k, False) + [
        _mth(leaf_hashes, start, start + k)
    ]


def verify_consistency(
    m: int,
    n: int,
    proof: Sequence[bytes],
    root_m: bytes,
    root_n: bytes,
    *,
    disabled: frozenset[str] = frozenset(),
) -> None:
    """Verify a consistency proof by running the §2.1.2 recursion in order.

    The recursion returns the hash of the larger span and of the earlier tree's
    portion inside it.  Both are required: ``big == root_n`` binds the proof to
    the later checkpoint, and ``small == root_m`` binds it to the earlier one.
    """
    m = _checked_size(m)
    n = _checked_size(n)
    if m > n:
        _fail(TL_REFUSED_SIZE, f"the earlier size {m} exceeds the later size {n}")
    root_m = _as_bytes(root_m, "earlier root")
    root_n = _as_bytes(root_n, "later root")
    if "root" not in disabled:
        if len(root_m) != HASH_BYTES or len(root_n) != HASH_BYTES:
            _fail(TL_REFUSED_ROOT, "a consistency root is not 32 bytes")
    proof = list(proof)
    if m == n:
        if "proof" not in disabled and proof:
            _fail(TL_REFUSED_CONSISTENCY, "equal sizes require an empty consistency proof")
        if "root" not in disabled and root_m != root_n:
            _fail(TL_REFUSED_CONSISTENCY, "equal sizes carry different roots")
        return
    if m == 0:
        if "proof" not in disabled and proof:
            _fail(TL_REFUSED_CONSISTENCY, "an empty earlier tree requires an empty proof")
        if "root" not in disabled and root_m != empty_tree_root():
            _fail(
                TL_REFUSED_CONSISTENCY,
                "an empty earlier tree's root is SHA-256 of the empty string",
            )
        return
    if "proof" not in disabled:
        for position, value in enumerate(proof):
            if len(value) != HASH_BYTES:
                _fail(
                    TL_REFUSED_CONSISTENCY,
                    f"proof element {position} is {len(value)} bytes, not {HASH_BYTES}",
                )
        if len(proof) > n.bit_length() + 1:
            _fail(
                TL_REFUSED_CONSISTENCY,
                f"{len(proof)} proof elements exceed the bound for size {n}",
            )
    big, small, consumed = _reconstruct(proof, 0, m, n, True, root_m)
    if "proof" not in disabled and consumed != len(proof):
        _fail(
            TL_REFUSED_CONSISTENCY,
            f"{len(proof) - consumed} proof element(s) were not consumed",
        )
    if "root" not in disabled:
        if small != root_m:
            _fail(
                TL_REFUSED_CONSISTENCY,
                f"the proof's smaller-tree reconstruction {small.hex()} is not the "
                f"authenticated {root_m.hex()}",
            )
        if big != root_n:
            _fail(
                TL_REFUSED_CONSISTENCY,
                f"the proof reconstructs {big.hex()}, not the later root {root_n.hex()}",
            )


def _reconstruct(
    proof: Sequence[bytes],
    position: int,
    m: int,
    count: int,
    complete: bool,
    root_m: bytes,
) -> tuple[bytes, bytes, int]:
    """Return ``(hash_of_span, hash_of_earlier_prefix_in_span, next_position)``."""
    if m == count:
        if complete:
            return root_m, root_m, position
        if position >= len(proof):
            _fail(TL_REFUSED_CONSISTENCY, "the consistency proof ends too early")
        value = proof[position]
        return value, value, position + 1
    k = largest_power_of_two_less_than(count)
    if m <= k:
        big_left, small_left, position = _reconstruct(proof, position, m, k, complete, root_m)
        if position >= len(proof):
            _fail(TL_REFUSED_CONSISTENCY, "the consistency proof ends too early")
        right = proof[position]
        return node_hash(big_left, right), small_left, position + 1
    big_right, small_right, position = _reconstruct(
        proof, position, m - k, count - k, False, root_m
    )
    if position >= len(proof):
        _fail(TL_REFUSED_CONSISTENCY, "the consistency proof ends too early")
    left = proof[position]
    return node_hash(left, big_right), node_hash(left, small_right), position + 1


# ---------------------------------------------------------------------------
# Checkpoint body and note signature.
# ---------------------------------------------------------------------------

NOTE_SIGNATURE_NAME_PATTERN = "the pinned test-only name"


def note_key_hash(name: str) -> bytes:
    """The note key hash: the first four bytes of ``SHA-256(name)``."""
    return hashlib.sha256(name.encode("utf-8")).digest()[:4]


def _canonical_decimal(text: bytes, where: str) -> int:
    if not text:
        _fail(TL_REFUSED_SIZE, f"{where}: an empty decimal")
    for byte in text:
        if not 0x30 <= byte <= 0x39:
            _fail(TL_REFUSED_SIZE, f"{where}: a non-decimal byte")
    if len(text) > 1 and text[:1] == b"0":
        _fail(TL_REFUSED_SIZE, f"{where}: a leading zero is not canonical decimal")
    value = int(text)
    return _checked_size(value)


def _valid_origin(origin: str) -> bool:
    """A checkpoint origin or note key name: one printable line, no newlines.

    A real Sigstore origin contains spaces (for example
    ``rekor.sigstore.dev - 2605736670972794746``), so spaces are allowed; leading
    and trailing whitespace and control characters are not, because they are not
    part of the line the format writes.
    """
    if not isinstance(origin, str) or not origin:
        return False
    if origin != origin.strip():
        return False
    return all(0x20 <= ord(c) <= 0x7E for c in origin)


@dataclass(frozen=True)
class Checkpoint:
    origin: str
    size: int
    root: bytes
    extensions: tuple[str, ...] = ()

    def body(self) -> bytes:
        return checkpoint_text(self.origin, self.size, self.root, self.extensions)


def checkpoint_text(
    origin: str,
    size: int,
    root: bytes,
    extensions: Sequence[str] = (),
) -> bytes:
    """The checkpoint note text: three mandatory lines, extensions, empty line."""
    if not _valid_origin(origin):
        _fail(TL_REFUSED_ORIGIN, f"origin {origin!r} is not a printable token")
    size = _checked_size(size)
    root = _as_bytes(root, "root")
    if len(root) != HASH_BYTES:
        _fail(TL_REFUSED_ROOT, f"the root is {len(root)} bytes, not {HASH_BYTES}")
    lines = [origin, str(size), base64.b64encode(root).decode("ascii")]
    for extension in extensions:
        if not isinstance(extension, str) or not extension or "\n" in extension:
            _fail(TL_REFUSED_CHECKPOINT, "an extension line is one non-empty line")
        if extension.startswith("\u2014 "):
            _fail(
                TL_REFUSED_CHECKPOINT,
                "an extension line may not begin with the signature prefix",
            )
        lines.append(extension)
    return ("\n".join(lines + [""]) + "\n").encode("utf-8")


def parse_checkpoint_body(text: bytes) -> Checkpoint:
    """Parse the exact pinned checkpoint body; the terminating empty line is part
    of the note text and therefore of the signed bytes."""
    raw = bytes(text)
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError as error:
        _fail(TL_REFUSED_CHECKPOINT, f"the checkpoint is not UTF-8: {error}")
    if not raw.endswith(b"\n\n"):
        _fail(
            TL_REFUSED_CHECKPOINT,
            "the note text must end with an empty line before the signature lines",
        )
    lines = raw[:-2].split(b"\n")
    if len(lines) < CHECKPOINT_MANDATORY_LINES:
        _fail(
            TL_REFUSED_CHECKPOINT,
            f"{len(lines)} body line(s); the pinned form has three mandatory lines",
        )
    if any(line == b"" for line in lines):
        _fail(TL_REFUSED_CHECKPOINT, "an empty body line before the terminator")
    try:
        origin = lines[0].decode("utf-8")
    except UnicodeDecodeError as error:
        _fail(TL_REFUSED_ORIGIN, f"the origin is not UTF-8: {error}")
    if not _valid_origin(origin):
        _fail(TL_REFUSED_ORIGIN, f"origin {origin!r} is not a printable token")
    size = _canonical_decimal(lines[1], "tree size")
    root = _strict_b64(lines[2], TL_REFUSED_ROOT, "root hash")
    if len(root) != HASH_BYTES:
        _fail(TL_REFUSED_ROOT, f"the root hash is {len(root)} bytes, not {HASH_BYTES}")
    extensions = []
    for line in lines[CHECKPOINT_MANDATORY_LINES:]:
        try:
            extensions.append(line.decode("utf-8"))
        except UnicodeDecodeError as error:
            _fail(TL_REFUSED_CHECKPOINT, f"an extension is not UTF-8: {error}")
    return Checkpoint(origin, size, root, tuple(extensions))


def _strict_b64(text: bytes, code: str, where: str) -> bytes:
    try:
        decoded = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as error:
        _fail(code, f"{where}: not canonical base64: {error}")
    if base64.b64encode(decoded) != text:
        _fail(code, f"{where}: not the canonical padded base64 encoding")
    return decoded


@dataclass(frozen=True)
class Signature:
    name: str
    key_hash: bytes
    value: bytes


def note_signature(text: bytes, name: str, key: bytes) -> bytes:
    """HMAC-SHA256 over the exact note text (test-only for this fixture)."""
    if not _valid_origin(name):
        _fail(TL_REFUSED_CHECKPOINT_SIGNATURE, f"signature name {name!r} is not a token")
    return hmac.new(bytes(key), bytes(text), hashlib.sha256).digest()


def sign_checkpoint(text: bytes, name: str, key: bytes) -> bytes:
    signature = note_signature(text, name, key)
    line = NOTE_SIGNATURE_PREFIX + name.encode("utf-8") + b" " + base64.b64encode(
        note_key_hash(name) + signature
    )
    return bytes(text) + line + b"\n"


def parse_signed_checkpoint(raw: bytes) -> tuple[Checkpoint, list[Signature]]:
    """Split a signed note into its checkpoint body and signature lines."""
    raw = bytes(raw)
    marker = b"\n" + NOTE_SIGNATURE_PREFIX
    position = raw.find(marker)
    if position < 0:
        if raw.startswith(NOTE_SIGNATURE_PREFIX):
            _fail(TL_REFUSED_CHECKPOINT, "the note has no body before its signature")
        text, signature_block = raw, b""
    else:
        text = raw[: position + 1]  # include the newline before the first signature
        signature_block = raw[position + 1 :]
    checkpoint = parse_checkpoint_body(text)
    signatures: list[Signature] = []
    if signature_block:
        if not signature_block.endswith(b"\n"):
            _fail(TL_REFUSED_CHECKPOINT_SIGNATURE, "a signature line is unterminated")
        for line in signature_block.split(b"\n")[:-1]:
            signatures.append(_parse_signature_line(line))
    return checkpoint, signatures


def _parse_signature_line(line: bytes) -> Signature:
    if not line.startswith(NOTE_SIGNATURE_PREFIX):
        _fail(TL_REFUSED_CHECKPOINT_SIGNATURE, "a non-signature line follows the body")
    payload = line[len(NOTE_SIGNATURE_PREFIX) :]
    space = payload.rfind(b" ")
    if space <= 0:
        _fail(TL_REFUSED_CHECKPOINT_SIGNATURE, "a signature line has no name/value split")
    name_bytes = payload[:space]
    value_bytes = payload[space + 1 :]
    try:
        name = name_bytes.decode("utf-8")
    except UnicodeDecodeError as error:
        _fail(TL_REFUSED_CHECKPOINT_SIGNATURE, f"a signature name is not UTF-8: {error}")
    if not _valid_origin(name):
        _fail(TL_REFUSED_CHECKPOINT_SIGNATURE, f"signature name {name!r} is not a token")
    raw_value = _strict_b64(value_bytes, TL_REFUSED_CHECKPOINT_SIGNATURE, "signature")
    if len(raw_value) < 4 + HASH_BYTES:
        _fail(TL_REFUSED_CHECKPOINT_SIGNATURE, "a signature is shorter than key hash + tag")
    return Signature(name, raw_value[:4], raw_value[4:])


def verify_signature(
    text: bytes,
    signatures: Sequence[Signature],
    *,
    key_name: str,
    key: bytes,
    disabled: frozenset[str] = frozenset(),
) -> Signature:
    """Verify with the *policy-selected* key name, never one from the note."""
    if "signature" in disabled:
        return Signature(key_name, note_key_hash(key_name), b"")
    if not signatures:
        _fail(TL_REFUSED_CHECKPOINT_SIGNATURE, "the checkpoint is unsigned")
    if not isinstance(key_name, str) or not key_name:
        _fail(TL_REFUSED_CHECKPOINT_SIGNATURE, "no key name was selected by policy")
    expected_hash = note_key_hash(key_name)
    for signature in signatures:
        if signature.name != key_name:
            continue
        if signature.key_hash != expected_hash:
            _fail(
                TL_REFUSED_CHECKPOINT_SIGNATURE,
                f"the signature for {key_name!r} carries key hash "
                f"{signature.key_hash.hex()}, not {expected_hash.hex()}",
            )
        expected = note_signature(text, key_name, key)
        if not hmac.compare_digest(signature.value, expected):
            _fail(
                TL_REFUSED_CHECKPOINT_SIGNATURE,
                "the signature does not verify over the exact note text",
            )
        return signature
    _fail(
        TL_REFUSED_CHECKPOINT_SIGNATURE,
        f"no signature names the policy-selected key {key_name!r}",
    )
    raise AssertionError("unreachable")


@dataclass(frozen=True)
class VerifiedHead:
    checkpoint: Checkpoint
    signed: bytes
    signature: Signature

    @property
    def origin(self) -> str:
        return self.checkpoint.origin

    @property
    def size(self) -> int:
        return self.checkpoint.size

    @property
    def root(self) -> bytes:
        return self.checkpoint.root


def verify_checkpoint(
    raw: bytes,
    *,
    key_name: str,
    key: bytes,
    expected_origin: str | None = None,
    previous: VerifiedHead | None = None,
    consistency_proof: Sequence[bytes] | None = None,
    recomputed_root: bytes | None = None,
    disabled: frozenset[str] = frozenset(),
) -> VerifiedHead:
    """Verify a signed checkpoint and, when given, its relationship to the last
    accepted head and to the root recomputed from the tiles.

    The checks run in the order §B.6 fixes: log identity, authorised key, origin,
    signature, authenticated size and root.  A smaller size is a rollback, an
    equal size with a different root is a split view, and a larger size without a
    valid consistency proof receives no append-only credit.
    """
    checkpoint, signatures = parse_signed_checkpoint(raw)
    if "origin" not in disabled:
        if expected_origin is not None and checkpoint.origin != expected_origin:
            _fail(
                TL_REFUSED_ORIGIN,
                f"the checkpoint origin {checkpoint.origin!r} is not the expected "
                f"{expected_origin!r}",
            )
        if previous is not None and checkpoint.origin != previous.origin:
            _fail(
                TL_REFUSED_ORIGIN,
                f"the checkpoint origin {checkpoint.origin!r} differs from the "
                f"accepted origin {previous.origin!r}",
            )
    signature = verify_signature(
        checkpoint.body(), signatures, key_name=key_name, key=key, disabled=disabled
    )
    if "root" not in disabled and checkpoint.size == 0:
        if checkpoint.root != empty_tree_root():
            _fail(
                TL_REFUSED_ROOT,
                "a size-0 checkpoint's root is SHA-256 of the empty string",
            )
    if "root" not in disabled and recomputed_root is not None:
        recomputed = _as_bytes(recomputed_root, "recomputed root")
        if recomputed != checkpoint.root:
            _fail(
                TL_REFUSED_ROOT,
                f"the checkpoint root {checkpoint.root.hex()} is not the root "
                f"recomputed from the tiles {recomputed.hex()}",
            )
    if previous is not None:
        if "rollback" not in disabled and checkpoint.size < previous.size:
            _fail(
                TL_REFUSED_ROLLBACK,
                f"tree size {checkpoint.size} is smaller than the accepted "
                f"{previous.size}: a stale checkpoint cannot replace it",
            )
        if checkpoint.size == previous.size:
            if "split-view" not in disabled and checkpoint.root != previous.root:
                _fail(
                    TL_REFUSED_SPLIT_VIEW,
                    f"two checkpoints at size {checkpoint.size} carry different roots "
                    f"({checkpoint.root.hex()} and {previous.root.hex()}): equivocation",
                )
        elif checkpoint.size > previous.size:
            if "consistency" not in disabled:
                if consistency_proof is None:
                    _fail(
                        TL_REFUSED_CONSISTENCY,
                        f"growth {previous.size} -> {checkpoint.size} has no "
                        "consistency proof",
                    )
                verify_consistency(
                    previous.size,
                    checkpoint.size,
                    consistency_proof,
                    previous.root,
                    checkpoint.root,
                    disabled=disabled,
                )
    return VerifiedHead(checkpoint, bytes(raw), signature)


# ---------------------------------------------------------------------------
# Tiles: entry bundles and hash tiles.
# ---------------------------------------------------------------------------


def _index_segments(index: int) -> str:
    """Encode a tile index as §B.3.2 records: zero-padded 3-digit elements, all
    but the last prefixed with ``x`` (1234067 -> x001/x234/067)."""
    if not isinstance(index, int) or index < 0:
        _fail(TL_REFUSED_TILE, f"tile index {index!r} is not a non-negative integer")
    digits = f"{index:03d}"
    groups: list[str] = []
    while len(digits) > 3:
        groups.insert(0, digits[-3:])
        digits = digits[:-3]
    groups.insert(0, digits.zfill(3))
    return "/".join(
        group if position == len(groups) - 1 else "x" + group
        for position, group in enumerate(groups)
    )


def hash_tile_path(level: int, index: int, width: int | None = None) -> str:
    if not isinstance(level, int) or level < 0:
        _fail(TL_REFUSED_TILE, f"tile level {level!r} is not a non-negative integer")
    path = f"tile/{level}/{_index_segments(index)}"
    if width is not None:
        if not 1 <= width <= TILE_ENTRIES:
            _fail(TL_REFUSED_TILE, f"partial width {width} is outside 1..{TILE_ENTRIES}")
        if width < TILE_ENTRIES:
            path += f".p/{width}"
    return path


def entry_bundle_path(index: int, width: int | None = None) -> str:
    path = f"tile/entries/{_index_segments(index)}"
    if width is not None:
        if not 1 <= width <= TILE_ENTRIES:
            _fail(TL_REFUSED_TILE, f"partial width {width} is outside 1..{TILE_ENTRIES}")
        if width < TILE_ENTRIES:
            path += f".p/{width}"
    return path


def encode_entry_bundle(entries: Sequence[bytes]) -> bytes:
    if len(entries) > TILE_ENTRIES:
        _fail(TL_REFUSED_TILE, f"{len(entries)} entries exceed a tile")
    out = bytearray()
    for position, entry in enumerate(entries):
        entry = _as_bytes(entry, f"entry {position}")
        if len(entry) > 0xFFFF:
            _fail(
                TL_REFUSED_TILE,
                f"entry {position} is {len(entry)} bytes; a uint16 length cannot carry it",
            )
        out += len(entry).to_bytes(2, "big") + entry
    return bytes(out)


def decode_entry_bundle(
    raw: bytes, expected: int | None = None, *, disabled: frozenset[str] = frozenset()
) -> list[bytes]:
    raw = bytes(raw)
    entries: list[bytes] = []
    position = 0
    while position < len(raw):
        if position + 2 > len(raw):
            if "tile" in disabled:
                break
            _fail(TL_REFUSED_TILE, "an entry bundle ends inside a uint16 length")
        length = int.from_bytes(raw[position : position + 2], "big")
        position += 2
        if position + length > len(raw):
            if "tile" in disabled:
                entries.append(raw[position:])
                position = len(raw)
                break
            _fail(
                TL_REFUSED_TILE,
                f"entry {len(entries)} declares {length} bytes but fewer remain",
            )
        entries.append(raw[position : position + length])
        position += length
        if len(entries) > TILE_ENTRIES:
            if "tile" in disabled:
                break
            _fail(TL_REFUSED_TILE, "an entry bundle carries more than 256 entries")
    if "tile" not in disabled and expected is not None and len(entries) != expected:
        _fail(
            TL_REFUSED_TILE,
            f"the entry bundle carries {len(entries)} entries, not the declared {expected}",
        )
    return entries


def encode_hash_tile(hashes: Sequence[bytes]) -> bytes:
    if len(hashes) > TILE_ENTRIES:
        _fail(TL_REFUSED_TILE, f"{len(hashes)} hashes exceed a tile")
    out = bytearray()
    for position, value in enumerate(hashes):
        value = _as_bytes(value, f"hash {position}")
        if len(value) != HASH_BYTES:
            _fail(TL_REFUSED_TILE, f"hash {position} is {len(value)} bytes, not 32")
        out += value
    return bytes(out)


def decode_hash_tile(
    raw: bytes, expected: int | None = None, *, disabled: frozenset[str] = frozenset()
) -> list[bytes]:
    raw = bytes(raw)
    if len(raw) % HASH_BYTES:
        if "tile" not in disabled:
            _fail(
                TL_REFUSED_TILE,
                f"a hash tile is {len(raw)} bytes, which is not a multiple of {HASH_BYTES}",
            )
        raw = raw[: len(raw) - (len(raw) % HASH_BYTES)]
    hashes = [raw[i : i + HASH_BYTES] for i in range(0, len(raw), HASH_BYTES)]
    if len(hashes) > TILE_ENTRIES:
        if "tile" not in disabled:
            _fail(TL_REFUSED_TILE, "a hash tile carries more than 256 hashes")
        hashes = hashes[:TILE_ENTRIES]
    if "tile" not in disabled and expected is not None and len(hashes) != expected:
        _fail(
            TL_REFUSED_TILE,
            f"the hash tile carries {len(hashes)} hashes, not the declared {expected}",
        )
    return hashes


class TileStore:
    """A read-only map from §B.3.2 tile paths to exact bytes.

    Every read is relative to a log prefix; the store makes no trust decision.
    A tile is untrusted until its cryptographic relationship to an authenticated
    checkpoint is established, which is what ``root`` and ``verify_tiles`` do.
    """

    def __init__(self, files: Mapping[str, bytes]) -> None:
        self._files = {str(path): bytes(data) for path, data in files.items()}

    @classmethod
    def from_directory(cls, root: str | Path) -> "TileStore":
        base = Path(root)
        if not base.is_dir():
            _fail(TL_REFUSED_IO, f"{base}: the tile store directory is absent")
        files: dict[str, bytes] = {}
        for path in sorted(base.rglob("*")):
            if path.is_file():
                files[path.relative_to(base).as_posix()] = path.read_bytes()
        return cls(files)

    def paths(self) -> list[str]:
        return sorted(self._files)

    def tile_rows(self) -> list[dict[str, Any]]:
        """Every tile as a record row (path, bytes, sha256), sorted by path."""
        return [
            {
                "path": path,
                "bytes": len(self._files[path]),
                "sha256": hashlib.sha256(self._files[path]).hexdigest(),
            }
            for path in self.paths()
        ]

    def available_leaves(self) -> int | None:
        return self._available_leaves()

    def has(self, path: str) -> bool:
        return path in self._files

    def read(self, path: str) -> bytes:
        if path not in self._files:
            _fail(TL_REFUSED_TILE, f"{path}: the tile is absent")
        return self._files[path]

    def _width(self, count: int, tile_index: int) -> int:
        width = min(TILE_ENTRIES, count - tile_index * TILE_ENTRIES)
        if width <= 0:
            _fail(TL_REFUSED_TILE, f"tile {tile_index} has no entries in this tree")
        return width

    def _read_prefix(self, base: str, needed: int, decoder, what: str) -> list[bytes]:
        """Read at least ``needed`` entries from the tile at ``base``.

        A mirror holding the current log may serve a full tile or a partial tile
        wider than an earlier checkpoint needs.  The prefix is the same leaves; a
        reader verifying an earlier size must not demand a tile re-cut for that
        size.  The exact-width path is preferred, then the full tile, then any
        wider partial tile, and every candidate must parse.
        """
        candidates = [f"{base}.p/{needed}" if needed < TILE_ENTRIES else base, base]
        for path in sorted(self._files):
            if path == base or path.startswith(base + ".p/"):
                candidates.append(path)
        seen: set[str] = set()
        for path in candidates:
            if path in seen or not self.has(path):
                continue
            seen.add(path)
            values = decoder(self.read(path), None)
            if len(values) >= needed:
                return values[:needed]
        _fail(
            TL_REFUSED_TILE,
            f"{what}: no tile at {base} carries {needed} entries",
        )
        raise AssertionError("unreachable")

    def entries(self, tile_index: int, size: int) -> list[bytes]:
        size = _checked_size(size)
        width = self._width(size, tile_index)
        return self._read_prefix(
            entry_bundle_path(tile_index), width, decode_entry_bundle, "entry bundle"
        )

    def hashes(self, level: int, tile_index: int, size: int) -> list[bytes]:
        size = _checked_size(size)
        if level < 0:
            _fail(TL_REFUSED_TILE, "a tile level is non-negative")
        count = size >> level
        width = self._width(count, tile_index)
        return self._read_prefix(
            hash_tile_path(level, tile_index), width, decode_hash_tile, "hash tile"
        )

    def leaf(self, index: int, size: int, *, disabled: frozenset[str] = frozenset()) -> bytes:
        size = _checked_size(size)
        index = _checked_index(index, size, disabled)
        tile_index, within = divmod(index, TILE_ENTRIES)
        return self.entries(tile_index, size)[within]

    def leaf_hash_at(self, index: int, size: int) -> bytes:
        size = _checked_size(size)
        index = _checked_index(index, size, frozenset())
        tile_index, within = divmod(index, TILE_ENTRIES)
        return self.hashes(0, tile_index, size)[within]

    def node_hash_at(self, level: int, node_index: int, size: int) -> bytes:
        size = _checked_size(size)
        span = 1 << level
        if node_index < 0 or (node_index + 1) * span > size:
            _fail(
                TL_REFUSED_TILE,
                f"level {level} node {node_index} is not a complete subtree of size {size}",
            )
        tile_index, within = divmod(node_index, TILE_ENTRIES)
        return self.hashes(level, tile_index, size)[within]

    def _span_hash(self, start: int, span: int, size: int) -> bytes:
        if span == 1:
            return self.leaf_hash_at(start, size)
        if start % span != 0 or start + span > size:
            _fail(TL_REFUSED_TILE, f"[{start}, {start + span}) is not a stored node")
        level = span.bit_length() - 1
        return self.node_hash_at(level, start >> level, size)

    def _tree_hash(self, start: int, count: int, size: int) -> bytes:
        if count == 0:
            return empty_tree_root()
        if start < 0 or start + count > size:
            _fail(
                TL_REFUSED_TILE,
                f"[{start}, {start + count}) is outside the authenticated size {size}",
            )
        if count == 1:
            return self.leaf_hash_at(start, size)
        if count & (count - 1) == 0 and start % count == 0:
            return self._span_hash(start, count, size)
        k = largest_power_of_two_less_than(count)
        return node_hash(
            self._tree_hash(start, k, size),
            self._tree_hash(start + k, count - k, size),
        )

    def root(self, size: int, *, disabled: frozenset[str] = frozenset()) -> bytes:
        size = _checked_size(size)
        if size == 0:
            return empty_tree_root()
        available = self._available_leaves()
        if "size" not in disabled:
            check_size_against_tiles(size, available)
        return self._tree_hash(0, size, size)

    def _available_leaves(self) -> int | None:
        """The leaf count the entry bundles prove, when the count is unambiguous."""
        tiles: dict[int, int] = {}
        for path, data in self._files.items():
            if not path.startswith("tile/entries/"):
                continue
            index = _parse_tile_index(path)
            if index is None:
                continue
            try:
                tiles[index] = len(decode_entry_bundle(data))
            except Refusal:
                continue
        if not tiles:
            return None
        if tiles.get(0) is None or tiles[0] != TILE_ENTRIES:
            return max(tiles) * TILE_ENTRIES + tiles[max(tiles)]
        last = max(tiles)
        return last * TILE_ENTRIES + tiles[last]

    def verify_tiles(
        self,
        size: int,
        expected_root: bytes,
        *,
        disabled: frozenset[str] = frozenset(),
    ) -> bytes:
        """Require the tiles to reproduce ``expected_root`` and to agree internally."""
        size = _checked_size(size)
        computed = self.root(size, disabled=disabled)
        expected_root = _as_bytes(expected_root, "expected root")
        if "root" not in disabled and computed != expected_root:
            _fail(
                TL_REFUSED_ROOT,
                f"the tiles reconstruct {computed.hex()}, not the authenticated "
                f"{expected_root.hex()}",
            )
        for tile_index in range(0, (size + TILE_ENTRIES - 1) // TILE_ENTRIES):
            entries = self.entries(tile_index, size)
            hashes = self.hashes(0, tile_index, size)
            if "tile" in disabled:
                continue
            for offset, (entry, stored) in enumerate(zip(entries, hashes)):
                if leaf_hash(entry) != stored:
                    _fail(
                        TL_REFUSED_TILE,
                        f"leaf {tile_index * TILE_ENTRIES + offset}: the entry bundle "
                        "and the level-0 hash tile disagree",
                    )
        return computed




class TiledLog:
    """A tile store bound to one authenticated tree size and root."""

    def __init__(self, store: TileStore, size: int, root: bytes) -> None:
        self.store = store
        self.size = _checked_size(size)
        self.root_bytes = _as_bytes(root, "root")
        if len(self.root_bytes) != HASH_BYTES:
            _fail(TL_REFUSED_ROOT, "the authenticated root is not 32 bytes")

    def verify(self) -> bytes:
        return self.store.verify_tiles(self.size, self.root_bytes)

    def leaf(self, index: int, *, disabled: frozenset[str] = frozenset()) -> bytes:
        return self.store.leaf(index, self.size, disabled=disabled)

    def inclusion_proof(self, index: int) -> list[bytes]:
        index = _checked_index(index, self.size, frozenset())
        return self._path(0, self.size, index)

    def _path(self, start: int, count: int, m: int) -> list[bytes]:
        if count == 1:
            return []
        k = largest_power_of_two_less_than(count)
        if m < k:
            return self._path(start, k, m) + [
                self.store._tree_hash(start + k, count - k, self.size)
            ]
        return self._path(start + k, count - k, m - k) + [
            self.store._tree_hash(start, k, self.size)
        ]

    def consistency_proof(self, m: int) -> list[bytes]:
        m = _checked_size(m)
        if m > self.size:
            _fail(TL_REFUSED_SIZE, f"the earlier size {m} exceeds {self.size}")
        if m == 0:
            return []
        return self._subproof(0, self.size, m, True)

    def _subproof(self, start: int, end: int, m: int, complete: bool) -> list[bytes]:
        count = end - start
        if m == count:
            return [] if complete else [self.store._tree_hash(start, count, self.size)]
        k = largest_power_of_two_less_than(count)
        if m <= k:
            return self._subproof(start, start + k, m, complete) + [
                self.store._tree_hash(start + k, count - k, self.size)
            ]
        return self._subproof(start + k, end, m - k, False) + [
            self.store._tree_hash(start, k, self.size)
        ]

    def verify_statement_inclusion(
        self,
        statement: bytes,
        index: int,
        proof: Sequence[bytes],
        *,
        disabled: frozenset[str] = frozenset(),
    ) -> None:
        """Bind the statement to the leaf at ``index``, then verify inclusion.

        The leaf bytes come from the statement, never from the tiles; the tile
        store is consulted only to confirm that the log actually carries that
        leaf at the claimed index (the absent-leaf refusal).
        """
        index = _checked_index(index, self.size, disabled)
        if "absent-leaf" not in disabled:
            stored = self.leaf(index)
            if stored != bytes(statement):
                _fail(
                    TL_REFUSED_INCLUSION_OF_ABSENT_LEAF,
                    f"leaf {index} is not the statement whose inclusion is claimed",
                )
        verify_inclusion(
            statement, index, self.size, proof, self.root_bytes, disabled=disabled
        )


def check_size_against_tiles(
    size: int, available: int | None, disabled: frozenset[str] = frozenset()
) -> None:
    """The named size check, usable directly by a qualification canary.

    ``available`` is the leaf count the entry bundles prove, or ``None`` when the
    store carries no entry bundle.  The refusal is a separate check from reading a
    tile, which is why it can be attributed and disabled on its own.
    """
    if "size" in disabled:
        return
    if available is not None and size > available:
        _fail(
            TL_REFUSED_SIZE,
            f"the tiles provide {available} leaves, fewer than the claimed size {size}",
        )


def _parse_tile_index(path: str) -> int | None:
    """Recover a tile index from a §B.3.2 path, or ``None`` if it is not one."""
    tail = path
    if ".p/" in tail:
        tail = tail[: tail.index(".p/")]
    if not tail.startswith("tile/entries/") and not tail.startswith("tile/"):
        return None
    if tail.startswith("tile/entries/"):
        segments = tail[len("tile/entries/") :]
    else:
        rest = tail[len("tile/") :]
        if "/" not in rest:
            return None
        segments = rest.split("/", 1)[1]
    value = 0
    parts = segments.split("/")
    for position, part in enumerate(parts):
        if position < len(parts) - 1:
            if not part.startswith("x") or len(part) != 4 or not part[1:].isdigit():
                return None
            value = value * 1000 + int(part[1:])
        else:
            if len(part) != 3 or not part.isdigit():
                return None
            value = value * 1000 + int(part)
    return value


# ---------------------------------------------------------------------------
# Fixture construction helpers (an offline log writer, not a Rekor server).
# ---------------------------------------------------------------------------


def build_entry_bundles(entries: Sequence[bytes]) -> dict[str, bytes]:
    """Encode the data tiles: 256 length-prefixed leaves per bundle."""
    files: dict[str, bytes] = {}
    for tile_index in range(0, (len(entries) + TILE_ENTRIES - 1) // TILE_ENTRIES):
        chunk = list(entries[tile_index * TILE_ENTRIES : (tile_index + 1) * TILE_ENTRIES])
        files[entry_bundle_path(tile_index, len(chunk))] = encode_entry_bundle(chunk)
    return files


def build_hash_tiles(leaf_hashes: Sequence[bytes]) -> dict[str, bytes]:
    """Encode every complete subtree hash the pinning formula stores.

    Level 0 holds the leaf hashes; level ``l > 0`` holds the
    ``floor(size / 2^l)`` complete-subtree hashes.  A partial right edge is
    recomputed by the reader; it is not stored at a level it does not complete.
    """
    size = len(leaf_hashes)
    for position, value in enumerate(leaf_hashes):
        if len(value) != HASH_BYTES:
            _fail(TL_REFUSED_TILE, f"leaf hash {position} is not 32 bytes")
    files: dict[str, bytes] = {}
    level = 0
    current = list(leaf_hashes)
    while current:
        for tile_index in range(0, (len(current) + TILE_ENTRIES - 1) // TILE_ENTRIES):
            chunk = current[
                tile_index * TILE_ENTRIES : (tile_index + 1) * TILE_ENTRIES
            ]
            files[hash_tile_path(level, tile_index, len(chunk))] = encode_hash_tile(chunk)
        if len(current) == 1:
            break
        current = [
            node_hash(current[i], current[i + 1]) for i in range(0, len(current) - 1, 2)
        ]
        level += 1
    return files


def append_leaf(
    leaf_hashes: list[bytes], entry: bytes, *, disabled: frozenset[str] = frozenset()
) -> int:
    """Append one leaf, refusing an exact duplicate (the fixture's publication rule)."""
    value = leaf_hash(entry)
    if "duplicate" not in disabled and value in leaf_hashes:
        _fail(
            TL_REFUSED_DUPLICATE_LEAF,
            f"leaf {value.hex()} is already present; the same entry would be "
            "counted twice",
        )
    leaf_hashes.append(value)
    return len(leaf_hashes) - 1


def verify_subject_binding(
    statement: bytes,
    repo_root: Path,
    *,
    disabled: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    """Bind a canonical statement to the bytes its subjects name (A9's reader).

    The statement's own bytes and the subject files are re-read here; the result
    is a TL refusal code so the binding has the same stable vocabulary as the
    Merkle checks.  With ``disabled={"binding"}`` the statement structure is still
    checked but the subject files are not re-hashed -- the qualification canary.
    """
    import intoto  # noqa: PLC0415 - imported lazily so Merkle work needs no A9

    try:
        return intoto.decode(
            bytes(statement), repo_root=None if "binding" in disabled else Path(repo_root)
        )
    except intoto.Refusal as refusal:
        _fail(
            TL_REFUSED_BINDING,
            f"the statement does not bind its subject bytes ({refusal.code}): "
            f"{refusal.message}",
        )
    raise AssertionError("unreachable")


# ---------------------------------------------------------------------------
# Command line.
# ---------------------------------------------------------------------------


def _load_json_file(path: str, code: str = TL_REFUSED_IO) -> Any:
    try:
        raw = Path(path).read_bytes()
    except OSError as error:
        _fail(code, f"{path}: {error}")
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        _fail(code, f"{path}: not JSON: {error}")


def _read_bytes(path: str) -> bytes:
    try:
        return Path(path).read_bytes()
    except OSError as error:
        _fail(TL_REFUSED_IO, f"{path}: {error}")


def _proof_from_file(path: str) -> list[bytes]:
    document = _load_json_file(path)
    if isinstance(document, dict):
        document = document.get("proof", document.get("hashes"))
    return parse_hex_list(document, code=TL_REFUSED_PROOF, where=path)


def _key(args: argparse.Namespace) -> tuple[str, bytes]:
    if args.test_only_key:
        import dsse  # noqa: PLC0415 - the A10 test key is imported only here

        name = args.key_name or "FIXTURE-1 test-only hmac-sha256"
        print(f"key=test-only A10 HMAC-SHA256 name={name!r} notATrustRoot=true")
        return name, dsse.test_only_key()
    if not args.key_name or not args.key_hex:
        _fail(
            TL_REFUSED_CHECKPOINT_SIGNATURE,
            "no verification key: pass --key-name and --key-hex, or --test-only-key",
        )
    return args.key_name, _as_hex(
        args.key_hex, code=TL_REFUSED_CHECKPOINT_SIGNATURE, where="--key-hex"
    )


def _command_prove(args: argparse.Namespace) -> None:
    store = TileStore.from_directory(args.log)
    root = store.root(args.size)
    store.verify_tiles(args.size, root)
    log = TiledLog(store, args.size, root)
    proof = log.inclusion_proof(args.index)
    leaf = log.leaf(args.index)
    document = {
        "index": args.index,
        "treeSize": args.size,
        "rootHash": root.hex(),
        "leafPayloadSha256": sha256_hex(leaf),
        "leafHash": leaf_hash(leaf).hex(),
        "proof": hex_list(proof),
    }
    if args.json:
        print(json.dumps(document, sort_keys=True))
    else:
        print(f"code={CODE_OK} index={args.index} size={args.size} root={root.hex()}")
        print(f"leafPayloadSha256={document['leafPayloadSha256']}")
        print(f"leafHash={document['leafHash']}")
        print("proof=" + ",".join(document["proof"]))
    print(f"code={CODE_OK}")


def _command_verify_inclusion(args: argparse.Namespace) -> None:
    statement = _read_bytes(args.leaf)
    proof = _proof_from_file(args.proof)
    if args.checkpoint:
        name, key = _key(args)
        head = verify_checkpoint(
            _read_bytes(args.checkpoint), key_name=name, key=key, expected_origin=args.origin
        )
        size, root = head.size, head.root
        print(
            f"checkpoint origin={head.origin} size={head.size} root={head.root.hex()} "
            "signature=verified"
        )
    else:
        if args.size is None or args.root is None:
            _fail(CODE_USAGE, "pass --checkpoint, or --size and --root")
        size = args.size
        root = _as_hex(args.root, code=TL_REFUSED_ROOT, where="--root")
    store = TileStore.from_directory(args.log)
    store.verify_tiles(size, root)
    log = TiledLog(store, size, root)
    log.verify_statement_inclusion(statement, args.index, proof)
    print(
        f"code={CODE_OK} index={args.index} size={size} root={root.hex()} "
        f"leafHash={leaf_hash(statement).hex()} proof=verified binding=verified"
    )


def _command_verify_consistency(args: argparse.Namespace) -> None:
    proof = _proof_from_file(args.proof)
    if args.checkpoint1 and args.checkpoint2:
        name, key = _key(args)
        first = verify_checkpoint(
            _read_bytes(args.checkpoint1), key_name=name, key=key, expected_origin=args.origin
        )
        second = verify_checkpoint(
            _read_bytes(args.checkpoint2),
            key_name=name,
            key=key,
            expected_origin=first.origin,
            previous=first,
            consistency_proof=proof,
        )
        print(
            f"checkpoint1 size={first.size} root={first.root.hex()} signature=verified"
        )
        print(
            f"checkpoint2 size={second.size} root={second.root.hex()} "
            "signature=verified consistency=verified"
        )
        print(
            f"code={CODE_OK} m={first.size} n={second.size} "
            f"root1={first.root.hex()} root2={second.root.hex()}"
        )
        return
    if args.root1 is None or args.root2 is None or args.m is None or args.n is None:
        _fail(CODE_USAGE, "pass --checkpoint1/--checkpoint2, or --m/--n/--root1/--root2")
    root1 = _as_hex(args.root1, code=TL_REFUSED_ROOT, where="--root1")
    root2 = _as_hex(args.root2, code=TL_REFUSED_ROOT, where="--root2")
    verify_consistency(args.m, args.n, proof, root1, root2)
    print(
        f"code={CODE_OK} m={args.m} n={args.n} root1={root1.hex()} "
        f"root2={root2.hex()} consistency=verified"
    )


def _command_checkpoint(args: argparse.Namespace) -> None:
    name, key = _key(args)
    raw = _read_bytes(args.file)
    previous = None
    if args.previous:
        previous = verify_checkpoint(
            _read_bytes(args.previous),
            key_name=name,
            key=key,
            expected_origin=args.origin,
        )
    proof = None
    if args.proof:
        proof = _proof_from_file(args.proof)
    recomputed = None
    if args.log:
        store = TileStore.from_directory(args.log)
        recomputed = store.root(args.size if args.size is not None else _checkpoint_size(raw))
    head = verify_checkpoint(
        raw,
        key_name=name,
        key=key,
        expected_origin=args.origin,
        previous=previous,
        consistency_proof=proof,
        recomputed_root=recomputed,
    )
    if args.json:
        print(
            json.dumps(
                {
                    "origin": head.origin,
                    "size": head.size,
                    "rootHash": head.root.hex(),
                    "signatureName": head.signature.name,
                    "signatureKeyHash": head.signature.key_hash.hex(),
                    "signatureVerified": True,
                    "noteTextSha256": sha256_hex(head.checkpoint.body()),
                    "signedNoteSha256": sha256_hex(head.signed),
                },
                sort_keys=True,
            )
        )
    else:
        print(
            f"code={CODE_OK} origin={head.origin} size={head.size} "
            f"root={head.root.hex()} signature=verified name={head.signature.name!r}"
        )
    print(f"code={CODE_OK}")


def _checkpoint_size(raw: bytes) -> int:
    checkpoint, _ = parse_signed_checkpoint(raw)
    return checkpoint.size


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tlog.py", description="offline RFC 6962 / C2SP tiled log verifier"
    )
    sub = parser.add_subparsers(dest="command")

    prove = sub.add_parser("prove", help="reconstruct a leaf and its inclusion proof")
    prove.add_argument("--log", required=True)
    prove.add_argument("--index", type=int, required=True)
    prove.add_argument("--size", type=int, required=True)
    prove.add_argument("--json", action="store_true")

    inclusion = sub.add_parser("verify-inclusion", help="verify a leaf's inclusion")
    inclusion.add_argument("--log", required=True)
    inclusion.add_argument("--index", type=int, required=True)
    inclusion.add_argument("--size", type=int)
    inclusion.add_argument("--root")
    inclusion.add_argument("--leaf", required=True)
    inclusion.add_argument("--proof", required=True)
    inclusion.add_argument("--checkpoint")
    inclusion.add_argument("--origin")

    consistency = sub.add_parser("verify-consistency", help="verify append-only growth")
    consistency.add_argument("--log")
    consistency.add_argument("--m", type=int)
    consistency.add_argument("--n", type=int)
    consistency.add_argument("--root1")
    consistency.add_argument("--root2")
    consistency.add_argument("--proof", required=True)
    consistency.add_argument("--checkpoint1")
    consistency.add_argument("--checkpoint2")
    consistency.add_argument("--origin")

    checkpoint = sub.add_parser("checkpoint", help="verify a signed checkpoint")
    checkpoint.add_argument("--file", required=True)
    checkpoint.add_argument("--origin")
    checkpoint.add_argument("--previous")
    checkpoint.add_argument("--proof")
    checkpoint.add_argument("--log")
    checkpoint.add_argument("--size", type=int)
    checkpoint.add_argument("--json", action="store_true")

    for command in (inclusion, consistency, checkpoint):
        command.add_argument("--key-name")
        command.add_argument("--key-hex")
        command.add_argument("--test-only-key", action="store_true")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    handlers = {
        "prove": _command_prove,
        "verify-inclusion": _command_verify_inclusion,
        "verify-consistency": _command_verify_consistency,
        "checkpoint": _command_checkpoint,
    }
    if args.command not in handlers:
        print(f"code={CODE_USAGE} no command")
        print(parser.format_usage().strip())
        return EXIT_USAGE
    try:
        handlers[args.command](args)
    except Refusal as refusal:
        print(f"code={refusal.code} {refusal.message}")
        return EXIT_USAGE if refusal.code == TL_REFUSED_IO else EXIT_REFUSED
    except OSError as error:
        print(f"code={TL_REFUSED_IO} {error}")
        return EXIT_USAGE
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
