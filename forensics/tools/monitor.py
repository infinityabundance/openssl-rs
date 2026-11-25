#!/usr/bin/env python3
"""monitor.py -- persistent checkpoint state, consistency monitoring and witnesses.

Why this tool exists
--------------------
``docs/ETP-ADDENDUM-B.md`` §B.7 requires a persistent, rollback-resistant
inventory of accepted checkpoints per log shard; §B.12 requires a monitor that
verifies checkpoints and consistency transitions over time; §B.11 requires
witnesses from independent administrative domains with a recorded quorum.  No
public log, no witness service and no network exist in this venue, so this module
does the part that can be done honestly offline:

  * it keeps an append-only store of every accepted checkpoint;
  * it re-verifies the log's signature and the append-only relationship between
    consecutive checkpoints, using ``tlog.py`` for the note format, the signature
    and the RFC 6962 consistency proof;
  * it refuses a smaller size, a conflicting head at an accepted size, a changed
    origin, a checkpoint observed before the last accepted one, a growth without
    a valid consistency proof, and a store whose bytes were edited afterwards;
  * it admits a witness quorum only through A15's distinct-domain rule, so a
    quorum is a count of established operator domains and never a count of
    labels.

What monitoring can and cannot establish
----------------------------------------
It can establish that a *sequence of heads is internally consistent and
append-only*: each head was signed by the policy key over its exact bytes, each
larger head is consistent with the last accepted one, no two accepted heads share
a size with different roots, and the recorded store has not changed since it was
written.  It cannot establish that the log is honest, that no other view of the
log exists, that the operator did not equivocate to a party this monitor never
saw, or that a witness exists.  A monitor that has observed only a subset of a
log cannot assert complete observation (§B.12).

No trusted clock
----------------
``observedAt`` is the monitor's own observation time, supplied explicitly by the
caller.  It is not a signing time, not an integrated time and not a timestamp
authority's answer (§B.9).  It is used only to order observations; a checkpoint
presented with an instant older than the last accepted observation is refused as
backdated.

The store
---------
One JSON object per line, append-only in the sense that a new record names its
predecessor and carries a digest over its own canonical bytes:

    {schema, seq, origin, treeSize, rootHash, signature, observedAt, source,
     noteSha256, prev, digest}

``treeSize``/``rootHash`` are lowercase hex; ``signature`` is the hex tag of the
policy key's note signature; ``noteSha256`` binds the exact signed note the
record was made from; ``prev`` is the previous record's ``digest`` (64 zeros for
the first) and ``digest`` is ``SHA-256`` over the canonical JSON of every other
field.  Editing any field, reordering records, dropping one or splicing one in
changes a digest or a link and is refused as ``MN_REFUSED_STORE_TAMPERED``.  The
digest is not a signature: an editor who recomputes every digest produces a
store that is *self-consistent* but cannot re-sign the checkpoints, and the
semantic audit (non-decreasing size, one root per size, one origin, non-decreasing
observation time) still refuses a rewritten history.

The ``disabled`` argument is a qualification seam.  The producer and the tests
use it to show that a refusal is attributable to the named check (the same input
is accepted when that check is disabled).  No command-line flag exposes it and no
evidence record is produced with a check disabled.

Witnesses
---------
A witness set is ``{operator, keyid, domain}`` per witness, plus the domain's
establishment record, the key's expiry and the witness's signature over the exact
checkpoint bytes.  Admissibility is A15's rule: two labels that share one
establishment record are one domain, so aliases collapse.  The signature and
expiry checks are witness-specific and are performed here; A15 documents that it
does not verify signatures.  A quorum is a count of distinct established
operator domains, never a threshold of labels.

Usage
-----
    python3 forensics/tools/monitor.py observe --note FILE --observed-at ISO \
        --source TEXT [--store FILE] [--proof FILE] [--expected-origin ORIGIN] \
        --key-name NAME (--key-hex HEX | --test-only-key) [--json]
    python3 forensics/tools/monitor.py status [--store FILE] [--json]
    python3 forensics/tools/monitor.py monitor [--store FILE] [--json]
    python3 forensics/tools/monitor.py witness [--witnesses FILE] [--note FILE] \
        [--k K] [--at ISO] [--keys FILE] [--json]

Exit status: 0 when the requested operation succeeds, 1 for a refusal, 2 for a
usage or I/O error.  The code (``MN_OK`` or ``MN_REFUSED_*``) is always printed.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import argparse
import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import dsse  # noqa: E402
import thresholds  # noqa: E402
import tlog  # noqa: E402

REPO_ROOT = TOOLS.parents[1]
TOOL_PATH = "forensics/tools/monitor.py"
MODEL_ID = "b5/monitor/1"
STORE_SCHEMA = "openssl-rs/b5/store/1"
RECORD_SCHEMA = "openssl-rs/b5/observation/1"
WITNESS_SCHEMA = "openssl-rs/b5/witness-set/1"

DEFAULT_STORE = REPO_ROOT / "evidence/b5/store/monitor-store.jsonl"
DEFAULT_WITNESSES = REPO_ROOT / "evidence/b5/WITNESSES.json"
DEFAULT_NOTE = REPO_ROOT / "evidence/b1/fixture/checkpoint-6.note"

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_USAGE = 2

GENESIS = "0" * 64

CODE_OK = "MN_OK"
CODE_USAGE = "MN_REFUSED_USAGE"
MN_REFUSED_USAGE = "MN_REFUSED_USAGE"

MN_REFUSED_IO = "MN_REFUSED_IO"
MN_REFUSED_CHECKPOINT = "MN_REFUSED_CHECKPOINT"
MN_REFUSED_SIGNATURE = "MN_REFUSED_SIGNATURE"
MN_REFUSED_ORIGIN = "MN_REFUSED_ORIGIN"
MN_REFUSED_ROLLBACK = "MN_REFUSED_ROLLBACK"
MN_REFUSED_SPLIT_VIEW = "MN_REFUSED_SPLIT_VIEW"
MN_REFUSED_INCONSISTENT = "MN_REFUSED_INCONSISTENT"
MN_REFUSED_BACKDATED = "MN_REFUSED_BACKDATED"
MN_REFUSED_STORE_TAMPERED = "MN_REFUSED_STORE_TAMPERED"
MN_REFUSED_NO_WITNESS = "MN_REFUSED_NO_WITNESS"
MN_REFUSED_WITNESS_QUORUM = "MN_REFUSED_WITNESS_QUORUM"
MN_REFUSED_WITNESS_ALIASED = "MN_REFUSED_WITNESS_ALIASED"
MN_REFUSED_WITNESS_EXPIRED = "MN_REFUSED_WITNESS_EXPIRED"
MN_REFUSED_WITNESS_SIGNATURE = "MN_REFUSED_WITNESS_SIGNATURE"

REFUSALS: dict[str, dict[str, str]] = {
    MN_REFUSED_CHECKPOINT: {
        "condition": (
            "a note is not the pinned three-line checkpoint body, a signed size-0 "
            "checkpoint carries a root other than SHA-256 of the empty string, or a "
            "size/root is not canonical"
        ),
        "prevents": (
            "that bytes which are not a checkpoint are read as an authenticated head"
        ),
    },
    MN_REFUSED_SIGNATURE: {
        "condition": (
            "a checkpoint carries no signature for the policy-selected key, the key "
            "hash is wrong, or the signature does not verify over the exact note text"
        ),
        "prevents": (
            "that an unsigned or differently signed head is recorded as accepted"
        ),
    },
    MN_REFUSED_ORIGIN: {
        "condition": (
            "a checkpoint's origin differs from the store's accepted origin or from "
            "the origin the caller expected"
        ),
        "prevents": (
            "that another log's or another shard's head is recorded as this log's "
            "state (cross-log and cross-shard substitution)"
        ),
    },
    MN_REFUSED_ROLLBACK: {
        "condition": "a checkpoint's tree size is smaller than the last accepted size",
        "prevents": (
            "that a stale checkpoint silently replaces a later accepted one"
        ),
    },
    MN_REFUSED_SPLIT_VIEW: {
        "condition": (
            "two checkpoints carry the same tree size and different authenticated "
            "roots"
        ),
        "prevents": (
            "that an equivocating head is accepted as ordinary append-only growth"
        ),
    },
    MN_REFUSED_INCONSISTENT: {
        "condition": (
            "a larger checkpoint has no consistency proof against the last accepted "
            "head, or the proof does not reconstruct both roots"
        ),
        "prevents": (
            "that a larger tree receives append-only credit without a verified "
            "relationship to the accepted one"
        ),
    },
    MN_REFUSED_BACKDATED: {
        "condition": (
            "a checkpoint is observed at an instant older than the last accepted "
            "observation, or the observation carries no stated instant"
        ),
        "prevents": (
            "that an observation is ordered before one already accepted, and that an "
            "unstamped observation is read as current"
        ),
    },
    MN_REFUSED_STORE_TAMPERED: {
        "condition": (
            "a store record's chained digest, sequence number, predecessor link or "
            "schema does not verify, or the recorded sequence violates the monitor's "
            "own invariants (non-decreasing size, one root per size, one origin, "
            "non-decreasing observation time)"
        ),
        "prevents": (
            "that bytes edited after the fact are read as the accepted history"
        ),
    },
    MN_REFUSED_NO_WITNESS: {
        "condition": "no witness set exists, or it contains no witness",
        "prevents": (
            "that the absence of a witness is read as a witness quorum or as a "
            "witness-independent result"
        ),
    },
    MN_REFUSED_WITNESS_QUORUM: {
        "condition": (
            "fewer than k distinct established operator domains have a qualifying "
            "witness"
        ),
        "prevents": (
            "that fewer independent witnesses than the recorded quorum are read as "
            "meeting it"
        ),
    },
    MN_REFUSED_WITNESS_ALIASED: {
        "condition": (
            "two witness labels resolve to one establishment record, so the set counts "
            "fewer domains than labels"
        ),
        "prevents": (
            "that one operator is counted twice by spelling its domain twice"
        ),
    },
    MN_REFUSED_WITNESS_EXPIRED: {
        "condition": (
            "a witness key expired before the evaluation instant, or its expiry is "
            "absent or unreadable"
        ),
        "prevents": (
            "that a key which is no longer authorised is counted toward a quorum"
        ),
    },
    MN_REFUSED_WITNESS_SIGNATURE: {
        "condition": (
            "a witness signature does not verify over the exact checkpoint bytes, "
            "signs different bytes, or no key is recorded for its keyid"
        ),
        "prevents": (
            "that a witness which did not sign this checkpoint is counted toward a "
            "quorum"
        ),
    },
    MN_REFUSED_USAGE: {
        "condition": "the command line is malformed or a required argument is absent",
        "prevents": "that a refused invocation is read as an accepted operation",
    },
    MN_REFUSED_IO: {
        "condition": "a required path is absent, unreadable or not a regular file",
        "prevents": "that an unreadable record is read as an empty or agreeing one",
    },
}

ALL_CODES = (CODE_OK,) + tuple(REFUSALS)

_TLOG_CODE_MAP = {
    tlog.TL_REFUSED_CHECKPOINT: MN_REFUSED_CHECKPOINT,
    tlog.TL_REFUSED_ROOT: MN_REFUSED_CHECKPOINT,
    tlog.TL_REFUSED_SIZE: MN_REFUSED_CHECKPOINT,
    tlog.TL_REFUSED_CHECKPOINT_SIGNATURE: MN_REFUSED_SIGNATURE,
    tlog.TL_REFUSED_ORIGIN: MN_REFUSED_ORIGIN,
    tlog.TL_REFUSED_ROLLBACK: MN_REFUSED_ROLLBACK,
    tlog.TL_REFUSED_SPLIT_VIEW: MN_REFUSED_SPLIT_VIEW,
    tlog.TL_REFUSED_CONSISTENCY: MN_REFUSED_INCONSISTENT,
}

# Map a monitor-level check name onto the ``tlog`` disabled names it controls.
_TLOG_DISABLED = {
    "checkpoint": "root",
    "signature": "signature",
    "origin": "origin",
    "consistency": "consistency",
}

RECORD_KEYS = (
    "origin",
    "treeSize",
    "rootHash",
    "signature",
    "observedAt",
    "source",
)


class Refusal(Exception):
    """A stable refusal code and the conclusion it prevents."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


class UsageError(Exception):
    """A malformed invocation (exit status 2)."""


def _fail(code: str, message: str) -> None:
    raise Refusal(code, message)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(bytes(data)).hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _record_digest(record: Mapping[str, Any]) -> str:
    body = {key: value for key, value in record.items() if key != "digest"}
    return sha256_hex(_canonical(body))


# ---------------------------------------------------------------------------
# Instants: the monitor never reads a clock
# ---------------------------------------------------------------------------

_INSTANT = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)


def instant(value: Any) -> datetime | None:
    """Parse an explicitly zoned ISO 8601 instant; never a bare local time.

    A time with no offset is not an instant this monitor can order: it might be
    two different moments in two venues.  It is refused rather than guessed.
    """
    if isinstance(value, datetime):
        return value if value.tzinfo is not None else None
    if not isinstance(value, str) or not _INSTANT.match(value):
        return None
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


# ---------------------------------------------------------------------------
# The persistent store
# ---------------------------------------------------------------------------


def _tlog_disabled(disabled: frozenset[str]) -> frozenset[str]:
    return frozenset(
        _TLOG_DISABLED[name] for name in disabled if name in _TLOG_DISABLED
    )


@dataclass
class CheckpointStore:
    """An ordered list of accepted observations, verified on construction.

    ``from_bytes``/``from_path`` refuse a store whose chain does not verify.  A
    caller that disables the ``store`` check (the qualification seam) receives
    the records unverified; that is never done by a command and never recorded
    as evidence.
    """

    records: list[dict[str, Any]] = field(default_factory=list)

    # -- construction ------------------------------------------------------
    @classmethod
    def from_bytes(
        cls, data: bytes, *, disabled: frozenset[str] = frozenset()
    ) -> "CheckpointStore":
        try:
            text = bytes(data).decode("utf-8")
        except UnicodeDecodeError as error:
            _fail(MN_REFUSED_STORE_TAMPERED, f"the store is not UTF-8: {error}")
        records: list[dict[str, Any]] = []
        if text:
            for number, line in enumerate(text.splitlines(), 1):
                if not line.strip():
                    _fail(
                        MN_REFUSED_STORE_TAMPERED,
                        f"line {number} is blank; an appended record is never blank",
                    )
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as error:
                    _fail(
                        MN_REFUSED_STORE_TAMPERED,
                        f"line {number} is not JSON: {error}",
                    )
                if not isinstance(record, dict):
                    _fail(
                        MN_REFUSED_STORE_TAMPERED,
                        f"line {number} is not a JSON object",
                    )
                records.append(record)
        store = cls(records)
        if "store" not in disabled:
            store.verify_chain()
        return store

    @classmethod
    def from_path(
        cls, path: Path | str | None, *, disabled: frozenset[str] = frozenset()
    ) -> "CheckpointStore":
        if path is None:
            return cls([])
        target = Path(path)
        if not target.exists():
            return cls([])
        if not target.is_file():
            _fail(MN_REFUSED_IO, f"{target} is not a regular file")
        try:
            data = target.read_bytes()
        except OSError as error:
            _fail(MN_REFUSED_IO, f"cannot read {target}: {error}")
        return cls.from_bytes(data, disabled=disabled)

    # -- queries -----------------------------------------------------------
    @property
    def head(self) -> dict[str, Any] | None:
        return self.records[-1] if self.records else None

    @property
    def observations(self) -> int:
        return len(self.records)

    @property
    def origin(self) -> str | None:
        return self.records[0]["origin"] if self.records else None

    def roots_by_size(self) -> dict[int, set[str]]:
        roots: dict[int, set[str]] = {}
        for record in self.records:
            roots.setdefault(record["treeSize"], set()).add(record["rootHash"])
        return roots

    # -- verification ------------------------------------------------------
    def verify_chain(self) -> None:
        expected_prev = GENESIS
        for number, record in enumerate(self.records, 1):
            if record.get("schema") != RECORD_SCHEMA:
                _fail(
                    MN_REFUSED_STORE_TAMPERED,
                    f"record {number} does not declare the {RECORD_SCHEMA} schema",
                )
            if record.get("seq") != number:
                _fail(
                    MN_REFUSED_STORE_TAMPERED,
                    f"record {number} claims sequence {record.get('seq')!r}",
                )
            if record.get("prev") != expected_prev:
                _fail(
                    MN_REFUSED_STORE_TAMPERED,
                    f"record {number} names a predecessor the chain does not have",
                )
            digest = record.get("digest")
            if not isinstance(digest, str) or digest != _record_digest(record):
                _fail(
                    MN_REFUSED_STORE_TAMPERED,
                    f"record {number}'s chained digest does not verify over its bytes",
                )
            for key in RECORD_KEYS:
                if key not in record:
                    _fail(
                        MN_REFUSED_STORE_TAMPERED,
                        f"record {number} has no {key}",
                    )
            expected_prev = digest

    def audit(self) -> dict[str, Any]:
        """Re-check the monitor's own invariants over the recorded sequence."""
        problems: list[str] = []
        last_size = -1
        last_instant: datetime | None = None
        roots: dict[int, str] = {}
        for number, record in enumerate(self.records, 1):
            size = record.get("treeSize")
            if not isinstance(size, int) or isinstance(size, bool) or size < 0:
                problems.append(f"record {number} has no usable treeSize")
                continue
            if size < last_size:
                problems.append(
                    f"record {number} rolls the size back from {last_size} to {size}"
                )
            if size in roots and roots[size] != record.get("rootHash"):
                problems.append(
                    f"record {number} gives size {size} a second root"
                )
            roots.setdefault(size, record.get("rootHash"))
            observed = instant(record.get("observedAt"))
            if observed is None:
                problems.append(f"record {number} has no zoned observation instant")
            elif last_instant is not None and observed < last_instant:
                problems.append(
                    f"record {number} is observed before the record it follows"
                )
            last_instant = observed
            last_size = size
        origins = {record.get("origin") for record in self.records}
        if len(origins) > 1:
            problems.append(
                "the store records more than one origin: "
                + ", ".join(sorted(str(origin) for origin in origins))
            )
        if problems:
            _fail(MN_REFUSED_STORE_TAMPERED, "; ".join(problems))
        return {
            "observations": len(self.records),
            "origin": self.origin,
            "sizes": [record["treeSize"] for record in self.records],
            "transitions": max(len(self.records) - 1, 0),
            "rootsPerSize": {
                str(size): sorted(values) for size, values in self.roots_by_size().items()
            },
        }

    # -- mutation ----------------------------------------------------------
    def append(self, record: Mapping[str, Any]) -> dict[str, Any]:
        stored = {key: record[key] for key in record}
        stored["schema"] = RECORD_SCHEMA
        stored["seq"] = len(self.records) + 1
        stored["prev"] = self.records[-1]["digest"] if self.records else GENESIS
        stored["digest"] = _record_digest(stored)
        self.records.append(stored)
        return stored

    def serialise(self) -> bytes:
        return b"".join(_canonical(record) + b"\n" for record in self.records)


# ---------------------------------------------------------------------------
# Observation
# ---------------------------------------------------------------------------


def _checkpoint_record(
    checkpoint: tlog.Checkpoint, signature: tlog.Signature, note: bytes, **fields: Any
) -> dict[str, Any]:
    return {
        "origin": checkpoint.origin,
        "treeSize": checkpoint.size,
        "rootHash": checkpoint.root.hex(),
        "signature": signature.value.hex(),
        "observedAt": fields["observed_at"],
        "source": fields["source"],
        "noteSha256": sha256_hex(note),
    }


def observe(
    store: CheckpointStore,
    signed_note: bytes,
    *,
    key_name: str,
    key: bytes | None,
    observed_at: str,
    source: str,
    consistency_proof: Sequence[bytes] | None = None,
    expected_origin: str | None = None,
    disabled: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    """Verify one checkpoint and append it, or refuse with a stable code.

    The order is fixed and documented: checkpoint parse, signature, origin,
    rollback, split view, backdating, consistency.  A checkpoint that is both
    backdated and inconsistent refuses ``MN_REFUSED_BACKDATED`` first; the
    consistency check is never skipped on the accepted path.
    """
    if "store" not in disabled:
        store.verify_chain()
        store.audit()

    head = store.head
    origin_expected = expected_origin or (head["origin"] if head else None)
    if not isinstance(key_name, str) or not key_name:
        _fail(MN_REFUSED_SIGNATURE, "no policy key name was selected")
    if key is None and "signature" not in disabled:
        _fail(MN_REFUSED_SIGNATURE, "no policy key material was supplied")

    try:
        verified = tlog.verify_checkpoint(
            bytes(signed_note),
            key_name=key_name,
            key=bytes(key or b""),
            expected_origin=origin_expected,
            disabled=_tlog_disabled(disabled),
        )
    except tlog.Refusal as refusal:
        _fail(
            _TLOG_CODE_MAP.get(refusal.code, MN_REFUSED_CHECKPOINT),
            refusal.message,
        )

    checkpoint = verified.checkpoint
    root_hex = checkpoint.root.hex()

    if head is not None:
        if "rollback" not in disabled and checkpoint.size < head["treeSize"]:
            _fail(
                MN_REFUSED_ROLLBACK,
                f"tree size {checkpoint.size} is smaller than the accepted "
                f"{head['treeSize']}: a stale checkpoint cannot replace it",
            )
        if "split-view" not in disabled:
            for record in store.records:
                if (
                    record["treeSize"] == checkpoint.size
                    and record["rootHash"] != root_hex
                ):
                    _fail(
                        MN_REFUSED_SPLIT_VIEW,
                        f"size {checkpoint.size} already has the accepted root "
                        f"{record['rootHash']} and this head carries {root_hex}: "
                        "equivocation",
                    )

    observed = instant(observed_at)
    if observed is None:
        _fail(
            MN_REFUSED_BACKDATED,
            f"the observation instant {observed_at!r} is absent, local or unreadable; "
            "an observation with no stated instant cannot be ordered",
        )
    if "backdated" not in disabled and head is not None:
        previous = instant(head["observedAt"])
        if previous is None or observed < previous:
            _fail(
                MN_REFUSED_BACKDATED,
                f"the checkpoint is observed at {observed_at}, before the accepted "
                f"{head['observedAt']}",
            )

    consistency: dict[str, Any] | None = None
    if head is not None and checkpoint.size > head["treeSize"]:
        if "consistency" not in disabled:
            if consistency_proof is None:
                _fail(
                    MN_REFUSED_INCONSISTENT,
                    f"growth {head['treeSize']} -> {checkpoint.size} has no "
                    "consistency proof",
                )
            try:
                tlog.verify_consistency(
                    head["treeSize"],
                    checkpoint.size,
                    list(consistency_proof),
                    bytes.fromhex(head["rootHash"]),
                    checkpoint.root,
                )
            except tlog.Refusal as refusal:
                _fail(MN_REFUSED_INCONSISTENT, refusal.message)
        consistency = {
            "from": head["treeSize"],
            "to": checkpoint.size,
            "verified": "consistency" not in disabled,
            "elements": len(consistency_proof or ()),
        }

    record = store.append(
        _checkpoint_record(
            checkpoint,
            verified.signature,
            bytes(signed_note),
            observed_at=observed_at,
            source=source,
        )
    )
    return {
        "code": CODE_OK,
        "outcome": "OBSERVED",
        "origin": checkpoint.origin,
        "treeSize": checkpoint.size,
        "rootHash": root_hex,
        "observedAt": observed_at,
        "source": source,
        "observations": store.observations,
        "consistency": consistency,
        "recordDigest": record["digest"],
        "record": record,
    }


def status(
    store: CheckpointStore, *, disabled: frozenset[str] = frozenset()
) -> dict[str, Any]:
    """The latest accepted head, the accepted size and the observation count."""
    if "store" not in disabled:
        store.verify_chain()
        store.audit()
    head = store.head
    return {
        "code": CODE_OK,
        "outcome": "NO_OBSERVATIONS" if head is None else "MONITORED",
        "observations": store.observations,
        "origin": store.origin,
        "acceptedSize": None if head is None else head["treeSize"],
        "head": None
        if head is None
        else {
            "origin": head["origin"],
            "treeSize": head["treeSize"],
            "rootHash": head["rootHash"],
            "observedAt": head["observedAt"],
            "recordDigest": head["digest"],
        },
        "chain": "disabled" if "store" in disabled else "verified",
    }


# ---------------------------------------------------------------------------
# Witness admission, delegated to A15's distinct-domain rule
# ---------------------------------------------------------------------------


def _witness_list(witness_set: Any) -> list[Mapping[str, Any]]:
    if isinstance(witness_set, Mapping):
        witnesses = witness_set.get("witnesses")
        if witnesses is None:
            witnesses = witness_set.get("witnessSet")
    else:
        witnesses = witness_set
    if witnesses is None:
        return []
    if not isinstance(witnesses, list):
        raise UsageError("a witness set is a list or a document with 'witnesses'")
    return [item for item in witnesses if isinstance(item, Mapping)]


def _key_bytes(value: Any) -> bytes | None:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, str):
        try:
            return bytes.fromhex(value)
        except ValueError:
            return None
    return None


def _witness_date(value: Any) -> date | None:
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return date.fromisoformat(value[:10])
    except ValueError:
        return None


def admit_witnesses(
    checkpoint_body: bytes,
    witness_set: Any,
    *,
    k: int,
    at: Any,
    keys: Mapping[str, Any] | None = None,
    disabled: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    """Admit a witness quorum over the exact checkpoint bytes.

    A15's rule is reused, not restated: ``thresholds.distinct_domains`` groups the
    witnesses by their domain's establishment record, so two labels that share
    one record are one domain.  The witness-specific checks (signature over the
    exact checkpoint bytes, key expiry) are performed here; A15 documents that it
    does not verify signatures.
    """
    try:
        tlog.parse_checkpoint_body(bytes(checkpoint_body))
    except tlog.Refusal as refusal:
        _fail(MN_REFUSED_CHECKPOINT, refusal.message)

    witnesses = _witness_list(witness_set)
    if isinstance(k, bool) or not isinstance(k, int) or k < 1:
        raise UsageError("a witness quorum is a positive integer k")
    if not witnesses:
        if "no-witness" not in disabled:
            _fail(
                MN_REFUSED_NO_WITNESS,
                "no witness set exists; witness admission is NOT_RUN, not met",
            )
    key_map = {
        keyid: _key_bytes(value) for keyid, value in (keys or {}).items()
    }
    moment = _witness_date(at)
    if moment is None:
        _fail(
            MN_REFUSED_WITNESS_EXPIRED,
            f"the witness evaluation instant {at!r} is absent or unreadable; no key "
            "can be shown unexpired",
        )

    approved: list[dict[str, Any]] = []
    domains: list[dict[str, Any]] = []
    verdicts: list[dict[str, Any]] = []
    for index, witness in enumerate(witnesses, 1):
        operator = witness.get("operator")
        keyid = witness.get("keyid")
        domain = witness.get("domain")
        verdict: dict[str, Any] = {
            "index": index,
            "operator": operator,
            "keyid": keyid,
            "domain": domain,
            "qualified": False,
        }
        verdicts.append(verdict)
        if not all(isinstance(value, str) and value for value in (operator, keyid, domain)):
            verdict["reason"] = "the witness has no operator, keyid and domain"
            if "witness-signature" not in disabled:
                _fail(MN_REFUSED_WITNESS_SIGNATURE, verdict["reason"])
            continue

        signed_note = witness.get("signedNote")
        if isinstance(signed_note, str):
            signed_note = signed_note.encode("utf-8")
        if "witness-signature" not in disabled:
            if not isinstance(signed_note, (bytes, bytearray, memoryview)):
                _fail(
                    MN_REFUSED_WITNESS_SIGNATURE,
                    f"witness {keyid!r} carries no signature bytes",
                )
            try:
                parsed, signatures = tlog.parse_signed_checkpoint(bytes(signed_note))
            except tlog.Refusal as refusal:
                _fail(MN_REFUSED_WITNESS_SIGNATURE, refusal.message)
            if parsed.body() != bytes(checkpoint_body):
                _fail(
                    MN_REFUSED_WITNESS_SIGNATURE,
                    f"witness {keyid!r} signed different checkpoint bytes",
                )
            material = key_map.get(keyid)
            if material is None:
                _fail(
                    MN_REFUSED_WITNESS_SIGNATURE,
                    f"no key is recorded for witness keyid {keyid!r}",
                )
            try:
                tlog.verify_signature(
                    bytes(checkpoint_body),
                    signatures,
                    key_name=keyid,
                    key=material,
                )
            except tlog.Refusal as refusal:
                _fail(MN_REFUSED_WITNESS_SIGNATURE, refusal.message)

        expires = _witness_date(witness.get("expiresAt"))
        if "witness-expiry" not in disabled:
            if expires is None:
                _fail(
                    MN_REFUSED_WITNESS_EXPIRED,
                    f"witness {keyid!r} declares no readable expiry",
                )
            if expires < moment:
                _fail(
                    MN_REFUSED_WITNESS_EXPIRED,
                    f"witness key {keyid!r} expired at {expires}, before {moment}",
                )

        verdict["qualified"] = True
        verdict["expiresAt"] = None if expires is None else expires.isoformat()
        verdict["establishedBy"] = witness.get("domainEvidence")
        approved.append(
            {
                "identity": operator,
                "domainId": domain,
                "role": "witness",
                "verified": True,
                "approvedAt": witness.get("approvedAt") or moment.isoformat(),
                "expiresAt": (
                    None if expires is None else expires.isoformat()
                ),
            }
        )
        domains.append(
            {
                "domainId": domain,
                "kind": "external",
                "independentOfCandidate": True,
                "establishedBy": witness.get("domainEvidence"),
            }
        )

    structural = thresholds.distinct_domains(
        approved, {"candidateDomain": "openssl-rs", "domains": domains}
    )
    if (
        structural["aliases"] or structural["duplicateIdentities"]
    ) and "witness-alias" not in disabled:
        collapsed = sorted(
            {
                label
                for group in structural["aliases"]
                for label in group["domainIds"]
            }
            | set(structural["duplicateIdentities"])
        )
        _fail(
            MN_REFUSED_WITNESS_ALIASED,
            "these witness labels or identities resolve to one domain: "
            + ", ".join(collapsed),
        )
    count = int(structural["count"])
    if count < k and "quorum" not in disabled:
        _fail(
            MN_REFUSED_WITNESS_QUORUM,
            f"{count} distinct established witness domain(s) and the recorded "
            f"quorum is k={k}",
        )
    return {
        "code": CODE_OK,
        "outcome": "WITNESS_QUORUM_MET",
        "required": k,
        "distinctDomains": count,
        "witnesses": len(witnesses),
        "groups": structural["groups"],
        "aliases": structural["aliases"],
        "selfAsserted": structural["selfAsserted"],
        "notIndependent": structural["notIndependent"],
        "verdicts": verdicts,
        "admittedUnderDisabledCheck": bool(
            {"no-witness", "quorum", "witness-alias", "witness-expiry",
             "witness-signature"} & set(disabled)
        ),
    }


# ---------------------------------------------------------------------------
# Loading helpers
# ---------------------------------------------------------------------------


def load_proof(path: Path | str) -> list[bytes]:
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        _fail(MN_REFUSED_IO, f"cannot read the consistency proof {path}: {error}")
    proof = document.get("proof") if isinstance(document, Mapping) else document
    if not isinstance(proof, list):
        _fail(MN_REFUSED_IO, f"{path} carries no proof list")
    values: list[bytes] = []
    for index, value in enumerate(proof):
        if (
            not isinstance(value, str)
            or len(value) % 2
            or any(c not in "0123456789abcdef" for c in value)
        ):
            _fail(MN_REFUSED_IO, f"{path}: proof element {index} is not lower-case hex")
        values.append(bytes.fromhex(value))
    return values


def _read_bytes(path: Path | str, what: str) -> bytes:
    target = Path(path)
    if not target.is_file():
        _fail(MN_REFUSED_IO, f"{what} {target} is not a regular file")
    try:
        return target.read_bytes()
    except OSError as error:
        _fail(MN_REFUSED_IO, f"cannot read {what} {target}: {error}")


def _load_json_document(path: Path | str, what: str) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        _fail(MN_REFUSED_IO, f"cannot read {what} {path}: {error}")


def checkpoint_body(note: bytes) -> bytes:
    """The exact body bytes of a signed checkpoint note."""
    try:
        return tlog.parse_signed_checkpoint(bytes(note))[0].body()
    except tlog.Refusal as refusal:
        _fail(MN_REFUSED_CHECKPOINT, refusal.message)


def witness_document_fields(
    document: Any,
) -> tuple[list[Mapping[str, Any]], int | None, Any, dict[str, Any]]:
    """Read the B5 witness inventory and a synthetic witness set alike."""
    if not isinstance(document, Mapping):
        raise UsageError("a witness document is an object")
    witnesses = _witness_list(document)
    quorum = document.get("requiredQuorum")
    k = quorum.get("k") if isinstance(quorum, Mapping) else document.get("k")
    at = document.get("evaluatedAt") or document.get("at")
    keys = document.get("keys")
    return witnesses, k if isinstance(k, int) else None, at, dict(keys or {})


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # type: ignore[override]
        raise UsageError(message)


def _print_result(result: Mapping[str, Any], as_json: bool) -> None:
    if as_json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return
    head = result.get("head") or {}
    size = result.get("treeSize")
    if size is None:
        size = head.get("treeSize")
    if size is None:
        size = result.get("acceptedSize")
    print(
        "code={code} outcome={outcome} observations={observations} "
        "origin={origin} size={size} root={root}".format(
            code=result.get("code"),
            outcome=result.get("outcome"),
            observations=result.get("observations", result.get("witnesses")),
            origin=result.get("origin"),
            size=size,
            root=result.get("rootHash") or head.get("rootHash"),
        )
    )


def _parser() -> _Parser:
    parser = _Parser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    observe_parser = sub.add_parser("observe", help="verify and append one checkpoint")
    observe_parser.add_argument("--store", default=str(DEFAULT_STORE))
    observe_parser.add_argument("--note", required=True)
    observe_parser.add_argument("--observed-at", required=True)
    observe_parser.add_argument("--source", required=True)
    observe_parser.add_argument("--proof", default=None)
    observe_parser.add_argument("--expected-origin", default=None)
    observe_parser.add_argument("--key-name", required=True)
    observe_parser.add_argument("--key-hex", default=None)
    observe_parser.add_argument("--test-only-key", action="store_true")
    observe_parser.add_argument("--json", action="store_true")

    status_parser = sub.add_parser("status", help="print the latest accepted head")
    status_parser.add_argument("--store", default=str(DEFAULT_STORE))
    status_parser.add_argument("--json", action="store_true")

    monitor_parser = sub.add_parser("monitor", help="re-check the recorded sequence")
    monitor_parser.add_argument("--store", default=str(DEFAULT_STORE))
    monitor_parser.add_argument("--json", action="store_true")

    witness_parser = sub.add_parser("witness", help="admit a witness quorum")
    witness_parser.add_argument("--witnesses", default=str(DEFAULT_WITNESSES))
    witness_parser.add_argument("--note", default=str(DEFAULT_NOTE))
    witness_parser.add_argument("--k", default=None)
    witness_parser.add_argument("--at", default=None)
    witness_parser.add_argument("--keys", default=None)
    witness_parser.add_argument("--json", action="store_true")

    return parser


def main(argv: list[str]) -> int:
    try:
        args = _parser().parse_args(argv)
    except UsageError as error:
        print(f"code={MN_REFUSED_USAGE} message={error}")
        return EXIT_USAGE

    try:
        if args.command == "observe":
            store = CheckpointStore.from_path(Path(args.store))
            note = _read_bytes(args.note, "checkpoint note")
            proof = load_proof(args.proof) if args.proof else None
            key: bytes | None
            if args.test_only_key and args.key_hex:
                raise UsageError("select one key source, not both")
            if args.test_only_key:
                key = dsse.test_only_key()
            elif args.key_hex:
                key = _key_bytes(args.key_hex)
                if key is None:
                    raise UsageError("--key-hex is not lower-case hex")
            else:
                raise UsageError("--key-hex or --test-only-key is required")
            result = observe(
                store,
                note,
                key_name=args.key_name,
                key=key,
                observed_at=args.observed_at,
                source=args.source,
                consistency_proof=proof,
                expected_origin=args.expected_origin,
            )
            try:
                Path(args.store).parent.mkdir(parents=True, exist_ok=True)
                Path(args.store).write_bytes(store.serialise())
            except OSError as error:
                _fail(MN_REFUSED_IO, f"cannot write the store {args.store}: {error}")
            _print_result(result, args.json)
            return EXIT_OK

        if args.command == "status":
            store = CheckpointStore.from_path(Path(args.store))
            result = status(store)
            _print_result(result, args.json)
            return EXIT_OK

        if args.command == "monitor":
            store = CheckpointStore.from_path(Path(args.store))
            audit = store.audit()
            result = {
                "code": CODE_OK,
                "outcome": "MONITORED",
                "observations": audit["observations"],
                "origin": audit["origin"],
                "sizes": audit["sizes"],
                "transitions": audit["transitions"],
                "head": None
                if store.head is None
                else {
                    "treeSize": store.head["treeSize"],
                    "rootHash": store.head["rootHash"],
                    "observedAt": store.head["observedAt"],
                },
            }
            _print_result(result, args.json)
            if not args.json:
                print(
                    "monitor: sizes={sizes} transitions={transitions} "
                    "chain=verified".format(**result)
                )
            return EXIT_OK

        # witness
        document = _load_json_document(args.witnesses, "witness set")
        witnesses, document_k, document_at, document_keys = witness_document_fields(
            document
        )
        k = args.k if args.k is not None else document_k
        if k is None:
            raise UsageError("no quorum k is recorded and none was supplied")
        k = int(k)
        at = args.at if args.at is not None else document_at
        if at is None:
            raise UsageError("no evaluation instant is recorded and none was supplied")
        keys = document_keys
        if args.keys:
            loaded = _load_json_document(args.keys, "witness keys")
            if not isinstance(loaded, Mapping):
                raise UsageError("a witness key file is an object of keyid: hex")
            keys = dict(loaded)
        body = checkpoint_body(_read_bytes(args.note, "checkpoint note"))
        result = admit_witnesses(
            body,
            {"witnesses": list(witnesses)},
            k=k,
            at=at,
            keys=keys,
        )
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(
                f"code={result['code']} outcome={result['outcome']} "
                f"witnesses={result['witnesses']} "
                f"distinctDomains={result['distinctDomains']} "
                f"required={result['required']}"
            )
            for verdict in result["verdicts"]:
                print(
                    f"  witness: operator={verdict.get('operator')!r} "
                    f"keyid={verdict.get('keyid')!r} domain={verdict.get('domain')!r} "
                    f"qualified={verdict.get('qualified')}"
                )
        return EXIT_OK

    except UsageError as error:
        print(f"code={MN_REFUSED_USAGE} message={error}")
        return EXIT_USAGE
    except Refusal as refusal:
        print(f"code={refusal.code} message={refusal.message}")
        return EXIT_USAGE if refusal.code == MN_REFUSED_IO else EXIT_REFUSED


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
