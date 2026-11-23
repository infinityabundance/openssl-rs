#!/usr/bin/env python3
"""Evidence freshness: dependency-aware, automatic invalidation (ETP-T9).

The problem this tool exists for
--------------------------------
An evidence artefact is a statement about an identity: these bytes, this source
commit, this tool version, this instrument configuration, these upstream
records. It stays true only while those inputs stay still. The repository has
historically carried artefacts forward by convention -- a receipt written
against build B was read as though it described build B', and only a hand audit
found the difference (``evidence/etp0/TRUST-GAPS.json`` classes
``identity_mismatch`` and ``evidence_not_reconstructable``). Freshness is
therefore computed here from a recorded dependency model, not asserted in prose.

Three questions, kept separate
------------------------------
* ``record`` derives, for every evidence artefact, the inputs its claim depends
  on and writes the registry. Identity, cited paths, producing tool and
  instrument are derived from the artefact's own structured fields and from the
  claim and traceability documents; only carry-forward declarations and
  population exclusions are hand-written, and every one of them is labelled.
* ``check`` answers "what does *this* change set invalidate?", and separately
  "is any artefact stale with respect to the tree it names?". The second is
  computed as the first over ``<artefact identity commit>..HEAD``, so there is
  one invalidation engine, not two.
* ``diff`` classifies a change set on its own, and can re-derive a committed
  history record of several ranges.

Conservative, and openly so
---------------------------
A dependency either matches the change set or it does not. When its identity
cannot be resolved (an ``UNKNOWN`` tool digest, a missing cited path, an
artefact that names only a binary) the artefact is *unresolved*, never
*unaffected*: silence is not evidence of non-impact. "No test covers this" is
not expressible as a preservation procedure, because procedures are implemented
in this file rather than supplied as prose.

Carry-forward
-------------
A stale artefact may stay in the tree only as

* ``EXPLICIT_HISTORY`` -- labelled with the identity it was true at, and
  mechanically excluded from current claims; or
* ``PRESERVATION`` -- a stated argument with its own evidence and a closed-set
  procedure this tool executes. A procedure that names a touched dependency
  fails, and an unimplemented procedure is refused rather than trusted.

What this tool does not decide
------------------------------
It does not decide whether an experiment occurred, whether a tool version is
qualified for a use (ETP-3), whether a claim is true, or whether two different
identities are equivalent. It does not read prose for dependencies: a path
named only in running text is recorded as an advisory citation, never as an
authority. It does not infer that an untouched file is irrelevant to an
artefact's property; that inference is what the dependency model encodes, and a
wrong model invalidates nothing rather than too much -- the model is therefore
declared and reviewable.

Determinism
-----------
No timestamp is written. Every list is sorted on a documented key, JSON is
emitted with sorted keys inside refusal records and fixed separators, and the
same registry and change set produce byte-identical output.

Python 3.11 standard library only.

Usage
-----
    python3 forensics/tools/freshness.py record
    python3 forensics/tools/freshness.py record --at COMMIT --out PATH
    python3 forensics/tools/freshness.py check                 # tree sweep
    python3 forensics/tools/freshness.py check --base A --head B
    python3 forensics/tools/freshness.py check --paths-file PATHS
    python3 forensics/tools/freshness.py diff --base A --head B
    python3 forensics/tools/freshness.py diff --runs PATH [--write]

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS_DIR = Path(__file__).resolve().parent

REGISTRY = REPO_ROOT / "evidence" / "etp-t9" / "DEPENDENCIES.json"
CLAIMS = REPO_ROOT / "evidence" / "etp" / "claims.json"
TRACEABILITY = REPO_ROOT / "evidence" / "etp-t1" / "TRACEABILITY.json"
INSTRUMENTS = REPO_ROOT / "evidence" / "etp3" / "instruments.json"

SCHEMA = "openssl-rs/etp/freshness-dependencies/1"
HISTORY_SCHEMA = "openssl-rs/etp/freshness-history/1"
TRIAGE_SCHEMA = "openssl-rs/etp/identity-triage/1"
TRIAGE_PATH = REPO_ROOT / "evidence" / "etp-t9" / "IDENTITY-TRIAGE.json"

# ---------------------------------------------------------------------------
# The model's fixed vocabulary
# ---------------------------------------------------------------------------

# Dependency kinds. A kind names *why* a change matters, and each is matched by
# exactly one rule in `_dependency_moved`.
DEPENDENCY_KINDS = (
    "source_tree",  # crate source and the build inputs that shape the binary
    "verification_tool",  # the producing/checking tool and its controls
    "instrument",  # an instrument register entry and the harness it runs
    "path",  # a named document or data file the claim reads
    "upstream_evidence",  # another evidence artefact this one re-uses
    "venue",  # the court image and launcher that supplied the environment
)

# The crate build-input closure. A change to any of these changes the bytes a
# build-derived artefact measured, so every such artefact depends on all of it.
BUILD_INPUTS = (
    "src",
    "Cargo.toml",
    "Cargo.lock",
    "build.rs",
    "rust-toolchain.toml",
    "libcrypto.ld",
)

VENUE_INPUTS = (
    "docker/openssl-rs-court.sh",
    "docker/openssl-rs-court.Dockerfile",
    "docker/openssl-rs-court-tools.Dockerfile",
    "docker/openssl-rs-court-tools-install.sh",
    "docker/openssl-rs-court-entrypoint.sh",
    "docker/openssl-rs-court-expand.Dockerfile",
)

# Identity fields, in precedence order. The first tier is the artefact's own
# observational identity; the second names an upstream artefact (so it becomes
# an upstream dependency, not this artefact's own identity).
OWN_IDENTITY_KEYS = (
    "source_identity.repository_head",
    "source_identity.commit",
    "identity.commit",
    "source_head",
    "repository_head",
    "head_at_start",
    "head_at_adjudication",
    "evidence_source_head",
    "source_commit",
    "recorded_at_commit",
    "commit",
    "bound_commit",
)
UPSTREAM_IDENTITY_KEYS = (
    "inventory_source_head",
    "closure_receipts_repository_head",
    "parent_freeze.commit",
    "parent_freeze",
)

# Keys whose value is a path this artefact reads. Matched by leaf name at any
# depth up to three, because identity blocks nest them (`source_identity.inventory_path`).
PATH_LEAVES = (
    "path",
    "paths",
    "inventory_path",
    "receipt_path",
    "ledger_record",
    "artifact_rel",
    "freeze",
    "digests_source",
    "previous_record",
    "recipe",
    "document",
    "log",
    "logs",
    "files",
    "inputs",
)
PATH_KEYS = PATH_LEAVES

# A citation is an *upstream evidence* edge only when the field states that
# this artefact re-uses another one. A bare cross-reference between two records
# is a path dependency: it invalidates on change but must not create
# transitivity, or mutually-referencing records form a cycle that means nothing
# about evidence derivation.
UPSTREAM_LEAVES = (
    "inventory_path",
    "receipt_path",
    "ledger_record",
    "artifact_rel",
    "freeze",
    "digests_source",
    "previous_record",
    "document",
    "recipe",
)

# Keys naming the tool that produced or checks the artefact.
TOOL_KEYS = ("tool", "tool.path", "producer", "generator", "script")

# Population rule. Kept declarative so the excluded population is visible.
POPULATION_ROOTS = ("evidence/", "courts/", "artifacts/")
POPULATION_EXCLUDED_PREFIXES = (
    "evidence/etp-t9/",  # this item's own registry and receipt: no self-reference
    "evidence/etp5/probes/",  # generated probe sources, rebuilt by run_probes.py
)
POPULATION_EXCLUDED_SEGMENTS = ("/raw/", "/fixtures/")
ARTEFACT_SUFFIXES = (".json", ".md", ".txt")
MAX_ARTEFACT_BYTES = 512 * 1024

# Verdicts that a claim may carry while still being read as current evidence.
# A withdrawn, superseded, refuted or contradicted claim is already not current,
# so invalidating it changes nothing and is reported as a finding, not a gate.
NON_CURRENT_VERDICTS = frozenset({"WITHDRAWN", "SUPERSEDED", "REFUTED", "CONTRADICTED"})

# Preservation procedures. The set is closed and each is implemented here, so
# an argument cannot be a paragraph of prose that the tool takes on trust.
PRESERVATION_PROCEDURES = (
    "comment_only",  # every changed line in the concern is a line comment
    "narrowed_scope_untouched",  # the coarse dependency is wider than the concern
    "instrument_register_unchanged",  # the register entry is byte-identical
    "blob_identical",  # the dependency's bytes are identical at both ends
)

# Line-comment markers for the languages `comment_only` admits. The procedure
# refuses every other language rather than guessing.
LINE_COMMENT = {".rs": "//", ".c": "//", ".h": "//"}

HEX = re.compile(r"^[0-9a-f]{7,40}$")
BACKTICK_PATH = re.compile(r"`((?:src|docs|evidence|courts|artifacts|forensics|docker)/[A-Za-z0-9_./-]+)`")

# ---------------------------------------------------------------------------
# Identity triage (ETP-T9 follow-up)
# ---------------------------------------------------------------------------

# Every artefact the registry records without an identity is triaged once. The
# triage is a *declared* overlay, not a derivation performed at check time: the
# classifier below records why each artefact is treated as it is, and `check`
# consumes the committed record. A class is a statement about what can be
# established, never a grade.
#
#   DERIVED       an identity established by a recorded rule (a digest-bound
#                 freeze record, or a harness input read from the tree)
#   DECLARED      the artefact names the tree it was taken at in a structured or
#                 narrow prose field, and that commit resolves
#   HISTORICAL    the artefact is a record of a past moment; its identity is the
#                 commit it was introduced at (or the tree it itself declares)
#                 and it may not be cited as current evidence
#   UNCERTIFIABLE no identity can be established or honestly declared
TRIAGE_CLASSES = ("DERIVED", "DECLARED", "HISTORICAL", "UNCERTIFIABLE")

# Field paths that name the tree an artefact was taken at. These are exact
# paths, not leaf names: `source.working_tree.repository_head` in a freeze record
# names the instrument's tree, not the measured candidate, and must not be read
# as this artefact's identity. An exact set can miss a declaration (which is
# conservative) but cannot invent one.
TRIAGE_IDENTITY_FIELDS = (
    "head",
    "head_at_start",
    "identity.head",
    "identity.source.head",
    "identity.analysis_candidate",
    "source.head",
    "candidate.head",
    "candidate_identity.source_head",
    "source_identity.head",
    "source_identity.repository_head",
    "source_identity.repository_head_start",
    "repository_head_at_measurement",
    "analysis_candidate",
    "source_candidate",
)

# A tracked harness input is not a measurement: its truth is that these bytes are
# in the tree, so the tree it is read from is its identity. The rule is
# definitional and labelled `heuristic` in the record, because it does not claim
# the input was used in any run.
TRIAGE_INPUT_PREFIXES = ("courts/", "forensics/tools/")
TRIAGE_INPUT_SUFFIXES = (".c", ".h", ".sh", ".py", ".pem", ".txt")

# A narrow prose declaration: "frozen inventory at `67ae7f8e9`". The window is
# bounded and the phrase is required, so ordinary prose cannot become an
# identity. The commit must still resolve and be an ancestor of the tree.
TRIAGE_FROZEN_AT = re.compile(r"(?i)\bfrozen\b[^.]{0,80}?\bat\s+([0-9a-f]{7,40})\b")
TRIAGE_SUPERSEDED = re.compile(r"(?i)\bsuperseded\b")
TRIAGE_CANDIDATE_NAME = re.compile(r"^openssl-rs\s+\d+\.\d+\.\d+")
TRIAGE_BUILD_OUTPUT = re.compile(r"\.(?:so|a)$|\.so\.\d+$")

# The closed set of reasons an artefact can be UNCERTIFIABLE, each with what
# would make it certifiable. A cause outside this set is a refusal.
TRIAGE_CAUSES = {
    "U1": (
        "multi-commit-no-declaration",
        "the artefact was modified in more than one commit and names no tree; a declared identity commit, "
        "or a single-commit history, would make it certifiable",
    ),
    "U2": (
        "candidate-name-only",
        "the artefact names a candidate version, not a tree; a commit field, or a tracked mapping from the "
        "candidate name to the tree measured, would make it certifiable",
    ),
    "U3": (
        "declared-identity-unresolvable",
        "the declared commit does not resolve to an ancestor of this tree; a resolving commit would make it "
        "certifiable",
    ),
    "U4": (
        "ambiguous-own-identity",
        "the artefact declares more than one tree and does not certify them equivalent; one tree, or a check "
        "that they are source-equivalent, would make it certifiable",
    ),
    "U5": (
        "uncheckable-source-binding",
        "the source-root digest has no recorded rule and the freeze record it names cannot be read from the "
        "tree; a non-null hash rule and a tracked, digest-matching freeze record would make it certifiable",
    ),
    "U6": (
        "build-output-no-identity",
        "a build output names no source tree; a build-identity record naming the source commit and the output "
        "digest would make it certifiable",
    ),
    "U7": (
        "self-qualified-declaration",
        "the declared tree is qualified by a dirty worktree, so the artefact does not claim to correspond to "
        "it; a clean-tree declaration, or the base commit plus the patch digest, would make it certifiable",
    ),
}
TRIAGE_CAUSE_CODES = tuple(TRIAGE_CAUSES)


# ---------------------------------------------------------------------------
# Small utilities
# ---------------------------------------------------------------------------


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_hex(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def canonical(value: Any) -> str:
    """Canonical JSON, used for digests and for sorting refusal records."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def dump_json(document: Any) -> str:
    return json.dumps(document, indent=2, ensure_ascii=False, sort_keys=False) + "\n"


class JsonError(Exception):
    """A document could not be read as unambiguous JSON."""


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise JsonError(f"duplicate key {key!r}")
        seen[key] = value
    return seen


def load_json(path: Path) -> Any:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise JsonError(f"{path}: {exc}") from exc
    try:
        return json.loads(
            text,
            object_pairs_hook=_no_duplicates,
            parse_constant=lambda token: (_ for _ in ()).throw(JsonError(f"non-finite {token}")),
        )
    except json.JSONDecodeError as exc:
        raise JsonError(f"{path}: {exc}") from exc


@dataclass(frozen=True, order=True)
class Refusal:
    """A named refusal. `rule` is a stable identifier, never a message."""

    rule: str
    where: str
    detail: str

    def as_dict(self) -> dict[str, str]:
        return {"rule": self.rule, "where": self.where, "detail": self.detail}


# ---------------------------------------------------------------------------
# Git layer: everything is read at a named commit, never from the working tree
# ---------------------------------------------------------------------------


class Git:
    def __init__(self, repo: Path) -> None:
        self.repo = repo
        self._trees: dict[str, list[str]] = {}
        self._blobs: dict[tuple[str, str], bytes | None] = {}
        self._diffs: dict[tuple[str, str], list[dict[str, str]]] = {}
        self._commits: dict[str, str | None] = {}
        self._last: dict[tuple[str, str], str | None] = {}
        self._exists: dict[tuple[str, str], bool] = {}

    def run(self, *args: str) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            ["git", "-c", "safe.directory=*", "-c", "core.fsmonitor=false", "-C", str(self.repo), *args],
            capture_output=True,
            check=False,
        )

    def resolve(self, rev: str) -> str | None:
        """Resolve a revision to a full commit id, or None.

        A symbolic revision is never cached: `HEAD` moves between calls in a
        test fixture, and a stale cached HEAD would silently turn a change set
        into the empty set.
        """
        if rev != "HEAD" and rev in self._commits:
            return self._commits[rev]
        result = self.run("rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}")
        value = result.stdout.decode().strip() if result.returncode == 0 else None
        if rev != "HEAD":
            self._commits[rev] = value or None
        return value or None

    def head(self) -> str | None:
        return self.resolve("HEAD")

    def tracked(self, commit: str) -> list[str]:
        if commit not in self._trees:
            result = self.run("ls-tree", "-r", "-z", "--name-only", commit)
            names = result.stdout.decode("utf-8", "surrogateescape").split("\0") if result.returncode == 0 else []
            self._trees[commit] = sorted(name for name in names if name)
        return self._trees[commit]

    def exists(self, commit: str, path: str) -> bool:
        key = (commit, path)
        if key not in self._exists:
            self._exists[key] = self.run("cat-file", "-e", f"{commit}:{path}").returncode == 0
        return self._exists[key]

    def blob(self, commit: str, path: str) -> bytes | None:
        key = (commit, path)
        if key not in self._blobs:
            result = self.run("cat-file", "blob", f"{commit}:{path}")
            self._blobs[key] = result.stdout if result.returncode == 0 else None
        return self._blobs[key]

    def digest(self, commit: str, path: str) -> str | None:
        data = self.blob(commit, path)
        return sha256_bytes(data) if data is not None else None

    def text(self, commit: str, path: str) -> str | None:
        data = self.blob(commit, path)
        if data is None:
            return None
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return None

    def changed(self, base: str, head: str) -> list[dict[str, str]]:
        """Paths that differ between two commits. A rename is a delete plus an add.

        A rename is deliberately not followed: the same path at both ends is the
        only shape from which non-impact can be concluded mechanically.
        """
        key = (base, head)
        if key in self._diffs:
            return self._diffs[key]
        result = self.run("diff", "--name-status", "--no-renames", base, head)
        rows: list[dict[str, str]] = []
        if result.returncode == 0:
            for line in result.stdout.decode("utf-8", "surrogateescape").splitlines():
                if not line.strip():
                    continue
                parts = line.split("\t")
                if len(parts) < 2:
                    continue
                rows.append({"status": parts[0][:1], "path": parts[-1]})
        self._diffs[key] = sorted(rows, key=lambda item: (item["path"], item["status"]))
        return self._diffs[key]

    def changed_for(self, base: str, head: str) -> list[dict[str, str]]:
        return self.changed(base, head)

    def is_ancestor(self, base: str, head: str) -> bool:
        return self.run("merge-base", "--is-ancestor", base, head).returncode == 0

    def last_commit(self, commit: str, path: str) -> str | None:
        """The last commit at or before `commit` that changed `path`.

        Provenance, not identity: a file's last-modifying commit is an upper
        bound on when it was written, never the tree it was measured on.
        """
        key = (commit, path)
        if key not in self._last:
            result = self.run("log", "-1", "--format=%H", commit, "--", path)
            value = result.stdout.decode().strip() if result.returncode == 0 else ""
            self._last[key] = value or None
        return self._last[key]

    def commits_touching(self, commit: str, path: str) -> int:
        """How many commits at or before `commit` changed `path`.

        One means the path has been introduced and never modified, so its bytes
        at `commit` are exactly its bytes at the introduced commit. More than
        one means no single moment explains the current bytes.
        """
        result = self.run("rev-list", "--count", commit, "--", path)
        value = result.stdout.decode().strip() if result.returncode == 0 else "0"
        try:
            return int(value)
        except ValueError:
            return 0

    def introducing_commit(self, commit: str, path: str) -> str | None:
        """The commit at or before `commit` that added `path`, or None."""
        result = self.run("log", "--diff-filter=A", "--format=%H", commit, "--", path)
        if result.returncode != 0:
            return None
        found = result.stdout.decode().split()
        return found[-1] if found else None

    def commit_time(self, commit: str) -> int:
        """Committer date, for a deterministic order between two identities."""
        result = self.run("show", "-s", "--format=%ct", commit)
        try:
            return int(result.stdout.decode().strip())
        except ValueError:
            return 0

    def diff_hunks(self, base: str, head: str, path: str) -> list[str] | None:
        """Added and removed lines for one path, or None when the diff fails."""
        result = self.run("diff", "-U0", "--no-color", base, head, "--", path)
        if result.returncode != 0:
            return None
        lines = result.stdout.decode("utf-8", "surrogateescape").splitlines()
        changed: list[str] = []
        for line in lines:
            if line.startswith(("+++", "---", "@@", "diff ", "index ", "new file", "deleted file", "old mode", "new mode")):
                continue
            if line[:1] in "+-":
                changed.append(line[1:])
        return changed


# ---------------------------------------------------------------------------
# Path classification and matching
# ---------------------------------------------------------------------------


def change_class(path: str) -> str:
    """Classify a changed path by the kind of input it is."""
    if path.startswith("src/"):
        return "source"
    if path in BUILD_INPUTS or path in ("artifacts/phase2/libcrypto.ld",):
        return "build"
    if path in VENUE_INPUTS:
        return "venue"
    if path.startswith("forensics/tools/") or path.startswith("courts/") or path.startswith("forensics/etp"):
        return "tool"
    if path.startswith("evidence/etp3/") or path.startswith("evidence/etp-t6/"):
        return "instrument"
    if path.startswith("evidence/") or path.startswith("artifacts/"):
        return "evidence"
    if path.startswith("docs/"):
        return "docs"
    if path.startswith("docker/"):
        return "venue"
    return "other"


def path_within(dep: str, changed: str) -> bool:
    """A dependency covers a changed path by equality or directory containment.

    A directory dependency is written without a trailing slash. A file
    dependency never covers a sibling, so `src/foo.rs` and `src/foo.rs.bak` are
    different inputs.
    """
    if not dep or not changed:
        return False
    dep = dep.rstrip("/")
    if dep == changed:
        return True
    return changed.startswith(dep + "/")


def token_closure(paths: Iterable[str]) -> list[str]:
    """The changed paths plus their ancestor directories.

    The claim algebra matches invalidation tokens by equality, so a claim that
    names a directory (`src`) is invalidated by a change to `src/bn/limbs.rs`
    only if the directory token is present. Adding ancestors is conservative:
    it can invalidate a claim, never preserve one.
    """
    tokens: set[str] = set()
    for path in paths:
        if not path:
            continue
        tokens.add(path)
        parts = path.split("/")[:-1]
        while parts:
            tokens.add("/".join(parts))
            parts = parts[:-1]
    return sorted(tokens)


# ---------------------------------------------------------------------------
# The claim algebra is imported, never reimplemented
# ---------------------------------------------------------------------------


_ALGEBRA: Any = None


def claim_algebra():
    """Load `forensics/tools/etp_claims.py` by path, once per process.

    The invalidation edges, the transitive propagation and the token semantics
    are the algebra's, not this tool's. If the module cannot be loaded the
    engine refuses rather than approximating the algebra.
    """
    global _ALGEBRA
    if _ALGEBRA is not None:
        return _ALGEBRA
    path = TOOLS_DIR / "etp_claims.py"
    spec = importlib.util.spec_from_file_location("_etp_claims_for_freshness", path)
    if spec is None or spec.loader is None:
        raise JsonError(f"cannot load the claim algebra at {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _ALGEBRA = module
    return module


# ---------------------------------------------------------------------------
# Derivation: build the registry from the tree
# ---------------------------------------------------------------------------


@dataclass
class Derivation:
    """Derived facts about one artefact, before declarations are merged."""

    path: str
    sha256: str
    kind: str
    identity: dict[str, Any] = field(default_factory=dict)
    dependencies: list[dict[str, Any]] = field(default_factory=list)
    citations: list[dict[str, Any]] = field(default_factory=list)
    claim_ids: list[str] = field(default_factory=list)
    derivation: dict[str, Any] = field(default_factory=dict)


def _dig(data: Any, dotted: str) -> Any:
    node = data
    for part in dotted.split("."):
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return None
    return node


def _walks(node: Any, depth: int = 0, path: str = "") -> Iterable[tuple[str, Any]]:
    if depth > 3:
        return
    if isinstance(node, dict):
        for key, value in node.items():
            here = f"{path}.{key}" if path else key
            yield here, value
            yield from _walks(value, depth + 1, here)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from _walks(value, depth + 1, f"{path}[{index}]")


def _hex_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value.strip()] if HEX.match(value.strip()) else []
    return []


def extract_identity(document: Any, text: str | None) -> dict[str, Any]:
    """Derive the identity an artefact names.

    Own identity prefers the shallowest structured field in `OWN_IDENTITY_KEYS`.
    Distinct values found at the same tier make the identity AMBIGUOUS and every
    one of them is then evaluated, because the tool may not pick the convenient
    one. A prose document falls back to a recorded heuristic: an explicit
    `commit`/`head`/`S =` mention, marked as heuristic so a reader can check it.
    """
    found: dict[str, list[dict[str, str]]] = {}
    if isinstance(document, (dict, list)):
        for field_path, value in _walks(document):
            leaf = field_path.split(".")[-1].split("[")[0]
            if leaf in ("commit", "repository_head", "source_head", "bound_commit", "recorded_at_commit"):
                for token in _hex_strings(value):
                    found.setdefault(leaf, []).append({"field": field_path, "value": token})

    ordered: list[dict[str, str]] = []
    for key_path in OWN_IDENTITY_KEYS:
        head, _, leaf = key_path.rpartition(".")
        value = _dig(document, key_path) if head else (document.get(leaf) if isinstance(document, dict) else None)
        if value is None and isinstance(document, dict):
            value = _dig(document, leaf)
        for token in _hex_strings(value):
            ordered.append({"field": key_path, "value": token})
    for leaf, entries in found.items():
        for entry in entries:
            if not any(item["value"] == entry["value"] and item["field"] == entry["field"] for item in ordered):
                ordered.append(entry)

    upstream: list[dict[str, str]] = []
    for key_path in UPSTREAM_IDENTITY_KEYS:
        value = _dig(document, key_path)
        for token in _hex_strings(value):
            upstream.append({"field": key_path, "value": token})

    distinct = sorted({item["value"] for item in ordered}, key=lambda value: (-len(value), value))
    if not distinct and text:
        heuristic = _prose_identity(text)
        if heuristic is not None:
            return {
                "commit": heuristic,
                "kind": "heuristic-prose",
                "ambiguous": False,
                "all": [{"field": "prose", "value": heuristic}],
                "upstream": upstream,
                "note": "the artefact names no structured identity; this commit was read from its prose and is advisory",
            }
    return {
        "commit": distinct[0] if distinct else None,
        "kind": "structured" if distinct else "none",
        "ambiguous": len(distinct) > 1,
        "all": sorted(ordered, key=lambda item: (item["field"], item["value"])),
        "upstream": sorted(upstream, key=lambda item: (item["field"], item["value"])),
        "note": (
            "more than one own identity is named at equal precedence; every one is evaluated"
            if len(distinct) > 1
            else None
        ),
    }


PROSE_IDENTITY = re.compile(
    r"(?i)(?:\bcommit\b|\bhead\b|\bbound\s+(?:to|at)\b|\bat\s+S\b|\bS\s*=)\s*`?([0-9a-f]{7,40})`?"
)


def _prose_identity(text: str) -> str | None:
    head = "\n".join(text.splitlines()[:80])
    matches = [match.group(1) for match in PROSE_IDENTITY.finditer(head)]
    if not matches:
        return None
    return sorted(set(matches), key=lambda value: (-len(value), value))[0]


def normalise_dependency_path(item: str) -> str:
    """Reduce a cited path to a repository-relative file path.

    A `file:line` citation names the file; an absolute court path under
    `/work/` names the same file the checkout holds. Anything else is left as
    written, so an untracked path stays visibly untracked.
    """
    value = item.strip()
    stripped = re.sub(r":\d+(?:-\d+)?$", "", value)
    if stripped.startswith("/work/"):
        stripped = stripped[len("/work/") :]
    return stripped


def coarsen_paths(paths: Iterable[str], limit: int = 48) -> tuple[list[str], int]:
    """Replace an exact citation set with its ancestor prefixes when it is huge.

    A prefix covers every path beneath it, so the replacement can only
    invalidate more often than the exact list: the model stays conservative and
    the registry stays reviewable. Returns (paths, number replaced).
    """
    exact = sorted({item for item in paths if item})
    if len(exact) <= limit:
        return exact, 0
    current = exact
    depth = 1
    while len(current) > limit and depth < 5:
        current = sorted({"/".join(item.split("/")[:depth]) for item in current})
        depth += 1
    return current, len(exact)


def _reuses_evidence(field_path: str) -> bool:
    leaf = field_path.split(".")[-1].split("[")[0]
    return leaf in UPSTREAM_LEAVES or field_path.endswith("source.path")


def _collect_paths(document: Any) -> list[tuple[str, str]]:
    """(field, path) pairs for every structured path leaf in the document."""
    found: list[tuple[str, str]] = []

    def add(field: str, item: Any) -> None:
        if isinstance(item, str) and "/" in item and " " not in item:
            found.append((field, normalise_dependency_path(item)))
        elif isinstance(item, dict):
            for candidate in ("path", "id", "name"):
                if isinstance(item.get(candidate), str):
                    add(field, item[candidate])

    for field_path, value in _walks(document):
        leaf = field_path.split(".")[-1].split("[")[0]
        if leaf not in PATH_LEAVES:
            continue
        if isinstance(value, str):
            add(field_path, value)
        elif isinstance(value, list):
            for item in value:
                add(field_path, item)
        elif isinstance(value, dict):
            add(field_path, value)
    return found


def _tool_document(document: Any) -> dict[str, Any] | None:
    for key_path in TOOL_KEYS:
        value = _dig(document, key_path)
        if isinstance(value, dict) and isinstance(value.get("path"), str):
            return value
        if isinstance(value, str) and "/" in value:
            return {"path": value}
    return None


def _instrument_entries(repo: Git, commit: str) -> dict[str, dict[str, Any]]:
    """Instrument id -> register entry, derived from the register itself."""
    text = repo.text(commit, "evidence/etp3/instruments.json")
    if text is None:
        return {}
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        return {}
    entries: dict[str, dict[str, Any]] = {}
    for entry in document.get("instruments", []):
        if isinstance(entry, dict) and isinstance(entry.get("id"), str):
            entries[entry["id"]] = entry
    return entries


def _traceability_evidence(repo: Git, commit: str) -> dict[str, dict[str, Any]]:
    """Cited path -> traceability evidence node, derived from the graph."""
    text = repo.text(commit, "evidence/etp-t1/TRACEABILITY.json")
    if text is None:
        return {}
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        return {}
    by_path: dict[str, dict[str, Any]] = {}
    for node in document.get("nodes", []):
        if not isinstance(node, dict) or node.get("type") != "evidence":
            continue
        source = node.get("source")
        if isinstance(source, dict) and isinstance(source.get("path"), str):
            by_path[source["path"]] = node
    return by_path


def _claims_by_path(repo: Git, commit: str) -> dict[str, list[dict[str, Any]]]:
    text = repo.text(commit, "evidence/etp/claims.json")
    if text is None:
        return {}
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        return {}
    by_path: dict[str, list[dict[str, Any]]] = {}
    for claim in document.get("claims", []):
        if not isinstance(claim, dict):
            continue
        cited: set[str] = set()
        for entry in claim.get("evidence", []):
            if isinstance(entry, dict) and isinstance(entry.get("path"), str):
                cited.add(entry["path"])
        for dependency in claim.get("invalidation", {}).get("depends_on", []):
            if isinstance(dependency, dict) and dependency.get("kind") in ("path", "authority", "evidence"):
                if isinstance(dependency.get("id"), str):
                    cited.add(dependency["id"])
        for path in cited:
            by_path.setdefault(path, []).append(claim)
    return by_path


def in_population(path: str) -> bool:
    if not path.endswith(ARTEFACT_SUFFIXES):
        return False
    if not path.startswith(POPULATION_ROOTS):
        return False
    if any(path.startswith(prefix) for prefix in POPULATION_EXCLUDED_PREFIXES):
        return False
    if any(segment in path for segment in POPULATION_EXCLUDED_SEGMENTS):
        return False
    return True


def population(repo: Git, commit: str) -> tuple[list[str], list[dict[str, str]]]:
    """The tracked artefacts in scope, and the exclusions with their reasons.

    The population is derived from the tree and extended by every path a typed
    claim or a traceability evidence node cites, so a cited record outside the
    evidence roots is still modelled rather than silently missed.
    """
    tracked = repo.tracked(commit)
    tracked_set = set(tracked)
    selected: set[str] = set()
    excluded: list[dict[str, str]] = []
    oversize: set[str] = set()

    for path in tracked:
        if not path.endswith(ARTEFACT_SUFFIXES):
            continue
        if not path.startswith(POPULATION_ROOTS):
            continue
        if in_population(path):
            data = repo.blob(commit, path)
            if data is not None and len(data) > MAX_ARTEFACT_BYTES:
                oversize.add(path)
                excluded.append({"path": path, "reason": "larger than the 512 KiB artefact bound"})
                continue
            selected.add(path)
        elif path.startswith("docs/"):
            excluded.append(
                {"path": path, "reason": "normative document: a claim dependency, not an evidence artefact"}
            )
        elif path.startswith("evidence/etp-t9/"):
            excluded.append({"path": path, "reason": "this item's own registry and receipt; a dependency model cannot contain itself"})
        else:
            excluded.append({"path": path, "reason": "raw campaign payload, fixture or generated probe source"})

    for path, claims in sorted(_claims_by_path(repo, commit).items()):
        if path.startswith("docs/"):
            excluded.append(
                {
                    "path": path,
                    "reason": "normative document cited as claim evidence: a claim dependency, not an evidence artefact",
                }
            )
            continue
        if path in tracked_set and path not in oversize:
            selected.add(path)

    for path in sorted(_traceability_evidence(repo, commit)):
        if path.startswith("docs/"):
            excluded.append(
                {
                    "path": path,
                    "reason": "normative document cited by a traceability node: a claim dependency, not an evidence artefact",
                }
            )
            continue
        if path in tracked_set and path not in oversize:
            selected.add(path)

    unique = {(item["path"], item["reason"]) for item in excluded}
    return sorted(selected), [{"path": path, "reason": reason} for path, reason in sorted(unique)]


def _kind_of(path: str) -> str:
    if "RECEIPT" in Path(path).name.upper() or path.endswith(".md"):
        return "receipt" if "RECEIPT" in Path(path).name.upper() else "document"
    if "LEDGER" in Path(path).name.upper():
        return "ledger"
    if Path(path).name.upper().startswith("MANIFEST"):
        return "manifest"
    if path.endswith(".json"):
        return "record"
    return "artefact"


def derive(repo: Git, commit: str) -> dict[str, Any]:
    """Derive the dependency registry at `commit`."""
    paths, excluded = population(repo, commit)
    claims = _claims_by_path(repo, commit)
    trace = _traceability_evidence(repo, commit)
    instruments = _instrument_entries(repo, commit)

    artefacts: list[dict[str, Any]] = []
    for path in paths:
        text = repo.text(commit, path)
        document: Any = None
        if path.endswith(".json") and text is not None:
            try:
                document = json.loads(text)
            except json.JSONDecodeError:
                document = None
        derived = Derivation(
            path=path,
            sha256=repo.digest(commit, path) or "",
            kind=_kind_of(path),
            identity=extract_identity(document, text),
        )

        deps: dict[tuple[str, str], dict[str, Any]] = {}

        def add(kind: str, ident: str, derivation: str, **extra: Any) -> None:
            key = (kind, ident)
            if key in deps:
                return
            record = {"kind": kind, "id": ident, "source": "derived", "derivation": derivation}
            record.update({key_name: value for key_name, value in extra.items() if value is not None})
            deps[key] = record

        # Build-derived artefacts depend on the whole crate input closure - but
        # only when the artefact names the tree it was taken at. An artefact that
        # names no identity cannot be tied to any input, and is reported as
        # unresolved rather than given a convenient baseline.
        binary = path.startswith("artifacts/") and not path.endswith(ARTEFACT_SUFFIXES)
        bound_to_a_tree = derived.identity.get("commit") is not None or binary
        if bound_to_a_tree and (derived.kind in ("receipt", "record", "ledger", "manifest", "artefact") or document is not None):
            for item in BUILD_INPUTS:
                add("source_tree", item, "crate build-input closure: any change reshapes the measured binary")
            for item in VENUE_INPUTS:
                add("venue", item, "the court environment that produced the measurement")

        # The producing tool and the controls that qualify it.
        tool = _tool_document(document) if document is not None else None
        if tool is not None and isinstance(tool.get("path"), str):
            tool_path = tool["path"]
            if repo.exists(commit, tool_path):
                controls = [f"forensics/tools/tests/test_{Path(tool_path).stem}.py"]
                controls = [item for item in controls if repo.exists(commit, item)]
                add(
                    "verification_tool",
                    tool_path,
                    "field tool.path",
                    sha256=tool.get("sha256") if isinstance(tool.get("sha256"), str) else None,
                    version=tool.get("version"),
                    controls=controls,
                )

        # Instruments: the register entry and the harness it runs.
        instrument_ids: list[str] = []
        if isinstance(document, (dict, list)):
            for field_path, value in _walks(document):
                if field_path.split(".")[-1].split("[")[0] == "instrument_id" and isinstance(value, str):
                    instrument_ids.append(value)
        for instrument_id in sorted(set(instrument_ids)):
            entry = instruments.get(instrument_id)
            if entry is None:
                add("instrument", instrument_id, "field instrument_id; the register has no such entry")
                continue
            add(
                "instrument",
                instrument_id,
                "field instrument_id",
                register_entry_sha256=sha256_hex(canonical(entry)),
                paths=sorted(item for item in entry.get("paths", []) if isinstance(item, str)),
            )

        # Named paths, tools and upstream evidence.
        if document is not None:
            collected = [(field_path, item) for field_path, item in _collect_paths(document) if item != path]
            tools = [
                (field, item)
                for field, item in collected
                if item.startswith("forensics/tools/")
                and item.endswith((".py", ".sh"))
                and _reuses_evidence(field)
            ]
            upstreams = [
                (field, item)
                for field, item in collected
                if _reuses_evidence(field)
                and repo.exists(commit, item)
                and item.endswith(ARTEFACT_SUFFIXES)
                and item not in {t for _, t in tools}
            ]
            taken = {item for _, item in tools} | {item for _, item in upstreams}
            plain = [(field, item) for field, item in collected if item not in taken]
            for field_path, item in tools:
                add("verification_tool", item, f"field {field_path}", present=repo.exists(commit, item))
            for field_path, item in upstreams:
                add("upstream_evidence", item, f"field {field_path}")

            # Present citations may be coarsened: a prefix covers everything
            # beneath it, so the replacement can only invalidate more often.
            # Absent citations keep their exact text unless there are very many,
            # because their absence is the finding (ETP-0 `not_reconstructable`).
            # Citations are kept exact: a coarsened prefix over-invalidates (a
            # change to any sibling would look like non-impact when it is not),
            # and the registry's size is not a safety property.
            present_paths = sorted({item for _, item in plain if repo.exists(commit, item)})
            absent_paths = sorted({item for _, item in plain if not repo.exists(commit, item)})
            for item in present_paths:
                add("path", item, "field citation")
            for item in absent_paths:
                add("path", item, "field citation; not tracked in this tree", present=False)
            for key_path in ("inventory_path", "freeze", "digests_source", "previous_record", "ledger_record"):
                value = _dig(document, key_path)
                if isinstance(value, str) and value != path:
                    if repo.exists(commit, value):
                        add("upstream_evidence", value, f"field {key_path}")
                    else:
                        add("path", value, f"field {key_path}", present=False)

        # The claims that cite this artefact, and the paths they bind it to.
        citing = claims.get(path, [])
        derived.claim_ids = sorted({str(claim.get("id")) for claim in citing})
        for claim in citing:
            for location in claim.get("scope", {}).get("locations", []):
                if isinstance(location, str) and location != path:
                    add("path", location, f"claim {claim.get('id')} scope.locations")
            for dependency in claim.get("invalidation", {}).get("depends_on", []):
                if not isinstance(dependency, dict):
                    continue
                ident = dependency.get("id")
                if isinstance(ident, str) and ident != path:
                    kind = "path" if dependency.get("kind") in ("path", "authority") else dependency.get("kind")
                    if kind in DEPENDENCY_KINDS:
                        add(kind, ident, f"claim {claim.get('id')} invalidation.depends_on")

        # Traceability nodes bind an instrument and extra paths.
        node = trace.get(path)
        if node is not None:
            for item in node.get("paths", []) if isinstance(node.get("paths"), list) else []:
                if isinstance(item, str) and item != path:
                    add("path", item, "traceability node paths")
            if isinstance(node.get("instrument_id"), str):
                entry = instruments.get(node["instrument_id"])
                if entry is not None:
                    add(
                        "instrument",
                        node["instrument_id"],
                        "traceability node instrument_id",
                        register_entry_sha256=sha256_hex(canonical(entry)),
                        paths=sorted(item for item in entry.get("paths", []) if isinstance(item, str)),
                    )

        # Advisory prose citations: recorded, never authoritative.
        citations: list[dict[str, Any]] = []
        if text is not None and path.endswith((".md", ".txt")):
            for candidate in sorted(set(BACKTICK_PATH.findall(text)))[:200]:
                if candidate == path:
                    continue
                citations.append({"path": candidate, "present": repo.exists(commit, candidate)})

        source_flags = {
            "identity": derived.identity["kind"],
            "dependencies": "derived: structured fields, claims, traceability and instrument register",
            "citations": "derived: prose backticks, advisory only",
        }
        artefacts.append(
            {
                "path": path,
                "kind": derived.kind,
                "sha256": derived.sha256,
                "identity": derived.identity,
                "provenance": {
                    "last_commit": repo.last_commit(commit, path),
                    "basis": "git last-modified commit; provenance only, never an identity claim",
                },
                "depends_on": [deps[key] for key in sorted(deps)],
                "citations": citations,
                "claim_ids": derived.claim_ids,
                "derivation": source_flags,
            }
        )

    counts = {
        "artefacts": len(artefacts),
        "with_structured_identity": sum(1 for item in artefacts if item["identity"]["kind"] == "structured"),
        "with_heuristic_identity": sum(1 for item in artefacts if item["identity"]["kind"] == "heuristic-prose"),
        "without_identity": sum(1 for item in artefacts if item["identity"]["commit"] is None),
        "bound_to_a_tree": sum(1 for item in artefacts if item["identity"]["commit"] is not None),
        "dependencies": sum(len(item["depends_on"]) for item in artefacts),
        "citations": sum(len(item["citations"]) for item in artefacts),
        "excluded": len(excluded),
    }
    return {
        "schema": SCHEMA,
        "kind": "evidence-dependency-registry",
        "item": "ETP-T9",
        "recorded_at_commit": commit,
        "model": {
            "dependency_kinds": list(DEPENDENCY_KINDS),
            "build_inputs": list(BUILD_INPUTS),
            "venue_inputs": list(VENUE_INPUTS),
            "population_roots": list(POPULATION_ROOTS),
            "population_excluded_prefixes": list(POPULATION_EXCLUDED_PREFIXES),
            "population_excluded_segments": list(POPULATION_EXCLUDED_SEGMENTS),
            "artefact_suffixes": list(ARTEFACT_SUFFIXES),
            "max_artefact_bytes": MAX_ARTEFACT_BYTES,
            "preservation_procedures": list(PRESERVATION_PROCEDURES),
            "derived": [
                "own identity: shallowest structured field in the precedence list, every distinct value evaluated",
                "dependencies: structured path/tool/instrument fields, citing claims' scope and invalidation inputs, traceability evidence nodes",
                "build inputs: the crate build-input closure for every build-derived artefact",
                "advisory citations: prose backticks, never authoritative",
            ],
            "declared": [
                "population exclusions in `excluded`",
                "carry-forward declarations in `declarations`",
                "the preservation procedures implemented by forensics/tools/freshness.py",
            ],
        },
        "counts": counts,
        "excluded": excluded,
        "declarations": [],
        "artefacts": artefacts,
    }


# ---------------------------------------------------------------------------
# Identity triage
# ---------------------------------------------------------------------------


def _triage_declared(repo: Git, head: str, document: Any) -> list[dict[str, str]]:
    """Own-identity declarations whose commit resolves as an ancestor.

    Only exact field paths in `TRIAGE_IDENTITY_FIELDS` are read. A value that
    does not resolve, or resolves outside this tree's history, is not an identity
    of this artefact: it is reported by the caller as uncertifiable, never
    silently dropped.
    """
    found: list[dict[str, str]] = []
    if not isinstance(document, (dict, list)):
        return found
    for field_path, value in _walks(document):
        if field_path not in TRIAGE_IDENTITY_FIELDS:
            continue
        if not isinstance(value, str) or not HEX.match(value.strip()):
            continue
        commit = repo.resolve(value.strip())
        if commit is None or not repo.is_ancestor(commit, head):
            continue
        found.append({"field": field_path, "value": value.strip(), "commit": commit})
    return found


def _triage_qualifier(document: Any) -> str | None:
    """Why a declared tree is disqualified by the artefact's own fields.

    A declaration of a commit is not a declaration of a tree when the same
    record says the measured worktree was dirty and does not certify the
    build-relevant paths clean. `build_relevant_clean: true` is accepted as that
    certification, because it is the field the campaign records for exactly that
    purpose.
    """
    if not isinstance(document, dict):
        return None
    for field_path, value in _walks(document):
        leaf = field_path.split(".")[-1].split("[")[0]
        if leaf == "build_relevant_clean" and value is False:
            return f"{field_path} is false"
        if leaf == "build_relevant_status" and isinstance(value, str) and value.strip():
            return f"{field_path} records a modified build-relevant path"
    for field_path, value in _walks(document):
        if field_path.split(".")[-1].split("[")[0] != "worktree":
            continue
        if not isinstance(value, str) or "dirty" not in value.lower():
            continue
        parent = ".".join(field_path.rsplit(".", 1)[:-1])
        certified = any(
            other.split(".")[-1] == "build_relevant_clean" and flag is True
            for other, flag in _walks(document)
            if other.rsplit(".", 1)[0] == parent
        )
        if not certified:
            return f"{field_path} records a dirty worktree"
    return None


def _triage_freeze(repo: Git, commit: str, document: Any) -> tuple[dict[str, str] | None, str | None]:
    """Follow a digest-bound `freeze` field to the tree its record declares.

    The derivation is mechanical and checkable: the named record must be tracked
    at `commit`, its blob digest must equal the recorded `freeze_sha256`, and it
    must declare exactly one own identity. Returns (identity, failure reason).
    """
    if not isinstance(document, dict):
        return None, None
    target = document.get("freeze")
    recorded = document.get("freeze_sha256")
    if not isinstance(target, str) or not target:
        return None, None
    if not isinstance(recorded, str) or not re.fullmatch(r"[0-9a-f]{64}", recorded):
        return None, f"the freeze field names {target!r} without a recorded digest"
    if not repo.exists(commit, target):
        return None, f"the freeze record {target!r} is not tracked at {commit[:12]}"
    digest = repo.digest(commit, target)
    if digest != recorded:
        return None, f"the freeze record {target!r} is {digest}, not the recorded {recorded}"
    text = repo.text(commit, target)
    try:
        record = json.loads(text) if text is not None else None
    except json.JSONDecodeError:
        record = None
    if record is None:
        return None, f"the freeze record {target!r} is not readable JSON"
    declared = _triage_declared(repo, commit, record)
    commits = sorted({item["commit"] for item in declared})
    if len(commits) != 1:
        return None, (
            f"the freeze record {target!r} declares {len(commits)} distinct tree(s), not one"
            if commits
            else f"the freeze record {target!r} declares no tree"
        )
    return {
        "field": f"freeze:{target}",
        "commit": commits[0],
        "all": sorted({item["field"] for item in declared}),
    }, None


def _triage_superseded(document: Any, text: str | None) -> bool:
    if isinstance(document, dict) and document.get("superseded") is True:
        return True
    if text:
        return bool(TRIAGE_SUPERSEDED.search("\n".join(text.splitlines()[:40])))
    return False


def _triage_candidate_name(document: Any) -> str | None:
    if not isinstance(document, (dict, list)):
        return None
    for field_path, value in _walks(document):
        if field_path.split(".")[-1].split("[")[0] != "candidate_identity":
            continue
        if isinstance(value, str) and TRIAGE_CANDIDATE_NAME.match(value.strip()):
            return value.strip()
    return None


def _triage_prose_frozen_at(repo: Git, head: str, text: str | None) -> str | None:
    if not text:
        return None
    prose = "\n".join(text.splitlines()[:80])
    matches = [
        repo.resolve(item)
        for item in TRIAGE_FROZEN_AT.findall(re.sub(r"[>`]", " ", prose))
    ]
    for commit in matches:
        if commit is not None and repo.is_ancestor(commit, head):
            return commit
    return None


def _triage_record(path: str) -> dict[str, Any]:
    return {
        "path": path,
        "class": "",
        "rule": "",
        "field": None,
        "identity": None,
        "ambiguous": False,
        "heuristic": False,
        "cause": None,
        "cause_name": None,
        "reason": "",
        "certifiable_if": None,
    }


def _uncertifiable(record: dict[str, Any], code: str, detail: str = "") -> dict[str, Any]:
    name, certifiable = TRIAGE_CAUSES[code]
    record["class"] = "UNCERTIFIABLE"
    record["rule"] = code
    record["cause"] = code
    record["cause_name"] = name
    record["reason"] = detail or name
    record["certifiable_if"] = certifiable
    return record


def triage_one(repo: Git, commit: str, path: str) -> dict[str, Any]:
    """Classify one artefact that the registry records without an identity."""
    record = _triage_record(path)
    text = repo.text(commit, path)
    document: Any = None
    if path.endswith(".json") and text is not None:
        try:
            document = json.loads(text)
        except json.JSONDecodeError:
            document = None
    declared = _triage_declared(repo, commit, document)
    qualifier = _triage_qualifier(document)
    freeze, freeze_failure = _triage_freeze(repo, commit, document)
    superseded = _triage_superseded(document, text)

    if declared:
        commits = sorted({item["commit"] for item in declared})
        if qualifier:
            return _uncertifiable(record, "U7", f"{qualifier}; the declared tree is not the tree measured")
        # Several declared trees are recorded. The earliest is adopted because
        # evaluating a wider range can only over-invalidate; the others stay
        # visible in `identity.all`.
        chosen = sorted(commits, key=lambda item: (repo.commit_time(item), item))[0]
        record["identity"] = {
            "commit": chosen,
            "all": [dict(item) for item in sorted(declared, key=lambda item: (item["field"], item["commit"]))],
            "source": "declared",
        }
        record["field"] = ",".join(sorted({item["field"] for item in declared}))
        record["ambiguous"] = len(commits) > 1
        record["rule"] = "declared-identity-field"
        record["reason"] = (
            "the artefact names the tree it was taken at in "
            + record["field"]
            + (" (superseded: read as history)" if superseded else "")
        )
        record["class"] = "HISTORICAL" if superseded else "DECLARED"
        return record

    if freeze is not None:
        record["identity"] = {
            "commit": freeze["commit"],
            "all": [{"field": freeze["field"], "commit": freeze["commit"], "declared": freeze["all"]}],
            "source": "derived",
        }
        record["field"] = freeze["field"]
        record["rule"] = "digest-bound-freeze-record"
        record["reason"] = (
            "the freeze field names "
            + freeze["field"].split(":", 1)[1]
            + ", whose recorded digest matches and which declares one tree"
        )
        record["class"] = "HISTORICAL" if superseded else "DERIVED"
        return record

    if path.endswith(".md"):
        frozen_at = _triage_prose_frozen_at(repo, commit, text)
        if frozen_at is not None:
            record["identity"] = {"commit": frozen_at, "all": [], "source": "declared"}
            record["field"] = "prose:frozen at"
            record["rule"] = "declared-prose-frozen-at"
            record["reason"] = "the artefact states that it is a frozen record at a named commit"
            record["class"] = "HISTORICAL"
            return record

    if path.startswith(TRIAGE_INPUT_PREFIXES) and path.endswith(TRIAGE_INPUT_SUFFIXES) or path.endswith(
        ".schema.json"
    ):
        record["identity"] = {"commit": commit, "all": [], "source": "derived"}
        record["rule"] = "tracked-input-at-head"
        record["heuristic"] = True
        record["reason"] = (
            "a tracked harness input or schema is read from the tree that contains it; the identity is the "
            "tree the registry was recorded at, and a later change to its bytes is FR_EVIDENCE_SUPERSEDED"
        )
        record["class"] = "DERIVED"
        return record

    candidate = _triage_candidate_name(document)
    if candidate:
        return _uncertifiable(
            record,
            "U2",
            f"the only declared identity is the candidate name {candidate!r}, and the repository binds that "
            "name to more than one tree, so it does not determine a commit",
        )

    if TRIAGE_BUILD_OUTPUT.search(path):
        return _uncertifiable(record, "U6", "a build output carries an embedded binary, not the tree that produced it")

    root_hash = document.get("source_root_hash") if isinstance(document, dict) else None
    root_rule = document.get("source_root_hash_rule") if isinstance(document, dict) else None
    if (root_hash is not None and root_rule is None) or freeze_failure:
        detail = "; ".join(
            item
            for item in (
                "source_root_hash is recorded with source_root_hash_rule null"
                if root_hash is not None and root_rule is None
                else None,
                freeze_failure,
            )
            if item
        )
        return _uncertifiable(record, "U5", detail)

    count = repo.commits_touching(commit, path)
    if count == 1:
        introduced = repo.introducing_commit(commit, path)
        if introduced is not None:
            record["identity"] = {"commit": introduced, "all": [], "source": "introduced"}
            record["rule"] = "introduced-at-single-commit"
            record["reason"] = (
                "the artefact was introduced in one commit and never modified, so its bytes are exactly the "
                "bytes at that commit; it is a record of that moment, not of the current tree"
            )
            record["class"] = "HISTORICAL"
            return record

    return _uncertifiable(
        record,
        "U1",
        f"the artefact was changed in {count} commits and names no tree, so no single moment explains its "
        "current bytes",
    )


def triage(repo: Git, registry: dict[str, Any], commit: str) -> dict[str, Any]:
    """Derive the identity triage for every artefact the registry leaves unbound."""
    paths = [
        str(item.get("path"))
        for item in registry.get("artefacts", [])
        if isinstance(item, dict) and (item.get("identity") or {}).get("commit") is None
    ]
    records = [triage_one(repo, commit, path) for path in sorted(paths)]
    counts = {name: 0 for name in TRIAGE_CLASSES}
    causes: dict[str, int] = {}
    for record in records:
        counts[record["class"]] = counts.get(record["class"], 0) + 1
        if record["class"] == "UNCERTIFIABLE":
            causes[record["cause"]] = causes.get(record["cause"], 0) + 1
    counts["total"] = len(records)
    return {
        "schema": TRIAGE_SCHEMA,
        "kind": "evidence-identity-triage",
        "item": "ETP-T9",
        "registry": "evidence/etp-t9/DEPENDENCIES.json",
        "registry_recorded_at_commit": registry.get("recorded_at_commit"),
        "recorded_at_commit": commit,
        "classes": list(TRIAGE_CLASSES),
        "causes": {code: {"name": name, "certifiable_if": certifiable} for code, (name, certifiable) in TRIAGE_CAUSES.items()},
        "identity_fields": list(TRIAGE_IDENTITY_FIELDS),
        "input_rule": {
            "prefixes": list(TRIAGE_INPUT_PREFIXES),
            "suffixes": list(TRIAGE_INPUT_SUFFIXES),
            "note": "a tracked harness input or schema is read from the tree that contains it; this rule is definitional, not a measurement identity",
        },
        "counts": {**counts, "uncertifiable_by_cause": dict(sorted(causes.items()))},
        "artefacts": records,
    }


def triage_index(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(item.get("path")): item
        for item in document.get("artefacts", [])
        if isinstance(item, dict) and isinstance(item.get("path"), str)
    }


def validate_triage(
    document: dict[str, Any], registry: dict[str, Any], repo: Git | None = None
) -> list[Refusal]:
    """Structural validation of the triage record against the registry it binds.

    The triage must cover exactly the artefacts the registry leaves unbound. A
    missing or extra record is stale, not merely a note: a triage that silently
    stops covering an artefact would leave that artefact unclassified.
    """
    findings: list[Refusal] = []
    if not isinstance(document, dict) or document.get("schema") != TRIAGE_SCHEMA:
        return [Refusal("FR_TRIAGE_SCHEMA", "$", f"schema must be {TRIAGE_SCHEMA!r}")]
    if document.get("registry_recorded_at_commit") != registry.get("recorded_at_commit"):
        findings.append(
            Refusal(
                "FR_TRIAGE_STALE",
                "$",
                f"the triage binds registry {document.get('registry_recorded_at_commit')!r}, the registry records "
                f"{registry.get('recorded_at_commit')!r}",
            )
        )
    records = [item for item in document.get("artefacts", []) if isinstance(item, dict)]
    expected = {
        str(item.get("path"))
        for item in registry.get("artefacts", [])
        if isinstance(item, dict) and (item.get("identity") or {}).get("commit") is None
    }
    seen: set[str] = set()
    for item in records:
        path = item.get("path")
        if not isinstance(path, str) or not path:
            findings.append(Refusal("FR_TRIAGE_SCHEMA", "$.artefacts", "a triage record must name a path"))
            continue
        if path in seen:
            findings.append(Refusal("FR_TRIAGE_SCHEMA", path, "the triage records this path twice"))
        seen.add(path)
        cls = item.get("class")
        if cls not in TRIAGE_CLASSES:
            findings.append(Refusal("FR_TRIAGE_SCHEMA", path, f"class {cls!r} is not one of {list(TRIAGE_CLASSES)}"))
            continue
        if cls == "UNCERTIFIABLE":
            cause = item.get("cause")
            if cause not in TRIAGE_CAUSES:
                findings.append(
                    Refusal("FR_TRIAGE_SCHEMA", path, f"cause {cause!r} is not one of {list(TRIAGE_CAUSES)}")
                )
            if not isinstance(item.get("reason"), str) or not item["reason"].strip():
                findings.append(Refusal("FR_TRIAGE_SCHEMA", path, "an uncertifiable record must state its reason"))
            if item.get("identity") is not None:
                findings.append(
                    Refusal("FR_TRIAGE_SCHEMA", path, "an uncertifiable record may not carry an identity")
                )
            continue
        identity = item.get("identity")
        commit = identity.get("commit") if isinstance(identity, dict) else None
        if not isinstance(commit, str) or not HEX.match(commit):
            findings.append(Refusal("FR_TRIAGE_SCHEMA", path, f"{cls} must name an identity commit"))
        elif repo is not None and repo.resolve(commit) is None:
            findings.append(Refusal("FR_TRIAGE_SCHEMA", path, f"identity commit {commit!r} does not resolve"))
        if not isinstance(item.get("rule"), str) or not item["rule"].strip():
            findings.append(Refusal("FR_TRIAGE_SCHEMA", path, f"{cls} must name the rule it was derived by"))
    missing = sorted(expected - seen)
    extra = sorted(seen - expected)
    if missing:
        findings.append(
            Refusal("FR_TRIAGE_STALE", missing[0], f"{len(missing)} unbound artefact(s) are not triaged: {', '.join(missing[:8])}")
        )
    if extra:
        findings.append(
            Refusal("FR_TRIAGE_STALE", extra[0], f"{len(extra)} triaged artefact(s) are not unbound in the registry: {', '.join(extra[:8])}")
        )
    counts = {name: 0 for name in TRIAGE_CLASSES}
    for item in records:
        if item.get("class") in counts:
            counts[item["class"]] += 1
    reported = document.get("counts") or {}
    for name, value in counts.items():
        if reported.get(name) != value:
            findings.append(
                Refusal("FR_TRIAGE_SCHEMA", "$", f"counts.{name} is {reported.get(name)!r}, the records give {value}")
            )
    return sorted(set(findings), key=lambda item: (item.rule, item.where, item.detail))


def triaged_registry(registry: dict[str, Any], index: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """The registry with triage identities and annotations applied, copied.

    The caller's registry is never mutated: the committed registry stays the
    derivation record, and the triage stays the declared overlay on top of it.
    """
    document = json.loads(json.dumps(registry))
    for artefact in document.get("artefacts", []):
        if not isinstance(artefact, dict):
            continue
        record = index.get(str(artefact.get("path")))
        if record is None:
            continue
        cls = record.get("class")
        identity = record.get("identity") if isinstance(record.get("identity"), dict) else None
        current = artefact.get("identity") if isinstance(artefact.get("identity"), dict) else {}
        if cls in ("DECLARED", "DERIVED", "HISTORICAL") and identity and current.get("commit") is None:
            artefact["identity"] = {
                "commit": identity.get("commit"),
                "kind": "triage-" + str(cls).lower(),
                "ambiguous": bool(record.get("ambiguous")),
                "all": identity.get("all", []),
                "upstream": [],
                "note": "identity triage: " + str(record.get("rule")),
            }
        artefact["triage"] = {
            "class": cls,
            "rule": record.get("rule"),
            "cause": record.get("cause"),
            "reason": record.get("reason"),
        }
    return document


def _triage_history_cited(index: dict[str, dict[str, Any]], claims_doc: dict[str, Any]) -> list[dict[str, str]]:
    """Current claims that cite an artefact the triage declares historical."""
    findings: list[dict[str, str]] = []
    for claim in claims_doc.get("claims", []):
        if not isinstance(claim, dict):
            continue
        if claim.get("verdict", {}).get("state") in NON_CURRENT_VERDICTS:
            continue
        for entry in claim.get("evidence", []):
            if not isinstance(entry, dict):
                continue
            record = index.get(str(entry.get("path")))
            if record is not None and record.get("class") == "HISTORICAL":
                findings.append(
                    {
                        "claim": str(claim.get("id")),
                        "path": str(entry.get("path")),
                        "rule": str(record.get("rule")),
                        "identity": str((record.get("identity") or {}).get("commit")),
                    }
                )
    return sorted(findings, key=lambda item: (item["claim"], item["path"]))


# ---------------------------------------------------------------------------
# The invalidation engine
# ---------------------------------------------------------------------------


@dataclass
class Outcome:
    path: str
    verdict: str
    rule: str | None
    dependency: dict[str, Any] | None
    argument: str

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "path": self.path,
            "verdict": self.verdict,
            "argument": self.argument,
        }
        if self.rule:
            payload["rule"] = self.rule
        if self.dependency:
            payload["dependency"] = self.dependency
        return payload


def _preservation_check(
    repo: Git,
    declaration: dict[str, Any],
    base: str | None,
    head: str,
    changed: list[dict[str, str]],
    dependencies: list[dict[str, Any]],
) -> Refusal | None:
    """Execute a preservation argument. Returns a refusal, or None on success.

    A declaration has the shape::

        {"kind": "PRESERVATION", "argument": "...", "procedure": "...",
         "concerned_paths": [...], "assumes_unchanged": [...],
         "evidence": [{"path": ..., "sha256": ...}]}

    Every field is required. `concerned_paths` and `assumes_unchanged` name
    dependencies of the artefact; both are checked against the change set, so an
    argument that assumes away a file the change actually touched is refused.
    """
    where = declaration.get("artefact", "")
    procedure = declaration.get("procedure")
    if base is None:
        return Refusal(
            "FR_PRESERVATION_UNDECIDABLE",
            where,
            "a bare path list names no base identity, so no preservation procedure can be executed",
        )
    if not isinstance(procedure, str) or procedure not in PRESERVATION_PROCEDURES:
        return Refusal(
            "FR_PRESERVATION_UNDECIDABLE",
            where,
            f"procedure {procedure!r} is not one of {list(PRESERVATION_PROCEDURES)}",
        )
    argument = declaration.get("argument")
    if not isinstance(argument, str) or len(argument.split()) < 6:
        return Refusal("FR_PRESERVATION_INCOMPLETE", where, "the argument is absent or a bare assertion")
    concerned = declaration.get("concerned_paths")
    assumed = declaration.get("assumes_unchanged")
    evidence = declaration.get("evidence")
    if not isinstance(concerned, list) or not concerned or not isinstance(assumed, list) or not assumed:
        return Refusal(
            "FR_PRESERVATION_INCOMPLETE",
            where,
            "concerned_paths and assumes_unchanged must both name at least one dependency",
        )
    if not isinstance(evidence, list) or not evidence:
        return Refusal("FR_PRESERVATION_UNEVIDENCED", where, "the argument cites no evidence of its own")
    for item in evidence:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            return Refusal("FR_PRESERVATION_UNEVIDENCED", where, "an evidence entry has no path")
        path = item["path"]
        recorded = item.get("sha256")
        actual = repo.digest(head, path)
        if actual is None:
            return Refusal("FR_PRESERVATION_UNEVIDENCED", where, f"cited evidence {path!r} is absent at {head[:12]}")
        if not isinstance(recorded, str) or recorded != actual:
            return Refusal(
                "FR_PRESERVATION_UNEVIDENCED",
                where,
                f"cited evidence {path!r} records {recorded!r} but is {actual} at {head[:12]}",
            )

    declared_paths = {
        item.get("id")
        for item in dependencies
        if item.get("kind") in DEPENDENCY_KINDS and isinstance(item.get("id"), str)
    }
    dependency_candidates: list[str] = []
    for item in dependencies:
        for key in ("id", "paths", "controls"):
            value = item.get(key)
            if isinstance(value, str):
                dependency_candidates.append(value)
            elif isinstance(value, list):
                dependency_candidates.extend(entry for entry in value if isinstance(entry, str))
    declared_paths.update(dependency_candidates)
    for item in list(concerned) + list(assumed):
        if not isinstance(item, str):
            return Refusal("FR_PRESERVATION_INCOMPLETE", where, "every path in the argument must be a string")
        if not any(path_within(item, dep) or path_within(dep, item) for dep in declared_paths):
            return Refusal(
                "FR_PRESERVATION_INCOMPLETE",
                where,
                f"{item!r} is not a dependency of this artefact, so the argument is about something else",
            )

    touched = [row["path"] for row in changed]
    for item in assumed:
        for path in touched:
            if path_within(item, path) or path_within(path, item):
                return Refusal(
                    "FR_PRESERVATION_TOUCHED",
                    where,
                    f"the argument assumes {item!r} unchanged, but the change set touches {path!r}",
                )

    # A preservation argument is about this artefact's own inputs. A touched
    # dependency that the argument does not mention is unaccounted for, and an
    # unaccounted change is not non-impact: the procedures below prove a
    # property of the paths they are given, never of the paths they omit.
    dependency_candidates = sorted(set(dependency_candidates))

    def covers(item: str, path: str) -> bool:
        return path_within(item, path) or path_within(path, item)

    touched_dependencies = [
        path for path in touched if any(covers(dependency, path) for dependency in dependency_candidates)
    ]

    def named_in(entries: list[Any], path: str) -> bool:
        return any(isinstance(entry, str) and covers(entry, path) for entry in entries)

    if procedure == "comment_only":
        uncovered = [path for path in touched_dependencies if not named_in(concerned, path)]
        if uncovered:
            return Refusal(
                "FR_PRESERVATION_INCOMPLETE",
                where,
                f"the argument does not account for touched dependency {uncovered[0]!r}",
            )
        admitted = [item for item in concerned if Path(item).suffix in LINE_COMMENT]
        if not admitted:
            return Refusal(
                "FR_PRESERVATION_UNDECIDABLE",
                where,
                "comment_only admits only " + ", ".join(sorted(LINE_COMMENT)) + " under its stated preconditions",
            )
        for item in concerned:
            if not any(covers(item, path) for path in touched_dependencies):
                continue
            if Path(item).suffix not in LINE_COMMENT:
                return Refusal(
                    "FR_PRESERVATION_UNDECIDABLE",
                    where,
                    f"{item!r} is a touched concern outside " + ", ".join(sorted(LINE_COMMENT)),
                )
        for item in admitted:
            marker = LINE_COMMENT[Path(item).suffix]
            for revision in (base, head):
                text = repo.text(revision, item)
                if text is None:
                    return Refusal(
                        "FR_PRESERVATION_UNDECIDABLE", where, f"{item!r} is absent at {revision[:12]}"
                    )
                if "/*" in text or re.search(r"(?<![A-Za-z0-9_])b?r#*\"", text):
                    return Refusal(
                        "FR_PRESERVATION_UNDECIDABLE",
                        where,
                        f"{item!r} at {revision[:12]} contains a block comment or a raw string; a line-comment argument cannot be proven there",
                    )
            lines = repo.diff_hunks(base, head, item)
            if lines is None:
                return Refusal("FR_PRESERVATION_UNDECIDABLE", where, f"the diff for {item!r} could not be read")
            for line in lines:
                stripped = line.lstrip()
                if stripped and not stripped.startswith(marker):
                    return Refusal(
                        "FR_PRESERVATION_FAILED",
                        where,
                        f"{item!r} changes line {stripped[:60]!r}, which is not a line comment",
                    )
        return None

    if procedure == "narrowed_scope_untouched":
        for item in concerned:
            for path in touched:
                if path_within(item, path) or path_within(path, item):
                    return Refusal(
                        "FR_PRESERVATION_TOUCHED",
                        where,
                        f"the narrowed concern {item!r} is touched by {path!r}",
                    )
        return None

    if procedure == "instrument_register_unchanged":
        register = "evidence/etp3/instruments.json"
        uncovered = [
            path for path in touched_dependencies if path != register and not covers(register, path)
        ]
        if uncovered:
            return Refusal(
                "FR_PRESERVATION_INCOMPLETE",
                where,
                f"the register procedure does not account for touched dependency {uncovered[0]!r}",
            )
        if repo.digest(base, "evidence/etp3/instruments.json") != repo.digest(head, "evidence/etp3/instruments.json"):
            return Refusal(
                "FR_PRESERVATION_FAILED",
                where,
                "the instrument register differs between the two identities",
            )
        return None

    if procedure == "blob_identical":
        for item in assumed:
            if repo.digest(base, item) != repo.digest(head, item):
                return Refusal("FR_PRESERVATION_FAILED", where, f"{item!r} differs between the two identities")
        return None

    return Refusal("FR_PRESERVATION_UNDECIDABLE", where, f"procedure {procedure!r} is not implemented")


def _dependency_moved(
    repo: Git,
    dependency: dict[str, Any],
    changed: list[dict[str, str]],
    base: str,
    head: str,
) -> tuple[bool, dict[str, str] | None, str | None]:
    """Return (moved, matching change, unresolved reason)."""
    kind = dependency.get("kind")
    ident = dependency.get("id")
    if kind not in DEPENDENCY_KINDS or not isinstance(ident, str):
        return False, None, f"dependency kind {kind!r} or id {ident!r} is not in the model"

    candidates: list[str] = [ident]
    for extra in ("paths", "controls"):
        value = dependency.get(extra)
        if isinstance(value, list):
            candidates.extend(item for item in value if isinstance(item, str))

    # A matched path is an established change, whatever the recorded digest is:
    # the identity question is asked only when no path moved.
    for row in changed:
        for candidate in candidates:
            if path_within(candidate, row["path"]) or path_within(row["path"], candidate):
                return True, {"path": row["path"], "status": row["status"]}, None

    # A dependency that names a path the tree does not contain cannot be
    # evaluated, and that is not non-impact: it is the ETP-0
    # `evidence_not_reconstructable` class, reported mechanically.
    if dependency.get("present") is False:
        return False, None, f"dependency {ident!r} is not tracked in this tree"

    if kind == "verification_tool":
        recorded = dependency.get("sha256")
        if not isinstance(recorded, str) or recorded == "UNKNOWN" or not re.fullmatch(r"[0-9a-f]{64}", recorded):
            return False, None, f"tool {ident!r} is recorded without a usable digest"

    if kind == "instrument" and not isinstance(dependency.get("register_entry_sha256"), str):
        return False, None, f"instrument {ident!r} has no recorded register entry digest"

    if kind == "instrument":
        register = "evidence/etp3/instruments.json"
        for row in changed:
            if row["path"] == register:
                # The register moved; only the entry's own bytes decide non-impact.
                recorded = dependency.get("register_entry_sha256")
                if not isinstance(recorded, str):
                    return True, {"path": register, "status": row["status"]}, None
                entries = _instrument_entries(repo, head)
                entry = entries.get(str(ident))
                if entry is None or sha256_hex(canonical(entry)) != recorded:
                    return True, {"path": register, "status": row["status"]}, None
    return False, None, None


def _postdates(repo: Git, commit: Any, head: str) -> bool:
    """True when `commit` is `head` or a descendant of it.

    Evidence taken at or after the change's head already incorporates that
    change, so the change cannot invalidate it. An unresolvable or unrelated
    identity is *not* treated as incorporating: non-impact is never inferred,
    so it falls through to the conservative path.
    """
    if not isinstance(commit, str):
        return False
    resolved = repo.resolve(commit)
    if resolved is None:
        return False
    return repo.is_ancestor(head, resolved)


def evaluate(
    repo: Git,
    registry: dict[str, Any],
    claims_doc: dict[str, Any],
    changed: list[dict[str, str]],
    base: str | None,
    head: str,
    full_records: bool = False,
    triage: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Evaluate a change set against the registry.

    Every artefact gets a verdict and an argument. `UNAFFECTED` carries the
    argument that establishes non-impact: every dependency was evaluated, none
    matched, and every dependency's identity resolved. Anything else is reported
    by name, so a dependent can be inspected rather than assumed.

    `triage` is the identity-triage index. It is an overlay, not a derivation:
    it supplies the identity the committed registry could not read, excludes a
    historical artefact from current claims, and makes an uncertifiable one
    `UNRESOLVED` rather than `UNAFFECTED`.
    """
    if triage:
        registry = triaged_registry(registry, triage)
    declarations = {
        item["artefact"]: item
        for item in registry.get("declarations", [])
        if isinstance(item, dict) and isinstance(item.get("artefact"), str)
    }
    artefacts = [item for item in registry.get("artefacts", []) if isinstance(item, dict)]
    by_path = {item.get("path"): item for item in artefacts}

    direct: dict[str, tuple[dict[str, Any], dict[str, str]]] = {}
    unresolved: dict[str, str] = {}
    postdating: set[str] = set()
    for artefact in artefacts:
        path = artefact.get("path")
        if not isinstance(path, str):
            continue
        if _postdates(repo, artefact.get("identity", {}).get("commit"), head):
            postdating.add(path)
            continue
        for dependency in artefact.get("depends_on", []):
            if not isinstance(dependency, dict) or dependency.get("kind") == "upstream_evidence":
                continue
            moved, match, reason = _dependency_moved(repo, dependency, changed, base, head)
            if moved and match is not None:
                direct[path] = (dependency, match)
                break
            if reason is not None:
                unresolved.setdefault(path, reason)

    # An upstream artefact that is invalidated, superseded or unresolved
    # invalidates every artefact that re-uses it. Cycles are refused, not looped.
    dependents: dict[str, list[str]] = {}
    for artefact in artefacts:
        path = artefact.get("path")
        for dependency in artefact.get("depends_on", []):
            if isinstance(dependency, dict) and dependency.get("kind") == "upstream_evidence":
                dependents.setdefault(str(dependency.get("id")), []).append(str(path))

    # A re-used artefact that cannot be shown current is not current, even when
    # this change set did not itself invalidate it. An upstream that is absent,
    # unmodelled or unresolved makes the dependent *unresolved*: reporting it
    # UNAFFECTED would infer non-impact from a dependency that was never
    # evaluated, which is the one inference this model forbids. Unresolved is
    # pre-existing, so it is reported separately and does not gate a change set.
    not_current: dict[str, str] = {}
    for node in sorted(dependents):
        source = by_path.get(node)
        if source is None:
            not_current[node] = f"upstream evidence {node!r} is not modelled by the registry"
            continue
        if not repo.exists(head, node):
            not_current[node] = f"upstream evidence {node!r} is absent at {head[:12]}"
        elif node in declarations and declarations[node].get("kind") == "HISTORY":
            # A re-used artefact declared explicit history is not current
            # evidence, whatever its bytes say. Excluding it from claims while
            # letting another artefact re-use it would leave the exclusion half
            # enforced.
            not_current[node] = f"upstream evidence {node!r} is declared explicit history"
        elif node in postdating:
            continue
        elif node in unresolved:
            not_current[node] = f"upstream evidence {node!r} is unresolved: {unresolved[node]}"
        elif not source.get("depends_on") and source.get("identity", {}).get("commit") is None:
            not_current[node] = f"upstream evidence {node!r} models no dependency and names no identity"
    for upstream, upstream_dependents in sorted(dependents.items()):
        for dependent in sorted(upstream_dependents):
            if dependent in direct or dependent in unresolved:
                continue
            if upstream in not_current:
                unresolved[dependent] = not_current[upstream]

    invalidated = dict(direct)
    frontier = sorted(invalidated)
    while frontier:
        node = frontier.pop()
        for dependent in sorted(dependents.get(node, [])):
            if dependent in invalidated:
                continue
            source = by_path.get(node, {})
            dependency = {"kind": "upstream_evidence", "id": node}
            invalidated[dependent] = (
                dependency,
                {"path": node, "status": "upstream", "via": source.get("path", node)},
            )
            frontier.append(dependent)
    for path, reason in unresolved.items():
        invalidated.setdefault(
            path,
            ({"kind": "unresolved", "id": path}, {"path": path, "status": "unresolved", "reason": reason}),
        )

    outcomes: list[Outcome] = []
    for artefact in artefacts:
        path = str(artefact.get("path"))
        declaration = declarations.get(path)
        if declaration is not None and declaration.get("kind") == "HISTORY":
            outcomes.append(
                Outcome(
                    path,
                    "HISTORY",
                    None,
                    None,
                    "declared explicit history at "
                    + str(declaration.get("identity", {}).get("commit"))
                    + "; excluded from current claims",
                )
            )
            continue
        triage_record = artefact.get("triage") or {}
        if triage_record.get("class") == "HISTORICAL":
            outcomes.append(
                Outcome(
                    path,
                    "HISTORY",
                    None,
                    None,
                    "identity triage "
                    + str(triage_record.get("rule"))
                    + " at "
                    + str((artefact.get("identity") or {}).get("commit"))
                    + "; excluded from current claims",
                )
            )
            continue
        if path in invalidated:
            dependency, match = invalidated[path]
            if declaration is not None and declaration.get("kind") == "PRESERVATION":
                refusal = _preservation_check(
                    repo, {**declaration, "artefact": path}, base, head, changed, artefact.get("depends_on", [])
                )
                if refusal is None:
                    outcomes.append(
                        Outcome(
                            path,
                            "CARRIED_FORWARD",
                            None,
                            dependency,
                            "preservation argument verified by procedure "
                            + str(declaration.get("procedure"))
                            + " against "
                            + str(match),
                        )
                    )
                else:
                    outcomes.append(Outcome(path, "INVALIDATED", refusal.rule, dependency, refusal.detail))
                continue
            if dependency.get("kind") == "unresolved":
                outcomes.append(
                    Outcome(
                        path,
                        "UNRESOLVED",
                        "FR_DEPENDENCY_UNRESOLVED",
                        dependency,
                        str(match.get("reason") or match.get("status")),
                    )
                )
            elif dependency.get("kind") == "upstream_evidence":
                outcomes.append(
                    Outcome(
                        path,
                        "INVALIDATED",
                        "FR_EVIDENCE_TRANSITIVE",
                        dependency,
                        "re-uses " + str(dependency.get("id")) + ", which is not current",
                    )
                )
            else:
                rule = "FR_EVIDENCE_INVALIDATED"
                detail = f"{dependency.get('kind')} {dependency.get('id')!r} moved at {match.get('path')!r}"
                if direct.get(path, (None, None))[0] is None:
                    rule, detail = "FR_DEPENDENCY_UNRESOLVED", str(unresolved.get(path))
                outcomes.append(Outcome(path, "INVALIDATED", rule, dependency, detail))
            continue
        if triage_record.get("class") == "UNCERTIFIABLE":
            outcomes.append(
                Outcome(
                    path,
                    "UNRESOLVED",
                    "FR_IDENTITY_UNCERTIFIABLE",
                    {"kind": "uncertifiable", "id": path, "cause": triage_record.get("cause")},
                    "identity triage: "
                    + str(triage_record.get("cause"))
                    + "; "
                    + str(triage_record.get("reason")),
                )
            )
            continue
        if not artefact.get("depends_on") and artefact.get("identity", {}).get("commit") is None:
            outcomes.append(
                Outcome(
                    path,
                    "UNMODELLED",
                    "FR_NO_MODELLED_DEPENDENCY",
                    None,
                    "the registry models no dependency and the artefact names no identity; "
                    "non-impact cannot be established, so it is not reported as unaffected",
                )
            )
            continue
        if path in postdating:
            outcomes.append(
                Outcome(
                    path,
                    "UNAFFECTED",
                    None,
                    None,
                    "the artefact's identity is at or after the change set's head, so the change is already "
                    "part of what it measured",
                )
            )
            continue
        outcomes.append(
            Outcome(
                path,
                "UNAFFECTED",
                None,
                None,
                f"all {len(artefact.get('depends_on', []))} dependencies evaluated; none matches the change set "
                "and every identity resolved",
            )
        )

    # Claims: the algebra decides which become unsupported. Only a reason caused
    # by *this* change set gates; a pre-existing gap (an artefact that never
    # named an identity, a file that was already absent) is reported as
    # `preexisting` and is the tree sweep's business, not this change set's.
    clock = claim_algebra()
    claims = [claim for claim in claims_doc.get("claims", []) if isinstance(claim, dict)]
    # A claim whose identity is at or after the change's head already
    # incorporates the change; the algebra is asked only about the rest.
    candidates = [
        claim
        for claim in claims
        if not _postdates(repo, claim.get("identity", {}).get("source", {}).get("commit"), head)
    ]
    candidate_ids = {id(claim) for claim in candidates}
    stale_paths = {item.path for item in outcomes if item.verdict == "INVALIDATED"}
    tokens = token_closure([row["path"] for row in changed] + sorted(stale_paths))
    algebra = clock.invalidated_claims(candidates, tokens)
    changed_paths = {row["path"]: row["status"] for row in changed}

    claim_findings: list[dict[str, Any]] = []
    claim_refusals: list[Refusal] = []
    preexisting: dict[str, list[str]] = {}
    verdicts = {str(claim.get("id")): claim.get("verdict", {}).get("state") for claim in claims}
    by_outcome = {item.path: item for item in outcomes}
    for claim in claims:
        claim_id = str(claim.get("id"))
        verdict = claim.get("verdict", {}).get("state")
        reasons: list[str] = []
        old: list[str] = []
        cited = [
            entry.get("path")
            for entry in claim.get("evidence", [])
            if isinstance(entry, dict) and isinstance(entry.get("path"), str)
        ]
        for path in sorted(set(cited)):
            # A change to the evidence itself is caused by this change set.
            # It must be the change-caused reason, never a pre-existing one:
            # the artefact's bytes at head are not the bytes the claim cited.
            if path in changed_paths:
                if repo.exists(head, path):
                    reasons.append(f"this change set changes evidence {path!r}")
                else:
                    reasons.append(f"this change set removes evidence {path!r}")
                continue
            outcome = by_outcome.get(path)
            if outcome is not None and outcome.verdict == "INVALIDATED":
                reasons.append(f"evidence {path!r} is invalidated by this change set")
            elif outcome is not None and outcome.verdict == "UNRESOLVED":
                old.append(f"evidence {path!r} has an unresolved dependency identity")
            elif outcome is not None and outcome.verdict == "UNMODELLED":
                old.append(f"evidence {path!r} has no modelled dependency")
            triage_record = (triage or {}).get(path) or {}
            if triage_record.get("class") == "HISTORICAL":
                old.append(f"evidence {path!r} is historical by identity triage ({triage_record.get('rule')})")
            elif triage_record.get("class") == "UNCERTIFIABLE":
                old.append(
                    f"evidence {path!r} is uncertifiable by identity triage ({triage_record.get('cause')})"
                )
            if not repo.exists(head, path):
                old.append(f"evidence {path!r} is already absent at {head[:12]}")
        if claim_id in algebra["invalidated"]:
            reasons.append("the claim algebra invalidates it from the change set")
        for dependent in claim.get("invalidation", {}).get("depends_on", []):
            if isinstance(dependent, dict) and dependent.get("kind") == "claim":
                if dependent.get("id") in algebra["invalidated"]:
                    reasons.append(f"dependency claim {dependent.get('id')} is invalidated")
        if old:
            preexisting[claim_id] = sorted(set(old))
        if reasons:
            claim_findings.append(
                {
                    "id": claim_id,
                    "verdict": verdict,
                    "reasons": sorted(set(reasons)),
                    "current": verdict not in NON_CURRENT_VERDICTS,
                }
            )
            if verdict not in NON_CURRENT_VERDICTS:
                claim_refusals.append(
                    Refusal(
                        "FR_CLAIM_EVIDENCE_STALE",
                        claim_id,
                        "; ".join(sorted(set(reasons)))[:400],
                    )
                )

    counts: dict[str, int] = {}
    for outcome in outcomes:
        counts[outcome.verdict] = counts.get(outcome.verdict, 0) + 1

    # Refusals here answer one question only: what did *this* change set
    # invalidate? A dependency that cannot be resolved (an UNKNOWN tool digest,
    # no declared identity, no modelled dependency) is reported in `records` and
    # counted in `by_verdict`, and gates in the tree sweep, not here - otherwise
    # a pre-existing gap would be attributed to an unrelated change.
    refusals = [
        Refusal(item.rule or "FR_EVIDENCE_INVALIDATED", item.path, item.argument)
        for item in outcomes
        if item.verdict == "INVALIDATED"
    ]
    refusals.extend(claim_refusals)
    refusals = sorted(set(refusals), key=lambda item: (item.rule, item.where, item.detail))

    by_class: dict[str, int] = {}
    for row in changed:
        key = change_class(row["path"])
        by_class[key] = by_class.get(key, 0) + 1

    reported = sorted(
        (item for item in outcomes if full_records or item.verdict in ("INVALIDATED", "UNRESOLVED", "UNMODELLED", "CARRIED_FORWARD", "HISTORY")),
        key=lambda item: item.path,
    )
    unaffected = sorted(item.path for item in outcomes if item.verdict == "UNAFFECTED")
    unmodelled = sorted(item.path for item in outcomes if item.verdict == "UNMODELLED")
    dependency_counts = {str(item.get("path")): len(item.get("depends_on", [])) for item in artefacts}

    return {
        "base": base if base is not None else "PATHS",
        "head": head,
        "change_set": {
            "count": len(changed),
            "by_class": dict(sorted(by_class.items())),
            "paths": [{"path": row["path"], "status": row["status"]} for row in changed],
        },
        "artefacts": {
            "total": len(outcomes),
            "by_verdict": dict(sorted(counts.items())),
            "records": [item.as_dict() for item in reported],
            "unaffected": {
                "count": len(unaffected),
                "argument": (
                    "every dependency of each named artefact was evaluated; none matches the change set, "
                    "and every dependency identity resolved (no UNKNOWN tool digest, no absent citation, "
                    "no inherited-only identity)"
                ),
                "dependency_counts": {path: dependency_counts.get(path, 0) for path in unaffected},
            },
            "unmodelled": {
                "count": len(unmodelled),
                "argument": (
                    "these artefacts have neither a modelled dependency nor a declared identity; "
                    "the engine will not call them unaffected and does not report them as invalidated"
                ),
                "paths": unmodelled,
            },
        },
        "claims": {
            "total": len(claims),
            "algebra_invalidated": algebra["invalidated"],
            "algebra_transitive_only": algebra["transitive_only"],
            "findings": claim_findings,
            "verified_current": sorted(
                str(claim.get("id"))
                for claim in claims
                if claim.get("verdict", {}).get("state") not in NON_CURRENT_VERDICTS
                and str(claim.get("id")) not in {item["id"] for item in claim_findings}
                and str(claim.get("id")) not in preexisting
                and id(claim) in candidate_ids
            ),
            "not_verified_current": sorted(
                str(claim.get("id"))
                for claim in claims
                if claim.get("verdict", {}).get("state") not in NON_CURRENT_VERDICTS
                and id(claim) in candidate_ids
                and (
                    str(claim.get("id")) in preexisting
                    or str(claim.get("id")) in {item["id"] for item in claim_findings}
                )
            ),
            "incorporates_the_change": sorted(
                str(claim.get("id")) for claim in claims if id(claim) not in candidate_ids
            ),
            "already_not_current": sorted(
                str(claim.get("id")) for claim in claims if claim.get("verdict", {}).get("state") in NON_CURRENT_VERDICTS
            ),
            "preexisting": preexisting,
            "history_cited_as_current": [item.as_dict() for item in _history_cited_as_current(registry, claims_doc)],
            "triage_history_cited_as_current": _triage_history_cited(triage or {}, claims_doc),
            "verdicts": dict(sorted(verdicts.items())),
        },
        "refusals": [item.as_dict() for item in refusals],
        "status": "PASS" if not refusals else "REFUSED",
    }


# ---------------------------------------------------------------------------
# Registry validation
# ---------------------------------------------------------------------------


def validate_registry(repo: Git, registry: dict[str, Any], commit: str) -> list[Refusal]:
    findings: list[Refusal] = []
    if not isinstance(registry, dict) or registry.get("schema") != SCHEMA:
        return [Refusal("FR_SCHEMA", "$", f"schema must be {SCHEMA!r}")]
    if "policy" in registry or "acceptance" in registry:
        findings.append(Refusal("FR_ENGINE_SELF_DECLARED_POLICY", "$", "the registry declares its own acceptance policy"))
    seen: dict[str, str] = {}
    ids: set[str] = set()
    for index, artefact in enumerate(registry.get("artefacts", [])):
        if not isinstance(artefact, dict):
            findings.append(Refusal("FR_SCHEMA", f"$.artefacts[{index}]", "an artefact must be an object"))
            continue
        path = artefact.get("path")
        if not isinstance(path, str) or not path:
            findings.append(Refusal("FR_SCHEMA", f"$.artefacts[{index}]", "an artefact must name a path"))
            continue
        if path in seen:
            findings.append(Refusal("FR_DUPLICATE_ARTEFACT", path, f"also declared at {seen[path]}"))
        seen[path] = f"$.artefacts[{index}]"
        ids.add(path)
        digest = artefact.get("sha256")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            findings.append(Refusal("FR_SCHEMA", path, "sha256 must be a 64-character hex digest"))
        for dependency in artefact.get("depends_on", []):
            if not isinstance(dependency, dict) or dependency.get("kind") not in DEPENDENCY_KINDS:
                findings.append(
                    Refusal("FR_UNKNOWN_DEPENDENCY_KIND", path, f"unknown dependency {dependency!r}"[:200])
                )

    graph: dict[str, list[str]] = {}
    for artefact in registry.get("artefacts", []):
        if not isinstance(artefact, dict):
            continue
        path = str(artefact.get("path"))
        graph.setdefault(path, [])
        for dependency in artefact.get("depends_on", []):
            if isinstance(dependency, dict) and dependency.get("kind") == "upstream_evidence":
                target = str(dependency.get("id"))
                graph[path].append(target)
    for cycle in _cycles(graph):
        findings.append(Refusal("FR_DEPENDENCY_CYCLE", cycle[0], " -> ".join(cycle)))

    for index, declaration in enumerate(registry.get("declarations", [])):
        if not isinstance(declaration, dict):
            findings.append(Refusal("FR_SCHEMA", f"$.declarations[{index}]", "a declaration must be an object"))
            continue
        target = declaration.get("artefact")
        if target not in ids:
            findings.append(
                Refusal("FR_DECLARATION_UNKNOWN_TARGET", str(target), "the declaration names no artefact in the registry")
            )
            continue
        if declaration.get("kind") not in ("HISTORY", "PRESERVATION"):
            findings.append(Refusal("FR_DECLARATION_INVALID", str(target), "kind must be HISTORY or PRESERVATION"))
        if declaration.get("kind") == "HISTORY":
            identity = declaration.get("identity")
            if not isinstance(identity, dict) or not isinstance(identity.get("commit"), str):
                findings.append(
                    Refusal("FR_DECLARATION_INVALID", str(target), "HISTORY must name the commit it was true at")
                )
            elif repo.resolve(identity["commit"]) is None:
                findings.append(
                    Refusal("FR_DECLARATION_INVALID", str(target), f"unknown history commit {identity['commit']!r}")
                )
    return sorted(set(findings), key=lambda item: (item.rule, item.where, item.detail))


def _cycles(graph: dict[str, list[str]]) -> list[list[str]]:
    WHITE, GREY, BLACK = 0, 1, 2
    colour: dict[str, int] = {node: WHITE for node in graph}
    stack: list[str] = []
    found: list[list[str]] = []

    def visit(node: str) -> None:
        colour[node] = GREY
        stack.append(node)
        for neighbour in sorted(graph.get(node, [])):
            if neighbour not in colour:
                colour[neighbour] = WHITE
                graph.setdefault(neighbour, [])
            if colour[neighbour] == GREY:
                at = stack.index(neighbour)
                found.append(stack[at:] + [neighbour])
            elif colour[neighbour] == WHITE:
                visit(neighbour)
        stack.pop()
        colour[node] = BLACK

    for node in sorted(graph):
        if colour.get(node, WHITE) == WHITE:
            visit(node)
    return sorted(found)


# ---------------------------------------------------------------------------
# Modes
# ---------------------------------------------------------------------------


def _history_cited_as_current(registry: dict[str, Any], claims_doc: dict[str, Any]) -> list[Refusal]:
    """A HISTORY artefact may not be cited as current evidence by a claim."""
    history = {
        item["artefact"]
        for item in registry.get("declarations", [])
        if isinstance(item, dict) and item.get("kind") == "HISTORY"
    }
    findings: list[Refusal] = []
    for claim in claims_doc.get("claims", []):
        if not isinstance(claim, dict):
            continue
        if claim.get("verdict", {}).get("state") in NON_CURRENT_VERDICTS:
            continue
        for entry in claim.get("evidence", []):
            if isinstance(entry, dict) and entry.get("path") in history:
                findings.append(
                    Refusal(
                        "FR_HISTORY_CITED_AS_CURRENT",
                        str(claim.get("id")),
                        f"cites {entry['path']!r}, which is declared explicit history",
                    )
                )
    return findings


def mode_record(args: argparse.Namespace) -> int:
    repo = Git(Path(args.repo).resolve())
    commit = repo.resolve(args.at)
    if commit is None:
        print(json.dumps({"status": "REFUSED", "reason": f"cannot resolve {args.at!r}"}))
        return 1
    document = derive(repo, commit)
    target = Path(args.out).resolve()
    if target.exists():
        try:
            existing = load_json(target)
        except JsonError:
            existing = None
        if isinstance(existing, dict) and existing.get("schema") == SCHEMA:
            document["declarations"] = existing.get("declarations", [])
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(dump_json(document), encoding="utf-8")
    print(
        json.dumps(
            {
                "status": "RECORDED",
                "out": str(target),
                "at": commit,
                "artefacts": document["counts"]["artefacts"],
                "dependencies": document["counts"]["dependencies"],
                "without_identity": document["counts"]["without_identity"],
                "excluded": document["counts"]["excluded"],
            },
            sort_keys=True,
        )
    )
    return 0


def _load_registry(path: Path) -> dict[str, Any]:
    document = load_json(path)
    if not isinstance(document, dict):
        raise JsonError("the registry must be a JSON object")
    return document


def _load_triage(path: Path) -> dict[str, Any]:
    document = load_json(path)
    if not isinstance(document, dict):
        raise JsonError("the identity triage must be a JSON object")
    return document


def _change_set(args: argparse.Namespace, repo: Git) -> tuple[list[dict[str, str]], str | None, str] | None:
    if args.paths or args.paths_file:
        paths = list(args.paths or [])
        if args.paths_file:
            text = Path(args.paths_file).read_text(encoding="utf-8")
            paths.extend(line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#"))
        head = repo.resolve(args.head or "HEAD")
        if head is None:
            return None
        # A bare path list has no base identity, so no preservation procedure
        # can be executed against it: `_preservation_check` refuses.
        return [{"path": path, "status": "M"} for path in sorted(set(paths))], None, head
    base = repo.resolve(args.base)
    head = repo.resolve(args.head or "HEAD")
    if base is None or head is None:
        return None
    return repo.changed(base, head), base, head


def mode_check(args: argparse.Namespace) -> int:
    repo = Git(Path(args.repo).resolve())
    try:
        registry = _load_registry(Path(args.registry))
        claims_doc = load_json(Path(args.claims))
    except JsonError as exc:
        print(json.dumps({"status": "REFUSED", "reason": str(exc)}, sort_keys=True))
        return 1
    head = repo.resolve(args.head or "HEAD")
    if head is None:
        print(json.dumps({"status": "REFUSED", "reason": "cannot resolve HEAD"}, sort_keys=True))
        return 1

    triage_document: dict[str, Any] | None = None
    triage_findings: list[Refusal] = []
    triage_path = Path(args.triage).resolve() if args.triage else TRIAGE_PATH
    if triage_path.is_file():
        try:
            triage_document = _load_triage(triage_path)
        except JsonError as exc:
            triage_findings.append(Refusal("FR_TRIAGE_SCHEMA", str(triage_path), str(exc)))
    else:
        triage_findings.append(
            Refusal(
                "FR_TRIAGE_MISSING",
                str(triage_path),
                "the identity triage is required: an artefact with no identity cannot be certified current, "
                "so an absent triage is a refusal rather than a note",
            )
        )
    if triage_document is not None:
        triage_findings.extend(validate_triage(triage_document, registry, repo))
    index = triage_index(triage_document) if triage_document is not None else {}

    structural = validate_registry(repo, registry, head) + triage_findings
    if structural:
        print(
            json.dumps(
                {"status": "REFUSED", "structural_refusals": [item.as_dict() for item in structural]},
                sort_keys=True,
                indent=2,
            )
        )
        return 1

    tree_mode = not args.base and not args.paths and not args.paths_file
    if tree_mode:
        result = _tree_sweep(repo, registry, claims_doc, head, triage=index)
    else:
        computed = _change_set(args, repo)
        if computed is None:
            print(json.dumps({"status": "REFUSED", "reason": "cannot resolve the change-set range"}, sort_keys=True))
            return 1
        changed, base, resolved_head = computed
        result = evaluate(repo, registry, claims_doc, changed, base, resolved_head, triage=index)
        result["mode"] = "check"
        result["triage"] = {
            "applied": bool(index),
            "counts": dict(sorted((triage_document or {}).get("counts", {}).items()))
            if triage_document is not None
            else {},
            "uncertifiable_evidence": sorted(
                {
                    str(entry.get("path"))
                    for claim in claims_doc.get("claims", [])
                    if isinstance(claim, dict)
                    for entry in claim.get("evidence", [])
                    if isinstance(entry, dict) and (index.get(str(entry.get("path"))) or {}).get("class") == "UNCERTIFIABLE"
                }
            ),
        }

    result["triage_record"] = (
        {
            "path": _repo_relative(repo, triage_path),
            "recorded_at_commit": triage_document.get("recorded_at_commit"),
            "counts": triage_document.get("counts"),
        }
        if triage_document is not None
        else None
    )
    result["structural_refusals"] = [item.as_dict() for item in structural]
    print(dump_json(result))
    return 0 if result.get("status") == "PASS" else 1


def mode_triage(args: argparse.Namespace) -> int:
    """Record or verify the identity triage of every unbound artefact."""
    repo = Git(Path(args.repo).resolve())
    try:
        registry = _load_registry(Path(args.registry))
    except JsonError as exc:
        print(json.dumps({"status": "REFUSED", "reason": str(exc)}, sort_keys=True))
        return 1
    at = repo.resolve(args.at or str(registry.get("recorded_at_commit") or "HEAD"))
    if at is None:
        print(json.dumps({"status": "REFUSED", "reason": "cannot resolve the derivation commit"}, sort_keys=True))
        return 1
    document = triage(repo, registry, at)
    findings = validate_triage(document, registry, repo)
    if findings:
        print(
            json.dumps(
                {"status": "REFUSED", "triage_refusals": [item.as_dict() for item in findings]},
                sort_keys=True,
                indent=2,
            )
        )
        return 1
    rendered = dump_json(document)
    target = Path(args.out).resolve()
    if args.write:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(rendered, encoding="utf-8")
        print(
            json.dumps(
                {
                    "status": "WRITTEN",
                    "out": _repo_relative(repo, target),
                    "at": at,
                    "counts": document["counts"],
                },
                sort_keys=True,
            )
        )
        return 0
    committed = target.read_text(encoding="utf-8") if target.exists() else None
    if committed != rendered:
        print(
            json.dumps(
                {
                    "status": "REFUSED",
                    "reason": "the committed triage differs from the derived one",
                    "counts": document["counts"],
                },
                sort_keys=True,
            )
        )
        return 1
    print(json.dumps({"status": "PASS", "counts": document["counts"]}, sort_keys=True))
    return 0


def _tree_sweep(
    repo: Git,
    registry: dict[str, Any],
    claims_doc: dict[str, Any],
    head: str,
    triage: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Is each artefact still true of the tree it names?

    Freshness is the same invalidation engine applied to
    `<artefact identity commit>..HEAD`. An artefact with no resolvable identity
    commit inherits one from a single upstream artefact, and is unresolved when
    even that fails: the tool does not invent an identity to avoid a refusal.

    With a triage index, a declared or derived identity is used, a historical
    artefact is excluded from current claims, and an uncertifiable one is
    `UNRESOLVED` with `FR_IDENTITY_UNCERTIFIABLE` rather than merely noted.
    """
    if triage:
        registry = triaged_registry(registry, triage)
    artefacts = [item for item in registry.get("artefacts", []) if isinstance(item, dict)]
    by_path = {str(item.get("path")): item for item in artefacts}

    def base_for(artefact: dict[str, Any], seen: set[str]) -> tuple[str | None, str]:
        if (artefact.get("triage") or {}).get("class") == "UNCERTIFIABLE":
            # An uncertifiable artefact is not given an identity by inheritance:
            # a tree inherited from a neighbour would certify the very artefact
            # the triage says cannot be certified. It stays unresolved.
            return None, "uncertifiable"
        identity = artefact.get("identity", {})
        commit = identity.get("commit")
        if isinstance(commit, str) and repo.resolve(commit) is not None:
            return repo.resolve(commit), "own"
        path = str(artefact.get("path"))
        if path in seen:
            return None, "cycle"
        seen.add(path)
        upstream = [
            str(dependency.get("id"))
            for dependency in artefact.get("depends_on", [])
            if isinstance(dependency, dict) and dependency.get("kind") == "upstream_evidence"
        ]
        resolved: set[str] = set()
        for candidate in upstream:
            target = by_path.get(candidate)
            if target is None:
                continue
            commit, _ = base_for(target, seen)
            if commit is not None:
                resolved.add(commit)
        if len(resolved) == 1:
            return next(iter(resolved)), "inherited"
        return None, "none" if not resolved else "ambiguous"

    records: list[dict[str, Any]] = []

    def absent_dependencies(artefact: dict[str, Any]) -> list[str]:
        return sorted(
            {
                str(dependency.get("id"))
                for dependency in artefact.get("depends_on", [])
                if isinstance(dependency, dict) and dependency.get("present") is False
            }
        )

    for artefact in artefacts:
        path = str(artefact.get("path"))
        base, how = base_for(artefact, set())
        absent = absent_dependencies(artefact)
        modelled = len(artefact.get("depends_on", []))
        if not repo.exists(head, path):
            records.append(
                {
                    "path": path,
                    "verdict": "ABSENT",
                    "rule": "FR_EVIDENCE_ABSENT",
                    "argument": f"the registry records this artefact but it is absent at {head[:12]}",
                    "claims": artefact.get("claim_ids", []),
                    "superseded": True,
                    "modelled_dependencies": modelled,
                    "absent_dependencies": absent,
                }
            )
            continue
        current_digest = repo.digest(head, path)
        superseded = current_digest is not None and current_digest != artefact.get("sha256")
        if base is None:
            triage_record = artefact.get("triage") or {}
            if triage_record.get("class") == "UNCERTIFIABLE":
                records.append(
                    {
                        "path": path,
                        "verdict": "UNRESOLVED",
                        "rule": "FR_IDENTITY_UNCERTIFIABLE",
                        "argument": (
                            "identity triage "
                            + str(triage_record.get("cause"))
                            + ": "
                            + str(triage_record.get("reason"))
                            + "; the artefact cannot be certified current"
                        ),
                        "claims": artefact.get("claim_ids", []),
                        "superseded": superseded,
                        "modelled_dependencies": modelled,
                        "absent_dependencies": absent,
                    }
                )
                continue
            records.append(
                {
                    "path": path,
                    "verdict": "UNRESOLVED",
                    "rule": "FR_IDENTITY_UNKNOWN",
                    "argument": (
                        f"the artefact names no usable identity commit ({how}); provenance is the last "
                        f"commit that touched it ({(artefact.get('provenance') or {}).get('last_commit')}), "
                        "which is not the tree it was measured on"
                    ),
                    "claims": artefact.get("claim_ids", []),
                    "superseded": superseded,
                    "modelled_dependencies": modelled,
                    "absent_dependencies": absent,
                }
            )
            continue
        changed = repo.changed(base, head)
        # The whole registry is evaluated, not only this artefact: an upstream
        # artefact that is absent or unmodelled makes this one unresolved, and a
        # one-artefact view could not see that edge.
        # The registry already carries the triage identities and annotations,
        # so the per-artefact evaluation is not asked to apply the overlay a
        # second time.
        outcome = evaluate(repo, registry, {"claims": []}, changed, base, head, True, triage=None)
        record = next(
            (item for item in outcome["artefacts"]["records"] if item.get("path") == path),
            None,
        )
        if record is None:  # pragma: no cover - evaluate always records every artefact
            record = {
                "path": path,
                "verdict": "UNRESOLVED",
                "rule": "FR_DEPENDENCY_UNRESOLVED",
                "argument": "the invalidation engine produced no record for this artefact",
            }
        record["identity_commit"] = base
        record["identity_source"] = how
        record["claims"] = artefact.get("claim_ids", [])
        record["changed_since"] = len(changed)
        record["superseded"] = superseded
        record["modelled_dependencies"] = modelled
        record["absent_dependencies"] = absent
        records.append(record)

    # Claims are swept against their own identity, and against the artefacts
    # they cite, exactly as in change-set mode.
    claim_base = claims_doc.get("source_identity", {}).get("commit")
    claim_changed = repo.changed(claim_base, head) if isinstance(claim_base, str) and repo.resolve(claim_base) else []
    claim_eval = evaluate(repo, registry, claims_doc, claim_changed, claim_base or head, head, triage=triage)

    counts: dict[str, int] = {}
    for record in records:
        counts[record["verdict"]] = counts.get(record["verdict"], 0) + 1
    stale = [record for record in records if record["verdict"] in ("INVALIDATED", "UNRESOLVED", "ABSENT")]
    cited_stale = [record for record in stale if record.get("claims")]

    refusals: list[Refusal] = []
    for record in records:
        if record.get("superseded"):
            refusals.append(
                Refusal(
                    "FR_EVIDENCE_SUPERSEDED",
                    record["path"],
                    f"the registry records {artefact_digest(registry, record['path'])}; the tree holds {repo.digest(head, record['path'])}",
                )
            )
    for record in stale:
        rule = record.get("rule") or "FR_EVIDENCE_INVALIDATED"
        dependency = record.get("dependency") or {}
        detail = record.get("argument", "")
        if dependency:
            detail = f"{dependency.get('kind')} {dependency.get('id')!r}: {detail}"
        if record["verdict"] == "INVALIDATED" and not rule.startswith("FR_PRESERVATION"):
            # In the tree, an invalidated artefact is a stale artefact that is
            # being carried with neither an explicit-history label nor a
            # verified preservation argument. That is the refusal.
            rule = "FR_CARRY_FORWARD_UNDECLARED"
        refusals.append(Refusal(rule, record["path"], detail[:400]))
    claim_refusals = [item for item in claim_eval["refusals"] if item["rule"].startswith("FR_CLAIM")]
    refusals.extend(Refusal(item["rule"], item["where"], item["detail"]) for item in claim_refusals)
    refusals.extend(_history_cited_as_current(registry, claims_doc))
    triage_history = _triage_history_cited(triage or {}, claims_doc)
    for item in triage_history:
        refusals.append(
            Refusal(
                "FR_HISTORY_CITED_AS_CURRENT",
                item["claim"],
                f"cites {item['path']!r}, which identity triage declares history "
                f"({item['rule']} at {item['identity']})",
            )
        )
    claim_verdicts = claim_eval["claims"].get("verdicts", {})
    for claim_id, reasons in sorted(claim_eval["claims"].get("preexisting", {}).items()):
        if claim_verdicts.get(claim_id) in NON_CURRENT_VERDICTS:
            continue
        refusals.append(
            Refusal(
                "FR_CLAIM_EVIDENCE_STALE",
                claim_id,
                "; ".join(reasons)[:400],
            )
        )
    refusals = sorted(set(refusals), key=lambda item: (item.rule, item.where, item.detail))

    triage_counts: dict[str, int] = {}
    for artefact in artefacts:
        record = artefact.get("triage") or {}
        if record:
            key = str(record.get("class"))
            triage_counts[key] = triage_counts.get(key, 0) + 1
    return {
        "mode": "check-tree",
        "base": "per-artefact identity",
        "head": head,
        "artefacts": {
            "total": len(records),
            "by_verdict": dict(sorted(counts.items())),
            "records": sorted(records, key=lambda item: item["path"]),
            "stale_cited_by_a_claim": sorted(record["path"] for record in cited_stale),
        },
        "triage": {
            "applied": bool(triage),
            "counts": dict(sorted(triage_counts.items())),
            "uncertifiable": sorted(
                path for path, item in (triage or {}).items() if item.get("class") == "UNCERTIFIABLE"
            ),
            "historical_cited_as_current": triage_history,
        },
        "claims": claim_eval["claims"],
        "refusals": [item.as_dict() for item in refusals],
        "status": "PASS" if not refusals else "REFUSED",
    }


def artefact_digest(registry: dict[str, Any], path: str) -> str:
    for artefact in registry.get("artefacts", []):
        if isinstance(artefact, dict) and artefact.get("path") == path:
            return str(artefact.get("sha256"))
    return "UNKNOWN"


def mode_diff(args: argparse.Namespace) -> int:
    repo = Git(Path(args.repo).resolve())
    if args.runs:
        return _runs_record(repo, args)
    base = repo.resolve(args.base)
    head = repo.resolve(args.head or "HEAD")
    if base is None or head is None:
        print(json.dumps({"status": "REFUSED", "reason": "cannot resolve the range"}, sort_keys=True))
        return 1
    changed = repo.changed(base, head)
    by_class: dict[str, list[str]] = {}
    for row in changed:
        by_class.setdefault(change_class(row["path"]), []).append(row["path"])
    payload = {
        "mode": "diff",
        "base": base,
        "head": head,
        "count": len(changed),
        "by_class": {key: sorted(value) for key, value in sorted(by_class.items())},
        "status": "OK",
    }
    print(dump_json(payload))
    return 0


def _repo_relative(repo: Git, path: Path) -> str:
    """A path relative to the repository root when it lies inside it.

    The history record must not embed the checkout location: the same record is
    re-derived from a clean checkout, from the court's ``/work`` mount and from
    a developer working tree, and a recorded absolute path would make those
    derivations differ for a reason that has nothing to do with the evidence.
    """
    resolved = path.resolve()
    try:
        return str(resolved.relative_to(repo.repo))
    except ValueError:
        return str(resolved)


def _runs_record(repo: Git, args: argparse.Namespace) -> int:
    """Re-derive the results of a committed multi-range history record."""
    path = Path(args.runs).resolve()
    try:
        document = load_json(path)
        registry = _load_registry(Path(args.registry))
        claims_doc = load_json(Path(args.claims))
        triage_document = _load_triage(Path(args.triage).resolve() if args.triage else TRIAGE_PATH)
    except JsonError as exc:
        print(json.dumps({"status": "REFUSED", "reason": str(exc)}, sort_keys=True))
        return 1
    triage_findings = validate_triage(triage_document, registry, repo)
    if triage_findings:
        print(
            json.dumps(
                {"status": "REFUSED", "triage_refusals": [item.as_dict() for item in triage_findings]},
                sort_keys=True,
            )
        )
        return 1
    index = triage_index(triage_document)
    runs = document.get("runs", []) if isinstance(document, dict) else []
    if not runs:
        print(json.dumps({"status": "REFUSED", "reason": "no runs declared"}, sort_keys=True))
        return 1
    head = repo.resolve("HEAD")
    if head is None:
        print(json.dumps({"status": "REFUSED", "reason": "cannot resolve HEAD"}, sort_keys=True))
        return 1
    structural = validate_registry(repo, registry, head)
    if structural:
        print(
            json.dumps(
                {"status": "REFUSED", "structural_refusals": [item.as_dict() for item in structural]},
                sort_keys=True,
                indent=2,
            )
        )
        return 1
    derived: list[dict[str, Any]] = []
    for run in runs:
        base = repo.resolve(run.get("base"))
        head = repo.resolve(run.get("head") or "HEAD")
        if base is None or head is None:
            print(json.dumps({"status": "REFUSED", "reason": f"cannot resolve run {run.get('name')!r}"}, sort_keys=True))
            return 1
        changed = repo.changed(base, head)
        result = evaluate(repo, registry, claims_doc, changed, base, head, triage=index)
        derived.append(
            {
                "name": run.get("name"),
                "purpose": run.get("purpose"),
                "base": base,
                "head": head,
                "change_set": result["change_set"],
                "artefacts": result["artefacts"],
                "claims": result["claims"],
                "refusals": result["refusals"],
                "status": result["status"],
            }
        )
    payload = {
        "schema": HISTORY_SCHEMA,
        "kind": "evidence-freshness-history",
        "item": "ETP-T9",
        "registry": _repo_relative(repo, Path(args.registry)),
        "registry_sha256": sha256_bytes(Path(args.registry).read_bytes()),
        "runs": derived,
    }
    rendered = dump_json(payload)
    if args.write:
        path.write_text(rendered, encoding="utf-8")
        print(json.dumps({"status": "WRITTEN", "runs": len(derived), "out": str(path)}, sort_keys=True))
        return 0
    committed = path.read_text(encoding="utf-8")
    if rendered != committed:
        print(json.dumps({"status": "REFUSED", "reason": "the committed history record differs from the derived one"}, sort_keys=True))
        return 1
    print(json.dumps({"status": "PASS", "runs": len(derived)}, sort_keys=True))
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command")

    record = sub.add_parser("record")
    record.add_argument("--at", default="HEAD")
    record.add_argument("--out", default=str(REGISTRY))
    record.add_argument("--repo", default=str(REPO_ROOT))

    for name in ("check", "diff"):
        command = sub.add_parser(name)
        command.add_argument("--registry", default=str(REGISTRY))
        command.add_argument("--claims", default=str(CLAIMS))
        command.add_argument("--triage", default=str(TRIAGE_PATH))
        command.add_argument("--repo", default=str(REPO_ROOT))
        command.add_argument("--base")
        command.add_argument("--head")
        command.add_argument("--paths", action="append", default=[])
        command.add_argument("--paths-file")
        if name == "diff":
            command.add_argument("--runs")
            command.add_argument("--write", action="store_true")

    triage_command = sub.add_parser("triage")
    triage_command.add_argument("--registry", default=str(REGISTRY))
    triage_command.add_argument("--repo", default=str(REPO_ROOT))
    triage_command.add_argument("--at", default=None, help="derive at the registry's commit by default")
    triage_command.add_argument("--out", default=str(TRIAGE_PATH))
    triage_command.add_argument("--write", action="store_true")

    args = parser.parse_args(argv)
    if args.command == "record":
        return mode_record(args)
    if args.command == "check":
        return mode_check(args)
    if args.command == "diff":
        return mode_diff(args)
    if args.command == "triage":
        return mode_triage(args)
    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
