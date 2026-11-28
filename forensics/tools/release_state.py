#!/usr/bin/env python3
"""openssl-rs — a release receipt must agree with itself and with the lifecycle.

Why this gate exists
--------------------
`render_docs.py --check` proves that a document agrees with the *inputs* it is
rendered from.  It does not prove that an input agrees with itself.  The
0.0.51 publish receipt shipped four contradictions that a document/evidence
comparison cannot see:

    status: PUBLISHED                 release_process: nothing was uploaded
    registry_verification: VERIFIED   download_sha256_recomputed: PENDING
    packaging.crate_path_note:        no publish has run
    non_claims:                       every package detail is pending

The README carried the same stale story in hand-written prose outside its
generated blocks.  This tool reads the receipts and that prose and refuses the
four contradiction classes, one stable code per class:

* ``RS_PUBLISHED_WITH_PREPUBLICATION_CLAIM`` — a receipt says ``PUBLISHED``
  while ``release_process``, ``disclosure``, a ``packaging.*note`` or a
  ``non_claims`` entry still asserts a pre-publication state (no upload, status
  pending, pre-publish, ...).  When the associated build receipt asserts a
  released identity, the same rule covers its ``status``, ``published_as`` and
  ``crate_package`` fields: a released build that still says "pending publish"
  is the same contradiction (this is what the 0.0.51 build receipt carried after
  the publish receipt was corrected).
* ``RS_VERIFIED_WITHOUT_RECOMPUTED_HASH`` — ``registry_verification.status`` is
  ``VERIFIED`` but ``download_sha256_recomputed`` is absent, ``PENDING``,
  ``NOT_RUN`` or unequal to ``checksum``; or the download verification says it
  did not run.
* ``RS_TREE_EQUIVALENCE_UNPROVEN`` — a receipt claims the packaging tree equals
  the release tree without a digest value recorded at the released commit, or a
  released build receipt names a different source commit than its publish
  receipt without a stated reconciliation.  A ``release_tree_digest_recomputed_at``
  that names a working tree (or no commit at all) is refused even when the
  publish receipt states the same digest: the receipt that carries the
  recomputation field must name the released commit.
* ``RS_DOC_CONTRADICTS_LIFECYCLE`` — README prose outside the generated blocks
  says a published version is unreleased, not pushed, or checksum-pending.

The supersede rule (code 4)
---------------------------
A correction record is allowed to quote the false text it corrects.  Text inside
a *marked* supersede/correction sentence or paragraph is non-asserting:

  * a paragraph whose first sentence begins ``Superseded`` / ``Correction``
    (markdown emphasis and ``>`` markers allowed), or
  * a sentence whose first word is ``Superseded`` / ``Superseding`` /
    ``Correction`` / ``Corrected``.

This is deliberately narrow: it exempts one explicitly marked unit, not "any
text mentioning an old version".  An unqualified copy of the same claim fails.
The rule is applied to README prose and to receipt fields that carry the same
correction record (the 0.0.51 disclosure explicitly supersedes its pre-publish
text), never as a general escape hatch.

test-baseline.json
------------------
The baseline is a single current record.  It is read and applied to the newest
published version as a corroborating identity witness: the build receipt's
measured source commit and the baseline's ``source_commit`` must name the same
tree.  A mismatch is a code-3 refusal, because a released build has then named a
second, unreconciled source identity.

Usage
-----
    python3 forensics/tools/release_state.py             # check the repository
    python3 forensics/tools/release_state.py --list      # print the codes
    python3 forensics/tools/release_state.py --version 0.0.51

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import REPO_ROOT  # noqa: E402

ATLAS = Path("forensics/memory-safety/campaign/safe-c33/atlas-refresh")
README = Path("README.md")
BASELINE = ATLAS / "test-baseline.json"

RS_PUBLISHED_WITH_PREPUBLICATION_CLAIM = "RS_PUBLISHED_WITH_PREPUBLICATION_CLAIM"
RS_VERIFIED_WITHOUT_RECOMPUTED_HASH = "RS_VERIFIED_WITHOUT_RECOMPUTED_HASH"
RS_TREE_EQUIVALENCE_UNPROVEN = "RS_TREE_EQUIVALENCE_UNPROVEN"
RS_DOC_CONTRADICTS_LIFECYCLE = "RS_DOC_CONTRADICTS_LIFECYCLE"

CODES: tuple[str, ...] = (
    RS_PUBLISHED_WITH_PREPUBLICATION_CLAIM,
    RS_VERIFIED_WITHOUT_RECOMPUTED_HASH,
    RS_TREE_EQUIVALENCE_UNPROVEN,
    RS_DOC_CONTRADICTS_LIFECYCLE,
)

GENERATED_BEGIN = re.compile(r"<!--\s*BEGIN GENERATED\b.*?-->")
GENERATED_END = re.compile(r"<!--\s*END GENERATED\b.*?-->")


@dataclass(frozen=True)
class Finding:
    code: str
    version: str
    field: str
    detail: str

    def render(self) -> str:
        return f"[{self.code}] {self.version}: {self.field}: {self.detail}"


# ---------------------------------------------------------------------------
# Shared text helpers
# ---------------------------------------------------------------------------

_CORRECTION_MARK = re.compile(
    r"^[\s>*_`\"'(\[]*(?:\*\*|__)?\s*"
    r"(?:supersed(?:ed|ing)|correction|corrected)\b",
    re.IGNORECASE,
)

_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+")


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return " ".join(_as_text(v) for _k, v in sorted(value.items()) if v is not None)
    if isinstance(value, (list, tuple)):
        return " ".join(_as_text(v) for v in value)
    return str(value)


def _sentences(text: str) -> list[str]:
    flat = re.sub(r"\s+", " ", text).strip()
    return [s for s in _SENTENCE_SPLIT.split(flat) if s]


def is_correction_marker(sentence: str) -> bool:
    """True when a sentence begins with an explicit supersede/correction mark."""
    return bool(_CORRECTION_MARK.match(sentence))


def asserting_sentences(text: str) -> list[str]:
    """Sentences that are not inside an explicitly marked correction."""
    return [s for s in _sentences(text) if not is_correction_marker(s)]


def readme_prose(text: str) -> str:
    """README text with every ``BEGIN/END GENERATED`` block removed, inclusive."""
    kept: list[str] = []
    inside = False
    for line in text.splitlines():
        if GENERATED_BEGIN.search(line):
            inside = True
            continue
        if GENERATED_END.search(line):
            inside = False
            continue
        if not inside:
            kept.append(line)
    return "\n".join(kept)


def _snippet(text: str, limit: int = 140) -> str:
    text = re.sub(r"\s+", " ", text).strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


# ---------------------------------------------------------------------------
# Code 1: PUBLISHED beside a pre-publication assertion
# ---------------------------------------------------------------------------

_PREPUBLICATION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bno\s+(?:cargo\s+)?(?:publish|upload|push)\b", re.I),
    re.compile(r"\bno\s+(?:release\s+)?(?:commit|tag)\b[^.]{0,50}\b(?:push|upload)\b", re.I),
    re.compile(r"\bnothing\s+(?:has|was|had)\s+(?:been\s+)?(?:uploaded|published|pushed)\b", re.I),
    re.compile(r"\b(?:has|have|had)\s+not\s+(?:yet\s+)?(?:been\s+)?"
               r"(?:uploaded|published|pushed)\b", re.I),
    re.compile(r"\b(?:was|is|are|were)\s+not\s+(?:yet\s+)?(?:been\s+)?"
               r"(?:uploaded|published|pushed)\b", re.I),
    re.compile(r"\bnot\s+(?:yet\s+)?(?:been\s+)?(?:uploaded|published|pushed)\b", re.I),
    re.compile(r"\bis\s+(?:still\s+)?pre-?publish\b", re.I),
    re.compile(r"\bpending\s+publish\b", re.I),
    re.compile(r"^\s*(?:still\s+)?pending\b", re.I),
    re.compile(r"\bpre-?publication\s+state\b", re.I),
    # NOT_RUN is a valid verdict for a BOUNDARY/SEAL gate, so it is not, by
    # itself, a pre-publication claim.  Only the publication vocabulary counts
    # here; a download that did not run is code 2's subject.
    re.compile(r"\bstatus\s+(?:PENDING|unpublished|unreleased)\b", re.I),
    re.compile(r"\b(?:checksum|upload|publish|release|packaging|details?)\b"
               r"[^.\n]{0,40}?\b(?:is|are|remains?)\s+(?:still\s+)?"
               r"(?:PENDING|unpublished|unreleased)\b", re.I),
    re.compile(r"\b(?:is|are|remains?)\s+(?:still\s+)?"
               r"(?:PENDING|unpublished|unreleased)\b", re.I),
    re.compile(r"\bchecksum\s+(?:is|was|remains?)\s+(?:deliberately\s+|still\s+)?"
               r"(?:PENDING|pending)\b", re.I),
    re.compile(r"\bchecksum\b[^.\n]{0,20}?\brecorded\s+as\s+(?:PENDING|pending)\b", re.I),
    re.compile(r"\bno\b[^.\n]{0,30}?\b(?:package|upload|publish)\b"
               r"[^.\n]{0,30}?\b(?:produced|created|uploaded|published|occurred)\b", re.I),
)


def _prepublication_assertions(text: str) -> list[str]:
    hits: list[str] = []
    # A field whose whole value is a placeholder is itself the assertion.
    if text.strip().strip("`*_ '").upper() in {
        "PENDING", "NOT_RUN", "NOT RUN", "UNPUBLISHED", "UNRELEASED",
    }:
        hits.append(text.strip())
    for sentence in asserting_sentences(text):
        for pattern in _PREPUBLICATION_PATTERNS:
            match = pattern.search(sentence)
            if match:
                hits.append(match.group(0).strip())
                break
    return hits


def _publish_text_fields(publish: dict) -> Iterable[tuple[str, str]]:
    release_process = publish.get("release_process")
    if isinstance(release_process, dict):
        for key, value in sorted(release_process.items()):
            yield f"release_process.{key}", _as_text(value)
    elif release_process is not None:
        yield "release_process", _as_text(release_process)

    if "disclosure" in publish:
        yield "disclosure", _as_text(publish.get("disclosure"))

    packaging = publish.get("packaging")
    if isinstance(packaging, dict):
        for key, value in sorted(packaging.items()):
            if "note" in key.lower() or "status" in key.lower():
                yield f"packaging.{key}", _as_text(value)

    for index, entry in enumerate(publish.get("non_claims") or []):
        yield f"non_claims[{index}]", _as_text(entry)


def _build_text_fields(build: dict) -> Iterable[tuple[str, str]]:
    """The build receipt's publication-lifecycle fields.

    A candidate build that explicitly says it is pending is not making a
    lifecycle claim; only a build that asserts a released identity has to agree
    with the publish receipt, so the caller scans only those.
    """
    yield "status", _as_text(build.get("status"))
    yield "published_as", _as_text(build.get("published_as"))
    crate_package = build.get("crate_package")
    if isinstance(crate_package, dict):
        for key, value in sorted(crate_package.items()):
            if key.lower() in {"status", "note", "path"} or "note" in key.lower():
                yield f"crate_package.{key}", _as_text(value)


def _check_published_prepublication(
    version: str, publish: dict, build: dict | None = None
) -> list[Finding]:
    if str(publish.get("status", "")).upper() != "PUBLISHED":
        return []
    fields = list(_publish_text_fields(publish))
    if isinstance(build, dict) and _release_claiming_build(build):
        fields.extend(_build_text_fields(build))
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for field, text in fields:
        for claim in _prepublication_assertions(text):
            key = (field, claim.lower())
            if key in seen:
                continue
            seen.add(key)
            findings.append(Finding(
                RS_PUBLISHED_WITH_PREPUBLICATION_CLAIM,
                version,
                field,
                f"status is PUBLISHED but {field} still asserts a pre-publication "
                f"state: {claim!r}",
            ))
    return findings


# ---------------------------------------------------------------------------
# Code 2: VERIFIED without a matching recomputed download hash
# ---------------------------------------------------------------------------

_NOT_RUN = re.compile(r"\bNOT[ _]RUN\b|\bnot[ _]run\b", re.IGNORECASE)


def _check_registry_verification(version: str, publish: dict) -> list[Finding]:
    verification = publish.get("registry_verification")
    if not isinstance(verification, dict):
        return []

    findings: list[Finding] = []
    status = str(verification.get("status", "")).upper()
    recomputed = verification.get("download_sha256_recomputed")
    checksum = verification.get("checksum")
    download_text = _as_text(verification.get("download_verification"))

    if status == "VERIFIED":
        if not isinstance(recomputed, str) or not recomputed.strip():
            findings.append(Finding(
                RS_VERIFIED_WITHOUT_RECOMPUTED_HASH, version,
                "registry_verification.download_sha256_recomputed",
                "status is VERIFIED but no recomputed download hash is recorded",
            ))
        elif recomputed.strip().upper() in {"PENDING", "NOT_RUN", "NOT RUN"}:
            findings.append(Finding(
                RS_VERIFIED_WITHOUT_RECOMPUTED_HASH, version,
                "registry_verification.download_sha256_recomputed",
                f"status is VERIFIED but the recomputed hash is {recomputed!r}",
            ))
        elif not isinstance(checksum, str) or recomputed.strip().lower() != checksum.strip().lower():
            findings.append(Finding(
                RS_VERIFIED_WITHOUT_RECOMPUTED_HASH, version,
                "registry_verification.download_sha256_recomputed",
                f"recomputed hash {recomputed!r} differs from registry checksum "
                f"{checksum!r}",
            ))
        if not download_text or _NOT_RUN.search(download_text):
            findings.append(Finding(
                RS_VERIFIED_WITHOUT_RECOMPUTED_HASH, version,
                "registry_verification.download_verification",
                f"status is VERIFIED but download verification says {download_text!r}",
            ))
    elif download_text and _NOT_RUN.search(download_text):
        findings.append(Finding(
            RS_VERIFIED_WITHOUT_RECOMPUTED_HASH, version,
            "registry_verification.download_verification",
            f"download verification says {download_text!r}",
        ))
    return findings


# ---------------------------------------------------------------------------
# Code 3: a tree-equivalence claim without a released-commit digest
# ---------------------------------------------------------------------------

_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
_HEX64_ANY = re.compile(r"\b[0-9a-fA-F]{64}\b")
_EQUIVALENCE_NOTE = re.compile(
    r"(?:packaging|release)[- ]tree[^.]{0,120}?"
    r"(?:identical|equals|same\s+tree|same\s+content\s+identity)"
    r"|(?:identical|equals|same\s+tree)\b[^.]{0,80}?"
    r"(?:packaging|release)[- ]tree",
    re.IGNORECASE | re.DOTALL,
)
_TREE_DIGEST_IN_NOTE = re.compile(
    r"(?:packaging|release)[- ]tree(?:[- ]digest)?[^.]{0,100}?"
    r"\b(?P<digest>[0-9a-fA-F]{64})\b",
    re.IGNORECASE | re.DOTALL,
)


def _is_hex64(value: Any) -> bool:
    return isinstance(value, str) and bool(_HEX64.match(value.strip()))


def _commit_matches(left: Any, right: Any) -> bool:
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    left, right = left.strip().lower(), right.strip().lower()
    if len(left) < 7 or len(right) < 7:
        return False
    return left.startswith(right) or right.startswith(left)


def _release_claiming_build(build: dict | None) -> bool:
    """A build asserts a released identity rather than merely a candidate one."""
    if not isinstance(build, dict):
        return False
    source = build.get("source_identity") or {}
    return (
        str(build.get("status", "")).upper() == "RELEASED"
        or bool(build.get("release_commit"))
        or bool(source.get("release_tree_digest_recomputed_at"))
    )


def _build_source_commits(build: dict | None) -> list[str]:
    if not isinstance(build, dict):
        return []
    source = build.get("source_identity") or {}
    values = [
        build.get("release_commit"),
        source.get("measured_source_commit"),
        source.get("build_head"),
        source.get("build_ran_at_head"),
        source.get("install_source_commit"),
    ]
    return [v.strip() for v in values if isinstance(v, str) and v.strip()]


def _publish_source_commits(publish: dict) -> list[str]:
    source = publish.get("source_identity") or {}
    values = [
        source.get("commit"),
        source.get("candidate_commit"),
        source.get("release_commit"),
    ]
    return [v.strip() for v in values if isinstance(v, str) and v.strip()]


def _publish_reconciliation_text(publish: dict) -> str:
    source = publish.get("source_identity") or {}
    parts = [_as_text(source)]
    packaging = publish.get("packaging") or {}
    parts.extend(_as_text(v) for k, v in sorted(packaging.items())
                 if "note" in k.lower() or "status" in k.lower())
    parts.append(_as_text(publish.get("reconciliation")))
    return " ".join(parts)


def _equivalence_claim(publish: dict, build: dict | None) -> bool:
    source = publish.get("source_identity") or {}
    if _is_hex64(source.get("release_tree_digest")):
        return True
    if source.get("release_tree_digest_recomputed_at") is not None:
        return True
    if _EQUIVALENCE_NOTE.search(_as_text(source)):
        return True
    if _release_claiming_build(build):
        build_source = build.get("source_identity") or {}  # type: ignore[union-attr]
        if _is_hex64(build_source.get("release_tree_digest")):
            return True
        if build_source.get("release_tree_digest_recomputed_at") is not None:
            return True
        if _EQUIVALENCE_NOTE.search(_as_text(build_source)):
            return True
    return False


def _digest_recorded_at_release(publish: dict, build: dict | None) -> bool:
    source = publish.get("source_identity") or {}
    if not isinstance(source.get("commit"), str) or not source.get("commit", "").strip():
        return False
    if _is_hex64(source.get("release_tree_digest")):
        return True
    if _TREE_DIGEST_IN_NOTE.search(_as_text(source)):
        return True

    if isinstance(build, dict) and _release_claiming_build(build):
        build_source = build.get("source_identity") or {}
        digest = build_source.get("release_tree_digest")
        recomputed_at = build_source.get("release_tree_digest_recomputed_at")
        if _is_hex64(digest) and isinstance(recomputed_at, str):
            if any(_commit_matches(recomputed_at, c) for c in _publish_source_commits(publish)):
                return True
            if _commit_matches(recomputed_at, build.get("release_commit")):
                return True

    # A publish receipt may reconcile explicitly to the build receipt by naming
    # it and carrying the same digest.
    text = _publish_reconciliation_text(publish)
    build_digest = ((build or {}).get("source_identity") or {}).get("release_tree_digest")
    if _is_hex64(build_digest) and build_digest.lower() in text.lower():
        return True
    return False


def _stated_reconciliation(version: str, publish: dict, build: dict) -> bool:
    publish_commits = _publish_source_commits(publish)
    build_commits = _build_source_commits(build)
    if any(_commit_matches(b, p) for b in build_commits for p in publish_commits):
        return True

    text = _publish_reconciliation_text(publish)
    if _as_text(publish.get("reconciliation")).strip():
        return True
    if _as_text(build.get("reconciliation")).strip():
        return True
    if f"build-{version}.json" in text or f"build-{version}" in text:
        return True
    for commit in build_commits:
        if commit.lower() in text.lower():
            return True

    build_source = build.get("source_identity") or {}
    digest = build_source.get("release_tree_digest")
    if _is_hex64(digest) and digest.lower() in text.lower():
        return True
    recomputed_at = build_source.get("release_tree_digest_recomputed_at")
    if isinstance(recomputed_at, str) and any(
        _commit_matches(recomputed_at, p) for p in publish_commits
    ):
        return True
    return False


def _check_tree_equivalence(
    version: str,
    publish: dict,
    build: dict | None,
    baseline: dict | None,
) -> list[Finding]:
    findings: list[Finding] = []
    if _equivalence_claim(publish, build) and not _digest_recorded_at_release(publish, build):
        findings.append(Finding(
            RS_TREE_EQUIVALENCE_UNPROVEN, version,
            "source_identity (publish/build)",
            "a packaging-tree/release-tree equivalence is claimed, but no digest "
            "value is recorded at the released commit",
        ))

    if isinstance(build, dict) and _release_claiming_build(build):
        build_source = build.get("source_identity") or {}
        recomputed_at = build_source.get("release_tree_digest_recomputed_at")
        if isinstance(recomputed_at, str) and recomputed_at.strip():
            publish_commits = _publish_source_commits(publish)
            named = re.search(r"\b[0-9a-fA-F]{7,40}\b", recomputed_at)
            if named is None or not any(
                _commit_matches(named.group(0), commit) for commit in publish_commits
            ):
                findings.append(Finding(
                    RS_TREE_EQUIVALENCE_UNPROVEN, version,
                    "build-%s.source_identity.release_tree_digest_recomputed_at" % version,
                    "the digest is not recorded at the released commit %r: %r"
                    % (publish_commits, recomputed_at),
                ))

        publish_commits = _publish_source_commits(publish)
        build_commits = _build_source_commits(build)
        if not any(_commit_matches(b, p) for b in build_commits for p in publish_commits):
            if not _stated_reconciliation(version, publish, build):
                findings.append(Finding(
                    RS_TREE_EQUIVALENCE_UNPROVEN, version,
                    "build-%s.source_identity.measured_source_commit" % version,
                    "build source identity %r differs from publish source identity "
                    "%r with no stated reconciliation"
                    % (build_commits, publish_commits),
                ))

    if isinstance(build, dict) and isinstance(baseline, dict):
        measured = (build.get("source_identity") or {}).get("measured_source_commit")
        baseline_commit = baseline.get("source_commit")
        if (
            isinstance(measured, str)
            and isinstance(baseline_commit, str)
            and not _commit_matches(measured, baseline_commit)
        ):
            findings.append(Finding(
                RS_TREE_EQUIVALENCE_UNPROVEN, version,
                "build-%s.source_identity.measured_source_commit" % version,
                f"build measured {measured!r} but test-baseline.json names "
                f"{baseline_commit!r}",
            ))
    return findings


# ---------------------------------------------------------------------------
# Code 4: README prose contradicts the published lifecycle
# ---------------------------------------------------------------------------

_LIFECYCLE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bunpublished\b", re.I),
    re.compile(r"\bunreleased\b", re.I),
    re.compile(r"\bnot\s+(?:yet\s+)?(?:been\s+)?(?:published|released|pushed|uploaded)\b", re.I),
    re.compile(r"\bno\s+(?:release\s+)?(?:commit|tag)\b[^.]{0,50}\b(?:push|upload)\b", re.I),
    re.compile(r"\bno\s+(?:release\s+)?(?:push|upload|publish)\b", re.I),
    re.compile(r"\bno\s+upload\s+(?:has|had)\s+(?:occurred|happened)\b", re.I),
    re.compile(r"\bchecksum\s+(?:is|was|remains?)\b[^.]{0,20}?\bPENDING\b", re.I),
    re.compile(r"\bchecksum\b[^.]{0,30}?\bPENDING\b", re.I),
    re.compile(r"\bstatus\s+(?:is\s+|was\s+|remains?\s+)?PENDING\b", re.I),
)

_VERSION = re.compile(r"\b(?:v)?(?P<version>\d+\.\d+\.\d+)\b")


def _check_readme(version: str, publish: dict, prose: str) -> list[Finding]:
    if str(publish.get("status", "")).upper() != "PUBLISHED":
        return []
    findings: list[Finding] = []
    for paragraph in re.split(r"\n\s*\n", prose):
        sentences = _sentences(paragraph)
        if sentences and is_correction_marker(sentences[0]):
            # An explicitly marked correction paragraph is non-asserting.
            continue
        for sentence in sentences:
            if is_correction_marker(sentence):
                continue
            if version not in _VERSION.findall(sentence):
                continue
            for pattern in _LIFECYCLE_PATTERNS:
                match = pattern.search(sentence)
                if match:
                    findings.append(Finding(
                        RS_DOC_CONTRADICTS_LIFECYCLE, version,
                        "README.md (prose outside generated blocks)",
                        f"publish receipt is PUBLISHED but prose asserts {match.group(0)!r}: "
                        f"{_snippet(sentence)}",
                    ))
                    break
    return findings


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------


def check_version(
    version: str,
    publish: dict,
    build: dict | None = None,
    baseline: dict | None = None,
    readme: str = "",
) -> list[Finding]:
    """All refusal codes for one version's documents."""
    findings: list[Finding] = []
    findings.extend(_check_published_prepublication(version, publish, build))
    findings.extend(_check_registry_verification(version, publish))
    findings.extend(_check_tree_equivalence(version, publish, build, baseline))
    findings.extend(_check_readme(version, publish, readme_prose(readme)))
    return findings


def _version_key(version: str) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in version.split("."))
    except ValueError:
        return (0,)


def versions(root: Path = REPO_ROOT) -> list[str]:
    atlas = root / ATLAS
    found = {path.stem[len("publish-"):] for path in atlas.glob("publish-*.json")}
    return sorted(found, key=_version_key)


def _load(root: Path, relative: Path) -> dict:
    return json.loads((root / relative).read_text(encoding="utf-8"))


def check_root(root: Path = REPO_ROOT, only: Iterable[str] | None = None) -> list[Finding]:
    """Check every publish receipt under the atlas-refresh directory."""
    atlas = root / ATLAS
    readme_text = (root / README).read_text(encoding="utf-8")
    baseline_path = root / BASELINE
    baseline = _load(root, BASELINE) if baseline_path.is_file() else None

    all_versions = versions(root)
    selected = list(only) if only is not None else all_versions
    newest = max(all_versions, key=_version_key) if all_versions else None

    findings: list[Finding] = []
    for version in selected:
        publish_path = atlas / f"publish-{version}.json"
        if not publish_path.is_file():
            continue
        publish = _load(root, publish_path.relative_to(root))
        build_path = atlas / f"build-{version}.json"
        build = (
            _load(root, build_path.relative_to(root)) if build_path.is_file() else None
        )
        # The baseline is one current record, so it is a witness only for the
        # newest published version.
        version_baseline = baseline if version == newest else None
        findings.extend(check_version(
            version, publish, build, version_baseline, readme_text
        ))
    return findings


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", default=None, help="repository root")
    parser.add_argument("--version", action="append", default=None,
                        help="check one version (repeatable)")
    parser.add_argument("--list", action="store_true", help="print the refusal codes")
    args = parser.parse_args(argv)

    root = Path(args.root).resolve() if args.root else REPO_ROOT

    if args.list:
        print("README.md + atlas-refresh/publish-*.json: release_state_consistency")
        for code in CODES:
            print(f"  {code}")
        return 0

    findings = check_root(root, only=args.version)
    for finding in findings:
        print(finding.render())
    if findings:
        print(f"release-state: {len(findings)} refusal(s) across "
              f"{len({f.version for f in findings})} version(s)")
        return 1
    print("release-state: ok: every publish receipt agrees with itself, with its "
          "build identity, and with the README lifecycle")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
