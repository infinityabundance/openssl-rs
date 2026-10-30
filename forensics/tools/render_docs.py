#!/usr/bin/env python3
"""Render the evidence-derived documentation blocks.

Reads only machine-readable evidence and rewrites only the text between
``<!-- BEGIN GENERATED: <name> -->`` / ``<!-- END GENERATED: <name> -->``
markers.  ``--check`` regenerates in memory, writes nothing, and exits non-zero
if any rendered block differs from the committed copy.

Evidence inputs (no others):

* ``forensics/downstream/runtime-functional-atlas.json``
* ``forensics/downstream/build-link-atlas.json``
* ``forensics/memory-safety/campaign/safe-c33/CAMPAIGN-STATUS.json``
* ``forensics/memory-safety/campaign/safe-c33/atlas-refresh/unsafe-census.json``
* ``forensics/memory-safety/campaign/safe-c33/atlas-refresh/post-census-delta.json``
* ``forensics/memory-safety/campaign/safe-c33/atlas-refresh/boundary-sweep-*.json``
* ``forensics/memory-safety/campaign/safe-c33/atlas-refresh/test-baseline.json``
* ``Cargo.toml`` and ``atlas-refresh/publish-*.json``
* ``atlas-refresh/build-<version>.json`` (the working-tree install identity: commit,
  source-tree digest and library hashes)
* ``body.candidate_identity`` (the identity the downstream atlas was measured at)

The working-tree identity is the build receipt, not the atlas: the atlas records
where its downstream rows were measured, which can be a different build.  Using
the atlas for the README's "source identity" line published a version string
next to hashes that build did not produce.

Usage:
    render_docs.py --check   # exit 0 clean, 1 drift, 2 structural error
    render_docs.py --write   # rewrite the marked blocks
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

CAMPAIGN = Path("forensics/memory-safety/campaign/safe-c33")
ATLAS = Path("forensics/downstream/runtime-functional-atlas.json")
BUILD_LINK = Path("forensics/downstream/build-link-atlas.json")
CENSUS = CAMPAIGN / "atlas-refresh/unsafe-census.json"
DELTA = CAMPAIGN / "atlas-refresh/post-census-delta.json"
STATUS_JSON = CAMPAIGN / "CAMPAIGN-STATUS.json"
TEST_BASELINE = CAMPAIGN / "atlas-refresh/test-baseline.json"
SWEEP_GLOB = "boundary-sweep-*.json"
PUBLISH_GLOB = "publish-*.json"
BUILD_GLOB = "build-*.json"

# Display names used in the rendered blocks (repo-relative, short).
ATLAS_S = "forensics/downstream/runtime-functional-atlas.json"
BUILD_LINK_S = "forensics/downstream/build-link-atlas.json"
STATUS_S = "CAMPAIGN-STATUS.json"
BUILD_S = "atlas-refresh/build-"
CENSUS_S = "atlas-refresh/unsafe-census.json"
DELTA_S = "atlas-refresh/post-census-delta.json"
TEST_BASELINE_S = "atlas-refresh/test-baseline.json"

README = Path("README.md")
STATUS_DOC = CAMPAIGN / "STATUS-2026-10-20.md"

# block name -> destination file
BLOCKS = {
    "readme-achievements": README,
    "readme-l7-families": README,
    "readme-memory-safety": README,
    "status-current-evidence": STATUS_DOC,
    "status-mechanisms": STATUS_DOC,
    "status-subphase-outcomes": STATUS_DOC,
    "status-reduction-census": STATUS_DOC,
}


class RenderError(RuntimeError):
    """Evidence is missing, inconsistent, or the markers are malformed."""


def load_json(path: Path) -> dict:
    try:
        with path.open(encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError as exc:
        raise RenderError(f"missing evidence file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise RenderError(f"invalid JSON in {path}: {exc}") from exc


def candidate_identity(atlas: dict) -> dict:
    """Stable candidate identity from the atlas, not the working-tree HEAD."""
    raw = atlas.get("body", {}).get("candidate_identity") or {}
    commit = next(
        (
            str(raw[key])
            for key in ("commit", "candidate_commit", "git_commit", "git_head")
            if raw.get(key)
        ),
        None,
    )
    libs = []
    for key, value in sorted(raw.items()):
        if key.endswith("_sha256") and value:
            name = key[: -len("_sha256")].replace("_so_", ".so.")
            libs.append((name, str(value)))
    if not commit and not libs:
        raise RenderError("atlas body.candidate_identity records neither commit nor hashes")
    return {"commit": commit, "libs": libs}


def build_identity(refresh: Path, version: str) -> dict:
    """The working-tree install identity, from ``build-<version>.json``.

    A build receipt names the source commit, the source-tree digest and every
    library digest of the build the working tree produces.  It is required: a
    missing receipt is a structural error, because falling back to the atlas
    would bind the current version string to a different build's hashes.  The
    receipt is not a publish receipt, so a published version never claims the
    working tree produced the published bytes unless the hashes match.
    """
    matches = []
    for path in sorted(refresh.glob(BUILD_GLOB)):
        data = load_json(path)
        if str(data.get("version")) == version:
            matches.append((path, data))
    if not matches:
        raise RenderError(
            f"no build receipt for crate version {version} under atlas-refresh/"
        )
    path, data = matches[-1]
    source = data.get("source_identity") or {}
    artefacts = data.get("artefacts") or {}
    libs = []
    for name in ("libcrypto.so.3", "libssl.so.3"):
        digest = str((artefacts.get(name) or {}).get("sha256") or "")
        if not digest:
            raise RenderError(f"build receipt {path.name} has no {name} digest")
        libs.append((name, digest))
    commit = str(source.get("measured_source_commit") or "")
    tree = str(source.get("build_source_tree_digest") or "")
    measured_tree = str(source.get("measured_source_tree_digest") or "")
    release_tree = str(source.get("release_tree_digest") or "")
    if not commit or not tree:
        raise RenderError(
            f"build receipt {path.name} records no source commit or build source-tree digest"
        )
    for label, digest in (("build", tree), ("measured", measured_tree), ("release", release_tree)):
        if digest and not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise RenderError(
                f"build receipt {path.name} has a malformed {label} source-tree digest"
            )
    return {
        "commit": commit,
        "tree": tree,
        "measured_tree": measured_tree,
        "release_tree": release_tree,
        "libs": libs,
        "source": f"atlas-refresh/{path.name}",
    }


def cargo_version(root: Path) -> str:
    text = (root / "Cargo.toml").read_text(encoding="utf-8")
    try:
        import tomllib  # Python >= 3.11

        return str(tomllib.loads(text)["package"]["version"])
    except ImportError:
        match = re.search(
            r'^\[package\](?:.|\n)*?^version\s*=\s*"([^"]+)"', text, re.MULTILINE
        )
        if not match:
            raise RenderError("cannot read [package] version from Cargo.toml")
        return match.group(1)


def receipt_number(path: Path) -> int:
    match = re.search(r"-([BM])(\d+)\.json$", path.name)
    if not match:
        raise RenderError(f"unrecognised receipt name: {path.name}")
    return int(match.group(2))


def load_sweeps(refresh: Path) -> list[tuple[int, str, dict]]:
    out = []
    for path in refresh.glob(SWEEP_GLOB):
        data = load_json(path)
        out.append((receipt_number(path), path.stem, data))
    return sorted(out)


def family_names(atlas: dict) -> tuple[list[str], list[str], list[str]]:
    """Return ``(union of L7 families, candidate-only, authority-only)``.

    A candidate/authority level difference is a measured result (the atlas can
    record an authority-only HARNESS drop or a candidate-only lift), not a
    malformed atlas.  It is disclosed in the rendered text, never reconciled by
    changing a row.
    """
    runs = atlas["body"]["runs"]
    levels: dict[tuple[str, str], set[str]] = {"candidate": set(), "authority": set()}
    for run in runs:
        if run.get("subject") not in levels:
            continue
        if run.get("level") == "L7-functional":
            levels[run["subject"]].add(run["family_id"].split(":", 1)[-1])
    cand, auth = levels["candidate"], levels["authority"]
    return sorted(cand | auth), sorted(cand - auth), sorted(auth - cand)


def census_partition(census: dict, delta: dict) -> dict[str, int]:
    pinned = delta["pinned_census"]["partition"]
    change = delta["delta_partition"]
    combined = delta["combined_partition"]
    pinned_files = len(census["files"])
    declared = census["candidate"]["src_rs_files"]
    if pinned_files != declared or pinned_files != delta["pinned_census"]["src_rs_files"]:
        raise RenderError(
            "census file count disagrees with the delta receipt: "
            f"census={pinned_files} declared={declared} "
            f"delta={delta['pinned_census']['src_rs_files']}"
        )
    rebuilt = dict(pinned)
    for key, value in change.items():
        rebuilt[key] = rebuilt.get(key, 0) + value
    total = sum(rebuilt.values())
    if total != combined["total"] or total != delta["current_tree"]["src_rs_files"]:
        raise RenderError(
            "census partition does not add up: "
            f"rebuilt={rebuilt} total={total} combined={combined} "
            f"current_tree={delta['current_tree']['src_rs_files']}"
        )
    for key, value in rebuilt.items():
        if combined.get(key) != value:
            raise RenderError(
                f"census partition mismatch for {key}: {combined.get(key)} != {value}"
            )
    return combined


def test_baseline(root: Path, candidate: dict) -> dict:
    """The last *full* library run, from its own evidence record.

    A publish receipt attests a release, not the test suite, and later
    commits add tests without a further full run, so a receipt is never a
    source for the count.  A missing or unusable baseline is rendered as
    UNKNOWN rather than back-filled from a receipt.

    The record carries the commit it was taken at, never the current git
    HEAD: if that commit is not the candidate's, the count is a floor, not
    the current total.
    """
    try:
        data = load_json(root / TEST_BASELINE)
        counts = {key: int(data[key]) for key in ("passed", "failed", "ignored")}
        commit = str(data["source_commit"])
        kind = str(data["kind"])
        observed = int(data.get("observed_total") or 0)
        observed_note = str(data.get("observed_total_note") or "")
        tree_unchanged = bool(data.get("source_tree_unchanged"))
        if kind != "full-library-run":
            raise ValueError(f"kind is {kind!r}, not 'full-library-run'")
    except (RenderError, KeyError, TypeError, ValueError) as exc:
        return {"unknown": True, "reason": str(exc) or "no usable record"}
    return {
        "unknown": False,
        "passed": counts["passed"],
        "failed": counts["failed"],
        "ignored": counts["ignored"],
        "source_commit": commit,
        "kind": kind,
        "floor": candidate.get("commit") != commit and not tree_unchanged,
        "tree_unchanged": tree_unchanged,
        "observed_total": observed,
        "observed_total_note": observed_note,
    }


def test_counts(tests: dict, verb: str = "passing") -> str:
    """The bare count, or UNKNOWN when no full run is on record."""
    if tests["unknown"]:
        return "**UNKNOWN**"
    return (
        f"**{tests['passed']:,} {verb}, {tests['failed']} failing, "
        f"{tests['ignored']} ignored**"
    )


def test_row(tests: dict, label: str, verb: str = "passing") -> str:
    """A complete table row for a library-test count."""
    if tests["unknown"]:
        result = (
            "**UNKNOWN** — no full library run is on record; a release "
            "receipt is not a test count"
        )
        evidence = f"`{TEST_BASELINE_S}` (absent or unusable)"
    else:
        result = test_counts(tests, verb)
        if tests["floor"]:
            result += (
                f" at `{tests['source_commit']}` — a **floor**, not the current "
                "count: later commits add tests without a further full run"
            )
        if tests.get("observed_total"):
            result += (
                f"; **{tests['observed_total']:,} total tests observed** on a later "
                "tree — a full-suite pass after the recorded commit is `NOT_RUN`"
            )
        evidence = f"`{TEST_BASELINE_S}` (`{tests['kind']}`)"
    return f"| {label} | {result} | {evidence} |"


def publish_identity(refresh: Path, root: Path, version: str, candidate: dict) -> dict:
    receipts = [load_json(p) for p in refresh.glob(PUBLISH_GLOB)]
    published = [r for r in receipts if r.get("status") == "PUBLISHED"]
    if not published:
        raise RenderError("no PUBLISHED receipt under atlas-refresh/")
    ordered = sorted(
        published, key=lambda r: (r.get("date", ""), r.get("version", ""))
    )
    latest = ordered[-1]
    previous = ordered[-2] if len(ordered) > 1 else None
    verification = latest.get("registry_verification") or {}
    artefacts = latest.get("artefacts") or {}
    published_version = latest.get("version", version)
    # A version string is not an identity: the working tree can carry a
    # published version number while containing later source changes.  Call
    # the tree the published crate only when every candidate library hash is
    # the hash recorded in the publish receipt.
    same_artefacts = all(
        str(artefacts.get(name) or "") == digest
        for name, digest in candidate.get("libs") or []
    )
    return {
        "version": published_version,
        "date": latest.get("date", ""),
        "checksum": verification.get("checksum_prefix", ""),
        "libcrypto": str(artefacts.get("libcrypto.so.3", ""))[:8],
        "libssl": str(artefacts.get("libssl.so.3", ""))[:8],
        "source": f"atlas-refresh/publish-{published_version}.json",
        "is_candidate": published_version == version and same_artefacts,
        "previous": (previous or {}).get("version", ""),
    }


def boundary_evidence(sweeps, status_json: dict) -> dict:
    independent, batch, author, scoped = [], [], [], []
    for number, name, data in sweeps:
        label = f"B{number}"
        graduation = data.get("graduation")
        state = graduation.get("state", "") if isinstance(graduation, dict) else ""
        if state == "BOUNDARY_INDEPENDENTLY_CHECKED":
            independent.append(label)
        elif state == "BATCH_INDEPENDENTLY_CHECKED":
            batch.append(label)
        elif state == "BATCH_AUTHOR_EVIDENCED":
            author.append(label)
        for boundary in data.get("boundaries") or []:
            if not isinstance(boundary, dict):
                continue
            disposition = str(boundary.get("disposition", ""))
            if disposition.startswith("SAFETY_DISCHARGED"):
                scoped.append((label, boundary.get("id", "?"), disposition))

    scoped_labels = sorted({label for label, _, _ in scoped})

    # Cross-check the receipt-derived classification against the campaign JSON.
    plane = status_json.get("independently_checked_plane") or []
    plane_states = {
        re.sub(r"^boundary-sweep-", "", str(entry.get("receipt", ""))): entry.get("state")
        for entry in plane
        if isinstance(entry, dict)
    }
    for label in independent + batch + author:
        expected = plane_states.get(label)
        if expected and expected != _state_for(label, independent, batch, author):
            raise RenderError(
                f"{label}: receipt state differs from CAMPAIGN-STATUS independently_checked_plane"
            )
    return {
        "independent": independent,
        "batch": batch,
        "author": author,
        "scoped": scoped_labels,
    }


def _state_for(label: str, independent, batch, author) -> str:
    if label in independent:
        return "BOUNDARY_INDEPENDENTLY_CHECKED"
    if label in batch:
        return "BATCH_INDEPENDENTLY_CHECKED"
    if label in author:
        return "BATCH_AUTHOR_EVIDENCED"
    return ""



def stop_class_defects(sweeps) -> list[dict]:
    """Find STOP-class defects in the receipts and derive whether they are open.

    A finding is open unless a receipt at or after its origin records the same id
    with a closing disposition (SAFETY_DISCHARGED / FIXED / CLOSED).
    """
    entries: dict[str, dict] = {}
    for number, name, data in sweeps:
        receipt = name.removeprefix("boundary-sweep-")
        for defect in data.get("defects") or []:
            if not isinstance(defect, dict):
                continue
            severity = str(defect.get("severity", "")).upper()
            if "STOP" not in severity:
                continue
            defect_id = str(defect.get("id", ""))
            disposition = str(defect.get("disposition", ""))
            entries.setdefault(
                defect_id,
                {
                    "id": defect_id,
                    "receipt": receipt,
                    "number": number,
                    "severity": severity,
                    "disposition": disposition,
                    "closed_by": receipt
                    if _closing(disposition)
                    else None,
                },
            )
        stop_status = str(data.get("stop_status", ""))
        for match in re.finditer(
            r"STOP[- ](?:CLASS|LEVEL)(.*?)(B\d+-X\d+|NEO-[A-Z]+-\d+)",
            stop_status,
            re.DOTALL,
        ):
            if re.search(r"\bOPEN\b|NOT REPAIRED|NEW STOP", match.group(0), re.IGNORECASE):
                defect_id = match.group(2)
                entries.setdefault(
                    defect_id,
                    {
                        "id": defect_id,
                        "receipt": receipt,
                        "number": number,
                        "severity": "STOP-CLASS",
                        "disposition": "OPEN",
                        "closed_by": None,
                    },
                )

    for entry in entries.values():
        if entry["closed_by"]:
            continue
        for number, name, data in sweeps:
            if number < entry["number"]:
                continue
            receipt = name.removeprefix("boundary-sweep-")
            for boundary in data.get("boundaries") or []:
                if not isinstance(boundary, dict):
                    continue
                if boundary.get("id") == entry["id"] and _closing(
                    str(boundary.get("disposition", ""))
                ):
                    entry["closed_by"] = receipt
                    entry["disposition"] = boundary.get("disposition", "")
                    break
            if entry["closed_by"]:
                break
            for defect in data.get("defects") or []:
                if not isinstance(defect, dict):
                    continue
                if defect.get("id") == entry["id"] and _closing(
                    str(defect.get("disposition", ""))
                ):
                    entry["closed_by"] = receipt
                    entry["disposition"] = defect.get("disposition", "")
                    break
    return sorted(entries.values(), key=lambda e: (e["number"], e["id"]))


def _closing(disposition: str) -> bool:
    return disposition.startswith(("SAFETY_DISCHARGED", "FIXED", "CLOSED"))


def compact(labels: list[str]) -> str:
    """B41,B42,B43 -> B41–B43; otherwise comma-separated."""
    if not labels:
        return "none"
    numbers = sorted(int(label[1:]) for label in labels)
    if numbers == list(range(numbers[0], numbers[-1] + 1)) and len(numbers) > 1:
        return f"B{numbers[0]}–B{numbers[-1]}"
    return ", ".join(f"B{n}" for n in numbers)


def plural(count: int, singular: str, plural_form: str | None = None) -> str:
    return f"{count} {singular if count == 1 else (plural_form or singular + 's')}"


class Evidence:
    def __init__(self, root: Path):
        self.root = root
        self.atlas = load_json(root / ATLAS)
        self.build_link = load_json(root / BUILD_LINK)
        self.status = load_json(root / STATUS_JSON)
        self.census = load_json(root / CENSUS)
        self.delta = load_json(root / DELTA)
        refresh = root / CAMPAIGN / "atlas-refresh"
        self.refresh = refresh
        self.sweeps = load_sweeps(refresh)
        self.candidate = candidate_identity(self.atlas)
        self.version = cargo_version(root)
        self.build = build_identity(refresh, self.version)
        self.families, self.cand_only, self.auth_only = family_names(self.atlas)
        self.partition = census_partition(self.census, self.delta)
        self.tests = test_baseline(root, self.build)
        self.publish = publish_identity(refresh, root, self.version, self.build)
        self.boundaries = boundary_evidence(self.sweeps, self.status)
        self.stop_defects = stop_class_defects(self.sweeps)
        self.mechanisms = [
            m
            for m in self.status.get("mechanism_discharges") or []
            if m.get("state") == "SAFETY_DISCHARGED"
        ]
        self.consumers = self.status["consumers"]
        self.reuse = self.atlas.get("body", {}).get("evidence_reuse") or {}
        self.gates = self.status.get("gates") or {}
        self.invariants = self.status.get("structural_invariants") or {}
        self.known_gaps = self.status.get("known_gaps") or []

    def evidence_reuse(self) -> dict:
        """The atlas's carried-forward disclosure, with the names as a set.

        ``body.evidence_reuse = null`` is the atlas's record of a full
        no-reuse run: every row was measured for this candidate, so there is
        nothing carried forward.  It is not the same state as a reuse block
        whose rows belong to a superseded identity.
        """
        if not self.reuse:
            return {
                "mode": "no-reuse",
                "reused": 0,
                "match": True,
                "names": set(),
                "full": True,
            }
        return {
            "mode": str(self.reuse.get("mode", "unknown")),
            "reused": int(self.reuse.get("families_reused", 0) or 0),
            "match": bool(self.reuse.get("candidate_identity_match", False)),
            "names": set(self.reuse.get("reused_families") or []),
            "full": False,
        }

    def gate_state(self, key: str) -> str:
        """A gate's recorded state, never a default PASS."""
        gate = self.gates.get(key) or {}
        return str(gate.get("state") or gate.get("result") or "UNKNOWN")

    # -- derived values -------------------------------------------------
    def counts(self) -> dict:
        return self.atlas["body"]["counts"]

    def corpus(self) -> dict:
        counts = self.counts()
        subject = counts["by_subject"]
        build = self.build_counts()
        if build["recipes"] != counts.get("with_recipe"):
            raise RenderError(
                "build-link and runtime atlases disagree on the recipe count: "
                f"build-link={build['recipes']} runtime={counts.get('with_recipe')}"
            )
        l4 = sum(
            1
            for run in self.atlas["body"]["runs"]
            if run.get("subject") == "candidate" and run.get("level") == "L4-linked"
        )
        return {
            "total": counts["p1000"],
            "recipes": build["recipes"],
            "built": build["built"],
            "linked": build["linked"],
            "no_recipe": counts.get("no_recipe", 0),
            "candidate": subject["candidate"]["functional"],
            "authority": subject["authority"]["functional"],
            "loaded": subject["candidate"]["loaded"],
            "l4": l4,
            "not_attempted": subject["candidate"]["not_attempted"],
            "failed": subject["candidate"]["failed"],
        }

    def build_counts(self) -> dict:
        counts = self.build_link.get("body", {}).get("counts") or {}
        candidate = (counts.get("by_subject") or {}).get("candidate") or {}
        return {
            "recipes": int(counts.get("with_recipe") or 0),
            "built": int(candidate.get("built") or 0),
            "linked": int(candidate.get("linked") or 0),
        }

    def audit(self) -> dict:
        return self.status.get("per_file_audit") or {}

    def open_stop(self) -> list[dict]:
        return [d for d in self.stop_defects if not d["closed_by"]]

    def l7_agreement(self) -> str:
        """The candidate/authority L7 comparison, including a measured asymmetry."""
        corpus = self.corpus()
        if not self.cand_only and not self.auth_only:
            return (
                "candidate and authority rows agree "
                f"({corpus['candidate']} = {corpus['authority']})"
            )
        parts = []
        if self.cand_only:
            parts.append(
                "candidate-only " + ", ".join(f"`{n}`" for n in self.cand_only)
            )
        if self.auth_only:
            parts.append(
                "authority-only " + ", ".join(f"`{n}`" for n in self.auth_only)
            )
        return (
            f"candidate {corpus['candidate']} / authority {corpus['authority']} "
            f"`L7-functional`; measured asymmetry: {'; '.join(parts)}"
        )

    def identity_text(self) -> str:
        bits = [
            f"candidate commit `{self.build['commit']}`",
            f"build source-tree digest `{self.build['tree']}`",
        ]
        if self.build["measured_tree"] and self.build["measured_tree"] != self.build["tree"]:
            bits.append(
                "measured source at that commit `"
                f"{self.build['measured_tree']}`; the build tree differs only in the "
                "`Cargo.toml`/`Cargo.lock` release-metadata fields"
            )
        release_tree = self.build["release_tree"]
        if release_tree and release_tree != self.build["tree"]:
            # The 0.0.44 packaging tree bumps Cargo.toml/Cargo.lock after S', and
            # the install was deliberately not rebuilt.  Say so on the identity
            # line itself, so a version string never sits next to hashes without a
            # machine-checked statement of which tree produced them.
            bits.append(
                f"release-tree digest `{release_tree}` (the packaging tree; within the "
                "digested build inputs it differs from the build tree only in "
                "`Cargo.toml`/`Cargo.lock`, and the library hashes below describe the "
                "build tree, not a rebuild at this version)"
            )
        if self.publish["is_candidate"]:
            bits.append(
                f"crate version `{self.version}` (**published** "
                f"{self.publish['date']}, checksum `{self.publish['checksum']}…`)"
            )
        else:
            bits.append(
                f"working-tree crate version `{self.version}` (**not published "
                "at this candidate identity**)"
            )
        bits.extend(
            f"`{name}` sha256 `{digest}`" for name, digest in self.build["libs"]
        )
        return "; ".join(bits)

    # -- blocks ---------------------------------------------------------
    def achievements(self) -> str:
        corpus = self.corpus()
        reuse = self.evidence_reuse()
        mechanisms = ", ".join(
            f"{m['id']} {m['mechanism']}".replace("shared reference counting", "refcounting")
            for m in self.mechanisms
        )
        audit = self.audit()
        partition = self.partition
        b = self.boundaries
        cohort = set(self.consumers.get("l7_families") or [])
        cohort_reused = len(cohort & reuse["names"])
        if reuse["match"]:
            freshness = "measured at the identity above"
            if reuse.get("full"):
                freshness = (
                    "measured at the identity above in a **full no-reuse run** "
                    "(`evidence_reuse = null`)"
                )
                reuse_text = (
                    "Downstream evidence reuse: **no carried-forward rows** "
                    "(`evidence_reuse = null`); every recipe-backed row was measured "
                    "at the candidate identity above."
                )
            elif reuse["reused"]:
                newly = corpus["recipes"] - reuse["reused"]
                freshness = (
                    "measured at the identity above; "
                    f"**{cohort_reused}/{len(cohort)} cohort rows reuse committed "
                    "measurements at that same identity**"
                )
                reuse_text = (
                    "Downstream evidence reuse: "
                    f"**{reuse['reused']} of {corpus['recipes']} recipe-backed "
                    f"families reuse committed rows at the same candidate identity** "
                    f"(`{reuse['mode']}`, `candidate_identity_match=true`); "
                    f"{plural(newly, 'family', 'families')} "
                    f"{'was' if newly == 1 else 'were'} newly measured in the latest "
                    "batch. A reused row is still a measurement at the identity above, "
                    "but it was not re-run in that batch. The Safe-33 cohort has "
                    f"{cohort_reused}/{len(cohort)} of its families in the reused set."
                )
            else:
                reuse_text = (
                    "Downstream evidence reuse: **no carried-forward rows** "
                    "(`candidate_identity_match=true`); these rows are measured at the "
                    "identity above."
                )
        else:
            freshness = (
                f"**carried forward** — {cohort_reused}/{len(cohort)} cohort rows are in "
                "`evidence_reuse.reused_families` and "
                "`candidate_identity_match=false`"
            )
            reuse_text = (
                "Downstream evidence reuse: "
                f"**{reuse['reused']} of {corpus['recipes']} recipe-backed families "
                f"carried forward** (`{reuse['mode']}`); `candidate_identity_match` = "
                "`false`. A carried-forward row is compatibility evidence from the "
                "build recorded on that row, not a fresh measurement at the identity "
                f"above. The Safe-33 cohort has {cohort_reused}/{len(cohort)} of its "
                "families in that set."
            )
        reuse_cell = (
            f"{reuse['reused']} of {corpus['recipes']} rows reuse committed "
            "measurements at the same identity"
            if reuse["match"] and not reuse.get("full")
            else (
                "no carried-forward rows (full no-reuse measurement)"
                if reuse["match"]
                else f"{reuse['reused']} of {corpus['recipes']} recipe-backed rows carried "
                     "forward"
            )
        )
        gap_bits = "; ".join(
            f"`{g.get('id', '?')}` {g.get('status', '?')}" for g in self.known_gaps
        )
        invariants = ", ".join(
            f"`{key}`" for key in sorted(self.invariants) if key != "source"
        )
        return "\n".join(
            [
                f"Source identity: {self.identity_text()}. Derived by "
                "`forensics/tools/render_docs.py`; `--check` fails if a block and "
                "its evidence disagree.",
                "",
                "| Dimension | Result | Evidence |",
                "|---|---|---|",
                "| **Downstream drop-in, Safe-33 cohort** | "
                f"**{self.consumers['l7_functional']} / {self.consumers['families_total']} "
                f"families at `L7-functional`**, candidate and authority; {freshness} | "
                f"`{ATLAS_S}` (`body.runs`); `{STATUS_S}` (`consumers`) |",
                "| **Downstream drop-in, 1000-family corpus** | "
                f"**{corpus['candidate']} / {corpus['total']} at `L7-functional`**; "
                f"{self.l7_agreement()}; "
                f"**{corpus['recipes']} recipes, {corpus['built']} built, {corpus['linked']} linked**; "
                f"{corpus['loaded']} loaded, {corpus['l4']} `L4-linked`, "
                f"{corpus['failed']} failed, {corpus['not_attempted']} not attempted "
                f"({corpus['no_recipe']} with no recipe); {reuse_cell} | "
                f"same atlas, `body.counts.by_subject`, `body.evidence_reuse`; "
                f"`{BUILD_LINK_S}` |",
                test_row(self.tests, "**Library test suite**"),
                "| **Memory safety: mechanisms** | "
                f"**{plural(len(self.mechanisms), 'mechanism')} discharged at mechanism scope** "
                f"— {mechanisms} | `{STATUS_S}` (`mechanism_discharges`) |",
                "| **Memory safety: boundaries** | "
                f"{plural(len(b['scoped']), 'scoped boundary discharge')} "
                f"({compact(b['scoped'])}); "
                f"**{compact(b['independent'])} independently checked**; "
                f"{compact(b['batch'])} batch-checked; "
                f"{compact(b['author'])} author-evidenced | "
                "`atlas-refresh/boundary-sweep-*.json` |",
                "| **Memory safety: files converted / partial** | "
                f"**{partition['total']} files**: {partition['ZERO_UNSAFE']} `ZERO_UNSAFE`, "
                f"{partition['BOUNDARY_COVERED']} `BOUNDARY_COVERED`, "
                f"{partition['PARTIAL']} `PARTIAL` "
                f"(audited {audit.get('audited', '?')}/{audit.get('partial_total', '?')}), "
                f"{partition['TEST_ONLY']} `TEST_ONLY`, "
                f"**{self.delta['unaccounted_files']} unaccounted** | "
                f"`{CENSUS_S}`, `{DELTA_S}` |",
                "| **`SAFE_COMPATIBLE` consumers** | "
                f"**{self.consumers['safe_compatible']} / {self.consumers['families_total']}** "
                "— no family has a proven dependency closure | "
                f"`{STATUS_S}` (`consumers`) |",
                "| **BOUNDARY / SEAL gates** | "
                f"**`{self.gate_state('boundary_gate')}` / `{self.gate_state('seal_gate')}`** "
                "— no independent caller/dependency-closure audit, Miri/ASan/Loom/mutation "
                "control, authority differential, full forensic regeneration or held-out "
                "compatibility for the S16–S61 cluster | "
                f"`{STATUS_S}` (`gates.boundary_gate`, `gates.seal_gate`) |",
                "| **Allocator / ABI invariants** | "
                f"**preserved** — recorded invariant planes: {invariants or 'none recorded'} | "
                f"`{STATUS_S}` (`structural_invariants`) |",
                "| **Known gaps** | " + (gap_bits or "none recorded") + " | "
                f"`{STATUS_S}` (`known_gaps`) |",
                "| **Release** | " + self.release_text() + " | "
                f"`{self.publish['source']}`; `Cargo.toml` |",
                "",
                reuse_text,
            ]
        )

    def release_text(self) -> str:
        """The published release, and whether it is the candidate tree itself.

        The published version and the tree version are separate facts. When a
        publish receipt names the tree version *and* the build receipt's
        library hashes are the receipt's, the tree is released and the row says
        so instead of repeating a stale "not published" claim.  The row also
        states what the crate payload contains: source and documentation only.
        The install-tree hashes describe a repository build, never the payload.
        """
        published = (
            f"**Published: {self.publish['version']}** on crates.io "
            f"({self.publish['date']}), checksum `{self.publish['checksum']}…`, "
            f"install-tree artefacts `libcrypto.so.3` `{self.publish['libcrypto']}…` / "
            f"`libssl.so.3` `{self.publish['libssl']}…`."
        )
        payload = (
            " The published crate ships **source and documentation only, with no "
            "binaries**; those install-tree hashes describe the repository build "
            "recorded in the receipt, not the crate payload."
        )
        previous = (
            f" {self.publish['previous']} remains the previous release."
            if self.publish["previous"]
            else ""
        )
        if self.publish["is_candidate"]:
            return (
                f"{published}{payload} This evidence is bound to the {self.version} "
                f"tree, which is the published {self.publish['version']} crate.{previous}"
            )
        return (
            f"{published}{payload} **Working tree: {self.version} — the candidate, "
            "not yet published.** This evidence is bound to the "
            f"{self.version} tree, not to the published "
            f"{self.publish['version']} crate.{previous}"
        )

    def l7_families(self) -> str:
        corpus = self.corpus()
        reuse = self.evidence_reuse()
        cohort = set(self.consumers.get("l7_families") or [])
        carried = [name for name in self.families if name in reuse["names"]]
        marker = "" if reuse["match"] else "†"
        listed = ", ".join(
            f"`{name}`" + (marker if name in reuse["names"] else "")
            for name in self.families
        )
        not_carried = sorted(set(self.families) - reuse["names"])
        if reuse.get("full"):
            uncovered = ""
        elif reuse["match"]:
            uncovered = (
                f" Newly measured in the latest batch: "
                f"{', '.join(f'`{n}`' for n in not_carried)}."
                if not_carried
                else ""
            )
        else:
            uncovered = (
                f" Not in that list: {', '.join(f'`{n}`' for n in not_carried)}; the "
                "atlas-level `candidate_identity_match=false` still applies, so it is not "
                "claimed as a fresh measurement at the identity above."
                if not_carried
                else ""
            )
        if reuse.get("full"):
            freshness = (
                "**Freshness:** `evidence_reuse = null`; all "
                f"{len(self.families)} listed rows were measured at the candidate "
                "identity above in the latest full no-reuse run."
            )
        elif reuse["match"]:
            freshness = (
                "**Freshness:** `candidate_identity_match=true`; "
                f"{len(carried)} of {len(self.families)} listed rows reuse committed "
                "measurements at the identity above. Reused rows are measurements at "
                "that identity, not rows carried forward from a different candidate. "
                "The Safe-33 cohort has "
                f"{len(cohort & reuse['names'])}/{len(cohort)} of its families in the "
                "reused set." + uncovered
            )
        else:
            freshness = (
                f"**† carried forward:** {len(carried)} of {len(self.families)} listed "
                f"rows are in `evidence_reuse.reused_families` (`{reuse['mode']}`, "
                "`candidate_identity_match=false`); they were not re-measured at the "
                "identity above. The Safe-33 cohort has "
                f"{len(cohort & reuse['names'])}/{len(cohort)} of its families in the same "
                "carried-forward set." + uncovered
            )
        return "\n".join(
            [
                f"**{len(self.families)} of {corpus['total']} counted corpus families are "
                "`L7-functional`** — " + self.l7_agreement() + "; "
                f"{corpus['failed']} failed, "
                f"{corpus['loaded']} loaded, {corpus['recipes']} recipes, "
                f"{corpus['not_attempted']} not attempted.",
                "",
                listed + ".",
                "",
                freshness,
            ]
        )

    def memory_safety(self) -> str:
        b = self.boundaries
        audit = self.audit()
        partition = self.partition
        uninit = self.status.get("uninitialised_storage_census") or {}
        mechanisms = "; ".join(
            f"{m['id']} {m['mechanism']}" for m in self.mechanisms
        )
        open_defects = self.open_stop()
        if self.stop_defects:
            stop_bits = []
            for defect in self.stop_defects:
                if defect["closed_by"]:
                    where = (
                        f"fixed in {defect['closed_by']}"
                        if defect["closed_by"] == defect["receipt"]
                        else f"closed by {defect['closed_by']}"
                    )
                    stop_bits.append(
                        f"`{defect['id']}` (`{defect['severity']}`, "
                        f"{defect['receipt']}) **{where}**"
                    )
                else:
                    stop_bits.append(
                        f"`{defect['id']}` (`{defect['severity']}`, "
                        f"{defect['receipt']}) **OPEN**"
                    )
            stop_text = (
                f"**{len(open_defects)} open** — " + "; ".join(stop_bits)
                if open_defects
                else "**0 open** — " + "; ".join(stop_bits)
            )
        else:
            stop_text = "**none found in the receipts**"

        open_mechanisms = sorted(
            {
                str(entry.get("mechanism"))
                for entry in self.status.get("independently_checked_plane") or []
                if entry.get("mechanism") and not entry.get("safety_discharged")
            }
        )
        not_discharged = (
            "Receipt-backed mechanisms still open: "
            + ", ".join(f"`{name}`" for name in open_mechanisms)
            + "; `SAFE_COMPATIBLE` remains "
            + f"{self.consumers['safe_compatible']}/{self.consumers['families_total']}."
            if open_mechanisms
            else "No incomplete mechanism is recorded in the independently checked plane."
        )

        scoped: dict[str, list[str]] = {}
        for label, ident in _scoped_pairs(self.sweeps):
            scoped.setdefault(label, []).append(ident)
        scoped_text = (
            ", ".join(
                f"{label} (" + ", ".join(f"`{i}`" for i in ids) + ")"
                for label, ids in scoped.items()
            )
            if scoped
            else "none"
        )
        retained = uninit.get("retained") or []
        uninit_text = (
            f"**{uninit.get('unsound_total_fixed', '?')} UNSOUND fixed** "
            f"({uninit.get('unsound_owner_shaped', '?')} owner-shaped + "
            f"{uninit.get('unsound_frame_local_same_shape', '?')} frame-local), from "
            f"{uninit.get('owner_shaped_examined', '?')} owner-shaped entries examined; "
            f"{uninit.get('safe_by_construction', '?')} safe-by-construction and "
            f"{uninit.get('misuse_resistant', '?')} misuse-resistant. "
            f"{uninit.get('class_status', '')} Retained: "
            + "; ".join(r.rstrip(".") for r in retained[:3])
        )
        gap_bits = "; ".join(
            f"`{g.get('id', '?')}` {g.get('status', '?')}" for g in self.known_gaps
        )

        return "\n".join(
            [
                "| Status | What it covers |",
                "|---|---|",
                "| **Discharged (mechanism scope)** | "
                f"**{len(self.mechanisms)}** — {mechanisms}. Mechanism scope only; "
                "not a file-level or consumer-level graduation. |",
                "| **Discharged (scoped boundary)** | "
                f"**{plural(len(b['scoped']), 'receipt')}** — {scoped_text}. Retained "
                "boundaries stay `CONTRACTED`. |",
                "| **Independently checked (not discharged)** | "
                f"{compact(b['independent'])} boundary-checked "
                "(memory-BIO constructor/destructor, connect-BIO descriptor); "
                f"{compact(b['batch'])} batch-checked; "
                f"{compact(b['author'])} **author-evidenced only**. |",
                "| **Uninitialised-storage class** | " + uninit_text + " |",
                f"| **STOP-class defects** | {stop_text}. |",
                "| **Audited but not converted** | "
                f"**{partition['PARTIAL']} `PARTIAL` files**; "
                f"{audit.get('audited', '?')}/{audit.get('partial_total', '?')} "
                f"audited, {audit.get('remaining', '?')} remaining. "
                "Audit completion is not discharge. |",
                "| **Not discharged** | " + not_discharged + " |",
                "| **BOUNDARY / SEAL gates** | "
                f"**`{self.gate_state('boundary_gate')}` / `{self.gate_state('seal_gate')}`** "
                "— the S16–S61 cluster has no independent caller/dependency-closure audit, "
                "Miri/ASan/Loom/mutation control, authority differential, full forensic "
                "regeneration or held-out compatibility. |",
                "| **Known gaps** | " + (gap_bits or "none recorded") + " |",
                "| **`SAFE_COMPATIBLE` consumers** | "
                f"**{self.consumers['safe_compatible']} / {self.consumers['families_total']}** "
                "— no consumer family has a proven dependency closure. |",
            ]
        )

    def status_mechanisms(self) -> str:
        rows = [
            "| id | mechanism | source | state | evidence |",
            "|---|---|---|---|---|",
        ]
        for m in self.status.get("mechanism_discharges") or []:
            evidence = ", ".join(f"`{e}`" for e in (m.get("evidence") or []))
            rows.append(
                f"| {m.get('id', '?')} | {m.get('mechanism', '?')} | "
                f"`{m.get('source', '?')}` | {m.get('state', '?')} | {evidence} |"
            )
        return "\n".join(rows)

    def status_subphase_outcomes(self) -> str:
        rows = ["| subphase | outcome | evidence |", "|---|---|---|"]
        for s in self.status.get("subphase_outcomes") or []:
            rows.append(
                f"| {s.get('subphase', '?')} | {s.get('outcome', '?')} | "
                f"`{s.get('evidence', '?')}` |"
            )
        return "\n".join(rows)

    def status_reduction_census(self) -> str:
        r = self.status.get("reduction_census") or {}
        if not r:
            return (
                "**UNKNOWN** — no reduction census is recorded in "
                "`CAMPAIGN-STATUS.json`."
            )
        return "\n".join(
            [
                "| class | count | state |",
                "|---|---|---|",
                f"| BENIGN | {r['benign']} | no behaviour removed |",
                f"| DIVERGENCE | {r['divergence']} | explicit, compatibility "
                "consequence recorded |",
                f"| LATENT REGRESSION | {r['latent_regression']} | "
                f"{r.get('latent_repaired_before_census', '?')} repaired before the "
                f"census; {r.get('latent_closed_by_s20', '?')} closed by S20; "
                f"**{r.get('latent_open_now', '?')} open now** |",
                "",
                f"Highest-scoring open entry at the census: "
                f"{r.get('highest_score_open_at_census', '?')}. Source: "
                f"`{r.get('artifact', '?')}`. {r.get('note', '')}",
            ]
        )

    def status_evidence(self) -> str:
        corpus = self.corpus()
        reuse = self.evidence_reuse()
        mechanisms = ", ".join(m["id"] for m in self.mechanisms)
        partition = self.partition
        invariants = ", ".join(
            f"`{key}`" for key in sorted(self.invariants) if key != "source"
        )
        return "\n".join(
            [
                "| item | current value | source |",
                "|---|---|---|",
                f"| candidate identity | {self.identity_text()} | "
                f"`{self.build['source']}`; `Cargo.toml` |",
                "| working-tree version | "
                + (
                    f"**{self.version}** — **published** on crates.io "
                    f"({self.publish['date']}, checksum "
                    f"`{self.publish['checksum']}…`) | `Cargo.toml`; "
                    f"`{self.publish['source']}` |"
                    if self.publish["is_candidate"]
                    else f"**{self.version}** — **not published at this candidate "
                    "identity** | `Cargo.toml` |"
                ),
                "| published release | "
                f"**{self.publish['version']}** on crates.io ({self.publish['date']}, "
                f"checksum `{self.publish['checksum']}…`), install-tree artefacts "
                f"`libcrypto.so.3` `{self.publish['libcrypto']}…` / "
                f"`libssl.so.3` `{self.publish['libssl']}…`; the crate payload is "
                "source and documentation only, with no binaries | "
                f"`{self.publish['source']}` |",
                "| evidence binding | "
                + (
                    f"the evidence in this table is bound to the "
                    f"**{self.version} tree**, which is the published "
                    f"{self.publish['version']} crate; downstream rows are bound to "
                    "the candidate identity recorded in the atlas | this document; "
                    f"`{ATLAS_S}` (`body.candidate_identity`, "
                    "`body.evidence_reuse`) |"
                    if self.publish["is_candidate"]
                    else (
                        "the evidence in this table is bound to the "
                        f"**{self.version} tree**, not to the published "
                        f"{self.publish['version']} crate; downstream rows are bound "
                        "to the candidate identity recorded in the atlas | this "
                        f"document; `{ATLAS_S}` (`body.candidate_identity`, "
                        "`body.evidence_reuse`) |"
                    )
                ),
                test_row(self.tests, "library tests", verb="passed"),
                "| cohort | "
                f"**{self.consumers['l7_functional']}/{self.consumers['families_total']}** "
                "at `L7-functional` | `" + ATLAS_S + "` (`body.runs`) |",
                "| corpus (1000 families) | "
                f"{corpus['candidate']} candidate / {corpus['authority']} authority "
                f"`L7-functional`; {corpus['recipes']} recipes, {corpus['built']} built, "
                f"{corpus['linked']} linked; {corpus['loaded']} loaded, {corpus['l4']} `L4-linked`, "
                f"{corpus['failed']} failed, {corpus['not_attempted']} not attempted "
                f"({corpus['no_recipe']} with no recipe) | "
                f"`{ATLAS_S}` (`body.counts.by_subject`); `{BUILD_LINK_S}` |",
                "| downstream evidence reuse | "
                + (
                    "no carried-forward rows (`evidence_reuse = null`); all "
                    f"{corpus['recipes']} recipe-backed families were measured at this "
                    "candidate identity | same atlas, `body.evidence_reuse` |"
                    if reuse.get("full")
                    else (
                        f"{reuse['reused']} of {corpus['recipes']} recipe-backed "
                        + (
                            "families reuse committed rows at the same identity "
                            if reuse["match"]
                            else "families are carried forward from the superseded "
                                 "identity "
                        )
                        + f"(`{reuse['mode']}`); `candidate_identity_match` = "
                        f"`{str(reuse['match']).lower()}` | same atlas, "
                        "`body.evidence_reuse` |"
                    )
                ),
                "| `SAFE_COMPATIBLE` consumers | "
                f"**{self.consumers['safe_compatible']}/{self.consumers['families_total']}** | "
                f"`{STATUS_S}` (`consumers`) |",
                "| mechanisms `SAFETY_DISCHARGED` | "
                f"**{len(self.mechanisms)}**: {mechanisms} | "
                f"`{STATUS_S}` (`mechanism_discharges`) |",
                "| file census | "
                f"**{partition['total']} files**: {partition['ZERO_UNSAFE']} `ZERO_UNSAFE`, "
                f"{partition['BOUNDARY_COVERED']} `BOUNDARY_COVERED`, "
                f"{partition['PARTIAL']} `PARTIAL`, {partition['TEST_ONLY']} `TEST_ONLY`; "
                f"{self.delta['unaccounted_files']} unaccounted | "
                f"`{CENSUS_S}`; `{DELTA_S}` |",
                "| BOUNDARY / SEAL gates | "
                f"**`{self.gate_state('boundary_gate')}` / `{self.gate_state('seal_gate')}`** | "
                f"`{STATUS_S}` (`gates`) |",
                "| allocator / ABI invariants | "
                f"**preserved** — {invariants or 'none recorded'} | "
                f"`{STATUS_S}` (`structural_invariants`) |",
            ]
        )

    def blocks(self) -> dict[str, str]:
        return {
            "readme-achievements": self.achievements(),
            "readme-l7-families": self.l7_families(),
            "readme-memory-safety": self.memory_safety(),
            "status-current-evidence": self.status_evidence(),
            "status-mechanisms": self.status_mechanisms(),
            "status-subphase-outcomes": self.status_subphase_outcomes(),
            "status-reduction-census": self.status_reduction_census(),
        }


def _scoped_pairs(sweeps):
    for number, name, data in sweeps:
        for boundary in data.get("boundaries") or []:
            if isinstance(boundary, dict) and str(
                boundary.get("disposition", "")
            ).startswith("SAFETY_DISCHARGED"):
                yield f"B{number}", boundary.get("id", "?")


BEGIN = "<!-- BEGIN GENERATED: {name} -->"
END = "<!-- END GENERATED: {name} -->"


def block_pattern(name: str) -> re.Pattern:
    return re.compile(
        re.escape(BEGIN.format(name=name))
        + r"(.*?)"
        + re.escape(END.format(name=name)),
        re.DOTALL,
    )


def replace_blocks(path: Path, blocks: dict[str, str], names: list[str]) -> str:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise RenderError(f"missing document: {path}") from exc
    for name in names:
        pattern = block_pattern(name)
        matches = pattern.findall(text)
        begin_count = text.count(BEGIN.format(name=name))
        end_count = text.count(END.format(name=name))
        if begin_count != 1 or end_count != 1 or len(matches) != 1:
            raise RenderError(
                f"{path}: marker pair '{name}' must appear exactly once "
                f"(BEGIN={begin_count}, END={end_count}, pairs={len(matches)})"
            )
        replacement = (
            BEGIN.format(name=name)
            + "\n"
            + blocks[name].strip("\n")
            + "\n"
            + END.format(name=name)
        )
        text = pattern.sub(lambda _m: replacement, text, count=1)
    return text


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="report drift, write nothing")
    mode.add_argument("--write", action="store_true", help="rewrite the marked blocks")
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[2],
        help="repository root (default: derived from this script's path)",
    )
    args = parser.parse_args(argv)
    root = args.root.resolve()

    try:
        evidence = Evidence(root)
        blocks = evidence.blocks()
        rendered = {
            path: replace_blocks(
                root / path,
                blocks,
                [name for name, dest in BLOCKS.items() if dest == path],
            )
            for path in sorted(set(BLOCKS.values()), key=str)
        }
    except RenderError as exc:
        print(f"render_docs: ERROR: {exc}", file=sys.stderr)
        return 2

    drift = []
    for path, new_text in rendered.items():
        current = (root / path).read_text(encoding="utf-8")
        if current == new_text:
            continue
        names = [name for name, dest in BLOCKS.items() if dest == path]
        changed = [
            name
            for name in names
            if block_pattern(name).findall(current) != block_pattern(name).findall(new_text)
        ]
        drift.append((path, changed or names))

    if args.check:
        if drift:
            for path, names in drift:
                print(f"DRIFT: {path}: {', '.join(names)}")
            return 1
        print("render_docs: clean — all generated blocks match their evidence")
        return 0

    for path, new_text in rendered.items():
        (root / path).write_text(new_text, encoding="utf-8")
        names = [name for name, dest in BLOCKS.items() if dest == path]
        print(f"wrote {path} ({', '.join(names)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
