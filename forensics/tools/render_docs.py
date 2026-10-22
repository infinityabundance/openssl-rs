#!/usr/bin/env python3
"""Render the evidence-derived documentation blocks.

Reads only machine-readable evidence and rewrites only the text between
``<!-- BEGIN GENERATED: <name> -->`` / ``<!-- END GENERATED: <name> -->``
markers.  ``--check`` regenerates in memory, writes nothing, and exits non-zero
if any rendered block differs from the committed copy.

Evidence inputs (no others):

* ``forensics/downstream/runtime-functional-atlas.json``
* ``forensics/memory-safety/campaign/safe-c33/CAMPAIGN-STATUS.json``
* ``forensics/memory-safety/campaign/safe-c33/atlas-refresh/unsafe-census.json``
* ``forensics/memory-safety/campaign/safe-c33/atlas-refresh/post-census-delta.json``
* ``forensics/memory-safety/campaign/safe-c33/atlas-refresh/boundary-sweep-*.json``
* ``Cargo.toml`` and ``atlas-refresh/publish-*.json``
* ``body.candidate_identity`` (candidate library hashes / commit)

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
CENSUS = CAMPAIGN / "atlas-refresh/unsafe-census.json"
DELTA = CAMPAIGN / "atlas-refresh/post-census-delta.json"
STATUS_JSON = CAMPAIGN / "CAMPAIGN-STATUS.json"
SWEEP_GLOB = "boundary-sweep-*.json"
PUBLISH_GLOB = "publish-*.json"

# Display names used in the rendered blocks (repo-relative, short).
ATLAS_S = "forensics/downstream/runtime-functional-atlas.json"
STATUS_S = "CAMPAIGN-STATUS.json"
CENSUS_S = "atlas-refresh/unsafe-census.json"
DELTA_S = "atlas-refresh/post-census-delta.json"

README = Path("README.md")
STATUS_DOC = CAMPAIGN / "STATUS-2026-10-20.md"

# block name -> destination file
BLOCKS = {
    "readme-achievements": README,
    "readme-l7-families": README,
    "readme-memory-safety": README,
    "status-current-evidence": STATUS_DOC,
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


def family_names(atlas: dict) -> list[str]:
    runs = atlas["body"]["runs"]
    levels: dict[tuple[str, str], set[str]] = {"candidate": set(), "authority": set()}
    for run in runs:
        if run.get("subject") not in levels:
            continue
        if run.get("level") == "L7-functional":
            levels[run["subject"]].add(run["family_id"].split(":", 1)[-1])
    cand, auth = levels["candidate"], levels["authority"]
    if cand != auth:
        raise RenderError(
            "candidate/authority L7 family sets differ: "
            f"candidate-only={sorted(cand - auth)} authority-only={sorted(auth - cand)}"
        )
    return sorted(cand)


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


TEST_RE = re.compile(r"(\d[\d,]*)\s+passed[^0-9]{0,40}?(\d[\d,]*)\s+failed[^0-9]{0,40}?(\d[\d,]*)\s+ignored")


def as_int(text: str) -> int:
    return int(text.replace(",", ""))


def test_evidence(refresh: Path, root: Path) -> dict:
    """Most recent *committed receipt* that states a library test count."""
    candidates: list[tuple[str, int, str, tuple[int, int, int]]] = []
    for path in refresh.glob(PUBLISH_GLOB):
        data = load_json(path)
        identity = data.get("evidence_at_this_identity") or {}
        text = identity.get("library_tests")
        if isinstance(text, str):
            match = TEST_RE.search(text)
            if match:
                candidates.append(
                    (
                        data.get("date", ""),
                        1,
                        f"atlas-refresh/{path.name}",
                        tuple(as_int(g) for g in match.groups()),
                    )
                )
    for number, name, data in load_sweeps(refresh):
        for control in data.get("controls") or []:
            if not isinstance(control, dict):
                continue
            observed = control.get("observed")
            if not isinstance(observed, str):
                continue
            if "test" not in str(control.get("instrument", "")).lower():
                continue
            if "lib" not in str(control.get("instrument", "")):
                continue
            match = TEST_RE.search(observed)
            if match:
                candidates.append(
                    (
                        data.get("date", ""),
                        0,
                        f"atlas-refresh/{name}.json",
                        tuple(as_int(g) for g in match.groups()),
                    )
                )
                break
    if not candidates:
        raise RenderError("no receipt states a library test count")
    date, _, source, (passed, failed, ignored) = max(candidates)
    return {
        "date": date,
        "source": source,
        "passed": passed,
        "failed": failed,
        "ignored": ignored,
    }


def publish_identity(refresh: Path, root: Path, version: str) -> dict:
    receipts = [load_json(p) for p in refresh.glob(PUBLISH_GLOB)]
    published = [r for r in receipts if r.get("status") == "PUBLISHED"]
    if not published:
        raise RenderError("no PUBLISHED receipt under atlas-refresh/")
    latest = max(published, key=lambda r: (r.get("date", ""), r.get("version", "")))
    verification = latest.get("registry_verification") or {}
    return {
        "version": latest.get("version", version),
        "date": latest.get("date", ""),
        "checksum": verification.get("checksum_prefix", ""),
        "source": f"atlas-refresh/publish-{latest.get('version', version)}.json",
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
        self.status = load_json(root / STATUS_JSON)
        self.census = load_json(root / CENSUS)
        self.delta = load_json(root / DELTA)
        refresh = root / CAMPAIGN / "atlas-refresh"
        self.refresh = refresh
        self.sweeps = load_sweeps(refresh)
        self.candidate = candidate_identity(self.atlas)
        self.version = cargo_version(root)
        self.families = family_names(self.atlas)
        self.partition = census_partition(self.census, self.delta)
        self.tests = test_evidence(refresh, root)
        self.publish = publish_identity(refresh, root, self.version)
        self.boundaries = boundary_evidence(self.sweeps, self.status)
        self.stop_defects = stop_class_defects(self.sweeps)
        self.mechanisms = [
            m
            for m in self.status.get("mechanism_discharges") or []
            if m.get("state") == "SAFETY_DISCHARGED"
        ]
        self.consumers = self.status["consumers"]

    # -- derived values -------------------------------------------------
    def counts(self) -> dict:
        return self.atlas["body"]["counts"]

    def corpus(self) -> dict:
        counts = self.counts()
        subject = counts["by_subject"]
        return {
            "total": counts["p1000"],
            "candidate": subject["candidate"]["functional"],
            "authority": subject["authority"]["functional"],
            "loaded": subject["candidate"]["loaded"],
            "not_attempted": subject["candidate"]["not_attempted"],
            "failed": subject["candidate"]["failed"],
        }

    def audit(self) -> dict:
        return self.status.get("per_file_audit") or {}

    def open_stop(self) -> list[dict]:
        return [d for d in self.stop_defects if not d["closed_by"]]

    def identity_text(self) -> str:
        bits = []
        if self.candidate["commit"]:
            bits.append(f"candidate commit `{self.candidate['commit']}`")
        bits.append(f"crate version `{self.version}`")
        bits.extend(
            f"`{name}` sha256 `{digest}`" for name, digest in self.candidate["libs"]
        )
        return "; ".join(bits)

    # -- blocks ---------------------------------------------------------
    def achievements(self) -> str:
        corpus = self.corpus()
        mechanisms = ", ".join(
            f"{m['id']} {m['mechanism']}".replace("shared reference counting", "refcounting")
            for m in self.mechanisms
        )
        audit = self.audit()
        partition = self.partition
        b = self.boundaries
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
                "families at `L7-functional`**, candidate and authority | "
                f"`{ATLAS_S}` (`body.runs`) |",
                "| **Downstream drop-in, 1000-family corpus** | "
                f"**{corpus['candidate']} / {corpus['total']} at `L7-functional`**; "
                f"candidate {corpus['candidate']} = authority {corpus['authority']}; "
                f"**{corpus['failed']} failed**; {corpus['loaded']} loaded; "
                f"{corpus['not_attempted']} not attempted | same atlas, "
                "`body.counts.by_subject` |",
                "| **Library test suite** | "
                f"**{self.tests['passed']:,} passing, {self.tests['failed']} failing, "
                f"{self.tests['ignored']} ignored** | `{self.tests['source']}` |",
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
                "| **Memory safety: file census** | "
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
                "| **Release** | "
                f"**{self.publish['version']}** on crates.io ({self.publish['date']}), "
                f"checksum `{self.publish['checksum']}…` | "
                f"`{self.publish['source']}` |",
            ]
        )

    def l7_families(self) -> str:
        corpus = self.corpus()
        listed = ", ".join(f"`{name}`" for name in self.families)
        return "\n".join(
            [
                f"**{len(self.families)} of {corpus['total']} counted corpus families are "
                "`L7-functional`** — candidate and authority rows agree "
                f"({corpus['candidate']} = {corpus['authority']}); {corpus['failed']} failed, "
                f"{corpus['loaded']} loaded, {corpus['not_attempted']} not attempted.",
                "",
                listed + ".",
            ]
        )

    def memory_safety(self) -> str:
        b = self.boundaries
        audit = self.audit()
        partition = self.partition
        mechanisms = "; ".join(
            f"{m['id']} {m['mechanism']}" for m in self.mechanisms
        )
        closed = [d for d in self.stop_defects if d["closed_by"]]
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
                f"| **STOP-class defects** | {stop_text}. |",
                "| **Audited but not converted** | "
                f"**{partition['PARTIAL']} `PARTIAL` files**; "
                f"{audit.get('audited', '?')}/{audit.get('partial_total', '?')} "
                f"audited, {audit.get('remaining', '?')} remaining. "
                "Audit completion is not discharge. |",
                "| **Not discharged** | " + not_discharged + " |",
                "| **`SAFE_COMPATIBLE` consumers** | "
                f"**{self.consumers['safe_compatible']} / {self.consumers['families_total']}** "
                "— no consumer family has a proven dependency closure. |",
            ]
        )

    def status_evidence(self) -> str:
        corpus = self.corpus()
        mechanisms = ", ".join(m["id"] for m in self.mechanisms)
        partition = self.partition
        return "\n".join(
            [
                "| item | current value | source |",
                "|---|---|---|",
                f"| candidate identity | {self.identity_text()} | "
                f"`{ATLAS_S}` (`body.candidate_identity`); `Cargo.toml` |",
                "| version / release | "
                f"**{self.publish['version']}** published to crates.io "
                f"({self.publish['date']}, checksum `{self.publish['checksum']}…`) | "
                f"`Cargo.toml`; `{self.publish['source']}` |",
                "| library tests | "
                f"**{self.tests['passed']:,} passed / {self.tests['failed']} failed / "
                f"{self.tests['ignored']} ignored** | `{self.tests['source']}` |",
                "| cohort | "
                f"**{self.consumers['l7_functional']}/{self.consumers['families_total']}** "
                "at `L7-functional` | `" + ATLAS_S + "` (`body.runs`) |",
                "| corpus (1000 families) | "
                f"{corpus['candidate']} candidate / {corpus['authority']} authority "
                f"`L7-functional`; {corpus['loaded']} loaded; "
                f"{corpus['not_attempted']} not attempted; {corpus['failed']} failed | "
                "same atlas, `body.counts.by_subject` |",
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
            ]
        )

    def blocks(self) -> dict[str, str]:
        return {
            "readme-achievements": self.achievements(),
            "readme-l7-families": self.l7_families(),
            "readme-memory-safety": self.memory_safety(),
            "status-current-evidence": self.status_evidence(),
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
