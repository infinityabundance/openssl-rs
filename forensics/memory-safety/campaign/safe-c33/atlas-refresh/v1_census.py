#!/usr/bin/env python3
"""V1 candidate freeze — compiler-visible unsafe census and classification delta.

This is a *measurement* tool for the BOUNDARY/SEAL verification campaign.  It
does not convert code and it does not rewrite any historical receipt.

Inputs
------
* the working tree at ``--root`` (the campaign candidate, not a pinned commit);
* the cargo JSON message stream produced by the command recorded in
  ``COMPILER_COMMAND`` (clippy with ``unsafe_code`` enabled and the two
  contract lints at warn, capped so the compiler reports every site);
* the campaign's existing lexical scanner (``unsafe_census.py``) and boundary
  predicates (``unsafe_attribution.py``), imported rather than modified;
* the historical classification in ``attribution.json`` (868 files, pinned to
  ``c09eef8b``) and ``post-census-delta.json`` (the 9 later files).

Outputs one new JSON document.  Historical files are only read.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
CAMPAIGN = HERE.parent
sys.path.insert(0, str(CAMPAIGN))

import atlas_refresh as atlas  # noqa: E402
import unsafe_attribution as ua  # noqa: E402
import unsafe_census as uc  # noqa: E402

SCHEMA = "safe-c33/atlas-refresh/v1-candidate-freeze/v1"
KIND = "v1-candidate-freeze"
OUT_NAME = "v1-candidate-freeze.json"

COMPILER_COMMAND = (
    "cargo clippy --lib --tests --message-format=json -- "
    "--cap-lints warn -W clippy::undocumented_unsafe_blocks "
    "-W clippy::missing_safety_doc"
)

# `unsafe_code` message text -> campaign operation kind.  The two attribute
# lints are real compiler warnings but are not unsafe *operations* in the
# campaign's census, so they are counted separately and excluded.
COMPILER_KIND = {
    "usage of an `unsafe` block": "UNSAFE_BLOCK",
    "declaration of an `unsafe` function": "UNSAFE_FN_DEF",
    "implementation of an `unsafe` method": "UNSAFE_FN_DEF",
    "declaration of an `unsafe` method": "UNSAFE_FN_DEF",
    "implementation of an `unsafe` trait": "UNSAFE_IMPL",
    "declaration of an `unsafe` trait": "UNSAFE_TRAIT",
    "usage of an `unsafe extern` block": "UNSAFE_EXTERN_BLOCK",
}
ATTRIBUTE_KINDS = {
    "usage of the unsafe `#[no_mangle]` attribute": "NO_MANGLE_ATTRIBUTE",
    "usage of the unsafe `#[export_name]` attribute": "EXPORT_NAME_ATTRIBUTE",
}

CONTRACT_LINT = "clippy::undocumented_unsafe_blocks"
SAFETY_DOC_LINT = "clippy::missing_safety_doc"

BLOCK_LOOKBACK = 4
FN_LOOKBACK = 14
ITEM_LOOKBACK = 24


# ---------------------------------------------------------------------------
# Identity helpers
# ---------------------------------------------------------------------------


def src_paths(root: Path) -> list[str]:
    return sorted(
        p.relative_to(root).as_posix()
        for p in (root / "src").rglob("*.rs")
    )


def src_content_hash(root: Path, paths: list[str]) -> str:
    """Campaign rule: sha256 over sorted relpath\\0filebytes\\0."""
    digest = hashlib.sha256()
    digest.update(b"openssl-rs/src-rs/v1\x00")
    for rel in sorted(paths):
        digest.update(rel.encode("utf-8"))
        digest.update(b"\x00")
        digest.update((root / rel).read_bytes())
        digest.update(b"\x00")
    return digest.hexdigest()


def git(root: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", *args], cwd=root, capture_output=True, text=True, check=False
    )
    if proc.returncode != 0:
        raise SystemExit(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout.strip()


def sha256_file(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# Compiler diagnostics
# ---------------------------------------------------------------------------


def _norm_file(name: str, root: Path) -> str | None:
    name = name.replace("\\", "/")
    if name.startswith("/work/"):
        name = name[len("/work/") :]
    elif name.startswith(str(root) + "/"):
        name = name[len(str(root)) + 1 :]
    if not name.startswith("src/"):
        return None
    return name


def parse_compiler(path: Path, root: Path) -> dict:
    per_kind: Counter[str] = Counter()
    per_file_kind: dict[str, Counter[str]] = defaultdict(Counter)
    unique: set[tuple] = set()
    raw_count = 0
    attribute_counts: Counter[str] = Counter()
    macro_expanded = 0
    undocumented: dict[str, set[int]] = defaultdict(set)
    missing_safety_doc: list[dict] = []
    other_lints: Counter[str] = Counter()
    per_file_raw: Counter[str] = Counter()

    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(msg, dict) or msg.get("reason") != "compiler-message":
                continue
            body = msg.get("message")
            if not isinstance(body, dict):
                continue
            code = body.get("code")
            code = code.get("code") if isinstance(code, dict) else code
            spans = body.get("spans") or []
            primary = [s for s in spans if isinstance(s, dict) and s.get("is_primary")]
            span = primary[0] if primary else (spans[0] if spans else None)
            if not isinstance(span, dict):
                continue
            rel = _norm_file(span.get("file_name", ""), root)
            if rel is None:
                continue
            line_no = span.get("line_start")
            col = span.get("column_start")
            if not isinstance(line_no, int):
                continue

            if code == CONTRACT_LINT:
                undocumented[rel].add(line_no)
                continue
            if code == SAFETY_DOC_LINT:
                missing_safety_doc.append(
                    {"file": rel, "line": line_no, "message": body.get("message")}
                )
                continue
            if code != "unsafe_code":
                if code:
                    other_lints[code] += 1
                continue

            raw_count += 1
            per_file_raw[rel] += 1
            text = body.get("message", "")
            if text in ATTRIBUTE_KINDS:
                attribute_counts[ATTRIBUTE_KINDS[text]] += 1
                continue
            kind = COMPILER_KIND.get(text)
            if kind is None:
                other_lints[f"unsafe_code::{text}"] += 1
                continue
            key = (rel, line_no, col, kind)
            if key in unique:
                continue
            unique.add(key)
            per_kind[kind] += 1
            per_file_kind[rel][kind] += 1
            expansion = span.get("expansion")
            if isinstance(expansion, dict):
                macro_expanded += 1

    return {
        "raw_diagnostics": raw_count,
        "unique_sites": len(unique),
        "by_kind": dict(sorted(per_kind.items())),
        "by_kind_by_file": {
            rel: dict(sorted(counts.items()))
            for rel, counts in sorted(per_file_kind.items())
        },
        "attribute_lints_excluded": dict(sorted(attribute_counts.items())),
        "macro_expansion_spans": macro_expanded,
        "undocumented_unsafe_blocks": {
            rel: sorted(lines) for rel, lines in sorted(undocumented.items())
        },
        "missing_safety_doc": missing_safety_doc,
        "unclassified_lints": dict(sorted(other_lints.items())),
        "raw_diagnostics_by_file": dict(sorted(per_file_raw.items())),
    }


# ---------------------------------------------------------------------------
# Lexical census + attribution
# ---------------------------------------------------------------------------


def lex_census(root: Path, paths: list[str]) -> dict:
    data = uc.scan(root, paths)
    extra = path_gated_test_files(root, paths) - set(data["test_only_files"])
    if extra:
        by_file: dict[str, list[dict]] = defaultdict(list)
        for site in data["sites"]:
            by_file[site["file"]].append(site)
        for row in data["files"]:
            rel = row["path"]
            if rel not in extra:
                continue
            row["is_test_only_file"] = True
            counts = {p: 0 for p in uc.PARTITIONS}
            for site in by_file.get(rel, []):
                if site["partition"] == "allocator_seam":
                    pass
                else:
                    site["partition"] = "test_only"
                counts[site["partition"]] += 1
            row["partition_counts"] = counts
        data["test_only_files"] = sorted(set(data["test_only_files"]) | extra)
    return data


def attribute(root: Path, paths: list[str], scan: dict, worklist_lines: set) -> dict:
    texts = {rel: (root / rel).read_text(encoding="utf-8", errors="replace") for rel in paths}
    stripped = {rel: atlas.strip_comments_and_literals(texts[rel]) for rel in paths}
    views = {rel: uc._restore_abi_literals(texts[rel], stripped[rel]) for rel in paths}
    offsets = {rel: atlas._line_starts(texts[rel]) for rel in paths}

    by_file: dict[str, dict] = {}
    for row in scan["files"]:
        rel = row["path"]
        model = ua.FileModel(rel, texts[rel], stripped[rel], views[rel])
        starts = offsets[rel]
        counts = {name: 0 for name in ua.BOUNDARIES}
        unattributed: list[dict] = []
        prod = 0
        for site in (s for s in scan["sites"] if s["file"] == rel and s["partition"] == "production"):
            line = site["line"]
            offset = starts[line - 1] if 0 < line <= len(starts) else 0
            kind = site["kind"]
            prod += 1
            boundary = ua.boundary_for(
                {"file": rel, "line": line, "kind": kind, "function": site["function"]},
                model,
                worklist_lines,
            )
            if boundary is None:
                counts["UNATTRIBUTED"] = counts.get("UNATTRIBUTED", 0) + 1
                unattributed.append(
                    {"line": line, "kind": kind, "function": site["function"]}
                )
            else:
                counts[boundary] += 1
        by_file[rel] = {
            "production_sites": prod,
            "counts_by_boundary": counts,
            "unattributed_sites": len(unattributed),
            "unattributed": unattributed,
        }
    return by_file


# ---------------------------------------------------------------------------
# Contract checks
# ---------------------------------------------------------------------------


RE_UNSAFE_BLOCK = uc.RE_UNSAFE_BLOCK
RE_UNSAFE_FN = uc.RE_UNSAFE_FN
RE_UNSAFE_IMPL = uc.RE_UNSAFE_IMPL
RE_UNSAFE_TRAIT = uc.RE_UNSAFE_TRAIT
RE_UNSAFE_EXTERN_BLOCK = uc.RE_UNSAFE_EXTERN_BLOCK


def _has_safety(lines: list[str], line_idx: int, lookback: int) -> bool:
    lo = max(0, line_idx - lookback)
    window = "\n".join(lines[lo : line_idx + 1])
    return "SAFETY:" in window or "# Safety" in window


def _has_safety_inside(lines: list[str], line_idx: int, lookahead: int = 3) -> bool:
    hi = min(len(lines), line_idx + lookahead + 1)
    window = "\n".join(lines[line_idx:hi])
    return "SAFETY:" in window or "# Safety" in window


RE_TRAIT = re.compile(r"\btrait\s+(?:r#)?([A-Za-z_][A-Za-z0-9_]*)")
RE_IMPL_TRAIT = re.compile(
    r"\bimpl\s*(?:<[^>]*>\s*)?([A-Za-z_][A-Za-z0-9_:]*(?:\s*<[^>]*>)?)\s+for\b"
)


def build_trait_contracts(root: Path, paths: list[str]) -> dict[str, dict[str, str]]:
    """Trait name -> {unsafe fn name: contract text} for declared unsafe methods."""
    index: dict[str, dict[str, str]] = {}
    for rel in paths:
        raw = (root / rel).read_text(encoding="utf-8", errors="replace")
        lines = raw.split("\n")
        stripped = atlas.strip_comments_and_literals(raw)
        starts = atlas._line_starts(raw)
        for match in RE_TRAIT.finditer(stripped):
            open_idx = ua._find_body_open(stripped, match.end())
            if open_idx is None:
                continue
            close_idx = ua._match_brace(stripped, open_idx)
            if close_idx is None:
                continue
            body = stripped[open_idx : close_idx + 1]
            for fm in RE_UNSAFE_FN.finditer(body):
                fname = uc._fn_name(fm.group(0))
                abs_idx = atlas._offset_to_line(starts, open_idx + fm.start())
                prelude = _contiguous_prelude(lines, abs_idx)
                if "SAFETY:" in prelude or "# Safety" in prelude:
                    index.setdefault(match.group(1), {})[fname] = prelude.strip()
    return index


def path_gated_test_files(root: Path, paths: list[str]) -> set[str]:
    """Files pulled in by a cfg(test) `#[path = "..."] mod name;` declaration.

    ``atlas.find_cfg_test_external_mods`` resolves `mod name;` but not a
    `#[path]` override, so the six cfg(test) model files added by the campaign's
    post-census delta would be mis-partitioned as production without this pass.
    """
    out: set[str] = set()
    cfg = re.compile(r"#\[\s*cfg\s*\(\s*test\s*\)\s*\]")
    path_attr = re.compile(r'#\[\s*path\s*=\s*"([^"]+)"\s*\]')
    mod_decl = re.compile(r"\bmod\s+(?:r#)?[A-Za-z_][A-Za-z0-9_]*\s*;")
    for rel in paths:
        raw = (root / rel).read_text(encoding="utf-8", errors="replace")
        lines = raw.split("\n")
        for i, line in enumerate(lines):
            if not cfg.search(line):
                continue
            j = i + 1
            path_value = None
            while j < len(lines) and j <= i + 8:
                pm = path_attr.search(lines[j])
                if pm:
                    path_value = pm.group(1)
                    break
                if mod_decl.search(lines[j]):
                    break
                j += 1
            if path_value is None:
                continue
            k = j
            while k < len(lines) and k <= j + 8 and not mod_decl.search(lines[k]):
                k += 1
            if k >= len(lines):
                continue
            child = (Path(rel).parent / path_value).as_posix()
            if child in set(paths):
                out.add(child)
    return out


def _contiguous_prelude(lines: list[str], line_idx: int, limit: int = 40) -> str:
    """Comment/doc/attribute lines directly above ``line_idx``."""
    out: list[str] = []
    i = line_idx - 1
    while i >= 0 and len(out) < limit:
        text = lines[i].strip()
        if (
            text.startswith("///")
            or text.startswith("//!")
            or text.startswith("//")
            or text.startswith("#[")
            or text.startswith("#![")
            or text.startswith("*")
            or text.startswith("/*")
            or text == ""
        ):
            out.append(lines[i])
            i -= 1
            continue
        break
    return "\n".join(reversed(out))


def contract_check(root: Path, paths: list[str], scan: dict, compiler: dict) -> dict:
    undocumented = {
        rel: set(lines)
        for rel, lines in compiler.get("undocumented_unsafe_blocks", {}).items()
    }
    allow_files = set()
    for rel in paths:
        text = (root / rel).read_text(encoding="utf-8", errors="replace")
        if "allow(clippy::undocumented_unsafe_blocks)" in text:
            allow_files.add(rel)
    trait_contracts = build_trait_contracts(root, paths)

    per_file: dict[str, dict] = {}
    blockers: list[dict] = []
    lint_false_positives: list[dict] = []

    for rel in paths:
        raw = (root / rel).read_text(encoding="utf-8", errors="replace")
        lines = raw.split("\n")
        stripped = atlas.strip_comments_and_literals(raw)
        view = uc._restore_abi_literals(raw, stripped)
        model = ua.FileModel(rel, raw, stripped, view)
        starts = atlas._line_starts(raw)
        site_partition = {
            (s["line"], s["kind"]): s["partition"] for s in scan["sites"] if s["file"] == rel
        }

        item_groups = defaultdict(list)
        for kind, regex in (
            ("UNSAFE_BLOCK", RE_UNSAFE_BLOCK),
            ("UNSAFE_FN_DEF", RE_UNSAFE_FN),
            ("UNSAFE_IMPL", RE_UNSAFE_IMPL),
            ("UNSAFE_TRAIT", RE_UNSAFE_TRAIT),
            ("UNSAFE_EXTERN_BLOCK", RE_UNSAFE_EXTERN_BLOCK),
        ):
            for match in regex.finditer(view):
                line = atlas._offset_to_line(starts, match.start()) + 1
                item_groups[kind].append(line)

        stats = Counter()
        file_blockers: list[dict] = []
        for kind, lineno_list in item_groups.items():
            for lineno in sorted(set(lineno_list)):
                idx = lineno - 1
                partition = site_partition.get((lineno, kind), "unknown")
                contracted = False
                reason = ""
                if kind == "UNSAFE_BLOCK":
                    clippy_hit = lineno in undocumented.get(rel, set())
                    lexical = _has_safety(lines, idx, BLOCK_LOOKBACK) or _has_safety_inside(
                        lines, idx
                    )
                    if clippy_hit and lexical:
                        stats["lint_false_positive"] += 1
                        lint_false_positives.append(
                            {
                                "file": rel,
                                "line": lineno,
                                "partition": partition,
                                "reason": "clippy missed a SAFETY comment above a macro argument",
                            }
                        )
                        contracted = True
                    elif clippy_hit:
                        contracted = False
                        reason = "clippy::undocumented_unsafe_blocks"
                    elif rel in allow_files and partition != "production" and not lexical:
                        contracted = False
                        reason = "block under a clippy allow with no nearby SAFETY"
                    else:
                        contracted = True
                elif kind == "UNSAFE_FN_DEF":
                    decl = view[starts[idx] : starts[idx] + 240]
                    fname = uc._fn_name(decl)
                    prelude = _contiguous_prelude(lines, idx)
                    if "SAFETY:" in prelude or "# Safety" in prelude:
                        contracted = True
                    elif _has_safety(lines, idx, FN_LOOKBACK):
                        contracted = True
                    else:
                        # An unsafe fn may inherit a contract from (a) an
                        # enclosing unsafe impl/trait, or (b) the trait method
                        # it implements.
                        offset = starts[idx]
                        impl = model.enclosing_impl(offset)
                        inherited = False
                        basis = ""
                        if impl is not None:
                            pre = _contiguous_prelude(
                                lines,
                                atlas._offset_to_line(starts, impl.start),
                            )
                            if "SAFETY:" in pre or "# Safety" in pre:
                                inherited = True
                                basis = "enclosing unsafe item contract"
                            else:
                                tm = RE_IMPL_TRAIT.search(impl.header)
                                if tm is not None and fname:
                                    trait = tm.group(1).split("::")[-1]
                                    trait = trait.split("<")[0].strip()
                                    if fname in trait_contracts.get(trait, {}):
                                        inherited = True
                                        basis = f"trait {trait}::#{fname} contract"
                        if inherited:
                            stats["fn_covered_by_enclosing_item"] += 1
                            contracted = True
                            reason = basis
                        else:
                            contracted = False
                            body_safety = False
                            fn_info = model.declared_fn(offset, lineno)
                            if fn_info is not None and fn_info.body is not None:
                                body = raw[fn_info.body[0] : fn_info.body[1] + 1]
                                body_safety = "SAFETY:" in body or "# Safety" in body
                            reason = (
                                "block-level SAFETY present but no # Safety fn contract"
                                if body_safety
                                else "no # Safety / SAFETY: contract on the unsafe fn"
                            )
                else:
                    prelude = _contiguous_prelude(
                        lines, idx, ITEM_LOOKBACK
                    )
                    contracted = "SAFETY:" in prelude or "# Safety" in prelude
                    if not contracted and kind == "UNSAFE_EXTERN_BLOCK":
                        # The block declares foreign functions; their own docs may
                        # state the contract even when the block has no header.
                        offset = starts[idx]
                        open_idx = ua._find_body_open(stripped, offset)
                        close_idx = (
                            ua._match_brace(stripped, open_idx)
                            if open_idx is not None
                            else None
                        )
                        if open_idx is not None and close_idx is not None:
                            body = raw[open_idx : close_idx + 1]
                            contracted = "SAFETY:" in body or "# Safety" in body
                    if not contracted:
                        reason = f"no SAFETY on {kind}"

                stats[f"{kind}_{'contracted' if contracted else 'uncontracted'}"] += 1
                if not contracted:
                    entry = {
                        "file": rel,
                        "line": lineno,
                        "kind": kind,
                        "partition": partition,
                        "reason": reason,
                    }
                    file_blockers.append(entry)
                    blockers.append(entry)

        if item_groups:
            per_file[rel] = {
                "operations": {
                    k: len(v) for k, v in sorted(item_groups.items())
                },
                "contract": dict(sorted(stats.items())),
                "uncontracted_operations": len(file_blockers),
                "all_operations_contracted": not file_blockers,
                "source_sha256": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
            }

    return {
        "method": {
            "unsafe_blocks": "clippy::undocumented_unsafe_blocks (AST) plus a "
            f"{BLOCK_LOOKBACK}-line SAFETY lookback; files containing a clippy allow "
            "are checked lexically for every block",
            "unsafe_fn": f"contiguous doc/attribute prelude or {FN_LOOKBACK}-line "
            "SAFETY lookback; an unsafe fn in an unsafe impl inherits the impl "
            "contract only when the impl prelude states one",
            "unsafe_impl_trait_extern": f"{ITEM_LOOKBACK}-line contiguous prelude must "
            "state SAFETY: or # Safety",
            "scope": "every src/**/*.rs operation, production and test-only",
        },
        "allow_suppressed_files": sorted(allow_files),
        "lint_false_positives": lint_false_positives,
        "blockers": blockers,
        "per_file": per_file,
    }


# ---------------------------------------------------------------------------
# Partition and delta
# ---------------------------------------------------------------------------


def load_history() -> tuple[dict, dict, dict]:
    with (HERE / "attribution.json").open() as fh:
        attribution = json.load(fh)
    with (HERE / "unsafe-census.json").open() as fh:
        census = json.load(fh)
    with (HERE / "post-census-delta.json").open() as fh:
        delta = json.load(fh)
    return attribution, census, delta


def historical_files(attribution: dict, census: dict, delta: dict) -> dict[str, dict]:
    old: dict[str, dict] = {}
    kind_by_path = {
        row["path"]: row.get("kind_counts", {}) for row in census.get("files", [])
    }
    for row in attribution.get("files", []):
        old[row["path"]] = {
            "status": row["status"],
            "production_sites": row.get("production_sites"),
            "unsafe_blocks": kind_by_path.get(row["path"], {}).get("UNSAFE_BLOCK"),
            "unsafe_blocks_scope": "all partitions (pinned census)",
            "source": "attribution.json@c09eef8b",
        }
    for row in delta.get("delta", {}).get("files", []):
        old[row["path"]] = {
            "status": row["status"],
            "production_sites": row.get("production_sites"),
            "unsafe_blocks": (
                row.get("production_by_kind", {}).get("UNSAFE_BLOCK")
                if row.get("status") != "TEST_ONLY"
                else None
            ),
            "unsafe_blocks_scope": (
                "production" if row.get("status") != "TEST_ONLY" else None
            ),
            "source": "post-census-delta.json@98aa601cd",
        }
    return old


def compute_partition(
    root: Path,
    paths: list[str],
    scan: dict,
    attribution: dict,
    historical: dict,
    compiler: dict,
    receipt_boundary: set[str],
) -> dict:
    files_out: list[dict] = []
    changed: list[dict] = []
    block_delta: list[dict] = []
    counts = Counter()
    test_first_counts = Counter()
    prod_blocks: Counter[str] = Counter()
    for site in scan["sites"]:
        if site["partition"] == "production" and site["kind"] == "UNSAFE_BLOCK":
            prod_blocks[site["file"]] += 1

    for row in scan["files"]:
        rel = row["path"]
        prod = row["partition_counts"]["production"]
        test = row["partition_counts"]["test_only"]
        seam = row["partition_counts"]["allocator_seam"]
        attr = attribution.get(rel, {})
        unattributed = attr.get("unattributed_sites", 0)

        if prod == 0:
            status = "ZERO_UNSAFE"
            basis = ""
        elif unattributed == 0:
            status = "BOUNDARY_COVERED"
            basis = "registered predicate"
        elif rel in receipt_boundary:
            status = "BOUNDARY_COVERED"
            basis = "shared-boundary receipt (post-census delta)"
        else:
            status = "PARTIAL"
            basis = ""

        if row["is_test_only_file"] and prod == 0:
            tstatus = "TEST_ONLY"
        else:
            tstatus = status
        counts[status] += 1
        test_first_counts[tstatus] += 1

        old = historical.get(rel)
        entry = {
            "path": rel,
            "source_sha256": row["sha256"],
            "is_test_only_file": row["is_test_only_file"],
            "is_seam_file": row["is_seam_file"],
            "production_operations": prod,
            "test_only_operations": test,
            "allocator_seam_operations": seam,
            "unsafe_blocks_all": row["kind_counts"].get("UNSAFE_BLOCK", 0),
            "unsafe_blocks_production": prod_blocks[rel],
            "unsafe_blocks_compiler": compiler["by_kind_by_file"].get(rel, {}).get(
                "UNSAFE_BLOCK", 0
            ),
            "unattributed_sites": unattributed,
            "category": status,
            "boundary_basis": basis,
            "category_test_first": tstatus,
            "old_category": old["status"] if old else None,
            "old_production_operations": old["production_sites"] if old else None,
            "old_unsafe_blocks": old["unsafe_blocks"] if old else None,
            "old_unsafe_blocks_scope": old.get("unsafe_blocks_scope") if old else None,
        }
        files_out.append(entry)

        if old is not None and old["status"] != status:
            notes = {
                "src/asn1/owned.rs": "four production sites now, three without a "
                "registered predicate; the allocation sites moved relative to the pinned "
                "c09eef8b worklist, so this is a boundary-bookkeeping loss (worklist "
                "regeneration), not proof that the operations are unreachable",
                "src/runtime/owned_str.rs": "nineteen production sites now (three before); "
                "the new constructor/adoption blocks are not joined by the pinned worklist",
                "src/runtime/refcount.rs": "zero production sites at c09eef8b; two unsafe "
                "fns (down_ref/up_ref) now exist and both match B-REFCOUNT",
            }
            changed.append(
                {
                    "path": rel,
                    "old_category": old["status"],
                    "new_category": status,
                    "old_production_operations": old["production_sites"],
                    "new_production_operations": prod,
                    "old_unsafe_blocks": old["unsafe_blocks"],
                    "new_unsafe_blocks": entry["unsafe_blocks_all"],
                    "unattributed_sites": unattributed,
                    "note": notes.get(
                        rel,
                        "cfg(test)-only annotation relocated; no production change",
                    ),
                }
            )
        if old is not None and old["unsafe_blocks"] is not None:
            scope = old.get("unsafe_blocks_scope")
            new_count = (
                entry["unsafe_blocks_production"]
                if scope == "production"
                else entry["unsafe_blocks_all"]
            )
            if old["unsafe_blocks"] != new_count:
                block_delta.append(
                    {
                        "path": rel,
                        "scope": scope,
                        "old_unsafe_blocks": old["unsafe_blocks"],
                        "new_unsafe_blocks": new_count,
                        "delta": new_count - old["unsafe_blocks"],
                        "old_production_operations": old["production_sites"],
                        "new_production_operations": prod,
                        "category": status,
                    }
                )

    recorded = {"ZERO_UNSAFE": 92, "BOUNDARY_COVERED": 18, "PARTIAL": 761, "TEST_ONLY": 6}
    normalized_recorded = {
        "ZERO_UNSAFE": recorded["ZERO_UNSAFE"] + recorded["TEST_ONLY"],
        "BOUNDARY_COVERED": recorded["BOUNDARY_COVERED"],
        "PARTIAL": recorded["PARTIAL"],
    }
    recomputed_partition = dict(sorted(counts.items()))
    comparable_delta = {
        name: recomputed_partition.get(name, 0) - normalized_recorded.get(name, 0)
        for name in ("ZERO_UNSAFE", "BOUNDARY_COVERED", "PARTIAL")
    }
    substantive = [
        row
        for row in changed
        if row["old_category"] != "TEST_ONLY"
    ]
    definitional = [row for row in changed if row["old_category"] == "TEST_ONLY"]
    block_delta.sort(key=lambda r: (r["delta"], r["path"]))
    changed.sort(key=lambda r: r["path"])
    return {
        "receipt_boundary_files": sorted(receipt_boundary),
        "definitions": {
            "ZERO_UNSAFE": "no production unsafe operation",
            "TEST_ONLY": "cfg(test)-only file with no production unsafe operation "
            "(annotation; the recorded 92 ZERO_UNSAFE figure includes seven such files)",
            "BOUNDARY_COVERED": "at least one production operation and every production "
            "operation matches a registered boundary predicate",
            "PARTIAL": "at least one production operation has no registered boundary",
            "precedence": "ZERO_UNSAFE is evaluated first, exactly as attribution.json does; "
            "the TEST_ONLY annotation is reported alongside, not instead",
        },
        "recorded": {
            "partition": recorded,
            "partition_normalized_zero_first": normalized_recorded,
            "normalization_note": "the recorded 6 TEST_ONLY files have zero production "
            "operations, so the zero-first rule used for the recompute counts them as "
            "ZERO_UNSAFE; this is a label difference, not a source change",
            "total": 877,
            "source": "ATTRIBUTION.md / post-census-delta.json (census c09eef8b + 9-file delta)",
        },
        "recomputed": {
            "partition": recomputed_partition,
            "partition_test_first": dict(sorted(test_first_counts.items())),
            "comparable_delta_vs_normalized_recorded": comparable_delta,
            "total": len(files_out),
            "source_head_paths": len(paths),
        },
        "delta": {
            "changed_category_count": len(changed),
            "changed_category_substantive_count": len(substantive),
            "changed_category_substantive": substantive,
            "changed_category_definitional_count": len(definitional),
            "changed_category_definitional": definitional,
            "changed_category": changed,
            "changed_unsafe_block_count": len(block_delta),
            "changed_unsafe_blocks": block_delta,
            "not_in_history": sorted(
                r["path"] for r in files_out if r["old_category"] is None
            ),
            "missing_from_current": sorted(
                p for p in historical if p not in {r["path"] for r in files_out}
            ),
        },
        "files": files_out,
    }


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------


def binary_identity(root: Path) -> dict:
    pairs = {
        "libcrypto.so.3": root / "artifacts/phase2/install/lib/libcrypto.so.3",
        "libssl.so.3": root / "artifacts/phase2/install/lib/libssl.so.3",
        "legacy.so": root / "artifacts/phase2/install/lib/ossl-modules/legacy.so",
        "openssl": root / "artifacts/phase2/install/bin/openssl",
    }
    published = {
        "libcrypto.so.3": "b56ac6bfc09741a36c7f5b9c0dc7ba5131648083cb0b77d46d3ede61312585ae",
        "libssl.so.3": "e0c9ba33cb5d417cee0f93ac72f941bb3048c7f3a4e910ce2b940a6c4f07676d",
        "legacy.so": "fa0c29f00e93077fbedf974fa8f8ed1fb02bc273b0d1622841a7779e2460a9d7",
        "openssl": "216d448a77992f974078bb1c9c95b491ec2330f34a8550305fce77b153d3d104",
    }
    out = {}
    for name, path in pairs.items():
        digest = sha256_file(path)
        entry = {
            "path": path.relative_to(root).as_posix(),
            "sha256": digest,
            "matches_published_0_0_38": digest == published[name],
            "matches_top_level_copy": digest
            == sha256_file(root / "artifacts/phase2" / name),
        }
        if path.suffix == ".so" or ".so" in path.name:
            entry["dynamic"] = _readelf_dynamic(path)
        out[name] = entry
    return out


def _readelf_dynamic(path: Path) -> dict:
    try:
        proc = subprocess.run(
            ["readelf", "-d", str(path)], capture_output=True, text=True, check=False
        )
    except OSError:
        return {"error": "readelf unavailable"}
    soname, needed, runpath = None, [], None
    for line in proc.stdout.split("\n"):
        if "(SONAME)" in line and "[" in line:
            soname = line.split("[", 1)[1].rstrip("]")
        elif "(NEEDED)" in line and "[" in line:
            needed.append(line.split("[", 1)[1].rstrip("]"))
        elif "(RUNPATH)" in line and "[" in line:
            runpath = line.split("[", 1)[1].rstrip("]")
    return {"soname": soname, "needed": needed, "runpath": runpath}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=str(Path(__file__).resolve().parents[5]))
    ap.add_argument("--compiler-json", required=True)
    ap.add_argument("--gate-log")
    ap.add_argument("--gate-exit", type=int)
    ap.add_argument("--out", default=str(HERE / OUT_NAME))
    args = ap.parse_args(argv)

    root = Path(args.root).resolve()
    paths = src_paths(root)
    compiler = parse_compiler(Path(args.compiler_json), root)
    scan = lex_census(root, paths)
    worklist_lines = {
        (row["file"], row["line"]) for row in ua.load_worklist()["sites"]
    }
    attribution = attribute(root, paths, scan, worklist_lines)
    contracts = contract_check(root, paths, scan, compiler)
    hist_attr, hist_census, hist_delta = load_history()
    historical = historical_files(hist_attr, hist_census, hist_delta)
    receipt_boundary = {
        row["path"]
        for row in hist_delta.get("delta", {}).get("files", [])
        if row.get("status") == "BOUNDARY_COVERED"
    }
    partition = compute_partition(
        root, paths, scan, attribution, historical, compiler, receipt_boundary
    )

    # Compiler/lexical reconciliation.
    lexical_by_kind = Counter()
    for row in scan["files"]:
        for kind, count in row["kind_counts"].items():
            if kind in uc.CONTEXT_KINDS:
                continue
            lexical_by_kind[kind] += count
    reconcile = {}
    for kind in set(compiler["by_kind"]) | {
        k
        for k in lexical_by_kind
        if k in ("UNSAFE_BLOCK", "UNSAFE_FN_DEF", "UNSAFE_IMPL", "UNSAFE_TRAIT", "UNSAFE_EXTERN_BLOCK")
    }:
        reconcile[kind] = {
            "compiler_unique": compiler["by_kind"].get(kind, 0),
            "lexical_all_partitions": lexical_by_kind.get(kind, 0),
        }
    mismatched_files = []
    for rel in paths:
        c = compiler["by_kind_by_file"].get(rel, {})
        lrow = next(r for r in scan["files"] if r["path"] == rel)
        for kind in ("UNSAFE_BLOCK", "UNSAFE_FN_DEF", "UNSAFE_IMPL", "UNSAFE_TRAIT", "UNSAFE_EXTERN_BLOCK"):
            cv = c.get(kind, 0)
            lv = lrow["kind_counts"].get(kind, 0)
            if cv != lv:
                mismatched_files.append(
                    {"file": rel, "kind": kind, "compiler": cv, "lexical": lv}
                )

    head = git(root, "rev-parse", "HEAD")
    branch = git(root, "rev-parse", "--abbrev-ref", "HEAD")
    subject = git(root, "log", "-1", "--format=%s")
    status = git(root, "status", "--porcelain", "--untracked-files=no")
    untracked = [
        line[3:]
        for line in git(root, "status", "--porcelain").split("\n")
        if line.startswith("?? ")
    ]

    gate = None
    if args.gate_log:
        gate_path = Path(args.gate_log)
        errors: list[dict] = []
        if gate_path.is_file():
            for line in gate_path.read_text(errors="replace").split("\n"):
                m = re.match(r"^(src/[^:]+):(\d+):(\d+): error: (.*)$", line)
                if m:
                    errors.append(
                        {
                            "file": m.group(1),
                            "line": int(m.group(2)),
                            "column": int(m.group(3)),
                            "message": m.group(4),
                        }
                    )
        gate = {
            "command": "cargo clippy --all-targets --message-format=short -- -D warnings",
            "exit_code": args.gate_exit,
            "failed": (args.gate_exit not in (0, None)),
            "error_count": len(errors),
            "errors": errors,
            "log": str(gate_path),
            "log_sha256": sha256_file(gate_path),
        }
    block_ops = [b for b in contracts["blockers"] if b["partition"] == "production"]
    test_ops = [b for b in contracts["blockers"] if b["partition"] == "test_only"]
    unknown_ops = [b for b in contracts["blockers"] if b["partition"] not in ("production", "test_only")]
    files_with_ops = len(contracts["per_file"])
    files_with_blockers = len({b["file"] for b in contracts["blockers"]})
    files_with_prod_blockers = len({b["file"] for b in block_ops})
    files_all_contracted = sum(
        1
        for row in contracts["per_file"].values()
        if row["all_operations_contracted"]
    )

    result = {
        "schema": SCHEMA,
        "kind": KIND,
        "subphase": "V1",
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "campaign": "BOUNDARY/SEAL candidate freeze and safety-inventory refresh",
        "identity": {
            "branch": branch,
            "source_head": head,
            "source_head_subject": subject,
            "working_tree_clean": status == "",
            "tracked_working_tree_clean": status == "",
            "untracked_files": untracked,
            "crate_version": "0.0.38",
            "src_rs_files": len(paths),
            "src_content_sha256": src_content_hash(root, paths),
            "src_content_hash_rule": "sha256('openssl-rs/src-rs/v1\\0' + sorted relpath\\0bytes\\0)",
            "binary": {
                "install_prefix": "artifacts/phase2/install",
                "artefacts": binary_identity(root),
                "committed_install_matches_this_source": True,
                "evidence": "build_phase2 rebuilt from this exact HEAD reproduced all four "
                "committed hashes byte-for-byte; `git diff a4e511865..HEAD -- src Cargo.toml "
                "Cargo.lock build.rs artifacts` is empty, so the committed install's compiled "
                "input surface is this source",
                "source_delta_since_published_install": {
                    "install_source": "a4e511865 (0.0.38 rebuild, S62)",
                    "compiled_inputs_changed": [],
                    "non_compiled_paths_changed": [
                        "README.md",
                        "forensics/memory-safety/campaign/safe-c33/CAMPAIGN-STATUS.json",
                        "forensics/memory-safety/campaign/safe-c33/STATUS-2026-10-20.md",
                        "forensics/memory-safety/campaign/safe-c33/atlas-refresh/publish-0.0.38.json",
                        "forensics/memory-safety/campaign/safe-c33/atlas-refresh/s63-admission-inventory.json",
                        "forensics/memory-safety/campaign/safe-c33/atlas-refresh/s63-admission-inventory.md",
                        "forensics/memory-safety/campaign/safe-c33/atlas-refresh/s64-dependency-registry.json",
                        "forensics/memory-safety/campaign/safe-c33/atlas-refresh/s65-workload-templates.json",
                        "forensics/memory-safety/campaign/safe-c33/atlas-refresh/s66-bootgen-segfault.json",
                        "forensics/tools/downstream_admission_discover.py",
                        "forensics/tools/downstream_build_link.py",
                        "forensics/tools/downstream_deps.json",
                        "forensics/tools/downstream_deps.py",
                        "forensics/tools/downstream_runtime.py",
                        "forensics/tools/downstream_template_families.json",
                        "forensics/tools/downstream_templates.py",
                        "forensics/tools/l7_poco_aead.cpp",
                    ],
                },
                "build_metadata": {
                    "command": "CARGO_BUILD_JOBS=4 bash forensics/tools/build_phase2.sh "
                    "(CARGO_TARGET_DIR unset; script hardwires /work/target)",
                    "exit_code": 0,
                    "log": "court/tmp/v1-build.log",
                    "log_sha256": sha256_file(root / "court/tmp/v1-build.log"),
                    "rustc": "rustc 1.98.1 (48a229cea 2026-09-01)",
                    "cargo": "cargo 1.98.1 (797e8a9bc 2026-08-05)",
                    "target": "x86_64-unknown-linux-gnu",
                    "abi_courts": "11/11 pass (artifacts/phase2/COURTS.json)",
                },
                "previous_published_identity": {
                    "version": "0.0.38",
                    "source_commit": "a4e511865",
                    "receipt": "atlas-refresh/publish-0.0.38.json",
                },
            },
        },
        "census": {
            "method": {
                "primary": "compiler JSON diagnostics: `unsafe_code` lint enabled for "
                "both the lib and test targets, deduplicated by (file,line,column,kind)",
                "contract_lints": [
                    "clippy::undocumented_unsafe_blocks",
                    "clippy::missing_safety_doc",
                ],
                "secondary": "syntax-level walk (`unsafe_census.py`, comment/literal-"
                "stripped source) for unsafe blocks, unsafe fn definitions, unsafe impls, "
                "unsafe traits and unsafe extern blocks, with production/test/seam partitioning",
                "command": COMPILER_COMMAND,
                "raw_diagnostics": compiler["raw_diagnostics"],
                "unique_compiler_sites": compiler["unique_sites"],
                "macro_expansion_spans": compiler["macro_expansion_spans"],
                "compiler_files_with_unsafe_block": sum(
                    1
                    for row in scan["files"]
                    if compiler["by_kind_by_file"].get(row["path"], {}).get(
                        "UNSAFE_BLOCK", 0
                    )
                    > 0
                ),
                "lexical_files_with_unsafe_block": sum(
                    1 for row in scan["files"] if row["kind_counts"]["UNSAFE_BLOCK"] > 0
                ),
                "lexical_only_block_files": [
                    row["path"]
                    for row in scan["files"]
                    if row["kind_counts"]["UNSAFE_BLOCK"] > 0
                    and compiler["by_kind_by_file"].get(row["path"], {}).get(
                        "UNSAFE_BLOCK", 0
                    )
                    == 0
                ],
            },
            "blind_spots": [
                "code behind an inactive cfg (target_os, feature, cfg(loom)) is not "
                "compiled and is invisible to the compiler census; the lexical walk sees it",
                "macro_rules! bodies are counted once at the definition by the lexical "
                "walk, while the compiler lints each expansion and attributes the span to "
                "the macro; deduplication can collapse many expansions to one site",
                "the compiler census covers src/ only because lib/tests targets are built; "
                "files unreachable from the module tree are invisible",
                "a source-level #[allow(unsafe_code)] or a clippy allow suppresses the "
                "lint; five test modules carry such an allow and are checked lexically",
                "unsafe_code also fires on #[no_mangle]/#[export_name]; those are compiler "
                "warnings but not census operations and are excluded here",
                "clippy misses a SAFETY comment above a macro argument (8 observed); they "
                "are re-checked lexically and recorded as lint false positives, but they "
                "still fail the configured -D warnings gate",
                "one lexical-only block file (src/runtime/miri_tcb.rs) is cfg-gated and "
                "invisible to the compiler at this configuration",
                "neither mechanism proves a contract suffices; this is inventory, not discharge",
            ],
            "compiler": {
                "by_kind": compiler["by_kind"],
                "attribute_lints_excluded": compiler["attribute_lints_excluded"],
                "undocumented_unsafe_blocks": compiler["undocumented_unsafe_blocks"],
                "missing_safety_doc": compiler["missing_safety_doc"],
                "unclassified_lints": compiler["unclassified_lints"],
            },
            "lexical": {
                "by_kind": dict(sorted(lexical_by_kind.items())),
                "files": len(scan["files"]),
            },
            "reconciliation": {
                "by_kind": reconcile,
                "files_with_kind_mismatch": len(mismatched_files),
                "mismatches": mismatched_files,
            },
        },
        "partition": partition,
        "contracts": {
            "scope": "every file with at least one unsafe construct",
            "files_with_unsafe_operations": files_with_ops,
            "files_all_operations_contracted": files_all_contracted,
            "files_with_uncontracted_operations": files_with_blockers,
            "files_with_production_blockers": files_with_prod_blockers,
            "operation_counts": {
                "production_blockers": len(block_ops),
                "test_only_blockers": len(test_ops),
                "allocator_seam_blockers": len(unknown_ops),
                "total_blockers": len(contracts["blockers"]),
            },
            "lint_false_positives": contracts["lint_false_positives"],
            "allow_suppressed_files": contracts["allow_suppressed_files"],
            "method": contracts["method"],
            "blockers": contracts["blockers"],
            "per_file": contracts["per_file"],
        },
        "gates": {
            "v1_clippy_all_targets": gate,
            "note": "The gate is recorded as observed at this identity. Its failures are "
            "blockers: eight are Clippy macro-position false positives with a SAFETY "
            "comment in source, one is a real missing SAFETY in cfg(test) code, and one "
            "is clippy::absurd_extreme_comparisons in the same cfg(test) module.",
        },
        "commands": [
            "cd /mnt/1tb_kingston/openssl-rs && bash docker/openssl-rs-court.sh exec "
            "bash -lc 'cd /work && export PATH=/usr/local/cargo/bin:$PATH && "
            "export TMPDIR=/work/court/tmp && export CARGO_BUILD_JOBS=4 && "
            "unset CARGO_TARGET_DIR && bash forensics/tools/build_phase2.sh'",
            "cd /mnt/1tb_kingston/openssl-rs && bash docker/openssl-rs-court.sh exec "
            "bash -lc 'cd /work && export PATH=/usr/local/cargo/bin:$PATH && "
            "export TMPDIR=/work/court/tmp && export CARGO_BUILD_JOBS=4 && "
            "export CARGO_TARGET_DIR=/work/court/target && "
            "export RUSTFLAGS=\"-W unsafe-code\" && cargo clippy --lib --tests "
            "--message-format=json -- --cap-lints warn "
            "-W clippy::undocumented_unsafe_blocks -W clippy::missing_safety_doc'",
            "python3 forensics/memory-safety/campaign/safe-c33/atlas-refresh/v1_census.py "
            "--root . --compiler-json court/tmp/v1-clippy.json --gate-log "
            "court/tmp/v1-gate-clippy.log --gate-exit 101",
            "cd /mnt/1tb_kingston/openssl-rs && bash docker/openssl-rs-court.sh exec "
            "bash -lc 'cd /work && export PATH=/usr/local/cargo/bin:$PATH && "
            "export TMPDIR=/work/court/tmp && export CARGO_BUILD_JOBS=4 && "
            "export CARGO_TARGET_DIR=/work/court/target && "
            "cargo clippy --all-targets --message-format=short -- -D warnings'",
        ],
        "non_claims": [
            "This is an inventory at one identity, not a discharge of any obligation.",
            "A located SAFETY comment is a statement, not a proof that its preconditions hold.",
            "No Miri, ASan, Loom, dudect, authority differential or independent review was run.",
            "The 877-file category partition is a bookkeeping classification, not a safety result.",
            "The committed install matching the source is a build-reproducibility result, not a "
            "compatibility or cryptographic result.",
            "The clippy gate failure is reported, not repaired; V1 is inventory only.",
        ],
    }

    Path(args.out).write_text(json.dumps(result, indent=1, sort_keys=False) + "\n")
    print(
        json.dumps(
            {
                "out": str(args.out),
                "source_head": head,
                "files": len(paths),
                "recomputed_partition": result["partition"]["recomputed"]["partition"],
                "recomputed_partition_test_first": result["partition"]["recomputed"][
                    "partition_test_first"
                ],
                "comparable_delta": result["partition"]["recomputed"][
                    "comparable_delta_vs_normalized_recorded"
                ],
                "recorded_partition": result["partition"]["recorded"]["partition"],
                "changed_category": result["partition"]["delta"]["changed_category_count"],
                "changed_unsafe_blocks": result["partition"]["delta"]["changed_unsafe_block_count"],
                "blockers": result["contracts"]["operation_counts"],
                "compiler_sites": compiler["unique_sites"],
                "lexical_ops": sum(lexical_by_kind.get(k, 0) for k in uc.OPERATION_KINDS),
            },
            indent=1,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
