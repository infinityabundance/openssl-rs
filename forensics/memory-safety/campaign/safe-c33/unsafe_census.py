#!/usr/bin/env python3
"""Honest per-file denominator of unsafe operations in ``src/**/*.rs``.

This is a measurement tool, not a conversion tool.  It enumerates lexical
unsafe operations, high-risk call sites, FFI definitions/calls, and a separate
raw-pointer-type context metric.  Every site is classified as production,
test-only, or allocator-seam using the helpers in ``atlas_refresh.py`` so the
test/seam partition does not drift from that report.

The scanner is intentionally lexical: it reuses
``atlas_refresh.strip_comments_and_literals`` (the campaign's existing
comment/string/char-literal stripper) and therefore preserves byte offsets and
1-based line numbers.  Because that stripper also blanks the ABI name in
``extern "C"``, the scanner restores only that semantically significant
literal after stripping; comments and every other literal remain stripped.  It
is not a Rust parser; the residual limitations are recorded in the generated
Markdown report.

Run:
  python3 forensics/memory-safety/campaign/safe-c33/unsafe_census.py
  python3 forensics/memory-safety/campaign/safe-c33/unsafe_census.py --check

``--check`` re-derives the core counts with an independent ``grep -E`` pass over
a temporary tree of stripped sources.  Any per-file mismatch exits non-zero.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import atlas_refresh as atlas  # noqa: E402  (local campaign helper)


SCHEMA = "openssl-rs/atlas/unsafe-census/v2"
KIND = "safe33-unsafe-census"
OUT_DIR = HERE / "atlas-refresh"
JSON_PATH = OUT_DIR / "unsafe-census.json"
MD_PATH = OUT_DIR / "UNSAFE-CENSUS.md"
PRIOR_CENSUS = "artifacts/phase25/source-census.json"

PARTITIONS = ("production", "test_only", "allocator_seam")

# Operation kinds.  RAW_POINTER_TYPE is deliberately absent: it is a context
# metric, not an unsafe operation.
UNSAFE_LANGUAGE_KINDS = (
    "UNSAFE_BLOCK",
    "UNSAFE_FN_DEF",
    "UNSAFE_IMPL",
    "UNSAFE_TRAIT",
    "UNSAFE_EXTERN_BLOCK",
)
HIGH_RISK_KINDS = ("HIGH_RISK_CALL",)
FFI_KINDS = ("EXTERN_C_FN_DEF", "NONALLOC_FFI_CALL")
OPERATION_KINDS = UNSAFE_LANGUAGE_KINDS + HIGH_RISK_KINDS + FFI_KINDS
CONTEXT_KINDS = ("RAW_POINTER_TYPE",)
ALL_KINDS = OPERATION_KINDS + CONTEXT_KINDS

# Short stable codes used by the compact site arrays.  The mapping is emitted
# itself (top-level `kind_codes`) so the JSON remains self-describing.
KIND_CODES = {
    "UNSAFE_BLOCK": "UB",
    "UNSAFE_FN_DEF": "UF",
    "UNSAFE_IMPL": "UI",
    "UNSAFE_TRAIT": "UT",
    "UNSAFE_EXTERN_BLOCK": "UE",
    "HIGH_RISK_CALL": "HR",
    "EXTERN_C_FN_DEF": "EC",
    "NONALLOC_FFI_CALL": "FC",
}
assert set(KIND_CODES) == set(OPERATION_KINDS)

# Regexes over stripped source.  They must stay in step with the grep
# reconciliation patterns further down; the latter are the independent check.
RE_UNSAFE_BLOCK = re.compile(r"\bunsafe\s*\{")
RE_UNSAFE_FN = re.compile(
    r'\bunsafe\s+(?:extern\s+(?:"[^"]*"\s+)?)?(?:async\s+)?'
    r"fn\s+(?:r#)?[A-Za-z_][A-Za-z0-9_]*"
)
RE_UNSAFE_IMPL = re.compile(r"\bunsafe\s+impl\b")
RE_UNSAFE_TRAIT = re.compile(r"\bunsafe\s+trait\b")
RE_UNSAFE_EXTERN_BLOCK = re.compile(
    r'\bunsafe\s+extern\s+(?:r#)?"[^"]*"\s*\{'
)
RE_EXTERN_C_FN = re.compile(
    r'\bextern\s+"C"\s+fn\s+(?:r#)?[A-Za-z_][A-Za-z0-9_]*'
)
RE_FFI_CALL = re.compile(
    r"\b(?:CRYPTO_|OPENSSL_|ossl_)[A-Za-z0-9_]*"
    r"(?:\s*::\s*<[^<>]*>)?\s*\("
)
RE_RAW_POINTER_TYPE = re.compile(r"\*\s*(?:mut|const)\b")

# Each high-risk family is counted once per call expression.  The patterns do
# not overlap on the same offset, but a defensive offset-set is used anyway.
HIGH_RISK_PATTERNS = (
    ("transmute", re.compile(r"\btransmute(?:_copy)?\s*(?:::\s*<[^;{}()]*>)?\s*\(")),
    ("assume_init", re.compile(r"\bassume_init(?:_ref|_mut)?\s*\(")),
    ("from_raw_parts", re.compile(r"\bfrom_raw_parts(?:_mut)?\s*\(")),
    ("box_from_raw", re.compile(r"\bBox\s*::\s*from_raw\s*\(")),
    ("nonnull_new_unchecked", re.compile(r"\bNonNull\s*::\s*new_unchecked\s*\(")),
    ("get_unchecked", re.compile(r"\bget_unchecked(?:_mut)?\s*\(")),
    ("unreachable_unchecked", re.compile(r"\bunreachable_unchecked\s*\(")),
    ("set_len", re.compile(r"\bset_len\s*\(")),
)

# grep -E patterns for --check.  These intentionally reproduce the lexical
# contract above without calling the scanner.
CHECK_PATTERNS = {
    "UNSAFE_BLOCK": r"\bunsafe[[:space:]]*\{",
    "UNSAFE_FN_DEF": (
        r"\bunsafe[[:space:]]+"
        r'(extern[[:space:]]+"[^"]*"[[:space:]]+)?'
        r"(async[[:space:]]+)?fn[[:space:]]+(r#)?[A-Za-z_][A-Za-z0-9_]*"
    ),
    "UNSAFE_IMPL": r"\bunsafe[[:space:]]+impl\b",
    "UNSAFE_TRAIT": r"\bunsafe[[:space:]]+trait\b",
    "UNSAFE_EXTERN_BLOCK": r'\bunsafe[[:space:]]+extern[[:space:]]+"[^"]*"[[:space:]]*\{',
    "EXTERN_C_FN_DEF": r'\bextern[[:space:]]+"C"[[:space:]]+fn[[:space:]]+(r#)?[A-Za-z_][A-Za-z0-9_]*',
    "HIGH_RISK_CALL": (
        r"\btransmute(_copy)?[[:space:]]*(::[[:space:]]*<[^;{}()]*>)?[[:space:]]*\("
        r"|\bassume_init(_ref|_mut)?[[:space:]]*\("
        r"|\bfrom_raw_parts(_mut)?[[:space:]]*\("
        r"|\bBox[[:space:]]*::[[:space:]]*from_raw[[:space:]]*\("
        r"|\bNonNull[[:space:]]*::[[:space:]]*new_unchecked[[:space:]]*\("
        r"|\bget_unchecked(_mut)?[[:space:]]*\("
        r"|\bunreachable_unchecked[[:space:]]*\("
        r"|\bset_len[[:space:]]*\("
    ),
    "NONALLOC_FFI_CALL": (
        r"\b(CRYPTO_|OPENSSL_|ossl_)[A-Za-z0-9_]*"
        r"(::[[:space:]]*<[^<>]*>[[:space:]]*)?[[:space:]]*\("
    ),
    "RAW_POINTER_TYPE": r"\*[[:space:]]*(mut|const)\b",
}

# Definitions matched by the high-risk / FFI call regexes must be subtracted
# from raw grep call counts.
CHECK_HIGH_RISK_DEFS = (
    r"\bfn[[:space:]]+"
    r"(transmute|transmute_copy|assume_init|assume_init_ref|assume_init_mut|"
    r"from_raw_parts|from_raw_parts_mut|get_unchecked|get_unchecked_mut|"
    r"unreachable_unchecked|set_len)[[:space:]]*\("
)
# `unsafe extern "C" fn` is counted once, under UNSAFE_FN_DEF.  The
# EXTERN_C_FN_DEF kind is the disjoint remainder (safe ABI definitions).
CHECK_UNSAFE_EXTERN_C_FN = (
    r'\bunsafe[[:space:]]+extern[[:space:]]+"C"[[:space:]]+fn[[:space:]]+'
    r"(r#)?[A-Za-z_][A-Za-z0-9_]*"
)
CHECK_FFI_DEFS = (
    r"\bfn[[:space:]]+(CRYPTO_|OPENSSL_|ossl_)[A-Za-z0-9_]*"
    r"[[:space:]]*(::[[:space:]]*<[^<>]*>[[:space:]]*)?[[:space:]]*\("
)

FFI_PREFIX_RE = re.compile(r"(?:CRYPTO_|OPENSSL_|ossl_)[A-Za-z0-9_]*")


# ---------------------------------------------------------------------------
# Candidate / prior-census helpers.
# ---------------------------------------------------------------------------


def _prior_census(root: Path, head: str) -> dict:
    path = root / PRIOR_CENSUS
    out = {
        "path": PRIOR_CENSUS,
        "present": path.is_file(),
        "reused_for_per_file_denominator": False,
    }
    if not path.is_file():
        out["reason"] = "artifact absent"
        return out
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        body = data.get("body", {})
        counts = body.get("counts", {})
        cross = body.get("crosschecks", {})
        lexical = cross.get("lexical", {})
        consts = body.get("sites", {}).get("consts", {})
        candidate = consts.get("candidate_commit")
        out.update(
            {
                "schema": data.get("schema"),
                "kind": data.get("kind"),
                "generator": data.get("generator"),
                "authority": data.get("authority"),
                "candidate_commit": candidate,
                "counts": {
                    "files": counts.get("files"),
                    "rust_files": counts.get("rust_files"),
                    "operations": counts.get("operations"),
                    "sites": counts.get("sites"),
                    "unsafe_contexts": counts.get("unsafe_contexts"),
                    "contexts_by_kind": counts.get("contexts_by_kind"),
                    "sites_by_kind": counts.get("sites_by_kind"),
                },
                "lexical_crosscheck": {
                    "unsafe_blocks": lexical.get("unsafe_blocks"),
                    "unsafe_fns": lexical.get("unsafe_fns"),
                    "unsafe_impls": lexical.get("unsafe_impls"),
                    "unsafe_externs": lexical.get("unsafe_externs"),
                    "extern_c_fns": lexical.get("extern_c_fns"),
                },
            }
        )
        out["candidate_matches_head"] = candidate == head
        out["reason"] = (
            "schema and count categories consulted; not reused because the "
            "artifact is bound to a different source candidate and does not "
            "provide this production/test/seam lexical partition"
            if candidate != head
            else "schema and count categories consulted; regenerated here for "
            "the production/test/seam partition and independent grep check"
        )
    except Exception as exc:  # noqa: BLE001 - report the failure, do not hide it
        out["error"] = f"{type(exc).__name__}: {exc}"
    return out


# ---------------------------------------------------------------------------
# Scanning helpers.
# ---------------------------------------------------------------------------


def _fn_name(match_text: str) -> str:
    m = re.search(r"\bfn\s+(?:r#)?([A-Za-z_][A-Za-z0-9_]*)", match_text)
    return m.group(1) if m else ""


def _ffi_name(match_text: str) -> str:
    m = FFI_PREFIX_RE.search(match_text)
    return m.group(0) if m else match_text.split("(", 1)[0].strip()


def _restore_abi_literals(text: str, stripped: str) -> str:
    """Restore only the string literal immediately after ``extern``.

    ``atlas_refresh.strip_comments_and_literals`` blanks every string literal,
    including the ABI name in ``extern "C"``.  ABI names are semantically
    significant syntax, not data, so for the ABI-specific patterns we copy the
    original literal back into the already-stripped view.  Comments and every
    other literal remain stripped.  Offsets and line numbers are preserved.

    A candidate literal is restored only when the ``extern`` token itself is
    visible in the stripped view; this rejects occurrences inside comments or
    string literals.
    """
    out = list(stripped)
    for m in re.finditer(r'\bextern\s+(?=")', text):
        if stripped[m.start():m.start() + len("extern")] != "extern":
            continue
        quote = m.end()
        if quote >= len(text) or text[quote] != '"':
            continue
        end = atlas._scan_quoted(text, quote)
        if stripped[quote:end].strip():
            continue
        out[quote:end] = text[quote:end]
    return "".join(out)


def _partition_for(
    rel: str,
    offset: int,
    *,
    is_seam: bool,
    file_is_test: bool,
    module_ranges: list[dict],
    item_ranges: list[dict],
) -> tuple[str, bool, bool]:
    """Return (partition, in_test_module, in_test_item)."""
    in_module = file_is_test or any(
        r["start"] <= offset <= r["end"] for r in module_ranges
    )
    in_item = any(r["start"] <= offset <= r["end"] for r in item_ranges)
    if is_seam:
        return "allocator_seam", in_module, in_item
    if in_module or in_item:
        return "test_only", in_module, in_item
    return "production", in_module, in_item


def _build_surface_and_test_files(root: Path, rel_paths: list[str]):
    """One prepass: allocator surface + external cfg(test) module files.

    This mirrors the prepass in ``atlas_refresh.scan_files`` exactly.
    """
    surface = atlas._empty_surface()
    test_only_files: set[str] = set()
    for rel in rel_paths:
        text = (root / rel).read_text(encoding="utf-8", errors="replace")
        stripped = atlas.strip_comments_and_literals(text)
        atlas._surface_add_source(surface, rel, stripped)
        test_only_files.update(atlas.find_cfg_test_external_mods(root, rel, stripped))
    surface = atlas._finish_surface(surface)
    return surface, test_only_files


def _empty_kind_counts() -> dict[str, int]:
    return {kind: 0 for kind in ALL_KINDS}


def scan(root: Path, rel_paths: list[str]):
    surface, test_only_files = _build_surface_and_test_files(root, rel_paths)
    allocator_names = set(surface["alloc"]) | set(surface["release"])

    sites: list[dict] = []
    files: list[dict] = []
    content_hash = hashlib.sha256()
    content_hash.update(b"openssl-rs/src-rs/v1\x00")

    for rel in rel_paths:
        raw = (root / rel).read_bytes()
        content_hash.update(rel.encode("utf-8"))
        content_hash.update(b"\x00")
        content_hash.update(raw)
        content_hash.update(b"\x00")

        text = raw.decode("utf-8", "replace")
        stripped = atlas.strip_comments_and_literals(text)
        view = _restore_abi_literals(text, stripped)
        lines = view.split("\n")
        starts = atlas._line_starts(text)
        module_ranges, item_ranges, _external = atlas.find_cfg_test_ranges(view)
        is_seam = rel in atlas.SEAM_FILES
        file_is_test = rel in test_only_files

        file_sites: list[dict] = []
        seen_offsets: set[int] = set()
        kind_counts = _empty_kind_counts()
        partition_counts = {p: 0 for p in PARTITIONS}
        context_counts = {p: 0 for p in PARTITIONS}
        context_total = 0

        def add_site(kind: str, offset: int, callee: str = "") -> None:
            line = atlas._offset_to_line(starts, offset) + 1
            partition, in_mod, in_item = _partition_for(
                rel,
                offset,
                is_seam=is_seam,
                file_is_test=file_is_test,
                module_ranges=module_ranges,
                item_ranges=item_ranges,
            )
            site = {
                "file": rel,
                "line": line,
                "kind": kind,
                "callee": callee,
                "function": atlas._enclosing_fn(lines, line - 1),
                "partition": partition,
                "in_test_module": in_mod,
                "in_test_item": in_item,
                "is_test_only_file": file_is_test,
                "is_seam_file": is_seam,
            }
            file_sites.append(site)
            kind_counts[kind] += 1
            partition_counts[partition] += 1

        # Unsafe language constructs.
        for m in RE_UNSAFE_BLOCK.finditer(view):
            add_site("UNSAFE_BLOCK", m.start())
        for m in RE_UNSAFE_FN.finditer(view):
            add_site("UNSAFE_FN_DEF", m.start(), _fn_name(m.group(0)))
        for m in RE_UNSAFE_IMPL.finditer(view):
            add_site("UNSAFE_IMPL", m.start())
        for m in RE_UNSAFE_TRAIT.finditer(view):
            add_site("UNSAFE_TRAIT", m.start())
        for m in RE_UNSAFE_EXTERN_BLOCK.finditer(view):
            add_site("UNSAFE_EXTERN_BLOCK", m.start())

        # High-risk call families.
        for family, pattern in HIGH_RISK_PATTERNS:
            for m in pattern.finditer(view):
                if m.start() in seen_offsets:
                    continue
                if atlas._is_fn_definition(view, m.start()):
                    continue
                seen_offsets.add(m.start())
                add_site("HIGH_RISK_CALL", m.start(), family)

        # Extern "C" function definitions.  An `unsafe extern "C" fn` is
        # already one UNSAFE_FN_DEF site; counting it again here would make the
        # denominator double-count the same source construct.  The disjoint
        # remainder is EXTERN_C_FN_DEF, while
        # `extern_c_fn_definitions_total` below records the full ABI count.
        unsafe_fn_matches = list(RE_UNSAFE_FN.finditer(view))
        unsafe_extern_offsets: set[int] = set()
        for uf in unsafe_fn_matches:
            em = re.search(r"\bextern\b", uf.group(0))
            if em:
                unsafe_extern_offsets.add(uf.start() + em.start())
        extern_c_fn_total = 0
        for m in RE_EXTERN_C_FN.finditer(view):
            extern_c_fn_total += 1
            if m.start() in unsafe_extern_offsets:
                continue
            add_site("EXTERN_C_FN_DEF", m.start(), _fn_name(m.group(0)))

        # Non-allocator C calls by the three OpenSSL prefixes.
        for m in RE_FFI_CALL.finditer(view):
            if atlas._is_fn_definition(view, m.start()):
                continue
            callee = _ffi_name(m.group(0))
            if callee in allocator_names:
                continue
            add_site("NONALLOC_FFI_CALL", m.start(), callee)

        # Raw-pointer type context: counted, never added to operation totals.
        for m in RE_RAW_POINTER_TYPE.finditer(view):
            context_total += 1
            partition, _in_mod, _in_item = _partition_for(
                rel,
                m.start(),
                is_seam=is_seam,
                file_is_test=file_is_test,
                module_ranges=module_ranges,
                item_ranges=item_ranges,
            )
            context_counts[partition] += 1

        sites.extend(file_sites)
        files.append(
            {
                "path": rel,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "is_test_only_file": file_is_test,
                "is_seam_file": is_seam,
                "kind_counts": kind_counts,
                "partition_counts": partition_counts,
                "raw_pointer_type_context": context_total,
                "raw_pointer_type_context_by_partition": context_counts,
                "extern_c_fn_definitions_total": extern_c_fn_total,
                "extern_c_fn_definitions_also_unsafe_fn": len(
                    unsafe_extern_offsets
                ),
                "total_operations": len(file_sites),
            }
        )

    sites.sort(
        key=lambda s: (
            s["file"],
            s["line"],
            s["kind"],
            s["callee"],
            s["function"],
        )
    )
    return {
        "sites": sites,
        "files": files,
        "surface": surface,
        "test_only_files": test_only_files,
        "src_content_sha256": content_hash.hexdigest(),
    }


# ---------------------------------------------------------------------------
# Report construction.
# ---------------------------------------------------------------------------


def _compact_for_json(data: dict, *, intern_functions: bool = False) -> dict:
    """Return the minified v2 payload.

    Sites are grouped by file and encoded as `[line, kind_code, function]`
    arrays.  Per-file aggregate counts are retained verbatim.  When
    `intern_functions` is true the third element is an index into a top-level
    `function_names` table; that is only used if the string form exceeds the
    repository size target.
    """
    codes = dict(KIND_CODES)
    by_file: dict[str, list[list]] = {row["path"]: [] for row in data["files"]}
    if intern_functions:
        names = sorted({site["function"] for site in data["sites"]})
        name_to_id = {name: idx for idx, name in enumerate(names)}
        site_fields = ["line", "kind_code", "function_id"]
        for site in data["sites"]:
            by_file[site["file"]].append(
                [site["line"], codes[site["kind"]], name_to_id[site["function"]]]
            )
    else:
        names = None
        site_fields = ["line", "kind_code", "function"]
        for site in data["sites"]:
            by_file[site["file"]].append(
                [site["line"], codes[site["kind"]], site["function"]]
            )

    files = []
    for row in data["files"]:
        compact_row = dict(row)
        compact_row["sites"] = by_file[row["path"]]
        files.append(compact_row)

    out = {key: value for key, value in data.items() if key != "sites"}
    out["files"] = files
    out["kind_codes"] = codes
    out["site_array_fields"] = site_fields
    if names is not None:
        out["function_names"] = names
    return out


def _closure_files(rel_paths: list[str]) -> list[str]:
    patterns = list(atlas.MECHANISM_PATHS.values())
    return sorted(
        p for p in rel_paths if any(atlas.matches_any(p, pats) for pats in patterns)
    )


def build(root: Path) -> dict:
    rel_paths = atlas.list_src_rs(root)
    scanned = scan(root, rel_paths)
    sites = scanned["sites"]
    files = scanned["files"]
    surface = scanned["surface"]

    head = atlas.git("rev-parse", "HEAD", root=root)
    branch = atlas.git("rev-parse", "--abbrev-ref", "HEAD", root=root)
    version = atlas.crate_version(root)

    closure = _closure_files(rel_paths)
    closure_set = set(closure)
    file_rows = {row["path"]: row for row in files}

    by_kind = {kind: 0 for kind in OPERATION_KINDS}
    by_kind_partition = {
        kind: {p: 0 for p in PARTITIONS} for kind in OPERATION_KINDS
    }
    by_partition = {p: 0 for p in PARTITIONS}
    for site in sites:
        by_kind[site["kind"]] += 1
        by_kind_partition[site["kind"]][site["partition"]] += 1
        by_partition[site["partition"]] += 1

    context_by_partition = {p: 0 for p in PARTITIONS}
    context_total = 0
    extern_c_fn_total = 0
    extern_c_fn_also_unsafe = 0
    for row in files:
        context_total += row["raw_pointer_type_context"]
        extern_c_fn_total += row["extern_c_fn_definitions_total"]
        extern_c_fn_also_unsafe += row["extern_c_fn_definitions_also_unsafe_fn"]
        for p in PARTITIONS:
            context_by_partition[p] += row[
                "raw_pointer_type_context_by_partition"
            ][p]

    # Reconciliation invariant inside the generator itself.
    if sum(by_kind.values()) != len(sites):
        raise AssertionError("kind totals do not reconcile with site count")
    if sum(by_partition.values()) != len(sites):
        raise AssertionError("partition totals do not reconcile with site count")
    for row in files:
        if sum(row["kind_counts"].values()) != row["total_operations"]:
            raise AssertionError(f"per-file kind totals do not reconcile: {row['path']}")
        if sum(row["partition_counts"].values()) != row["total_operations"]:
            raise AssertionError(
                f"per-file partition totals do not reconcile: {row['path']}"
            )

    zero_all = [
        p
        for p in closure
        if file_rows[p]["partition_counts"]["production"] == 0
    ]
    strict_kinds = set(UNSAFE_LANGUAGE_KINDS) | set(HIGH_RISK_KINDS)
    zero_strict = [
        p
        for p in closure
        if sum(
            file_rows[p]["kind_counts"][k] for k in strict_kinds
        )
        == 0
    ]

    prior = _prior_census(root, head)

    return {
        "schema": SCHEMA,
        "kind": KIND,
        "generator": "forensics/memory-safety/campaign/safe-c33/unsafe_census.py",
        "generated_utc": atlas.candidate_utc(root),
        "candidate": {
            "head_sha": head,
            "branch": branch,
            "crate_version": version,
            "src_rs_files": len(rel_paths),
            "src_content_sha256": scanned["src_content_sha256"],
            "src_content_hash_rule": (
                "sha256 over the byte string 'openssl-rs/src-rs/v1\\0' followed, "
                "for each src/**/*.rs in sorted relative-path order, by "
                "relpath\\0filebytes\\0"
            ),
        },
        "method": {
            "source_partition": (
                "production = not in a #[cfg(test)] module/item and not an "
                "allocator-seam file; test_only = in a #[cfg(test)] inline "
                "module/item or a file pulled in by #[cfg(test)] mod name; "
                "allocator_seam = src/runtime/mem.rs or src/runtime/secure.rs. "
                "The partition order is seam, then test, then production."
            ),
            "stripping": (
                "atlas_refresh.strip_comments_and_literals; offsets and 1-based "
                "line numbers are preserved. The ABI string literal immediately "
                "after `extern` is restored so `extern \"C\"` remains visible; "
                "comments and every other literal stay stripped."
            ),
            "enclosing_function": (
                "atlas_refresh._enclosing_fn: nearest preceding fn at lower "
                "indentation (best effort)"
            ),
            "allocator_surface": {
                "seam_files": surface["seam_files"],
                "alloc_count": len(surface["alloc"]),
                "release_count": len(surface["release"]),
                "aliases": surface["aliases"],
                "excluded_from_allocator_surface": surface["excluded"],
            },
            "operation_kinds": list(OPERATION_KINDS),
            "context_kinds": list(CONTEXT_KINDS),
            "context_kind_is_not_an_operation": True,
            "extern_c_fn_definition_accounting": (
                "an `unsafe extern \"C\" fn` is counted once under "
                "UNSAFE_FN_DEF; EXTERN_C_FN_DEF is the disjoint safe-ABI "
                "remainder. totals.extern_c_fn_definitions_total records the "
                "full number of named per-item `extern \"C\" fn` definitions. "
                "Function-pointer types such as `extern \"C\" fn(...)` are "
                "not definitions and are not counted."
            ),
            "check_command": (
                "python3 forensics/memory-safety/campaign/safe-c33/"
                "unsafe_census.py --check"
            ),
        },
        "prior_census": prior,
        "totals": {
            "operations": len(sites),
            "by_kind": by_kind,
            "by_partition": by_partition,
            "by_kind_partition": by_kind_partition,
            "raw_pointer_type_context": context_total,
            "raw_pointer_type_context_by_partition": context_by_partition,
            "extern_c_fn_definitions_total": extern_c_fn_total,
            "extern_c_fn_definitions_also_unsafe_fn": extern_c_fn_also_unsafe,
            "extern_c_fn_definitions_safe_abi": extern_c_fn_total
            - extern_c_fn_also_unsafe,
        },
        "files": files,
        "sites": sites,
        "closure": {
            "source": (
                "union of atlas_refresh.MECHANISM_PATHS (the nine Safe-33 "
                "mechanism path sets)"
            ),
            "files": closure,
            "files_count": len(closure),
            "zero_production_operation_files": zero_all,
            "zero_production_operation_files_count": len(zero_all),
            "zero_production_unsafe_language_or_high_risk_files": zero_strict,
            "zero_production_unsafe_language_or_high_risk_files_count": len(
                zero_strict
            ),
        },
    }


# ---------------------------------------------------------------------------
# Markdown report.
# ---------------------------------------------------------------------------


def _fmt_int(value) -> str:
    return f"{value:,}" if isinstance(value, int) else "n/a"


def render_markdown(data: dict, compact: dict | None = None) -> str:
    cand = data["candidate"]
    totals = data["totals"]
    prior = data["prior_census"]
    closure = data["closure"]
    lines: list[str] = []

    lines.append("# Unsafe census — src/**/*.rs")
    lines.append("")
    lines.append(
        "Deterministic, candidate-bound measurement of unsafe operations. "
        "This report makes no safety or compatibility claim."
    )
    lines.append("")
    lines.append(f"- Schema: `{data['schema']}`")
    lines.append(f"- Generator: `{data['generator']}`")
    lines.append(f"- Generated (candidate-bound): `{data['generated_utc']}`")
    lines.append(f"- Branch: `{cand['branch']}`")
    lines.append(f"- HEAD: `{cand['head_sha']}`")
    lines.append(f"- Crate version: `{cand['crate_version']}`")
    lines.append(f"- Rust files: {_fmt_int(cand['src_rs_files'])}")
    lines.append(f"- Source content sha256: `{cand['src_content_sha256']}`")
    lines.append("")

    lines.append("## Compact JSON schema")
    lines.append("")
    lines.append(
        "The JSON is minified (no indentation) and uses schema v2. "
        "`kind_codes` maps each operation kind to the code used in site arrays."
    )
    if compact is not None:
        fields = ", ".join(f"`{field}`" for field in compact["site_array_fields"])
        lines.append(
            f"`files[].sites` records are three-element arrays ({fields}); "
            "the third field is "
            + (
                "an integer index into the top-level `function_names` table."
                if "function_names" in compact
                else "the enclosing function name."
            )
        )
    lines.append(
        "`kind_codes` maps: "
        + ", ".join(f"`{kind}`=`{code}`" for kind, code in sorted(KIND_CODES.items()))
        + "."
    )
    lines.append(
        "Per-file aggregates remain in `files[].kind_counts`, "
        "`files[].partition_counts`, and the scalar count fields; "
        "`RAW_POINTER_TYPE` remains a per-file context scalar, not a site."
    )
    lines.append("")
    lines.append("## Existing Phase-25 census")
    lines.append("")
    if prior.get("present"):
        lines.append(f"- Path: `{prior.get('path')}`")
        lines.append(f"- Schema: `{prior.get('schema')}`")
        lines.append(f"- Generator: `{prior.get('generator')}`")
        lines.append(f"- Candidate commit: `{prior.get('candidate_commit')}`")
        lines.append(
            f"- Candidate matches current HEAD: "
            f"`{prior.get('candidate_matches_head')}`"
        )
        lines.append(
            f"- Reused for the per-file denominator: "
            f"`{prior.get('reused_for_per_file_denominator')}`"
        )
        lines.append(f"- Reason: {prior.get('reason')}")
        lex = prior.get("lexical_crosscheck", {})
        lines.append(
            "- Lexical cross-check from the artifact: "
            f"unsafe_blocks={_fmt_int(lex.get('unsafe_blocks'))}, "
            f"unsafe_fns={_fmt_int(lex.get('unsafe_fns'))}, "
            f"unsafe_impls={_fmt_int(lex.get('unsafe_impls'))}, "
            f"unsafe_externs={_fmt_int(lex.get('unsafe_externs'))}, "
            f"extern_c_fns={_fmt_int(lex.get('extern_c_fns'))}."
        )
    else:
        lines.append("- No usable Phase-25 source census was found.")
    lines.append("")

    lines.append("## Totals by kind")
    lines.append("")
    lines.append(
        "| kind | production | test-only | allocator seam | total |"
    )
    lines.append("|---|---:|---:|---:|---:|")
    for kind in OPERATION_KINDS:
        row = totals["by_kind_partition"][kind]
        lines.append(
            f"| `{kind}` | {_fmt_int(row['production'])} | "
            f"{_fmt_int(row['test_only'])} | "
            f"{_fmt_int(row['allocator_seam'])} | "
            f"{_fmt_int(totals['by_kind'][kind])} |"
        )
    lines.append(
        f"| **operations** | **{_fmt_int(totals['by_partition']['production'])}** | "
        f"**{_fmt_int(totals['by_partition']['test_only'])}** | "
        f"**{_fmt_int(totals['by_partition']['allocator_seam'])}** | "
        f"**{_fmt_int(totals['operations'])}** |"
    )
    lines.append("")
    lines.append("### Separate context metric (not an unsafe operation)")
    lines.append("")
    lines.append(
        f"Raw-pointer type contexts (`*mut` / `*const`): "
        f"**{_fmt_int(totals['raw_pointer_type_context'])}** "
        f"(production {_fmt_int(totals['raw_pointer_type_context_by_partition']['production'])}, "
        f"test-only {_fmt_int(totals['raw_pointer_type_context_by_partition']['test_only'])}, "
        f"allocator seam {_fmt_int(totals['raw_pointer_type_context_by_partition']['allocator_seam'])})."
    )
    lines.append("")
    lines.append(
        "Extern \"C\" function definitions: "
        f"**{_fmt_int(totals['extern_c_fn_definitions_total'])}** total; "
        f"{_fmt_int(totals['extern_c_fn_definitions_also_unsafe_fn'])} are "
        "`unsafe extern \"C\" fn` and are counted once under "
        "`UNSAFE_FN_DEF`, leaving "
        f"{_fmt_int(totals['extern_c_fn_definitions_safe_abi'])} safe-ABI "
        "`EXTERN_C_FN_DEF` sites."
    )
    lines.append("")

    productive = [
        f
        for f in data["files"]
        if f["partition_counts"]["production"] > 0
    ]
    productive.sort(
        key=lambda f: (-f["partition_counts"]["production"], f["path"])
    )
    lines.append("## Top 25 production files")
    lines.append("")
    lines.append("| file | production ops | breakdown |")
    lines.append("|---|---:|---|")
    for f in productive[:25]:
        breakdown = ", ".join(
            f"{kind}={f['kind_counts'][kind]}"
            for kind in OPERATION_KINDS
            if f["kind_counts"][kind]
        )
        lines.append(
            f"| `{f['path']}` | {_fmt_int(f['partition_counts']['production'])} | "
            f"{breakdown} |"
        )
    lines.append("")

    lines.append("## Closure files with ZERO production unsafe ops")
    lines.append("")
    lines.append(
        f"Closure set: {_fmt_int(closure['files_count'])} files "
        "(union of the nine Safe-33 mechanism path sets)."
    )
    lines.append("")
    lines.append(
        f"- Zero production operations (all counted kinds, including extern "
        f"\"C\" definitions and non-allocator FFI calls): "
        f"**{_fmt_int(closure['zero_production_operation_files_count'])}**"
    )
    lines.append(
        f"- Zero production unsafe-language constructs or high-risk calls "
        f"(narrower subset): "
        f"**{_fmt_int(closure['zero_production_unsafe_language_or_high_risk_files_count'])}**"
    )
    lines.append("")
    for path in closure["zero_production_operation_files"]:
        lines.append(f"- `{path}`")
    lines.append("")

    lines.append("## Method")
    lines.append("")
    lines.append(f"- Partition: {data['method']['source_partition']}")
    lines.append(f"- Stripping: {data['method']['stripping']}")
    lines.append(f"- Enclosing function: {data['method']['enclosing_function']}")
    lines.append(
        "- Closure zero-production lists can include allocator-seam files "
        "(`src/runtime/mem.rs`, `src/runtime/secure.rs`): their operations are "
        "classified as allocator seam, so their production count is zero by "
        "the partition, not because the file is unsafe-free."
    )
    surf = data["method"]["allocator_surface"]
    lines.append(
        f"- Allocator surface: {surf['alloc_count']} alloc and "
        f"{surf['release_count']} release names discovered from "
        f"{', '.join('`' + s + '`' for s in surf['seam_files'])}; "
        "those calls are excluded from `NONALLOC_FFI_CALL`."
    )
    lines.append(
        "- `RAW_POINTER_TYPE` is a context metric and is excluded from every "
        "operation total."
    )
    lines.append("")

    lines.append("## Independent reconciliation")
    lines.append("")
    lines.append(
        "Run `python3 forensics/memory-safety/campaign/safe-c33/"
        "unsafe_census.py --check` for an independent `grep -E` pass over a "
        "temporary tree of stripped sources.  It compares per-file counts for "
        "the unsafe constructs, extern \"C\" definitions, high-risk calls, "
        "non-allocator FFI calls, and raw-pointer contexts; any mismatch exits "
        "non-zero."
    )
    lines.append("")

    lines.append("## Residual limitations")
    lines.append("")
    lines.append(
        "- Lexical scanner, not a Rust parser: macro bodies are counted where "
        "written; tokens produced only by macro expansion are not observed."
    )
    lines.append(
        "- Enclosing function is a best-effort nearest-indent heuristic; "
        "closures, nested items, and macro-generated functions can be "
        "misattributed."
    )
    lines.append(
        "- Test classification follows `atlas_refresh`: `#[cfg(test)]` inline "
        "modules/items and resolvable `#[cfg(test)] mod name;` files only. "
        "`#[path]` overrides, `cfg_attr(..., cfg(test))`, and "
        "`cfg(any(test, ...))` are not reclassified."
    )
    lines.append(
        "- `EXTERN_C_FN_DEF` counts named per-item `extern \"C\" fn` "
        "definitions; function-pointer types such as `extern \"C\" fn(...)` "
        "and bare `fn` declarations inside `extern \"C\" { ... }` blocks are "
        "not separate definition sites (the enclosing unsafe extern block is "
        "counted)."
    )
    lines.append(
        "- `NONALLOC_FFI_CALL` is lexical and prefix-based; calls through "
        "function pointers, type aliases, or macros are not observed. The "
        "allocator exclusion set is derived from the seam files, not from C "
        "headers."
    )
    lines.append(
        "- `RAW_POINTER_TYPE` counts `*mut` / `*const` type-syntax occurrences, "
        "not distinct declarations or pointer values."
    )
    lines.append(
        "- Counts are a denominator, not a severity ranking. They say nothing "
        "about reachability, ownership soundness, compatibility, or "
        "cryptographic correctness."
    )
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# --check: independent grep reconciliation.
# ---------------------------------------------------------------------------


def _strip_tree(root: Path, rel_paths: list[str], tmp: Path) -> None:
    for rel in rel_paths:
        text = (root / rel).read_text(encoding="utf-8", errors="replace")
        stripped = atlas.strip_comments_and_literals(text)
        view = _restore_abi_literals(text, stripped)
        dest = tmp / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        # grep is line-oriented, while several legitimate Rust forms (e.g. a
        # turbofish split over lines) put whitespace/newlines inside a call
        # expression.  Newline-normalising the already-stripped view keeps
        # grep's match set aligned with the offset-preserving Python scanner;
        # this view is only used for count reconciliation, never for lines.
        dest.write_text(view.replace("\n", " "), encoding="utf-8")


def _grep_counts(tmp: Path, pattern: str) -> Counter:
    proc = subprocess.run(
        [
            "grep",
            "-R",
            "-o",
            "-H",
            "-E",
            "--include=*.rs",
            pattern,
            str(tmp),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode not in (0, 1):
        raise RuntimeError(
            f"grep failed ({proc.returncode}): "
            f"{proc.stderr.decode('utf-8', 'replace').strip()}"
        )
    counts: Counter = Counter()
    for line in proc.stdout.decode("utf-8", "replace").splitlines():
        path, sep, _match = line.partition(":")
        if not sep:
            continue
        counts[os.path.relpath(path, tmp)] += 1
    return counts


def _grep_matches(tmp: Path, pattern: str) -> list[tuple[str, str]]:
    proc = subprocess.run(
        [
            "grep",
            "-R",
            "-o",
            "-H",
            "-E",
            "--include=*.rs",
            pattern,
            str(tmp),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode not in (0, 1):
        raise RuntimeError(
            f"grep failed ({proc.returncode}): "
            f"{proc.stderr.decode('utf-8', 'replace').strip()}"
        )
    out: list[tuple[str, str]] = []
    for line in proc.stdout.decode("utf-8", "replace").splitlines():
        path, sep, match = line.partition(":")
        if not sep:
            continue
        out.append((os.path.relpath(path, tmp), match))
    return out


def _expected_counts(data: dict, failures: list[str]) -> dict[str, Counter]:
    expected: dict[str, Counter] = {kind: Counter() for kind in CHECK_PATTERNS}
    code_to_kind = {code: kind for kind, code in data["kind_codes"].items()}
    for row in data["files"]:
        path = row["path"]
        for rec in row.get("sites", []):
            if not isinstance(rec, list) or len(rec) != 3:
                failures.append(f"site_array: {path}: malformed record {rec!r}")
                continue
            _line, code, _function = rec
            kind = code_to_kind.get(code)
            if kind is None:
                failures.append(f"site_array: {path}: unknown kind code {code!r}")
                continue
            expected[kind][path] += 1
        for kind, count in row["kind_counts"].items():
            actual = expected[kind][path]
            if actual != count:
                failures.append(
                    f"site_array: {path}: {kind}: sites={actual} "
                    f"kind_counts={count}"
                )
        if len(row.get("sites", [])) != row["total_operations"]:
            failures.append(
                f"site_array: {path}: sites={len(row.get('sites', []))} "
                f"total_operations={row['total_operations']}"
            )
        expected["RAW_POINTER_TYPE"][path] += row["raw_pointer_type_context"]
    return expected


def _compare(
    kind: str, actual: Counter, expected: Counter, failures: list[str]
) -> None:
    paths = sorted(set(actual) | set(expected))
    for path in paths:
        if actual.get(path, 0) != expected.get(path, 0):
            failures.append(
                f"{kind}: {path}: grep={actual.get(path, 0)} "
                f"census={expected.get(path, 0)}"
            )


def check(root: Path, data: dict) -> int:
    rel_paths = atlas.list_src_rs(root)
    # The JSON records only counts, so rediscover the exact allocator name set
    # from the same seam helpers used by the generator.
    surface, _test_files = _build_surface_and_test_files(root, rel_paths)
    allocator_names = set(surface["alloc"]) | set(surface["release"])

    failures: list[str] = []
    expected = _expected_counts(data, failures)

    with tempfile.TemporaryDirectory(prefix="unsafe-census-check-") as tmp_name:
        tmp = Path(tmp_name)
        _strip_tree(root, rel_paths, tmp)

        for kind in (
            "UNSAFE_BLOCK",
            "UNSAFE_FN_DEF",
            "UNSAFE_IMPL",
            "UNSAFE_TRAIT",
            "UNSAFE_EXTERN_BLOCK",
            "RAW_POINTER_TYPE",
        ):
            actual = _grep_counts(tmp, CHECK_PATTERNS[kind])
            _compare(kind, actual, expected[kind], failures)

        # Extern "C" definitions: the census counts `unsafe extern "C" fn`
        # once under UNSAFE_FN_DEF, so subtract that overlap from the raw grep
        # count before comparing EXTERN_C_FN_DEF (the safe-ABI remainder).
        extern_all = _grep_counts(tmp, CHECK_PATTERNS["EXTERN_C_FN_DEF"])
        extern_unsafe = _grep_counts(tmp, CHECK_UNSAFE_EXTERN_C_FN)
        extern_disjoint = extern_all.copy()
        extern_disjoint.subtract(extern_unsafe)
        _compare(
            "EXTERN_C_FN_DEF",
            extern_disjoint,
            expected["EXTERN_C_FN_DEF"],
            failures,
        )
        if sum(extern_all.values()) != data["totals"]["extern_c_fn_definitions_total"]:
            failures.append(
                "EXTERN_C_FN_DEF total: grep="
                f"{sum(extern_all.values())} census="
                f"{data['totals']['extern_c_fn_definitions_total']}"
            )

        # High-risk calls: raw grep includes function definitions; subtract
        # those definitions to match the scanner's `_is_fn_definition` filter.
        high_actual = _grep_counts(tmp, CHECK_PATTERNS["HIGH_RISK_CALL"])
        high_defs = _grep_counts(tmp, CHECK_HIGH_RISK_DEFS)
        high_actual.subtract(high_defs)
        _compare("HIGH_RISK_CALL", high_actual, expected["HIGH_RISK_CALL"], failures)

        # Non-allocator FFI calls: filter allocator names and subtract per-item
        # function definitions.
        ffi_actual: Counter = Counter()
        for rel, match_text in _grep_matches(tmp, CHECK_PATTERNS["NONALLOC_FFI_CALL"]):
            if _ffi_name(match_text) in allocator_names:
                continue
            ffi_actual[rel] += 1
        ffi_defs: Counter = Counter()
        for rel, match_text in _grep_matches(tmp, CHECK_FFI_DEFS):
            if _ffi_name(match_text) in allocator_names:
                continue
            ffi_defs[rel] += 1
        ffi_actual.subtract(ffi_defs)
        _compare(
            "NONALLOC_FFI_CALL",
            ffi_actual,
            expected["NONALLOC_FFI_CALL"],
            failures,
        )

    if failures:
        print(f"FAIL: {len(failures)} per-file reconciliation mismatch(es)")
        for item in failures[:40]:
            print(f"  {item}")
        if len(failures) > 40:
            print(f"  ... {len(failures) - 40} more")
        return 1

    print(
        "PASS: independent stripped-source grep reconciliation matches "
        f"{len(rel_paths)} files and "
        f"{sum(sum(c.values()) for c in expected.values())} counted sites"
    )
    return 0


# ---------------------------------------------------------------------------
# Entry point.
# ---------------------------------------------------------------------------


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="independently reconcile the generated JSON with grep over stripped sources",
    )
    args = parser.parse_args(argv)

    root = atlas.repo_root()
    if args.check:
        if not JSON_PATH.is_file():
            print(f"FAIL: {JSON_PATH} is absent; run the generator first")
            return 1
        data = json.loads(JSON_PATH.read_text(encoding="utf-8"))
        return check(root, data)

    data = build(root)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    compact = _compact_for_json(data)
    JSON_PATH.write_text(
        json.dumps(compact, separators=(",", ":"), sort_keys=True),
        encoding="utf-8",
    )
    MD_PATH.write_text(render_markdown(data, compact), encoding="utf-8")

    totals = data["totals"]
    print(
        f"wrote {JSON_PATH.relative_to(root)} and {MD_PATH.relative_to(root)} "
        f"for {data['candidate']['head_sha']}: "
        f"{totals['operations']} operations "
        f"(production={totals['by_partition']['production']}, "
        f"test_only={totals['by_partition']['test_only']}, "
        f"allocator_seam={totals['by_partition']['allocator_seam']}); "
        f"raw-pointer contexts={totals['raw_pointer_type_context']}; "
        f"closure zero-production={data['closure']['zero_production_operation_files_count']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
