#!/usr/bin/env python3
"""Conservative boundary attribution for the safe-c33 unsafe census.

This is a measurement/audit tool, not a conversion tool.  It attributes each
*production* unsafe operation recorded by ``atlas-refresh/unsafe-census.json``
to at most one registered boundary, or leaves it in the explicit
``UNATTRIBUTED`` queue.

Attribution is **not** discharge.  A site placed under a boundary is merely
covered by that boundary's declared scope; no caller contract, aliasing proof,
lifetime proof or cryptographic property is established here.  See §7 of
``AGENTS.md``.

Candidate binding
-----------------
The census is pinned to the commit recorded in ``candidate.head_sha`` and the
``src/`` content hash recorded in ``candidate.src_content_sha256``.  The
working tree may legitimately be ahead of that commit, so this tool reads every
source file from the pinned commit through ``git archive`` and verifies the
census content hash before using any line context.  It never reads ``src/``
from the working tree.

Source classification
---------------------
The production/test/seam partition is reconstructed exactly as
``unsafe_census.py`` did, using the shared ``atlas_refresh`` helpers:
``#[cfg(test)]`` module/item ranges, external ``#[cfg(test)] mod name;`` files,
and the allocator seam files.  Per-file partition counts are reconciled against
the census; a mismatch is a hard failure.

Boundary precedence
-------------------
One site belongs to at most one boundary.  Predicates are evaluated in this
fixed order and the first match wins, so counts are stable and never
double-counted:

  1. B-ALLOC-SEAM   exact (file, line) join with site-worklist.json
  2. B-REFCOUNT     src/runtime/refcount.rs, or a function/line using up_ref/down_ref
  3. B-LOCK         src/runtime/thread.rs, or a function/line using CRYPTO_THREAD_*
  4. B-DESTRUCTOR   destructor-trait unsafe impl, or a *_destroy_body function
  5. B-OWNER-ADOPT  shared-owner constructor using adopt/from_raw/assume_init/into_raw
  6. B-OPAQUE       the four opaque-representation files
  7. B-FFI-ABI      EVERY EXTERN_C_FN_DEF / NONALLOC_FFI_CALL (coverage-by-policy)

Anything else is UNATTRIBUTED.

Run:
  python3 forensics/memory-safety/campaign/safe-c33/unsafe_attribution.py
  python3 forensics/memory-safety/campaign/safe-c33/unsafe_attribution.py --check
"""

from __future__ import annotations

import argparse
import bisect
import hashlib
import io
import json
import re
import subprocess
import sys
import tarfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
ATLAS_DIR = HERE / "atlas-refresh"
CENSUS_PATH = ATLAS_DIR / "unsafe-census.json"
WORKLIST_PATH = ATLAS_DIR / "site-worklist.json"
OUT_JSON = ATLAS_DIR / "attribution.json"
OUT_MD = HERE / "ATTRIBUTION.md"

sys.path.insert(0, str(HERE))

import atlas_refresh as atlas  # noqa: E402  (local campaign helper)
import unsafe_census as uc  # noqa: E402  (reuse the exact stripper/restorer)

SCHEMA = "openssl-rs/p25-safe-c33/unsafe-attribution/1"
KIND = "production-unsafe-site-attribution"

BOUNDARIES = (
    "B-ALLOC-SEAM",
    "B-REFCOUNT",
    "B-LOCK",
    "B-DESTRUCTOR",
    "B-OWNER-ADOPT",
    "B-OPAQUE",
    "B-FFI-ABI",
)

BOUNDARY_META = {
    "B-ALLOC-SEAM": {
        "scope": (
            "Production allocation/release call sites listed in "
            "atlas-refresh/site-worklist.json.  The join is exact on "
            "(file, line); each matched census operation on that line is "
            "attributed."
        ),
        "evidence": [
            "atlas-refresh/site-worklist.json",
            "OWNER-DUPLICATES.md",
            "REFCOUNT-BOUNDARY.md",
        ],
        "predicate": "(file, line) appears in site-worklist.json",
        "coverage": "per-site (line-exact call-site evidence)",
    },
    "B-REFCOUNT": {
        "scope": (
            "Sites in src/runtime/refcount.rs and remaining sites whose "
            "enclosing function or immediate source window references "
            "up_ref/down_ref.  Evaluated after B-ALLOC-SEAM."
        ),
        "evidence": ["REFCOUNT-BOUNDARY.md"],
        "predicate": (
            "file == src/runtime/refcount.rs OR "
            "\\b(down_ref|up_ref)\\s*\\( in the enclosing fn / line window"
        ),
        "coverage": "per-site within a declared mechanism scope",
    },
    "B-LOCK": {
        "scope": (
            "Sites in src/runtime/thread.rs and remaining sites whose "
            "enclosing function or immediate source window references "
            "CRYPTO_THREAD_*.  Evaluated after B-ALLOC-SEAM and B-REFCOUNT."
        ),
        "evidence": ["OPAQUE-REPRESENTATIONS.md (subphase 44)"],
        "predicate": (
            "file == src/runtime/thread.rs OR \\bCRYPTO_THREAD_ in the "
            "enclosing fn / line window"
        ),
        "coverage": "per-site within a declared mechanism scope",
    },
    "B-DESTRUCTOR": {
        "scope": (
            "unsafe impls of the destructor traits enumerated in "
            "DESTRUCTOR-CONTRACTS.md (CtxDestroy, CipherDestroy, KdfDestroy, "
            "MacDestroy, DrbgCtx, GcmDestroy, FreeOnDrop, Drop) and "
            "definitions of *_destroy_body.  Send/Sync and other unsafe impls "
            "are deliberately not attributed here."
        ),
        "evidence": ["DESTRUCTOR-CONTRACTS.md"],
        "predicate": (
            "kind == UNSAFE_IMPL and impl trait in DESTRUCTOR_TRAITS, OR "
            "enclosing fn name ends with destroy_body"
        ),
        "coverage": "per-site, trait-scoped",
    },
    "B-OWNER-ADOPT": {
        "scope": (
            "unsafe adopt/from_raw/RawCtx/assume_init/into_raw sites whose "
            "enclosing constructor is associated with one of the shared owner "
            "types OwnedBuf, OwnedStr, OwnedCtx, RawCtx or OwnedBlock.  Local "
            "owner types with other names are left unattributed."
        ),
        "evidence": ["OWNER-DUPLICATES.md (canonical shared types)"],
        "predicate": (
            "enclosing fn name in OWNER_CTOR_NAMES AND impl header/function "
            "mentions a shared owner type AND an adopt-ish token is present"
        ),
        "coverage": "per-site, constructor-scoped",
    },
    "B-OPAQUE": {
        "scope": (
            "Remaining sites in the opaque-representation files named in "
            "OPAQUE-REPRESENTATIONS.md: src/runtime/thread.rs, "
            "src/runtime/stack.rs, src/runtime/lhash.rs, src/bn/recp.rs.  "
            "Sites already claimed by an earlier boundary keep that boundary; "
            "this is file-level representation coverage, not a per-site proof."
        ),
        "evidence": ["OPAQUE-REPRESENTATIONS.md"],
        "predicate": "file in OPAQUE_FILES",
        "coverage": "file-level (representation boundary)",
    },
    "B-FFI-ABI": {
        "scope": (
            "Every EXTERN_C_FN_DEF and every non-allocator CRYPTO_* / "
            "OPENSSL_* / ossl_* call recorded by the census that is not "
            "already claimed by an earlier, more specific boundary.  This is "
            "residual coverage-by-policy at the ABI edge, not a per-site ABI "
            "proof; allocator calls are covered by B-ALLOC-SEAM instead."
        ),
        "evidence": ["AGENTS.md §0/§10 (C ABI facade policy)"],
        "predicate": "kind in {EXTERN_C_FN_DEF, NONALLOC_FFI_CALL}",
        "coverage": "coverage-by-policy (not per-site proof)",
    },
}

# Destructor traits audited in DESTRUCTOR-CONTRACTS.md.  Send/Sync and other
# unsafe impls are not destructor boundaries and intentionally stay unattributed.
DESTRUCTOR_TRAITS = {
    "CtxDestroy",
    "CipherDestroy",
    "KdfDestroy",
    "MacDestroy",
    "DrbgCtx",
    "GcmDestroy",
    "FreeOnDrop",
    "Drop",
}

SHARED_OWNER_RE = re.compile(r"\b(OwnedBuf|OwnedStr|OwnedCtx|RawCtx|OwnedBlock)\b")
OWNER_CTOR_NAMES = {
    "adopt",
    "adopt_cleansed",
    "adopt_plain",
    "adopt_secure",
    "adopt_conditional",
    "adopt_nullable",
    "adopt_secure_cleansed",
    "take",
    "take_string",
    "from_raw",
    "from_raw_clear",
    "from_raw_parts",
    "from_raw_parts_mut",
    "assume_init",
    "assume_init_ref",
    "assume_init_mut",
    "into_raw",
    "new",
    "new_zeroed",
    "new_uninit",
    "new_with_release",
}
ADOPT_NAME_RE = re.compile(r"^(adopt|from_raw|assume_init|into_raw|take)")
ADOPT_TOKEN_RE = re.compile(
    r"\b(adopt\w*|from_raw\w*|assume_init\w*|into_raw\w*|take\w*|RawCtx)\b"
)
DOWN_UP_RE = re.compile(r"\b(down_ref|up_ref)\s*\(")
THREAD_RE = re.compile(r"\bCRYPTO_THREAD_")
IMPL_TRAIT_RE = re.compile(
    r"([A-Za-z_][A-Za-z0-9_:]*)\s*(?:<[^<>]*>\s*)?\bfor\b", re.S
)

OPAQUE_FILES = {
    "src/runtime/thread.rs",
    "src/runtime/stack.rs",
    "src/runtime/lhash.rs",
    "src/bn/recp.rs",
}

FN_RE = re.compile(r"\bfn\s+(?:r#)?([A-Za-z_][A-Za-z0-9_]*)")
IMPL_RE = re.compile(r"(?m)^[ \t]*(?:unsafe[ \t]+)?impl\b")


# ---------------------------------------------------------------------------
# Pinned source access
# ---------------------------------------------------------------------------


def load_census() -> dict:
    with CENSUS_PATH.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def load_worklist() -> dict:
    with WORKLIST_PATH.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def pinned_sources(rev: str) -> dict[str, str]:
    """Read every src/**/*.rs file from ``rev`` through one git archive."""
    proc = subprocess.run(
        ["git", "archive", "--format=tar", rev, "src"],
        cwd=ROOT,
        capture_output=True,
    )
    if proc.returncode != 0:
        raise SystemExit(
            "pinned source commit is unavailable: "
            f"{rev}: {proc.stderr.decode('utf-8', 'replace').strip()}"
        )
    out: dict[str, str] = {}
    with tarfile.open(fileobj=io.BytesIO(proc.stdout)) as tar:
        for member in tar.getmembers():
            if not member.isfile() or not member.name.endswith(".rs"):
                continue
            handle = tar.extractfile(member)
            if handle is None:
                continue
            out[member.name] = handle.read().decode("utf-8", "replace")
    return out


def content_hash(texts: dict[str, str]) -> str:
    digest = hashlib.sha256()
    digest.update(b"openssl-rs/src-rs/v1\x00")
    for rel in sorted(texts):
        digest.update(rel.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(texts[rel].encode("utf-8"))
        digest.update(b"\x00")
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# Test/seam partition reconstruction (same contract as unsafe_census.py)
# ---------------------------------------------------------------------------


def resolve_external_mod(rel: str, name: str, path_set: set[str]) -> str | None:
    base = Path(rel)
    if base.name == "mod.rs":
        candidates = [base.parent / f"{name}.rs", base.parent / name / "mod.rs"]
    elif rel in ("src/lib.rs", "src/main.rs"):
        candidates = [Path("src") / f"{name}.rs", Path("src") / name / "mod.rs"]
    else:
        stem_dir = base.with_suffix("")
        candidates = [stem_dir / f"{name}.rs", stem_dir / name / "mod.rs"]
    for cand in candidates:
        posix = cand.as_posix()
        if posix in path_set:
            return posix
    return None


def build_test_files(texts: dict[str, str], views: dict[str, str]) -> set[str]:
    path_set = set(texts)
    test_files: set[str] = set()
    for rel in sorted(texts):
        _modules, _items, names = atlas.find_cfg_test_ranges(views[rel])
        for name in names:
            child = resolve_external_mod(rel, name, path_set)
            if child is not None:
                test_files.add(child)
    return test_files


def partition_for(
    rel: str,
    offset: int,
    *,
    is_seam: bool,
    file_is_test: bool,
    module_ranges: list[dict],
    item_ranges: list[dict],
) -> str:
    in_module = file_is_test or any(
        r["start"] <= offset <= r["end"] for r in module_ranges
    )
    in_item = any(r["start"] <= offset <= r["end"] for r in item_ranges)
    if is_seam:
        return "allocator_seam"
    if in_module or in_item:
        return "test_only"
    return "production"


# ---------------------------------------------------------------------------
# Lightweight lexical context for predicates
# ---------------------------------------------------------------------------


def _find_body_open(text: str, pos: int, limit: int = 8000) -> int | None:
    """Find the `{` that opens a fn/impl body, ignoring `;` in brackets."""
    depth = 0
    stop = min(len(text), pos + limit)
    i = pos
    while i < stop:
        ch = text[i]
        if ch in "([":
            depth += 1
        elif ch in ")]":
            if depth:
                depth -= 1
        elif ch == "{" and depth == 0:
            return i
        elif ch == ";" and depth == 0:
            return None
        elif ch == "}" and depth == 0:
            return None
        i += 1
    return None


def _match_brace(text: str, open_idx: int) -> int | None:
    depth = 0
    for idx in range(open_idx, len(text)):
        ch = text[idx]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return idx
    return None


class FnInfo:
    __slots__ = ("name", "decl", "line", "body")

    def __init__(self, name: str, decl: int, line: int, body: tuple[int, int] | None):
        self.name = name
        self.decl = decl
        self.line = line
        self.body = body


class ImplInfo:
    __slots__ = ("start", "end", "header")

    def __init__(self, start: int, end: int | None, header: str):
        self.start = start
        self.end = end
        self.header = header


class FileModel:
    """Precomputed function/impl spans and lines for one source file."""

    def __init__(self, rel: str, raw: str, stripped: str, view: str):
        self.rel = rel
        self.raw = raw
        self.stripped = stripped
        self.view = view
        self.starts = atlas._line_starts(raw)
        self.lines = stripped.split("\n")
        self.fns: list[FnInfo] = []
        for match in FN_RE.finditer(stripped):
            name = match.group(1)
            open_idx = _find_body_open(stripped, match.end())
            body = None
            if open_idx is not None:
                close_idx = _match_brace(stripped, open_idx)
                if close_idx is not None:
                    body = (open_idx, close_idx)
            line = atlas._offset_to_line(self.starts, match.start()) + 1
            self.fns.append(FnInfo(name, match.start(), line, body))
        self.fn_offsets = [f.decl for f in self.fns]
        self.impls: list[ImplInfo] = []
        for match in IMPL_RE.finditer(stripped):
            open_idx = _find_body_open(stripped, match.end())
            end = None
            if open_idx is not None:
                end = _match_brace(stripped, open_idx)
            header = stripped[match.start() : (open_idx if open_idx is not None else match.start() + 300)]
            self.impls.append(ImplInfo(match.start(), end, header))
        self.impl_offsets = [i.start for i in self.impls]

    def enclosing_fn(self, offset: int) -> FnInfo | None:
        idx = bisect.bisect_right(self.fn_offsets, offset) - 1
        while idx >= 0:
            fn = self.fns[idx]
            if fn.body is not None and fn.body[0] <= offset <= fn.body[1]:
                return fn
            idx -= 1
        return None

    def declared_fn(self, offset: int, line: int) -> FnInfo | None:
        """For an UNSAFE_FN_DEF site, the fn declared on that line.

        The census offsets the site at `unsafe`, before the `fn` token, so the
        declaration is the first `fn` at or after the site offset.
        """
        idx = bisect.bisect_left(self.fn_offsets, offset)
        if idx < len(self.fns) and self.fns[idx].line == line:
            return self.fns[idx]
        return None

    def enclosing_impl(self, offset: int) -> ImplInfo | None:
        idx = bisect.bisect_right(self.impl_offsets, offset) - 1
        while idx >= 0:
            impl = self.impls[idx]
            if impl.end is not None and impl.start <= offset <= impl.end:
                return impl
            idx -= 1
        return None

    def fn_for(self, kind: str, offset: int, line: int) -> FnInfo | None:
        if kind == "UNSAFE_FN_DEF":
            declared = self.declared_fn(offset, line)
            if declared is not None:
                return declared
        return self.enclosing_fn(offset)

    def text_for(self, fn: FnInfo | None, line: int) -> str:
        parts: list[str] = []
        if fn is not None and fn.body is not None:
            parts.append(self.stripped[fn.body[0] : fn.body[1] + 1])
        low = max(0, line - 3)
        high = min(len(self.lines), line + 2)
        parts.append("\n".join(self.lines[low:high]))
        return "\n".join(parts)


# ---------------------------------------------------------------------------
# Boundary predicates
# ---------------------------------------------------------------------------


def boundary_for(
    site: dict,
    model: FileModel,
    worklist_lines: set[tuple[str, str | int]],
) -> str | None:
    rel = site["file"]
    line = site["line"]
    kind = site["kind"]
    offset = model.starts[line - 1]
    fn = model.fn_for(kind, offset, line)
    impl = model.enclosing_impl(offset)
    fn_name = fn.name if fn is not None else site["function"]
    context = model.text_for(fn, line)

    # 1. B-ALLOC-SEAM — exact line join with the production worklist.
    if (rel, line) in worklist_lines:
        return "B-ALLOC-SEAM"

    # 2. B-REFCOUNT.
    if rel == "src/runtime/refcount.rs" or DOWN_UP_RE.search(context):
        return "B-REFCOUNT"

    # 3. B-LOCK.
    if rel == "src/runtime/thread.rs" or THREAD_RE.search(context):
        return "B-LOCK"

    # 4. B-DESTRUCTOR.
    if fn_name.endswith("destroy_body"):
        return "B-DESTRUCTOR"
    if kind == "UNSAFE_IMPL" and impl is not None:
        match = IMPL_TRAIT_RE.search(impl.header)
        if match is not None and match.group(1).split("::")[-1] in DESTRUCTOR_TRAITS:
            return "B-DESTRUCTOR"

    # 5. B-OWNER-ADOPT.
    if fn is not None and fn_name in OWNER_CTOR_NAMES:
        owner_text = ""
        if impl is not None:
            owner_text += impl.header + "\n"
        if fn.body is not None:
            owner_text += model.stripped[fn.decl : fn.body[1] + 1]
        adoptish = bool(ADOPT_NAME_RE.match(fn_name)) or bool(
            ADOPT_TOKEN_RE.search(owner_text)
        )
        if adoptish and SHARED_OWNER_RE.search(owner_text):
            return "B-OWNER-ADOPT"

    # 6. B-OPAQUE (file-level representation boundary).
    if rel in OPAQUE_FILES:
        return "B-OPAQUE"

    # 7. B-FFI-ABI (coverage-by-policy at the ABI edge).
    if kind in ("EXTERN_C_FN_DEF", "NONALLOC_FFI_CALL"):
        return "B-FFI-ABI"

    return None


# ---------------------------------------------------------------------------
# Document construction
# ---------------------------------------------------------------------------


def build_document() -> dict:
    census = load_census()
    worklist = load_worklist()
    candidate = census["candidate"]
    rev = candidate["head_sha"]

    paths = [row["path"] for row in census["files"]]
    if len(paths) != len(set(paths)):
        raise SystemExit("census has duplicate file paths")
    if len(paths) != candidate["src_rs_files"]:
        raise SystemExit(
            "census file count does not match candidate.src_rs_files: "
            f"{len(paths)} != {candidate['src_rs_files']}"
        )

    texts = pinned_sources(rev)
    if set(texts) != set(paths):
        missing = sorted(set(paths) - set(texts))
        extra = sorted(set(texts) - set(paths))
        raise SystemExit(
            "pinned source tree does not match census file set: "
            f"missing={missing[:5]} extra={extra[:5]}"
        )

    recomputed_hash = content_hash(texts)
    if recomputed_hash != candidate["src_content_sha256"]:
        raise SystemExit(
            "pinned source content hash does not match the census candidate: "
            f"{recomputed_hash} != {candidate['src_content_sha256']}"
        )

    stripped: dict[str, str] = {}
    views: dict[str, str] = {}
    for rel in paths:
        raw = texts[rel]
        stripped[rel] = atlas.strip_comments_and_literals(raw)
        views[rel] = uc._restore_abi_literals(raw, stripped[rel])

    test_files = build_test_files(texts, views)

    code_to_kind = {code: name for name, code in census["kind_codes"].items()}
    worklist_lines = {(row["file"], row["line"]) for row in worklist["sites"]}

    files_out: list[dict] = []
    by_boundary_totals = {name: 0 for name in BOUNDARIES}
    unattributed_by_kind: dict[str, int] = {}
    production_by_kind: dict[str, int] = {}
    production_total = 0
    attributed_total = 0
    unattributed_total = 0
    joined_worklist_rows: set[tuple[str, int]] = set()

    for row in sorted(census["files"], key=lambda r: r["path"]):
        rel = row["path"]
        raw = texts[rel]
        view = views[rel]
        stripped_text = stripped[rel]
        starts = atlas._line_starts(raw)
        module_ranges, item_ranges, _external = atlas.find_cfg_test_ranges(view)
        is_seam = rel in atlas.SEAM_FILES
        file_is_test = rel in test_files
        model = FileModel(rel, raw, stripped_text, view)

        counts = {name: 0 for name in BOUNDARIES}
        unattributed: list[dict] = []
        prod_by_kind: dict[str, int] = {}
        prod_count = 0
        test_count = 0
        seam_count = 0

        for line, code, function in sorted(
            row["sites"], key=lambda s: (s[0], s[1], s[2])
        ):
            if line < 1 or line > len(starts):
                raise SystemExit(f"site line out of range: {rel}:{line}")
            offset = starts[line - 1]
            partition = partition_for(
                rel,
                offset,
                is_seam=is_seam,
                file_is_test=file_is_test,
                module_ranges=module_ranges,
                item_ranges=item_ranges,
            )
            if partition == "allocator_seam":
                seam_count += 1
                continue
            if partition == "test_only":
                test_count += 1
                continue

            kind = code_to_kind[code]
            prod_count += 1
            prod_by_kind[kind] = prod_by_kind.get(kind, 0) + 1

            site = {
                "file": rel,
                "line": line,
                "kind": kind,
                "function": function,
            }
            boundary = boundary_for(site, model, worklist_lines)
            if boundary is None:
                counts["UNATTRIBUTED"] = counts.get("UNATTRIBUTED", 0) + 1
                unattributed_by_kind[kind] = unattributed_by_kind.get(kind, 0) + 1
                unattributed.append(
                    {"line": line, "kind": kind, "function": function}
                )
                unattributed_total += 1
            else:
                counts[boundary] += 1
                by_boundary_totals[boundary] += 1
                attributed_total += 1
                if boundary == "B-ALLOC-SEAM":
                    joined_worklist_rows.add((rel, line))

        expected = row["partition_counts"]
        if prod_count != expected["production"]:
            raise SystemExit(
                f"production partition drift: {rel}: "
                f"{prod_count} != {expected['production']}"
            )
        if test_count != expected["test_only"]:
            raise SystemExit(
                f"test partition drift: {rel}: {test_count} != {expected['test_only']}"
            )
        if seam_count != expected["allocator_seam"]:
            raise SystemExit(
                f"seam partition drift: {rel}: "
                f"{seam_count} != {expected['allocator_seam']}"
            )

        for kind, count in prod_by_kind.items():
            production_by_kind[kind] = production_by_kind.get(kind, 0) + count
        production_total += prod_count

        status = (
            "ZERO_UNSAFE"
            if prod_count == 0
            else ("BOUNDARY_COVERED" if not unattributed else "PARTIAL")
        )
        files_out.append(
            {
                "path": rel,
                "status": status,
                "production_sites": prod_count,
                "attributed_sites": prod_count - len(unattributed),
                "unattributed_sites": len(unattributed),
                "test_only_sites": test_count,
                "allocator_seam_sites": seam_count,
                "production_by_kind": {
                    k: prod_by_kind[k] for k in sorted(prod_by_kind)
                },
                "counts_by_boundary": {
                    name: counts.get(name, 0) for name in BOUNDARIES
                },
                "unattributed": unattributed,
            }
        )

    census_totals = census["totals"]
    census_prod = census_totals["by_partition"]["production"]
    if production_total != census_prod:
        raise SystemExit(
            f"production total does not reconcile: {production_total} != {census_prod}"
        )
    if attributed_total + unattributed_total != production_total:
        raise SystemExit("attributed + unattributed does not equal production")
    if sum(by_boundary_totals.values()) != attributed_total:
        raise SystemExit("boundary counts do not sum to attributed sites")

    census_by_kind = {
        kind: count
        for kind, count in census_totals["by_kind_partition"].items()
        if count.get("production", 0)
    }
    if production_by_kind != {
        kind: values["production"] for kind, values in census_by_kind.items()
    }:
        raise SystemExit("production kind totals do not reconcile with the census")

    zero_unsafe = sum(1 for f in files_out if f["status"] == "ZERO_UNSAFE")
    covered = sum(1 for f in files_out if f["status"] == "BOUNDARY_COVERED")
    partial = sum(1 for f in files_out if f["status"] == "PARTIAL")
    if zero_unsafe + covered + partial != len(files_out):
        raise SystemExit("file status totals do not reconcile")

    unattributed_files = [f for f in files_out if f["unattributed_sites"] > 0]
    queue_files = sorted(
        (
            {"path": f["path"], "sites": f["unattributed_sites"]}
            for f in unattributed_files
        ),
        key=lambda item: (-item["sites"], item["path"]),
    )

    doc = {
        "schema": SCHEMA,
        "kind": KIND,
        "not_a_discharge": True,
        "statement": (
            "Attribution is not discharge.  A site under a boundary is covered "
            "by that boundary's declared scope only; no caller contract, "
            "aliasing proof, lifetime proof or cryptographic property is "
            "established.  UNATTRIBUTED is an explicit queue, not a claim of "
            "safety or a claim of defect."
        ),
        "source_identity": {
            "census_path": str(CENSUS_PATH.relative_to(ROOT)),
            "worklist_path": str(WORKLIST_PATH.relative_to(ROOT)),
            "census_schema": census.get("schema"),
            "census_generated_utc": census.get("generated_utc"),
            "candidate_head_sha": rev,
            "candidate_src_content_sha256": candidate["src_content_sha256"],
            "recomputed_src_content_sha256": recomputed_hash,
            "src_rs_files": len(paths),
            "source_read_from": (
                "pinned census candidate commit via git archive; the working "
                "tree is never read for line context"
            ),
        },
        "boundary_registry": BOUNDARY_META,
        "precedence": list(BOUNDARIES),
        "totals": {
            "files_total": len(files_out),
            "files_zero_unsafe": zero_unsafe,
            "files_boundary_covered": covered,
            "files_partial": partial,
            "production_sites": production_total,
            "attributed_sites": attributed_total,
            "unattributed_sites": unattributed_total,
            "unattributed_files": len(unattributed_files),
            "attributed_by_boundary": dict(by_boundary_totals),
            "production_by_kind": dict(sorted(production_by_kind.items())),
            "unattributed_by_kind": dict(sorted(unattributed_by_kind.items())),
            "worklist_rows": worklist.get("row_count", len(worklist["sites"])),
            "worklist_rows_joined_to_production_sites": len(joined_worklist_rows),
            "worklist_rows_without_production_site": (
                worklist.get("row_count", len(worklist["sites"]))
                - len(joined_worklist_rows)
            ),
        },
        "reconciliation": {
            "census_production_sites": census_prod,
            "recomputed_production_sites": production_total,
            "attributed_plus_unattributed": attributed_total + unattributed_total,
            "per_file_partition_counts_match": True,
            "production_kind_totals_match": True,
            "source_content_hash_matches_census": (
                recomputed_hash == candidate["src_content_sha256"]
            ),
        },
        "unattributed_queue": {
            "site_count": unattributed_total,
            "file_count": len(unattributed_files),
            "files": queue_files,
        },
        "files": files_out,
    }
    return doc


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def fmt_int(value: int) -> str:
    return f"{value:,}"


def render_markdown(doc: dict) -> str:
    totals = doc["totals"]
    src = doc["source_identity"]
    lines: list[str] = []
    lines.append("# Unsafe-site boundary attribution — safe-c33")
    lines.append("")
    lines.append(
        "**Attribution is NOT discharge.** A site placed under a boundary is "
        "covered by that boundary's declared scope only. Nothing here proves a "
        "caller contract, aliasing, lifetime, initialisation or cryptographic "
        "property, and no subsystem or consumer graduates by this record. "
        "`UNATTRIBUTED` is an explicit queue: it is neither a safety claim nor "
        "a defect claim."
    )
    lines.append("")
    lines.append(
        f"Source: `{src['census_path']}` bound to candidate "
        f"`{src['candidate_head_sha']}` with `src/` content hash "
        f"`{src['candidate_src_content_sha256']}`. Line context is read from "
        "that pinned commit, never from the working tree."
    )
    lines.append("")
    lines.append("## Totals")
    lines.append("")
    lines.append("| metric | value |")
    lines.append("|---|---:|")
    lines.append(f"| production unsafe sites (census) | {fmt_int(totals['production_sites'])} |")
    lines.append(f"| attributed sites | {fmt_int(totals['attributed_sites'])} |")
    lines.append(f"| **unattributed sites** | **{fmt_int(totals['unattributed_sites'])}** |")
    lines.append(f"| files total | {fmt_int(totals['files_total'])} |")
    lines.append(f"| files ZERO_UNSAFE (no production site) | {fmt_int(totals['files_zero_unsafe'])} |")
    lines.append(f"| files BOUNDARY_COVERED | {fmt_int(totals['files_boundary_covered'])} |")
    lines.append(f"| files PARTIAL | {fmt_int(totals['files_partial'])} |")
    lines.append(f"| **unattributed files** | **{fmt_int(totals['unattributed_files'])}** |")
    lines.append(f"| worklist rows | {fmt_int(totals['worklist_rows'])} |")
    lines.append(
        "| worklist rows joined to a production site | "
        f"{fmt_int(totals['worklist_rows_joined_to_production_sites'])} |"
    )
    lines.append(
        "| worklist rows with no production unsafe site | "
        f"{fmt_int(totals['worklist_rows_without_production_site'])} |"
    )
    lines.append("")
    lines.append("Boundary counts are exclusive: the first matching predicate in "
                 "the fixed precedence list wins, so a site is counted once.")
    lines.append("")
    lines.append("## Sites by boundary")
    lines.append("")
    lines.append("| boundary | sites | coverage | evidence |")
    lines.append("|---|---:|---|---|")
    for name in BOUNDARIES:
        meta = BOUNDARY_META[name]
        evidence = ", ".join(f"`{item}`" for item in meta["evidence"])
        lines.append(
            f"| `{name}` | {fmt_int(totals['attributed_by_boundary'][name])} | "
            f"{meta['coverage']} | {evidence} |"
        )
    lines.append(
        f"| **UNATTRIBUTED** | **{fmt_int(totals['unattributed_sites'])}** | "
        "**explicit queue — no boundary registered** | — |"
    )
    lines.append("")
    lines.append("## Production and unattributed sites by kind")
    lines.append("")
    lines.append("| kind | production | unattributed |")
    lines.append("|---|---:|---:|")
    for kind in sorted(totals["production_by_kind"]):
        lines.append(
            f"| `{kind}` | {fmt_int(totals['production_by_kind'][kind])} | "
            f"{fmt_int(totals['unattributed_by_kind'].get(kind, 0))} |"
        )
    lines.append("")
    lines.append("## 40 files with the most unattributed sites")
    lines.append("")
    lines.append("| file | production | attributed | unattributed | main unattributed kinds |")
    lines.append("|---|---:|---:|---:|---|")
    top = sorted(
        doc["files"],
        key=lambda f: (-f["unattributed_sites"], f["path"]),
    )[:40]
    for row in top:
        if row["unattributed_sites"] == 0:
            break
        kinds: dict[str, int] = {}
        for site in row["unattributed"]:
            kinds[site["kind"]] = kinds.get(site["kind"], 0) + 1
        kind_text = ", ".join(
            f"{k}={v}" for k, v in sorted(kinds.items(), key=lambda kv: (-kv[1], kv[0]))
        )
        lines.append(
            f"| `{row['path']}` | {fmt_int(row['production_sites'])} | "
            f"{fmt_int(row['attributed_sites'])} | "
            f"{fmt_int(row['unattributed_sites'])} | {kind_text} |"
        )
    lines.append("")
    lines.append("## Boundary predicates")
    lines.append("")
    for name in BOUNDARIES:
        meta = BOUNDARY_META[name]
        lines.append(f"### `{name}`")
        lines.append("")
        lines.append(meta["scope"])
        lines.append("")
        lines.append(f"Predicate: `{meta['predicate']}`")
        lines.append("")
    lines.append("## Residual limitations")
    lines.append("")
    lines.append(
        "- The census is lexical, not a Rust parser: macro-generated operations "
        "are counted only where the macro token appears in source, and no "
        "expansion-site attribution is possible."
    )
    lines.append(
        "- Generic and trait-level obligations (for example an `unsafe trait` "
        "definition or a generic impl) are not per-site proofs; `UNSAFE_TRAIT` "
        "and Send/Sync `unsafe impl` sites are deliberately left unattributed "
        "because no boundary in this registry owns those obligations."
    )
    lines.append(
        "- One source site can serve more than one obligation. The output "
        "assigns exactly one boundary by precedence so counts reconcile; that "
        "is a reporting choice, not a claim that the other obligations vanish."
    )
    lines.append(
        "- `B-ALLOC-SEAM` is a line-exact join with the worklist. A multi-line "
        "call whose operation is recorded on a different line is not joined. "
        "Most worklist rows are safe allocation/release calls with no "
        "production unsafe operation on the same line; those rows are reported "
        "as `worklist_rows_without_production_site`."
    )
    lines.append(
        "- `B-FFI-ABI` is coverage-by-policy at the ABI edge, not a per-site "
        "ABI or callback proof. It does not discharge a reentrancy or ABI "
        "obligation."
    )
    lines.append(
        "- `B-OPAQUE` is file-level representation coverage, not a per-site "
        "proof of the opaque-representation contract."
    )
    lines.append(
        "- The attribution is bound to the census candidate commit, which may "
        "differ from the current source HEAD. It does not describe uncommitted "
        "or later source without regenerating the census."
    )
    lines.append("")
    lines.append("## Reconciliation")
    lines.append("")
    rec = doc["reconciliation"]
    lines.append("| check | result |")
    lines.append("|---|---|")
    lines.append(
        f"| census production sites | {fmt_int(rec['census_production_sites'])} |"
    )
    lines.append(
        f"| recomputed production sites | {fmt_int(rec['recomputed_production_sites'])} |"
    )
    lines.append(
        f"| attributed + unattributed | {fmt_int(rec['attributed_plus_unattributed'])} |"
    )
    lines.append(
        "| per-file production/test/seam counts | "
        f"{'match' if rec['per_file_partition_counts_match'] else 'MISMATCH'} |"
    )
    lines.append(
        "| per-kind production totals | "
        f"{'match' if rec['production_kind_totals_match'] else 'MISMATCH'} |"
    )
    lines.append(
        "| source content hash vs census | "
        f"{'match' if rec['source_content_hash_matches_census'] else 'MISMATCH'} |"
    )
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def serialise(doc: dict) -> str:
    return json.dumps(doc, indent=2, sort_keys=True) + "\n"


def check() -> int:
    doc = build_document()
    rendered = serialise(doc)
    failures: list[str] = []

    rec = doc["reconciliation"]
    if rec["census_production_sites"] != rec["recomputed_production_sites"]:
        failures.append("production total does not reconcile with census")
    if rec["attributed_plus_unattributed"] != rec["census_production_sites"]:
        failures.append("attributed + unattributed does not equal census production")
    if not rec["per_file_partition_counts_match"]:
        failures.append("per-file partition counts do not match census")
    if not rec["production_kind_totals_match"]:
        failures.append("per-kind production totals do not match census")
    if not rec["source_content_hash_matches_census"]:
        failures.append("pinned source content hash does not match census")

    if OUT_JSON.exists():
        on_disk = OUT_JSON.read_text(encoding="utf-8")
        if on_disk != rendered:
            failures.append(
                f"{OUT_JSON.relative_to(ROOT)} is stale or nondeterministic "
                "(recomputed bytes differ)"
            )

    totals = doc["totals"]
    print(
        "census production: "
        f"{rec['census_production_sites']}  recomputed: "
        f"{rec['recomputed_production_sites']}  attributed: "
        f"{totals['attributed_sites']}  unattributed: "
        f"{totals['unattributed_sites']}"
    )
    print(
        "files: "
        f"{totals['files_total']} (zero={totals['files_zero_unsafe']}, "
        f"covered={totals['files_boundary_covered']}, "
        f"partial={totals['files_partial']}); "
        f"unattributed files: {totals['unattributed_files']}"
    )
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}", file=sys.stderr)
        return 1
    print("OK: attribution reconciles with the census")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Attribute production unsafe sites to registered boundaries. "
            "Attribution is not discharge."
        )
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="recompute totals, reconcile with the census, and verify the "
        "on-disk attribution.json is byte-identical",
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help="print boundary totals and the top unattributed files without writing",
    )
    args = parser.parse_args(argv)

    if args.check:
        return check()

    doc = build_document()
    OUT_JSON.write_text(serialise(doc), encoding="utf-8")
    OUT_MD.write_text(render_markdown(doc), encoding="utf-8")

    totals = doc["totals"]
    print(f"wrote {OUT_JSON.relative_to(ROOT)}")
    print(f"wrote {OUT_MD.relative_to(ROOT)}")
    print(
        f"production {totals['production_sites']}, "
        f"attributed {totals['attributed_sites']}, "
        f"unattributed {totals['unattributed_sites']}, "
        f"unattributed files {totals['unattributed_files']}"
    )
    if args.stats:
        for name in BOUNDARIES:
            print(f"  {name}: {totals['attributed_by_boundary'][name]}")
        print("  top unattributed files:")
        for item in doc["unattributed_queue"]["files"][:15]:
            print(f"    {item['sites']:6d}  {item['path']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
