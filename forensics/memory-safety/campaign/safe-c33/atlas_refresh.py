#!/usr/bin/env python3
"""Safe-33 atlas refresh — a lightweight, candidate-bound measurement.

This generator is *measurement only*. It converts no source, regenerates no
Phase-25 evidence graph, and claims no graduation. It pins the exact current
`src/` tree and reports, honestly, where the nine ownership mechanisms stand
between the 33 already-drop-in-compatible downstream consumers and
`SAFE_COMPATIBLE`.

Design constraints (see the task / AGENTS.md §6, §18):
  * Python standard library only; no crate deps, no network.
  * Fast and low-memory: one streaming pass over `src/**/*.rs` (~30 MB).
  * Candidate-bound: the report records the git HEAD, the crate version and a
    content hash over every `src/**/*.rs` (sorted path + bytes), so the refresh
    is provably tied to one tree.

Everything the tool asserts about mechanism→file association is declared as
data in MECHANISM_PATHS below, derived from CLOSURE.md (the "authority
evidence" prefix column) and the `converted_files_on_branch` file lists in
state.json / PROGRESS.md. Keeping it as data makes the mapping auditable.

Run:  python3 forensics/memory-safety/campaign/safe-c33/atlas_refresh.py
Out:  forensics/memory-safety/campaign/safe-c33/atlas-refresh/{candidate.json,REPORT.md}
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

# --------------------------------------------------------------------------
# 1. Declared data: seam tokens, allocator sites, mechanism→path mapping.
# --------------------------------------------------------------------------

# An ownership seam is any of these owning-type/destructor markers. Their
# presence in a file is evidence that at least part of the file's raw
# ownership has been reconstructed behind an owning abstraction.
SEAM_TOKENS = [
    "OwnedCtx",
    "OwnedBuf",
    "OwnedBlock",
    "OwnedStr",
    "PropqSlot",
    "RawCtx",
    "OwnedRaw",
    "CtxDestroy",
    "CipherDestroy",
    "impl Drop",
]

# Allocation / release **call** names are discovered from the allocator seam
# (`src/runtime/mem.rs` and the secure allocator in `src/runtime/secure.rs`)
# rather than maintained as a hand-written subset. A site is an identifier
# followed by optional whitespace (and an optional turbofish) and `(` — not a
# `use` import, a function-pointer table entry, or a doc-comment mention. Seam
# constructors legitimately contain these calls, so a call site is *not* by
# itself a defect; it is a site that must be accounted for.
SEAM_SURFACE_FILES = (
    "src/runtime/mem.rs",
    "src/runtime/secure.rs",
)

# The allocator seam implementations. Their own calls are the seam being
# defined, not interior consumer sites, and are reported separately as
# "allocator seam".
SEAM_FILES = set(SEAM_SURFACE_FILES)

# Public seam functions that are queries/utilities, not allocator operations.
_NON_ALLOCATOR_FN_NAMES = {
    "CRYPTO_memcmp",
    "CRYPTO_set_mem_functions",
    "CRYPTO_get_mem_functions",
    "OPENSSL_cleanse",
}
_ALLOC_FN_MARKERS = (
    "malloc",
    "zalloc",
    "calloc",
    "realloc",
    "strdup",
    "strndup",
    "memdup",
    "aligned_alloc",
)


def _call_pattern(names) -> re.Pattern[str]:
    names = list(names)
    if not names:
        # A pattern that cannot match: keeps the scanner total well-defined
        # when a surface is unexpectedly empty.
        return re.compile(r"(?!x)x")
    alternation = "|".join(re.escape(n) for n in names)
    return re.compile(
        rf"\b(?P<name>{alternation})\s*(?:::\s*<[^<>\n]*>\s*)?\("
    )


# Adoption / transfer tokens are recorded separately. They move or reclaim an
# existing block; they are not raw allocation or release sites and are never
# added to the allocator-site counts.
ADOPT_CALL_RE = re.compile(
    r"\bOwned[A-Za-z0-9_]*\s*::\s*(?:from_raw|take|adopt)\s*\("
    r"|\badopt(?:_cleansed)?\s*\("
)

# A file that *defines* the core allocator entry points is the `CRYPTO_*` seam's
# own implementation, not an unconverted interior consumer. Its calls are the
# seam being defined and must not be reported as residual.
ALLOC_DEF_RE = re.compile(
    r"\bfn\s+CRYPTO_(?:malloc|zalloc|calloc|strdup|memdup|free|clear_free)\b"
)

# Mechanism → src/ path mapping. A trailing "/" is a directory prefix; a bare
# path is an exact file. Derived from CLOSURE.md §2 "authority evidence"
# (crypto/… and ssl/ prefixes → the crate's directory layout) plus the file
# lists in state.json (`converted_files_on_branch`) and PROGRESS.md. Overlap
# between mechanisms is intentional and expected; the union is deduplicated.
MECHANISM_PATHS = {
    "ERR": [
        "src/runtime/err.rs",
        "src/runtime/err_state.rs",
        "src/runtime/err_sites.rs",
        "src/runtime/err_loaders.rs",
        "src/runtime/err_reasons.rs",
        "src/runtime/err_strings.rs",
        "src/ssl/ssl_err_legacy.rs",
    ],
    "RAND_CMS_STORE_KEYFMT": [
        "src/rand/",
        "src/cms/",
        "src/store/",
        "src/pem/",
        "src/pkcs7/",
        "src/pkcs12/",
        "src/cmp/",
        "src/crmf/",
    ],
    "BIO": [
        "src/runtime/bio/",
        "src/context/core_bio.rs",
    ],
    "EVP_PKEY_PROVIDER": [
        "src/evp/",
        "src/provider/",
        "src/property/",
        "src/params/",
        "src/ec/",
        "src/rsa/",
        "src/dsa/",
        "src/dh/",
        "src/bn/",
        "src/ffc/",
    ],
    "RUNTIME_ALLOC_OWNERSHIP": [
        "src/runtime/mem.rs",
        "src/runtime/secure.rs",
        "src/runtime/buffer.rs",
        "src/runtime/stack.rs",
        "src/runtime/ex_data.rs",
        "src/runtime/init.rs",
        "src/runtime/lhash.rs",
        "src/context/",
    ],
    "ASN1_OCSP": [
        "src/asn1/",
        "src/ocsp/",
        "src/ts/",
        "src/runtime/obj.rs",
        "src/runtime/obj_table.rs",
    ],
    "X509_VERIFY_POLICY": [
        "src/x509/",
    ],
    "RUNTIME_CONCURRENCY": [
        "src/runtime/thread.rs",
        "src/runtime/thread_arch.rs",
        "src/runtime/thread_events.rs",
        "src/runtime/threads_common.rs",
        "src/runtime/init.rs",
    ],
    "SSL_SESSION": [
        "src/ssl/",
    ],
}

# The nine mechanisms, in the CLOSURE.md ranking order used by the ledger.
MECHANISM_ORDER = [
    "ERR",
    "RAND_CMS_STORE_KEYFMT",
    "BIO",
    "EVP_PKEY_PROVIDER",
    "RUNTIME_ALLOC_OWNERSHIP",
    "ASN1_OCSP",
    "X509_VERIFY_POLICY",
    "RUNTIME_CONCURRENCY",
    "SSL_SESSION",
]

CAMPAIGN_DIR = "forensics/memory-safety/campaign/safe-c33"
STATE_PATH = f"{CAMPAIGN_DIR}/state.json"
P1000_PATH = "forensics/downstream/p1000-run.json"
CENSUS_PATH = "artifacts/phase25/source-census.json"
OUT_DIR = f"{CAMPAIGN_DIR}/atlas-refresh"


# --------------------------------------------------------------------------
# 2. Small filesystem / git helpers.
# --------------------------------------------------------------------------

def repo_root() -> Path:
    """Locate the repository root from this file's location."""
    return Path(__file__).resolve().parents[4]


def git(*args: str, root: Path) -> str:
    out = subprocess.run(
        ["git", *args],
        cwd=root,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return out.stdout.decode("utf-8", "replace").strip()


def crate_version(root: Path) -> str:
    toml = (root / "Cargo.toml").read_text(encoding="utf-8", errors="replace")
    m = re.search(r'^version\s*=\s*"([^"]+)"', toml, re.MULTILINE)
    return m.group(1) if m else "UNKNOWN"


def candidate_utc(root: Path) -> str:
    """Deterministic generation stamp, bound to the candidate rather than wall time.

    Runs of the same candidate must produce byte-identical output. `SOURCE_DATE_EPOCH`
    is honoured when set; otherwise the HEAD commit time is used.
    """
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if epoch and epoch.isdigit():
        ts = _dt.datetime.fromtimestamp(int(epoch), _dt.timezone.utc)
        return ts.strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        iso = git("show", "-s", "--format=%cI", "HEAD", root=root)
        ts = _dt.datetime.fromisoformat(iso)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=_dt.timezone.utc)
        return ts.astimezone(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return "1970-01-01T00:00:00Z"


def list_src_rs(root: Path) -> list[str]:
    base = root / "src"
    out = []
    for dirpath, _dirs, files in os.walk(base):
        for f in files:
            if f.endswith(".rs"):
                out.append(str((Path(dirpath) / f).relative_to(root)))
    return sorted(out)


def _blank(out: list[str], start: int, end: int) -> None:
    """Replace characters in `out[start:end]` with spaces, keeping newlines."""
    for k in range(start, end):
        if out[k] != "\n":
            out[k] = " "


def _scan_quoted(text: str, quote_at: int) -> int:
    """Return the offset just past the closing `"` of a normal string."""
    n = len(text)
    j = quote_at + 1
    while j < n:
        if text[j] == "\\":
            j += 2
            continue
        if text[j] == '"':
            return j + 1
        j += 1
    return n


def _scan_char(text: str, quote_at: int) -> int:
    """Return the offset just past the closing `'` of a char literal."""
    n = len(text)
    j = quote_at + 1
    while j < n:
        if text[j] == "\\":
            j += 2
            continue
        if text[j] == "'":
            return j + 1
        j += 1
    return n


def _raw_string_end(text: str, start: int) -> int | None:
    """If a raw string starts at `start`, return its end offset (else None).

    Handles `r"…"`, `r#"…"#`, `br"…"`, `br#"…"#`, `cr"…"`, `cr#"…"#`.
    The prefix must not be the tail of a larger identifier.
    """
    n = len(text)
    if start > 0 and (text[start - 1].isalnum() or text[start - 1] == "_"):
        return None
    for prefix in ("br", "cr", "r"):
        if not text.startswith(prefix, start):
            continue
        j = start + len(prefix)
        if j >= n:
            continue
        if text[j] == '"':
            # A raw string's body still ends at an unescaped `"`.
            k = j + 1
            while k < n:
                if text[k] == '"':
                    return k + 1
                k += 1
            return n
        if text[j] == "#":
            k = j
            hashes = 0
            while k < n and text[k] == "#":
                hashes += 1
                k += 1
            if k < n and text[k] == '"':
                closer = '"' + "#" * hashes
                end = text.find(closer, k + 1)
                return (end + len(closer)) if end != -1 else n
    return None


def strip_comments_and_literals(text: str) -> str:
    """Blank comments and string/char literals, preserving offsets and lines.

    This is a small hand-written scanner rather than a regex so `//` inside a
    string and quotes inside a comment cannot fool it. Every removed character
    becomes a space; newlines are kept, so offsets and 1-based line numbers are
    identical to the original source.
    """
    n = len(text)
    out = list(text)
    i = 0
    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n:
            if text[i + 1] == "/":
                end = text.find("\n", i)
                if end == -1:
                    end = n
                _blank(out, i, end)
                i = end
                continue
            if text[i + 1] == "*":
                depth = 1
                j = i + 2
                while j < n and depth > 0:
                    if text[j] == "/" and j + 1 < n and text[j + 1] == "*":
                        depth += 1
                        j += 2
                    elif text[j] == "*" and j + 1 < n and text[j + 1] == "/":
                        depth -= 1
                        j += 2
                    else:
                        j += 1
                _blank(out, i, j)
                i = j
                continue
        if c in "rbc":
            end = _raw_string_end(text, i)
            if end is not None:
                _blank(out, i, end)
                i = end
                continue
        if c in "bc" and i + 1 < n and text[i + 1] == '"':
            end = _scan_quoted(text, i + 1)
            _blank(out, i, end)
            i = end
            continue
        if c in "bc" and i + 1 < n and text[i + 1] == "'" and i + 2 < n:
            if text[i + 2] == "\\":
                end = _scan_char(text, i + 1)
            elif i + 3 < n and text[i + 3] == "'":
                end = i + 4
            else:
                end = None
            if end is not None:
                _blank(out, i, end)
                i = end
                continue
        if c == '"':
            end = _scan_quoted(text, i)
            _blank(out, i, end)
            i = end
            continue
        if c == "'":
            # A char literal is `'x'` or `'\…'`; `'a` in `'a>` is a lifetime and
            # stays in the stripped view (it cannot form a call token).
            if i + 1 < n and text[i + 1] == "\\":
                end = _scan_char(text, i)
                _blank(out, i, end)
                i = end
                continue
            if i + 2 < n and text[i + 2] == "'":
                _blank(out, i, i + 3)
                i += 3
                continue
        i += 1
    return "".join(out)


PUB_SEAM_FN_RE = re.compile(
    r"\bpub(?P<restricted>\s*\([^)]*\))?\s+"
    r"(?:unsafe\s+)?(?:extern\s+)?"
    r"(?:const\s+)?(?:async\s+)?(?:default\s+)?"
    r"fn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
)
OPENSSL_FN_DEF_RE = re.compile(r"\bfn\s+(OPENSSL_[A-Za-z0-9_]*)\s*\(")
# The C authority's allocator aliases. Container destructors such as
# `OPENSSL_sk_free`/`OPENSSL_LH_free` are deliberately not included.
_OPENSSL_ALLOCATOR_ALIASES = {
    "OPENSSL_malloc",
    "OPENSSL_zalloc",
    "OPENSSL_calloc",
    "OPENSSL_realloc",
    "OPENSSL_free",
    "OPENSSL_clear_free",
    "OPENSSL_strdup",
    "OPENSSL_strndup",
    "OPENSSL_memdup",
}


def _public_seam_fn_names(stripped: str) -> list[str]:
    """Public `fn` names in an allocator-seam file (excluding `pub(crate)`)."""
    names = []
    for m in PUB_SEAM_FN_RE.finditer(stripped):
        restricted = m.group("restricted") or ""
        if re.search(r"\b(?:crate|super|self)\b", restricted):
            continue
        names.append(m.group("name"))
    return sorted(set(names))


def _classify_allocator_fn(name: str) -> tuple[str, str] | None:
    """Classify a seam function as an allocation/release operation and family.

    Families keep secure, cleansing, array, aligned and duplicate operations
    visible instead of folding everything into a plain malloc count.
    """
    if name in _NON_ALLOCATOR_FN_NAMES:
        return None
    if name.endswith(("_initialized", "_allocated", "_actual_size", "_used")):
        return None
    is_free = "_free" in name
    is_done = name.endswith("_done")
    is_alloc = any(marker in name for marker in _ALLOC_FN_MARKERS)
    if not (is_free or is_done or is_alloc):
        return None
    kind = "release" if (is_free or is_done) else "alloc"
    if name.startswith("OPENSSL_"):
        return kind, "openssl_alias"
    if "secure" in name:
        if name.endswith("_init") or is_done:
            family = "secure_arena"
        elif "_clear_free" in name:
            family = "secure_cleansing_release"
        elif is_free:
            family = "secure_release"
        elif "aligned" in name:
            family = "aligned"
        elif "_array" in name:
            family = "secure_array"
        elif "zalloc" in name:
            family = "secure_zalloc"
        elif "calloc" in name:
            family = "secure_calloc"
        else:
            family = "secure_alloc"
        return kind, family
    if "aligned" in name:
        family = "aligned"
    elif "_array" in name:
        family = "array"
    elif "_clear_realloc" in name:
        family = "clear_realloc"
    elif "realloc" in name:
        family = "realloc"
    elif "_clear_free" in name:
        family = "cleansing_release"
    elif is_free:
        family = "plain_release"
    elif "strdup" in name or "strndup" in name or "memdup" in name:
        family = "dup"
    elif "calloc" in name:
        family = "calloc"
    elif "zalloc" in name:
        family = "zalloc"
    elif "malloc" in name:
        family = "malloc"
    else:
        family = "other"
    return kind, family


def _empty_surface() -> dict:
    return {
        "seam_files": [],
        "alloc": {},
        "release": {},
        "aliases": [],
        "excluded": [],
    }


def _surface_add_source(surface: dict, rel: str, stripped: str) -> None:
    """Accumulate seam names (and discovered OPENSSL_* aliases) from one file."""
    if rel in SEAM_SURFACE_FILES:
        surface["seam_files"].append(rel)
        for name in _public_seam_fn_names(stripped):
            classified = _classify_allocator_fn(name)
            if classified is None:
                surface["excluded"].append(name)
                continue
            kind, family = classified
            surface[kind][name] = family
    for name in OPENSSL_FN_DEF_RE.findall(stripped):
        if name not in _OPENSSL_ALLOCATOR_ALIASES:
            continue
        classified = _classify_allocator_fn(name)
        if classified is None:
            continue
        kind, _family = classified
        surface[kind][name] = "openssl_alias"
        surface["aliases"].append(name)


def _finish_surface(surface: dict) -> dict:
    surface["seam_files"] = sorted(set(surface["seam_files"]))
    surface["aliases"] = sorted(set(surface["aliases"]))
    surface["excluded"] = sorted(set(surface["excluded"]))
    return surface


def surface_regexes(surface: dict) -> tuple[re.Pattern[str], re.Pattern[str]]:
    return (
        _call_pattern(sorted(surface["alloc"])),
        _call_pattern(sorted(surface["release"])),
    )


def discover_allocator_surface(root: Path, rel_paths: list[str]) -> dict:
    """Read the seam files and any `OPENSSL_*` alias definitions in `src/`."""
    surface = _empty_surface()
    for rel in rel_paths:
        stripped = strip_comments_and_literals(
            (root / rel).read_text(encoding="utf-8", errors="replace")
        )
        _surface_add_source(surface, rel, stripped)
    return _finish_surface(surface)


def _line_starts(text: str) -> list[int]:
    starts = [0]
    for idx, ch in enumerate(text):
        if ch == "\n":
            starts.append(idx + 1)
    return starts


def _offset_to_line(starts: list[int], offset: int) -> int:
    """0-based line index for a character offset."""
    import bisect

    return bisect.bisect_right(starts, offset) - 1


def _balanced_end(text: str, open_idx: int) -> int | None:
    """Return the index of the delimiter matching `text[open_idx]`."""
    pairs = {"(": ")", "[": "]", "{": "}"}
    opener = text[open_idx]
    closer = pairs.get(opener)
    if closer is None:
        return None
    depth = 0
    j = open_idx
    while j < len(text):
        ch = text[j]
        if ch == opener:
            depth += 1
        elif ch == closer:
            depth -= 1
            if depth == 0:
                return j
        j += 1
    return None


def _split_top_level(expr: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    start = 0
    for i, ch in enumerate(expr):
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append(expr[start:i])
            start = i + 1
    parts.append(expr[start:])
    return [p.strip() for p in parts if p.strip()]


def _cfg_is_test(expr: str) -> bool:
    """True when the cfg predicate is satisfied only under `test`.

    `test` and `all(...)` containing `test` are test-only. `any(test, …)` and
    `not(test)` are deliberately NOT classified as test-only: they can be
    enabled without `test`.
    """
    expr = expr.strip()
    if expr == "test":
        return True
    m = re.match(r"all\s*\(", expr)
    if m:
        open_idx = m.end() - 1
        close = _balanced_end(expr, open_idx)
        if close is None:
            return False
        return any(_cfg_is_test(p) for p in _split_top_level(expr[open_idx + 1:close]))
    return False


def _iter_cfg_test_attr_ends(stripped: str):
    """Yield the offset just past `]` for each cfg(test)/cfg(all(test,…)) attr."""
    for m in re.finditer(r"#\s*!?\s*\[\s*cfg\s*\(", stripped):
        open_idx = m.end() - 1
        close = _balanced_end(stripped, open_idx)
        if close is None:
            continue
        j = close + 1
        while j < len(stripped) and stripped[j].isspace():
            j += 1
        if j >= len(stripped) or stripped[j] != "]":
            continue
        if _cfg_is_test(stripped[open_idx + 1:close]):
            yield j + 1


ITEM_RE = re.compile(
    r"(?:pub(?:\s*\([^)]*\))?\s+)?"
    r"(?:unsafe\s+)?(?:extern\s+)?"
    r"(?:async\s+)?(?:default\s+)?(?:const\s+)?"
    r"(fn|impl|trait|struct|enum|union|mod|const|static|use|type|macro_rules|extern)\b"
)


def _find_item_after(text: str, pos: int) -> tuple[str, int, str | None] | None:
    """Find the item following attributes at `pos`.

    Returns `(kind, item_start, module_name_or_None)`; None when no item keyword
    is found. This is a lexical helper, not a full Rust item parser.
    """
    n = len(text)
    while True:
        while pos < n and text[pos].isspace():
            pos += 1
        if text.startswith("#[", pos) or text.startswith("#![", pos):
            bracket = text.find("[", pos)
            end = _balanced_end(text, bracket)
            if end is None:
                return None
            pos = end + 1
            continue
        break
    m = ITEM_RE.match(text, pos)
    if not m:
        return None
    kind = m.group(1)
    name = None
    if kind == "mod":
        mm = re.match(
            r"\s+(?:r#)?([A-Za-z_][A-Za-z0-9_]*)", text[m.end():]
        )
        if mm:
            name = mm.group(1)
    return kind, pos, name


def _item_end(text: str, start: int, kind: str) -> int | None:
    """Exclusive end offset of an item: brace span or terminating `;`."""
    prefer_semicolon = kind in {"use", "const", "static", "type"}
    depth = 0
    for k in range(start, len(text)):
        ch = text[k]
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        elif ch == "{":
            if depth == 0 and not prefer_semicolon:
                end = _balanced_end(text, k)
                return (end + 1) if end is not None else None
            depth += 1
        elif ch == "}":
            depth -= 1
        elif ch == ";" and depth == 0:
            return k + 1
    return None


def _mod_terminator(text: str, start: int) -> tuple[str, int] | None:
    for k in range(start, len(text)):
        if text[k] == "{":
            return "brace", k
        if text[k] == ";":
            return "semi", k
    return None


def find_cfg_test_ranges(stripped: str):
    """Locate cfg(test) ranges for inline modules and individual items.

    Returns `(module_ranges, item_ranges, external_module_names)`. Module ranges
    cover the brace span of an inline `mod`; item ranges cover the brace span or
    terminating statement of `fn`, `impl`, `const`, `use`, `static`, etc.
    """
    module_ranges: list[dict] = []
    item_ranges: list[dict] = []
    external_names: list[str] = []
    for pos in _iter_cfg_test_attr_ends(stripped):
        item = _find_item_after(stripped, pos)
        if item is None:
            continue
        kind, start, name = item
        if kind == "mod":
            term = _mod_terminator(stripped, start)
            if term is None:
                continue
            term_kind, at = term
            if term_kind == "semi":
                if name:
                    external_names.append(name)
                continue
            end = _balanced_end(stripped, at)
            if end is not None:
                module_ranges.append({"name": name or "<unnamed>", "start": at, "end": end})
            continue
        end = _item_end(stripped, start, kind)
        if end is not None:
            item_ranges.append({"kind": kind, "start": start, "end": end - 1})
    # Deduplicate identical spans (stacked cfg attributes can name the same item).
    def _dedupe(ranges):
        seen = set()
        out = []
        for r in ranges:
            key = (r["start"], r["end"])
            if key not in seen:
                seen.add(key)
                out.append(r)
        return out

    return _dedupe(module_ranges), _dedupe(item_ranges), sorted(set(external_names))


def _resolve_mod_file(root: Path, rel: str, name: str) -> str | None:
    """Best-effort path of an external `mod name;` declaration.

    Covers the layouts this crate uses: `dir/mod.rs`, `src/lib.rs`/`main.rs`, and
    `dir/file.rs`. `#[path]` overrides and inline-module nesting are not handled;
    those remain a stated limitation.
    """
    base = Path(rel)
    if base.name == "mod.rs":
        candidates = [base.parent / f"{name}.rs", base.parent / name / "mod.rs"]
    elif rel in ("src/lib.rs", "src/main.rs"):
        candidates = [Path("src") / f"{name}.rs", Path("src") / name / "mod.rs"]
    else:
        stem_dir = base.with_suffix("")
        candidates = [stem_dir / f"{name}.rs", stem_dir / name / "mod.rs"]
    for cand in candidates:
        if (root / cand).is_file():
            return cand.as_posix()
    return None


def find_cfg_test_external_mods(root: Path, rel: str, stripped: str) -> list[str]:
    """Files pulled in by a cfg(test) `mod name;` declaration in `rel`."""
    _modules, _items, names = find_cfg_test_ranges(stripped)
    out = []
    for name in names:
        child = _resolve_mod_file(root, rel, name)
        if child is not None:
            out.append(child)
    return sorted(set(out))


def count_cfg_attr_cfg_test(stripped: str) -> int:
    """Count `cfg_attr(..., cfg(test))` attributes (detected, not reclassified)."""
    total = 0
    for m in re.finditer(r"#\s*!?\s*\[\s*cfg_attr\s*\(", stripped):
        close = _balanced_end(stripped, m.end() - 1)
        if close is None:
            continue
        inner = stripped[m.end():close]
        if re.search(r"\bcfg\s*\(\s*(?:all\s*\(\s*)?test\b", inner):
            total += 1
    return total


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" \t"))


FN_RE = re.compile(r"\bfn\s+(?:r#)?([A-Za-z_][A-Za-z0-9_]*)")


def _enclosing_fn(lines: list[str], line_idx: int) -> str:
    """Best-effort enclosing function: nearest preceding `fn` at lower indent."""
    target_indent = _indent(lines[line_idx])
    for i in range(line_idx, -1, -1):
        m = FN_RE.search(lines[i])
        if not m:
            continue
        if i == line_idx or _indent(lines[i]) < target_indent:
            return m.group(1)
    return "<top-level>"


def _is_fn_definition(stripped: str, pos: int) -> bool:
    """True when the identifier at `pos` is the name in `fn NAME(`."""
    k = pos - 1
    while k >= 0 and stripped[k].isspace():
        k -= 1
    end = k + 1
    while k >= 0 and (stripped[k].isalnum() or stripped[k] == "_"):
        k -= 1
    return stripped[k + 1:end] == "fn"


def _collect_call_sites(
    stripped: str,
    lines: list[str],
    starts: list[int],
    module_ranges: list[dict],
    item_ranges: list[dict],
    rel: str,
    is_seam: bool,
    file_is_test: bool,
    regex: re.Pattern[str],
    kind: str,
    family_map: dict,
) -> list[dict]:
    sites = []
    for m in regex.finditer(stripped):
        if _is_fn_definition(stripped, m.start()):
            continue
        line_idx = _offset_to_line(starts, m.start())
        if "name" in m.groupdict() and m.group("name"):
            callee = m.group("name")
        else:
            callee = re.sub(r"\s+", "", m.group(0))[:-1]
        in_module = file_is_test or any(
            r["start"] <= m.start() <= r["end"] for r in module_ranges
        )
        in_item = any(
            r["start"] <= m.start() <= r["end"] for r in item_ranges
        )
        family = "adopt" if kind == "adopt" else family_map.get(callee, "other")
        sites.append({
            "file": rel,
            "line": line_idx + 1,
            "kind": kind,
            "callee": callee,
            "family": family,
            "function": _enclosing_fn(lines, line_idx),
            "in_test": in_module or in_item,
            "in_test_module": in_module,
            "in_test_item": in_item,
            "is_seam_file": is_seam,
        })
    return sites


def scan_files(root: Path, rel_paths: list[str]):
    """One pass: content hash plus comment/literal-stripped call-site scan."""
    # Pre-pass: discover the allocator surface from the seam files, discover any
    # OPENSSL_* aliases, and resolve `#[cfg(test)] mod name;` external files.
    surface = _empty_surface()
    test_only_files: set[str] = set()
    for rel in rel_paths:
        text = (root / rel).read_text(encoding="utf-8", errors="replace")
        stripped = strip_comments_and_literals(text)
        _surface_add_source(surface, rel, stripped)
        test_only_files.update(find_cfg_test_external_mods(root, rel, stripped))
    surface = _finish_surface(surface)
    alloc_re, release_re = surface_regexes(surface)

    per_file = {}
    content_hash = hashlib.sha256()
    content_hash.update(b"openssl-rs/src-rs/v1\x00")
    for rel in rel_paths:
        raw = (root / rel).read_bytes()
        content_hash.update(rel.encode("utf-8"))
        content_hash.update(b"\x00")
        content_hash.update(raw)
        content_hash.update(b"\x00")
        text = raw.decode("utf-8", "replace")
        stripped = strip_comments_and_literals(text)
        lines = stripped.split("\n")
        starts = _line_starts(text)
        is_seam = rel in SEAM_FILES
        file_is_test = rel in test_only_files

        module_ranges, item_ranges, _external = find_cfg_test_ranges(stripped)
        alloc_sites = _collect_call_sites(
            stripped, lines, starts, module_ranges, item_ranges, rel, is_seam,
            file_is_test, alloc_re, "alloc", surface["alloc"]
        )
        release_sites = _collect_call_sites(
            stripped, lines, starts, module_ranges, item_ranges, rel, is_seam,
            file_is_test, release_re, "release", surface["release"]
        )
        adopt_sites = _collect_call_sites(
            stripped, lines, starts, module_ranges, item_ranges, rel, is_seam,
            file_is_test, ADOPT_CALL_RE, "adopt", {}
        )

        def production(sites: list[dict]) -> list[dict]:
            return [s for s in sites if not s["in_test"] and not s["is_seam_file"]]

        seams = [t for t in SEAM_TOKENS if t in stripped]
        per_file[rel] = {
            "sha256": hashlib.sha256(raw).hexdigest(),
            "seams": seams,
            "has_seam": bool(seams),
            "defines_allocator": bool(ALLOC_DEF_RE.search(stripped)),
            "alloc_sites": alloc_sites,
            "release_sites": release_sites,
            "adopt_sites": adopt_sites,
            "production_sites": production(alloc_sites) + production(release_sites),
            "production_alloc_sites": production(alloc_sites),
            "production_release_sites": production(release_sites),
            "test_sites": [
                s for s in alloc_sites + release_sites
                if s["in_test"] and not s["is_seam_file"]
            ],
            "seam_sites": [
                s for s in alloc_sites + release_sites + adopt_sites
                if s["is_seam_file"]
            ],
            "test_module_ranges": [
                {
                    "name": r["name"],
                    "start_line": _offset_to_line(starts, r["start"]) + 1,
                    "end_line": _offset_to_line(starts, r["end"]) + 1,
                }
                for r in module_ranges
            ],
            "item_test_ranges": [
                {
                    "kind": r["kind"],
                    "start_line": _offset_to_line(starts, r["start"]) + 1,
                    "end_line": _offset_to_line(starts, r["end"]) + 1,
                }
                for r in item_ranges
            ],
            "cfg_attr_cfg_test": count_cfg_attr_cfg_test(stripped),
            "file_is_test": file_is_test,
        }
    return per_file, content_hash.hexdigest(), sorted(test_only_files), surface


def matches_any(rel: str, patterns: list[str]) -> bool:
    for pat in patterns:
        if pat.endswith("/"):
            if rel.startswith(pat):
                return True
        elif rel == pat:
            return True
    return False


# --------------------------------------------------------------------------
# 3. Evidence loading (small summaries only; never echoed whole).
# --------------------------------------------------------------------------

def load_state(root: Path) -> dict:
    with open(root / STATE_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def load_p1000_counts(root: Path) -> dict:
    with open(root / P1000_PATH, encoding="utf-8") as fh:
        d = json.load(fh)
    b = d["body"]
    passes = [v for v in b["verdicts"] if v.get("verdict") == "DROP_IN_PASS"]
    return {
        "body_hash": d["body_hash"],
        "counts": b["counts"],
        "ladder_levels": b["ladder"]["levels"],
        "pass_families": sorted(
            (v["family_id"], v.get("candidate_level")) for v in passes
        ),
    }


def load_census_file_hashes(root: Path) -> dict | None:
    """Optional: frozen per-file sha256 from the Phase-25 census, used only as a
    candidate-binding cross-check (how many current closure files differ from
    the frozen census). Silently skipped if the artifact is absent/unreadable."""
    path = root / CENSUS_PATH
    if not path.exists():
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            d = json.load(fh)
        rows = d["body"]["files"]["rows"]
        cols = d["body"]["files"]["columns"]
        pi, si = cols.index("path"), cols.index("file_sha256")
        return {r[pi]: r[si] for r in rows}
    except Exception:
        return None


# --------------------------------------------------------------------------
# 4. Computation.
# --------------------------------------------------------------------------

def family_breakdown(sites: list[dict]) -> dict:
    """Count alloc/release calls and files by declared allocator family."""
    raw: dict[str, dict] = {}
    for site in sites:
        family = site.get("family", "other")
        rec = raw.setdefault(family, {
            "alloc_calls": 0, "alloc_files": set(),
            "release_calls": 0, "release_files": set(),
        })
        if site["kind"] == "alloc":
            rec["alloc_calls"] += 1
            rec["alloc_files"].add(site["file"])
        elif site["kind"] == "release":
            rec["release_calls"] += 1
            rec["release_files"].add(site["file"])
    return {
        family: {
            "alloc_calls": rec["alloc_calls"],
            "alloc_files": len(rec["alloc_files"]),
            "release_calls": rec["release_calls"],
            "release_files": len(rec["release_files"]),
        }
        for family, rec in sorted(raw.items())
    }


def build(root: Path, args) -> dict:
    rel_paths = list_src_rs(root)
    per_file, content_sha, external_test_files, surface = scan_files(root, rel_paths)
    alloc_re, release_re = surface_regexes(surface)
    allocator_files = sorted(p for p in SEAM_FILES if p in per_file)

    head = git("rev-parse", "HEAD", root=root)
    branch = git("rev-parse", "--abbrev-ref", "HEAD", root=root)
    version = crate_version(root)

    state = load_state(root)
    p1000 = load_p1000_counts(root)

    # --- Cohort (33). state.json#cohort is authoritative; p1000-run is the
    #     frozen verdict artifact and a cross-check on count + level split.
    cohort = state["cohort"]
    families = cohort["families"]
    fam_rows = []
    for name in sorted(families):
        f = families[name]
        fam_rows.append({
            "family": name,
            "level": f["level"],
            "libssl": f["libssl"],
            "evidence": f["evidence"],
            "rank": f["rank"],
            "mechanisms": list(f["mechanisms"]),
        })

    # --- Mechanisms.
    mech_state = {m["id"]: m for m in state["mechanisms"]}
    mechanism_rows = []
    union_files = set()
    for mid in MECHANISM_ORDER:
        pats = MECHANISM_PATHS[mid]
        closure = [p for p in rel_paths if matches_any(p, pats)]
        union_files.update(closure)
        m = mech_state.get(mid, {})
        seam_files = [p for p in closure if per_file[p]["has_seam"]]
        zero_alloc = [p for p in closure if not per_file[p]["production_alloc_sites"]]
        alloc_def = [p for p in closure if per_file[p]["defines_allocator"]]
        no_seam_alloc = [
            p for p in closure
            if not per_file[p]["has_seam"]
            and per_file[p]["production_alloc_sites"]
            and not per_file[p]["defines_allocator"]
        ]
        seam_alloc = [
            p for p in closure
            if per_file[p]["has_seam"]
            and per_file[p]["production_alloc_sites"]
            and not per_file[p]["defines_allocator"]
        ]
        closure_prod_alloc = sum(
            len(per_file[p]["production_alloc_sites"]) for p in closure
        )
        closure_prod_release = sum(
            len(per_file[p]["production_release_sites"]) for p in closure
        )
        closure_alloc_files = [p for p in closure if per_file[p]["production_alloc_sites"]]
        interior_alloc_sites = sum(
            len(per_file[p]["production_alloc_sites"]) for p in no_seam_alloc
        )
        interior_release_sites = sum(
            len(per_file[p]["production_release_sites"]) for p in no_seam_alloc
        )
        seam_alloc_sites = sum(
            len(per_file[p]["production_alloc_sites"]) for p in seam_alloc
        )
        mechanism_rows.append({
            "id": mid,
            "category": m.get("category"),
            "state": m.get("state"),
            "families_total": m.get("families_total"),
            "families_measured": m.get("families_measured"),
            "families_inferred": m.get("families_inferred"),
            "crate_unsafe_operations_frozen": m.get("crate_unsafe_operations"),
            "crate_files_frozen": m.get("crate_files"),
            "converted_files_on_branch": list(m.get("converted_files_on_branch", [])),
            # Recomputed against the CURRENT tree. "production" = a call, not a
            # token; comments/literals stripped; test-only and seam-file calls
            # excluded.
            "closure_files_recomputed": len(closure),
            "closure_seam_files": len(seam_files),
            "closure_zero_raw_files": len(zero_alloc),
            "closure_zero_production_alloc_files": len(zero_alloc),
            "closure_production_alloc_files": len(closure_alloc_files),
            "closure_production_alloc_calls": closure_prod_alloc,
            "closure_production_release_calls": closure_prod_release,
            "closure_no_seam_raw_files": len(no_seam_alloc),
            "closure_no_seam_production_alloc_files": len(no_seam_alloc),
            "closure_seam_raw_files": len(seam_alloc),
            "closure_seam_bearing_production_alloc_files": len(seam_alloc),
            "closure_seam_bearing_production_alloc_sites": seam_alloc_sites,
            "closure_allocator_definition_files": sorted(alloc_def),
            # Deprecated alias: alloc + release production calls, never test or
            # seam-file calls. Prefer the split fields above.
            "closure_raw_sites": closure_prod_alloc + closure_prod_release,
            "unconverted_interior_files": sorted(no_seam_alloc),
            "unconverted_interior_file_count": len(no_seam_alloc),
            # Deprecated alias kept for consumers of the previous report; it is
            # the PRODUCTION ALLOCATION call count, not alloc+release.
            "unconverted_interior_sites": interior_alloc_sites,
            "unconverted_interior_production_alloc_sites": interior_alloc_sites,
            "unconverted_interior_production_release_sites": interior_release_sites,
        })

    # --- Whole-tree scan totals. Production counts exclude test-only sites and
    #     the allocator-seam file; each of those is reported separately below.
    with_seam = [p for p in rel_paths if per_file[p]["has_seam"]]
    non_seam_files = [p for p in rel_paths if p not in SEAM_FILES]

    production_alloc_sites = [
        s for p in non_seam_files for s in per_file[p]["production_alloc_sites"]
    ]
    production_release_sites = [
        s for p in non_seam_files for s in per_file[p]["production_release_sites"]
    ]
    test_alloc_sites = [
        s for p in non_seam_files for s in per_file[p]["alloc_sites"]
        if s["in_test"] and not s["is_seam_file"]
    ]
    test_release_sites = [
        s for p in non_seam_files for s in per_file[p]["release_sites"]
        if s["in_test"] and not s["is_seam_file"]
    ]
    seam_alloc_sites = [
        s for p in SEAM_FILES for s in per_file.get(p, {}).get("seam_sites", [])
        if s["kind"] == "alloc"
    ]
    seam_release_sites = [
        s for p in SEAM_FILES for s in per_file.get(p, {}).get("seam_sites", [])
        if s["kind"] == "release"
    ]
    seam_adopt_sites = [
        s for p in SEAM_FILES for s in per_file.get(p, {}).get("seam_sites", [])
        if s["kind"] == "adopt"
    ]
    all_adopt_sites = [s for p in rel_paths for s in per_file[p]["adopt_sites"]]
    production_adopt_sites = [
        s for s in all_adopt_sites if not s["in_test"] and not s["is_seam_file"]
    ]

    # Sites newly classified test-only by an individual-item cfg(test) range
    # (not an inline module range and not an external test module file).
    item_reclassified_sites = [
        s
        for p in rel_paths
        for s in per_file[p]["alloc_sites"]
        + per_file[p]["release_sites"]
        + per_file[p]["adopt_sites"]
        if s["in_test_item"] and not s["in_test_module"] and not s["is_seam_file"]
    ]
    item_reclassified_alloc_release = [
        s for s in item_reclassified_sites if s["kind"] in ("alloc", "release")
    ]

    production_alloc_calls = len(production_alloc_sites)
    production_alloc_files = sorted({s["file"] for s in production_alloc_sites})
    production_release_calls = len(production_release_sites)
    production_release_files = sorted({s["file"] for s in production_release_sites})
    test_calls = len(test_alloc_sites) + len(test_release_sites)
    test_files = sorted({s["file"] for s in test_alloc_sites + test_release_sites})
    seam_calls = len(seam_alloc_sites) + len(seam_release_sites)
    seam_files_present = sorted(p for p in SEAM_FILES if p in per_file)
    files_with_prod_alloc = [
        p for p in non_seam_files if per_file[p]["production_alloc_sites"]
    ]
    files_zero_prod_alloc = [
        p for p in non_seam_files if not per_file[p]["production_alloc_sites"]
    ]
    no_seam_prod_alloc_files = sorted(
        p for p in non_seam_files
        if per_file[p]["production_alloc_sites"]
        and not per_file[p]["has_seam"]
        and not per_file[p]["defines_allocator"]
    )
    seam_bearing_prod_alloc_files = [
        p for p in non_seam_files
        if per_file[p]["production_alloc_sites"] and per_file[p]["has_seam"]
    ]
    seam_bearing_prod_alloc_sites = sum(
        len(per_file[p]["production_alloc_sites"])
        for p in seam_bearing_prod_alloc_files
    )

    # --- Closure-restricted scan.
    closure_files = sorted(union_files)
    closure_seam = [p for p in closure_files if per_file[p]["has_seam"]]
    closure_no_seam_alloc = [
        p for p in closure_files
        if not per_file[p]["has_seam"]
        and per_file[p]["production_alloc_sites"]
        and not per_file[p]["defines_allocator"]
    ]
    closure_seam_alloc = [
        p for p in closure_files
        if per_file[p]["has_seam"]
        and per_file[p]["production_alloc_sites"]
        and not per_file[p]["defines_allocator"]
    ]
    closure_prod_alloc_total = sum(
        len(per_file[p]["production_alloc_sites"]) for p in closure_files
    )
    closure_prod_release_total = sum(
        len(per_file[p]["production_release_sites"]) for p in closure_files
    )
    interior_alloc_unresolved = sum(
        len(per_file[p]["production_alloc_sites"]) for p in closure_no_seam_alloc
    )
    interior_release_unresolved = sum(
        len(per_file[p]["production_release_sites"]) for p in closure_no_seam_alloc
    )
    seam_bearing_alloc = sum(
        len(per_file[p]["production_alloc_sites"]) for p in closure_seam_alloc
    )
    seam_bearing_release = sum(
        len(per_file[p]["production_release_sites"]) for p in closure_seam_alloc
    )
    test_module_count = sum(
        len(per_file[p]["test_module_ranges"]) for p in rel_paths
    )
    item_test_range_count = sum(
        len(per_file[p]["item_test_ranges"]) for p in rel_paths
    )
    cfg_attr_cfg_test_count = sum(
        per_file[p]["cfg_attr_cfg_test"] for p in rel_paths
    )
    production_by_family = family_breakdown(
        production_alloc_sites + production_release_sites
    )
    test_by_family = family_breakdown(test_alloc_sites + test_release_sites)
    seam_by_family = family_breakdown(seam_alloc_sites + seam_release_sites)

    # --- Coverage gap: top-level src/ modules named by NO mechanism mapping.
    #     This is honest unknown coverage: the nine-mechanism closure does not
    #     cover every module the conversion touches.
    covered_prefixes = set()
    for pats in MECHANISM_PATHS.values():
        for pat in pats:
            covered_prefixes.add(pat)
    uncovered_dirs: dict[str, int] = {}
    for p in rel_paths:
        if not matches_any(p, list(covered_prefixes)):
            parts = p.split("/")
            key = parts[1] if len(parts) > 2 else p
            uncovered_dirs[key] = uncovered_dirs.get(key, 0) + 1

    # --- Per-consumer mechanism status (metric 5).
    mech_by_recon = {mid: (mech_state[mid]["state"] == "OWNERSHIP_RECONSTRUCTED")
                     for mid in MECHANISM_ORDER}
    per_consumer = []
    SAFE_COMPATIBLE = 0
    for row in fam_rows:
        need = row["mechanisms"]
        recon = [m for m in need if mech_by_recon.get(m)]
        open_ = [m for m in need if not mech_by_recon.get(m)]
        per_consumer.append({
            "family": row["family"],
            "level": row["level"],
            "evidence": row["evidence"],
            "mechanisms_required": len(need),
            "mechanisms_ownership_reconstructed": len(recon),
            "mechanisms_unsafe_open": len(open_),
            "unsafe_open_ids": sorted(open_),
            "safe_compatible_eligible": False,
        })

    # --- Ledger vs seam heuristic: files the ledger lists as converted on this
    #     branch that carry NO recognised seam token. Measures how much the
    #     file-level seam heuristic undercounts reconstruction.
    ledger_missing = []
    ledger_present = 0
    ledger_absent = []
    for mid in MECHANISM_ORDER:
        for f in mech_state.get(mid, {}).get("converted_files_on_branch", []):
            if f not in per_file:
                ledger_absent.append({"mechanism": mid, "file": f})
            elif per_file[f]["has_seam"]:
                ledger_present += 1
            else:
                ledger_missing.append({"mechanism": mid, "file": f})

    # --- Census cross-check (frozen hashes vs current tree).
    crosscheck = None
    frozen = load_census_file_hashes(root)
    if frozen is not None:
        changed = [p for p in closure_files
                   if p in frozen and frozen[p] != per_file[p]["sha256"]]
        unknown = [p for p in closure_files if p not in frozen]
        crosscheck = {
            "source": CENSUS_PATH,
            "closure_files_matched": len(closure_files) - len(changed) - len(unknown),
            "closure_files_changed_since_frozen_census": len(changed),
            "closure_files_absent_from_frozen_census": len(unknown),
            "note": (
                "The census is the FROZEN Phase-25 atlas (earlier candidate). "
                "A changed file is candidate drift since that freeze, not a defect."
            ),
        }

    # --- Unknown coverage vs demonstrated failure (distinguished explicitly).
    demonstrated_failure = []
    for mrow in mechanism_rows:
        if mrow["closure_no_seam_production_alloc_files"] > 0:
            demonstrated_failure.append({
                "mechanism": mrow["id"],
                "unconverted_interior_files": mrow[
                    "closure_no_seam_production_alloc_files"
                ],
                "unconverted_interior_alloc_calls": mrow[
                    "unconverted_interior_production_alloc_sites"
                ],
            })
    unknown_coverage = []
    for mrow in mechanism_rows:
        if (mrow["families_inferred"] or 0) > 0:
            unknown_coverage.append({
                "mechanism": mrow["id"],
                "families_without_symbol_fingerprint": mrow["families_inferred"],
            })

    # --- Next-target ranking. The ranked metric is the corrected production
    #     ALLOCATION call count in the mechanism's closure (test-only and
    #     seam-file calls excluded). It is a work-burden metric, NOT a defect
    #     count. Reachability is retained as context and in the secondary score.
    reach = {mid: 0 for mid in MECHANISM_ORDER}
    for row in fam_rows:
        for mid in row["mechanisms"]:
            reach[mid] += 1
    targets = []
    for mrow in mechanism_rows:
        mid = mrow["id"]
        targets.append({
            "mechanism": mid,
            "state": mrow["state"],
            "families_reaching": reach[mid],
            "production_alloc_calls": mrow["closure_production_alloc_calls"],
            "production_release_calls": mrow["closure_production_release_calls"],
            "production_alloc_files": mrow["closure_production_alloc_files"],
            "no_seam_production_alloc_files": mrow[
                "closure_no_seam_production_alloc_files"
            ],
            "no_seam_production_alloc_calls": mrow[
                "unconverted_interior_production_alloc_sites"
            ],
            "rank_metric": (
                "production allocation call sites in the mechanism closure "
                "(work burden, not a defect count)"
            ),
            "reach_x_alloc_score": reach[mid] * mrow["closure_production_alloc_calls"],
        })
    targets.sort(
        key=lambda t: (
            -t["production_alloc_calls"],
            -t["reach_x_alloc_score"],
            t["mechanism"],
        )
    )

    # --- Per-site evidence queue: every production alloc/release CALL in a
    #     non-test, non-seam file. Test-only and seam-file calls are excluded by
    #     construction (`production_sites`).
    worklist = []
    for p in rel_paths:
        for s in per_file[p]["production_sites"]:
            worklist.append({
                "file": s["file"],
                "line": s["line"],
                "kind": s["kind"],
                "callee": s["callee"],
                "family": s["family"],
                "function": s["function"],
                "seam_bearing_file": per_file[s["file"]]["has_seam"],
                "in_safe33_closure": s["file"] in union_files,
            })
    worklist.sort(
        key=lambda r: (r["file"], r["line"], r["kind"], r["callee"], r["function"])
    )

    doc = {
        "schema": "openssl-rs/p25-safe-c33/atlas-refresh/1",
        "measurement_revision": 2,
        "kind": "safe-c33-atlas-refresh",
        "generator": f"{CAMPAIGN_DIR}/atlas_refresh.py",
        "generated_utc": candidate_utc(root),
        "candidate": {
            "head_sha": head,
            "branch": branch,
            "crate_name": "openssl-rs",
            "crate_version": version,
            "src_rs_files": len(rel_paths),
            "src_content_sha256": content_sha,
            "src_content_hash_rule": (
                "sha256 over the byte string 'openssl-rs/src-rs/v1\\0' followed, "
                "for each src/**/*.rs in sorted relative-path order, by "
                "relpath\\0filebytes\\0"
            ),
            "inventory_head_sha_frozen": state.get("head_sha"),
            "inventory_base_sha": state.get("base_sha"),
        },
        "cohort": {
            "authoritative_source": (
                "forensics/memory-safety/campaign/safe-c33/state.json#cohort "
                "(cross-checked against forensics/downstream/p1000-run.json "
                "body.counts / verdicts)"
            ),
            "candidate_verdict": cohort["verdict"],
            "count": cohort["count"],
            "levels": cohort["levels"],
            "l7_functional": list(cohort["l7_functional"]),
            "build_link_only": list(cohort["build_link_only"]),
            "fingerprinted": list(cohort["fingerprinted"]),
            "p1000_counts": p1000["counts"],
            "p1000_ladder_levels": p1000["ladder_levels"],
            "p1000_pass_families_match": sorted(
                n.split(":", 1)[1] for n, _lvl in p1000["pass_families"]
            ) == sorted(families.keys()),
            "families": fam_rows,
        },
        "mechanism_file_mapping": {
            "rule": (
                "declared as data in atlas_refresh.py:MECHANISM_PATHS; trailing "
                "'/' = directory prefix, bare path = exact file; derived from "
                "CLOSURE.md 'authority evidence' prefixes + state.json "
                "converted_files_on_branch + PROGRESS.md"
            ),
            "paths": MECHANISM_PATHS,
        },
        "mechanisms": mechanism_rows,
        "recomputed_source_scan": {
            "seam_tokens": SEAM_TOKENS,
            "measurement_method": (
                "comments and string/char literals are blanked in place by a "
                "hand-written scanner (offsets and line numbers preserved); a "
                "site is an identifier followed by optional whitespace/turbofish "
                "and '(' and is not a `fn` definition; alloc/release names are "
                "discovered from the seam files; test classification covers inline "
                "cfg(test) modules, external `mod name;` files, and individual items"
            ),
            "allocator_surface": {
                "source_files": surface["seam_files"],
                "alloc_names": sorted(surface["alloc"]),
                "release_names": sorted(surface["release"]),
                "families": {
                    name: {"kind": kind, "family": family}
                    for kind, mapping in (
                        ("alloc", surface["alloc"]),
                        ("release", surface["release"]),
                    )
                    for name, family in mapping.items()
                },
                "openssl_alias_names": surface["aliases"],
                "excluded_public_functions": surface["excluded"],
            },
            "adoption_call_pattern": ADOPT_CALL_RE.pattern,
            # Deprecated keys retained for consumers of the previous report.
            # They now mean call-only, production (non-test, non-seam) sites.
            "raw_site_patterns": [alloc_re.pattern, release_re.pattern],
            "files_zero_raw_sites": len(files_zero_prod_alloc),
            "files_with_raw_sites": len(files_with_prod_alloc),
            "raw_site_keys_note": (
                "`raw_site_patterns`, `files_zero_raw_sites`, `files_with_raw_sites` "
                "and `raw_sites_total` are deprecated aliases. They now describe "
                "production call sites (comments/literals stripped; test and "
                "seam excluded), not the old token regex counts."
            ),
            "files_total": len(rel_paths),
            "files_with_seam": len(with_seam),
            "files_zero_production_alloc_calls": len(files_zero_prod_alloc),
            "files_with_production_alloc_calls": len(files_with_prod_alloc),
            "production_alloc_calls": production_alloc_calls,
            "production_alloc_call_files": len(production_alloc_files),
            "production_release_calls": production_release_calls,
            "production_release_call_files": len(production_release_files),
            "test_only_alloc_calls": len(test_alloc_sites),
            "test_only_release_calls": len(test_release_sites),
            "test_only_calls": test_calls,
            "test_only_call_files": len(test_files),
            "seam_file_alloc_calls": len(seam_alloc_sites),
            "seam_file_release_calls": len(seam_release_sites),
            "seam_file_calls": seam_calls,
            "seam_file_adoption_calls": len(seam_adopt_sites),
            "seam_file_files": seam_files_present,
            "seam_file_label": (
                "allocator seam implementation; excluded from consumer-site counts"
            ),
            "adoption_calls_total": len(all_adopt_sites),
            "production_adoption_calls": len(production_adopt_sites),
            "no_seam_production_alloc_files": no_seam_prod_alloc_files,
            "no_seam_production_alloc_file_count": len(no_seam_prod_alloc_files),
            "sites_inside_seam_bearing_files": seam_bearing_prod_alloc_sites,
            "seam_bearing_files_with_production_alloc": len(
                seam_bearing_prod_alloc_files
            ),
            "allocator_definition_files": allocator_files,
            "test_detection_method": (
                "cfg-attribute brace span for inline cfg(test) modules, path "
                "resolution for external `#[cfg(test)] mod name;` files, and "
                "brace/statement spans for individual cfg(test) items; not a "
                "full parser (residual limitation reported)"
            ),
            "test_module_count": test_module_count,
            "item_cfg_test_range_count": item_test_range_count,
            "item_cfg_test_sites_reclassified": len(item_reclassified_sites),
            "item_cfg_test_alloc_release_reclassified": len(
                item_reclassified_alloc_release
            ),
            "cfg_attr_cfg_test_attributes": cfg_attr_cfg_test_count,
            "external_test_module_files": external_test_files,
            "external_test_module_file_count": len(external_test_files),
            "production_by_family": production_by_family,
            "test_only_by_family": test_by_family,
            "seam_file_by_family": seam_by_family,
            "family_note": (
                "Families keep secure, cleansing, array, aligned, duplicate and "
                "realloc operations visible; they are not folded into plain malloc."
            ),
            # Deprecated alias: production alloc + release calls only. It does
            # NOT include test-only sites, seam-file sites or adoption tokens.
            "raw_sites_total": production_alloc_calls + production_release_calls,
            "raw_sites_total_note": (
                "DEPRECATED ALIAS, not used as a headline. Use "
                "production_alloc_calls and production_release_calls separately; "
                "they are not interchangeable and their sum is not a defect count."
            ),
            "allocator_definition_note": (
                "Files defining the CRYPTO_* allocator entry points (the seam "
                "itself); their calls are the seam being defined, not interior "
                "residuals, and are excluded from metric 4. Both "
                "`src/runtime/mem.rs` and `src/runtime/secure.rs` are treated "
                "as allocator seam implementations."
            ),
        },
        "site_worklist": {
            "path": f"{OUT_DIR}/site-worklist.json",
            "row_count": len(worklist),
            "fields": [
                "file", "line", "kind", "callee", "family", "function",
                "seam_bearing_file", "in_safe33_closure",
            ],
            "note": (
                "Per-site evidence queue: production (non-test, non-seam) alloc "
                "and release call sites only, sorted by file then line."
            ),
        },
        "cohort_metrics": {
            "1_unique_closure_files": len(closure_files),
            "2_files_ownership_reconstructed": len(closure_seam),
            "3_files_fully_discharged_obligations": 0,
            "3_note": (
                "Obligations are discharged ONLY at the seal point "
                "(AGENTS.md §7 SAFETY_DISCHARGED, §18). No per-site validity "
                "contract has been proven for any closure file at this "
                "candidate, so this is honestly 0. A present seam is "
                "OWNERSHIP_RECONSTRUCTED, which is not discharge."
            ),
            "4_unresolved_interior_raw_sites": {
                "unconverted_no_seam_files": len(closure_no_seam_alloc),
                "unconverted_no_seam_production_alloc_calls": interior_alloc_unresolved,
                "unconverted_no_seam_production_release_calls": interior_release_unresolved,
                "seam_bearing_files_with_production_alloc_calls": len(closure_seam_alloc),
                "seam_bearing_production_alloc_calls_unclassified": seam_bearing_alloc,
                "seam_bearing_production_release_calls_unclassified": seam_bearing_release,
                "allocator_definition_files_excluded": sorted(
                    p for p in closure_files if per_file[p]["defines_allocator"]
                ),
                "upper_bound_total": (
                    interior_alloc_unresolved
                    + interior_release_unresolved
                    + seam_bearing_alloc
                    + seam_bearing_release
                ),
                "note": (
                    "Allocation calls and release calls are reported separately "
                    "and must not be added into one 'raw site' figure. Calls in "
                    "no-seam files are unambiguously unclassified interior work. "
                    "Calls in seam-bearing files are mixed: they include "
                    "legitimate seam-constructor/release sites and any remaining "
                    "interior sites — this lightweight pass cannot separate them, "
                    "so they are reported as classification burden, not as "
                    "defects."
                ),
            },
            "5_consumers_safe_compatible": SAFE_COMPATIBLE,
            "5_note": (
                "0 by construction: no mechanism is SAFETY_DISCHARGED, so no "
                "consumer's dependency closure can be discharged. Functional "
                "re-testing is required before any graduation."
            ),
            "per_consumer": per_consumer,
            "closure_production_alloc_calls_total": closure_prod_alloc_total,
            "closure_production_release_calls_total": closure_prod_release_total,
            # Deprecated alias: alloc + release production calls, not a defect count.
            "closure_raw_sites_total": closure_prod_alloc_total + closure_prod_release_total,
        },
        "unknown_vs_demonstrated_failure": {
            "unknown_coverage": unknown_coverage,
            "unknown_coverage_note": (
                "Mechanism dependence is MEASURED (symbol fingerprint) for 6 "
                "families and INFERRED (linkage/surface) for 27; isync and "
                "nginx reach L7 with no fingerprint. The join speaks for 6 of "
                "1000. Absence of a fingerprint is unknown coverage, not a pass."
            ),
            "demonstrated_failure": demonstrated_failure,
            "demonstrated_failure_note": (
                "A closure file with at least one production allocation CALL and "
                "NO ownership seam is a known-unconverted interior allocation "
                "site in a mechanism a consumer needs. This is the only class "
                "this refresh asserts as failure-shaped; it is not a functional "
                "regression."
            ),
        },
        "census_crosscheck": crosscheck,
        "ledger_seam_crosscheck": {
            "note": (
                "Files state.json lists as converted_files_on_branch that carry "
                "NO recognised seam token in the current tree. The file-level "
                "seam heuristic therefore UNDERCOUNTS reconstruction for "
                "structural/lock-based conversions that leave no owner token."
            ),
            "ledger_files_total": ledger_present + len(ledger_missing),
            "seam_token_present": ledger_present,
            "missing_seam_token": ledger_missing,
            "file_not_in_tree": ledger_absent,
        },
        "mapping_coverage": {
            "covered_top_level_modules": sorted(
                {p.split("/")[1] for p in closure_files if p.count("/") >= 2}
            ),
            "uncovered_top_level_modules": dict(
                sorted(uncovered_dirs.items(), key=lambda kv: (-kv[1], kv[0]))
            ),
            "note": (
                "src modules named by none of the nine mechanism directory "
                "rules (e.g. mac, sm2, modes, des, sm3). Their conversion "
                "work is real but is OUT of this nine-mechanism closure: a "
                "known coverage gap of this refresh, not a claim they are "
                "unconverted."
            ),
        },
        "next_targets": targets,
        "non_claims": [
            "This refresh measures ownership-reconstruction progress only; it "
            "claims no SAFETY_DISCHARGED and no SAFE_COMPATIBLE.",
            "The 33 historical DROP_IN_PASS verdicts are against an EARLIER "
            "candidate; functional re-testing is required before graduation.",
            "A present seam (OwnedCtx/OwnedBuf/impl Drop/…) is "
            "OWNERSHIP_RECONSTRUCTED, never discharge.",
            "Mechanism→file association is a declared directory mapping, not a "
            "per-symbol proof; it is an upper bound used for reachability.",
            "Production allocation calls are a work-burden metric, not a defect "
            "count; allocation and release calls are reported separately.",
            "Calls in files that also carry a seam token are classification "
            "burden, not proven defects or proven conversions.",
        ],
    }
    return doc, worklist


# --------------------------------------------------------------------------
# 5. Human report.
# --------------------------------------------------------------------------

def render_report(doc: dict) -> str:
    c = doc["candidate"]
    coh = doc["cohort"]
    scan = doc["recomputed_source_scan"]
    cm = doc["cohort_metrics"]
    us = doc["unknown_vs_demonstrated_failure"]
    L = []
    a = L.append

    a("# Safe-33 atlas refresh — candidate-bound ownership-reconstruction status")
    a("")
    a(f"Candidate stamp {doc['generated_utc']} (deterministic HEAD commit time; "
      "`SOURCE_DATE_EPOCH` honoured) by `{doc['generator']}` (stdlib only). "
      "**Measurement only** — no source conversion, no Phase-25 regeneration, "
      "no graduation claimed.")
    a("")
    a("## Candidate pin")
    a("")
    a(f"- HEAD `{c['head_sha']}` on `{c['branch']}`")
    a(f"- crate `{c['crate_name']} {c['crate_version']}`")
    a(f"- `src/**/*.rs`: **{c['src_rs_files']}** files, content sha256 "
      f"`{c['src_content_sha256']}`")
    a(f"- frozen inventory was at `{c['inventory_head_sha_frozen']}` (base "
      f"`{c['inventory_base_sha']}`); this refresh re-pins the current tree")
    a("")
    a("## The frozen 33 (authoritative: `state.json#cohort`)")
    a("")
    a(f"- verdict `{coh['candidate_verdict']}`, **{coh['count']}** families "
      f"({coh['levels']['L7-functional']} L7-functional, "
      f"{coh['levels']['L4-linked']} L4-linked)")
    a(f"- p1000 counts: "
      f"`DROP_IN_PASS={coh['p1000_counts']['verdicts']['DROP_IN_PASS']}`, "
      f"`DROP_IN_FAIL={coh['p1000_counts']['verdicts']['DROP_IN_FAIL']}`, "
      f"`DROP_IN_NOT_APPLICABLE={coh['p1000_counts']['verdicts']['DROP_IN_NOT_APPLICABLE']}`")
    a(f"- 33 names verified against `p1000-run.json`: "
      f"{coh['p1000_pass_families_match']}")
    a("")
    a("| family | level | libssl | evidence |")
    a("|---|---|---|---|")
    for f in coh["families"]:
        a(f"| {f['family']} | {f['level']} | {str(f['libssl']).lower()} | {f['evidence']} |")
    a("")
    a("## Nine mechanisms — ownership-reconstruction status")
    a("")
    a("`state` is from `state.json` (vocabulary: `UNSAFE_OPEN` < "
      "`OWNERSHIP_RECONSTRUCTED` < `SAFETY_DISCHARGED`; **none** is discharged). "
      "`closure` / `seam` / call counts are recomputed against the current tree. "
      "**Production allocation calls** is a work-burden metric, not a defect count; "
      "test-only and allocator-seam calls are excluded.")
    a("")
    a("| mechanism | state | families | closure files | seam files | no-seam prod-alloc files | production alloc calls | production release calls |")
    a("|---|---|---|---|---|---|---|---|")
    for m in doc["mechanisms"]:
        a(f"| {m['id']} | {m['state']} | {m['families_total']} | "
          f"{m['closure_files_recomputed']} | {m['closure_seam_files']} | "
          f"{m['closure_no_seam_production_alloc_files']} | "
          f"{m['closure_production_alloc_calls']} | "
          f"{m['closure_production_release_calls']} |")
    a("")
    a("## Cohort metrics (items 1–5, reported independently)")
    a("")
    a("| # | metric | value |")
    a("|---|---|---|")
    a(f"| 1 | unique source files in the union of the nine closures | **{cm['1_unique_closure_files']}** |")
    a(f"| 2 | files with reconstructed ownership (seam present) | **{cm['2_files_ownership_reconstructed']}** |")
    a(f"| 3 | files with fully discharged obligations | **{cm['3_files_fully_discharged_obligations']}** |")
    _m4 = cm['4_unresolved_interior_raw_sites']
    a(f"| 4 | unresolved interior production calls in the closure (no-seam files) | "
      f"**alloc: {_m4['unconverted_no_seam_production_alloc_calls']} calls / "
      f"{_m4['unconverted_no_seam_files']} files**; "
      f"**release: {_m4['unconverted_no_seam_production_release_calls']} calls** |")
    a(f"| 5 | consumers eligible for `SAFE_COMPATIBLE` | **{cm['5_consumers_safe_compatible']}** |")
    a("")
    a(f"- **3** is 0 by construction: {cm['3_note']}")
    a(f"- **4** detail: {_m4['note']}")
    a(f"- **4** classification burden (not defects): "
      f"{_m4['seam_bearing_production_alloc_calls_unclassified']} production "
      f"allocation calls and {_m4['seam_bearing_production_release_calls_unclassified']} "
      f"production release calls live in {_m4['seam_bearing_files_with_production_alloc_calls']} "
      f"seam-bearing closure files.")
    _adeff = _m4['allocator_definition_files_excluded']
    a(f"- **4** exclusions: the `CRYPTO_*` allocator definitions "
      f"({', '.join('`'+x+'`' for x in _adeff) or 'none'}) are the seam itself, "
      f"not interior residuals, and are excluded from the count above.")
    a("")
    a("### Whole-tree call-site scan (current candidate)")
    a("")
    a("A *site* is a call expression (`NAME(`), not a `use` import, comment "
      "mention or function-pointer table entry. Comments and string/char literals "
      "are stripped in place before scanning.")
    a("")
    a("| class | calls | files |")
    a("|---|---|---|")
    a(f"| production allocation calls | **{scan['production_alloc_calls']}** | "
      f"{scan['production_alloc_call_files']} |")
    a(f"| production release calls | **{scan['production_release_calls']}** | "
      f"{scan['production_release_call_files']} |")
    a(f"| test-only calls (alloc + release; excludes the allocator-seam file) | "
      f"{scan['test_only_calls']} "
      f"(alloc {scan['test_only_alloc_calls']}, release {scan['test_only_release_calls']}) | "
      f"{scan['test_only_call_files']} |")
    a(f"| allocator-seam calls (all calls in "
      f"{', '.join('`'+x+'`' for x in scan['seam_file_files'])}; "
      f"including their own test modules; excluded above) | "
      f"{scan['seam_file_calls']} (alloc {scan['seam_file_alloc_calls']}, "
      f"release {scan['seam_file_release_calls']}, adoption {scan['seam_file_adoption_calls']}) | "
      f"{len(scan['seam_file_files'])} |")
    a("")
    a(f"- files with a seam: **{scan['files_with_seam']}**")
    a(f"- files with at least one production allocation call: "
      f"**{scan['files_with_production_alloc_calls']}**")
    a(f"- files with zero production allocation calls (excluding the seam file): "
      f"**{scan['files_zero_production_alloc_calls']}**")
    a(f"- **files with at least one production allocation call and no recognised "
      f"seam (the true no-seam candidate set): {scan['no_seam_production_alloc_file_count']}**")
    a("  - " + (", ".join('`'+x+'`' for x in scan['no_seam_production_alloc_files']) or "none"))
    a(f"- **sites inside seam-bearing files (classification burden, not defects): "
      f"{scan['sites_inside_seam_bearing_files']}** production allocation calls in "
      f"{scan['seam_bearing_files_with_production_alloc']} files")
    a(f"- adoption/transfer calls recorded separately (never counted as raw "
      f"sites): {scan['adoption_calls_total']} total, "
      f"{scan['production_adoption_calls']} production")
    a(f"- allocator-seam files (excluded from consumer counts): "
      f"{', '.join('`'+x+'`' for x in scan['allocator_definition_files']) or 'none'}")
    a(f"- test-classification detail: {scan['test_detection_method']}; "
      f"{scan['test_module_count']} inline `cfg(test)` module spans, "
      f"{scan['item_cfg_test_range_count']} individual cfg(test) item spans, "
      f"{scan['external_test_module_file_count']} external `#[cfg(test)] mod name;` "
      f"files treated as test-only "
      f"({', '.join('`'+x+'`' for x in scan['external_test_module_files']) or 'none'})")
    a(f"- sites reclassified test-only by individual-item cfg(test) ranges "
      f"(not already covered by a module/file): **{scan['item_cfg_test_sites_reclassified']}** "
      f"(alloc/release: {scan['item_cfg_test_alloc_release_reclassified']})")
    a(f"- `cfg_attr(..., cfg(test))` attributes detected but NOT reclassified "
      f"(conditional attribute, not a test-only marker): "
      f"{scan['cfg_attr_cfg_test_attributes']}")
    a("")
    a("Seam tokens counted: " + ", ".join(f"`{t}`" for t in scan["seam_tokens"]) + ".")
    a("")
    a("### Discovered allocator surface")
    a("")
    surf = scan["allocator_surface"]
    a(f"Derived from {', '.join('`'+x+'`' for x in surf['source_files'])}: "
      f"{len(surf['alloc_names'])} allocation and {len(surf['release_names'])} "
      f"release call names.")
    a("")
    a("- alloc: " + ", ".join(f"`{n}`" for n in surf["alloc_names"]))
    a("- release: " + ", ".join(f"`{n}`" for n in surf["release_names"]))
    if surf["openssl_alias_names"]:
        a("- `OPENSSL_*` aliases found as definitions: " +
          ", ".join(f"`{n}`" for n in surf["openssl_alias_names"]))
    else:
        a("- `OPENSSL_*` aliases found as definitions: none")
    a("- public seam functions excluded as queries/utilities: " +
      (", ".join(f"`{n}`" for n in surf["excluded_public_functions"]) or "none"))
    a("")
    a("### Per-family production call counts")
    a("")
    a("Family counts are kept separate so secure/cleansing/array/aligned/duplicate "
      "operations are visible and are not folded into a plain malloc figure. "
      "All counts are call sites; they are not defect counts.")
    a("")
    a("| family | production alloc calls | files | production release calls | files | test-only calls | seam calls |")
    a("|---|---:|---:|---:|---:|---:|---:|")
    families = sorted(
        set(scan["production_by_family"])
        | set(scan["test_only_by_family"])
        | set(scan["seam_file_by_family"])
    )
    for fam in families:
        prod = scan["production_by_family"].get(fam, {})
        test = scan["test_only_by_family"].get(fam, {})
        seam = scan["seam_file_by_family"].get(fam, {})
        p_alloc = prod.get("alloc_calls", 0)
        p_release = prod.get("release_calls", 0)
        test_calls = test.get("alloc_calls", 0) + test.get("release_calls", 0)
        seam_calls = seam.get("alloc_calls", 0) + seam.get("release_calls", 0)
        if p_alloc == p_release == test_calls == seam_calls == 0:
            continue
        a(f"| {fam} | {p_alloc} | {prod.get('alloc_files', 0)} | "
          f"{p_release} | {prod.get('release_files', 0)} | {test_calls} | {seam_calls} |")
    a("")
    a("### Per-site worklist")
    a("")
    a(f"Every production (non-test, non-seam) allocation and release call is "
      f"written to `{doc['site_worklist']['path']}` "
      f"(**{doc['site_worklist']['row_count']} rows**, sorted by file then line). "
      f"Fields: {', '.join('`'+f+'`' for f in doc['site_worklist']['fields'])}.")
    a("")
    a("> Caveat — *seam present* is a **file-level heuristic** over the "
      "comment/literal-stripped source: a file is counted as reconstructed if "
      "any seam token appears anywhere in code, even for an unrelated inner "
      "type. It is an upper bound on reconstructed ownership, used for "
      "reachability, never a per-site proof.")
    a("")
    a("### Mapping coverage (unknown coverage, stated)")
    a("")
    a(doc["mapping_coverage"]["note"])
    a("")
    unc = doc["mapping_coverage"]["uncovered_top_level_modules"]
    a("Top-level modules outside the nine-mechanism closure (files): " +
      ", ".join(f"`{k}`({v})" for k, v in list(unc.items())[:18]) + ".")
    a("")
    a("## Per-consumer mechanism status (metric 5)")
    a("")
    a("`recon` = mechanisms the consumer needs that are `OWNERSHIP_RECONSTRUCTED`; "
      "`open` = `UNSAFE_OPEN`. Eligible = needs **all** its mechanisms discharged.")
    a("")
    a("| family | level | mechs | recon | open | open mechanisms | eligible |")
    a("|---|---|---|---|---|---|---|")
    for p in cm["per_consumer"]:
        om = ", ".join(p["unsafe_open_ids"]) or "—"
        a(f"| {p['family']} | {p['level']} | {p['mechanisms_required']} | "
          f"{p['mechanisms_ownership_reconstructed']} | "
          f"{p['mechanisms_unsafe_open']} | {om} | no |")
    a("")
    a("## Distinguishing unknown coverage from demonstrated failure")
    a("")
    a(f"- **Unknown coverage** — {us['unknown_coverage_note']}")
    a("  - mechanisms with linkage-inferred families: " +
      ", ".join(f"{u['mechanism']} ({u['families_without_symbol_fingerprint']})"
                for u in us["unknown_coverage"]))
    a(f"- **Demonstrated failure** — {us['demonstrated_failure_note']}")
    a("  - mechanisms with unconverted (no-seam) interior files: " +
      (", ".join(f"{d['mechanism']} ({d['unconverted_interior_files']})"
                 for d in us["demonstrated_failure"]) or "none"))
    a("")
    a("## Next engineering target (ranked by production allocation calls)")
    a("")
    a("The rank metric is the corrected **production allocation call count** in "
      "the mechanism closure. It is a work-burden metric, **not a defect count**. "
      "Reachability is the count of the 33 that depend on the mechanism (upper "
      "bound) and is retained as context and in the secondary score. This ranking "
      "differs from the earlier report, which ranked by a conflated alloc+release "
      "figure over no-seam files only.")
    a("")
    a("| rank | mechanism | state | production alloc calls | production release calls | families reaching | no-seam prod-alloc files | reach × alloc score |")
    a("|---|---|---|---|---|---|---|---|")
    for i, t in enumerate(doc["next_targets"], 1):
        a(f"| {i} | {t['mechanism']} | {t['state']} | "
          f"**{t['production_alloc_calls']}** | {t['production_release_calls']} | "
          f"{t['families_reaching']} | {t['no_seam_production_alloc_files']} | "
          f"{t['reach_x_alloc_score']} |")
    a("")
    if doc["census_crosscheck"]:
        cc = doc["census_crosscheck"]
        a("## Candidate-binding cross-check vs the frozen census")
        a("")
        a(f"- closure files matching frozen census hash: {cc['closure_files_matched']}")
        a(f"- closure files CHANGED since the frozen census: "
          f"{cc['closure_files_changed_since_frozen_census']}")
        a(f"- closure files absent from the frozen census: "
          f"{cc['closure_files_absent_from_frozen_census']}")
        a(f"- {cc['note']}")
        a("")
    ls = doc["ledger_seam_crosscheck"]
    a("## Ledger vs seam heuristic")
    a("")
    a(f"Of **{ls['ledger_files_total']}** files the ledger lists as converted on this "
      f"branch, **{len(ls['missing_seam_token'])}** carry no recognised seam token: "
      + (", ".join('`'+m['file']+'`' for m in ls['missing_seam_token']) or "none") + ".")
    a("")
    a(f"{ls['note']}")
    a("")
    a("## Residual limitations (not papered over)")
    a("")
    a("- The scanner is a hand-written lexical pass, not a Rust parser. It "
      "correctly ignores comments and string/char literals, but calls produced "
      "by macros or `include!` are not visible to it.")
    a("- Inline `#[cfg(test)] mod tests { … }` and external "
      "`#[cfg(test)] mod name;` files are reclassified as test-only, and "
      "`#[cfg(test)]`/`#[cfg(all(test, ...))]` on individual `fn`, `impl`, "
      "`const`, `use`, and `static` items is now reclassified by item span. "
      "`cfg(any(test, ...))` is deliberately treated as production (it can be "
      "enabled without `test`). `cfg_attr(..., cfg(test))` is detected and "
      "counted but NOT reclassified: a conditional attribute does not by itself "
      "make an item test-only. `cfg(test)` on struct fields or other non-item "
      "positions is not handled.")
    a("- External-module resolution covers `dir/mod.rs`, `src/lib.rs`/`main.rs`, "
      "and `dir/file.rs`; `#[path]` overrides and modules declared inside inline "
      "modules are not resolved.")
    a("- The allocator surface is derived from public `fn` definitions in "
      "`src/runtime/mem.rs` and `src/runtime/secure.rs`, plus `OPENSSL_*` alias "
      "definitions discovered elsewhere in `src/`. C macros (`OPENSSL_free`, "
      "`OPENSSL_malloc`, …) have no Rust function to discover; allocator wrappers "
      "defined outside the seam files are only counted if they are the declared "
      "seam names or an `OPENSSL_*` alias. `CRYPTO_secure_malloc_init`/`_done` "
      "are counted in the separate `secure_arena` family.")
    a("- Container/lock/ex_data operations that contain `alloc`/`free` are not "
      "heap block allocation or release and are deliberately excluded: "
      "`OPENSSL_sk_free`, `OPENSSL_sk_pop_free`, `OPENSSL_LH_free`, "
      "`OPENSSL_INIT_free`, `CRYPTO_THREAD_lock_free`, `CRYPTO_free_ex_data`, "
      "`CRYPTO_free_ex_index`, `CRYPTO_alloc_ex_data`, and "
      "`CRYPTO_dup_ex_data`. `CRYPTO_aligned_alloc_array` and "
      "`CRYPTO_clear_realloc_array` are discovered seam functions with no "
      "observed call site at this candidate.")
    a("- The enclosing `function` is a best-effort backwards scan for the "
      "nearest `fn` at lower indentation; trait declarations, macro bodies, and "
      "unusual layouts can misattribute a name.")
    a("- Seam presence remains a file-level token heuristic and is an upper "
      "bound on reconstruction, never a per-site proof.")
    a("")
    a("## Non-claims")
    a("")
    for n in doc["non_claims"]:
        a(f"- {n}")
    a("")
    return "\n".join(L)


# --------------------------------------------------------------------------
# 6. Entry point.
# --------------------------------------------------------------------------

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", default=None, help="repository root (default: autodetect)")
    ap.add_argument("--out-dir", default=None, help=f"output dir (default: {OUT_DIR})")
    ap.add_argument("--stdout", action="store_true", help="print report to stdout")
    args = ap.parse_args(argv)

    root = Path(args.root).resolve() if args.root else repo_root()
    out_dir = (root / (args.out_dir or OUT_DIR))
    out_dir.mkdir(parents=True, exist_ok=True)

    doc, worklist = build(root, args)

    cand_path = out_dir / "candidate.json"
    cand_path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    worklist_doc = {
        "schema": "openssl-rs/p25-safe-c33/atlas-refresh/site-worklist/1",
        "generator": f"{CAMPAIGN_DIR}/atlas_refresh.py",
        "generated_utc": doc["generated_utc"],
        "candidate": {
            "head_sha": doc["candidate"]["head_sha"],
            "src_content_sha256": doc["candidate"]["src_content_sha256"],
        },
        "metric": (
            "production allocation/release call sites: comments and literals "
            "stripped, call expressions only, test modules and the allocator "
            "seam excluded"
        ),
        "row_count": len(worklist),
        "sites": worklist,
    }
    worklist_path = out_dir / "site-worklist.json"
    worklist_path.write_text(
        json.dumps(worklist_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    report = render_report(doc)
    (out_dir / "REPORT.md").write_text(report, encoding="utf-8")

    if args.stdout:
        sys.stdout.write(report)
    else:
        c = doc["candidate"]
        print(f"wrote {cand_path.relative_to(root)}")
        print(f"wrote {worklist_path.relative_to(root)}")
        print(f"wrote {(out_dir / 'REPORT.md').relative_to(root)}")
        print(f"candidate HEAD {c['head_sha']} src sha256 {c['src_content_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
