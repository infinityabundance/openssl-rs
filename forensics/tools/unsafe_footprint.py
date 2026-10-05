#!/usr/bin/env python3
"""openssl-rs — the measured `unsafe` / FFI footprint of the crate, per module.

Why this exists
---------------
The whole reason to write OpenSSL in Rust rather than C is memory safety, and a
project that never measures the *remaining* unsafe surface has not earned that
benefit — it has only asserted it. `docs/UNSAFE.md` asserted that `unsafe` is
"concentrated in narrow modules" without a number behind the claim. This
generator replaces the assertion with a measurement: it scans `src/**/*.rs` and
records, per module, how much `unsafe` and how much C-ABI surface the crate
actually carries, and it classifies each module as **boundary** (the translation
layer, where `unsafe` is expected) or **core** (parsers and algorithms, where it
is not).

The measurement is deliberately unflattering. `docs/UNSAFE.md` §2's example
boundary (`src/ffi/**`) turns out to carry almost none of the crate's `unsafe`;
`extern "C"` is declared in the parser and algorithm modules themselves, and the
`unsafe` that marshals pointers sits beside the ASN.1 and X.509 parsers rather
than in a separate shim. That is the finding, and `docs/UNSAFE.md` now cites this
table instead of denying it.

Exact definitions (so the number cannot be quietly redefined)
------------------------------------------------------------
All counts are over the crate's Rust source under `src/`, with **line comments,
(nested) block comments and string/character literals removed** first, so a
`SAFETY:` comment that says "unsafe" or a string containing the word does not
count as code.

  * ``unsafe_sites`` — occurrences of the `unsafe` keyword in code. Each unsafe
    block, function, impl, trait and `unsafe extern` block carries exactly one
    `unsafe` keyword, so this is the number of unsafe constructs. Sub-counts
    (they may overlap; they are a breakdown, not a partition):
      ``unsafe_blocks``  = `unsafe {`
      ``unsafe_fns``     = `unsafe fn` (an `unsafe extern "C" fn` counts under
                            ``unsafe_externs``, not here)
      ``unsafe_externs`` = `unsafe extern`
      ``unsafe_impls``   = `unsafe impl`
      ``unsafe_traits``  = `unsafe trait`
  * ``extern_c_fns`` — occurrences of `extern "C" fn` in code: a C-ABI function
    definition or declaration, whichever side of the boundary it is on.
  * ``safety_comments`` — occurrences of `SAFETY:` (the invariant-catalogue
    marker `docs/UNSAFE.md` §2 requires). Counted over the raw text, because the
    marker *is* a comment.

Classification (documented, and the growth court reads it)
----------------------------------------------------------
A module is the first path component under `src/` (a directory, or a top-level
file's stem), so `src/x509/v3_san.rs` is module `x509` and `src/aes.rs` is module
`aes`.

  * **boundary** — modules whose job is to mediate the C ABI, the operating
    system, dynamic loading or threads: `ffi`, `runtime`, `dso`, `engine`,
    `async`, `context`. Growth here is expected and allowed; it is the cost of
    speaking C.
  * **core** — everything else, and **an unlisted module is core by default**
    (the conservative direction). This deliberately includes the parser and
    algorithm modules the review names — `asn1`, `x509`, `pem`, `cms`, `ssl`
    (the TLS message parsers), `bn`, `rsa`, `ec`, `evp` — *and* the provider
    framework and the encode/decode planes, because an `unsafe` there is no more
    justified than one in the parser it dispatches to. The `UNSAFE-FOOTPRINT`
    growth court fails if a core module's count rises above its recorded bound.

What this does and does not establish
-------------------------------------
It establishes the *size and location* of the crate's unsafe surface, measured
by a defined lexical scan. It does **not** establish that any `unsafe` block is
correct, that the SAFETY comments are true, or that the memory-safety benefit is
realised: a count is not a proof. `docs/UNSAFE.md` and `forensics/STATUS.md`
state that non-claim explicitly.

Outputs
-------
  forensics/atlas/unsafe-footprint.json

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    ATLAS,
    REPO_ROOT,
    InputRef,
    envelope,
    rel,
    sha256_file,
    write_json,
)

OUT = ATLAS / "unsafe-footprint.json"
GENERATOR = "forensics/tools/unsafe_footprint.py"
SRC = REPO_ROOT / "src"

# ---------------------------------------------------------------------------
# The classification. `boundary` is an explicit, reasoned allowlist; every other
# module (including a module added later) is `core`. The growth court reads this
# through `scan()` so the two cannot disagree about which modules may grow.
# ---------------------------------------------------------------------------
BOUNDARY_MODULES: dict[str, str] = {
    "ffi": "the FFI/ABI translation module (the boundary docs/UNSAFE.md section 2 names)",
    "runtime": "the runtime boundary: allocator, error queue, stack, thread/atomic, BIO and "
               "configuration primitives (the mem/atomic primitives docs/UNSAFE.md section 2 "
               "names)",
    "dso": "dynamic loading (dlopen/dlsym/dlvsym, LoadLibrary)",
    "engine": "dynamic engine loading",
    "async": "async job / thread-pool glue",
    "context": "operating-system and context glue",
}

# The parser / algorithm modules the review names, recorded so a reader can see
# that the classification did not quietly move one of them into `boundary`.
NAMED_CORE_MODULES = ("asn1", "x509", "pem", "cms", "ssl", "bn", "rsa", "ec", "evp")

_RAW_STRING = re.compile(r'(?:br|rb|r)(?P<h>#{0,255})"')
_RE_UNSAFE = re.compile(r"\bunsafe\b")
_RE_UNSAFE_BLOCK = re.compile(r"\bunsafe\s*\{")
_RE_UNSAFE_FN = re.compile(r"\bunsafe\s+fn\b")
_RE_UNSAFE_EXTERN = re.compile(r"\bunsafe\s+extern\b")
_RE_UNSAFE_IMPL = re.compile(r"\bunsafe\s+impl\b")
_RE_UNSAFE_TRAIT = re.compile(r"\bunsafe\s+trait\b")
_RE_EXTERN_C_FN = re.compile(r'extern\s+"C"\s+fn')
_RE_SAFETY = re.compile(r"\bSAFETY\s*:")


def code_only(text: str, keep_strings: bool = False) -> str:
    """The source with comments removed, and (by default) string literals blanked.

    Newlines are preserved so the result is line-comparable, and the blanking is
    space-for-character so a column does not move. A best-effort Rust lexer:
    nested block comments, raw strings (`r#"..."#`), byte strings, escapes and
    char literals (but not lifetimes) are handled; it is a scanner, not a
    parser, and it is documented as such.

    `keep_strings=True` still consumes string and character literals -- so a
    `//` inside a string is not mistaken for a comment -- but keeps their text, so
    a construct whose *spelling includes a string* (`extern "C" fn`) can be
    matched against the result. It must not be used for the `unsafe` count, where
    a string containing the word is not an unsafe site.
    """
    blank = (lambda piece: piece) if keep_strings else (
        lambda piece: "".join("\n" if ch == "\n" else " " for ch in piece)
    )
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":
            j = text.find("\n", i)
            stop = n if j < 0 else j
            out.append(" " * (stop - i))
            i = stop
            continue
        if c == "/" and nxt == "*":
            depth = 1
            out.append("  ")
            i += 2
            while i < n and depth:
                if text[i:i + 2] == "/*":
                    depth += 1
                    out.append("  ")
                    i += 2
                elif text[i:i + 2] == "*/":
                    depth -= 1
                    out.append("  ")
                    i += 2
                else:
                    out.append("\n" if text[i] == "\n" else " ")
                    i += 1
            continue
        raw = _RAW_STRING.match(text, i)
        if raw is not None:
            hashes = raw.group("h")
            terminator = '"' + hashes
            end = text.find(terminator, raw.end())
            stop = n if end < 0 else end + len(terminator)
            out.append(blank(text[i:stop]))
            i = stop
            continue
        if c == '"':
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == '"':
                    j += 1
                    break
                j += 1
            out.append(blank(text[i:j]))
            i = j
            continue
        if c == "'":
            # A char literal (`'a'`, `'\n'`, `'\u{1F600}'`), not a lifetime (`'a`).
            if text[i + 1:i + 2] == "\\":
                j = i + 2
                while j < n and text[j] != "'":
                    j += 2 if text[j] == "\\" and j + 1 < n else 1
                stop = min(j + 1, n)
                out.append(blank(text[i:stop]))
                i = stop
                continue
            if text[i + 2:i + 3] == "'":
                out.append(blank(text[i:i + 3]))
                i += 3
                continue
        out.append(c)
        i += 1
    return "".join(out)


def module_of(relpath: Path) -> str:
    """The module a source file belongs to: its first component under `src/`."""
    parts = relpath.parts
    if len(parts) == 1:
        return parts[0][:-3]
    return parts[0]


def classify(module: str) -> str:
    return "boundary" if module in BOUNDARY_MODULES else "core"


def _metrics(text: str) -> dict:
    code = code_only(text)
    # `extern "C" fn` has a string in its spelling, so it is counted over the
    # comment-free but string-preserving view; `unsafe`/`unsafe {` are counted
    # over the view with strings blanked, because a string is not a site.
    code_kept = code_only(text, keep_strings=True)
    return {
        "lines": text.count("\n") + (0 if text.endswith("\n") or not text else 1),
        "unsafe_sites": len(_RE_UNSAFE.findall(code)),
        "unsafe_blocks": len(_RE_UNSAFE_BLOCK.findall(code)),
        "unsafe_fns": len(_RE_UNSAFE_FN.findall(code)),
        "unsafe_externs": len(_RE_UNSAFE_EXTERN.findall(code)),
        "unsafe_impls": len(_RE_UNSAFE_IMPL.findall(code)),
        "unsafe_traits": len(_RE_UNSAFE_TRAIT.findall(code)),
        "extern_c_fns": len(_RE_EXTERN_C_FN.findall(code_kept)),
        # The SAFETY marker is a comment, so it is counted over the raw text.
        "safety_comments": len(_RE_SAFETY.findall(text)),
    }


def _accumulate(dst: dict, add: dict) -> None:
    for key, value in add.items():
        if key == "lines":
            dst[key] = dst.get(key, 0) + value
            continue
        dst[key] = dst.get(key, 0) + value


def scan() -> dict:
    """The footprint of every module, by the definitions in this module's docstring.

    Deterministic: the sources are walked in sorted order and no wall-clock,
    environment or host value enters the result.
    """
    files = sorted(SRC.rglob("*.rs"))
    modules: dict[str, dict] = {}
    sources = hashlib.sha256()
    for path in files:
        text = path.read_text(encoding="utf-8", errors="replace")
        module = module_of(path.relative_to(SRC))
        entry = modules.setdefault(module, {"module": module, "classification": classify(module),
                                            "files": 0})
        entry["files"] += 1
        _accumulate(entry, _metrics(text))
        relpath = path.relative_to(REPO_ROOT).as_posix()
        sources.update(relpath.encode("utf-8"))
        sources.update(b"\0")
        sources.update(sha256_file(path).encode("ascii"))
        sources.update(b"\n")

    rows = [modules[name] for name in sorted(modules)]
    totals: dict = {
        "files": len(files),
        "lines": sum(row["lines"] for row in rows),
        "unsafe_sites": 0,
        "unsafe_blocks": 0,
        "unsafe_fns": 0,
        "unsafe_externs": 0,
        "unsafe_impls": 0,
        "unsafe_traits": 0,
        "extern_c_fns": 0,
        "safety_comments": 0,
        "by_class": {
            "boundary": {"modules": 0, "unsafe_sites": 0, "extern_c_fns": 0},
            "core": {"modules": 0, "unsafe_sites": 0, "extern_c_fns": 0},
        },
    }
    for row in rows:
        for key in ("unsafe_sites", "unsafe_blocks", "unsafe_fns", "unsafe_externs",
                    "unsafe_impls", "unsafe_traits", "extern_c_fns", "safety_comments"):
            totals[key] += row.get(key, 0)
        split = totals["by_class"][row["classification"]]
        split["modules"] += 1
        split["unsafe_sites"] += row.get("unsafe_sites", 0)
        split["extern_c_fns"] += row.get("extern_c_fns", 0)
    return {"modules": rows, "totals": totals, "sources_sha256": sources.hexdigest()}


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    args = ap.parse_args(argv)
    del args

    result = scan()
    body = {
        "definitions": {
            "unsafe_sites": (
                "occurrences of the `unsafe` keyword in code (line comments, nested block "
                "comments and string/char literals removed); one keyword per unsafe block, fn, "
                "impl, trait or `unsafe extern` block, so this is the number of unsafe constructs"
            ),
            "unsafe_blocks": "`unsafe {` in code",
            "unsafe_fns": "`unsafe fn` in code (an `unsafe extern \"C\" fn` counts under "
                          "`unsafe_externs`, not here)",
            "unsafe_externs": "`unsafe extern` in code",
            "unsafe_impls": "`unsafe impl` in code",
            "unsafe_traits": "`unsafe trait` in code",
            "extern_c_fns": "`extern \"C\" fn` in code",
            "safety_comments": "occurrences of `SAFETY:`, counted over the raw text because the "
                               "marker is a comment",
            "module": "the first path component under `src/` (a directory, or a top-level file's "
                      "stem)",
        },
        "classification": {
            "policy": (
                "a module is `boundary` when it is named in BOUNDARY_MODULES (FFI/ABI glue, the "
                "runtime primitives, dynamic loading, threads, OS glue) and `core` otherwise; an "
                "unlisted module -- including one added later -- is `core` by default, the "
                "conservative direction. `code_only` and the metric definitions above are the "
                "exact measurement this file records."
            ),
            "boundary": BOUNDARY_MODULES,
            "named_core_modules": list(NAMED_CORE_MODULES),
        },
        "scan": {
            "root": "src",
            "files": sum(m["files"] for m in result["modules"]),
            "lines": result["totals"]["lines"],
            "sources_sha256": result["sources_sha256"],
        },
        "totals": result["totals"],
        "modules": result["modules"],
    }
    inputs = [
        InputRef(
            name="crate-sources",
            sha256=result["sources_sha256"],
            note=(
                "sha256 over the sorted (repo-relative path, file sha256) pairs of every "
                "src/**/*.rs file; the crate source tree has no single path to hash, and this "
                "pins exactly the bytes the scan read"
            ),
        )
    ]
    doc = envelope(kind="unsafe-footprint", inputs=inputs, body=body, generator=GENERATOR)
    write_json(OUT, doc)

    t = result["totals"]
    core = t["by_class"]["core"]
    boundary = t["by_class"]["boundary"]
    print(f"[unsafe-footprint] {t['files']} files, {t['lines']} lines; "
          f"{t['unsafe_sites']} unsafe site(s), {t['extern_c_fns']} `extern \"C\" fn`, "
          f"{t['safety_comments']} SAFETY comment(s)")
    print(f"  core:     {core['modules']} module(s), {core['unsafe_sites']} unsafe site(s), "
          f"{core['extern_c_fns']} `extern \"C\" fn`")
    print(f"  boundary: {boundary['modules']} module(s), {boundary['unsafe_sites']} unsafe "
          f"site(s), {boundary['extern_c_fns']} `extern \"C\" fn`")
    print(f"  -> {rel(OUT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
