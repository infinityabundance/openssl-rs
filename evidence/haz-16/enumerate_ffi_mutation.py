#!/usr/bin/env python3
"""Enumerate exported FFI entries that can mutate caller-visible state.

Static, text-level enumeration.  The point is a *checkable population*, not a
proof: the candidate set is produced mechanically, and `CLASSIFICATION.json`
records the manual disposition of every candidate it names.

Method
------
1.  Walk every `.rs` file under `src/`.
2.  Locate `#[no_mangle]` items whose inner attribute block is followed by an
    `extern "C" fn` (optionally `pub`, optionally `unsafe`).
3.  Extract the function body by brace matching from the first `{` after the
    parameter list.
4.  Mark the entry as guarded when the body calls `guard_ffi`.
5.  Mark the entry as a *mutation candidate* when the body contains at least one
    of the mutation signals below.  The signals are deliberately broad; the
    manual pass narrows them to caller-visible state.

Signals are regular expressions rather than a Rust parser because the crate is
formatted by rustfmt and the exported functions are emitted one per item, which
makes brace matching reliable here.  The enumerator is evidence tooling, not a
build input.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"

EXPORT = re.compile(
    r"#\[no_mangle\]\s*"
    r"(?:#\[[^\]]*\]\s*)*"
    r"(?:pub(?:\([^)]*\))?\s+)?"
    r"(?:unsafe\s+)?extern\s+\"C\"\s+fn\s+([A-Za-z0-9_]+)\s*\(",
    re.MULTILINE,
)

# Broad signals that a body writes to something other than locals it owns.
MUTATION_SIGNALS = {
    "field_assign": re.compile(r"\(\s*\*[A-Za-z_][A-Za-z0-9_]*\s*\)\s*\.\s*[A-Za-z_][A-Za-z0-9_]*\s*(?:\|=|&=|\+=|-=|=)(?!=)"),
    "raw_field_assign": re.compile(r"\(\s*\*\s*[A-Za-z_][A-Za-z0-9_]*\s*\)\s*\.\s*[A-Za-z_]"),
    "out_param": re.compile(r"\*\s*(?:out|outl|outlen|len|size|ret|p|q|val|res|rlen|slen|siglen|mdlen)\s*=(?!=)"),
    "ptr_write": re.compile(r"(?:ptr::(?:write|copy|copy_nonoverlapping)|core::ptr::(?:write|copy|copy_nonoverlapping)|copy_nonoverlapping)\s*\("),
    "vec_mutate": re.compile(r"\.\s*(?:push|insert|remove|swap_remove|retain|clear|truncate|extend_from_slice|resize|reserve)\s*\("),
    "setter_call": re.compile(r"\b(?:set_[a-z_]+|raise_site|ERR_set_mark|ERR_clear_last_mark)\s*\("),
    "release": re.compile(r"(?:Box::from_raw|CRYPTO_free|OPENSSL_free|\b[A-Za-z_][A-Za-z0-9_]*_free\s*\(|destroy|into_raw|from_raw)"),
    "borrow_mut": re.compile(r"(?:as_mut\s*\(|\.iter_mut\s*\(|&mut\s+\*|mem::(?:take|swap|replace))\b"),
}

CALLER_VISIBLE_HINTS = re.compile(
    r"\b(?:ctx|st|stack|bio|bn|rsa|ec|key|x509|store|x|pkey|md|cipher|obj|lh|sk)\b",
    re.IGNORECASE,
)


def body_of(text: str, open_paren: int) -> str | None:
    """Return the text of the function body starting after `open_paren`."""
    i = text.find(")", open_paren)
    if i < 0:
        return None
    brace = text.find("{", i)
    if brace < 0:
        return None
    depth = 0
    for j in range(brace, len(text)):
        c = text[j]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[brace : j + 1]
    return None


def main() -> int:
    records = []
    files = sorted(SRC.rglob("*.rs"))
    for path in files:
        text = path.read_text(encoding="utf-8", errors="replace")
        for m in EXPORT.finditer(text):
            name = m.group(1)
            body = body_of(text, m.end() - 1)
            if body is None:
                continue
            signals = sorted(k for k, rx in MUTATION_SIGNALS.items() if rx.search(body))
            guarded = "guard_ffi" in body
            records.append(
                {
                    "file": str(path.relative_to(ROOT)),
                    "name": name,
                    "guarded": guarded,
                    "signals": signals,
                    "candidate": guarded and bool(signals),
                }
            )

    exported = len(records)
    guarded = sum(1 for r in records if r["guarded"])
    candidates = [r for r in records if r["candidate"]]
    by_file: dict[str, int] = {}
    for r in candidates:
        by_file[r["file"]] = by_file.get(r["file"], 0) + 1

    out = {
        "method": "static: #[no_mangle] extern \"C\" fn + guard_ffi + mutation signals",
        "scripts_scanned": len(files),
        "exported_functions_found": exported,
        "guard_ffi_wrapped": guarded,
        "mutation_candidates": len(candidates),
        "candidates_by_file": dict(sorted(by_file.items(), key=lambda kv: (-kv[1], kv[0]))),
        "candidates": candidates,
    }
    json.dump(out, sys.stdout, indent=2, sort_keys=False)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
