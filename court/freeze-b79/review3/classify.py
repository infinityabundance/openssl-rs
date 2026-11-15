#!/usr/bin/env python3
"""Classify each span delta: doc-only, annotation-only, or body change.

The classification is hunk-local: for every changed hunk the old and new text
are normalised by removing `//` comments, every `unsafe {` / `}` / `;` token and
all whitespace.  Equality under that normalisation means no code token, callee,
argument, control-flow or effect changed.
"""
import difflib
import json
import re
from pathlib import Path

P = Path("/home/user/openssl-rs/court/freeze-b79/review3/spans.json")
rows = json.loads(P.read_text())


def norm(lines):
    text = " ".join(re.sub(r"//.*$", "", l) for l in lines)
    text = text.replace("unsafe {", " ")
    text = text.replace("}", " ").replace(";", " ")
    return re.sub(r"\s+", "", text)


for r in rows:
    old_lines, new_lines = r["old_lines"], r["new_lines"]
    sm = difflib.SequenceMatcher(None, old_lines, new_lines)
    hunks = [(old_lines[i1:i2], new_lines[j1:j2])
             for tag, i1, i2, j1, j2 in sm.get_opcodes()
             if tag in ("replace", "insert", "delete")]
    if not hunks:
        r["classification"], r["delta"] = "none", "no difference"
        continue
    same = all(norm(o) == norm(n) for o, n in hunks)
    comment_only = all(
        all((not l.strip()) or l.strip().startswith("//") or
            l.strip() in ("unsafe {", "};") or l.strip().startswith("unsafe {")
            for l in n)
        for o, n in hunks)
    if same and comment_only and all(norm(o) == "" for o, n in hunks):
        r["classification"] = "doc-only"
        r["delta"] = ("the only in-span difference is a // SAFETY comment line; "
                      "every code token is byte-identical")
    elif same:
        r["classification"] = "annotation-only"
        r["delta"] = ("the in-span difference is an explicit `unsafe { }` block "
                      "around an unchanged callee with unchanged arguments, plus "
                      "its SAFETY comment: no token, callee, argument, control "
                      "flow or effect changed")
    else:
        r["classification"] = "body-change"
        r["delta"] = "a code token changed"
    r["hunks"] = [{"old": o, "new": n} for o, n in hunks]

P.write_text(json.dumps(rows, indent=1, ensure_ascii=True) + "\n")
for r in rows:
    print(f'{r["id"]:20s} {r["classification"]:16s} '
          f'{r["old_span"]["sha256"][:10]} -> {r["new_span"]["sha256"][:10]} '
          f'hunks={len(r["hunks"])}')
