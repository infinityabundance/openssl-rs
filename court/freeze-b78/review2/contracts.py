#!/usr/bin/env python3
"""Extract the doc contract immediately preceding each of the 21 definitions.

Prints a compact JSON: item -> {file, def_line, safety_doc, notes_doc, has_allow_missing}.
"""

import json
import re
from pathlib import Path

ROOT = Path(".").resolve()
closure = json.load(open(ROOT / "evidence/closure-ssh-b78c.json"))
targets = [o for o in closure["obligations"] if o["mechanism"] in ("C_ABI_CONTRACT", "BIO", "SSL_SESSION")]

out = {}
for o in targets:
    p = ROOT / o["file"]
    lines = p.read_text(encoding="utf-8", errors="replace").split("\n")
    # find the definition line by name in the file (first matching fn)
    idx = None
    for i, ln in enumerate(lines):
        if re.search(r"\bfn\s+" + re.escape(o["item"]) + r"\b", ln):
            idx = i
            break
    safety, notes, allow = [], [], False
    if idx is not None:
        j = idx - 1
        # walk back over attributes, then the contiguous /// doc block
        while j >= 0 and lines[j].lstrip().startswith("#["):
            if "missing_safety_doc" in lines[j]:
                allow = True
            j -= 1
        doc = []
        while j >= 0 and lines[j].lstrip().startswith("///"):
            doc.insert(0, lines[j])
            j -= 1
        text = "\n".join(doc)
        # split on '# Safety' / '# Notes'
        m = re.search(r"#\s*Safety\b(.*?)(?=\n\s*///\s*#\s|\Z)", text, re.S)
        if m:
            safety = re.sub(r"\n\s*///\s*", " ", m.group(1)).strip()
        m2 = re.search(r"#\s*Notes\b(.*?)\Z", text, re.S)
        if m2:
            notes = re.sub(r"\n\s*///\s*", " ", m2.group(1)).strip()
    out[o["id"]] = {
        "item": o["item"],
        "file": o["file"],
        "def_line": (idx + 1) if idx is not None else None,
        "safety_doc": safety,
        "notes_doc": notes,
        "allow_missing_safety_doc": allow,
    }
print(json.dumps(out, indent=1))
