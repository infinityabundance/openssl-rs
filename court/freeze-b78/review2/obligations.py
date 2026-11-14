#!/usr/bin/env python3
"""Per-obligation caller analysis for the 21 obligations of the three weakest
mechanisms, plus closure-wide safe-pub reachability.

Reads evidence/closure-ssh-b78c.json, joins each obligation to the current
source by (file, enclosing item, line), and reports, from a lexical scan:

  * every textual occurrence of the item name outside its definition,
  * the enclosing function of each occurrence (and whether that function is
    `safe` or `unsafe`),
  * whether any *safe* function in the crate reaches the item (directly or
    transitively through the name-based call graph),
  * whether any *externally reachable safe pub* function reaches it.

Run from the repository root:
  python3 court/freeze-b78/review2/obligations.py > court/freeze-b78/review2/obligations.json
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import surface  # noqa: E402

ROOT = Path(".").resolve()


def main():
    records, files, by_name = surface.build_records()
    surface.analyze_quiet = True  # not used; analyze() is not called for output

    # annotate safe/external/direct_unsafe without printing
    import io
    import contextlib

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        out = surface.analyze(records, files, by_name)

    closure = json.load(open(ROOT / "evidence/closure-ssh-b78c.json"))
    wanted = {"C_ABI_CONTRACT", "BIO", "SSL_SESSION"}
    obligations = [o for o in closure["obligations"] if o["mechanism"] in wanted]

    # build an index from (file, name) to records
    by_file_name = {}
    for r in records:
        by_file_name.setdefault((r["file"], r["name"]), []).append(r)

    # direct callee edges by qualified key
    key = lambda r: r["file"] + "::" + r["name"] + "@" + str(r["line"])
    index = {key(r): r for r in records}

    # forward reachability (multi-source BFS) from safe definitions.  A node is
    # "reached by a safe fn" when some safe fn's body reaches it through the
    # name-based call graph, i.e. the node is called (directly or not) from safe
    # Rust.  One witness per node is retained for the report.
    from collections import deque

    def multi_source(sources):
        seen = {}
        dq = deque()
        for r in sources:
            k = key(r)
            if k not in seen:
                seen[k] = k
                dq.append(r)
        while dq:
            r = dq.popleft()
            w = seen[key(r)]
            for c in r["callees"]:
                if c in index and c not in seen:
                    seen[c] = w
                    dq.append(index[c])
        return seen

    safe_fns = [r for r in records if r["safe"] and r["definition"]]
    ext_safe = [r for r in safe_fns if r["external"] and r["vis"] == "pub"]
    reached_by_safe = multi_source(safe_fns)
    reached_by_ext = multi_source(ext_safe)

    results = []
    for o in obligations:
        name = o["item"]
        file = o["file"]
        defs = by_file_name.get((file, name), [])
        def_sites = [(d["line"], d["vis"], d["unsafe"], d["extern"], d["attrs"]) for d in defs]
        # textual call sites across the tree
        sites = []
        for path in files:
            rel = str(path.relative_to(ROOT))
            raw = path.read_text(encoding="utf-8", errors="replace")
            text = surface.atlas.strip_comments_and_literals(raw)
            for m in re.finditer(r"\b" + re.escape(name) + r"\b", text):
                line = raw.count("\n", 0, m.start()) + 1
                if rel == file and any(abs(line - d[0]) < 3 for d in def_sites):
                    continue  # definition (allow a few lines for the signature)
                # enclosing function = innermost record containing the offset
                enclosing = None
                best = None
                for r in records:
                    if r["file"] != rel or not r["definition"]:
                        continue
                    if r["body_start"] is not None and r["body_start"] < m.start() < r["body_end"]:
                        if best is None or r["body_start"] > best:
                            best = r["body_start"]
                            enclosing = r
                after = text[m.end() : m.end() + 3]
                before = text[max(0, m.start() - 3) : m.start()]
                shape = "mention"
                if after.lstrip().startswith("("):
                    shape = "call"
                elif before.rstrip().endswith(("Some", "&", "=", ",", "(", "")) or after.lstrip().startswith((",", ")", ";")):
                    shape = "address-or-value"
                sites.append(
                    {
                        "file": rel,
                        "line": line,
                        "shape": shape,
                        "enclosing": (enclosing["name"] if enclosing else None),
                        "enclosing_unsafe": (enclosing["unsafe"] if enclosing else None),
                        "enclosing_vis": (enclosing["vis"] if enclosing else None),
                        "enclosing_external": (enclosing["external"] if enclosing else None),
                    }
                )
        # safe reachability
        dkeys = [key(d) for d in defs]
        safe_witness = [reached_by_safe[k] for k in dkeys if k in reached_by_safe]
        ext_witness = [reached_by_ext[k] for k in dkeys if k in reached_by_ext]
        external_reachers = sorted(set(ext_witness))
        safe_nonext_reachers = sorted(set(safe_witness) - set(ext_witness))
        results.append(
            {
                "id": o["id"],
                "mechanism": o["mechanism"],
                "file": file,
                "line": o["line"],
                "item": name,
                "kind": o["kind"],
                "contract": o["contract"],
                "definitions": [
                    {"line": d[0], "vis": d[1], "unsafe": d[2], "extern": d[3], "attrs": d[4]} for d in def_sites
                ],
                "call_sites": sites,
                "call_sites_total": len(sites),
                "reached_by_safe_fn": sorted(set(safe_witness)),
                "reached_by_external_safe_pub": external_reachers,
                "reached_by_safe_non_public": safe_nonext_reachers,
                "unsafe_entry_only": not external_reachers,
            }
        )

    # closure-wide: how many of the 290 are reachable from a safe pub fn
    all_ob = closure["obligations"]
    reachable = 0
    by_mech = {}
    for o in all_ob:
        d = by_file_name.get((o["file"], o["item"]), [])
        ext = [reached_by_ext[key(x)] for x in d if key(x) in reached_by_ext]
        m = by_mech.setdefault(o["mechanism"], {"total": 0, "reached_by_external_safe_pub": 0, "examples": []})
        m["total"] += 1
        if ext:
            m["reached_by_external_safe_pub"] += 1
            reachable += 1
            if len(m["examples"]) < 3:
                m["examples"].append({"obligation": o["id"], "safe_pub_reachers": ext[:3]})

    out = {
        "schema": "openssl-rs/review/obligation-callers/v1",
        "closure": "evidence/closure-ssh-b78c.json",
        "obligations": results,
        "closure_wide": {
            "total": len(all_ob),
            "reached_by_external_safe_pub": reachable,
            "by_mechanism": by_mech,
        },
        "surface_counts": out,
    }
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
