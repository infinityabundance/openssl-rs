#!/usr/bin/env python3
"""Verify the Blocker-1 premise from committed evidence.

For each of the seven `copyctx` rows: is its recorded coordinate the definition
line of `copyctx` at the inventory head the carry-forward chain names, and does
that definition's normalised text hash to the boundary's declared span hash?
"""
import hashlib
import json
import subprocess
import sys

REPO = sys.argv[1] if len(sys.argv) > 1 else "."
NORM = "split on universal newlines, rstrip each line, join '\\n', sha256 UTF-8"


def blob(commit, path):
    return subprocess.check_output(
        ["git", "-C", REPO, "show", f"{commit}:{path}"], text=True)


def span_at(commit, path, want_line):
    """Definition span whose body-brace encloses `want_line`, plus its hash."""
    text = blob(commit, path)
    lines = text.splitlines()
    # find a line that declares `fn copyctx(` <- deliberately narrow: this is a
    # probe for one operation, not the resolver
    starts = [i for i, ln in enumerate(lines) if "fn copyctx(" in ln]
    for s in starts:
        depth = 0
        end = None
        for i in range(s, len(lines)):
            depth += lines[i].count("{") - lines[i].count("}")
            if depth == 0 and i >= s and "{" in "".join(lines[s:i + 1]):
                end = i
                break
        if end is None:
            continue
        if s + 1 <= want_line <= end + 1:
            body = "\n".join(x.rstrip() for x in lines[s:end + 1])
            return {"def_line": s + 1, "start": s + 1, "end": end + 1,
                    "sha256": hashlib.sha256(body.encode()).hexdigest()}
    return None


def main():
    sites = json.load(open(
        "forensics/memory-safety/campaign/safe-c33/atlas-refresh/"
        "openssh-v1i-sites.json"))
    rows = [b for b in sites["boundaries"] if "copyctx" in (b.get("operation") or "")]
    chain_heads = {
        "evidence/closure-ssh-b76c.json": "0238c6e4adbc7ed85a42be68b6fb965e139bd93e",
        "evidence/closure-ssh-b77.json": "ada7df257e157964f3baade5ec40b66e9a9cbf35",
    }
    for b in rows:
        print(f"{b['id']} {b['operation']} {b['file']} "
              f"recorded_line={b.get('inventory_line')} -> {b['line']} "
              f"span={b['span_start_line']}-{b['span_end_line']}")
        for path, head in chain_heads.items():
            got = span_at(head, b["file"], b.get("inventory_line") or 0)
            if got is None:
                print(f"   {path.split('/')[-1]:26s} {head[:10]}: "
                      f"line {b.get('inventory_line')} names no copyctx body")
                continue
            same = got["sha256"] == b["span_sha256"]
            print(f"   {path.split('/')[-1]:26s} {head[:10]}: "
                  f"def {got['def_line']} {got['start']}-{got['end']} "
                  f"sha={got['sha256'][:16]} match={same}")


if __name__ == "__main__":
    main()
