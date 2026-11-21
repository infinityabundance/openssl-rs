#!/usr/bin/env python3
"""Summarise valgrind memcheck ctgrind logs into file:line sites."""
import re, subprocess, sys, collections

BASE = int(sys.argv[1], 16)
LOG = sys.argv[2]
LIB = "/work/artifacts/phase2/install/lib/libcrypto.so.3"

kind_re = re.compile(r"^==\d+== (Conditional jump or move depends on uninitialised value\(s\)|Use of uninitialised value of size \d+|Syscall param .* uninitialised)")
at_re = re.compile(r"^==\d+==\s+(?:at|by) 0x([0-9a-fA-F]+): (.+?)(?: \((.*)\))?$")

blocks = []
cur = None
for line in open(LOG, errors="replace"):
    m = kind_re.match(line)
    if m:
        cur = {"kind": m.group(1), "frames": []}
        blocks.append(cur)
        continue
    m = at_re.match(line)
    if m and cur is not None:
        addr, func, where = m.groups()
        cur["frames"].append((int(addr, 16), func.strip(), (where or "").strip()))

def line_for(addr):
    off = addr - BASE
    if off < 0:
        return None, None
    out = subprocess.run(["addr2line", "-e", LIB, "-f", "-C", "-i", "0x%x" % off],
                         capture_output=True, text=True).stdout.splitlines()
    # pairs of (func, file:line)
    pairs = []
    for i in range(0, len(out) - 1, 2):
        pairs.append((out[i], out[i + 1]))
    return off, pairs

agg = collections.Counter()
rows = []
for b in blocks:
    if not b["frames"]:
        continue
    addr, func, where = b["frames"][0]
    off, pairs = line_for(addr)
    if pairs:
        fn, fl = pairs[0]
        if fl in ("??:0", "??:?"):
            fn, fl = func, "?"
    else:
        fn, fl = func, "?"
    stack = " <- ".join(f[1] for f in b["frames"][:4])
    key = (b["kind"], fl, fn)
    agg[key] += 1
    rows.append((b["kind"], fl, fn, stack))

print("total contexts:", len(blocks))
for (kind, fl, fn), n in agg.most_common():
    print(f"{n:4d}  {kind[:34]:34s} {fl}  {fn}")
print("\n-- first 12 distinct stacks --")
seen = set()
for kind, fl, fn, stack in rows:
    k = (kind, fl, stack)
    if k in seen:
        continue
    seen.add(k)
    print(f"[{kind[:30]}] {fl}\n    {stack}")
    if len(seen) >= 12:
        break
