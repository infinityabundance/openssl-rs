#!/usr/bin/env python3
"""Classify valgrind ctgrind sites by DSO offset, function, and instruction."""
import re, sys, bisect, collections

BASE = int(sys.argv[1], 16)
LOGS = sys.argv[2:]

# function ranges
sym_re = re.compile(r"^\s*\d+:\s+([0-9a-f]+)\s+(\d+)\s+FUNC\s+\S+\s+\S+\s+(\S+)\s+(.+)$")
F = []
for line in open("lc.syms"):
    m = sym_re.match(line)
    if not m:
        continue
    a, sz, ndx, n = m.groups()
    if ndx == "UND" or not int(sz):
        continue
    F.append((int(a, 16), int(sz), n.strip().split("@@")[0].split("@")[0]))
F.sort(); st = [f[0] for f in F]
def fname(off):
    i = bisect.bisect_right(st, off) - 1
    if i >= 0 and F[i][0] <= off < F[i][0] + F[i][1]:
        return F[i][2]
    return "?"

# instruction starts
ins = {}
hdr = re.compile(r"^  ([0-9a-f]+):\t(.*)$")
for line in open("lc.dis", errors="replace"):
    m = hdr.match(line)
    if not m:
        continue
    parts = line.rstrip("\n").split("\t")
    if len(parts) < 3:
        continue
    a = int(parts[0].strip().rstrip(":"), 16)
    txt = "\t".join(parts[2:]).strip()
    ins[a] = txt
starts = sorted(ins)

def instr_at(off):
    i = bisect.bisect_right(starts, off) - 1
    if i >= 0 and starts[i] == off:
        return ins[off]
    if i >= 0 and off - starts[i] <= 8:
        return ins[starts[i]] + "  (offset +%d)" % (off - starts[i])
    return "?"

kind_re = re.compile(r"^==\d+== (Conditional jump or move depends on uninitialised value\(s\)|Use of uninitialised value of size \d+)")
at_re = re.compile(r"^==\d+==\s+at 0x([0-9a-fA-F]+):")
for log in LOGS:
    blocks = []
    cur = None
    for line in open(log, errors="replace"):
        m = kind_re.match(line)
        if m:
            cur = {"kind": m.group(1), "addr": None}
            blocks.append(cur)
            continue
        m = at_re.match(line)
        if m and cur is not None and cur["addr"] is None:
            cur["addr"] = int(m.group(1), 16)
    agg = collections.Counter()
    detail = []
    for b in blocks:
        if b["addr"] is None:
            continue
        off = b["addr"] - BASE
        fn = fname(off)
        it = instr_at(off)
        mn = it.split()[0] if it and it != "?" else "?"
        kind = "branch" if b["kind"].startswith("Conditional") else "address"
        agg[(kind, fn, mn)] += 1
        detail.append((kind, fn, mn, off, it))
    print("### %s: %d contexts" % (log, len(blocks)))
    for (kind, fn, mn), n in agg.most_common():
        print("  %4d  %-8s %-6s %s" % (n, kind, mn, fn))
    print("  -- distinct sites --")
    seen = set()
    for kind, fn, mn, off, it in detail:
        k = (kind, off)
        if k in seen:
            continue
        seen.add(k)
        print("  %-8s %#08x %-6s %-46s %s" % (kind, off, mn, fn, it[:70]))
