#!/usr/bin/env python3
"""Resolve relocations inside data-symbol ranges (method/dispatch tables)."""
import re, sys, bisect

sym_re = re.compile(r"^\s*\d+:\s+([0-9a-f]+)\s+(\d+)\s+(\S+)\s+\S+\s+\S+\s+(\S+)\s+(.+)$")
data_syms = []
addr_name = {}
for line in open("lc.syms"):
    m = sym_re.match(line)
    if not m:
        continue
    a, sz, typ, ndx, name = m.groups()
    name = name.strip().split("@@")[0].split("@")[0]
    if ndx == "UND":
        continue
    addr_name.setdefault(int(a, 16), name)
    if typ == "OBJECT" and int(sz):
        data_syms.append((int(a, 16), int(sz), name))
data_syms.sort()
dstarts = [d[0] for d in data_syms]

rel = []
rel_re = re.compile(r"^([0-9a-f]{16})\s+[0-9a-f]+\s+(R_X86_64_(\S+))\s+([0-9a-f]+)?\s*(.*)$")
for line in open("lc.reloc"):
    m = rel_re.match(line)
    if not m:
        continue
    off, typ, short, val, rest = m.groups()
    rest = rest.strip()
    nm = None
    if rest:
        nm = rest.split("+")[0].split("@@")[0].split("@")[0]
        addend = rest
    elif val:
        nm = addr_name.get(int(val, 16))
        addend = val
    else:
        continue
    rel.append((int(off, 16), short, nm, addend, rest))
rel.sort()

def dump(lo, hi, label):
    print(f"== {label} [{lo:#x},{hi:#x}) ==")
    for off, short, nm, addend, rest in rel:
        if lo <= off < hi:
            print(f"  +{off-lo:#05x}  {short:16s} {nm or '?'}  {rest}")

for arg in sys.argv[1:]:
    hits = [d for d in data_syms if d[2] == arg]
    if not hits:
        # maybe given as hex address
        a = int(arg, 16)
        i = bisect.bisect_right(dstarts, a) - 1
        if i >= 0:
            hits = [data_syms[i]]
    for a, sz, name in hits:
        dump(a, a + sz, f"{name} @ {a:#x} size {sz:#x}")
