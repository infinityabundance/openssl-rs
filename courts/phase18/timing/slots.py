#!/usr/bin/env python3
"""Annotate call/jmp sites in a function with GOT/data-slot symbols."""
import re, sys, collections

# slot -> symbol
slot = {}
rel_re = re.compile(r"^([0-9a-f]{16})\s+[0-9a-f]+\s+(R_X86_64_(?:RELATIVE|64|GLOB_DAT|JUMP_SLOT))\s+([0-9a-f]+)?\s*(.*)$")
for line in open("lc.reloc"):
    m = rel_re.match(line)
    if not m:
        continue
    off, typ, val, rest = m.groups()
    rest = rest.strip()
    nm = rest.split("+")[0].split("@@")[0].split("@")[0] if rest else None
    slot.setdefault(int(off, 16), nm or (("DATA+0x" + val) if val else typ))

# addr -> function name
sym_re = re.compile(r"^\s*\d+:\s+([0-9a-f]+)\s+(\d+)\s+FUNC\s+\S+\s+\S+\s+(\S+)\s+(.+)$")
an = {}
for line in open("lc.syms"):
    m = sym_re.match(line)
    if m:
        a, sz, ndx, name = m.groups()
        if ndx != "UND":
            an.setdefault(int(a, 16), name.strip().split("@@")[0].split("@")[0])

def show(lo, hi=None, func=None):
    print(f"### {func or lo}")
    hdr = re.compile(r"^([0-9a-f]{16}) <(.+)>:$")
    ins = re.compile(r"^  ([0-9a-f]+):\t(.*)$")
    incall = False
    for line in open("lc.dis", errors="replace"):
        line = line.rstrip("\n")
        h = hdr.match(line)
        if h:
            a = int(h.group(1), 16)
            incall = (func is not None and h.group(2) == func) or (func is None and lo <= a < hi)
            if incall:
                print(f"  -- {h.group(2)} @ {h.group(1)}")
            continue
        if not incall:
            continue
        m = ins.match(line)
        if not m:
            continue
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        a = int(parts[0].strip().rstrip(":"), 16)
        if func is None and not (lo <= a < hi):
            continue
        txt = "\t".join(parts[2:]).strip()
        if txt.split()[0] in ("call", "jmp"):
            cm = re.search(r"#\s*([0-9a-f]+)", txt)
            extra = ""
            if cm:
                s = int(cm.group(1), 16)
                extra = f"   SLOT {cm.group(1)} -> {slot.get(s,'?')}"
            print(f"    {parts[0].strip()}  {txt}{extra}")

if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "func":
        show(None, None, sys.argv[2])
    else:
        show(int(sys.argv[2], 16), int(sys.argv[3], 16))
