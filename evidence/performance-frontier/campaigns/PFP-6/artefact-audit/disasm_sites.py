#!/usr/bin/env python3
"""disasm_sites.py — extract every conditional transfer, setcc and cmovcc from
an objdump -d listing of one symbol extent.

Columns: symbol, addr, insn, operands, prev2, prev1, target, kind
  kind = jcc | setcc | cmovcc
  prev1/prev2 are the preceding two instructions (the flag source context).
"""
import re, sys

INSN = re.compile(r"^\s*([0-9a-f]+):\t(.*)$")
JCC = {"jmp"}
SET = re.compile(r"^set[a-z]+$")
CMOV = re.compile(r"^cmov[a-z]+$")


def split(rest):
    rest = rest.split("#")[0].strip()
    parts = rest.split(None, 1)
    if not parts:
        return "", ""
    return parts[0], (parts[1] if len(parts) > 1 else "")


def main(path, symbol):
    insns = []
    for line in open(path, errors="replace"):
        m = INSN.match(line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        op, args = split(m.group(2))
        insns.append((addr, op, args))
    rows = []
    for i, (addr, op, args) in enumerate(insns):
        kind = None
        if op.startswith("j") and op not in JCC:
            kind = "jcc"
        elif SET.match(op):
            kind = "setcc"
        elif CMOV.match(op):
            kind = "cmovcc"
        if kind is None:
            continue
        prev1 = "%s %s" % (insns[i - 1][1], insns[i - 1][2]) if i >= 1 else ""
        prev2 = "%s %s" % (insns[i - 2][1], insns[i - 2][2]) if i >= 2 else ""
        print("\t".join([symbol, "%x" % addr, op, args, prev2.strip(), prev1.strip(), kind]))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
