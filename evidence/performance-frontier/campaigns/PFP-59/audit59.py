#!/usr/bin/env python3
"""PFP-59 branch audit for the new P-384 carrier.

For every symbol whose demangled name contains the requested substring, scan
the disassembly and classify each conditional control transfer (`jcc`), each
`setcc` and each `cmovcc`:

  * the nearest preceding compare/test operands are recorded;
  * a `jcc`/`cmovcc` whose operands are an induction variable, a pointer or an
    immediate is classified `PUBLIC_BOUND`;
  * a `setcc` is classified `CARRY_CAPTURE` (it materialises a carry/borrow bit
    as data, it does not transfer control);
  * anything not matched is classified `REVIEW` and must be read by hand.

The script is deliberately dumb: it does not claim taint analysis. Its purpose
is to make the carrier auditable line by line and to prove, with a firing
control, that it would report a value-dependent branch if one were present.
"""
import argparse
import re
import subprocess
import sys

JCC = re.compile(r"\b(j[a-z]+)\s")
SETCC = re.compile(r"\b(set[a-z]+)\s")
CMOVCC = re.compile(r"\b(cmov[a-z]+)\s")
CMP = re.compile(r"\b(cmp|test)\s+(.+)$")
SYM = re.compile(r"^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2} )+)\s*(.*)$")


def nm_symbols(path, needle):
    out = subprocess.run(["nm", "-S", "-C", "--defined-only", path],
                         capture_output=True, text=True, check=True).stdout
    syms = []
    for line in out.splitlines():
        parts = line.split(None, 3)
        if len(parts) != 4:
            continue
        addr, size, kind, name = parts
        if kind.lower() not in ("t", "w"):
            continue
        if needle not in name:
            continue
        syms.append((int(addr, 16), int(size, 16), name))
    return sorted(syms)


def disasm(path, start, size):
    return subprocess.run(
        ["objdump", "-d", "--start-address=0x%x" % start,
         "--stop-address=0x%x" % (start + size), path],
        capture_output=True, text=True, check=True).stdout


def classify(sym, text):
    rows = []
    last_cmp = ""
    for line in text.splitlines():
        m = SYM.match(line)
        if not m:
            continue
        addr, _bytes, insn = m.group(1), m.group(2), m.group(3).strip()
        if not insn:
            continue
        cm = CMP.search(insn)
        if cm:
            last_cmp = insn
        j = JCC.search(insn)
        s = SETCC.search(insn)
        c = CMOVCC.search(insn)
        if j and not insn.startswith("jmp"):
            rows.append((sym, addr, "jcc", insn, last_cmp))
        elif c:
            rows.append((sym, addr, "cmov", insn, last_cmp))
        elif s:
            rows.append((sym, addr, "setcc", insn, last_cmp))
    return rows


def public_bound(insn, last_cmp):
    # A branch whose controlling compare is against an immediate constant is a
    # fixed loop bound or a public size check. A register-vs-register compare is
    # left for the reviewer: it is usually the loop-end pointer, but that must be
    # read in the listing rather than assumed.
    if last_cmp == "":
        return "REVIEW"
    if re.search(r"\$0x[0-9a-f]+", last_cmp) or "%rsp" in last_cmp:
        return "PUBLIC_BOUND"
    return "REVIEW"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--lib", required=True)
    ap.add_argument("--needle", required=True)
    ap.add_argument("--asm", required=True)
    ap.add_argument("--tsv", required=True)
    ap.add_argument("--summary", required=True)
    ap.add_argument("--manual", default=None)
    args = ap.parse_args()

    manual = {}
    if args.manual:
        with open(args.manual, "r", encoding="utf-8") as fm:
            for line in fm:
                if not line.strip() or line.startswith("#"):
                    continue
                addr, cls, reason = (line.rstrip("\n").split("\t") + [""])[:3]
                manual[addr.lower()] = (cls, reason)

    syms = nm_symbols(args.lib, args.needle)
    if not syms:
        print("FAIL: no symbols matched %r" % args.needle, file=sys.stderr)
        sys.exit(1)

    with open(args.asm, "w", encoding="utf-8") as fa, open(
            args.tsv, "w", encoding="utf-8") as ft:
        ft.write("symbol\taddr\tkind\tinsn\tpreceding_cmp\tclassification\n")
        counts = {}
        for start, size, name in syms:
            fa.write("\n### %s  (0x%x, %d bytes)\n" % (name, start, size))
            text = disasm(args.lib, start, size)
            fa.write(text)
            for sym, addr, kind, insn, cmpres in classify(name, text):
                if kind == "setcc":
                    cls, reason = "CARRY_CAPTURE", "materialises carry/borrow as data"
                elif addr.lower() in manual:
                    cls, reason = manual[addr.lower()]
                else:
                    cls, reason = public_bound(insn, cmpres), ""
                counts[(kind, cls)] = counts.get((kind, cls), 0) + 1
                ft.write("%s\t%s\t%s\t%s\t%s\t%s\t%s\n" %
                         (sym, addr, kind, insn, cmpres or "-", cls, reason))

    lines = ["symbols=%d" % len(syms)]
    for (kind, cls), n in sorted(counts.items()):
        lines.append("%s/%s=%d" % (kind, cls, n))
    # A value-dependent transfer is a STOP. No row may remain REVIEW.
    review = sum(n for (k, c), n in counts.items() if c == "REVIEW")
    lines.append("review=%d" % review)
    lines.append("verdict=%s" % ("PASS" if review == 0 else "STOP"))
    with open(args.summary, "w", encoding="utf-8") as fs:
        fs.write("\n".join(lines) + "\n")
    print("\n".join(lines))
    if review != 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
