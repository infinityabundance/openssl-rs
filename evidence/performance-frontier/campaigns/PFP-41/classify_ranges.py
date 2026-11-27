#!/usr/bin/env python3
"""classify_ranges.py — PFP-41 static instruction-mix measurement.

For each named address range of `mont_mul_ladder_into` (the inlined CIOS
dispatch), disassemble via objdump, classify every instruction into one
category, and report counts and percentages plus memory-reference and
stack-spill (rsp/rbp-relative) tallies.

A disassembly count is a STATIC property of the emitted code. It is not a
timing measurement and says nothing about stalls, ports or IPC.
"""
import re
import subprocess
import sys
from collections import Counter

LINE = re.compile(r"^\s*([0-9a-f]+):\t(.*)$")
MEM = re.compile(r"\([^)]*\)")
STACK = re.compile(r"[-+]?0x[0-9a-f]+\(%[er](?:sp|bp)\)")

# (start, end-exclusive)
RANGES = {
    # n = 4, fully unrolled straight-line CIOS (no backedge)
    "n4.full":            (0x2D3C1A, 0x2D40E5),
    "n4.core":            (0x2D3C1A, 0x2D401A),   # product+reduce rows + acc stores
    "n4.final_sub_mask":  (0x2D401A, 0x2D40E5),   # masked conditional subtraction
    # n = 16: outer loop over b (16 iterations); the inner product+reduce rows
    # are fully unrolled inside the outer body.
    "n16.prologue":       (0x2D4BD3, 0x2D4E00),
    "n16.outer_body":     (0x2D4E00, 0x2D5287),   # 1 of 16 iterations
    "n16.tail":           (0x2D528C, 0x2D56F0),
    # n = 32: outer loop over b (32 iterations); inner product and reduction
    # rows are rolled and unrolled 2 limbs per iteration.
    "n32.prologue":       (0x2D5A6A, 0x2D5AD1),
    "n32.outer_prefix":   (0x2D5AD1, 0x2D5AE0),
    "n32.product_inner":  (0x2D5AE0, 0x2D5B24),   # 16 iterations of 2 products
    "n32.reduce_setup":   (0x2D5B25, 0x2D5B60),
    "n32.reduce_inner":   (0x2D5B60, 0x2D5BAA),   # 16 entries of 2 products
    "n32.outer_tail":     (0x2D5AA0, 0x2D5AD1),
    "n32.final_sub":      (0x2D5BB0, 0x2D5BEB),   # 16 iterations of 2 limbs
    "n32.mask":           (0x2D5C10, 0x2D5C3E),   # 32 iterations of 1 limb
    "n32.final_tail":     (0x2D5BEC, 0x2D5C44),
    # generic runtime-n CIOS fallback (mont_mul_cios_into inlined)
    "gen.product_inner":  (0x2D4310, 0x2D4352),   # 2 products / iteration
    "gen.reduce_inner":   (0x2D43D0, 0x2D4416),   # 2 products / iteration
}

MULISH = ("mul", "mulq", "mulx", "imul", "imulq")
ADDS = ("add", "addq", "addb", "addl", "sub", "subq", "subb", "sbb", "sbbq")
SHIFTS = ("shl", "shr", "sar", "sal", "rol", "ror")


def split_operands(args):
    """Split AT&T operands on commas at paren depth 0."""
    out, cur, depth = [], "", 0
    for ch in args:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def classify(mnem, args):
    ops = split_operands(args)
    dest = ops[-1] if ops else ""
    mem_ops = [o for o in ops if MEM.search(o)]
    has_mem = bool(mem_ops)
    is_store = bool(dest) and bool(MEM.search(dest))
    is_load = has_mem and not is_store

    if mnem in MULISH:
        return "mul"
    if mnem == "adox":
        return "adox"
    if mnem == "adcx":
        return "adcx"
    if mnem.startswith("adc"):
        return "adc"
    if mnem in ADDS:
        return "add/sub"
    if mnem.startswith("mov"):
        if is_store:
            return "store"
        if is_load:
            return "load"
        return "mov(reg)"
    if mnem in SHIFTS:
        return "shift"
    if mnem.startswith("j"):
        return "branch"
    if mnem.startswith("cmov") or mnem.startswith("set"):
        return "cmov/setcc"
    return "other"


def load_range(dso, lo, hi):
    out = subprocess.check_output(
        ["objdump", "-d", "--no-show-raw-insn",
         "--start-address=0x%x" % lo, "--stop-address=0x%x" % hi, dso], text=True)
    rows = []
    for line in out.splitlines():
        m = LINE.match(line)
        if not m:
            continue
        text = m.group(2).split("#")[0].strip()
        parts = text.split(None, 1)
        mnem = parts[0]
        args = parts[1] if len(parts) > 1 else ""
        rows.append((int(m.group(1), 16), mnem, args, text))
    return rows


ORDER = ["mul", "adc", "adox", "adcx", "add/sub", "mov(reg)", "load", "store",
         "shift", "branch", "cmov/setcc", "other"]


def main():
    dso = sys.argv[1]
    out_listing = []
    summary = []
    for name, (lo, hi) in RANGES.items():
        rows = load_range(dso, lo, hi)
        c = Counter(classify(m, a) for (_x, m, a, _t) in rows)
        n = len(rows)
        stack = sum(1 for (_x, m, a, _t) in rows if STACK.search(a))
        memrefs = sum(1 for (_x, m, a, _t) in rows
                      if any(MEM.search(o) for o in split_operands(a)))
        summary.append((name, lo, hi, n, c, stack, memrefs))
        out_listing.append("\n===== %s  0x%06x..0x%06x  instructions=%d =====\n"
                           % (name, lo, hi, n))
        for (x, m, a, t) in rows:
            out_listing.append("  %06x:\t%s\n" % (x, t))

    print("%-20s %6s %6s %7s %7s  %s" % ("range", "insns", "mem", "rsp/rbp", "spill%", "mix"))
    for (name, lo, hi, n, c, stack, memrefs) in summary:
        mix = " ".join("%s=%d(%.1f%%)" % (k, c[k], 100.0 * c[k] / n)
                       for k in ORDER if c[k])
        print("%-20s %6d %6d %7d %6.1f%%  %s"
              % (name, n, memrefs, stack, 100.0 * stack / n if n else 0, mix))

    with open(sys.argv[2], "w") as f:
        f.write("".join(out_listing))
    print("\nlistings written to %s" % sys.argv[2])


if __name__ == "__main__":
    main()
