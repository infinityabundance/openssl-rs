#!/usr/bin/env python3
"""count_pfp48.py — PFP-48 static instruction count.

Same instrument as PFP-41/PFP-46: locate `mont_mul_ladder_into`, read its
dispatch jump table (n-4 for n in 4..64), and report for n = 4, 16, 32 the arm
region size and instructions per limb product (2*N*N products), plus every
tight back-edge loop body and its instructions-per-product.

This variant additionally reports:
  * the whole-symbol opcode census (mulq/mulx/adcx/adox);
  * the n=128 branch (the `cmp $0x80` fall-through), because modexp-8192 uses a
    128-limb modulus and the jump table stops at n=64.

Usage: count_pfp48.py <dso> <tag>
"""
import re
import struct
import subprocess
import sys

LINE = re.compile(r"^\s*([0-9a-f]+):\t(.*)$")
NM_LINE = re.compile(r"^([0-9a-f]+)\s+([0-9a-f]+)\s+\w\s+(.*)$")


def run(*argv):
    return subprocess.check_output(argv, text=True)


def symbol(dso, sym):
    for line in run("nm", "-S", "--defined-only", "-C", dso).splitlines():
        m = NM_LINE.match(line)
        if m and m.group(3).strip() == sym:
            return int(m.group(1), 16), int(m.group(2), 16)
    raise SystemExit("symbol not found: " + sym)


def load_insns(dso, start, size):
    out = run("objdump", "-d", "--no-show-raw-insn",
              "--start-address=0x%x" % start,
              "--stop-address=0x%x" % (start + size), dso)
    ins = []
    for line in out.splitlines():
        m = LINE.match(line)
        if not m:
            continue
        rest = m.group(2).strip()
        p = rest.split(None, 1)
        ins.append((int(m.group(1), 16), p[0], p[1].strip() if len(p) > 1 else ""))
    return ins


def table_base(ins):
    for i, (addr, op, args) in enumerate(ins):
        if op == "lea" and i + 3 < len(ins):
            if ins[i + 1][1] == "movslq" and ins[i + 2][1] == "add" \
                    and ins[i + 3][1] == "jmp":
                m = re.search(r"#\s*([0-9a-f]+)", args)
                if m:
                    return int(m.group(1), 16)
    return None


def read_table(dso, base, count):
    out = run("objdump", "-s", "--start-address=0x%x" % base,
              "--stop-address=0x%x" % (base + count * 4), dso)
    vals = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 5 and re.fullmatch(r"[0-9a-f]{6,}", parts[0]):
            for h in parts[1:5]:
                if re.fullmatch(r"[0-9a-f]{8}", h):
                    vals.append(struct.unpack("<i", bytes.fromhex(h))[0])
    return vals[:count]


def backedge_loops(ins, lo, hi):
    loops = []
    for idx, (addr, op, args) in enumerate(ins):
        if not lo <= addr < hi or not (op.startswith("j") and op != "jmp"):
            continue
        m = re.match(r"^([0-9a-f]+)", args.strip())
        if not m:
            continue
        t = int(m.group(1), 16)
        if lo <= t <= addr:
            body = [x for x in ins if t <= x[0] <= addr]
            loops.append((t, addr, len(body)))
    return loops


def census(ins):
    c = {}
    for _, op, _ in ins:
        c[op] = c.get(op, 0) + 1
    return c


def report_loop(body_loops, tag=None):
    mul = sum(1 for x in body_loops if x[1] in ("mulq", "mulx", "imul"))
    opc = census(body_loops)
    return mul, opc


def main():
    dso, tag = sys.argv[1], sys.argv[2]
    sym = "openssl_rs::bn::arith::mont_mul_ladder_into"
    start, size = symbol(dso, sym)
    ins = load_insns(dso, start, size)
    opc = census(ins)

    print("tag=%s symbol=0x%06x..0x%06x insns=%d" % (tag, start, start + size, len(ins)))
    print("  census mulq=%d mulx=%d adcx=%d adox=%d imul=%d" % (
        opc.get("mulq", 0), opc.get("mulx", 0), opc.get("adcx", 0),
        opc.get("adox", 0), opc.get("imul", 0)))

    base = table_base(ins)
    if base is not None:
        vals = read_table(dso, base, 61)  # n-4 for n in 4..64
        arms = {n: base + vals[n - 4] for n in range(4, 65) if n - 4 < len(vals)}
        starts = sorted(set(arms.values()) | {start + size})

        def region(a):
            i = starts.index(a)
            return a, starts[i + 1]

        print("  jump_table=0x%06x" % base)
        for n in (4, 16, 32):
            a = arms.get(n)
            if a is None:
                print("  n=%d MISSING" % n)
                continue
            lo, hi = region(a)
            body = [x for x in ins if lo <= x[0] < hi]
            products = 2 * n * n
            print("  n=%-3d arm=0x%06x region_insns=%4d products=%5d full_per_product=%.3f"
                  % (n, a, len(body), products, len(body) / products))
            loops = sorted(backedge_loops(ins, lo, hi), key=lambda z: z[2])
            for (t, e, _b) in loops:
                bl = [x for x in ins if t <= x[0] <= e]
                mul, lopc = report_loop(bl)
                if mul:
                    print("        loop 0x%06x..0x%06x body=%3d mul=%d "
                          "loop_per_product=%.2f" %
                          (t, e, len(bl), mul, len(bl) / mul))
    else:
        print("  jump_table=none")

    # n=128: the >64 dispatch handler is the target of the `ja` that guards the
    # `cmp $0x3c` table; inside it, `cmp $0x80; jne <generic>` selects n=128 as
    # the fall-through, so the arm window is [fall-through, jne-target).
    n128 = None
    end = None
    # 1) find the dispatch guard `cmp $0x3c` and, within a few instructions (LLVM
    #    interleaves spill stores), the `ja T` that selects the >64 handler.
    guard_target = None
    for i, (addr, op, args) in enumerate(ins):
        if op == "cmp" and "$0x3c" in args:
            for k in range(i + 1, min(i + 6, len(ins))):
                if ins[k][1] == "ja":
                    m = re.match(r"^([0-9a-f]+)", ins[k][2].strip())
                    if m:
                        guard_target = int(m.group(1), 16)
                    break
            break
    # 2) in the >64 handler, `cmp $0x80; jne <generic>` selects n=128 as the
    #    fall-through, so the arm window is [fall-through, jne-target).
    if guard_target is not None:
        gi = next((k for k, x in enumerate(ins) if x[0] == guard_target), None)
        if gi is not None:
            for i in range(gi, len(ins) - 1):
                op, args = ins[i][1], ins[i][2]
                if op == "cmp" and "$0x80" in args and ins[i + 1][1].startswith("j"):
                    jn = ins[i + 1]
                    m = re.match(r"^([0-9a-f]+)", jn[2].strip())
                    if m and i + 2 < len(ins):
                        n128 = ins[i + 2][0]
                        end = int(m.group(1), 16)
                    break
    if n128 is None or end is None or end <= n128:
        print("  n=128 window not identified")
    else:
        body = [x for x in ins if n128 <= x[0] < end]
        products = 2 * 128 * 128
        print("  n=128 body=0x%06x..0x%06x region_insns=%d products=%d full_per_product=%.3f"
              % (n128, end, len(body), products, len(body) / products))
        for (t, e, _b) in sorted(backedge_loops(ins, n128, end), key=lambda z: z[2]):
            bl = [x for x in ins if t <= x[0] <= e]
            mul, _ = report_loop(bl)
            if mul:
                print("        128 loop 0x%06x..0x%06x body=%3d mul=%d "
                      "loop_per_product=%.2f" % (t, e, len(bl), mul, len(bl) / mul))


if __name__ == "__main__":
    main()
