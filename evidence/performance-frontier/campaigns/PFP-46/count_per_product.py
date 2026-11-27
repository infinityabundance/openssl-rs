#!/usr/bin/env python3
"""count_per_product.py — PFP-46 step 1.

Reproduce the PFP-41 static instruction count for the SAME CIOS ladder kernel,
per build variant. No timing: every figure is an objdump instruction count.

For each build (portable baseline x86-64, and `-C target-feature=+bmi2`):

  * locate `mont_mul_ladder_into`, read its dispatch jump table (entries are
    signed 4-byte offsets from the table base, indexed by n-4 for n in [4,64]);
  * find each inlined width arm, take its region [arm, next arm start);
  * report total instructions in the arm and instructions per limb product
    (2*N*N products: N product rows + N reduction rows of N products each),
    which is the PFP-41 full-arm figure (10.33 at n=32, 9.14 at n=16);
  * for the dominant product-accumulation loop, report the tight-loop body
    size and the multiplication step, i.e. instructions per limb product in
    the loop that PFP-41's "8.0 arithmetic" refers to.

Usage: count_per_product.py <dso> <tag>
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
    raise SystemExit("jump table not found")


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


def extra_starts(ins, start, size):
    """The >64 dispatch: `cmp $0x80; jne generic`; the fall-through is n=128."""
    extra = set()
    for i, (addr, op, args) in enumerate(ins):
        if op == "cmp" and ("$0x80" in args or "$0x80," in args) and i + 1 < len(ins):
            nxt = ins[i + 1]
            if nxt[1] in ("jne", "je", "jne", "jb", "jae"):
                t = re.match(r"^([0-9a-f]+)", nxt[2].strip())
                if t:
                    extra.add(int(t.group(1), 16))
            if nxt[1].startswith("j") and nxt[0] == addr + 4:
                extra.add(nxt[0])
    return extra


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


def main():
    dso, tag = sys.argv[1], sys.argv[2]
    sym = "openssl_rs::bn::arith::mont_mul_ladder_into"
    start, size = symbol(dso, sym)
    ins = load_insns(dso, start, size)
    base = table_base(ins)
    vals = read_table(dso, base, 61)  # n-4 for n in 4..64
    arms = {n: base + vals[n - 4] for n in range(4, 65) if n - 4 < len(vals)}

    starts = set(arms.values()) | {start + size}
    starts = sorted(starts)

    def region(a):
        i = starts.index(a)
        return a, starts[i + 1]

    print("tag=%s symbol=0x%06x..0x%06x table=0x%06x" % (tag, start, start + size, base))
    for n in (4, 16, 32):
        a = arms.get(n)
        if a is None:
            print("n=%d MISSING" % n)
            continue
        lo, hi = region(a)
        body = [x for x in ins if lo <= x[0] < hi]
        products = 2 * n * n
        loops = sorted(backedge_loops(ins, lo, hi), key=lambda z: z[2])
        line = ("n=%-3d arm=0x%06x region_insns=%4d products=%5d "
                "full_per_product=%.2f" % (n, a, len(body), products,
                                           len(body) / products))
        print(line)
        for (t, e, b) in loops:
            body_loops = [x for x in ins if t <= x[0] <= e]
            mul = sum(1 for x in body_loops if x[1] in ("mulq", "mulx", "imul"))
            # products per iteration: the loop `add $k,%reg` that steps the index
            step = None
            for x in body_loops:
                m = re.match(r"^\$0x([0-9a-f]+),", x[2])
                if x[1] == "add" and m:
                    v = int(m.group(1), 16)
                    if v in (1, 2, 4):
                        step = v
            if step:
                prods = step if n <= 32 else step
                # mul count == limb products per iteration
                print("        loop 0x%06x..0x%06x body=%3d mul=%d step=%d "
                      "loop_per_product=%.2f" %
                      (t, e, len(body_loops), mul, step, len(body_loops) / mul if mul else 0.0))
            else:
                print("        loop 0x%06x..0x%06x body=%3d mul=%d" %
                      (t, e, len(body_loops), mul))


if __name__ == "__main__":
    main()
