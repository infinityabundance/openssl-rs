#!/usr/bin/env python3
"""analyse_loops.py — PFP-41.

Locate the inlined CIOS specialisation arms inside the single symbol
`mont_mul_ladder_into` and, for the additive Montgomery kernels, report the
loop backedges (tight-loop candidates) with their body sizes.

The dispatch is `match m.len() { 4,6,9,16,32,48,64 => fixed, 128 => fixed,
_ => generic }`, compiled as a jump table indexed by (n-4) for n in [4,64],
a separate `cmp $0x80` for 128, and the generic slice kernel for the rest.

Inputs are produced by objdump in the court. Nothing here is a timing
measurement; every figure is a static instruction count.
"""
import re
import struct
import subprocess
import sys

SYM_START = 0x2D3B80
SYM_STOP = 0x2D3B80 + 0x2431
JT_BASE = 0x66F5E0
JT_ENTRIES = 61  # n-4 for n in [4,64]

LINE = re.compile(r"^\s*([0-9a-f]+):\t(.*)$")


def split_insn(rest):
    rest = rest.split("#")[0].strip()
    p = rest.split(None, 1)
    return (p[0], p[1].strip() if len(p) > 1 else "")


def load_insns(dso):
    out = subprocess.check_output(
        ["objdump", "-d", "--no-show-raw-insn",
         "--start-address=0x%x" % SYM_START, "--stop-address=0x%x" % SYM_STOP,
         dso], text=True)
    ins = []
    for line in out.splitlines():
        m = LINE.match(line)
        if not m:
            continue
        op, args = split_insn(m.group(2))
        ins.append((int(m.group(1), 16), op, args))
    return ins


def jump_table(dso):
    out = subprocess.check_output(
        ["objdump", "-s", "--start-address=0x%x" % JT_BASE,
         "--stop-address=0x%x" % (JT_BASE + JT_ENTRIES * 4), dso], text=True)
    vals = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and len(parts[0]) == 6 and re.fullmatch(r"[0-9a-f]{6}", parts[0]):
            for h in parts[1:5]:
                if re.fullmatch(r"[0-9a-f]{8}", h):
                    vals.append(struct.unpack("<i", bytes.fromhex(h))[0])
    vals = vals[:JT_ENTRIES]
    return {n: (JT_BASE + vals[n - 4]) & 0xFFFFFFFFFFFFFFFF
            for n in range(4, 65) if n - 4 < len(vals)}


def branch_target(args):
    m = re.match(r"^([0-9a-f]+)\b", args.strip())
    return int(m.group(1), 16) if m and not args.strip().startswith("*") else None


def main():
    dso = sys.argv[1]
    ins = load_insns(dso)
    jt = jump_table(dso)
    want = {4: None, 6: None, 9: None, 16: None, 32: None, 48: None, 64: None, 128: None}
    for n in want:
        want[n] = jt.get(n)

    # Distinct arm starts (the 128 arm is discovered by its distinct target).
    starts = set(v for v in want.values() if v is not None)
    # add the n=128 and generic starts observed from the cmp $0x80 path
    extra = [0x2D410A, 0x2D424E]
    starts |= set(e for e in extra if SYM_START <= e < SYM_STOP)
    starts.add(SYM_STOP)
    starts = sorted(starts)

    def region(addr):
        for i, s in enumerate(starts):
            if s == addr:
                return addr, starts[i + 1]
        return addr, SYM_STOP

    print("=== jump-table arm targets ===")
    for n in sorted(want):
        if want[n] is not None:
            print("n=%-3d arm=0x%06x" % (n, want[n]))
    print("n=128  arm=0x%06x (cmp $0x80 path)" % 0x2D410A)
    print("generic arm=0x%06x" % 0x2D424E)

    print("\n=== backedges (target <= jump) inside each arm region ===")
    for n in [4, 6, 9, 16, 32, 48, 64, 128]:
        a = want.get(n)
        if a is None:
            continue
        lo, hi = region(a)
        loops = []
        for idx, (addr, op, args) in enumerate(ins):
            if not lo <= addr < hi:
                continue
            if op.startswith("j") and op != "jmp":
                t = branch_target(args)
                if t is not None and lo <= t <= addr:
                    body = [x for x in ins if t <= x[0] <= addr]
                    loops.append((t, addr, len(body)))
            elif op == "jmp":
                t = branch_target(args)
                if t is not None and lo <= t <= addr:
                    body = [x for x in ins if t <= x[0] <= addr]
                    loops.append((t, addr, len(body)))
        n_ins = sum(1 for (addr, _o, _a) in ins if lo <= addr < hi)
        print("\nn=%-3d region 0x%06x..0x%06x  instructions=%d  backedges=%d"
              % (n, lo, hi, n_ins, len(loops)))
        for (t, e, b) in sorted(loops, key=lambda z: z[2]):
            print("    loop 0x%06x..0x%06x  body=%d" % (t, e, b))


if __name__ == "__main__":
    main()
