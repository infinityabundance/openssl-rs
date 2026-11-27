#!/usr/bin/env python3
"""reconcile.py — PFP-41 executed-instruction arithmetic.

Static code size is not executed count for a rolled loop, so this sums each
region times its trip count. Trip counts are read from the loop-control
immediates in the disassembly (recorded in raw/loop-bodies.dis):
  n=16 outer loop : cmp $0x80,%rdx ; add $0x8,%rdx  -> 16 iterations
  n=32 outer loop : cmp $0x100,%r15; add $0x8,%r15  -> 32 iterations
  n=32 product    : cmp $0x21,%rsi ; add $0x2,%rsi  -> 16 iterations (2 limbs)
  n=32 reduction  : cmp $0x20,%r9  ; add $0x2,%r9   -> 16 entries (last partial)
  n=32 final sub  : cmp $0x20,%rdx ; add $0x2,%rdx  -> 16 iterations (2 limbs)
  n=32 mask       : cmp $0x20,%rdi ; inc %rdi       -> 32 iterations
  generic n=16    : inner 2-limb loops -> n/2 = 8 iterations, outer n = 16
"""
import re
import subprocess
import sys

LINE = re.compile(r"^\s*([0-9a-f]+):\t(.*)$")


def count(dso, lo, hi):
    out = subprocess.check_output(
        ["objdump", "-d", "--no-show-raw-insn",
         "--start-address=0x%x" % lo, "--stop-address=0x%x" % hi, dso], text=True)
    return sum(1 for line in out.splitlines() if LINE.match(line))


def main():
    dso = sys.argv[1]
    C = lambda a, b: count(dso, a, b)

    n4 = C(0x2D3C1A, 0x2D40E5)

    n16_pro = C(0x2D4BD3, 0x2D4E00)
    n16_body = C(0x2D4E00, 0x2D5287)
    n16_tail = C(0x2D528C, 0x2D56F0)
    n16 = n16_pro + 16 * n16_body + n16_tail

    n32_pro = C(0x2D5A6A, 0x2D5AD1)
    n32_pref = C(0x2D5AD1, 0x2D5AE0)
    n32_prod = C(0x2D5AE0, 0x2D5B24)
    n32_rsetup = C(0x2D5B25, 0x2D5B60)
    n32_rfull = C(0x2D5B60, 0x2D5BAA)
    n32_rlast = C(0x2D5B60, 0x2D5B84)
    n32_rtail = C(0x2D5AA0, 0x2D5AD1)
    n32_fsub = C(0x2D5BB0, 0x2D5BEB)
    n32_mask = C(0x2D5C10, 0x2D5C3E)
    n32_ftail = C(0x2D5BEC, 0x2D5C44)
    n32_outer = n32_pref + 16 * n32_prod + n32_rsetup + 15 * n32_rfull + n32_rlast + n32_rtail
    n32 = n32_pro + 32 * n32_outer + 16 * n32_fsub + 32 * n32_mask + n32_ftail

    gen_prod = C(0x2D4310, 0x2D4352)
    gen_red = C(0x2D43D0, 0x2D4416)
    gen_core = 16 * (8 * gen_prod + 8 * gen_red)

    def row(name, tot, prod):
        print("%-24s total=%-7d products=%-5d per-product=%.2f"
              % (name, tot, prod, tot / prod))

    print("region counts: n16 pro=%d body=%d tail=%d | n32 prod=%d rfull=%d rlast=%d pref=%d rsetup=%d rtail=%d fsub=%d mask=%d ftail=%d"
          % (n16_pro, n16_body, n16_tail, n32_prod, n32_rfull, n32_rlast,
             n32_pref, n32_rsetup, n32_rtail, n32_fsub, n32_mask, n32_ftail))
    print()
    row("n=4  specialised", n4, 32)
    row("n=16 specialised", n16, 2 * 16 * 16)
    row("n=32 specialised", n32, 2 * 32 * 32)
    print("%-24s tight-core=%-7d (16*(8*%d+8*%d)); the campaign's 6,457 leaves %d for tails/final"
          % ("generic n=16 (core)", gen_core, gen_prod, gen_red, 6457 - gen_core))
    print()
    print("n=32 outer-iteration body = %d  (prefix %d + product 16*%d + rsetup %d + reduc 15*%d+%d + rtail %d)"
          % (n32_outer, n32_pref, n32_prod, n32_rsetup, n32_rfull, n32_rlast, n32_rtail))


if __name__ == "__main__":
    main()
