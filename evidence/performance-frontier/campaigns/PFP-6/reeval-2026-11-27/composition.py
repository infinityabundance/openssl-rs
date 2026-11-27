#!/usr/bin/env python3
"""composition.py — per-operation Montgomery-kernel call structure from a
callgrind log of `bench_pfp5 --only <workload>`.

Callgrind's raw format names a function once (`fn=(id) name`) and refers to it
by id afterwards. The harness in profiling mode performs three exponentiations
(one CHECK plus one warm-up plus one timed), so per-operation counts are the
totals divided by three; the script asserts exact divisibility.

It prints every call arc from `run_mont_ladder` to a Montgomery kernel, so the
squaring-role arcs and the multiply/table/conversion arcs can be read rather
than assumed.
"""
import re, sys, collections

NAME = re.compile(r"^(c?fn)=\((\d+)\)(?: (.*))?$")
CALLS = re.compile(r"^calls=(\d+)")


def parse(path):
    lines = open(path, errors="replace").read().splitlines()
    ids = {}
    for line in lines:
        m = NAME.match(line)
        if m and m.group(3):
            ids[m.group(2)] = m.group(3)
    caller = None
    arcs = []
    i = 0
    while i < len(lines):
        line = lines[i]
        m = NAME.match(line)
        if m:
            kind, cid, nm = m.group(1), m.group(2), m.group(3)
            name = nm if nm else ids.get(cid)
            if kind == "fn":
                caller = name
            else:
                c = CALLS.match(lines[i + 1]) if i + 1 < len(lines) else None
                if c:
                    calls = int(c.group(1))
                    parts = lines[i + 2].split() if i + 2 < len(lines) else []
                    if calls > 0 and len(parts) == 2 and parts[1].isdigit():
                        arcs.append((caller, name, calls, int(parts[1])))
        i += 1
    return arcs


def main(path, ops=3):
    arcs = parse(path)
    merged = collections.Counter()
    ir = collections.Counter()
    for caller, callee, calls, cost in arcs:
        if caller and "arith::run_mont_ladder" in caller and callee:
            if any(k in callee for k in ("mont_mul_sos_into", "mont_mul_cios_into",
                                         "mont_mul_ladder_into", "mont_sqr_into")):
                merged[callee] += calls
                ir[callee] += cost
    print("callee, calls_total, calls_per_operation, ir_total, ir_per_call")
    for callee, calls in sorted(merged.items()):
        assert calls % ops == 0, (callee, calls)
        print("%s, %d, %d, %d, %d" % (
            callee, calls, calls // ops, ir[callee], ir[callee] // calls))
    print("\narcs (caller -> callee, calls, inclusive Ir):")
    for caller, callee, calls, cost in arcs:
        if caller and "arith::run_mont_ladder" in caller and callee and any(
                k in callee for k in ("mont_mul_sos_into", "mont_mul_cios_into",
                                      "mont_mul_ladder_into", "mont_sqr_into")):
            print("  %s -> %s calls=%d ir=%d (%.1f/op)" % (
                caller.split("::")[-1], callee.split("::")[-1], calls, cost, calls / ops))


if __name__ == "__main__":
    main(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 3)
