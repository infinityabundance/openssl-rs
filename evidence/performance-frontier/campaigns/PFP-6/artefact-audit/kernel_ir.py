#!/usr/bin/env python3
"""kernel_ir.py — deterministic per-call and per-ladder-operation instruction
counts of the carriers, from the callgrind runs of `sign` (64 iterations) at the
artefact digests.

Callgrind introduces a name once per id (`fn=(id) name`, `cfn=(id) name`) and
later refers to the id alone, so ids are resolved through a map.  For each call
edge the first cost line after `calls=` is the callee's inclusive Ir for those
calls (later lines are further position splits and are not summed).

Only edges whose caller is `run_mont_ladder` are used for the ladder cost: that
is the function that runs the fixed ladder, so its edges are exactly the
schedule's multiply (256 in-loop + 1 final) and the squaring (256).  Exact
divisibility (ir % calls == 0) is asserted.
"""
import json, re, sys

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
    edges = []
    for i, line in enumerate(lines):
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
                        edges.append((caller, name, calls, int(parts[1])))
            continue
        calls = CALLS.match(line)
        if calls:
            continue
    return edges


def kernel_edges(path):
    res = {}
    for caller, callee, calls, ir in parse(path):
        if caller and "arith::run_mont_ladder" in caller and callee:
            if "mont_mul_ladder_into" in callee or "mont_mul_sos_into" in callee:
                e = res.setdefault(callee, {"calls": 0, "ir": 0})
                e["calls"] += calls
                e["ir"] += ir
    for name, e in res.items():
        e["ir_per_call"] = e["ir"] // e["calls"]
        assert e["ir_per_call"] * e["calls"] == e["ir"], (name, e)
    return res


def main():
    a = kernel_edges(sys.argv[1])
    b = kernel_edges(sys.argv[2])

    def get(d, key):
        for k, v in d.items():
            if key in k:
                return v
        return None

    sos_a = get(a, "mont_mul_sos_into")
    cios_b = get(b, "mont_mul_ladder_into")
    sos_b = get(b, "mont_mul_sos_into")
    if not (sos_a and cios_b and sos_b):
        sys.exit("FATAL: a ladder->kernel edge is missing from the callgrind logs")

    # 64 sign operations per log.
    ladder_a = sos_a["ir"] // 64
    ladder_b = cios_b["ir"] // 64 + sos_b["ir"] // 64
    out = {
        "sign_operations": 64,
        "a": {
            "sos_calls_per_sign": sos_a["calls"] // 64,
            "sos_ir_per_call": sos_a["ir_per_call"],
            "sos_ir_per_sign": sos_a["ir"] // 64,
        },
        "b": {
            "cios_calls_per_sign": cios_b["calls"] // 64,
            "cios_ir_per_call": cios_b["ir_per_call"],
            "sos_calls_per_sign": sos_b["calls"] // 64,
            "sos_ir_per_call": sos_b["ir_per_call"],
            "cios_ir_per_sign": cios_b["ir"] // 64,
            "sos_ir_per_sign": sos_b["ir"] // 64,
        },
        "cios_over_sos_multiply_ir": round(cios_b["ir_per_call"] / sos_a["ir_per_call"], 6),
        "cios_over_sos_ladder_ir": round(ladder_b / ladder_a, 6),
        "note": "instruction counts, not time; both sides are the artefact's own "
                "callgrind run of the same harness and population",
    }
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
