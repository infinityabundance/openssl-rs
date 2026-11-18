#!/usr/bin/env python3
"""Targeted probe: why the b78 DECODER_METHOD witness loses the table argument.

Read-only instrumentation. It loads the *same* DsoGraph the closure uses (the
disassembly cache is reused) and prints the register-derivation facts for the
three `file_load` constructor call sites. Nothing here changes a verdict; it
exists so a witness repair can be evaluated without a 30-minute closure run.
"""
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "forensics/tools"))
import consumer_closure as cc  # noqa: E402

INSTALL = ROOT / "artifacts/phase2/install"


def main():
    dso = INSTALL / "lib/libcrypto.so.3"
    t0 = time.time()
    g = cc.DsoGraph(dso, ROOT / "court/tmp/v4-consumer-closure")
    t1 = time.time()
    g.source_root = str(ROOT)
    g.install_prefix = str(INSTALL)
    g.precision = cc.PrecisionResolver(g)
    g.precision.run()
    g.precision.publish()
    t2 = time.time()
    print(f"graph={t1-t0:.1f}s precision={t2-t1:.1f}s")

    fstart = cc._external_function_address(g, "file_load")
    print("file_load", hex(fstart) if fstart else None)
    insns = g.precision.insns_by_func.get(fstart, ())
    ctor = cc._phw_function_addresses(g, cc.DECODER_METHOD_CONSTRUCTOR)
    print("ctor addrs", [hex(a) for a in sorted(ctor)])
    table = cc._phw_symbol_addr(g, cc.DECODER_METHOD_TABLE)
    print("table", hex(table))
    print("table size", g.sym_sizes.get(cc.DECODER_METHOD_TABLE))

    idx_of = {a: i for i, (a, _t) in enumerate(insns)}
    call_idxs = [i for i, (a, t) in enumerate(insns)
                 if t.startswith("call") and not t.split(None, 1)[1].startswith("*")
                 and int(t.split()[1].split()[0], 16) in ctor]
    for i in call_idxs:
        print("ctor call at", hex(insns[i][0]), "idx", i)
        print("  prev:", [insns[j][1] for j in range(max(0, i - 4), i)])
        rd = cc._reaching_defs(g, fstart, i, "%rsi")
        print("  reaching defs %rsi:", rd if rd is None else sorted(rd))
        roots = cc._led_reg_roots(g, fstart, i, "%rsi")
        print("  roots %rsi:", None if roots is None else sorted(hex(r) for r in roots))
        if rd:
            for d in sorted(rd):
                print("    def", hex(insns[d][0]), insns[d][1])
                rd2 = cc._reaching_defs(g, fstart, d, "%r13")
                print("    reaching defs %r13 at def:", rd2 if rd2 is None else sorted(rd2))
    # every def of %r13 in the function, with indices
    defs = [(i, t) for i, (_a, t) in enumerate(insns)
            if "%r13" in cc._defined_regs_at(t)]
    print("r13 defs:", [(hex(insns[i][0]), t) for i, t in defs])
    cfg = cc._function_cfg(g, fstart)
    print("open_reach blocks:", len(cfg["open_reach"]), "blocks:", len(cfg["blocks"]))


if __name__ == "__main__":
    main()
