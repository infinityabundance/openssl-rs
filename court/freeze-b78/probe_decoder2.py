#!/usr/bin/env python3
"""Fast targeted probe (no PrecisionResolver): exact indices and the prototype
table-cursor derivation for the b78 `file_load` decoder sites, plus the
`X509V3_EXT_REQ_add_conf` CONF-method site facts.

Read-only instrumentation; it changes no verdict.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "forensics/tools"))
import consumer_closure as cc  # noqa: E402

INSTALL = ROOT / "artifacts/phase2/install"


class _Prec:
    def __init__(self, insns):
        self.insns_by_func = insns

    def switch_targets(self, base, a):
        return set()


class _P:
    def __init__(self, base, insns):
        self.funcs = base.funcs
        self.start_set = base.start_set
        self.names_at = base.names_at
        self.sym_sizes = base.sym_sizes
        self.sections = base.sections
        self.dynamic_defs = base.dynamic_defs
        self.slot_syms = base.slot_syms
        self._base = base
        self.precision = _Prec(insns)

    def __getattr__(self, name):
        return getattr(object.__getattribute__(self, "_base"), name)


def proto(g, fstart, idx, reg, table_addr, extent, max_depth=12):
    """Prototype: roots of `reg` at `idx`, following copies, the named table,
    constant-stride self-advances and unique-writer spill/reload round trips."""
    insns = g.precision.insns_by_func.get(fstart, ())
    seen = set()
    trace = []

    def walk(i, r, depth):
        if (i, r) in seen:
            trace.append(f"cut {i}:{r}")
            return set()
        if depth > max_depth:
            return None
        seen.add((i, r))
        defs = cc._reaching_defs(g, fstart, i, r)
        if defs is None:
            trace.append(f"TOP {i}:{r}")
            return None
        if not defs:
            trace.append(f"entry {i}:{r}")
            return set()
        roots = set()
        for d in sorted(defs):
            if d < 0 or d >= len(insns):
                return None
            text = insns[d][1]
            mn, _rest, ops = cc._insn_parts(text.split("#", 1)[0].strip())
            if mn == "lea" and len(ops) == 2:
                m = re.fullmatch(r"-?0x[0-9a-f]+\((%r[a-z0-9]+)\)",
                                 ops[0].strip())
                if m and cc._canon(m.group(1)) != "%rip":
                    base = cc._canon(m.group(1))
                    imm = int(ops[0].strip().split("(")[0], 16)
                    if base == r:
                        if not (0 < imm <= extent and extent % imm == 0):
                            trace.append(f"unbounded self-lea {text}")
                            return None
                        sub = walk(d, r, depth + 1)
                        trace.append(f"self-lea {hex(insns[d][0])} {text}")
                    else:
                        sub = walk(d, base, depth + 1)
                        trace.append(f"copy-lea {hex(insns[d][0])} {text}")
                    if sub is None:
                        return None
                    roots |= sub
                    continue
                root = cc._insn_comment_addr(text)
                if root is None:
                    return None
                trace.append(f"lea {hex(insns[d][0])} -> {hex(root)}")
                roots.add(root)
                continue
            if mn in ("mov", "movq") and len(ops) == 2:
                src = ops[0].strip()
                if cc._canon(src) in cc._REGS:
                    sub = walk(d, cc._canon(src), depth + 1)
                    trace.append(f"copy {hex(insns[d][0])} {text}")
                    if sub is None:
                        return None
                    roots |= sub
                    continue
                slot = cc._stack_slot_abs(g, fstart, d, src)
                if slot is not None:
                    writes = cc._stack_slot_writes(g, fstart, slot)
                    stores = [w for w in writes if w["kind"] == "store"]
                    esc = [w for w in writes if w["kind"] == "address"]
                    if esc or len(stores) != 1:
                        trace.append(f"slot {slot} ambiguous esc={len(esc)} "
                                     f"stores={len(stores)}")
                        return None
                    s = stores[0]
                    if cc._canon(s["source"]) not in cc._REGS:
                        return None
                    sub = walk(s["index"], cc._canon(s["source"]), depth + 1)
                    trace.append(f"reload {hex(insns[d][0])} <- "
                                 f"{hex(insns[s['index']][0])}")
                    if sub is None:
                        return None
                    roots |= sub
                    continue
                return None
            return None
        return roots

    return walk(idx, reg, 0), trace


def main():
    dso = INSTALL / "lib/libcrypto.so.3"
    g0 = cc.DsoGraph(dso, ROOT / "court/tmp/v4-consumer-closure")
    g = _P(g0, dict(g0.functions))
    g.source_root = str(ROOT)
    g.install_prefix = str(INSTALL)

    table = cc._phw_symbol_addr(g, cc.DECODER_METHOD_TABLE)
    extent = g.sym_sizes.get(cc.DECODER_METHOD_TABLE)
    print("table", hex(table), "extent", extent)

    for leaf in ("file_load", "X509V3_EXT_REQ_add_conf"):
        fstart = cc._external_function_address(g, leaf)
        insns = g.precision.insns_by_func.get(fstart, ())
        print(f"== {leaf} @ {hex(fstart)} insns={len(insns)}")
        cfg = cc._function_cfg(g, fstart)
        print("   blocks", len(cfg["blocks"]), "open", len(cfg["open_reach"]))
        for i, (a, t) in enumerate(insns):
            if not re.match(r"call\s+\*", t):
                continue
            reg = cc._canon(t.split("*")[1])
            print(f"   site {hex(a)} idx={i} operand={reg}")
            roots_old = cc._led_reg_roots(g, fstart, i, reg)
            print("     old roots:", None if roots_old is None
                  else sorted(hex(r) for r in roots_old))
            roots, trace = proto(g, fstart, i, reg, table, extent or 0)
            print("     proto roots:", None if roots is None
                  else sorted(hex(r) for r in roots))
            for line in trace:
                print("       .", line)
            rd = cc._reaching_defs(g, fstart, i, reg)
            if rd:
                for d in sorted(rd):
                    print(f"       def idx={d} {hex(insns[d][0])} {insns[d][1]}")


if __name__ == "__main__":
    main()
