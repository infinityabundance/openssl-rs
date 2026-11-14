#!/usr/bin/env python3
"""Probe the repaired decoder witness against the b78 image (fast, no resolver)."""
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


def main():
    g0 = cc.DsoGraph(INSTALL / "lib/libcrypto.so.3",
                     ROOT / "court/tmp/v4-consumer-closure")
    g = _P(g0, dict(g0.functions))
    g.source_root = str(ROOT)
    g.install_prefix = str(INSTALL)
    table = cc._phw_symbol_addr(g, cc.DECODER_METHOD_TABLE)
    extent = g.sym_sizes[cc.DECODER_METHOD_TABLE]
    fstart = cc._external_function_address(g, "file_load")
    insns = g.precision.insns_by_func[fstart]
    pins = {0x24DFED: "newctx", 0x24E046: "set_ctx_params", 0x24E090: "freectx"}
    print("table", hex(table), "extent", extent)
    for site_addr, slot in pins.items():
        # re-derive this row's site: the transfer that reads the row's slot
        found = []
        for i, (a, text) in enumerate(insns):
            m = re.match(r"call\s+\*%r", text)
            if not m:
                continue
            reg = cc._canon(text.split("*")[1])
            origin = cc._reg_origin(g, fstart, i, reg)
            if origin.get("kind") == "load" and origin.get("offset") == \
                    cc.DECODER_METHOD_SITES[site_addr]["read"]:
                found.append(a)
        print(f"{slot}: candidate transfers reading +{cc.DECODER_METHOD_SITES[site_addr]['read']:#x}"
              f" -> {[hex(x) for x in found]}")

    # cursor derivation on the constructor call in file_load
    ctor = cc._phw_function_addresses(g, cc.DECODER_METHOD_CONSTRUCTOR)
    call_idx = next(i for i, (a, t) in enumerate(insns)
                    if t.startswith("call ") and not t.split(None, 1)[1].startswith("*")
                    and int(t.split()[1].split()[0], 16) in ctor)
    roots, cursor = cc._led_table_cursor(g, fstart, call_idx, "%rsi",
                                         table, extent)
    print("roots", None if roots is None else sorted(hex(r) for r in roots))
    print("cursor", {k: (hex(v) if isinstance(v, int) else v)
                     for k, v in cursor.items() if k != "steps"})
    print("steps", cursor["steps"])
    guard = cc._led_table_terminator_guard(g, fstart, cursor["cursor_reg"],
                                           cursor["row_stride"], extent)
    print("guard", guard)

    # full witness on each of the three real sites
    for a in (0x2cc9aa, 0x2cca08, 0x2ccd86):
        text = next(t for ad, t in insns if ad == a)
        site = {"kind": "call", "func": fstart, "addr": a, "text": text,
                "targets": set(), "unresolved": True, "reason": "materialised",
                "class": "materialised", "field_offsets": set(), "seam": None,
                "arg_deps": set(), "arg_targets": set()}
        try:
            w = cc.decoder_method_object_witness(g, site, "file_load")
        except Exception as e:  # noqa: BLE001
            print(hex(a), "EXC", type(e).__name__, str(e)[:200])
            continue
        if isinstance(w, tuple):
            print(hex(a), "tuple", str(w)[:300])
        elif w is None:
            print(hex(a), "none")
        else:
            print(hex(a), "OK class", w.get("class"), "slot",
                  (w.get("field") or {}).get("name"),
                  "arg", (w.get("object") or {}).get("argument", {}).get(
                      "row_stride"))


if __name__ == "__main__":
    main()
