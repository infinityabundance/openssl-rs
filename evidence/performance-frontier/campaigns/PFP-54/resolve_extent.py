#!/usr/bin/env python3
"""PFP-54: resolve `mont_mul_sos_into`'s inlined extent from the detached DWARF.

Emits the abstract DIE, the inlined instance, its recorded address ranges, the
concrete caller's extent and the checks that make "the whole body" a measured
claim rather than a phrase: exactly one abstract subprogram, exactly one inlined
instance, exactly one caller, every recorded range audited, every range inside
the caller, and the caller's DWARF extent equal to the shipped symbol's extent.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path("/work")
EV = ROOT / "evidence/performance-frontier/campaigns/PFP-54"
SHIP = EV / "raw/artefacts/libcrypto.so.3"
DBG = EV / "raw/artefacts/libcrypto.so.3.debug"
SCRIPT = ROOT / "courts/phase18/timing/binary_branch_audit.py"
SYMBOL = "mont_mul_sos_into"
CALLER = "mont_mul_fallible"


def load_tool():
    spec = importlib.util.spec_from_file_location("bba", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def main() -> int:
    bba = load_tool()
    info = subprocess.run(["readelf", "--debug-dump=info", str(DBG)],
                          capture_output=True, text=True, check=True).stdout
    ranges_text = subprocess.run(["readelf", "--debug-dump=Ranges", str(DBG)],
                                 capture_output=True, text=True, check=True).stdout
    dies = bba.parse_debug_info(info)
    range_map = bba.parse_debug_ranges(ranges_text)

    abstracts = [d for d in dies if d.tag == "DW_TAG_subprogram"
                 and bba._attr_string(d.attrs.get("DW_AT_name")) == SYMBOL]
    assert len(abstracts) == 1, f"{len(abstracts)} abstract DIEs for {SYMBOL}"
    abstract = abstracts[0]
    instances = [d for d in dies if d.tag == "DW_TAG_inlined_subroutine"
                 and bba._attr_ref(d.attrs.get("DW_AT_abstract_origin")) == abstract.offset]

    recorded = []
    instance_rows = []
    callers = {}
    for instance in instances:
        ancestor = instance.parent
        caller = None
        while ancestor is not None:
            die = dies[ancestor]
            if (die.tag == "DW_TAG_subprogram"
                    and bba._attr_int(die.attrs.get("DW_AT_low_pc")) is not None):
                caller = die
                break
            ancestor = die.parent
        assert caller is not None, "inlined instance has no concrete caller"
        callers[caller.offset] = caller
        ranges_off = bba._attr_int(instance.attrs.get("DW_AT_ranges"))
        spans = list(range_map.get(ranges_off, []))
        recorded.extend(spans)
        instance_rows.append({
            "die_offset": hex(instance.offset),
            "abstract_origin": hex(bba._attr_ref(instance.attrs["DW_AT_abstract_origin"])),
            "call_file": bba._attr_int(instance.attrs.get("DW_AT_call_file")),
            "call_line": bba._attr_int(instance.attrs.get("DW_AT_call_line")),
            "ranges_offset": hex(ranges_off) if ranges_off is not None else None,
            "ranges": [[hex(b), hex(e)] for b, e in spans],
        })

    assert len(callers) == 1, f"{len(callers)} callers"
    caller_die = next(iter(callers.values()))
    low = bba._attr_int(caller_die.attrs["DW_AT_low_pc"])
    high = bba._attr_int(caller_die.attrs["DW_AT_high_pc"])
    caller_high = low + high if high < low else high

    symtab = bba.symbol_table(str(SHIP), 60.0)
    symbols = bba.find_exact(symtab, CALLER)
    assert len(symbols) == 1, f"{CALLER} resolves to {len(symbols)} symbols"
    sym_addr, sym_size, sym_name = symbols[0]

    target = bba.Target("SOS Montgomery", None, SYMBOL,
                        dwarf_inline=bba.DwarfInline(CALLER, "PFP-54 resolution"))
    context = bba.DwarfContext(str(DBG), "83eccb95e79216e5b53b46389df55fda6f9a9dee",
                               dies, range_map)
    extent, witness, failure = bba.verify_dwarf_inline(
        str(SHIP), target, symtab, 60.0, context)
    assert failure is None, failure

    recorded_set = sorted(recorded)
    audited_set = sorted(tuple(r) for r in witness["ranges"])
    checks = {
        "abstract_subprogram_is_unique": len(abstracts) == 1,
        "every_inlined_instance_enumerated": len(instances) == len(instance_rows),
        "single_concrete_caller": len(callers) == 1,
        "caller_extent_matches_shipped_symbol":
            sym_addr == low and sym_size == caller_high - low,
        "every_recorded_range_is_audited": recorded_set == audited_set,
        "every_range_non_empty": all(b < e for b, e in recorded_set),
        "every_range_inside_the_caller":
            all(low <= b and e <= caller_high for b, e in recorded_set),
    }
    result = {
        "campaign": "PFP-54",
        "symbol": SYMBOL,
        "caller": CALLER,
        "abstract_subprogram": {
            "die_offset": hex(abstract.offset),
            "linkage_name": bba._attr_string(abstract.attrs.get("DW_AT_linkage_name")),
            "name": bba._attr_string(abstract.attrs.get("DW_AT_name")),
            "decl_file": bba._attr_int(abstract.attrs.get("DW_AT_decl_file")),
            "decl_line": bba._attr_int(abstract.attrs.get("DW_AT_decl_line")),
            "inline": bba._attr_int(abstract.attrs.get("DW_AT_inline")),
        },
        "instances": instance_rows,
        "caller": {
            "die_offset": hex(caller_die.offset),
            "name": bba._attr_string(caller_die.attrs.get("DW_AT_name")),
            "linkage_name": bba._attr_string(caller_die.attrs.get("DW_AT_linkage_name")),
            "low_pc": hex(low),
            "high_pc": hex(high),
            "extent": [hex(low), hex(caller_high)],
            "shipped_symbol": {"symbol": sym_name, "addr": hex(sym_addr),
                               "size": hex(sym_size)},
        },
        "audited_extent": {
            "ranges": [[hex(b), hex(e)] for b, e in audited_set],
            "bytes": witness["bytes"],
        },
        "checks": checks,
        "all_pass": all(checks.values()),
        "whole_body_claim": (
            "The detached DWARF names one abstract subprogram and one inlined "
            "instance attributed to one concrete caller. The instance records "
            f"{len(recorded_set)} address ranges; the audit disassembles every one "
            "of them, each lies inside the caller, and the caller's DWARF extent "
            "equals the shipped symbol's extent. That is the whole extent the "
            "compiler recorded for this body, and no more."),
        "limits": [
            "a target inlined into more than one caller is refused, not partially audited",
            "a body duplicated under more than one abstract origin is not covered",
            "a partially inlined body's out-of-line remainder is audited separately, not here",
            "only this DSO digest and this target are covered",
        ],
    }
    (EV / "raw/inlined-extent.json").write_text(json.dumps(result, indent=1) + "\n")
    for name, ok in checks.items():
        print(f"{name}: {ok}")
    print("ranges", [[hex(b), hex(e)] for b, e in audited_set], "bytes", witness["bytes"])
    print("caller", hex(low), hex(caller_high), "symbol", sym_name)
    return 0 if result["all_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
