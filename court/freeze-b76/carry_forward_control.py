#!/usr/bin/env python3
"""Load-bearing negative control for the carry-forward coordinate tolerance.

`carry_forward_candidates` tolerates a moved definition, but its line-based
fallback must never match a *different* operation.  b76 exposed the failure:
commit 69d43bb8d deleted four `*_free_void` thunks from `src/cmp/cmp_ctx.rs`
and the next definitions were emitted at the same lines, so an item-blind
fallback reported the deleted operations as present and the carry was
suppressed instead of recorded as removed.

Both directions are asserted here:

  (a) same file + kind + item at a new line  -> carried / re-enrolled;
  (b) same file + kind + line, different item -> removed, "no longer exists".

The control is demonstrably load-bearing: the same two fixtures are run again
against an in-memory copy of the shipped function with the item requirement
removed, and (b) must then report the retired operation as present.

Run from the repository root (no compilation, no network):
    python3 court/freeze-b76/carry_forward_control.py
Exit status 0 means the shipped logic is item-strict AND the mutant is caught.
"""

from __future__ import annotations

import collections
import importlib.util
import inspect
import pathlib
import sys
import textwrap

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL = ROOT / "forensics/tools/consumer_closure.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("consumer_closure", TOOL)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["consumer_closure"] = mod
    spec.loader.exec_module(mod)
    return mod


def previous(item: str, line: int) -> dict:
    return {
        "receipt": "fixture-closure.json",
        "receipt_sha256": "0" * 64,
        "obligations": [{
            "id": f"V1:src/cmp/cmp_ctx.rs:{line}:UNSAFE_FN_DEF",
            "stable_id": f"src/cmp/cmp_ctx.rs::UNSAFE_FN_DEF::{item}",
            "file": "src/cmp/cmp_ctx.rs", "line": line,
            "kind": "UNSAFE_FN_DEF", "item": item,
            "status": "DISCHARGED", "contract": "contracted",
            "discharge_receipt": "R-1",
        }],
    }


def census(item: str, line: int, contracted: bool) -> dict:
    rec = {"file": "src/cmp/cmp_ctx.rs", "line": line,
           "kind": "UNSAFE_FN_DEF", "item": item, "partition": "production"}
    if contracted:
        return {"contracted_operations": [rec], "blockers": []}
    return {"contracted_operations": [],
            "blockers": [dict(rec, reason="no attached contract")]}


REACHABLE = {"src/cmp/cmp_ctx.rs"}
CASE_A = (previous("x509_free_void", 376), census("x509_free_void", 640, True))
CASE_B = (previous("x509_free_void", 376),
          census("general_name_free_void", 376, False))


def run(fn, case):
    prev, contracts = case
    return fn(prev, contracts, collections.Counter(), REACHABLE)


def mutant_of(mod):
    """The shipped function with the item requirement removed (pre-repair)."""
    src = inspect.getsource(mod.carry_forward_candidates)
    header = "matched = [pair for pair in by_exact.get((f, line, kind), [])"
    guard = 'if pair[1].get("item") == item]'
    if header not in src or guard not in src:
        raise SystemExit("control is stale: the repaired fallback was not found "
                         "in carry_forward_candidates")
    src = textwrap.dedent(src)
    src = src.replace(header, header + "  # MUTANT: item requirement removed")
    src = src.replace(guard, "if True]")
    namespace = dict(mod.__dict__)
    exec(compile(src, "<carry_forward_mutant>", "exec"), namespace)
    return namespace["carry_forward_candidates"]


def main() -> int:
    mod = load_tool()
    failures: list[str] = []

    def check(name, got, want):
        if got != want:
            failures.append(f"{name}: got {got!r}, want {want!r}")

    # ---- shipped logic -------------------------------------------------- #
    out_a, sum_a = run(mod.carry_forward_candidates, CASE_A)
    check("(a) moved definition is carried", len(out_a), 1)
    check("(a) moved definition is not removed", sum_a["removed_count"], 0)
    check("(a) carried identity", (out_a[0]["stable_id"],
                                   out_a[0]["current_census_line"]),
          ("src/cmp/cmp_ctx.rs::UNSAFE_FN_DEF::x509_free_void", 640))

    out_b, sum_b = run(mod.carry_forward_candidates, CASE_B)
    check("(b) recycled line carries nothing", len(out_b), 0)
    check("(b) recycled line is recorded removed", sum_b["removed_count"], 1)
    check("(b) removed identity", (sum_b["removed"][0]["item"],
                                   sum_b["removed"][0]["line"]),
          ("x509_free_void", 376))
    check("(b) removal names non-existence",
          "no longer exists as a source unsafe operation"
          in (sum_b["removed"][0]["reason"] or ""), True)
    check("(b) previously discharged status is retained for the record",
          sum_b["removed"][0]["previous_status"], "DISCHARGED")

    # ---- the same fixtures against the pre-repair (item-blind) logic ---- #
    mutant = mutant_of(mod)
    m_out_a, _ = run(mutant, CASE_A)
    check("mutant still carries the moved definition (mutation is narrow)",
          len(m_out_a), 1)
    m_out_b, m_sum_b = run(mutant, CASE_B)
    check("LOAD-BEARING: mutant reports the retired operation as present",
          (len(m_out_b), m_sum_b["removed_count"]), (1, 0))
    check("LOAD-BEARING: the reported-present ghost is the retired identity",
          m_out_b[0]["item"] if m_out_b else None, "x509_free_void")

    if failures:
        print("carry-forward control: FAILED")
        for f in failures:
            print("  -", f)
        return 1
    print("carry-forward control: ok")
    print("  (a) src/cmp/cmp_ctx.rs::UNSAFE_FN_DEF::x509_free_void moved "
          "376 -> 640: carried, removed_count=0")
    print("  (b) line 376 now general_name_free_void: carried=0, "
          "removed=1 (x509_free_void), reason='... the operation no longer "
          "exists as a source unsafe operation'")
    print("  mutant (item requirement removed): (b) carried=1 "
          "removed_count=0 -- i.e. the retired thunk is reported present, "
          "which is what produced CARRY_FORWARD_SUPPRESSED at b76")
    return 0


if __name__ == "__main__":
    sys.exit(main())
