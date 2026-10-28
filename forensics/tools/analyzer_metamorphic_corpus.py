#!/usr/bin/env python3
"""Metamorphic corpus for the consumer-closure edge resolver.

The fixtures below are small synthetic call graphs with controlled function,
instruction and call-index records.  They are fed to the *production* resolver
paths (`PrecisionResolver` output shape -> `apply_evidence_classes` ->
`build_edge_records` -> `validate_edge_records`), not to a reimplementation.

What the corpus establishes
---------------------------
Stability: the semantic edge record is unchanged by an identical rebuild and by
code-layout perturbation, and it survives a symbol rename and a thunk
substitution.  Sensitivity: an argument-derived callback is bounded by a finite
caller set and stays unresolved when the caller set is unbounded; an
unreachable writer is excluded with a reachability witness; an exclusion with no
reason, or an omission of a known exclusion, makes the analyzer refuse.

What it does not establish
--------------------------
This is evidence of stability and sensitivity, not a soundness proof.  The
fixtures are synthetic: they do not exercise a real linker, LTO, PLT/GOT
tricks, dlopen-supplied targets, or provider dispatch tables.  Those are listed
as explicit non-coverage in the emitted receipt.

Run:  python3 forensics/tools/analyzer_metamorphic_corpus.py \
          --out forensics/memory-safety/campaign/safe-c33/atlas-refresh/\
analyzer-metamorphic-corpus.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import consumer_closure as cc  # noqa: E402

SCHEMA = "openssl-rs/campaign/safe-c33/analyzer-metamorphic-corpus/v1"
TOOL = "forensics/tools/analyzer_metamorphic_corpus.py"

# The fixture's semantic call graph.  Addresses are artifact-local: every case
# below either rebuilds this exact graph or transforms it.
FUNCTIONS = {
    0x10: "...property5store11alg_cleanup",
    0x100: "...property5store21ossl_method_store_add",
    0x200: "...property5store27ossl_method_store_cache_set",
    0x300: "fixture_caller_of_store",
    0x350: "fixture_caller_of_caller",
    0x400: "OSSL_DECODER_free",
    0x410: "impl_free_thunk",
    0x420: "OSSL_ENCODER_free",
    0x500: "...property5store21ossl_method_store_add.dead",
    0x600: "dead_target",
}

RAW_INSNS = {
    0x10: [(0x10, "ret")],
    0x100: [
        (0x100, "push   %rbx"),
        (0x101, "sub    $0x8,%rsp"),
        (0x102, "mov    0x18(%rsp),%rax"),
        (0x103, "mov    %rax,0x20(%rbx)"),
        (0x104, "ret"),
    ],
    0x200: [
        (0x200, "push   %rbx"),
        (0x201, "sub    $0x8,%rsp"),
        (0x202, "mov    0x18(%rsp),%rax"),
        (0x203, "mov    %rax,0x20(%rbx)"),
        (0x204, "ret"),
    ],
    0x300: [(0x300, "ret")],
    0x350: [(0x350, "ret")],
    0x400: [(0x400, "ret")],
    0x420: [(0x420, "ret")],
    0x500: [
        (0x500, "push   %rbx"),
        (0x501, "sub    $0x8,%rsp"),
        (0x502, "mov    0x18(%rsp),%rax"),
        (0x503, "mov    %rax,0x20(%rbx)"),
        (0x504, "ret"),
    ],
    0x600: [(0x600, "ret")],
}


class _Precision:
    """The only PrecisionResolver state the semantic rule reads."""

    def __init__(self, insns_by_func):
        self.calls = []
        self.insns_by_func = insns_by_func
        self.import_addrs = set()


class FixtureGraph:
    name = "metamorphic-fixture.so"

    @property
    def slot_func_targets(self):
        return {v for vs in self.slot_funcs.values() for v in vs}


def _call_row(caller, call_site, value):
    """A call record whose stack argument 6 is the stored value."""
    return {
        "caller": caller,
        "call_site": call_site,
        "args": [cc.PValue() for _ in range(6)],
        "stack": [value],
        "open": [True] * 6,
    }


def _arg_row(caller, call_site, index, value):
    args = [cc.PValue() for _ in range(6)]
    args[index] = value
    opened = [False] * 6
    return {"caller": caller, "call_site": call_site, "args": args,
            "stack": [], "open": opened}


def make_fixture(*, base=0, pad=0, rename=None, store="thunk",
                 param_mode=None, dead_writer=True):
    """Build one fixture graph.  Every knob is a metamorphic transformation."""
    rename = dict(rename or {})

    def A(addr):
        return base + addr

    def N(name):
        return rename.get(name, name)

    g = FixtureGraph()
    g.funcs = {}
    for addr, name in FUNCTIONS.items():
        if addr == 0x500 and not dead_writer:
            continue
        g.funcs[A(addr)] = N(name)
    g.start_set = set(g.funcs)
    g.all_syms = dict(g.funcs)
    g.names_at = {a: {n} for a, n in g.funcs.items()}
    g.dynamic_defs = {"OSSL_DECODER_free": A(0x400),
                      "OSSL_ENCODER_free": A(0x420)}
    if param_mode == "unbounded":
        g.dynamic_defs["exported_callback_api"] = A(0x300)
    g.slot_syms = {}
    g.slot_funcs = {A(0x9000): {A(0x420)}}
    g.slot_data = {}
    g.sym_sizes = {}
    g.taken_code = set()
    g.taken_data = set()
    g.field_stores = {}
    g.unknown_call_arg_targets = set()
    g.evidence_classes = {}
    g.residual_sites = []
    g.resolved_targets = set()
    g.precision_counts = {}
    g.direct = {}
    g.import_addrs = set()
    g.section_of = lambda _a: ".text"
    g.static_slot = lambda _a: None
    g.seam_symbol = lambda _a: None
    g.cstring_at = lambda _a: None
    g.is_data = lambda _a: False

    insns = {}
    for fstart, raw in RAW_INSNS.items():
        if fstart == 0x500 and not dead_writer:
            continue
        seq = [(A(fstart) + i, "nop") for i in range(pad)]
        seq += [(A(fstart) + pad + i, text) for i, (_a, text) in enumerate(raw)]
        insns[A(fstart)] = seq
    if store == "thunk":
        insns[A(0x410)] = [
            (A(0x410),
             f"jmp    *0x8bf0(%rip)        # {A(0x9000):x} <OSSL_ENCODER_free>")]
    g.precision = _Precision(insns)

    thunk = cc.PValue.one(A(0x410))
    direct = cc.PValue.one(A(0x420))
    stored = thunk if store == "thunk" else direct
    if param_mode in ("finite", "unbounded"):
        stored = cc.PValue.one(("arg", 3))

    g._semantic_call_index = {
        A(0x100): {
            (A(0x300), A(0x301)): _call_row(A(0x300), A(0x301), stored),
            (A(0x300), A(0x303)): _call_row(
                A(0x300), A(0x303), cc.PValue.one(A(0x400))),
        },
        A(0x200): {
            (A(0x300), A(0x305)): _call_row(A(0x300), A(0x305), stored),
        },
    }
    if dead_writer:
        g._semantic_call_index[A(0x500)] = {
            (A(0x300), A(0x307)): _call_row(
                A(0x300), A(0x307), cc.PValue.one(A(0x600))),
        }
    if param_mode in ("finite", "unbounded"):
        # The finite caller set of fixture_caller_of_store.
        g._semantic_call_index[A(0x300)] = {
            (A(0x350), A(0x351)): _arg_row(
                A(0x350), A(0x351), 3, cc.PValue.one(A(0x410))),
        }

    g.sites = {
        (A(0x10), A(0x11), "call"): {
            "kind": "call", "func": A(0x10), "addr": A(0x11),
            "text": "call   *0x20(%rbx)", "targets": set(),
            "unresolved": True, "reason": "field-of-unknown-base",
            "class": "field", "field_offsets": {0x20}, "seam": None,
            "arg_deps": set(),
        }
    }
    g.reach = {A(0x10), A(0x100), A(0x200), A(0x300), A(0x400),
               A(0x410), A(0x420)}
    if param_mode in ("finite", "unbounded"):
        g.reach.add(A(0x350))
    return g


def classify(**opts):
    """Run the production evidence pass and edge-record builder."""
    g = make_fixture(**opts)
    cc.apply_evidence_classes(g, set(), g.reach)
    records = cc.build_edge_records({g.name: g})
    return g, records


# --------------------------------------------------------------------------- #
# normalisation: addresses are witnesses, never identity
# --------------------------------------------------------------------------- #
ARTIFACT_LOCAL_KEYS = {
    "call_site", "writer_address", "site_address", "function_address",
    "addr", "address", "instruction", "from", "to",
}
EVIDENCE_IDENTITY_KEYS = ("symbol", "declared_name", "present", "writer",
                          "reachable_set_member")


def _clean(value):
    if isinstance(value, dict):
        return {k: _clean(v) for k, v in sorted(value.items())
                if k not in ARTIFACT_LOCAL_KEYS}
    if isinstance(value, list):
        return [_clean(v) for v in value]
    return value


def edge_view(records):
    """The address-free semantic view used for every comparison."""
    out = []
    for rec in records:
        ident = rec["semantic_identity"]
        exclusions = []
        for ex in rec.get("exclusions") or ():
            evidence = ex.get("evidence") or {}
            exclusions.append({
                "target": ex.get("target"),
                "reason": ex.get("reason"),
                "evidence": {k: evidence.get(k)
                             for k in EVIDENCE_IDENTITY_KEYS if k in evidence},
            })
        out.append({
            "edge_id": rec["edge_id"],
            "defining_function": ident["defining_function"],
            "source_operation": ident["source_operation"],
            "operation_kind": ident["operation_kind"],
            "call_site_role": ident["call_site_role"],
            "disposition": rec["disposition"],
            "target_set": rec.get("target_set") or [],
            "witness_id": rec.get("witness_id"),
            "missing_property": rec.get("missing_property"),
            "provenance_chain": sorted(
                ({"target": c["target"], "derivation": _clean(c["derivation"])}
                 for c in ident["provenance_chain"]),
                key=lambda c: c["target"]),
            "exclusions": sorted(
                exclusions,
                key=lambda e: (str(e["target"]), str(e["reason"]))),
        })
    return sorted(out, key=lambda r: r["edge_id"])


def apply_rename(view, mapping):
    def rewrite(value):
        if isinstance(value, str):
            for old, new in mapping.items():
                value = new if value == old else value.replace(old, new)
            return value
        if isinstance(value, dict):
            return {rewrite(k): rewrite(v) for k, v in value.items()}
        if isinstance(value, list):
            return [rewrite(v) for v in value]
        return value
    return rewrite(view)


def semantic_record(records):
    return next(r for r in records
                if r["semantic_identity"]["call_site_role"] == "method-store-slot")


def _case(case_id, input_desc, transformation, expected, observed, ok,
          evidence=None):
    return {
        "id": case_id,
        "input": input_desc,
        "transformation": transformation,
        "expected_property": expected,
        "observed_result": observed,
        "verdict": "PASS" if ok else "FAIL",
        "evidence": evidence or {},
    }


# --------------------------------------------------------------------------- #
# the seven cases
# --------------------------------------------------------------------------- #
def case_identical_rebuild():
    _g1, r1 = classify()
    _g2, r2 = classify()
    v1, v2 = edge_view(r1), edge_view(r2)
    return _case(
        "a-identical-input-rebuild",
        "fixture graph (base=0, pad=0, thunk store)",
        "build the same fixture twice",
        "identical semantic graph and verdict",
        "identical" if v1 == v2 else "diverged",
        v1 == v2,
        {"records": len(v1), "disposition": v1[0]["disposition"]})


def case_layout_perturbation():
    _g1, r1 = classify()
    _g2, r2 = classify(base=0x1000, pad=7)
    v1, v2 = edge_view(r1), edge_view(r2)
    return _case(
        "b-layout-perturbation",
        "fixture graph (base=0, pad=0)",
        "shift all function/instruction addresses by 0x1000 and insert 7 "
        "padding instructions per function",
        "no lost reachable targets; identical semantic graph",
        "identical" if v1 == v2 else "diverged",
        v1 == v2,
        {"base_records": len(v1), "shifted_records": len(v2)})


def case_symbol_rename():
    _g1, r1 = classify()
    mapping = {"impl_free_thunk": "impl_free_thunk__alias"}
    _g2, r2 = classify(rename=mapping)
    expected = apply_rename(edge_view(r1), mapping)
    observed = edge_view(r2)
    return _case(
        "c-symbol-rename-alias",
        "fixture graph with an in-image thunk wrapper",
        "rename impl_free_thunk to impl_free_thunk__alias; keep the body",
        "provenance preserved: the rename is the only difference",
        "preserved" if expected == observed else "provenance changed",
        expected == observed,
        {"renamed_symbols": mapping,
         "target_set": semantic_record(r2).get("target_set")})


def case_thunk_substitution():
    _g1, r1 = classify(store="thunk")
    _g2, r2 = classify(store="direct")
    t1 = semantic_record(r1)["target_set"]
    t2 = semantic_record(r2)["target_set"]
    return _case(
        "d-thunk-substitution",
        "fixture graph storing the thunk address",
        "replace the stored thunk with the direct callee address",
        "equivalent target set after thunk canonicalisation",
        "equivalent" if t1 == t2 else f"differed: {t1} != {t2}",
        t1 == t2,
        {"thunk_target_set": t1, "direct_target_set": t2})


def case_argument_callback():
    _gf, rf = classify(param_mode="finite")
    _gu, ru = classify(param_mode="unbounded")
    vf = semantic_record(rf)
    vu = semantic_record(ru)
    finite_ok = (vf["disposition"] == cc.DISPOSITION_PROVED
                 and "OSSL_ENCODER_free" in vf["target_set"])
    unbounded_ok = (vu["disposition"] == cc.DISPOSITION_UNRESOLVED
                    and bool(vu["missing_property"])
                    and "OSSL_ENCODER_free" not in vu["target_set"])
    return _case(
        "e-argument-derived-callback",
        "fixture graph whose writer slot is fed by a parameter",
        "finite caller set (one reachable caller passes an in-image callback) "
        "vs. an unbounded dynamic-export caller",
        "finite caller set -> bounded; unbounded caller set -> unresolved",
        (f"finite={vf['disposition']}, unbounded={vu['disposition']}"),
        finite_ok and unbounded_ok,
        {"finite_target_set": vf["target_set"],
         "unbounded_missing_property": vu["missing_property"]})


def case_unknown_target_injection():
    _g, records = classify()
    tampered = json.loads(json.dumps(records))
    tampered[0]["exclusions"].append({
        "target": "OSSL_ENCODER_free", "reason": None, "evidence": {}})
    defects = cc.validate_edge_records(tampered)
    refusal = cc.edge_refusal_for(defects)

    _gu, ru = classify(param_mode="unbounded")
    vu = semantic_record(ru)
    not_omitted = (vu["disposition"] == cc.DISPOSITION_UNRESOLVED
                   and "OSSL_ENCODER_free" not in vu["target_set"])
    ok = bool(defects) and refusal is not None \
        and refusal["code"] == "EDGE_RECORD_EXCLUSION_UNSOUND" and not_omitted
    return _case(
        "f-unknown-target-injection",
        "a valid fixture record plus an injected unknown exclusion",
        "add an exclusion with no reason; separately inject a non-image "
        "callback value",
        "the analyzer refuses the closure and never silently omits the target",
        (f"refusal={refusal['code'] if refusal else None}, "
         f"unknown-disposition={vu['disposition']}"),
        ok,
        {"defects": defects[:4],
         "unknown_missing_property": vu["missing_property"]})


def case_unreachable_target():
    _g, records = classify()
    view = semantic_record(records)
    witness = [e for e in view.get("exclusions") or ()
               if e["target"] == "dead_target"]
    has_witness = bool(witness) and all(
        e["reason"] == "not-in-reachable-set"
        and e["evidence"].get("reachable_set_member") is False
        for e in witness)
    absent = "dead_target" not in (view.get("target_set") or [])
    clean = not cc.validate_edge_records(records)

    omitted = json.loads(json.dumps(records))
    rec = semantic_record(omitted)
    rec["exclusions"] = [e for e in rec.get("exclusions") or ()
                         if e.get("target") != "dead_target"]
    sensitivity = bool(cc.validate_edge_records(omitted))
    return _case(
        "g-unreachable-target-insertion",
        "fixture graph with a writer outside the reachable set",
        "insert an unreachable writer that stores dead_target",
        "excluded with a defensible reachability witness; removing the "
        "witness makes the analyzer refuse",
        (f"witness={has_witness}, absent_from_target_set={absent}, "
         f"accounted={clean}, omission_refused={sensitivity}"),
        has_witness and absent and clean and sensitivity,
        {"exclusions": witness})


CASES = (
    case_identical_rebuild,
    case_layout_perturbation,
    case_symbol_rename,
    case_thunk_substitution,
    case_argument_callback,
    case_unknown_target_injection,
    case_unreachable_target,
)

NOT_COVERED = [
    "real linker behaviour at scale (section GC, identical-code folding, "
    "symbol versioning)",
    "link-time optimisation (LTO) and cross-language inlining",
    "PLT/GOT tricks beyond the fixture's link-time constant thunk slot",
    "dlopen-supplied and dlsym-resolved targets",
    "provider dispatch tables selected at runtime",
    "the full library's real instruction idioms; the fixtures use the "
    "instruction shapes the semantic rule recognises",
]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out",
                    default=("forensics/memory-safety/campaign/safe-c33/"
                             "atlas-refresh/analyzer-metamorphic-corpus.json"))
    args = ap.parse_args(argv)

    cases = [fn() for fn in CASES]
    passed = sum(1 for c in cases if c["verdict"] == "PASS")
    failed = [c["id"] for c in cases if c["verdict"] != "PASS"]
    tool_path = Path(__file__).resolve().parent / "consumer_closure.py"
    doc = {
        "schema": SCHEMA,
        "tool": {
            "path": TOOL,
            "covered_tool": cc.TOOL,
            "covered_tool_sha256": hashlib.sha256(
                tool_path.read_bytes()).hexdigest(),
            "edge_record_schema": cc.EDGE_RECORD_SCHEMA,
        },
        "claim": ("stability and sensitivity evidence for the edge resolver: "
                  "not a proof of soundness"),
        "fixture_model": (
            "synthetic function/instruction/call-index fixtures fed to the "
            "production evidence pass and edge-record builder; no real object "
            "file or linker is exercised"),
        "cases": cases,
        "summary": {"total": len(cases), "passed": passed,
                    "failed": failed},
        "not_covered": NOT_COVERED,
        "non_claims": [
            "A PASS is not a soundness result: the corpus shows that named "
            "transformations do not change the named properties, not that no "
            "transformation can.",
            "The fixtures are synthetic and do not reproduce the real "
            "library's layout, linker behaviour, or runtime dispatch.",
            "The refusal case establishes that an unaccounted exclusion is "
            "detected; it does not establish that every real derivation is "
            "complete.",
        ],
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"out": str(out), "summary": doc["summary"]}, indent=1))
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
