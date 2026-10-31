#!/usr/bin/env python3
"""Metamorphic corpus for the consumer-closure edge resolver.

The fixtures below are small synthetic call graphs with controlled function,
instruction and call-index records.  They are fed to the *production* resolver
paths (`PrecisionResolver` output shape -> `apply_evidence_classes` ->
`build_edge_records` -> `validate_edge_records`), not to a reimplementation.

What the corpus establishes
---------------------------
Stability: the semantic edge record is unchanged by an identical rebuild and by
code-layout perturbation, and it survives a symbol rename, a thunk
substitution, and a module rename.  Sensitivity: an argument-derived callback
is bounded by a finite caller set and stays unresolved when the caller set is
unbounded; an unreachable writer is excluded with a reachability witness; an
exclusion with no reason, or an omission of a known exclusion, makes the
analyzer refuse.  Mutually redundant accounting: a record whose ``target_set``,
``admitted_targets`` or provenance chain disagree is refused, a fabricated or
payload-free derivation step is refused, and a negative reachability claim that
contradicts the final upper-bound oracle is refused.  Row kinds: a target drop
labelled as a caller/writer claim, a writer reason used as a target drop, a
free-text declared-name derivation, a declared target that is reachable or not
a candidate, and a forged caller contribution are all refused.

v1.5 adds the *closure* axis.  A residual site's bound is class-independent, so
a PROVED->UNRESOLVED re-classification cannot shrink it (the monotone-bound
case); residual admission is iterated to a least fixed point, so a dispatch
chain nested behind an unresolved site is reached (the nested-dispatch case);
a non-convergent iteration is a refusal, not a partial bound; and the analysis
identity is the .text-and-symbol-table canonical hash, not the DSO file digest
(the neutral-rebuild case).

v1.6 adds *admission by refutation*.  An exclusion derived against the
pre-closure direct set is false when the sound bound reaches its subject, so
the subject's contribution is admitted and the closure recomputed (the
refuted-caller case); an exclusion the sound bound does not reach survives and
still validates (the surviving-caller case); and a refuted subject with no
finite recorded contribution turns a resolved site into UNRESOLVED with a
named property instead of keeping an unsound finite claim.  Two mutation
controls show that the cases are sensitive to the mechanism: disabling
admission makes the first fail, and admitting unconditionally makes the second
fail.

What it does not establish
--------------------------
This is evidence of stability and sensitivity, not a soundness proof.  The
fixtures are synthetic: they do not exercise a real linker, LTO, PLT/GOT
tricks, dlopen-supplied targets, or provider dispatch tables.  Those are listed
as explicit non-coverage in the emitted receipt.  The corpus also does not
re-derive a target set to a fixpoint; it checks the record's internal ledgers
and the oracle, not a second resolution of the image.  (v1.5's closure cases
exercise the fixpoint of the *graph builder* on synthetic evidence; they still
do not re-resolve a real image.)

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
    # round 4: per-call-site attribution carries addresses beside names; the
    # names are the identity, the addresses are artifact-local witnesses.
    "function", "value", "target_addresses", "site",
}
EVIDENCE_IDENTITY_KEYS = ("symbol", "declared_name", "present", "writer",
                          "reachable_set_member", "targets",
                          "would_store_targets")


def _clean(value):
    if isinstance(value, dict):
        return {k: _clean(v) for k, v in sorted(value.items())
                if k not in ARTIFACT_LOCAL_KEYS}
    if isinstance(value, list):
        return [_clean(v) for v in value]
    return value


def edge_view(records):
    """The address-free semantic view used for every comparison."""
    def row_view(row):
        evidence = row.get("evidence") or {}
        claim = {**_clean(row.get("claim") or {}),
                 # the module is a witness: a rename must not change
                 # the semantic comparison
                 **({"module": "<module>"}
                    if (row.get("claim") or {}).get("module") else {})}
        return {
            "target": row.get("target"),
            "reason": row.get("reason"),
            "row_kind": row.get("row_kind"),
            "claim": claim,
            "evidence": {k: evidence.get(k)
                         for k in EVIDENCE_IDENTITY_KEYS if k in evidence},
        }

    out = []
    for rec in records:
        ident = rec["semantic_identity"]
        out.append({
            # The module is a witness, not identity: two revisions (or a rename)
            # must compare equal on the semantic graph, while the record's
            # edge_id still includes the module for uniqueness (H9).
            "edge_id": (rec["edge_id"].split("::", 1)[1]
                        if "::" in rec["edge_id"] else rec["edge_id"]),
            "defining_function": ident["defining_function"],
            "source_operation": ident["source_operation"],
            "operation_kind": ident["operation_kind"],
            "call_site_role": ident["call_site_role"],
            "disposition": rec["disposition"],
            "disposition_demotion": rec.get("disposition_demotion"),
            "target_set": rec.get("target_set") or [],
            "target_reachability": rec.get("target_reachability"),
            "witness_id": rec.get("witness_id"),
            "missing_property": rec.get("missing_property"),
            "candidate_source": _clean(rec.get("candidate_source") or {}),
            "unattributed_admissions": sorted(
                _clean(rec.get("unattributed_admissions") or ()),
                key=lambda a: str(a.get("target"))),
            "provenance_chain": sorted(
                ({"target": c["target"], "derivation": _clean(c["derivation"])}
                 for c in ident["provenance_chain"]),
                key=lambda c: c["target"]),
            "exclusions": sorted(
                (row_view(e) for e in (rec.get("exclusions") or ())),
                key=lambda e: (str(e["target"]), str(e["reason"]))),
            "excluded_callers": sorted(
                (row_view(e) for e in (rec.get("excluded_callers") or ())),
                key=lambda e: (str(e["target"]), str(e["reason"]))),
            "excluded_writers": sorted(
                (row_view(e) for e in (rec.get("excluded_writers") or ())),
                key=lambda e: (str(e["target"]), str(e["reason"]))),
            "unbounded_call_sites": sorted(
                (row_view(e) for e in (rec.get("unbounded_call_sites") or ())),
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
# the cases
# --------------------------------------------------------------------------- #
def _json_clone(records):
    return json.loads(json.dumps(records))


def _defect_case(case_id, input_desc, transformation, mutator, *, expected):
    """Mutate one ledger of a valid record set and require a refusal."""
    _g, records = classify()
    tampered = _json_clone(records)
    mutator(semantic_record(tampered))
    defects = cc.validate_edge_records(tampered)
    refusal = cc.edge_refusal_for(defects)
    ok = bool(defects) and refusal is not None \
        and refusal["code"] == "EDGE_RECORD_EXCLUSION_UNSOUND"
    return _case(
        case_id, input_desc, transformation, expected,
        (f"refused: {refusal['code']}" if ok else
         f"accepted (defects={defects[:2]})"),
        ok, {"defects": defects[:6]})


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
    # Both dispositions must also survive the accounting and derivation rules:
    # a bounded set must be derivable, and an UNRESOLVED record's partial
    # admitted set is intentionally not required to be.
    finite_ok = (vf["disposition"] == cc.DISPOSITION_PROVED
                 and "OSSL_ENCODER_free" in vf["target_set"]
                 and not cc.validate_edge_records(rf))
    unbounded_ok = (vu["disposition"] == cc.DISPOSITION_UNRESOLVED
                    and bool(vu["missing_property"])
                    and "OSSL_ENCODER_free" not in vu["target_set"]
                    and not cc.validate_edge_records(ru))
    return _case(
        "e-argument-derived-callback",
        "fixture graph whose writer slot is fed by a parameter",
        "finite caller set (one reachable caller passes an in-image callback) "
        "vs. an unbounded dynamic-export caller",
        "finite caller set -> bounded; unbounded caller set -> unresolved; "
        "both validate under the mutually redundant accounting rules",
        (f"finite={vf['disposition']}, unbounded={vu['disposition']}"),
        finite_ok and unbounded_ok,
        {"finite_target_set": vf["target_set"],
         "unbounded_missing_property": vu["missing_property"],
         "unbounded_admitted_targets":
             semantic_record(ru)["exclusion_accounting"]["admitted_targets"]})


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
    writer_subject = [e for e in view.get("excluded_writers") or ()
                      if e["reason"] == "writer-not-in-reachable-set"]
    has_witness = bool(witness) and all(
        e["reason"] == "no-reachable-writer"
        and e["row_kind"] == "target-drop"
        and e["evidence"].get("reachable_writers") == []
        for e in witness)
    has_subject = bool(writer_subject) and all(
        e["row_kind"] == "subject"
        and e["evidence"].get("would_store_targets") == ["dead_target"]
        for e in writer_subject)
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
        "the target drop is bound to a subject writer row and a defendable "
        "would_store_targets mapping; removing the drop makes the analyzer "
        "refuse",
        (f"drop={has_witness}, subject={has_subject}, "
         f"absent_from_target_set={absent}, accounted={clean}, "
         f"omission_refused={sensitivity}"),
        has_witness and has_subject and absent and clean and sensitivity,
        {"exclusions": witness, "excluded_writers": writer_subject})


def case_module_rename():
    _g1, r1 = classify()
    g2 = make_fixture()
    g2.name = "metamorphic-fixture-renamed.so"
    cc.apply_evidence_classes(g2, set(), g2.reach)
    r2 = cc.build_edge_records({g2.name: g2})
    oracle = cc.ReachabilityOracle({g2.name: g2}, {(g2.name, a) for a in g2.reach})
    r3 = cc.build_edge_records({g2.name: g2}, oracle)
    same = edge_view(r1) == edge_view(r2)
    clean = not cc.validate_edge_records(r2)
    clean_oracle = not cc.validate_edge_records(r3, oracle)
    return _case(
        "h-module-rename",
        "fixture graph named metamorphic-fixture.so",
        "rename the module to metamorphic-fixture-renamed.so; keep every "
        "function, edge and oracle fact",
        "the semantic graph is unchanged and both the record and oracle checks "
        "stay clean",
        (f"semantic_graph_equal={same}, clean={clean}, "
         f"clean_with_oracle={clean_oracle}"),
        same and clean and clean_oracle,
        {"records": len(r2), "oracle": oracle.describe()})


def case_target_set_shrunk():
    def drop_one(rec):
        rec["target_set"].pop()

    return _defect_case(
        "i-target-set-shrunk",
        "valid fixture record with two proved targets",
        "drop one entry from target_set only; leave the accounting block intact",
        drop_one,
        expected="mutually redundant accounting refuses the disagreement")


def case_chain_row_removed():
    def drop_chain(rec):
        rec["semantic_identity"]["provenance_chain"].pop()

    return _defect_case(
        "j-chain-row-removed",
        "valid fixture record with one derivation per proved target",
        "delete the provenance chain row for one claimed target",
        drop_chain,
        expected="a claimed target without a derivation is refused")


def case_chain_step_fabricated():
    def fabricate(rec):
        rec["semantic_identity"]["provenance_chain"][0]["derivation"][0] = {
            "step": "trust-me"}

    return _defect_case(
        "k-chain-step-fabricated",
        "valid fixture record",
        "replace a derivation step with {step: trust-me}",
        fabricate,
        expected="a step outside the closed vocabulary is refused")


def case_chain_step_payload_free():
    def strip(rec):
        rec["semantic_identity"]["provenance_chain"][0]["derivation"][0] = {
            "step": "linkage"}

    return _defect_case(
        "l-chain-step-payload-free",
        "valid fixture record",
        "replace a derivation step with {step: linkage} and no payload",
        strip,
        expected="a step that carries no evidence is refused")


def case_stale_admitted_accounting():
    def stale(rec):
        rec["exclusion_accounting"]["admitted_targets"].pop()

    return _defect_case(
        "m-stale-admitted-accounting",
        "valid fixture record",
        "remove one name from accounting.admitted_targets",
        stale,
        expected="target_set and admitted_targets must agree")


def case_exclusion_names_admitted_target():
    def exclude_admitted(rec):
        name = rec["target_set"][0]
        rec["exclusions"].append({
            "target": name,
            "reason": "target-not-in-reachable-set",
            "row_kind": "target-drop",
            "claim": {"kind": "target-not-in-reachable-set",
                      "module": rec["semantic_identity"]
                                ["artifact_local_witness"]["module"],
                      "subjects": [name]},
            "evidence": {"reachable_set_member": False, "symbol": name,
                         "reachable_basis": "pre-closure-direct",
                         "symbols_checked": [name]}})

    return _defect_case(
        "n-exclusion-names-admitted-target",
        "valid fixture record",
        "exclude a target that the same record claims as proved",
        exclude_admitted,
        expected="an admitted target cannot also be excluded")


def case_reachable_member_flipped():
    def flip(rec):
        for row in rec.get("excluded_writers") or ():
            if row.get("reason") == "writer-not-in-reachable-set":
                row["evidence"]["reachable_set_member"] = True

    return _defect_case(
        "o-reachable-member-flipped",
        "valid fixture record with an unreachable writer",
        "set the excluded writer subject row's reachable_set_member to True",
        flip,
        expected="a negative reachability claim requires exactly False")


def case_declared_absent_present():
    def present(rec):
        rec["exclusions"][0]["evidence"]["present"] = True

    g, oracle, rec = declared_record()
    present(rec)
    defects = cc.validate_edge_records([rec], oracle)
    return _case(
        "p-declared-absent-present",
        "valid declared-name-absent record with a structured target list",
        "set the declared-name-absent evidence present field to True",
        "an absent-name claim requires exactly False",
        ("refused: " + defects[0][:160]) if defects else "accepted",
        bool(defects), {"defects": defects[:4]})


def case_stale_excluded_accounting():
    def stale(rec):
        rec["exclusion_accounting"]["excluded_targets"].pop()

    return _defect_case(
        "q-stale-excluded-accounting",
        "valid fixture record",
        "remove one name from accounting.excluded_targets",
        stale,
        expected="stale exclusion accounting cannot hide a changed list")


def case_icf_duplicate_target():
    _g, records = classify()
    tampered = _json_clone(records)
    rec = semantic_record(tampered)
    rec["target_set"].append(rec["target_set"][0])
    defects = cc.validate_edge_records(tampered)
    return _case(
        "r-icf-duplicate-target",
        "valid fixture record",
        "add a duplicate of an admitted name to target_set, as identical-code "
        "folding produces",
        "names are compared as sets, so a duplicate name is not a disagreement",
        "clean" if not defects else f"refused: {defects[:2]}",
        not defects,
        {"target_set": rec["target_set"], "defects": defects[:4]})


def case_oracle_disagreement():
    g = make_fixture()
    cc.apply_evidence_classes(g, set(), g.reach)
    oracle = cc.ReachabilityOracle({g.name: g}, {(g.name, 0x500)})
    records = cc.build_edge_records({g.name: g}, oracle)
    defects = cc.validate_edge_records(records, oracle)
    audit = cc.reachability_exclusion_audit({g.name: g}, oracle)
    violations = [r for r in audit if r["in_final_upper_bound"]]
    writer_evidence = [
        e["evidence"] for e in semantic_record(records).get("excluded_writers") or ()
        if e.get("reason") == "writer-not-in-reachable-set"]
    ok = bool(defects) and bool(violations) and all(
        ev.get("reachable_basis") == "final-upper-bound"
        and ev.get("reachable_set_member") is True
        for ev in writer_evidence)
    return _case(
        "s-oracle-disagreement",
        "valid fixture record plus a final upper bound that reaches the "
        "excluded writer",
        "build the records against the oracle; the derivation-time direct set "
        "does not reach the writer, the final upper bound does",
        "the record is refused and the audit reports the writer as reachable",
        (f"defects={len(defects)}, audit_violations={len(violations)}"),
        ok,
        {"defects": defects[:6], "audit": audit})


def case_oracle_agreement():
    g = make_fixture()
    cc.apply_evidence_classes(g, set(), g.reach)
    oracle = cc.ReachabilityOracle({g.name: g}, {(g.name, a) for a in g.reach})
    records = cc.build_edge_records({g.name: g}, oracle)
    defects = cc.validate_edge_records(records, oracle)
    audit = cc.reachability_exclusion_audit({g.name: g}, oracle)
    violations = [r for r in audit if r["in_final_upper_bound"]]
    bases = {e["evidence"].get("reachable_basis")
             for e in semantic_record(records).get("excluded_writers") or ()
             if e.get("reason") == "writer-not-in-reachable-set"}
    ok = not defects and not violations and bases == {"final-upper-bound"}
    return _case(
        "t-oracle-agreement",
        "valid fixture record plus a final upper bound that does not reach the "
        "excluded writer",
        "build and validate the records against the agreeing oracle",
        "clean validation, no audit violation, and the evidence names the "
        "final upper bound as its basis",
        (f"defects={defects[:2]}, violations={len(violations)}, bases={bases}"),
        ok,
        {"defects": defects[:4], "audit": audit})


# --------------------------------------------------------------------------- #
# v1.2 hole controls (reviewer H1-H10)
# --------------------------------------------------------------------------- #
# Every check below has a control that changes verdict if and only if that
# check is disabled; the mutation table lives in edge-validator-hardening.json.
CALLER_MODULE = "metamorphic-caller-fixture.so"
CALLER_FUNCTIONS = {
    0x700: "site_func",
    0x1000: "target_ok",
    0x1100: "target_dropped",
    0x1200: "excluded_caller",
    0x1300: "reachable_caller",
    0x1400: "target_unreachable",
    0x2000: "alias_primary",
    0x3000: "reachable_target",
}
CALLER_REACH = (0x700, 0x1000, 0x1100, 0x1300, 0x3000)


class CallerFixture:
    name = CALLER_MODULE
    funcs = dict(CALLER_FUNCTIONS)
    start_set = set(CALLER_FUNCTIONS)
    all_syms = dict(CALLER_FUNCTIONS)
    names_at = {a: {n} for a, n in CALLER_FUNCTIONS.items()}


def caller_fixture(alias=False):
    g = CallerFixture()
    g.names_at = {a: set(n) for a, n in CALLER_FUNCTIONS.items()}
    if alias:
        g.names_at[0x3000] = {"reachable_target", "alias_secondary"}
    g.sites = {(0x700, 0x701, "call"): {
        "kind": "call", "func": 0x700, "addr": 0x701,
        "text": "call *%rax", "targets": {0x1000}, "unresolved": False,
        "reason": "reachable-caller target bounding",
        "class": "reachable-caller-target", "field_offsets": set(),
        "arg_deps": {0}, "arg_targets": {0x1100},
        "reachable_caller_bound": {
            "reachable_callers": [{
                "function": "0x1300", "symbol": "reachable_caller",
                "reachable": True, "reason": None,
                "call_sites": [{"call_site": "0x1301", "arguments": [{
                    "argument": 0, "argument_index": 0,
                    "value": ["0x1000"], "targets": ["0x1000"],
                    "non_image_values": [], "unresolved": False,
                    "witness_instruction": [
                        {"addr": "0x12ff", "text": "lea"}]}]}],
                "contributed_targets": ["0x1000"]}],
            "excluded_callers": [{
                "function": "0x1200", "symbol": "excluded_caller",
                "reachable": False,
                "in_reachable_set": False, "reason": "x",
                "in_image_references": [],
                "call_sites": [{"call_site": "0x1201", "arguments": [{
                    "argument": 0, "argument_index": 0,
                    "value": [], "targets": ["0x1100"],
                    "non_image_values": [], "unresolved": True,
                    "witness_instruction": [
                        {"addr": "0x11ff", "text": "mov"}]}]}],
                "contributed_targets": ["0x1100"]}],
            "bounded_targets": ["0x1000"]}}}
    return g


def caller_oracle(g, extra=()):
    return cc.ReachabilityOracle(
        {g.name: g},
        {(g.name, a) for a in CALLER_REACH} | {(g.name, a) for a in extra})


def caller_record(alias=False, oracle=None):
    g = caller_fixture(alias=alias)
    if oracle is None:
        oracle = caller_oracle(g)
    rec = cc._edge_record(g, g.sites[(0x700, 0x701, "call")], 1, oracle)
    return g, oracle, rec


def declared_record(target="target_unreachable", listed=None,
                    name="unrelated_absent_name", include_targets=True,
                    oracle=None):
    """A record whose only exclusion is `declared-name-absent`.

    The target must be a candidate that the final upper bound does not reach;
    the declared name must be absent from the image.  `target_unreachable` is an
    image symbol that the fixture's oracle does not reach.
    """
    g, oracle, rec = caller_record(oracle=oracle)
    listed = [target] if listed is None else listed
    evidence = {"declared_name": name, "present": False}
    if include_targets:
        evidence["targets"] = list(listed)
    rec["exclusions"] = [{
        "target": target,
        "reason": "declared-name-absent",
        "row_kind": "target-drop",
        "claim": {"kind": "declared-name-absent", "module": CALLER_MODULE,
                  "subjects": [name]},
        "evidence": evidence,
    }]
    rec["candidate_source"]["targets"] = sorted({"target_ok", target})
    rec["candidate_source"]["excluded_callers"][0][
        "contributed_targets"] = []
    rec["candidate_source"]["excluded_callers"][0]["call_sites"] = []
    rec["exclusion_accounting"].update({
        "candidate_targets": rec["candidate_source"]["targets"],
        "admitted_targets": ["target_ok"],
        "excluded_targets": [target],
        "unaccounted_targets": [],
    })
    return g, oracle, rec


# --------------------------------------------------------------------------- #
# round 4: per-call-site attribution for every caller, and the conservative
# admission of a candidate that no caller row attributes
# --------------------------------------------------------------------------- #
ATTRIBUTION_FUNCTIONS = {
    0x10: "root",
    0x20: "reachable_caller",
    0x30: "excluded_caller",
    0x40: "site_func",
    0x50: "target_ok",
    0x60: "target_dropped",
}
ATTRIBUTION_MODULE = "metamorphic-attribution-fixture.so"


class _AttributionPrecision:
    """The argument-summary state the production attribution rule reads."""

    import_addrs = set()

    def __init__(self, calls, insns, summary=None):
        self.calls = calls
        self.insns_by_func = insns
        self.summary = summary or {}

    def summary_vals(self, f, k):
        return set(self.summary.get(f, {}).get(k, ()))


class _AttributionGraph:
    name = ATTRIBUTION_MODULE
    funcs = dict(ATTRIBUTION_FUNCTIONS)
    start_set = set(ATTRIBUTION_FUNCTIONS)
    all_syms = dict(ATTRIBUTION_FUNCTIONS)
    names_at = {a: {n} for a, n in ATTRIBUTION_FUNCTIONS.items()}
    dynamic_defs = {}
    relocs = []
    taken_code = set()
    taken_data = set()
    slot_funcs = {}
    slot_data = {}
    slot_syms = {}
    field_stores = {}
    unknown_call_arg_targets = set()
    import_addrs = set()
    evidence_classes = {}
    residual_sites = []
    resolved_targets = set()
    precision_counts = {}

    @property
    def slot_func_targets(self):
        return set()

    def section_of(self, _a):
        return ".text"

    def static_slot(self, _a):
        return None

    def seam_symbol(self, _a):
        return None

    def cstring_at(self, _a):
        return None

    def is_data(self, _a):
        return False


def _attribution_graph(excluded_has_call_site=True):
    """A site whose callback parameter is passed by two in-image callers.

    The reachable caller passes a literal; the excluded caller forwards its own
    parameter, which its argument summary resolves to ``target_dropped``.  With
    ``excluded_has_call_site=False`` the excluded caller is still a direct
    caller but has no recorded call arguments, so it has an empty call-site
    list and contributes nothing.
    """
    g = _AttributionGraph()
    insns = {
        0x20: [(0x24, "lea    0x2c8(%rip),%rsi  # 50 <target_ok>"),
               (0x25, "call   0x40 <site_func>")],
        0x30: [(0x35, "call   0x40 <site_func>")],
    }
    calls = [
        (0x20, 0x40, [cc.PValue(), cc.PValue.one(0x50)], 0x25),
    ]
    if excluded_has_call_site:
        calls.append((0x30, 0x40, [cc.PValue(), cc.PValue.one(("arg", 1))],
                      0x35))
    g.direct = {0x20: {0x40}} if excluded_has_call_site \
        else {0x30: {0x40}}
    g.precision = _AttributionPrecision(
        calls, insns, {0x30: {1: {0x60}}})
    g.sites = {(0x40, 0x41, "call"): {
        "kind": "call", "func": 0x40, "addr": 0x41,
        "text": "call *%rbp", "targets": {0x50, 0x60},
        "unresolved": True, "reason": "reg-value-partial[arg]",
        "class": "materialised", "field_offsets": set(), "seam": None,
        "arg_deps": {1}, "arg_targets": {0x50, 0x60}}}
    return g


def _attribution_oracle(g):
    return cc.ReachabilityOracle(
        {g.name: g},
        {(g.name, a) for a in (0x10, 0x20, 0x40, 0x50, 0x60)})


def attribution_record(excluded_has_call_site=True):
    g = _attribution_graph(excluded_has_call_site)
    cc.apply_evidence_classes(g, set(), {0x10, 0x20, 0x40})
    oracle = _attribution_oracle(g)
    rec = cc._edge_record(g, g.sites[(0x40, 0x41, "call")], 1, oracle)
    return g, oracle, rec


def zero_attribution_record():
    """A bound whose rows exist but attribute nothing."""
    g = _attribution_graph(False)
    g.sites = {(0x40, 0x41, "call"): {
        "kind": "call", "func": 0x40, "addr": 0x41,
        "text": "call *%rbp", "targets": set(), "unresolved": False,
        "reason": "reachable-caller target bounding",
        "class": "reachable-caller-target", "field_offsets": set(),
        "arg_deps": {1}, "arg_targets": {0x50, 0x60},
        "reachable_caller_bound": {
            "schema": cc.REACHABLE_CALLER_SCHEMA,
            "reachable_callers": [{
                "function": "0x20", "symbol": "reachable_caller",
                "reachable": True, "reason": None, "call_sites": [],
                "contributed_targets": []}],
            "excluded_callers": [{
                "function": "0x30", "symbol": "excluded_caller",
                "reachable": False, "in_reachable_set": False,
                "reason": "x", "in_image_references": [],
                "call_sites": [], "contributed_targets": []}],
            "bounded_targets": []}}}
    oracle = _attribution_oracle(g)
    rec = cc._edge_record(g, g.sites[(0x40, 0x41, "call")], 1, oracle)
    return g, oracle, rec


def admit_attribution_record():
    """The required empty-call-site fixture, built at the record level.

    The excluded caller row exists but has an empty call-site list and an empty
    contribution, so nothing attributes ``target_dropped``.  It must be
    admitted, never dropped.
    """
    g = _attribution_graph(False)
    g.sites = {(0x40, 0x41, "call"): {
        "kind": "call", "func": 0x40, "addr": 0x41,
        "text": "call *%rbp", "targets": {0x50}, "unresolved": False,
        "reason": "reachable-caller target bounding",
        "class": "reachable-caller-target", "field_offsets": set(),
        "arg_deps": {1}, "arg_targets": {0x50, 0x60},
        "reachable_caller_bound": {
            "schema": cc.REACHABLE_CALLER_SCHEMA,
            "reachable_callers": [{
                "function": "0x20", "symbol": "reachable_caller",
                "reachable": True, "reason": None,
                "call_sites": [{"call_site": "0x25", "arguments": [{
                    "argument_index": 1, "targets": ["0x50"],
                    "value": ["0x50"], "non_image_values": [],
                    "unresolved": False, "witness_instruction": []}]}],
                "contributed_targets": ["0x50"]}],
            "excluded_callers": [{
                "function": "0x30", "symbol": "excluded_caller",
                "reachable": False, "in_reachable_set": False,
                "reason": "x", "in_image_references": [],
                "call_sites": [], "contributed_targets": []}],
            "bounded_targets": ["0x50"], "unattributed_targets": ["0x60"]}}}
    oracle = _attribution_oracle(g)
    rec = cc._edge_record(g, g.sites[(0x40, 0x41, "call")], 1, oracle)
    return g, oracle, rec


def case_caller_attribution_from_summary():
    g, oracle, rec = attribution_record()
    excluded = rec["candidate_source"]["excluded_callers"][0]
    witness = excluded["call_sites"][0]["arguments"][0]
    dropped = [e["target"] for e in rec["exclusions"]
               if e["reason"] == "not-contributed-by-reachable-callers"]
    ok = (not cc.validate_edge_records([rec], oracle)
          and dropped == ["target_dropped"]
          and witness.get("argument_index") == 1
          and witness.get("targets") == ["target_dropped"]
          and excluded["contributed_targets"] == ["target_dropped"])
    return _case(
        "au-excluded-caller-attribution",
        "two in-image callers; the excluded caller forwards its own parameter",
        "resolve the excluded caller's contribution through its argument "
        "summary (the same expansion that produced the site's flat targets)",
        "the dropped target is recomputable from the excluded caller's "
        "per-call-site witness and the record validates cleanly",
        (f"dropped={dropped}, witness_targets={witness.get('targets')}, "
         f"contributed={excluded['contributed_targets']}"),
        ok, {"candidate_source": _clean(rec["candidate_source"])})


def case_unattributed_candidate_admitted():
    g, oracle, rec = admit_attribution_record()
    admitted = rec["exclusion_accounting"]["admitted_targets"]
    admissions = rec.get("unattributed_admissions") or []
    ok = (not cc.validate_edge_records([rec], oracle)
          and not rec["exclusions"]
          and admitted == ["target_dropped", "target_ok"]
          and [a["target"] for a in admissions] == ["target_dropped"])
    return _case(
        "av-unattributed-target-admitted",
        "the excluded caller has no recorded call arguments (empty call-site "
        "list), so nothing attributes target_dropped",
        "build the record with an empty excluded-caller row",
        "target_dropped is admitted, not dropped, and listed in "
        "unattributed_admissions; the record validates cleanly",
        (f"exclusions={rec['exclusions']}, admitted={admitted}, "
         f"admissions={[a['target'] for a in admissions]}"),
        ok, {"unattributed_admissions": admissions})


def case_zero_attribution_unresolved():
    g, oracle, rec = zero_attribution_record()
    ok = (rec["disposition"] == cc.DISPOSITION_UNRESOLVED
          and rec["target_set"] == []
          and (rec.get("missing_property") or "").startswith(
              "caller attribution incomplete:")
          and not rec["exclusions"]
          and not cc.validate_edge_records([rec], oracle))
    return _case(
        "aw-wholly-unattributable-unresolved",
        "a bound whose caller rows exist but attribute no candidate",
        "build the edge record",
        "no bounded set is emitted: the record is UNRESOLVED and names the "
        "incomplete attribution",
        (f"disposition={rec['disposition']}, "
         f"missing_property={rec.get('missing_property')!r}"),
        ok, {"missing_property": rec.get("missing_property"),
             "unattributed_admissions": rec.get("unattributed_admissions")})


def case_attribution_witness_mismatch():
    _g, oracle, rec = caller_record()
    rec["candidate_source"]["excluded_callers"][0]["call_sites"] = []
    return _verdict_case(
        "ax-contribution-without-witness",
        "an excluded caller keeps its contributed target but loses the call "
        "site that would witness it",
        "the contribution must equal the union of its per-call-site targets",
        cc.validate_edge_records([rec], oracle))


def case_unattributed_admission_forged():
    _g, oracle, rec = admit_attribution_record()
    if rec.get("unattributed_admissions"):
        rec["unattributed_admissions"][0]["target"] = "target_ok"
    return _verdict_case(
        "ay-forged-unattributed-admission",
        "an unattributed admission names a target a reachable caller "
        "contributes",
        "an admission must be genuinely unattributed and listed in both places",
        cc.validate_edge_records([rec], oracle))


def case_zero_attribution_proved_refused():
    _g, oracle, rec = zero_attribution_record()
    candidates = sorted(rec["candidate_source"]["targets"])
    rec["disposition"] = cc.DISPOSITION_PROVED
    rec["target_set"] = candidates
    rec["target_set_claim"] = True
    rec["target_reachability"] = "claimed"
    rec["missing_property"] = None
    rec["exclusion_accounting"]["admitted_targets"] = candidates
    rec["semantic_identity"]["provenance_chain"] = [
        {"target": t,
         "derivation": [{"step": "unattributed-admission",
                         "reason": "forged"}]}
        for t in candidates]
    return _verdict_case(
        "az-zero-attribution-proved",
        "a record with zero attribution is forced to claim PROVED_TARGET_SET",
        "a caller-bound narrowing with no attributable candidate cannot claim "
        "a bounded set",
        cc.validate_edge_records([rec], oracle))


def _target_claim(target, subject, checked=None):
    return {
        "target": target,
        "reason": "target-not-in-reachable-set",
        "row_kind": "target-drop",
        "claim": {"kind": "target-not-in-reachable-set",
                  "module": CALLER_MODULE, "subjects": [subject]},
        "evidence": {"reachable_set_member": False, "symbol": subject,
                     "reachable_basis": "final-upper-bound",
                     "symbols_checked": ([subject] if checked is None
                                          else checked)}}


def _verdict_case(case_id, transformation, expected, defects):
    ok = bool(defects)
    return _case(
        case_id, "caller-bound / semantic fixture", transformation, expected,
        ("refused: " + defects[0][:160]) if ok else "accepted",
        ok, {"defects": defects[:4]})


def case_h10_caller_bound_positive():
    g, oracle, rec = caller_record()
    defects = cc.validate_edge_records([rec], oracle)
    audit = cc.reachability_exclusion_audit({g.name: g}, oracle, [rec])
    dropped_reachable = oracle.is_reachable(g.name, "target_dropped")[0]
    caller_absent = oracle.is_reachable(g.name, "excluded_caller")[0] is False
    ok = (not defects and not [r for r in audit if r["violation"]]
          and dropped_reachable and caller_absent)
    return _case(
        "u-v110-caller-bound-clean",
        "caller-bound fixture (v1m shape)",
        "drop 178-style targets contributed only by one genuinely unreachable "
        "caller, while the dropped targets themselves are reachable",
        "caller-scoped claim validates cleanly with no oracle violation",
        (f"defects={len(defects)}, violations="
         f"{len([r for r in audit if r['violation']])}, "
         f"dropped_reachable={dropped_reachable}, "
         f"caller_absent={caller_absent}"),
        ok, {"defects": defects[:4]})


def case_h1_target_evidence_binding():
    _g, oracle, rec = caller_record()
    rec["exclusions"] = [_target_claim("reachable_target", "excluded_caller")]
    rec["candidate_source"]["targets"] = ["reachable_target", "target_ok"]
    rec["exclusion_accounting"].update({
        "candidate_targets": ["reachable_target", "target_ok"],
        "excluded_targets": ["reachable_target"]})
    return _verdict_case(
        "v-target-evidence-binding",
        "exclude a reachable target whose evidence names a different absent "
        "symbol",
        "claims about exactly the excluded target are refused",
        cc.validate_edge_records([rec], oracle))


def case_h2_claim_module_binding():
    g, _oracle, rec = caller_record()
    other = CallerFixture()
    other.name = "metamorphic-other-fixture.so"
    other.funcs = {0x1300: "reachable_caller", 0x9000: "other_func"}
    other.all_syms = dict(other.funcs)
    other.names_at = {a: {n} for a, n in other.funcs.items()}
    oracle = cc.ReachabilityOracle(
        {g.name: g, other.name: other},
        {(g.name, a) for a in CALLER_REACH} | {(other.name, 0x1300)})
    for row in rec["exclusions"] + (rec.get("excluded_callers") or []):
        row["claim"]["module"] = other.name
    return _verdict_case(
        "w-claim-module-binding",
        "rebind the claim to a different DSO that also reaches the named caller",
        "a claim whose module is not the record's module is refused",
        cc.validate_edge_records([rec], oracle))


def case_h3_icf_alias():
    _g, oracle, rec = caller_record(alias=True)
    rec["exclusions"] = [_target_claim("alias_secondary", "alias_secondary")]
    rec["candidate_source"]["targets"] = ["alias_secondary", "target_ok"]
    rec["exclusion_accounting"].update({
        "candidate_targets": ["alias_secondary", "target_ok"],
        "excluded_targets": ["alias_secondary"]})
    return _verdict_case(
        "x-icf-alias-escape",
        "exclude an ICF alias recorded at a reachable address",
        "every name at a reachable address is reachable, so the alias is "
        "refused",
        cc.validate_edge_records([rec], oracle))


def case_h4_forged_caller_count():
    _g, oracle, rec = caller_record()
    rec["exclusions"] = [_target_claim("excluded_caller", "excluded_caller",
                                       checked=[])]
    rec["exclusions"][0]["evidence"]["reachable_caller_count"] = 0
    rec["candidate_source"]["targets"] = ["excluded_caller", "target_ok"]
    rec["exclusion_accounting"].update({
        "candidate_targets": ["excluded_caller", "target_ok"],
        "excluded_targets": ["excluded_caller"]})
    return _verdict_case(
        "y-forged-caller-count",
        "claim reachable_caller_count=0 with an empty symbols_checked list",
        "the exemption is gone; the covered symbols are mandatory",
        cc.validate_edge_records([rec], oracle))


def case_h5_no_writer_self_contradiction():
    _g, oracle, rec = caller_record()
    rec["exclusions"] = [{
        "target": "target_dropped", "reason": "no-reachable-writer",
        "claim": {"kind": "no-reachable-writer", "module": CALLER_MODULE,
                  "subjects": []},
        "evidence": {"writer": "w",
                     "derived_targets": ["target_dropped", "target_ok"],
                     "reachable_writers": []}}]
    return _verdict_case(
        "z-no-writer-self-contradiction",
        "exclude a target that the claim's own derived_targets contain",
        "a self-contradicting writer claim is refused",
        cc.validate_edge_records([rec], oracle))


def case_h5_declared_name_unrelated():
    _g, oracle, rec = declared_record(target="target_dropped",
                                      listed=["target_dropped"])
    return _verdict_case(
        "z2-declared-name-unrelated",
        "exclude a reachable target under an unrelated absent declared name",
        "a declared-name claim cannot map a reachable target to an absent name",
        cc.validate_edge_records([rec], oracle))


def case_declared_name_free_text():
    _g, oracle, rec = declared_record(include_targets=False)
    rec["exclusions"][0]["claim"]["target_derivation"] = (
        "a free-text claim is not a mapping")
    return _verdict_case(
        "ag-declared-name-free-text",
        "replace evidence.targets with a free-text target_derivation",
        "a free-text derivation is not a structured target mapping",
        cc.validate_edge_records([rec], oracle))


def case_declared_name_target_membership():
    _g, oracle, rec = declared_record(listed=["target_ok"])
    return _verdict_case(
        "at-declared-name-target-not-listed",
        "exclude a candidate target that evidence.targets does not list",
        "the dropped target must be one of the structured evidence.targets",
        cc.validate_edge_records([rec], oracle))


def case_declared_name_targets_not_candidates():
    _g, oracle, rec = declared_record(
        listed=["target_unreachable", "invented_name"])
    return _verdict_case(
        "ah-declared-name-targets-not-candidates",
        "list a declared target that candidate_source does not enumerate",
        "every evidence.targets entry must be a candidate",
        cc.validate_edge_records([rec], oracle))


def case_declared_name_structured_clean():
    _g, oracle, rec = declared_record()
    defects = cc.validate_edge_records([rec], oracle)
    audit = cc.reachability_exclusion_audit({_g.name: _g}, oracle, [rec])
    ok = (not defects and not [r for r in audit if r["violation"]])
    return _case(
        "ai-declared-name-structured-clean",
        "an absent declared name mapped to an unreachable candidate target",
        "use a structured evidence.targets list",
        "the structured mapping validates cleanly and has no audit violation",
        (f"defects={len(defects)}, violations="
         f"{len([r for r in audit if r['violation']])}"),
        ok, {"defects": defects[:4]})


def case_target_drop_with_subject_row():
    _g, oracle, rec = caller_record()
    rec["exclusions"][0]["row_kind"] = "subject"
    return _verdict_case(
        "aj-target-drop-with-subject-row",
        "label a target drop in exclusions[] as a caller/writer subject row",
        "a target drop cannot be justified by a caller/writer claim",
        cc.validate_edge_records([rec], oracle))


def case_writer_used_as_target_drop():
    _g, oracle, rec = caller_record()
    rec["exclusions"].append({
        "target": "target_dropped",
        "reason": "writer-not-in-reachable-set",
        "row_kind": "target-drop",
        "claim": {"kind": "writer-not-in-reachable-set",
                  "module": CALLER_MODULE,
                  "subjects": ["excluded_caller"]},
        "evidence": {"reachable_set_member": False,
                     "reachable_basis": "final-upper-bound",
                     "symbol": "excluded_caller",
                     "symbols_checked": ["excluded_caller"],
                     "would_store_targets": ["target_dropped"]}})
    return _verdict_case(
        "ak-writer-used-as-target-drop",
        "put a writer-not-in-reachable-set row in exclusions[]",
        "the reason vocabulary is split by row kind",
        cc.validate_edge_records([rec], oracle))


def case_forged_contributed_targets():
    _g, oracle, rec = caller_record()
    rec["candidate_source"]["callers"][0]["contributed_targets"] = [
        "target_ok", "target_dropped"]
    rec["candidate_source"]["callers"][0]["call_sites"][0][
        "arguments"][0]["targets"] = ["target_ok", "target_dropped"]
    for row in rec["exclusions"]:
        if row["reason"] == "not-contributed-by-reachable-callers":
            row["claim"]["reachable_callers"][0]["contributed_targets"] = [
                "target_ok", "target_dropped"]
    return _verdict_case(
        "al-forged-contributed-targets",
        "both the claim and candidate_source make a reachable caller "
        "contribute the dropped target",
        "the target is then not droppable and the admitted set is not the "
        "reachable image set",
        cc.validate_edge_records([rec], oracle))


def case_argument_source_mapping_required():
    _g, oracle, rec = caller_record()
    del rec["candidate_source"]["callers"]
    return _verdict_case(
        "am-argument-source-mapping-required",
        "omit the caller mapping from an argument-targets candidate source",
        "the drop is not recomputable without the mapping",
        cc.validate_edge_records([rec], oracle))


def case_dropped_target_not_excluded_contribution():
    _g, oracle, rec = caller_record()
    rec["candidate_source"]["excluded_callers"][0][
        "contributed_targets"] = ["target_ok"]
    rec["candidate_source"]["excluded_callers"][0][
        "call_sites"][0]["arguments"][0]["targets"] = ["target_ok"]
    return _verdict_case(
        "an-dropped-target-not-excluded-contribution",
        "exclude a target that no excluded caller contributes",
        "the drop must be justified by an excluded caller that produces it",
        cc.validate_edge_records([rec], oracle))


def case_candidates_equal_admitted_plus_excluded():
    _g, oracle, rec = caller_record()
    rec["exclusion_accounting"]["candidate_enumeration"] = "not-applicable"
    rec["candidate_source"]["targets"].append("extra_candidate")
    rec["exclusion_accounting"]["candidate_targets"].append(
        "extra_candidate")
    return _verdict_case(
        "ao-candidates-equal-admitted-plus-excluded",
        "add a candidate that is neither admitted nor excluded",
        "candidates must equal admitted plus excluded",
        cc.validate_edge_records([rec], oracle))


def case_writer_would_store_binding():
    _g, oracle, rec = caller_record()
    # Use the semantic fixture for the writer-subject row.
    _sg, srecords = classify()
    rec = semantic_record(json.loads(json.dumps(srecords)))
    for row in rec.get("excluded_writers") or ():
        if row.get("reason") == "writer-not-in-reachable-set":
            row["evidence"].pop("would_store_targets", None)
    defects = cc.validate_edge_records([rec])
    return _case(
        "ap-writer-would-store-binding",
        "remove would_store_targets from a writer subject row",
        "the writer subject is bound to the site's targets",
        "a writer subject row without would_store_targets is refused",
        ("refused: " + defects[0][:160]) if defects else "accepted",
        bool(defects), {"defects": defects[:4]})


def case_target_reachability_derived():
    _g, oracle, rec = caller_record()
    rec["target_reachability"] = "not-claimed"
    return _verdict_case(
        "aq-target-reachability-derived",
        "mark a PROVED_TARGET_SET record's target_reachability not-claimed",
        "target_reachability is derived from the disposition",
        cc.validate_edge_records([rec], oracle))


def case_sidecar_default_workdir():
    class _A:
        output = "/tmp/receipt.json"
        edge_records = None

    workdir = Path("/tmp/corpus-workdir")
    resolved = cc._edge_records_path(_A(), Path("/tmp"), "ab" * 32, workdir)
    ok = (resolved.parent == workdir
          and resolved.name.startswith("edge-records."))
    return _case(
        "ar-sidecar-default-workdir",
        "an --output outside the workdir",
        "resolve the default sidecar path",
        "the default is under the workdir, never beside --output",
        str(resolved), ok, {"resolved": str(resolved)})


def case_tool_identity_sha256():
    identity = cc._tool_identity()
    ok = (len(identity.get("sha256") or "") == 64
          and identity.get("schema") == cc.EDGE_RECORD_SCHEMA)
    return _case(
        "as-tool-identity-sha256",
        "the validator identity bound into the receipt",
        "read the tool identity",
        "the receipt tool block carries a 64-hex sha256 and the record schema",
        (f"sha256_len={len(identity.get('sha256') or '')}, "
         f"schema={identity.get('schema')}"),
        ok, {"tool": identity})


def _semantic_oracle_records():
    g = make_fixture()
    cc.apply_evidence_classes(g, set(), g.reach)
    oracle = cc.ReachabilityOracle({g.name: g}, {(g.name, a) for a in g.reach})
    records = cc.build_edge_records({g.name: g}, oracle)
    return g, oracle, records


def case_h6_semantic_excluded_caller():
    g, oracle, records = _semantic_oracle_records()
    tampered = _json_clone(records)
    rec = semantic_record(tampered)
    rec["candidate_source"]["rows"].append({
        "caller": g.funcs[0x300], "call_site": "0x999", "included": False,
        "reason": "caller-not-in-reachable-set", "targets": []})
    return _verdict_case(
        "aa-semantic-excluded-caller",
        "mark a semantic call-site row included:false for a reachable caller",
        "the candidate-source caller row is audited separately from the "
        "auxiliary exclusion list",
        cc.validate_edge_records(tampered, oracle))


def case_h6_caller_bound_dropped_target():
    _g, oracle, rec = caller_record()
    for row in rec["exclusions"]:
        if row["reason"] == "not-contributed-by-reachable-callers":
            row["claim"]["reachable_callers"][0]["contributed_targets"] = []
    return _verdict_case(
        "ab-caller-bound-dropped-target",
        "the claim omits the reachable caller's contribution while "
        "candidate_source records it",
        "the claim's per-caller mapping must equal candidate_source's",
        cc.validate_edge_records([rec], oracle))


def case_h7_candidate_deleted():
    _g, oracle, rec = caller_record()
    rec["exclusions"] = []
    rec["exclusion_accounting"].update({
        "excluded_targets": [], "candidate_targets": ["target_ok"]})
    return _verdict_case(
        "ac-candidate-and-exclusion-deleted",
        "delete an exclusion and its candidate from the accounting block",
        "candidate_source still names it, so the deletion is refused",
        cc.validate_edge_records([rec], oracle))


def case_h8_vacuous_target_set():
    class _V:
        name = "vacuous.so"
        funcs = {0x10: "empty_func", 0x20: "unused"}
        sites = {(0x10, 0x11, "call"): {
            "kind": "call", "func": 0x10, "addr": 0x11,
            "text": "call *%rax", "targets": set(), "unresolved": False,
            "reason": None, "class": "field", "field_offsets": set(),
            "seam": None, "arg_deps": set()}}

    rec = cc.build_edge_records({"vacuous.so": _V()})[0]
    ok = (rec["disposition"] == cc.DISPOSITION_UNRESOLVED
          and rec.get("disposition_demotion") == "empty-target-set"
          and bool(rec.get("missing_property")))
    return _case(
        "ad-vacuous-target-set-demoted",
        "a site with no admitted target and no ABI contract",
        "classify the site",
        "an empty target set is never PROVED_TARGET_SET",
        f"disposition={rec['disposition']}, "
        f"demotion={rec.get('disposition_demotion')}",
        ok, {"missing_property": rec.get("missing_property")})


def case_h8_question_function():
    class _N:
        name = "nosym.so"
        funcs = {}
        sites = {(0x10, 0x11, "call"): {
            "kind": "call", "func": 0x10, "addr": 0x11,
            "text": "call *%rax", "targets": {0x99}, "unresolved": False,
            "reason": None, "class": "field", "field_offsets": set(),
            "seam": None, "arg_deps": set()}}

    rec = cc.build_edge_records({"nosym.so": _N()})[0]
    ok = (rec["disposition"] == cc.DISPOSITION_UNRESOLVED
          and rec.get("disposition_demotion") == "no-defining-symbol")
    return _case(
        "ae-question-function-demoted",
        "a site whose containing function has no symbol",
        "classify the site",
        "a definition-less function is never PROVED_TARGET_SET or "
        "CONTRACT_BOUNDED",
        f"defining={rec['semantic_identity']['defining_function']!r}, "
        f"disposition={rec['disposition']}",
        ok, {"missing_property": rec.get("missing_property")})


def case_h9_duplicate_edge_id():
    _g, oracle, rec = caller_record()
    defects = cc.validate_edge_records([_json_clone(rec), _json_clone(rec)],
                                       oracle)
    ok = any("duplicate edge_id" in d for d in defects)
    return _case(
        "af-duplicate-edge-id",
        "two records with the same module/function/kind/role/ordinal",
        "validate the record set",
        "a duplicate edge identity is refused",
        ("refused: duplicate edge_id" if ok else "accepted"),
        ok, {"defects": defects[:4]})


# --------------------------------------------------------------------------- #
# v1.5: monotone bound and least-fixed-point residual admission
# --------------------------------------------------------------------------- #
# These cases exercise the *closure* rather than a single edge record.  They
# use the production `build_graph`, `unresolved_site_bound`, `analysis_identity`
# and `closure_refusals` functions; only the graph objects are synthetic.


class NestedDispatchGraph:
    """root -> dispatch A (unresolved) -> B -> dispatch B (unresolved) -> C.

    B has no direct predecessor: it is reached only through A's residual
    admission, so a one-pass closure never scans B's own unresolved site.
    """

    name = "nested-dispatch-fixture.so"
    funcs = {0x10: "root", 0x20: "dispatch_a", 0x30: "b",
             0x40: "dispatch_b", 0x50: "c"}
    start_set = set(funcs)
    direct = {0x10: {0x20}, 0x20: set(), 0x30: {0x40}, 0x40: set(),
              0x50: set()}
    taken_code = set()
    taken_data = set()
    address_taken_union = set()
    dynamic_reloc_targets = set()
    field_stores = {}
    unknown_call_arg_targets = set()
    sites = {}


def nested_dispatch_fixture():
    g = NestedDispatchGraph()
    g.sites = {
        (0x20, 0x21, "call"): {
            "kind": "call", "func": 0x20, "addr": 0x21,
            "text": "call *%rax", "targets": set(), "unresolved": True,
            "reason": "reg-top", "class": "materialised",
            "arg_targets": {0x30}},
        (0x40, 0x41, "call"): {
            "kind": "call", "func": 0x40, "addr": 0x41,
            "text": "call *%rax", "targets": set(), "unresolved": True,
            "reason": "reg-top", "class": "materialised",
            "arg_targets": {0x50}},
    }
    return g


def case_fixpoint_reaches_nested_unresolved():
    g = nested_dispatch_fixture()
    one_pass = cc.build_graph({g.name: g}, {(g.name, 0x10)}, {}, max_rounds=1)
    g = nested_dispatch_fixture()
    fixpoint = cc.build_graph({g.name: g}, {(g.name, 0x10)}, {})
    c = (g.name, 0x50)
    ok = (c not in one_pass["upper_reachable"]
          and one_pass["converged"] is False
          and c in fixpoint["upper_reachable"]
          and fixpoint["converged"] is True
          and (g.name, 0x30) not in fixpoint["direct_reachable"])
    return _case(
        "ag-fixpoint-reaches-nested-unresolved",
        "synthetic graph root -> dispatch A (unresolved) -> B -> dispatch B "
        "(unresolved) -> C, with B reachable only through A's residual "
        "admission",
        "close the graph once (max_rounds=1) and to its least fixed point",
        "the single pass omits C and reports non-convergence; the fixpoint "
        "includes C",
        (f"single_pass_has_C={c in one_pass['upper_reachable']}, "
         f"single_pass_converged={one_pass['converged']}, "
         f"fixpoint_has_C={c in fixpoint['upper_reachable']}, "
         f"fixpoint_rounds={fixpoint['closure_rounds']}"),
        ok,
        {"single_pass_round_sizes": one_pass["round_sizes"],
         "fixpoint_round_sizes": fixpoint["round_sizes"],
         "fixpoint_sites_scanned": fixpoint["sites_scanned_per_round"]})


class MonotoneBoundGraph:
    """One module whose evidence sources are pairwise distinct.

    ``0x50`` is admitted only by the in-image dynamic-relocation widening --
    the real ``CRYPTO_cbc128_encrypt`` shape: a function reached through a GOT
    slot that the pre-repair class-specific bound could not contain.
    """

    name = "monotone-bound-fixture.so"
    funcs = {0x10: "root", 0x20: "materialised_target",
             0x30: "field_target", 0x40: "argument_target",
             0x50: "got_target"}
    start_set = set(funcs)
    taken_code = {0x20}
    taken_data = {0x30}
    address_taken_union = {0x20, 0x30, 0x50}
    dynamic_reloc_targets = {0x50}
    field_stores = {0x20: {0x30}}
    unknown_call_arg_targets = {0x40}
    sites = {}


def case_monotone_bound_under_classification_loss():
    g = MonotoneBoundGraph()
    proved = {"kind": "call", "func": 0x10, "addr": 0x11,
              "text": "call *%rax", "targets": {0x20, 0x50},
              "unresolved": False, "class": "PROVED_TARGET_SET",
              "arg_targets": set()}
    residual = {**proved, "unresolved": True, "class": "materialised",
                "targets": set()}
    bound = cc.unresolved_site_bound(g, residual)
    class_sets = {
        "taken_code": set(g.taken_code),
        "taken_data": set(g.taken_data),
        "address_taken_union": set(g.address_taken_union),
        "dynamic_reloc_targets": set(g.dynamic_reloc_targets),
        "field_stores": {v for vs in g.field_stores.values() for v in vs},
        "unknown_call_arg_targets": set(g.unknown_call_arg_targets),
        "site_targets": set(proved["targets"]) | set(proved["arg_targets"]),
    }
    subsets = {k: sorted(v) for k, v in class_sets.items() if not v <= bound}
    proved_kept = set(proved["targets"]) <= bound
    ok = proved_kept and not subsets
    return _case(
        "ah-monotone-bound-under-classification-loss",
        "a site classified PROVED_TARGET_SET with {0x20, 0x50}, then "
        "UNRESOLVED with the same resolver targets dropped",
        "re-classify the site and recompute the residual bound",
        "the unresolved bound is a superset of the proved set and of every "
        "class-specific set",
        (f"proved_set_in_bound={proved_kept}, "
         f"class_sets_not_covered={subsets or 'none'}"),
        ok,
        {"bound": sorted(bound),
         "proved_targets": sorted(proved["targets"]),
         "residual_site_targets": sorted(residual["targets"])})


class _IdentityFixture:
    """A module whose .text and symbol rows are decoupled from its DSO digest."""

    def __init__(self, dso_sha, *, text_sha="a" * 64, size=4096,
                 rows=None, data_sha="d" * 64, reloc_add=0x10):
        self.name = "identity-fixture.so"
        self.sha256 = dso_sha
        self._text = text_sha
        self._size = size
        self._rows = rows or [["f", 0x10, 8, "T"], ["g", 0x20, 16, "T"]]
        self._data_sha = data_sha
        self._reloc_add = reloc_add

    def text_digest(self):
        return self._text, self._size

    def symbol_table_rows(self):
        return list(self._rows)

    def analysis_section_descriptors(self):
        return [
            {"name": ".text", "type": "PROGBITS", "addr": 0x1000,
             "size": self._size, "sha256": self._text},
            {"name": ".data.rel.ro", "type": "PROGBITS", "addr": 0x3000,
             "size": 64, "sha256": self._data_sha},
        ]

    def analysis_excluded_sections(self):
        return [".comment", ".debug_info"]

    def canonical_relocations(self):
        return [[".data.rel.ro", 0x0, "R_X86_64_RELATIVE", None,
                 self._reloc_add]]

    def dynamic_symbol_rows(self):
        return [["f", 0x10, "T"], ["g", 0x20, "T"]]

    def dynamic_entries(self):
        return {"soname": self.name, "needed": ["libc.so.6"],
                "runpath": [], "rpath": []}


def case_neutral_rebuild():
    """A comment-only edit: different DSO digest, identical analysis input."""
    original = _IdentityFixture("0" * 64)
    comment_only = _IdentityFixture("f" * 64)          # same .text and symbols
    code_change = _IdentityFixture("0" * 64, text_sha="b" * 64)
    i_original = cc.analysis_identity({original.name: original})
    i_comment = cc.analysis_identity({comment_only.name: comment_only})
    i_code = cc.analysis_identity({code_change.name: code_change})
    ok = (i_original["digest"] == i_comment["digest"]
          and i_original["modules"][original.name]["dso_sha256"]
          != i_comment["modules"][comment_only.name]["dso_sha256"]
          and i_original["digest"] != i_code["digest"])
    return _case(
        "ai-neutral-rebuild",
        "one module, two builds: a comment-only source edit (identical .text "
        "and symbol rows, different DSO digest) and a code edit",
        "compute the analysis identity for both builds",
        "the comment-only rebuild shares the analysis identity while its DSO "
        "digest differs, and the code edit changes the identity",
        (f"comment_only_same_identity="
         f"{i_original['digest'] == i_comment['digest']}, "
         f"dso_digest_differs="
         f"{original.sha256 != comment_only.sha256}, "
         f"code_edit_changes_identity={i_original['digest'] != i_code['digest']}"),
        ok,
        {"analysis_identity": i_original["digest"],
         "basis": i_original["basis"],
         "dso_digest_is_analysis_identity": i_original["modules"][
             original.name]["dso_sha256_is_analysis_identity"]})


def case_identity_covers_data_inputs():
    """The identity must change when .text and symbols stay identical but a
    data section or a relocation addend changes.

    This is the positive half of P0-A: the old identity hashed only .text and
    the symbol table, so a dispatch-table edit in .data.rel.ro was invisible.
    """
    original = _IdentityFixture("0" * 64)
    data_edit = _IdentityFixture("0" * 64, data_sha="e" * 64)
    reloc_edit = _IdentityFixture("0" * 64, reloc_add=0x20)
    i0 = cc.analysis_identity({original.name: original})
    idata = cc.analysis_identity({data_edit.name: data_edit})
    ireloc = cc.analysis_identity({reloc_edit.name: reloc_edit})
    m0, mdata = i0["modules"][original.name], idata["modules"][data_edit.name]
    ok = (m0["text_sha256"] == mdata["text_sha256"]
          and m0["symbol_table_sha256"] == mdata["symbol_table_sha256"]
          and m0["sections"] != mdata["sections"]
          and i0["digest"] != idata["digest"]
          and m0["relocation_table_sha256"]
          != ireloc["modules"][reloc_edit.name]["relocation_table_sha256"]
          and i0["digest"] != ireloc["digest"]
          and ".data.rel.ro" in i0["included_sections"]
          and ".debug_*" in i0["excluded_classes"])
    return _case(
        "aj-identity-covers-data-inputs",
        "one module with identical .text and symbol rows but a changed "
        ".data.rel.ro digest or relocation addend",
        "compute the analysis identity for the original, the data-section edit "
        "and the relocation edit",
        "the .text and symbol digests are unchanged, the data/relocation inputs "
        "and the full identity change",
        (f"text_unchanged={m0['text_sha256'] == mdata['text_sha256']}, "
         f"symbols_unchanged={m0['symbol_table_sha256'] == mdata['symbol_table_sha256']}, "
         f"data_identity_changes={i0['digest'] != idata['digest']}, "
         f"relocation_identity_changes={i0['digest'] != ireloc['digest']}"),
        ok,
        {"analysis_identity": i0["digest"],
         "basis": i0["basis"],
         "included_sections": i0["included_sections"]})


class _SymbolFixture:
    """A minimal module with one unresolved site at a reachable root."""

    name = "symbol-fixture.so"
    funcs = {0x10: "root", 0x20: "alias_target", 0x30: "dyn_target",
             0x40: "plt_stub"}
    start_set = set(funcs)
    direct = {}
    taken_code = set()
    taken_data = set()
    field_stores = {}
    unknown_call_arg_targets = set()
    dynamic_reloc_targets = set()
    slot_syms = {0x2000: {"plt_target"}}
    names_at = {0x20: {"alias_target"}}
    dynamic_defs = {"dyn_target": 0x30}
    functions = [(0x40, [(0x40, "jmp *0x1000(%rip) # 2000 <plt_target@plt>")])]
    sections = {".text": (0x0, 0, 0x100), ".plt": (0x40, 0, 0x10)}

    def __init__(self, symbol):
        self.address_taken_union = {("sym", symbol)}
        self.sites = {(0x10, 0x11, "call"): {
            "kind": "call", "func": 0x10, "addr": 0x11,
            "text": "call *%rax", "targets": set(), "unresolved": True,
            "reason": "test", "class": "unclassified",
            "arg_targets": set()}}

    def section_of(self, addr):
        if addr == 0x40:
            return ".plt"
        return ".text" if 0 <= addr < 0x100 else None

    def containing(self, addr):
        base = [a for a in sorted(self.start_set) if a <= addr]
        return base[-1] if base else None


def _symbol_closure(symbol, export_index=None):
    g = _SymbolFixture(symbol)
    return cc.build_graph({g.name: g}, {(g.name, 0x10)}, export_index or {}), g


def case_symbol_unresolved_refusal():
    closure, _g = _symbol_closure("no_such_symbol")
    rows = [r for r in closure["symbol_dispositions"]
            if r["symbol"] == "no_such_symbol"]
    refusals = cc.closure_refusals(closure)
    symbol_refusals = [r for r in refusals
                       if r["code"] == "CLOSURE_UNRESOLVED_SYMBOL"]
    ok = (len(rows) == 1 and rows[0]["disposition"] == "blocking"
          and len(symbol_refusals) == 1
          and [s["symbol"] for s in symbol_refusals[0]["symbols"]]
          == ["no_such_symbol"])
    return _case(
        "ak-unresolved-symbol-refusal",
        "a module whose residual bound names a symbol that no path resolves",
        "build the closure and evaluate closure_refusals",
        "the symbol has a blocking disposition and the closure refuses with "
        "CLOSURE_UNRESOLVED_SYMBOL naming it",
        (f"dispositions={[r['disposition'] for r in rows]}, "
         f"refusal_codes={[r['code'] for r in refusals]}"),
        ok,
        {"symbol_dispositions": rows,
         "summary": closure["symbol_disposition_summary"]})


def case_symbol_alias_resolved():
    closure, _g = _symbol_closure("alias_target")
    rows = [r for r in closure["symbol_dispositions"]
            if r["symbol"] == "alias_target"]
    ok = (len(rows) == 1 and rows[0]["disposition"] == "resolved"
          and rows[0]["path"] == "names-at"
          and ["symbol-fixture.so", 0x20] in rows[0]["targets"]
          and cc.closure_refusals(closure) == [])
    return _case(
        "al-alias-symbol-resolved",
        "a symbolic bound value whose defined-symbol-table alias is a "
        "function start in the same module",
        "resolve the symbolic value and evaluate closure_refusals",
        "the symbol resolves through names-at and the closure does not refuse",
        (f"dispositions={[(r['disposition'], r['path']) for r in rows]}, "
         f"refusals={[r['code'] for r in cc.closure_refusals(closure)]}"),
        ok,
        {"symbol_dispositions": rows})


def case_symbol_external_contract():
    closure, _g = _symbol_closure("malloc")
    rows = [r for r in closure["symbol_dispositions"] if r["symbol"] == "malloc"]
    ok = (len(rows) == 1 and rows[0]["disposition"] == "external-contract"
          and bool(rows[0]["external_interface"])
          and bool(rows[0]["external_justification"])
          and cc.closure_refusals(closure) == [])
    return _case(
        "am-external-contract-symbol",
        "a symbolic bound value naming a documented libc interface (malloc)",
        "resolve the symbolic value and evaluate closure_refusals",
        "the symbol is recorded as external-contract with its interface and "
        "the closure does not refuse",
        (f"dispositions={[(r['disposition'], r['external_interface']) for r in rows]}, "
         f"refusals={[r['code'] for r in cc.closure_refusals(closure)]}"),
        ok,
        {"symbol_dispositions": rows})


def case_symbol_refusal_mutation_control():
    """Disabling CLOSURE_UNRESOLVED_SYMBOL must make the first case fail."""
    closure, _g = _symbol_closure("no_such_symbol")
    original = cc.closure_refusals

    def without_symbol_refusal(c):
        return [r for r in original(c) if r["code"] != "CLOSURE_UNRESOLVED_SYMBOL"]

    cc.closure_refusals = without_symbol_refusal
    try:
        mutated = cc.closure_refusals(closure)
    finally:
        cc.closure_refusals = original
    ok = not any(r["code"] == "CLOSURE_UNRESOLVED_SYMBOL" for r in mutated)
    return _case(
        "an-unresolved-symbol-refusal-removed",
        "the blocking-symbol closure from ak-unresolved-symbol-refusal",
        "disable the CLOSURE_UNRESOLVED_SYMBOL branch and re-evaluate",
        "the refusal disappears, so the first case would fail",
        f"mutated_refusal_codes={[r['code'] for r in mutated]}",
        ok,
        {"mutated_refusals": mutated})


# --------------------------------------------------------------------------- #
# v1.6: admission by refutation
# --------------------------------------------------------------------------- #
# The exclusions were derived against the pre-closure direct set.  When the
# sound bound reaches an excluded caller, the exclusion is false; the caller's
# contribution is admitted and the closure recomputed.  The corpus exercises the
# production `admission_fixpoint`, `admit_refuted_exclusions` and record builder.


class AdmissionGraph:
    name = "admission-fixture.so"
    funcs = {0x10: "site_func", 0x20: "target_ok", 0x30: "excluded_caller",
             0x40: "target_dropped", 0x50: "reachable_caller"}
    start_set = set(funcs)
    all_syms = dict(funcs)
    names_at = {a: {n} for a, n in funcs.items()}
    taken_code = set()
    taken_data = set()
    address_taken_union = set()
    dynamic_reloc_targets = set()
    field_stores = {}
    unknown_call_arg_targets = set()
    slot_func_targets = set()
    sites = {}

    def __init__(self):
        self.direct = {0x10: {0x50}}

    def section_of(self, _a):
        return ".text"

    def containing(self, a):
        return max(x for x in self.funcs if x <= a)

    def static_slot(self, _a):
        return None

    def seam_symbol(self, _a):
        return None

    def cstring_at(self, _a):
        return None

    def is_data(self, _a):
        return False


def admission_fixture(*, reach_excluded, unbounded=False):
    g = AdmissionGraph()
    if reach_excluded:
        g.direct = {0x10: {0x50, 0x30}}
    excluded_targets = [] if unbounded else ["0x40"]
    excluded_args = [{
        "argument_index": 0, "targets": list(excluded_targets),
        "non_image_values": ["<top>"] if unbounded else [],
        "unresolved": bool(unbounded), "witness_instruction": []}]
    arg_targets = {0x20} | ({0x40} if not unbounded else set())
    g.sites = {(0x10, 0x11, "call"): {
        "kind": "call", "func": 0x10, "addr": 0x11,
        "text": "call *%rax", "targets": {0x20},
        "unresolved": False, "class": "reachable-caller-target",
        "reason": "reachable-caller target bounding",
        "field_offsets": set(), "arg_deps": {0}, "arg_targets": arg_targets,
        "reachable_caller_bound": {
            "reachable_callers": [{
                "function": "0x50", "symbol": "reachable_caller",
                "reachable": True, "reason": None,
                "call_sites": [{"call_site": "0x51", "arguments": [{
                    "argument": 0, "argument_index": 0,
                    "targets": ["0x20"], "non_image_values": [],
                    "unresolved": False, "witness_instruction": []}]}],
                "contributed_targets": ["0x20"]}],
            "excluded_callers": [{
                "function": "0x30", "symbol": "excluded_caller",
                "reachable": False, "reason": "not in this family's "
                "reachable set", "in_image_references": [],
                "call_sites": [{"call_site": "0x31",
                                "arguments": excluded_args}],
                "contributed_targets": excluded_targets}],
            "bounded_targets": ["0x20"],
            "attributed_targets": [hex(a) for a in sorted(arg_targets)],
            "unattributed_targets": []}}}
    return g


def _admission_run(g, *, admit=True):
    close = lambda: cc.build_graph({g.name: g}, {(g.name, 0x10)}, {})
    if not admit:
        return close(), None
    return cc.admission_fixpoint({g.name: g}, close)


def case_admission_refuted_caller():
    g = admission_fixture(reach_excluded=True)
    closure, report = _admission_run(g)
    site = g.sites[(0x10, 0x11, "call")]
    bound = site["reachable_caller_bound"]
    oracle = cc.ReachabilityOracle({g.name: g}, closure["upper_reachable"])
    records = cc.build_edge_records({g.name: g}, oracle)
    defects = cc.validate_edge_records(records, oracle)
    ok = (0x40 in site["targets"]
          and (g.name, 0x40) in closure["upper_reachable"]
          and bound["excluded_callers"] == []
          and any(r.get("admitted_by_refutation")
                  for r in bound["reachable_callers"])
          and report["refuted_exclusions"][cc.ADMISSION_ROLE_CALLER] == 1
          and report["admitted_by_refutation"]["count"] == 1
          and not defects)
    return _case(
        "bb-admission-refuted-caller",
        "a caller-bound site whose excluded caller the sound bound reaches",
        "run admission + closure recomputation",
        "the caller's target is admitted, the exclusion is gone, and the record "
        "validates against the sound bound",
        (f"target_admitted={0x40 in site['targets']}, "
         f"exclusions={len(bound['excluded_callers'])}, "
         f"passes={report['passes']}, "
         f"admitted_targets={report['admitted_by_refutation']['targets']}, "
         f"defects={defects[:2]}"),
        ok,
        {"passes": report["passes"],
         "refuted_exclusions": report["refuted_exclusions"],
         "admitted_by_refutation": report["admitted_by_refutation"],
         "reachable": sorted(f"{m}:{a:#x}" for m, a in
                             closure["upper_reachable"])})


def case_admission_surviving_caller():
    g = admission_fixture(reach_excluded=False)
    closure, report = _admission_run(g)
    site = g.sites[(0x10, 0x11, "call")]
    oracle = cc.ReachabilityOracle({g.name: g}, closure["upper_reachable"])
    defects = cc.validate_edge_records(
        cc.build_edge_records({g.name: g}, oracle), oracle)
    ok = (0x40 not in site["targets"]
          and len(site["reachable_caller_bound"]["excluded_callers"]) == 1
          and report["passes"] == 0
          and not defects)
    return _case(
        "bc-admission-surviving-caller",
        "a caller-bound site whose excluded caller the sound bound does not "
        "reach",
        "run admission + closure recomputation",
        "no admission occurs, the exclusion survives, and the record validates",
        (f"targets={sorted(site['targets'])}, "
         f"exclusions="
         f"{len(site['reachable_caller_bound']['excluded_callers'])}, "
         f"passes={report['passes']}, defects={defects[:2]}"),
        ok)


def case_admission_widens_to_unresolved():
    g = admission_fixture(reach_excluded=True, unbounded=True)
    closure, report = _admission_run(g)
    site = g.sites[(0x10, 0x11, "call")]
    oracle = cc.ReachabilityOracle({g.name: g}, closure["upper_reachable"])
    records = cc.build_edge_records({g.name: g}, oracle)
    defects = cc.validate_edge_records(records, oracle)
    ok = (site["unresolved"]
          and "refutation-unbounded" in (site.get("reason") or "")
          and site["reachable_caller_bound"]["excluded_callers"] == []
          and [r["disposition"] for r in records] == [cc.DISPOSITION_UNRESOLVED]
          and all(r.get("missing_property") for r in records)
          and not defects)
    return _case(
        "bd-admission-widens-to-unresolved",
        "a caller-bound site whose refuted caller passes an argument with no "
        "finite image target set",
        "run admission + closure recomputation",
        "the site becomes UNRESOLVED with a named refutation-unbounded "
        "property and the record validates",
        (f"unresolved={site['unresolved']}, "
         f"reason={site.get('reason')}, "
         f"dispositions={[r['disposition'] for r in records]}, "
         f"defects={defects[:2]}"),
        ok)


def case_admission_disabled_control():
    """Mutation control: without the pass the refuted case must fail."""
    g = admission_fixture(reach_excluded=True)
    closure, _report = _admission_run(g, admit=False)
    site = g.sites[(0x10, 0x11, "call")]
    oracle = cc.ReachabilityOracle({g.name: g}, closure["upper_reachable"])
    defects = cc.validate_edge_records(
        cc.build_edge_records({g.name: g}, oracle), oracle)
    ok = (0x40 not in site["targets"]
          and bool(site["reachable_caller_bound"]["excluded_callers"])
          and bool(defects))
    return _case(
        "be-admission-disabled-control",
        "the refuted-caller fixture with the admission pass disabled",
        "compute the closure without admission and build records",
        "the target is not admitted, the exclusion remains, and the validator "
        "refuses the record -- the admission case is sensitive to the mechanism",
        (f"target_admitted={0x40 in site['targets']}, "
         f"exclusions="
         f"{len(site['reachable_caller_bound']['excluded_callers'])}, "
         f"defects={len(defects)}"),
        ok)


def case_admission_unconditional_control():
    """Mutation control: admitting without the bound check must fail."""
    g = admission_fixture(reach_excluded=False)
    site = g.sites[(0x10, 0x11, "call")]
    bound = site["reachable_caller_bound"]
    moved = bound["excluded_callers"].pop()
    moved["admitted_by_refutation"] = True
    bound["reachable_callers"].append(moved)
    site["targets"] |= {0x40}
    closure = cc.build_graph({g.name: g}, {(g.name, 0x10)}, {})
    oracle = cc.ReachabilityOracle({g.name: g}, closure["upper_reachable"])
    defects = cc.validate_edge_records(
        cc.build_edge_records({g.name: g}, oracle), oracle)
    ok = not bound["excluded_callers"] and bool(defects)
    return _case(
        "bf-admission-unconditional-control",
        "the surviving-exclusion fixture with unconditional admission (no "
        "sound-bound check)",
        "move the excluded caller regardless of the oracle and build records",
        "the caller is claimed reachable although the bound does not reach it "
        "and the validator refuses the record",
        (f"exclusions={len(bound['excluded_callers'])}, "
         f"defects={len(defects)}"),
        ok)


def case_reachable_digest_canonicalisation():
    """Two neutral builds differ only in .llvm.<hash>; the digest must not."""
    class Names:
        name = "names.so"

        def __init__(self, suffix):
            self.funcs = {0x10: f"local_fn.llvm.{suffix}",
                          0x20: "CRYPTO_export@@OPENSSL_3.0.0"}

    reach = {("names.so", 0x10), ("names.so", 0x20)}
    a = cc.reachable_function_entries({"names.so": Names("111")}, reach)
    b = cc.reachable_function_entries({"names.so": Names("222")}, reach)
    raw_a = cc.reachable_function_entries({"names.so": Names("111")}, reach,
                                          canonical=False)
    raw_b = cc.reachable_function_entries({"names.so": Names("222")}, reach,
                                          canonical=False)
    ok = (a == b
          and cc.reachable_functions_digest(a) == cc.reachable_functions_digest(b)
          and cc.reachable_functions_digest(raw_a)
          != cc.reachable_functions_digest(raw_b))
    return _case(
        "ba-reachable-digest-canonicalisation",
        "two neutral builds whose reachable addresses are identical but whose "
        "compiler-generated .llvm.<hash> suffixes differ",
        "build the reachable-function list and digest in canonical and raw form",
        "the canonical digest is equal while the raw-name digest differs",
        (f"canonical_equal={a == b}, "
         f"canonical_digest={cc.reachable_functions_digest(a)[:16]}, "
         f"raw_digest_differs="
         f"{cc.reachable_functions_digest(raw_a) != cc.reachable_functions_digest(raw_b)}"),
        ok,
        {"canonical_entries": a, "raw_entries_a": raw_a,
         "raw_entries_b": raw_b})


# --------------------------------------------------------------------------- #
# v1.7: documentation state must not remove an obligation
# --------------------------------------------------------------------------- #
ENGINE_FILE = "src/engine/tb_x.rs"
ENGINE_ITEM = "engine_unregister_all_x"
ENGINE_KIND = "UNSAFE_FN_DEF"
ENGINE_LINE = 19


def _enrollment_fixture(*, contracted=True, blockers=None, item=ENGINE_ITEM,
                        line=ENGINE_LINE):
    """One site that is named by a site receipt and by the persistent ledger."""
    contract_records = ([{
        "file": ENGINE_FILE, "line": line, "kind": ENGINE_KIND,
        "item": item, "partition": "production",
        "contract_basis": "attached # Safety / SAFETY: contract"}]
                        if contracted else None)
    contracts = {
        "blockers": blockers or [],
        "contracted_operations": contract_records,
        "per_file": {ENGINE_FILE: {"all_operations_contracted": contracted is not None}},
    }
    boundaries = {ENGINE_FILE: [{
        "receipt": "p25-x-sites.json", "id": "X-1", "file": ENGINE_FILE,
        "line": line, "kind": ENGINE_KIND, "operation": item,
        "mechanism": "C_ABI_CONTRACT", "disposition": "BLOCKED"}]}
    ledger = {(ENGINE_FILE, line, ENGINE_KIND): {
        "file": ENGINE_FILE, "line": line, "kind": ENGINE_KIND,
        "mechanism": "C_ABI_CONTRACT", "operation": item, "basis": "fixture"}}
    return contracts, boundaries, ledger


def case_documented_obligation_persists():
    contracts, boundaries, ledger = _enrollment_fixture()
    obs, enr = cc.obligation_candidates(
        contracts, {ENGINE_FILE}, boundaries, ledger)
    want_stable = f"{ENGINE_FILE}::{ENGINE_KIND}::{ENGINE_ITEM}"
    ok = (len(obs) == 1
          and obs[0]["contract"] == "contracted"
          and obs[0]["item"] == ENGINE_ITEM
          and obs[0]["stable_id"] == want_stable
          and enr["enrolled_count"] == 1)
    return _case(
        "bg-documented-obligation-persists",
        "a reachable unsafe fn with an attached # Safety prelude, named by a "
        "site-enumerating receipt and by state.json#/obligation_mechanisms",
        "build the obligation queue from the inventory census",
        "the operation is enrolled and marked contracted; a contract is not a "
        "discharge",
        (f"obligations={len(obs)}, contract={obs[0]['contract'] if obs else None}, "
         f"stable_id={obs[0]['stable_id'] if obs else None}"),
        ok, {"enrollment": enr})


def case_documentation_stripped_obligation_persists():
    stripped = [{
        "file": ENGINE_FILE, "line": ENGINE_LINE, "kind": ENGINE_KIND,
        "item": ENGINE_ITEM, "partition": "production",
        "reason": "no # Safety / SAFETY: contract on the unsafe fn"}]
    contracts, boundaries, ledger = _enrollment_fixture(
        contracted=False, blockers=stripped)
    # The census at this identity has no contracted record at all.
    contracts["contracted_operations"] = []
    obs, enr = cc.obligation_candidates(
        contracts, {ENGINE_FILE}, boundaries, ledger)
    want_stable = f"{ENGINE_FILE}::{ENGINE_KIND}::{ENGINE_ITEM}"
    ok = (len(obs) == 1
          and obs[0]["contract"] == "uncontracted"
          and obs[0]["stable_id"] == want_stable)
    return _case(
        "bh-documentation-stripped-obligation-persists",
        "the same site after the # Safety prelude is stripped, so the census "
        "classifies it uncontracted again",
        "build the obligation queue",
        "the obligation PERSISTS and flips to uncontracted; the stable identity "
        "does not move with the documentation state",
        (f"obligations={len(obs)}, contract={obs[0]['contract'] if obs else None}, "
         f"stable_id={obs[0]['stable_id'] if obs else None}"),
        ok, {"enrollment": enr})


def case_new_unsafe_fn_enters():
    new_file = "src/engine/tb_new.rs"
    new_item = "brand_new_unsafe_fn"
    blockers = [
        {"file": ENGINE_FILE, "line": ENGINE_LINE, "kind": ENGINE_KIND,
         "item": ENGINE_ITEM, "partition": "production",
         "reason": "no # Safety / SAFETY: contract on the unsafe fn"},
        {"file": new_file, "line": 7, "kind": ENGINE_KIND,
         "item": new_item, "partition": "production",
         "reason": "no # Safety / SAFETY: contract on the unsafe fn"},
    ]
    contracts, boundaries, ledger = _enrollment_fixture(contracted=False)
    contracts["blockers"] = blockers
    contracts["contracted_operations"] = []
    obs, _ = cc.obligation_candidates(
        contracts, {ENGINE_FILE, new_file}, boundaries, ledger)
    ids = {o["stable_id"] for o in obs}
    ok = (len(obs) == 2
          and f"{new_file}::{ENGINE_KIND}::{new_item}" in ids)
    return _case(
        "bi-new-unsafe-fn-enters",
        "a genuinely new unsafe fn that no receipt or ledger entry names",
        "build the obligation queue",
        "the new operation ENTERS the queue as an uncontracted obligation",
        f"obligations={len(obs)}, stable_ids={sorted(ids)}",
        ok)


def case_removed_operation_leaves_with_reason():
    contracts, boundaries, ledger = _enrollment_fixture(contracted=False)
    contracts["blockers"] = []
    contracts["contracted_operations"] = []
    obs, enr = cc.obligation_candidates(
        contracts, {ENGINE_FILE}, boundaries, ledger)
    ok = (not obs
          and enr["excluded_count"] == 1
          and "no longer exists" in enr["excluded"][0]["reason"])
    return _case(
        "bj-removed-operation-leaves-with-reason",
        "a site receipt and ledger entry whose operation is absent from both the "
        "uncontracted blockers and the per-site contracted records",
        "build the obligation queue",
        "the obligation is not enrolled and the removal is recorded with a reason",
        (f"obligations={len(obs)}, excluded={enr['excluded_count']}, "
         f"reason={enr['excluded'][0]['reason'][:48] if enr['excluded'] else None}"),
        ok)


def case_legacy_inventory_documented_site_persists():
    contracts, boundaries, ledger = _enrollment_fixture(contracted=False)
    contracts["blockers"] = []
    contracts["contracted_operations"] = None
    contracts["per_file"] = {ENGINE_FILE: {"all_operations_contracted": False}}
    obs, enr = cc.obligation_candidates(
        contracts, {ENGINE_FILE}, boundaries, ledger)
    ok = (len(obs) == 1 and obs[0]["contract"] == "contracted"
          and "predates" in obs[0]["contract_basis"]
          and enr["contracted_records_present"] is False)
    return _case(
        "bk-legacy-inventory-documented-site-persists",
        "an inventory that predates per-site contracted-operation records, "
        "naming the site only through its receipt and the persistent ledger",
        "build the obligation queue",
        "the documented site is still enrolled, and the basis records that "
        "existence rests on the site receipt's enumeration",
        (f"obligations={len(obs)}, basis={obs[0]['contract_basis'][:52] if obs else None}"),
        ok)


def case_contracted_record_line_drift_stable_identity():
    """A doc comment shifts the site +7 lines; the census record moves with it."""
    contracts, boundaries, ledger = _enrollment_fixture()
    moved = ENGINE_LINE + 7
    contracts["contracted_operations"][0]["line"] = moved
    boundaries[ENGINE_FILE][0]["line"] = ENGINE_LINE  # plan still names the old line
    obs, _enr = cc.obligation_candidates(
        contracts, {ENGINE_FILE}, boundaries, ledger)
    want_stable = f"{ENGINE_FILE}::{ENGINE_KIND}::{ENGINE_ITEM}"
    ok = (len(obs) == 1
          and obs[0]["stable_id"] == want_stable
          and obs[0]["line"] == moved
          and obs[0]["site_receipt_line"] == ENGINE_LINE)
    return _case(
        "bm-contracted-record-line-drift-stable-identity",
        "the site receipt and ledger name line 19 while the census contracted "
        "record is at line 26 after a documentation prelude",
        "build the queue by exact coordinate then by stable identity",
        "the operation is enrolled once at the census coordinate, with the "
        "same file+kind+item identity and the receipt line kept as provenance",
        (f"obligations={len(obs)}, line={obs[0]['line'] if obs else None}, "
         f"plan_line={obs[0]['site_receipt_line'] if obs else None}, "
         f"stable_id={obs[0]['stable_id'] if obs else None}"),
        ok)


def case_plan_without_ledger_does_not_enroll():
    contracts = {
        "blockers": [],
        "contracted_operations": [{
            "file": ENGINE_FILE, "line": ENGINE_LINE, "kind": ENGINE_KIND,
            "item": ENGINE_ITEM, "partition": "production",
            "contract_basis": "attached # Safety / SAFETY: contract"}],
        "per_file": {},
    }
    boundaries = {ENGINE_FILE: [{
        "receipt": "p25-x-sites.json", "id": "X-1", "file": ENGINE_FILE,
        "line": ENGINE_LINE, "kind": ENGINE_KIND, "operation": ENGINE_ITEM,
        "mechanism": "C_ABI_CONTRACT", "disposition": "BLOCKED"}]}
    ledger = {(ENGINE_FILE, 999, ENGINE_KIND): {
        "file": ENGINE_FILE, "line": 999, "kind": ENGINE_KIND,
        "mechanism": "C_ABI_CONTRACT", "operation": "other_op",
        "basis": "fixture"}}
    obs, enr = cc.obligation_candidates(
        contracts, {ENGINE_FILE}, boundaries, ledger)
    ok = (not obs
          and enr["enrolled_count"] == 0
          and len(enr["ledger_entries_without_site_plan"]) == 1)
    return _case(
        "bl-plan-without-ledger-does-not-enroll",
        "a site receipt naming a documented operation that the persistent ledger "
        "never recorded, plus a ledger entry with no site plan",
        "build the obligation queue",
        "the plan-only site does not grow the target set and the ledger-without-"
        "plan gap is recorded explicitly",
        (f"obligations={len(obs)}, gaps="
         f"{len(enr['ledger_entries_without_site_plan'])}"),
        ok)


def case_carried_forward_contract_not_in_ledger():
    """A previously enumerated obligation with a contract, no receipt, no ledger."""
    prev_line = ENGINE_LINE
    moved = ENGINE_LINE + 9
    stable = f"{ENGINE_FILE}::{ENGINE_KIND}::{ENGINE_ITEM}"
    previous = {
        "applied": True,
        "receipt": "closure-x-previous.json",
        "receipt_sha256": "0" * 64,
        "receipt_generated_utc": "2026-10-30T00:00:00Z",
        "receipt_verdict": "ACCEPTED",
        "obligations": [{
            "id": f"V1:{ENGINE_FILE}:{prev_line}:{ENGINE_KIND}",
            "stable_id": stable, "file": ENGINE_FILE, "line": prev_line,
            "kind": ENGINE_KIND, "item": ENGINE_ITEM,
            "partition": "production", "contract": "uncontracted",
            "status": "BLOCKED", "site_receipt": None,
            "discharge_receipt": None}],
    }
    contracts = {
        "blockers": [],
        "contracted_operations": [{
            "file": ENGINE_FILE, "line": moved, "kind": ENGINE_KIND,
            "item": ENGINE_ITEM, "partition": "production",
            "contract_basis": "attached # Safety / SAFETY: contract"}],
        "per_file": {ENGINE_FILE: {}},
    }
    obs, enr = cc.obligation_candidates(
        contracts, {ENGINE_FILE}, {}, {}, carry_forward=previous)
    cf = enr["carry_forward"]
    ok = (len(obs) == 1
          and obs[0]["contract"] == "contracted"
          and obs[0]["stable_id"] == stable
          and obs[0]["line"] == prev_line
          and obs[0]["current_census_line"] == moved
          and cf["carried_forward_count"] == 1
          and cf["already_present_count"] == 0)
    return _case(
        "bn-carried-forward-contract-not-in-ledger",
        "an obligation the previous ACCEPTED closure enumerated that now has an "
        "attached # Safety prelude, is named by no site receipt, and is absent "
        "from state.json#/obligation_mechanisms",
        "build the queue with carry-forward by stable identity",
        "the obligation PERSISTS, is marked contracted, and keeps its previous "
        "enumeration coordinate while recording the current census coordinate; "
        "a contract is not a discharge",
        (f"obligations={len(obs)}, contract={obs[0]['contract'] if obs else None}, "
         f"line={obs[0]['line'] if obs else None}, "
         f"current={obs[0].get('current_census_line') if obs else None}, "
         f"carried={cf['carried_forward_count']}"),
        ok, {"enrollment": cf})


def case_carried_forward_bounded_to_enumerated():
    """Contracted operations no closure enumerated are never enrolled."""
    stable = f"{ENGINE_FILE}::{ENGINE_KIND}::{ENGINE_ITEM}"
    previous = {
        "applied": True,
        "receipt": "closure-x-previous.json", "receipt_sha256": "0" * 64,
        "obligations": [{
            "id": f"V1:{ENGINE_FILE}:{ENGINE_LINE}:{ENGINE_KIND}",
            "stable_id": stable, "file": ENGINE_FILE, "line": ENGINE_LINE,
            "kind": ENGINE_KIND, "item": ENGINE_ITEM,
            "partition": "production", "contract": "uncontracted",
            "status": "BLOCKED", "site_receipt": None,
            "discharge_receipt": None}],
    }
    contracted = [{
        "file": ENGINE_FILE, "line": ENGINE_LINE, "kind": ENGINE_KIND,
        "item": ENGINE_ITEM, "partition": "production",
        "contract_basis": "attached # Safety / SAFETY: contract"}]
    for n in range(40):
        contracted.append({
            "file": ENGINE_FILE, "line": 100 + n, "kind": ENGINE_KIND,
            "item": f"documented_only_{n}", "partition": "production",
            "contract_basis": "attached # Safety / SAFETY: contract"})
    contracts = {"blockers": [], "contracted_operations": contracted,
                 "per_file": {ENGINE_FILE: {}}}
    obs, enr = cc.obligation_candidates(
        contracts, {ENGINE_FILE}, {}, {}, carry_forward=previous)
    cf = enr["carry_forward"]
    ok = (len(obs) == 1
          and cf["carried_forward_count"] == 1
          and cf["contracted_operations_never_enumerated"] == 41
          and all(o["item"] == ENGINE_ITEM for o in obs))
    return _case(
        "bo-carried-forward-bounded-to-enumerated",
        "41 contracted operations in the inventory of which the previous closure "
        "enumerated exactly one",
        "build the queue with carry-forward",
        "only the previously enumerated operation is enrolled; the 40 contracted "
        "operations no closure enumerated stay out of the queue",
        (f"obligations={len(obs)}, carried={cf['carried_forward_count']}, "
         f"contracted_never_enumerated="
         f"{cf['contracted_operations_never_enumerated']}"),
        ok, {"enrollment": cf})


def case_carried_forward_removed_operation_recorded():
    """A carried-forward operation absent from the current census is removed."""
    stable = f"{ENGINE_FILE}::{ENGINE_KIND}::{ENGINE_ITEM}"
    previous = {
        "applied": True,
        "receipt": "closure-x-previous.json", "receipt_sha256": "0" * 64,
        "obligations": [{
            "id": f"V1:{ENGINE_FILE}:{ENGINE_LINE}:{ENGINE_KIND}",
            "stable_id": stable, "file": ENGINE_FILE, "line": ENGINE_LINE,
            "kind": ENGINE_KIND, "item": ENGINE_ITEM,
            "partition": "production", "contract": "contracted",
            "status": "BLOCKED", "site_receipt": None,
            "discharge_receipt": None}],
    }
    contracts = {"blockers": [], "contracted_operations": [],
                 "per_file": {ENGINE_FILE: {}}}
    obs, enr = cc.obligation_candidates(
        contracts, {ENGINE_FILE}, {}, {}, carry_forward=previous)
    cf = enr["carry_forward"]
    ok = (not obs and cf["removed_count"] == 1
          and "no longer exists" in cf["removed"][0]["reason"]
          and cf["removed"][0]["previous_status"] == "BLOCKED")
    return _case(
        "bp-carried-forward-removed-operation-recorded",
        "an operation the previous closure enumerated that the current per-site "
        "census no longer contains",
        "build the queue with carry-forward",
        "the obligation leaves the queue and the removal is recorded with a "
        "reason and its previous status",
        (f"obligations={len(obs)}, removed={cf['removed_count']}, "
         f"reason={cf['removed'][0]['reason'][:44] if cf['removed'] else None}"),
        ok, {"enrollment": cf})


def case_carried_forward_unreachable_file_removed():
    """A carried obligation whose file is unreachable at this artifact leaves."""
    stable = f"{ENGINE_FILE}::{ENGINE_KIND}::{ENGINE_ITEM}"
    moved = ENGINE_LINE + 9
    previous = {
        "applied": True,
        "receipt": "closure-x-previous.json", "receipt_sha256": "0" * 64,
        "obligations": [{
            "id": f"V1:{ENGINE_FILE}:{ENGINE_LINE}:{ENGINE_KIND}",
            "stable_id": stable, "file": ENGINE_FILE, "line": ENGINE_LINE,
            "kind": ENGINE_KIND, "item": ENGINE_ITEM,
            "partition": "production", "contract": "uncontracted",
            "status": "BLOCKED", "site_receipt": None,
            "discharge_receipt": None}],
    }
    contracts = {
        "blockers": [],
        "contracted_operations": [{
            "file": ENGINE_FILE, "line": moved, "kind": ENGINE_KIND,
            "item": ENGINE_ITEM, "partition": "production",
            "contract_basis": "attached # Safety / SAFETY: contract"}],
        "per_file": {ENGINE_FILE: {}},
    }
    evidence = {"source": "graph.reachable_files",
                "artifact_sha256": "1" * 64, "reachable_file_count": 0}
    gone, gone_enr = cc.obligation_candidates(
        contracts, set(), {}, {}, carry_forward=previous,
        reachability_evidence=evidence)
    cf = gone_enr["carry_forward"]
    removed = cf["removed"][0] if cf["removed"] else {}
    ev = removed.get("reachable_file_evidence") or {}
    # control: the operation still exists at the current census coordinate, so
    # only reachability can justify the removal
    kept, kept_enr = cc.obligation_candidates(
        contracts, {ENGINE_FILE}, {}, {}, carry_forward=previous,
        reachability_evidence=dict(evidence, reachable_file_count=1))
    ok = (not gone
          and cf["removed_count"] == 1
          and removed.get("reason") == "no-longer-reachable-at-this-artifact"
          and removed.get("operation_still_in_census") is True
          and removed.get("current_census_lines") == [moved]
          and ev.get("file_in_reachable_set") is False
          and ev.get("reachable_file_count") == 0
          and len(kept) == 1
          and kept_enr["carry_forward"]["carried_forward_count"] == 1
          and kept_enr["carry_forward"]["removed_count"] == 0)
    return _case(
        "bq-carried-forward-unreachable-file-removed",
        "a previously enumerated operation that still exists in the current "
        "census, in a file the current closure's reachable-file set does not "
        "contain",
        "build the queue with carry-forward and the reachable-file set",
        "the obligation leaves the queue with reason "
        "no-longer-reachable-at-this-artifact, citing the unreachable-file "
        "evidence; the same fixture with the file reachable still carries it",
        (f"unreachable: obligations={len(gone)}, "
         f"removed={cf['removed_count']}, "
         f"reason={removed.get('reason')}, "
         f"still_in_census={removed.get('operation_still_in_census')}; "
         f"reachable control: obligations={len(kept)}, "
         f"carried={kept_enr['carry_forward']['carried_forward_count']}"),
        ok, {"enrollment": cf,
             "reachable_control": kept_enr["carry_forward"]})


def case_stale_range_does_not_discharge():
    """A scoped discharge needs stable identity and the current coordinate."""
    previous_line = ENGINE_LINE
    current_line = ENGINE_LINE + 9
    other_item = ENGINE_ITEM + "_other"
    mechanisms = {"MECH": {"state": "OWNERSHIP_RECONSTRUCTED"}}

    def obligation(current):
        return {
            "id": f"V1:{ENGINE_FILE}:{previous_line}:{ENGINE_KIND}",
            "stable_id": f"{ENGINE_FILE}::{ENGINE_KIND}::{ENGINE_ITEM}",
            "file": ENGINE_FILE, "line": previous_line,
            "current_census_line": current,
            "kind": ENGINE_KIND, "item": ENGINE_ITEM,
            "partition": "production", "contract": "contracted",
            "mechanism": "MECH",
            "carried_forward_from": {
                "receipt": "closure-x-previous.json",
                "previous_line": previous_line},
        }

    def boundary(operation, lo, hi):
        return {"receipt": "p25-x-sites.json", "id": "X-STALE",
                "file": ENGINE_FILE, "line": lo, "kind": ENGINE_KIND,
                "operation": operation,
                "disposition":
                    f"SAFETY_DISCHARGED: {ENGINE_FILE}:{lo}-{hi}"}

    def run(oblig, bound):
        plane = {"mechanism_discharges": {},
                 "scoped_boundary_discharges":
                     {bound["id"]: {"receipt": bound["receipt"]}},
                 "err_scope": {}}
        cc.adjudicate(oblig, mechanisms, [bound], plane)
        return oblig

    # the stale drift: the receipt names another operation and its range covers
    # only the previous enumeration coordinate
    stale = run(obligation(current_line),
                boundary("module::" + other_item, previous_line,
                         previous_line + 5))
    # range alone never establishes a match, even when it covers current
    wrong_op = run(obligation(current_line),
                   boundary("module::" + other_item, previous_line,
                            current_line))
    # control: right operation, range covers the current coordinate
    control = run(obligation(current_line),
                  boundary("module::" + ENGINE_ITEM, previous_line,
                           current_line))
    rej = stale.get("stale_discharge_rejections") or []
    ok = (stale["status"] == "BLOCKED"
          and len(rej) == 1
          and rej[0]["previous_coordinate"] == previous_line
          and rej[0]["current_coordinate"] == current_line
          and rej[0]["declared_range_for_file"] == [
              [previous_line, previous_line + 5]]
          and str(current_line) in stale["status_reason"]
          and str(previous_line) in stale["status_reason"]
          and wrong_op["status"] == "BLOCKED"
          and wrong_op.get("discharge_receipt") is None
          and control["status"] == "DISCHARGED")
    return _case(
        "br-stale-range-does-not-discharge-under-drift",
        "a carried operation at current census coordinate 109 whose previous "
        "coordinate 100 is covered by a neighbouring receipt's declared range "
        "[100,105]",
        "adjudicate the scoped discharge at the current coordinate",
        "the discharge does not apply: the site is BLOCKED and the stale range "
        "and both coordinates are named; a widened range with the wrong "
        "operation still does not discharge, while the right operation inside "
        "the range does",
        (f"stale={stale['status']}, rejected={len(rej)}, "
         f"wrong_operation={wrong_op['status']}, "
         f"control={control['status']}"),
        ok, {"stale": {"status": stale["status"],
                       "status_reason": stale["status_reason"],
                       "rejections": rej},
             "wrong_operation": {"status": wrong_op["status"],
                                 "discharge_receipt":
                                     wrong_op.get("discharge_receipt")},
             "control": {"status": control["status"],
                         "discharge_receipt": control.get("discharge_receipt")}})


# --------------------------------------------------------------------------- #
# S2b: nested static-instance dispatch (image-wide writer completeness)
# --------------------------------------------------------------------------- #


def _nested_fixture(*, extra_instance=False, rogue_value=False,
                    unproven_writer=False, c_void_writer=False):
    """A second-level dispatch plus a controlled set of pointer-field writers.

    The consumer loads ``ctx.hw`` (offset 0xb8) and calls ``hw.cipher``
    (offset 0x8).  ``HW_A`` and ``HW_B`` are declared ``static Hw`` instances;
    every mutation below changes only the writer population.
    """
    class _P:
        pass

    class G:
        name = "nested-fixture.so"
        source_root = None
        start_set = {0x3000, 0x3100, 0x3200, 0x3300, 0x3400}
        funcs = {0x1000: "consumer", 0x2000: "init_a",
                 0x2100: "init_b", 0x2200: "rogue_writer",
                 0x2300: "unproven_writer", 0x2400: "typed_writer",
                 0x2500: "get_ptr",
                 0x3000: "f0", 0x3100: "f1", 0x3200: "f2",
                 0x3300: "f3", 0x3400: "f4"}
        all_syms = dict(funcs)
        names_at = {0x9000: {"HW_A"}, 0x9100: {"HW_B"},
                    0x3000: {"f0"}, 0x3100: {"f1"}, 0x3200: {"f2"},
                    0x3300: {"f3"}, 0x3400: {"f4"}}
        sym_sizes = {"HW_A": 16, "HW_B": 16}
        dynamic_defs = {}
        taken_code = set()
        slot_funcs = {}

        def section_of(self, a):
            return ".data.rel.ro" if a in (0x9000, 0x9100) else ".text"

        def static_slot(self, a):
            return {0x9000: {0x3000}, 0x9008: {0x3100},
                    0x9100: {0x3000}, 0x9108: {0x3200}}.get(a)

    g = G()
    p = _P()
    consumer = [(0x1000, "mov    0xb8(%rdi),%rax"),
                (0x1004, "call   *0x8(%rax)")]
    writer_a = [(0x2000, "mov    $0x9000,%rax"),
                (0x2004, "mov    %rax,0xb8(%rdi)")]
    writer_b = [(0x2100, "mov    $0x9100,%rax"),
                (0x2104, "mov    %rax,0xb8(%rdi)")]
    rogue = [(0x2200, "mov    $0xc000,%rax"),
             (0x2204, "mov    %rax,0xb8(%rdi)")]
    unproven = [(0x2300, "call   0x2500"),
                (0x2304, "mov    $0x9000,%rdx"),
                (0x2308, "mov    %rdx,0xb8(%rax)")]
    typed = [(0x2400, "mov    $0x9000,%rax"),
             (0x2404, "mov    %rax,0xb8(%rdi)")]
    p.insns_by_func = {0x1000: consumer, 0x2000: writer_a,
                       0x2100: writer_b, 0x2200: rogue,
                       0x2300: unproven, 0x2400: typed,
                       0x2500: [(0x2500, "ret")]}
    if extra_instance:
        p.insns_by_func[0x2100] = writer_b
    else:
        del p.insns_by_func[0x2100]
    if not rogue_value:
        del p.insns_by_func[0x2200]
    if not unproven_writer:
        del p.insns_by_func[0x2300]
    if not c_void_writer:
        del p.insns_by_func[0x2400]
    g.precision = p
    g._s1_ctx_cache = {0x1000: {"file": "src/nested.rs",
                                "function": "consumer", "line": 1,
                                "var": "ctx", "type": "Ctx",
                                "param": "vctx", "param_index": 0,
                                "declared": "vctx: *mut Ctx"}}
    g._s1_docs_cache = {"src/nested.rs": (
        "#[repr(C)]\n"
        "pub struct Ctx {\n"
        "    pub pad: [u8; 0xb8],\n"
        "    pub hw: *const Hw,\n"
        "    pub other: usize,\n"
        "}\n"
        "#[repr(C)]\n"
        "pub struct Hw {\n"
        "    pub init: unsafe extern \"C\" fn(*mut Ctx) -> c_int,\n"
        "    pub cipher: unsafe extern \"C\" fn(*mut Ctx) -> c_int,\n"
        "}\n"
        "static HW_A: Hw = Hw { init: f0, cipher: f1 };\n"
        "static HW_B: Hw = Hw { init: f0, cipher: f2 };\n")}

    def span(header, body):
        return {"file": "src/nested.rs", "line": 10, "header": header,
                "body": body}

    g._s1_writer_src_cache = {
        0x2000: {"file": "src/nested.rs", "name": "init_a", "via": "module",
                 "span": span("unsafe extern \"C\" fn init_a(vctx: *mut Ctx, "
                               "hw: *const Hw)",
                               "(*vctx).hw = hw;")},
        0x2100: {"file": "src/nested.rs", "name": "init_b", "via": "module",
                 "span": span("unsafe extern \"C\" fn init_b(vctx: *mut Ctx, "
                               "hw: *const Hw)",
                               "(*vctx).hw = hw;")},
        0x2200: {"file": "src/nested.rs", "name": "rogue_writer",
                 "via": "module",
                 "span": span("unsafe extern \"C\" fn rogue_writer("
                               "vctx: *mut Ctx)", "(*vctx).hw = 0xc000;")},
        0x2300: {"file": "src/nested.rs", "name": "unproven_writer",
                 "via": "module",
                 "span": span("unsafe extern \"C\" fn unproven_writer("
                               "vctx: *mut Ctx)", "(*vctx).hw = get();")},
        0x2400: {"file": "src/nested.rs", "name": "typed_writer",
                 "via": "module",
                 "span": span("unsafe extern \"C\" fn typed_writer("
                               "vctx: *mut c_void, hw: *const Hw)",
                               "let ctx = vctx.cast::<Ctx>(); "
                               "(*ctx).hw = hw;")},
        0x2500: {"file": "src/nested.rs", "name": "get_ptr",
                 "via": "module",
                 "span": span("unsafe extern \"C\" fn get_ptr("
                               ") -> *mut c_void", "core::ptr::null_mut()")},
    }
    site = {"kind": "call", "func": 0x1000, "addr": 0x1004,
            "text": "call   *0x8(%rax)", "targets": set(),
            "unresolved": True, "reason": "base-slot-partial",
            "class": "field", "field_offsets": {0xb8}, "seam": None}
    return g, site


def case_nested_static_instance_writer_completeness():
    """The S2b rule is complete only when the writer population is complete."""
    g, site = _nested_fixture()
    complete = cc.nested_static_instance_witness(g, site, "consumer")
    complete_ok = (isinstance(complete, dict) and complete.get("resolved")
                   and complete.get("targets") == ["0x3100"]
                   and complete["completeness"]["stores_at_slot"] == 1
                   and complete["completeness"]["unproven_base_stores"] == 0)

    g, site = _nested_fixture(extra_instance=True)
    widened = cc.nested_static_instance_witness(g, site, "consumer")
    widened_ok = (isinstance(widened, dict) and widened.get("resolved")
                  and widened.get("targets") == ["0x3100", "0x3200"]
                  and widened["completeness"]["stores_at_slot"] == 2)

    g, site = _nested_fixture(rogue_value=True)
    rogue = cc.nested_static_instance_witness(g, site, "consumer")
    rogue_ok = (isinstance(rogue, dict) and not rogue.get("resolved")
                and rogue.get("refusal") == "unaccounted-writer-value")

    g, site = _nested_fixture(unproven_writer=True)
    unproven = cc.nested_static_instance_witness(g, site, "consumer")
    unproven_ok = (isinstance(unproven, dict) and not unproven.get("resolved")
                   and unproven.get("refusal") == "writer-set-incomplete"
                   and unproven.get("unproven_base_stores"))

    g, site = _nested_fixture(c_void_writer=True)
    cast = cc.nested_static_instance_witness(g, site, "consumer")
    cast_ok = (isinstance(cast, dict) and cast.get("resolved")
               and cast.get("targets") == ["0x3100"]
               and any(r.get("base_origin") == "entry-parameter-cast"
                       for r in cast.get("stored_by", [])))

    ok = complete_ok and widened_ok and rogue_ok and unproven_ok and cast_ok
    return _case(
        "s2b-nested-static-instance-writer-completeness",
        "a context pointer field whose pointee is a repr(C) table of function "
        "pointers, with a controlled writer population",
        "prove the member target set from the declared static instances; then "
        "add a second valid instance, a writer storing an undeclared value, a "
        "writer whose base is not the context type, and a c_void entry "
        "parameter whose body cast names the context type",
        "the complete writer set proves {0x3100}; a new valid instance widens "
        "it to {0x3100,0x3200}; an undeclared value refuses as "
        "unaccounted-writer-value; an unproven base refuses as "
        "writer-set-incomplete; a unique body cast qualifies the base and "
        "still proves {0x3100}",
        (f"complete={complete_ok}, widened={widened_ok}, "
         f"rogue={rogue_ok}, unproven={unproven_ok}, cast={cast_ok}"),
        ok, {"complete": complete, "widened": widened, "rogue": rogue,
             "unproven": unproven, "cast": cast})


def _nested_const_table_fixture(*, elements=2, bad_element=False):
    """A context pointer field written by a phi of leas into one const table.

    ``const METHODS: [FnSlot; N]`` lives at ``0x9000`` under one immutable
    data symbol of size ``8 * N``.  The writer selects elements with a branch
    (a CFG phi of two ``lea`` instructions); the consumer calls ``slot.f``
    (member offset 0).  Only ``elements`` and ``bad_element`` change.
    """

    class _P:
        pass

    class G:
        name = "nested-const-table-fixture.so"
        source_root = None
        start_set = {0x3000, 0x3100, 0x3200, 0x3300, 0x3400, 0x3500}
        funcs = {0x1000: "consumer", 0x2000: "set_hw",
                 0x3000: "f0", 0x3100: "f1", 0x3200: "f2",
                 0x3300: "f3", 0x3400: "f4", 0x3500: "f5"}
        all_syms = dict(funcs)
        all_syms[0x9000] = "anon.const.methods"
        names_at = {0x9000: {"anon.const.methods"},
                    0x3000: {"f0"}, 0x3100: {"f1"}, 0x3200: {"f2"},
                    0x3300: {"f3"}, 0x3400: {"f4"}, 0x3500: {"f5"}}
        sym_sizes = {"anon.const.methods": 8 * elements}
        dynamic_defs = {}
        taken_code = set()
        slot_funcs = {}

        def section_of(self, a):
            return ".data.rel.ro" if 0x9000 <= a < 0x9100 else ".text"

        def static_slot(self, a):
            vals = {0x9000: {0x3100}, 0x9008: {0x3200}, 0x9010: {0x3300}}
            if bad_element:
                vals[0x9008] = {0xC000}
            return vals.get(a)

    g = G()
    p = _P()
    # A CFG phi: each branch materialises one element of the same table.
    writer = [(0x2000, "test   %esi,%esi"),
              (0x2001, "je     2008"),
              (0x2002, "lea    0x9000(%rip),%rcx        # 9000"),
              (0x2007, "jmp    200a"),
              (0x2008, "lea    0x9008(%rip),%rcx        # 9008"),
              (0x200a, "mov    %rcx,0xb0(%rdi)")]
    p.insns_by_func = {0x1000: [(0x1000, "mov    0xb0(%rdi),%rax"),
                                (0x1004, "call   *(%rax)")],
                       0x2000: writer}
    g.precision = p
    g._s1_ctx_cache = {0x1000: {"file": "src/const_table.rs",
                                "function": "consumer", "line": 1,
                                "var": "ctx", "type": "Ctx",
                                "param": "vctx", "param_index": 0,
                                "declared": "vctx: *mut Ctx"}}
    g._s1_docs_cache = {"src/const_table.rs": (
        "#[repr(C)]\n"
        "pub struct Ctx {\n"
        "    pub pad: [u8; 0xb0],\n"
        "    pub hw: *const FnSlot,\n"
        "}\n"
        "#[repr(C)]\n"
        "pub struct FnSlot {\n"
        "    pub f: unsafe extern \"C\" fn(*mut Ctx) -> c_int,\n"
        "}\n")}
    g._s1_writer_src_cache = {
        0x2000: {"file": "src/const_table.rs", "name": "set_hw",
                 "via": "module",
                 "span": {"file": "src/const_table.rs", "line": 10,
                          "header": ("unsafe extern \"C\" fn set_hw("
                                     "vctx: *mut Ctx, hw: *const FnSlot)"),
                          "body": ("(*vctx).hw = if compressed { &METHODS[1] } "
                                   "else { &METHODS[0] };")}},
    }
    site = {"kind": "call", "func": 0x1000, "addr": 0x1004,
            "text": "call   *(%rax)", "targets": set(),
            "unresolved": True, "reason": "base-slot-partial",
            "class": "field", "field_offsets": {0xB0}, "seam": None}
    return g, site


def case_nested_local_const_table_phi():
    """A phi of leas into one const table resolves to the complete table."""
    g, site = _nested_const_table_fixture(elements=2)
    two = cc.nested_static_instance_witness(g, site, "consumer")
    two_ok = (isinstance(two, dict) and two.get("resolved")
              and two.get("targets") == ["0x3100", "0x3200"]
              and two.get("local_const_tables")
              and two["local_const_tables"][0]["count"] == 2)

    g, site = _nested_const_table_fixture(elements=3)
    three = cc.nested_static_instance_witness(g, site, "consumer")
    three_ok = (isinstance(three, dict) and three.get("resolved")
                and three.get("targets") == ["0x3100", "0x3200", "0x3300"]
                and three["local_const_tables"][0]["count"] == 3)

    g, site = _nested_const_table_fixture(elements=3, bad_element=True)
    bad = cc.nested_static_instance_witness(g, site, "consumer")
    bad_ok = (isinstance(bad, dict) and not bad.get("resolved")
              and bad.get("refusal") == "writer-set-incomplete"
              and any(row.get("reason") ==
                      "local-const-table-element-not-function"
                      for row in bad.get("unaccounted_values") or ()))

    ok = two_ok and three_ok and bad_ok
    return _case(
        "s2b-nested-local-const-table-phi",
        "a context pointer field whose value is a CFG phi of two leas into "
        "one in-image const table, with the consumer calling slot.f",
        "prove the two selected elements; then declare a third element no lea "
        "selects; then make one element's selected member a non-function",
        "the phi proves exactly {0x3100,0x3200}; the length comes from the "
        "containing symbol and stride, so the 3-element table proves the "
        "complete {0x3100,0x3200,0x3300} even though only two leas name it; "
        "a non-function member refuses with the specific element reason",
        (f"two={two_ok}, three={three_ok}, bad={bad_ok}"),
        ok, {"two": two, "three": three, "bad": bad})


def _nested_chain_fixture(*, second_writer=False, other_type=False,
                          vector_same=False, vector_other=False,
                          whole_copy=False):
    """A one-level chain ``ctx->key->hw`` with a controlled writer set.

    The call reads ``hw->cipher`` (member offset 8).  Writers store the table
    pointer into ``Key.hw`` at offset 0; a store at the *same displacement*
    through an ``Other`` base is present only when requested, and a vector
    copy either shares the ``Key`` owner type (a real overlap) or an ``Other``
    one (provably disjoint).
    """

    class _P:
        pass

    class G:
        name = "nested-chain-fixture.so"
        source_root = None
        start_set = {0x3000, 0x3100, 0x3200, 0x3300, 0x3400}
        funcs = {0x1000: "consumer", 0x2000: "init_a", 0x2100: "init_b",
                 0x2200: "other_init", 0x2300: "vector_same",
                 0x2400: "vector_other", 0x2500: "copy_key",
                 0x3000: "f0", 0x3100: "f1", 0x3200: "f2",
                 0x3300: "f3", 0x3400: "f4"}
        all_syms = dict(funcs)
        names_at = {0x9000: {"HW_A"}, 0x9100: {"HW_B"},
                    0x3000: {"f0"}, 0x3100: {"f1"}, 0x3200: {"f2"},
                    0x3300: {"f3"}, 0x3400: {"f4"}}
        sym_sizes = {"HW_A": 16, "HW_B": 16}
        dynamic_defs = {}
        taken_code = set()
        slot_funcs = {}

        def section_of(self, a):
            return ".data.rel.ro" if a in (0x9000, 0x9100) else ".text"

        def static_slot(self, a):
            return {0x9000: {0x3000}, 0x9008: {0x3100},
                    0x9100: {0x3000}, 0x9108: {0x3200}}.get(a)

    g = G()
    p = _P()
    consumer = [(0x1000, "mov    (%rdi),%rax"),
                (0x1004, "mov    (%rax),%rax"),
                (0x1008, "call   *0x8(%rax)")]
    init_a = [(0x2000, "mov    $0x9000,%rax"),
              (0x2004, "mov    %rax,(%rdi)")]
    init_b = [(0x2100, "mov    $0x9100,%rax"),
              (0x2104, "mov    %rax,(%rdi)")]
    other = [(0x2200, "mov    $0xc000,%rax"),
             (0x2204, "mov    %rax,(%rdi)")]
    vec_same = [(0x2300, "movups %xmm0,(%rdi)")]
    vec_other = [(0x2400, "movups %xmm0,(%rdi)")]
    copy_key = [(0x2500, "movups (%rsi),%xmm0"),
                (0x2502, "movups %xmm0,(%rdi)")]
    p.insns_by_func = {0x1000: consumer, 0x2000: init_a}
    if second_writer:
        p.insns_by_func[0x2100] = init_b
    if other_type:
        p.insns_by_func[0x2200] = other
    if vector_same:
        p.insns_by_func[0x2300] = vec_same
    if vector_other:
        p.insns_by_func[0x2400] = vec_other
    if whole_copy:
        p.insns_by_func[0x2500] = copy_key
    g.precision = p
    g._s1_ctx_cache = {0x1000: {"file": "src/chain.rs",
                                "function": "consumer", "line": 1,
                                "var": "ctx", "type": "Ctx",
                                "param": "ctx", "param_index": 0,
                                "declared": "ctx: *mut Ctx"}}
    g._s1_docs_cache = {"src/chain.rs": (
        "#[repr(C)]\n"
        "pub struct Ctx {\n"
        "    pub key: *const Key,\n"
        "}\n"
        "#[repr(C)]\n"
        "pub struct Key {\n"
        "    pub hw: *const Hw,\n"
        "    pub pad: [u8; 8],\n"
        "}\n"
        "#[repr(C)]\n"
        "pub struct Hw {\n"
        "    pub init: unsafe extern \"C\" fn(*mut Ctx) -> c_int,\n"
        "    pub cipher: unsafe extern \"C\" fn(*mut Ctx) -> c_int,\n"
        "}\n"
        "#[repr(C)]\n"
        "pub struct Other {\n"
        "    pub hw: *const u8,\n"
        "}\n"
        "static HW_A: Hw = Hw { init: f0, cipher: f1 };\n"
        "static HW_B: Hw = Hw { init: f0, cipher: f2 };\n")}

    def span(header, body):
        return {"file": "src/chain.rs", "line": 10, "header": header,
                "body": body}

    g._s1_writer_src_cache = {
        0x2000: {"file": "src/chain.rs", "name": "init_a", "via": "module",
                 "span": span("unsafe extern \"C\" fn init_a(key: *mut Key)",
                               "(*key).hw = &HW_A;")},
        0x2100: {"file": "src/chain.rs", "name": "init_b", "via": "module",
                 "span": span("unsafe extern \"C\" fn init_b(key: *mut Key)",
                               "(*key).hw = &HW_B;")},
        0x2200: {"file": "src/chain.rs", "name": "other_init",
                 "via": "module",
                 "span": span("unsafe extern \"C\" fn other_init("
                               "o: *mut Other)", "(*o).hw = 0xc000;")},
        0x2300: {"file": "src/chain.rs", "name": "vector_same",
                 "via": "module",
                 "span": span("unsafe extern \"C\" fn vector_same("
                               "key: *mut Key)",
                               "core::ptr::write_bytes(key, 0, 1);")},
        0x2400: {"file": "src/chain.rs", "name": "vector_other",
                 "via": "module",
                 "span": span("unsafe extern \"C\" fn vector_other("
                               "o: *mut Other)",
                               "core::ptr::write_bytes(o, 0, 1);")},
        0x2500: {"file": "src/chain.rs", "name": "copy_key",
                 "via": "module",
                 "span": span("unsafe extern \"C\" fn copy_key("
                               "dst: *mut Key, src: *const Key)",
                               "*dst = *src;")},
    }
    site = {"kind": "call", "func": 0x1000, "addr": 0x1008,
            "text": "call   *0x8(%rax)", "targets": set(),
            "unresolved": True, "reason": "base-slot-partial",
            "class": "field", "field_offsets": {0}, "seam": None}
    return g, site


def case_nested_chain_field_writer_index():
    """The writer index is keyed by (owning type, field), not displacement."""
    g, site = _nested_chain_fixture()
    chain = cc.nested_static_instance_witness(g, site, "consumer")
    chain_ok = (isinstance(chain, dict) and chain.get("resolved")
                and chain.get("targets") == ["0x3100"]
                and chain["completeness"]["stores_at_slot"] == 1
                and chain["pointer_slot"]["object"] == "Key"
                and chain["pointer_slot"]["field"] == "hw"
                and len(chain["pointer_slot"].get("chain") or []) == 2)

    g, site = _nested_chain_fixture(second_writer=True)
    widened = cc.nested_static_instance_witness(g, site, "consumer")
    widened_ok = (isinstance(widened, dict) and widened.get("resolved")
                  and widened.get("targets") == ["0x3100", "0x3200"]
                  and widened["completeness"]["stores_at_slot"] == 2)

    g, site = _nested_chain_fixture(other_type=True)
    other = cc.nested_static_instance_witness(g, site, "consumer")
    other_ok = (isinstance(other, dict) and other.get("resolved")
                and other.get("targets") == ["0x3100"]
                and other["completeness"]["excluded_different_object_stores"] >= 1)

    g, site = _nested_chain_fixture(vector_same=True)
    overlap = cc.nested_static_instance_witness(g, site, "consumer")
    overlap_ok = bool(isinstance(overlap, dict) and not overlap.get("resolved")
                      and overlap.get("refusal") == "writer-set-incomplete"
                      and overlap.get("overlapping_non_scalar_stores"))

    g, site = _nested_chain_fixture(vector_other=True)
    disjoint = cc.nested_static_instance_witness(g, site, "consumer")
    disjoint_ok = (isinstance(disjoint, dict) and disjoint.get("resolved")
                   and disjoint.get("targets") == ["0x3100"])

    ok = (chain_ok and widened_ok and other_ok and overlap_ok and disjoint_ok)
    return _case(
        "s2b-nested-chain-field-writer-index",
        "a one-level object chain ctx->key->hw whose table pointer field is "
        "written at one displacement by several possible owning types",
        "resolve only the writers keyed by (Key, hw@0); add a second Key "
        "writer, a same-displacement Other writer, a same-type vector copy, "
        "and a different-type vector copy",
        "the chain proves {0x3100}; a second Key writer widens it to "
        "{0x3100,0x3200}; the Other store is not counted and does not break "
        "the proof; the same-type vector copy refuses as "
        "writer-set-incomplete; the different-type vector copy is disjoint",
        (f"chain={chain_ok}, widened={widened_ok}, other={other_ok}, "
         f"overlap={overlap_ok}, disjoint={disjoint_ok}"),
        ok, {"chain": chain, "widened": widened, "other": other,
             "overlap": overlap, "disjoint": disjoint})


def case_nested_same_owner_whole_struct_copy():
    """A same-owner whole-object copy cannot add a target."""
    g, site = _nested_chain_fixture(whole_copy=True)
    copied = cc.nested_static_instance_witness(g, site, "consumer")
    copied_ok = (isinstance(copied, dict) and copied.get("resolved")
                 and copied.get("targets") == ["0x3100"]
                 and copied.get("same_owner_whole_struct_copies")
                 and not copied.get("overlapping_non_scalar_stores"))

    g, site = _nested_chain_fixture(vector_same=True)
    unsourced = cc.nested_static_instance_witness(g, site, "consumer")
    unsourced_ok = (isinstance(unsourced, dict)
                    and not unsourced.get("resolved")
                    and unsourced.get("refusal") == "writer-set-incomplete")

    ok = copied_ok and unsourced_ok
    return _case(
        "s2b-nested-same-owner-whole-struct-copy",
        "a Key.hw pointer field plus a whole-Key copy from another Key object",
        "add a copy that loads offset 0 of a same-owner source and stores it "
        "at offset 0 of the destination; keep a copy with no source witness",
        "the same-owner whole-object copy is accounted and the proven set is "
        "unchanged ({0x3100}); a copy without a source witness still refuses",
        (f"copied={copied_ok}, unsourced={unsourced_ok}"),
        ok, {"copied": copied, "unsourced": unsourced})


def _nested_symbol_fixture(*, other=False, undemanglable=False,
                           whole_copy=False, generic=None):
    """A Key.hw writer typed only by its function symbol.

    ``Key`` and ``Other`` are distinct repr(C) structs.  The store functions
    have no source span on purpose, so their base type can come only from the
    demangled symbol: a method receiver (``<Key as Store>::store``) or the
    generic argument of a whole-object primitive (``drop_in_place<Key>``).
    A symbol that names no type, or two types, must keep the refusal.
    """

    class _P:
        pass

    class G:
        name = "nested-symbol-fixture.so"
        source_root = None
        start_set = {0x3000, 0x3100, 0x3200, 0x3300, 0x3400}
        funcs = {0x1000: "consumer",
                 0x2300: "_RNvMs_Key_store",
                 0x2400: "_RNvMs_Other_store",
                 0x2500: "_Rundemanglable_zzz",
                 0x2600: "_RNvMs_Key_copy",
                 0x2700: "_Rdrop_in_place_generic",
                 0x3000: "f0", 0x3100: "f1", 0x3200: "f2",
                 0x3300: "f3", 0x3400: "f4"}
        all_syms = dict(funcs)
        names_at = {0x9000: {"HW_A"}, 0x9100: {"HW_B"},
                    0x3000: {"f0"}, 0x3100: {"f1"}, 0x3200: {"f2"},
                    0x3300: {"f3"}, 0x3400: {"f4"}}
        sym_sizes = {"HW_A": 16, "HW_B": 16}
        dynamic_defs = {}
        taken_code = set()
        slot_funcs = {}

        def section_of(self, a):
            return ".data.rel.ro" if a in (0x9000, 0x9100) else ".text"

        def static_slot(self, a):
            return {0x9000: {0x3000}, 0x9008: {0x3100},
                    0x9100: {0x3000}, 0x9108: {0x3200}}.get(a)

    g = G()
    p = _P()
    consumer = [(0x1000, "mov    (%rdi),%rax"),
                (0x1004, "mov    (%rax),%rax"),
                (0x1008, "call   *0x8(%rax)")]
    key_store = [(0x2300, "mov    $0x9000,%rax"),
                 (0x2304, "mov    %rax,(%rdi)")]
    other_store = [(0x2400, "mov    $0x9100,%rax"),
                   (0x2404, "mov    %rax,(%rdi)")]
    undem = [(0x2500, "mov    $0x9000,%rax"),
             (0x2504, "mov    %rax,(%rdi)")]
    copy_key = [(0x2600, "movups (%rdi),%xmm0"),
                (0x2604, "movups %xmm0,(%rdi)")]
    generic_store = [(0x2700, "mov    $0x9000,%rax"),
                     (0x2704, "mov    %rax,(%rdi)")]
    if generic == "other":
        generic_store = [(0x2700, "mov    $0x9100,%rax"),
                         (0x2704, "mov    %rax,(%rdi)")]
    p.insns_by_func = {0x1000: consumer}
    if generic in (None, "other"):
        p.insns_by_func[0x2300] = key_store
    if other:
        p.insns_by_func[0x2400] = other_store
    if undemanglable:
        p.insns_by_func[0x2500] = undem
    if whole_copy:
        p.insns_by_func[0x2600] = copy_key
    if generic is not None:
        p.insns_by_func[0x2700] = generic_store
    g.precision = p
    g._s1_ctx_cache = {0x1000: {"file": "src/sym.rs",
                                "function": "consumer", "line": 1,
                                "var": "ctx", "type": "Ctx",
                                "param": "ctx", "param_index": 0,
                                "declared": "ctx: *mut Ctx"}}
    g._s1_docs_cache = {"src/sym.rs": (
        "#[repr(C)]\n"
        "pub struct Ctx {\n"
        "    pub key: *const Key,\n"
        "}\n"
        "#[repr(C)]\n"
        "pub struct Key {\n"
        "    pub hw: *const Hw,\n"
        "    pub pad: [u8; 8],\n"
        "}\n"
        "#[repr(C)]\n"
        "pub struct Other {\n"
        "    pub hw: *const u8,\n"
        "}\n"
        "#[repr(C)]\n"
        "pub struct Hw {\n"
        "    pub init: unsafe extern \"C\" fn(*mut Ctx) -> c_int,\n"
        "    pub cipher: unsafe extern \"C\" fn(*mut Ctx) -> c_int,\n"
        "}\n"
        "static HW_A: Hw = Hw { init: f0, cipher: f1 };\n"
        "static HW_B: Hw = Hw { init: f0, cipher: f2 };\n"
        "pub trait Store {\n"
        "    unsafe fn store(ptr: *mut Self);\n"
        "    unsafe fn copy(ptr: *mut Self);\n"
        "}\n")}
    g._s1_demangle_cache = {
        0x2300: ("<openssl_rs[abc]::sym::Key as "
                 "openssl_rs[abc]::sym::Store>::store"),
        0x2400: ("<openssl_rs[abc]::sym::Other as "
                 "openssl_rs[abc]::sym::Store>::store"),
        0x2500: "_Rundemanglable_zzz",
        0x2600: ("<openssl_rs[abc]::sym::Key as "
                 "openssl_rs[abc]::sym::Store>::copy"),
        0x2700: "_Rdrop_in_place_generic",
    }
    if generic == "key":
        g._s1_demangle_cache[0x2700] = (
            "core::ptr::drop_in_place<openssl_rs[abc]::sym::Key>")
    elif generic == "other":
        g._s1_demangle_cache[0x2700] = (
            "core::ptr::drop_in_place<openssl_rs[abc]::sym::Other>")
    elif generic == "two":
        g._s1_demangle_cache[0x2700] = (
            "core::ptr::drop_in_place<openssl_rs[abc]::sym::Key, "
            "openssl_rs[abc]::sym::Other>")
    elif generic == "none":
        g._s1_demangle_cache[0x2700] = "_Rundemanglable_zzz"
    site = {"kind": "call", "func": 0x1000, "addr": 0x1008,
            "text": "call   *0x8(%rax)", "targets": set(),
            "unresolved": True, "reason": "base-slot-partial",
            "class": "field", "field_offsets": {0}, "seam": None}
    return g, site


def case_nested_symbol_writer_typing():
    """A method symbol's receiver type qualifies or excludes a store base."""
    g, site = _nested_symbol_fixture()
    typed = cc.nested_static_instance_witness(g, site, "consumer")
    typed_ok = (isinstance(typed, dict) and typed.get("resolved")
                and typed.get("targets") == ["0x3100"]
                and any(r.get("base_symbol_owner") == "Key"
                        for r in typed.get("stored_by", [])))

    g, site = _nested_symbol_fixture(other=True)
    other = cc.nested_static_instance_witness(g, site, "consumer")
    other_ok = (isinstance(other, dict) and other.get("resolved")
                and other.get("targets") == ["0x3100"]
                and other["completeness"]["excluded_different_object_stores"] >= 1
                and any(r.get("symbol_owner") == "Other"
                        for r in other.get("excluded_different_object_stores", [])))

    g, site = _nested_symbol_fixture(undemanglable=True)
    undem = cc.nested_static_instance_witness(g, site, "consumer")
    undem_ok = (isinstance(undem, dict) and not undem.get("resolved")
                and undem.get("refusal") == "writer-set-incomplete"
                and undem.get("unproven_base_stores"))

    g, site = _nested_symbol_fixture(whole_copy=True)
    copied = cc.nested_static_instance_witness(g, site, "consumer")
    copied_ok = (isinstance(copied, dict) and copied.get("resolved")
                 and copied.get("targets") == ["0x3100"]
                 and copied.get("same_owner_whole_struct_copies")
                 and not copied.get("overlapping_non_scalar_stores"))

    ok = typed_ok and other_ok and undem_ok and copied_ok
    return _case(
        "s2b-nested-symbol-writer-typing",
        "a Key.hw writer whose source is absent but whose mangled method "
        "symbol names the receiver type",
        "add a symbol-typed Key writer, a symbol-typed Other writer, an "
        "undemanglable writer symbol, and a same-owner whole-Key copy",
        "the Key symbol writer is counted; the Other symbol writer is "
        "excluded with Other as the witness; the undemanglable symbol keeps "
        "the writer-set-incomplete refusal; the same-owner copy adds no "
        "target and leaves the set at {0x3100}",
        (f"typed={typed_ok}, other={other_ok}, undem={undem_ok}, "
         f"copied={copied_ok}"),
        ok, {"typed": typed, "other": other, "undem": undem,
             "copied": copied})


def case_nested_symbol_generic_writer_typing():
    """A whole-object primitive's generic argument types the store base."""
    g, site = _nested_symbol_fixture(generic="key")
    key = cc.nested_static_instance_witness(g, site, "consumer")
    key_ok = (isinstance(key, dict) and key.get("resolved")
              and key.get("targets") == ["0x3100"]
              and any(r.get("base_symbol_owner") == "Key"
                      and r.get("base_symbol_basis") == "generic-argument"
                      for r in key.get("stored_by", [])))

    g, site = _nested_symbol_fixture(generic="other")
    other = cc.nested_static_instance_witness(g, site, "consumer")
    other_ok = (isinstance(other, dict) and other.get("resolved")
                and other.get("targets") == ["0x3100"]
                and any(r.get("symbol_owner") == "Other"
                        for r in other.get(
                            "excluded_different_object_stores", [])))

    g, site = _nested_symbol_fixture(generic="none")
    none = cc.nested_static_instance_witness(g, site, "consumer")
    none_stores = (none.get("unproven_base_stores") or []) if isinstance(
        none, dict) else []
    none_ok = (isinstance(none, dict) and not none.get("resolved")
               and none.get("refusal") == "writer-set-incomplete"
               and bool(none_stores)
               and all(not r.get("symbol_owner") for r in none_stores))

    g, site = _nested_symbol_fixture(generic="two")
    two = cc.nested_static_instance_witness(g, site, "consumer")
    two_stores = (two.get("unproven_base_stores") or []) if isinstance(
        two, dict) else []
    two_ok = (isinstance(two, dict) and not two.get("resolved")
              and two.get("refusal") == "writer-set-incomplete"
              and bool(two_stores)
              and all(not r.get("symbol_owner") for r in two_stores))

    ok = key_ok and other_ok and none_ok and two_ok
    return _case(
        "s2b-nested-symbol-generic-writer-typing",
        "a sourceless Key.hw writer whose only type evidence is the generic "
        "argument of the enclosing whole-object primitive symbol",
        "use drop_in_place<Key>, drop_in_place<Other>, a symbol with no type "
        "argument, and a symbol naming two candidate types",
        "the Key instantiation is counted for Key.hw; the Other instantiation "
        "is excluded as a different owner; the untyped and two-type symbols "
        "stay unqualified and keep the writer-set-incomplete refusal",
        (f"key={key_ok}, other={other_ok}, none={none_ok}, two={two_ok}"),
        ok, {"key": key, "other": other, "none": none, "two": two})


CASES = (
    case_identical_rebuild,
    case_layout_perturbation,
    case_symbol_rename,
    case_thunk_substitution,
    case_argument_callback,
    case_unknown_target_injection,
    case_unreachable_target,
    case_module_rename,
    case_target_set_shrunk,
    case_chain_row_removed,
    case_chain_step_fabricated,
    case_chain_step_payload_free,
    case_stale_admitted_accounting,
    case_exclusion_names_admitted_target,
    case_reachable_member_flipped,
    case_declared_absent_present,
    case_stale_excluded_accounting,
    case_icf_duplicate_target,
    case_oracle_disagreement,
    case_oracle_agreement,
    case_h10_caller_bound_positive,
    case_h1_target_evidence_binding,
    case_h2_claim_module_binding,
    case_h3_icf_alias,
    case_h4_forged_caller_count,
    case_h5_no_writer_self_contradiction,
    case_h5_declared_name_unrelated,
    case_h6_semantic_excluded_caller,
    case_h6_caller_bound_dropped_target,
    case_h7_candidate_deleted,
    case_h8_vacuous_target_set,
    case_h8_question_function,
    case_h9_duplicate_edge_id,
    case_declared_name_free_text,
    case_declared_name_target_membership,
    case_declared_name_targets_not_candidates,
    case_declared_name_structured_clean,
    case_target_drop_with_subject_row,
    case_writer_used_as_target_drop,
    case_forged_contributed_targets,
    case_argument_source_mapping_required,
    case_dropped_target_not_excluded_contribution,
    case_candidates_equal_admitted_plus_excluded,
    case_writer_would_store_binding,
    case_target_reachability_derived,
    case_sidecar_default_workdir,
    case_tool_identity_sha256,
    # round 4: per-call-site attribution for every caller + conservative fallback
    case_caller_attribution_from_summary,
    case_unattributed_candidate_admitted,
    case_zero_attribution_unresolved,
    case_attribution_witness_mismatch,
    case_unattributed_admission_forged,
    case_zero_attribution_proved_refused,
    # v1.5: monotone bound, least-fixed-point admission, analysis identity
    case_fixpoint_reaches_nested_unresolved,
    case_monotone_bound_under_classification_loss,
    case_neutral_rebuild,
    case_identity_covers_data_inputs,
    case_symbol_unresolved_refusal,
    case_symbol_alias_resolved,
    case_symbol_external_contract,
    case_symbol_refusal_mutation_control,
    case_reachable_digest_canonicalisation,
    # v1.6: admission by refutation of unsound exclusions
    case_admission_refuted_caller,
    case_admission_surviving_caller,
    case_admission_widens_to_unresolved,
    case_admission_disabled_control,
    case_admission_unconditional_control,
    # v1.7: documentation state never removes an obligation from the queue
    case_documented_obligation_persists,
    case_documentation_stripped_obligation_persists,
    case_new_unsafe_fn_enters,
    case_removed_operation_leaves_with_reason,
    case_legacy_inventory_documented_site_persists,
    case_contracted_record_line_drift_stable_identity,
    case_plan_without_ledger_does_not_enroll,
    # v1.8: the queue carries forward previously enumerated obligations
    case_carried_forward_contract_not_in_ledger,
    case_carried_forward_bounded_to_enumerated,
    case_carried_forward_removed_operation_recorded,
    # v1.9: carried entries require reachability, and a discharge requires
    # stable identity plus the operation's current coordinate
    case_carried_forward_unreachable_file_removed,
    case_stale_range_does_not_discharge,
    # S2b: nested static-instance dispatch and image-wide writer completeness
    case_nested_static_instance_writer_completeness,
    # S2b: (owning type, field) writer index across a one-level object chain
    case_nested_chain_field_writer_index,
    # S2b: a phi/select of leas into one local const table, complete length
    case_nested_local_const_table_phi,
    # S2b: a same-owner whole-object copy propagates only existing values
    case_nested_same_owner_whole_struct_copy,
    # S2b: a base typed by the enclosing method symbol's receiver
    case_nested_symbol_writer_typing,
    # S2b: a base typed by a whole-object primitive's generic argument
    case_nested_symbol_generic_writer_typing,
)

NOT_COVERED = [
    "real linker behaviour at scale (section GC, identical-code folding, "
    "symbol versioning)",
    "link-time optimisation (LTO) and cross-language inlining",
    "PLT/GOT tricks beyond the fixture's link-time constant thunk slot",
    "dlopen-supplied and dlsym-resolved targets",
    "provider dispatch tables selected at runtime",
    "admission by refutation of a *real* excluded writer/caller; the corpus "
    "exercises the caller-bound shape on a synthetic bound, not a real image",
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
            "A monotone residual bound is not a completeness result: the fixpoint "
            "cannot admit a function that no materialised-address evidence names, "
            "and the closure cases use synthetic evidence, not a real image.",
            "The neutral-rebuild case is a metamorphic relation on the identity "
            "function.  Byte-identical .text across independent real builds is a "
            "separate measurement, not something this fixture establishes.",
            "The identity cases bind the enumerated analysis inputs (sections, "
            "relocations, symbol tables, loader entries).  They do not prove "
            "that no other input exists, and the fixtures are not real ELF "
            "section tables.",
            "The fixtures are synthetic and do not reproduce the real "
            "library's layout, linker behaviour, or runtime dispatch.",
            "The refusal cases establish that the named disagreements are "
            "detected; they do not establish that every real derivation is "
            "complete.",
            "The validator compares a record's own ledgers (target_set, "
            "admitted_targets, provenance chain) and the final upper-bound "
            "oracle.  The ledgers are mutually redundant within the record, "
            "not independent derivations.  It does not re-derive the target "
            "set to a fixpoint, so a record that is internally consistent and "
            "consistent with the upper bound is not thereby proved complete, "
            "and it cannot distinguish an analyzer-produced record from a "
            "forged one that is internally consistent.  Admissibility needs "
            "the identity chain (tool sha256, artefact sha256, sidecar digest) "
            "and a re-run of the pinned validator over the pinned sidecar.",
        ],
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"out": str(out), "summary": doc["summary"]}, indent=1))
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
