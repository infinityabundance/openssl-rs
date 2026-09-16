#!/usr/bin/env python3
"""openssl-rs — the Phase 4 obligation ledger, and it is a *projection*.

What this tool is for
---------------------
`forensics/phase-state.json` may only call a stratum `complete` when nothing in it
is unaccounted for. Phase 4 is the stratum that owns BIO, CONF and the buffer
object, and "accounted for" has to keep four very different situations apart:

  * **implemented** -- the crate defines the symbol.
  * **open** -- the symbol belongs to *this* stratum and is not built yet. An
    honest, recorded gap, and the only list that blocks the stratum.
  * **deferred** -- the symbol needs a subsystem a later stratum owns. A recorded,
    machine-checked hand-off with the dependency named.
  * **handoffs_discharged** -- the reverse edge: symbols an earlier stratum handed
    to this one, which this stratum then built. Phase 3 handed over sixteen.

Conflating any two of those would let scaffolding look like progress.

This ledger does not decide its own universe
--------------------------------------------
It used to, with a `(module, prefixes)` family list, and that is how nineteen Phase 4
exports -- every `COMP_*`, the three `conf_ssl_*` helpers, `OPENSSL_config` and
`OPENSSL_load_builtin_modules` -- were in no family and therefore in no ledger, while
the stratum's seal called it complete (docs/DECISIONS.md D97). A prefix that matches
nothing reports nothing.

The universe comes from `forensics/atlas/symbol-ownership.json`, which assigns every
one of the authority's 6,499 exports to exactly one stratum by one stated rule (D72).
The prefixes survive only as a *label* -- which module is expected to hold a symbol --
and an unlabelled symbol is reported rather than filed under "other".

Outputs
-------
  forensics/phase4-obligations.json

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    PRODUCTION_AUTHORITY,
    REPO_ROOT,
    InputRef,
    envelope,
    implemented_surface_input,
    rel,
    resolve_authority,
    write_json,
)

OUT = REPO_ROOT / "forensics" / "phase4-obligations.json"
GENERATOR = "forensics/tools/phase4_obligations.py"

ATLAS_OWNERSHIP = "forensics/atlas/symbol-ownership.json"

# Which module of the stratum is expected to hold a symbol. A **label**, not a
# discovery mechanism: the universe comes from the atlas, and `main` fails when any
# symbol the atlas gives this stratum fits no entry here.
MODULE_PREFIXES: list[tuple[str, tuple[str, ...]]] = [
    ("src/runtime/bio/", ("BIO_", "BIO_s_", "BIO_f_", "BIO_new_", "BIO_set_")),
    ("src/runtime/buffer.rs", ("BUF_",)),
    ("src/runtime/bio/comp.rs", ("COMP_",)),
    ("src/runtime/conf/", ("CONF_", "NCONF_", "OPENSSL_INIT_", "OPENSSL_config",
                           "OPENSSL_load_builtin_modules", "conf_ssl_")),
    ("src/runtime/obj.rs", ("OBJ_create_objects",)),
    ("src/runtime/lhash.rs", ("OPENSSL_LH_",)),
    ("src/runtime/err.rs", ("ERR_",)),
]

# Symbols of the projection that a later stratum owns outright, with the dependency
# that places them there. Each reason names a *dependency*, not a difficulty.
HANDED_ON: dict[str, tuple[int, str]] = {
    # The four ASN.1 filter controls. All four are declared in `bio.h` -- this
    # stratum's header -- so the ownership atlas gives them to Phase 4, but each is a
    # control over the streaming encoder the ASN.1 template machinery implements, so
    # the obligation is Phase 5's. Phase 5 built them and declares them discharged in
    # its `handoffs_discharged`; they stay `deferred` here, because a hand-off is
    # sticky and counting Phase 5's work as this stratum's would make this ledger
    # claim work it did not do. See docs/DECISIONS.md D57 and D91.
    **{
        sym: (5, "a control over the streaming encoder the ASN.1 template machinery "
                  "implements; the template machinery is Phase 5")
        for sym in (
            "BIO_asn1_get_prefix", "BIO_asn1_get_suffix",
            "BIO_asn1_set_prefix", "BIO_asn1_set_suffix",
        )
    },
    # The provider core owns `OSSL_LIB_CTX` and the core dispatch table. These two
    # are the provider core's own BIO surface.
    "BIO_s_core": (6, "the provider core-to-BIO method; OSSL_LIB_CTX is Phase 6"),
    "BIO_new_from_core_bio": (6, "wraps an OSSL_CORE_BIO; OSSL_LIB_CTX is Phase 6"),
    # The CONF module registry. `CONF_modules_load` begins with
    # `conf_diagnostics()`, which reads and writes the `OSSL_LIB_CTX`
    # configuration-diagnostics flag, and that flag is not cosmetic: it masks the
    # `CONF_MFLAGS_IGNORE_ERRORS`, `IGNORE_RETURN_CODES`, `SILENT` and
    # `IGNORE_MISSING_FILE` bits of the flags argument, which changes what
    # `CONF_modules_load` and `CONF_modules_load_file*` return. A registry that
    # cannot read the flag reports the wrong result for a real configuration, so
    # the whole family is handed to the stratum that owns `OSSL_LIB_CTX` rather
    # than approximated. `crypto/conf/conf_mod.c` also reaches `DSO_load` and
    # `OPENSSL_load_builtin_modules`, both later strata. See docs/DECISIONS.md D50.
    "CONF_modules_load": (6, "calls conf_diagnostics -> OSSL_LIB_CTX_get/set_conf_diagnostics; OSSL_LIB_CTX is Phase 6"),
    "CONF_modules_load_file": (6, "forwards to CONF_modules_load_file_ex; OSSL_LIB_CTX is Phase 6"),
    "CONF_modules_load_file_ex": (6, "reads and preserves OSSL_LIB_CTX diagnostics, and calls CONF_modules_load; OSSL_LIB_CTX is Phase 6"),
    "CONF_modules_finish": (6, "finishes the initialized-module list, which only CONF_modules_load populates; Phase 6"),
    "CONF_modules_unload": (6, "unloads entries of the module list and calls DSO_free; DSO is a later stratum and OSSL_LIB_CTX is Phase 6"),
    "CONF_module_add": (6, "adds to the supported-module list guarded by the RCU lock that the module registry owns; Phase 6"),
    "CONF_imodule_get_flags": (6, "reads a CONF_IMODULE, which only the module registry creates; Phase 6"),
    "CONF_imodule_get_module": (6, "reads a CONF_IMODULE, which only the module registry creates; Phase 6"),
    "CONF_imodule_get_name": (6, "reads a CONF_IMODULE, which only the module registry creates; Phase 6"),
    "CONF_imodule_get_usr_data": (6, "reads a CONF_IMODULE, which only the module registry creates; Phase 6"),
    "CONF_imodule_get_value": (6, "reads a CONF_IMODULE, which only the module registry creates; Phase 6"),
    "CONF_imodule_set_flags": (6, "writes a CONF_IMODULE, which only the module registry creates; Phase 6"),
    "CONF_imodule_set_usr_data": (6, "writes a CONF_IMODULE, which only the module registry creates; Phase 6"),
    "CONF_module_get_usr_data": (6, "reads a CONF_MODULE, which only the module registry creates; Phase 6"),
    "CONF_module_set_usr_data": (6, "writes a CONF_MODULE, which only the module registry creates; Phase 6"),
    # `crypto/conf/conf_mall.c`. Its whole body is a loop of `CONF_module_add`
    # calls over the built-in modules, so it cannot exist before the registry does.
    # This one was in no ledger at all until D97.
    "OPENSSL_load_builtin_modules": (6, "registers every built-in CONF_MODULE through CONF_module_add, which Phase 6 owns"),
    # The non-blocking test filter is a RAND consumer: its read and write paths both
    # call RAND_priv_bytes to decide whether to report a retry, so its observable
    # behaviour cannot be reproduced without the RAND subsystem. The factory,
    # create, destroy, gets, puts and ctrl are independent of RAND, but the
    # obligation is per symbol and a method whose read/write abort would be a
    # scaffold, not an implementation.
    "BIO_f_nbio_test": (9, "its read and write call RAND_priv_bytes; RAND is Phase 9"),
}

# Symbols the Phase 3 ledger hands to this stratum (`forensics/phase3-obligations.json`,
# `deferred` rows whose `owning_phase` is 4). Every one of them lives in a Phase 3
# module, because that is where the code that needed the sink already was, but the
# obligation is this stratum's: each needs a `BIO *` or a `FILE *`, and BIO is
# Phase 4. Declaring them here is what lets `ownership_audit.py` prove that the two
# ledgers agree -- Phase 3 must list exactly these as deferred to Phase 4, and this
# stratum must list exactly these as the hand-offs it discharged, so no symbol can
# be counted as implemented by two strata at once. See docs/DECISIONS.md D57.
HANDED_OFF_FROM_PHASE3 = (
    "ERR_add_error_mem_bio",
    "ERR_print_errors",
    "ERR_print_errors_cb",
    "ERR_print_errors_fp",
    "OBJ_create_objects",
    "OPENSSL_INIT_free",
    "OPENSSL_INIT_new",
    "OPENSSL_INIT_set_config_appname",
    "OPENSSL_INIT_set_config_file_flags",
    "OPENSSL_INIT_set_config_filename",
    "OPENSSL_LH_node_stats",
    "OPENSSL_LH_node_stats_bio",
    "OPENSSL_LH_node_usage_stats",
    "OPENSSL_LH_node_usage_stats_bio",
    "OPENSSL_LH_stats",
    "OPENSSL_LH_stats_bio",
)


def load(atlas: Path, name: str) -> dict:
    return json.loads((atlas / name).read_text(encoding="utf-8"))["body"]


def implemented() -> set[str]:
    doc = json.loads(
        (REPO_ROOT / "forensics" / "atlas" / "implemented-surface.json").read_text(
            encoding="utf-8"
        )
    )
    return set(doc["body"]["libraries"]["libcrypto"]["implemented_symbols"])


def module_of(symbol: str) -> str | None:
    for module, prefixes in MODULE_PREFIXES:
        for pre in prefixes:
            if symbol == pre or symbol.startswith(pre):
                return module
    return None


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)

    auth = resolve_authority(args.authority)
    atlas = REPO_ROOT / "forensics" / "atlas" / auth.id
    done = implemented()

    ownership = json.loads(
        (REPO_ROOT / ATLAS_OWNERSHIP).read_text(encoding="utf-8")
    )["body"]
    mine = [r for r in ownership["records"]
            if r["owner_phase"] == 4 and r["library"] == "libcrypto"]
    if not mine:
        raise SystemExit(
            "phase4-obligations: the ownership atlas assigns this stratum no "
            "exports, which means the atlas or this tool is wrong"
        )

    unlabelled: list[str] = []
    owned: dict[str, dict] = {}
    deferred: list[dict] = []

    def claim(sym: str, header: str | None) -> None:
        module = module_of(sym)
        owned[sym] = {"module": module, "declaring_header": header}

    for row in mine:
        sym = row["symbol"]
        if module_of(sym) is None:
            unlabelled.append(sym)
            continue
        claim(sym, row.get("declaring_header"))

    # The hand-offs Phase 3 handed this stratum are part of the working set even
    # though the atlas gives their declaring header to Phase 3: they are symbols
    # this stratum implemented, and a stratum's ledger has to contain the work it
    # did as well as the work it owes.
    for sym in HANDED_OFF_FROM_PHASE3:
        if sym not in owned:
            claim(sym, None)

    if unlabelled:
        raise SystemExit(
            "phase4-obligations: the ownership atlas gives this stratum exports "
            "that no entry in MODULE_PREFIXES labels, so the ledger cannot say "
            "which module is expected to hold them -- add a label:\n  "
            + "\n  ".join(sorted(unlabelled))
        )

    undeclared = sorted(s for s in HANDED_OFF_FROM_PHASE3 if s not in done)
    if undeclared:
        raise SystemExit(
            "phase4-obligations: these symbols were handed from Phase 3 and are "
            "still not implemented, so they belong in HANDED_ON with a later phase "
            "rather than in the discharged hand-off list:\n  "
            + "\n  ".join(undeclared)
        )

    for sym in sorted(owned):
        handed = HANDED_ON.get(sym)
        if handed is None:
            continue
        phase, reason = handed
        if phase <= 4:
            raise SystemExit(
                f"phase4-obligations: {sym} is deferred to phase {phase}, "
                "not later"
            )
        deferred.append({
            "symbol": sym, "owning_phase": phase, "reason": reason,
            "module": owned[sym]["module"],
            "declaring_header": owned[sym]["declaring_header"],
            "implemented_by_owner": sym in done,
        })

    handed_on = {r["symbol"] for r in deferred}
    implemented_here = sorted(s for s in owned if s in done and s not in handed_on)
    open_rows = [
        {"symbol": s, "module": owned[s]["module"],
         "declaring_header": owned[s]["declaring_header"]}
        for s in sorted(owned) if s not in done and s not in handed_on
    ]

    if len(owned) != len(implemented_here) + len(handed_on) + len(open_rows):
        raise SystemExit(
            "phase4-obligations: the ledger does not account for exactly its own "
            f"working set: owned={len(owned)} implemented={len(implemented_here)} "
            f"deferred={len(handed_on)} open={len(open_rows)}"
        )

    body = {
        "rule": (
            "the stratum's working set is the projection of forensics/atlas/"
            "symbol-ownership.json for phase 4, plus the symbols Phase 3 handed it: "
            "a symbol belongs to the stratum that owns the header declaring it, and "
            "a discharged hand-off belongs to the stratum that built it"
        ),
        "module_prefixes": [{"module": m, "prefixes": list(p)}
                            for m, p in MODULE_PREFIXES],
        "counts": {
            "atlas_owned": len(mine),
            "received_by_handoff": len(HANDED_OFF_FROM_PHASE3),
            "owned": len(owned),
            "implemented": len(implemented_here),
            "deferred_to_later_phase": len(deferred),
            "open_in_this_stratum": len(open_rows),
        },
        "implemented": implemented_here,
        "deferred": sorted(deferred, key=lambda r: r["symbol"]),
        "open": open_rows,
        "handoffs_discharged": {"3": sorted(HANDED_OFF_FROM_PHASE3)},
        "owned_by_module": dict(
            sorted(Counter(v["module"] for v in owned.values()).items())
        ),
        "deferred_by_phase": dict(
            sorted(Counter(r["owning_phase"] for r in deferred).items())
        ),
        # A hand-off is not a gap. `open` is the only list that blocks the stratum.
        "complete": not open_rows,
        "note": (
            "`complete` is true only when every export in the working set is either "
            "implemented or handed to a later stratum. `open` entries belong to this "
            "stratum and are recorded gaps, not deferrals; while any exist Phase 4 "
            "cannot be called complete, and it is what returned the stratum to "
            "`in-progress` after D97. `implemented_by_owner` on a deferred row records "
            "that the receiving stratum has since discharged the hand-off. Nothing "
            "here is a parity claim."
        ),
    }

    inputs = [
        InputRef(name="authority-symbols",
                 path=atlas / "symbols-libcrypto.json"),
        InputRef(name="symbol-ownership", path=REPO_ROOT / ATLAS_OWNERSHIP),
        implemented_surface_input(),
    ]
    doc = envelope(kind="phase4-obligations", authority=auth.id, inputs=inputs,
                   body=body, generator=GENERATOR)
    write_json(OUT, doc)

    c = body["counts"]
    print(f"[phase4-obligations] atlas={c['atlas_owned']} "
          f"received={c['received_by_handoff']} owned={c['owned']} "
          f"implemented={c['implemented']} deferred={c['deferred_to_later_phase']} "
          f"open={c['open_in_this_stratum']}")
    print(f"  complete={body['complete']}")
    print(f"  owned by module: {body['owned_by_module']}")
    print(f"  deferred by phase: {body['deferred_by_phase']}")
    for row in open_rows:
        print(f"  OPEN {row['symbol']} [{row['module']}]")
    print(f"  -> {rel(OUT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
