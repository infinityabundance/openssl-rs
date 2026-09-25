#!/usr/bin/env python3
"""openssl-rs — the Phase 10 obligation ledger, and it is a *projection*.

Phase 10 is the key-format layer: the `OSSL_ENCODER`/`OSSL_DECODER` codec framework and the
provider rows that publish its codecs, the PKCS#12 container, and `OSSL_STORE`.
`docs/PHASE-10-SUBPHASES.md` is its plan and this ledger is the machine-checkable arithmetic
behind it.

This ledger does not decide its own universe
--------------------------------------------
The universe comes from `forensics/atlas/symbol-ownership.json`, which assigns every one of the
authority's 6,499 exports to exactly one stratum by one stated rule
(`forensics/tools/ownership_rules.py`, D72). This file selects the rows the atlas assigns to
Phase 10 and reports them, and it adds the symbols earlier strata handed over.

**The atlas gives Phase 10 272 exports over four headers** — `pkcs12.h` (117), `store.h` (76),
`decoder.h` (41) and `encoder.h` (38) — and **26 more arrive as recorded edges** from phases 5
and 7. The hand-offs are the PKCS#8 and PVK container readers and writers (`crypto/pem/pvkfmt.c`,
`crypto/pem/pem_pk8.c`) and the four `crypto/asn1/d2i_pr.c`/`i2d_evp.c` readers D354/D355's
siblings handed forward.

**Eighty-seven of the atlas-owned exports are already implemented**, and that is the finding
this ledger exists to make visible rather than the stratum's own count: all 79 `encoder.h`/
`decoder.h` exports and 8 `pkcs12.h` ones were landed by Phase 8's 8.8 chain, because
`crypto/evp/p_lib.c:1196`'s `print_pkey` calls `OSSL_ENCODER_CTX_new_for_pkey` first (D362) and
the decoder framework followed to unblock the `PEM_read_*` readers (D363-D367). So a ledger that
showed a whole working set open would be wrong in the other direction from Phase 9's.

The edges are discovered rather than typed: every row of every `forensics/phase*-obligations.json`
whose `owning_phase` is 10, so a stratum that defers a symbol to this one is recorded on both
sides by construction.

Four situations, kept apart
---------------------------
  * **implemented** -- the crate defines the symbol.
  * **open** -- this stratum's, not built yet. The only list that blocks the stratum.
  * **deferred** -- a recorded hand-off to a later stratum with the dependency named.
  * **handoffs_discharged** -- the reverse edge, discovered above.

Outputs
-------
  forensics/phase10-obligations.json

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

OUT = REPO_ROOT / "forensics" / "phase10-obligations.json"
GENERATOR = "forensics/tools/phase10_obligations.py"
PHASE = 10
ATLAS_OWNERSHIP = "forensics/atlas/symbol-ownership.json"

# Which module of the crate is expected to hold a symbol. A **label**: the universe comes from
# the atlas, and `main` fails when any symbol the atlas gives this stratum (or an earlier one
# hands it) fits no entry here.
#
# **Order is part of the meaning.** `module_of` answers with the first entry that matches, so
# `d2i_PKCS12`/`i2d_PKCS12` have to precede nothing here but `d2i_PKCS8PrivateKey` must not
# capture them -- which it cannot, because `d2i_PKCS8PrivateKey` does not start with
# `d2i_PKCS12`. `i2d_PKCS8PrivateKey` and `i2d_PublicKey` likewise share no prefix.
#
# **The hand-off rows are labelled with the crate module the authority's own defining unit
# names**, not restated as their declaring header: the authority wrote the PKCS#8 container read
# inside `crypto/pem/pem_pk8.c` and the PVK format inside `crypto/pem/pvkfmt.c`, and a label of
# `pem.h` would place them in a module that does not hold them.
MODULE_PREFIXES: list[tuple[str, tuple[str, ...]]] = [
    # The PKCS#12 layer. `crypto/pkcs12/`'s fifteen units all land under one crate module, and
    # the four `OPENSSL_*` conversion helpers (`p12_utl.c`) are the only exports in the stratum
    # whose names carry no `PKCS` prefix, so they are named explicitly.
    ("src/pkcs12/mod.rs", ("OPENSSL_asc2uni", "OPENSSL_uni2asc",
                           "OPENSSL_uni2utf8", "OPENSSL_utf82uni")),
    ("src/pkcs12/mod.rs", ("PKCS12_", "PKCS8_")),
    ("src/pkcs12/mod.rs", ("d2i_PKCS12", "i2d_PKCS12")),
    # The store. `crypto/store/`'s four export-bearing units (`store_lib.c`, `store_meth.c`,
    # `store_register.c`, `store_strings.c`) all land under one crate module.
    ("src/store/mod.rs", ("OSSL_STORE_",)),
    # The codec framework's remainder. Its 79 exports are already implemented as
    # `src/decoder_*.rs`/`src/encoder_*.rs`, so the label names those modules rather than the
    # stratum's plan.
    ("src/decoder_lib.rs", ("OSSL_DECODER_",)),
    ("src/encoder_lib.rs", ("OSSL_ENCODER_",)),
    # The hand-offs. `crypto/pem/pvkfmt.c` (the PVK format), `crypto/pem/pem_pk8.c` (the
    # PKCS#8 container), `crypto/pem/pem_pkey.c` (the traditional-write helper), and Phase 7's
    # `crypto/asn1/d2i_pr.c`/`i2d_evp.c` pair.
    ("src/pem/pvkfmt.rs", ("b2i_", "i2b_")),
    ("src/pem/pem_pk8.rs", ("d2i_PKCS8PrivateKey", "i2d_PKCS8PrivateKey")),
    ("src/pem/pem_pkey.rs", ("PEM_",)),
    ("src/asn1/d2i_pr.rs", ("d2i_AutoPrivateKey", "d2i_PrivateKey")),
    ("src/asn1/i2d_evp.rs", ("i2d_KeyParams", "i2d_PublicKey", "i2d_PrivateKey")),
]


# ---------------------------------------------------------------------------------------------
# The blocked hand-offs. **Empty, and that is a measurement rather than an omission.**
#
# The rule is Phase 8's and Phase 9's: a symbol whose declaring header is this stratum's but
# whose *body* needs a name no module of this crate defines is recorded here with the reason
# naming the callee, the authority file and line the call sits on, and the stratum that owns the
# callee. Phase 10 owns the key-format layer itself, so every symbol it receives lands in `open`
# rather than here: the twenty-six are blocked on nothing but this stratum's own work, and a
# same-stratum blocker is recorded as `open` because a stratum cannot hand a symbol to itself.
#
# The one place a real cross-stratum blocker could appear is the `OSSL_OP_ENCODER` codecs, which
# are provider rows rather than exports and are therefore the census's, not this ledger's; where
# a row is blocked on a later stratum's primitive, `provider-algorithms.json` carries its
# `blocked_by` and `phase_state.py` reads it -- not this file.
# ---------------------------------------------------------------------------------------------

BLOCKED_HANDOFFS: list[tuple[tuple[str, ...], int, str]] = []


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))["body"]


def implemented() -> set[str]:
    doc = json.loads(
        (REPO_ROOT / "forensics" / "atlas" / "implemented-surface.json").read_text(
            encoding="utf-8"
        )
    )
    return set(doc["body"]["libraries"]["libcrypto"]["implemented_symbols"])


def declared_headers(atlas: Path) -> dict[str, str]:
    return {r["name"]: r["header"] for r in load(atlas / "functions.json")["records"]}


def incoming_handoffs() -> dict[int, list[dict]]:
    """Every recorded edge that hands a symbol to this stratum, read from the ledgers.

    The unit of discovery is a *row*, not a name list, so the reason and the declaring header
    travel with the symbol from wherever it was deferred and are not restated here. A ledger that
    cannot be read is a failure rather than an empty edge set: a missing file would otherwise
    look exactly like "no stratum deferred anything to Phase 10" -- and for this stratum that
    would hide all twenty-six of its hand-offs.
    """
    out: dict[int, list[dict]] = {}
    found_any = False
    for path in sorted((REPO_ROOT / "forensics").glob("phase*-obligations.json")):
        try:
            source = int(path.stem.split("-")[0].removeprefix("phase"))
        except ValueError:
            continue
        if source >= PHASE:
            continue
        found_any = True
        for row in load(path).get("deferred", []):
            if int(row["owning_phase"]) != PHASE:
                continue
            out.setdefault(source, []).append(row)
    if not found_any:
        raise SystemExit(
            "phase10-obligations: no earlier stratum's ledger is readable, so the incoming "
            "hand-off set would be empty for the wrong reason"
        )
    return out


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
    headers = declared_headers(atlas)

    ownership = json.loads((REPO_ROOT / ATLAS_OWNERSHIP).read_text(encoding="utf-8"))["body"]
    mine = [r for r in ownership["records"]
            if r["owner_phase"] == PHASE and r["library"] == "libcrypto"]
    if not mine:
        raise SystemExit(
            "phase10-obligations: the ownership atlas assigns this stratum no exports, "
            "which means the atlas or this tool is wrong"
        )

    incoming = incoming_handoffs()
    owned: dict[str, dict] = {}

    for row in mine:
        owned[row["symbol"]] = {
            "module": module_of(row["symbol"]),
            "declaring_header": row.get("declaring_header"),
            "from": None,
        }
    for source, rows in sorted(incoming.items()):
        for row in rows:
            sym = row["symbol"]
            if sym in owned:
                raise SystemExit(
                    f"phase10-obligations: {sym} is both the atlas's for phase {PHASE} and "
                    f"deferred here by phase {source}; one of the two is wrong"
                )
            owned[sym] = {
                "module": module_of(sym),
                "declaring_header": row.get("declaring_header") or headers.get(sym),
                "from": source,
            }

    unlabelled = sorted(s for s, v in owned.items() if v["module"] is None)
    if unlabelled:
        raise SystemExit(
            "phase10-obligations: the ownership atlas gives this stratum (or an earlier "
            "stratum handed it) exports that no entry in MODULE_PREFIXES labels, so the "
            "ledger cannot say which module is expected to hold them -- add a label:\n  "
            + "\n  ".join(f"{s}  ({owned[s]['declaring_header']})" for s in unlabelled)
        )

    # The fail-closed deferral mechanism, unchanged from Phases 8 and 9: a symbol in
    # `BLOCKED_HANDOFFS` that the crate now defines is a stale row rather than a harmless one,
    # because a table that can keep covering a landed symbol can hide the next real gap behind it.
    blocked: dict[str, dict] = {}
    for symbols, phase, reason in BLOCKED_HANDOFFS:
        for sym in symbols:
            if sym not in owned:
                raise SystemExit(
                    f"phase10-obligations: BLOCKED_HANDOFFS names {sym}, which is not in this "
                    f"stratum's working set (or is not an authority export at all)"
                )
            if sym in done:
                raise SystemExit(
                    f"phase10-obligations: BLOCKED_HANDOFFS records {sym} as blocked on phase "
                    f"{phase}, but the crate defines it; retire the row"
                )
            blocked[sym] = {
                "symbol": sym,
                "owning_phase": phase,
                "declaring_header": owned[sym]["declaring_header"],
                "reason": reason,
            }
    deferred_names = set(blocked)
    deferred: list[dict] = sorted(blocked.values(), key=lambda r: r["symbol"])

    implemented_here = sorted(s for s in owned if s in done and s not in deferred_names)
    open_rows = [
        {"symbol": s, "module": owned[s]["module"],
         "declaring_header": owned[s]["declaring_header"],
         "received_from_phase": owned[s]["from"]}
        for s in sorted(owned) if s not in done and s not in deferred_names
    ]

    if len(owned) != len(implemented_here) + len(deferred_names) + len(open_rows):
        raise SystemExit(
            "phase10-obligations: the ledger does not account for exactly its own working "
            f"set: owned={len(owned)} implemented={len(implemented_here)} "
            f"deferred={len(deferred_names)} open={len(open_rows)}"
        )

    body = {
        "rule": (
            "the stratum's working set is the projection of forensics/atlas/"
            "symbol-ownership.json for phase 10, plus every symbol an earlier stratum's "
            "ledger records as handed to it: a symbol belongs to the stratum that owns the "
            "header declaring it, and a discharged hand-off belongs to the stratum that "
            "built it"
        ),
        "module_prefixes": [{"module": m, "prefixes": list(p)}
                            for m, p in MODULE_PREFIXES],
        "counts": {
            "atlas_owned": len(mine),
            "received_by_handoff": sum(len(v) for v in incoming.values()),
            "owned": len(owned),
            "implemented": len(implemented_here),
            "deferred_to_later_phase": len(deferred),
            "open_in_this_stratum": len(open_rows),
        },
        "implemented": implemented_here,
        "deferred": deferred,
        "open": open_rows,
        "handoffs_discharged": {
            str(source): sorted(row["symbol"] for row in rows)
            for source, rows in sorted(incoming.items())
        },
        # The reasons, kept as they were written by the stratum that deferred them rather than
        # restated: a second statement of the same reason is a second thing to keep true, and
        # `ownership_audit.py` compares the two sides already.
        "handoffs_discharged_with_reasons": {
            str(source): sorted(rows, key=lambda r: r["symbol"])
            for source, rows in sorted(incoming.items())
        },
        "owned_by_module": dict(sorted(Counter(v["module"] for v in owned.values()).items())),
        "owned_by_header": dict(
            sorted(Counter(v["declaring_header"] for v in owned.values()).items())
        ),
        "deferred_by_phase": dict(
            sorted(Counter(r["owning_phase"] for r in deferred).items())
        ),
        "complete": not open_rows,
        "note": (
            "`complete` is true only when every export in the working set is either "
            "implemented or handed to a later stratum. `open` is the only list that blocks "
            "the stratum. Unlike every earlier activation this ledger does not start with the "
            "whole working set open: eighty-seven of the atlas-owned exports were landed by "
            "Phase 8's 8.8 chain before this stratum was activated, and the ledger reports "
            "them as `implemented` because `implemented-surface.json` does -- docs/PHASE-10-"
            "SUBPHASES.md section 4 is the measurement. Nothing here is a parity claim: a "
            "symbol in `implemented` is at most `IMPLEMENTED` in docs/PARITY_MODEL.md terms, "
            "and docs/PHASE-10-SUBPHASES.md section 4 decides when the stratum may be called "
            "complete."
        ),
    }

    inputs = [
        InputRef(name="authority-symbols", path=atlas / "symbols-libcrypto.json"),
        InputRef(name="authority-functions", path=atlas / "functions.json"),
        InputRef(name="symbol-ownership", path=REPO_ROOT / ATLAS_OWNERSHIP),
        implemented_surface_input(),
        *[
            InputRef(name=f"phase{source}-obligations",
                     path=REPO_ROOT / f"forensics/phase{source}-obligations.json")
            for source in sorted(incoming)
        ],
    ]
    doc = envelope(kind="phase10-obligations", authority=auth.id, inputs=inputs,
                   body=body, generator=GENERATOR)
    write_json(OUT, doc)

    c = body["counts"]
    print(f"[phase10-obligations] atlas={c['atlas_owned']} "
          f"received={c['received_by_handoff']} owned={c['owned']} "
          f"implemented={c['implemented']} deferred={c['deferred_to_later_phase']} "
          f"open={c['open_in_this_stratum']}")
    print(f"  complete={body['complete']}")
    print(f"  owned by header: {body['owned_by_header']}")
    print(f"  owned by module: {body['owned_by_module']}")
    print(f"  hand-offs discharged: "
          f"{ {k: len(v) for k, v in body['handoffs_discharged'].items()} }")
    print(f"  -> {rel(OUT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
