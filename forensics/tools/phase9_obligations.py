#!/usr/bin/env python3
"""openssl-rs — the Phase 9 obligation ledger, and it is a *projection*.

Phase 9 is the random layer: `rand.h`'s front, the BN random family behind it, the providers'
DRBG framework and its three instantiations, and the seed sources those draw on.
`docs/PHASE-9-SUBPHASES.md` is its plan and this ledger is the machine-checkable arithmetic
behind it.

This ledger does not decide its own universe
--------------------------------------------
The universe comes from `forensics/atlas/symbol-ownership.json`, which assigns every one of the
authority's 6,499 exports to exactly one stratum by one stated rule
(`forensics/tools/ownership_rules.py`, D72). This file selects the rows the atlas assigns to
Phase 9 and reports them, and it adds the symbols earlier strata handed over.

**And the hand-offs are the larger half, which is the finding this ledger exists to make
visible.** The atlas gives Phase 9 **twenty-five** exports, all of them `rand.h`'s. The other
**sixty-eight** arrive as recorded edges from phases 4, 5, 7 and 8: bodies whose declaring
header belongs to an earlier stratum and whose *body* is the random layer. Phase 9's work
therefore lives in ten earlier strata's modules, and a ledger that showed only its own header
would understate the stratum by a factor of nearly four (docs/DECISIONS.md D294).

The edges are discovered rather than typed: every row of every `forensics/phase*-obligations.json`
whose `owning_phase` is 9, so a stratum that defers a symbol to this one is recorded on both
sides by construction.

Four situations, kept apart
---------------------------
  * **implemented** -- the crate defines the symbol.
  * **open** -- this stratum's, not built yet. The only list that blocks the stratum.
  * **deferred** -- a recorded hand-off to a later stratum with the dependency named.
  * **handoffs_discharged** -- the reverse edge, discovered above.

Outputs
-------
  forensics/phase9-obligations.json

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

OUT = REPO_ROOT / "forensics" / "phase9-obligations.json"
GENERATOR = "forensics/tools/phase9_obligations.py"
PHASE = 9
ATLAS_OWNERSHIP = "forensics/atlas/symbol-ownership.json"

# Which module of the crate is expected to hold a symbol. A **label**: the universe comes from
# the atlas, and `main` fails when any symbol the atlas gives this stratum (or an earlier one
# hands it) fits no entry here.
#
# **Order is part of the meaning.** `module_of` answers with the first entry that matches, so
# `BN_rand` has to precede nothing here but `BN_generate_dsa_nonce` has to precede
# `BN_generate_prime`s, and `BN_priv_rand` must come before any shorter `BN_p` spelling.
#
# **The hand-off rows are labelled with the module of the stratum that owns the header**, not
# with a `src/rand/` home, because that is where the crate will build them: the authority wrote
# the random call *inside* the key type's constructor, and moving it would be a different
# library. `BIO_f_reliable` is the worked example -- its body is `sig_out`'s random fill in
# `crypto/evp/bio_ok.c`, and the module that will hold it is `src/evp/bio_enc.rs`.
MODULE_PREFIXES: list[tuple[str, tuple[str, ...]]] = [
    # 9.1 -- the BN random family, and the two neighbours in `crypto/bn/` whose bodies are the
    # same primitive. `bn_rand.c` also holds `BN_generate_dsa_nonce`, which is why it is here
    # rather than with the prime generators.
    ("src/bn/rand.rs", ("BN_bntest_rand", "BN_generate_dsa_nonce", "BN_priv_rand",
                        "BN_pseudo_rand", "BN_rand")),
    ("src/bn/blinding.rs", ("BN_BLINDING_",)),
    # `bn_prime.c`, `bn_x931p.c` and the primality tests. `BN_X931_` comes before nothing that
    # contains it, and `BN_generate_prime` must not capture `BN_generate_dsa_nonce` -- which it
    # cannot, because that name is claimed by the row above, which is why the order holds.
    ("src/bn/primes.rs", ("BN_check_prime", "BN_generate_prime", "BN_is_prime", "BN_X931_")),
    ("src/bn/gf2m.rs", ("BN_GF2m_mod_solve_quad", "BN_GF2m_mod_sqrt")),
    # 9.2 -- the front, and `rand_uniform.c`'s two consumers with it.
    ("src/rand/mod.rs", ("RAND_",)),
    # 9.6 -- the hand-offs, each labelled with the module of the stratum that owns its header.
    ("src/des/mod.rs", ("DES_",)),
    ("src/rsa/mod.rs", ("RSA_",)),
    ("src/dh/mod.rs", ("DH_",)),
    ("src/dsa/mod.rs", ("DSA_",)),
    ("src/ec/mod.rs", ("EC",)),
    ("src/pem/pem_lib.rs", ("PEM_",)),
    ("src/hpke/mod.rs", ("OSSL_HPKE_",)),
    # The two `BIO_` hand-offs whose crate home is already filed under another module, named
    # before the catch-all below so the label is where the code actually is: `BIO_f_nbio_test` is
    # `crypto/bio/bf_nbio.c` and lands in `src/runtime/bio/`, and `BIO_f_reliable` is
    # `crypto/evp/bio_ok.c` and landed in `src/evp/bio_ok.rs`.
    ("src/runtime/bio/", ("BIO_f_nbio_test",)),
    ("src/evp/bio_ok.rs", ("BIO_f_reliable",)),
    ("src/evp/bio_enc.rs", ("BIO_",)),
    ("src/evp/", ("EVP_",)),
]


# ---------------------------------------------------------------------------------------------
# The blocked hand-offs. **Empty, and that is a measurement rather than an omission.**
#
# The rule is Phase 8's: a symbol whose declaring header is this stratum's but whose *body* needs
# a name no module of this crate defines, with the reason naming the callee, the authority file
# and line the call sits on, and the stratum that owns the callee. Phase 9 owns the random layer
# itself, so every symbol it receives lands here: the ninety-three are blocked on nothing but
# this stratum's own work, and a same-stratum blocker is recorded as `open` rather than as a
# hand-off, because a stratum cannot hand a symbol to itself.
#
# Two rows were *removed* from phase 8's table into this stratum's `open` list rather than
# deferred onward -- `DH_KDF_X9_42` and `ECDH_KDF_X9_62` -- because phase 8's own row named the
# condition under which its owner was wrong and the provider plan answers it
# (docs/DECISIONS.md D296).
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
    look exactly like "no stratum deferred anything to Phase 9" -- and for this stratum that
    would hide sixty-eight of its ninety-three symbols.
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
            "phase9-obligations: no earlier stratum's ledger is readable, so the incoming "
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
            "phase9-obligations: the ownership atlas assigns this stratum no exports, "
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
                    f"phase9-obligations: {sym} is both the atlas's for phase {PHASE} and "
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
            "phase9-obligations: the ownership atlas gives this stratum (or an earlier "
            "stratum handed it) exports that no entry in MODULE_PREFIXES labels, so the "
            "ledger cannot say which module is expected to hold them -- add a label:\n  "
            + "\n  ".join(f"{s}  ({owned[s]['declaring_header']})" for s in unlabelled)
        )

    # The fail-closed deferral mechanism, unchanged from Phase 8: a symbol in `BLOCKED_HANDOFFS`
    # that the crate now defines is a stale row rather than a harmless one, because a table that
    # can keep covering a landed symbol can hide the next real gap behind it.
    blocked: dict[str, dict] = {}
    for symbols, phase, reason in BLOCKED_HANDOFFS:
        for sym in symbols:
            if sym not in owned:
                raise SystemExit(
                    f"phase9-obligations: BLOCKED_HANDOFFS names {sym}, which is not in this "
                    f"stratum's working set (or is not an authority export at all)"
                )
            if sym in done:
                raise SystemExit(
                    f"phase9-obligations: BLOCKED_HANDOFFS records {sym} as blocked on phase "
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
            "phase9-obligations: the ledger does not account for exactly its own working "
            f"set: owned={len(owned)} implemented={len(implemented_here)} "
            f"deferred={len(deferred_names)} open={len(open_rows)}"
        )

    body = {
        "rule": (
            "the stratum's working set is the projection of forensics/atlas/"
            "symbol-ownership.json for phase 9, plus every symbol an earlier stratum's "
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
            "the stratum, and it starts at the whole working set, which is the honest "
            "starting state. Nothing here is a parity claim: a symbol in `implemented` is "
            "at most `IMPLEMENTED` in docs/PARITY_MODEL.md terms, and docs/PHASE-9-"
            "SUBPHASES.md section 4 decides when the stratum may be called complete."
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
    doc = envelope(kind="phase9-obligations", authority=auth.id, inputs=inputs,
                   body=body, generator=GENERATOR)
    write_json(OUT, doc)

    c = body["counts"]
    print(f"[phase9-obligations] atlas={c['atlas_owned']} "
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
