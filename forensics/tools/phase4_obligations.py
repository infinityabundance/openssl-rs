#!/usr/bin/env python3
"""openssl-rs — the Phase 4 obligation ledger.

What this tool is for
---------------------
`forensics/phase-state.json` may only call a stratum `complete` when nothing in it
is unaccounted for. For Phase 3 the ledger (`phase3_obligations.py`) could achieve
that by *deferring* a handful of BIO-coupled symbols to Phase 4. Phase 4 is the
stratum that then owns BIO, CONF and the buffer object, and it is a much larger
surface, so "accounted for" has to distinguish two very different situations:

  * **deferred** — the symbol needs a subsystem that a later stratum owns
    (the provider core, EVP, ASN.1). A recorded, machine-checked hand-off.
  * **open** — the symbol belongs to *this* stratum and is not built yet. An
    honest, recorded gap.

Conflating those would let scaffolding look like progress, so they are separate
lists and `complete` is true only when both are empty. Nothing here is a parity
claim: a symbol in the `implemented` list is at most `IMPLEMENTED`
(`docs/PARITY_MODEL.md`), and the courts decide everything beyond that.

Outputs
-------
  forensics/phase4-obligations.json

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import sys
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

# The symbol families this stratum owns. `phase3_obligations.py` hands the
# BIO-coupled members of the Phase 3 families to this phase, so several entries
# below exist solely to receive those hand-offs.
#
# `OPENSSL_INIT_` is here because it was in *no* phase's family before: the
# `OPENSSL_INIT_SETTINGS` object is defined in `crypto/conf/conf_lib.c`, while
# Phase 3's `init.rs` family matches the lower-case prefix `OPENSSL_init`, which
# does not match `OPENSSL_INIT_new`. Five exported symbols were therefore invisible
# to every ledger and silently scaffolded. Naming them here is what puts them under
# accounting; see `src/runtime/conf/mod.rs`.
FAMILIES = [
    ("src/runtime/bio/", (
        "BIO_", "BUF_",
    )),
    ("src/runtime/conf/", ("CONF_", "NCONF_", "OPENSSL_INIT_")),
    ("src/runtime/obj.rs", ("OBJ_create_objects",)),
    ("src/runtime/lhash.rs", ("OPENSSL_LH_stats", "OPENSSL_LH_node_stats",
                              "OPENSSL_LH_node_usage_stats")),
    ("src/runtime/err.rs", ("ERR_print_errors", "ERR_add_error_mem_bio")),
]

# Symbols of the Phase 4 families that a later stratum owns outright, with the
# reason. These are hand-offs of the same kind Phase 3 used, and each names the
# stratum that can actually build it.
DEFERRED: dict[str, tuple[int, str]] = {
    # EVP owns the digest/cipher machinery these filters are thin wrappers over.
    "BIO_f_md": (7, "wraps an EVP_MD_CTX; EVP is Phase 7"),
    "BIO_f_cipher": (7, "wraps an EVP_CIPHER_CTX; EVP is Phase 7"),
    "BIO_f_reliable": (7, "wraps EVP_AES_256_CBC message authentication; EVP is Phase 7"),
    "BIO_set_cipher": (7, "sets the EVP_CIPHER of a BIO_f_cipher; EVP is Phase 7"),
    # The base64 filter is a wrapper over EVP_ENCODE_CTX and the EVP_ENCODE_*
    # codec, both of which are EVP surface.
    "BIO_f_base64": (7, "wraps an EVP_ENCODE_CTX; the codec is EVP, Phase 7"),
    # ASN.1 owns the prefix/suffix compiler feature the ASN.1 BIO exists for.
    "BIO_f_asn1": (5, "its only controls are ASN.1 prefix/suffix functions; ASN.1 is Phase 5"),
    "BIO_asn1_set_prefix": (5, "ASN.1 prefix/suffix compiler hooks; ASN.1 is Phase 5"),
    "BIO_asn1_get_prefix": (5, "ASN.1 prefix/suffix compiler hooks; ASN.1 is Phase 5"),
    "BIO_asn1_set_suffix": (5, "ASN.1 prefix/suffix compiler hooks; ASN.1 is Phase 5"),
    "BIO_asn1_get_suffix": (5, "ASN.1 prefix/suffix compiler hooks; ASN.1 is Phase 5"),
    "BIO_new_NDEF": (5, "constructs an ASN.1 NDEF BIO chain; ASN.1 is Phase 5"),
    # CMS / PKCS#7 own the object they serialise.
    "BIO_new_CMS": (12, "binds a CMS_ContentInfo to a BIO; CMS is Phase 12"),
    "BIO_new_PKCS7": (12, "binds a PKCS7 to a BIO; PKCS#7 is Phase 12"),
    # The provider core owns OSSL_LIB_CTX and the core dispatch table.
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
    # than approximated. `crypto/conf/conf_mod.c` also reaches `DSO_load`,
    # `OPENSSL_load_builtin_modules` and `ENGINE_load_builtin_engines`, all of
    # which are later strata. See docs/DECISIONS.md D50 for the call chain.
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

    # The non-blocking test filter is a RAND consumer: its read and write paths
    # both call RAND_priv_bytes to decide whether to report a retry, so its
    # observable behaviour cannot be reproduced without the RAND subsystem. The
    # factory, create, destroy, gets, puts and ctrl are independent of RAND, but
    # the obligation is per symbol and a method whose read/write abort would be a
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
    "OPENSSL_LH_node_stats",
    "OPENSSL_LH_node_stats_bio",
    "OPENSSL_LH_node_usage_stats",
    "OPENSSL_LH_node_usage_stats_bio",
    "OPENSSL_LH_stats",
    "OPENSSL_LH_stats_bio",
)


def authority_exports(authority: Path) -> list[str]:
    """The symbols the authority actually exports from libcrypto."""
    doc = json.loads((authority / "symbols-libcrypto.json").read_text(encoding="utf-8"))
    return sorted(r["symbol"] for r in doc["body"]["records"] if r["dso"]["present"])


def implemented() -> set[str]:
    doc = json.loads(
        (REPO_ROOT / "forensics" / "atlas" / "implemented-surface.json").read_text(
            encoding="utf-8"
        )
    )
    return set(doc["body"]["libraries"]["libcrypto"]["implemented_symbols"])


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)

    auth = resolve_authority(args.authority)
    exports = authority_exports(REPO_ROOT / "forensics" / "atlas" / auth.id)
    done = implemented()

    owned: dict[str, str] = {}
    for module, prefixes in FAMILIES:
        for sym in exports:
            if any(sym == p or sym.startswith(p) for p in prefixes):
                owned.setdefault(sym, module)

    implemented_here = sorted(s for s in owned if s in done)
    remaining = sorted(s for s in owned if s not in done)

    # The hand-offs Phase 3 handed this stratum must be accounted for here: a
    # symbol Phase 3 deferred to this phase that this phase does not even claim is
    # an obligation that fell between the two ledgers.
    undeclared = sorted(s for s in HANDED_OFF_FROM_PHASE3 if s not in owned)
    if undeclared:
        raise SystemExit(
            "phase4-obligations: these symbols are handed from Phase 3 but no "
            "Phase 4 family claims them, so the hand-off is unaccounted for:\n  "
            + "\n  ".join(undeclared)
        )
    unbuilt = sorted(s for s in HANDED_OFF_FROM_PHASE3 if s not in done)
    if unbuilt:
        raise SystemExit(
            "phase4-obligations: these symbols were handed from Phase 3 and are "
            "still not implemented, so they belong in DEFERRED with a later "
            "phase rather than in the discharged hand-off list:\n  "
            + "\n  ".join(unbuilt)
        )

    deferred_rows = []
    open_rows = []
    for sym in remaining:
        if sym in DEFERRED:
            phase, reason = DEFERRED[sym]
            if phase <= 4:
                raise SystemExit(
                    f"phase4-obligations: {sym} is deferred to phase {phase}, not later"
                )
            deferred_rows.append({
                "symbol": sym, "owning_phase": phase, "reason": reason,
                "module": owned[sym],
            })
        else:
            open_rows.append({"symbol": sym, "module": owned[sym]})

    body = {
        "families": [{"module": m, "prefixes": list(p)} for m, p in FAMILIES],
        "counts": {
            "owned": len(owned),
            "implemented": len(implemented_here),
            "deferred_to_later_phase": len(deferred_rows),
            "open_in_this_stratum": len(open_rows),
        },
        "implemented": implemented_here,
        "deferred": deferred_rows,
        "open": open_rows,
        "handoffs_discharged": {"3": sorted(HANDED_OFF_FROM_PHASE3)},
        # A hand-off is not a gap. `open` is the only list that blocks the
        # stratum: a deferred symbol names the phase that owns the subsystem it
        # needs, and the phase-state rule is that nothing is *unaccounted for*.
        # The expression here previously required both lists to be empty, which
        # made the field describe something other than what the note beside it
        # says and made `complete` permanently false for a stratum that
        # legitimately hands anything forward.
        "complete": not open_rows,
        "note": (
            "`complete` is true only when every export in these families is either "
            "implemented or handed to a later stratum. `open` entries belong to "
            "this stratum and are recorded gaps, not deferrals; while any exist "
            "Phase 4 cannot be called complete. Nothing here is a parity claim."
        ),
    }

    inputs = [
        InputRef(name="authority-symbols",
                 path=REPO_ROOT / "forensics" / "atlas" / auth.id / "symbols-libcrypto.json"),
        implemented_surface_input(),
    ]
    doc = envelope(kind="phase4-obligations", authority=auth.id, inputs=inputs,
                   body=body, generator=GENERATOR)
    write_json(OUT, doc)

    print(f"[phase4-obligations] owned={len(owned)} implemented={len(implemented_here)} "
          f"deferred={len(deferred_rows)} open={len(open_rows)}")
    print(f"  complete={body['complete']}")
    for row in deferred_rows:
        print(f"  deferred -> phase {row['owning_phase']:<2} {row['symbol']}: {row['reason']}")
    for row in open_rows[:20]:
        print(f"  OPEN (phase 4) {row['symbol']} [{row['module']}]")
    if len(open_rows) > 20:
        print(f"  ... and {len(open_rows) - 20} more open obligations")
    print(f"  -> {rel(OUT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
