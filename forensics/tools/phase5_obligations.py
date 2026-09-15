#!/usr/bin/env python3
"""openssl-rs — the Phase 5 obligation ledger, and it is a *projection*.

This ledger does not decide its own universe
--------------------------------------------
It used to. The rule was stated correctly -- *a symbol belongs to the stratum that
owns the header declaring it* -- but the candidates were chosen with a prefix test,
`^(BN_|ASN1_|d2i_|i2d_|PEM_)`. So discovery and assignment used different rules,
and an export like `a2d_ASN1_OBJECT` (declared in `asn1.h`, matching no prefix) was
invisible to this ledger, to every other ledger and to `ownership_audit.py`
simultaneously. That is the D49/D51 defect class a third time.

The universe now comes from `forensics/atlas/symbol-ownership.json`, which assigns
**every one of the authority's 6,499 exports** to exactly one stratum by one stated
rule (`forensics/tools/ownership_rules.py`, documented in D72). This file selects
the rows that atlas assigns to Phase 5 and reports them as owned / implemented /
handed-on / open. There is no prefix here and no per-symbol judgement: a symbol
this ledger does not mention is a symbol the atlas gives to another stratum, and a
symbol the atlas gives to this stratum cannot be absent from the ledger.

The hand-off machinery (`HANDED_ON`) is unchanged and is not a discovery
mechanism: a hand-off names a *dependency* on a subsystem that does not exist yet,
which is why each row carries the stratum that will absorb it and a reason.

Failure is loud. An empty projection, an atlas that cannot be read, or an export
the atlas could not assign stops the run; none of them quietly becomes "unowned".

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import re
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

OUT = REPO_ROOT / "forensics" / "phase5-obligations.json"
GENERATOR = "forensics/tools/phase5_obligations.py"

# Which stratum owns a header. An entry is a *decision*, and the value is the
# phase that will implement the subsystem the header declares. Headers not listed
# here stop the run: silence would be an assignment by default, which is how a
# symbol becomes invisible.
HEADER_PHASE: dict[str, int] = {
    # Phase 5 — this stratum.
    "bn.h": 5,
    "asn1.h": 5,
    "asn1t.h": 5,
    # Phase 6 — the provider core and library contexts.
    "core_names.h": 6,
    "core_object.h": 6,
    "provider.h": 6,
    "params.h": 6,
    # Phase 7 — EVP.
    "evp.h": 7,
    # Phase 8 — the native primitives, whose key types live in these headers.
    "dsa.h": 8,
    "dh.h": 8,
    "rsa.h": 8,
    "ec.h": 8,
    # Phase 10 — persistence and interchange.
    "pkcs12.h": 10,
    "store.h": 10,
    "encoder.h": 10,
    "decoder.h": 10,
    # Phase 11 — X.509 and path validation.
    "x509.h": 11,
    "x509v3.h": 11,
    "x509_acert.h": 11,
    "x509_vfy.h": 11,
    # Phase 12 — the remaining protocol families.
    "cms.h": 12,
    "ocsp.h": 12,
    "ts.h": 12,
    "pkcs7.h": 12,
    "crmf.h": 12,
    "cmp.h": 12,
    "ess.h": 12,
    "ct.h": 12,
}

# Which module of Phase 5 owns a header it claims.
MODULE_OF_HEADER: dict[str, str] = {
    "bn.h": "src/bn/",
    "asn1.h": "src/asn1/",
    "asn1t.h": "src/asn1/",
    "pem.h": "src/pem/",
}

# The prefix *projection* of the header rule above, in the shape
# `forensics/tools/ownership_audit.py` consumes: that audit asks whether every
# implemented export is claimed by some phase family, and it reads families as
# prefixes. The authoritative rule for this stratum remains the declaring header —
# the prefixes cannot separate `d2i_X509` from `d2i_ASN1_INTEGER`, which is the
# whole reason the rule is header-based — so this list is deliberately the union of
# what the modules' symbols actually look like, and a symbol that fits no entry here
# is exactly what that audit exists to surface.
#
# `PEM_write_bio_ASN1_stream` is declared in `asn1.h` and so belongs to `src/asn1/`,
# while `d2i_PKCS8PrivateKey_*`/`i2d_PKCS8PrivateKey_*` are declared in `pem.h` and
# belong to `src/pem/`; both are named here because a prefix cannot express them.
FAMILIES = [
    ("src/bn/", ("BN_",)),
    ("src/asn1/", ("ASN1_", "d2i_", "i2d_", "PEM_write_bio_ASN1_stream",
                   "BIO_asn1_", "BIO_f_asn1", "BIO_new_NDEF")),
    ("src/pem/", ("PEM_", "d2i_PKCS8PrivateKey", "i2d_PKCS8PrivateKey")),
]

# Symbols the Phase 4 ledger hands to this stratum (`forensics/phase4-obligations.json`,
# `deferred` rows whose `owning_phase` is 5). Each is a BIO that exists only to carry
# an ASN.1 or DER codec, so the obligation is this stratum's even though the code
# that needed the sink already lives in Phase 4. Declaring them here is what lets
# `ownership_audit.py` prove the two ledgers agree: Phase 4 must list exactly these
# as deferred to Phase 5, and this stratum must list exactly these as the hand-offs
# it discharged, so no symbol can be counted as implemented by two strata at once.
HANDED_OFF_FROM_PHASE4 = (
    "BIO_asn1_get_prefix",
    "BIO_asn1_get_suffix",
    "BIO_asn1_set_prefix",
    "BIO_asn1_set_suffix",
    "BIO_f_asn1",
    "BIO_new_NDEF",
)

# Exports of this stratum's families that a *later* stratum owns outright, with the
# reason. `bn.h` declares every one of them, so they are this stratum's by D64's rule;
# what they need is the RAND/DRBG subsystem, which is Phase 9 and which does not exist
# yet. The reason is therefore a dependency rather than a judgement about difficulty,
# which is what makes each row checkable: `crypto/bn/bn_rand.c` and its callers reach
# `RAND_bytes_ex`, and the RAND stratum is where that lands.
#
# A hand-off is not a gap -- `open` is the only list that blocks the stratum -- but it
# is also not parity, so the seal states the count and the reason rather than quietly
# moving them out of view.
HANDED_ON: dict[str, tuple[int, str]] = {}
HANDED_ON.update({
    sym: (9, "draws from the RAND subsystem; RAND/DRBG is Phase 9")
    for sym in (
        "BN_rand", "BN_rand_ex", "BN_rand_range", "BN_rand_range_ex",
        "BN_priv_rand", "BN_priv_rand_ex", "BN_priv_rand_range",
        "BN_priv_rand_range_ex", "BN_pseudo_rand", "BN_pseudo_rand_range",
        "BN_bntest_rand",
    )
})
HANDED_ON.update({
    sym: (9, "draws prime candidates with BN_priv_rand; RAND is Phase 9")
    for sym in ("BN_generate_prime", "BN_generate_prime_ex", "BN_generate_prime_ex2")
})
HANDED_ON.update({
    sym: (9, "picks Miller-Rabin bases with BN_priv_rand_range; RAND is Phase 9")
    for sym in (
        "BN_check_prime", "BN_is_prime", "BN_is_prime_ex",
        "BN_is_prime_fasttest", "BN_is_prime_fasttest_ex",
    )
})
HANDED_ON.update({
    sym: (9, "draws candidates with BN_priv_rand; RAND is Phase 9")
    for sym in (
        "BN_X931_derive_prime_ex", "BN_X931_generate_Xpq",
        "BN_X931_generate_prime_ex",
    )
})
HANDED_ON.update({
    sym: (9, "searches with a random field element; RAND is Phase 9")
    for sym in (
        "BN_GF2m_mod_sqrt", "BN_GF2m_mod_sqrt_arr",
        "BN_GF2m_mod_solve_quad", "BN_GF2m_mod_solve_quad_arr",
    )
})
HANDED_ON.update({
    sym: (9, "re-creates the blinding factor through BN_BLINDING_create_param, "
              "which draws it from RAND; RAND is Phase 9")
    for sym in (
        "BN_BLINDING_create_param", "BN_BLINDING_update",
        "BN_BLINDING_convert", "BN_BLINDING_convert_ex",
    )
})
HANDED_ON["BN_generate_dsa_nonce"] = (
    9, "derives a nonce from the digest and entropy; RAND is Phase 9",
)
HANDED_ON.update({
    sym: (7, "digests and signs through EVP_PKEY/EVP_MD/X509_ALGOR; the EVP "
             "framework is Phase 7 and the algorithm identifier is Phase 11")
    for sym in ("ASN1_item_sign_ex", "ASN1_item_verify_ex")
})

# Two CONF modules that `asn1.h` declares. They are registered with
# `CONF_module_add`, which Phase 4 handed to Phase 6 because only the module
# registry constructs a `CONF_MODULE` -- so neither can be written before that
# registry exists, whatever the ASN.1 stratum owns.
HANDED_ON["ASN1_add_oid_module"] = (
    6, "registers a CONF module with CONF_module_add, which Phase 4 handed to "
       "Phase 6 because only the module registry constructs a CONF_MODULE",
)
# The two string generators in `asn1_gen.c`. Both take an `X509V3_CTX *` --
# `x509v3.h`'s structure, Phase 11 -- and `ASN1_generate_nconf` *constructs* one
# through the `X509V3_set_nconf` macro even on its null-`CONF` path, so neither can
# be written without that structure. `ASN1_str2mask`, in the same translation unit,
# depends on nothing outside this stratum and Phase 4, so it is written here.
HANDED_ON.update({
    sym: (11, "reads an X509V3_CTX through X509V3_get_string/X509V3_get_section for "
              "the MULTI form and constructs one with X509V3_set_nconf; X509V3_CTX "
              "is x509v3.h's and is Phase 11")
    for sym in ("ASN1_generate_v3", "ASN1_generate_nconf")
})

HANDED_ON["ASN1_add_stable_module"] = (
    11, "registers a CONF module with CONF_module_add (Phase 6, the module "
        "registry) and its handler parses a section value with "
        "X509V3_parse_list (Phase 11); the later of the two dependencies is the "
        "binding one",
)

# D73's hand-offs, which are dispositions by *behaviour* rather than by declaring
# header. `asn1.h` and `pem.h` declare all of these, which is the rule the ownership
# atlas applies, so the atlas gives them to this stratum; what they need is a
# subsystem the stratum above owns.
#
# `SMIME_crlf_copy` is deliberately **not** in this set. It was, on the reason that
# `asn_mime.c` is the CMS/PKCS#7 translation unit -- which is a *file* argument, not a
# dependency, and so the error D49 recorded, committed in the other direction. Its
# only needs are `BIO_f_buffer` and the translation unit's own `strip_eol`, both
# present, so it is implemented here; `SMIME_text` stays because the MIME header
# parser it reads is `asn_mime.c`'s reader, which lands with `SMIME_read_ASN1_ex`.
HANDED_ON.update({
    sym: (12, "operates over CMS and PKCS#7, which is Phase 12; asn_mime.c")
    for sym in (
        "SMIME_read_ASN1", "SMIME_read_ASN1_ex", "SMIME_text",
        "SMIME_write_ASN1", "SMIME_write_ASN1_ex",
    )
})
HANDED_ON.update({
    sym: (7, "writes through BIO_f_base64, the EVP base64 filter BIO that Phase 4 "
              "deferred to Phase 7")
    for sym in ("PEM_write_bio_ASN1_stream",)
})

# `pem.h`'s remaining exports, each with the dependency it is waiting on rather than
# the file it lives in. `crypto/pem/pem_lib.c` is not one subsystem: its reader and
# writer are a base64 codec over `EVP_ENCODE_CTX`, its encrypted writer and reader are
# an `EVP_CIPHER` pass over `EVP_BytesToKey` and `RAND_bytes`, its password callback
# reads a pass phrase through `EVP_read_pw_string_min`, and its signing pair is an
# `EVP_MD_CTX`. Two of its exports need none of that and are implemented in
# `src/pem/pem_lib.rs`; these are the ones that do.
HANDED_ON.update({
    sym: (7, "the PEM block codec is EVP_ENCODE_CTX, which Phase 7 owns (evp.h)")
    for sym in (
        # The reader and the writer of a whole `-----BEGIN ...-----` block.
        "PEM_read", "PEM_read_bio", "PEM_read_bio_ex",
        "PEM_write", "PEM_write_bio",
        # Both are wrappers over the reader above.
        "PEM_bytes_read_bio", "PEM_bytes_read_bio_secmem",
    )
})
HANDED_ON.update({
    sym: (7, "tests the PEM name against EVP_PKEY_asn1_find_str, which Phase 7 owns")
    for sym in ("PEM_ASN1_read", "PEM_ASN1_read_bio")
})
HANDED_ON.update({
    sym: (7, "takes an EVP_CIPHER and derives its key with EVP_BytesToKey and a "
              "RAND_bytes IV, all Phase 7")
    for sym in (
        "PEM_ASN1_write", "PEM_ASN1_write_bio", "PEM_ASN1_write_bio_ctx",
    )
})
HANDED_ON.update({
    sym: (7, "decrypts through EVP_CIPHER_CTX with EVP_BytesToKey, which Phase 7 owns")
    for sym in ("PEM_do_header",)
})
HANDED_ON.update({
    sym: (7, "reads a pass phrase through EVP_read_pw_string_min, which Phase 7 owns")
    for sym in ("PEM_def_callback",)
})
HANDED_ON.update({
    sym: (7, "digests through an EVP_MD_CTX and signs with an EVP_PKEY, which Phase 7 "
              "owns")
    for sym in ("PEM_SignInit", "PEM_SignUpdate", "PEM_SignFinal")
})
HANDED_ON.update({
    sym: (7, "writes an EVP_PKEY's parameters, which Phase 7 owns")
    for sym in ("PEM_write_bio_Parameters",)
})
HANDED_ON.update({
    sym: (11, "encodes through i2d_X509_REQ_NEW, which the X509 stratum owns")
    for sym in ("PEM_write_X509_REQ_NEW", "PEM_write_bio_X509_REQ_NEW")
})
HANDED_ON.update({
    sym: (11, "reads or writes X509_INFO, and every arm of it is an X509, X509_CRL or "
              "X509_PUBKEY decode, all Phase 11")
    for sym in (
        "PEM_X509_INFO_read", "PEM_X509_INFO_read_bio",
        "PEM_X509_INFO_read_ex", "PEM_X509_INFO_read_bio_ex",
        "PEM_X509_INFO_write_bio",
    )
})
HANDED_ON.update({
    sym: (10, "reads and writes the PKCS#8 container, which is Phase 10")
    for sym in (
        "b2i_PrivateKey", "b2i_PrivateKey_bio", "b2i_PublicKey", "b2i_PublicKey_bio",
        "i2b_PrivateKey_bio", "i2b_PublicKey_bio", "b2i_PVK_bio", "b2i_PVK_bio_ex",
        "i2b_PVK_bio", "i2b_PVK_bio_ex",
        "d2i_PKCS8PrivateKey_bio", "d2i_PKCS8PrivateKey_fp",
        "i2d_PKCS8PrivateKey_bio", "i2d_PKCS8PrivateKey_fp",
        "i2d_PKCS8PrivateKey_nid_bio", "i2d_PKCS8PrivateKey_nid_fp",
    )
})
HANDED_ON.update({
    sym: (7, "reads or writes an EVP_PKEY, which is Phase 7")
    for sym in (
        "PEM_read_bio_PrivateKey", "PEM_read_bio_PrivateKey_ex",
        "PEM_read_bio_Parameters", "PEM_read_bio_Parameters_ex",
        "PEM_write_bio_PrivateKey_traditional",
        "PEM_write_bio_PKCS8PrivateKey_nid", "PEM_write_PKCS8PrivateKey_nid",
    )
})

# The two item-list interrogators. `asn1.h` declares them, so the ownership atlas
# gives them to this stratum, but their behaviour is a property of the authority's
# *generated* `asn1_item_list.h` as a whole: which names resolve, and the index
# order `ASN1_ITEM_get` answers in.
#
# Measured against the ownership atlas: that list has **147** entries, and their
# `<name>_it` accessors are owned by this stratum for 40 of them and by Phase 8 for
# 7, Phase 10 for 6, Phase 11 for 64 and Phase 12 for 30. So 107 of the 147 are
# items no stratum before Phase 12 will have, and an implementation over the 40
# that exist today would answer NULL for `X509` — a wrong function that no court
# could catch, because the names it gets wrong are exactly the ones whose codecs
# are later phases'. The dependency is the list, not the difficulty.
#
# Phase 12 is named rather than Phase 11 because the list is only whole once the
# last of its phases has landed, and an item list that is missing its CMS and
# PKCS#7 entries is not a shorter list, it is a different one.
HANDED_ON.update({
    sym: (12, "enumerates the authority's generated asn1_item_list.h, whose 147 "
              "entries include 107 items owned by Phases 8, 10, 11 and 12 "
              "(7/6/64/30); both functions' behaviour is the whole list")
    for sym in ("ASN1_ITEM_lookup", "ASN1_ITEM_get")
})

def load(atlas: Path, name: str) -> dict:
    return json.loads((atlas / name).read_text(encoding="utf-8"))["body"]


def authority_exports(atlas: Path) -> list[str]:
    """The symbols the authority actually exports from libcrypto."""
    return sorted(
        r["symbol"] for r in load(atlas, "symbols-libcrypto.json")["records"]
        if r["dso"]["present"]
    )


def declared_headers(atlas: Path) -> dict[str, str]:
    return {r["name"]: r["header"] for r in load(atlas, "functions.json")["records"]}



def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)

    auth = resolve_authority(args.authority)
    atlas = REPO_ROOT / "forensics" / "atlas" / auth.id
    exports = authority_exports(atlas)
    headers = declared_headers(atlas)

    implemented = set(
        json.loads(
            (REPO_ROOT / "forensics" / "atlas" / "implemented-surface.json").read_text(
                encoding="utf-8"
            )
        )["body"]["libraries"]["libcrypto"]["implemented_symbols"]
    )

    # The stratum's scope comes from the **global ownership atlas**, not from a
    # prefix. `forensics/atlas/symbol-ownership.json` assigns every one of the
    # authority's 6,499 exports to exactly one stratum using the declaring-header
    # rule this tool always documented (D66) and could not previously enforce: a
    # prefix test chose the candidates, so `a2d_ASN1_OBJECT` -- declared in
    # `asn1.h`, matching none of `^(BN_|ASN1_|d2i_|i2d_|PEM_)` -- was invisible to
    # this ledger, to every other ledger and to `ownership_audit.py` at once. That
    # is the D49/D51 defect class, and D72 records the fix: one artifact, one rule,
    # applied to the whole authority, with `unknown == 0` and
    # `multiply_owned == 0` asserted there rather than assumed here.
    atlas_ownership = json.loads(
        (REPO_ROOT / "forensics" / "atlas" / "symbol-ownership.json").read_text(
            encoding="utf-8"
        )
    )["body"]
    mine = [r for r in atlas_ownership["records"] if r["owner_phase"] == 5]
    if not mine:
        raise SystemExit(
            "phase5-obligations: the ownership atlas assigns this stratum no "
            "exports, which means the atlas or this tool is wrong"
        )

    owned: dict[str, dict] = {}
    deferred: list[dict] = []
    unresolved: list[str] = []

    def claim(sym: str, module: str, header: str) -> None:
        owned[sym] = {
            "symbol": sym, "module": module, "declaring_header": header,
        }

    for row in mine:
        sym = row["symbol"]
        header = row["declaring_header"]
        handed = HANDED_ON.get(sym)
        if handed is not None:
            # The header declares it, so the stratum owns it and the ledger counts
            # it as covered -- and then hands it on, because what it needs is a
            # subsystem that does not exist yet. The reason is a *dependency*, not
            # a difficulty, which is what makes the hand-off checkable: RAND is
            # Phase 9, and no RAND surface exists in this crate yet.
            phase, reason = handed
            claim(sym, f"(phase {phase})", header or "bn.h")
            deferred.append({
                "symbol": sym, "owning_phase": phase,
                "declaring_header": header or "bn.h",
                "reason": reason,
            })
            continue
        claim(sym, MODULE_OF_HEADER.get(header, "src/asn1/"), header or "(no installed header)")

    # The hand-offs Phase 4 handed this stratum must be accounted for here: a symbol
    # Phase 4 deferred to Phase 5 that this stratum does not even claim is an
    # obligation that fell between the two ledgers. They do not match the candidate
    # prefix, because the header that declares them is `bio.h` -- Phase 4's header --
    # so they are claimed by name.
    for sym in HANDED_OFF_FROM_PHASE4:
        if sym not in exports:
            raise SystemExit(
                f"phase5-obligations: {sym} is handed from Phase 4 but the "
                "authority does not export it from this build profile"
            )
        owned.setdefault(sym, {
            "symbol": sym,
            "module": "src/asn1/",
            "declaring_header": headers.get(sym, "bio.h"),
        })

    bad = [r for r in deferred if r["owning_phase"] <= 5]
    if bad:
        raise SystemExit(
            "phase5-obligations: a hand-off must name a LATER stratum than this "
            "one:\n  " + "\n  ".join(r["symbol"] for r in bad)
        )

    atlas_symbols = {r["symbol"] for r in mine}
    by_name = [s for s in HANDED_OFF_FROM_PHASE4 if s not in atlas_symbols]
    if len(owned) != len(mine) + len(by_name):
        raise SystemExit(
            "phase5-obligations: the projection covers "
            f"{len(owned)} exports but the atlas assigns this stratum {len(mine)} "
            f"plus {len(by_name)} of the {len(HANDED_OFF_FROM_PHASE4)} Phase 4 "
            "hand-offs (the rest the atlas already assigns, because their "
            "declaration moved to a header this stratum owns)"
        )

    implemented_here = sorted(s for s in owned if s in implemented)
    handed_on = {r["symbol"] for r in deferred}
    open_rows = [
        {"symbol": s, "module": owned[s]["module"],
         "declaring_header": owned[s]["declaring_header"]}
        for s in sorted(owned) if s not in implemented and s not in handed_on
    ]

    body = {
        "rule": (
            "the stratum's scope is the projection of forensics/atlas/"
            "symbol-ownership.json for phase 5: a symbol belongs to the stratum "
            "that owns the header declaring it, `pem.h`'s typed names resolve "
            "through the type's header, and the exports no installed header "
            "declares are dispositioned in ownership_rules.ABI_ONLY_OWNER"
        ),
        "header_phase": dict(sorted(HEADER_PHASE.items())),
        "module_of_header": dict(sorted(MODULE_OF_HEADER.items())),
        "counts": {
            "atlas_owned": len(mine),
            "owned": len(owned),
            "implemented": len(implemented_here),
            "deferred_to_later_phase": len(deferred),
            "open_in_this_stratum": len(open_rows),
        },
        "implemented": implemented_here,
        "deferred": sorted(deferred, key=lambda r: r["symbol"]),
        "open": open_rows,
        "handoffs_discharged": {"4": sorted(HANDED_OFF_FROM_PHASE4)},
        "owned_by_module": dict(
            sorted(
                Counter(
                    v["module"] for v in owned.values()
                    if not v["module"].startswith("(")
                ).items()
            )
        ),
        "deferred_by_phase": dict(
            sorted(Counter(r["owning_phase"] for r in deferred).items())
        ),
        # A hand-off is not a gap. `open` is the only list that blocks the
        # stratum: it is this stratum's unimplemented surface.
        "complete": not open_rows,
        "note": (
            "`owned` is every export the stratum's families cover, which includes the "
            "ones the declaring-header rule hands to a later phase: a deferred symbol "
            "is still matched by this stratum's prefixes, so counting it here is what "
            "makes `implemented + deferred + open == owned`. `open` is the only list "
            "that blocks the stratum. The families are derived from the atlas, not "
            "typed: see this generator's header for why, and note that a deferred "
            "symbol names the stratum that owns the header it is declared in, which is "
            "checkable without reading this file. Nothing here is a parity claim."
        ),
    }

    inputs = [
        InputRef(name="authority-symbols", path=atlas / "symbols-libcrypto.json"),
        InputRef(name="authority-functions", path=atlas / "functions.json"),
        InputRef(name="authority-typedefs", path=atlas / "typedefs.json"),
        InputRef(name="authority-structs", path=atlas / "structs.json"),
        implemented_surface_input(),
    ]
    doc = envelope(kind="phase5-obligations", authority=auth.id, inputs=inputs,
                   body=body, generator=GENERATOR)
    write_json(OUT, doc)

    c = body["counts"]
    print(f"[phase5-obligations] atlas={c['atlas_owned']} owned={c['owned']} "
          f"implemented={c['implemented']} deferred={c['deferred_to_later_phase']} "
          f"open={c['open_in_this_stratum']}")
    print(f"  complete={body['complete']}")
    print(f"  owned by module: {body['owned_by_module']}")
    print(f"  deferred by phase: {body['deferred_by_phase']}")
    for module in sorted(body["owned_by_module"]):
        rows = [r for r in open_rows if r["module"] == module]
        print(f"  open in {module}: {len(rows)}")
    print(f"  -> {rel(OUT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
