#!/usr/bin/env python3
"""openssl-rs — the Phase 8 obligation ledger, and it is a *projection*.

Phase 8 is the native cryptographic primitives: the digests, the symmetric ciphers and
their modes, and the four asymmetric key types (`RSA`, `DH`/`DHX`, `DSA`, `EC`) together
with the ASN.1 method objects that name them. `docs/PHASE-8-SUBPHASES.md` is its plan and
this ledger is the machine-checkable arithmetic behind it.

This ledger does not decide its own universe
--------------------------------------------
The universe comes from `forensics/atlas/symbol-ownership.json`, which assigns every one
of the authority's 6,499 exports to exactly one stratum by one stated rule
(`forensics/tools/ownership_rules.py`, D72). This file selects the rows the atlas assigns
to Phase 8 and reports them, and it adds the symbols earlier strata handed over -- a
stratum's ledger has to contain the work it owes *and* the work it built.

**The hand-offs are read from the other ledgers, not typed here.** Phase 6's generator
lists its incoming edges as a literal, which is right for a stratum that had one source of
them and wrong as a pattern: the list is a fact about four *other* files. Here the edges
are discovered -- every row of every `forensics/phase*-obligations.json` whose
`owning_phase` is 8 -- so a stratum that defers a symbol to this one is recorded on both
sides by construction. Phase 7 deferred **twenty-seven** rows here, and they are the
`EVP_PKEY_*` accessors and the `EVP_PKEY_meth_*`/`d2i_*` readers whose bodies need an
`EVP_PKEY_ASN1_METHOD`, which is 8.8's work.

Four situations, kept apart
---------------------------
  * **implemented** -- the crate defines the symbol.
  * **open** -- this stratum's, not built yet. The only list that blocks the stratum.
    Phase 8 starts with its entire working set here, which is the honest starting state.
  * **deferred** -- a recorded hand-off to a later stratum with the dependency named.
  * **handoffs_discharged** -- the reverse edge, discovered above.

Outputs
-------
  forensics/phase8-obligations.json

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

OUT = REPO_ROOT / "forensics" / "phase8-obligations.json"
GENERATOR = "forensics/tools/phase8_obligations.py"
PHASE = 8
ATLAS_OWNERSHIP = "forensics/atlas/symbol-ownership.json"

# Which module of the stratum is expected to hold a symbol. A **label**: the universe
# comes from the atlas, and `main` fails when any symbol the atlas gives this stratum fits
# no entry here.
#
# The families are the atlas's header assignment seen from the crate's side. Two things are
# worth saying before the table, because both are easy to get wrong:
#
#   * **A symbol's declaring header is not its translation unit.** `rsa.h` declares 154
#     exports, and sixteen of them are `EVP_PKEY_CTX_set_rsa_*` -- the ctrl helpers whose
#     bodies are `crypto/rsa/rsa_pmeth.c`'s. They are labelled with the key type because
#     that is the file a reader looking for the RSA ctrl surface should open, and because
#     the atlas's rule is the header, not the directory.
#   * **Order is part of the meaning.** `module_of` answers with the first entry that
#     matches, so a specific prefix has to come before a general one that contains it --
#     `EVP_PKEY_get0_RSA` before nothing here (the `evp.h` hand-offs are labelled per key
#     type), and `EVP_PKEY_CTX_set_ec_param` before `EVP_PKEY_CTX_set_ecdh`. The counts in
#     the generator's output are what make the ordering checkable.
MODULE_PREFIXES: list[tuple[str, tuple[str, ...]]] = [
    # 8.1 -- the digest primitives. One module per construction, because that is how the
    # authority is laid out and how a reader looks for one: `crypto/md5/`, `crypto/sha/`,
    # `crypto/ripemd/`, `crypto/whrlpool/`, `crypto/mdc2/`.
    ("src/digest/md4.rs", ("MD4",)),
    ("src/digest/md5.rs", ("MD5",)),
    ("src/digest/mdc2.rs", ("MDC2",)),
    ("src/digest/ripemd.rs", ("RIPEMD160",)),
    ("src/digest/wp.rs", ("WHIRLPOOL",)),
    # `SHA1` and the five SHA-2 spellings. `SHA224_Init` and `SHA256_Init` share a context
    # and a block function, which is why they share a module rather than getting one each.
    ("src/digest/sha1.rs", ("SHA1",)),
    ("src/digest/sha2.rs", ("SHA224", "SHA256", "SHA384", "SHA512")),
    # 8.2 -- the symmetric ciphers. `BF` rather than `BF_` because the header's own name is
    # `blowfish.h` and `BF_options` is not the only spelling a reader may start from.
    ("src/des/mod.rs", ("DES",)),
    ("src/aes.rs", ("AES_",)),
    ("src/camellia.rs", ("Camellia",)),
    ("src/blowfish.rs", ("BF",)),
    ("src/cast.rs", ("CAST",)),
    ("src/idea.rs", ("IDEA",)),
    ("src/rc2.rs", ("RC2",)),
    ("src/rc4.rs", ("RC4",)),
    ("src/seed.rs", ("SEED",)),
    # 8.3 -- the modes and the AEAD constructions. `modes.h` declares the whole
    # `CRYPTO_*` family, and its members are labelled with the one module the authority
    # writes them in: `crypto/modes/`.
    ("src/modes/mod.rs", ("CRYPTO_",)),
    # 8.4 -- RSA, including the ASN.1 item objects `rsa.h` declares.
    ("src/rsa/mod.rs", ("RSA", "PKCS1_MGF1", "d2i_RSA", "i2d_RSA",
                        "EVP_PKEY_CTX_get0_rsa", "EVP_PKEY_CTX_get_rsa",
                        "EVP_PKEY_CTX_set0_rsa", "EVP_PKEY_CTX_set1_rsa",
                        "EVP_PKEY_CTX_set_rsa",
                        "EVP_PKEY_get0_RSA", "EVP_PKEY_get1_RSA", "EVP_PKEY_set1_RSA")),
    # 8.5 -- DH and DHX.
    ("src/dh/mod.rs", ("DH", "d2i_DH", "i2d_DH",
                       "EVP_PKEY_CTX_get0_dh", "EVP_PKEY_CTX_get_dh",
                       "EVP_PKEY_CTX_set0_dh", "EVP_PKEY_CTX_set_dh",
                       "EVP_PKEY_get0_DH", "EVP_PKEY_get1_DH", "EVP_PKEY_set1_DH")),
    # 8.6 -- DSA.
    ("src/dsa/mod.rs", ("DSA", "d2i_DSA", "i2d_DSA", "EVP_PKEY_CTX_set_dsa",
                        "EVP_PKEY_get0_DSA", "EVP_PKEY_get1_DSA", "EVP_PKEY_set1_DSA")),
    # 8.7 -- EC. The order inside this row matters: `ECParameters` is not a prefix of
    # `ECPKParameters`, and `EC_` requires its underscore, which is what keeps `ECDSA_`
    # and `ECDH_` from being read as `EC_KEY_`'s.
    ("src/ec/mod.rs", ("EC_", "ECPARAMETERS", "ECPK", "ECParameters", "ECDH_", "ECDSA_",
                       "OSSL_EC_", "EVP_PKEY_CTX_get0_ecdh", "EVP_PKEY_CTX_get_ecdh",
                       "EVP_PKEY_CTX_set0_ecdh", "EVP_PKEY_CTX_set_ecdh",
                       "EVP_PKEY_CTX_set_ec_param", "EVP_PKEY_CTX_set_ec_paramgen",
                       "EVP_PKEY_get0_EC", "EVP_PKEY_get1_EC", "EVP_PKEY_set1_EC",
                       "d2i_EC", "i2d_EC", "i2o_EC", "o2i_EC")),
    # 8.8 -- the ASN.1 method objects and the two `standard_methods[]` tables. The
    # twenty-seven `evp.h` names Phase 7 handed over land here: they are the readers of a
    # table whose contents are this stratum's, and the table is `crypto/asn1/ameth_lib.c`'s.
    ("src/asn1/ameth.rs", ("EVP_PKEY_type", "EVP_PKEY_meth_", "EVP_PKEY_assign",
                           "d2i_PublicKey", "d2i_KeyParams",
                           "EVP_PKEY_get0_hmac", "EVP_PKEY_get0_poly1305",
                           "EVP_PKEY_get0_siphash", "EVP_PKEY_get_ec_point_conv_form",
                           "EVP_PKEY_get_field_type", "EVP_PKEY_encrypt_old",
                           "EVP_PKEY_decrypt_old")),
    # 8.9 -- the thirty `pem.h` helpers. They are one family -- read or write a
    # `DHparams`, an `RSA`/`DSA`/`EC` key -- and the authority spreads them over
    # `crypto/pem/pem_oth.c`, `pem_pkey.c` and `pem_lib.c`, so the label is the family's
    # name and not a translation unit's.
    ("src/pem/key_legacy.rs", ("PEM_read_DH", "PEM_read_DSA", "PEM_read_EC",
                               "PEM_read_RSA", "PEM_read_bio_DH", "PEM_read_bio_DSA",
                               "PEM_read_bio_EC", "PEM_read_bio_RSA",
                               "PEM_write_DH", "PEM_write_DSA", "PEM_write_EC",
                               "PEM_write_RSA", "PEM_write_bio_DH", "PEM_write_bio_DSA",
                               "PEM_write_bio_EC", "PEM_write_bio_RSA")),
]


# ---------------------------------------------------------------------------------------------
# The blocked hand-offs: a symbol whose declaring header is this stratum's but whose **body**
# needs a name no module of this crate defines.
#
# The reason is the same one Phase 7's ledger gives for its own table: a reason that names the
# callee, the authority file and line the call sits on, and the stratum that owns the callee is
# a reason a reader can check, whereas "needs the random layer" is one a reader can only
# believe. What `owning_phase` means is **the latest stratum the symbol is blocked on**, since
# that is the first phase whose completion retires the row.
#
# A row here is retired by landing the symbol: `main` fails if a symbol in this table is already
# implemented, so the table cannot quietly cover a name the crate defines.
#
# **This table is deliberately short, and the shortness is a reading rather than an omission.**
# Phase 8's four key types are 8.4-8.7's work and their blockers are *inside* the stratum --
# `RSA_get0_key` needs the `RSA` object that `RSA_new` allocates, not another stratum's name --
# and a same-stratum blocker is recorded as `open` rather than as a hand-off, because a stratum
# cannot hand a symbol to itself. What is here is the subset whose binding dependency is
# genuinely another stratum's, verified call by call.
# ---------------------------------------------------------------------------------------------

BLOCKED_HANDOFFS: list[tuple[tuple[str, ...], int, str]] = [
    # (1) `DES_random_key`, which is one call and one stratum.
    (
        ("DES_random_key",),
        9,
        "`crypto/des/rand_key.c:22` is `RAND_priv_bytes((unsigned char *)ret, "
        "sizeof(DES_cblock))` and its failure arm answers 0. `rand.h` is Phase 9's, and this "
        "is the one `des.h` export whose body is the random layer rather than the cipher. "
        "`DES_string_to_key` and `DES_string_to_2keys` are *not* in this row: they build a "
        "key from a string with `DES_cbc_cksum`, which is this stratum's own.",
    ),
    # (2) The RSA blinding pair, which is the BN blinding object's random path.
    (
        ("RSA_blinding_on", "RSA_setup_blinding"),
        9,
        "`RSA_blinding_on` (`crypto/rsa/rsa_crpt.c:68`) is a lock plus "
        "`RSA_setup_blinding`, and `RSA_setup_blinding` (`:104`) ends in "
        "`BN_BLINDING_create_param` (`crypto/bn/bn_blind.c`), whose `ai`/`e` values come from "
        "`BN_rand_range_ex` -> `bnrand` -> `RAND_bytes_ex` (`crypto/bn/bn_rand.c:50`). So both "
        "are blocked on Phase 9 through BN's own random path, and `RSA_blinding_off` is *not* "
        "in this row: it frees the object and needs nothing random.",
    ),
    # (3) The four key generators and the parameter generators, all on the same BN path.
    (
        ("RSA_generate_key", "RSA_generate_key_ex", "RSA_generate_multi_prime_key",
         "RSA_X931_generate_key_ex", "RSA_X931_derive_ex",
         "DH_generate_key", "DH_generate_parameters", "DH_generate_parameters_ex",
         "DSA_generate_key", "DSA_generate_parameters_ex",
         "EC_KEY_generate_key"),
        9,
        "every one of these reaches a BN random primitive: `ossl_rsa_keygen`'s primes come "
        "from `BN_generate_prime_ex2` (`crypto/rsa/rsa_gen.c:388`), `DH_generate_parameters_ex` "
        "from the same call at `crypto/dh/dh_gen.c:217`, `DH_generate_key`'s private value from "
        "`BN_priv_rand_ex` (`crypto/dh/dh_key.c:336`), `DSA_generate_key`/`_parameters_ex` from "
        "`crypto/dsa/dsa_key.c` and `crypto/dsa/dsa_gen.c`'s equivalents, and "
        "`EC_KEY_generate_key`'s scalar from `BN_rand_range` on the group order. All of them "
        "land on `bnrand` -> `RAND_bytes_ex` (`crypto/bn/bn_rand.c:50`), which is Phase 9's, so "
        "Phase 9 is the phase that retires the eleven. `DH_generate_parameters` is the "
        "deprecated wrapper over `DH_generate_parameters_ex` and is in the row for the same "
        "reason.",
    ),
    # (4) The two X9 KDF wrappers, which are provider KDF fetches.
    (
        ("DH_KDF_X9_42", "ECDH_KDF_X9_62"),
        9,
        "each is an `EVP_KDF` fetch of a *provider* KDF: `crypto/dh/dh_kdf.c:40` asks for "
        "`OSSL_KDF_NAME_X942KDF_ASN1` and `crypto/ec/ecdh_kdf.c:34` for "
        "`OSSL_KDF_NAME_X963KDF`, then derives through `EVP_KDF_derive`. The `EVP_KDF` object "
        "is Phase 7's and every KDF the fetch can find is a provider implementation, so the "
        "answer is a later stratum's. Phase 9 is named because it is the stratum the plan puts "
        "the provider KDF family in; if that plan names a different stratum, this row is the "
        "one to correct, and `docs/DECISIONS.md` D197 says so.",
    ),
]


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

    The unit of discovery is a *row*, not a name list, so the reason and the declaring
    header travel with the symbol from wherever it was deferred and are not restated here.
    A ledger that cannot be read is a failure rather than an empty edge set: a missing
    file would otherwise look exactly like "no stratum deferred anything to Phase 8".
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
            "phase8-obligations: no earlier stratum's ledger is readable, so the "
            "incoming hand-off set would be empty for the wrong reason"
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
            "phase8-obligations: the ownership atlas assigns this stratum no exports, "
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
                    f"phase8-obligations: {sym} is both the atlas's for phase {PHASE} and "
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
            "phase8-obligations: the ownership atlas gives this stratum (or an earlier "
            "stratum handed it) exports that no entry in MODULE_PREFIXES labels, so the "
            "ledger cannot say which module is expected to hold them -- add a label:\n  "
            + "\n  ".join(f"{s}  ({owned[s]['declaring_header']})" for s in unlabelled)
        )

    # The fail-closed deferral mechanism: a symbol in `BLOCKED_HANDOFFS` that the crate now
    # defines is a stale row rather than a harmless one, because a table that can keep
    # covering a landed symbol can hide the next real gap behind it.
    blocked: dict[str, dict] = {}
    for symbols, phase, reason in BLOCKED_HANDOFFS:
        for sym in symbols:
            if sym not in owned:
                raise SystemExit(
                    f"phase8-obligations: BLOCKED_HANDOFFS names {sym}, which is not in this "
                    f"stratum's working set (or is not an authority export at all)"
                )
            if sym in done:
                raise SystemExit(
                    f"phase8-obligations: BLOCKED_HANDOFFS records {sym} as blocked on phase "
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
            "phase8-obligations: the ledger does not account for exactly its own working "
            f"set: owned={len(owned)} implemented={len(implemented_here)} "
            f"deferred={len(deferred_names)} open={len(open_rows)}"
        )

    body = {
        "rule": (
            "the stratum's working set is the projection of forensics/atlas/"
            "symbol-ownership.json for phase 8, plus every symbol an earlier stratum's "
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
        # The reasons, kept as they were written by the stratum that deferred them rather
        # than restated: a second statement of the same reason is a second thing to keep
        # true, and `ownership_audit.py` compares the two sides already.
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
            "at most `IMPLEMENTED` in docs/PARITY_MODEL.md terms, and docs/PHASE-8-"
            "SUBPHASES.md §4 decides when the stratum may be called complete."
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
    doc = envelope(kind="phase8-obligations", authority=auth.id, inputs=inputs,
                   body=body, generator=GENERATOR)
    write_json(OUT, doc)

    c = body["counts"]
    print(f"[phase8-obligations] atlas={c['atlas_owned']} "
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
