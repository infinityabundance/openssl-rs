#!/usr/bin/env python3
"""openssl-rs — the Phase 7 obligation ledger, and it is a *projection*.

Phase 7 is the EVP framework: the fetch layer, the method stores, the `EVP_*` object
families and the `EVP_PKEY` layer. `docs/PHASE-7-SUBPHASES.md` is its plan and this
ledger is the machine-checkable arithmetic behind it.

This ledger does not decide its own universe
--------------------------------------------
The universe comes from `forensics/atlas/symbol-ownership.json`, which assigns every one
of the authority's 6,499 exports to exactly one stratum by one stated rule
(`forensics/tools/ownership_rules.py`, D72). This file selects the rows the atlas assigns
to Phase 7 and reports them, and it adds the symbols earlier strata handed over -- a
stratum's ledger has to contain the work it owes *and* the work it built.

**The hand-offs are read from the other ledgers, not typed here.** Phase 6's generator
lists its incoming edges as a literal with the reason attached, which is right for a
stratum that had one source of them and wrong as a pattern: the list is a fact about four
*other* files, and a fact maintained by hand in a fifth place is the class of defect this
project keeps removing. Here the edges are discovered -- every row of every
`forensics/phase*-obligations.json` whose `owning_phase` is 7 -- so a stratum that defers
a symbol to this one is recorded on both sides by construction, and the reasons stay where
they were written. `ownership_audit.py` then reconciles the two readings in both
directions, so an edge recorded on one side only is a failure rather than a half-record.

Four situations, kept apart
---------------------------
  * **implemented** -- the crate defines the symbol.
  * **open** -- this stratum's, not built yet. The only list that blocks the stratum.
    Phase 7 starts with its entire working set here, which is the honest starting state.
  * **deferred** -- a recorded hand-off to a later stratum with the dependency named.
  * **handoffs_discharged** -- the reverse edge, discovered above.

Outputs
-------
  forensics/phase7-obligations.json

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

OUT = REPO_ROOT / "forensics" / "phase7-obligations.json"
GENERATOR = "forensics/tools/phase7_obligations.py"
PHASE = 7
ATLAS_OWNERSHIP = "forensics/atlas/symbol-ownership.json"

# Which module of the stratum is expected to hold a symbol. A **label**: the universe
# comes from the atlas, and `main` fails when any symbol the atlas gives this stratum fits
# no entry here.
#
# The families are the atlas's header assignment seen from the crate's side, and three of
# them are surprising enough to say why here. `OSSL_HPKE_*` is `crypto/hpke/hpke.c`, whose
# whole surface is `hpke.h`'s and is therefore this stratum's even though HPKE is not an
# EVP object. `HMAC_*` and `CMAC_*` are `crypto/hmac/hmac.c` and `crypto/cmac/cmac.c`, the
# legacy one-shot interfaces, which are *not* the MAC implementations underneath --
# `EVP_MAC` fetches those from a provider -- so they belong with the EVP framework that
# they are a façade over. And `EVP_PKEY_*` is split across the four `src/evp/` modules the
# 7.4 row names, which is why they are labelled per side rather than by one prefix.
MODULE_PREFIXES: list[tuple[str, tuple[str, ...]]] = [
    # 7.2's default-property surface is `evp_fetch.c`'s and is labelled with the fetch
    # layer rather than with a module of its own: the property string is what the fetch
    # path is *for*, and the plan's 7.2 row keeps them in one subphase for that reason.
    ("src/evp/fetch.rs", ("OSSL_METHOD_", "EVP_default_properties_",
                          "EVP_get1_default_properties", "EVP_set_default_properties")),
    ("src/evp/namemap_names.rs", ("EVP_names", "EVP_is_a", "evp_names")),
    # 7.3 -- the symmetric method objects and their legacy wrappers.
    ("src/evp/cipher.rs", ("EVP_CIPHER_", "EVP_Encrypt", "EVP_Decrypt", "EVP_Cipher")),
    ("src/evp/digest.rs", ("EVP_MD_", "EVP_Digest", "EVP_sha", "EVP_md", "EVP_Q_digest")),
    ("src/evp/mac.rs", ("EVP_MAC_", "EVP_MAC", "EVP_Q_mac")),
    ("src/evp/kdf.rs", ("EVP_KDF_", "EVP_KDF")),
    # 7.4's PBE registry (`crypto/evp/evp_pbe.c`) and the two scrypt wrappers that are
    # declared beside it. They are not KDFs in the `EVP_KDF` sense -- they are the table of
    # password-based-encryption constructions an `EVP_PKEY` method is looked up through --
    # which is why they are labelled where the key layer is rather than with the KDFs.
    ("src/evp/pbe.rs", ("EVP_PBE_",)),
    ("src/evp/rand.rs", ("EVP_RAND_", "EVP_RAND")),
    ("src/evp/skeymgmt.rs", ("OSSL_SKEYMGMT_", "EVP_SKEY")),
    ("src/evp/legacy_cipher.rs", ("EVP_aes_", "EVP_aria_", "EVP_camellia_", "EVP_des",
                                  "EVP_rc2", "EVP_rc4", "EVP_idea", "EVP_cast5",
                                  "EVP_seed", "EVP_bf_", "EVP_sm4", "EVP_chacha20",
                                  "EVP_xcbc", "EVP_null", "EVP_enc_null",
                                  "EVP_get_cipher")),
    ("src/evp/legacy_digest.rs", ("EVP_md4", "EVP_md5", "EVP_sha1", "EVP_sha224",
                                  "EVP_sha256", "EVP_sha384", "EVP_sha512", "EVP_sha3",
                                  "EVP_shake", "EVP_blake2", "EVP_ripemd", "EVP_whirlpool",
                                  "EVP_mdc2", "EVP_sm3", "EVP_get_digest")),
    # 7.4 -- the `EVP_PKEY` layer, its context, and the ASN.1 glue declared in `evp.h`.
    #
    # **Order is part of the meaning here.** `module_of` answers with the first entry that
    # matches, and `EVP_PKEY_` is a prefix of `EVP_PKEY_CTX_`, `EVP_PKEY_asn1_`,
    # `EVP_PKEY_meth_` and `EVP_PKEY_param*` -- so the general entry has to come **last**,
    # or the ledger sends a reader of `EVP_PKEY_CTX_new` to the file that holds `EVP_PKEY`
    # itself, which is exactly the failure Phase 6's own `MODULE_PREFIXES` comment warns
    # about. The counts in the generator's output are what make the ordering checkable.
    ("src/evp/pkey_ctx.rs", ("EVP_PKEY_CTX", "EVP_PKEY_ASN1_METHOD", "EVP_PKEY_meth",
                             "EVP_PKEY_param_check", "EVP_PKEY_paramgen",
                             "EVP_PKEY_keygen", "EVP_PKEY_check",
                             "EVP_PKEY_get0_asn1", "EVP_PKEY_get0_provider",
                             "EVP_PKEY_asn1_")),
    ("src/evp/pkey_asn1.rs", ("ASN1_item_sign", "ASN1_item_verify", "d2i_", "i2d_")),
    # The five asymmetric method-object families, one file each: the `EVP_<KIND>_fetch` /
    # `up_ref` / `is_a` / `names_do_all` / parameter-descriptor set the authority builds
    # with a macro. Separate rows rather than one prefix because the plan's 7.3/7.4 boundary
    # runs between them: 7.3 builds the four symmetric ones and 7.4 these five.
    ("src/evp/signature.rs", ("EVP_SIGNATURE_",)),
    ("src/evp/asymcipher.rs", ("EVP_ASYM_CIPHER_",)),
    ("src/evp/kem.rs", ("EVP_KEM_",)),
    ("src/evp/exchange.rs", ("EVP_KEYEXCH_",)),
    ("src/evp/keymgmt.rs", ("EVP_KEYMGMT_",)),
    # General last: see the note above.
    ("src/evp/pkey.rs", ("EVP_PKEY_",)),
    # 7.5 -- the BIO, encoding and PEM bridges.
    ("src/evp/bio_enc.rs", ("BIO_f_base64", "BIO_f_cipher", "BIO_f_md", "BIO_f_ok",
                            "BIO_f_reliable", "BIO_set_cipher")),
    ("src/evp/encode.rs", ("EVP_ENCODE_CTX_", "EVP_Encode", "EVP_Decode")),
    ("src/evp/p_legacy.rs", ("EVP_Open", "EVP_Seal", "EVP_Sign", "EVP_Verify",
                             "EVP_DecryptFinal", "EVP_BytesToKey",
                             "EVP_get_pw_prompt", "EVP_set_pw_prompt",
                             "EVP_read_pw_string")),
    ("src/evp/pem_bridge.rs", ("PEM_", "PKCS5_", "PKCS8_")),
    # 7.6 -- the MAC, KDF and HPKE header surfaces.
    ("src/mac/hmac.rs", ("HMAC_",)),
    ("src/mac/cmac.rs", ("CMAC_",)),
    ("src/hpke/mod.rs", ("OSSL_HPKE_",)),
    ("src/evp/legacy_evp.rs", ("OpenSSL_add_all", "OPENSSL_add_all", "EVP_cleanup",
                               "EVP_add_cipher", "EVP_add_digest", "EVP_add_alg_module",
                               "SSLeay_add", "OpenSSL_add_all_algorithms")),
    # The one-shot legacy MAC. `EVP_MAC` fetches a provider's implementation; this is the
    # older `HMAC()`/`HMAC_Init_ex()` façade over the same construction, and it belongs to
    # the same file as its four `HMAC_CTX_*` siblings.
    ("src/mac/hmac.rs", ("HMAC",)),
]


# ---------------------------------------------------------------------------------------------
# 7.3g's hand-off table
#
# Every entry is a group of prefix-matched exports, the primitive unit whose functions their
# callbacks call, and the sentence that says which translation unit they come from. The prefix
# groups are deliberately per-family rather than one `EVP_` catch-all: a row that named one
# primitive unit for all one hundred and sixty-four statics would be a row nobody could check.
#
# `EVP_sm3` is its own row rather than part of a `EVP_sm` group because there is no other
# `EVP_sm` name here, and `EVP_sha` covers `EVP_shake128`/`EVP_shake256` because they are
# `legacy_sha.c`'s alongside SHA-2 and a reader looking for them will not find them under a
# `shake` prefix.
# ---------------------------------------------------------------------------------------------

LEGACY_HANDOFFS: list[tuple[tuple[str, ...], str, str]] = [
    (("EVP_aes_",), "crypto/aes/",
     "`e_aes.c`, `e_aes_cbc_hmac_sha1.c` and `e_aes_cbc_hmac_sha256.c` build them over the "
     "low-level AES API, and the CBC-HMAC pair additionally over `HMAC_Init_ex`"),
    (("EVP_aria_",), "crypto/aria/", "`e_aria.c`"),
    (("EVP_camellia_",), "crypto/camellia/", "`e_camellia.c`"),
    (("EVP_des",), "crypto/des/",
     "`e_des.c`, `e_des3.c` and `e_old.c`; `EVP_desx_cbc` is `e_des.c`'s DESX construction"),
    (("EVP_rc2",), "crypto/rc2/", "`e_rc2.c`"),
    (("EVP_rc4",), "crypto/rc4/",
     "`e_rc4.c` and `e_rc4_hmac_md5.c`, the second being a composition with `crypto/md5/`"),
    (("EVP_idea",), "crypto/idea/", "`e_idea.c`"),
    (("EVP_cast5",), "crypto/cast/", "`e_cast.c`"),
    (("EVP_seed",), "crypto/seed/", "`e_seed.c`"),
    (("EVP_bf_",), "crypto/bf/", "`e_bf.c`"),
    (("EVP_sm4",), "crypto/sm4/", "`e_sm4.c`"),
    (("EVP_chacha20",), "crypto/chacha/ and crypto/poly1305/",
     "`e_chacha20_poly1305.c`; the AEAD is a composition of the two primitive units"),
    (("EVP_xcbc",), "crypto/aes/",
     "`e_xcbc_d.c`, which is the XCBC-MAC construction over the AES-CBC primitive"),
    (("EVP_md4",), "crypto/md4/", "`legacy_md4.c`"),
    (("EVP_md5",), "crypto/md5/",
     "`legacy_md5.c` and `legacy_md5_sha1.c`, the second an MD5-then-SHA1 composition"),
    (("EVP_mdc2",), "crypto/mdc2/", "`legacy_mdc2.c`, itself over `crypto/des/`"),
    (("EVP_sha",), "crypto/sha/",
     "`legacy_sha.c`, which builds every SHA-1, SHA-2, SHA-3 and SHAKE static in one table"),
    (("EVP_blake2",), "crypto/blake2/", "`legacy_blake2.c`"),
    (("EVP_ripemd",), "crypto/ripemd/", "`legacy_ripemd.c`"),
    (("EVP_whirlpool",), "crypto/whirlpool/", "`legacy_wp.c`"),
    (("EVP_sm3",), "crypto/sm3/", "`legacy_sm3.c`"),
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
    file would otherwise look exactly like "no stratum deferred anything to Phase 7".
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
            "phase7-obligations: no earlier stratum's ledger is readable, so the "
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
            "phase7-obligations: the ownership atlas assigns this stratum no exports, "
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
                    f"phase7-obligations: {sym} is both the atlas's for phase {PHASE} and "
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
            "phase7-obligations: the ownership atlas gives this stratum (or an earlier "
            "stratum handed it) exports that no entry in MODULE_PREFIXES labels, so the "
            "ledger cannot say which module is expected to hold them -- add a label:\n  "
            + "\n  ".join(f"{s}  ({owned[s]['declaring_header']})" for s in unlabelled)
        )

    # 7.3g's hand-off, and the plan's §2 predicts it: the legacy `EVP_CIPHER` and `EVP_MD`
    # statics are one `EVP_add_*` registration each of a method whose callbacks call a
    # *primitive* -- `AES_encrypt`, `SHA256_Update`, `Camellia_EncryptBlock` -- and the
    # primitive units are Phase 13's. What 7.3g *can* do is done and is not in this table:
    # the four walkers in `names.c`, and the two adders, which take their method from the
    # caller and read no primitive at all.
    #
    # `EVP_get_cipherbyname` and `EVP_get_digestbyname` were in this table for one revision of
    # the plan and are **not** in it now. Their bodies need nothing Phase 13 has -- the legacy
    # lookup is only the first of three steps, and the namemap retry and the fetch behind it are
    # this stratum's -- and what Phase 13 changes is which names the first step finds. Refusing to
    # write a function whose *input* is another stratum's contents would have been the same
    # mistake as refusing to write `EVP_add_cipher`. RT-EVP-NAMES is what settled it, and
    # `src/evp/legacy_evp.rs`'s module doc is where the reversal is argued.
    handed_on: dict[str, dict] = {}
    for prefixes, primitive, note in LEGACY_HANDOFFS:
        for sym in owned:
            if sym in done or sym in handed_on:
                continue
            if any(sym == p or sym.startswith(p) for p in prefixes):
                handed_on[sym] = {
                    "symbol": sym,
                    "owning_phase": 13,
                    "declaring_header": owned[sym]["declaring_header"],
                    "reason": (
                        f"a legacy method static whose callbacks call {primitive}'s own "
                        f"primitives; {note}"
                    ),
                }
    handed_on_names = set(handed_on)
    deferred: list[dict] = list(handed_on.values())

    implemented_here = sorted(s for s in owned if s in done and s not in handed_on_names)
    open_rows = [
        {"symbol": s, "module": owned[s]["module"],
         "declaring_header": owned[s]["declaring_header"],
         "received_from_phase": owned[s]["from"]}
        for s in sorted(owned) if s not in done and s not in handed_on_names
    ]

    if len(owned) != len(implemented_here) + len(handed_on_names) + len(open_rows):
        raise SystemExit(
            "phase7-obligations: the ledger does not account for exactly its own working "
            f"set: owned={len(owned)} implemented={len(implemented_here)} "
            f"deferred={len(handed_on_names)} open={len(open_rows)}"
        )

    body = {
        "rule": (
            "the stratum's working set is the projection of forensics/atlas/"
            "symbol-ownership.json for phase 7, plus every symbol an earlier stratum's "
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
        "deferred": sorted(deferred, key=lambda r: r["symbol"]),
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
            "at most `IMPLEMENTED` in docs/PARITY_MODEL.md terms, and docs/PHASE-7-"
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
    doc = envelope(kind="phase7-obligations", authority=auth.id, inputs=inputs,
                   body=body, generator=GENERATOR)
    write_json(OUT, doc)

    c = body["counts"]
    print(f"[phase7-obligations] atlas={c['atlas_owned']} "
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
