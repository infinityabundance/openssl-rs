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



# ---------------------------------------------------------------------------------------------
# The blocked hand-offs: a symbol whose declaring header is this stratum's but whose **body**
# needs a name no module of this crate defines.
#
# The 7.3g table above is one mechanism -- a legacy method static whose callbacks call a primitive
# unit -- and this table is the other. They are kept apart because a reason that says "the
# callbacks call AES" is a statement about a whole subsystem, whereas the reasons below name the
# callee, the authority file and line the call sits on, and the stratum that owns the callee. That
# is the difference between a reason a reader can check and one a reader can only believe.
#
# What `owning_phase` means, in one sentence: **the latest stratum the symbol is blocked on**,
# because that is the first phase whose completion retires the row. A row naming an earlier phase
# would promise a landing that cannot happen -- `PEM_read_bio_PrivateKey` is reached through
# `OSSL_DECODER_CTX_new_for_pkey` (Phase 10) *first* and through `PEM_bytes_read_bio` (Phase 13)
# on its fallback, and it cannot be written until both exist. Where a symbol is blocked on more
# than one phase, its reason names every one of them and says which is the binding one.
# `forensics/tools/phase5_obligations.py` records this convention for the earlier strata
# ("the later of the two dependencies is the binding one", its `ASN1_add_stable_module` row), and
# `docs/DECISIONS.md` D196 records that this stratum follows it rather than reading it off the
# subphase row, which lists the blocker a symbol is reached through **first**.
#
# A row here is retired by landing the symbol: `main` fails if a symbol in this table is already
# implemented, so the table cannot quietly cover a name the crate defines. That is the same
# discipline `forensics/prerequisites.json` uses, and it is what stops a real future gap hiding
# behind a stale row.
# ---------------------------------------------------------------------------------------------

BLOCKED_HANDOFFS: list[tuple[tuple[str, ...], int, str]] = [
    # (1) The four low-level key types' accessors -- twelve, one cause.
    (
        ("EVP_PKEY_get0_RSA", "EVP_PKEY_get1_RSA", "EVP_PKEY_set1_RSA",
         "EVP_PKEY_get0_DSA", "EVP_PKEY_get1_DSA", "EVP_PKEY_set1_DSA",
         "EVP_PKEY_get0_DH", "EVP_PKEY_get1_DH", "EVP_PKEY_set1_DH",
         "EVP_PKEY_get0_EC_KEY", "EVP_PKEY_get1_EC_KEY", "EVP_PKEY_set1_EC_KEY"),
        8,
        "all twelve reach `evp_pkey_get_legacy` (`crypto/evp/p_lib.c:2154`) through their file's "
        "own `evp_pkey_get0_<TYPE>_int` (`crypto/evp/p_legacy.c:40`, `:76`; "
        "`crypto/evp/p_lib.c:887`, `:998`), and that function's body past its fast paths is "
        "`evp_pkey_copy_downgraded` (`crypto/evp/p_lib.c:2066`), which **constructs** an "
        "`RSA`/`DH`/`DSA`/`EC_KEY` and imports into its `ameth`. Neither the four types nor the "
        "ameth objects exist yet, so every one of the twelve is blocked on Phase 8 -- and so are "
        "the `RSA_up_ref`/`RSA_free` (`p_legacy.c:29`, `:35`), `EC_KEY_up_ref`/`EC_KEY_free` "
        "(`:67`, `:70`), `DSA_up_ref`/`DSA_free` (`p_lib.c:905`, `:911`) and "
        "`ossl_dh_is_named_safe_prime_group`/`DH_get0_q`/`DH_up_ref`/`DH_free` (`p_lib.c:982`, "
        "`:985`, `:987`, `:993`) names the `set1_*` and `get1_*` spellings call directly. "
        "`evp_pkey_get_legacy` carries its own `forensics/prerequisites.json` row (Phase 8, "
        "D193); this row is the twelve exports that sit behind it.",
    ),
    # (2) The MAC-key getters, which read an ASN1_OCTET_STRING out of the downgraded key.
    (
        ("EVP_PKEY_get0_hmac", "EVP_PKEY_get0_poly1305", "EVP_PKEY_get0_siphash"),
        8,
        "each is `pkey->type == <type> ? evp_pkey_get_legacy(pkey) : NULL` and then reads "
        "`os->length`/`os->data` off the answer (`crypto/evp/p_lib.c:843`, `:859`, `:877`). "
        "`evp_pkey_get_legacy` (`crypto/evp/p_lib.c:2154`) is the whole dependency and it is "
        "Phase 8's: it constructs a legacy key with `evp_pkey_copy_downgraded` (`:2066`) and "
        "caches it against an `ameth` the crate cannot find. Same row in "
        "`forensics/prerequisites.json`, same stratum.",
    ),
    # (3) The one assign, which is three Phase-8 calls in five lines.
    (
        ("EVP_PKEY_assign",),
        8,
        "`crypto/evp/p_lib.c:791` calls `EVP_PKEY_type` (`:797`, the `standard_methods[]` walk "
        "`crypto/evp/evp_pkey_type.c:63` is the export for), `EC_KEY_get0_group` and "
        "`EC_GROUP_get_curve_name` (`:801`, `:803`) on the incoming key, and then "
        "`detect_foreign_key` -> `ossl_dh_is_foreign` (`:819`, `:782`). Every one is Phase 8's; "
        "the `EVP_PKEY_set_type` call between them is landed. `EVP_PKEY_assign_RSA`/`_DSA`/`_DH`/"
        "`_EC_KEY` are `#define`s over this function (`include/openssl/evp.h`), so the four "
        "`set1_*` names in the first row wait on it too.",
    ),
    # (4) The two `_old` RSA helpers.
    (
        ("EVP_PKEY_encrypt_old", "EVP_PKEY_decrypt_old"),
        8,
        "`crypto/evp/p_enc.c:32` and `crypto/evp/p_dec.c:32` both take the low-level key with "
        "`evp_pkey_get0_RSA_int` (`crypto/evp/p_legacy.c:40`, which is `evp_pkey_get_legacy` "
        "behind a type test) and then call the primitive -- `RSA_public_encrypt` (`p_enc.c:36`) "
        "and `RSA_private_decrypt` (`p_dec.c:36`). Both the accessor and the two primitives are "
        "Phase 8's.",
    ),
    # (5) The two EC parameter getters, which take the legacy route for a non-provider key.
    (
        ("EVP_PKEY_get_ec_point_conv_form", "EVP_PKEY_get_field_type"),
        8,
        "each opens with `pkey->keymgmt == NULL || pkey->keydata == NULL` and answers its "
        "legacy arm -- `EVP_PKEY_get0_EC_KEY` then `EC_KEY_get_conv_form` "
        "(`crypto/evp/p_lib.c:2472`, `:2477`) or `EC_KEY_get0_group` then "
        "`EC_GROUP_get_field_type` (`:2512`, `:2517`, `:2521`). The provider arm above those "
        "needs nothing foreign, but the legacy arm is compiled in and the crate's "
        "`EVP_PKEY_get0_EC_KEY` is itself withheld in this stratum, so both are Phase 8's.",
    ),
    # (6) `EVP_PKEY_type`.
    (
        ("EVP_PKEY_type",),
        8,
        "`crypto/evp/evp_pkey_type.c:63` is `EVP_PKEY_asn1_find(&e, type)` and then "
        "`ameth->pkey_id`. The function is landed -- `src/evp/pkey_asn1.rs` holds it as the "
        "`pub(crate) evp_pkey_type` helper `EVP_PKEY_get_base_id` calls (D193) -- and the export "
        "is withheld because its whole answer is the `standard_methods[]` table "
        "`crypto/asn1/ameth_lib.c:54` fills from `crypto/asn1/standard_methods.h`, whose twelve "
        "`ossl_<alg>_asn1_meth` objects are Phase 8's. The `ENGINE_finish(e)` at `:75` is the "
        "`*pe = NULL` mechanism D181 records, not a second blocker.",
    ),
    # (7) The six print entry points, which are `print_pkey` and its encoder.
    (
        ("EVP_PKEY_print_public", "EVP_PKEY_print_private", "EVP_PKEY_print_params",
         "EVP_PKEY_print_public_fp", "EVP_PKEY_print_private_fp",
         "EVP_PKEY_print_params_fp"),
        10,
        "the three `_fp` twins are `BIO_new_fp` around the three others, and all six reach "
        "`print_pkey` (`crypto/evp/p_lib.c:1196`), whose first statement is "
        "`OSSL_ENCODER_CTX_new_for_pkey` (`:1211`) followed by "
        "`OSSL_ENCODER_CTX_get_num_encoders` (`:1213`) and `OSSL_ENCODER_to_bio` (`:1214`). "
        "Those three are `encoder.h`'s and Phase 10's, and the call is unconditional -- it is "
        "not the legacy fallback that decides whether the export can be written. The fallback "
        "arm below it (`pkey->ameth->pub_print`/`priv_print`/`param_print`, at `:1233`, `:1241`, "
        "`:1249`) is Phase 8's ameth *contents*, so Phase 8 also feeds these six; the struct "
        "and its three function-pointer fields are already declared, which is why Phase 10 is "
        "the binding one.",
    ),
    # (8) The engine pair.
    (
        ("EVP_PKEY_set1_engine", "EVP_PKEY_get0_engine"),
        13,
        "`crypto/evp/p_lib.c:732` calls `ENGINE_init` (`:735`), `ENGINE_get_pkey_meth` (`:739`) "
        "and `ENGINE_finish` (`:736`, `:745`) and writes `pkey->pmeth_engine`; `:750` reads "
        "`pkey->engine`. `ENGINE` is `engine.h`'s and Phase 13's, and this crate's `EvpPkey` "
        "has neither field -- they are absent with the rest of the legacy attribute block "
        "(`src/evp/pkey.rs` module doc), so the pair is blocked on Phase 13 and on nothing else.",
    ),
    # (9) The three `d2i` spellings that are Phase 8 alone.
    (
        ("d2i_PublicKey", "d2i_KeyParams", "d2i_KeyParams_bio"),
        8,
        "`d2i_PublicKey` (`crypto/asn1/d2i_pu.c:28`) is a `switch` on "
        "`EVP_PKEY_get_base_id(ret)` whose three arms call `d2i_RSAPublicKey` (`:52`), "
        "`d2i_DSAPublicKey` (`:59`) and `o2i_ECPublicKey` (`:71`), plus "
        "`evp_pkey_copy_downgraded` (`:42`) for the provided-EC input. `d2i_KeyParams` "
        "(`crypto/asn1/d2i_param.c:18`) refuses unless `ret->ameth != NULL && "
        "ret->ameth->param_decode != NULL` (`:31`) and then calls it, and `d2i_KeyParams_bio` "
        "(`:49`) is a `BUF_MEM` read around it. Every one of those names is Phase 8's; the "
        "`asn1_d2i_read_bio`/`EVP_PKEY_set_type` calls are landed.",
    ),
    # (10) The four private-key decoders: the codec first, the ameth second.
    (
        ("d2i_PrivateKey", "d2i_PrivateKey_ex", "d2i_AutoPrivateKey",
         "d2i_AutoPrivateKey_ex"),
        10,
        "all four are `d2i_PrivateKey_decoder` then, if it answered NULL, "
        "`ossl_d2i_PrivateKey_legacy` (`crypto/asn1/d2i_pr.c:172`-`:175`, `:247`-`:250`). The "
        "decoder builds an `OSSL_DECODER_CTX` with `OSSL_DECODER_CTX_new_for_pkey` (`:78`), "
        "which is `decoder.h`'s and Phase 10's and is called **first**; the fallback reads "
        "`ret->ameth->old_priv_decode`/`priv_decode`/`priv_decode_ex` (`:130`, `:132`) and calls "
        "`evp_pkcs82pkey_legacy` (`crypto/evp/evp_pkey.c:52`-`:59` is the same fields again), "
        "which is Phase 8's. So both phases feed these four and Phase 10 is the binding one: "
        "an export cannot be half-written, and the half that runs first is the decoder.",
    ),
    # (11) The five encoders.
    (
        ("i2d_PrivateKey", "i2d_PKCS8PrivateKey", "i2d_PublicKey", "i2d_KeyParams",
         "i2d_KeyParams_bio"),
        10,
        "all five reach `i2d_provided` (`crypto/asn1/i2d_evp.c:33`) whenever the key is "
        "provided, and that function is `OSSL_ENCODER_CTX_new_for_pkey` (`:53`) + "
        "`OSSL_ENCODER_to_data` (`:59`) + `OSSL_ENCODER_CTX_free` (`:64`), `encoder.h`'s and "
        "Phase 10's. Their non-provided arms are Phase 8's as well -- `i2d_PublicKey`'s "
        "`switch` calls `i2d_RSAPublicKey`/`i2d_DSAPublicKey`/`i2o_ECPublicKey` (`:159`, "
        "`:162`, `:165`) through `EVP_PKEY_get0_RSA`/`_DSA`/`_EC_KEY`, and "
        "`i2d_PrivateKey_impl`'s calls `a->ameth->old_priv_encode` (`:106`) and "
        "`EVP_PKEY2PKCS8` (`crypto/evp/evp_pkey.c:129`, itself an encoder context) -- so Phase 8 "
        "feeds these five too and Phase 10 is the binding one.",
    ),
    # (12) The two Phase-5 hand-offs whose delegate is Phase 11's.
    (
        ("ASN1_item_sign_ex", "ASN1_item_verify_ex"),
        11,
        "`ASN1_item_sign_ex` (`crypto/asn1/a_sign.c:121`) builds its digest context and then "
        "hands it to `ASN1_item_sign_ctx` (`:138`); `ASN1_item_verify_ex` "
        "(`crypto/asn1/a_verify.c:95`) is the same shape around `ASN1_item_verify_ctx` (`:104`). "
        "Both delegates are declared in `x509.h`, are defined in those same two files "
        "(`a_sign.c:146`, `a_verify.c:111`) and are Phase 11's exports, so the Phase 5 -> 7 "
        "hand-off cannot be completed here; `forensics/prerequisites.json` carries the pair "
        "with this reason and `RT-EVP-PKEY`'s `NOT_MEASURED` lines name them. "
        "`evp_md_ctx_new_ex`, the other callee, is `crypto/evp/digest.c`'s own internal and "
        "belongs with this stratum.",
    ),
    # (13) The three registry readers.
    (
        ("EVP_PKEY_meth_find", "EVP_PKEY_meth_get_count", "EVP_PKEY_meth_get0"),
        8,
        "`EVP_PKEY_meth_find` (`crypto/evp/pmeth_lib.c:106`) searches `standard_methods[]` "
        "(`:54`) with `OBJ_bsearch_pmeth_func` (`:114`); `EVP_PKEY_meth_get_count` (`:646`) "
        "answers `OSSL_NELEM(standard_methods)` plus the application stack; "
        "`EVP_PKEY_meth_get0` (`:655`) indexes the table outright before it touches that "
        "stack. The ten `ossl_<alg>_pkey_method` objects the table holds are Phase 8's "
        "contents (D163, D165, D184), and the application half of the registry is already "
        "landed and courted -- so Phase 8 is the only phase that retires these three, and a "
        "stub would answer the application count where the authority answers twelve more.",
    ),
    # (14) `EVP_PKEY_CTX_get_algor` -- the same `d2i_X509_ALGOR` as its cipher sibling.
    (
        ("EVP_PKEY_CTX_get_algor",),
        11,
        "`crypto/evp/evp_lib.c:1455` decodes the provider's `OSSL_SIGNATURE_PARAM_ALGORITHM_ID` "
        "answer with `d2i_X509_ALGOR` (`:1490`), which is `crypto/asn1/x_algor.c:26`'s generated "
        "`IMPLEMENT_ASN1_FUNCTIONS` export and Phase 11's. `forensics/prerequisites.json` "
        "carries `d2i_X509_ALGOR` with this coordinate; D190 recorded the withholding and "
        "D193 restated it.",
    ),
    # (15) `EVP_SealInit`.
    (
        ("EVP_SealInit",),
        9,
        "`crypto/evp/p_seal.c:42` takes the session key from `EVP_CIPHER_CTX_rand_key` and "
        "`:46` fills the IV with `RAND_priv_bytes_ex(libctx, iv, len, 0)`; `rand.h` is Phase "
        "9's, and `EVP_CIPHER_CTX_rand_key` (`crypto/evp/evp_enc.c:1751`, `:1764`) is itself "
        "withheld in this stratum on the same call -- which is why the deferral is Phase 9 and "
        "not a same-stratum one. `forensics/prerequisites.json`'s `RAND_priv_bytes_ex` row is "
        "this dependency.",
    ),
    # (16) The two password readers, which are a `UI` program.
    (
        ("EVP_read_pw_string", "EVP_read_pw_string_min"),
        13,
        "`EVP_read_pw_string_min` (`crypto/evp/evp_key.c:52`) is `UI_new` (`:56`), "
        "`UI_add_input_string` (`:62`), `UI_add_verify_string` (`:70`), `UI_process` (`:78`) "
        "and `UI_free` (`:84`), and `ui.h` is Phase 13's. `EVP_read_pw_string` (`:47`) is its "
        "one-line spelling. `EVP_get_pw_prompt`/`EVP_set_pw_prompt` are this file's too and did "
        "land: they touch the file's own eighty-byte static and no `UI` at all.",
    ),
    # (17) `EVP_CIPHER_CTX_get_algor`.
    (
        ("EVP_CIPHER_CTX_get_algor",),
        11,
        "`crypto/evp/evp_lib.c:1337` is `EVP_PKEY_CTX_get_algor`'s cipher-side twin and decodes "
        "the same `OSSL_SIGNATURE_PARAM_ALGORITHM_ID` octet string with the same "
        "`d2i_X509_ALGOR` (`:1372`), `crypto/asn1/x_algor.c:26`'s and Phase 11's. One "
        "`forensics/prerequisites.json` row covers both accessors.",
    ),
    # (18) `EVP_CIPHER_CTX_rand_key`.
    (
        ("EVP_CIPHER_CTX_rand_key",),
        9,
        "`crypto/evp/evp_enc.c:1751` falls through to "
        "`RAND_priv_bytes_ex(libctx, key, kl, 0)` (`:1764`) for every cipher without "
        "`EVP_CIPH_RAND_KEY`, which is every provider cipher; `rand.h` is Phase 9's. "
        "`EVP_SealInit` above is the caller that made this visible, and the "
        "`RAND_priv_bytes_ex` row in `forensics/prerequisites.json` names both.",
    ),
    # (19) `BIO_f_reliable`.
    (
        ("BIO_f_reliable",),
        9,
        "`crypto/evp/bio_ok.c:127` is `return &methods_ok`, and `methods_ok` (`:112`) is a "
        "`BIO_METHOD` whose write path is `ok_write` (`:254`) -> `sig_out` -- and `sig_out` "
        "fills the record's digest half with `RAND_bytes(md_data, md_size)` (`:456`). "
        "`rand.h` is Phase 9's, and the method struct cannot be published with a callback that "
        "has no callee, so the export is withheld rather than the table partial.",
    ),
    # (20) `EVP_add_alg_module`.
    (
        ("EVP_add_alg_module",),
        11,
        "`crypto/evp/evp_cnf.c:69` registers `alg_module_init` (`:24`), whose `fips_mode` arm "
        "reads the section value with `X509V3_get_value_bool` (`:46`, defined at "
        "`crypto/x509/v3_utl.c:266` and declared in `x509v3.h`, Phase 11's). The other three "
        "calls in the handler -- `CONF_imodule_get_value`, `NCONF_get_section`, "
        "`evp_set_default_properties_int` -- are landed, so Phase 11 is the only blocker, and "
        "it is the same one the subphase plan names for this name.",
    ),
    # (21) The HPKE GREASE value.
    (
        ("OSSL_HPKE_get_grease_value",),
        9,
        "`crypto/hpke/hpke.c:1377`'s only observable is whether the GREASE ciphertext gets "
        "filled, and it is filled by `RAND_bytes_ex(libctx, ct, ctlen, 0)` (`:1433`) -- "
        "`rand.h`, Phase 9. Its random-suite arm additionally reaches "
        "`ossl_rand_uniform_uint32` (`crypto/hpke/hpke_util.c:198`, `:220`, `:243`), the same "
        "stratum. D195 recorded the withholding and `forensics/prerequisites.json`'s "
        "`RAND_bytes_ex` row names both coordinates.",
    ),
    # (22) The eight PEM names `EVP_md5` blocks, three of which RAND_bytes also blocks.
    (
        ("PEM_do_header", "PEM_bytes_read_bio", "PEM_bytes_read_bio_secmem",
         "PEM_ASN1_read", "PEM_ASN1_read_bio", "PEM_ASN1_write",
         "PEM_ASN1_write_bio", "PEM_ASN1_write_bio_ctx"),
        13,
        "`PEM_do_header` (`crypto/pem/pem_lib.c:445`) derives the block key with "
        "`EVP_BytesToKey(cipher->cipher, EVP_md5(), ...)` (`:479`), and `EVP_md5` is "
        "`crypto/evp/legacy_md5.c:36`'s legacy `EVP_MD` over `MD5_Init`/`_Update`/`_Final` -- "
        "which 7.3g handed to Phase 13 with its primitive unit named, so it is Phase 13's and "
        "not this stratum's even though `evp.h` declares it. The other seven reach it through "
        "one or two calls: `PEM_bytes_read_bio` (`:286`) and its `_secmem` spelling (`:294`) "
        "call `PEM_do_header` from `pem_bytes_read_bio_flags`, `PEM_ASN1_read_bio` "
        "(`crypto/pem/pem_oth.c:20`) calls `PEM_bytes_read_bio` (`:28`), `PEM_ASN1_read` "
        "(`pem_lib.c:111`) calls `PEM_ASN1_read_bio`, and the `PEM_ASN1_write*` trio "
        "(`:303`, `:428`, `:436`) shares `PEM_ASN1_write_bio_internal`, whose encrypted arm "
        "calls `EVP_md5` (`:392`) as well as `RAND_bytes` for the DEK salt (`:386`, Phase 9). "
        "So Phase 9 also feeds the write trio and Phase 13 is the binding phase for all eight.",
    ),
    # (23) `PEM_def_callback`.
    (
        ("PEM_def_callback",),
        13,
        "`crypto/pem/pem_lib.c:36`'s `userdata == NULL` arm is "
        "`EVP_read_pw_string_min(buf, min_len, num, prompt, rwflag)` (`:62`), the `UI` "
        "program two rows above, and `ui.h` is Phase 13's. The `userdata != NULL` arm is a "
        "`strlen`/`memcpy` with `num` as the clamp and needs nothing foreign, but an export "
        "cannot be half-written and the arm every `PEM_write_*PrivateKey*` caller reaches is "
        "the other one. D194 recorded this and kept `forensics/prerequisites.json`'s `UI_new` "
        "row rather than adding one naming `EVP_read_pw_string_min`, which is a Phase-7-owned "
        "export and may not appear there.",
    ),
    # (24) The fifteen reader/writer spellings the codec is reached through first.
    (
        ("PEM_read_bio_PrivateKey", "PEM_read_bio_PrivateKey_ex", "PEM_read_PrivateKey",
         "PEM_read_PrivateKey_ex", "PEM_read_bio_Parameters", "PEM_read_bio_Parameters_ex",
         "PEM_write_bio_PrivateKey", "PEM_write_bio_PrivateKey_ex", "PEM_write_PrivateKey",
         "PEM_write_PrivateKey_ex", "PEM_write_bio_Parameters",
         "PEM_write_bio_PKCS8PrivateKey", "PEM_write_bio_PKCS8PrivateKey_nid",
         "PEM_write_PKCS8PrivateKey", "PEM_write_PKCS8PrivateKey_nid"),
        13,
        "the six readers are `pem_read_bio_key` (`crypto/pem/pem_pkey.c:216`), whose first "
        "attempt is `pem_read_bio_key_decoder` (`:35`) -> `OSSL_DECODER_CTX_new_for_pkey` "
        "(`:49`, `decoder.h`, Phase 10) and whose fallback is `pem_read_bio_key_legacy` "
        "(`:101`) -> `PEM_bytes_read_bio_secmem` (`:116`) or `PEM_bytes_read_bio` (`:127`) -- "
        "which is the eighth name of the row above and therefore Phase 13. The six writers "
        "expand `IMPLEMENT_PEM_provided_write_body_*` (`crypto/pem/pem_local.h`), whose encoder "
        "call is Phase 10 and whose `legacy:` label reaches "
        "`PEM_write_bio_PKCS8PrivateKey`/`PEM_write_bio_PrivateKey_traditional` (Phase 13 and "
        "10); the four PKCS#8 spellings are `do_pk8pkey` (`crypto/pem/pem_pk8.c:69`), whose "
        "`OSSL_ENCODER_CTX_new_for_pkey` (`:75`) is Phase 10 and whose "
        "`cb = PEM_def_callback` (`:91`) is Phase 13. So Phase 10 is what these fifteen are "
        "reached through **first** -- which is what 7.5's `NOT_MEASURED` lines say -- and Phase "
        "13 is the phase that retires them, because the fallback legs cannot be omitted.",
    ),
    # (25) `PEM_write_bio_PrivateKey_traditional`.
    (
        ("PEM_write_bio_PrivateKey_traditional",),
        13,
        "`crypto/pem/pem_pkey.c:342` needs `evp_pkey_copy_downgraded` (`:356`, Phase 8, for the "
        "provided-key copy), `x->ameth->old_priv_encode`/`x->ameth->pem_str` (`:359`, `:364`, "
        "Phase 8's ameth contents), the `i2d_PrivateKey` function pointer (`:365`, Phase 10) and "
        "`PEM_ASN1_write_bio` (`:365`, Phase 13 behind `EVP_md5` and Phase 9 behind "
        "`RAND_bytes`). Four strata feed it and Phase 13 is the latest, so Phase 13 retires it. "
        "D194 named this as the one name of the private-key family that needs the ameth "
        "*before* it needs the encoder, and this row is the four-dependency version of that "
        "sentence.",
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

    # The second deferral mechanism, and the fail-closed one: a symbol in `BLOCKED_HANDOFFS` that
    # the crate now defines is a stale row rather than a harmless one, because a table that can
    # keep covering a landed symbol can hide the next real gap behind it. Same rule
    # `forensics/prerequisites.json` uses, same reason.
    blocked: dict[str, dict] = {}
    for symbols, phase, reason in BLOCKED_HANDOFFS:
        for sym in symbols:
            if sym not in owned:
                raise SystemExit(
                    f"phase7-obligations: BLOCKED_HANDOFFS names {sym}, which is not in this "
                    f"stratum's working set (or is not an authority export at all)"
                )
            if sym in done:
                raise SystemExit(
                    f"phase7-obligations: BLOCKED_HANDOFFS records {sym} as blocked on phase "
                    f"{phase}, but the crate defines it; retire the row"
                )
            if sym in handed_on:
                raise SystemExit(
                    f"phase7-obligations: {sym} is in both LEGACY_HANDOFFS and BLOCKED_HANDOFFS; "
                    f"one cause per symbol, or the two reasons will disagree"
                )
            blocked[sym] = {
                "symbol": sym,
                "owning_phase": phase,
                "declaring_header": owned[sym]["declaring_header"],
                "reason": reason,
            }
    deferred_names = handed_on_names | set(blocked)
    deferred: list[dict] = list(handed_on.values()) + list(blocked.values())

    implemented_here = sorted(s for s in owned if s in done and s not in deferred_names)
    open_rows = [
        {"symbol": s, "module": owned[s]["module"],
         "declaring_header": owned[s]["declaring_header"],
         "received_from_phase": owned[s]["from"]}
        for s in sorted(owned) if s not in done and s not in deferred_names
    ]

    if len(owned) != len(implemented_here) + len(deferred_names) + len(open_rows):
        raise SystemExit(
            "phase7-obligations: the ledger does not account for exactly its own working "
            f"set: owned={len(owned)} implemented={len(implemented_here)} "
            f"deferred={len(deferred_names)} open={len(open_rows)}"
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
