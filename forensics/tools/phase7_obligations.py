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

# The structured blocker claim and its fail-closed proof. Shared with
# `prerequisite_gate.py` rather than duplicated: the checks are the same facts about the
# same atlases, and two copies would be two things to keep true. See D198.
from blocker_liveness import (  # noqa: E402
    BlockerAtlas,
    Blocker,
    BlockedHandoff,
    blockers_to_json,
    check_rows,
    phase_states,
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
    # `EVP_md5` and `EVP_md5_sha1` were the tenth and eleventh rows here until D293 landed
    # them: `legacy_md5.c` and `legacy_md5_sha1.c` are transcribed in `src/evp/legacy_md5.rs`,
    # so the row is retired rather than left covering a symbol the crate now defines -- which
    # `BLOCKED_HANDOFFS`' own fail-closed rule refuses. `EVP_md4` and `EVP_mdc2` stay.
    (("EVP_mdc2",), "crypto/mdc2/", "`legacy_mdc2.c`, itself over `crypto/des/`"),
    (("EVP_sha",), "crypto/sha/",
     "`legacy_sha.c`, which builds every SHA-1, SHA-2, SHA-3 and SHAKE static in one table"),
    (("EVP_blake2",), "providers/implementations/digests/",
     "`legacy_blake2.c`, whose callbacks call the provider BLAKE2 implementation's "
     "`ossl_blake2b_*`/`ossl_blake2s_*` (the authority has no `crypto/blake2/`; the name this "
     "row carried from D196 was wrong and the unit check found it)"),
    (("EVP_ripemd",), "crypto/ripemd/", "`legacy_ripemd.c`"),
    (("EVP_whirlpool",), "crypto/whrlpool/",
     "`legacy_wp.c`, whose callbacks call `crypto/whrlpool/`'s own primitives; the directory "
     "is spelled `whrlpool`, and the `crypto/whirlpool/` this row carried from D196 was a "
     "typo the unit check found"),
    (("EVP_sm3",), "crypto/sm3/", "`legacy_sm3.c`"),
]



# ---------------------------------------------------------------------------------------------
# The blocked hand-offs: a symbol whose declaring header is this stratum's but whose **body**
# needs a name no module of this crate defines.
#
# The 7.3g table above is one mechanism -- a legacy method static whose callbacks call a primitive
# unit -- and this table is the other. They are kept apart because a reason that says "the
# callbacks call AES" is a statement about a whole subsystem, whereas a row here is a *structured*
# claim whose truth `forensics/tools/blocker_liveness.py` proves rather than a reader believes.
#
# Each row is a `BlockedHandoff`: the deferred `symbols`, the latest phase it is blocked on
# (`binding_phase`, the old `owning_phase`), and the smallest set of `Blocker`s that carries the
# claim. A `Blocker` names the blocker's `name`, the `authority_unit` and `line` it is defined at,
# its `kind` (`exported` / `internal` / `type`) and the `owning_phase` -- the stratum that lands
# it. `check_rows` then proves, fail-closed and before this tool writes anything:
#
#   1. every blocker is a real authority name (export-defining-units, internal-symbols or
#      typedef-owners) -- a name no record contains is a typo, not a reason;
#   2. every blocker is currently absent from the crate;
#   3. every blocker's `owning_phase` is the phase its own authority record (or the
#      `forensics/prerequisites.json` row that lands it) assigns, and `binding_phase` is the
#      latest of them;
#   4. if every blocker has landed, the deferral is invalid and the row must be retired -- this
#      is the `EVP_PKEY_new_mac_key` case D196 found by hand and the machinery now finds;
#   5. if the binding phase is complete and a blocker is still absent, the completed stratum did
#      not produce the name it owed.
#
# A row that names only some of the names its reason mentions is honest because the omitted ones
# cannot carry the claim: they are this stratum's own withheld exports, or internal names with no
# recorded owner phase of their own. Each such row says so in its `note`, and `docs/DECISIONS.md`
# D198 lists the few places where no machine-checkable claim exists at all.
#
# What `binding_phase` means, in one sentence: **the latest stratum the symbol is blocked on**,
# because that is the first phase whose completion retires the row. A row naming an earlier phase
# would promise a landing that cannot happen -- `PEM_read_bio_PrivateKey` is reached through
# `OSSL_DECODER_CTX_new_for_pkey` (Phase 10) *first* and through `PEM_bytes_read_bio` (Phase 13)
# on its fallback, and it cannot be written until both exist. `check_rows` enforces the convention
# mechanically: `binding_phase` must be the latest `owning_phase` its blockers declare.
# `forensics/tools/phase5_obligations.py` records the convention for the earlier strata
# ("the later of the two dependencies is the binding one", its `ASN1_add_stable_module` row),
# `docs/DECISIONS.md` D196 records that this stratum follows it, and D198 records that the
# convention is now a check rather than a sentence.
# ---------------------------------------------------------------------------------------------

BLOCKED_HANDOFFS: list[BlockedHandoff] = [
    BlockedHandoff(
        symbols=(
            "EVP_PKEY_get0_RSA", "EVP_PKEY_get1_RSA", "EVP_PKEY_set1_RSA", "EVP_PKEY_get0_DSA",
            "EVP_PKEY_get1_DSA", "EVP_PKEY_set1_DSA", "EVP_PKEY_get0_DH", "EVP_PKEY_get1_DH",
            "EVP_PKEY_set1_DH", "EVP_PKEY_get0_EC_KEY", "EVP_PKEY_get1_EC_KEY",
            "EVP_PKEY_set1_EC_KEY"
        ),
        binding_phase=8,
        blocked_by=(
            Blocker("RSA", "types.h", 155, "type", 8),
            Blocker("DSA", "types.h", 150, "type", 8),
            Blocker("DH", "types.h", 146, "type", 8),
            Blocker("EC_KEY", "types.h", 163, "type", 8),
            Blocker("evp_pkey_get_legacy", "crypto/evp/p_lib.c", 2154, "internal", 8),
            Blocker("evp_pkey_copy_downgraded", "crypto/evp/p_lib.c", 2066, "internal", 8),
        ),
        reason=(
            "all twelve reach `evp_pkey_get_legacy` (`crypto/evp/p_lib.c:2154`) through their "
                "file's own `evp_pkey_get0_<TYPE>_int` (`crypto/evp/p_legacy.c:40`, `:76`; "
                "`crypto/evp/p_lib.c:887`, `:998`), and that function's body past its fast paths is "
                "`evp_pkey_copy_downgraded` (`crypto/evp/p_lib.c:2066`), which **constructs** an "
                "`RSA`/`DH`/`DSA`/`EC_KEY` and imports into its `ameth`. Neither the four types nor "
                "the ameth objects exist yet, so every one of the twelve is blocked on Phase 8 -- and "
                "so are the `RSA_up_ref`/`RSA_free` (`p_legacy.c:29`, `:35`), "
                "`EC_KEY_up_ref`/`EC_KEY_free` (`:67`, `:70`), `DSA_up_ref`/`DSA_free` "
                "(`p_lib.c:905`, `:911`) and "
                "`ossl_dh_is_named_safe_prime_group`/`DH_get0_q`/`DH_up_ref`/`DH_free` "
                "(`p_lib.c:982`, `:985`, `:987`, `:993`) names the `set1_*` and `get1_*` spellings "
                "call directly. `evp_pkey_get_legacy` carries its own `forensics/prerequisites.json` "
                "row (Phase 8, D193); this row is the twelve exports that sit behind it."
        ),
        note=(
            "the four low-level key types are declared only in the weak `types.h`, so they carry "
                "no authority phase of their own; `evp_pkey_get_legacy`, whose phase 8 the atlas and "
                "the prerequisites row agree on, corroborates them. The set is the type family plus "
                "the one function whose body needs it."
        ),
    ),
    BlockedHandoff(
        symbols=(
            "EVP_PKEY_get0_hmac", "EVP_PKEY_get0_poly1305", "EVP_PKEY_get0_siphash"
        ),
        binding_phase=8,
        blocked_by=(
            Blocker("evp_pkey_get_legacy", "crypto/evp/p_lib.c", 2154, "internal", 8),
            Blocker("evp_pkey_copy_downgraded", "crypto/evp/p_lib.c", 2066, "internal", 8),
        ),
        reason=(
            "each is `pkey->type == <type> ? evp_pkey_get_legacy(pkey) : NULL` and then reads "
                "`os->length`/`os->data` off the answer (`crypto/evp/p_lib.c:843`, `:859`, `:877`). "
                "`evp_pkey_get_legacy` (`crypto/evp/p_lib.c:2154`) is the whole dependency and it is "
                "Phase 8's: it constructs a legacy key with `evp_pkey_copy_downgraded` (`:2066`) and "
                "caches it against an `ameth` the crate cannot find. Same row in "
                "`forensics/prerequisites.json`, same stratum."
        ),
    ),
    BlockedHandoff(
        symbols=(
            "EVP_PKEY_encrypt_old", "EVP_PKEY_decrypt_old"
        ),
        binding_phase=8,
        blocked_by=(
            Blocker("RSA_public_encrypt", "crypto/rsa/rsa_crpt.c", 33, "exported", 8),
            Blocker("RSA_private_decrypt", "crypto/rsa/rsa_crpt.c", 45, "exported", 8),
            Blocker("evp_pkey_get_legacy", "crypto/evp/p_lib.c", 2154, "internal", 8),
        ),
        reason=(
            "`crypto/evp/p_enc.c:32` and `crypto/evp/p_dec.c:32` both take the low-level key with "
                "`evp_pkey_get0_RSA_int` (`crypto/evp/p_legacy.c:40`, which is `evp_pkey_get_legacy` "
                "behind a type test) and then call the primitive -- `RSA_public_encrypt` "
                "(`p_enc.c:36`) and `RSA_private_decrypt` (`p_dec.c:36`). Both the accessor and the "
                "two primitives are Phase 8's."
        ),
        note=(
            "`evp_pkey_get0_RSA_int` has no recorded owner phase, so its own dependency "
                "`evp_pkey_get_legacy` is named in its place; the two primitives are the direct "
                "calls."
        ),
    ),
    BlockedHandoff(
        symbols=(
            "EVP_PKEY_get_ec_point_conv_form", "EVP_PKEY_get_field_type"
        ),
        binding_phase=8,
        blocked_by=(
            Blocker("EVP_PKEY_get0_EC_KEY", "crypto/evp/p_legacy.c", 45, "exported", 7),
            Blocker("evp_pkey_get_legacy", "crypto/evp/p_lib.c", 2154, "internal", 8),
        ),
        reason=(
            "each opens with `pkey->keymgmt == NULL || pkey->keydata == NULL` and answers its "
                "legacy arm -- `EVP_PKEY_get0_EC_KEY` then `EC_KEY_get_conv_form` "
                "(`crypto/evp/p_lib.c:2472`, `:2477`) or `EC_KEY_get0_group` then "
                "`EC_GROUP_get_field_type` (`:2512`, `:2517`, `:2521`). The three EC accessors "
                "landed with D340; what is still absent is `EVP_PKEY_get0_EC_KEY` itself, this "
                "stratum's own withheld export, whose whole body is `evp_pkey_get_legacy` "
                "(`crypto/evp/p_lib.c:2154`) -- so the row names the accessor and its one "
                "dependency, which is what it actually waits on."
        ),
    ),
    BlockedHandoff(
        symbols=(
            "EVP_PKEY_type",
        ),
        binding_phase=8,
        blocked_by=(
            Blocker("ossl_rsa_asn1_meths", "crypto/rsa/rsa_ameth.c", 968, "internal", 8),
        ),
        reason=(
            "`crypto/evp/evp_pkey_type.c:63` is `EVP_PKEY_asn1_find(&e, type)` and then "
                "`ameth->pkey_id`. The function is landed -- `src/evp/pkey_asn1.rs` holds it as the "
                "`pub(crate) evp_pkey_type` helper `EVP_PKEY_get_base_id` calls (D193) -- and the "
                "export is withheld because its whole answer is the `standard_methods[]` table "
                "`crypto/asn1/ameth_lib.c:54` fills from `crypto/asn1/standard_methods.h`, whose "
                "twelve `ossl_<alg>_asn1_meth` objects are Phase 8's. The `ENGINE_finish(e)` at `:75` "
                "is the `*pe = NULL` mechanism D181 records, not a second blocker."
        ),
        note=(
            "`ossl_rsa_asn1_meths` is the object the prerequisite row names as the first of the "
                "twelve `standard_methods[]` entries; the other eleven are the same stratum, same "
                "table, same answer, and no record gives any of them a phase of its own."
        ),
    ),
    BlockedHandoff(
        symbols=(
            "EVP_PKEY_print_public", "EVP_PKEY_print_private", "EVP_PKEY_print_params",
            "EVP_PKEY_print_public_fp", "EVP_PKEY_print_private_fp",
            "EVP_PKEY_print_params_fp"
        ),
        binding_phase=10,
        blocked_by=(
            Blocker("OSSL_ENCODER_CTX_new_for_pkey", "crypto/encode_decode/encoder_pkey.c", 342, "exported", 10),
            Blocker("OSSL_ENCODER_CTX_get_num_encoders", "crypto/encode_decode/encoder_lib.c", 345, "exported", 10),
            Blocker("OSSL_ENCODER_to_bio", "crypto/encode_decode/encoder_lib.c", 68, "exported", 10),
            Blocker("ossl_rsa_asn1_meths", "crypto/rsa/rsa_ameth.c", 968, "internal", 8),
        ),
        reason=(
            "the three `_fp` twins are `BIO_new_fp` around the three others, and all six reach "
                "`print_pkey` (`crypto/evp/p_lib.c:1196`), whose first statement is "
                "`OSSL_ENCODER_CTX_new_for_pkey` (`:1211`) followed by "
                "`OSSL_ENCODER_CTX_get_num_encoders` (`:1213`) and `OSSL_ENCODER_to_bio` (`:1214`). "
                "Those three are `encoder.h`'s and Phase 10's, and the call is unconditional -- it is "
                "not the legacy fallback that decides whether the export can be written. The fallback "
                "arm below it (`pkey->ameth->pub_print`/`priv_print`/`param_print`, at `:1233`, "
                "`:1241`, `:1249`) is Phase 8's ameth *contents*, so Phase 8 also feeds these six; "
                "the struct and its three function-pointer fields are already declared, which is why "
                "Phase 10 is the binding one."
        ),
    ),
    BlockedHandoff(
        symbols=(
            "EVP_PKEY_set1_engine", "EVP_PKEY_get0_engine"
        ),
        binding_phase=13,
        blocked_by=(
            Blocker("ENGINE_init", "crypto/engine/eng_init.c", 86, "exported", 13),
            Blocker("ENGINE_get_pkey_meth", "crypto/engine/tb_pkmeth.c", 74, "exported", 13),
            Blocker("ENGINE_finish", "crypto/engine/eng_init.c", 106, "exported", 13),
        ),
        reason=(
            "`crypto/evp/p_lib.c:732` calls `ENGINE_init` (`:735`), `ENGINE_get_pkey_meth` "
                "(`:739`) and `ENGINE_finish` (`:736`, `:745`) and writes `pkey->pmeth_engine`; "
                "`:750` reads `pkey->engine`. `ENGINE` is `engine.h`'s and Phase 13's, and this "
                "crate's `EvpPkey` has neither field -- they are absent with the rest of the legacy "
                "attribute block (`src/evp/pkey.rs` module doc), so the pair is blocked on Phase 13 "
                "and on nothing else."
        ),
    ),
    BlockedHandoff(
        symbols=(
            "d2i_PublicKey", "d2i_KeyParams", "d2i_KeyParams_bio"
        ),
        binding_phase=8,
        blocked_by=(
            Blocker("d2i_RSAPublicKey", "crypto/rsa/rsa_asn1.c", 117, "exported", 8),
            Blocker("d2i_DSAPublicKey", "crypto/dsa/dsa_asn1.c", 67, "exported", 8),
            Blocker("o2i_ECPublicKey", "crypto/ec/ec_asn1.c", 1121, "exported", 8),
            Blocker("evp_pkey_copy_downgraded", "crypto/evp/p_lib.c", 2066, "internal", 8),
        ),
        reason=(
            "`d2i_PublicKey` (`crypto/asn1/d2i_pu.c:28`) is a `switch` on "
                "`EVP_PKEY_get_base_id(ret)` whose three arms call `d2i_RSAPublicKey` (`:52`), "
                "`d2i_DSAPublicKey` (`:59`) and `o2i_ECPublicKey` (`:71`), plus "
                "`evp_pkey_copy_downgraded` (`:42`) for the provided-EC input. `d2i_KeyParams` "
                "(`crypto/asn1/d2i_param.c:18`) refuses unless `ret->ameth != NULL && "
                "ret->ameth->param_decode != NULL` (`:31`) and then calls it, and `d2i_KeyParams_bio` "
                "(`:49`) is a `BUF_MEM` read around it. Every one of those names is Phase 8's; the "
                "`asn1_d2i_read_bio`/`EVP_PKEY_set_type` calls are landed."
        ),
    ),
    BlockedHandoff(
        symbols=(
            "d2i_PrivateKey", "d2i_PrivateKey_ex", "d2i_AutoPrivateKey",
            "d2i_AutoPrivateKey_ex"
        ),
        binding_phase=10,
        blocked_by=(
            Blocker("OSSL_DECODER_CTX_new_for_pkey", "crypto/encode_decode/decoder_pkey.c", 821, "exported", 10),
            Blocker("ossl_rsa_asn1_meths", "crypto/rsa/rsa_ameth.c", 968, "internal", 8),
        ),
        reason=(
            "all four are `d2i_PrivateKey_decoder` then, if it answered NULL, "
                "`ossl_d2i_PrivateKey_legacy` (`crypto/asn1/d2i_pr.c:172`-`:175`, `:247`-`:250`). The "
                "decoder builds an `OSSL_DECODER_CTX` with `OSSL_DECODER_CTX_new_for_pkey` (`:78`), "
                "which is `decoder.h`'s and Phase 10's and is called **first**; the fallback reads "
                "`ret->ameth->old_priv_decode`/`priv_decode`/`priv_decode_ex` (`:130`, `:132`) and "
                "calls `evp_pkcs82pkey_legacy` (`crypto/evp/evp_pkey.c:52`-`:59` is the same fields "
                "again), which is Phase 8's. So both phases feed these four and Phase 10 is the "
                "binding one: an export cannot be half-written, and the half that runs first is the "
                "decoder."
        ),
    ),
    BlockedHandoff(
        symbols=(
            "i2d_PrivateKey", "i2d_PKCS8PrivateKey", "i2d_PublicKey", "i2d_KeyParams",
            "i2d_KeyParams_bio"
        ),
        binding_phase=10,
        blocked_by=(
            Blocker("OSSL_ENCODER_CTX_new_for_pkey", "crypto/encode_decode/encoder_pkey.c", 342, "exported", 10),
            Blocker("OSSL_ENCODER_to_data", "crypto/encode_decode/encoder_lib.c", 119, "exported", 10),
            Blocker("OSSL_ENCODER_CTX_free", "crypto/encode_decode/encoder_meth.c", 645, "exported", 10),
            Blocker("ossl_rsa_asn1_meths", "crypto/rsa/rsa_ameth.c", 968, "internal", 8),
        ),
        reason=(
            "all five reach `i2d_provided` (`crypto/asn1/i2d_evp.c:33`) whenever the key is "
                "provided, and that function is `OSSL_ENCODER_CTX_new_for_pkey` (`:53`) + "
                "`OSSL_ENCODER_to_data` (`:59`) + `OSSL_ENCODER_CTX_free` (`:64`), `encoder.h`'s and "
                "Phase 10's. Their non-provided arms are Phase 8's as well -- `i2d_PublicKey`'s "
                "`switch` calls `i2d_RSAPublicKey`/`i2d_DSAPublicKey`/`i2o_ECPublicKey` (`:159`, "
                "`:162`, `:165`) through `EVP_PKEY_get0_RSA`/`_DSA`/`_EC_KEY`, and "
                "`i2d_PrivateKey_impl`'s calls `a->ameth->old_priv_encode` (`:106`) and "
                "`EVP_PKEY2PKCS8` (`crypto/evp/evp_pkey.c:129`, itself an encoder context) -- so "
                "Phase 8 feeds these five too and Phase 10 is the binding one."
        ),
    ),
    BlockedHandoff(
        symbols=(
            "ASN1_item_sign_ex", "ASN1_item_verify_ex"
        ),
        binding_phase=11,
        blocked_by=(
            Blocker("ASN1_item_sign_ctx", "crypto/asn1/a_sign.c", 146, "exported", 11),
            Blocker("ASN1_item_verify_ctx", "crypto/asn1/a_verify.c", 111, "exported", 11),
        ),
        reason=(
            "`ASN1_item_sign_ex` (`crypto/asn1/a_sign.c:121`) builds its digest context and then "
                "hands it to `ASN1_item_sign_ctx` (`:138`); `ASN1_item_verify_ex` "
                "(`crypto/asn1/a_verify.c:95`) is the same shape around `ASN1_item_verify_ctx` "
                "(`:104`). Both delegates are declared in `x509.h`, are defined in those same two "
                "files (`a_sign.c:146`, `a_verify.c:111`) and are Phase 11's exports, so the Phase 5 "
                "-> 7 hand-off cannot be completed here; `forensics/prerequisites.json` carries the "
                "pair with this reason and `RT-EVP-PKEY`'s `NOT_MEASURED` lines name them. "
                "`evp_md_ctx_new_ex`, the other callee, is `crypto/evp/digest.c`'s own internal and "
                "belongs with this stratum."
        ),
    ),
    BlockedHandoff(
        symbols=(
            "EVP_PKEY_meth_find", "EVP_PKEY_meth_get_count", "EVP_PKEY_meth_get0"
        ),
        binding_phase=8,
        blocked_by=(
            Blocker("ossl_rsa_pkey_method", "crypto/rsa/rsa_pmeth.c", 851, "internal", 8),
        ),
        reason=(
            "`EVP_PKEY_meth_find` (`crypto/evp/pmeth_lib.c:106`) searches `standard_methods[]` "
                "(`:54`) with `OBJ_bsearch_pmeth_func` (`:114`); `EVP_PKEY_meth_get_count` (`:646`) "
                "answers `OSSL_NELEM(standard_methods)` plus the application stack; "
                "`EVP_PKEY_meth_get0` (`:655`) indexes the table outright before it touches that "
                "stack. The ten `ossl_<alg>_pkey_method` objects the table holds are Phase 8's "
                "contents (D163, D165, D184), and the application half of the registry is already "
                "landed and courted -- so Phase 8 is the only phase that retires these three, and a "
                "stub would answer the application count where the authority answers twelve more."
        ),
        note=(
            "the same shape as row 6: `ossl_rsa_pkey_method` is the first of the ten "
                "`standard_methods[]` `EVP_PKEY_METHOD` objects the prerequisite row names."
        ),
    ),
    BlockedHandoff(
        symbols=(
            "EVP_add_alg_module",
        ),
        binding_phase=11,
        blocked_by=(
            Blocker("X509V3_get_value_bool", "crypto/x509/v3_utl.c", 266, "exported", 11),
        ),
        reason=(
            "`crypto/evp/evp_cnf.c:69` registers `alg_module_init` (`:24`), whose `fips_mode` arm "
                "reads the section value with `X509V3_get_value_bool` (`:46`, defined at "
                "`crypto/x509/v3_utl.c:266` and declared in `x509v3.h`, Phase 11's). The other three "
                "calls in the handler -- `CONF_imodule_get_value`, `NCONF_get_section`, "
                "`evp_set_default_properties_int` -- are landed, so Phase 11 is the only blocker, and "
                "it is the same one the subphase plan names for this name."
        ),
    ),
    BlockedHandoff(
        symbols=(
            "PEM_read_bio_PrivateKey", "PEM_read_bio_PrivateKey_ex", "PEM_read_PrivateKey",
            "PEM_read_PrivateKey_ex", "PEM_read_bio_Parameters", "PEM_read_bio_Parameters_ex",
            "PEM_write_bio_PrivateKey", "PEM_write_bio_PrivateKey_ex", "PEM_write_PrivateKey",
            "PEM_write_PrivateKey_ex", "PEM_write_bio_Parameters",
            "PEM_write_bio_PKCS8PrivateKey", "PEM_write_bio_PKCS8PrivateKey_nid",
            "PEM_write_PKCS8PrivateKey", "PEM_write_PKCS8PrivateKey_nid"
        ),
        binding_phase=13,
        blocked_by=(
            Blocker("OSSL_DECODER_CTX_new_for_pkey", "crypto/encode_decode/decoder_pkey.c", 821, "exported", 10),
            Blocker("OSSL_ENCODER_CTX_new_for_pkey", "crypto/encode_decode/encoder_pkey.c", 342, "exported", 10),
            Blocker("UI_new", "crypto/ui/ui_lib.c", 18, "exported", 13),
        ),
        reason=(
            "the six readers are `pem_read_bio_key` (`crypto/pem/pem_pkey.c:216`), whose first "
                "attempt is `pem_read_bio_key_decoder` (`:35`) -> `OSSL_DECODER_CTX_new_for_pkey` "
                "(`:49`, `decoder.h`, Phase 10) and whose fallback is `pem_read_bio_key_legacy` "
                "(`:101`) -> `PEM_bytes_read_bio_secmem` (`:116`) or `PEM_bytes_read_bio` (`:127`) -- "
                "which is the eighth name of the row above and therefore Phase 13. The six writers "
                "expand `IMPLEMENT_PEM_provided_write_body_*` (`crypto/pem/pem_local.h`), whose "
                "encoder call is Phase 10 and whose `legacy:` label reaches "
                "`PEM_write_bio_PKCS8PrivateKey`/`PEM_write_bio_PrivateKey_traditional` (Phase 13 and "
                "10); the four PKCS#8 spellings are `do_pk8pkey` (`crypto/pem/pem_pk8.c:69`), whose "
                "`OSSL_ENCODER_CTX_new_for_pkey` (`:75`) is Phase 10 and whose `cb = "
                "PEM_def_callback` (`:91`) is Phase 13. So Phase 10 is what these fifteen are reached "
                "through **first** -- which is what 7.5's `NOT_MEASURED` lines say -- and Phase 13 is "
                "the phase that retires them, because the fallback legs cannot be omitted."
        ),
    ),
    BlockedHandoff(
        symbols=(
            "PEM_write_bio_PrivateKey_traditional",
        ),
        binding_phase=10,
        blocked_by=(
            Blocker("evp_pkey_copy_downgraded", "crypto/evp/p_lib.c", 2066, "internal", 8),
            Blocker("OSSL_ENCODER_CTX_new_for_pkey", "crypto/encode_decode/encoder_pkey.c", 342, "exported", 10),
            Blocker("RAND_bytes", "crypto/rand/rand_lib.c", 500, "exported", 9),
        ),
        reason=(
            "`crypto/pem/pem_pkey.c:342` needs `evp_pkey_copy_downgraded` (`:356`, Phase 8, for "
                "the provided-key copy), `x->ameth->old_priv_encode`/`x->ameth->pem_str` (`:359`, "
                "`:364`, Phase 8's ameth contents), the `i2d_PrivateKey` function pointer (`:365`, "
                "Phase 10) and `PEM_ASN1_write_bio` (`:365`, Phase 13 behind `EVP_md5` and Phase 9 "
                "behind `RAND_bytes`). Four strata feed it and Phase 13 is the latest, so Phase 13 "
                "retires it. D194 named this as the one name of the private-key family that needs the "
                "ameth *before* it needs the encoder, and this row is the four-dependency version of "
                "that sentence."
        ),
    ),
]


# ---------------------------------------------------------------------------------------------
# The third deferral mechanism: a hand-off whose blocker has since landed.
#
# `BLOCKED_HANDOFFS` above makes a *structured claim* -- "this export is withheld because file:line
# calls `X`, and `X` is not in the crate" -- and `blocker_liveness.check_rows` fires the moment `X`
# lands, because a table that can keep covering a landed blocker can hide the next real gap behind
# it. The prescription is "retire the row".
#
# **Retiring these five rows would be a false statement about this stratum, not a correction of
# one.** `owning_phase` is the stratum that committed to building the export, and for all twelve
# names here that is Phase 9: `forensics/phase9-obligations.json` already lists them in its `open`
# list as hand-offs received from this stratum, and `docs/PHASE-9-SUBPHASES.md` section 9.6 is the
# row that owes them. Removing the row would move each name into *this* stratum's `open` list and
# un-seal a stratum whose plan never claimed them; the honest difference is that the *blocker* is
# gone, not that the hand-off is. So the row is **retargeted** from a blocked claim to an
# unconditional one -- D173's precedent, "a deferral that had to move" -- and the reason records
# what landed rather than repeating a claim that no longer holds.
#
# The rows are authored as `(symbols, owning_phase, reason)`. They carry no `blocked_by`, so
# `check_rows` does not run on them and there is nothing left to go stale: an unconditional hand-off
# is falsified by the owner's ledger, which already counts them, rather than by a file:line.
# ---------------------------------------------------------------------------------------------

UNBLOCKED_HANDOFFS: list[tuple[tuple[str, ...], int, str]] = [
    (
        ("EVP_SealInit",),
        9,
        "`crypto/evp/p_seal.c:42` takes the session key from `EVP_CIPHER_CTX_rand_key` and `:46` "
        "fills the IV with `RAND_priv_bytes_ex(libctx, iv, len, 0)`. The `RAND_*` front landed in "
        "D313, so the blocker this row named is now a landed callee; `EVP_CIPHER_CTX_rand_key` is "
        "the second name of this group and is owed with it.",
    ),
    (
        ("EVP_CIPHER_CTX_rand_key",),
        9,
        "`crypto/evp/evp_enc.c:1751`'s fall-through for every cipher without `EVP_CIPH_RAND_KEY` "
        "is `RAND_priv_bytes_ex(libctx, key, kl, 0)` (`:1764`), which landed in D313. What remains "
        "is this stratum's own transcription of the accessor.",
    ),
    (
        ("BIO_f_reliable",),
        9,
        "`crypto/evp/bio_ok.c:456`'s `sig_out` fills the record's digest half with "
        "`RAND_bytes(md_data, md_size)`, which landed in D313. The whole `bio_ok.c` unit is this "
        "stratum's -- `forensics/prerequisites.json`'s `units` block records it as "
        "`deferred_to_a_later_stratum` to Phase 9 -- so the export is owed with the unit rather "
        "than by the stratum that declares `BIO_f_reliable` in `evp.h`.",
    ),
    (
        ("OSSL_HPKE_get_grease_value",),
        9,
        "`crypto/hpke/hpke.c:1433` fills the GREASE ciphertext with `RAND_bytes_ex(libctx, ct, "
        "ctlen, 0)`, and its random-suite arm reaches `ossl_rand_uniform_uint32` "
        "(`crypto/hpke/hpke_util.c`); both are `crypto/rand/`'s and landed in D313. The remaining "
        "dependency is this stratum's own HPKE-utility transcription.",
    ),
    (
        (
            "PEM_do_header", "PEM_bytes_read_bio", "PEM_bytes_read_bio_secmem",
            "PEM_ASN1_read", "PEM_ASN1_read_bio", "PEM_ASN1_write", "PEM_ASN1_write_bio",
            "PEM_ASN1_write_bio_ctx",
        ),
        9,
        "`PEM_do_header` derives the block key with `EVP_BytesToKey(cipher->cipher, EVP_md5(), "
        "...)` (`crypto/pem/pem_lib.c:479`) and the write trio shares `PEM_ASN1_write_bio_internal`'s "
        "DEK salt `RAND_bytes` (`:386`). Both names this row's reason gave have landed -- `EVP_md5` "
        "in D293 and the `RAND_*` front in D313 -- so neither is a blocker any longer. **D350 corrects "
        "what this reason left out:** `PEM_do_header` (`crypto/pem/pem_lib.c:467`) and the write trio "
        "(`:372`) also call `PEM_def_callback` (`:36-69`), whose own chain is `EVP_read_pw_string_min` "
        "(`crypto/evp/evp_key.c:52`, Phase 7) -> the `UI_*` objects (`crypto/ui/ui_lib.c`, Phase 13), "
        "so the eight were blocked on Phase 13 and not on this stratum's transcription alone. D350 "
        "lands that closure (`src/ui/`, `src/evp/p_legacy.rs`, `src/pem/pem_lib.rs`), so all eight are "
        "in Phase 9's `implemented` list and the row stands as the hand-off **edge** rather than being "
        "retired: retiring it would move eight built exports into this sealed stratum's `implemented` "
        "list on the strength of work it did not do, and drop them from Phase 9's "
        "`received_by_handoff`.",
    ),
    (
        ("EVP_PKEY_CTX_get_algor", "EVP_CIPHER_CTX_get_algor"),
        11,
        "Both accessors decode an `OSSL_SIGNATURE_PARAM_ALGORITHM_ID` octet string with "
        "`d2i_X509_ALGOR` (`crypto/evp/evp_lib.c:1490`, `:1372`), the single blocker the old rows "
        "named. D348 transcribed `crypto/asn1/x_algor.c` whole as `src/asn1/x_algor.rs`, so that "
        "export is landed and the blocker is gone -- which is why the rows move here from "
        "`BLOCKED_HANDOFFS` rather than being retired: the exports are still this stratum's to "
        "write, and only the authority *blocker* has landed. The one remaining dependency is the "
        "legacy `OBJ_NAME` digest lookup the decoded identifier is read through, which is Phase 13's "
        "(D343, D344), not a file:line in `x_algor.c` -- so a `Blocker` row would be stale on the "
        "day it was written.",
    ),
    (
        ("EVP_PKEY_assign",),
        8,
        "`crypto/evp/p_lib.c:791`'s body is `EVP_PKEY_type` (`:797`), the two "
        "`EC_KEY_get0_group`/`EC_GROUP_get_curve_name` calls (`:801`, `:803`), `EVP_PKEY_set_type` "
        "(`:816`) and `detect_foreign_key` (`:819`), whose four `is_foreign` calls are "
        "`ossl_ec_key_is_foreign`, `ossl_dsa_is_foreign`, `ossl_rsa_is_foreign` and "
        "`ossl_dh_is_foreign` (`crypto/evp/p_lib.c:760-787`). **Every one of the four landed with "
        "D340 or D351** (`src/ec/backend.rs`, `src/dsa/backend.rs` and `src/rsa/backend.rs` in "
        "D351, `src/dh/backend.rs` with the same), and the two `EC_KEY_get0_group`/"
        "`EC_GROUP_get_curve_name` calls landed with D340, so the only name this export still "
        "waits on is Phase 8's own `EVP_PKEY_type` -- which is not another stratum's blocker but "
        "the `standard_methods[]` cycle D341 measured, and the same cycle that keeps the fifteen "
        "in `src/asn1/ameth.rs`. So the row moves here from `BLOCKED_HANDOFFS` rather than being "
        "retired: the export is still Phase 8's to write, and only the authority *blockers* have "
        "landed. `EVP_PKEY_assign_RSA`/`_DSA`/`_DH`/`_EC_KEY` are `#define`s over it "
        "(`include/openssl/evp.h`), so the four `set1_*` names in the first row wait on it too.",
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
    # The three authority records the blockers resolve against, the crate's own
    # definitions (for the internal and type blockers), and the derived phase states.
    blocker_atlas = BlockerAtlas.from_repo(
        authority_source=auth.source, implemented=done
    )
    states = phase_states()

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
        # The 7.3g claim is about a whole primitive **unit**, not a name, so it cannot be a
        # `Blocker`. What can be checked is that the unit the reason names is really in the
        # authority: a typo in `crypto/md5/` would otherwise hand a family to a stratum for a
        # reason nothing corroborates. The check reads the committed atlases, not the 55 MB
        # source tree, so it is as strong in CI as in the court. This is the unit-level half
        # of the same liveness idea.
        units = [u.strip().rstrip("/") for u in primitive.split(" and ")]
        unknown = [u for u in units if not blocker_atlas.unit_is_known(u)]
        if unknown:
            raise SystemExit(
                f"phase7-obligations: LEGACY_HANDOFFS names {primitive!r}, but no authority "
                f"translation unit any atlas records lives under "
                f"{', '.join(unknown)}; the unit is a typo or the atlas is stale"
            )
        for sym in owned:
            if sym in done or sym in handed_on:
                continue
            if any(sym == p or sym.startswith(p) for p in prefixes):
                handed_on[sym] = {
                    "symbol": sym,
                    "owning_phase": 13,
                    "binding_phase": 13,
                    "declaring_header": owned[sym]["declaring_header"],
                    "blocked_by": [],
                    "reason": (
                        f"a legacy method static whose callbacks call {primitive}'s own "
                        f"primitives; {note}"
                    ),
                }
    handed_on_names = set(handed_on)

    # The third mechanism (see `UNBLOCKED_HANDOFFS`): a hand-off whose blocker has landed. Same
    # fail-closed rule as `BLOCKED_HANDOFFS` for a symbol outside the working set, and **not** the
    # same rule for a symbol the crate now defines -- deliberately, and the asymmetry is the whole
    # point of keeping the two tables apart:
    #
    #   * a `BLOCKED_HANDOFFS` row is falsified by its blocker landing, because its claim IS
    #     "file:line calls X and X is absent";
    #   * an `UNBLOCKED_HANDOFFS` row makes no such claim, so it is not falsified by *itself* being
    #     built. The row is the hand-off **edge**: it is what puts the symbol in the receiving
    #     stratum's working set, and it is what `phase9_obligations.py` reads to count the symbol
    #     as that stratum's. Retiring it the moment the owner lands the symbol would move the
    #     symbol into *this* stratum's `implemented` list on the strength of work this stratum did
    #     not do, and take it off the owner's books at the same time. So the row stays, and where
    #     the landing appears is the owner's ledger, which this tool cannot read: it is written
    #     later in the pipeline, and reading a possibly-stale ledger would be worse than not
    #     reading one.
    #
    # What still fails closed is a row that hands on a symbol this stratum may not name at all,
    # and one that collides with either of the other two mechanisms.
    unblocked_handed_on: dict[str, dict] = {}
    for symbols, owning_phase, reason in UNBLOCKED_HANDOFFS:
        for sym in symbols:
            if sym not in owned:
                raise SystemExit(
                    f"phase7-obligations: UNBLOCKED_HANDOFFS names {sym}, which is not in this "
                    f"stratum's working set (or is not an authority export at all)"
                )
            if sym in handed_on or any(sym in r.symbols for r in BLOCKED_HANDOFFS):
                raise SystemExit(
                    f"phase7-obligations: {sym} is handed on by two of the three mechanisms; "
                    f"one cause per symbol, or the reasons will disagree"
                )
            unblocked_handed_on[sym] = {
                "symbol": sym,
                "owning_phase": owning_phase,
                "binding_phase": owning_phase,
                "declaring_header": owned[sym]["declaring_header"],
                "blocked_by": [],
                "reason": reason,
            }
    unblocked_handed_on_names = set(unblocked_handed_on)

    # The second deferral mechanism, and the fail-closed one: a symbol in `BLOCKED_HANDOFFS` that
    # the crate now defines is a stale row rather than a harmless one, because a table that can
    # keep covering a landed symbol can hide the next real gap behind it. Same rule
    # `forensics/prerequisites.json` uses, same reason.
    blocked: dict[str, dict] = {}
    for row in BLOCKED_HANDOFFS:
        for sym in row.symbols:
            if sym not in owned:
                raise SystemExit(
                    f"phase7-obligations: BLOCKED_HANDOFFS names {sym}, which is not in this "
                    f"stratum's working set (or is not an authority export at all)"
                )
            if sym in done:
                raise SystemExit(
                    f"phase7-obligations: BLOCKED_HANDOFFS records {sym} as blocked on phase "
                    f"{row.binding_phase}, but the crate defines it; retire the row"
                )
            if sym in handed_on:
                raise SystemExit(
                    f"phase7-obligations: {sym} is in both LEGACY_HANDOFFS and BLOCKED_HANDOFFS; "
                    f"one cause per symbol, or the two reasons will disagree"
                )
            blocked[sym] = {
                "symbol": sym,
                "owning_phase": row.binding_phase,
                "binding_phase": row.binding_phase,
                "declaring_header": owned[sym]["declaring_header"],
                "blocked_by": blockers_to_json(row.blocked_by),
                "reason": row.reason,
                **({"note": row.note} if row.note else {}),
            }

    # The liveness proof the old table lacked: each `blocked_by` name is real, absent, and
    # owned by the phase the row declares; a row whose blockers have all landed is invalid,
    # and so is one whose binding stratum sealed without producing a blocker. `check_rows`
    # runs before this tool writes anything, so a stale reason cannot reach the ledger.
    liveness = check_rows(
        blocker_atlas,
        list(BLOCKED_HANDOFFS),
        phase_state=states,
    )
    if liveness:
        raise SystemExit(
            "phase7-obligations: blocker liveness failed:\n  " + "\n  ".join(liveness)
        )
    deferred_names = handed_on_names | set(blocked) | unblocked_handed_on_names
    deferred: list[dict] = (
        list(handed_on.values())
        + list(blocked.values())
        + list(unblocked_handed_on.values())
    )

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
        # The re-audit of every deferral against the liveness check. `structured_rows`
        # carry a name-resolvable claim; `legacy_rows` are 7.3g's, whose cause is a whole
        # primitive unit and whose reason is checked at the unit level; `findings` is 0
        # or this generator would not have reached here.
        "blocker_liveness": {
            "structured_rows": len(BLOCKED_HANDOFFS),
            "structured_blockers": sum(len(r.blocked_by) for r in BLOCKED_HANDOFFS),
            "legacy_rows": len(handed_on_names),
            "legacy_unit_claims": len(LEGACY_HANDOFFS),
            # The third mechanism: a hand-off whose blocker has landed, retargeted from a blocked
            # claim to an unconditional one rather than retired (see `UNBLOCKED_HANDOFFS`).
            "unblocked_rows": len(UNBLOCKED_HANDOFFS),
            "unblocked_symbols": len(unblocked_handed_on_names),
            "findings": len(liveness),
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
        # The blocker resolution and liveness proof read these; naming them keeps the
        # provenance honest and makes the generator go stale when one of them moves.
        InputRef(name="export-defining-units",
                 path=REPO_ROOT / "forensics/atlas/export-defining-units.json"),
        InputRef(name="internal-symbols",
                 path=REPO_ROOT / "forensics/atlas/internal-symbols.json"),
        InputRef(name="typedef-owners",
                 path=REPO_ROOT / "forensics/atlas/typedef-owners.json"),
        InputRef(name="prerequisites", path=REPO_ROOT / "forensics/prerequisites.json"),
        InputRef(name="phase-state", path=REPO_ROOT / "forensics/phase-state.json"),
        InputRef(
            name="authority-source-tree-and-crate-source",
            note=(
                "every blocker's `authority_unit:line` is checked for existence and range "
                "against forensics/authorities/src/<authority>/, and every candidate "
                "definition is read from src/"
            ),
        ),
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
    bl = body["blocker_liveness"]
    print(f"  blocker liveness: {bl['structured_rows']} structured rows / "
          f"{bl['structured_blockers']} blockers checked, "
          f"{bl['legacy_rows']} legacy rows over {bl['legacy_unit_claims']} unit claims, "
          f"findings={bl['findings']}")
    print(f"  owned by header: {body['owned_by_header']}")
    print(f"  owned by module: {body['owned_by_module']}")
    print(f"  hand-offs discharged: "
          f"{ {k: len(v) for k, v in body['handoffs_discharged'].items()} }")
    print(f"  -> {rel(OUT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
