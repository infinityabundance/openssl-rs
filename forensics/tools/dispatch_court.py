#!/usr/bin/env python3
"""openssl-rs — the dispatch plane: `OSSL_FUNC_*` identities and callback signatures.

Why this exists
---------------
`include/openssl/core_dispatch.h` declares the provider facing contract twice over, and both
halves are *numbers and types rather than symbols*:

    #define OSSL_FUNC_CIPHER_NEWCTX 1
    OSSL_CORE_MAKE_FUNC(void *, cipher_newctx, (void *provctx))

The macro expands to `typedef void *(OSSL_FUNC_cipher_newctx_fn)(void *provctx);`. So the
identity is a preprocessor constant and the signature is a typedef'd function type, and neither
is an exported symbol. That puts the whole file outside the reach of every other instrument:

  * the Phase 1 atlas records both, but nothing compared them;
  * `ABI-PROTOTYPE` compares *exported declarations*, so it sees none of this;
  * the ABI courts resolve exported symbols at their ELF versions, and these are not symbols;
  * a runtime court drives an API and observes values, so a wrong dispatch id is visible only if
    a probe happens to call exactly that entry, and a wrong callback arity only if the wrong
    register is read in a way the probe can see.

The gap is not hypothetical. The Phase 6 third-party provider court found **bad core dispatch
IDs** by driving a provider, and `docs/DECISIONS.md` D170 records **two wrong callback types in
landed code** -- `KeyexchDeriveFn` declared three parameters where the header declares four, and
`KeyexchDeriveSkeyFn` returning `c_int` where the header returns `void *`, a truncated pointer.
Both were struct members, invisible to the prototype court by construction, and D170 named the
generable `OSSL_CORE_MAKE_FUNC` type-plane check as the highest-value missing evidence plane.
This tool is that plane, and its first run found the class again -- see D180.

What it checks
--------------
Two planes, both read from the Phase 1 atlas's *Clang* output rather than from header text, so
the authority side is never re-parsed by hand:

  * **identities** -- every `const OSSL_FUNC_X: c_int = n;` in the crate against the atlas's
    recorded value for the macro `OSSL_FUNC_X`. A wrong identity is a wrong dispatch slot.
  * **signatures** -- every Rust `type X = unsafe extern "C" fn(...) -> T;` in the crate against
    the atlas's recorded underlying type of the function-type typedef it implements,
    canonicalised by the same functions `ABI-PROTOTYPE`'s type plane uses, and resolved against
    the aliases of the file it is declared in, so a Rust alias of an alias reads through.

The link between a Rust alias and its authority typedef
-------------------------------------------------------
The crate's names are usually the authority's names in Rust spelling --
`OSSL_FUNC_BIO_read_ex_fn` is `OsslFuncBioReadEx`, `OSSL_FUNC_cipher_gettable_ctx_params_fn` is
`CipherGettableCtxParamsFn` -- so the link is the *squashed* name (lowercased, non-alphanumerics
dropped) with an optional `OSSLFunc`/`OsslFunc` prefix and an optional `Fn` suffix removed. The
resolution order, first match wins:

  1. `NOT_A_DISPATCH`, a declaration that the alias is something else, with a reason. It wins
     over every link, because the three aliases whose names *collide* with dispatch typedefs
     while declaring a different type (`BIO_meth_set_read_ex`'s `char *` against the core
     dispatch's `void *`) are exactly the ones a convention cannot tell apart;
  2. `LINKS`, an explicit link. It wins over the convention and the doc, because it is where a
     fact the names cannot carry is recorded -- `CipherInitFn` is one Rust type for **two**
     authority typedefs, and the crate's own doc names only the first;
  3. the convention;
  4. the `OSSL_FUNC_*_fn` names in the alias's doc comment, for the cases the convention gets
     wrong (`ChildFreeFn` is `OSSL_FUNC_provider_free_fn`).

`LINKS` and `NOT_A_DISPATCH` accept either a bare alias name or `Name@src/path.rs`. The file
form is tried first and exists because a crate may declare one name twice with different types:
`ConfInitFn` is `CONF_METHOD.init` in `src/runtime/conf/types.rs` and `conf_init_func` in
`src/runtime/confmod/mod.rs`.

Two authority typedefs that squash to one key are only accepted when they *are* the same
signature -- `CRYPTO_free_fn` and `OSSL_FUNC_CRYPTO_free_fn` are the public-header and
dispatch-header spelling of one callback -- and both are then checked.

A Rust alias no link resolves must be exempted with a reason. There is no third outcome, because
an unlinked alias silently having no counterpart is the one hole a naming convention leaves: a
typo'd name would pass. `run_courts.py`'s `COURTLESS` is the same idiom.

    python3 forensics/tools/dispatch_court.py
    python3 forensics/tools/dispatch_court.py --report    # the unlinked sets

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    PRODUCTION_AUTHORITY,
    REPO_ROOT,
    InputRef,
    envelope,
    rel,
    resolve_authority,
    write_json,
)
from prototype_court import (  # noqa: E402
    RUST_ALIAS_RE,
    alias_target,
    blank_comments,
    canon_c_type,
    canon_rust_type,
)

OUT = REPO_ROOT / "forensics" / "atlas" / "dispatch-court.json"
GENERATOR = "forensics/tools/dispatch_court.py"
SRC = REPO_ROOT / "src"

IDENTITY_RE = re.compile(
    r"const\s+(OSSL_FUNC_[A-Z0-9_]+)\s*:\s*(?:c_int|c_uint|i32|u32)\s*=\s*(\d+)\s*;"
)
# `[^;]*?` bounds the parameter list because a function type contains no `;`, and the scan runs
# over comment-blanked text so a doc comment cannot supply one.
FN_ALIAS_RE = re.compile(
    r"type\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"((?:Option<\s*)?(?:unsafe\s+)?extern\s+\"C\"\s+fn\s*\([^;]*?\)\s*(?:->\s*[^;]+?)?)\s*;"
)
DOC_FN_RE = re.compile(r"OSSL_FUNC_[A-Za-z0-9_]+_fn")

# ---------------------------------------------------------------------------------------------
# The exemption reasons. One constant per authority declaration mechanism, so that a family is
# written once and every alias still names its own reason.
# ---------------------------------------------------------------------------------------------

# `include/internal/core.h:41-47` -- internal, so the Phase 1 atlas, whose universe is the
# installed public surface, records neither the struct nor its members.
MCM = ("not a provider dispatch: the authority declares it as a member of "
       "`OSSL_METHOD_CONSTRUCT_METHOD` (`include/internal/core.h:41-47`), a struct of plain "
       "function pointers in an internal header, so there is no typedef for the atlas to record")
DSO_INT = ("not a provider dispatch: declared in `include/internal/dso.h`, which is not installed, "
           "so the atlas has no record of it")
CONF_METHOD = ("not a provider dispatch: a member of `include/openssl/conftypes.h:21-32`'s "
               "`struct conf_method_st`, a plain function pointer rather than an "
               "`OSSL_CORE_MAKE_FUNC` declaration")
CONF_INT = ("not a provider dispatch: a member of the `CONF_METHOD` vtable, which the atlas "
            "records as a struct of plain function pointers rather than as typedefs")
EVP_LEGACY = ("not a provider dispatch: a member of `EVP_CIPHER`'s or `EVP_MD`'s legacy callback "
              "list in `evp.h`, declared as a plain function pointer rather than through "
              "`OSSL_CORE_MAKE_FUNC`")
# `crypto/rsa/rsa_local.h:102-147` -- the `RSA_METHOD` members (Phase 8.4). Like `evp.h`'s legacy
# list, the struct declares each callback inline as a plain function pointer; unlike it, the header
# is *internal*, so the atlas -- whose universe is the installed public surface -- records no
# `typedef` for any of the eight and there is no authority name for the crate's aliases to link to.
RSA_METHOD_VTABLE = ("not a provider dispatch: a member of `RSA_METHOD`'s vtable, declared inline "
                     "in `crypto/rsa/rsa_local.h:102-147` as a plain function pointer rather than "
                     "through `OSSL_CORE_MAKE_FUNC`; the header is internal, so the atlas records "
                     "no typedef for it")
# `crypto/dh/dh_local.h:47-64` -- the `DH_METHOD` members (Phase 8.5). The same shape as
# `RSA_METHOD`'s vtable: each callback is declared inline as a plain function pointer, the header
# is internal, and the atlas -- whose universe is the installed public surface -- records no
# `typedef` for any of the six, so there is no authority name for the crate's aliases to link to.
DH_METHOD_VTABLE = ("not a provider dispatch: a member of `DH_METHOD`'s vtable, declared inline "
                    "in `crypto/dh/dh_local.h:47-64` as a plain function pointer rather than "
                    "through `OSSL_CORE_MAKE_FUNC`; the header is internal, so the atlas records "
                    "no typedef for it")
# `crypto/dsa/dsa_local.h:46-70` -- the `DSA_METHOD` members (Phase 8.6). The third of the same
# shape: every callback is declared inline as a plain function pointer, the header is internal, and
# the atlas -- whose universe is the installed public surface -- records no `typedef` for any of the
# eight, so there is no authority name for the crate's aliases to link to.
DSA_METHOD_VTABLE = ("not a provider dispatch: a member of `DSA_METHOD`'s vtable, declared inline "
                     "in `crypto/dsa/dsa_local.h:46-70` as a plain function pointer rather than "
                     "through `OSSL_CORE_MAKE_FUNC`; the header is internal, so the atlas records "
                     "no typedef for it")
# `crypto/ec/ec_local.h:43-200` -- the `EC_METHOD` members (Phase 8.7). The fourth of the same
# shape, and the largest: **fifty-five** callbacks declared inline as plain function pointers in an
# internal header, so the atlas -- whose universe is the installed public surface -- records no
# `typedef` for any of them. The crate's aliases fold the ones the authority spells identically
# (`EcGroupFinishFn` is both `group_finish` and `group_clear_finish`, `EcFieldSqrFn` is six
# members), which is why thirty aliases cover fifty-five members.
EC_METHOD_VTABLE = ("not a provider dispatch: a member of `EC_METHOD`'s vtable, declared inline "
                    "in `crypto/ec/ec_local.h:43-200` as a plain function pointer rather than "
                    "through `OSSL_CORE_MAKE_FUNC`; the header is internal, so the atlas records "
                    "no typedef for it")
# `crypto/ec/ec_local.h:664-688` -- the `EC_KEY_METHOD` members. The same shape again; the four
# aliases below are the ones only this table declares (the other nine members reuse an `EC_METHOD`
# alias, because the authority spells `set_private`, `keygen`, `compute_key`, `sign_setup`,
# `sign_sig` and `verify_sig` identically in both).
EC_KEY_METHOD_VTABLE = ("not a provider dispatch: a member of `EC_KEY_METHOD`'s table, declared "
                        "inline in `crypto/ec/ec_local.h:664-688` as a plain function pointer "
                        "rather than through `OSSL_CORE_MAKE_FUNC`; the header is internal, so the "
                        "atlas records no typedef for it")
# `crypto/ec/ec_local.h:257-258` -- `struct ec_group_st`'s `field_mod_func`. Not a method table at
# all: it is a function pointer **member of the group object**, stored by
# `ossl_ec_GFp_nist_group_set_curve` (one of `BN_nist_mod_192`..`_521`) and called through
# `group` rather than through `group->meth`.
EC_GROUP_FIELD_MOD = ("not a provider dispatch: `struct ec_group_st`'s `field_mod_func` member "
                      "(`crypto/ec/ec_local.h:257-258`), a function pointer on the *group object* "
                      "rather than in a method table, declared inline in an internal header")
# `crypto/ec/ec_curve.c:2536` -- `curve_list[]`'s fourth column, `const EC_METHOD *(*meth)(void)`,
# declared inline in the internal `_ec_list_element_st` rather than through `OSSL_CORE_MAKE_FUNC`.
EC_CURVE_METHOD_COLUMN = ("not a provider dispatch: `curve_list[]`'s fourth column "
                          "(`crypto/ec/ec_curve.c:2536`), a plain function pointer declared inline "
                          "in the internal `_ec_list_element_st` rather than through "
                          "`OSSL_CORE_MAKE_FUNC`")
LHASH_MACRO = ("not a provider dispatch: `lhash.h.in`'s `LHASH_HASH_FN` / `LHASH_COMP_FN` / "
               "`LHASH_DOALL*` macros generate it per type, so there is no single typedef")
SK_MACRO = ("not a provider dispatch: `safestack.h.in`'s `sk_*_compfunc` / `freefunc` / "
            "`copyfunc` macros generate it per type, so there is no single typedef")
OBJ_INT = ("not a provider dispatch: `include/crypto/objects.h`'s `OBJ_NAME` table member, an "
           "internal header the atlas does not record")
# `include/crypto/evp.h:145-192` -- the `EVP_PKEY_METHOD` members. The body is in an internal
# header, so the atlas records no typedef for any of them, and the struct-member record it does
# keep is empty for a struct whose body it cannot see.
PKEY_METHOD = ("not a provider dispatch: the type of `EVP_PKEY_METHOD`'s members, declared inline "
               "in `include/crypto/evp.h:145-192`. The atlas records no typedef for them because "
               "its universe is the installed public surface and that header is internal: 307 of "
               "the 465 struct records have no body at all and only 8 of the 158 complete ones "
               "have a function-pointer field, none of them this one. So the check these need is "
               "a second Clang pass over the internal headers or a generated C assertion, not a "
               "consumer of `structs.json` -- see docs/DECISIONS.md D185")
# `crypto/evp/ctrl_params_translate.c:161-166` -- the two function *types* the translation tables
# store, not function pointers to a `OSSL_CORE_MAKE_FUNC` typedef.
XLAT = ("not a provider dispatch: one of `ctrl_params_translate.c`'s two function *types*, "
        "`fixup_args_fn` and `cleanup_args_fn`, which the translation tables store as function "
        "pointers and which the authority declares as bare typedefs rather than through "
        "`OSSL_CORE_MAKE_FUNC`")
# `crypto/evp/ctrl_params_translate.c:748-751` -- `fix_cipher_md`'s two function-pointer
# parameters, which the authority spells inline in its own signature rather than as typedefs, and
# which the crate names in order to parameterise that one function over the cipher and the digest.
XLAT_GET = ("not a provider dispatch: the type of `fix_cipher_md`'s two function-pointer "
            "parameters (`ctrl_params_translate.c:748-751`), which the authority spells inline in "
            "its own signature rather than as typedefs; the crate names them to parameterise one "
            "function over `EVP_CIPHER` and `EVP_MD`")
CRATE_LOCAL = "not an authority type: a crate-local callback shape with no header counterpart"
# `providers/implementations/include/prov/drbg.h:59-165` -- `struct prov_drbg_st`'s cached virtual
# functions (`instantiate`, `uninstantiate`, `reseed`, `generate`) and its two `dnew`/`dfree`
# callbacks. They are declared **inline in the struct as plain function pointers**, exactly as
# `RSA_METHOD`'s and `EVP_PKEY_METHOD`'s members are, and the header is internal (`prov/`), so the
# atlas -- whose universe is the installed public surface -- records no typedef for any of them and
# the convention rule has no name to join on (D309).
DRBG_VTABLE = ("not a provider dispatch: a member of `struct prov_drbg_st`, declared inline in "
               "`providers/implementations/include/prov/drbg.h:59-165` as a plain function pointer "
               "rather than through `OSSL_CORE_MAKE_FUNC`; the header is internal, so the atlas "
               "records no typedef for it")
# `cipher_aes_wrp.c:28-30` -- the wrap rows' `aeswrap_fn`, a typedef local to a provider
# implementation file. The atlas's universe is the installed public surface, so it records no
# typedef for it, and unlike `block128_f`/`cbc128_f` its name is not declared in a header the
# convention rule can reach. `crypto/modes/wrap128.c`'s `CRYPTO_128_*` have the same shape.
WRAP_FN = ("not a provider dispatch: `cipher_aes_wrp.c:28-30`'s `aeswrap_fn`, a typedef local to a "
           "provider implementation file, which the atlas -- whose universe is the installed "
           "public surface -- records no typedef for")
# `providers/implementations/encode_decode/decode_der2key.h` -- `key_from_pkcs8_t`, the callback
# the decoder rows' `key_from_pkcs8` slot holds (it wraps `OSSL_FUNC_keymgmt_load`). It is a
# typedef local to a provider implementation header, exactly `aeswrap_fn`'s shape, so the atlas --
# whose universe is the installed public surface -- records no typedef for it and the convention
# rule has no name to join on. The five sibling aliases for the same header's callbacks
# (`d2i_PKCS8_fn`, `d2i_PUBKEY_fn`, `check_key_fn`, `adjust_key_fn`, `free_key_fn`) are declared
# Rust-ABI `unsafe fn`, so the function-alias reader never extracts them.
KEY_FROM_PKCS8_FN = (
    "not a provider dispatch: `decode_der2key.h`'s `key_from_pkcs8_t`, a typedef local to a "
    "provider implementation header, which the atlas -- whose universe is the installed public "
    "surface -- records no typedef for")
# `providers/implementations/encode_decode/decode_msblob2key.c` and `decode_pvk2key.c` declare
# their `keytype_desc_st` callback fields as `.c`-local typedefs (`b2i_of_void_fn`,
# `adjust_key_fn`, `free_key_fn`, `b2i_PVK_of_bio_pw_fn`, `check_key_fn`). The atlas's universe is
# the installed public surface, so it records no typedef for a `.c`-local type (the same rule D333
# applies to `EcFieldSetToOneFn`), and the convention rule has no authority name to join on. The
# crate declares one Rust alias per type; `adjust_key_fn`/`free_key_fn` appear in both files with
# the same canonical signature, so a bare name exempts both. Landed with 10.6's two decoder units.
KEYTYPE_DESC_CALLBACK = (
    "not a provider dispatch: a `.c`-local callback typedef of a provider implementation's "
    "`keytype_desc_st` (`decode_msblob2key.c`/`decode_pvk2key.c`), which the atlas -- whose "
    "universe is the installed public surface -- records no typedef for")
# `prov/ciphercommon.h:30` -- `PROV_CIPHER_FUNC(type, name, args)` expands to
# `typedef type(*OSSL_##name##_fn) args`, so the typedef is produced by the preprocessor and there
# is no `typedef` declaration for a declaration reader to record. `OSSL_xts_stream_fn` is the one
# instance the crate names.
PROV_CIPHER_FUNC_TYPE = (
    "not a provider dispatch: `prov/ciphercommon.h:30`'s `PROV_CIPHER_FUNC` macro generates it as "
    "`typedef type(*OSSL_##name##_fn) args`, so the header carries no `typedef` declaration and "
    "the atlas records none")
# `cipher_tdes.h:26-29` -- the member type of `PROV_TDES_CTX`'s `tstream` union, written inline in
# the struct rather than introduced with a `typedef`.
TDES_TSTREAM_FN = (
    "not a provider dispatch: the type of `PROV_TDES_CTX`'s `tstream` union member "
    "(`cipher_tdes.h:26-29`), written inline in the struct rather than introduced with a "
    "`typedef`, so the atlas records no name for it")
# `crypto/ui/ui_local.h:20-59` -- the `UI_METHOD` members (Phase 13 staging, D350). The same shape
# as `RSA_METHOD`'s vtable: each callback is declared inline as a plain function pointer in an
# internal header, and the atlas -- whose universe is the installed public surface -- records no
# `typedef` for any of them, so there is no authority name for the crate's aliases to link to.
UI_METHOD_VTABLE = ("not a provider dispatch: a member of `UI_METHOD`'s vtable, declared inline "
                    "in `crypto/ui/ui_local.h:20-59` as a plain function pointer rather than "
                    "through `OSSL_CORE_MAKE_FUNC`; the header is internal, so the atlas records "
                    "no typedef for it")
# `include/internal/thread_arch.h:57` -- `CRYPTO_THREAD_ROUTINE`, the thread routine the pool and
# the native layer both take. A **function-pointer typedef** rather than a struct member, but the
# atlas records no typedef for it for the same reason as the vtable families above: its universe is
# the installed public surface and `internal/thread_arch.h` is not installed. The crate's alias
# squashes to exactly this name, so without an entry the convention rule leaves it unlinked -- which
# is what D397's first run of this court reported. `CRYPTO_THREAD_RETVAL` needs no entry: it is a
# scalar typedef with no declarator for the signature reader to see.
THREAD_ARCH_INT = ("not a provider dispatch: declared in `include/internal/thread_arch.h:57`, "
                   "which is not installed, so the atlas has no record of it")


def _inline(fn: str, spelling: str) -> str:
    return (f"not a provider dispatch: the type of a parameter of `{fn}`, spelled `{spelling}` "
            f"inline in the header rather than as a typedef")


# ---------------------------------------------------------------------------------------------
# `LINKS` -- explicit links, where the names cannot carry the fact.
# ---------------------------------------------------------------------------------------------
LINKS: dict[str, tuple[str, ...]] = {
    # One Rust type for the encrypt and the decrypt init, which the authority spells twice with
    # the same signature. The crate's doc names only the first.
    "CipherInitFn": ("OSSL_FUNC_cipher_encrypt_init_fn", "OSSL_FUNC_cipher_decrypt_init_fn"),
    "CipherPipelineInitFn": ("OSSL_FUNC_cipher_pipeline_encrypt_init_fn",
                             "OSSL_FUNC_cipher_pipeline_decrypt_init_fn"),
    "CipherSkeyInitFn": ("OSSL_FUNC_cipher_encrypt_skey_init_fn",
                         "OSSL_FUNC_cipher_decrypt_skey_init_fn"),
    # `OSSL_LIB_CTX`'s memory functions, whose callback types live in the public `crypto.h`
    # rather than in `core_dispatch.h`.
    "MallocFn": ("CRYPTO_malloc_fn",),
    "ReallocFn": ("CRYPTO_realloc_fn",),
    # The `stack.rs` declaration of `FreeFn` is the `sk_*_freefunc` shape and is exempted
    # below, which is why this one is scoped to its file.
    "FreeFn@src/runtime/mem.rs": ("CRYPTO_free_fn",),
    # The ex_data callbacks, from `crypto.h`.
    "NewFunc": ("CRYPTO_EX_new",),
    "DupFunc": ("CRYPTO_EX_dup",),
    # `conf.h`'s module-init function type, for the `confmod` declaration of the name.
    "ConfInitFn@src/runtime/confmod/mod.rs": ("conf_init_func",),
    # `core.h`'s provider entry point and thread-stop handler: function-type typedefs that are
    # not `OSSL_FUNC_*` and whose names do not squash to the crate's.
    "ProviderInitFn": ("OSSL_provider_init_fn",),
    "ThreadStopHandlerFn": ("OSSL_thread_stop_handler_fn",),
    # The deprecated BIO callback pair, from `bio.h`.
    "BioCallbackFn": ("BIO_callback_fn",),
    "BioCallbackExFn": ("BIO_callback_fn_ex",),
    "BioInfoCb": ("BIO_info_cb",),
    # `include/openssl/modes.h:40-44`'s `ccm128_f`. The authority's name ends `_f` rather than
    # `_fn`, so the convention rule (which strips only `_fn`) cannot reach it.
    "Ccm128Fn": ("ccm128_f",),
    # `encoder.h`'s two libcrypto-side callbacks for an encoder chain. They are not `OSSL_FUNC_*`
    # provider dispatch functions -- they are what a *caller* of `OSSL_ENCODER_CTX_set_construct`
    # supplies -- and the authority's names end `_CONSTRUCT`/`_CLEANUP` rather than `_fn`, so the
    # convention rule cannot reach them. Landed with the encoder method object (D360).
    "EncoderConstructFn": ("OSSL_ENCODER_CONSTRUCT",),
    "EncoderCleanupFn": ("OSSL_ENCODER_CLEANUP",),
    "DecoderConstructFn": ("OSSL_DECODER_CONSTRUCT",),
    "DecoderCleanupFn": ("OSSL_DECODER_CLEANUP",),
}

# ---------------------------------------------------------------------------------------------
# `NOT_A_DISPATCH` -- what each remaining alias is instead. Checked in both directions: an entry
# naming an alias the crate does not declare is a failure.
# ---------------------------------------------------------------------------------------------
NOT_A_DISPATCH: dict[str, str] = {
    # --- `OSSL_METHOD_CONSTRUCT_METHOD` (`include/internal/core.h`) -------------------------
    "AlgorithmFn": MCM,
    "AlgorithmPreFn": MCM,
    "AlgorithmPostFn": MCM,
    "AlgorithmReserveStoreFn": MCM,
    "AlgorithmUnreserveStoreFn": MCM,
    "McmConstructFn": MCM,
    "McmDestructFn": MCM,
    "McmGetFn": MCM,
    "McmPutFn": MCM,
    "McmGetTmpStoreFn": MCM,
    "McmLockStoreFn": MCM,
    "McmUnlockStoreFn": MCM,
    "MethodFromAlgorithmFn": MCM,
    # --- `EVP_CIPHER` / `EVP_MD` legacy callback lists (`evp.h`) -----------------------------
    "CipherDoAllFn": EVP_LEGACY,
    "MdDoAllFn": EVP_LEGACY,
    "CipherLegacyInitFn": EVP_LEGACY,
    "CipherLegacyDoFn": EVP_LEGACY,
    "CipherLegacyCleanupFn": EVP_LEGACY,
    "CipherLegacyAsn1Fn": EVP_LEGACY,
    "CipherLegacyCtrlFn": EVP_LEGACY,
    "MdLegacyInitFn": EVP_LEGACY,
    "MdLegacyUpdateFn": EVP_LEGACY,
    "MdLegacyFinalFn": EVP_LEGACY,
    "MdLegacyCopyFn": EVP_LEGACY,
    "MdLegacyCleanupFn": EVP_LEGACY,
    "MdLegacyCtrlFn": EVP_LEGACY,
    # --- `RSA_METHOD`'s vtable (`crypto/rsa/rsa_local.h:102-147`, Phase 8.4) -----------------
    "RsaCryptFn": RSA_METHOD_VTABLE,
    "RsaModExpFn": RSA_METHOD_VTABLE,
    "RsaBnModExpFn": RSA_METHOD_VTABLE,
    "RsaLifecycleFn": RSA_METHOD_VTABLE,
    "RsaSignFn": RSA_METHOD_VTABLE,
    "RsaVerifyFn": RSA_METHOD_VTABLE,
    "RsaKeygenFn": RSA_METHOD_VTABLE,
    "RsaMultiPrimeKeygenFn": RSA_METHOD_VTABLE,
    # --- `DH_METHOD`'s vtable (`crypto/dh/dh_local.h:47-64`, Phase 8.5) ---------------------
    "DhGenerateKeyFn": DH_METHOD_VTABLE,
    "DhComputeKeyFn": DH_METHOD_VTABLE,
    "DhBnModExpFn": DH_METHOD_VTABLE,
    "DhLifecycleFn": DH_METHOD_VTABLE,
    "DhGenerateParamsFn": DH_METHOD_VTABLE,
    # --- `DSA_METHOD`'s vtable (`crypto/dsa/dsa_local.h:46-70`, Phase 8.6) -------------------
    "DsaDoSignFn": DSA_METHOD_VTABLE,
    "DsaSignSetupFn": DSA_METHOD_VTABLE,
    "DsaDoVerifyFn": DSA_METHOD_VTABLE,
    "DsaModExpFn": DSA_METHOD_VTABLE,
    "DsaBnModExpFn": DSA_METHOD_VTABLE,
    "DsaLifecycleFn": DSA_METHOD_VTABLE,
    "DsaParamgenFn": DSA_METHOD_VTABLE,
    "DsaKeygenFn": DSA_METHOD_VTABLE,
    # --- `EC_METHOD`'s vtable (`crypto/ec/ec_local.h:43-200`, Phase 8.7) ---------------------
    "EcGroupInitFn": EC_METHOD_VTABLE,
    "EcGroupFinishFn": EC_METHOD_VTABLE,
    "EcGroupCopyFn": EC_METHOD_VTABLE,
    "EcGroupSetCurveFn": EC_METHOD_VTABLE,
    "EcGroupGetCurveFn": EC_METHOD_VTABLE,
    "EcGroupQueryFn": EC_METHOD_VTABLE,
    "EcGroupCheckDiscriminantFn": EC_METHOD_VTABLE,
    "EcGroupFullInitFn": EC_METHOD_VTABLE,
    "EcPointInitFn": EC_METHOD_VTABLE,
    "EcPointFinishFn": EC_METHOD_VTABLE,
    "EcPointCopyFn": EC_METHOD_VTABLE,
    "EcPointSetToInfinityFn": EC_METHOD_VTABLE,
    "EcPointSetAffineFn": EC_METHOD_VTABLE,
    "EcPointGetAffineFn": EC_METHOD_VTABLE,
    "EcPointSetCompressedFn": EC_METHOD_VTABLE,
    "EcPoint2OctFn": EC_METHOD_VTABLE,
    "EcOct2PointFn": EC_METHOD_VTABLE,
    "EcPointAddFn": EC_METHOD_VTABLE,
    "EcPointDblFn": EC_METHOD_VTABLE,
    "EcPointUnaryFn": EC_METHOD_VTABLE,
    "EcPointIsAtInfinityFn": EC_METHOD_VTABLE,
    "EcPointIsOnCurveFn": EC_METHOD_VTABLE,
    "EcPointCmpFn": EC_METHOD_VTABLE,
    "EcPointsMakeAffineFn": EC_METHOD_VTABLE,
    "EcPointMulFn": EC_METHOD_VTABLE,
    "EcPrecomputeMultFn": EC_METHOD_VTABLE,
    "EcFieldMulFn": EC_METHOD_VTABLE,
    "EcFieldSqrFn": EC_METHOD_VTABLE,
    # The one three-argument `EC_METHOD` column: `int (*field_set_to_one)(const EC_GROUP *,
    # BIGNUM *, BN_CTX *)` (`ec_local.h:165`). It is a separate crate alias from `EcFieldSqrFn`
    # because it takes no multiplicand, and the convention rule has no authority name to join on --
    # the header is internal and the atlas records no typedef for it (D333's rule).
    "EcFieldSetToOneFn": EC_METHOD_VTABLE,
    "EcPriv2OctFn": EC_METHOD_VTABLE,
    "EcOct2PrivFn": EC_METHOD_VTABLE,
    "EcComputeKeyFn": EC_METHOD_VTABLE,
    "EcKeyInitFn": EC_METHOD_VTABLE,
    "EcKeyCheckFn": EC_METHOD_VTABLE,
    "EcKeyCopyFn": EC_METHOD_VTABLE,
    "EcKeyFinishFn": EC_METHOD_VTABLE,
    "EcKeySignSetupFn": EC_METHOD_VTABLE,
    "EcKeySignSigFn": EC_METHOD_VTABLE,
    "EcKeyVerifySigFn": EC_METHOD_VTABLE,
    "EcLadderFn": EC_METHOD_VTABLE,
    # --- `EC_KEY_METHOD`'s table (`crypto/ec/ec_local.h:664-688`, Phase 8.7) ------------------
    "EcKeySetGroupFn": EC_KEY_METHOD_VTABLE,
    "EcKeySetPublicFn": EC_KEY_METHOD_VTABLE,
    "EcKeySignFn": EC_KEY_METHOD_VTABLE,
    "EcKeyVerifyFn": EC_KEY_METHOD_VTABLE,
    # `set_private` is the one member both tables declare with the same signature.
    "EcKeySetPrivateFn": EC_METHOD_VTABLE,
    # --- `struct ec_group_st`'s `field_mod_func` (`crypto/ec/ec_local.h:257-258`, Phase 8.7) --
    "EcFieldModFn": EC_GROUP_FIELD_MOD,
    # `curve_list[]`'s fourth-column type (`crypto/ec/ec_curve.c:2536`), the one alias this tranche
    # adds: a plain function pointer in the internal `_ec_list_element_st` rather than through
    # `OSSL_CORE_MAKE_FUNC`, so the convention rule has no authority name to join on.
    "EcMethodCtor": EC_CURVE_METHOD_COLUMN,
    # `ECDH_compute_key`'s inline `KDF` parameter type (`crypto/ec/ec_kmeth.c:148-151`), a plain
    # function pointer the authority spells in its own signature rather than through
    # `OSSL_CORE_MAKE_FUNC`, so the convention rule has no name to join on.
    "EcdhKdfFn": _inline("ECDH_compute_key",
                         "void *(*KDF)(const void *in, size_t inlen, void *out, size_t *outlen)"),
    # --- `struct prov_drbg_st`'s vtable (`prov/drbg.h:59-165`, Phase 9.4, D309) -------------
    "ProvDrbgInstantiateFn": DRBG_VTABLE,
    "ProvDrbgUninstantiateFn": DRBG_VTABLE,
    "ProvDrbgReseedFn": DRBG_VTABLE,
    "ProvDrbgGenerateFn": DRBG_VTABLE,
    "ProvDrbgNewFn": DRBG_VTABLE,
    "ProvDrbgFreeFn": DRBG_VTABLE,
    # --- `BIO_meth_set_*`'s inline parameter types (`bio.h`) ---------------------------------
    # The `_ex` two take `char *` where the *core dispatch* typedefs of the same shape take
    # `void *`, and `BIO_meth_set_ctrl` returns `long` where `OSSL_FUNC_BIO_ctrl_fn` returns
    # `int` -- three aliases whose squashed names reach the dispatch typedefs and whose declared
    # types are the `BIO_METHOD` vtable's, so the convention rule cannot tell them apart.
    "BioReadExFn": _inline("BIO_meth_set_read_ex", "int (*bread)(BIO *, char *, size_t, size_t *)"),
    "BioWriteExFn": _inline("BIO_meth_set_write_ex",
                            "int (*bwrite)(BIO *, const char *, size_t, size_t *)"),
    "BioCtrlFn": _inline("BIO_meth_set_ctrl", "long (*ctrl)(BIO *, int, long, void *)"),
    "BioReadFn": _inline("BIO_meth_set_read", "int (*read)(BIO *, char *, int)"),
    "BioWriteFn": _inline("BIO_meth_set_write", "int (*write)(BIO *, const char *, int)"),
    "BioCreateFn": _inline("BIO_meth_set_create", "int (*create)(BIO *)"),
    "BioDestroyFn": _inline("BIO_meth_set_destroy", "int (*destroy)(BIO *)"),
    "BioSendmmsgFn": _inline("BIO_meth_set_sendmmsg",
                             "int (*f)(BIO *, BIO_MSG *, size_t, size_t, uint64_t, size_t *)"),
    "BioCallbackCtrlFn": _inline("BIO_meth_set_callback_ctrl",
                                 "long (*callback_ctrl)(BIO *, int, BIO_info_cb *)"),
    # --- `UI_METHOD`'s vtable (`crypto/ui/ui_local.h:20-59`, Phase 13 staging, D350) ---------
    "UiOpenSessionFn": UI_METHOD_VTABLE,
    "UiWriteStringFn": UI_METHOD_VTABLE,
    "UiDuplicateDataFn": UI_METHOD_VTABLE,
    "UiDestroyDataFn": UI_METHOD_VTABLE,
    "UiConstructPromptFn": UI_METHOD_VTABLE,
    # --- other inline parameter types in the public headers -----------------------------------
    "DumpCb": _inline("BIO_dump_cb", "int (*cb)(const void *, size_t, void *)"),
    "ErrPrintCb": _inline("ERR_print_errors_cb", "int (*cb)(const char *, size_t, void *)"),
    # The callback parameter of `BN_BLINDING_create_param` (`include/openssl/bn.h:440-448`).
    # Like the two above it is a *public header* function pointer with no typedef, so there is
    # no authority name for the crate's `BnModExp` to link to -- and the convention rule cannot
    # reach it either, because the parameter is named `bn_mod_exp` where the crate's alias is
    # `BnModExp`. `BN_mod_exp_mont` has exactly this signature.
    "BnModExp@src/bn/blinding.rs": _inline(
        "BN_BLINDING_create_param",
        "int (*bn_mod_exp)(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m, "
        "BN_CTX *ctx, BN_MONT_CTX *m_ctx)"),
    "ObjNameHashFn": OBJ_INT,
    "ObjNameCmpFn": OBJ_INT,
    "ObjNameFreeFn": OBJ_INT,
    "ObjNameDoAllFn": _inline("OBJ_NAME_do_all", "void (*fn)(const OBJ_NAME *, void *arg)"),
    "CreateChildCbFn": _inline("OSSL_FUNC_provider_register_child_cb_fn",
                               "int (*create_cb)(const OSSL_CORE_HANDLE *, "
                               "const OSSL_DISPATCH *, void *)"),
    "RemoveChildCbFn": _inline("OSSL_FUNC_provider_register_child_cb_fn",
                               "void (*remove_cb)(const OSSL_CORE_HANDLE *, void *)"),
    "GlobalPropsCbFn": _inline("OSSL_FUNC_provider_register_child_cb_fn",
                               "int (*global_props_cb)(const void *, const OSSL_PARAM *)"),
    # --- macros, internal headers, and the crate's own shapes ---------------------------------
    "CompFunc": LHASH_MACRO,
    "CompThunk": LHASH_MACRO,
    "HashFunc": LHASH_MACRO,
    "HashThunk": LHASH_MACRO,
    "DoallFunc": LHASH_MACRO,
    "DoallThunk": LHASH_MACRO,
    "DoallArgFunc": LHASH_MACRO,
    "DoallArgThunk": LHASH_MACRO,
    "LhHash": LHASH_MACRO,
    "LhCmp": LHASH_MACRO,
    "CompFn": SK_MACRO,
    "CopyFn": SK_MACRO,
    "FreeThunk": SK_MACRO,
    "FreeFn@src/runtime/stack.rs": SK_MACRO,
    "SkCompFn": SK_MACRO,
    "SkCopyFn": SK_MACRO,
    "SkFreeFn": SK_MACRO,
    "AesWrapFn@src/provider/cipher.rs": WRAP_FN,
    "OsslXtsStreamFn": PROV_CIPHER_FUNC_TYPE,
    # The same macro-generated typedef one header over. `cipher_sm4_xts.h:14-17` invokes
    # `PROV_CIPHER_FUNC(void, xts_stream, ...)` with `SM4_KEY` parameters and a trailing `enc` where
    # `cipher_aes_xts.h`'s invocation of the same macro uses `AES_KEY` and no `enc`, so the two
    # produce one typedef *name* with two different types and cannot share a translation unit. The
    # crate therefore declares two Rust aliases; both are generated, so neither has a `typedef` for
    # the atlas to record.
    "OsslSm4XtsStreamFn": PROV_CIPHER_FUNC_TYPE,
    "TdesStreamFn": TDES_TSTREAM_FN,
    # `provider_util.h:140-143`'s `struct ag_capable_st` writes its predicate inline, as
    # `int (*capable)(void)`. The authority introduces no typedef for that type, so there is no
    # authority name for the crate's `AlgorithmCapability` to link to.
    "AlgorithmCapability": ("not a provider dispatch: the predicate field of "
                           "`OSSL_ALGORITHM_CAPABLE` (`provider_util.h:140-143`), spelled inline "
                           "as `int (*capable)(void)` rather than declared as a typedef"),
    "ConfInitFn@src/runtime/conf/types.rs": CONF_METHOD,
    "ConfFinishFn": ("not a provider dispatch: the crate's `conf_finish_func` equivalent for the "
                     "`CONF_METHOD` vtable; the authority declares the module finish callback "
                     "only as a local typedef in `conf.h`, which the atlas does not record"),
    "KeyFromPkcs8Fn": KEY_FROM_PKCS8_FN,
    # --- `decode_msblob2key.c`/`decode_pvk2key.c`'s `.c`-local `keytype_desc_st` callbacks (10.6) --
    "B2iOfVoidFn": KEYTYPE_DESC_CALLBACK,
    "B2iPvkOfBioPwFn": KEYTYPE_DESC_CALLBACK,
    "AdjustKeyFn": KEYTYPE_DESC_CALLBACK,
    "FreeKeyFn": KEYTYPE_DESC_CALLBACK,
    "CheckKeyFn": KEYTYPE_DESC_CALLBACK,
    "ConfCreateFn": CONF_INT,
    "ConfDestroyFn": CONF_INT,
    "ConfDestroyDataFn": CONF_INT,
    "ConfDumpFn": CONF_INT,
    "ConfLoadFn": CONF_INT,
    "ConfLoadBioFn": CONF_INT,
    # --- the thread layer's one alias (`include/internal/thread_arch.h`, D397) ----------------
    "CryptoThreadRoutine": THREAD_ARCH_INT,
    "ConfIsNumberFn": CONF_INT,
    "ConfToIntFn": CONF_INT,
    "DsoMergerFunc": DSO_INT,
    "DsoNameConverterFunc": DSO_INT,
    "RcuCbFn": ("not a provider dispatch: `include/internal/rcu.h`'s callback shape, in an "
                "internal header the atlas does not record"),
    "MethodDoAllFn": ("not a provider dispatch: the crate's own method-store traversal callback, "
                      "constructed from `OSSL_METHOD_CONSTRUCT_METHOD`; the authority has no "
                      "named type for it"),
    "MethodFreeFn": ("not a provider dispatch: the crate's own method-store free callback, "
                     "constructed from `OSSL_METHOD_CONSTRUCT_METHOD`; the authority has no "
                     "named type for it"),
    "MethodUpRefFn": ("not a provider dispatch: the crate's own method-store up-ref callback, "
                      "constructed from `OSSL_METHOD_CONSTRUCT_METHOD`; the authority has no "
                      "named type for it"),
    "ProviderDoAllFn": ("not a provider dispatch: the crate's own provider-table traversal "
                        "callback; the authority has no named type for it"),
    "GenericDoAllFn": ("not a provider dispatch: the crate's own do-all callback, constructed "
                       "from `OSSL_METHOD_CONSTRUCT_METHOD`; the authority has no named type "
                       "for it"),
    # --- `EVP_PKEY_METHOD`'s eighteen callback shapes (`include/crypto/evp.h`) -----------------
    "PkeyMethInitFn": PKEY_METHOD,
    "PkeyMethCleanupFn": PKEY_METHOD,
    "PkeyMethCopyFn": PKEY_METHOD,
    "PkeyMethParamgenFn": PKEY_METHOD,
    "PkeyMethSignFn": PKEY_METHOD,
    "PkeyMethCryptFn": PKEY_METHOD,
    "PkeyMethVerifyFn": PKEY_METHOD,
    "PkeyMethVerifyRecoverFn": PKEY_METHOD,
    "PkeyMethSignctxInitFn": PKEY_METHOD,
    "PkeyMethSignctxFn": PKEY_METHOD,
    "PkeyMethVerifyctxFn": PKEY_METHOD,
    "PkeyMethDeriveFn": PKEY_METHOD,
    "PkeyMethCtrlFn": PKEY_METHOD,
    "PkeyMethCtrlStrFn": PKEY_METHOD,
    "PkeyMethDigestsignFn": PKEY_METHOD,
    "PkeyMethDigestverifyFn": PKEY_METHOD,
    "PkeyMethCheckFn": PKEY_METHOD,
    "PkeyMethDigestCustomFn": PKEY_METHOD,
    # --- `pmeth_fn` (`crypto/evp/pmeth_lib.c:48`) --------------------------------------------
    "PmethFn": ("not a provider dispatch: `typedef const EVP_PKEY_METHOD *(*pmeth_fn)(void)` -- "
                 "the accessor a row of `crypto/evp/pmeth_lib.c`'s second `standard_methods[]` is. "
                 "It takes no arguments and *returns* the method object, so it is not a callback "
                 "signature the dispatch plane compares; D355 landed it with the table it "
                 "populates."),
    "FixupArgsFn": XLAT,
    "CleanupArgsFn": XLAT,
    "XlatGetNameFn": XLAT_GET,
    "XlatGetByNameFn": XLAT_GET,
    "Rfunc": CRATE_LOCAL,
    "CharIo": CRATE_LOCAL,
    "NistReduce": CRATE_LOCAL,
}


def squash(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def authority_key(typedef_name: str) -> str:
    name = typedef_name
    if name.startswith("OSSL_FUNC_"):
        name = name[len("OSSL_FUNC_"):]
    if name.endswith("_fn"):
        name = name[:-len("_fn")]
    return squash(name)


def rust_key(alias: str) -> str:
    for prefix in ("OSSLFunc", "OsslFunc"):
        if alias.startswith(prefix):
            alias = alias[len(prefix):]
            break
    if alias.endswith("Fn"):
        alias = alias[:-2]
    return squash(alias)


def as_fptr(canonical: str) -> str:
    """A C function *type*'s canonical form with the Rust function-item head tag.

    `canon_c_type` renders a C function type as `fn(ret; args)` and a C function *pointer* as
    `fptr(ret; args)`; `canon_rust_type` renders a Rust `unsafe extern "C" fn(...) -> T` item
    type as `fptr(ret; args)`. The two languages spell the same declarator two ways and the ABI
    is identical, so only the head tag is normalised.
    """
    return "fptr(" + canonical[len("fn("):] if canonical.startswith("fn(") else canonical


def load_authority(authority_id: str):
    atlas = REPO_ROOT / "forensics" / "atlas" / authority_id
    records = json.loads((atlas / "macros.json").read_text(encoding="utf-8"))["body"]["records"]
    identities: dict[str, int] = {}
    expressions: list[str] = []
    for rec in records:
        name = rec.get("name", "")
        if not name.startswith("OSSL_FUNC_") or rec.get("kind") != "object-like":
            continue
        value = (rec.get("value") or "").strip()
        if re.fullmatch(r"\d+", value):
            identities.setdefault(name, int(value))
        else:
            # A macro that expands to another macro or an expression is not an identity this
            # plane can compare, and it is reported as coverage rather than guessed.
            expressions.append(name)

    typedef_records = json.loads(
        (atlas / "typedefs.json").read_text(encoding="utf-8")
    )["body"]["records"]
    typedefs = {
        r["name"]: r["underlying_type"] for r in typedef_records if r.get("underlying_type")
    }
    fn_types: dict[str, str] = {}
    for name, underlying in typedefs.items():
        canonical = canon_c_type(underlying, typedefs)
        if canonical and (canonical.startswith("fn(") or canonical.startswith("fptr(")):
            fn_types[name] = underlying
    return identities, fn_types, typedefs, sorted(expressions)


def read_crate():
    """The crate's identity constants, its function-type aliases, and every type alias."""
    identities: dict[str, tuple[int, str]] = {}
    aliases: list[dict] = []
    scope_by_file: dict[str, dict[str, str]] = {}
    files: list[str] = []
    for path in sorted(SRC.rglob("*.rs")):
        try:
            raw = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        text = blank_comments(raw)
        file = rel(path)
        files.append(file)
        per_file: dict[str, str] = {}
        for m in RUST_ALIAS_RE.finditer(text):
            per_file.setdefault(m.group(1), alias_target(text, m.end()).strip())
        scope_by_file[file] = per_file
        for m in IDENTITY_RE.finditer(text):
            identities.setdefault(m.group(1), (int(m.group(2)), file))
        for m in FN_ALIAS_RE.finditer(text):
            lines = raw[: m.start()].splitlines()
            if raw[: m.start()].rsplit("\n", 1)[-1].strip() != "":
                # The declaration shares its line with `pub(crate)`, so the partial last line is
                # not a doc comment.
                lines = lines[:-1]
            doc: list[str] = []
            for line in reversed(lines):
                if line.strip().startswith("///"):
                    doc.append(line)
                    continue
                break
            aliases.append({"name": m.group(1), "rhs": m.group(2).strip(), "file": file,
                            "doc": "\n".join(reversed(doc))})

    # An alias is often declared in a file that sorts after its definition (`mod.rs` defines one
    # that `method.rs` uses), so a name defined in exactly one file is usable as a fallback,
    # exactly as `ABI-PROTOTYPE`'s reader does. A name defined in more than one file and not
    # present in the declaring file is deliberately left unresolved rather than guessed.
    seen: dict[str, int] = {}
    for per_file in scope_by_file.values():
        for name in per_file:
            seen[name] = seen.get(name, 0) + 1
    unique = {name: target for per_file in scope_by_file.values()
              for name, target in per_file.items() if seen[name] == 1}
    for alias in aliases:
        scope = dict(unique)
        scope.update(scope_by_file.get(alias["file"], {}))
        alias["scope"] = scope
    return identities, aliases, files


def resolve(alias: dict, by_key: dict[str, list[str]]) -> tuple[list[str], str, str | None]:
    """The targets, how the link was made, and the exemption reason if there is one."""
    both = (f"{alias['name']}@{alias['file']}", alias["name"])
    for key in both:
        if key in NOT_A_DISPATCH:
            return [], "exempt", NOT_A_DISPATCH[key]
    for key in both:
        if key in LINKS:
            return list(LINKS[key]), "explicit", None
    convention = by_key.get(rust_key(alias["name"]), [])
    if convention:
        return convention, "convention", None
    documented = sorted(set(DOC_FN_RE.findall(alias["doc"])))
    if documented:
        return documented, "documented", None
    return [], "unlinked", None


def compare(identities_auth, fn_types, typedefs, identities_rs, aliases_rs) -> dict:
    out: dict = {
        "identities": {"checked": [], "mismatches": [], "authority_only": []},
        "signatures": {"checked": [], "mismatches": [], "unmapped": [], "unlinked": [],
                       "not_a_dispatch": [], "authority_only": []},
        "links": {"explicit": 0, "documented": 0, "convention": 0},
        "problems": [],
    }

    # --- plane 1: the identity numbers -----------------------------------------------------
    for name in sorted(identities_rs):
        got, where = identities_rs[name]
        want = identities_auth.get(name)
        row = {"symbol": name, "crate": got, "crate_at": where, "authority": want}
        if want is None:
            out["problems"].append({
                "problem": "the crate declares a dispatch identity the authority does not define",
                **row,
            })
        elif want != got:
            out["identities"]["mismatches"].append(row)
        else:
            out["identities"]["checked"].append(row)
    out["identities"]["authority_only"] = sorted(set(identities_auth) - set(identities_rs))

    # --- plane 2: the callback signatures ---------------------------------------------------
    by_key: dict[str, list[str]] = {}
    for name in fn_types:
        by_key.setdefault(authority_key(name), []).append(name)

    claimed: set[str] = set()
    for alias in aliases_rs:
        name, file = alias["name"], alias["file"]
        targets, how, reason = resolve(alias, by_key)
        if how == "exempt":
            out["signatures"]["not_a_dispatch"].append(
                {"alias": name, "at": file, "why": reason})
            continue
        if how == "unlinked":
            out["signatures"]["unlinked"].append({"alias": name, "at": file})
            continue
        missing = [t for t in targets if t not in fn_types]
        if missing:
            out["problems"].append({
                "problem": "a link names an authority function-type typedef that does not exist",
                "alias": name, "at": file, "missing": missing, "how": how,
            })
            continue

        canon_of = {t: as_fptr(canon_c_type(fn_types[t], typedefs) or "") for t in targets}
        if len(set(canon_of.values())) > 1:
            out["problems"].append({
                "problem": "the link is ambiguous: the candidate authority typedefs do not agree "
                           "on one signature, so the Rust alias cannot be one of them",
                "alias": name, "at": file, "how": how, "candidates": canon_of,
            })
            continue

        out["links"][how] += 1
        got = canon_rust_type(alias["rhs"], alias["scope"])
        for target in targets:
            claimed.add(target)
            want = canon_of[target]
            row = {"alias": name, "authority": target, "at": file, "how": how,
                   "authority_signature": want, "crate_signature": got}
            if got is None or want == "fptr(":
                out["signatures"]["unmapped"].append({
                    **row, "why": "one side's function type did not canonicalise",
                })
            elif want != got:
                out["signatures"]["mismatches"].append(row)
            else:
                out["signatures"]["checked"].append(row)

    declared = {f"{a['name']}@{a['file']}" for a in aliases_rs} | {a["name"] for a in aliases_rs}
    for key in list(LINKS) + list(NOT_A_DISPATCH):
        if key not in declared:
            out["problems"].append({
                "problem": "a link or exemption names an alias the crate does not declare",
                "key": key,
            })

    out["signatures"]["authority_only"] = sorted(set(fn_types) - claimed)
    return out


def sensitivity_report(identities_auth, fn_types, typedefs, identities_rs, aliases_rs) -> dict:
    """Show that each plane can see the defect class it claims to cover.

    Every control asserts *both* halves: that the perturbed input is reported, and that the
    correct input is not. A control that only checked the first half would pass for a plane that
    reports everything.
    """
    report: dict = {"what": (
        "the same comparison functions, run over deliberately perturbed inputs, must notice; and "
        "over the correct inputs, must not"), "controls": []}
    good = compare(identities_auth, fn_types, typedefs, identities_rs, aliases_rs)

    # The identity plane: one declared constant moved by one.
    pick = next((n for n in sorted(identities_rs) if n in identities_auth), None)
    if pick is not None:
        bad = dict(identities_rs)
        bad[pick] = (identities_rs[pick][0] + 1, identities_rs[pick][1])
        b = compare(identities_auth, fn_types, typedefs, bad, aliases_rs)
        report["controls"].append({
            "control": "identity-number",
            "what": f"`{pick}` moved by one must be reported, the correct value must not",
            "detected": bool(not good["identities"]["mismatches"]
                             and len(b["identities"]["mismatches"]) == 1),
            "observed": {"symbol": pick, "authority": identities_auth.get(pick),
                         "correct": [r["crate"] for r in good["identities"]["checked"]
                                     if r["symbol"] == pick],
                         "perturbed": [r["crate"] for r in b["identities"]["mismatches"]
                                       if r["symbol"] == pick]},
        })

    # The signature plane: one checked alias given one extra parameter.
    row = next((r for r in good["signatures"]["checked"]), None)
    if row is not None:
        target = next(a for a in aliases_rs
                      if a["name"] == row["alias"] and a["file"] == row["at"])
        perturbed = target["rhs"].replace("fn(", "fn(*mut c_void, ", 1)
        assert perturbed != target["rhs"], "the perturbation did not apply"
        bad = [dict(a) for a in aliases_rs]
        for a in bad:
            if a["name"] == row["alias"] and a["file"] == row["at"]:
                a["rhs"] = perturbed
        b = compare(identities_auth, fn_types, typedefs, identities_rs, bad)
        report["controls"].append({
            "control": "callback-arity",
            "what": f"`{row['alias']}` given one extra parameter must be reported, the correct "
                    f"signature must not",
            "detected": bool(not good["signatures"]["mismatches"]
                             and any(r["alias"] == row["alias"]
                                     for r in b["signatures"]["mismatches"])),
            "observed": {"alias": row["alias"], "authority": row["authority"],
                         "correct": row["crate_signature"],
                         "perturbed": next((r["crate_signature"]
                                            for r in b["signatures"]["mismatches"]
                                            if r["alias"] == row["alias"]), None)},
        })

    # The link rule's own hole: an alias that no link resolves and no exemption covers must be
    # reported, which is what stops a typo'd name from silently having no counterpart.
    if row is not None:
        renamed = "Zz" + row["alias"]
        bad = []
        for a in aliases_rs:
            a = dict(a)
            if a["name"] == row["alias"] and a["file"] == row["at"]:
                a["name"] = renamed
                a["doc"] = ""
            bad.append(a)
        b = compare(identities_auth, fn_types, typedefs, identities_rs, bad)
        report["controls"].append({
            "control": "unlinked-typo",
            "what": f"`{row['alias']}` renamed so no link resolves it must be reported as "
                    f"unlinked rather than exempted by silence",
            "detected": bool(any(r["alias"] == renamed for r in b["signatures"]["unlinked"])),
            "observed": {"renamed": renamed,
                         "unlinked": [r["alias"] for r in b["signatures"]["unlinked"]
                                      if r["alias"] == renamed]},
        })

    report["all_detected"] = bool(report["controls"]) and all(
        c["detected"] for c in report["controls"])
    return report


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    ap.add_argument("--report", action="store_true")
    args = ap.parse_args(argv)

    auth = resolve_authority(args.authority)
    identities_auth, fn_types, typedefs, expressions = load_authority(auth.id)
    identities_rs, aliases_rs, files = read_crate()
    result = compare(identities_auth, fn_types, typedefs, identities_rs, aliases_rs)

    if args.report:
        print(f"authority identities               : {len(identities_auth)} "
              f"(+{len(expressions)} non-numeric)")
        print(f"crate identities                   : {len(identities_rs)}")
        print(f"authority function-type typedefs   : {len(fn_types)}")
        print(f"crate function-type aliases        : {len(aliases_rs)}")
        print(f"links by source                    : {result['links']}")
        print("\n--- unlinked and unexempted Rust aliases ---")
        for row in result["signatures"]["unlinked"]:
            print(f"  {row['alias']:<28} {row['at']}")
        print("\n--- problems ---")
        for row in result["problems"]:
            print(" ", json.dumps(row))
        print("\n--- mismatches ---")
        for row in result["signatures"]["mismatches"]:
            print(" ", json.dumps(row))
        print("\n--- unmapped ---")
        for row in result["signatures"]["unmapped"]:
            print(" ", json.dumps(row))
        print("\n--- identity mismatches ---")
        for row in result["identities"]["mismatches"]:
            print(" ", json.dumps(row))
        return 0

    counts = {
        "identities_checked": len(result["identities"]["checked"]),
        "identities_mismatches": len(result["identities"]["mismatches"]),
        "identities_authority_only": len(result["identities"]["authority_only"]),
        "signatures_checked": len(result["signatures"]["checked"]),
        "signatures_mismatches": len(result["signatures"]["mismatches"]),
        "signatures_unmapped": len(result["signatures"]["unmapped"]),
        "signatures_unlinked": len(result["signatures"]["unlinked"]),
        "signatures_not_a_dispatch": len(result["signatures"]["not_a_dispatch"]),
        "signatures_authority_only": len(result["signatures"]["authority_only"]),
        "links_explicit": result["links"]["explicit"],
        "links_documented": result["links"]["documented"],
        "links_convention": result["links"]["convention"],
        "problems": len(result["problems"]),
    }
    sensitivity = sensitivity_report(identities_auth, fn_types, typedefs, identities_rs,
                                     aliases_rs)
    body = {
        "what": (
            "every `OSSL_FUNC_*` dispatch identity the crate declares agrees with the "
            "authority's recorded macro value, and every Rust function-type alias the crate "
            "declares agrees with the canonical form of the authority function-type typedef it "
            "implements"
        ),
        "why": (
            "the dispatch contract is numbers and types rather than symbols, so no other "
            "instrument reaches it: the prototype court sees only exported declarations, the ABI "
            "courts resolve only symbols, and a runtime court sees a wrong identity or a wrong "
            "callback arity only if a probe happens to exercise exactly that entry "
            "(docs/DECISIONS.md D170 records two landed defects of this shape, and this plane's "
            "first run found the same class again -- see D180)"
        ),
        "canonical_form": (
            "the authority's typedef body and the crate's alias are both read by "
            "`ABI-PROTOTYPE`'s canonicaliser, so pointer depth, pointee constness, integer width "
            "and signedness and function-pointer shape are compared while a struct pointee's "
            "name is discarded; a C function *type* and a Rust `extern \"C\" fn` item type "
            "differ only in the canonical head tag and are compared after normalising it"
        ),
        "link_rule": (
            "an alias is resolved to its authority typedef by `NOT_A_DISPATCH` first, then "
            "`LINKS`, then the squashed name with an optional `OSSLFunc`/`OsslFunc` prefix and "
            "`Fn` suffix removed, then the `OSSL_FUNC_*_fn` names in its doc comment. An alias "
            "that none of them resolves must be exempted with a reason, so a typo cannot "
            "silently acquire no counterpart; the tables accept `Name@src/path.rs` for a name "
            "the crate declares twice with different types"
        ),
        "counts": counts,
        "authority_census": {
            "function_type_typedefs": len(fn_types),
            "identity_macros": len(identities_auth),
            "identity_macros_non_numeric": len(expressions),
            "crate_files_read": len(files),
        },
        "identities": result["identities"],
        "signatures": result["signatures"],
        "problems": result["problems"],
        "sensitivity": sensitivity,
        "note": (
            "`signatures_authority_only` is coverage, not a defect: the authority declares the "
            "dispatch contract for every stratum and the crate has reached seven of them, so an "
            "unclaimed typedef is work not yet done rather than a disagreement. What is a defect "
            "is a claim that disagrees, an alias that links to nothing and is not exempted, and "
            "a link or exemption that names something that does not exist."
        ),
    }

    inputs = [
        InputRef(name="authority-macros",
                 path=REPO_ROOT / "forensics" / "atlas" / auth.id / "macros.json"),
        InputRef(name="authority-typedefs",
                 path=REPO_ROOT / "forensics" / "atlas" / auth.id / "typedefs.json"),
    ]
    write_json(OUT, envelope(kind="dispatch-court", authority=auth.id, inputs=inputs,
                             body=body, generator=GENERATOR))

    print(f"[dispatch-court] authority={auth.id}")
    print(f"  identities: checked={counts['identities_checked']} "
          f"mismatches={counts['identities_mismatches']} "
          f"authority-only={counts['identities_authority_only']}")
    print(f"  signatures: checked={counts['signatures_checked']} "
          f"mismatches={counts['signatures_mismatches']} "
          f"unmapped={counts['signatures_unmapped']} unlinked={counts['signatures_unlinked']} "
          f"exempted={counts['signatures_not_a_dispatch']} "
          f"authority-only={counts['signatures_authority_only']}")
    print(f"  links: explicit={counts['links_explicit']} "
          f"documented={counts['links_documented']} convention={counts['links_convention']}")
    print(f"  problems={counts['problems']} "
          f"sensitivity_ok={sensitivity['all_detected']}")
    print(f"  -> {rel(OUT)}")

    return 1 if (counts["identities_mismatches"] or counts["signatures_mismatches"]
                 or counts["signatures_unmapped"] or counts["signatures_unlinked"]
                 or counts["problems"] or not sensitivity["all_detected"]) else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
