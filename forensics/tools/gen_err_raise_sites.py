#!/usr/bin/env python3
"""openssl-rs — generate the authority's `ERR_raise*` coordinates.

Why this exists
---------------
`ERR_raise(lib, reason)` is a macro:

    #define ERR_raise_data                                        \\
        (ERR_new(),                                               \\
            ERR_set_debug(OPENSSL_FILE, OPENSSL_LINE, OPENSSL_FUNC), \\
            ERR_set_error)

so every error the authority raises also records **where in the authority source
it was raised**: the translation unit, the line of the raise, and the enclosing
function. Those three strings are readable by any caller through
`ERR_get_error_all` / `ERR_peek_error_all`, and by `ERR_print_errors`. They are
therefore part of the observed contract, not private archaeology.

This tool derives them mechanically instead of transcribing them:

  * the `__FILE__` prefix is computed from the admitted build record
    (`relpath(source_tree, build_dir)`), because the authority was built
    out-of-tree and the compiler's `__FILE__` is the source path *as spelled on
    the command line*;
  * the line number is the line of the raise call in the pinned source;
  * the function name is the enclosing function, which is what `OPENSSL_FUNC`
    (`__func__`) expands to;
  * `lib` and `reason` are resolved by compiling a one-off C program against the
    authority's own headers, so the numbers are the authority's numbers and not
    a transcription of the header arithmetic.

Scope
-----
The file list below is the *subsystem set of the phase being closed*. Every
authority file that raises errors belongs in the obligation set; a phase adds
the files it implements. Sites in files not yet listed remain registered
obligations of a later phase, and `forensics/atlas/err-raise-sites.json`
records which files are covered so the uncovered remainder is visible rather
than implied.

Outputs
-------
  forensics/atlas/err-raise-sites.json   the machine-readable atlas document
  src/runtime/err_sites.rs               the Rust constants the runtime uses

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    PRODUCTION_AUTHORITY,
    REPO_ROOT,
    InputRef,
    authority_build_dir,
    envelope,
    rel,
    resolve_authority,
    run,
    write_json,
    write_text,
)

GENERATOR = "forensics/tools/gen_err_raise_sites.py"
OUT_JSON = REPO_ROOT / "forensics" / "atlas" / "err-raise-sites.json"
OUT_RS = REPO_ROOT / "src" / "runtime" / "err_sites.rs"

# The authority files whose raise sites this phase reconstructs. Each entry is
# (path relative to the authority source tree, Rust-style stem for the
# generated constant names).
COVERED_FILES = [
    ("crypto/stack/stack.c", "STACK"),
    ("crypto/ex_data.c", "EX_DATA"),
    ("crypto/init.c", "INIT"),
    # Phase 4: BIO, CONF and the object database. Every authority file in these
    # subsystems that raises an error belongs to the obligation set; the list is
    # the subsystem set of the phase, not a selection of convenient files.
    ("crypto/bio/bio_lib.c", "BIO_LIB"),
    ("crypto/bio/bio_meth.c", "BIO_METH"),
    ("crypto/bio/bio_addr.c", "BIO_ADDR"),
    ("crypto/bio/bio_cb.c", "BIO_CB"),
    ("crypto/bio/bio_dump.c", "BIO_DUMP"),
    ("crypto/bio/bio_print.c", "BIO_PRINT"),
    ("crypto/bio/bio_sock.c", "BIO_SOCK"),
    ("crypto/bio/bio_sock2.c", "BIO_SOCK2"),
    ("crypto/bio/bss_acpt.c", "BSS_ACPT"),
    ("crypto/bio/bss_bio.c", "BSS_BIO"),
    ("crypto/bio/bss_conn.c", "BSS_CONN"),
    ("crypto/bio/bss_core.c", "BSS_CORE"),
    ("crypto/bio/bss_dgram.c", "BSS_DGRAM"),
    ("crypto/bio/bss_dgram_pair.c", "BSS_DGRAM_PAIR"),
    ("crypto/bio/bss_fd.c", "BSS_FD"),
    ("crypto/bio/bss_file.c", "BSS_FILE"),
    ("crypto/bio/bss_log.c", "BSS_LOG"),
    ("crypto/bio/bss_mem.c", "BSS_MEM"),
    ("crypto/bio/bss_null.c", "BSS_NULL"),
    ("crypto/bio/bss_sock.c", "BSS_SOCK"),
    ("crypto/bio/bf_buff.c", "BF_BUFF"),
    ("crypto/bio/bf_lbuf.c", "BF_LBUF"),
    ("crypto/bio/bf_nbio.c", "BF_NBIO"),
    ("crypto/bio/bf_null.c", "BF_NULL"),
    ("crypto/bio/bf_prefix.c", "BF_PREFIX"),
    ("crypto/bio/bf_readbuff.c", "BF_READBUFF"),
    ("crypto/bio/ossl_core_bio.c", "OSSL_CORE_BIO"),
    ("crypto/conf/conf_api.c", "CONF_API"),
    ("crypto/conf/conf_def.c", "CONF_DEF"),
    ("crypto/conf/conf_lib.c", "CONF_LIB"),
    ("crypto/conf/conf_mod.c", "CONF_MOD"),
    ("crypto/conf/conf_sap.c", "CONF_SAP"),
    # Phase 6.10e: the `ssl_conf` configuration module's own translation unit. Its
    # three accessors are Phase 4's surface and its two module callbacks are Phase 6's
    # (the handler reads `CONF_imodule_get_value` and needs `CONF_module_add`), so the
    # file belongs here -- and leaving it out is why `ssl_module_init` had no
    # coordinates to raise from. See `docs/DECISIONS.md` D128.
    ("crypto/conf/conf_ssl.c", "CONF_SSL"),
    # The object database's one Phase 4 obligation (`OBJ_create_objects`) reads a
    # BIO, so its raise sites are part of this stratum.
    ("crypto/objects/obj_dat.c", "OBJ_DAT"),
    # `OBJ_create` parses its numeric-OID argument through `OBJ_txt2obj` and hence
    # `a2d_ASN1_OBJECT`, so a *malformed* OID raises an ASN.1 error from that file.
    # The coordinate is observable through a Phase 4 export even though the
    # surrounding ASN.1 parser is Phase 5, which is why this one file is covered
    # here rather than deferred with the rest of `crypto/asn1`.
    ("crypto/asn1/a_object.c", "A_OBJECT"),
    # The buffer object the memory BIO is built from is part of this stratum.
    ("crypto/buffer/buffer.c", "BUFFER"),
    # `crypto/o_str.c`'s string and hex codecs. The module was in *no* phase's
    # symbol family until it was found by the ownership audit
    # (`forensics/tools/ownership_audit.py`): its eleven exports matched no
    # prefix any ledger listed, so they were invisible to every obligation
    # table. CONF's reader needs three of them (`OPENSSL_strlcpy`,
    # `OPENSSL_strlcat`, `OPENSSL_strcasecmp`), which is how the gap surfaced;
    # see docs/DECISIONS.md D51.
    ("crypto/o_str.c", "O_STR"),
    # Phase 5: the `crypto/bn` stratum. Every authority file in this subsystem that
    # raises an error belongs to the obligation set — the list is the subsystem set
    # of the phase, not a selection of convenient files. Functions this phase
    # deliberately hands to a later stratum (the `BN_rand*` family, which needs the
    # RAND stratum) still contribute their file's coordinates, because the phase
    # owns the *surface* the coordinates belong to; what is deferred is the
    # implementation, and `phase5-obligations.json` records that separately.
    ("crypto/bn/bn_add.c", "BN_ADD"),
    ("crypto/bn/bn_blind.c", "BN_BLIND"),
    ("crypto/bn/bn_conv.c", "BN_CONV"),
    ("crypto/bn/bn_ctx.c", "BN_CTX"),
    ("crypto/bn/bn_div.c", "BN_DIV"),
    ("crypto/bn/bn_exp.c", "BN_EXP"),
    ("crypto/bn/bn_exp2.c", "BN_EXP2"),
    ("crypto/bn/bn_gcd.c", "BN_GCD"),
    ("crypto/bn/bn_gf2m.c", "BN_GF2M"),
    ("crypto/bn/bn_intern.c", "BN_INTERN"),
    ("crypto/bn/bn_lib.c", "BN_LIB"),
    ("crypto/bn/bn_mod.c", "BN_MOD"),
    ("crypto/bn/bn_mpi.c", "BN_MPI"),
    ("crypto/bn/bn_prime.c", "BN_PRIME"),
    ("crypto/bn/bn_rand.c", "BN_RAND"),
    ("crypto/bn/bn_recp.c", "BN_RECP"),
    ("crypto/bn/bn_rsa_fips186_4.c", "BN_RSA_FIPS186_4"),
    ("crypto/bn/bn_shift.c", "BN_SHIFT"),
    ("crypto/bn/bn_sqrt.c", "BN_SQRT"),
    # Phase 5: the `crypto/asn1` substrate. The same rule as `crypto/bn` applies —
    # every authority file in the subsystem that raises an error belongs to the
    # obligation set, because the stratum owns the *surface* those coordinates
    # belong to. The files that implement another stratum's surface are excluded
    # and are listed at the end of this block with the phase that owns them, so
    # the exclusion is visible rather than implied. (`a_object.c` is already
    # covered: Phase 4's `OBJ_create` reaches it through `a2d_ASN1_OBJECT`.)
    ("crypto/asn1/a_bitstr.c", "A_BITSTR"),
    ("crypto/asn1/a_d2i_fp.c", "A_D2I_FP"),
    ("crypto/asn1/a_dup.c", "A_DUP"),
    ("crypto/asn1/a_gentm.c", "A_GENTM"),
    ("crypto/asn1/a_i2d_fp.c", "A_I2D_FP"),
    ("crypto/asn1/a_int.c", "A_INT"),
    ("crypto/asn1/a_mbstr.c", "A_MBSTR"),
    ("crypto/asn1/a_octet.c", "A_OCTET"),
    ("crypto/asn1/a_print.c", "A_PRINT"),
    ("crypto/asn1/a_strnid.c", "A_STRNID"),
    ("crypto/asn1/a_strex.c", "A_STREX"),
    ("crypto/asn1/a_time.c", "A_TIME"),
    ("crypto/asn1/a_type.c", "A_TYPE"),
    ("crypto/asn1/a_utf8.c", "A_UTF8"),
    ("crypto/asn1/a_utctm.c", "A_UTCTM"),
    ("crypto/asn1/asn1_gen.c", "ASN1_GEN"),
    ("crypto/asn1/asn1_item_list.c", "ASN1_ITEM_LIST"),
    ("crypto/asn1/asn1_lib.c", "ASN1_LIB"),
    ("crypto/asn1/asn1_parse.c", "ASN1_PARSE"),
    ("crypto/asn1/asn_moid.c", "ASN_MOID"),
    ("crypto/asn1/asn_mstbl.c", "ASN_MSTBL"),
    ("crypto/asn1/asn_pack.c", "ASN_PACK"),
    ("crypto/asn1/bio_asn1.c", "BIO_ASN1"),
    ("crypto/asn1/bio_ndef.c", "BIO_NDEF"),
    # Covered although most of its *symbols* belong to later strata. The exclusion
    # rule is per-symbol and by declaring header, so a translation unit is not the
    # unit of classification: `evp_asn1.c` declares `ASN1_TYPE_set_octetstring`,
    # `ASN1_TYPE_get_octetstring`, `ASN1_TYPE_set_int_octetstring` and
    # `ASN1_TYPE_get_int_octetstring` in `asn1.h` — Phase 5's header — and each of
    # them raises `ASN1_R_DATA_IS_WRONG` from this file. Leaving the TU out because
    # the rest of it is Phase 7's surface lost a coordinate that Phase 5 needs, which
    # is the same file-versus-symbol error D49 recorded for `a2d_ASN1_OBJECT`.
    ("crypto/asn1/evp_asn1.c", "EVP_ASN1"),
    ("crypto/asn1/f_int.c", "F_INT"),
    ("crypto/asn1/f_string.c", "F_STRING"),
    ("crypto/asn1/tasn_dec.c", "TASN_DEC"),
    ("crypto/asn1/tasn_enc.c", "TASN_ENC"),
    ("crypto/asn1/tasn_new.c", "TASN_NEW"),
    ("crypto/asn1/tasn_utl.c", "TASN_UTL"),
    ("crypto/asn1/x_int64.c", "X_INT64"),
    ("crypto/asn1/x_long.c", "X_LONG"),
    # `ASN1_item_print` is Phase 5's, but its integer leaf calls
    # `i2s_ASN1_INTEGER`, whose definition and two `ERR_raise` sites are in this
    # Phase 11 translation unit. The coordinates are observable through a Phase 5
    # export, so this file is covered here rather than deferred with the rest of
    # `crypto/x509` — the same per-symbol-not-per-file reasoning as `a_object.c`
    # above and D49.
    ("crypto/x509/v3_utl.c", "V3_UTL"),
    # `SMIME_crlf_copy` and `i2d_ASN1_bio_stream` are Phase 5's, and
    # `SMIME_crlf_copy`'s two refusals come from this file. The rest of the
    # translation unit is the MIME reader and writer, which is Phase 12's; the file
    # is covered for the coordinates a Phase 5 export can raise, exactly as
    # `a_object.c` is covered by Phase 4 for `a2d_ASN1_OBJECT` (D49).
    ("crypto/asn1/asn_mime.c", "ASN_MIME"),
    # Deliberately *not* covered, with the stratum that owns each: `a_digest.c`,
    # `ameth_lib.c` (Phase 7); `d2i_param.c`, `d2i_pr.c`, `d2i_pu.c`, `i2d_evp.c`,
    # `n_pkey.c`, `p5_pbe.c`, `p5_pbev2.c` (Phase 10 or 11 as their exports say); `a_sign.c`,
    # `a_verify.c`, `x_pkey.c` (Phase 11); the rest of `asn_mime.c`
    # (Phase 12; the file is covered above for the two coordinates a Phase 5 export
    # raises);
    # `nsseq.c` (Phase 13). Their raises are visible as uncovered sites in
    # `forensics/atlas/err-raise-sites.json` until those phases land.
    #
    # `x_algor.c` was on this list ("Phase 11") and is not any more: D348 transcribes
    # `crypto/asn1/x_algor.c` whole as `src/asn1/x_algor.rs`, so its one raise --
    # `ossl_x509_algor_get_md`'s `ASN1_R_UNKNOWN_DIGEST` at `:165` -- is a coordinate a
    # crate module can reach and is covered below.
    #
    # `p5_scrypt.c` was on this list and is not any more: 7.4c lands
    # `PKCS5_v2_scrypt_keyivgen`/`_ex`, which are that file's and Phase 7's by its
    # `evp.h` declarations, and they raise the five `EVP_R_*` reasons at lines 252,
    # 261, 267, 278 and 289. The file is therefore covered for the coordinates a
    # Phase 7 export raises, which also brings in the nineteen `ERR_LIB_ASN1` sites of
    # `PKCS5_pbe2_set_scrypt` (Phase 11's export, same unit) — the same
    # per-file-not-per-symbol reasoning `asn_mime.c` and `v3_utl.c` already use above.
    #
    # `evp_asn1.c` was on this list and is not any more: see the comment where it is
    # covered. Two names that were on it are also worth correcting because they were
    # never excluded — `x_long.c` is covered above, and `n_pkey.c` does not exist in
    # the authority. A list of exclusions is a claim about the tree, and this one had
    # two false entries and one wrong reason.
    #
    # Phase 6: the parameter surface and the provider core it belongs to. Every
    # authority file in the subsystem that raises an error belongs to the obligation
    # set, by the same rule as `crypto/bn` and `crypto/asn1` above.
    #
    # `crypto/params.c` is also the file that forced `local_raise_macros` into this
    # generator. It spells its eight refusals as file-local macros (`err_out_of_range`
    # and friends) and then invokes them bare, so a scan for `ERR_raise*` found the
    # eight definitions and none of the fifty-odd call sites. The coordinates a caller
    # reads back are the *invocation* line, so the definitions are not merely
    # redundant — they are the wrong answer, and attributing them was impossible
    # anyway (`enclosing_function` refuses a line with no preceding definition).
    ("crypto/params.c", "PARAMS"),
    ("crypto/params_dup.c", "PARAMS_DUP"),
    ("crypto/params_from_text.c", "PARAMS_FROM_TEXT"),
    ("crypto/param_build.c", "PARAM_BUILD"),
    # Phase 6.6b: the name map. Five raise sites, and one of them is the first in this
    # table whose reason is chosen at run time — `core_namemap.c:288` raises
    # `(ret < 0) ? CRYPTO_R_TOO_MANY_NAMES : ERR_R_INTERNAL_ERROR`, so the generator
    # records it with `dynamic_reason` and the caller supplies which of the two it is.
    # `crypto/context.c`, `crypto/core_algorithm.c`, `crypto/thread/internal.c` and
    # `crypto/threads_common.c` are the rest of this stratum's files and raise nothing,
    # so they are absent rather than listed with an empty contribution.
    ("crypto/core_namemap.c", "CORE_NAMEMAP"),
    # Phase 6.7: the property engine. Two of its six files raise anything —
    # `property.c`, `property_query.c`, `defn_cache.c` and `property_err.c` raise
    # nothing. `property_string.c` is 6.7a's; `property_parse.c`'s grammar is 6.7b's,
    # and its coordinates are taken with the file because the rule is the *subsystem*
    # set rather than the implemented subset, exactly as Phase 4 and Phase 5 took
    # their own. A site nobody calls yet is a coordinate, not a claim.
    ("crypto/property/property_string.c", "PROPERTY_STRING"),
    ("crypto/property/property_parse.c", "PROPERTY_PARSE"),
    # Phase 6.9: DSO. Two of its files raise; `dso_err.c` is the string table,
    # `dso_openssl.c` is the null method of a different configuration, and
    # `dso_dl.c` is a method this profile does not build.
    ("crypto/dso/dso_lib.c", "DSO_LIB"),
    ("crypto/dso/dso_dlfcn.c", "DSO_DLFCN"),
    # Phase 6.8: the provider registry. Registered now, with 6.8a, rather than in the
    # subphase that first raises from each file, for 6.7's reason: the rule is the
    # *subsystem* set and a site nobody calls yet is a coordinate, not a claim. All
    # three files that raise use `ERR_LIB_CRYPTO` with `ERR_R_*` reasons -- there is no
    # `PROV_R_*` family in this subsystem, so `cryptoerr.h` already covers every one and
    # no internal header has to be added.
    #
    # `provider_child.c`, `provider_predefined.c` and `core_algorithm.c` raise nothing,
    # so they are deliberately **not** listed: a covered file with no sites would be an
    # entry that can never change and would read as coverage that does not exist.
    ("crypto/provider.c", "PROVIDER"),
    ("crypto/provider_core.c", "PROVIDER_CORE"),
    ("crypto/provider_conf.c", "PROVIDER_CONF"),
    # The file 7.1 transcribes first, and the only one of this stratum's that is not under a
    # directory the block below names: `crypto/core_fetch.c` is `ossl_method_construct`'s
    # translation unit, it is one of the two deferrals Phase 6 handed forward (D132, D134),
    # and its two `ossl_assert`-guarded `ERR_raise` sites are the coordinates a caller sees
    # when a NULL `result` reaches the walk's pre- or postcondition. `crypto/core_algorithm.c`
    # is its sibling, raises nothing, and is therefore absent.
    ("crypto/core_fetch.c", "CORE_FETCH"),
    # Phase 7: the EVP framework, and the *subsystem* set rather than the subphase that
    # first raises from each file -- 6.8a's rule, stated there as "a site nobody calls yet
    # is a coordinate, not a claim". Three parts, in the order they were derived:
    #
    #   * `crypto/evp/` is the directory whose exports `evp.h` declares, and forty-nine of
    #     its eighty-four translation units raise something in this profile;
    #   * `crypto/hpke/hpke.c` is 7.6's, and is *not* in `crypto/evp/` even though its
    #     surface is `hpke.h`'s -- the atlas gives it to this stratum by header, which is
    #     the rule D72 established and the reason this block is not a directory listing;
    #   * the eight remaining files are the per-symbol exceptions the plan's own 7.4 and
    #     7.5 rows name. `crypto/asn1/ameth_lib.c` was already excluded from Phase 5's block
    #     above **with this phase named**; `i2d_evp.c`, `d2i_pr.c`, `d2i_param.c` and
    #     `d2i_pu.c` are the same shape and had no earlier block to be excluded from;
    #     `pem_pkey.c` and `pem_pk8.c` are where the twenty-three `pem.h` hand-offs Phase 5
    #     recorded actually land. All of the eight declare their exports in `evp.h` or
    #     `pem.h` and therefore belong to this stratum and not to the stratum whose
    #     directory they sit in.
    #
    # **Thirty-seven of the eighty-four raise nothing and are deliberately absent**: the BIO
    # and encoding bridges (`bio_enc.c`, `bio_md.c`, `bio_ok.c`, `encode.c`), the twelve
    # `legacy_*` wrappers and the legacy cipher wrappers whose primitives are Phase 13's
    # (`e_des.c`, `e_rc4.c`, `e_bf.c`, `e_cast.c`, `e_idea.c`, `e_seed.c`, `e_sm4.c`,
    # `e_null.c`, `e_xcbc_d.c`, `e_old.c`, `m_null.c`), the four name/type helpers
    # (`names.c`, `evp_key.c`, `evp_pkey_type.c`, `ec_support.c`, `dh_support.c`), the two
    # algorithm tables (`c_allc.c`, `c_alld.c`), the method-object accessor `cmeth_lib.c`,
    # and `evp_err.c`. That last one is worth naming: it is the error *string* table for the
    # whole library and it raises nothing at all, which is exactly the shape of entry this
    # list is supposed to avoid -- it can never change and would read as coverage that does
    # not exist. The same note applies to `crypto/hmac/hmac.c` and `crypto/cmac/cmac.c`:
    # they look like they must raise and they do not, because both are façades over
    # `EVP_MAC` and every refusal a caller sees comes from the provider's implementation.
    #
    # **Seven sites pass a reason constant where the library argument belongs** --
    # `exchange.c` at 572, 601, 607 and 619, `kdf_lib.c` at 241 and `mac_lib.c` at 119 and
    # 130 all spell `ERR_raise(ERR_R_EVP_LIB, ...)`. It is the authority's own shape and it
    # is kept: what a caller reads back through `ERR_get_error_all` is the number that
    # argument evaluates to, so "correcting" it would be a divergence rather than a fix.
    ("crypto/evp/asymcipher.c", "ASYMCIPHER"),
    ("crypto/evp/bio_b64.c", "BIO_B64"),
    ("crypto/evp/ctrl_params_translate.c", "CTRL_PARAMS_TRANSLATE"),
    ("crypto/evp/dh_ctrl.c", "DH_CTRL"),
    ("crypto/evp/digest.c", "DIGEST"),
    ("crypto/evp/dsa_ctrl.c", "DSA_CTRL"),
    ("crypto/evp/e_aes.c", "E_AES"),
    ("crypto/evp/e_aes_cbc_hmac_sha1.c", "E_AES_CBC_HMAC_SHA1"),
    ("crypto/evp/e_aria.c", "E_ARIA"),
    ("crypto/evp/e_camellia.c", "E_CAMELLIA"),
    ("crypto/evp/e_chacha20_poly1305.c", "E_CHACHA20_POLY1305"),
    ("crypto/evp/e_des3.c", "E_DES3"),
    ("crypto/evp/e_rc2.c", "E_RC2"),
    ("crypto/evp/e_rc5.c", "E_RC5"),
    ("crypto/evp/ec_ctrl.c", "EC_CTRL"),
    ("crypto/evp/evp_cnf.c", "EVP_CNF"),
    ("crypto/evp/evp_enc.c", "EVP_ENC"),
    ("crypto/evp/evp_fetch.c", "EVP_FETCH"),
    ("crypto/evp/evp_lib.c", "EVP_LIB"),
    ("crypto/evp/evp_pbe.c", "EVP_PBE"),
    ("crypto/evp/evp_pkey.c", "EVP_PKEY"),
    ("crypto/evp/evp_rand.c", "EVP_RAND"),
    ("crypto/evp/evp_utils.c", "EVP_UTILS"),
    ("crypto/evp/exchange.c", "EXCHANGE"),
    ("crypto/evp/kdf_lib.c", "KDF_LIB"),
    ("crypto/evp/kdf_meth.c", "KDF_METH"),
    ("crypto/evp/kem.c", "KEM"),
    ("crypto/evp/keymgmt_lib.c", "KEYMGMT_LIB"),
    ("crypto/evp/keymgmt_meth.c", "KEYMGMT_METH"),
    ("crypto/evp/m_sigver.c", "M_SIGVER"),
    ("crypto/evp/mac_lib.c", "MAC_LIB"),
    ("crypto/evp/mac_meth.c", "MAC_METH"),
    ("crypto/evp/p5_crpt.c", "P5_CRPT"),
    ("crypto/evp/p5_crpt2.c", "P5_CRPT2"),
    ("crypto/evp/p_dec.c", "P_DEC"),
    ("crypto/evp/p_enc.c", "P_ENC"),
    ("crypto/evp/p_legacy.c", "P_LEGACY"),
    ("crypto/evp/p_lib.c", "P_LIB"),
    ("crypto/evp/p_open.c", "P_OPEN"),
    ("crypto/evp/p_seal.c", "P_SEAL"),
    ("crypto/evp/p_sign.c", "P_SIGN"),
    ("crypto/evp/p_verify.c", "P_VERIFY"),
    ("crypto/evp/pbe_scrypt.c", "PBE_SCRYPT"),
    ("crypto/evp/pmeth_check.c", "PMETH_CHECK"),
    ("crypto/evp/pmeth_gn.c", "PMETH_GN"),
    ("crypto/evp/pmeth_lib.c", "PMETH_LIB"),
    ("crypto/evp/s_lib.c", "S_LIB"),
    ("crypto/evp/signature.c", "SIGNATURE"),
    ("crypto/evp/skeymgmt_meth.c", "SKEYMGMT_METH"),
    ("crypto/hpke/hpke.c", "HPKE"),
    ("crypto/hpke/hpke_util.c", "HPKE_UTIL"),
    ("crypto/asn1/ameth_lib.c", "AMETH_LIB"),
    ("crypto/asn1/p5_scrypt.c", "P5_SCRYPT"),
    ("crypto/asn1/i2d_evp.c", "I2D_EVP"),
    ("crypto/asn1/d2i_pr.c", "D2I_PR"),
    ("crypto/asn1/d2i_param.c", "D2I_PARAM"),
    ("crypto/asn1/d2i_pu.c", "D2I_PU"),
    ("crypto/pem/pem_lib.c", "PEM_LIB"),
    ("crypto/pem/pem_oth.c", "PEM_OTH"),
    ("crypto/pem/pem_pkey.c", "PEM_PKEY"),
    ("crypto/pem/pem_pk8.c", "PEM_PK8"),
    # Phase 8: the providers' own translation units. Until this block existed the
    # `PROV_R_*` family had exactly one covered file (`crypto/hpke/hpke_util.c`, added
    # by 7.6 for the shared helpers), so the provider half of the cipher and digest
    # surface had no coordinates at all -- while the authority raises from every
    # failure arm the crate transcribes. `src/provider/cipher.rs` therefore returned 0
    # where the authority *also* queued a specific error, which `RT-CIPHER` could not
    # see because it did not drain the queue. The rule is Phase 4/5/6's: the list is
    # the *subsystem* set of the stratum, not a selection of convenient files, and a
    # site nobody calls yet is a coordinate rather than a claim.
    #
    # Two of the four files here are build-generated (`.c.in`) and are resolved from
    # the build tree by `resolve_site_source`; the generated text is what the compiler
    # saw, and its `__FILE__` carries no source-tree prefix. The other two spellings
    # are the source tree's and its prefix is the usual `relpath` one. The difference
    # is measured, not assumed: `ciphercommon.c`'s records read
    # `providers/implementations/ciphers/ciphercommon.c` while
    # `ciphercommon_block.c`'s read `../../src/openssl-3.6.4/.../ciphercommon_block.c`.
    ("providers/implementations/ciphers/ciphercommon.c", "PROV_CIPHERCOMMON"),
    ("providers/implementations/ciphers/ciphercommon_block.c", "PROV_CIPHERCOMMON_BLOCK"),
    ("providers/implementations/ciphers/cipher_aes_hw.c", "PROV_CIPHER_AES_HW"),
    ("providers/implementations/ciphers/cipher_camellia_hw.c", "PROV_CIPHER_CAMELLIA_HW"),
    ("providers/implementations/ciphers/cipher_tdes_common.c", "PROV_CIPHER_TDES_COMMON"),
    ("providers/implementations/ciphers/cipher_null.c", "PROV_CIPHER_NULL"),
    ("providers/implementations/ciphers/cipher_aes_ocb.c", "PROV_CIPHER_AES_OCB"),
    ("providers/implementations/ciphers/cipher_aes_wrp.c", "PROV_CIPHER_AES_WRP"),
    ("providers/implementations/ciphers/cipher_aes_xts.c", "PROV_CIPHER_AES_XTS"),
    ("providers/implementations/ciphers/ciphercommon_ccm.c", "PROV_CIPHERCOMMON_CCM"),
    ("providers/implementations/ciphers/cipher_aes_siv.c", "PROV_CIPHER_AES_SIV"),
    # `cipher_chacha20.c` is a **source-tree** file rather than a `.c.in` template, so its `__FILE__`
    # carries the source-tree prefix and its seven raises are its own: three
    # `PROV_R_FAILED_TO_SET_PARAMETER` in the getter (one per key it publishes) and four in the setter
    # -- two `PROV_R_FAILED_TO_GET_PARAMETER` for the two length keys and one reason each for the
    # length checks they guard. The row's sibling `cipher_chacha20_hw.c` raises nothing at all, so it
    # is absent for the reason `cipher_cts.c` is: an entry that can never change would read as
    # coverage that does not exist.
    ("providers/implementations/ciphers/cipher_chacha20.c", "PROV_CIPHER_CHACHA20"),
    # `cipher_chacha20_poly1305.c` is the *other* kind of generated unit: it is a `.c.in` template
    # (`cipher_chacha20_poly1305.c.in`), so the build compiles it from the build tree and its
    # `__FILE__` carries **no** source-tree prefix -- `providers/implementations/ciphers/
    # cipher_chacha20_poly1305.c` where its source-tree sibling `cipher_chacha20.c` directly above
    # carries `../../src/openssl-3.6.4/`. Both spellings are measured from the two objects and
    # confirmed end to end by `courts/layout/oracle-mem-file.c`, which prints the `file` the
    # authority hands a caller-installed allocator for each row.
    #
    # Its raises are its own, and there are **twenty-nine**: five `PROV_R_REPEATED_PARAMETER` in
    # the getter's generated decoder (`:142`, `:153`, `:176`, `:185`, `:197` -- one per key it
    # locates) and five in the setter's (`:305`, `:316`, `:331`, `:350`, `:361`); seven in
    # `chacha20_poly1305_get_ctx_params`' body (`:221`, `:227`, `:233`, `:239` for the four
    # `PROV_R_FAILED_TO_SET_PARAMETER` writes, then `:245` type, `:249` `PROV_R_TAG_NOT_SET` on a
    # decrypting context and `:253` `PROV_R_INVALID_TAG_LENGTH`); eleven in
    # `chacha20_poly1305_set_ctx_params`' body (`:396`, `:407`, `:418`, `:437`, `:450` for the five
    # `PROV_R_FAILED_TO_GET_PARAMETER`s, `:400` and `:411` for the two length refusals, `:422`
    # `PROV_R_INVALID_TAG_LENGTH`, `:427` `PROV_R_TAG_NOT_NEEDED`, `:442` `PROV_R_INVALID_DATA` and
    # `:456` `PROV_R_INVALID_IV_LENGTH`); and the one `PROV_R_OUTPUT_BUFFER_TOO_SMALL` in
    # `chacha20_poly1305_cipher` (`:512`). The sibling `cipher_chacha20_poly1305_hw.c` raises
    # **nothing** -- it returns 0 -- so it is absent for the reason `cipher_chacha20_hw.c` is.
    ("providers/implementations/ciphers/cipher_chacha20_poly1305.c", "PROV_CIPHER_CHACHA20_POLY1305"),
    # `cipher_aria_hw.c` is a **source-tree** file, and unlike `cipher_sm4.c` and `cipher_sm4_hw.c`
    # it *does* have a failure arm: `cipher_hw_aria_initkey` raises `PROV_R_KEY_SETUP_FAILED` at
    # line 25 when the schedule function answers negative. The note this entry replaces said
    # `cipher_aria*.c` raised nothing, which was true of the primitive and false of the row's hw --
    # and it was the ARIA rows landing that made the difference visible (D270). `cipher_aria.c`
    # itself still raises nothing and is absent for `cipher_chacha20_hw.c`'s reason.
    ("providers/implementations/ciphers/cipher_aria_hw.c", "PROV_CIPHER_ARIA_HW"),
    # `cipher_sm4_xts.c` is a source-tree file with six raises, one per failure arm the row has that
    # the shared engine does not own: the key-length check in `sm4_xts_init` (`:54`), the 2^20-block
    # data-unit limit (`:142`), the output-size check (`:171`) and the cipher failure (`:176`) in
    # `sm4_xts_stream_update`, and the two `xts_standard` arms of `sm4_xts_set_ctx_params` (`:227`,
    # `:235`). Its `cipher_sm4_xts_hw.c` raises nothing, like `cipher_sm4_hw.c`.
    ("providers/implementations/ciphers/cipher_sm4_xts.c", "PROV_CIPHER_SM4_XTS"),
    # The AES-CBC-HMAC-SHA row layer. It is a **source-tree** file, so its `__FILE__` carries the
    # `../../src/openssl-3.6.4/` prefix, and its raises are its own: three
    # `PROV_R_FAILED_TO_GET_PARAMETER` in the setter (the AEAD mac key, the multiblock AAD pair and
    # the multiblock ENC trio, plus the two length keys), one `PROV_R_INVALID_KEY_LENGTH` for the
    # `keylen` check, and one `ERR_R_INTERNAL_ERROR` for the TLS-version/`removetlsfixed` assertion.
    # Its HW siblings (`cipher_aes_cbc_hmac_sha1_hw.c`, `cipher_aes_cbc_hmac_sha256_hw.c`) raise
    # **nothing** in this profile -- they return 0 -- so they are absent for the reason
    # `cipher_chacha20_hw.c` is. The nine `*_etm_*` units are absent for a stronger reason: on this
    # profile `AES_CBC_HMAC_SHA_ETM_CAPABLE` is undefined (`aes_platform.h:114-121` is aarch64-only),
    # so both their row layer and their hw files compile the stub branch and raise nothing.
    ("providers/implementations/ciphers/cipher_aes_cbc_hmac_sha.c", "PROV_CIPHER_AES_CBC_HMAC_SHA"),
    # The AES-GCM-SIV row layer. Also a **source-tree** file, and its raises are its own: one
    # `PROV_R_INVALID_KEY_LENGTH` in `ossl_aes_gcm_siv_init` and one more in
    # `ossl_aes_gcm_siv_set_ctx_params`, a `PROV_R_INVALID_IV_LENGTH`, a
    # `PROV_R_OUTPUT_BUFFER_TOO_SMALL` in the cipher entry point, three
    # `PROV_R_FAILED_TO_SET_PARAMETER` in the getter (one per key it publishes) and two
    # `PROV_R_FAILED_TO_GET_PARAMETER` in the setter. Its `_hw.c` and `_polyval.c` siblings raise
    # **nothing** -- they return 0 -- so they are absent for the reason `cipher_chacha20_hw.c` is.
    ("providers/implementations/ciphers/cipher_aes_gcm_siv.c", "PROV_CIPHER_AES_GCM_SIV"),
    # Deliberately *not* covered, with the reason: `cipher_sm4.c` and `cipher_sm4_hw.c` raise
    # nothing at all in this profile -- there is no failure arm in either -- so an entry would read
    # as coverage that does not exist. The SM4 *primitive* `crypto/sm4/sm4.c` has no failure path
    # either, `ossl_sm4_set_key` always answering 1.
    ("providers/implementations/macs/cmac_prov.c", "PROV_CMAC_PROV"),
    ("providers/implementations/macs/gmac_prov.c", "PROV_GMAC_PROV"),
    # The row lands with this stratum and its two generated decoders are the only
    # sites it raises from in this profile: two in the get decoder (`block-size`,
    # `size`) and five in the set decoder (`digest`, `engine`, `key`, `properties`,
    # `tls-data-size`). The two `fips` keys the generator also emits are
    # `# if defined(FIPS_MODULE)`-guarded in the generated text, so their
    # coordinates exist and no reachable arm uses them -- the same shape as
    # `cmac_prov.c`'s three and `gmac_prov.c`'s.
    ("providers/implementations/macs/hmac_prov.c", "PROV_HMAC_PROV"),
    ("providers/implementations/include/prov/blake2_params.inc", "PROV_BLAKE2_PARAMS"),
    # The BLAKE2 MAC implementation, which `blake2b_mac.c` and `blake2s_mac.c` each `#include` as
    # their whole body. It is a *source-tree* file, so unlike the `.c.in`-generated units its
    # `__FILE__` carries the `../../src/openssl-3.6.4/` prefix -- the opposite of D235's finding,
    # and measured from the two object files rather than assumed.
    ("providers/implementations/macs/blake2_mac_impl.c", "PROV_BLAKE2_MAC_IMPL"),
    ("providers/implementations/macs/poly1305_prov.c", "PROV_POLY1305_PROV"),
    ("providers/implementations/macs/siphash_prov.c", "PROV_SIPHASH_PROV"),
    # The largest MAC unit, and the only one that raises from helper functions rather than from
    # the row's own bodies: `kmac_prov.c`'s generated text carries twenty-one sites, and five of
    # them are the encoding helpers' (`right_encode`, `encode_string`) plus `bytepad`'s
    # passed-NULL guard. Its two generated decoders raise for four keys in this profile --
    # `block-size`/`size` in the get decoder and `custom`/`key`/`size`/`xof` in the set one -- and
    # the two `fips` keys each generator also emits are `# if defined(FIPS_MODULE)`-guarded, so
    # their coordinates exist and no reachable arm uses them, the same shape as `cmac_prov.c`'s.
    ("providers/implementations/macs/kmac_prov.c", "PROV_KMAC_PROV"),
    # Phase 8's digest half. `digestcommon.c` is generated and shared by every digest
    # row the *default* provider publishes. The other `*_prov.c` units raise nothing in
    # this profile and are deliberately absent (an entry that can never change would read
    # as coverage that does not exist). `mdc2_prov.c` is one of the exceptions that proves
    # D206's rule again at the provider-file level: it *does* raise
    # (`mdc2_set_ctx_params` at `:51`), but MDC2 is a **legacy** provider row
    # (`providers/legacyprov.c:95`, beside MD4 at `:92` and WHIRLPOOL at `:98`), so no
    # translation unit this crate transcribes reaches it. It is named here rather than
    # listed, and it joins the covered set in the legacy provider's stratum.
    ("providers/implementations/digests/digestcommon.c", "PROV_DIGESTCOMMON"),
    # Phase 8's KDF half (D346). The two rows `DH_KDF_X9_42` and `ECDH_KDF_X9_62` fetch are
    # `X942KDF-ASN1` and `X963KDF`, and this stratum publishes both, so the two units'
    # raises are coordinates this crate now has. Both are `.c.in`-generated, so (D235's
    # finding, confirmed by `strings` on the two objects) their `__FILE__` is the bare
    # build-relative path and their line numbers are the generated text's, not the
    # template's. `sskdf.c` raises from `sskdf_size`/`sskdf_derive`/`x963kdf_derive` and from
    # the two generated decoders; `x942kdf.c` raises from `find_alg_id`, `x942kdf_size`,
    # `x942kdf_derive`, `x942kdf_hash_kdm` and its two decoders.
    ("providers/implementations/kdfs/sskdf.c", "PROV_SSKDF"),
    ("providers/implementations/kdfs/x942kdf.c", "PROV_X942KDF"),
    # The PKCS12 KDF (8.10's first provider-KDF row). `pkcs12kdf.c` is `.c.in`-generated, so its
    # `__FILE__` is the bare build-relative path and its line numbers are the generated text's.
    # It raises from `pkcs12kdf_derive` (`:69`, `:75`), `kdf_pkcs12_derive` (`:234`, `:239`) and
    # its two generated decoders (`:288`-`:366`, `:451`).
    ("providers/implementations/kdfs/pkcs12kdf.c", "PROV_PKCS12KDF"),
    # The SSH KDF (8.10's second provider-KDF row). `sshkdf.c` is `.c.in`-generated too, so its
    # `__FILE__` is bare and its line numbers are the generated text's. It raises from
    # `kdf_sshkdf_derive` (`:186`, `:190`, `:194`, `:198`, `:202`), `kdf_sshkdf_set_ctx_params`
    # (`:435`, `:472`) and its two generated decoders (`:301`-`:397`, `:536`).
    ("providers/implementations/kdfs/sshkdf.c", "PROV_SSHKDF"),
    # PBKDF2 (8.10's third provider-KDF row). `pbkdf2.c` is `.c.in`-generated, so its `__FILE__` is
    # bare and its line numbers are the generated text's. It raises from `lower_bound_check_passed`
    # (`:248`, the *variable* reason the lower-bound function selected, and `:252`),
    # `kdf_pbkdf2_derive` (`:270`, `:275`), `kdf_pbkdf2_set_ctx_params` (`:431`) and its two
    # generated decoders (`:327`-`:398`, `:525`), plus `pbkdf2_derive`'s own overflow guard
    # (`:606`).
    ("providers/implementations/kdfs/pbkdf2.c", "PROV_PBKDF2"),
    # HKDF and TLS13-KDF (8.10's fourth unit, five rows). `hkdf.c` is `.c.in`-generated, so its
    # `__FILE__` is bare and its line numbers are the generated text's. It raises from
    # `kdf_hkdf_size` (`:199`), `kdf_hkdf_derive` (`:239`, `:243`, `:247`),
    # `hkdf_common_set_ctx_params` (`:299`, `:313`, `:320`, `:325`), `HKDF_Extract` (`:1055`),
    # `kdf_tls1_3_derive` (`:1349`), `kdf_tls1_3_set_ctx_params` (`:1629`) and its four generated
    # decoders (`:407`-`:498` and the info counter at `:429`; `:586`-`:647`; `:825`-`:894` and its
    # counter at `:836`; `:1440`-`:1599`).
    ("providers/implementations/kdfs/hkdf.c", "PROV_HKDF"),
    # TLS1-PRF (8.10's fifth provider-KDF row). `tls1_prf.c` is `.c.in`-generated, so its
    # `__FILE__` is bare and its line numbers are the generated text's. It raises from
    # `fips_ems_check_passed` (`:205`), `fips_digest_check_passed` (`:230`),
    # `fips_key_check_passed` (`:246`), `kdf_tls1_prf_derive` (`:263`, `:267`, `:271`, `:275`),
    # `kdf_tls1_prf_set_ctx_params` (`:537`) and its two generated decoders
    # (`:372`-`:470`, `:655`-`:667`).
    ("providers/implementations/kdfs/tls1_prf.c", "PROV_TLS1_PRF"),
    # KBKDF (8.10's sixth provider-KDF row). `kbkdf.c` is `.c.in`-generated, so its `__FILE__` is
    # bare and its line numbers are the generated text's. It raises from
    # `fips_kbkdf_key_check_passed` (`:203`), `kbkdf_derive` (`:315`, `:320`, `:326`, `:341`,
    # `:349`), `kbkdf_set_ctx_params` (`:667`, `:680`) and its two generated decoders
    # (`:432`-`:619` and the info counter at `:465`; `:778`-`:790`).
    ("providers/implementations/kdfs/kbkdf.c", "PROV_KBKDF"),
    # SCRYPT (8.10's seventh provider-KDF row). `scrypt.c` is `.c.in`-generated and its whole body
    # is behind `#ifndef OPENSSL_NO_SCRYPT`, which this profile does not define, so its `__FILE__`
    # is bare and its line numbers are the generated text's. It raises from `set_digest` (`:171`),
    # `kdf_scrypt_derive` (`:198`, `:203`), its two generated decoders (`:264`-`:336`, `:432`) and
    # `scrypt_alg` (`:615`, `:626`, `:644`, `:654`, `:661`, `:670`, `:699` -- the last six
    # `ERR_LIB_EVP`, unlike every other unit in this table).
    ("providers/implementations/kdfs/scrypt.c", "PROV_SCRYPT"),
    # KRB5KDF (8.10's eighth provider-KDF row). `krb5kdf.c` is `.c.in`-generated, so its `__FILE__`
    # is bare and its line numbers are the generated text's. It raises from `krb5kdf_derive`
    # (`:140`, `:144`, `:148`), `KRB5KDF` (`:538`, `:557`, `:563`, `:584`, `:618`) and its two
    # generated decoders (`:199`-`:244`, `:314`).
    ("providers/implementations/kdfs/krb5kdf.c", "PROV_KRB5KDF"),
    # HMAC-DRBG-KDF (8.10's ninth provider-KDF row). `hmacdrbg_kdf.c` is `.c.in`-generated, so its
    # `__FILE__` is bare and its line numbers are the generated text's. It raises from
    # `hmac_drbg_kdf_new` (`:53`), `hmac_drbg_kdf_set_ctx_params` (`:386`) and its two generated
    # decoders (`:177`-`:188`, `:273`-`:327`).
    ("providers/implementations/kdfs/hmacdrbg_kdf.c", "PROV_HMACDRBG_KDF"),
    # This pass's Argon2 unit (RFC 9106), the last three `OSSL_OP_KDF` rows. `argon2.c` is
    # `.c.in`-generated, so its `__FILE__` is bare and its line numbers are the generated text's:
    # the `.in` template expands two `produce_param_decoder` calls into ~370 generated lines ahead
    # of `initialize`, so reading the template would attribute every site to a line the compiler
    # never saw. It raises from `initialize` (`:741`), the three `new` constructors (`:938`, `:957`,
    # `:976`), `kdf_argon2_derive` (`:1031`, `:1039`, `:1045`, `:1052`, `:1065`, `:1071`, `:1077`,
    # `:1084`, `:1092`), the nine ctx setters (`:1157`-`:1373`) and its two generated decoders
    # (`:1448`-`:1579`, `:1711`).
    ("providers/implementations/kdfs/argon2.c", "PROV_ARGON2"),
    # The generic SKEYMGMT row (8.10's `OSSL_OP_SKEYMGMT` pair, one of the two units).
    # `skeymgmt/generic.c` is `.c.in`-generated, so its `__FILE__` is bare and its line number is
    # the generated text's. It raises only from its generated import decoder (`:63`), on a repeated
    # `raw-bytes`. `skeymgmt/aes_skmgmt.c` raises nothing at all and so is deliberately absent, the
    # same reasoning `mdc2_prov.c` and `rsa_meth.c` are named under above.
    ("providers/implementations/skeymgmt/generic.c", "PROV_GENERIC_SKEYMGMT"),
    # The KEYEXCH unit the `OSSL_OP_KEYMGMT` gate unlocks (8.5's first exchange unit).
    # `exchange/kdf_exch.c` is a plain `.c` (not generated), so its `__FILE__` carries the
    # source-tree prefix. It raises once, from `kdf_derive` (`:117`), when the caller's buffer is
    # smaller than the KDF's fixed output size. `kdf_legacy_kmgmt.c` itself raises nothing and so is
    # deliberately absent, on the same reasoning as `skeymgmt/aes_skmgmt.c` above.
    ("providers/implementations/exchange/kdf_exch.c", "PROV_KDF_EXCH"),
    # The `DH`/`DHX` key types (D387). `keymgmt/dh_kmgmt.c` is a plain `.c`, so its `__FILE__`
    # carries the source-tree prefix. It raises five times: `dh_gen_common_set_params`
    # (`:544`, `:558`) and `dh_gen_set_params` (`:681`) with `ERR_R_PASSED_INVALID_ARGUMENT`,
    # `dhx_gen_set_params` (`:653`) with `ERR_R_UNSUPPORTED`, and `dh_gen` (`:725`) through
    # `ERR_raise_data` with a formatted `gen_type` message.
    ("providers/implementations/keymgmt/dh_kmgmt.c", "PROV_DH_KMGMT"),
    # The `DH` key exchange row (D387). `exchange/dh_exch.c.in` is `.c.in`-generated, so its
    # `__FILE__` is the bare build-relative path and its line numbers are the generated text's:
    # `dh_match_params` (`:165`), `dh_plain_derive` (`:194`, `:204`) and `dh_X9_42_kdf_derive`
    # (`:234`) in the hand-written body, and the two generated decoders'
    # `PROV_R_REPEATED_PARAMETER` sites (`:402`-`:542` set, `:712`-`:785` get).
    ("providers/implementations/exchange/dh_exch.c", "PROV_DH_EXCH"),
    # Phase 8.10's ECX chain (this pass): the four `X25519`/`X448`/`ED25519`/`ED448` key types, the
    # two key-exchange rows they gate and the two DHKEM rows. All three are `.c.in`-generated, so
    # each `__FILE__` is the bare build-relative path and each line number is the generated text's.
    # `keymgmt/ecx_kmgmt.c` raises five times -- `ecx_gen_set_params`'s group-name mismatch
    # (`:1144`, `ERR_R_PASSED_INVALID_ARGUMENT`), two `ERR_R_EC_LIB` sites in `ecx_gen` (`:1255`,
    # `:1264`) and `ecx_validate`'s `PROV_R_ALGORITHM_MISMATCH` (`:1514`) -- plus the eleven
    # generated `PROV_R_REPEATED_PARAMETER` sites its four decoders carry.
    ("providers/implementations/keymgmt/ecx_kmgmt.c", "PROV_ECX_KMGMT"),
    # `exchange/ecx_exch.c` raises three times, all `ERR_LIB_PROV`/`ERR_R_INTERNAL_ERROR`: `ecx_init`
    # (`:86`), `ecx_set_peer` (`:124`) and the two reference failures in `ecx_dupctx` (`:168`,
    # `:174`). It has no generated decoders (its only `FIPS_MODULE`-guarded one is not compiled).
    ("providers/implementations/exchange/ecx_exch.c", "PROV_ECX_EXCH"),
    # `kem/ecx_kem.c` raises from `ecx_pubkey` (`:155`, `PROV_R_NOT_A_PUBLIC_KEY`),
    # `ossl_ecx_dhkem_derive_private` (`:401`, `PROV_R_INVALID_INPUT_LENGTH` with an
    # `ikmlen`/`Nsk` message), `dhkem_encap` (`:618`, `:622`, `PROV_R_BAD_LENGTH`),
    # `dhkem_decap` (`:681`, `PROV_R_BAD_LENGTH`; `:685`, `PROV_R_INVALID_KEY`) and the two
    # `ecxkem_{encapsulate,decapsulate}` default arms (`:720`, `:734`, `PROV_R_INVALID_MODE`), plus
    # its one generated `PROV_R_REPEATED_PARAMETER` decoder.
    ("providers/implementations/kem/ecx_kem.c", "PROV_ECX_KEM"),
    # 8.10's `HMAC`/`SIPHASH`/`POLY1305`/`CMAC` key types. `keymgmt/mac_legacy_kmgmt.c` is a plain
    # `.c`, so its `__FILE__` carries the source-tree prefix. It raises eight times: three
    # `ERR_R_PASSED_INVALID_ARGUMENT` sites in `mac_key_fromdata` (`:187` private-key type, `:202`
    # property type, `:212` the CMAC cipher load), one each in `mac_gen_set_params` (`:422`) and
    # `cmac_gen_set_params` (`:444`), and three in `mac_gen` (`:481` `ERR_R_PROV_LIB`, `:490`
    # `PROV_R_INVALID_KEY`, `:503` `ERR_R_INTERNAL_ERROR`).
    ("providers/implementations/keymgmt/mac_legacy_kmgmt.c", "PROV_MAC_LEGACY_KMGMT"),
    # Phase 8's `rsa_kmgmt.c` and `dsa_kmgmt.c` (D391). Both are plain `.c` files, so their
    # `__FILE__` carries the source-tree prefix. `rsa_kmgmt.c` raises once, the
    # `PROV_R_KEY_SIZE_TOO_SMALL` refusal of `rsa_gen_set_params` at `:513`; `dsa_kmgmt.c`
    # raises twice, `ERR_R_PASSED_INVALID_ARGUMENT` from `dsa_gen_set_params` at `:486` and
    # `ERR_R_INTERNAL_ERROR` from `dsa_load` at `:633`.
    ("providers/implementations/keymgmt/rsa_kmgmt.c", "PROV_RSA_KMGMT"),
    ("providers/implementations/keymgmt/dsa_kmgmt.c", "PROV_DSA_KMGMT"),
    # 8.10's `EC`/`SM2` key types and the `ECDH` exchange row. `keymgmt/ec_kmgmt.c` is a plain
    # `.c`, so its `__FILE__` carries the source-tree prefix. It raises four times, all with
    # `PROV_R_*` reasons: `common_get_params` (`:632` `PROV_R_NO_PARAMETERS_SET`, `:729`
    # `PROV_R_NOT_A_PUBLIC_KEY`), `ec_gen_set_group` (`:1021` `PROV_R_INVALID_CURVE`) and
    # `ec_gen_assign_group` (`:1241` `PROV_R_NO_PARAMETERS_SET`).
    ("providers/implementations/keymgmt/ec_kmgmt.c", "PROV_EC_KMGMT"),
    # `exchange/ecdh_exch.c.in` is `.c.in`-generated, so its `__FILE__` is the bare
    # build-relative path. It raises from `ecdh_init` (`:65`), `ecdh_match_params` (`:114`),
    # `ecdh_plain_derive` (`:172`, `:176`), `ecdh_X9_62_kdf_derive` (`:208`) and its two generated
    # decoders' `PROV_R_REPEATED_PARAMETER` sites.
    ("providers/implementations/exchange/ecdh_exch.c", "PROV_ECDH_EXCH"),
    # The two EC KEM functions the EC keymgmt/gen path needs, and the unit's own rows.
    # `kem/ec_kem.c.in` is `.c.in`-generated. It raises from `eckey_check` (`:82`),
    # `ossl_ec_match_params` (`:236`), `ossl_ec_dhkem_derive_private` (`:415`, `:441`),
    # `generate_ecdhkm` (`:534`), `derive_secret` (`:598`), `dhkem_encap` (`:672`, `:676`, `:692`),
    # `dhkem_decap` and its one generated decoder.
    ("providers/implementations/kem/ec_kem.c", "PROV_EC_KEM"),
    # `crypto/sm2/sm2_key.c`: SM2's private-key range check, whose two raises are the
    # `ERR_LIB_SM2` null-parameter and invalid-private-key reasons.
    ("crypto/sm2/sm2_key.c", "SM2_KEY"),
    # Phase 8's SM2 signature crypt unit. `crypto/sm2/sm2_sign.c` is a plain `.c`, so its `__FILE__`
    # carries the source-tree prefix. Its raises are the `ERR_LIB_SM2` refusals of the three message
    # helpers (`ossl_sm2_compute_z_digest`'s null-public-key, digest, BN and curve/point guards,
    # `sm2_compute_msg_hash`'s invalid-digest and EVP refusals, `sm2_sig_gen`'s private-key, EC, BN
    # and ECDSA refusals and `sm2_sig_verify`'s bad-signature, EC and BN ones) plus the two
    # `ossl_sm2_internal_*` entry points' null-parameter, BN, ECDSA and invalid-encoding refusals.
    ("crypto/sm2/sm2_sign.c", "SM2_SIGN"),
    # Phase 8's SM2 encryption crypt unit. A plain `.c`, so its `__FILE__` carries the source-tree
    # prefix. Its raises are the `ERR_LIB_SM2` refusals of `ossl_sm2_plaintext_size`,
    # `ossl_sm2_encrypt` and `ossl_sm2_decrypt` -- the invalid-encoding, invalid-argument,
    # internal-error, EC/BN/EVP/ASN1-lib and buffer-too-small reasons -- and the
    # `SM2_R_INVALID_DIGEST` refusal of the decrypt path's C3 comparison.
    ("crypto/sm2/sm2_crypt.c", "SM2_CRYPT"),
    # Phase 8's SM2 signature unit. `.c.in`-generated, so the bare build-relative path. Its raises
    # are the `PROV_R_XOF_DIGESTS_NOT_ALLOWED` and `PROV_R_INVALID_DIGEST` refusals of
    # `sm2sig_set_mdname`, the `PROV_R_NO_KEY_SET` refusal of `sm2sig_signature_init`, and the two
    # generated decoders' `PROV_R_REPEATED_PARAMETER` sites.
    ("providers/implementations/signature/sm2_sig.c", "PROV_SM2_SIG"),
    # Phase 8's SM2 asym-cipher unit. `.c.in`-generated too. Its raises are the
    # `PROV_R_INVALID_KEY` refusal of `sm2_asym_encrypt`'s size-query arm and the two generated
    # decoders' `PROV_R_REPEATED_PARAMETER` sites.
    ("providers/implementations/asymciphers/sm2_enc.c", "PROV_SM2_ENC"),
    # This pass's `DSA` signature unit. `signature/dsa_sig.c` is `.c.in`-generated, so its
    # `__FILE__` is the bare build-relative path (D235's finding, the same one `dh_exch.c`
    # carries). Its raises are its own: the four generated decoder refusals
    # (`PROV_R_REPEATED_PARAMETER`, one per named parameter in each of the three decoders), the
    # digest refusals of `dsa_setup_md` (`PROV_R_INVALID_DIGEST`/`PROV_R_DIGEST_NOT_ALLOWED`),
    # the `PROV_R_XOF_DIGESTS_NOT_ALLOWED` arm, the `PROV_R_NO_KEY_SET` of
    # `dsa_signverify_init`, and the `dsa_sigalg_set_ctx_params` refusals.
    ("providers/implementations/signature/dsa_sig.c", "PROV_DSA_SIG"),
    # This pass's `ECDSA` signature unit. `signature/ecdsa_sig.c` is `.c.in`-generated, so its
    # `__FILE__` is the bare build-relative path, like `dsa_sig.c`'s. Its raises are the same
    # shape: the generated decoder refusals (`PROV_R_REPEATED_PARAMETER`, one per named parameter
    # in each of the four decoders), the three `PROV_R_INVALID_DIGEST` refusals and the
    # `PROV_R_DIGEST_NOT_ALLOWED` pair of `ecdsa_setup_md`, its `PROV_R_XOF_DIGESTS_NOT_ALLOWED`
    # arm, and the `PROV_R_NO_KEY_SET` of `ecdsa_signverify_init`.
    ("providers/implementations/signature/ecdsa_sig.c", "PROV_ECDSA_SIG"),
    # This pass's `EdDSA` signature unit. `signature/eddsa_sig.c` is `.c.in`-generated, so its
    # `__FILE__` is the bare build-relative path too. Its raises are the `PROV_R_NO_KEY_SET` and
    # two `ERR_R_INTERNAL_ERROR` sites of `eddsa_signverify_init` and `eddsa_dupctx`, the
    # `PROV_R_OUTPUT_BUFFER_TOO_SMALL`/`PROV_R_NOT_A_PRIVATE_KEY`/`PROV_R_FAILED_TO_SIGN` trio of
    # each sign path, the `ph`-instance refusals (`PROV_R_INVALID_PREHASHED_DIGEST_LENGTH`,
    # `PROV_R_INVALID_DIGEST_LENGTH`, `PROV_R_INVALID_EDDSA_INSTANCE_FOR_ATTEMPTED_OPERATION`), the
    # two `PROV_R_INVALID_DIGEST` refusals of the digest inits, the `PROV_R_NO_INSTANCE_ALLOWED`
    # and unknown-instance refusals of `eddsa_set_ctx_params_internal`, and the three decoders'
    # `PROV_R_REPEATED_PARAMETER` sites. The two `PROV_R_FAILED_TO_SIGN` raises inside the
    # `S390X_EC_ASM` arms are recorded but not compiled on this profile.
    ("providers/implementations/signature/eddsa_sig.c", "PROV_EDDSA_SIG"),
    # Phase 8's `rsa_sig.c.in` (D395), the largest signature unit. `.c.in`-generated, so the bare
    # build-relative path. Its raises are the generated decoders' `PROV_R_REPEATED_PARAMETER`
    # sites (four decoders over the compiled names), the `rsa_setup_md`/`rsa_setup_mgf1_md`
    # digest refusals, the `rsa_check_padding`/`rsa_check_parameters`/`rsa_pss_compute_saltlen`
    # PSS refusals, the `PROV_R_INVALID_SIGNATURE_SIZE`/`PROV_R_INVALID_DIGEST_LENGTH`/
    # `PROV_R_KEY_SIZE_TOO_SMALL` of `rsa_sign_directly`, the `PROV_R_OUTPUT_BUFFER_TOO_SMALL`
    # and `PROV_R_ALGORITHM_MISMATCH` of `rsa_verify_recover`, the `PROV_R_NO_KEY_SET` and
    # `PROV_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE` of `rsa_signverify_init`, the
    # `PROV_R_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE`/`PROV_R_NOT_SUPPORTED`/
    # `PROV_R_INVALID_MGF1_MD` refusals of `rsa_set_ctx_params`, and the
    # `PROV_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE` of both `rsa_dupctx`'s method and
    # `rsa_sigalg_signverify_init`. The `FIPS_MODULE` raises of `rsa_x931_padding_allowed` and
    # `rsa_pss_saltlen_check_passed` are recorded but not compiled on this profile.
    ("providers/implementations/signature/rsa_sig.c", "PROV_RSA_SIG"),
    # `providers/common/der/der_rsa_key.c` (D395): two `ERR_LIB_RSA` refusals in
    # `ossl_DER_w_RSASSA_PSS_params`, a negative salt length (`:308`) and a trailer field other
    # than 1 (`:312`). It is a plain `.c`, so its `__FILE__` carries the source-tree prefix.
    ("providers/common/der/der_rsa_key.c", "DER_RSA_KEY"),
    # `providers/common/securitycheck.c` (D395): the two `ERR_LIB_PROV` refusals of
    # `ossl_rsa_key_op_get_protect` -- the `PROV_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE`
    # PSS refusal (`:47`) and the `ERR_R_INTERNAL_ERROR` unknown-operation arm (`:54`). The
    # other eight functions raise nothing on this profile.
    ("providers/common/securitycheck.c", "SECURITYCHECK"),
    # Phase 8's `rsa_enc.c.in` (D396), the `RSA` `OSSL_OP_ASYM_CIPHER` row. `.c.in`-generated, so
    # the bare build-relative path. Its raises are the generated decoder refusals, the
    # `PROV_R_INVALID_PADDING_MODE`/`PROV_R_INVALID_KEY`/`PROV_R_OUTPUT_BUFFER_TOO_SMALL`/
    # `PROV_R_FAILED_TO_DECRYPT`/`PROV_R_BAD_TLS_CLIENT_VERSION`/
    # `PROV_R_BAD_LENGTH`/`ERR_R_INTERNAL_ERROR` refusals of its four bodies, and the
    # `rsa_init` `ERR_R_INTERNAL_ERROR` arm. The `FIPS_MODULE` X9.31/key-check raises are recorded
    # but not compiled on this profile.
    ("providers/implementations/asymciphers/rsa_enc.c", "PROV_RSA_ENC"),
    # Phase 8's `rsa_kem.c.in` (D396), the `RSA` `OSSL_OP_KEM` row. `.c.in`-generated, so the bare
    # build-relative path. Its raises are the generated decoder refusals, the
    # `PROV_R_INVALID_KEY`/`PROV_R_INVALID_OUTPUT_LENGTH`/`PROV_R_BAD_LENGTH` refusals of the two
    # RSASVE bodies, and the one **dynamic** reason at `rsasve_recover`'s degenerate-ciphertext
    # guard (`ERR_LIB_RSA` with `RSA_R_DATA_TOO_SMALL` or `RSA_R_DATA_TOO_LARGE_FOR_MODULUS` chosen
    # at run time).
    ("providers/implementations/kem/rsa_kem.c", "PROV_RSA_KEM"),
    # The SLH-DSA core's signature unit. `crypto/slh_dsa/slh_dsa.c` is a plain `.c`, so its
    # `__FILE__` carries the source-tree prefix. It raises the four `ERR_LIB_PROV` refusals of
    # `slh_sign_internal`/`slh_verify_internal`: the `PROV_R_INVALID_SIGNATURE_SIZE`
    # destination-size guard, the `PROV_R_MISSING_KEY` "no private key" and "no public key"
    # guards, and the named field of the oversize-message refusal.
    ("crypto/slh_dsa/slh_dsa.c", "SLH_DSA"),
    # Phase 10.1's SLH-DSA key unit. `crypto/slh_dsa/slh_dsa_key.c` is a plain `.c`, so its
    # `__FILE__` carries the source-tree prefix. The unit's whole body raises nothing but the three
    # `#ifndef FIPS_MODULE` arms of `ossl_slh_dsa_key_to_text` (`:494` `ERR_R_PASSED_NULL_PARAMETER`,
    # `:500`/`:507` the `PROV_R_MISSING_KEY` "no %s key material available" guards), which land with
    # the text-encoder caller the printer's own divergence row named (D398).
    ("crypto/slh_dsa/slh_dsa_key.c", "SLH_DSA_KEY"),
    # This pass's ML-KEM core. `crypto/ml_kem/ml_kem.c` is a plain `.c`, so its `__FILE__` carries
    # the source-tree prefix. It raises nine times, each with the algorithm name interpolated: the
    # three `PROV_R_INVALID_KEY` refusals of `parse_pubkey`/`parse_prvkey` (the `t` vector, the `s`
    # vector and the public-key-hash mismatch), the five `ERR_LIB_CRYPTO` `ERR_R_INTERNAL_ERROR`
    # paths (`parse_pubkey`'s, `genkey`'s, `encap`'s, `decap`'s and `ossl_ml_kem_key_new`'s
    # missing-SHA3 one) and `ossl_ml_kem_key_new`'s `ERR_R_PASSED_INVALID_ARGUMENT` for an unknown
    # variant.
    ("crypto/ml_kem/ml_kem.c", "ML_KEM"),
    # This pass's ML-KEM KEM unit. `.c.in`-generated, so the bare build-relative path. Its raises
    # are the two `PROV_R_MISSING_KEY` refusals of the encapsulate/decapsulate inits, the
    # `PROV_R_MISSING_KEY` refusal inside `ml_kem_encapsulate`, the five `PROV_R_NULL_*`/
    # `PROV_R_OUTPUT_BUFFER_TOO_SMALL` output guards of `ml_kem_encapsulate`, the
    # `PROV_R_OUTPUT_BUFFER_TOO_SMALL` guard of `ml_kem_decapsulate`, and the generated
    # set-ctx-params decoder's `PROV_R_INVALID_SEED_LENGTH` and `PROV_R_REPEATED_PARAMETER` sites.
    ("providers/implementations/kem/ml_kem_kem.c", "PROV_ML_KEM_KEM"),
    # This pass's ML-KEM keymgmt unit. `.c.in`-generated too. Every raise is a generated decoder's
    # `PROV_R_REPEATED_PARAMETER` site: the import decoder's four keys (priv, pub, priv_len,
    # pub_len), the get-params decoder's five, and the gen-set-params decoder's one (`seed`).
    ("providers/implementations/keymgmt/ml_kem_kmgmt.c", "PROV_ML_KEM_KMGMT"),
    # This pass's `mlx_kmgmt.c.in`. `.c.in`-generated, so the bare build-relative path. Its raises
    # are the generated decoders' `PROV_R_REPEATED_PARAMETER` sites -- the import decoder's two
    # keys (priv, pub), the get-params decoder's six, the set-params decoder's two, and the
    # gen-set-params decoder's one (`properties`) -- plus `export_sub_cb`'s two `ERR_R_INTERNAL_ERROR`
    # length checks, the export/fromdata `PROV_R_MISSING_KEY` and `PROV_R_INVALID_KEY_LENGTH`
    # refusals, the get-params two `PROV_R_OUTPUT_BUFFER_TOO_SMALL` guards, the set-params
    # `PROV_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE` mutation refusal and its `PROV_R_INVALID_KEY`
    # length guard, and `dup`'s `PROV_R_UNSUPPORTED_SELECTION`.
    ("providers/implementations/keymgmt/mlx_kmgmt.c", "PROV_MLX_KMGMT"),
    # This pass's `mlx_kem.c`. A plain `.c`, so its `__FILE__` carries the source-tree prefix. Its
    # raises are the three `PROV_R_MISSING_KEY` refusals of the two inits and `mlx_kem_encapsulate`,
    # the five `PROV_R_NULL_*`/`PROV_R_OUTPUT_BUFFER_TOO_SMALL` output guards of `mlx_kem_encapsulate`,
    # the four `ERR_R_INTERNAL_ERROR` "unexpected size" checks (two per body), the
    # `PROV_R_OUTPUT_BUFFER_TOO_SMALL` and `PROV_R_WRONG_CIPHERTEXT_SIZE` guards of
    # `mlx_kem_decapsulate`, and the `PROV_R_MISSING_KEY` refusal inside it.
    ("providers/implementations/kem/mlx_kem.c", "PROV_MLX_KEM"),
    # The SLH-DSA keymgmt unit. `.c.in`-generated, so the bare build-relative path. Every raise is
    # a generated decoder's `PROV_R_REPEATED_PARAMETER` site: the import decoder's two keys
    # (priv, pub), the get-params decoder's seven, and the gen-set-params decoder's two. The
    # `FIPS_MODULE` pairwise-test raises are recorded but not compiled on this profile.
    ("providers/implementations/keymgmt/slh_dsa_kmgmt.c", "PROV_SLH_DSA_KMGMT"),
    # The SLH-DSA signature unit. `.c.in`-generated too. Its raises are the generated
    # set-ctx-params decoder's four `PROV_R_REPEATED_PARAMETER` sites, the get-ctx-params
    # decoder's one, the `PROV_R_NO_KEY_SET` refusal of `slh_dsa_signverify_msg_init`, and the
    # `PROV_R_INVALID_DIGEST` refusal of `slh_dsa_digest_signverify_init`.
    ("providers/implementations/signature/slh_dsa_sig.c", "PROV_SLH_DSA_SIG"),
    # The ML-DSA core's three raising units. `crypto/ml_dsa/ml_dsa_encoders.c` is a plain `.c`, so
    # its `__FILE__` carries the source-tree prefix; it raises once, the `PROV_R_INVALID_KEY`
    # refusal of `ossl_ml_dsa_sk_decode`'s public-key-hash check (`:820`). `ml_dsa_key.c` raises
    # once, the `PROV_R_INVALID_KEY` refusal of `ossl_ml_dsa_generate_key`'s "explicit private key
    # does not match seed" check (`:501`), which `ossl_ml_dsa_key_reset`s the key first.
    # `ml_dsa_sign.c` raises the three `PROV_R_BAD_LENGTH` guards of `ossl_ml_dsa_mu_init` (`:135`),
    # `ossl_ml_dsa_sign` (`:181`) and `ossl_ml_dsa_verify` (`:344`). The other five `crypto/ml_dsa/`
    # units -- `params`, `ntt`, `key_compress`, `sample` and `matrix` -- raise nothing.
    ("crypto/ml_dsa/ml_dsa_encoders.c", "ML_DSA_ENCODERS"),
    ("crypto/ml_dsa/ml_dsa_key.c", "ML_DSA_KEY"),
    ("crypto/ml_dsa/ml_dsa_sign.c", "ML_DSA_SIGN"),
    # The ML-DSA keymgmt unit. `.c.in`-generated, so the bare build-relative path and the
    # post-expansion coordinates. Its raises are the two `PROV_R_INVALID_KEY_LENGTH` refusals of
    # `ml_dsa_import`'s seed check and `ml_dsa_export`, the `PROV_R_INVALID_SEED_LENGTH` refusal
    # beside them, the `PROV_R_MISSING_KEY` refusal of `ml_dsa_export`, the two
    # `PROV_R_FAILED_TO_GENERATE_KEY` refusals of `ml_dsa_gen` and `ml_dsa_load`'s no-seed arm, the
    # two `PROV_R_INVALID_KEY` refusals of `ml_dsa_import`'s key check and `ml_dsa_validate`, and
    # the generated decoders' `PROV_R_REPEATED_PARAMETER` sites.
    ("providers/implementations/keymgmt/ml_dsa_kmgmt.c", "PROV_ML_DSA_KMGMT"),
    # The ML-DSA signature unit. `.c.in`-generated too. Its raises are the `PROV_R_NO_KEY_SET`
    # refusals of the sign and verify message inits, the `PROV_R_INVALID_DIGEST` refusal of
    # `ml_dsa_digest_signverify_init`, the `PROV_R_INVALID_SEED_LENGTH` refusal of
    # `ml_dsa_set_ctx_params`'s `test-entropy` decoder, and the generated set-ctx-params decoder's
    # `PROV_R_REPEATED_PARAMETER` sites.
    ("providers/implementations/signature/ml_dsa_sig.c", "PROV_ML_DSA_SIG"),
    # 8.10's `HMAC`/`SIPHASH`/`POLY1305`/`CMAC` signature rows. `signature/mac_legacy_sig.c` is a
    # plain `.c`, so its `__FILE__` carries the source-tree prefix. It raises once, the
    # `PROV_R_NO_KEY_SET` refusal of `mac_digest_sign_init` (`:107`).
    ("providers/implementations/signature/mac_legacy_sig.c", "PROV_MAC_LEGACY_SIG"),
    # Phase 8.4: the `crypto/rsa` subsystem. The same rule as `crypto/bn` above -- this is
    # the *subsystem* set, not a selection of convenient files, because every one of them
    # raises from a surface Phase 8 owns and a coordinate's `file` string is part of the
    # observable error record.
    #
    # `rsa_meth.c` is deliberately **absent**: D284 measured the whole file as allocations
    # and stored pointers, so it raises nothing, and an entry that could never change would
    # read as coverage that does not exist -- the reasoning `mdc2_prov.c` is named under
    # above. `rsa_err.c` is absent for the generator's own reason: it is the generated
    # reason-string table, not a raiser.
    ("crypto/rsa/rsa_lib.c", "RSA_LIB"),
    ("crypto/rsa/rsa_crpt.c", "RSA_CRPT"),
    ("crypto/rsa/rsa_pk1.c", "RSA_PK1"),
    ("crypto/rsa/rsa_none.c", "RSA_NONE"),
    ("crypto/rsa/rsa_x931.c", "RSA_X931"),
    ("crypto/rsa/rsa_oaep.c", "RSA_OAEP"),
    ("crypto/rsa/rsa_pss.c", "RSA_PSS"),
    ("crypto/rsa/rsa_ossl.c", "RSA_OSSL"),
    ("crypto/rsa/rsa_gen.c", "RSA_GEN"),
    ("crypto/rsa/rsa_chk.c", "RSA_CHK"),
    ("crypto/rsa/rsa_sign.c", "RSA_SIGN"),
    ("crypto/rsa/rsa_saos.c", "RSA_SAOS"),
    ("crypto/rsa/rsa_pmeth.c", "RSA_PMETH"),
    # Phase 8.8's three remaining `EVP_PKEY_METHOD` units (D355). `rsa_pmeth.c` above was
    # already a coordinate from 8.4; these three join it because the crate transcribes their
    # raising bodies whole. Their site counts in this profile are DSA 5, DH 4 and EC 11, and
    # each is named by the callback that raises rather than by a table listing: the digest and
    # curve refusals of `pkey_dsa_ctrl`/`pkey_dsa_ctrl_str`, the parameter-name and
    # keys-not-set refusals of `pkey_dh_ctrl_str`/`pkey_dh_keygen`/`pkey_dh_derive`, and the
    # eleven EC refusals of `pkey_ec_sign`, `pkey_ec_derive`, `pkey_ec_ctrl`,
    # `pkey_ec_ctrl_str`, `pkey_ec_paramgen` and `pkey_ec_keygen`.
    ("crypto/dsa/dsa_pmeth.c", "DSA_PMETH"),
    ("crypto/dh/dh_pmeth.c", "DH_PMETH"),
    ("crypto/ec/ec_pmeth.c", "EC_PMETH"),
    ("crypto/rsa/rsa_ameth.c", "RSA_AMETH"),
    ("crypto/rsa/rsa_backend.c", "RSA_BACKEND"),
    ("crypto/rsa/rsa_asn1.c", "RSA_ASN1"),
    ("crypto/rsa/rsa_mp.c", "RSA_MP"),
    ("crypto/rsa/rsa_prn.c", "RSA_PRN"),
    # Phase 8.6's `crypto/dsa/dsa_prn.c` (D362) raises twice, both
    # `ERR_LIB_DSA`/`ERR_R_BUF_LIB` at `:28` and `:43`.
    ("crypto/dsa/dsa_prn.c", "DSA_PRN"),
    ("crypto/rsa/rsa_sp800_56b_check.c", "RSA_SP800_56B_CHECK"),
    # Phase 8's `crypto/dsa/dsa_check.c` (D391). The unit is transcribed whole as
    # `src/dsa/check.rs` and raises three times, all `ERR_LIB_DSA`: the two
    # `DSA_R_BAD_FFC_PARAMETERS`/`DSA_R_MODULUS_TOO_LARGE` refusals of `dsa_precheck_params`
    # at `:25` and `:31`, and its `DSA_R_BAD_Q_VALUE` at `:37`. Its third neighbour
    # `DSA_R_BAD_FFC_PARAMETERS` is the same reason as the first.
    ("crypto/dsa/dsa_check.c", "DSA_CHECK"),
    ("crypto/rsa/rsa_sp800_56b_gen.c", "RSA_SP800_56B_GEN"),
    ("crypto/rsa/rsa_x931g.c", "RSA_X931G"),
    ("crypto/rsa/rsa_depr.c", "RSA_DEPR"),
    ("crypto/rsa/rsa_schemes.c", "RSA_SCHEMES"),
    ("crypto/rsa/rsa_mp_names.c", "RSA_MP_NAMES"),
    ("crypto/rsa/rsa_acvp_test_params.c", "RSA_ACVP_TEST_PARAMS"),
    # Phase 8.8's `crypto/asn1/x_algor.c` (D348). The unit is transcribed whole as
    # `src/asn1/x_algor.rs`, and it raises once: `ossl_x509_algor_get_md`'s
    # `ASN1_R_UNKNOWN_DIGEST` at `:165`, the coordinate a caller sees when an OID
    # resolves to no digest method.
    ("crypto/asn1/x_algor.c", "X_ALGOR"),
    # Phase 8.5's `crypto/ffc` subsystem. The same rule as `crypto/rsa` above: these are the
    # units of the stratum that **raise**, and a coordinate's `file` string is part of the
    # observable error record. `ffc_params_validate.c` raises the DH
    # `NOT_SUITABLE_GENERATOR` reason at `:125` and the two DSA prime reasons at `:172` and
    # `:178`; `ffc_params_generate.c` raises the DH and DSA `BAD_FFC_PARAMETERS` reasons from
    # its L/N pair test, all three of them on the `#else` arm this profile compiles.
    #
    # `ffc_params.c`, `ffc_key_generate.c`, `ffc_key_validate.c`, `ffc_dh.c` and
    # `ffc_backend.c` are deliberately **absent**: none of them raises anything (they
    # allocate, copy, compare, print and validate ranges), so an entry for them would read as
    # coverage that does not exist -- the reasoning `rsa_meth.c` and `mdc2_prov.c` are named
    # under above.
    ("crypto/ffc/ffc_params_generate.c", "FFC_PARAMS_GENERATE"),
    ("crypto/ffc/ffc_params_validate.c", "FFC_PARAMS_VALIDATE"),
    # Phase 8.5's `crypto/dh` object layer, key layer, generator and validator. The subsystem
    # set again, minus the two units that raise nothing: `dh_meth.c` (D329 measured its whole
    # body as allocations and stored pointers) and `dh_depr.c` (its one function allocates a
    # context and dispatches), so neither gets an entry that could never change. `dh_kdf.c`,
    # `dh_asn1.c` and `dh_rfc5114.c` raise nothing either. `dh_group_params.c`'s one site is
    # D332's: the named-group unit the four earlier slices recorded as a separable follow-up
    # now has a crate module, so its single `DH_R_INVALID_PARAMETER_NID` at `:47` is covered
    # like every other landed coordinate.
    ("crypto/dh/dh_lib.c", "DH_LIB"),
    ("crypto/dh/dh_key.c", "DH_KEY"),
    ("crypto/dh/dh_gen.c", "DH_GEN"),
    ("crypto/dh/dh_check.c", "DH_CHECK"),
    ("crypto/dh/dh_group_params.c", "DH_GROUP_PARAMS"),
    # D351's `crypto/dh/dh_backend.c`: the provider/legacy key bridge. It raises twice, both on
    # the PKCS#8 decode path -- `DH_R_BN_ERROR` at `:222` and `DH_R_DECODE_ERROR` at `:235` --
    # and like every other unit the file string is part of the observable error record.
    ("crypto/dh/dh_backend.c", "DH_BACKEND"),
    # 8.8's `crypto/dh/dh_ameth.c` -- the `EVP_PKEY_ASN1_METHOD` objects. Its decode/encode
    # callbacks, its `do_dh_print` err label and its two key checks all raise, so the unit joins
    # the covered set with the objects that make its coordinates observable. `:297` is
    # `dynamic_reason`: the authority raises a computed `reason`.
    ("crypto/dh/dh_ameth.c", "DH_AMETH"),
    # Phase 8.6's `crypto/dsa` object layer and its `dsa_ossl.c`. The subsystem set again, minus
    # the five units that raise nothing: `dsa_meth.c` (D333 measured its whole body as allocations
    # and stored pointers), `dsa_gen.c` (every failure is a `return 0` and the reason a caller sees
    # is the FFC generator's own site -- the reasoning `dh_kdf.c` and `dh_asn1.c` were named
    # under), `dsa_key.c` (its only `ERR_raise`s are inside `#ifdef FIPS_MODULE`), `dsa_sign.c`
    # and `dsa_vrf.c` (dispatch) and `dsa_depr.c` (allocation and dispatch). `dsa_ossl.c` is where
    # the sign and verify reasons are raised -- nine sites, one of them the authority's only
    # dynamic-reason site in this stratum -- and `dsa_lib.c` is where the constructor's two
    # refusals are.
    ("crypto/dsa/dsa_lib.c", "DSA_LIB"),
    ("crypto/dsa/dsa_ossl.c", "DSA_OSS"),
    # D351's `crypto/dsa/dsa_backend.c`: the DSA half of the same bridge. Its four raises are
    # `DSA_R_BN_ERROR` (`:154`, `:171`), `ERR_R_BN_LIB` (`:159`, `:163`), `DSA_R_DECODE_ERROR`
    # (`:182`) and `ERR_R_INTERNAL_ERROR` (`:175`), all on the PKCS#8 decode path.
    ("crypto/dsa/dsa_backend.c", "DSA_BACKEND"),
    # 8.8's `crypto/dsa/dsa_ameth.c` -- the same shape as `dh_ameth.c` above: the decode/encode
    # callbacks, the private-key readers and the key checks raise, and the objects that reach them
    # land here.
    ("crypto/dsa/dsa_ameth.c", "DSA_AMETH"),
    # Phase 8.7's `crypto/ec` curve tables and `crypto/evp/ec_support.c`. The subsystem set again,
    # restricted to the two units D334 gives a crate module: `ec_curve.c` raises from the group
    # constructors (four `ERR_R_EC_LIB`/`ERR_R_BN_LIB`/`ERR_R_OBJ_LIB` sites in
    # `ec_group_new_from_data`'s `#ifndef FIPS_MODULE` tail and the `ERR_raise_data`/
    # `EC_R_UNKNOWN_GROUP` pair in `EC_GROUP_new_by_curve_name_ex`), and `ec_support.c` raises
    # nothing -- it is listed with an empty site set rather than omitted, so a later raise in it
    # cannot be invisible. **The lexical scan emits every site whether or not a landed path reaches
    # it**, which is the same treatment D330 records for the two FIPS-only FFC coordinates: the
    # constructors themselves are `open` in this slice, so these coordinates are carried for the
    # slice that lands them rather than reached by anything here.
    ("crypto/ec/ec_curve.c", "EC_CURVE"),
    ("crypto/evp/ec_support.c", "EC_SUPPORT"),
    # Phase 8.7's remaining `crypto/ec` layer — the group and point objects, the field arithmetic
    # they dispatch to, the multiplication ladder, the point-encoding units, the key layer, the
    # two signature/shared-secret units, the provider backend and the `ec.h` DER entry points.
    # D334 registered only the two units its first slice gave a crate module; D340 lands the rest
    # of the block, so the subsystem set is now complete. The same rule as `crypto/rsa` and
    # `crypto/dsa` above applies: a coordinate's `file` string is part of the observable error
    # record, so every unit of the stratum that **raises** is listed. `ec_cvt.c` raises nothing
    # and is listed with an empty site set rather than omitted, `ec_support.c`'s case above.
    ("crypto/ec/ec_lib.c", "EC_LIB"),
    ("crypto/ec/ecp_smpl.c", "ECP_SMPL"),
    ("crypto/ec/ecp_mont.c", "ECP_MONT"),
    ("crypto/ec/ecp_nist.c", "ECP_NIST"),
    ("crypto/ec/ec_mult.c", "EC_MULT"),
    ("crypto/ec/ecp_oct.c", "ECP_OCT"),
    ("crypto/ec/ec_oct.c", "EC_OCT"),
    ("crypto/ec/ec2_smpl.c", "EC2_SMPL"),
    ("crypto/ec/ec2_oct.c", "EC2_OCT"),
    ("crypto/ec/ec_key.c", "EC_KEY"),
    ("crypto/ec/ec_kmeth.c", "EC_KMETH"),
    ("crypto/ec/ecdsa_ossl.c", "ECDSA_OSSL"),
    ("crypto/ec/ecdh_ossl.c", "ECDH_OSSL"),
    ("crypto/ec/ecdsa_sign.c", "ECDSA_SIGN"),
    ("crypto/ec/ecdsa_vrf.c", "ECDSA_VRF"),
    ("crypto/ec/ec_check.c", "EC_CHECK"),
    ("crypto/ec/ec_cvt.c", "EC_CVT"),
    # `ec_backend.c` is the provider group/key backend the group object reaches through
    # `EC_GROUP_to_params`/`EC_GROUP_new_from_params`, and `ec_asn1.c` supplies the three `ec.h`
    # DER entry points `ecdsa_ossl.c` reaches (`ECDSA_size`, `i2d_ECDSA_SIG`, `d2i_ECDSA_SIG`).
    ("crypto/ec/ec_backend.c", "EC_BACKEND"),
    ("crypto/ec/ec_asn1.c", "EC_ASN1"),
    # `ec_ameth.c` is the `EVP_PKEY_ASN1_METHOD` object unit; the one export of it this stratum
    # lands, `ECParameters_print`, is the `EC_KEY_PRINT_PARAM` arm of its static
    # `do_EC_KEY_print`, and it raises at `:292` and `:341`. Covering the unit gives those two
    # coordinates their generated constants rather than a hand-written reconstruction.
    ("crypto/ec/ec_ameth.c", "EC_AMETH"),
    # `eck_prn.c` is the deprecated printer unit `ec_asn1.c`'s parameter family is printed
    # through: `ECPKParameters_print`/`_print_fp` and `ECParameters_print_fp` raise their own
    # records. Its four sites are the coordinates the printer transcription reproduces.
    ("crypto/ec/eck_prn.c", "ECK_PRN"),
    # `crypto/param_build_set.c` is the unit `ec_backend.c` reaches for its four
    # `ossl_param_build_set_*` helpers. D330 and D331 both recorded it as having no crate
    # module and no plan row; 8.7's backend is the first caller that needs it, so it joins the
    # covered set here. Its one reason is `CRYPTO_R_TOO_SMALL_BUFFER` (`cryptoerr.h`, already in
    # the resolver's include set).
    ("crypto/param_build_set.c", "PARAM_BUILD_SET"),
    # Phase 9's `crypto/rand` subsystem. **The subsystem set, not a selection of convenient
    # files**, for `crypto/rsa`'s reason and one more of its own: this stratum's symbols are
    # raised from inside bodies whose declaring header belongs to *earlier* strata (`BN_rand`,
    # `RSA_generate_key_ex`, `EVP_SealInit`), so a coordinate's `file` string is what tells a
    # caller which unit refused -- and the units are the ones the random layer owns.
    #
    # `rand_uniform.c` is deliberately **absent**: its two functions are arithmetic over a
    # `RAND_POOL` and raise nothing, so an entry for it would read as coverage that does not
    # exist -- the reasoning `mdc2_prov.c` is named under above. `rand_err.c` is absent for the
    # generator's own reason: it is the generated reason-string table, not a raiser.
    # `rand_engine.c` does not exist in 3.6.4; the ENGINE arms live in `rand_lib.c` and are
    # Phase 13's, but the file is covered here because the sites it raises from are Phase 9's.
    ("crypto/rand/rand_lib.c", "RAND_LIB"),
    ("crypto/rand/randfile.c", "RANDFILE"),
    ("crypto/rand/rand_pool.c", "RAND_POOL"),
    # `prov_seed.c` **joins the covered set in D309, when its first caller lands**: it is the
    # core-side half of the provider seeding up-call (`ossl_rand_get_entropy` and its seven
    # siblings), and `$CRYPTO` in `crypto/rand/build.info:4` says it is built on this profile. Its
    # two raises are `ERR_LIB_RAND`/`ERR_R_RAND_LIB` on the pool-allocation failure path, which is
    # exactly the kind of coordinate a caller sees rather than a diagnostic.
    ("crypto/rand/prov_seed.c", "PROV_SEED"),
    # Phase 9's `providers/implementations/rands` subsystem -- the four `OSSL_OP_RAND` rows and
    # the seed sources they draw on. `crngt.c` is **not** in this list because it is not in the
    # authority: the continuous test is `fips_crng_test.c`, which is, and the correction is
    # recorded in `forensics/prerequisites.json`'s `units` block (docs/DECISIONS.md D294).
    ("providers/implementations/rands/drbg.c", "PROV_DRBG"),
    ("providers/implementations/rands/drbg_ctr.c", "PROV_DRBG_CTR"),
    ("providers/implementations/rands/drbg_hash.c", "PROV_DRBG_HASH"),
    ("providers/implementations/rands/drbg_hmac.c", "PROV_DRBG_HMAC"),
    ("providers/implementations/rands/seed_src.c", "PROV_SEED_SRC"),
    ("providers/implementations/rands/test_rng.c", "PROV_TEST_RNG"),
    ("providers/implementations/rands/fips_crng_test.c", "PROV_FIPS_CRNG_TEST"),
    # Deliberately *not* covered yet, with the stratum that owns each: the AEAD
    # template `ciphercommon_gcm.c.in` (9: no row reaches it, because
    # `deflt_ciphers[]` carries no GCM row in this crate -- D234); the
    # `cipher_chacha20*.c`, `cipher_aes_siv.c`, `cipher_aes_gcm_siv.c` (9, or
    # 8.3's blocked rows: `cipher_aes_siv.c`'s three rows needed the `OSSL_OP_MAC`
    # CMAC row, which landed with them (D241); `cipher_aes_gcm_siv.c` and
    # `cipher_chacha20*.c` (9);
    # whose `ciphercommon_ccm.c.in` sibling *is* covered above, because the three
    # AES-CCM rows land in 8.3);
    # `cipher_cts.c` and the `cipher_*_cts.inc` pair raise nothing and are absent for
    # that reason; `cipher_aria_hw.c`, `cipher_sm4_xts.c`, `cipher_des.c`,
    # `cipher_rc2.c`, `cipher_rc4_hmac_md5.c`, `cipher_rc5.c` and the
    # `cipher_aes_cbc_hmac_*` family are not this profile's rows. Their raises stay
    # visible as uncovered sites until those strata land.
    #
    # Phase 13 staging: `crypto/ui/ui_lib.c` and `crypto/ui/ui_openssl.c`. The `UI` program lands
    # ahead of its stratum (D350) because `EVP_read_pw_string_min` is its only caller and the PEM
    # hinge needs it. Both files raise from surfaces the crate now has: `ui_lib.c`'s twenty sites
    # are `ERR_LIB_UI` with the generic `ERR_R_*` codes and the eleven `UI_R_*` ones, and
    # `ui_openssl.c`'s single reachable site is the `tcgetattr` errno fallback
    # (`UI_R_UNKNOWN_TTYGET_ERRNO_VALUE`). `ui_err.c` defines no site (it is the reason-string
    # `ui_err.c` defines no site (it is the reason-string
    # table) and `ui_null.c` raises nothing, so neither is covered.
    ("crypto/ui/ui_lib.c", "UI_LIB"),
    ("crypto/ui/ui_openssl.c", "UI_OPENSSL"),
    # Phase 8.9's `crypto/pem/pem_all.c`. The `IMPLEMENT_PEM_*` expansions raise nothing --
    # they are one call to a `PEM_ASN1_*` -- so the two sites are the two hand-written readers'
    # (`PEM_read_bio_DHparams` at `:201`, `PEM_read_DHparams` at `:214`).
    ("crypto/pem/pem_all.c", "PEM_ALL"),
    # Phase 10 staging: `crypto/passphrase.c`, the passphrase bridge the encode/decode
    # framework stands on (D356). Its four `ossl_pw_set_*` setters and the `static
    # do_ui_passphrase` processor raise `ERR_LIB_CRYPTO` with `ERR_R_PASSED_NULL_PARAMETER`,
    # `ERR_R_UI_LIB` and `ERR_R_INTERRUPTED_OR_CANCELLED`; the eleven sites in
    # `ossl_pw_get_passphrase` and its five one-call callers are covered by this file's entry
    # even though those six functions are withheld, because a raise site is a property of the
    # translation unit rather than of the subset a stratum has reached.
    ("crypto/passphrase.c", "PASSPHRASE"),
    # Phase 10 staging: the three `crypto/encode_decode/encoder_*` units (D360). Each raises from
    # bodies the encoder landing writes, so the three entries land with the code. Their counts are
    # 6 (`encoder_meth.c`), 14 (`encoder_lib.c`) and 2 (`encoder_pkey.c`).
    ("crypto/encode_decode/encoder_meth.c", "ENCODER_METH"),
    ("crypto/encode_decode/encoder_lib.c", "ENCODER_LIB"),
    ("crypto/encode_decode/encoder_pkey.c", "ENCODER_PKEY"),
    # Phase 10's `crypto/encode_decode/decoder_meth.c` -- the `OSSL_DECODER` object. It raises
    # `ERR_R_INVALID_PROVIDER_FUNCTIONS` at `:280` and `ERR_R_PASSED_NULL_PARAMETER` at its four
    # accessor sites.
    ("crypto/encode_decode/decoder_meth.c", "DECODER_METH"),
    # Phase 10's `crypto/encode_decode/decoder_lib.c` -- the `OSSL_DECODER_INSTANCE` and
    # `OSSL_DECODER_CTX` object layer.
    ("crypto/encode_decode/decoder_lib.c", "DECODER_LIB"),
    # Phase 10's `crypto/encode_decode/decoder_pkey.c` -- the decoder cache, the pkey half that
    # `OSSL_DECODER_CTX_new_for_pkey` builds, and the four passphrase setters.
    ("crypto/encode_decode/decoder_pkey.c", "DECODER_PKEY"),
    # Phase 10.1's first provider codec unit: `providers/implementations/encode_decode/
    # encode_key2text.c` -- the text-encoder tables and the six per-key-type printers behind them.
    # It is a plain `.c`, so its `__FILE__` carries the source-tree prefix. Its raises are the
    # null-argument guards of the six printers and the `PROV_R_NOT_A_PRIVATE_KEY`,
    # `PROV_R_NOT_A_PUBLIC_KEY`, `PROV_R_NOT_PARAMETERS` and `PROV_R_INVALID_KEY` refusals they
    # carry, plus `ERR_R_CRYPTO_LIB` in `rsa_to_text`; the `ERR_R_PASSED_INVALID_ARGUMENT` in the
    # `MAKE_TEXT_ENCODER` body is a preprocessor macro's and is not attributed, the same rule
    # `encode_key2any.c`'s `MAKE_ENCODER` is under.
    ("providers/implementations/encode_decode/encode_key2text.c", "PROV_ENCODE_KEY2TEXT"),
    # Phase 10.1's second provider codec unit: `providers/implementations/encode_decode/
    # encode_key2blob.c` -- the `EC`/`SM2` public-point blob encoders. It is a plain `.c`, so its
    # `__FILE__` carries the source-tree prefix. Its one raise is the
    # `ERR_R_PASSED_INVALID_ARGUMENT` in the `MAKE_BLOB_ENCODER` body, and a local raise macro is
    # attributed to each invocation line (`:175`, `:177`) -- the same rule `MAKE_TEXT_ENCODER` is
    # under above.
    ("providers/implementations/encode_decode/encode_key2blob.c", "PROV_ENCODE_KEY2BLOB"),
    # Phase 10.1's first provider codec *decoder* unit: `providers/implementations/encode_decode/
    # decode_epki2pki.c` -- the `EncryptedPrivateKeyInfo`-to-`PrivateKeyInfo` engine. It is a
    # generated `.c.in`, so its `__FILE__` carries only the build-relative path. Its two raises are
    # the machine-generated `set_ctx_params` parser's `PROV_R_REPEATED_PARAMETER` (`:87`) and the
    # passphrase refusal's `PROV_R_UNABLE_TO_GET_PASSPHRASE` (`:179`).
    ("providers/implementations/encode_decode/decode_epki2pki.c", "PROV_DECODE_EPKI2PKI"),
    # Phase 10.1's PQC codec closure units (D435). The first is
    # `providers/implementations/encode_decode/ml_common_codecs.c`, the shared SPKI/PKCS#8 format
    # tables and `ossl_ml_common_pkcs8_fmt_order`: its one raise is the `PROV_R_ML_DSA_NO_FORMAT`
    # "no %s private key %s formats are enabled" refusal (`:83`). It is a plain `.c`, so its
    # `__FILE__` carries the source-tree prefix.
    ("providers/implementations/encode_decode/ml_common_codecs.c", "ML_COMMON_CODECS"),
    # The second is `providers/implementations/encode_decode/ml_kem_codecs.c`, the ML-KEM d2i/i2d
    # PKCS#8 and PUBKEY codecs and the text printer. It is a plain `.c`. Its raises are the
    # `PROV_R_BAD_ENCODING`/`PROV_R_UNEXPECTED_KEY_PARAMETERS`/`PROV_R_ML_KEM_NO_FORMAT`/
    # `PROV_R_INVALID_KEY`/`PROV_R_NOT_A_PUBLIC_KEY`/`PROV_R_NOT_A_PRIVATE_KEY` decoders, the
    # `ERR_LIB_OSSL_DECODER`/`ERR_LIB_OSSL_ENCODER` `ERR_R_INTERNAL_ERROR` encode paths, the
    # `ERR_LIB_PROV` `ERR_R_INTERNAL_ERROR` output-format arms, the `ERR_R_PASSED_NULL_PARAMETER`
    # null guard of the printer and its `PROV_R_MISSING_KEY` "no %s key material available" arm.
    ("providers/implementations/encode_decode/ml_kem_codecs.c", "ML_KEM_CODECS"),
    # The third is `providers/implementations/encode_decode/ml_dsa_codecs.c`, the ML-DSA sibling:
    # the same decoder and encoder raises, `PROV_R_ML_DSA_NO_FORMAT` in place of ML-KEM's, and the
    # printer's `ERR_LIB_PROV` `ERR_R_PASSED_NULL_PARAMETER` guard and two `PROV_R_MISSING_KEY` arms.
    ("providers/implementations/encode_decode/ml_dsa_codecs.c", "ML_DSA_CODECS"),
    # Phase 10 staging: `crypto/pkcs12/p12_decr.c`, the PBE buffer crypt and the ASN.1 decrypt/
    # encrypt pair `PKCS8_decrypt` reads an `EncryptedPrivateKeyInfo` through (D368). Its
    # thirteen sites are `ERR_LIB_PKCS12` with `ERR_R_EVP_LIB`, `ERR_R_PASSED_NULL_PARAMETER`,
    # `ERR_R_INTERNAL_ERROR` and the four `PKCS12_R_*` reasons, so covering the unit gives the
    # decrypt path its coordinates rather than a hand-written reconstruction. `p12_p8d.c` is
    # **not** covered: `PKCS8_decrypt`/`PKCS8_decrypt_ex` raise nothing, so an entry for it would
    # read as coverage that does not exist -- the reasoning `mdc2_prov.c` is named under above.
    ("crypto/pkcs12/p12_decr.c", "PKCS12"),
    # Phase 11 staging: `crypto/x509/x509_att.c`, the `X509at_add1_attr*` family
    # `PKCS8_pkey_add1_attr*` is one call each to (D368). Its twenty-six sites are
    # `ERR_LIB_X509`, mostly `ERR_R_PASSED_NULL_PARAMETER`, `ERR_R_CRYPTO_LIB` and
    # `ERR_R_ASN1_LIB` with the four `X509_R_*` reasons the duplicate/unknown-name/wrong-type
    # refusals carry.
    ("crypto/x509/x509_att.c", "X509_ATT"),
    # Phase 11 staging: `crypto/x509/x_pubkey.c`, the `X509_PUBKEY` object layer the `d2i`/
    # `i2d` public-key family and `ossl_d2i_PUBKEY_legacy` are written in (D369). Its
    # twenty-four sites are `ERR_LIB_X509`, `ERR_LIB_ASN1` and `ERR_LIB_EVP` with the generic
    # `ERR_R_*` codes, `ASN1_R_DECODE_ERROR`, `EVP_R_DECODE_ERROR` and the three `X509_R_*`
    # refusals (`PUBLIC_KEY_ENCODE_ERROR`, `METHOD_NOT_SUPPORTED`, `UNSUPPORTED_ALGORITHM`).
    # D349 had the unit deliberately absent because the four functions then landed raised
    # nothing; the completion is what changes that.
    ("crypto/x509/x_pubkey.c", "X509_PUBKEY"),
    # Phase 8.7's ECX key objects (D372): `crypto/ec/ecx_key.c` (the `ECX_KEY` object and
    # `ossl_ecx_compute_key`) and `crypto/ec/ecx_backend.c` (the backend the legacy methods and
    # the providers share). The first is `ERR_LIB_PROV` with the four `PROV_R_*` reasons on the
    # X25519/X448 agreement path; the second is `ERR_LIB_EC` with `ERR_R_EC_LIB`,
    # `EC_R_INVALID_ENCODING` and `EC_R_FAILED_MAKING_PUBLIC_KEY`.
    ("crypto/ec/ecx_key.c", "ECX_KEY"),
    ("crypto/ec/ecx_backend.c", "ECX_BACKEND"),
    # `crypto/ec/ecx_meth.c` (D372), the two method tables' four rows: `EVP_PKEY_ASN1_METHOD`
    # and `EVP_PKEY_METHOD` for X25519, X448, Ed25519 and Ed448. Its thirty-one sites are
    # `ERR_LIB_EC`, `ERR_LIB_DH` and `ERR_LIB_ASN1` with the `EC_R_*`/`ERR_R_*` reasons the two
    # tables' decode, sign and key-generation arms carry.
    ("crypto/ec/ecx_meth.c", "ECX_METH"),
]

# Raise macros, in the forms the authority actually spells them. `ERR_raise`
# and `ERR_raise_data` are the modern entry points; `<LIB>err(...)` are the
# per-library aliases defined in err.h and both route through `ERR_raise_data`.
RAISE_RE = re.compile(
    r"(?P<macro>ERR_raise_data|ERR_raise|[A-Z][A-Za-z0-9_]*err)\s*\("
)
# A resolvable library argument must be a constant, and a resolvable reason must
# be an upper-case constant. Anything else means the match is not a plain raise
# site and is recorded as unattributed instead of guessed.
#
# "A constant" and not "an `ERR_LIB_*` constant", because the authority has seven
# sites that pass a *reason* constant where the library argument belongs:
# `ERR_raise(ERR_R_EVP_LIB, ERR_R_UNSUPPORTED)` in `crypto/evp/exchange.c` at
# 572, 601, 607 and 619, `crypto/evp/kdf_lib.c` at 241 and `crypto/evp/mac_lib.c`
# at 119 and 130. The old form of this pattern rejected them, which was right
# about the *shape* -- a library argument that is not a library constant is
# usually a call spelled inside a macro body -- and wrong about these seven,
# which are real, reachable, observable raise sites in Phase 7's surface.
#
# Emitting them is a transcription and not an interpretation. `ERR_set_error`
# packs `(lib & ERR_LIB_MASK) << ERR_LIB_OFFSET`, and the authority's
# `ERR_LIB_MASK` is `0xFF`, so `ERR_R_EVP_LIB` -- a reason, `(4|ERR_RFLAG_COMMON)`
# = `0x80004` -- contributes exactly the `4` that `ERR_LIB_EVP` would: the seven
# sites are observationally identical to `ERR_raise(ERR_LIB_EVP, ...)`. The
# resolved value is still what is emitted rather than the low byte, because the
# table records what the authority's own argument evaluates to and the masking
# belongs to the code that consumes it.
LIB_CONST_RE = re.compile(r"^(?:ERR_LIB|ERR_R)_[A-Z0-9_]+$")
REASON_CONST_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
# A function definition: a line starting at column 0 that introduces a
# parameter list. The name is the identifier immediately before the parenthesis
# group that *encloses* what follows, because a return type may itself contain a
# parenthesised macro invocation — `LHASH_OF(CONF_VALUE) *CONF_load(` — and a
# lazy-match regex would then report the macro's name (`HASH_OF`) instead of the
# function's, and `_dopr` as `dopr`. Six sites were mis-attributed that way; the
# coordinates are readable through `ERR_get_error_all`, so they are contract.
IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
# A file-local object-like or function-like `#define`.
DEFINE_RE = re.compile(r"^#\s*define\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b(?P<body>.*)$")


def definition_name(line: str) -> str | None:
    """The function a column-0 definition line introduces, or None.

    Rejects preprocessor lines, comment continuations, declarations and macro
    invocations that stand alone. A definition macro that wraps a single
    identifier (`DEFINE_RUN_ONCE_STATIC(do_init_module_list_lock)`) reports the
    identifier, because that is what `__func__` expands to inside the body it
    generates.
    """
    if not line or line[0] in " \t#{}*/":
        return None
    stripped = line.rstrip()
    if stripped.endswith(";"):
        return None
    candidates: list[tuple[str, int]] = []
    for i, ch in enumerate(stripped):
        if ch != "(":
            continue
        j = i - 1
        while j >= 0 and stripped[j] in " \t":
            j -= 1
        k = j
        while k >= 0 and (stripped[k].isalnum() or stripped[k] == "_"):
            k -= 1
        name = stripped[k + 1 : j + 1]
        if name and (name[0].isalpha() or name[0] == "_"):
            candidates.append((name, i))
    for name, open_idx in candidates:
        depth = 0
        j = open_idx
        while j < len(stripped):
            if stripped[j] == "(":
                depth += 1
            elif stripped[j] == ")":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        closed = j < len(stripped)
        tail = stripped[j + 1 :].lstrip() if closed else ""
        # Either the group closes the line (a one-line signature), is followed
        # only by a body, or is still open (a wrapped signature). Anything else
        # is a call nested in a return type or an argument list.
        if not closed or j == len(stripped) - 1 or tail.startswith("{"):
            if closed and name.upper() == name and any(c.isalpha() for c in name):
                inner = stripped[open_idx + 1 : j].strip()
                if IDENT_RE.fullmatch(inner):
                    return inner
            return name
    return None


def relpath_prefix(source: Path, build_dir: Path) -> str:
    """The `__FILE__` prefix the authority's compiler would have used.

    Files the build compiles from the *source tree* are passed to the compiler with a
    path under that tree, so the compiler records `relpath(source_tree, build_dir)` in
    front of the source-relative path. Files the build *generates* into the build tree
    (the `.c.in` templates: `ciphercommon.c`, `ciphercommon_gcm.c`,
    `ciphercommon_ccm.c`, `digestcommon.c`) are compiled from the build directory and
    record only their build-relative path. Both are derived from the admitted build
    record by `resolve_site_source`, never hand-typed: the spellings differ and the ERR
    record carries the compiler's, so getting this wrong is a contract divergence.
    """
    return os.path.relpath(str(source.resolve()), str(build_dir.resolve())) + "/"


def resolve_site_source(auth, build_dir: Path, rel_source: str) -> tuple[Path, bool]:
    """Where a covered translation unit's text actually lives, and whether it is generated.

    Returns `(path, generated)`. A unit present in the admitted source tree is read from
    there and its `__FILE__` carries the source-tree prefix. A unit the build generates
    into the build tree (the `.c.in` templates) is read from the build tree and its
    `__FILE__` is the bare build-relative path -- `ciphercommon.c` is the first of these,
    and the authority's own ERR records show the two spellings differ. Reading the `.in`
    instead would attribute every site to a line number the compiler never saw, because
    the template expands `produce_param_decoder` into ~130 generated lines before the
    first real function.
    """
    path = auth.source / rel_source
    if path.is_file():
        return path, False
    generated = build_dir / rel_source
    if generated.is_file():
        return generated, True
    raise SystemExit(f"authority file missing: {path} (and not generated at {generated})")


def definition_name_joined(lines: list[str], i: int) -> str | None:
    """`definition_name` for a definition whose parameter list wraps to the next line.

    `produce_param_decoder` emits

        static int ossl_cipher_generic_get_params_decoder
            (const OSSL_PARAM *p, struct ..._st *r)

    so the name sits at the end of one line and the `(` opens the next. Scanning the
    single line finds no parameter list and the whole generated decoder, and every
    `ERR_raise_data` inside it, appears to have no enclosing function. Joining exactly
    one continuation line when the first holds no `(` recovers the name. It is the
    authority's `__func__`, so it is contract.
    """
    got = definition_name(lines[i])
    if got is not None:
        return got
    if i + 1 >= len(lines) or "(" in lines[i]:
        return None
    nxt = lines[i + 1].lstrip()
    if not nxt.startswith("("):
        return None
    return definition_name(lines[i].rstrip() + " " + nxt)


def enclosing_function(lines: list[str], lineno: int) -> str:
    """Name of the function whose body contains `lineno` (1-based)."""
    best = None
    for i in range(lineno - 1):
        got = definition_name_joined(lines, i)
        if got:
            best = got
    if best is None:
        raise SystemExit(f"no enclosing function found for line {lineno}")
    # `if`/`while`/`for` at column 0 are not function definitions; the authority
    # never spells them at column 0, but guard anyway.
    if best in {"if", "while", "for", "switch", "return"}:
        raise SystemExit(f"refusing to treat `{best}` as a function at {lineno}")
    return best


def balanced_call(lines: list[str], start: int, open_paren_col: int) -> tuple[str, int]:
    """Return (call text, first line number) for the call beginning at `start`."""
    text = ""
    depth = 0
    first = start
    i = start
    col = open_paren_col
    while i < len(lines):
        line = lines[i]
        seg = line[col:] if i == start else line
        text += (" " if text else "") + seg
        for ch in seg:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    return text, first
        i += 1
        col = 0
    raise SystemExit(f"unbalanced call starting at line {start + 1}")


def split_args(call: str) -> list[str]:
    """Split the macro argument list, respecting nesting and string literals."""
    inner = call[call.index("(") + 1 : call.rindex(")")]
    out, cur, depth, in_str, in_chr, esc = [], "", 0, False, False, False
    for ch in inner:
        if in_str:
            cur += ch
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if in_chr:
            cur += ch
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == "'":
                in_chr = False
            continue
        if ch == '"':
            in_str = True
            cur += ch
        elif ch == "'":
            in_chr = True
            cur += ch
        elif ch in "([{":
            depth += 1
            cur += ch
        elif ch in ")]}":
            depth -= 1
            cur += ch
        elif ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def mask_comments_and_strings(text: str) -> str:
    """Blank out C comments and string/char literals, preserving line structure.

    A raise macro mentioned inside a comment or a string is not a raise site --
    `bio_lib.c` carries an example spelling of `ERR_raise(...)` in a comment --
    and scanning the raw text would register it as one. Masking preserves every
    byte offset and every newline, so line numbers and column indices computed
    against the masked text address the same places in the raw text.
    """
    out: list[str] = []
    i = 0
    n = len(text)
    state = "code"
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if state == "code":
            if c == "/" and nxt == "*":
                out.append("  ")
                i += 2
                state = "block"
                continue
            if c == "/" and nxt == "/":
                out.append("  ")
                i += 2
                state = "line"
                continue
            if c == '"':
                out.append(" ")
                i += 1
                state = "string"
                continue
            if c == "'":
                out.append(" ")
                i += 1
                state = "char"
                continue
            out.append(c)
            i += 1
        elif state == "block":
            if c == "*" and nxt == "/":
                out.append("  ")
                i += 2
                state = "code"
                continue
            out.append("\n" if c == "\n" else " ")
            i += 1
        elif state == "line":
            if c == "\n":
                out.append("\n")
                state = "code"
            else:
                out.append(" ")
            i += 1
        else:  # string or char
            if c == "\\":
                out.append(" ")
                if i + 1 < n:
                    out.append("\n" if nxt == "\n" else " ")
                i += 2
                continue
            if (state == "string" and c == '"') or (state == "char" and c == "'"):
                out.append(" ")
                i += 1
                state = "code"
                continue
            out.append("\n" if c == "\n" else " ")
            i += 1
    return "".join(out)


def local_raise_macros(masked: list[str]) -> tuple[dict[str, dict], set[int]]:
    """The file's own `#define`s whose body *is* a raise, and the lines they own.

    `crypto/params.c` spells its eight refusals as macros:

        #define err_out_of_range      \\
            ERR_raise(ERR_LIB_CRYPTO, \\
                CRYPTO_R_PARAM_VALUE_TOO_LARGE_FOR_DESTINATION)

    and uses them bare -- `err_out_of_range;` -- at forty-odd call sites. The
    raise those sites *record* is not at the definition: `ERR_raise_data` expands
    `OPENSSL_FILE`/`OPENSSL_LINE`/`OPENSSL_FUNC` at the point of expansion, so the
    coordinates a caller reads back through `ERR_get_error_all` are the
    **invocation** line and the enclosing function, with the macro's own
    `lib`/`reason`. Scanning only for the macro names `ERR_raise`,
    `ERR_raise_data` and `<LIB>err` therefore finds the definition and none of
    the invocations, and the whole file appears to raise nothing.

    This reads the definition to learn the `lib`/`reason` pair and returns it, so
    the main scan can attribute each bare invocation. A macro whose body is not a
    resolvable raise is not returned: it is not this tool's business.

    The second return value is every line the preprocessor owns -- each `#`
    directive together with its backslash continuations. Those lines must be
    skipped by the main scan, because a raise *inside* a macro body is not a call
    site: its `ERR_raise(` line carries no `__LINE__` of its own, and attributing
    a site to it would invent a coordinate the authority never records and would
    attribute it to whatever function name happened to precede the `#define`.
    """
    out: dict[str, dict] = {}
    preproc: set[int] = set()
    i = 0
    while i < len(masked):
        if masked[i].lstrip().startswith("#"):
            j = i
            body = masked[i]
            while body.rstrip().endswith("\\") and j + 1 < len(masked):
                j += 1
                body = body.rstrip()[:-1] + " " + masked[j]
            preproc.update(range(i, j + 1))
        m = DEFINE_RE.match(masked[i])
        if not m:
            i += 1
            continue
        name = m.group("name")
        # A backslash-continued definition is one logical line. Join it so the
        # raise call inside the body can be parsed as a whole call.
        body = m.group("body")
        j = i
        while body.rstrip().endswith("\\") and j + 1 < len(masked):
            j += 1
            body = body.rstrip()[:-1] + " " + masked[j]
        i = j + 1
        rm = RAISE_RE.search(body)
        if rm is None:
            continue
        call = body[rm.start():]
        args = split_args(call)
        if len(args) < 2:
            continue
        macro = rm.group("macro")
        if macro in ("ERR_raise", "ERR_raise_data"):
            lib_sym, reason_sym = args[0], args[1]
        else:
            lib_sym, reason_sym = "ERR_LIB_" + macro[: -len("err")], args[0]
        if not LIB_CONST_RE.match(lib_sym):
            continue
        out[name] = {
            "macro": macro,
            "lib_symbol": lib_sym,
            "reason_symbol": reason_sym,
            "dynamic_reason": not REASON_CONST_RE.match(reason_sym),
        }
    return out, preproc


def scan(path: Path) -> tuple[list[dict], list[dict]]:
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    masked = mask_comments_and_strings(text).splitlines()
    if len(masked) != len(lines):
        raise SystemExit(f"{path}: masking changed the line count")
    file_macros, preproc = local_raise_macros(masked)
    macro_re = (
        re.compile(r"\b(" + "|".join(re.escape(n) for n in file_macros) + r")\b")
        if file_macros
        else None
    )
    sites: list[dict] = []
    unattributed: list[dict] = []
    i = 0
    while i < len(lines):
        # A raise behind a preprocessor definition is a macro body, not a call.
        if i in preproc:
            i += 1
            continue
        # A bare invocation of one of this file's own raise macros is a site at
        # *this* line: see `local_raise_macros`.
        if macro_re is not None:
            mm = macro_re.search(masked[i])
            if mm is not None:
                spec = file_macros[mm.group(1)]
                sites.append(
                    {
                        "file": rel(path),
                        "line": i + 1,
                        "function": enclosing_function(lines, i + 1),
                        "macro": spec["macro"],
                        "lib_symbol": spec["lib_symbol"],
                        "reason_symbol": (
                            None if spec["dynamic_reason"] else spec["reason_symbol"]
                        ),
                        "dynamic_reason": spec["dynamic_reason"],
                        "data_format": None,
                        "via_macro": mm.group(1),
                    }
                )
                i += 1
                continue
        m = RAISE_RE.search(masked[i])
        if not m:
            i += 1
            continue
        call, _ = balanced_call(lines, i, m.start())
        args = split_args(call)
        if len(args) < 2:
            raise SystemExit(f"{path}:{i + 1}: unparsable raise call: {call!r}")
        macro = m.group("macro")
        # ERR_raise / <LIB>err carry an implicit library argument for the
        # per-library aliases; those are defined in err.h as
        # `#define X509err(f, r) ERR_raise_data(ERR_LIB_X509, (r), NULL)`,
        # so the explicit two-argument form only occurs for ERR_raise itself.
        if macro == "ERR_raise" or macro == "ERR_raise_data":
            lib_sym, reason_sym = args[0], args[1]
        else:
            lib_sym = "ERR_LIB_" + macro[: -len("err")]
            reason_sym = args[0]
        # A raise whose *library* is not a plain `ERR_LIB_*` constant is not a
        # site this tool can attribute; it is a call spelled inside a macro body
        # or an expression. Such a match is recorded as *unattributed* rather
        # than emitted with a guessed constant. A raise whose *reason* is a
        # runtime expression (`get_last_socket_error()`, `errno`, `(int)-l`) is a
        # real site: the file/line/function are still the authority's, and only
        # the reason is supplied at run time, so it is emitted with
        # `dynamic_reason` set and resolved by the caller.
        if not LIB_CONST_RE.match(lib_sym):
            unattributed.append(
                {
                    "file": rel(path),
                    "line": i + 1,
                    "macro": macro,
                    "lib_symbol": lib_sym,
                    "reason_symbol": reason_sym,
                    "call": call.strip(),
                }
            )
            i += 1
            continue
        dynamic_reason = not REASON_CONST_RE.match(reason_sym)
        sites.append(
            {
                "file": rel(path),
                "line": i + 1,
                "function": enclosing_function(lines, i + 1),
                "macro": macro,
                "lib_symbol": lib_sym,
                "reason_symbol": None if dynamic_reason else reason_sym,
                "dynamic_reason": dynamic_reason,
                "data_format": args[2] if len(args) > 2 and "NULL" not in args[2] else None,
            }
        )
        i += 1
    return sites, unattributed


def resolve_symbols(authority, symbols: list[str], work: Path) -> dict[str, int]:
    """Ask the authority's own headers what each symbol evaluates to."""
    src = work / "resolve_err_symbols.c"
    body = [
        "#include <openssl/err.h>",
        "#include <openssl/cryptoerr.h>",
        "#include <openssl/asn1err.h>",
        "#include <openssl/bioerr.h>",
        "#include <openssl/bnerr.h>",
        "#include <openssl/conferr.h>",
        "#include <openssl/objectserr.h>",
        "#include <openssl/x509err.h>",
        # `X509V3_R_*` lives in its own header, not in `x509err.h`; the
        # `crypto/x509` translation units raise from that library.
        "#include <openssl/x509v3err.h>",
        "#include <openssl/sslerr.h>",
    # Phase 7 needs three more installed reason families: `EVP_R_*` for `crypto/evp/`,
    # `PEM_R_*` for the two `crypto/pem/` files the plan's 7.5 row owns, and
    # `RSA_R_*` for the two sites in `p_lib.c` that raise one. All three are installed
    # headers, so no `internal/` fallthrough is added for this stratum.
    "#include <openssl/evperr.h>",
    "#include <openssl/pemerr.h>",
    "#include <openssl/rsaerr.h>",
    # Phase 9 needs `RAND_R_*` for `crypto/rand/rand_lib.c`, `randfile.c` and `rand_pool.c`.
    # `randerr.h` is an installed header, so this is `evperr.h`'s case again rather than the
    # `internal/` fallthrough below. `RAND_R_*` is the one family whose *library* is also the
    # stratum: the sites are the random layer raising about itself.
    "#include <openssl/randerr.h>",
    # Phase 7.6 needs `PROV_R_*`: `crypto/hpke/hpke_util.c` is a `crypto/` file whose
    # helpers raise with the *provider* library's reasons (they are shared with the
    # `providers/` implementations that use the same labelled extract/expand).
    # `proverr.h` is an installed header, so this is the same fallthrough-free case as
    # `evperr.h` above.
    "#include <openssl/proverr.h>",
    # Phase 8.5 needs `DH_R_*` and `DSA_R_*`: `crypto/ffc/ffc_params_validate.c` and
    # `ffc_params_generate.c` are the shared FFC units, so the DH and DSA layers' reasons are
    # raised from a `crypto/ffc/` file -- `internal/ffc.h`'s own comment says as much about the
    # `FFC_CHECK_*`/`FFC_ERROR_*` split. Both headers are installed, so this is `evperr.h`'s
    # fallthrough-free case again.
    "#include <openssl/dherr.h>",
    "#include <openssl/dsaerr.h>",
    # Phase 8.7 needs `EC_R_UNKNOWN_GROUP`: `crypto/ec/ec_curve.c`'s
    # `EC_GROUP_new_by_curve_name_ex` raises it through `ERR_raise_data`, and the resolver reads
    # the reason's *name* out of the header rather than its value out of the build, so the header
    # has to be in this include set even though the constructor itself is `open` in this slice.
    # `ecerr.h` is installed, so this is `dherr.h`'s case again.
    "#include <openssl/ecerr.h>",
    # Phase 13 staging: `UI_R_*` for `crypto/ui/ui_lib.c` and `ui_openssl.c`, which D350
    # transcribes. `uierr.h` is an installed header, so this is `ecerr.h`'s case again.
    "#include <openssl/uierr.h>",
    # Phase 10 staging: `OSSL_ENCODER_R_*` for `crypto/encode_decode/encoder_lib.c`, whose
    # "no encoders were found" refusal is the message D361 transcribes. `encodererr.h` is an
    # installed header, so this is `ecerr.h`'s case again.
    "#include <openssl/encodererr.h>",
    # Phase 10 staging: `OSSL_DECODER_R_*` for `crypto/encode_decode/decoder_lib.c`,
    # whose "no decoders were found" refusal is the message D364 transcribes.
    # `decodererr.h` is an installed header, so this is `ecerr.h`'s case again.
    "#include <openssl/decodererr.h>",
    # Phase 10 staging: `PKCS12_R_*` for `crypto/pkcs12/p12_decr.c`, whose decrypt/encrypt
    # refusals D368 transcribes. `pkcs12err.h` is an installed header, so this is `ecerr.h`'s
    # case again.
    "#include <openssl/pkcs12err.h>",
        # `PROP_R_*` is the first reason family this table needs that lives in an
        # *internal* header rather than an installed one: `internal/propertyerr.h`,
        # which the property grammar raises from. It is resolveable because the
        # authority's source tree is committed; the source include directory is added
        # **after** the installed one below, so every `openssl/...` header still comes
        # from the built prefix and only `internal/...` falls through to the tree the
        # build was made from.
        "#include <internal/propertyerr.h>",
        # `DSO_R_*` likewise, from `internal/dsoerr.h`.
        "#include <internal/dsoerr.h>",
        # `SM2_R_*` for `crypto/sm2/sm2_key.c`, the SM2 private-key range check D389 transcribes.
        # `crypto/sm2err.h` is not installed either, so it is the same fallthrough case as
        # `internal/propertyerr.h`; it carries the `crypto/` prefix rather than `internal/`.
        "#include <crypto/sm2err.h>",
        "#include <stdio.h>",
        "",
    ]
    body.append("int main(void) {")
    seen = []
    for s in symbols:
        if s in seen:
            continue
        seen.append(s)
        body.append(f'    printf("{s}=%lld\\n", (long long)({s}));')
    body.append("    return 0;")
    body.append("}")
    write_text(src, "\n".join(body) + "\n")

    binp = work / "resolve_err_symbols"
    include = authority.prefix / "include"
    libdir = authority.libdir
    res = run(
        [
            "clang",
            "-std=c11",
            "-I",
            str(include),
            # Second, so it only supplies what the prefix does not have: the
            # `internal/` headers, which are not installed but are the source the
            # authority's own objects were compiled against.
            "-I",
            str(authority.source / "include"),
            "-o",
            str(binp),
            str(src),
        ]
    )
    if not res.ok:
        raise SystemExit("failed to build the symbol resolver:\n" + res.stderr)
    res = run([str(binp)])
    if not res.ok:
        raise SystemExit("failed to run the symbol resolver:\n" + res.stderr)
    out: dict[str, int] = {}
    for line in res.stdout.splitlines():
        if "=" not in line:
            continue
        k, _, v = line.partition("=")
        out[k.strip()] = int(v.strip())
    missing = [s for s in seen if s not in out]
    if missing:
        raise SystemExit("symbols not resolved: " + ", ".join(missing))
    return out


def const_name(stem: str, line: int) -> str:
    return f"{stem}_{line}"

def c_literal(s: str) -> str:
    return 'c"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def render_rust(doc: dict, prefix: str) -> str:
    sites = doc["body"]["sites"]
    out = [
        "//! Authority `ERR_raise*` coordinates — GENERATED, do not edit.",
        "//!",
        "//! Regenerate with `forensics/tools/gen_err_raise_sites.py` inside the",
        "//! court container. See `forensics/atlas/err-raise-sites.json` for the",
        "//! machine-readable form and `docs/ERROR_MODEL.md` for why these strings",
        "//! are part of the contract rather than private archaeology.",
        "//!",
        f"//! Authority: `{doc['authority']}`; `__FILE__` prefix `{prefix}`.",
        "",
        "use core::ffi::{c_int, CStr};",
        "",
        "/// One recorded authority raise site: where `ERR_raise*` ran, and with what.",
        "#[derive(Clone, Copy, Debug)]",
        "pub(crate) struct ErrSite {",
        "    /// `OPENSSL_FILE` — the authority's translation unit, as the compiler",
        "    /// spelled it. Derived from the admitted build record, never hand-typed.",
        "    pub file: &'static CStr,",
        "    /// `OPENSSL_LINE`.",
        "    pub line: c_int,",
        "    /// `OPENSSL_FUNC`.",
        "    pub func: &'static CStr,",
        "    /// `ERR_GET_LIB` of the raised code, which is the value of the site's",
        "    /// library argument after `ERR_LIB_MASK`. The two differ only at the",
        "    /// seven sites whose argument is a reason constant; see `LIB_CONST_RE`.",
        "    pub lib: c_int,",
        "    /// The raised reason, including any `ERR_RFLAG_*` bits.",
        "    pub reason: c_int,",
        "    /// True when the authority supplies the reason at run time (a syscall",
        "    /// error or a computed value) rather than from a header constant; the",
        "    /// `reason` field is then 0 and the caller passes the real value to",
        "    /// `raise_site_dynamic`.",
        "    pub dynamic_reason: bool,",
        "}",
        "",
    ]
    for s in sites:
        label = s["reason_symbol"] or s["macro"] + " dynamic reason"
        out.append(
            f"/// `{s['function']}` at `{s['rel_source']}:{s['line']}` ({label})."
        )
        out.append(f"pub(crate) const {s['const_name']}: ErrSite = ErrSite {{")
        # One field per line, which is what `rustfmt` produces for a literal whose
        # fields do not fit its 18-column single-line budget. Packing two fields
        # per line made the generated file fail `cargo fmt --all -- --check`, and
        # `err_sites.rs` is *not* in `evidence_determinism.py`'s compared set, so
        # nothing caught it until CI did. Emitting the formatted shape removes the
        # manual `cargo fmt` step the pipeline silently depended on.
        out.append(f"    file: {c_literal(s['file'])},")
        out.append(f"    line: {s['line']},")
        out.append('    func: ' + c_literal(s['function']) + ',')
        out.append(f"    lib: {s['lib']},")
        out.append(f"    reason: {s['reason']},")
        out.append(f"    dynamic_reason: {str(bool(s['dynamic_reason'])).lower()},")
        out.append("};")
        out.append("")

    out += [
        "/// Every recorded raise site, in authority source order.",
        "///",
        "/// This is the complete inventory for the covered files, including the",
        "/// allocation-failure arms that no runtime path in this crate can reach",
        "/// (`sk_reserve`'s growth overflow and the two `ex_data.c` stack-growth",
        "/// arms). It is kept so that coverage accounting, cross-checks and the",
        "/// court's negative controls can enumerate the authority's sites rather",
        "/// than a subset, which is also why it carries an `allow`: it is a",
        "/// reference table, not a call site.",
        "#[allow(dead_code)]",
        "pub(crate) static ALL: &[ErrSite] = &[",
    ]
    for s in sites:
        out.append(f"    {s['const_name']},")
    out += ["];", ""]
    return "\n".join(out)


def check_against_artefact() -> int:
    """The weak tier: verify the generated Rust against the committed artefact.

    Used when the authority's source tree is absent, which is the case on every runner that has
    only the repository. It catches a hand-edited `err_sites.rs` and a JSON that has drifted
    from it. It cannot catch the authority having changed -- the authority is pinned by archive
    hash elsewhere, and the court, which has the tree, re-derives. Which tier ran is printed,
    because a check that silently weakens is the thing this project exists not to have.

    The pairing is exact rather than approximate: `render_rust` is a pure function of the
    committed document, so the comparison is the generator run against its own output.
    """
    if not OUT_JSON.is_file():
        print(
            f"[{GENERATOR}] neither the authority's source tree nor "
            f"{rel(OUT_JSON)} is present; nothing can be checked",
            file=sys.stderr,
        )
        return 1
    doc = json.loads(OUT_JSON.read_text(encoding="utf-8"))
    prefix = doc["body"]["prefix"]
    expected = render_rust(doc, prefix)
    actual = OUT_RS.read_text(encoding="utf-8") if OUT_RS.is_file() else ""
    if actual != expected:
        # The first differing line, because a 900-line coordinate table makes "they differ"
        # useless on its own.
        exp_lines = expected.splitlines()
        act_lines = actual.splitlines()
        at = next(
            (i for i, (a, b) in enumerate(zip(act_lines, exp_lines)) if a != b),
            min(len(act_lines), len(exp_lines)),
        )
        print(
            f"[{GENERATOR}] {rel(OUT_RS)} does not match {rel(OUT_JSON)}; the generated "
            f"file was edited by hand, the artefact is stale, or the renderer changed "
            f"without the artefact being regenerated. First difference at line {at + 1}:\n"
            f"  committed: {act_lines[at] if at < len(act_lines) else '<eof>'}\n"
            f"  from json: {exp_lines[at] if at < len(exp_lines) else '<eof>'}",
            file=sys.stderr,
        )
        return 1
    print(
        f"[err-raise-sites] ok (weak tier, authority source absent): {rel(OUT_RS)} "
        f"matches {rel(OUT_JSON)}"
    )
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)

    # The authority's source tree is **not committed**, so a runner that has only the
    # repository cannot re-derive the coordinates. That is a fact about this project and not a
    # defect: the tree is ~100 MB and the courts, which do have it, are where re-derivation
    # happens. So the generator has two tiers, and which one ran is printed rather than
    # implied:
    #
    #   * authority present  -> re-derive from the covered units' `ERR_raise*` sites (the
    #                           strong tier, and the one the pipeline and the CI `courts` job
    #                           use);
    #   * authority absent   -> check `err_sites.rs` against the committed JSON, which still
    #                           catches a hand-edit or a stale artefact.
    #
    # This is `gen_ctype_table.py`'s pattern, and it is here for the same reason: the pair is
    # what `evidence_determinism.py` needs in order to run this generator on a runner that has
    # no authority. That was D109's open half -- the generator was in neither the determinism
    # list nor the portability list, so `err_sites.rs` could drift silently. Adding it to only
    # one of the two lists would have replaced one silent gap with two (docs/DECISIONS.md
    # D109, closed by D135).
    first_source = COVERED_FILES[0][0]
    if not (resolve_authority(args.authority).source / first_source).is_file():
        return check_against_artefact()

    auth = resolve_authority(args.authority)
    build_dir = authority_build_dir(auth.id)
    prefix = relpath_prefix(auth.source, build_dir)

    all_sites: list[dict] = []
    unattributed: list[dict] = []
    input_paths: dict[str, Path] = {}
    for rel_source, stem in COVERED_FILES:
        path, generated = resolve_site_source(auth, build_dir, rel_source)
        found, skipped = scan(path)
        input_paths[rel_source] = path
        for s in found:
            s["rel_source"] = rel_source
            # The `__FILE__` the authority's compiler saw. A source-tree file is spelled
            # with the `relpath(source_tree, build_dir)` prefix; a build-generated file
            # is spelled with only its build-relative path. Derived from which tree the
            # file is actually in, not typed.
            s["file"] = rel_source if generated else prefix + rel_source
            s["generated"] = generated
            s["const_name"] = const_name(stem, s["line"])
            all_sites.append(s)
        for s in skipped:
            s["rel_source"] = rel_source
            unattributed.append(s)

    symbols: list[str] = []
    for s in all_sites:
        symbols.append(s["lib_symbol"])
        if s["reason_symbol"] is not None:
            symbols.append(s["reason_symbol"])
    symbols.append("ERR_LIB_SYS")

    work = REPO_ROOT / "court" / "err-sites"
    work.mkdir(parents=True, exist_ok=True)
    values = resolve_symbols(auth, symbols, work)

    for s in all_sites:
        s["lib"] = values[s["lib_symbol"]]
        s["reason"] = values[s["reason_symbol"]] if s["reason_symbol"] else 0

    body = {
        "prefix": prefix,
        "covered_files": [f for f, _ in COVERED_FILES],
        "sites": all_sites,
        "unattributed": unattributed,
        "counts": {"sites": len(all_sites), "unattributed": len(unattributed)},
        "note": (
            "`file` is the authority's `__FILE__` string, derived from "
            "relpath(source_tree, build_dir) of the admitted build record. It is "
            "a build artifact of the forensic build, reproduced exactly rather "
            "than normalized away, so the candidate's ERR records compare "
            "byte-for-byte with the authority's."
        ),
        "via_macro_note": (
            "A site carries `via_macro` **only** when the raise was spelled as a "
            "call to a macro the same file defines (`crypto/params.c`'s "
            "`err_out_of_range` and its seven siblings), in which case the value "
            "names that macro. The `line`/`function` are then the *invocation*, "
            "because `ERR_raise_data` expands `OPENSSL_LINE`/`OPENSSL_FUNC` where "
            "it is used; `lib_symbol`/`reason_symbol` come from the definition. "
            "Sites without the key were spelled as a direct `ERR_raise*` call. "
            "The key is absent rather than null so that adding the macro form "
            "left every previously recorded site byte-identical."
        ),
    }

    inputs = [
        InputRef(name=f"authority:{rel_source}", path=input_paths[rel_source])
        for rel_source, _ in COVERED_FILES
    ]
    build_records = REPO_ROOT / "forensics" / "authorities" / "BUILD_RECORDS.json"
    if build_records.exists():
        inputs.append(InputRef(name="build-record", path=build_records))
    doc = envelope(
        kind="err-raise-sites",
        authority=auth.id,
        inputs=inputs,
        body=body,
        generator=GENERATOR,
    )
    write_json(OUT_JSON, doc)
    write_text(OUT_RS, render_rust(doc, prefix))

    print(f"[err-raise-sites] authority={auth.id} prefix={prefix}")
    print(f"  sites: {len(all_sites)}")
    if unattributed:
        print(f"  unattributed (recorded, not emitted): {len(unattributed)}")
        for s in unattributed:
            print(f"    {s['rel_source']}:{s['line']:<5} {s['macro']}("
                  f"{s['lib_symbol']}, {s['reason_symbol']})")
    print(f"  wrote {rel(OUT_JSON)}")
    print(f"  wrote {rel(OUT_RS)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
