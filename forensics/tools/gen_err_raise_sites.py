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
    # `a_verify.c`, `x_algor.c`, `x_pkey.c` (Phase 11); the rest of `asn_mime.c`
    # (Phase 12; the file is covered above for the two coordinates a Phase 5 export
    # raises);
    # `nsseq.c` (Phase 13). Their raises are visible as uncovered sites in
    # `forensics/atlas/err-raise-sites.json` until those phases land.
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
    ("providers/implementations/macs/siphash_prov.c", "PROV_SIPHASH_PROV"),
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
    # Phase 7.6 needs `PROV_R_*`: `crypto/hpke/hpke_util.c` is a `crypto/` file whose
    # helpers raise with the *provider* library's reasons (they are shared with the
    # `providers/` implementations that use the same labelled extract/expand).
    # `proverr.h` is an installed header, so this is the same fallthrough-free case as
    # `evperr.h` above.
    "#include <openssl/proverr.h>",
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
