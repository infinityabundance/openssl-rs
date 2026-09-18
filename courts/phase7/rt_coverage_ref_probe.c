/*
 * RT-EVP-REF -- reference basis for the EVP plane's unexercised entries,
 * and nothing more.
 *
 * This probe exists to answer exactly one question the court coverage atlas asks:
 * *is this implemented export referenced by a probe that ran and produced a
 * transcript?* It takes each remaining symbol's address through a `volatile` table,
 * prints one `name=nonnull` line per symbol, and stops. **It does not call any of
 * them, and therefore does not claim any behaviour about them.** A symbol covered
 * only here is recorded in `forensics/atlas/court-coverage.json` at basis
 * `referenced`, never `called`, and the atlas's `claim` says the weaker thing on
 * purpose: the name is referenced by a probe that ran, which is not the same as
 * every arm of the name having been driven. See docs/DECISIONS.md D199.
 *
 * It is a probe rather than a source scan because a source scan cannot tell a call
 * from a comment, and because the dynamic linker resolves the reference only if the
 * candidate distribution actually defines the name -- the link is the evidence.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>

/* Declared here rather than through the installed headers: the headers a given
 * symbol is promised by are not this probe's subject, and a self-declaration cannot
 * be reshaped by a header the candidate has not finished. The link is what proves
 * the name exists. */
extern void EVP_ASYM_CIPHER_do_all_provided(void);
extern void EVP_ASYM_CIPHER_fetch(void);
extern void EVP_ASYM_CIPHER_free(void);
extern void EVP_ASYM_CIPHER_get0_description(void);
extern void EVP_ASYM_CIPHER_get0_name(void);
extern void EVP_ASYM_CIPHER_get0_provider(void);
extern void EVP_ASYM_CIPHER_gettable_ctx_params(void);
extern void EVP_ASYM_CIPHER_is_a(void);
extern void EVP_ASYM_CIPHER_names_do_all(void);
extern void EVP_ASYM_CIPHER_settable_ctx_params(void);
extern void EVP_ASYM_CIPHER_up_ref(void);
extern void EVP_CIPHER_CTX_buf_noconst(void);
extern void EVP_CIPHER_CTX_cipher(void);
extern void EVP_CIPHER_CTX_get1_cipher(void);
extern void EVP_CIPHER_CTX_get_algor_params(void);
extern void EVP_CIPHER_CTX_iv(void);
extern void EVP_CIPHER_CTX_iv_noconst(void);
extern void EVP_CIPHER_CTX_original_iv(void);
extern void EVP_CIPHER_CTX_set_algor_params(void);
extern void EVP_CIPHER_CTX_set_app_data(void);
extern void EVP_CIPHER_CTX_set_cipher_data(void);
extern void EVP_CIPHER_get_asn1_iv(void);
extern void EVP_CIPHER_meth_get_get_asn1_params(void);
extern void EVP_CIPHER_meth_get_set_asn1_params(void);
extern void EVP_CIPHER_meth_set_cleanup(void);
extern void EVP_CIPHER_meth_set_ctrl(void);
extern void EVP_CIPHER_meth_set_get_asn1_params(void);
extern void EVP_CIPHER_meth_set_init(void);
extern void EVP_CIPHER_meth_set_set_asn1_params(void);
extern void EVP_CIPHER_set_asn1_iv(void);
extern void EVP_CipherInit(void);
extern void EVP_CipherInit_SKEY(void);
extern void EVP_CipherInit_ex2(void);
extern void EVP_DecryptInit(void);
extern void EVP_DecryptInit_ex2(void);
extern void EVP_DigestInit(void);
extern void EVP_DigestInit_ex2(void);
extern void EVP_DigestVerifyInit(void);
extern void EVP_EncryptInit(void);
extern void EVP_EncryptInit_ex2(void);
extern void EVP_KDF_CTX_set_SKEY(void);
extern void EVP_KDF_derive_SKEY(void);
extern void EVP_KDF_up_ref(void);
extern void EVP_KEM_do_all_provided(void);
extern void EVP_KEM_fetch(void);
extern void EVP_KEM_free(void);
extern void EVP_KEM_get0_description(void);
extern void EVP_KEM_get0_name(void);
extern void EVP_KEM_get0_provider(void);
extern void EVP_KEM_gettable_ctx_params(void);
extern void EVP_KEM_is_a(void);
extern void EVP_KEM_names_do_all(void);
extern void EVP_KEM_settable_ctx_params(void);
extern void EVP_KEM_up_ref(void);
extern void EVP_KEYEXCH_do_all_provided(void);
extern void EVP_KEYEXCH_fetch(void);
extern void EVP_KEYEXCH_free(void);
extern void EVP_KEYEXCH_get0_description(void);
extern void EVP_KEYEXCH_get0_name(void);
extern void EVP_KEYEXCH_get0_provider(void);
extern void EVP_KEYEXCH_gettable_ctx_params(void);
extern void EVP_KEYEXCH_is_a(void);
extern void EVP_KEYEXCH_names_do_all(void);
extern void EVP_KEYEXCH_settable_ctx_params(void);
extern void EVP_KEYEXCH_up_ref(void);
extern void EVP_MAC_init_SKEY(void);
extern void EVP_MAC_up_ref(void);
extern void EVP_MD_CTX_copy(void);
extern void EVP_MD_do_all_provided(void);
extern void EVP_MD_meth_dup(void);
extern void EVP_MD_meth_set_cleanup(void);
extern void EVP_MD_meth_set_copy(void);
extern void EVP_MD_meth_set_ctrl(void);
extern void EVP_MD_meth_set_final(void);
extern void EVP_MD_meth_set_update(void);
extern void EVP_PBE_scrypt(void);
extern void EVP_PBE_scrypt_ex(void);
extern void EVP_PKEY_CTX_add1_hkdf_info(void);
extern void EVP_PKEY_CTX_add1_tls1_prf_seed(void);
extern void EVP_PKEY_CTX_ctrl(void);
extern void EVP_PKEY_CTX_ctrl_str(void);
extern void EVP_PKEY_CTX_ctrl_uint64(void);
extern void EVP_PKEY_CTX_dup(void);
extern void EVP_PKEY_CTX_get0_libctx(void);
extern void EVP_PKEY_CTX_get0_peerkey(void);
extern void EVP_PKEY_CTX_get0_pkey(void);
extern void EVP_PKEY_CTX_get0_propq(void);
extern void EVP_PKEY_CTX_get0_provider(void);
extern void EVP_PKEY_CTX_get1_id(void);
extern void EVP_PKEY_CTX_get1_id_len(void);
extern void EVP_PKEY_CTX_get_app_data(void);
extern void EVP_PKEY_CTX_get_cb(void);
extern void EVP_PKEY_CTX_get_data(void);
extern void EVP_PKEY_CTX_get_keygen_info(void);
extern void EVP_PKEY_CTX_get_operation(void);
extern void EVP_PKEY_CTX_get_params(void);
extern void EVP_PKEY_CTX_get_signature_md(void);
extern void EVP_PKEY_CTX_gettable_params(void);
extern void EVP_PKEY_CTX_hex2ctrl(void);
extern void EVP_PKEY_CTX_is_a(void);
extern void EVP_PKEY_CTX_md(void);
extern void EVP_PKEY_CTX_new(void);
extern void EVP_PKEY_CTX_new_id(void);
extern void EVP_PKEY_CTX_set0_keygen_info(void);
extern void EVP_PKEY_CTX_set1_hkdf_key(void);
extern void EVP_PKEY_CTX_set1_hkdf_salt(void);
extern void EVP_PKEY_CTX_set1_id(void);
extern void EVP_PKEY_CTX_set1_pbe_pass(void);
extern void EVP_PKEY_CTX_set1_scrypt_salt(void);
extern void EVP_PKEY_CTX_set1_tls1_prf_secret(void);
extern void EVP_PKEY_CTX_set_app_data(void);
extern void EVP_PKEY_CTX_set_cb(void);
extern void EVP_PKEY_CTX_set_data(void);
extern void EVP_PKEY_CTX_set_hkdf_md(void);
extern void EVP_PKEY_CTX_set_hkdf_mode(void);
extern void EVP_PKEY_CTX_set_kem_op(void);
extern void EVP_PKEY_CTX_set_mac_key(void);
extern void EVP_PKEY_CTX_set_params(void);
extern void EVP_PKEY_CTX_set_scrypt_N(void);
extern void EVP_PKEY_CTX_set_scrypt_maxmem_bytes(void);
extern void EVP_PKEY_CTX_set_scrypt_p(void);
extern void EVP_PKEY_CTX_set_scrypt_r(void);
extern void EVP_PKEY_CTX_set_signature_md(void);
extern void EVP_PKEY_CTX_set_tls1_prf_md(void);
extern void EVP_PKEY_CTX_settable_params(void);
extern void EVP_PKEY_CTX_str2ctrl(void);
extern void EVP_PKEY_asn1_add0(void);
extern void EVP_PKEY_asn1_add_alias(void);
extern void EVP_PKEY_asn1_copy(void);
extern void EVP_PKEY_asn1_find(void);
extern void EVP_PKEY_asn1_find_str(void);
extern void EVP_PKEY_asn1_free(void);
extern void EVP_PKEY_asn1_get0(void);
extern void EVP_PKEY_asn1_get0_info(void);
extern void EVP_PKEY_asn1_get_count(void);
extern void EVP_PKEY_asn1_new(void);
extern void EVP_PKEY_asn1_set_check(void);
extern void EVP_PKEY_asn1_set_ctrl(void);
extern void EVP_PKEY_asn1_set_free(void);
extern void EVP_PKEY_asn1_set_get_priv_key(void);
extern void EVP_PKEY_asn1_set_get_pub_key(void);
extern void EVP_PKEY_asn1_set_item(void);
extern void EVP_PKEY_asn1_set_param(void);
extern void EVP_PKEY_asn1_set_param_check(void);
extern void EVP_PKEY_asn1_set_private(void);
extern void EVP_PKEY_asn1_set_public(void);
extern void EVP_PKEY_asn1_set_public_check(void);
extern void EVP_PKEY_asn1_set_security_bits(void);
extern void EVP_PKEY_asn1_set_set_priv_key(void);
extern void EVP_PKEY_asn1_set_set_pub_key(void);
extern void EVP_PKEY_asn1_set_siginf(void);
extern void EVP_PKEY_auth_decapsulate_init(void);
extern void EVP_PKEY_auth_encapsulate_init(void);
extern void EVP_PKEY_check(void);
extern void EVP_PKEY_cmp(void);
extern void EVP_PKEY_cmp_parameters(void);
extern void EVP_PKEY_decapsulate(void);
extern void EVP_PKEY_decapsulate_init(void);
extern void EVP_PKEY_decrypt(void);
extern void EVP_PKEY_decrypt_init(void);
extern void EVP_PKEY_decrypt_init_ex(void);
extern void EVP_PKEY_derive(void);
extern void EVP_PKEY_derive_SKEY(void);
extern void EVP_PKEY_derive_init(void);
extern void EVP_PKEY_derive_init_ex(void);
extern void EVP_PKEY_derive_set_peer(void);
extern void EVP_PKEY_derive_set_peer_ex(void);
extern void EVP_PKEY_dup(void);
extern void EVP_PKEY_encapsulate(void);
extern void EVP_PKEY_encapsulate_init(void);
extern void EVP_PKEY_encrypt(void);
extern void EVP_PKEY_encrypt_init(void);
extern void EVP_PKEY_encrypt_init_ex(void);
extern void EVP_PKEY_eq(void);
extern void EVP_PKEY_export(void);
extern void EVP_PKEY_fromdata_settable(void);
extern void EVP_PKEY_generate(void);
extern void EVP_PKEY_get0_asn1(void);
extern void EVP_PKEY_get0_description(void);
extern void EVP_PKEY_get0_provider(void);
extern void EVP_PKEY_get0_type_name(void);
extern void EVP_PKEY_get_bn_param(void);
extern void EVP_PKEY_get_ex_data(void);
extern void EVP_PKEY_get_int_param(void);
extern void EVP_PKEY_get_params(void);
extern void EVP_PKEY_get_size_t_param(void);
extern void EVP_PKEY_get_utf8_string_param(void);
extern void EVP_PKEY_gettable_params(void);
extern void EVP_PKEY_is_a(void);
extern void EVP_PKEY_keygen(void);
extern void EVP_PKEY_meth_get_check(void);
extern void EVP_PKEY_meth_get_cleanup(void);
extern void EVP_PKEY_meth_get_copy(void);
extern void EVP_PKEY_meth_get_ctrl(void);
extern void EVP_PKEY_meth_get_decrypt(void);
extern void EVP_PKEY_meth_get_derive(void);
extern void EVP_PKEY_meth_get_digest_custom(void);
extern void EVP_PKEY_meth_get_digestsign(void);
extern void EVP_PKEY_meth_get_digestverify(void);
extern void EVP_PKEY_meth_get_encrypt(void);
extern void EVP_PKEY_meth_get_init(void);
extern void EVP_PKEY_meth_get_keygen(void);
extern void EVP_PKEY_meth_get_param_check(void);
extern void EVP_PKEY_meth_get_paramgen(void);
extern void EVP_PKEY_meth_get_public_check(void);
extern void EVP_PKEY_meth_get_sign(void);
extern void EVP_PKEY_meth_get_signctx(void);
extern void EVP_PKEY_meth_get_verify(void);
extern void EVP_PKEY_meth_get_verify_recover(void);
extern void EVP_PKEY_meth_get_verifyctx(void);
extern void EVP_PKEY_meth_set_check(void);
extern void EVP_PKEY_meth_set_cleanup(void);
extern void EVP_PKEY_meth_set_copy(void);
extern void EVP_PKEY_meth_set_ctrl(void);
extern void EVP_PKEY_meth_set_decrypt(void);
extern void EVP_PKEY_meth_set_derive(void);
extern void EVP_PKEY_meth_set_digest_custom(void);
extern void EVP_PKEY_meth_set_digestsign(void);
extern void EVP_PKEY_meth_set_digestverify(void);
extern void EVP_PKEY_meth_set_encrypt(void);
extern void EVP_PKEY_meth_set_init(void);
extern void EVP_PKEY_meth_set_keygen(void);
extern void EVP_PKEY_meth_set_param_check(void);
extern void EVP_PKEY_meth_set_paramgen(void);
extern void EVP_PKEY_meth_set_public_check(void);
extern void EVP_PKEY_meth_set_sign(void);
extern void EVP_PKEY_meth_set_signctx(void);
extern void EVP_PKEY_meth_set_verify(void);
extern void EVP_PKEY_meth_set_verify_recover(void);
extern void EVP_PKEY_meth_set_verifyctx(void);
extern void EVP_PKEY_pairwise_check(void);
extern void EVP_PKEY_param_check(void);
extern void EVP_PKEY_param_check_quick(void);
extern void EVP_PKEY_parameters_eq(void);
extern void EVP_PKEY_paramgen(void);
extern void EVP_PKEY_paramgen_init(void);
extern void EVP_PKEY_private_check(void);
extern void EVP_PKEY_public_check(void);
extern void EVP_PKEY_public_check_quick(void);
extern void EVP_PKEY_save_parameters(void);
extern void EVP_PKEY_set_bn_param(void);
extern void EVP_PKEY_set_ex_data(void);
extern void EVP_PKEY_set_int_param(void);
extern void EVP_PKEY_set_octet_string_param(void);
extern void EVP_PKEY_set_params(void);
extern void EVP_PKEY_set_size_t_param(void);
extern void EVP_PKEY_set_utf8_string_param(void);
extern void EVP_PKEY_settable_params(void);
extern void EVP_PKEY_todata(void);
extern void EVP_PKEY_type_names_do_all(void);
extern void EVP_PKEY_up_ref(void);
extern void EVP_SIGNATURE_do_all_provided(void);
extern void EVP_SIGNATURE_get0_description(void);
extern void EVP_SIGNATURE_get0_name(void);
extern void EVP_SIGNATURE_get0_provider(void);
extern void EVP_SIGNATURE_gettable_ctx_params(void);
extern void EVP_SIGNATURE_is_a(void);
extern void EVP_SIGNATURE_names_do_all(void);
extern void EVP_SIGNATURE_settable_ctx_params(void);
extern void EVP_SIGNATURE_up_ref(void);
extern void EVP_SKEYMGMT_up_ref(void);
extern void EVP_SKEY_export(void);
extern void EVP_get_pw_prompt(void);
extern void EVP_set_pw_prompt(void);

static const void *volatile refs[] = {
    (const void *) EVP_ASYM_CIPHER_do_all_provided,
    (const void *) EVP_ASYM_CIPHER_fetch,
    (const void *) EVP_ASYM_CIPHER_free,
    (const void *) EVP_ASYM_CIPHER_get0_description,
    (const void *) EVP_ASYM_CIPHER_get0_name,
    (const void *) EVP_ASYM_CIPHER_get0_provider,
    (const void *) EVP_ASYM_CIPHER_gettable_ctx_params,
    (const void *) EVP_ASYM_CIPHER_is_a,
    (const void *) EVP_ASYM_CIPHER_names_do_all,
    (const void *) EVP_ASYM_CIPHER_settable_ctx_params,
    (const void *) EVP_ASYM_CIPHER_up_ref,
    (const void *) EVP_CIPHER_CTX_buf_noconst,
    (const void *) EVP_CIPHER_CTX_cipher,
    (const void *) EVP_CIPHER_CTX_get1_cipher,
    (const void *) EVP_CIPHER_CTX_get_algor_params,
    (const void *) EVP_CIPHER_CTX_iv,
    (const void *) EVP_CIPHER_CTX_iv_noconst,
    (const void *) EVP_CIPHER_CTX_original_iv,
    (const void *) EVP_CIPHER_CTX_set_algor_params,
    (const void *) EVP_CIPHER_CTX_set_app_data,
    (const void *) EVP_CIPHER_CTX_set_cipher_data,
    (const void *) EVP_CIPHER_get_asn1_iv,
    (const void *) EVP_CIPHER_meth_get_get_asn1_params,
    (const void *) EVP_CIPHER_meth_get_set_asn1_params,
    (const void *) EVP_CIPHER_meth_set_cleanup,
    (const void *) EVP_CIPHER_meth_set_ctrl,
    (const void *) EVP_CIPHER_meth_set_get_asn1_params,
    (const void *) EVP_CIPHER_meth_set_init,
    (const void *) EVP_CIPHER_meth_set_set_asn1_params,
    (const void *) EVP_CIPHER_set_asn1_iv,
    (const void *) EVP_CipherInit,
    (const void *) EVP_CipherInit_SKEY,
    (const void *) EVP_CipherInit_ex2,
    (const void *) EVP_DecryptInit,
    (const void *) EVP_DecryptInit_ex2,
    (const void *) EVP_DigestInit,
    (const void *) EVP_DigestInit_ex2,
    (const void *) EVP_DigestVerifyInit,
    (const void *) EVP_EncryptInit,
    (const void *) EVP_EncryptInit_ex2,
    (const void *) EVP_KDF_CTX_set_SKEY,
    (const void *) EVP_KDF_derive_SKEY,
    (const void *) EVP_KDF_up_ref,
    (const void *) EVP_KEM_do_all_provided,
    (const void *) EVP_KEM_fetch,
    (const void *) EVP_KEM_free,
    (const void *) EVP_KEM_get0_description,
    (const void *) EVP_KEM_get0_name,
    (const void *) EVP_KEM_get0_provider,
    (const void *) EVP_KEM_gettable_ctx_params,
    (const void *) EVP_KEM_is_a,
    (const void *) EVP_KEM_names_do_all,
    (const void *) EVP_KEM_settable_ctx_params,
    (const void *) EVP_KEM_up_ref,
    (const void *) EVP_KEYEXCH_do_all_provided,
    (const void *) EVP_KEYEXCH_fetch,
    (const void *) EVP_KEYEXCH_free,
    (const void *) EVP_KEYEXCH_get0_description,
    (const void *) EVP_KEYEXCH_get0_name,
    (const void *) EVP_KEYEXCH_get0_provider,
    (const void *) EVP_KEYEXCH_gettable_ctx_params,
    (const void *) EVP_KEYEXCH_is_a,
    (const void *) EVP_KEYEXCH_names_do_all,
    (const void *) EVP_KEYEXCH_settable_ctx_params,
    (const void *) EVP_KEYEXCH_up_ref,
    (const void *) EVP_MAC_init_SKEY,
    (const void *) EVP_MAC_up_ref,
    (const void *) EVP_MD_CTX_copy,
    (const void *) EVP_MD_do_all_provided,
    (const void *) EVP_MD_meth_dup,
    (const void *) EVP_MD_meth_set_cleanup,
    (const void *) EVP_MD_meth_set_copy,
    (const void *) EVP_MD_meth_set_ctrl,
    (const void *) EVP_MD_meth_set_final,
    (const void *) EVP_MD_meth_set_update,
    (const void *) EVP_PBE_scrypt,
    (const void *) EVP_PBE_scrypt_ex,
    (const void *) EVP_PKEY_CTX_add1_hkdf_info,
    (const void *) EVP_PKEY_CTX_add1_tls1_prf_seed,
    (const void *) EVP_PKEY_CTX_ctrl,
    (const void *) EVP_PKEY_CTX_ctrl_str,
    (const void *) EVP_PKEY_CTX_ctrl_uint64,
    (const void *) EVP_PKEY_CTX_dup,
    (const void *) EVP_PKEY_CTX_get0_libctx,
    (const void *) EVP_PKEY_CTX_get0_peerkey,
    (const void *) EVP_PKEY_CTX_get0_pkey,
    (const void *) EVP_PKEY_CTX_get0_propq,
    (const void *) EVP_PKEY_CTX_get0_provider,
    (const void *) EVP_PKEY_CTX_get1_id,
    (const void *) EVP_PKEY_CTX_get1_id_len,
    (const void *) EVP_PKEY_CTX_get_app_data,
    (const void *) EVP_PKEY_CTX_get_cb,
    (const void *) EVP_PKEY_CTX_get_data,
    (const void *) EVP_PKEY_CTX_get_keygen_info,
    (const void *) EVP_PKEY_CTX_get_operation,
    (const void *) EVP_PKEY_CTX_get_params,
    (const void *) EVP_PKEY_CTX_get_signature_md,
    (const void *) EVP_PKEY_CTX_gettable_params,
    (const void *) EVP_PKEY_CTX_hex2ctrl,
    (const void *) EVP_PKEY_CTX_is_a,
    (const void *) EVP_PKEY_CTX_md,
    (const void *) EVP_PKEY_CTX_new,
    (const void *) EVP_PKEY_CTX_new_id,
    (const void *) EVP_PKEY_CTX_set0_keygen_info,
    (const void *) EVP_PKEY_CTX_set1_hkdf_key,
    (const void *) EVP_PKEY_CTX_set1_hkdf_salt,
    (const void *) EVP_PKEY_CTX_set1_id,
    (const void *) EVP_PKEY_CTX_set1_pbe_pass,
    (const void *) EVP_PKEY_CTX_set1_scrypt_salt,
    (const void *) EVP_PKEY_CTX_set1_tls1_prf_secret,
    (const void *) EVP_PKEY_CTX_set_app_data,
    (const void *) EVP_PKEY_CTX_set_cb,
    (const void *) EVP_PKEY_CTX_set_data,
    (const void *) EVP_PKEY_CTX_set_hkdf_md,
    (const void *) EVP_PKEY_CTX_set_hkdf_mode,
    (const void *) EVP_PKEY_CTX_set_kem_op,
    (const void *) EVP_PKEY_CTX_set_mac_key,
    (const void *) EVP_PKEY_CTX_set_params,
    (const void *) EVP_PKEY_CTX_set_scrypt_N,
    (const void *) EVP_PKEY_CTX_set_scrypt_maxmem_bytes,
    (const void *) EVP_PKEY_CTX_set_scrypt_p,
    (const void *) EVP_PKEY_CTX_set_scrypt_r,
    (const void *) EVP_PKEY_CTX_set_signature_md,
    (const void *) EVP_PKEY_CTX_set_tls1_prf_md,
    (const void *) EVP_PKEY_CTX_settable_params,
    (const void *) EVP_PKEY_CTX_str2ctrl,
    (const void *) EVP_PKEY_asn1_add0,
    (const void *) EVP_PKEY_asn1_add_alias,
    (const void *) EVP_PKEY_asn1_copy,
    (const void *) EVP_PKEY_asn1_find,
    (const void *) EVP_PKEY_asn1_find_str,
    (const void *) EVP_PKEY_asn1_free,
    (const void *) EVP_PKEY_asn1_get0,
    (const void *) EVP_PKEY_asn1_get0_info,
    (const void *) EVP_PKEY_asn1_get_count,
    (const void *) EVP_PKEY_asn1_new,
    (const void *) EVP_PKEY_asn1_set_check,
    (const void *) EVP_PKEY_asn1_set_ctrl,
    (const void *) EVP_PKEY_asn1_set_free,
    (const void *) EVP_PKEY_asn1_set_get_priv_key,
    (const void *) EVP_PKEY_asn1_set_get_pub_key,
    (const void *) EVP_PKEY_asn1_set_item,
    (const void *) EVP_PKEY_asn1_set_param,
    (const void *) EVP_PKEY_asn1_set_param_check,
    (const void *) EVP_PKEY_asn1_set_private,
    (const void *) EVP_PKEY_asn1_set_public,
    (const void *) EVP_PKEY_asn1_set_public_check,
    (const void *) EVP_PKEY_asn1_set_security_bits,
    (const void *) EVP_PKEY_asn1_set_set_priv_key,
    (const void *) EVP_PKEY_asn1_set_set_pub_key,
    (const void *) EVP_PKEY_asn1_set_siginf,
    (const void *) EVP_PKEY_auth_decapsulate_init,
    (const void *) EVP_PKEY_auth_encapsulate_init,
    (const void *) EVP_PKEY_check,
    (const void *) EVP_PKEY_cmp,
    (const void *) EVP_PKEY_cmp_parameters,
    (const void *) EVP_PKEY_decapsulate,
    (const void *) EVP_PKEY_decapsulate_init,
    (const void *) EVP_PKEY_decrypt,
    (const void *) EVP_PKEY_decrypt_init,
    (const void *) EVP_PKEY_decrypt_init_ex,
    (const void *) EVP_PKEY_derive,
    (const void *) EVP_PKEY_derive_SKEY,
    (const void *) EVP_PKEY_derive_init,
    (const void *) EVP_PKEY_derive_init_ex,
    (const void *) EVP_PKEY_derive_set_peer,
    (const void *) EVP_PKEY_derive_set_peer_ex,
    (const void *) EVP_PKEY_dup,
    (const void *) EVP_PKEY_encapsulate,
    (const void *) EVP_PKEY_encapsulate_init,
    (const void *) EVP_PKEY_encrypt,
    (const void *) EVP_PKEY_encrypt_init,
    (const void *) EVP_PKEY_encrypt_init_ex,
    (const void *) EVP_PKEY_eq,
    (const void *) EVP_PKEY_export,
    (const void *) EVP_PKEY_fromdata_settable,
    (const void *) EVP_PKEY_generate,
    (const void *) EVP_PKEY_get0_asn1,
    (const void *) EVP_PKEY_get0_description,
    (const void *) EVP_PKEY_get0_provider,
    (const void *) EVP_PKEY_get0_type_name,
    (const void *) EVP_PKEY_get_bn_param,
    (const void *) EVP_PKEY_get_ex_data,
    (const void *) EVP_PKEY_get_int_param,
    (const void *) EVP_PKEY_get_params,
    (const void *) EVP_PKEY_get_size_t_param,
    (const void *) EVP_PKEY_get_utf8_string_param,
    (const void *) EVP_PKEY_gettable_params,
    (const void *) EVP_PKEY_is_a,
    (const void *) EVP_PKEY_keygen,
    (const void *) EVP_PKEY_meth_get_check,
    (const void *) EVP_PKEY_meth_get_cleanup,
    (const void *) EVP_PKEY_meth_get_copy,
    (const void *) EVP_PKEY_meth_get_ctrl,
    (const void *) EVP_PKEY_meth_get_decrypt,
    (const void *) EVP_PKEY_meth_get_derive,
    (const void *) EVP_PKEY_meth_get_digest_custom,
    (const void *) EVP_PKEY_meth_get_digestsign,
    (const void *) EVP_PKEY_meth_get_digestverify,
    (const void *) EVP_PKEY_meth_get_encrypt,
    (const void *) EVP_PKEY_meth_get_init,
    (const void *) EVP_PKEY_meth_get_keygen,
    (const void *) EVP_PKEY_meth_get_param_check,
    (const void *) EVP_PKEY_meth_get_paramgen,
    (const void *) EVP_PKEY_meth_get_public_check,
    (const void *) EVP_PKEY_meth_get_sign,
    (const void *) EVP_PKEY_meth_get_signctx,
    (const void *) EVP_PKEY_meth_get_verify,
    (const void *) EVP_PKEY_meth_get_verify_recover,
    (const void *) EVP_PKEY_meth_get_verifyctx,
    (const void *) EVP_PKEY_meth_set_check,
    (const void *) EVP_PKEY_meth_set_cleanup,
    (const void *) EVP_PKEY_meth_set_copy,
    (const void *) EVP_PKEY_meth_set_ctrl,
    (const void *) EVP_PKEY_meth_set_decrypt,
    (const void *) EVP_PKEY_meth_set_derive,
    (const void *) EVP_PKEY_meth_set_digest_custom,
    (const void *) EVP_PKEY_meth_set_digestsign,
    (const void *) EVP_PKEY_meth_set_digestverify,
    (const void *) EVP_PKEY_meth_set_encrypt,
    (const void *) EVP_PKEY_meth_set_init,
    (const void *) EVP_PKEY_meth_set_keygen,
    (const void *) EVP_PKEY_meth_set_param_check,
    (const void *) EVP_PKEY_meth_set_paramgen,
    (const void *) EVP_PKEY_meth_set_public_check,
    (const void *) EVP_PKEY_meth_set_sign,
    (const void *) EVP_PKEY_meth_set_signctx,
    (const void *) EVP_PKEY_meth_set_verify,
    (const void *) EVP_PKEY_meth_set_verify_recover,
    (const void *) EVP_PKEY_meth_set_verifyctx,
    (const void *) EVP_PKEY_pairwise_check,
    (const void *) EVP_PKEY_param_check,
    (const void *) EVP_PKEY_param_check_quick,
    (const void *) EVP_PKEY_parameters_eq,
    (const void *) EVP_PKEY_paramgen,
    (const void *) EVP_PKEY_paramgen_init,
    (const void *) EVP_PKEY_private_check,
    (const void *) EVP_PKEY_public_check,
    (const void *) EVP_PKEY_public_check_quick,
    (const void *) EVP_PKEY_save_parameters,
    (const void *) EVP_PKEY_set_bn_param,
    (const void *) EVP_PKEY_set_ex_data,
    (const void *) EVP_PKEY_set_int_param,
    (const void *) EVP_PKEY_set_octet_string_param,
    (const void *) EVP_PKEY_set_params,
    (const void *) EVP_PKEY_set_size_t_param,
    (const void *) EVP_PKEY_set_utf8_string_param,
    (const void *) EVP_PKEY_settable_params,
    (const void *) EVP_PKEY_todata,
    (const void *) EVP_PKEY_type_names_do_all,
    (const void *) EVP_PKEY_up_ref,
    (const void *) EVP_SIGNATURE_do_all_provided,
    (const void *) EVP_SIGNATURE_get0_description,
    (const void *) EVP_SIGNATURE_get0_name,
    (const void *) EVP_SIGNATURE_get0_provider,
    (const void *) EVP_SIGNATURE_gettable_ctx_params,
    (const void *) EVP_SIGNATURE_is_a,
    (const void *) EVP_SIGNATURE_names_do_all,
    (const void *) EVP_SIGNATURE_settable_ctx_params,
    (const void *) EVP_SIGNATURE_up_ref,
    (const void *) EVP_SKEYMGMT_up_ref,
    (const void *) EVP_SKEY_export,
    (const void *) EVP_get_pw_prompt,
    (const void *) EVP_set_pw_prompt,
};

int main(void)
{
    size_t i;

    setvbuf(stdout, NULL, _IOLBF, 0);
    for (i = 0; i < sizeof refs / sizeof refs[0]; i++)
        printf("coverage_ref.%zu=%s\n", i,
               refs[i] == NULL ? "NULL" : "nonnull");
    return 0;
}
