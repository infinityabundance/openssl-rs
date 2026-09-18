/*
 * RT-RUNTIME-REF -- reference basis for the runtime plane: ERR's loaders and accessors, the object-name tables, and the
 * OPENSSL_* string/time/version/directory primitives,
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
extern void CRYPTO_alloc_ex_data(void);
extern void CRYPTO_free_ex_index(void);
extern void ERR_add_error_txt(void);
extern void ERR_add_error_vdata(void);
extern void ERR_get_error_line(void);
extern void ERR_load_ASN1_strings(void);
extern void ERR_load_ASYNC_strings(void);
extern void ERR_load_BIO_strings(void);
extern void ERR_load_BN_strings(void);
extern void ERR_load_BUF_strings(void);
extern void ERR_load_CMS_strings(void);
extern void ERR_load_COMP_strings(void);
extern void ERR_load_CONF_strings(void);
extern void ERR_load_CRYPTO_strings(void);
extern void ERR_load_CT_strings(void);
extern void ERR_load_DH_strings(void);
extern void ERR_load_DSA_strings(void);
extern void ERR_load_EC_strings(void);
extern void ERR_load_ENGINE_strings(void);
extern void ERR_load_ERR_strings(void);
extern void ERR_load_EVP_strings(void);
extern void ERR_load_KDF_strings(void);
extern void ERR_load_OBJ_strings(void);
extern void ERR_load_OCSP_strings(void);
extern void ERR_load_OSSL_STORE_strings(void);
extern void ERR_load_PEM_strings(void);
extern void ERR_load_PKCS12_strings(void);
extern void ERR_load_PKCS7_strings(void);
extern void ERR_load_RAND_strings(void);
extern void ERR_load_RSA_strings(void);
extern void ERR_load_TS_strings(void);
extern void ERR_load_UI_strings(void);
extern void ERR_load_X509V3_strings(void);
extern void ERR_load_X509_strings(void);
extern void ERR_load_strings(void);
extern void ERR_load_strings_const(void);
extern void ERR_peek_last_error_func(void);
extern void ERR_peek_last_error_line(void);
extern void ERR_peek_last_error_line_data(void);
extern void ERR_remove_state(void);
extern void ERR_remove_thread_state(void);
extern void ERR_set_error_data(void);
extern void ERR_unload_strings(void);
extern void ERR_vset_error(void);
extern void OBJ_NAME_add(void);
extern void OBJ_NAME_cleanup(void);
extern void OBJ_NAME_do_all(void);
extern void OBJ_NAME_do_all_sorted(void);
extern void OBJ_NAME_init(void);
extern void OBJ_NAME_new_index(void);
extern void OBJ_NAME_remove(void);
extern void OBJ_add_object(void);
extern void OBJ_add_sigid(void);
extern void OBJ_bsearch_(void);
extern void OBJ_bsearch_ex_(void);
extern void OBJ_cmp(void);
extern void OBJ_dup(void);
extern void OBJ_find_sigid_algs(void);
extern void OBJ_find_sigid_by_algs(void);
extern void OBJ_new_nid(void);
extern void OBJ_nid2ln(void);
extern void OBJ_sigid_free(void);
extern void OPENSSL_DIR_end(void);
extern void OPENSSL_DIR_read(void);
extern void OPENSSL_LH_doall(void);
extern void OPENSSL_LH_doall_arg(void);
extern void OPENSSL_LH_doall_arg_thunk(void);
extern void OPENSSL_buf2hexstr(void);
extern void OPENSSL_buf2hexstr_ex(void);
extern void OPENSSL_gmtime(void);
extern void OPENSSL_gmtime_adj(void);
extern void OPENSSL_gmtime_diff(void);
extern void OPENSSL_hexchar2int(void);
extern void OPENSSL_hexstr2buf(void);
extern void OPENSSL_hexstr2buf_ex(void);
extern void OPENSSL_init(void);
extern void OPENSSL_strcasecmp(void);
extern void OPENSSL_strlcat(void);
extern void OPENSSL_strlcpy(void);
extern void OPENSSL_strncasecmp(void);
extern void OPENSSL_strnlen(void);
extern void OPENSSL_strtoul(void);
extern void OPENSSL_version_build_metadata(void);
extern void OPENSSL_version_major(void);
extern void OPENSSL_version_minor(void);
extern void OPENSSL_version_patch(void);
extern void OPENSSL_version_pre_release(void);
extern void OpenSSL_version(void);
extern void OpenSSL_version_num(void);

static const void *volatile refs[] = {
    (const void *) CRYPTO_alloc_ex_data,
    (const void *) CRYPTO_free_ex_index,
    (const void *) ERR_add_error_txt,
    (const void *) ERR_add_error_vdata,
    (const void *) ERR_get_error_line,
    (const void *) ERR_load_ASN1_strings,
    (const void *) ERR_load_ASYNC_strings,
    (const void *) ERR_load_BIO_strings,
    (const void *) ERR_load_BN_strings,
    (const void *) ERR_load_BUF_strings,
    (const void *) ERR_load_CMS_strings,
    (const void *) ERR_load_COMP_strings,
    (const void *) ERR_load_CONF_strings,
    (const void *) ERR_load_CRYPTO_strings,
    (const void *) ERR_load_CT_strings,
    (const void *) ERR_load_DH_strings,
    (const void *) ERR_load_DSA_strings,
    (const void *) ERR_load_EC_strings,
    (const void *) ERR_load_ENGINE_strings,
    (const void *) ERR_load_ERR_strings,
    (const void *) ERR_load_EVP_strings,
    (const void *) ERR_load_KDF_strings,
    (const void *) ERR_load_OBJ_strings,
    (const void *) ERR_load_OCSP_strings,
    (const void *) ERR_load_OSSL_STORE_strings,
    (const void *) ERR_load_PEM_strings,
    (const void *) ERR_load_PKCS12_strings,
    (const void *) ERR_load_PKCS7_strings,
    (const void *) ERR_load_RAND_strings,
    (const void *) ERR_load_RSA_strings,
    (const void *) ERR_load_TS_strings,
    (const void *) ERR_load_UI_strings,
    (const void *) ERR_load_X509V3_strings,
    (const void *) ERR_load_X509_strings,
    (const void *) ERR_load_strings,
    (const void *) ERR_load_strings_const,
    (const void *) ERR_peek_last_error_func,
    (const void *) ERR_peek_last_error_line,
    (const void *) ERR_peek_last_error_line_data,
    (const void *) ERR_remove_state,
    (const void *) ERR_remove_thread_state,
    (const void *) ERR_set_error_data,
    (const void *) ERR_unload_strings,
    (const void *) ERR_vset_error,
    (const void *) OBJ_NAME_add,
    (const void *) OBJ_NAME_cleanup,
    (const void *) OBJ_NAME_do_all,
    (const void *) OBJ_NAME_do_all_sorted,
    (const void *) OBJ_NAME_init,
    (const void *) OBJ_NAME_new_index,
    (const void *) OBJ_NAME_remove,
    (const void *) OBJ_add_object,
    (const void *) OBJ_add_sigid,
    (const void *) OBJ_bsearch_,
    (const void *) OBJ_bsearch_ex_,
    (const void *) OBJ_cmp,
    (const void *) OBJ_dup,
    (const void *) OBJ_find_sigid_algs,
    (const void *) OBJ_find_sigid_by_algs,
    (const void *) OBJ_new_nid,
    (const void *) OBJ_nid2ln,
    (const void *) OBJ_sigid_free,
    (const void *) OPENSSL_DIR_end,
    (const void *) OPENSSL_DIR_read,
    (const void *) OPENSSL_LH_doall,
    (const void *) OPENSSL_LH_doall_arg,
    (const void *) OPENSSL_LH_doall_arg_thunk,
    (const void *) OPENSSL_buf2hexstr,
    (const void *) OPENSSL_buf2hexstr_ex,
    (const void *) OPENSSL_gmtime,
    (const void *) OPENSSL_gmtime_adj,
    (const void *) OPENSSL_gmtime_diff,
    (const void *) OPENSSL_hexchar2int,
    (const void *) OPENSSL_hexstr2buf,
    (const void *) OPENSSL_hexstr2buf_ex,
    (const void *) OPENSSL_init,
    (const void *) OPENSSL_strcasecmp,
    (const void *) OPENSSL_strlcat,
    (const void *) OPENSSL_strlcpy,
    (const void *) OPENSSL_strncasecmp,
    (const void *) OPENSSL_strnlen,
    (const void *) OPENSSL_strtoul,
    (const void *) OPENSSL_version_build_metadata,
    (const void *) OPENSSL_version_major,
    (const void *) OPENSSL_version_minor,
    (const void *) OPENSSL_version_patch,
    (const void *) OPENSSL_version_pre_release,
    (const void *) OpenSSL_version,
    (const void *) OpenSSL_version_num,
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
