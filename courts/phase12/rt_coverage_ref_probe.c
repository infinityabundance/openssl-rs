/*
 * RT-PHASE12-REF -- the reference basis the CMS/OCSP/CMP/CT/TS stratum's court
 * coverage needs, and nothing more.
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
 * The 149 names below are the stratum's `implemented` exports this reference
 * basis covers, and every one of them is a *pre-activation* landing: the whole of
 * `ocsp_asn.c` (75), the CT units `ct_sct.c`/`ct_log.c`/`ct_policy.c`/`ct_oct.c`/
 * `ct_b64.c`/`ct_prn.c` (59), `pk7_asn1.c` with `pk7_lib.c` (14) and `http_lib.c`'s
 * `OSSL_parse_url` (1). No unit of the stratum's own has landed yet, so this is the
 * only court 12.0 can register; the plan's behavioural courts are named in
 * `forensics/tools/phase12_courts.py`'s `PENDING_COURTS` with the subphase that
 * brings each.
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
extern void CTLOG_STORE_free(void);
extern void CTLOG_STORE_get0_log_by_id(void);
extern void CTLOG_STORE_load_file(void);
extern void CTLOG_STORE_new(void);
extern void CTLOG_STORE_new_ex(void);
extern void CTLOG_free(void);
extern void CTLOG_get0_log_id(void);
extern void CTLOG_get0_name(void);
extern void CTLOG_get0_public_key(void);
extern void CTLOG_new(void);
extern void CTLOG_new_ex(void);
extern void CTLOG_new_from_base64(void);
extern void CTLOG_new_from_base64_ex(void);
extern void CT_POLICY_EVAL_CTX_free(void);
extern void CT_POLICY_EVAL_CTX_get0_cert(void);
extern void CT_POLICY_EVAL_CTX_get0_issuer(void);
extern void CT_POLICY_EVAL_CTX_get0_log_store(void);
extern void CT_POLICY_EVAL_CTX_get_time(void);
extern void CT_POLICY_EVAL_CTX_new(void);
extern void CT_POLICY_EVAL_CTX_new_ex(void);
extern void CT_POLICY_EVAL_CTX_set1_cert(void);
extern void CT_POLICY_EVAL_CTX_set1_issuer(void);
extern void CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE(void);
extern void CT_POLICY_EVAL_CTX_set_time(void);
extern void OCSP_BASICRESP_free(void);
extern void OCSP_BASICRESP_it(void);
extern void OCSP_BASICRESP_new(void);
extern void OCSP_CERTID_free(void);
extern void OCSP_CERTID_it(void);
extern void OCSP_CERTID_new(void);
extern void OCSP_CERTSTATUS_free(void);
extern void OCSP_CERTSTATUS_it(void);
extern void OCSP_CERTSTATUS_new(void);
extern void OCSP_CRLID_free(void);
extern void OCSP_CRLID_it(void);
extern void OCSP_CRLID_new(void);
extern void OCSP_ONEREQ_free(void);
extern void OCSP_ONEREQ_it(void);
extern void OCSP_ONEREQ_new(void);
extern void OCSP_REQINFO_free(void);
extern void OCSP_REQINFO_it(void);
extern void OCSP_REQINFO_new(void);
extern void OCSP_REQUEST_free(void);
extern void OCSP_REQUEST_it(void);
extern void OCSP_REQUEST_new(void);
extern void OCSP_RESPBYTES_free(void);
extern void OCSP_RESPBYTES_it(void);
extern void OCSP_RESPBYTES_new(void);
extern void OCSP_RESPDATA_free(void);
extern void OCSP_RESPDATA_it(void);
extern void OCSP_RESPDATA_new(void);
extern void OCSP_RESPID_free(void);
extern void OCSP_RESPID_it(void);
extern void OCSP_RESPID_new(void);
extern void OCSP_RESPONSE_free(void);
extern void OCSP_RESPONSE_it(void);
extern void OCSP_RESPONSE_new(void);
extern void OCSP_REVOKEDINFO_free(void);
extern void OCSP_REVOKEDINFO_it(void);
extern void OCSP_REVOKEDINFO_new(void);
extern void OCSP_SERVICELOC_free(void);
extern void OCSP_SERVICELOC_it(void);
extern void OCSP_SERVICELOC_new(void);
extern void OCSP_SIGNATURE_free(void);
extern void OCSP_SIGNATURE_it(void);
extern void OCSP_SIGNATURE_new(void);
extern void OCSP_SINGLERESP_free(void);
extern void OCSP_SINGLERESP_it(void);
extern void OCSP_SINGLERESP_new(void);
extern void OSSL_parse_url(void);
extern void PKCS7_DIGEST_free(void);
extern void PKCS7_DIGEST_it(void);
extern void PKCS7_DIGEST_new(void);
extern void PKCS7_ENCRYPT_free(void);
extern void PKCS7_ENCRYPT_it(void);
extern void PKCS7_ENCRYPT_new(void);
extern void PKCS7_ENC_CONTENT_free(void);
extern void PKCS7_ENC_CONTENT_it(void);
extern void PKCS7_ENC_CONTENT_new(void);
extern void PKCS7_free(void);
extern void PKCS7_it(void);
extern void PKCS7_new(void);
extern void PKCS7_new_ex(void);
extern void PKCS7_set_type(void);
extern void SCT_LIST_free(void);
extern void SCT_LIST_print(void);
extern void SCT_LIST_validate(void);
extern void SCT_free(void);
extern void SCT_get0_extensions(void);
extern void SCT_get0_log_id(void);
extern void SCT_get0_signature(void);
extern void SCT_get_log_entry_type(void);
extern void SCT_get_signature_nid(void);
extern void SCT_get_source(void);
extern void SCT_get_timestamp(void);
extern void SCT_get_validation_status(void);
extern void SCT_get_version(void);
extern void SCT_new(void);
extern void SCT_new_from_base64(void);
extern void SCT_print(void);
extern void SCT_set0_extensions(void);
extern void SCT_set0_log_id(void);
extern void SCT_set0_signature(void);
extern void SCT_set1_extensions(void);
extern void SCT_set1_log_id(void);
extern void SCT_set1_signature(void);
extern void SCT_set_log_entry_type(void);
extern void SCT_set_signature_nid(void);
extern void SCT_set_source(void);
extern void SCT_set_timestamp(void);
extern void SCT_set_version(void);
extern void SCT_validate(void);
extern void SCT_validation_status_string(void);
extern void d2i_OCSP_BASICRESP(void);
extern void d2i_OCSP_CERTID(void);
extern void d2i_OCSP_CERTSTATUS(void);
extern void d2i_OCSP_CRLID(void);
extern void d2i_OCSP_ONEREQ(void);
extern void d2i_OCSP_REQINFO(void);
extern void d2i_OCSP_REQUEST(void);
extern void d2i_OCSP_RESPBYTES(void);
extern void d2i_OCSP_RESPDATA(void);
extern void d2i_OCSP_RESPID(void);
extern void d2i_OCSP_RESPONSE(void);
extern void d2i_OCSP_REVOKEDINFO(void);
extern void d2i_OCSP_SERVICELOC(void);
extern void d2i_OCSP_SIGNATURE(void);
extern void d2i_OCSP_SINGLERESP(void);
extern void d2i_SCT_LIST(void);
extern void i2d_OCSP_BASICRESP(void);
extern void i2d_OCSP_CERTID(void);
extern void i2d_OCSP_CERTSTATUS(void);
extern void i2d_OCSP_CRLID(void);
extern void i2d_OCSP_ONEREQ(void);
extern void i2d_OCSP_REQINFO(void);
extern void i2d_OCSP_REQUEST(void);
extern void i2d_OCSP_RESPBYTES(void);
extern void i2d_OCSP_RESPDATA(void);
extern void i2d_OCSP_RESPID(void);
extern void i2d_OCSP_RESPONSE(void);
extern void i2d_OCSP_REVOKEDINFO(void);
extern void i2d_OCSP_SERVICELOC(void);
extern void i2d_OCSP_SIGNATURE(void);
extern void i2d_OCSP_SINGLERESP(void);
extern void i2d_SCT_LIST(void);
extern void i2o_SCT(void);
extern void i2o_SCT_LIST(void);
extern void o2i_SCT(void);
extern void o2i_SCT_LIST(void);

static const void *volatile refs[] = {
    (const void *) CTLOG_STORE_free,
    (const void *) CTLOG_STORE_get0_log_by_id,
    (const void *) CTLOG_STORE_load_file,
    (const void *) CTLOG_STORE_new,
    (const void *) CTLOG_STORE_new_ex,
    (const void *) CTLOG_free,
    (const void *) CTLOG_get0_log_id,
    (const void *) CTLOG_get0_name,
    (const void *) CTLOG_get0_public_key,
    (const void *) CTLOG_new,
    (const void *) CTLOG_new_ex,
    (const void *) CTLOG_new_from_base64,
    (const void *) CTLOG_new_from_base64_ex,
    (const void *) CT_POLICY_EVAL_CTX_free,
    (const void *) CT_POLICY_EVAL_CTX_get0_cert,
    (const void *) CT_POLICY_EVAL_CTX_get0_issuer,
    (const void *) CT_POLICY_EVAL_CTX_get0_log_store,
    (const void *) CT_POLICY_EVAL_CTX_get_time,
    (const void *) CT_POLICY_EVAL_CTX_new,
    (const void *) CT_POLICY_EVAL_CTX_new_ex,
    (const void *) CT_POLICY_EVAL_CTX_set1_cert,
    (const void *) CT_POLICY_EVAL_CTX_set1_issuer,
    (const void *) CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE,
    (const void *) CT_POLICY_EVAL_CTX_set_time,
    (const void *) OCSP_BASICRESP_free,
    (const void *) OCSP_BASICRESP_it,
    (const void *) OCSP_BASICRESP_new,
    (const void *) OCSP_CERTID_free,
    (const void *) OCSP_CERTID_it,
    (const void *) OCSP_CERTID_new,
    (const void *) OCSP_CERTSTATUS_free,
    (const void *) OCSP_CERTSTATUS_it,
    (const void *) OCSP_CERTSTATUS_new,
    (const void *) OCSP_CRLID_free,
    (const void *) OCSP_CRLID_it,
    (const void *) OCSP_CRLID_new,
    (const void *) OCSP_ONEREQ_free,
    (const void *) OCSP_ONEREQ_it,
    (const void *) OCSP_ONEREQ_new,
    (const void *) OCSP_REQINFO_free,
    (const void *) OCSP_REQINFO_it,
    (const void *) OCSP_REQINFO_new,
    (const void *) OCSP_REQUEST_free,
    (const void *) OCSP_REQUEST_it,
    (const void *) OCSP_REQUEST_new,
    (const void *) OCSP_RESPBYTES_free,
    (const void *) OCSP_RESPBYTES_it,
    (const void *) OCSP_RESPBYTES_new,
    (const void *) OCSP_RESPDATA_free,
    (const void *) OCSP_RESPDATA_it,
    (const void *) OCSP_RESPDATA_new,
    (const void *) OCSP_RESPID_free,
    (const void *) OCSP_RESPID_it,
    (const void *) OCSP_RESPID_new,
    (const void *) OCSP_RESPONSE_free,
    (const void *) OCSP_RESPONSE_it,
    (const void *) OCSP_RESPONSE_new,
    (const void *) OCSP_REVOKEDINFO_free,
    (const void *) OCSP_REVOKEDINFO_it,
    (const void *) OCSP_REVOKEDINFO_new,
    (const void *) OCSP_SERVICELOC_free,
    (const void *) OCSP_SERVICELOC_it,
    (const void *) OCSP_SERVICELOC_new,
    (const void *) OCSP_SIGNATURE_free,
    (const void *) OCSP_SIGNATURE_it,
    (const void *) OCSP_SIGNATURE_new,
    (const void *) OCSP_SINGLERESP_free,
    (const void *) OCSP_SINGLERESP_it,
    (const void *) OCSP_SINGLERESP_new,
    (const void *) OSSL_parse_url,
    (const void *) PKCS7_DIGEST_free,
    (const void *) PKCS7_DIGEST_it,
    (const void *) PKCS7_DIGEST_new,
    (const void *) PKCS7_ENCRYPT_free,
    (const void *) PKCS7_ENCRYPT_it,
    (const void *) PKCS7_ENCRYPT_new,
    (const void *) PKCS7_ENC_CONTENT_free,
    (const void *) PKCS7_ENC_CONTENT_it,
    (const void *) PKCS7_ENC_CONTENT_new,
    (const void *) PKCS7_free,
    (const void *) PKCS7_it,
    (const void *) PKCS7_new,
    (const void *) PKCS7_new_ex,
    (const void *) PKCS7_set_type,
    (const void *) SCT_LIST_free,
    (const void *) SCT_LIST_print,
    (const void *) SCT_LIST_validate,
    (const void *) SCT_free,
    (const void *) SCT_get0_extensions,
    (const void *) SCT_get0_log_id,
    (const void *) SCT_get0_signature,
    (const void *) SCT_get_log_entry_type,
    (const void *) SCT_get_signature_nid,
    (const void *) SCT_get_source,
    (const void *) SCT_get_timestamp,
    (const void *) SCT_get_validation_status,
    (const void *) SCT_get_version,
    (const void *) SCT_new,
    (const void *) SCT_new_from_base64,
    (const void *) SCT_print,
    (const void *) SCT_set0_extensions,
    (const void *) SCT_set0_log_id,
    (const void *) SCT_set0_signature,
    (const void *) SCT_set1_extensions,
    (const void *) SCT_set1_log_id,
    (const void *) SCT_set1_signature,
    (const void *) SCT_set_log_entry_type,
    (const void *) SCT_set_signature_nid,
    (const void *) SCT_set_source,
    (const void *) SCT_set_timestamp,
    (const void *) SCT_set_version,
    (const void *) SCT_validate,
    (const void *) SCT_validation_status_string,
    (const void *) d2i_OCSP_BASICRESP,
    (const void *) d2i_OCSP_CERTID,
    (const void *) d2i_OCSP_CERTSTATUS,
    (const void *) d2i_OCSP_CRLID,
    (const void *) d2i_OCSP_ONEREQ,
    (const void *) d2i_OCSP_REQINFO,
    (const void *) d2i_OCSP_REQUEST,
    (const void *) d2i_OCSP_RESPBYTES,
    (const void *) d2i_OCSP_RESPDATA,
    (const void *) d2i_OCSP_RESPID,
    (const void *) d2i_OCSP_RESPONSE,
    (const void *) d2i_OCSP_REVOKEDINFO,
    (const void *) d2i_OCSP_SERVICELOC,
    (const void *) d2i_OCSP_SIGNATURE,
    (const void *) d2i_OCSP_SINGLERESP,
    (const void *) d2i_SCT_LIST,
    (const void *) i2d_OCSP_BASICRESP,
    (const void *) i2d_OCSP_CERTID,
    (const void *) i2d_OCSP_CERTSTATUS,
    (const void *) i2d_OCSP_CRLID,
    (const void *) i2d_OCSP_ONEREQ,
    (const void *) i2d_OCSP_REQINFO,
    (const void *) i2d_OCSP_REQUEST,
    (const void *) i2d_OCSP_RESPBYTES,
    (const void *) i2d_OCSP_RESPDATA,
    (const void *) i2d_OCSP_RESPID,
    (const void *) i2d_OCSP_RESPONSE,
    (const void *) i2d_OCSP_REVOKEDINFO,
    (const void *) i2d_OCSP_SERVICELOC,
    (const void *) i2d_OCSP_SIGNATURE,
    (const void *) i2d_OCSP_SINGLERESP,
    (const void *) i2d_SCT_LIST,
    (const void *) i2o_SCT,
    (const void *) i2o_SCT_LIST,
    (const void *) o2i_SCT,
    (const void *) o2i_SCT_LIST,
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
