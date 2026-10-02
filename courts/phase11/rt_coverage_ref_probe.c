/*
 * RT-X509-REF -- the reference basis the X.509 stratum's court coverage needs, and
 * nothing more.
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
 * The 1,007 names below are the stratum's `implemented` exports this reference basis
 * covers. 954 are the ones earlier strata landed and this stratum now owns -- the 952
 * atlas-owned exports Phase 8's 8.8 chain and Phase 10's pulled-forward X.509 subphases
 * (10.8-10.16, D442-D451) landed, and the two `ASN1_generate_*` hand-offs Phase 5
 * landed. The other 39 are Phase 11.1a's and 11.4a's own: as
 * `forensics/phase11-obligations.json` records them, those two subphases landed
 * `x509_lu.c`, `x509_meth.c`, `x509_set.c`, `x509_req.c` and `x_req.c`, and the
 * behavioural court `RT-X509-STORE` (`courts/phase11/rt_x509_store_probe.c`) **calls**
 * 97 of their exports and observes them. The 39 below are the ones it cannot: 37 need an
 * `X509_STORE` or `X509_STORE_CTX` that 11.1a does not build (`X509_STORE_new`/
 * `X509_STORE_CTX_new` are withheld -- their blocker is `X509_VERIFY_PARAM`, 11.2's --
 * and the candidate's shell `abort`s on either, so `X509_STORE_add_lookup`,
 * `X509_STORE_get0_objects`/`get0_param`, the twenty-six callback `set_*`/`get_*` pairs,
 * `lock`/`unlock`/`up_ref` and the whole `X509_STORE_CTX_*` read path cannot be driven
 * without re-declaring those structs), `X509_SIG_INFO_get` reads an `X509_SIG_INFO` that
 * `x509.h` leaves opaque, and `X509_get_signature_info` would compare the crate's
 * recorded `EVP_get_digestbyname` divergence D333/D343 rather than this unit's contract.
 * So for these the atlas holds the weaker true statement -- the name is referenced by a
 * probe that ran -- and never `called` (docs/DECISIONS.md D199,
 * docs/PHASE-11-SUBPHASES.md section 4.3).
 *
 * 11.1b and 11.5 landed later (`x509_trust.c`, `by_store.c`, `x509_d2.c`, `v3_prn.c`, `v3_conf.c`'s
 * extension-building chain, and `v3_utl.c`'s name checks and `get1_*` accessors) and added
 * thirty-three more `implemented` exports. **Every one of them is `called` by `RT-X509-STORE`** --
 * the behavioural court grew the arms that drive the trust table, the STORE-URI lookup, the four
 * printers, the nine builders and the six checks -- so at that point this reference basis was
 * unchanged: no name is added below, the count stayed 993, and those 33 are recorded `called`, the
 * stronger true statement, from the behavioural probe's own import.
 *
 * The subphases after 11.5 add fourteen names below, and they are the ones no behavioural court
 * can drive. 11.7a lands the four free-standing default-path answers
 * `X509_get_default_{cert_area,cert_dir,cert_file,private_dir}`: each answers a compile-time path
 * built from the admitted build's forensic `OPENSSLDIR`, while the candidate answers its own
 * `OPENSSL_RS_OPENSSLDIR` (empty when unset), so the two sides diverge by construction and no
 * observation of them can be equal (the same reason `ossl_get_modulesdir` is not compared).
 * 11.4b lands `X509_STORE_CTX_print_verify_cb`: it prints a *context that has run the verify
 * engine*, and `X509_STORE_CTX_init` -- the call that installs the callbacks and seeds the
 * certificate -- is still withheld (11.2), so the probe cannot build a context that has anything
 * to print. 11.1d-f land the two lookup constructors (`X509_LOOKUP_file`, `X509_LOOKUP_hash_dir`)
 * and the seven `x509_d2.c` drivers (`X509_STORE_load_file(_ex)`, `_load_path`, `_load_locations(_ex)`,
 * `X509_STORE_set_default_paths(_ex)`): each cascades through a constructor into
 * `X509_get_default_cert_file`/`_dir`, so the same `OPENSSLDIR` divergence reaches them. All
 * fourteen are the weaker true statement -- referenced by a probe that ran, never `called`.
 *
 * Some of the 1,007 are, independently, imported by a behavioural court -- 401 of the 954
 * by Phases 8 and 10, and 3 more (`X509_REQ_get_version`, `X509_REQ_get_subject_name`,
 * `X509_REQ_get0_signature`) by `RT-X509-STORE`, which reads them while driving the
 * `X509_REQ` surface. Listing a name here cannot weaken a stronger edge: the atlas
 * records `called` wherever a behavioural court imports the name, and `referenced` only
 * where this probe is the sole importer.
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
extern void ACCESS_DESCRIPTION_free(void);
extern void ACCESS_DESCRIPTION_it(void);
extern void ACCESS_DESCRIPTION_new(void);
extern void ADMISSIONS_free(void);
extern void ADMISSIONS_get0_admissionAuthority(void);
extern void ADMISSIONS_get0_namingAuthority(void);
extern void ADMISSIONS_get0_professionInfos(void);
extern void ADMISSIONS_it(void);
extern void ADMISSIONS_new(void);
extern void ADMISSIONS_set0_admissionAuthority(void);
extern void ADMISSIONS_set0_namingAuthority(void);
extern void ADMISSIONS_set0_professionInfos(void);
extern void ADMISSION_SYNTAX_free(void);
extern void ADMISSION_SYNTAX_get0_admissionAuthority(void);
extern void ADMISSION_SYNTAX_get0_contentsOfAdmissions(void);
extern void ADMISSION_SYNTAX_it(void);
extern void ADMISSION_SYNTAX_new(void);
extern void ADMISSION_SYNTAX_set0_admissionAuthority(void);
extern void ADMISSION_SYNTAX_set0_contentsOfAdmissions(void);
extern void ASIdOrRange_free(void);
extern void ASIdOrRange_it(void);
extern void ASIdOrRange_new(void);
extern void ASIdentifierChoice_free(void);
extern void ASIdentifierChoice_it(void);
extern void ASIdentifierChoice_new(void);
extern void ASIdentifiers_free(void);
extern void ASIdentifiers_it(void);
extern void ASIdentifiers_new(void);
extern void ASN1_digest(void);
extern void ASN1_generate_nconf(void);
extern void ASN1_generate_v3(void);
extern void ASN1_item_digest(void);
extern void ASN1_item_sign(void);
extern void ASN1_item_sign_ctx(void);
extern void ASN1_item_verify(void);
extern void ASN1_item_verify_ctx(void);
extern void ASN1_sign(void);
extern void ASN1_verify(void);
extern void ASRange_free(void);
extern void ASRange_it(void);
extern void ASRange_new(void);
extern void AUTHORITY_INFO_ACCESS_free(void);
extern void AUTHORITY_INFO_ACCESS_it(void);
extern void AUTHORITY_INFO_ACCESS_new(void);
extern void AUTHORITY_KEYID_free(void);
extern void AUTHORITY_KEYID_it(void);
extern void AUTHORITY_KEYID_new(void);
extern void BASIC_CONSTRAINTS_free(void);
extern void BASIC_CONSTRAINTS_it(void);
extern void BASIC_CONSTRAINTS_new(void);
extern void CERTIFICATEPOLICIES_free(void);
extern void CERTIFICATEPOLICIES_it(void);
extern void CERTIFICATEPOLICIES_new(void);
extern void CRL_DIST_POINTS_free(void);
extern void CRL_DIST_POINTS_it(void);
extern void CRL_DIST_POINTS_new(void);
extern void DIST_POINT_NAME_dup(void);
extern void DIST_POINT_NAME_free(void);
extern void DIST_POINT_NAME_it(void);
extern void DIST_POINT_NAME_new(void);
extern void DIST_POINT_free(void);
extern void DIST_POINT_it(void);
extern void DIST_POINT_new(void);
extern void DIST_POINT_set_dpname(void);
extern void EDIPARTYNAME_free(void);
extern void EDIPARTYNAME_it(void);
extern void EDIPARTYNAME_new(void);
extern void EVP_PKCS82PKEY(void);
extern void EVP_PKEY2PKCS8(void);
extern void EVP_PKEY_add1_attr(void);
extern void EVP_PKEY_add1_attr_by_NID(void);
extern void EVP_PKEY_add1_attr_by_OBJ(void);
extern void EVP_PKEY_add1_attr_by_txt(void);
extern void EVP_PKEY_delete_attr(void);
extern void EVP_PKEY_get_attr(void);
extern void EVP_PKEY_get_attr_by_NID(void);
extern void EVP_PKEY_get_attr_by_OBJ(void);
extern void EVP_PKEY_get_attr_count(void);
extern void EXTENDED_KEY_USAGE_free(void);
extern void EXTENDED_KEY_USAGE_it(void);
extern void EXTENDED_KEY_USAGE_new(void);
extern void GENERAL_NAMES_free(void);
extern void GENERAL_NAMES_it(void);
extern void GENERAL_NAMES_new(void);
extern void GENERAL_NAME_cmp(void);
extern void GENERAL_NAME_dup(void);
extern void GENERAL_NAME_free(void);
extern void GENERAL_NAME_get0_otherName(void);
extern void GENERAL_NAME_get0_value(void);
extern void GENERAL_NAME_it(void);
extern void GENERAL_NAME_new(void);
extern void GENERAL_NAME_print(void);
extern void GENERAL_NAME_set0_othername(void);
extern void GENERAL_NAME_set0_value(void);
extern void GENERAL_NAME_set1_X509_NAME(void);
extern void GENERAL_SUBTREE_free(void);
extern void GENERAL_SUBTREE_it(void);
extern void GENERAL_SUBTREE_new(void);
extern void IPAddressChoice_free(void);
extern void IPAddressChoice_it(void);
extern void IPAddressChoice_new(void);
extern void IPAddressFamily_free(void);
extern void IPAddressFamily_it(void);
extern void IPAddressFamily_new(void);
extern void IPAddressOrRange_free(void);
extern void IPAddressOrRange_it(void);
extern void IPAddressOrRange_new(void);
extern void IPAddressRange_free(void);
extern void IPAddressRange_it(void);
extern void IPAddressRange_new(void);
extern void ISSUER_SIGN_TOOL_free(void);
extern void ISSUER_SIGN_TOOL_it(void);
extern void ISSUER_SIGN_TOOL_new(void);
extern void ISSUING_DIST_POINT_free(void);
extern void ISSUING_DIST_POINT_it(void);
extern void ISSUING_DIST_POINT_new(void);
extern void NAME_CONSTRAINTS_check(void);
extern void NAME_CONSTRAINTS_check_CN(void);
extern void NAME_CONSTRAINTS_free(void);
extern void NAME_CONSTRAINTS_it(void);
extern void NAME_CONSTRAINTS_new(void);
extern void NAMING_AUTHORITY_free(void);
extern void NAMING_AUTHORITY_get0_authorityId(void);
extern void NAMING_AUTHORITY_get0_authorityText(void);
extern void NAMING_AUTHORITY_get0_authorityURL(void);
extern void NAMING_AUTHORITY_it(void);
extern void NAMING_AUTHORITY_new(void);
extern void NAMING_AUTHORITY_set0_authorityId(void);
extern void NAMING_AUTHORITY_set0_authorityText(void);
extern void NAMING_AUTHORITY_set0_authorityURL(void);
extern void NETSCAPE_SPKAC_free(void);
extern void NETSCAPE_SPKAC_it(void);
extern void NETSCAPE_SPKAC_new(void);
extern void NETSCAPE_SPKI_b64_decode(void);
extern void NETSCAPE_SPKI_b64_encode(void);
extern void NETSCAPE_SPKI_free(void);
extern void NETSCAPE_SPKI_get_pubkey(void);
extern void NETSCAPE_SPKI_it(void);
extern void NETSCAPE_SPKI_new(void);
extern void NETSCAPE_SPKI_set_pubkey(void);
extern void NETSCAPE_SPKI_sign(void);
extern void NETSCAPE_SPKI_verify(void);
extern void NOTICEREF_free(void);
extern void NOTICEREF_it(void);
extern void NOTICEREF_new(void);
extern void OSSL_AA_DIST_POINT_free(void);
extern void OSSL_AA_DIST_POINT_it(void);
extern void OSSL_AA_DIST_POINT_new(void);
extern void OSSL_ALLOWED_ATTRIBUTES_CHOICE_free(void);
extern void OSSL_ALLOWED_ATTRIBUTES_CHOICE_it(void);
extern void OSSL_ALLOWED_ATTRIBUTES_CHOICE_new(void);
extern void OSSL_ALLOWED_ATTRIBUTES_ITEM_free(void);
extern void OSSL_ALLOWED_ATTRIBUTES_ITEM_it(void);
extern void OSSL_ALLOWED_ATTRIBUTES_ITEM_new(void);
extern void OSSL_ALLOWED_ATTRIBUTES_SYNTAX_free(void);
extern void OSSL_ALLOWED_ATTRIBUTES_SYNTAX_it(void);
extern void OSSL_ALLOWED_ATTRIBUTES_SYNTAX_new(void);
extern void OSSL_ATAV_free(void);
extern void OSSL_ATAV_it(void);
extern void OSSL_ATAV_new(void);
extern void OSSL_ATTRIBUTES_SYNTAX_free(void);
extern void OSSL_ATTRIBUTES_SYNTAX_it(void);
extern void OSSL_ATTRIBUTES_SYNTAX_new(void);
extern void OSSL_ATTRIBUTE_DESCRIPTOR_free(void);
extern void OSSL_ATTRIBUTE_DESCRIPTOR_it(void);
extern void OSSL_ATTRIBUTE_DESCRIPTOR_new(void);
extern void OSSL_ATTRIBUTE_MAPPINGS_free(void);
extern void OSSL_ATTRIBUTE_MAPPINGS_it(void);
extern void OSSL_ATTRIBUTE_MAPPINGS_new(void);
extern void OSSL_ATTRIBUTE_MAPPING_free(void);
extern void OSSL_ATTRIBUTE_MAPPING_it(void);
extern void OSSL_ATTRIBUTE_MAPPING_new(void);
extern void OSSL_ATTRIBUTE_TYPE_MAPPING_free(void);
extern void OSSL_ATTRIBUTE_TYPE_MAPPING_it(void);
extern void OSSL_ATTRIBUTE_TYPE_MAPPING_new(void);
extern void OSSL_ATTRIBUTE_VALUE_MAPPING_free(void);
extern void OSSL_ATTRIBUTE_VALUE_MAPPING_it(void);
extern void OSSL_ATTRIBUTE_VALUE_MAPPING_new(void);
extern void OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_free(void);
extern void OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_it(void);
extern void OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_new(void);
extern void OSSL_BASIC_ATTR_CONSTRAINTS_free(void);
extern void OSSL_BASIC_ATTR_CONSTRAINTS_it(void);
extern void OSSL_BASIC_ATTR_CONSTRAINTS_new(void);
extern void OSSL_DAY_TIME_BAND_free(void);
extern void OSSL_DAY_TIME_BAND_it(void);
extern void OSSL_DAY_TIME_BAND_new(void);
extern void OSSL_DAY_TIME_free(void);
extern void OSSL_DAY_TIME_it(void);
extern void OSSL_DAY_TIME_new(void);
extern void OSSL_GENERAL_NAMES_print(void);
extern void OSSL_HASH_free(void);
extern void OSSL_HASH_it(void);
extern void OSSL_HASH_new(void);
extern void OSSL_INFO_SYNTAX_POINTER_free(void);
extern void OSSL_INFO_SYNTAX_POINTER_it(void);
extern void OSSL_INFO_SYNTAX_POINTER_new(void);
extern void OSSL_INFO_SYNTAX_free(void);
extern void OSSL_INFO_SYNTAX_it(void);
extern void OSSL_INFO_SYNTAX_new(void);
extern void OSSL_NAMED_DAY_free(void);
extern void OSSL_NAMED_DAY_it(void);
extern void OSSL_NAMED_DAY_new(void);
extern void OSSL_PRIVILEGE_POLICY_ID_free(void);
extern void OSSL_PRIVILEGE_POLICY_ID_it(void);
extern void OSSL_PRIVILEGE_POLICY_ID_new(void);
extern void OSSL_ROLE_SPEC_CERT_ID_SYNTAX_free(void);
extern void OSSL_ROLE_SPEC_CERT_ID_SYNTAX_it(void);
extern void OSSL_ROLE_SPEC_CERT_ID_SYNTAX_new(void);
extern void OSSL_ROLE_SPEC_CERT_ID_free(void);
extern void OSSL_ROLE_SPEC_CERT_ID_it(void);
extern void OSSL_ROLE_SPEC_CERT_ID_new(void);
extern void OSSL_TARGETING_INFORMATION_free(void);
extern void OSSL_TARGETING_INFORMATION_it(void);
extern void OSSL_TARGETING_INFORMATION_new(void);
extern void OSSL_TARGETS_free(void);
extern void OSSL_TARGETS_it(void);
extern void OSSL_TARGETS_new(void);
extern void OSSL_TARGET_free(void);
extern void OSSL_TARGET_it(void);
extern void OSSL_TARGET_new(void);
extern void OSSL_TIME_PERIOD_free(void);
extern void OSSL_TIME_PERIOD_it(void);
extern void OSSL_TIME_PERIOD_new(void);
extern void OSSL_TIME_SPEC_ABSOLUTE_free(void);
extern void OSSL_TIME_SPEC_ABSOLUTE_it(void);
extern void OSSL_TIME_SPEC_ABSOLUTE_new(void);
extern void OSSL_TIME_SPEC_DAY_free(void);
extern void OSSL_TIME_SPEC_DAY_it(void);
extern void OSSL_TIME_SPEC_DAY_new(void);
extern void OSSL_TIME_SPEC_MONTH_free(void);
extern void OSSL_TIME_SPEC_MONTH_it(void);
extern void OSSL_TIME_SPEC_MONTH_new(void);
extern void OSSL_TIME_SPEC_TIME_free(void);
extern void OSSL_TIME_SPEC_TIME_it(void);
extern void OSSL_TIME_SPEC_TIME_new(void);
extern void OSSL_TIME_SPEC_WEEKS_free(void);
extern void OSSL_TIME_SPEC_WEEKS_it(void);
extern void OSSL_TIME_SPEC_WEEKS_new(void);
extern void OSSL_TIME_SPEC_X_DAY_OF_free(void);
extern void OSSL_TIME_SPEC_X_DAY_OF_it(void);
extern void OSSL_TIME_SPEC_X_DAY_OF_new(void);
extern void OSSL_TIME_SPEC_free(void);
extern void OSSL_TIME_SPEC_it(void);
extern void OSSL_TIME_SPEC_new(void);
extern void OSSL_USER_NOTICE_SYNTAX_free(void);
extern void OSSL_USER_NOTICE_SYNTAX_it(void);
extern void OSSL_USER_NOTICE_SYNTAX_new(void);
extern void OTHERNAME_cmp(void);
extern void OTHERNAME_free(void);
extern void OTHERNAME_it(void);
extern void OTHERNAME_new(void);
extern void PBE2PARAM_free(void);
extern void PBE2PARAM_it(void);
extern void PBE2PARAM_new(void);
extern void PBEPARAM_free(void);
extern void PBEPARAM_it(void);
extern void PBEPARAM_new(void);
extern void PBKDF2PARAM_free(void);
extern void PBKDF2PARAM_it(void);
extern void PBKDF2PARAM_new(void);
extern void PBMAC1PARAM_free(void);
extern void PBMAC1PARAM_it(void);
extern void PBMAC1PARAM_new(void);
extern void PEM_read_PUBKEY(void);
extern void PEM_read_PUBKEY_ex(void);
extern void PEM_read_bio_PUBKEY(void);
extern void PEM_read_bio_PUBKEY_ex(void);
extern void PEM_write_bio_X509_PUBKEY(void);
extern void PKCS5_pbe2_set(void);
extern void PKCS5_pbe2_set_iv(void);
extern void PKCS5_pbe2_set_iv_ex(void);
extern void PKCS5_pbe_set(void);
extern void PKCS5_pbe_set0_algor(void);
extern void PKCS5_pbe_set0_algor_ex(void);
extern void PKCS5_pbe_set_ex(void);
extern void PKCS5_pbkdf2_set(void);
extern void PKCS5_pbkdf2_set_ex(void);
extern void PKCS8_PRIV_KEY_INFO_free(void);
extern void PKCS8_PRIV_KEY_INFO_it(void);
extern void PKCS8_PRIV_KEY_INFO_new(void);
extern void PKCS8_pkey_add1_attr(void);
extern void PKCS8_pkey_add1_attr_by_NID(void);
extern void PKCS8_pkey_add1_attr_by_OBJ(void);
extern void PKCS8_pkey_get0(void);
extern void PKCS8_pkey_get0_attrs(void);
extern void PKCS8_pkey_set0(void);
extern void PKEY_USAGE_PERIOD_free(void);
extern void PKEY_USAGE_PERIOD_it(void);
extern void PKEY_USAGE_PERIOD_new(void);
extern void POLICYINFO_free(void);
extern void POLICYINFO_it(void);
extern void POLICYINFO_new(void);
extern void POLICYQUALINFO_free(void);
extern void POLICYQUALINFO_it(void);
extern void POLICYQUALINFO_new(void);
extern void POLICY_CONSTRAINTS_free(void);
extern void POLICY_CONSTRAINTS_it(void);
extern void POLICY_CONSTRAINTS_new(void);
extern void POLICY_MAPPINGS_it(void);
extern void POLICY_MAPPING_free(void);
extern void POLICY_MAPPING_it(void);
extern void POLICY_MAPPING_new(void);
extern void PROFESSION_INFO_free(void);
extern void PROFESSION_INFO_get0_addProfessionInfo(void);
extern void PROFESSION_INFO_get0_namingAuthority(void);
extern void PROFESSION_INFO_get0_professionItems(void);
extern void PROFESSION_INFO_get0_professionOIDs(void);
extern void PROFESSION_INFO_get0_registrationNumber(void);
extern void PROFESSION_INFO_it(void);
extern void PROFESSION_INFO_new(void);
extern void PROFESSION_INFO_set0_addProfessionInfo(void);
extern void PROFESSION_INFO_set0_namingAuthority(void);
extern void PROFESSION_INFO_set0_professionItems(void);
extern void PROFESSION_INFO_set0_professionOIDs(void);
extern void PROFESSION_INFO_set0_registrationNumber(void);
extern void PROXY_CERT_INFO_EXTENSION_free(void);
extern void PROXY_CERT_INFO_EXTENSION_it(void);
extern void PROXY_CERT_INFO_EXTENSION_new(void);
extern void PROXY_POLICY_free(void);
extern void PROXY_POLICY_it(void);
extern void PROXY_POLICY_new(void);
extern void SXNETID_free(void);
extern void SXNETID_it(void);
extern void SXNETID_new(void);
extern void SXNET_add_id_INTEGER(void);
extern void SXNET_add_id_asc(void);
extern void SXNET_add_id_ulong(void);
extern void SXNET_free(void);
extern void SXNET_get_id_INTEGER(void);
extern void SXNET_get_id_asc(void);
extern void SXNET_get_id_ulong(void);
extern void SXNET_it(void);
extern void SXNET_new(void);
extern void TLS_FEATURE_free(void);
extern void TLS_FEATURE_new(void);
extern void USERNOTICE_free(void);
extern void USERNOTICE_it(void);
extern void USERNOTICE_new(void);
extern void X509V3_EXT_add(void);
extern void X509V3_EXT_add_alias(void);
extern void X509V3_EXT_add_list(void);
extern void X509V3_EXT_cleanup(void);
extern void X509V3_EXT_d2i(void);
extern void X509V3_EXT_get(void);
extern void X509V3_EXT_get_nid(void);
extern void X509V3_EXT_i2d(void);
extern void X509V3_NAME_from_section(void);
extern void X509V3_add1_i2d(void);
extern void X509V3_add_standard_extensions(void);
extern void X509V3_add_value(void);
extern void X509V3_add_value_bool(void);
extern void X509V3_add_value_bool_nf(void);
extern void X509V3_add_value_int(void);
extern void X509V3_add_value_uchar(void);
extern void X509V3_conf_free(void);
extern void X509V3_get_d2i(void);
extern void X509V3_get_section(void);
extern void X509V3_get_string(void);
extern void X509V3_get_value_bool(void);
extern void X509V3_get_value_int(void);
extern void X509V3_parse_list(void);
extern void X509V3_section_free(void);
extern void X509V3_set_conf_lhash(void);
extern void X509V3_set_ctx(void);
extern void X509V3_set_issuer_pkey(void);
extern void X509V3_set_nconf(void);
extern void X509V3_string_free(void);
extern void X509_ALGORS_it(void);
extern void X509_ALGOR_cmp(void);
extern void X509_ALGOR_copy(void);
extern void X509_ALGOR_dup(void);
extern void X509_ALGOR_free(void);
extern void X509_ALGOR_get0(void);
extern void X509_ALGOR_it(void);
extern void X509_ALGOR_new(void);
extern void X509_ALGOR_set0(void);
extern void X509_ALGOR_set_md(void);
extern void X509_ATTRIBUTE_count(void);
extern void X509_ATTRIBUTE_create(void);
extern void X509_ATTRIBUTE_create_by_NID(void);
extern void X509_ATTRIBUTE_create_by_OBJ(void);
extern void X509_ATTRIBUTE_create_by_txt(void);
extern void X509_ATTRIBUTE_dup(void);
extern void X509_ATTRIBUTE_free(void);
extern void X509_ATTRIBUTE_get0_data(void);
extern void X509_ATTRIBUTE_get0_object(void);
extern void X509_ATTRIBUTE_get0_type(void);
extern void X509_ATTRIBUTE_it(void);
extern void X509_ATTRIBUTE_new(void);
extern void X509_ATTRIBUTE_set1_data(void);
extern void X509_ATTRIBUTE_set1_object(void);
extern void X509_CERT_AUX_free(void);
extern void X509_CERT_AUX_it(void);
extern void X509_CERT_AUX_new(void);
extern void X509_CINF_free(void);
extern void X509_CINF_it(void);
extern void X509_CINF_new(void);
extern void X509_CRL_INFO_free(void);
extern void X509_CRL_INFO_it(void);
extern void X509_CRL_INFO_new(void);
extern void X509_CRL_add1_ext_i2d(void);
extern void X509_CRL_add_ext(void);
extern void X509_CRL_check_suiteb(void);
extern void X509_CRL_cmp(void);
extern void X509_CRL_delete_ext(void);
extern void X509_CRL_digest(void);
extern void X509_CRL_dup(void);
extern void X509_CRL_free(void);
extern void X509_CRL_get0_extensions(void);
extern void X509_CRL_get0_lastUpdate(void);
extern void X509_CRL_get0_nextUpdate(void);
extern void X509_CRL_get0_signature(void);
extern void X509_CRL_get0_tbs_sigalg(void);
extern void X509_CRL_get_REVOKED(void);
extern void X509_CRL_get_ext(void);
extern void X509_CRL_get_ext_by_NID(void);
extern void X509_CRL_get_ext_by_OBJ(void);
extern void X509_CRL_get_ext_by_critical(void);
extern void X509_CRL_get_ext_count(void);
extern void X509_CRL_get_ext_d2i(void);
extern void X509_CRL_get_issuer(void);
extern void X509_CRL_get_lastUpdate(void);
extern void X509_CRL_get_nextUpdate(void);
extern void X509_CRL_get_signature_nid(void);
extern void X509_CRL_get_version(void);
extern void X509_CRL_it(void);
extern void X509_CRL_match(void);
extern void X509_CRL_new(void);
extern void X509_CRL_new_ex(void);
extern void X509_CRL_set1_lastUpdate(void);
extern void X509_CRL_set1_nextUpdate(void);
extern void X509_CRL_set_issuer_name(void);
extern void X509_CRL_set_version(void);
extern void X509_CRL_sign(void);
extern void X509_CRL_sign_ctx(void);
extern void X509_CRL_sort(void);
extern void X509_CRL_up_ref(void);
extern void X509_EXTENSION_create_by_NID(void);
extern void X509_EXTENSION_create_by_OBJ(void);
extern void X509_EXTENSION_dup(void);
extern void X509_EXTENSION_free(void);
extern void X509_EXTENSION_get_critical(void);
extern void X509_EXTENSION_get_data(void);
extern void X509_EXTENSION_get_object(void);
extern void X509_EXTENSION_it(void);
extern void X509_EXTENSION_new(void);
extern void X509_EXTENSION_set_critical(void);
extern void X509_EXTENSION_set_data(void);
extern void X509_EXTENSION_set_object(void);
extern void X509_NAME_ENTRY_create_by_NID(void);
extern void X509_NAME_ENTRY_create_by_OBJ(void);
extern void X509_NAME_ENTRY_create_by_txt(void);
extern void X509_NAME_ENTRY_dup(void);
extern void X509_NAME_ENTRY_free(void);
extern void X509_NAME_ENTRY_get_data(void);
extern void X509_NAME_ENTRY_get_object(void);
extern void X509_NAME_ENTRY_it(void);
extern void X509_NAME_ENTRY_new(void);
extern void X509_NAME_ENTRY_set(void);
extern void X509_NAME_ENTRY_set_data(void);
extern void X509_NAME_ENTRY_set_object(void);
extern void X509_NAME_add_entry(void);
extern void X509_NAME_add_entry_by_NID(void);
extern void X509_NAME_add_entry_by_OBJ(void);
extern void X509_NAME_add_entry_by_txt(void);
extern void X509_NAME_cmp(void);
extern void X509_NAME_delete_entry(void);
extern void X509_NAME_digest(void);
extern void X509_NAME_dup(void);
extern void X509_NAME_entry_count(void);
extern void X509_NAME_free(void);
extern void X509_NAME_get0_der(void);
extern void X509_NAME_get_entry(void);
extern void X509_NAME_get_index_by_NID(void);
extern void X509_NAME_get_index_by_OBJ(void);
extern void X509_NAME_get_text_by_NID(void);
extern void X509_NAME_get_text_by_OBJ(void);
extern void X509_NAME_hash_ex(void);
extern void X509_NAME_hash_old(void);
extern void X509_NAME_it(void);
extern void X509_NAME_new(void);
extern void X509_NAME_oneline(void);
extern void X509_NAME_print(void);
extern void X509_NAME_print_ex(void);
extern void X509_NAME_print_ex_fp(void);
extern void X509_NAME_set(void);
extern void X509_POLICY_NODE_print(void);
extern void X509_PUBKEY_dup(void);
extern void X509_PUBKEY_eq(void);
extern void X509_PUBKEY_free(void);
extern void X509_PUBKEY_get(void);
extern void X509_PUBKEY_get0(void);
extern void X509_PUBKEY_get0_param(void);
extern void X509_PUBKEY_it(void);
extern void X509_PUBKEY_new(void);
extern void X509_PUBKEY_new_ex(void);
extern void X509_PUBKEY_set(void);
extern void X509_PUBKEY_set0_param(void);
extern void X509_PUBKEY_set0_public_key(void);
extern void X509_PURPOSE_add(void);
extern void X509_PURPOSE_cleanup(void);
extern void X509_PURPOSE_get0(void);
extern void X509_PURPOSE_get0_name(void);
extern void X509_PURPOSE_get0_sname(void);
extern void X509_PURPOSE_get_by_id(void);
extern void X509_PURPOSE_get_by_sname(void);
extern void X509_PURPOSE_get_count(void);
extern void X509_PURPOSE_get_id(void);
extern void X509_PURPOSE_get_trust(void);
extern void X509_PURPOSE_get_unused_id(void);
extern void X509_PURPOSE_set(void);
extern void X509_REQ_get0_signature(void);
extern void X509_REQ_get_subject_name(void);
extern void X509_REQ_get_version(void);
extern void X509_REQ_set_pubkey(void);
extern void X509_REQ_set_subject_name(void);
extern void X509_REQ_set_version(void);
extern void X509_REVOKED_add1_ext_i2d(void);
extern void X509_REVOKED_add_ext(void);
extern void X509_REVOKED_delete_ext(void);
extern void X509_REVOKED_dup(void);
extern void X509_REVOKED_free(void);
extern void X509_REVOKED_get0_extensions(void);
extern void X509_REVOKED_get0_revocationDate(void);
extern void X509_REVOKED_get0_serialNumber(void);
extern void X509_REVOKED_get_ext(void);
extern void X509_REVOKED_get_ext_by_NID(void);
extern void X509_REVOKED_get_ext_by_OBJ(void);
extern void X509_REVOKED_get_ext_by_critical(void);
extern void X509_REVOKED_get_ext_count(void);
extern void X509_REVOKED_get_ext_d2i(void);
extern void X509_REVOKED_it(void);
extern void X509_REVOKED_new(void);
extern void X509_REVOKED_set_revocationDate(void);
extern void X509_REVOKED_set_serialNumber(void);
extern void X509_LOOKUP_file(void);
extern void X509_LOOKUP_hash_dir(void);
extern void X509_SIG_INFO_get(void);
extern void X509_SIG_INFO_set(void);
extern void X509_SIG_free(void);
extern void X509_SIG_get0(void);
extern void X509_SIG_getm(void);
extern void X509_SIG_it(void);
extern void X509_SIG_new(void);
extern void X509_STORE_CTX_get0_store(void);
extern void X509_STORE_CTX_get1_certs(void);
extern void X509_STORE_CTX_get1_crls(void);
extern void X509_STORE_CTX_get_by_subject(void);
extern void X509_STORE_CTX_get_obj_by_subject(void);
extern void X509_STORE_CTX_print_verify_cb(void);
extern void X509_STORE_add_lookup(void);
extern void X509_STORE_get0_objects(void);
extern void X509_STORE_get0_param(void);
extern void X509_STORE_get_cert_crl(void);
extern void X509_STORE_get_check_crl(void);
extern void X509_STORE_get_check_issued(void);
extern void X509_STORE_get_check_policy(void);
extern void X509_STORE_get_check_revocation(void);
extern void X509_STORE_get_cleanup(void);
extern void X509_STORE_get_ex_data(void);
extern void X509_STORE_get_get_crl(void);
extern void X509_STORE_get_get_issuer(void);
extern void X509_STORE_get_lookup_certs(void);
extern void X509_STORE_get_lookup_crls(void);
extern void X509_STORE_get_verify(void);
extern void X509_STORE_get_verify_cb(void);
extern void X509_STORE_load_file(void);
extern void X509_STORE_load_file_ex(void);
extern void X509_STORE_load_locations(void);
extern void X509_STORE_load_locations_ex(void);
extern void X509_STORE_load_path(void);
extern void X509_STORE_lock(void);
extern void X509_STORE_set_cert_crl(void);
extern void X509_STORE_set_check_crl(void);
extern void X509_STORE_set_check_issued(void);
extern void X509_STORE_set_check_policy(void);
extern void X509_STORE_set_check_revocation(void);
extern void X509_STORE_set_cleanup(void);
extern void X509_STORE_set_default_paths(void);
extern void X509_STORE_set_default_paths_ex(void);
extern void X509_STORE_set_ex_data(void);
extern void X509_STORE_set_get_crl(void);
extern void X509_STORE_set_get_issuer(void);
extern void X509_STORE_set_lookup_certs(void);
extern void X509_STORE_set_lookup_crls(void);
extern void X509_STORE_set_verify(void);
extern void X509_STORE_set_verify_cb(void);
extern void X509_STORE_unlock(void);
extern void X509_STORE_up_ref(void);
extern void X509_VAL_free(void);
extern void X509_VAL_it(void);
extern void X509_VAL_new(void);
extern void X509_add1_ext_i2d(void);
extern void X509_add1_reject_object(void);
extern void X509_add1_trust_object(void);
extern void X509_add_cert(void);
extern void X509_add_certs(void);
extern void X509_add_ext(void);
extern void X509_alias_get0(void);
extern void X509_alias_set1(void);
extern void X509_certificate_type(void);
extern void X509_chain_check_suiteb(void);
extern void X509_chain_up_ref(void);
extern void X509_check_akid(void);
extern void X509_check_ca(void);
extern void X509_check_issued(void);
extern void X509_check_private_key(void);
extern void X509_check_purpose(void);
extern void X509_cmp(void);
extern void X509_delete_ext(void);
extern void X509_digest(void);
extern void X509_digest_sig(void);
extern void X509_dup(void);
extern void X509_email_free(void);
extern void X509_find_by_issuer_and_serial(void);
extern void X509_find_by_subject(void);
extern void X509_free(void);
extern void X509_get0_authority_issuer(void);
extern void X509_get0_authority_key_id(void);
extern void X509_get0_authority_serial(void);
extern void X509_get0_distinguishing_id(void);
extern void X509_get0_extensions(void);
extern void X509_get0_pubkey(void);
extern void X509_get0_pubkey_bitstr(void);
extern void X509_get0_reject_objects(void);
extern void X509_get0_serialNumber(void);
extern void X509_get0_signature(void);
extern void X509_get0_subject_key_id(void);
extern void X509_get0_trust_objects(void);
extern void X509_get_default_cert_area(void);
extern void X509_get_default_cert_dir(void);
extern void X509_get_default_cert_dir_env(void);
extern void X509_get_default_cert_file(void);
extern void X509_get_default_cert_file_env(void);
extern void X509_get_default_private_dir(void);
extern void X509_get_ex_data(void);
extern void X509_get_ext(void);
extern void X509_get_ext_by_NID(void);
extern void X509_get_ext_by_OBJ(void);
extern void X509_get_ext_by_critical(void);
extern void X509_get_ext_count(void);
extern void X509_get_ext_d2i(void);
extern void X509_get_extended_key_usage(void);
extern void X509_get_extension_flags(void);
extern void X509_get_issuer_name(void);
extern void X509_get_key_usage(void);
extern void X509_get_pathlen(void);
extern void X509_get_proxy_pathlen(void);
extern void X509_get_pubkey(void);
extern void X509_get_serialNumber(void);
extern void X509_get_signature_info(void);
extern void X509_get_signature_nid(void);
extern void X509_get_subject_name(void);
extern void X509_get_version(void);
extern void X509_issuer_and_serial_cmp(void);
extern void X509_issuer_and_serial_hash(void);
extern void X509_issuer_name_cmp(void);
extern void X509_issuer_name_hash(void);
extern void X509_issuer_name_hash_old(void);
extern void X509_it(void);
extern void X509_keyid_get0(void);
extern void X509_keyid_set1(void);
extern void X509_new(void);
extern void X509_new_ex(void);
extern void X509_policy_level_get0_node(void);
extern void X509_policy_level_node_count(void);
extern void X509_policy_node_get0_parent(void);
extern void X509_policy_node_get0_policy(void);
extern void X509_policy_node_get0_qualifiers(void);
extern void X509_policy_tree_get0_level(void);
extern void X509_policy_tree_get0_policies(void);
extern void X509_policy_tree_get0_user_policies(void);
extern void X509_policy_tree_level_count(void);
extern void X509_pubkey_digest(void);
extern void X509_reject_clear(void);
extern void X509_self_signed(void);
extern void X509_set0_distinguishing_id(void);
extern void X509_set_ex_data(void);
extern void X509_set_proxy_flag(void);
extern void X509_set_proxy_pathlen(void);
extern void X509_set_version(void);
extern void X509_sign(void);
extern void X509_sign_ctx(void);
extern void X509_signature_dump(void);
extern void X509_subject_name_cmp(void);
extern void X509_subject_name_hash(void);
extern void X509_subject_name_hash_old(void);
extern void X509_supported_extension(void);
extern void X509_trust_clear(void);
extern void X509_trusted(void);
extern void X509_up_ref(void);
extern void X509_verify(void);
extern void X509_verify_cert_error_string(void);
extern void X509at_add1_attr(void);
extern void X509at_add1_attr_by_NID(void);
extern void X509at_add1_attr_by_OBJ(void);
extern void X509at_add1_attr_by_txt(void);
extern void X509at_delete_attr(void);
extern void X509at_get0_data_by_OBJ(void);
extern void X509at_get_attr(void);
extern void X509at_get_attr_by_NID(void);
extern void X509at_get_attr_by_OBJ(void);
extern void X509at_get_attr_count(void);
extern void X509v3_add_ext(void);
extern void X509v3_add_extensions(void);
extern void X509v3_addr_add_inherit(void);
extern void X509v3_addr_add_prefix(void);
extern void X509v3_addr_add_range(void);
extern void X509v3_addr_canonize(void);
extern void X509v3_addr_get_afi(void);
extern void X509v3_addr_get_range(void);
extern void X509v3_addr_inherits(void);
extern void X509v3_addr_is_canonical(void);
extern void X509v3_addr_subset(void);
extern void X509v3_asid_add_id_or_range(void);
extern void X509v3_asid_add_inherit(void);
extern void X509v3_asid_canonize(void);
extern void X509v3_asid_inherits(void);
extern void X509v3_asid_is_canonical(void);
extern void X509v3_asid_subset(void);
extern void X509v3_delete_ext(void);
extern void X509v3_get_ext(void);
extern void X509v3_get_ext_by_NID(void);
extern void X509v3_get_ext_by_OBJ(void);
extern void X509v3_get_ext_by_critical(void);
extern void X509v3_get_ext_count(void);
extern void a2i_GENERAL_NAME(void);
extern void a2i_IPADDRESS(void);
extern void a2i_IPADDRESS_NC(void);
extern void d2i_ACCESS_DESCRIPTION(void);
extern void d2i_ADMISSIONS(void);
extern void d2i_ADMISSION_SYNTAX(void);
extern void d2i_ASIdOrRange(void);
extern void d2i_ASIdentifierChoice(void);
extern void d2i_ASIdentifiers(void);
extern void d2i_ASRange(void);
extern void d2i_AUTHORITY_INFO_ACCESS(void);
extern void d2i_AUTHORITY_KEYID(void);
extern void d2i_BASIC_CONSTRAINTS(void);
extern void d2i_CERTIFICATEPOLICIES(void);
extern void d2i_CRL_DIST_POINTS(void);
extern void d2i_DIST_POINT(void);
extern void d2i_DIST_POINT_NAME(void);
extern void d2i_DSAPrivateKey_bio(void);
extern void d2i_DSAPrivateKey_fp(void);
extern void d2i_DSA_PUBKEY(void);
extern void d2i_DSA_PUBKEY_bio(void);
extern void d2i_DSA_PUBKEY_fp(void);
extern void d2i_ECPrivateKey_bio(void);
extern void d2i_ECPrivateKey_fp(void);
extern void d2i_EC_PUBKEY(void);
extern void d2i_EC_PUBKEY_bio(void);
extern void d2i_EC_PUBKEY_fp(void);
extern void d2i_EDIPARTYNAME(void);
extern void d2i_EXTENDED_KEY_USAGE(void);
extern void d2i_GENERAL_NAME(void);
extern void d2i_GENERAL_NAMES(void);
extern void d2i_IPAddressChoice(void);
extern void d2i_IPAddressFamily(void);
extern void d2i_IPAddressOrRange(void);
extern void d2i_IPAddressRange(void);
extern void d2i_ISSUER_SIGN_TOOL(void);
extern void d2i_ISSUING_DIST_POINT(void);
extern void d2i_NAMING_AUTHORITY(void);
extern void d2i_NETSCAPE_SPKAC(void);
extern void d2i_NETSCAPE_SPKI(void);
extern void d2i_NOTICEREF(void);
extern void d2i_OSSL_AA_DIST_POINT(void);
extern void d2i_OSSL_ALLOWED_ATTRIBUTES_CHOICE(void);
extern void d2i_OSSL_ALLOWED_ATTRIBUTES_ITEM(void);
extern void d2i_OSSL_ALLOWED_ATTRIBUTES_SYNTAX(void);
extern void d2i_OSSL_ATAV(void);
extern void d2i_OSSL_ATTRIBUTES_SYNTAX(void);
extern void d2i_OSSL_ATTRIBUTE_DESCRIPTOR(void);
extern void d2i_OSSL_ATTRIBUTE_MAPPING(void);
extern void d2i_OSSL_ATTRIBUTE_MAPPINGS(void);
extern void d2i_OSSL_ATTRIBUTE_TYPE_MAPPING(void);
extern void d2i_OSSL_ATTRIBUTE_VALUE_MAPPING(void);
extern void d2i_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX(void);
extern void d2i_OSSL_BASIC_ATTR_CONSTRAINTS(void);
extern void d2i_OSSL_DAY_TIME(void);
extern void d2i_OSSL_DAY_TIME_BAND(void);
extern void d2i_OSSL_HASH(void);
extern void d2i_OSSL_INFO_SYNTAX(void);
extern void d2i_OSSL_INFO_SYNTAX_POINTER(void);
extern void d2i_OSSL_NAMED_DAY(void);
extern void d2i_OSSL_PRIVILEGE_POLICY_ID(void);
extern void d2i_OSSL_ROLE_SPEC_CERT_ID(void);
extern void d2i_OSSL_ROLE_SPEC_CERT_ID_SYNTAX(void);
extern void d2i_OSSL_TARGET(void);
extern void d2i_OSSL_TARGETING_INFORMATION(void);
extern void d2i_OSSL_TARGETS(void);
extern void d2i_OSSL_TIME_PERIOD(void);
extern void d2i_OSSL_TIME_SPEC(void);
extern void d2i_OSSL_TIME_SPEC_ABSOLUTE(void);
extern void d2i_OSSL_TIME_SPEC_DAY(void);
extern void d2i_OSSL_TIME_SPEC_MONTH(void);
extern void d2i_OSSL_TIME_SPEC_TIME(void);
extern void d2i_OSSL_TIME_SPEC_WEEKS(void);
extern void d2i_OSSL_TIME_SPEC_X_DAY_OF(void);
extern void d2i_OSSL_USER_NOTICE_SYNTAX(void);
extern void d2i_OTHERNAME(void);
extern void d2i_PBE2PARAM(void);
extern void d2i_PBEPARAM(void);
extern void d2i_PBKDF2PARAM(void);
extern void d2i_PBMAC1PARAM(void);
extern void d2i_PKCS8_PRIV_KEY_INFO(void);
extern void d2i_PKCS8_PRIV_KEY_INFO_bio(void);
extern void d2i_PKCS8_PRIV_KEY_INFO_fp(void);
extern void d2i_PKCS8_bio(void);
extern void d2i_PKCS8_fp(void);
extern void d2i_PKEY_USAGE_PERIOD(void);
extern void d2i_POLICYINFO(void);
extern void d2i_POLICYQUALINFO(void);
extern void d2i_PROFESSION_INFO(void);
extern void d2i_PROXY_CERT_INFO_EXTENSION(void);
extern void d2i_PROXY_POLICY(void);
extern void d2i_PUBKEY(void);
extern void d2i_PUBKEY_bio(void);
extern void d2i_PUBKEY_ex(void);
extern void d2i_PUBKEY_ex_bio(void);
extern void d2i_PUBKEY_ex_fp(void);
extern void d2i_PUBKEY_fp(void);
extern void d2i_PrivateKey_bio(void);
extern void d2i_PrivateKey_ex_bio(void);
extern void d2i_PrivateKey_ex_fp(void);
extern void d2i_PrivateKey_fp(void);
extern void d2i_RSAPrivateKey_bio(void);
extern void d2i_RSAPrivateKey_fp(void);
extern void d2i_RSAPublicKey_bio(void);
extern void d2i_RSAPublicKey_fp(void);
extern void d2i_RSA_PUBKEY(void);
extern void d2i_RSA_PUBKEY_bio(void);
extern void d2i_RSA_PUBKEY_fp(void);
extern void d2i_SXNET(void);
extern void d2i_SXNETID(void);
extern void d2i_USERNOTICE(void);
extern void d2i_X509(void);
extern void d2i_X509_ALGOR(void);
extern void d2i_X509_ALGORS(void);
extern void d2i_X509_ATTRIBUTE(void);
extern void d2i_X509_AUX(void);
extern void d2i_X509_CERT_AUX(void);
extern void d2i_X509_CINF(void);
extern void d2i_X509_CRL(void);
extern void d2i_X509_CRL_INFO(void);
extern void d2i_X509_CRL_bio(void);
extern void d2i_X509_CRL_fp(void);
extern void d2i_X509_EXTENSION(void);
extern void d2i_X509_NAME(void);
extern void d2i_X509_NAME_ENTRY(void);
extern void d2i_X509_PUBKEY(void);
extern void d2i_X509_PUBKEY_bio(void);
extern void d2i_X509_PUBKEY_fp(void);
extern void d2i_X509_REVOKED(void);
extern void d2i_X509_SIG(void);
extern void d2i_X509_VAL(void);
extern void d2i_X509_bio(void);
extern void d2i_X509_fp(void);
extern void i2a_ACCESS_DESCRIPTION(void);
extern void i2d_ACCESS_DESCRIPTION(void);
extern void i2d_ADMISSIONS(void);
extern void i2d_ADMISSION_SYNTAX(void);
extern void i2d_ASIdOrRange(void);
extern void i2d_ASIdentifierChoice(void);
extern void i2d_ASIdentifiers(void);
extern void i2d_ASRange(void);
extern void i2d_AUTHORITY_INFO_ACCESS(void);
extern void i2d_AUTHORITY_KEYID(void);
extern void i2d_BASIC_CONSTRAINTS(void);
extern void i2d_CERTIFICATEPOLICIES(void);
extern void i2d_CRL_DIST_POINTS(void);
extern void i2d_DIST_POINT(void);
extern void i2d_DIST_POINT_NAME(void);
extern void i2d_DSAPrivateKey_bio(void);
extern void i2d_DSAPrivateKey_fp(void);
extern void i2d_DSA_PUBKEY(void);
extern void i2d_DSA_PUBKEY_bio(void);
extern void i2d_DSA_PUBKEY_fp(void);
extern void i2d_ECPrivateKey_bio(void);
extern void i2d_ECPrivateKey_fp(void);
extern void i2d_EC_PUBKEY(void);
extern void i2d_EC_PUBKEY_bio(void);
extern void i2d_EC_PUBKEY_fp(void);
extern void i2d_EDIPARTYNAME(void);
extern void i2d_EXTENDED_KEY_USAGE(void);
extern void i2d_GENERAL_NAME(void);
extern void i2d_GENERAL_NAMES(void);
extern void i2d_IPAddressChoice(void);
extern void i2d_IPAddressFamily(void);
extern void i2d_IPAddressOrRange(void);
extern void i2d_IPAddressRange(void);
extern void i2d_ISSUER_SIGN_TOOL(void);
extern void i2d_ISSUING_DIST_POINT(void);
extern void i2d_NAMING_AUTHORITY(void);
extern void i2d_NETSCAPE_SPKAC(void);
extern void i2d_NETSCAPE_SPKI(void);
extern void i2d_NOTICEREF(void);
extern void i2d_OSSL_AA_DIST_POINT(void);
extern void i2d_OSSL_ALLOWED_ATTRIBUTES_CHOICE(void);
extern void i2d_OSSL_ALLOWED_ATTRIBUTES_ITEM(void);
extern void i2d_OSSL_ALLOWED_ATTRIBUTES_SYNTAX(void);
extern void i2d_OSSL_ATAV(void);
extern void i2d_OSSL_ATTRIBUTES_SYNTAX(void);
extern void i2d_OSSL_ATTRIBUTE_DESCRIPTOR(void);
extern void i2d_OSSL_ATTRIBUTE_MAPPING(void);
extern void i2d_OSSL_ATTRIBUTE_MAPPINGS(void);
extern void i2d_OSSL_ATTRIBUTE_TYPE_MAPPING(void);
extern void i2d_OSSL_ATTRIBUTE_VALUE_MAPPING(void);
extern void i2d_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX(void);
extern void i2d_OSSL_BASIC_ATTR_CONSTRAINTS(void);
extern void i2d_OSSL_DAY_TIME(void);
extern void i2d_OSSL_DAY_TIME_BAND(void);
extern void i2d_OSSL_HASH(void);
extern void i2d_OSSL_INFO_SYNTAX(void);
extern void i2d_OSSL_INFO_SYNTAX_POINTER(void);
extern void i2d_OSSL_NAMED_DAY(void);
extern void i2d_OSSL_PRIVILEGE_POLICY_ID(void);
extern void i2d_OSSL_ROLE_SPEC_CERT_ID(void);
extern void i2d_OSSL_ROLE_SPEC_CERT_ID_SYNTAX(void);
extern void i2d_OSSL_TARGET(void);
extern void i2d_OSSL_TARGETING_INFORMATION(void);
extern void i2d_OSSL_TARGETS(void);
extern void i2d_OSSL_TIME_PERIOD(void);
extern void i2d_OSSL_TIME_SPEC(void);
extern void i2d_OSSL_TIME_SPEC_ABSOLUTE(void);
extern void i2d_OSSL_TIME_SPEC_DAY(void);
extern void i2d_OSSL_TIME_SPEC_MONTH(void);
extern void i2d_OSSL_TIME_SPEC_TIME(void);
extern void i2d_OSSL_TIME_SPEC_WEEKS(void);
extern void i2d_OSSL_TIME_SPEC_X_DAY_OF(void);
extern void i2d_OSSL_USER_NOTICE_SYNTAX(void);
extern void i2d_OTHERNAME(void);
extern void i2d_PBE2PARAM(void);
extern void i2d_PBEPARAM(void);
extern void i2d_PBKDF2PARAM(void);
extern void i2d_PBMAC1PARAM(void);
extern void i2d_PKCS8PrivateKeyInfo_bio(void);
extern void i2d_PKCS8PrivateKeyInfo_fp(void);
extern void i2d_PKCS8_PRIV_KEY_INFO(void);
extern void i2d_PKCS8_PRIV_KEY_INFO_bio(void);
extern void i2d_PKCS8_PRIV_KEY_INFO_fp(void);
extern void i2d_PKCS8_bio(void);
extern void i2d_PKCS8_fp(void);
extern void i2d_PKEY_USAGE_PERIOD(void);
extern void i2d_POLICYINFO(void);
extern void i2d_POLICYQUALINFO(void);
extern void i2d_PROFESSION_INFO(void);
extern void i2d_PROXY_CERT_INFO_EXTENSION(void);
extern void i2d_PROXY_POLICY(void);
extern void i2d_PUBKEY(void);
extern void i2d_PUBKEY_bio(void);
extern void i2d_PUBKEY_fp(void);
extern void i2d_PrivateKey_bio(void);
extern void i2d_PrivateKey_fp(void);
extern void i2d_RSAPrivateKey_bio(void);
extern void i2d_RSAPrivateKey_fp(void);
extern void i2d_RSAPublicKey_bio(void);
extern void i2d_RSAPublicKey_fp(void);
extern void i2d_RSA_PUBKEY(void);
extern void i2d_RSA_PUBKEY_bio(void);
extern void i2d_RSA_PUBKEY_fp(void);
extern void i2d_SXNET(void);
extern void i2d_SXNETID(void);
extern void i2d_USERNOTICE(void);
extern void i2d_X509(void);
extern void i2d_X509_ALGOR(void);
extern void i2d_X509_ALGORS(void);
extern void i2d_X509_ATTRIBUTE(void);
extern void i2d_X509_AUX(void);
extern void i2d_X509_CERT_AUX(void);
extern void i2d_X509_CINF(void);
extern void i2d_X509_CRL(void);
extern void i2d_X509_CRL_INFO(void);
extern void i2d_X509_CRL_bio(void);
extern void i2d_X509_CRL_fp(void);
extern void i2d_X509_EXTENSION(void);
extern void i2d_X509_NAME(void);
extern void i2d_X509_NAME_ENTRY(void);
extern void i2d_X509_PUBKEY(void);
extern void i2d_X509_PUBKEY_bio(void);
extern void i2d_X509_PUBKEY_fp(void);
extern void i2d_X509_REVOKED(void);
extern void i2d_X509_SIG(void);
extern void i2d_X509_VAL(void);
extern void i2d_X509_bio(void);
extern void i2d_X509_fp(void);
extern void i2d_re_X509_CRL_tbs(void);
extern void i2d_re_X509_tbs(void);
extern void i2s_ASN1_ENUMERATED(void);
extern void i2s_ASN1_ENUMERATED_TABLE(void);
extern void i2s_ASN1_IA5STRING(void);
extern void i2s_ASN1_INTEGER(void);
extern void i2s_ASN1_OCTET_STRING(void);
extern void i2s_ASN1_UTF8STRING(void);
extern void i2v_ASN1_BIT_STRING(void);
extern void i2v_GENERAL_NAME(void);
extern void i2v_GENERAL_NAMES(void);
extern void s2i_ASN1_IA5STRING(void);
extern void s2i_ASN1_INTEGER(void);
extern void s2i_ASN1_OCTET_STRING(void);
extern void s2i_ASN1_UTF8STRING(void);
extern void v2i_ASN1_BIT_STRING(void);
extern void v2i_GENERAL_NAME(void);
extern void v2i_GENERAL_NAMES(void);
extern void v2i_GENERAL_NAME_ex(void);

static const void *volatile refs[] = {
    (const void *) ACCESS_DESCRIPTION_free,
    (const void *) ACCESS_DESCRIPTION_it,
    (const void *) ACCESS_DESCRIPTION_new,
    (const void *) ADMISSIONS_free,
    (const void *) ADMISSIONS_get0_admissionAuthority,
    (const void *) ADMISSIONS_get0_namingAuthority,
    (const void *) ADMISSIONS_get0_professionInfos,
    (const void *) ADMISSIONS_it,
    (const void *) ADMISSIONS_new,
    (const void *) ADMISSIONS_set0_admissionAuthority,
    (const void *) ADMISSIONS_set0_namingAuthority,
    (const void *) ADMISSIONS_set0_professionInfos,
    (const void *) ADMISSION_SYNTAX_free,
    (const void *) ADMISSION_SYNTAX_get0_admissionAuthority,
    (const void *) ADMISSION_SYNTAX_get0_contentsOfAdmissions,
    (const void *) ADMISSION_SYNTAX_it,
    (const void *) ADMISSION_SYNTAX_new,
    (const void *) ADMISSION_SYNTAX_set0_admissionAuthority,
    (const void *) ADMISSION_SYNTAX_set0_contentsOfAdmissions,
    (const void *) ASIdOrRange_free,
    (const void *) ASIdOrRange_it,
    (const void *) ASIdOrRange_new,
    (const void *) ASIdentifierChoice_free,
    (const void *) ASIdentifierChoice_it,
    (const void *) ASIdentifierChoice_new,
    (const void *) ASIdentifiers_free,
    (const void *) ASIdentifiers_it,
    (const void *) ASIdentifiers_new,
    (const void *) ASN1_digest,
    (const void *) ASN1_generate_nconf,
    (const void *) ASN1_generate_v3,
    (const void *) ASN1_item_digest,
    (const void *) ASN1_item_sign,
    (const void *) ASN1_item_sign_ctx,
    (const void *) ASN1_item_verify,
    (const void *) ASN1_item_verify_ctx,
    (const void *) ASN1_sign,
    (const void *) ASN1_verify,
    (const void *) ASRange_free,
    (const void *) ASRange_it,
    (const void *) ASRange_new,
    (const void *) AUTHORITY_INFO_ACCESS_free,
    (const void *) AUTHORITY_INFO_ACCESS_it,
    (const void *) AUTHORITY_INFO_ACCESS_new,
    (const void *) AUTHORITY_KEYID_free,
    (const void *) AUTHORITY_KEYID_it,
    (const void *) AUTHORITY_KEYID_new,
    (const void *) BASIC_CONSTRAINTS_free,
    (const void *) BASIC_CONSTRAINTS_it,
    (const void *) BASIC_CONSTRAINTS_new,
    (const void *) CERTIFICATEPOLICIES_free,
    (const void *) CERTIFICATEPOLICIES_it,
    (const void *) CERTIFICATEPOLICIES_new,
    (const void *) CRL_DIST_POINTS_free,
    (const void *) CRL_DIST_POINTS_it,
    (const void *) CRL_DIST_POINTS_new,
    (const void *) DIST_POINT_NAME_dup,
    (const void *) DIST_POINT_NAME_free,
    (const void *) DIST_POINT_NAME_it,
    (const void *) DIST_POINT_NAME_new,
    (const void *) DIST_POINT_free,
    (const void *) DIST_POINT_it,
    (const void *) DIST_POINT_new,
    (const void *) DIST_POINT_set_dpname,
    (const void *) EDIPARTYNAME_free,
    (const void *) EDIPARTYNAME_it,
    (const void *) EDIPARTYNAME_new,
    (const void *) EVP_PKCS82PKEY,
    (const void *) EVP_PKEY2PKCS8,
    (const void *) EVP_PKEY_add1_attr,
    (const void *) EVP_PKEY_add1_attr_by_NID,
    (const void *) EVP_PKEY_add1_attr_by_OBJ,
    (const void *) EVP_PKEY_add1_attr_by_txt,
    (const void *) EVP_PKEY_delete_attr,
    (const void *) EVP_PKEY_get_attr,
    (const void *) EVP_PKEY_get_attr_by_NID,
    (const void *) EVP_PKEY_get_attr_by_OBJ,
    (const void *) EVP_PKEY_get_attr_count,
    (const void *) EXTENDED_KEY_USAGE_free,
    (const void *) EXTENDED_KEY_USAGE_it,
    (const void *) EXTENDED_KEY_USAGE_new,
    (const void *) GENERAL_NAMES_free,
    (const void *) GENERAL_NAMES_it,
    (const void *) GENERAL_NAMES_new,
    (const void *) GENERAL_NAME_cmp,
    (const void *) GENERAL_NAME_dup,
    (const void *) GENERAL_NAME_free,
    (const void *) GENERAL_NAME_get0_otherName,
    (const void *) GENERAL_NAME_get0_value,
    (const void *) GENERAL_NAME_it,
    (const void *) GENERAL_NAME_new,
    (const void *) GENERAL_NAME_print,
    (const void *) GENERAL_NAME_set0_othername,
    (const void *) GENERAL_NAME_set0_value,
    (const void *) GENERAL_NAME_set1_X509_NAME,
    (const void *) GENERAL_SUBTREE_free,
    (const void *) GENERAL_SUBTREE_it,
    (const void *) GENERAL_SUBTREE_new,
    (const void *) IPAddressChoice_free,
    (const void *) IPAddressChoice_it,
    (const void *) IPAddressChoice_new,
    (const void *) IPAddressFamily_free,
    (const void *) IPAddressFamily_it,
    (const void *) IPAddressFamily_new,
    (const void *) IPAddressOrRange_free,
    (const void *) IPAddressOrRange_it,
    (const void *) IPAddressOrRange_new,
    (const void *) IPAddressRange_free,
    (const void *) IPAddressRange_it,
    (const void *) IPAddressRange_new,
    (const void *) ISSUER_SIGN_TOOL_free,
    (const void *) ISSUER_SIGN_TOOL_it,
    (const void *) ISSUER_SIGN_TOOL_new,
    (const void *) ISSUING_DIST_POINT_free,
    (const void *) ISSUING_DIST_POINT_it,
    (const void *) ISSUING_DIST_POINT_new,
    (const void *) NAME_CONSTRAINTS_check,
    (const void *) NAME_CONSTRAINTS_check_CN,
    (const void *) NAME_CONSTRAINTS_free,
    (const void *) NAME_CONSTRAINTS_it,
    (const void *) NAME_CONSTRAINTS_new,
    (const void *) NAMING_AUTHORITY_free,
    (const void *) NAMING_AUTHORITY_get0_authorityId,
    (const void *) NAMING_AUTHORITY_get0_authorityText,
    (const void *) NAMING_AUTHORITY_get0_authorityURL,
    (const void *) NAMING_AUTHORITY_it,
    (const void *) NAMING_AUTHORITY_new,
    (const void *) NAMING_AUTHORITY_set0_authorityId,
    (const void *) NAMING_AUTHORITY_set0_authorityText,
    (const void *) NAMING_AUTHORITY_set0_authorityURL,
    (const void *) NETSCAPE_SPKAC_free,
    (const void *) NETSCAPE_SPKAC_it,
    (const void *) NETSCAPE_SPKAC_new,
    (const void *) NETSCAPE_SPKI_b64_decode,
    (const void *) NETSCAPE_SPKI_b64_encode,
    (const void *) NETSCAPE_SPKI_free,
    (const void *) NETSCAPE_SPKI_get_pubkey,
    (const void *) NETSCAPE_SPKI_it,
    (const void *) NETSCAPE_SPKI_new,
    (const void *) NETSCAPE_SPKI_set_pubkey,
    (const void *) NETSCAPE_SPKI_sign,
    (const void *) NETSCAPE_SPKI_verify,
    (const void *) NOTICEREF_free,
    (const void *) NOTICEREF_it,
    (const void *) NOTICEREF_new,
    (const void *) OSSL_AA_DIST_POINT_free,
    (const void *) OSSL_AA_DIST_POINT_it,
    (const void *) OSSL_AA_DIST_POINT_new,
    (const void *) OSSL_ALLOWED_ATTRIBUTES_CHOICE_free,
    (const void *) OSSL_ALLOWED_ATTRIBUTES_CHOICE_it,
    (const void *) OSSL_ALLOWED_ATTRIBUTES_CHOICE_new,
    (const void *) OSSL_ALLOWED_ATTRIBUTES_ITEM_free,
    (const void *) OSSL_ALLOWED_ATTRIBUTES_ITEM_it,
    (const void *) OSSL_ALLOWED_ATTRIBUTES_ITEM_new,
    (const void *) OSSL_ALLOWED_ATTRIBUTES_SYNTAX_free,
    (const void *) OSSL_ALLOWED_ATTRIBUTES_SYNTAX_it,
    (const void *) OSSL_ALLOWED_ATTRIBUTES_SYNTAX_new,
    (const void *) OSSL_ATAV_free,
    (const void *) OSSL_ATAV_it,
    (const void *) OSSL_ATAV_new,
    (const void *) OSSL_ATTRIBUTES_SYNTAX_free,
    (const void *) OSSL_ATTRIBUTES_SYNTAX_it,
    (const void *) OSSL_ATTRIBUTES_SYNTAX_new,
    (const void *) OSSL_ATTRIBUTE_DESCRIPTOR_free,
    (const void *) OSSL_ATTRIBUTE_DESCRIPTOR_it,
    (const void *) OSSL_ATTRIBUTE_DESCRIPTOR_new,
    (const void *) OSSL_ATTRIBUTE_MAPPINGS_free,
    (const void *) OSSL_ATTRIBUTE_MAPPINGS_it,
    (const void *) OSSL_ATTRIBUTE_MAPPINGS_new,
    (const void *) OSSL_ATTRIBUTE_MAPPING_free,
    (const void *) OSSL_ATTRIBUTE_MAPPING_it,
    (const void *) OSSL_ATTRIBUTE_MAPPING_new,
    (const void *) OSSL_ATTRIBUTE_TYPE_MAPPING_free,
    (const void *) OSSL_ATTRIBUTE_TYPE_MAPPING_it,
    (const void *) OSSL_ATTRIBUTE_TYPE_MAPPING_new,
    (const void *) OSSL_ATTRIBUTE_VALUE_MAPPING_free,
    (const void *) OSSL_ATTRIBUTE_VALUE_MAPPING_it,
    (const void *) OSSL_ATTRIBUTE_VALUE_MAPPING_new,
    (const void *) OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_free,
    (const void *) OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_it,
    (const void *) OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_new,
    (const void *) OSSL_BASIC_ATTR_CONSTRAINTS_free,
    (const void *) OSSL_BASIC_ATTR_CONSTRAINTS_it,
    (const void *) OSSL_BASIC_ATTR_CONSTRAINTS_new,
    (const void *) OSSL_DAY_TIME_BAND_free,
    (const void *) OSSL_DAY_TIME_BAND_it,
    (const void *) OSSL_DAY_TIME_BAND_new,
    (const void *) OSSL_DAY_TIME_free,
    (const void *) OSSL_DAY_TIME_it,
    (const void *) OSSL_DAY_TIME_new,
    (const void *) OSSL_GENERAL_NAMES_print,
    (const void *) OSSL_HASH_free,
    (const void *) OSSL_HASH_it,
    (const void *) OSSL_HASH_new,
    (const void *) OSSL_INFO_SYNTAX_POINTER_free,
    (const void *) OSSL_INFO_SYNTAX_POINTER_it,
    (const void *) OSSL_INFO_SYNTAX_POINTER_new,
    (const void *) OSSL_INFO_SYNTAX_free,
    (const void *) OSSL_INFO_SYNTAX_it,
    (const void *) OSSL_INFO_SYNTAX_new,
    (const void *) OSSL_NAMED_DAY_free,
    (const void *) OSSL_NAMED_DAY_it,
    (const void *) OSSL_NAMED_DAY_new,
    (const void *) OSSL_PRIVILEGE_POLICY_ID_free,
    (const void *) OSSL_PRIVILEGE_POLICY_ID_it,
    (const void *) OSSL_PRIVILEGE_POLICY_ID_new,
    (const void *) OSSL_ROLE_SPEC_CERT_ID_SYNTAX_free,
    (const void *) OSSL_ROLE_SPEC_CERT_ID_SYNTAX_it,
    (const void *) OSSL_ROLE_SPEC_CERT_ID_SYNTAX_new,
    (const void *) OSSL_ROLE_SPEC_CERT_ID_free,
    (const void *) OSSL_ROLE_SPEC_CERT_ID_it,
    (const void *) OSSL_ROLE_SPEC_CERT_ID_new,
    (const void *) OSSL_TARGETING_INFORMATION_free,
    (const void *) OSSL_TARGETING_INFORMATION_it,
    (const void *) OSSL_TARGETING_INFORMATION_new,
    (const void *) OSSL_TARGETS_free,
    (const void *) OSSL_TARGETS_it,
    (const void *) OSSL_TARGETS_new,
    (const void *) OSSL_TARGET_free,
    (const void *) OSSL_TARGET_it,
    (const void *) OSSL_TARGET_new,
    (const void *) OSSL_TIME_PERIOD_free,
    (const void *) OSSL_TIME_PERIOD_it,
    (const void *) OSSL_TIME_PERIOD_new,
    (const void *) OSSL_TIME_SPEC_ABSOLUTE_free,
    (const void *) OSSL_TIME_SPEC_ABSOLUTE_it,
    (const void *) OSSL_TIME_SPEC_ABSOLUTE_new,
    (const void *) OSSL_TIME_SPEC_DAY_free,
    (const void *) OSSL_TIME_SPEC_DAY_it,
    (const void *) OSSL_TIME_SPEC_DAY_new,
    (const void *) OSSL_TIME_SPEC_MONTH_free,
    (const void *) OSSL_TIME_SPEC_MONTH_it,
    (const void *) OSSL_TIME_SPEC_MONTH_new,
    (const void *) OSSL_TIME_SPEC_TIME_free,
    (const void *) OSSL_TIME_SPEC_TIME_it,
    (const void *) OSSL_TIME_SPEC_TIME_new,
    (const void *) OSSL_TIME_SPEC_WEEKS_free,
    (const void *) OSSL_TIME_SPEC_WEEKS_it,
    (const void *) OSSL_TIME_SPEC_WEEKS_new,
    (const void *) OSSL_TIME_SPEC_X_DAY_OF_free,
    (const void *) OSSL_TIME_SPEC_X_DAY_OF_it,
    (const void *) OSSL_TIME_SPEC_X_DAY_OF_new,
    (const void *) OSSL_TIME_SPEC_free,
    (const void *) OSSL_TIME_SPEC_it,
    (const void *) OSSL_TIME_SPEC_new,
    (const void *) OSSL_USER_NOTICE_SYNTAX_free,
    (const void *) OSSL_USER_NOTICE_SYNTAX_it,
    (const void *) OSSL_USER_NOTICE_SYNTAX_new,
    (const void *) OTHERNAME_cmp,
    (const void *) OTHERNAME_free,
    (const void *) OTHERNAME_it,
    (const void *) OTHERNAME_new,
    (const void *) PBE2PARAM_free,
    (const void *) PBE2PARAM_it,
    (const void *) PBE2PARAM_new,
    (const void *) PBEPARAM_free,
    (const void *) PBEPARAM_it,
    (const void *) PBEPARAM_new,
    (const void *) PBKDF2PARAM_free,
    (const void *) PBKDF2PARAM_it,
    (const void *) PBKDF2PARAM_new,
    (const void *) PBMAC1PARAM_free,
    (const void *) PBMAC1PARAM_it,
    (const void *) PBMAC1PARAM_new,
    (const void *) PEM_read_PUBKEY,
    (const void *) PEM_read_PUBKEY_ex,
    (const void *) PEM_read_bio_PUBKEY,
    (const void *) PEM_read_bio_PUBKEY_ex,
    (const void *) PEM_write_bio_X509_PUBKEY,
    (const void *) PKCS5_pbe2_set,
    (const void *) PKCS5_pbe2_set_iv,
    (const void *) PKCS5_pbe2_set_iv_ex,
    (const void *) PKCS5_pbe_set,
    (const void *) PKCS5_pbe_set0_algor,
    (const void *) PKCS5_pbe_set0_algor_ex,
    (const void *) PKCS5_pbe_set_ex,
    (const void *) PKCS5_pbkdf2_set,
    (const void *) PKCS5_pbkdf2_set_ex,
    (const void *) PKCS8_PRIV_KEY_INFO_free,
    (const void *) PKCS8_PRIV_KEY_INFO_it,
    (const void *) PKCS8_PRIV_KEY_INFO_new,
    (const void *) PKCS8_pkey_add1_attr,
    (const void *) PKCS8_pkey_add1_attr_by_NID,
    (const void *) PKCS8_pkey_add1_attr_by_OBJ,
    (const void *) PKCS8_pkey_get0,
    (const void *) PKCS8_pkey_get0_attrs,
    (const void *) PKCS8_pkey_set0,
    (const void *) PKEY_USAGE_PERIOD_free,
    (const void *) PKEY_USAGE_PERIOD_it,
    (const void *) PKEY_USAGE_PERIOD_new,
    (const void *) POLICYINFO_free,
    (const void *) POLICYINFO_it,
    (const void *) POLICYINFO_new,
    (const void *) POLICYQUALINFO_free,
    (const void *) POLICYQUALINFO_it,
    (const void *) POLICYQUALINFO_new,
    (const void *) POLICY_CONSTRAINTS_free,
    (const void *) POLICY_CONSTRAINTS_it,
    (const void *) POLICY_CONSTRAINTS_new,
    (const void *) POLICY_MAPPINGS_it,
    (const void *) POLICY_MAPPING_free,
    (const void *) POLICY_MAPPING_it,
    (const void *) POLICY_MAPPING_new,
    (const void *) PROFESSION_INFO_free,
    (const void *) PROFESSION_INFO_get0_addProfessionInfo,
    (const void *) PROFESSION_INFO_get0_namingAuthority,
    (const void *) PROFESSION_INFO_get0_professionItems,
    (const void *) PROFESSION_INFO_get0_professionOIDs,
    (const void *) PROFESSION_INFO_get0_registrationNumber,
    (const void *) PROFESSION_INFO_it,
    (const void *) PROFESSION_INFO_new,
    (const void *) PROFESSION_INFO_set0_addProfessionInfo,
    (const void *) PROFESSION_INFO_set0_namingAuthority,
    (const void *) PROFESSION_INFO_set0_professionItems,
    (const void *) PROFESSION_INFO_set0_professionOIDs,
    (const void *) PROFESSION_INFO_set0_registrationNumber,
    (const void *) PROXY_CERT_INFO_EXTENSION_free,
    (const void *) PROXY_CERT_INFO_EXTENSION_it,
    (const void *) PROXY_CERT_INFO_EXTENSION_new,
    (const void *) PROXY_POLICY_free,
    (const void *) PROXY_POLICY_it,
    (const void *) PROXY_POLICY_new,
    (const void *) SXNETID_free,
    (const void *) SXNETID_it,
    (const void *) SXNETID_new,
    (const void *) SXNET_add_id_INTEGER,
    (const void *) SXNET_add_id_asc,
    (const void *) SXNET_add_id_ulong,
    (const void *) SXNET_free,
    (const void *) SXNET_get_id_INTEGER,
    (const void *) SXNET_get_id_asc,
    (const void *) SXNET_get_id_ulong,
    (const void *) SXNET_it,
    (const void *) SXNET_new,
    (const void *) TLS_FEATURE_free,
    (const void *) TLS_FEATURE_new,
    (const void *) USERNOTICE_free,
    (const void *) USERNOTICE_it,
    (const void *) USERNOTICE_new,
    (const void *) X509V3_EXT_add,
    (const void *) X509V3_EXT_add_alias,
    (const void *) X509V3_EXT_add_list,
    (const void *) X509V3_EXT_cleanup,
    (const void *) X509V3_EXT_d2i,
    (const void *) X509V3_EXT_get,
    (const void *) X509V3_EXT_get_nid,
    (const void *) X509V3_EXT_i2d,
    (const void *) X509V3_NAME_from_section,
    (const void *) X509V3_add1_i2d,
    (const void *) X509V3_add_standard_extensions,
    (const void *) X509V3_add_value,
    (const void *) X509V3_add_value_bool,
    (const void *) X509V3_add_value_bool_nf,
    (const void *) X509V3_add_value_int,
    (const void *) X509V3_add_value_uchar,
    (const void *) X509V3_conf_free,
    (const void *) X509V3_get_d2i,
    (const void *) X509V3_get_section,
    (const void *) X509V3_get_string,
    (const void *) X509V3_get_value_bool,
    (const void *) X509V3_get_value_int,
    (const void *) X509V3_parse_list,
    (const void *) X509V3_section_free,
    (const void *) X509V3_set_conf_lhash,
    (const void *) X509V3_set_ctx,
    (const void *) X509V3_set_issuer_pkey,
    (const void *) X509V3_set_nconf,
    (const void *) X509V3_string_free,
    (const void *) X509_ALGORS_it,
    (const void *) X509_ALGOR_cmp,
    (const void *) X509_ALGOR_copy,
    (const void *) X509_ALGOR_dup,
    (const void *) X509_ALGOR_free,
    (const void *) X509_ALGOR_get0,
    (const void *) X509_ALGOR_it,
    (const void *) X509_ALGOR_new,
    (const void *) X509_ALGOR_set0,
    (const void *) X509_ALGOR_set_md,
    (const void *) X509_ATTRIBUTE_count,
    (const void *) X509_ATTRIBUTE_create,
    (const void *) X509_ATTRIBUTE_create_by_NID,
    (const void *) X509_ATTRIBUTE_create_by_OBJ,
    (const void *) X509_ATTRIBUTE_create_by_txt,
    (const void *) X509_ATTRIBUTE_dup,
    (const void *) X509_ATTRIBUTE_free,
    (const void *) X509_ATTRIBUTE_get0_data,
    (const void *) X509_ATTRIBUTE_get0_object,
    (const void *) X509_ATTRIBUTE_get0_type,
    (const void *) X509_ATTRIBUTE_it,
    (const void *) X509_ATTRIBUTE_new,
    (const void *) X509_ATTRIBUTE_set1_data,
    (const void *) X509_ATTRIBUTE_set1_object,
    (const void *) X509_CERT_AUX_free,
    (const void *) X509_CERT_AUX_it,
    (const void *) X509_CERT_AUX_new,
    (const void *) X509_CINF_free,
    (const void *) X509_CINF_it,
    (const void *) X509_CINF_new,
    (const void *) X509_CRL_INFO_free,
    (const void *) X509_CRL_INFO_it,
    (const void *) X509_CRL_INFO_new,
    (const void *) X509_CRL_add1_ext_i2d,
    (const void *) X509_CRL_add_ext,
    (const void *) X509_CRL_check_suiteb,
    (const void *) X509_CRL_cmp,
    (const void *) X509_CRL_delete_ext,
    (const void *) X509_CRL_digest,
    (const void *) X509_CRL_dup,
    (const void *) X509_CRL_free,
    (const void *) X509_CRL_get0_extensions,
    (const void *) X509_CRL_get0_lastUpdate,
    (const void *) X509_CRL_get0_nextUpdate,
    (const void *) X509_CRL_get0_signature,
    (const void *) X509_CRL_get0_tbs_sigalg,
    (const void *) X509_CRL_get_REVOKED,
    (const void *) X509_CRL_get_ext,
    (const void *) X509_CRL_get_ext_by_NID,
    (const void *) X509_CRL_get_ext_by_OBJ,
    (const void *) X509_CRL_get_ext_by_critical,
    (const void *) X509_CRL_get_ext_count,
    (const void *) X509_CRL_get_ext_d2i,
    (const void *) X509_CRL_get_issuer,
    (const void *) X509_CRL_get_lastUpdate,
    (const void *) X509_CRL_get_nextUpdate,
    (const void *) X509_CRL_get_signature_nid,
    (const void *) X509_CRL_get_version,
    (const void *) X509_CRL_it,
    (const void *) X509_CRL_match,
    (const void *) X509_CRL_new,
    (const void *) X509_CRL_new_ex,
    (const void *) X509_CRL_set1_lastUpdate,
    (const void *) X509_CRL_set1_nextUpdate,
    (const void *) X509_CRL_set_issuer_name,
    (const void *) X509_CRL_set_version,
    (const void *) X509_CRL_sign,
    (const void *) X509_CRL_sign_ctx,
    (const void *) X509_CRL_sort,
    (const void *) X509_CRL_up_ref,
    (const void *) X509_EXTENSION_create_by_NID,
    (const void *) X509_EXTENSION_create_by_OBJ,
    (const void *) X509_EXTENSION_dup,
    (const void *) X509_EXTENSION_free,
    (const void *) X509_EXTENSION_get_critical,
    (const void *) X509_EXTENSION_get_data,
    (const void *) X509_EXTENSION_get_object,
    (const void *) X509_EXTENSION_it,
    (const void *) X509_EXTENSION_new,
    (const void *) X509_EXTENSION_set_critical,
    (const void *) X509_EXTENSION_set_data,
    (const void *) X509_EXTENSION_set_object,
    (const void *) X509_NAME_ENTRY_create_by_NID,
    (const void *) X509_NAME_ENTRY_create_by_OBJ,
    (const void *) X509_NAME_ENTRY_create_by_txt,
    (const void *) X509_NAME_ENTRY_dup,
    (const void *) X509_NAME_ENTRY_free,
    (const void *) X509_NAME_ENTRY_get_data,
    (const void *) X509_NAME_ENTRY_get_object,
    (const void *) X509_NAME_ENTRY_it,
    (const void *) X509_NAME_ENTRY_new,
    (const void *) X509_NAME_ENTRY_set,
    (const void *) X509_NAME_ENTRY_set_data,
    (const void *) X509_NAME_ENTRY_set_object,
    (const void *) X509_NAME_add_entry,
    (const void *) X509_NAME_add_entry_by_NID,
    (const void *) X509_NAME_add_entry_by_OBJ,
    (const void *) X509_NAME_add_entry_by_txt,
    (const void *) X509_NAME_cmp,
    (const void *) X509_NAME_delete_entry,
    (const void *) X509_NAME_digest,
    (const void *) X509_NAME_dup,
    (const void *) X509_NAME_entry_count,
    (const void *) X509_NAME_free,
    (const void *) X509_NAME_get0_der,
    (const void *) X509_NAME_get_entry,
    (const void *) X509_NAME_get_index_by_NID,
    (const void *) X509_NAME_get_index_by_OBJ,
    (const void *) X509_NAME_get_text_by_NID,
    (const void *) X509_NAME_get_text_by_OBJ,
    (const void *) X509_NAME_hash_ex,
    (const void *) X509_NAME_hash_old,
    (const void *) X509_NAME_it,
    (const void *) X509_NAME_new,
    (const void *) X509_NAME_oneline,
    (const void *) X509_NAME_print,
    (const void *) X509_NAME_print_ex,
    (const void *) X509_NAME_print_ex_fp,
    (const void *) X509_NAME_set,
    (const void *) X509_POLICY_NODE_print,
    (const void *) X509_PUBKEY_dup,
    (const void *) X509_PUBKEY_eq,
    (const void *) X509_PUBKEY_free,
    (const void *) X509_PUBKEY_get,
    (const void *) X509_PUBKEY_get0,
    (const void *) X509_PUBKEY_get0_param,
    (const void *) X509_PUBKEY_it,
    (const void *) X509_PUBKEY_new,
    (const void *) X509_PUBKEY_new_ex,
    (const void *) X509_PUBKEY_set,
    (const void *) X509_PUBKEY_set0_param,
    (const void *) X509_PUBKEY_set0_public_key,
    (const void *) X509_PURPOSE_add,
    (const void *) X509_PURPOSE_cleanup,
    (const void *) X509_PURPOSE_get0,
    (const void *) X509_PURPOSE_get0_name,
    (const void *) X509_PURPOSE_get0_sname,
    (const void *) X509_PURPOSE_get_by_id,
    (const void *) X509_PURPOSE_get_by_sname,
    (const void *) X509_PURPOSE_get_count,
    (const void *) X509_PURPOSE_get_id,
    (const void *) X509_PURPOSE_get_trust,
    (const void *) X509_PURPOSE_get_unused_id,
    (const void *) X509_PURPOSE_set,
    (const void *) X509_REQ_get0_signature,
    (const void *) X509_REQ_get_subject_name,
    (const void *) X509_REQ_get_version,
    (const void *) X509_REQ_set_pubkey,
    (const void *) X509_REQ_set_subject_name,
    (const void *) X509_REQ_set_version,
    (const void *) X509_REVOKED_add1_ext_i2d,
    (const void *) X509_REVOKED_add_ext,
    (const void *) X509_REVOKED_delete_ext,
    (const void *) X509_REVOKED_dup,
    (const void *) X509_REVOKED_free,
    (const void *) X509_REVOKED_get0_extensions,
    (const void *) X509_REVOKED_get0_revocationDate,
    (const void *) X509_REVOKED_get0_serialNumber,
    (const void *) X509_REVOKED_get_ext,
    (const void *) X509_REVOKED_get_ext_by_NID,
    (const void *) X509_REVOKED_get_ext_by_OBJ,
    (const void *) X509_REVOKED_get_ext_by_critical,
    (const void *) X509_REVOKED_get_ext_count,
    (const void *) X509_REVOKED_get_ext_d2i,
    (const void *) X509_REVOKED_it,
    (const void *) X509_REVOKED_new,
    (const void *) X509_REVOKED_set_revocationDate,
    (const void *) X509_REVOKED_set_serialNumber,
    (const void *) X509_LOOKUP_file,
    (const void *) X509_LOOKUP_hash_dir,
    (const void *) X509_SIG_INFO_get,
    (const void *) X509_SIG_INFO_set,
    (const void *) X509_SIG_free,
    (const void *) X509_SIG_get0,
    (const void *) X509_SIG_getm,
    (const void *) X509_SIG_it,
    (const void *) X509_SIG_new,
    (const void *) X509_STORE_CTX_get0_store,
    (const void *) X509_STORE_CTX_get1_certs,
    (const void *) X509_STORE_CTX_get1_crls,
    (const void *) X509_STORE_CTX_get_by_subject,
    (const void *) X509_STORE_CTX_get_obj_by_subject,
    (const void *) X509_STORE_CTX_print_verify_cb,
    (const void *) X509_STORE_add_lookup,
    (const void *) X509_STORE_get0_objects,
    (const void *) X509_STORE_get0_param,
    (const void *) X509_STORE_get_cert_crl,
    (const void *) X509_STORE_get_check_crl,
    (const void *) X509_STORE_get_check_issued,
    (const void *) X509_STORE_get_check_policy,
    (const void *) X509_STORE_get_check_revocation,
    (const void *) X509_STORE_get_cleanup,
    (const void *) X509_STORE_get_ex_data,
    (const void *) X509_STORE_get_get_crl,
    (const void *) X509_STORE_get_get_issuer,
    (const void *) X509_STORE_get_lookup_certs,
    (const void *) X509_STORE_get_lookup_crls,
    (const void *) X509_STORE_get_verify,
    (const void *) X509_STORE_get_verify_cb,
    (const void *) X509_STORE_load_file,
    (const void *) X509_STORE_load_file_ex,
    (const void *) X509_STORE_load_locations,
    (const void *) X509_STORE_load_locations_ex,
    (const void *) X509_STORE_load_path,
    (const void *) X509_STORE_lock,
    (const void *) X509_STORE_set_cert_crl,
    (const void *) X509_STORE_set_check_crl,
    (const void *) X509_STORE_set_check_issued,
    (const void *) X509_STORE_set_check_policy,
    (const void *) X509_STORE_set_check_revocation,
    (const void *) X509_STORE_set_cleanup,
    (const void *) X509_STORE_set_default_paths,
    (const void *) X509_STORE_set_default_paths_ex,
    (const void *) X509_STORE_set_ex_data,
    (const void *) X509_STORE_set_get_crl,
    (const void *) X509_STORE_set_get_issuer,
    (const void *) X509_STORE_set_lookup_certs,
    (const void *) X509_STORE_set_lookup_crls,
    (const void *) X509_STORE_set_verify,
    (const void *) X509_STORE_set_verify_cb,
    (const void *) X509_STORE_unlock,
    (const void *) X509_STORE_up_ref,
    (const void *) X509_VAL_free,
    (const void *) X509_VAL_it,
    (const void *) X509_VAL_new,
    (const void *) X509_add1_ext_i2d,
    (const void *) X509_add1_reject_object,
    (const void *) X509_add1_trust_object,
    (const void *) X509_add_cert,
    (const void *) X509_add_certs,
    (const void *) X509_add_ext,
    (const void *) X509_alias_get0,
    (const void *) X509_alias_set1,
    (const void *) X509_certificate_type,
    (const void *) X509_chain_check_suiteb,
    (const void *) X509_chain_up_ref,
    (const void *) X509_check_akid,
    (const void *) X509_check_ca,
    (const void *) X509_check_issued,
    (const void *) X509_check_private_key,
    (const void *) X509_check_purpose,
    (const void *) X509_cmp,
    (const void *) X509_delete_ext,
    (const void *) X509_digest,
    (const void *) X509_digest_sig,
    (const void *) X509_dup,
    (const void *) X509_email_free,
    (const void *) X509_find_by_issuer_and_serial,
    (const void *) X509_find_by_subject,
    (const void *) X509_free,
    (const void *) X509_get0_authority_issuer,
    (const void *) X509_get0_authority_key_id,
    (const void *) X509_get0_authority_serial,
    (const void *) X509_get0_distinguishing_id,
    (const void *) X509_get0_extensions,
    (const void *) X509_get0_pubkey,
    (const void *) X509_get0_pubkey_bitstr,
    (const void *) X509_get0_reject_objects,
    (const void *) X509_get0_serialNumber,
    (const void *) X509_get0_signature,
    (const void *) X509_get0_subject_key_id,
    (const void *) X509_get0_trust_objects,
    (const void *) X509_get_default_cert_area,
    (const void *) X509_get_default_cert_dir,
    (const void *) X509_get_default_cert_dir_env,
    (const void *) X509_get_default_cert_file,
    (const void *) X509_get_default_cert_file_env,
    (const void *) X509_get_default_private_dir,
    (const void *) X509_get_ex_data,
    (const void *) X509_get_ext,
    (const void *) X509_get_ext_by_NID,
    (const void *) X509_get_ext_by_OBJ,
    (const void *) X509_get_ext_by_critical,
    (const void *) X509_get_ext_count,
    (const void *) X509_get_ext_d2i,
    (const void *) X509_get_extended_key_usage,
    (const void *) X509_get_extension_flags,
    (const void *) X509_get_issuer_name,
    (const void *) X509_get_key_usage,
    (const void *) X509_get_pathlen,
    (const void *) X509_get_proxy_pathlen,
    (const void *) X509_get_pubkey,
    (const void *) X509_get_serialNumber,
    (const void *) X509_get_signature_info,
    (const void *) X509_get_signature_nid,
    (const void *) X509_get_subject_name,
    (const void *) X509_get_version,
    (const void *) X509_issuer_and_serial_cmp,
    (const void *) X509_issuer_and_serial_hash,
    (const void *) X509_issuer_name_cmp,
    (const void *) X509_issuer_name_hash,
    (const void *) X509_issuer_name_hash_old,
    (const void *) X509_it,
    (const void *) X509_keyid_get0,
    (const void *) X509_keyid_set1,
    (const void *) X509_new,
    (const void *) X509_new_ex,
    (const void *) X509_policy_level_get0_node,
    (const void *) X509_policy_level_node_count,
    (const void *) X509_policy_node_get0_parent,
    (const void *) X509_policy_node_get0_policy,
    (const void *) X509_policy_node_get0_qualifiers,
    (const void *) X509_policy_tree_get0_level,
    (const void *) X509_policy_tree_get0_policies,
    (const void *) X509_policy_tree_get0_user_policies,
    (const void *) X509_policy_tree_level_count,
    (const void *) X509_pubkey_digest,
    (const void *) X509_reject_clear,
    (const void *) X509_self_signed,
    (const void *) X509_set0_distinguishing_id,
    (const void *) X509_set_ex_data,
    (const void *) X509_set_proxy_flag,
    (const void *) X509_set_proxy_pathlen,
    (const void *) X509_set_version,
    (const void *) X509_sign,
    (const void *) X509_sign_ctx,
    (const void *) X509_signature_dump,
    (const void *) X509_subject_name_cmp,
    (const void *) X509_subject_name_hash,
    (const void *) X509_subject_name_hash_old,
    (const void *) X509_supported_extension,
    (const void *) X509_trust_clear,
    (const void *) X509_trusted,
    (const void *) X509_up_ref,
    (const void *) X509_verify,
    (const void *) X509_verify_cert_error_string,
    (const void *) X509at_add1_attr,
    (const void *) X509at_add1_attr_by_NID,
    (const void *) X509at_add1_attr_by_OBJ,
    (const void *) X509at_add1_attr_by_txt,
    (const void *) X509at_delete_attr,
    (const void *) X509at_get0_data_by_OBJ,
    (const void *) X509at_get_attr,
    (const void *) X509at_get_attr_by_NID,
    (const void *) X509at_get_attr_by_OBJ,
    (const void *) X509at_get_attr_count,
    (const void *) X509v3_add_ext,
    (const void *) X509v3_add_extensions,
    (const void *) X509v3_addr_add_inherit,
    (const void *) X509v3_addr_add_prefix,
    (const void *) X509v3_addr_add_range,
    (const void *) X509v3_addr_canonize,
    (const void *) X509v3_addr_get_afi,
    (const void *) X509v3_addr_get_range,
    (const void *) X509v3_addr_inherits,
    (const void *) X509v3_addr_is_canonical,
    (const void *) X509v3_addr_subset,
    (const void *) X509v3_asid_add_id_or_range,
    (const void *) X509v3_asid_add_inherit,
    (const void *) X509v3_asid_canonize,
    (const void *) X509v3_asid_inherits,
    (const void *) X509v3_asid_is_canonical,
    (const void *) X509v3_asid_subset,
    (const void *) X509v3_delete_ext,
    (const void *) X509v3_get_ext,
    (const void *) X509v3_get_ext_by_NID,
    (const void *) X509v3_get_ext_by_OBJ,
    (const void *) X509v3_get_ext_by_critical,
    (const void *) X509v3_get_ext_count,
    (const void *) a2i_GENERAL_NAME,
    (const void *) a2i_IPADDRESS,
    (const void *) a2i_IPADDRESS_NC,
    (const void *) d2i_ACCESS_DESCRIPTION,
    (const void *) d2i_ADMISSIONS,
    (const void *) d2i_ADMISSION_SYNTAX,
    (const void *) d2i_ASIdOrRange,
    (const void *) d2i_ASIdentifierChoice,
    (const void *) d2i_ASIdentifiers,
    (const void *) d2i_ASRange,
    (const void *) d2i_AUTHORITY_INFO_ACCESS,
    (const void *) d2i_AUTHORITY_KEYID,
    (const void *) d2i_BASIC_CONSTRAINTS,
    (const void *) d2i_CERTIFICATEPOLICIES,
    (const void *) d2i_CRL_DIST_POINTS,
    (const void *) d2i_DIST_POINT,
    (const void *) d2i_DIST_POINT_NAME,
    (const void *) d2i_DSAPrivateKey_bio,
    (const void *) d2i_DSAPrivateKey_fp,
    (const void *) d2i_DSA_PUBKEY,
    (const void *) d2i_DSA_PUBKEY_bio,
    (const void *) d2i_DSA_PUBKEY_fp,
    (const void *) d2i_ECPrivateKey_bio,
    (const void *) d2i_ECPrivateKey_fp,
    (const void *) d2i_EC_PUBKEY,
    (const void *) d2i_EC_PUBKEY_bio,
    (const void *) d2i_EC_PUBKEY_fp,
    (const void *) d2i_EDIPARTYNAME,
    (const void *) d2i_EXTENDED_KEY_USAGE,
    (const void *) d2i_GENERAL_NAME,
    (const void *) d2i_GENERAL_NAMES,
    (const void *) d2i_IPAddressChoice,
    (const void *) d2i_IPAddressFamily,
    (const void *) d2i_IPAddressOrRange,
    (const void *) d2i_IPAddressRange,
    (const void *) d2i_ISSUER_SIGN_TOOL,
    (const void *) d2i_ISSUING_DIST_POINT,
    (const void *) d2i_NAMING_AUTHORITY,
    (const void *) d2i_NETSCAPE_SPKAC,
    (const void *) d2i_NETSCAPE_SPKI,
    (const void *) d2i_NOTICEREF,
    (const void *) d2i_OSSL_AA_DIST_POINT,
    (const void *) d2i_OSSL_ALLOWED_ATTRIBUTES_CHOICE,
    (const void *) d2i_OSSL_ALLOWED_ATTRIBUTES_ITEM,
    (const void *) d2i_OSSL_ALLOWED_ATTRIBUTES_SYNTAX,
    (const void *) d2i_OSSL_ATAV,
    (const void *) d2i_OSSL_ATTRIBUTES_SYNTAX,
    (const void *) d2i_OSSL_ATTRIBUTE_DESCRIPTOR,
    (const void *) d2i_OSSL_ATTRIBUTE_MAPPING,
    (const void *) d2i_OSSL_ATTRIBUTE_MAPPINGS,
    (const void *) d2i_OSSL_ATTRIBUTE_TYPE_MAPPING,
    (const void *) d2i_OSSL_ATTRIBUTE_VALUE_MAPPING,
    (const void *) d2i_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX,
    (const void *) d2i_OSSL_BASIC_ATTR_CONSTRAINTS,
    (const void *) d2i_OSSL_DAY_TIME,
    (const void *) d2i_OSSL_DAY_TIME_BAND,
    (const void *) d2i_OSSL_HASH,
    (const void *) d2i_OSSL_INFO_SYNTAX,
    (const void *) d2i_OSSL_INFO_SYNTAX_POINTER,
    (const void *) d2i_OSSL_NAMED_DAY,
    (const void *) d2i_OSSL_PRIVILEGE_POLICY_ID,
    (const void *) d2i_OSSL_ROLE_SPEC_CERT_ID,
    (const void *) d2i_OSSL_ROLE_SPEC_CERT_ID_SYNTAX,
    (const void *) d2i_OSSL_TARGET,
    (const void *) d2i_OSSL_TARGETING_INFORMATION,
    (const void *) d2i_OSSL_TARGETS,
    (const void *) d2i_OSSL_TIME_PERIOD,
    (const void *) d2i_OSSL_TIME_SPEC,
    (const void *) d2i_OSSL_TIME_SPEC_ABSOLUTE,
    (const void *) d2i_OSSL_TIME_SPEC_DAY,
    (const void *) d2i_OSSL_TIME_SPEC_MONTH,
    (const void *) d2i_OSSL_TIME_SPEC_TIME,
    (const void *) d2i_OSSL_TIME_SPEC_WEEKS,
    (const void *) d2i_OSSL_TIME_SPEC_X_DAY_OF,
    (const void *) d2i_OSSL_USER_NOTICE_SYNTAX,
    (const void *) d2i_OTHERNAME,
    (const void *) d2i_PBE2PARAM,
    (const void *) d2i_PBEPARAM,
    (const void *) d2i_PBKDF2PARAM,
    (const void *) d2i_PBMAC1PARAM,
    (const void *) d2i_PKCS8_PRIV_KEY_INFO,
    (const void *) d2i_PKCS8_PRIV_KEY_INFO_bio,
    (const void *) d2i_PKCS8_PRIV_KEY_INFO_fp,
    (const void *) d2i_PKCS8_bio,
    (const void *) d2i_PKCS8_fp,
    (const void *) d2i_PKEY_USAGE_PERIOD,
    (const void *) d2i_POLICYINFO,
    (const void *) d2i_POLICYQUALINFO,
    (const void *) d2i_PROFESSION_INFO,
    (const void *) d2i_PROXY_CERT_INFO_EXTENSION,
    (const void *) d2i_PROXY_POLICY,
    (const void *) d2i_PUBKEY,
    (const void *) d2i_PUBKEY_bio,
    (const void *) d2i_PUBKEY_ex,
    (const void *) d2i_PUBKEY_ex_bio,
    (const void *) d2i_PUBKEY_ex_fp,
    (const void *) d2i_PUBKEY_fp,
    (const void *) d2i_PrivateKey_bio,
    (const void *) d2i_PrivateKey_ex_bio,
    (const void *) d2i_PrivateKey_ex_fp,
    (const void *) d2i_PrivateKey_fp,
    (const void *) d2i_RSAPrivateKey_bio,
    (const void *) d2i_RSAPrivateKey_fp,
    (const void *) d2i_RSAPublicKey_bio,
    (const void *) d2i_RSAPublicKey_fp,
    (const void *) d2i_RSA_PUBKEY,
    (const void *) d2i_RSA_PUBKEY_bio,
    (const void *) d2i_RSA_PUBKEY_fp,
    (const void *) d2i_SXNET,
    (const void *) d2i_SXNETID,
    (const void *) d2i_USERNOTICE,
    (const void *) d2i_X509,
    (const void *) d2i_X509_ALGOR,
    (const void *) d2i_X509_ALGORS,
    (const void *) d2i_X509_ATTRIBUTE,
    (const void *) d2i_X509_AUX,
    (const void *) d2i_X509_CERT_AUX,
    (const void *) d2i_X509_CINF,
    (const void *) d2i_X509_CRL,
    (const void *) d2i_X509_CRL_INFO,
    (const void *) d2i_X509_CRL_bio,
    (const void *) d2i_X509_CRL_fp,
    (const void *) d2i_X509_EXTENSION,
    (const void *) d2i_X509_NAME,
    (const void *) d2i_X509_NAME_ENTRY,
    (const void *) d2i_X509_PUBKEY,
    (const void *) d2i_X509_PUBKEY_bio,
    (const void *) d2i_X509_PUBKEY_fp,
    (const void *) d2i_X509_REVOKED,
    (const void *) d2i_X509_SIG,
    (const void *) d2i_X509_VAL,
    (const void *) d2i_X509_bio,
    (const void *) d2i_X509_fp,
    (const void *) i2a_ACCESS_DESCRIPTION,
    (const void *) i2d_ACCESS_DESCRIPTION,
    (const void *) i2d_ADMISSIONS,
    (const void *) i2d_ADMISSION_SYNTAX,
    (const void *) i2d_ASIdOrRange,
    (const void *) i2d_ASIdentifierChoice,
    (const void *) i2d_ASIdentifiers,
    (const void *) i2d_ASRange,
    (const void *) i2d_AUTHORITY_INFO_ACCESS,
    (const void *) i2d_AUTHORITY_KEYID,
    (const void *) i2d_BASIC_CONSTRAINTS,
    (const void *) i2d_CERTIFICATEPOLICIES,
    (const void *) i2d_CRL_DIST_POINTS,
    (const void *) i2d_DIST_POINT,
    (const void *) i2d_DIST_POINT_NAME,
    (const void *) i2d_DSAPrivateKey_bio,
    (const void *) i2d_DSAPrivateKey_fp,
    (const void *) i2d_DSA_PUBKEY,
    (const void *) i2d_DSA_PUBKEY_bio,
    (const void *) i2d_DSA_PUBKEY_fp,
    (const void *) i2d_ECPrivateKey_bio,
    (const void *) i2d_ECPrivateKey_fp,
    (const void *) i2d_EC_PUBKEY,
    (const void *) i2d_EC_PUBKEY_bio,
    (const void *) i2d_EC_PUBKEY_fp,
    (const void *) i2d_EDIPARTYNAME,
    (const void *) i2d_EXTENDED_KEY_USAGE,
    (const void *) i2d_GENERAL_NAME,
    (const void *) i2d_GENERAL_NAMES,
    (const void *) i2d_IPAddressChoice,
    (const void *) i2d_IPAddressFamily,
    (const void *) i2d_IPAddressOrRange,
    (const void *) i2d_IPAddressRange,
    (const void *) i2d_ISSUER_SIGN_TOOL,
    (const void *) i2d_ISSUING_DIST_POINT,
    (const void *) i2d_NAMING_AUTHORITY,
    (const void *) i2d_NETSCAPE_SPKAC,
    (const void *) i2d_NETSCAPE_SPKI,
    (const void *) i2d_NOTICEREF,
    (const void *) i2d_OSSL_AA_DIST_POINT,
    (const void *) i2d_OSSL_ALLOWED_ATTRIBUTES_CHOICE,
    (const void *) i2d_OSSL_ALLOWED_ATTRIBUTES_ITEM,
    (const void *) i2d_OSSL_ALLOWED_ATTRIBUTES_SYNTAX,
    (const void *) i2d_OSSL_ATAV,
    (const void *) i2d_OSSL_ATTRIBUTES_SYNTAX,
    (const void *) i2d_OSSL_ATTRIBUTE_DESCRIPTOR,
    (const void *) i2d_OSSL_ATTRIBUTE_MAPPING,
    (const void *) i2d_OSSL_ATTRIBUTE_MAPPINGS,
    (const void *) i2d_OSSL_ATTRIBUTE_TYPE_MAPPING,
    (const void *) i2d_OSSL_ATTRIBUTE_VALUE_MAPPING,
    (const void *) i2d_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX,
    (const void *) i2d_OSSL_BASIC_ATTR_CONSTRAINTS,
    (const void *) i2d_OSSL_DAY_TIME,
    (const void *) i2d_OSSL_DAY_TIME_BAND,
    (const void *) i2d_OSSL_HASH,
    (const void *) i2d_OSSL_INFO_SYNTAX,
    (const void *) i2d_OSSL_INFO_SYNTAX_POINTER,
    (const void *) i2d_OSSL_NAMED_DAY,
    (const void *) i2d_OSSL_PRIVILEGE_POLICY_ID,
    (const void *) i2d_OSSL_ROLE_SPEC_CERT_ID,
    (const void *) i2d_OSSL_ROLE_SPEC_CERT_ID_SYNTAX,
    (const void *) i2d_OSSL_TARGET,
    (const void *) i2d_OSSL_TARGETING_INFORMATION,
    (const void *) i2d_OSSL_TARGETS,
    (const void *) i2d_OSSL_TIME_PERIOD,
    (const void *) i2d_OSSL_TIME_SPEC,
    (const void *) i2d_OSSL_TIME_SPEC_ABSOLUTE,
    (const void *) i2d_OSSL_TIME_SPEC_DAY,
    (const void *) i2d_OSSL_TIME_SPEC_MONTH,
    (const void *) i2d_OSSL_TIME_SPEC_TIME,
    (const void *) i2d_OSSL_TIME_SPEC_WEEKS,
    (const void *) i2d_OSSL_TIME_SPEC_X_DAY_OF,
    (const void *) i2d_OSSL_USER_NOTICE_SYNTAX,
    (const void *) i2d_OTHERNAME,
    (const void *) i2d_PBE2PARAM,
    (const void *) i2d_PBEPARAM,
    (const void *) i2d_PBKDF2PARAM,
    (const void *) i2d_PBMAC1PARAM,
    (const void *) i2d_PKCS8PrivateKeyInfo_bio,
    (const void *) i2d_PKCS8PrivateKeyInfo_fp,
    (const void *) i2d_PKCS8_PRIV_KEY_INFO,
    (const void *) i2d_PKCS8_PRIV_KEY_INFO_bio,
    (const void *) i2d_PKCS8_PRIV_KEY_INFO_fp,
    (const void *) i2d_PKCS8_bio,
    (const void *) i2d_PKCS8_fp,
    (const void *) i2d_PKEY_USAGE_PERIOD,
    (const void *) i2d_POLICYINFO,
    (const void *) i2d_POLICYQUALINFO,
    (const void *) i2d_PROFESSION_INFO,
    (const void *) i2d_PROXY_CERT_INFO_EXTENSION,
    (const void *) i2d_PROXY_POLICY,
    (const void *) i2d_PUBKEY,
    (const void *) i2d_PUBKEY_bio,
    (const void *) i2d_PUBKEY_fp,
    (const void *) i2d_PrivateKey_bio,
    (const void *) i2d_PrivateKey_fp,
    (const void *) i2d_RSAPrivateKey_bio,
    (const void *) i2d_RSAPrivateKey_fp,
    (const void *) i2d_RSAPublicKey_bio,
    (const void *) i2d_RSAPublicKey_fp,
    (const void *) i2d_RSA_PUBKEY,
    (const void *) i2d_RSA_PUBKEY_bio,
    (const void *) i2d_RSA_PUBKEY_fp,
    (const void *) i2d_SXNET,
    (const void *) i2d_SXNETID,
    (const void *) i2d_USERNOTICE,
    (const void *) i2d_X509,
    (const void *) i2d_X509_ALGOR,
    (const void *) i2d_X509_ALGORS,
    (const void *) i2d_X509_ATTRIBUTE,
    (const void *) i2d_X509_AUX,
    (const void *) i2d_X509_CERT_AUX,
    (const void *) i2d_X509_CINF,
    (const void *) i2d_X509_CRL,
    (const void *) i2d_X509_CRL_INFO,
    (const void *) i2d_X509_CRL_bio,
    (const void *) i2d_X509_CRL_fp,
    (const void *) i2d_X509_EXTENSION,
    (const void *) i2d_X509_NAME,
    (const void *) i2d_X509_NAME_ENTRY,
    (const void *) i2d_X509_PUBKEY,
    (const void *) i2d_X509_PUBKEY_bio,
    (const void *) i2d_X509_PUBKEY_fp,
    (const void *) i2d_X509_REVOKED,
    (const void *) i2d_X509_SIG,
    (const void *) i2d_X509_VAL,
    (const void *) i2d_X509_bio,
    (const void *) i2d_X509_fp,
    (const void *) i2d_re_X509_CRL_tbs,
    (const void *) i2d_re_X509_tbs,
    (const void *) i2s_ASN1_ENUMERATED,
    (const void *) i2s_ASN1_ENUMERATED_TABLE,
    (const void *) i2s_ASN1_IA5STRING,
    (const void *) i2s_ASN1_INTEGER,
    (const void *) i2s_ASN1_OCTET_STRING,
    (const void *) i2s_ASN1_UTF8STRING,
    (const void *) i2v_ASN1_BIT_STRING,
    (const void *) i2v_GENERAL_NAME,
    (const void *) i2v_GENERAL_NAMES,
    (const void *) s2i_ASN1_IA5STRING,
    (const void *) s2i_ASN1_INTEGER,
    (const void *) s2i_ASN1_OCTET_STRING,
    (const void *) s2i_ASN1_UTF8STRING,
    (const void *) v2i_ASN1_BIT_STRING,
    (const void *) v2i_GENERAL_NAME,
    (const void *) v2i_GENERAL_NAMES,
    (const void *) v2i_GENERAL_NAME_ex,
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
