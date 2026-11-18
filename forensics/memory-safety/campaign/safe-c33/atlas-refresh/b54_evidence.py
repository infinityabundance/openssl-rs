# Per-row evidence for boundary-sweep-B54 (generator input; kept beside the receipt).
# Key: (file, operation) -> dict(path, registration, caller, type_fact, verdict, missing)

PRINT_I2S = "PRINT_i2s (X509V3_EXT_print i2s arm)"
PRINT_I2R = "PRINT_i2r (X509V3_EXT_print i2r arm)"
PRINT_I2V = "PRINT_i2v/ENCODE (X509V3_EXT_print i2v arm)"
CONF_V2I = "CONFIG_DECODE_v2i (do_ext_nconf v2i arm)"
CONF_S2I = "CONFIG_DECODE_s2i (do_ext_nconf s2i arm)"
CONF_R2I = "CONFIG_DECODE_r2i (do_ext_nconf r2i arm)"
FREE = "FREE_HOOK (X509V3_EXT_print / do_ext_nconf release)"
HELP = "INTERNAL_HELPER (reached from a registered slot)"
D = "DISPATCH_DISCHARGED"
B = "BLOCKED"

PRINT_CALLER = "src/x509/v3_prn.rs:283 resolves the row, :296-316 decodes with that same row's `it`/`d2i`, :317 refuses a NULL decode, and :334-366 calls the slot on that object"
CONF_CALLER = "src/x509/v3_conf.rs:1041 resolves the row under the registry read hold, :1069 refuses a NULL/empty stack, :1087 calls the v2i slot; :1126-1132 encodes and frees with the same row's `it`"
S2I_CALLER = "src/x509/v3_conf.rs:1041 resolves the row, :1097 calls the s2i slot with the caller's NUL-terminated value, :1126-1132 encodes/frees with the same row's `it`"
R2I_CALLER = "src/x509/v3_conf.rs:1041 resolves the row, :1103 reads `(*ctx).db`/`db_meth`, :1110 calls the r2i slot, :1126-1132 encodes/frees with the same row's `it`"

E = {}


def add(file, op, path, registration, caller, type_fact, verdict=D, missing=None):
    E[(file, op)] = dict(
        path=path, registration=registration, caller=caller,
        type_fact=type_fact, verdict=verdict, missing=missing,
    )


# ---------------------------------------------------------------- i2s (7 + audit_i2s)
add("src/ct/ct_x509v3.rs", "i2s_poison", PRINT_I2S,
    "row `ossl_v3_ct_scts[1]` (NID_ct_precert_poison), slot `i2s`; `it = ASN1_NULL_it` (src/ct/ct_x509v3.rs:259-277)",
    PRINT_CALLER,
    "the callback reads neither argument, so no type fact is needed; it returns a fresh CRYPTO_strdup block that the dispatcher's OwnedStr releases once (src/x509/v3_prn.rs:345-346, :374)")
add("src/x509/v3_enum.rs", "i2s_ASN1_ENUMERATED_TABLE", PRINT_I2S,
    "row `ossl_v3_crl_reason` (NID_crl_reason), slot `i2s` = thunk `enum_i2s`; `it = ASN1_ENUMERATED_it`; `usr_data = &CRL_REASONS` (src/x509/v3_enum.rs:184-199)",
    PRINT_CALLER + "; thunk at src/x509/v3_enum.rs:137 casts the value to Asn1String",
    "ASN1_ENUMERATED decodes to the crate's shared `Asn1String` representation, which is exactly the thunk's cast and the `ASN1_ENUMERATED_get` parameter; `usr_data` is the row's own `BitStringBitname` array (the registrar pairing B51-R6 records)")
add("src/x509/v3_ia5.rs", "i2s_ASN1_IA5STRING", PRINT_I2S,
    "rows `ossl_v3_ns_ia5_list[0..6]` built by `ext_ia5string(nid)`, slot `i2s` = thunk `ia5_i2s`; `it = ASN1_IA5STRING_it` (src/x509/v3_ia5.rs:141-158)",
    PRINT_CALLER + "; thunk at src/x509/v3_ia5.rs:193 casts the value to Asn1String",
    "ASN1_IA5STRING decodes to the shared `Asn1String` representation the thunk and the callee take; the callee reads only `data`/`length`")
add("src/x509/v3_skid.rs", "i2s_ASN1_OCTET_STRING", PRINT_I2S,
    "row `ossl_v3_skey_id`, slot `i2s` = thunk `skid_i2s`; `it = ASN1_OCTET_STRING_it` (src/x509/v3_skid.rs:272-287); the same callee is the `i2s` of `ossl_v3_audit_identity` through `audit_i2s`",
    PRINT_CALLER + "; thunk at src/x509/v3_skid.rs:265; direct callers pass a live octet string and a NULL method (src/x509/v3_akid.rs:258)",
    "ASN1_OCTET_STRING decodes to the shared `Asn1String`; both rows declare that item, so every dispatch supplies an octet string with the `length`/`data` invariant the callee reads")
add("src/x509/v3_utf8.rs", "i2s_ASN1_UTF8STRING", PRINT_I2S,
    "row `ossl_v3_utf8_list[0]` (NID_subjectSignTool) built by `ext_utf8string`, slot `i2s` = thunk `utf8_i2s`; `it = ASN1_UTF8STRING_it` (src/x509/v3_utf8.rs:144-156)",
    PRINT_CALLER + "; thunk at src/x509/v3_utf8.rs:178",
    "ASN1_UTF8STRING decodes to the shared `Asn1String`; the callee reads only `data`/`length`")
add("src/x509/v3_utl.rs", "i2s_ASN1_ENUMERATED", PRINT_I2S,
    "internal: the table miss in `i2s_ASN1_ENUMERATED_TABLE` (src/x509/v3_enum.rs:180); `method` is unread",
    "src/x509/v3_enum.rs:180, itself the `i2s` slot of `ossl_v3_crl_reason`",
    "`a` is the same decoded `ASN1_ENUMERATED` the table walk already accepted; `method` is `let _ = method`, so the row's `usr_data` is not read on this path")
add("src/x509/v3_utl.rs", "i2s_ASN1_INTEGER", PRINT_I2S,
    "rows `ossl_v3_crl_num`, `ossl_v3_delta_crl`, `ossl_v3_inhibit_anyp` via thunk `int_i2s`, slot `i2s`; `it = ASN1_INTEGER_it` (src/x509/v3_int.rs:78-140)",
    PRINT_CALLER + "; thunk at src/x509/v3_int.rs:44; direct callers pass a live integer and a NULL method (src/x509/v3_cpols.rs:1513, src/x509/v3_asid.rs:734, src/x509/v3_sxnet.rs:390, src/asn1/tasn_prn.rs:724 docs)",
    "ASN1_INTEGER decodes to the shared `Asn1String`; `method` is `let _ = method`, so no `usr_data` obligation exists on this path")
add("src/x509/v3_audit_id.rs", "audit_i2s", PRINT_I2S,
    "row `ossl_v3_audit_identity`, slot `i2s`; `it = ASN1_OCTET_STRING_it` (src/x509/v3_audit_id.rs:50-64)",
    PRINT_CALLER + "; thunk casts at src/x509/v3_audit_id.rs:33",
    "the row declares ASN1_OCTET_STRING_it, so the decoded object is the `Asn1String` the thunk and callee take")

# ---------------------------------------------------------------- i2r (33)
add("src/ct/ct_x509v3.rs", "i2r_SCT_LIST", PRINT_I2R,
    "rows `ossl_v3_ct_scts[0]` (NID_ct_precert_scts) and `[2]` (NID_ct_cert_scts), slot `i2r`; `it = None`, `d2i = as_d2i(x509_ext_d2i_SCT_LIST | ocsp_ext_d2i_SCT_LIST)` (src/ct/ct_x509v3.rs:242-282)",
    "src/x509/v3_prn.rs:309-315 decodes with the same row's `d2i`; :362-366 calls the slot",
    "the row's only decoder is the SCT-list d2i, whose declared return is `*mut OpenSslStack` (as_d2i's signature, src/ct/ct_x509v3.rs:203-219), so the object is a stack of `Sct`; the printer casts to `OpenSslStack` and `SCT_LIST_print` takes exactly that")
add("src/ocsp/v3_ocsp.rs", "i2r_ocsp_crlid", PRINT_I2R,
    "row `ossl_v3_ocsp_crlid`, slot `i2r`; `it = OCSP_CRLID_it` (src/ocsp/v3_ocsp.rs:467-479)", PRINT_CALLER,
    "ASN1_item_d2i(OCSP_CRLID_it) yields the `OcspCrlId` the printer casts to (`in_.cast::<OcspCrlId>()`, :130)")
add("src/ocsp/v3_ocsp.rs", "i2r_ocsp_acutoff", PRINT_I2R,
    "row `ossl_v3_ocsp_acutoff`, slot `i2r`; `it = ASN1_GENERALIZEDTIME_it` (src/ocsp/v3_ocsp.rs:488-500)", PRINT_CALLER,
    "the decoded object is an ASN1_GENERALIZEDTIME, which this crate represents as `Asn1String`; the cast at :194 is exactly `ASN1_GENERALIZEDTIME_print`'s parameter type")
add("src/ocsp/v3_ocsp.rs", "i2r_ocsp_nonce", PRINT_I2R,
    "row `ossl_v3_ocsp_nonce`, slot `i2r`; `it = None`, `d2i = d2i_ocsp_nonce`, `ext_free = ocsp_nonce_free` (src/ocsp/v3_ocsp.rs:503-519)",
    "src/x509/v3_prn.rs:309-315 decodes with `d2i_ocsp_nonce`; :362-366 calls the slot",
    "`d2i_ocsp_nonce` builds an `ASN1_OCTET_STRING` (src/ocsp/v3_ocsp.rs:265-324) and `ocsp_nonce_free` releases the same type; the printer's cast to `Asn1String` at :351 is that type")
add("src/ocsp/v3_ocsp.rs", "i2r_ocsp_serviceloc", PRINT_I2R,
    "row `ossl_v3_ocsp_serviceloc`, slot `i2r`; `it = OCSP_SERVICELOC_it` (src/ocsp/v3_ocsp.rs:552-564)", PRINT_CALLER,
    "the decoded object is the `OcspServiceLoc` the printer casts to at :413")
add("src/x509/v3_ac_tgt.rs", "i2r_ISSUER_SERIAL", HELP,
    "internal: called only from `i2r_TARGET_CERT` (src/x509/v3_ac_tgt.rs:840) with `(*tc).targetCertificate`",
    "src/x509/v3_ac_tgt.rs:840",
    "the enclosing item makes `targetCertificate` an `OSSL_ISSUER_SERIAL *` (src/x509/v3_ac_tgt.rs:268), which is the printer's cast type")
add("src/x509/v3_ac_tgt.rs", "i2r_OBJECT_DIGEST_INFO", HELP,
    "internal: called from `i2r_TARGET_CERT` (src/x509/v3_ac_tgt.rs:870) with `(*tc).certDigestInfo`",
    "src/x509/v3_ac_tgt.rs:870",
    "`certDigestInfo` is an `OSSL_OBJECT_DIGEST_INFO *` under the enclosing item (src/x509/v3_ac_tgt.rs:272), the printer's cast type")
add("src/x509/v3_ac_tgt.rs", "i2r_TARGET_CERT", HELP,
    "internal: called from `i2r_TARGET`'s `OSSL_TGT_TARGET_CERT` arm (src/x509/v3_ac_tgt.rs:917) with the live union member",
    "src/x509/v3_ac_tgt.rs:917",
    "the selector test at :908 fixes the arm, and the CHOICE descriptor declares that arm as `OsslTargetCert`; the cast at :833 is that type")
add("src/x509/v3_ac_tgt.rs", "i2r_TARGET", HELP,
    "internal: called from `i2r_TARGETS` (src/x509/v3_ac_tgt.rs:950) with one stack element",
    "src/x509/v3_ac_tgt.rs:950",
    "`OSSL_TARGETS` is `SEQUENCE OF OSSL_TARGET` (its template names `OSSL_TARGET_it`, src/x509/v3_ac_tgt.rs:459-490), so each element is an `OsslTarget`; the cast at :897 is that type, and each union arm read is guarded by its selector (:900-935)")
add("src/x509/v3_ac_tgt.rs", "i2r_TARGETS", HELP,
    "internal: called from `i2r_TARGETING_INFORMATION` (src/x509/v3_ac_tgt.rs:978) with one stack element",
    "src/x509/v3_ac_tgt.rs:978",
    "`OSSL_TARGETING_INFORMATION` is `SEQUENCE OF OSSL_TARGETS`, so each element is an `OSSL_TARGETS` stack; the cast at :942 is `OpenSslStack`")
add("src/x509/v3_ac_tgt.rs", "i2r_TARGETING_INFORMATION", PRINT_I2R,
    "row `ossl_v3_targeting_information`, slot `i2r`; `it = OSSL_TARGETING_INFORMATION_it` (src/x509/v3_ac_tgt.rs:1004-1016)", PRINT_CALLER,
    "the decoded object is the outer `STACK_OF(OSSL_TARGETS)` the printer casts to at :970")
add("src/x509/v3_addr.rs", "i2r_IPAddrBlocks", PRINT_I2R,
    "row `ossl_v3_addr`, slot `i2r`; `it = IPAddrBlocks_it` (src/x509/v3_addr.rs:2823-2835)", PRINT_CALLER,
    "`IPAddrBlocks` is `SEQUENCE OF IPAddressFamily`, so the decoded object is the stack of `IpAddressFamily` the printer walks (:929, :936)")
add("src/x509/v3_admis.rs", "i2r_NAMING_AUTHORITY", HELP,
    "internal: called from `i2r_ADMISSION_SYNTAX` (src/x509/v3_admis.rs:695 and :742) with `(*entry).namingAuthority` / `(*pinfo).namingAuthority`",
    "src/x509/v3_admis.rs:695, :742",
    "both enclosing fields are declared `*mut NamingAuthority` in this module, which is the helper's cast type at :565; each call site null-checks first (:694, :741)")
add("src/x509/v3_admis.rs", "i2r_ADMISSION_SYNTAX", PRINT_I2R,
    "row `ossl_v3_ext_admission`, slot `i2r`; `it = ADMISSION_SYNTAX_it` (src/x509/v3_admis.rs:1301-1313)", PRINT_CALLER,
    "the decoded object is the `AdmissionSyntax` the printer casts to at :648; nested elements are typed by the same module's struct declarations")
add("src/x509/v3_asid.rs", "i2r_ASIdentifiers", PRINT_I2R,
    "row `ossl_v3_asid`, slot `i2r`; `it = ASIdentifiers_it` (src/x509/v3_asid.rs:1813-1825)", PRINT_CALLER,
    "the decoded object is the `AsIdentifiers` the printer casts to at :825; both choice fields are typed by the item's arms")
add("src/x509/v3_attrdesc.rs", "i2r_HASH", HELP,
    "internal: called from `i2r_INFO_SYNTAX_POINTER` (src/x509/v3_attrdesc.rs:725) with `(*pointer).hash`",
    "src/x509/v3_attrdesc.rs:725",
    "`OsslInfoSyntaxPointer.hash` is declared `*mut OsslHash` (src/x509/v3_attrdesc.rs:87), the helper's cast type at :645, and the call is null-guarded at :723")
add("src/x509/v3_attrdesc.rs", "i2r_INFO_SYNTAX_POINTER", HELP,
    "internal: called from `i2r_OSSL_INFO_SYNTAX`'s `OSSL_INFO_SYNTAX_TYPE_POINTER` arm (src/x509/v3_attrdesc.rs:777)",
    "src/x509/v3_attrdesc.rs:777",
    "the selector test at :767 fixes the arm, whose field is declared `*mut OsslInfoSyntaxPointer`; the cast at :707 is that type")
add("src/x509/v3_attrdesc.rs", "i2r_OSSL_INFO_SYNTAX", HELP,
    "internal: called from `i2r_OSSL_PRIVILEGE_POLICY_ID` (src/x509/v3_attrdesc.rs:835) with `(*ppid).privPolSyntax`",
    "src/x509/v3_attrdesc.rs:835",
    "`OsslPrivilegePolicyId.privPolSyntax` is declared as the info-syntax pointer type (src/x509/v3_attrdesc.rs, the `dominationRule`/`privPolSyntax` fields), the helper's cast type at :746")
add("src/x509/v3_attrdesc.rs", "i2r_OSSL_PRIVILEGE_POLICY_ID", HELP,
    "internal: called from `i2r_OSSL_ATTRIBUTE_DESCRIPTOR` (src/x509/v3_attrdesc.rs:939)",
    "src/x509/v3_attrdesc.rs:939",
    "`OsslAttributeDescriptor.dominationRule` is declared `*mut OsslPrivilegePolicyId` (src/x509/v3_attrdesc.rs:149), the helper's cast type at :802")
add("src/x509/v3_attrdesc.rs", "i2r_OSSL_ATTRIBUTE_DESCRIPTOR", PRINT_I2R,
    "row `ossl_v3_attribute_descriptor`, slot `i2r`; `it = OSSL_ATTRIBUTE_DESCRIPTOR_it` (src/x509/v3_attrdesc.rs:956-970)", PRINT_CALLER,
    "the decoded object is the `OsslAttributeDescriptor` the printer casts to at :858; the nested calls above are field-typed in the same module")
add("src/x509/v3_attrmap.rs", "i2r_ATTRIBUTE_MAPPING", HELP,
    "internal: called from `i2r_ATTRIBUTE_MAPPINGS` (src/x509/v3_attrmap.rs:671) with one stack element",
    "src/x509/v3_attrmap.rs:671",
    "`OSSL_ATTRIBUTE_MAPPINGS` is a sequence of attribute mappings, so the element is an `OsslAttributeMapping`; the cast at :584 is that type")
add("src/x509/v3_attrmap.rs", "i2r_ATTRIBUTE_MAPPINGS", PRINT_I2R,
    "row `ossl_v3_attribute_mappings`, slot `i2r`; `it = OSSL_ATTRIBUTE_MAPPINGS_it` (src/x509/v3_attrmap.rs:691-705)", PRINT_CALLER,
    "the decoded object is the mapping stack the printer casts to at :661")
add("src/x509/v3_authattid.rs", "i2r_ISSUER_SERIAL", HELP,
    "internal: called from `i2r_auth_attr_id` (src/x509/v3_authattid.rs:247) with one stack element",
    "src/x509/v3_authattid.rs:247",
    "`OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX` is a sequence of issuer-serials, so the element is an `OsslIssuerSerial`; the cast at :172 is that type")
add("src/x509/v3_authattid.rs", "i2r_auth_attr_id", PRINT_I2R,
    "row `ossl_v3_authority_attribute_identifier`, slot `i2r`; `it = OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_it` (src/x509/v3_authattid.rs:265-279)", PRINT_CALLER,
    "the decoded object is the issuer-serial stack the printer casts to at :238")
add("src/x509/v3_crld.rs", "i2r_idp", PRINT_I2R,
    "row `ossl_v3_idp`, slot `i2r`; `it = ISSUING_DIST_POINT_it` (src/x509/v3_crld.rs:2123-2140)", PRINT_CALLER,
    "the decoded object is the `IssuingDistPoint` the printer casts to at :1479")
add("src/x509/v3_crld.rs", "i2r_crldp", PRINT_I2R,
    "rows `ossl_v3_crld` and `ossl_v3_freshest_crl`, slot `i2r`; `it = CRL_DIST_POINTS_it` (src/x509/v3_crld.rs:2092-2118)", PRINT_CALLER,
    "`CRL_DIST_POINTS` is a sequence of `DIST_POINT`, so the decoded object is that stack and each element the `DistPoint` the printer casts to at :1650")
add("src/x509/v3_crld.rs", "i2r_crl_invdate", PRINT_I2R,
    "row `ossl_v3_crl_invdate`, slot `i2r`; `it = ASN1_GENERALIZEDTIME_it` (src/x509/v3_crld.rs:2144-2160)", PRINT_CALLER,
    "the decoded object is an ASN1_GENERALIZEDTIME, the `Asn1String` representation `ASN1_GENERALIZEDTIME_print` takes (:1698)")
add("src/x509/v3_crld.rs", "i2r_object", PRINT_I2R,
    "row `ossl_v3_crl_hold`, slot `i2r`; `it = ASN1_OBJECT_it` (src/x509/v3_crld.rs:2165-2181)", PRINT_CALLER,
    "the decoded object is the ASN1_OBJECT the printer casts to at :1718")
add("src/x509/v3_crld.rs", "i2r_aaidp", PRINT_I2R,
    "row `ossl_v3_aa_issuing_dist_point`, slot `i2r`; `it = OSSL_AA_DIST_POINT_it` (src/x509/v3_crld.rs:2186-2202)", PRINT_CALLER,
    "the decoded object is the `AaDistPoint` the printer casts to at :2011")
add("src/x509/v3_ncons.rs", "i2r_NAME_CONSTRAINTS", PRINT_I2R,
    "rows `ossl_v3_name_constraints`, `_holder_name_constraints`, `_delegated_name_constraints`, slot `i2r`; all declare `NAME_CONSTRAINTS_it` (src/x509/v3_ncons.rs:1512-1570)", PRINT_CALLER,
    "all three rows declare the same item, so every dispatch decodes a `NameConstraints`, the printer's cast type at :596")
add("src/x509/v3_pci.rs", "i2r_pci", PRINT_I2R,
    "row `ossl_v3_pci`, slot `i2r`; `it = PROXY_CERT_INFO_EXTENSION_it` (src/x509/v3_pci.rs:781-796)", PRINT_CALLER,
    "the decoded object is the `ProxyCertInfoExtension` the printer casts to at :589")
add("src/x509/v3_rolespec.rs", "i2r_OSSL_ROLE_SPEC_CERT_ID", HELP,
    "internal: called from `i2r_OSSL_ROLE_SPEC_CERT_ID_SYNTAX` (src/x509/v3_rolespec.rs:425) with one stack element",
    "src/x509/v3_rolespec.rs:425",
    "the syntax item is a sequence of role-spec certificate identifiers, so the element is an `OsslRoleSpecCertId`; the cast at :305 is that type")
add("src/x509/v3_rolespec.rs", "i2r_OSSL_ROLE_SPEC_CERT_ID_SYNTAX", PRINT_I2R,
    "row `ossl_v3_role_spec_cert_identifier`, slot `i2r`; `it = OSSL_ROLE_SPEC_CERT_ID_SYNTAX_it` (src/x509/v3_rolespec.rs:455-469)", PRINT_CALLER,
    "the decoded object is the identifier stack the printer casts to at :400")

# ---------------------------------------------------------------- i2v (11) + bitst_i2v
add("src/x509/v3_akid.rs", "i2v_AUTHORITY_KEYID", PRINT_I2V,
    "row `ossl_v3_akey_id`, slot `i2v` = thunk `akid_i2v`; `it = AUTHORITY_KEYID_it` (src/x509/v3_akid.rs:207-223)",
    "src/x509/v3_prn.rs:353-361 calls the slot with `extlist = NULL`",
    "the row declares AUTHORITY_KEYID_it, so the decoded object is the `AuthorityKeyid` the thunk casts to (:189); the returned stack transfers to the dispatcher, which pops it free at :372")
add("src/x509/v3_battcons.rs", "i2v_OSSL_BASIC_ATTR_CONSTRAINTS", PRINT_I2V,
    "row `ossl_v3_battcons`, slot `i2v`; `it = OSSL_BASIC_ATTR_CONSTRAINTS_it` (src/x509/v3_battcons.rs:301-315)",
    "src/x509/v3_prn.rs:353-361 calls the slot with `extlist = NULL`",
    "the decoded object is the `OsslBasicAttrConstraints` the callback casts to at :199")
add("src/x509/v3_bcons.rs", "i2v_BASIC_CONSTRAINTS", PRINT_I2V,
    "row `ossl_v3_bcons`, slot `i2v`; `it = BASIC_CONSTRAINTS_it` (src/x509/v3_bcons.rs:302-316)",
    "src/x509/v3_prn.rs:353-361 calls the slot with `extlist = NULL`",
    "the decoded object is the `BasicConstraints` the callback casts to at :200 (proven by B54-C2 and the B54-W witness)")
add("src/x509/v3_extku.rs", "i2v_EXTENDED_KEY_USAGE", PRINT_I2V,
    "rows built by `ext_key_usage_row` (`ossl_v3_ext_ku`, `_ocsp_accresp`, `_acc_cert_policies`, `_acc_priv_policies`), slot `i2v`; all `it = EXTENDED_KEY_USAGE_it` (src/x509/v3_extku.rs:297-313)",
    "src/x509/v3_prn.rs:353-361 calls the slot with `extlist = NULL`",
    "`EXTENDED_KEY_USAGE` is a sequence of ASN1_OBJECT, so the decoded object is that stack and each element the `Asn1Object` the callback reads (:192)")
add("src/x509/v3_info.rs", "i2v_AUTHORITY_INFO_ACCESS", PRINT_I2V,
    "rows `ossl_v3_info`, `ossl_v3_sinfo` built by `info_access_row`, slot `i2v`; `it = AUTHORITY_INFO_ACCESS_it` (src/x509/v3_info.rs:568-584)",
    "src/x509/v3_prn.rs:353-361 calls the slot with `extlist = NULL`",
    "the decoded object is the `ACCESS_DESCRIPTION` stack the callback casts to at :331; each element's `location` is a `GeneralName` field")
add("src/x509/v3_pcons.rs", "i2v_POLICY_CONSTRAINTS", PRINT_I2V,
    "row `ossl_v3_policy_constraints`, slot `i2v`; `it = POLICY_CONSTRAINTS_it` (src/x509/v3_pcons.rs:283-297)",
    "src/x509/v3_prn.rs:353-361 calls the slot with `extlist = NULL`",
    "the decoded object is the `PolicyConstraints` the callback casts to at :162")
add("src/x509/v3_pmaps.rs", "i2v_POLICY_MAPPINGS", PRINT_I2V,
    "row `ossl_v3_policy_mappings`, slot `i2v`; `it = POLICY_MAPPINGS_it` (src/x509/v3_pmaps.rs:353-367)",
    "src/x509/v3_prn.rs:353-361 calls the slot with `extlist = NULL`",
    "`POLICY_MAPPINGS` is a sequence of `POLICY_MAPPING`, so the decoded object is that stack and each element the `PolicyMapping` the callback reads (:208)")
add("src/x509/v3_tlsf.rs", "i2v_TLS_FEATURE", PRINT_I2V,
    "row `ossl_v3_tls_feature`, slot `i2v`; `it = tls_feature_it` (src/x509/v3_tlsf.rs:328-342)",
    "src/x509/v3_prn.rs:353-361 calls the slot with `extlist = NULL`",
    "`TLS_FEATURE` is `SEQUENCE OF ASN1_INTEGER`, so the decoded object is that stack and each element the `Asn1String` the callback reads (:186)")
add("src/x509/v3_san.rs", "i2v_GENERAL_NAMES", PRINT_I2V,
    "rows `ossl_v3_alt[0..2]` built by `alt_row`, slot `i2v` = thunk `san_i2v`; all `it = GENERAL_NAMES_it` (src/x509/v3_san.rs:1194-1218)",
    "src/x509/v3_prn.rs:353-361 calls the slot with `extlist = NULL`; direct caller src/x509/v3_akid.rs:290 passes `(*akeyid).issuer`",
    "the decoded object is the `GENERAL_NAMES` stack the thunk and callee take (:317); each element is a `GeneralName`")
add("src/x509/v3_san.rs", "i2v_GENERAL_NAME", HELP,
    "internal: called from `i2v_GENERAL_NAMES` (src/x509/v3_san.rs:330) with a stack element, and from `i2v_AUTHORITY_INFO_ACCESS` (src/x509/v3_info.rs:337) with `(*desc).location`",
    "src/x509/v3_san.rs:330; src/x509/v3_info.rs:337",
    "`GENERAL_NAMES` is a sequence of `GENERAL_NAME`, so each stack element is a `GeneralName`; `AccessDescription.location` is declared a `GeneralName *`, which is the callback's parameter type")
add("src/x509/v3_bitst.rs", "i2v_ASN1_BIT_STRING", HELP,
    "thunk `bitst_i2v` (src/x509/v3_bitst.rs:356), the `i2v` slot of `ossl_v3_nscert` and `ossl_v3_key_usage`; `it = ASN1_BIT_STRING_it`",
    "src/x509/v3_prn.rs:353-361 -> `bitst_i2v` (src/x509/v3_bitst.rs:349-358)",
    "the decoded object is an ASN1_BIT_STRING (the `Asn1String` the callback casts to at :242); `method` is the same row, whose `usr_data` is that row's `BitStringBitname` table (the registrar pairing)")

# ---------------------------------------------------------------- v2i (12) + bitst_v2i
add("src/x509/v3_addr.rs", "v2i_IPAddrBlocks", CONF_V2I,
    "row `ossl_v3_addr`, slot `v2i`; `it = IPAddrBlocks_it` (src/x509/v3_addr.rs:2823-2835)", CONF_CALLER,
    "`values` is the dispatcher's CONF_VALUE stack (all elements cast to `ConfValue` at :2262); the returned stack is the `IpAddressFamilies` sequence the row's item encodes. `_ctx` is unread, so NULL ctx is harmless here")
add("src/x509/v3_akid.rs", "v2i_AUTHORITY_KEYID", CONF_V2I,
    "row `ossl_v3_akey_id`, slot `v2i` = thunk `akid_v2i`; `it = AUTHORITY_KEYID_it` (src/x509/v3_akid.rs:207-223)", CONF_CALLER + "; thunk at src/x509/v3_akid.rs:194",
    "`values` elements are CONF_VALUE (:387); the returned `AuthorityKeyid` is the row's item type. `ctx` is read only after an explicit NULL guard that raises and returns (:455-461), so a NULL ctx cannot reach a dereference")
add("src/x509/v3_bitst.rs", "v2i_ASN1_BIT_STRING", CONF_V2I,
    "thunk `bitst_v2i` (src/x509/v3_bitst.rs:366), the `v2i` slot of `ossl_v3_nscert` and `ossl_v3_key_usage`; `it = ASN1_BIT_STRING_it`",
    CONF_CALLER + " -> `bitst_v2i` (src/x509/v3_bitst.rs:360-368)",
    "`nval` elements are CONF_VALUE (cast at :300); the returned ASN1_BIT_STRING is the row's item type; `usr_data` is the row's `BitStringBitname` table (registrar pairing)")
add("src/x509/v3_crld.rs", "v2i_crld", CONF_V2I,
    "rows `ossl_v3_crld`, `ossl_v3_freshest_crl`, slot `v2i`; `it = CRL_DIST_POINTS_it` (src/x509/v3_crld.rs:2092-2118)", CONF_CALLER,
    "`nval` elements are CONF_VALUE (:1343); the returned stack is `CRL_DIST_POINTS`. BUT the contract states `ctx` is live while the dispatcher permits NULL: an entry with no value takes the section branch and calls `X509V3_get_section(ctx, …)` (:1348), which dereferences `(*ctx).db` (src/x509/v3_conf.rs:430), so a documented-valid NULL ctx faults",
    B, "ctx non-NULL is not established: `X509V3_EXT_nconf*` document `ctx` as nullable (src/x509/v3_conf.rs:1223-1232, :1240-1250) and do_ext_nconf does not check it, while v2i_crld's value-less branch dereferences ctx at :1348 via X509V3_get_section (src/x509/v3_conf.rs:430)")
add("src/x509/v3_crld.rs", "v2i_idp", CONF_V2I,
    "row `ossl_v3_idp`, slot `v2i`; `it = ISSUING_DIST_POINT_it` (src/x509/v3_crld.rs:2123-2140)", CONF_CALLER,
    "`nval` elements are CONF_VALUE (:1567); the returned `IssuingDistPoint` is the row's item type. BUT `ctx` is forwarded to `set_dist_point_name` (:1576), whose value-less branch calls `X509V3_get_section(ctx, …)` (:1015), which dereferences ctx; the dispatcher permits NULL",
    B, "ctx non-NULL is not established (same defect as v2i_crld): the value-less entry reaches X509V3_get_section at :1015 with the NULL the entry contract allows")
add("src/x509/v3_crld.rs", "v2i_aaidp", CONF_V2I,
    "row `ossl_v3_aa_issuing_dist_point`, slot `v2i`; `it = OSSL_AA_DIST_POINT_it` (src/x509/v3_crld.rs:2186-2202)", CONF_CALLER,
    "`nval` elements are CONF_VALUE (:1926); the returned `AaDistPoint` is the row's item type. BUT the value-less branch calls `X509V3_get_section(ctx, (*cnf).name)` (:1931), which dereferences ctx, while the dispatcher permits NULL",
    B, "ctx non-NULL is not established: v2i_aaidp's own contract requires a live ctx, but do_ext_nconf's and the public entries' contracts permit NULL and the dispatcher passes it through to :1931")
add("src/x509/v3_ncons.rs", "v2i_NAME_CONSTRAINTS", CONF_V2I,
    "rows `ossl_v3_name_constraints`, `_holder_…`, `_delegated_…`, slot `v2i`; all declare `NAME_CONSTRAINTS_it` (src/x509/v3_ncons.rs:1512-1570)", CONF_CALLER,
    "`nval` elements are CONF_VALUE (:398); the returned `NameConstraints` is the row's item type. BUT the body forwards `ctx` to `v2i_GENERAL_NAME_ex` (:453), which reaches `do_dirname` -> `X509V3_get_section(ctx, …)` for a `dirName` value (src/x509/v3_san.rs:871), and the contract does not state that ctx must be live",
    B, "the contract states only that `method`/`ctx` «are the caller's»; the callback requires a live ctx on the `dirName` path (:453 -> src/x509/v3_san.rs:871), and the dispatcher permits NULL")
add("src/x509/v3_san.rs", "v2i_GENERAL_NAME_ex", CONF_V2I,
    "public helper; called from `v2i_NAME_CONSTRAINTS` (src/x509/v3_ncons.rs:453), `v2i_AUTHORITY_INFO_ACCESS` (src/x509/v3_info.rs:493) and `v2i_GENERAL_NAME` (:1120)",
    "src/x509/v3_ncons.rs:453; src/x509/v3_info.rs:493; src/x509/v3_san.rs:1120",
    "`cnf` is a live CONF_VALUE at every call site. BUT the stated contract «`ctx` is NULL or live» is false: the `dirName`/`otherName` arms call `do_dirname(value, ctx)` -> `X509V3_get_section(ctx, …)` (:871) and `ASN1_generate_v3(…, ctx)` (:817), both of which require a live ctx",
    B, "the contract is false: `ctx` is dereferenced on the `dirName` path (:871 -> src/x509/v3_conf.rs:430) after the contract admits NULL; and NULL is what the dispatcher may pass")
add("src/x509/v3_san.rs", "v2i_GENERAL_NAME", CONF_V2I,
    "public helper; called from `v2i_GENERAL_NAMES` (:1152), `v2i_issuer_alt` and `v2i_subject_alt`",
    "src/x509/v3_san.rs:1152, :1281, :1389",
    "`cnf` is a live CONF_VALUE and the returned `GeneralName` is a `GENERAL_NAMES` element. BUT the stated contract «`ctx` is NULL or live» is false for the same `dirName` path it forwards to",
    B, "same false contract as v2i_GENERAL_NAME_ex: the forwarded `ctx` is dereferenced at src/x509/v3_san.rs:871 on the `dirName` arm")
add("src/x509/v3_san.rs", "v2i_GENERAL_NAMES", CONF_V2I,
    "public helper; called from `v2i_crld`'s section path (src/x509/v3_crld.rs:966) with a parsed CONF_VALUE stack",
    "src/x509/v3_crld.rs:966",
    "`nval` elements are CONF_VALUE; each is handed to `v2i_GENERAL_NAME`, which dereferences a NULL ctx on the `dirName` arm",
    B, "the stated contract «`ctx` is NULL or live» is false: the elements reach `X509V3_get_section(ctx, …)` through `v2i_GENERAL_NAME` -> `do_dirname` (src/x509/v3_san.rs:871)")
add("src/x509/v3_san.rs", "v2i_issuer_alt", CONF_V2I,
    "row `ossl_v3_alt[1]`, slot `v2i` = thunk `san_v2i_issuer`; `it = GENERAL_NAMES_it` (src/x509/v3_san.rs:1194-1214)",
    CONF_CALLER + "; thunk at src/x509/v3_san.rs:1186",
    "`nval` elements are CONF_VALUE (:1281) and the returned stack is the `GENERAL_NAMES` the row's item encodes; each element is built by `v2i_GENERAL_NAME`. BUT the contract «ctx NULL or live» is false: the general-name arms dereference ctx (`copy_email` guards it, but `do_dirname`/`X509V3_get_section` does not, :871)",
    B, "false ctx contract: the `dirName` value reaches src/x509/v3_san.rs:871 with the NULL the contract allows")
add("src/x509/v3_san.rs", "v2i_subject_alt", CONF_V2I,
    "row `ossl_v3_alt[0]`, slot `v2i` = thunk `san_v2i`; `it = GENERAL_NAMES_it` (src/x509/v3_san.rs:1194-1214)",
    CONF_CALLER + "; thunk at src/x509/v3_san.rs:1178",
    "`nval` elements are CONF_VALUE (:1389) and the returned stack is the `GENERAL_NAMES` the row's item encodes. `copy_email` has an explicit NULL guard (:1429-1437) but the `dirName` arm's `do_dirname` -> `X509V3_get_section` (:871) does not, so the stated «ctx NULL or live» contract is false",
    B, "false ctx contract: the `dirName` value reaches src/x509/v3_san.rs:871 with the NULL the contract allows")

# ---------------------------------------------------------------- s2i (6)
add("src/ct/ct_x509v3.rs", "s2i_poison", CONF_S2I,
    "row `ossl_v3_ct_scts[1]`, slot `s2i`; `it = ASN1_NULL_it` (src/ct/ct_x509v3.rs:259-277)", S2I_CALLER,
    "the callback reads none of its arguments; the returned `ASN1_NULL` is exactly the row's item type, so the encode/free pairing is the registrar's declared one")
add("src/x509/v3_ia5.rs", "s2i_ASN1_IA5STRING", CONF_S2I,
    "rows `ossl_v3_ns_ia5_list[0..6]`, slot `s2i` = thunk `ia5_s2i`; `it = ASN1_IA5STRING_it` (src/x509/v3_ia5.rs:141-158)",
    S2I_CALLER + "; thunk at src/x509/v3_ia5.rs:217",
    "`value` is the caller's NUL-terminated string (the callee accepts NULL or NUL-terminated and frees its partial result); the returned ASN1_IA5STRING is the row's item type")
add("src/x509/v3_skid.rs", "s2i_ASN1_OCTET_STRING", CONF_S2I,
    "`s2i` slot of `ossl_v3_audit_identity` through `audit_s2i` (src/x509/v3_audit_id.rs:43), and the callee of `s2i_skey_id`'s fallback (src/x509/v3_skid.rs:218)",
    S2I_CALLER + "; src/x509/v3_skid.rs:218; src/x509/v3_audit_id.rs:43",
    "`str_` is non-NULL NUL-terminated at every call site (do_ext_nconf's contract; `s2i_skey_id`'s own contract); the returned ASN1_OCTET_STRING is the `ASN1_OCTET_STRING_it` both rows declare")
add("src/x509/v3_skid.rs", "s2i_skey_id", CONF_S2I,
    "row `ossl_v3_skey_id`, slot `s2i`; `it = ASN1_OCTET_STRING_it` (src/x509/v3_skid.rs:272-287)", S2I_CALLER,
    "`str_` is non-NULL NUL-terminated (stated and required by both `strcmp` calls); `ctx` is read only after an explicit NULL guard (:227-234), so a NULL ctx is refused, not dereferenced; the returned octet string is the row's item type")
add("src/x509/v3_utf8.rs", "s2i_ASN1_UTF8STRING", CONF_S2I,
    "row `ossl_v3_utf8_list[0]`, slot `s2i` = thunk `utf8_s2i`; `it = ASN1_UTF8STRING_it` (src/x509/v3_utf8.rs:144-156)",
    S2I_CALLER + "; thunk at src/x509/v3_utf8.rs:202",
    "`value` is NULL or NUL-terminated (handled by the callee); the returned ASN1_UTF8STRING is the row's item type")
add("src/x509/v3_utl.rs", "s2i_ASN1_INTEGER", CONF_S2I,
    "rows `ossl_v3_inhibit_anyp` via thunk `s2i_asn1_int`, slot `s2i`; `it = ASN1_INTEGER_it` (src/x509/v3_int.rs:117-140)",
    S2I_CALLER + "; thunk at src/x509/v3_int.rs:78; direct caller src/asn1/asn1_gen.rs:777 passes a NULL method",
    "`method` is `let _ = method`, so the NULL method of the ASN1-generator path is harmless; `value` is NULL or NUL-terminated and is refused when NULL (:529-535); the returned ASN1_INTEGER is the row's item type")

# ---------------------------------------------------------------- r2i (2)
add("src/x509/v3_cpols.rs", "r2i_certpol", CONF_R2I,
    "row `ossl_v3_cpols`, slot `r2i`; `it = CERTIFICATEPOLICIES_it` (src/x509/v3_cpols.rs:1602-1619)", R2I_CALLER,
    "the returned certificate-policy stack is the row's item type. BUT the dispatcher dereferences `ctx` before the call (:1103) and the callback calls `X509V3_get_section(ctx, …)` (:1012, :1295), while its own contract and the entry's admit NULL",
    B, "ctx non-NULL is not established: do_ext_nconf's r2i arm reads `(*ctx).db` at :1103 before any callback, and r2i_certpol dereferences ctx at :1012/:1295, but both `r2i_certpol` (:1246) and the public entries (:1223-1232) document `ctx` as nullable")
add("src/x509/v3_pci.rs", "r2i_pci", CONF_R2I,
    "row `ossl_v3_pci`, slot `r2i`; `it = PROXY_CERT_INFO_EXTENSION_it` (src/x509/v3_pci.rs:781-796)", R2I_CALLER,
    "the returned `ProxyCertInfoExtension` is the row's item type. BUT the dispatcher dereferences `ctx` at :1103 before the call and the callback calls `X509V3_get_section(ctx, …)` (:684), while the public entry contract admits NULL",
    B, "ctx non-NULL is not established: the dispatcher's r2i guard reads `(*ctx).db` at :1103 and r2i_pci dereferences ctx at :684, but X509V3_EXT_nconf* document `ctx` as nullable")

# ---------------------------------------------------------------- free (3)
add("src/ct/ct_sct.rs", "SCT_LIST_free", FREE,
    "`ext_free` of `ossl_v3_ct_scts[0]`/`[2]` through `as_free` (src/ct/ct_x509v3.rs:247, :281); also an exported `SCT_LIST_free` for C callers",
    "src/x509/v3_prn.rs:375-382 (ext_free, after the same row's d2i) and :374-382's print cleanup",
    "the print path frees the object the same row's `d2i` produced, i.e. a `STACK_OF(SCT)`; `SCT_LIST_free` pops each element with `sct_free_void`, so the release matches the decoder's element type. As an exported function its C contract is `NULL or a live STACK_OF(SCT)`")
add("src/ocsp/v3_ocsp.rs", "ocsp_nonce_free", FREE,
    "`ext_free` of `ossl_v3_ocsp_nonce`, whose `it` is None and whose `d2i` is `d2i_ocsp_nonce` (src/ocsp/v3_ocsp.rs:503-519)",
    "src/x509/v3_prn.rs:375-382; the do_ext_nconf path cannot reach it because the row has no v2i/s2i/r2i",
    "`d2i_ocsp_nonce` builds an ASN1_OCTET_STRING and this releases that same type; NULL is handled; the row's only decoder is the one whose type the free matches")
add("src/x509/v3_lib.rs", "ext_list_free", FREE,
    "the destructor of the registry's `ext_list`, whose comparator is `ext_cmp` (src/x509/v3_lib.rs:608-631)",
    "src/x509/v3_lib.rs:755 (`OPENSSL_sk_pop_free(list, Some(ext_list_free))` in `X509V3_EXT_cleanup`)",
    "every element is a `*const X509V3ExtMethod` pushed by this module's only writer, so the cast is the element type; a NULL element is ignored, a DYNAMIC row is the single `CRYPTO_malloc` block `X509V3_EXT_add_alias` made and is released once, and a non-DYNAMIC (caller-owned) row is left alone")

# ---------------------------------------------------------------- helpers (7)
add("src/x509/v3_asid.rs", "as_identifier_choice_canonize", HELP,
    "internal: called from `v2i_ASIdentifiers` on the object it is building (src/x509/v3_asid.rs:1441, :1445)",
    "src/x509/v3_asid.rs:1441, :1445",
    "the argument is `(*asid).asnum`/`(*asid).rdi` on an `ASIdentifiers` the same function owns; NULL and the `inherit` arm return early (:1268-1273), and the stack arm's elements are `AsIdOrRange` per the item descriptor")
add("src/x509/v3_bitst.rs", "bitst_i2v", PRINT_I2V,
    "`i2v` slot of `ossl_v3_nscert` and `ossl_v3_key_usage` (src/x509/v3_bitst.rs:371-402)",
    "src/x509/v3_prn.rs:353-361 -> this thunk",
    "forwards the row and the decoded ASN1_BIT_STRING unchanged to `i2v_ASN1_BIT_STRING`; both preconditions (item type and `usr_data` table) are the row's own")
add("src/x509/v3_bitst.rs", "bitst_v2i", CONF_V2I,
    "`v2i` slot of `ossl_v3_nscert` and `ossl_v3_key_usage` (src/x509/v3_bitst.rs:371-402)",
    CONF_CALLER + " -> this thunk",
    "forwards the row and the live CONF_VALUE stack unchanged to `v2i_ASN1_BIT_STRING`; both preconditions are the row's own, and `ctx` is dropped (NULL is harmless)")
add("src/x509/v3_timespec.rs", "print_int_month", HELP,
    "internal: called from `i2r_OSSL_TIME_SPEC`'s `intMonth` arm (src/x509/v3_timespec.rs:1973)",
    "src/x509/v3_timespec.rs:1973",
    "`month` is an `i64` value produced by `ASN1_INTEGER_get_int64` on a live element; the only pointer is `out`, the caller's live BIO")
add("src/x509/v3_timespec.rs", "print_bit_week", HELP,
    "internal: called from `i2r_OSSL_TIME_SPEC`'s `bitWeek` arm (src/x509/v3_timespec.rs:1930)",
    "src/x509/v3_timespec.rs:1930",
    "`bs` is `(*weeks).choice` under the `OSSL_TIME_SPEC_WEEKS_TYPE_BIT` selector, i.e. the ASN1_BIT_STRING arm the item declares")
add("src/x509/v3_timespec.rs", "print_day_of_week", HELP,
    "internal: called from `i2r_OSSL_TIME_SPEC`'s `bitDay` arm (src/x509/v3_timespec.rs:1773) and from `print_bit_named_day` (:1619)",
    "src/x509/v3_timespec.rs:1773, :1619",
    "`bs` is `(*days).choice` under the `OSSL_TIME_SPEC_DAY_TYPE_BIT` selector (or the `bitDay` member `print_bit_named_day` receives), i.e. the ASN1_BIT_STRING arm")
add("src/x509/v3_timespec.rs", "print_int_day_of_week", HELP,
    "internal: called from `i2r_OSSL_TIME_SPEC`'s `intDay` arm (src/x509/v3_timespec.rs:1759)",
    "src/x509/v3_timespec.rs:1759",
    "`dow` is an `i64` value produced by `ASN1_INTEGER_get_int64`; no pointer besides the caller's live BIO")

# ---------------------------------------------------------------- audit (2)
add("src/x509/v3_audit_id.rs", "audit_i2s", PRINT_I2S, "", "", "")
add("src/x509/v3_audit_id.rs", "audit_s2i", CONF_S2I,
    "row `ossl_v3_audit_identity`, slot `s2i`; `it = ASN1_OCTET_STRING_it` (src/x509/v3_audit_id.rs:50-64)",
    S2I_CALLER + "; thunk at src/x509/v3_audit_id.rs:43",
    "`value` is the caller's NUL-terminated string and is neither freed nor retained; the returned ASN1_OCTET_STRING is the row's item type")

# audit_i2s is written above as an i2s row; drop the placeholder only if overridden
E.pop(("src/x509/v3_audit_id.rs", "audit_i2s"))
add("src/x509/v3_audit_id.rs", "audit_i2s", PRINT_I2S,
    "row `ossl_v3_audit_identity`, slot `i2s`; `it = ASN1_OCTET_STRING_it` (src/x509/v3_audit_id.rs:50-64)",
    PRINT_CALLER + "; thunk casts at src/x509/v3_audit_id.rs:33",
    "the row declares ASN1_OCTET_STRING_it, so the decoded object is the `Asn1String` the thunk and `i2s_ASN1_OCTET_STRING` take")
