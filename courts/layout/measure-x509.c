// Layout measurement for the X.509 object core — `X509`, `X509_CRL`, `X509_NAME`,
// `X509_CINF`, `X509_CRL_INFO`, `X509_REVOKED`, `X509_VAL` and `X509_EXTENSION`.
//
// Phase 10.8 transcribes these objects into `src/x509/{x_x509,x_crl,x_name}.rs`,
// stacking them in `#[repr(C)]` structs whose field offsets are asserted with
// `core::mem::offset_of!`. The declarations alone are not enough: the trailing
// `ASN1_ENCODING` and `CRYPTO_EX_DATA` blocks are what decide every offset after
// them, and `X509_VAL` is an embedded pair rather than a pointer. This program
// compiles against the pinned authority's own internal header and prints the
// numbers the Rust asserts carry.
//
// See `courts/layout/README.md` for the include set.
#include <stdio.h>
#include <stddef.h>

#include <openssl/x509.h>
#include "crypto/x509.h"
#include "x509_local.h"

#define SHOW(T) printf("sizeof(%-31s) = %zu\n", #T, sizeof(T))
#define ALIGN(T) printf("alignof(%-30s) = %zu\n", #T, _Alignof(T))
#define OFF(T, m) printf("offsetof(%-23s, %-24s) = %zu\n", #T, #m, offsetof(T, m))

int main(void)
{
    SHOW(ASN1_STRING);
    SHOW(ASN1_ENCODING);
    SHOW(CRYPTO_EX_DATA);
    SHOW(X509_SIG_INFO);
    SHOW(X509_VAL);
    SHOW(struct X509_extension_st);
    SHOW(struct X509_name_entry_st);
    SHOW(struct X509_name_st);
    SHOW(struct x509_cinf_st);
    SHOW(struct x509_st);
    SHOW(struct X509_crl_info_st);
    SHOW(struct X509_crl_st);
    SHOW(struct x509_revoked_st);
    SHOW(struct x509_cert_aux_st);

    OFF(struct X509_extension_st, object);
    OFF(struct X509_extension_st, critical);
    OFF(struct X509_extension_st, value);

    OFF(struct X509_name_entry_st, object);
    OFF(struct X509_name_entry_st, value);
    OFF(struct X509_name_entry_st, set);
    OFF(struct X509_name_entry_st, size);

    OFF(struct X509_name_st, entries);
    OFF(struct X509_name_st, modified);
    OFF(struct X509_name_st, bytes);
    OFF(struct X509_name_st, canon_enc);
    OFF(struct X509_name_st, canon_enclen);

    OFF(struct x509_cinf_st, version);
    OFF(struct x509_cinf_st, serialNumber);
    OFF(struct x509_cinf_st, signature);
    OFF(struct x509_cinf_st, issuer);
    OFF(struct x509_cinf_st, validity);
    OFF(struct x509_cinf_st, subject);
    OFF(struct x509_cinf_st, key);
    OFF(struct x509_cinf_st, issuerUID);
    OFF(struct x509_cinf_st, subjectUID);
    OFF(struct x509_cinf_st, extensions);
    OFF(struct x509_cinf_st, enc);

    OFF(struct x509_st, cert_info);
    OFF(struct x509_st, sig_alg);
    OFF(struct x509_st, signature);
    OFF(struct x509_st, siginf);
    OFF(struct x509_st, references);
    OFF(struct x509_st, ex_data);
    OFF(struct x509_st, ex_pathlen);
    OFF(struct x509_st, ex_pcpathlen);
    OFF(struct x509_st, ex_flags);
    OFF(struct x509_st, ex_kusage);
    OFF(struct x509_st, ex_xkusage);
    OFF(struct x509_st, ex_nscert);
    OFF(struct x509_st, skid);
    OFF(struct x509_st, akid);
    OFF(struct x509_st, policy_cache);
    OFF(struct x509_st, crldp);
    OFF(struct x509_st, altname);
    OFF(struct x509_st, nc);
    OFF(struct x509_st, rfc3779_addr);
    OFF(struct x509_st, rfc3779_asid);
    OFF(struct x509_st, sha1_hash);
    OFF(struct x509_st, aux);
    OFF(struct x509_st, lock);
    OFF(struct x509_st, ex_cached);
    OFF(struct x509_st, distinguishing_id);
    OFF(struct x509_st, libctx);
    OFF(struct x509_st, propq);

    OFF(struct X509_crl_info_st, version);
    OFF(struct X509_crl_info_st, sig_alg);
    OFF(struct X509_crl_info_st, issuer);
    OFF(struct X509_crl_info_st, lastUpdate);
    OFF(struct X509_crl_info_st, nextUpdate);
    OFF(struct X509_crl_info_st, revoked);
    OFF(struct X509_crl_info_st, extensions);
    OFF(struct X509_crl_info_st, enc);

    OFF(struct X509_crl_st, crl);
    OFF(struct X509_crl_st, sig_alg);
    OFF(struct X509_crl_st, signature);
    OFF(struct X509_crl_st, references);
    OFF(struct X509_crl_st, flags);
    OFF(struct X509_crl_st, akid);
    OFF(struct X509_crl_st, idp);
    OFF(struct X509_crl_st, idp_flags);
    OFF(struct X509_crl_st, idp_reasons);
    OFF(struct X509_crl_st, crl_number);
    OFF(struct X509_crl_st, base_crl_number);
    OFF(struct X509_crl_st, issuers);
    OFF(struct X509_crl_st, sha1_hash);
    OFF(struct X509_crl_st, meth);
    OFF(struct X509_crl_st, meth_data);
    OFF(struct X509_crl_st, lock);
    OFF(struct X509_crl_st, libctx);
    OFF(struct X509_crl_st, propq);

    OFF(struct x509_revoked_st, serialNumber);
    OFF(struct x509_revoked_st, revocationDate);
    OFF(struct x509_revoked_st, extensions);
    OFF(struct x509_revoked_st, issuer);
    OFF(struct x509_revoked_st, reason);
    OFF(struct x509_revoked_st, sequence);

    OFF(struct x509_cert_aux_st, trust);
    OFF(struct x509_cert_aux_st, reject);
    OFF(struct x509_cert_aux_st, alias);
    OFF(struct x509_cert_aux_st, keyid);
    OFF(struct x509_cert_aux_st, other);
    return 0;
}
