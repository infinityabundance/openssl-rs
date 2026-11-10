/*
 * openssl-rs — Phase 25 B70 external control: the CMS stack freefunc thunks.
 *
 * SCOPE. B70 discharges the two private `OPENSSL_sk_pop_free` element-free
 * callbacks in src/cms/cms_lib.rs:
 *
 *   x509_free_void      (Rust) == `void (*)(void *)` over X509_free
 *   x509_crl_free_void  (Rust) == `void (*)(void *)` over X509_CRL_free
 *
 * Those thunks are not exported, so the probe cannot name them. It reaches the
 * same registrations through the public exported API. The two `get1` helpers
 * build a temporary stack, up-ref and push each choice, and drain that stack
 * with `OPENSSL_sk_pop_free` over the private thunk when an add step fails:
 *
 *   ossl_cms_get1_certs_ex / ossl_cms_get1_crls_ex in src/cms/cms_lib.rs.
 *
 * Certificate failure arm (REACHED). A `CMS_CertificateChoices` with
 * `type == 0` and `d == NULL`, appended after one valid certificate, makes
 * `X509_add_cert(stack, NULL, X509_ADD_FLAG_UP_REF)` return 0. The one live
 * element already pushed is then drained by the real private `x509_free_void`.
 * `CMS_get1_certs` answers NULL exactly when that arm ran.
 *
 * CRL failure arm (NOT_RUN). The arm fires when `X509_CRL_up_ref` or the
 * push fails. The only externally controllable trigger, a NULL datum, faults
 * inside `X509_CRL_up_ref` before the thunk is installed; a push failure needs
 * an allocation failure. The probe therefore exercises the CRL thunk's callee
 * (`X509_CRL_free`) through the success path, a NULL element and a direct NULL
 * call, and reports the failure arm as NOT_RUN rather than claiming it.
 *
 * A freshly created ASN.1 CHOICE is initialised with `type == -1` and `d ==
 * NULL`; the probe overwrites `type` through the crate's `repr(C)` choice
 * layout and first asserts that fresh layout, so a layout mismatch fails the
 * probe instead of silently changing it.
 *
 * Build (inside the court only):
 *   cc -std=c11 -O1 -Wall -Wextra \
 *      -I artifacts/phase2/install/include \
 *      -o court/tmp/closure-b70-cms/rt_cms_stack_thunks \
 *      courts/phase25/rt_cms_stack_thunks.c \
 *      -L artifacts/phase2/install/lib -lcrypto \
 *      -Wl,-rpath,/work/artifacts/phase2/install/lib
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/stack.h>
#include <openssl/x509.h>

#include <stdio.h>

/* `CMS_CertificateChoices` and `CMS_RevocationInfoChoice` share the
 * `{ int type; void *d; }` layout in the crate (`repr(C)`, cms_asn1.rs). The
 * public header keeps them opaque. */
struct cms_choice_layout {
    int type;
    void *d;
};

/* Probe-local `void (*)(void *)` adapters over the same callees the private
 * thunks wrap, used where the private thunk is not nameable. */
static void cert_free_cb(void *p)
{
    X509_free((X509 *)p);
}

static void crl_free_cb(void *p)
{
    X509_CRL_free((X509_CRL *)p);
}

static int fail(const char *what)
{
    fprintf(stderr, "FAIL %s\n", what);
    ERR_print_errors_fp(stderr);
    return 1;
}

int main(void)
{
    int rc = 0;
    X509 *cert = NULL;
    X509_CRL *crl = NULL;
    CMS_ContentInfo *cms = NULL;
    STACK_OF(X509) *certs = NULL;
    STACK_OF(X509_CRL) *crls = NULL;

    ERR_clear_error();

    cert = X509_new();
    crl = X509_CRL_new();
    if (cert == NULL || crl == NULL) {
        rc = fail("X509_new/X509_CRL_new");
        goto done;
    }

    cms = CMS_ContentInfo_new();
    if (cms == NULL) {
        rc = fail("CMS_ContentInfo_new");
        goto done;
    }
    if (!CMS_SignedData_init(cms)) {
        rc = fail("CMS_SignedData_init");
        goto done;
    }
    if (!CMS_add1_cert(cms, cert)) {
        rc = fail("CMS_add1_cert");
        goto done;
    }
    if (!CMS_add1_crl(cms, crl)) {
        rc = fail("CMS_add1_crl");
        goto done;
    }

    /* 1. Success path: the get1 helpers take an up-ref and return a live
     * one-element stack, which the exported freefunc releases. */
    certs = CMS_get1_certs(cms);
    if (certs == NULL) {
        rc = fail("CMS_get1_certs success path returned NULL");
        goto done;
    }
    if (OPENSSL_sk_num((OPENSSL_STACK *)certs) != 1) {
        rc = fail("CMS_get1_certs success path count != 1");
        goto done;
    }
    OPENSSL_sk_pop_free((OPENSSL_STACK *)certs, cert_free_cb);
    certs = NULL;

    crls = CMS_get1_crls(cms);
    if (crls == NULL) {
        rc = fail("CMS_get1_crls success path returned NULL");
        goto done;
    }
    if (OPENSSL_sk_num((OPENSSL_STACK *)crls) != 1) {
        rc = fail("CMS_get1_crls success path count != 1");
        goto done;
    }
    OPENSSL_sk_pop_free((OPENSSL_STACK *)crls, crl_free_cb);
    crls = NULL;

    /* 2. Certificate failure arm: the NULL-datum choice makes the add step
     * fail after the live certificate was already up-ref'd and pushed, so the
     * real private thunk drains exactly one live element. */
    {
        struct cms_choice_layout *cch =
            (struct cms_choice_layout *)CMS_add0_CertificateChoices(cms);

        if (cch == NULL) {
            rc = fail("CMS_add0_CertificateChoices");
            goto done;
        }
        if (cch->type != -1 || cch->d != NULL) {
            rc = fail("choice layout does not match repr(C) {int; void *}");
            goto done;
        }
        cch->type = 0; /* CMS_CERTCHOICE_CERT */
        cch->d = NULL;
    }

    certs = CMS_get1_certs(cms);
    if (certs != NULL) {
        rc = fail("CMS_get1_certs failure arm not taken");
        goto done;
    }

    /* 3. NULL element. The stack skips a NULL item before calling the
     * freefunc; the freefuncs below must also tolerate NULL directly (case 4). */
    {
        STACK_OF(X509) *ns = sk_X509_new_null();
        STACK_OF(X509_CRL) *ncrl = sk_X509_CRL_new_null();

        if (ns == NULL || ncrl == NULL) {
            rc = fail("sk_X509_new_null/sk_X509_CRL_new_null");
            goto done;
        }
        if (!OPENSSL_sk_push((OPENSSL_STACK *)ns, NULL)
            || !OPENSSL_sk_push((OPENSSL_STACK *)ncrl, NULL)) {
            rc = fail("OPENSSL_sk_push(NULL)");
            goto done;
        }
        OPENSSL_sk_pop_free((OPENSSL_STACK *)ns, cert_free_cb);
        OPENSSL_sk_pop_free((OPENSSL_STACK *)ncrl, crl_free_cb);
    }

    /* 4. The callees the thunks delegate to accept NULL. */
    X509_free(NULL);
    X509_CRL_free(NULL);

done:
    if (certs != NULL)
        OPENSSL_sk_pop_free((OPENSSL_STACK *)certs, cert_free_cb);
    if (crls != NULL)
        OPENSSL_sk_pop_free((OPENSSL_STACK *)crls, crl_free_cb);
    CMS_ContentInfo_free(cms);
    X509_free(cert);
    X509_CRL_free(crl);

    if (rc == 0)
        printf("PASS cms stack thunks: success=1/1 cert_failure_arm=real_thunk "
               "crl_failure_arm=NOT_RUN(needs_push_alloc_failure; NULL datum "
               "faults in X509_CRL_up_ref) null_element=1 direct_null_free=1\n");
    return rc;
}
