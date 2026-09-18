/*
 * RT-EVP-CLASS -- the four provider-only method classes the behavioural probes never fetched:
 * `EVP_ASYM_CIPHER`, `EVP_KEM`, `EVP_KEYEXCH` and `EVP_SIGNATURE`.
 *
 * The fifth, `EVP_KEYMGMT`, has its own court (`RT-EVP-KEYMGMT`), and `EVP_CIPHER`/`EVP_MD`/
 * `EVP_MAC`/`EVP_KDF`/`EVP_RAND`/`EVP_SKEYMGMT` are driven by their own. These four were not,
 * because nothing in the stratum fetches them -- their algorithms are Phases 8 and 13's. But
 * **the class object and its accessors are this stratum's**, and a probe can observe them without
 * any of those algorithms by publishing one method of its own. That is what this probe does, and
 * it is the difference between "the entry point resolves" (which a reference probe shows) and
 * "the entry point was called and answered" (which this shows).
 *
 * Each class gets one algorithm, `court-<class>`, published with the smallest dispatch table the
 * class' fetch will accept, plus its two context-parameter descriptors. The accessors are then
 * called on the fetched method and every answer is a relation: a string this probe chose, a
 * boolean this probe's own name produces, a pointer identity against the provider this probe
 * registered, or the two static parameter tables. No address is printed.
 *
 * `EVP_*_do_all_provided` walks every loaded provider, so only the probe's own names are counted;
 * the count of everything else is a statement about which strata exist and is deliberately not
 * printed.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>

static void sayb(const char *key, int b)
{
    printf("%s=%d err=%lu\n", key, b ? 1 : 0, ERR_peek_error());
    ERR_clear_error();
}

static void says(const char *key, const char *s)
{
    printf("%s=%s err=%lu\n", key, s == NULL ? "(null)" : s, ERR_peek_error());
    ERR_clear_error();
}

static int court_marker;

static void *c_newctx(void *provctx) { (void) provctx; return malloc(1); }
static void c_freectx(void *cctx) { free(cctx); }

/* ---- ASYM_CIPHER ---- */
static int asym_decrypt_init(void *cctx, void *provkey, const OSSL_PARAM params[])
{ (void) cctx; (void) provkey; (void) params; return 1; }
static int asym_decrypt(void *cctx, unsigned char *out, size_t *outlen, size_t outsize,
                        const unsigned char *in, size_t inlen)
{ (void) cctx; (void) out; (void) outsize; if (outlen) *outlen = 0; (void) in; (void) inlen; return 1; }
static const OSSL_PARAM asym_gt[] = { OSSL_PARAM_utf8_string("court-asym-gt", NULL, 0), OSSL_PARAM_END };
static const OSSL_PARAM asym_st[] = { OSSL_PARAM_utf8_string("court-asym-st", NULL, 0), OSSL_PARAM_END };
static const OSSL_PARAM *asym_gtable(void *cctx) { (void) cctx; return asym_gt; }
static const OSSL_PARAM *asym_stable(void *cctx) { (void) cctx; return asym_st; }

static const OSSL_DISPATCH asym_fns[] = {
    { OSSL_FUNC_ASYM_CIPHER_NEWCTX, (void (*)(void)) c_newctx },
    { OSSL_FUNC_ASYM_CIPHER_FREECTX, (void (*)(void)) c_freectx },
    { OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT, (void (*)(void)) asym_decrypt_init },
    { OSSL_FUNC_ASYM_CIPHER_DECRYPT, (void (*)(void)) asym_decrypt },
    { OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void)) asym_gtable },
    { OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void)) asym_stable },
    { 0, NULL }
};

/* ---- KEM ---- */
static int kem_encapsulate_init(void *vctx, void *provkey, const OSSL_PARAM params[])
{ (void) vctx; (void) provkey; (void) params; return 1; }
static int kem_encapsulate(void *vctx, unsigned char *out, size_t *outlen,
                           unsigned char *secret, size_t *secretlen)
{ (void) vctx; (void) out; if (outlen) *outlen = 0; (void) secret; if (secretlen) *secretlen = 0; return 1; }
static int kem_decapsulate_init(void *vctx, void *provkey, const OSSL_PARAM params[])
{ (void) vctx; (void) provkey; (void) params; return 1; }
static int kem_decapsulate(void *vctx, unsigned char *secret, size_t *secretlen,
                           const unsigned char *in, size_t inlen)
{ (void) vctx; (void) secret; if (secretlen) *secretlen = 0; (void) in; (void) inlen; return 1; }
static const OSSL_PARAM kem_gt[] = { OSSL_PARAM_utf8_string("court-kem-gt", NULL, 0), OSSL_PARAM_END };
static const OSSL_PARAM kem_st[] = { OSSL_PARAM_utf8_string("court-kem-st", NULL, 0), OSSL_PARAM_END };
static const OSSL_PARAM *kem_gtable(void *vctx) { (void) vctx; return kem_gt; }
static const OSSL_PARAM *kem_stable(void *vctx) { (void) vctx; return kem_st; }
/* The KEM class' balance clause counts the *pairs*: a lone `gettable` (or `settable`) is
 * refused where the other classes accept it. Both halves are published so the descriptor
 * counters are 2/2, which is one of the accepted values. */
static int kem_get_ctx(void *vctx, OSSL_PARAM params[]) { (void) vctx; (void) params; return 1; }
static int kem_set_ctx(void *vctx, const OSSL_PARAM params[]) { (void) vctx; (void) params; return 1; }

static const OSSL_DISPATCH kem_fns[] = {
    { OSSL_FUNC_KEM_NEWCTX, (void (*)(void)) c_newctx },
    { OSSL_FUNC_KEM_FREECTX, (void (*)(void)) c_freectx },
    { OSSL_FUNC_KEM_ENCAPSULATE_INIT, (void (*)(void)) kem_encapsulate_init },
    { OSSL_FUNC_KEM_ENCAPSULATE, (void (*)(void)) kem_encapsulate },
    { OSSL_FUNC_KEM_DECAPSULATE_INIT, (void (*)(void)) kem_decapsulate_init },
    { OSSL_FUNC_KEM_DECAPSULATE, (void (*)(void)) kem_decapsulate },
    { OSSL_FUNC_KEM_GET_CTX_PARAMS, (void (*)(void)) kem_get_ctx },
    { OSSL_FUNC_KEM_GETTABLE_CTX_PARAMS, (void (*)(void)) kem_gtable },
    { OSSL_FUNC_KEM_SET_CTX_PARAMS, (void (*)(void)) kem_set_ctx },
    { OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS, (void (*)(void)) kem_stable },
    { 0, NULL }
};

/* ---- KEYEXCH ---- */
static int exch_derive_init(void *vctx, void *provkey, const OSSL_PARAM params[])
{ (void) vctx; (void) provkey; (void) params; return 1; }
static int exch_derive(void *vctx, unsigned char *secret, size_t *secretlen)
{ (void) vctx; (void) secret; if (secretlen) *secretlen = 0; return 1; }
static int exch_set_peer(void *vctx, void *provkey) { (void) vctx; (void) provkey; return 1; }
static const OSSL_PARAM exch_gt[] = { OSSL_PARAM_utf8_string("court-exch-gt", NULL, 0), OSSL_PARAM_END };
static const OSSL_PARAM exch_st[] = { OSSL_PARAM_utf8_string("court-exch-st", NULL, 0), OSSL_PARAM_END };
static const OSSL_PARAM *exch_gtable(void *vctx) { (void) vctx; return exch_gt; }
static const OSSL_PARAM *exch_stable(void *vctx) { (void) vctx; return exch_st; }

static const OSSL_DISPATCH exch_fns[] = {
    { OSSL_FUNC_KEYEXCH_NEWCTX, (void (*)(void)) c_newctx },
    { OSSL_FUNC_KEYEXCH_FREECTX, (void (*)(void)) c_freectx },
    { OSSL_FUNC_KEYEXCH_INIT, (void (*)(void)) exch_derive_init },
    { OSSL_FUNC_KEYEXCH_DERIVE, (void (*)(void)) exch_derive },
    { OSSL_FUNC_KEYEXCH_SET_PEER, (void (*)(void)) exch_set_peer },
    { OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS, (void (*)(void)) exch_gtable },
    { OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS, (void (*)(void)) exch_stable },
    { 0, NULL }
};

/* ---- SIGNATURE ---- */
static int sig_sign_init(void *vctx, void *provkey, const OSSL_PARAM params[])
{ (void) vctx; (void) provkey; (void) params; return 1; }
static int sig_sign(void *vctx, unsigned char *sig, size_t *siglen, size_t sigsize,
                    const unsigned char *tbs, size_t tbslen)
{ (void) vctx; (void) sig; if (siglen) *siglen = 0; (void) sigsize; (void) tbs; (void) tbslen; return 1; }
static int sig_verify_init(void *vctx, void *provkey, const OSSL_PARAM params[])
{ (void) vctx; (void) provkey; (void) params; return 1; }
static int sig_verify(void *vctx, const unsigned char *sig, size_t siglen,
                      const unsigned char *tbs, size_t tbslen)
{ (void) vctx; (void) sig; (void) siglen; (void) tbs; (void) tbslen; return 1; }
static const OSSL_PARAM sig_gt[] = { OSSL_PARAM_utf8_string("court-sig-gt", NULL, 0), OSSL_PARAM_END };
static const OSSL_PARAM sig_st[] = { OSSL_PARAM_utf8_string("court-sig-st", NULL, 0), OSSL_PARAM_END };
static const OSSL_PARAM *sig_gtable(void *vctx) { (void) vctx; return sig_gt; }
static const OSSL_PARAM *sig_stable(void *vctx) { (void) vctx; return sig_st; }

static const OSSL_DISPATCH sig_fns[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void)) c_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void)) c_freectx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void)) sig_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void)) sig_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void)) sig_verify_init },
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void)) sig_verify },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void)) sig_gtable },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void (*)(void)) sig_stable },
    { 0, NULL }
};

static const OSSL_ALGORITHM court_asym_list[] = {
    { "court-asym", "provider=court-class", asym_fns, "court asym cipher" },
    { NULL, NULL, NULL, NULL }
};
static const OSSL_ALGORITHM court_kem_list[] = {
    { "court-kem", "provider=court-class", kem_fns, "court kem" },
    { NULL, NULL, NULL, NULL }
};
static const OSSL_ALGORITHM court_exch_list[] = {
    { "court-exch", "provider=court-class", exch_fns, "court key exchange" },
    { NULL, NULL, NULL, NULL }
};
static const OSSL_ALGORITHM court_sig_list[] = {
    { "court-sig", "provider=court-class", sig_fns, "court signature" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *court_query(void *provctx, int operation_id, int *no_cache)
{
    (void) provctx;
    *no_cache = 0;
    /* One list per operation: a walk of `OSSL_OP_ASYM_CIPHER` must not see a SIGNATURE
     * dispatch table, and returning all four for every operation makes the structural
     * check refuse the method. This is the shape `crypto/provider_core.c` expects. */
    switch (operation_id) {
    case OSSL_OP_ASYM_CIPHER:
        return court_asym_list;
    case OSSL_OP_KEM:
        return court_kem_list;
    case OSSL_OP_KEYEXCH:
        return court_exch_list;
    case OSSL_OP_SIGNATURE:
        return court_sig_list;
    default:
        return NULL;
    }
}

static int court_teardown(void *provctx) { (void) provctx; return 1; }

static const OSSL_DISPATCH court_dispatch[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void)) court_query },
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void)) court_teardown },
    { 0, NULL }
};

static int court_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
                      const OSSL_DISPATCH **out, void **provctx)
{
    (void) handle;
    (void) in;
    *out = court_dispatch;
    *provctx = &court_marker;
    return 1;
}

struct seen { int count; };

static void name_visitor(const char *name, void *data)
{
    struct seen *s = data;

    if (name != NULL && strncmp(name, "court-", 6) == 0)
        s->count++;
}

static void count_visitor(EVP_ASYM_CIPHER *c, void *arg) { (void) c; (*(int *) arg)++; }
static void count_visitor_kem(EVP_KEM *c, void *arg) { (void) c; (*(int *) arg)++; }
static void count_visitor_exch(EVP_KEYEXCH *c, void *arg) { (void) c; (*(int *) arg)++; }
static void count_visitor_sig(EVP_SIGNATURE *c, void *arg) { (void) c; (*(int *) arg)++; }

int main(void)
{
    OSSL_PROVIDER *prov;
    struct seen seen;
    int n;

    setvbuf(stdout, NULL, _IOLBF, 0);

    sayb("provider.add_builtin", OSSL_PROVIDER_add_builtin(NULL, "court-class", court_init));
    prov = OSSL_PROVIDER_load(NULL, "court-class");
    sayb("provider.load", prov != NULL);
    if (prov == NULL)
        return 0;

    /* ---- ASYM_CIPHER ---- */
    {
        EVP_ASYM_CIPHER *m = EVP_ASYM_CIPHER_fetch(NULL, "court-asym", NULL);

        sayb("asym.fetch", m != NULL);
        if (m != NULL) {
            says("asym.name", EVP_ASYM_CIPHER_get0_name(m));
            says("asym.description", EVP_ASYM_CIPHER_get0_description(m));
            sayb("asym.provider_is_ours", (const void *) EVP_ASYM_CIPHER_get0_provider(m) == (const void *) prov);
            sayb("asym.is_a.name", EVP_ASYM_CIPHER_is_a(m, "court-asym"));
            sayb("asym.is_a.other", EVP_ASYM_CIPHER_is_a(m, "no-such-asym"));
            sayb("asym.gettable_ctx", EVP_ASYM_CIPHER_gettable_ctx_params(m) != NULL);
            sayb("asym.settable_ctx", EVP_ASYM_CIPHER_settable_ctx_params(m) != NULL);
            sayb("asym.gettable_ctx.located",
                 OSSL_PARAM_locate_const(EVP_ASYM_CIPHER_gettable_ctx_params(m), "court-asym-gt") != NULL);
            memset(&seen, 0, sizeof seen);
            sayb("asym.names_do_all", EVP_ASYM_CIPHER_names_do_all(m, name_visitor, &seen));
            sayb("asym.names.count", seen.count == 1);
            sayb("asym.up_ref", EVP_ASYM_CIPHER_up_ref(m));
            EVP_ASYM_CIPHER_free(m);
            EVP_ASYM_CIPHER_free(m);
        }
        n = 0;
        EVP_ASYM_CIPHER_do_all_provided(NULL, count_visitor, &n);
        sayb("asym.do_all_provided.ours", n == 1);
    }

    /* ---- KEM ---- */
    {
        EVP_KEM *m = EVP_KEM_fetch(NULL, "court-kem", NULL);

        sayb("kem.fetch", m != NULL);
        if (m != NULL) {
            says("kem.name", EVP_KEM_get0_name(m));
            says("kem.description", EVP_KEM_get0_description(m));
            sayb("kem.provider_is_ours", (const void *) EVP_KEM_get0_provider(m) == (const void *) prov);
            sayb("kem.is_a.name", EVP_KEM_is_a(m, "court-kem"));
            sayb("kem.is_a.other", EVP_KEM_is_a(m, "no-such-kem"));
            sayb("kem.gettable_ctx", EVP_KEM_gettable_ctx_params(m) != NULL);
            sayb("kem.settable_ctx", EVP_KEM_settable_ctx_params(m) != NULL);
            sayb("kem.gettable_ctx.located",
                 OSSL_PARAM_locate_const(EVP_KEM_gettable_ctx_params(m), "court-kem-gt") != NULL);
            memset(&seen, 0, sizeof seen);
            sayb("kem.names_do_all", EVP_KEM_names_do_all(m, name_visitor, &seen));
            sayb("kem.names.count", seen.count == 1);
            sayb("kem.up_ref", EVP_KEM_up_ref(m));
            EVP_KEM_free(m);
            EVP_KEM_free(m);
        }
        n = 0;
        EVP_KEM_do_all_provided(NULL, count_visitor_kem, &n);
        sayb("kem.do_all_provided.ours", n == 1);
    }

    /* ---- KEYEXCH ---- */
    {
        EVP_KEYEXCH *m = EVP_KEYEXCH_fetch(NULL, "court-exch", NULL);

        sayb("exch.fetch", m != NULL);
        if (m != NULL) {
            says("exch.name", EVP_KEYEXCH_get0_name(m));
            says("exch.description", EVP_KEYEXCH_get0_description(m));
            sayb("exch.provider_is_ours", (const void *) EVP_KEYEXCH_get0_provider(m) == (const void *) prov);
            sayb("exch.is_a.name", EVP_KEYEXCH_is_a(m, "court-exch"));
            sayb("exch.is_a.other", EVP_KEYEXCH_is_a(m, "no-such-exch"));
            sayb("exch.gettable_ctx", EVP_KEYEXCH_gettable_ctx_params(m) != NULL);
            sayb("exch.settable_ctx", EVP_KEYEXCH_settable_ctx_params(m) != NULL);
            sayb("exch.gettable_ctx.located",
                 OSSL_PARAM_locate_const(EVP_KEYEXCH_gettable_ctx_params(m), "court-exch-gt") != NULL);
            memset(&seen, 0, sizeof seen);
            sayb("exch.names_do_all", EVP_KEYEXCH_names_do_all(m, name_visitor, &seen));
            sayb("exch.names.count", seen.count == 1);
            sayb("exch.up_ref", EVP_KEYEXCH_up_ref(m));
            EVP_KEYEXCH_free(m);
            EVP_KEYEXCH_free(m);
        }
        n = 0;
        EVP_KEYEXCH_do_all_provided(NULL, count_visitor_exch, &n);
        sayb("exch.do_all_provided.ours", n == 1);
    }

    /* ---- SIGNATURE ---- */
    {
        EVP_SIGNATURE *m = EVP_SIGNATURE_fetch(NULL, "court-sig", NULL);

        sayb("sig.fetch", m != NULL);
        if (m != NULL) {
            says("sig.name", EVP_SIGNATURE_get0_name(m));
            says("sig.description", EVP_SIGNATURE_get0_description(m));
            sayb("sig.provider_is_ours", (const void *) EVP_SIGNATURE_get0_provider(m) == (const void *) prov);
            sayb("sig.is_a.name", EVP_SIGNATURE_is_a(m, "court-sig"));
            sayb("sig.is_a.other", EVP_SIGNATURE_is_a(m, "no-such-sig"));
            sayb("sig.gettable_ctx", EVP_SIGNATURE_gettable_ctx_params(m) != NULL);
            sayb("sig.settable_ctx", EVP_SIGNATURE_settable_ctx_params(m) != NULL);
            sayb("sig.gettable_ctx.located",
                 OSSL_PARAM_locate_const(EVP_SIGNATURE_gettable_ctx_params(m), "court-sig-gt") != NULL);
            memset(&seen, 0, sizeof seen);
            sayb("sig.names_do_all", EVP_SIGNATURE_names_do_all(m, name_visitor, &seen));
            sayb("sig.names.count", seen.count == 1);
            sayb("sig.up_ref", EVP_SIGNATURE_up_ref(m));
            EVP_SIGNATURE_free(m);
            EVP_SIGNATURE_free(m);
        }
        n = 0;
        EVP_SIGNATURE_do_all_provided(NULL, count_visitor_sig, &n);
        sayb("sig.do_all_provided.ours", n == 1);
    }

    /* A name nobody publishes answers NULL on both sides, and the error queue is the
     * fetch's own -- the mark/pop pair every fetch does. */
    sayb("asym.fetch.missing", EVP_ASYM_CIPHER_fetch(NULL, "no-such-asym-at-all", NULL) == NULL);
    return 0;
}
