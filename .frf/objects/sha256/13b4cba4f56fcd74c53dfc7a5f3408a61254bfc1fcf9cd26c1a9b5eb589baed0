/*
 * RT-DSA -- the differential court for `crypto/dsa/` (Phase 8.6).
 *
 * This program is compiled **twice**, once against the admitted authority and once against the
 * candidate distribution shell, and the two `key=value` transcripts are diffed. It never decides
 * anything: a residual is a difference between two executions, so the expectation cannot drift
 * with the crate. `forensics/tools/phase8_courts.py` owns the comparison.
 *
 * What this court covers
 * ----------------------
 * **Two slices, one probe.** D333's first arms are the twenty-seven `DSA_meth_*` labels of
 * `crypto/dsa/dsa_meth.c`, where nothing does any cryptography: each function allocates a table,
 * stores a pointer in one, duplicates one, releases one, or reads one back, so their transcript is
 * about *identity, ownership and structure*. The rest are the object layer of `dsa_lib.c`, the
 * default-method family and the sign/verify bodies of `dsa_ossl.c`, the key generation of
 * `dsa_key.c`, the parameter generation of `dsa_gen.c`, the `DSA_SIG` object and dispatch of
 * `dsa_sign.c`, the verification dispatch of `dsa_vrf.c` and the deprecated wrapper of
 * `dsa_depr.c`.
 *
 * The arithmetic half observes *properties* only, because every value on this path is either
 * random or secret. A generated **1024/160 group** is the parameter set every key arm uses --
 * 1024 is the smallest `L` the FFC validators accept for DSA on this profile, since
 * `ffc_validate_LN` requires `L >= 1024 && N >= 160` -- and the arms print its bit widths, its
 * subgroup's primality, `DSA_bits`/`DSA_security_bits`, the *width bound* on the private exponent,
 * the range of the public key, the two halves of a signature as range predicates, and the
 * verification verdict. No private exponent, no nonce, no shared value and no signature half is
 * ever printed, and no `r` or `s` is compared by value: the tampered-signature arm builds `r + 1`
 * through `BN_add_word` and the probe prints only the verdict.
 *
 * Every refusal is observed through **both** its return value and the coordinate
 * `ERR_get_error_all` reports. Three of them leave **two** queue records, and that is why the
 * transcription uses one shared `err:` label per function rather than an early return per failure:
 * a zero-parameter body raises `DSA_R_INVALID_PARAMETERS` inside `dsa_sign_setup` and then
 * `ERR_R_BN_LIB` from `ossl_dsa_do_sign_int`'s epilogue, and a `q` narrower than
 * `MIN_DSA_SIGN_QBITS` raises `ERR_R_BN_LIB` twice from two different lines.
 *
 * What it does not cover, named rather than implied: the ASN.1 method objects (`dsa_ameth.c`) and
 * the two `dsa_prn.c` printers, which reach `EVP_PKEY_set1_DSA` and therefore Phase 11. D345 lands
 * `crypto/dsa/dsa_asn1.c` **whole** — the three templates and `DSAparams_dup` — and a block of arms
 * is theirs. D343 lands slice E's seven `crypto/evp/dsa_ctrl.c` controls, and the last
 * block of arms is theirs: a NULL context, a live context with no operation, and one with a
 * parameter-generation operation, where every control's built parameter array is echoed by the
 * probe's own keymgmt. `DSA_sign`, `DSA_verify` and `DSA_size`
 * **are** called, since D342 landed the DER `DSA-Sig-Value` codec they need (`crypto/packet.c` and
 * `crypto/asn1_dsa.c`); their arms print only the width the group fixes and the verdicts, never a
 * byte of a signature. D333 recorded the block this replaced.
 *
 * The allocator-attribution plane
 * -------------------------------
 * `CRYPTO_set_mem_functions`'s callbacks take `(size_t num, const char *file, int line)`, and all
 * three are part of the published contract: an embedder that installs an allocator receives them.
 * `dsa_meth.c` is a **source-tree** file, so `OPENSSL_FILE` in its bodies is
 * `../../src/openssl-3.6.4/crypto/dsa/dsa_meth.c` -- the prefix is present, unlike the `.c.in`
 * instances D279 and D280 had to distinguish. So the first thing this probe does is install an
 * allocator and record, for each arm, the **ordered sequence of `(kind, size, file)`** the library
 * requests inside a window that starts before the call and ends after it. That is how the claim
 * "this unit's allocation is attributed to this unit's translation unit" becomes a diff instead of
 * a constant in the crate.
 *
 * **The sequence, not just the set, is deliberate.** The order is load-bearing in three arms:
 * `DSA_meth_new` stores `flags` *before* duplicating the name, so a failed duplicate can release
 * the table; `DSA_meth_set1_name` duplicates *first* and releases second, so a failed duplicate
 * leaves the old name in place; `DSA_meth_free` releases the name *before* the table. A set of
 * `file` strings would make all three orders invisible.
 *
 * No address is ever printed: every function pointer is compared for equality with a local
 * sentinel and the *result* is printed, and the two name pointers are compared for *inequality*
 * rather than for their values. stdout is line-buffered, and no NULL-dereferencing entry point is
 * called -- a probe that aborts the harness compares nothing.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/* `DSA_meth_*` and `DSA_generate_parameters` are `OSSL_DEPRECATEDIN_3_0`. The deprecation is the
 * authority's own policy statement about application code, not about a court that must exercise the
 * entry points it declares; suppressing the diagnostic keeps `-Wall` output readable without
 * changing a single symbol this probe links. */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/bn.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/dh.h>
#include <openssl/dsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ the recorder */

#define EV_MAX 32
#define EV_NAME 512

/* Each event owns a copy of its `file` string rather than a pointer into the library, so a release
 * that happens before the window closes cannot leave the transcript reading freed memory. A NULL
 * `file` is recorded as the literal `<null>` for the same reason: the argument is itself part of
 * the contract, and dropping the event would hide exactly that. */
static char ev_file[EV_MAX][EV_NAME];
static unsigned long ev_size[EV_MAX];
static char ev_kind[EV_MAX];
static int nev;
static int recording;

static void record(char kind, size_t size, const char *file, int line)
{
    size_t n;

    if (!recording)
        return;
    if (file == NULL) {
        strcpy(ev_file[nev], "<null>");
    } else {
        n = strlen(file);
        if (n >= EV_NAME)
            n = EV_NAME - 1;
        memcpy(ev_file[nev], file, n);
        ev_file[nev][n] = '\0';
    }
    ev_kind[nev] = kind;
    ev_size[nev] = (unsigned long)size;
    if (nev < EV_MAX - 1)
        nev++;
    else
        ev_kind[nev] = kind; /* keep the count honest when the ring saturates */
    (void)line;
}

static void *my_malloc(size_t n, const char *file, int line)
{
    record('M', n, file, line);
    return malloc(n);
}

static void *my_realloc(void *p, size_t n, const char *file, int line)
{
    record('R', n, file, line);
    return realloc(p, n);
}

static void my_free(void *p, const char *file, int line)
{
    record('F', 0, file, line);
    free(p);
}

static void begin(void)
{
    nev = 0;
    recording = 1;
}

static void end(const char *arm)
{
    int i;

    recording = 0;
    printf("dsa.%s.ev=%d\n", arm, nev);
    for (i = 0; i < nev; i++)
        printf("dsa.%s.ev.%d=%c:%lu:%s\n", arm, i, ev_kind[i], ev_size[i], ev_file[i]);
}

/* ------------------------------------------------------------------ sentinels */

/* One per distinct function-pointer signature in `DSA_METHOD`. They are stored and compared, never
 * called: each returns its own constant so that a transcription which *did* call one would be
 * visible in the transcript rather than merely wrong. */
static DSA_SIG *sentinel_sign(const unsigned char *dgst, int dlen, DSA *dsa)
{
    (void)dgst; (void)dlen; (void)dsa;
    return NULL;
}

static int sentinel_setup(DSA *dsa, BN_CTX *ctx_in, BIGNUM **kinvp, BIGNUM **rp)
{
    (void)dsa; (void)ctx_in; (void)kinvp; (void)rp;
    return 0;
}

static int sentinel_verify(const unsigned char *dgst, int dgst_len, DSA_SIG *sig, DSA *dsa)
{
    (void)dgst; (void)dgst_len; (void)sig; (void)dsa;
    return 0;
}

static int sentinel_mod_exp(DSA *dsa, BIGNUM *rr, const BIGNUM *a1, const BIGNUM *p1,
    const BIGNUM *a2, const BIGNUM *p2, const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *in_mont)
{
    (void)dsa; (void)rr; (void)a1; (void)p1; (void)a2; (void)p2; (void)m; (void)ctx;
    (void)in_mont;
    return 0;
}

static int sentinel_bn_mod_exp(DSA *dsa, BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
    const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx)
{
    (void)dsa; (void)r; (void)a; (void)p; (void)m; (void)ctx; (void)m_ctx;
    return 0;
}

static int sentinel_life(DSA *dsa)
{
    (void)dsa;
    return 0;
}

static int sentinel_paramgen(DSA *dsa, int bits, const unsigned char *seed, int seed_len,
    int *counter_ret, unsigned long *h_ret, BN_GENCB *cb)
{
    (void)dsa; (void)bits; (void)seed; (void)seed_len; (void)counter_ret; (void)h_ret; (void)cb;
    return 0;
}

static int sentinel_keygen(DSA *dsa)
{
    (void)dsa;
    return 0;
}

/* The nine function-pointer pairs, each observed five ways: the member of a fresh table is NULL;
 * the setter answers 1; the getter then answers the *sentinel* rather than merely non-NULL; the
 * setter accepts NULL and still answers 1; and the getter is back to NULL. The round trip leaves
 * the member NULL, which is what lets one table serve all nine without order dependence. */
#define ROUNDTRIP(tag, GET, SET, SENT)                                  \
    do {                                                                \
        printf("dsa.%s.get_default_is_null=%d\n", tag,                 \
            (const void *)(GET)(m) == NULL);                            \
        printf("dsa.%s.set_ret=%d\n", tag, (SET)(m, (SENT)));          \
        printf("dsa.%s.get_is_sentinel=%d\n", tag,                     \
            (const void *)(GET)(m) == (const void *)(SENT));            \
        printf("dsa.%s.set_null_ret=%d\n", tag, (SET)(m, NULL));       \
        printf("dsa.%s.get_after_null_is_null=%d\n", tag,              \
            (const void *)(GET)(m) == NULL);                            \
    } while (0)

/* ------------------------------------------------------------------ the error queue */

/* Drain the error queue, printing each record's **packed code and coordinate**. The packed code
 * carries the library and the reason; the coordinate is `ERR_get_error_all`'s file/line/func,
 * which is the part of the record `gen_err_raise_sites.py` derives and which a court that
 * compared only the return value could not see at all. */
static void drain(const char *arm)
{
    int n = 0;

    for (;;) {
        const char *file = NULL;
        const char *func = NULL;
        int line = 0;
        unsigned long e = ERR_get_error_all(&file, &line, &func, NULL, NULL);

        if (e == 0)
            break;
        printf("dsa.%s.err.%d=%lu:%s:%d:%s\n", arm, n, e,
            file != NULL ? file : "(null)", line,
            func != NULL ? func : "(null)");
        n++;
    }
    printf("dsa.%s.err.count=%d\n", arm, n);
}

/* A tiny group built through the public accessor: `p` 23, `q` 11, `g` 2. `q` is 4 bits, so every
 * signature arm refuses on the `q`-width test rather than on anything about these numbers being
 * "wrong" -- which is why the probe can build a group no generator would produce. */
static DSA *tiny_group(void)
{
    DSA *d = DSA_new();
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *g = BN_new();

    if (d == NULL || p == NULL || q == NULL || g == NULL) {
        DSA_free(d); BN_free(p); BN_free(q); BN_free(g);
        return NULL;
    }
    BN_set_word(p, 23);
    BN_set_word(q, 11);
    BN_set_word(g, 2);
    if (DSA_set0_pqg(d, p, q, g) != 1) {
        BN_free(p); BN_free(q); BN_free(g);
        DSA_free(d);
        return NULL;
    }
    return d;
}

/* A signature object holding `r + 1` against the signer's `s`, built through `DSA_SIG_set0` so the
 * probe never writes through a borrow. Answers NULL when the signature has no usable `r`. */
static DSA_SIG *tamper_r(const DSA_SIG *sig)
{
    const BIGNUM *r = NULL;
    const BIGNUM *s = NULL;
    BIGNUM *r2;
    BIGNUM *s2;
    DSA_SIG *bad;

    DSA_SIG_get0(sig, &r, &s);
    if (r == NULL || s == NULL)
        return NULL;
    r2 = BN_dup(r);
    s2 = BN_dup(s);
    bad = DSA_SIG_new();
    if (r2 == NULL || s2 == NULL || bad == NULL) {
        BN_free(r2); BN_free(s2); DSA_SIG_free(bad);
        return NULL;
    }
    if (BN_add_word(r2, 1) != 1 || DSA_SIG_set0(bad, r2, s2) != 1) {
        BN_free(r2); BN_free(s2); DSA_SIG_free(bad);
        return NULL;
    }
    return bad;
}

/* ------------------------------------------------------------------ the control court's provider
 *
 * The `EVP_PKEY_CTX_set_dsa_paramgen_*` controls of `crypto/evp/dsa_ctrl.c` are decisions *about a
 * context*, so they need a context to decide about. This crate publishes no DSA `EVP_KEYMGMT`
 * (8.6's provider half is not landed), so `EVP_PKEY_CTX_new_from_name(NULL, "DSA", NULL)` answers
 * NULL on the candidate and a context on the authority -- an arm that compared that would be a
 * difference about a missing provider row rather than about the controls. The keymgmt below is the
 * smallest the structural check accepts, named `COURT-DSA` rather than `DSA` so that it cannot
 * shadow the default provider's own row in either binary's method store. Every parameter the
 * controls send is *echoed* by the generation callback that receives it, so the transcript observes
 * the parameter array the library built and not merely its return code; no echoed value is a
 * secret -- they are FFC sizes, a group name, a digest name and a property query. There is no
 * keyexch: every DSA control here is a parameter-generation one. */

struct court_ctx {
    int have_type;
    char type[64];
    int have_gindex;
    int gindex;
    int have_seed;
    unsigned long seedlen;
    int have_pbits;
    unsigned long pbits;
    int have_qbits;
    unsigned long qbits;
    int have_digest;
    char digest[64];
    int have_props;
    char props[64];
};

static struct court_ctx *court_new(void)
{
    struct court_ctx *c = malloc(sizeof(*c));

    if (c == NULL)
        return NULL;
    memset(c, 0, sizeof(*c));
    return c;
}

/* Print every parameter the library sent, one `key=value` line per entry. The rendering is by
 * `data_type`, so a wrong type is visible as well as a wrong value. */
static void court_dump(const char *arm, const OSSL_PARAM params[])
{
    int i;

    for (i = 0; params != NULL && params[i].key != NULL; i++) {
        const OSSL_PARAM *p = &params[i];

        if (p->data_type == OSSL_PARAM_INTEGER) {
            int64_t v = 0;
            OSSL_PARAM_get_int64(p, &v);
            printf("dsa.%s.p.%d=%s:int:%lld\n", arm, i, p->key, (long long)v);
        } else if (p->data_type == OSSL_PARAM_UNSIGNED_INTEGER) {
            uint64_t v = 0;
            OSSL_PARAM_get_uint64(p, &v);
            printf("dsa.%s.p.%d=%s:uint:%llu\n", arm, i, p->key, (unsigned long long)v);
        } else if (p->data_type == OSSL_PARAM_UTF8_STRING) {
            printf("dsa.%s.p.%d=%s:utf8:%s\n", arm, i, p->key,
                p->data != NULL ? (const char *)p->data : "<null>");
        } else if (p->data_type == OSSL_PARAM_OCTET_STRING) {
            printf("dsa.%s.p.%d=%s:octet:%zu\n", arm, i, p->key, p->data_size);
        } else {
            printf("dsa.%s.p.%d=%s:type%u:%zu\n", arm, i, p->key, p->data_type,
                p->data_size);
        }
    }
    printf("dsa.%s.p.count=%d\n", arm, i);
}

/* Remember the parameters, by copying the value rather than the pointer: the arrays the controls
 * build point at stack locals in the *calling* frame, so a stored pointer would be stale. */
static void court_store(struct court_ctx *c, const OSSL_PARAM params[])
{
    int i;

    for (i = 0; params != NULL && params[i].key != NULL; i++) {
        const OSSL_PARAM *p = &params[i];

        if (strcmp(p->key, "type") == 0) {
            c->have_type = 1;
            snprintf(c->type, sizeof(c->type), "%s", (const char *)p->data);
        } else if (strcmp(p->key, "gindex") == 0) {
            int64_t v = 0;
            OSSL_PARAM_get_int64(p, &v);
            c->have_gindex = 1;
            c->gindex = (int)v;
        } else if (strcmp(p->key, "seed") == 0) {
            c->have_seed = 1;
            c->seedlen = p->data_size;
        } else if (strcmp(p->key, "pbits") == 0) {
            uint64_t v = 0;
            OSSL_PARAM_get_uint64(p, &v);
            c->have_pbits = 1;
            c->pbits = (unsigned long)v;
        } else if (strcmp(p->key, "qbits") == 0) {
            uint64_t v = 0;
            OSSL_PARAM_get_uint64(p, &v);
            c->have_qbits = 1;
            c->qbits = (unsigned long)v;
        } else if (strcmp(p->key, "digest") == 0) {
            c->have_digest = 1;
            snprintf(c->digest, sizeof(c->digest), "%s", (const char *)p->data);
        } else if (strcmp(p->key, "properties") == 0) {
            c->have_props = 1;
            snprintf(c->props, sizeof(c->props), "%s", (const char *)p->data);
        }
    }
}

/* The settable and gettable lists, as the structural check reads them. The `data` pointers are
 * NULL and `data_size` is the width the *control* builds, which is all a list of names needs. */
static const OSSL_PARAM court_gen_settable[] = {
    { "type", OSSL_PARAM_UTF8_STRING, NULL, 0, 0 },
    { "gindex", OSSL_PARAM_INTEGER, NULL, sizeof(int), 0 },
    { "seed", OSSL_PARAM_OCTET_STRING, NULL, 0, 0 },
    { "pbits", OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0 },
    { "qbits", OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0 },
    { "digest", OSSL_PARAM_UTF8_STRING, NULL, 0, 0 },
    { "properties", OSSL_PARAM_UTF8_STRING, NULL, 0, 0 },
    { NULL, 0, NULL, 0, 0 }
};
static const OSSL_PARAM court_gen_gettable[] = {
    { NULL, 0, NULL, 0, 0 }
};

/* The keymgmt: only the generation callbacks carry state, because every DSA control reaches the
 * keymgmt through `EVP_PKEY_CTX_set_params` on a generation operation. */
static int court_marker;

static void *ck_new(void *provctx) { (void)provctx; return court_new(); }
static void ck_free(void *keydata) { free(keydata); }
static int ck_has(const void *keydata, int selection)
{ (void)keydata; (void)selection; return 1; }
static int ck_get_params(void *keydata, OSSL_PARAM params[])
{ (void)keydata; (void)params; return 1; }
static const OSSL_PARAM *ck_gettable_params(void *provctx) { (void)provctx; return NULL; }
static int ck_set_params(void *keydata, const OSSL_PARAM params[])
{ (void)keydata; (void)params; return 1; }
static const OSSL_PARAM *ck_settable_params(void *provctx) { (void)provctx; return NULL; }
static void *ck_gen_init(void *provctx, int selection, const OSSL_PARAM params[])
{ (void)provctx; (void)selection; (void)params; return court_new(); }
static void ck_gen_cleanup(void *genctx) { free(genctx); }
static void *ck_gen(void *genctx, OSSL_CALLBACK *cb, void *cbarg)
{ (void)genctx; (void)cb; (void)cbarg; return malloc(1); }
static int ck_gen_set_template(void *genctx, void *templ)
{ (void)genctx; (void)templ; return 1; }
static int ck_gen_set_params(void *genctx, const OSSL_PARAM params[])
{ court_dump("gen.set", params); court_store(genctx, params); return 1; }
static const OSSL_PARAM *ck_gen_settable_params(void *genctx, void *provctx)
{ (void)genctx; (void)provctx; return court_gen_settable; }
static int ck_gen_get_params(void *genctx, OSSL_PARAM params[])
{ court_dump("gen.get", params); return 1; }
static const OSSL_PARAM *ck_gen_gettable_params(void *genctx, void *provctx)
{ (void)genctx; (void)provctx; return court_gen_gettable; }
static void *ck_load(const void *reference, size_t reference_sz)
{ (void)reference; (void)reference_sz; return malloc(1); }
static const char *ck_query_operation_name(int operation_id)
{ (void)operation_id; return NULL; }
static void *ck_import(void *keydata, int selection, const OSSL_PARAM params[])
{ (void)keydata; (void)selection; (void)params; return malloc(1); }
static const OSSL_PARAM *ck_import_types(int selection) { (void)selection; return NULL; }
static int ck_export(void *keydata, int selection, OSSL_CALLBACK *cb, void *cbarg)
{ (void)keydata; (void)selection; (void)cb; (void)cbarg; return 1; }
static const OSSL_PARAM *ck_export_types(int selection) { (void)selection; return NULL; }
static void *ck_dup(const void *keydata, int selection)
{ (void)keydata; (void)selection; return malloc(1); }
static int ck_validate(const void *keydata, int selection, int checktype)
{ (void)keydata; (void)selection; (void)checktype; return 1; }
static int ck_match(const void *a, const void *b, int selection)
{ (void)a; (void)b; (void)selection; return 1; }

static const OSSL_DISPATCH court_keymgmt_fns[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))ck_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))ck_free },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))ck_has },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))ck_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))ck_gettable_params },
    { OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*)(void))ck_set_params },
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*)(void))ck_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))ck_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE, (void (*)(void))ck_gen_set_template },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))ck_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))ck_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN_GET_PARAMS, (void (*)(void))ck_gen_get_params },
    { OSSL_FUNC_KEYMGMT_GEN_GETTABLE_PARAMS, (void (*)(void))ck_gen_gettable_params },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))ck_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))ck_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))ck_load },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (void (*)(void))ck_query_operation_name },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))ck_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))ck_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))ck_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))ck_export_types },
    { OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))ck_dup },
    { OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))ck_validate },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))ck_match },
    { 0, NULL }
};

static const OSSL_ALGORITHM *court_query(void *provctx, int operation_id, int *no_cache)
{
    static const OSSL_ALGORITHM km[] = {
        { "COURT-DSA:court-dsa", "provider=court-dsa", court_keymgmt_fns,
          "the probe's keymgmt" },
        { NULL, NULL, NULL, NULL }
    };

    (void)provctx;
    *no_cache = 0;
    if (operation_id == OSSL_OP_KEYMGMT)
        return km;
    return NULL;
}

static int court_teardown(void *provctx) { (void)provctx; return 1; }

static const OSSL_DISPATCH court_dispatch[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))court_query },
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))court_teardown },
    { 0, NULL }
};

static int court_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
    const OSSL_DISPATCH **out, void **provctx)
{
    (void)handle;
    (void)in;
    *out = court_dispatch;
    *provctx = &court_marker;
    return 1;
}

/* The seven controls, three ways: a NULL context, a live one with no operation, and one with a
 * parameter-generation operation, so the *successful* path of each is observed as the parameter
 * array the library builds. Every refusal drains its queue. */
static void dsa_ctl_arms(void)
{
    OSSL_PROVIDER *prov;
    EVP_PKEY_CTX *null_ctx = NULL;
    EVP_PKEY_CTX *fresh = NULL;
    EVP_PKEY_CTX *gen = NULL;
    const EVP_MD *sha256 = EVP_MD_fetch(NULL, "SHA256", NULL);
    unsigned char seed[4];

    memset(seed, 0x5a, sizeof(seed));
    printf("dsa.ctl.md_fetched=%d\n", sha256 != NULL);

    /* ---- the NULL-context refusals: the gate answers -2 for six, and `set_dsa_paramgen_md`
     * reaches `EVP_PKEY_CTX_ctrl`'s own NULL test, also -2. */
    ERR_clear_error();
    printf("dsa.ctl.null.type=%d\n", EVP_PKEY_CTX_set_dsa_paramgen_type(null_ctx, "fips186_4"));
    printf("dsa.ctl.null.gindex=%d\n", EVP_PKEY_CTX_set_dsa_paramgen_gindex(null_ctx, 5));
    printf("dsa.ctl.null.seed=%d\n", EVP_PKEY_CTX_set_dsa_paramgen_seed(null_ctx, seed, 4));
    printf("dsa.ctl.null.bits=%d\n", EVP_PKEY_CTX_set_dsa_paramgen_bits(null_ctx, 2048));
    printf("dsa.ctl.null.q_bits=%d\n", EVP_PKEY_CTX_set_dsa_paramgen_q_bits(null_ctx, 256));
    printf("dsa.ctl.null.md_props=%d\n",
        EVP_PKEY_CTX_set_dsa_paramgen_md_props(null_ctx, "SHA256", NULL));
    printf("dsa.ctl.null.md=%d\n", EVP_PKEY_CTX_set_dsa_paramgen_md(null_ctx, sha256));
    drain("ctl_null");

    /* ---- the provider, and the live context with no operation at all */
    printf("dsa.ctl.provider.add=%d\n", OSSL_PROVIDER_add_builtin(NULL, "court-dsa", court_init));
    prov = OSSL_PROVIDER_load(NULL, "court-dsa");
    printf("dsa.ctl.provider.load=%d\n", prov != NULL);
    if (prov == NULL)
        return;

    fresh = EVP_PKEY_CTX_new_from_name(NULL, "COURT-DSA", NULL);
    printf("dsa.ctl.fresh=%d\n", fresh != NULL);
    if (fresh == NULL)
        return;
    printf("dsa.ctl.fresh.is_a_self=%d\n", EVP_PKEY_CTX_is_a(fresh, "COURT-DSA"));
    printf("dsa.ctl.fresh.operation=%d\n", EVP_PKEY_CTX_get_operation(fresh));

    /* On an operation-less context the gate refuses -2 and the ctrl wrapper refuses -1 with
     * `EVP_R_NO_OPERATION_SET`, so the two are told apart by the return value. */
    ERR_clear_error();
    printf("dsa.ctl.fresh.type=%d\n", EVP_PKEY_CTX_set_dsa_paramgen_type(fresh, "fips186_4"));
    printf("dsa.ctl.fresh.bits=%d\n", EVP_PKEY_CTX_set_dsa_paramgen_bits(fresh, 2048));
    printf("dsa.ctl.fresh.md=%d\n", EVP_PKEY_CTX_set_dsa_paramgen_md(fresh, sha256));
    drain("ctl_fresh");

    /* ---- the seven controls on a parameter-generation operation, each of which now succeeds and
     * echoes the parameter it built. The one `md_props` call with a NULL property query must send
     * one parameter and the one with a query must send two. */
    ERR_clear_error();
    gen = EVP_PKEY_CTX_new_from_name(NULL, "COURT-DSA", NULL);
    printf("dsa.ctl.gen=%d\n", gen != NULL);
    printf("dsa.ctl.gen.init=%d\n", EVP_PKEY_paramgen_init(gen));
    printf("dsa.ctl.gen.operation=%d\n", EVP_PKEY_CTX_get_operation(gen));
    ERR_clear_error();
    printf("dsa.ctl.gen.type=%d\n", EVP_PKEY_CTX_set_dsa_paramgen_type(gen, "fips186_4"));
    printf("dsa.ctl.gen.gindex=%d\n", EVP_PKEY_CTX_set_dsa_paramgen_gindex(gen, 5));
    printf("dsa.ctl.gen.seed=%d\n", EVP_PKEY_CTX_set_dsa_paramgen_seed(gen, seed, 4));
    printf("dsa.ctl.gen.bits=%d\n", EVP_PKEY_CTX_set_dsa_paramgen_bits(gen, 2048));
    printf("dsa.ctl.gen.q_bits=%d\n", EVP_PKEY_CTX_set_dsa_paramgen_q_bits(gen, 256));
    printf("dsa.ctl.gen.md_props_no_query=%d\n",
        EVP_PKEY_CTX_set_dsa_paramgen_md_props(gen, "SHA256", NULL));
    printf("dsa.ctl.gen.md_props_query=%d\n",
        EVP_PKEY_CTX_set_dsa_paramgen_md_props(gen, "SHA256", "provider=court-dsa"));
    printf("dsa.ctl.gen.md=%d\n", EVP_PKEY_CTX_set_dsa_paramgen_md(gen, sha256));
    drain("ctl_gen");

    EVP_PKEY_CTX_free(gen);
    EVP_PKEY_CTX_free(fresh);
    EVP_MD_free((EVP_MD *)sha256);
    OSSL_PROVIDER_unload(prov);
}

/* ------------------------------------------------------------------ the method table */

static void dsa_method_arms(void)
{
    DSA_METHOD *m;
    DSA_METHOD *dup;
    const DSA_METHOD *def;
    void *marker = (void *)0x1234;

    /* Warm-up, outside every window: the first `DSA_meth_new` runs whatever lazy library state the
     * allocation path has, and a window around it would record that rather than this unit. */
    m = DSA_meth_new("warmup", 0);
    if (m == NULL) {
        printf("dsa.warmup=0\n");
        return;
    }
    DSA_meth_free(m);

    begin();
    m = DSA_meth_new("court-dsa-method", 0x1234);
    end("new");
    printf("dsa.new.not_null=%d\n", m != NULL);

    begin();
    dup = DSA_meth_dup(m);
    end("dup");
    printf("dsa.dup.not_null=%d\n", dup != NULL);

    begin();
    printf("dsa.set1_name.ret=%d\n", DSA_meth_set1_name(m, "court-dsa-renamed"));
    end("set1_name");

    /* A refusal window: a NULL name is refused without an allocation on either side. */
    begin();
    printf("dsa.set1_name_null.ret=%d\n", DSA_meth_set1_name(m, NULL));
    end("set1_name_null");

    printf("dsa.new.name=%s\n", DSA_meth_get0_name(m));
    printf("dsa.new.flags=%d\n", DSA_meth_get_flags(m));
    printf("dsa.new.app_data_is_null=%d\n", DSA_meth_get0_app_data(m) == NULL);
    printf("dsa.dup.name=%s\n", DSA_meth_get0_name(dup));
    printf("dsa.dup.flags=%d\n", DSA_meth_get_flags(dup));
    printf("dsa.dup.app_data_is_null=%d\n", DSA_meth_get0_app_data(dup) == NULL);
    /* The duplicate's name is a second allocation, so the two pointers differ. */
    printf("dsa.dup.name_ptr_differs=%d\n",
        DSA_meth_get0_name(dup) != DSA_meth_get0_name(m));
    /* A NULL `set1_name` leaves the old name in place. */
    printf("dsa.set1_name_null.name_unchanged=%d\n",
        strcmp(DSA_meth_get0_name(m), "court-dsa-renamed") == 0);

    ROUNDTRIP("sign", DSA_meth_get_sign, DSA_meth_set_sign, sentinel_sign);
    ROUNDTRIP("sign_setup", DSA_meth_get_sign_setup, DSA_meth_set_sign_setup, sentinel_setup);
    ROUNDTRIP("verify", DSA_meth_get_verify, DSA_meth_set_verify, sentinel_verify);
    ROUNDTRIP("mod_exp", DSA_meth_get_mod_exp, DSA_meth_set_mod_exp, sentinel_mod_exp);
    ROUNDTRIP("bn_mod_exp", DSA_meth_get_bn_mod_exp, DSA_meth_set_bn_mod_exp, sentinel_bn_mod_exp);
    ROUNDTRIP("init", DSA_meth_get_init, DSA_meth_set_init, sentinel_life);
    ROUNDTRIP("finish", DSA_meth_get_finish, DSA_meth_set_finish, sentinel_life);
    ROUNDTRIP("paramgen", DSA_meth_get_paramgen, DSA_meth_set_paramgen, sentinel_paramgen);
    ROUNDTRIP("keygen", DSA_meth_get_keygen, DSA_meth_set_keygen, sentinel_keygen);

    /* `app_data` is not a function pointer and its NULL is a value, not a refusal. */
    printf("dsa.app_data.set_ret=%d\n", DSA_meth_set0_app_data(m, marker));
    printf("dsa.app_data.get_is_marker=%d\n", DSA_meth_get0_app_data(m) == marker);
    printf("dsa.app_data.set_null_ret=%d\n", DSA_meth_set0_app_data(m, NULL));
    printf("dsa.app_data.get_after_null_is_null=%d\n", DSA_meth_get0_app_data(m) == NULL);

    /* `flags` is stored verbatim and answered unconditionally. */
    printf("dsa.flags.set_ret=%d\n", DSA_meth_set_flags(m, 0x0f0f));
    printf("dsa.flags.get=%d\n", DSA_meth_get_flags(m));

    begin();
    DSA_meth_free(dup);
    end("free_dup");

    begin();
    DSA_meth_free(m);
    end("free_new");

    begin();
    DSA_meth_free(NULL);
    end("free_null");

    /* ---- the default-method family, and the authority's own table (dsa_ossl.c) ---- */

    def = DSA_get_default_method();
    printf("dsa.default.is_openssl=%d\n", def == DSA_OpenSSL());
    printf("dsa.default.name=%s\n", DSA_meth_get0_name(def));
    printf("dsa.default.flags=%d\n", DSA_meth_get_flags(def));
    /* The five members the authority's initialiser leaves NULL, and the five it fills. */
    printf("dsa.default.sign_nonnull=%d\n", DSA_meth_get_sign(def) != NULL);
    printf("dsa.default.sign_setup_nonnull=%d\n", DSA_meth_get_sign_setup(def) != NULL);
    printf("dsa.default.verify_nonnull=%d\n", DSA_meth_get_verify(def) != NULL);
    printf("dsa.default.init_nonnull=%d\n", DSA_meth_get_init(def) != NULL);
    printf("dsa.default.finish_nonnull=%d\n", DSA_meth_get_finish(def) != NULL);
    printf("dsa.default.mod_exp_is_null=%d\n", DSA_meth_get_mod_exp(def) == NULL);
    printf("dsa.default.bn_mod_exp_is_null=%d\n", DSA_meth_get_bn_mod_exp(def) == NULL);
    printf("dsa.default.app_data_is_null=%d\n", DSA_meth_get0_app_data(def) == NULL);
    printf("dsa.default.paramgen_is_null=%d\n", DSA_meth_get_paramgen(def) == NULL);
    printf("dsa.default.keygen_is_null=%d\n", DSA_meth_get_keygen(def) == NULL);
    DSA_set_default_method(NULL);
    printf("dsa.default.null_is_null=%d\n", DSA_get_default_method() == NULL);
    DSA_set_default_method(DSA_OpenSSL());
    printf("dsa.default.restored=%d\n", DSA_get_default_method() == DSA_OpenSSL());
}

/* ------------------------------------------------------------------ the object layer */

static void dsa_object_arms(void)
{
    DSA *d = DSA_new();
    DSA *out = DSA_new();
    const BIGNUM *p = NULL, *q = NULL, *g = NULL, *pub = NULL, *priv = NULL;
    BIGNUM *one = BN_new();
    BIGNUM *zero = BN_new();
    void *marker = (void *)0x4321;

    printf("dsa.obj.scratch_built=%d\n", d != NULL && out != NULL && one != NULL && zero != NULL);
    if (d == NULL || out == NULL || one == NULL || zero == NULL)
        return;
    BN_set_word(one, 1);
    BN_set_word(zero, 0);

    /* ---- the constructor's observable state */
    printf("dsa.obj.new.engine_is_null=%d\n", DSA_get0_engine(d) == NULL);
    printf("dsa.obj.new.cache_mont=%d\n", DSA_test_flags(d, DSA_FLAG_CACHE_MONT_P) != 0);
    /* The table's `DSA_FLAG_FIPS_METHOD` is the same bit as `DSA_FLAG_NON_FIPS_ALLOW`, and the
     * constructor clears it -- so a fresh object answers 0 here. */
    printf("dsa.obj.new.fips_method=%d\n", DSA_test_flags(d, DSA_FLAG_FIPS_METHOD) != 0);
    printf("dsa.obj.new.method_is_default=%d\n", DSA_get_method(d) == DSA_OpenSSL());
    printf("dsa.obj.new.bits=%d\n", DSA_bits(d));
    printf("dsa.obj.new.security_bits=%d\n", DSA_security_bits(d));
    DSA_get0_pqg(d, &p, &q, &g);
    printf("dsa.obj.new.pqg_null=%d\n", p == NULL && q == NULL && g == NULL);
    DSA_get0_key(d, &pub, &priv);
    printf("dsa.obj.new.key_null=%d\n", pub == NULL && priv == NULL);
    printf("dsa.obj.new.p_null=%d\n", DSA_get0_p(d) == NULL);
    printf("dsa.obj.new.q_null=%d\n", DSA_get0_q(d) == NULL);
    printf("dsa.obj.new.g_null=%d\n", DSA_get0_g(d) == NULL);
    printf("dsa.obj.new.priv_null=%d\n", DSA_get0_priv_key(d) == NULL);
    printf("dsa.obj.new.pub_null=%d\n", DSA_get0_pub_key(d) == NULL);

    {
        DSA *by_method = DSA_new_method(NULL);

        printf("dsa.obj.new_method.not_null=%d\n", by_method != NULL);
        if (by_method != NULL) {
            printf("dsa.obj.new_method.engine_is_null=%d\n", DSA_get0_engine(by_method) == NULL);
            printf("dsa.obj.new_method.cache_mont=%d\n",
                DSA_test_flags(by_method, DSA_FLAG_CACHE_MONT_P) != 0);
            DSA_free(by_method);
        }
    }

    /* ---- the flag trio */
    DSA_set_flags(d, 0x1234);
    printf("dsa.obj.flags.set=%d\n", DSA_test_flags(d, 0x1234));
    DSA_clear_flags(d, 0x0034);
    printf("dsa.obj.flags.cleared=%d\n", DSA_test_flags(d, 0x1234));
    printf("dsa.obj.flags.remaining=%d\n", DSA_test_flags(d, 0xFFFF));

    /* ---- the method setter, which answers 1 and re-runs the incoming table's `init` */
    printf("dsa.obj.set_method.ret=%d\n", DSA_set_method(d, DSA_OpenSSL()));
    printf("dsa.obj.set_method.cache_mont=%d\n", DSA_test_flags(d, DSA_FLAG_CACHE_MONT_P) != 0);

    /* ---- the ex-data pair, and NULL safety */
    printf("dsa.obj.exdata.set_ret=%d\n", DSA_set_ex_data(d, 0, marker));
    printf("dsa.obj.exdata.get_is_marker=%d\n", DSA_get_ex_data(d, 0) == marker);
    printf("dsa.obj.exdata.unset_is_null=%d\n", DSA_get_ex_data(d, 999) == NULL);

    /* ---- the three refusals `DSA_set0_pqg` makes before it stores anything */
    printf("dsa.obj.set0_pqg.all_null_refused=%d\n", DSA_set0_pqg(out, NULL, NULL, NULL));
    printf("dsa.obj.set0_pqg.p_only_refused=%d\n", DSA_set0_pqg(out, one, NULL, NULL));
    printf("dsa.obj.set0_pqg.pq_only_refused=%d\n", DSA_set0_pqg(out, one, one, NULL));
    printf("dsa.obj.set0_pqg.p_still_null=%d\n", DSA_get0_p(out) == NULL);

    /* ---- references and the two release paths */
    printf("dsa.obj.up_ref.ret=%d\n", DSA_up_ref(d));
    DSA_free(d);
    printf("dsa.obj.up_ref.survived_first_free=1\n");

    /* ---- `DSA_set0_key` always answers 1, and a NULL argument moves nothing. The key that is
     * handed over is a *third* object: `DSA_set0_key` takes ownership, so `out`'s release below is
     * what frees it and this scope must not release it again. */
    printf("dsa.obj.set0_key.both_null_ret=%d\n", DSA_set0_key(out, NULL, NULL));
    printf("dsa.obj.set0_key.pub_still_null=%d\n", DSA_get0_pub_key(out) == NULL);
    {
        BIGNUM *handed = BN_new();

        BN_set_word(handed, 7);
        printf("dsa.obj.set0_key.pub_ret=%d\n", DSA_set0_key(out, handed, NULL));
        printf("dsa.obj.set0_key.pub_is_seven=%d\n", BN_is_word(DSA_get0_pub_key(out), 7));
    }

    DSA_free(out);
    DSA_free(NULL);
    printf("dsa.obj.free_null.survived=1\n");

    BN_free(one);
    BN_free(zero);
    DSA_free(d);
}

/* ------------------------------------------------------------------ generation, signing, verification */

static void dsa_primitive_arms(void)
{
    /* A 20-byte digest, the SHA-1-sized input FIPS 186-2's 160-bit `q` is matched to. */
    static const unsigned char dgst[20] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc,
        0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x0f, 0x1e, 0x2d, 0x3c
    };
    /* A 20-byte seed, so the legacy generator's search is deterministic and its two
     * out-parameters are properties of the seed rather than of a random draw. */
    static unsigned char seed[20] = {
        0x2f, 0x2b, 0x11, 0x5d, 0x8e, 0x1f, 0x0a, 0x3c, 0x77, 0x91,
        0x40, 0x0d, 0x6b, 0x55, 0xee, 0x21, 0x9c, 0x03, 0xab, 0x7f
    };
    DSA *dsa = DSA_new();
    DSA_SIG *sig = NULL;
    DSA_SIG *bad = NULL;
    const BIGNUM *p = NULL, *q = NULL, *g = NULL, *pub = NULL, *priv = NULL, *r = NULL, *s = NULL;
    int counter = -1;
    unsigned long h = 0;
    BIGNUM *one = BN_new();

    BN_set_word(one, 1);
    printf("dsa.gen.group.built=%d\n", dsa != NULL && one != NULL);
    if (dsa == NULL || one == NULL)
        return;

    /* ---- parameter generation: a seeded 1024/160 group, then its properties */
    ERR_clear_error();
    printf("dsa.genparams_ex.seeded_ret=%d\n",
        DSA_generate_parameters_ex(dsa, 1024, seed, sizeof(seed), &counter, &h, NULL));
    drain("genparams_ex");
    printf("dsa.genparams_ex.counter_set=%d\n", counter >= 0);
    printf("dsa.genparams_ex.h_set=%d\n", h >= 1);
    printf("dsa.genparams_ex.bits=%d\n", DSA_bits(dsa));
    printf("dsa.genparams_ex.security_bits=%d\n", DSA_security_bits(dsa));
    DSA_get0_pqg(dsa, &p, &q, &g);
    printf("dsa.genparams_ex.p_bits=%d\n", p != NULL ? BN_num_bits(p) : -1);
    printf("dsa.genparams_ex.q_bits=%d\n", q != NULL ? BN_num_bits(q) : -1);
    printf("dsa.genparams_ex.p_odd=%d\n", p != NULL ? BN_is_odd(p) : -1);
    printf("dsa.genparams_ex.q_odd=%d\n", q != NULL ? BN_is_odd(q) : -1);
    printf("dsa.genparams_ex.g_in_range=%d\n",
        g != NULL && p != NULL && BN_cmp(g, one) > 0 && BN_cmp(g, p) < 0);
    /* Primality is a property of the generated group and the only thing a width cannot say. The
     * subgroup order is 160 bits, so 64 Miller-Rabin rounds are milliseconds rather than minutes. */
    {
        BN_CTX *ctx = BN_CTX_new();

        printf("dsa.genparams_ex.q_is_prime=%d\n",
            ctx != NULL && q != NULL ? BN_check_prime(q, ctx, NULL) : -1);
        printf("dsa.genparams_ex.p_is_prime=%d\n",
            ctx != NULL && p != NULL ? BN_check_prime(p, ctx, NULL) : -1);
        BN_CTX_free(ctx);
    }
    /* A negative control: `q * q` is not prime, so a `BN_check_prime` that always answered 1 would
     * be visible here rather than in the two lines above. */
    {
        BIGNUM *qq = q != NULL ? BN_dup(q) : NULL;
        BN_CTX *ctx = BN_CTX_new();

        if (qq != NULL && ctx != NULL)
            BN_sqr(qq, qq, ctx);
        printf("dsa.genparams_ex.q_squared_is_prime=%d\n",
            ctx != NULL && qq != NULL ? BN_check_prime(qq, ctx, NULL) : -1);
        BN_free(qq);
        BN_CTX_free(ctx);
    }

    /* ---- key generation */
    ERR_clear_error();
    printf("dsa.genkey.ret=%d\n", DSA_generate_key(dsa));
    drain("genkey");
    DSA_get0_key(dsa, &pub, &priv);
    printf("dsa.genkey.pub_nonnull=%d\n", pub != NULL);
    printf("dsa.genkey.priv_nonnull=%d\n", priv != NULL);
    /* The exponent is drawn in `[1, 2^160)`, so its *width* varies with the draw and only a bound
     * can be printed. */
    printf("dsa.genkey.priv_bits_le_q=%d\n",
        priv != NULL && q != NULL ? BN_num_bits(priv) <= BN_num_bits(q) : 0);
    printf("dsa.genkey.priv_nonzero=%d\n", priv != NULL ? BN_is_zero(priv) == 0 : 0);
    printf("dsa.genkey.pub_in_range=%d\n",
        pub != NULL && p != NULL ? BN_cmp(pub, p) < 0 && BN_cmp(pub, one) > 0 : 0);

    /* ---- `DSA_sign_setup`, the method-dispatched half of a signature */
    {
        BN_CTX *ctx = BN_CTX_new();
        BIGNUM *kinv = NULL;
        /* `*rp` must be a live `BIGNUM`: `dsa_sign_setup` writes `r` *through* it rather than
         * allocating one, so a NULL there is a null dereference on the authority. */
        BIGNUM *rr = BN_new();

        ERR_clear_error();
        printf("dsa.sign_setup.ret=%d\n",
            ctx != NULL ? DSA_sign_setup(dsa, ctx, &kinv, &rr) : -1);
        drain("sign_setup");
        printf("dsa.sign_setup.kinv_nonnull=%d\n", kinv != NULL);
        printf("dsa.sign_setup.r_nonnull=%d\n", rr != NULL);
        printf("dsa.sign_setup.r_in_range=%d\n",
            rr != NULL && q != NULL ? BN_is_zero(rr) == 0 && BN_cmp(rr, q) < 0 : 0);
        printf("dsa.sign_setup.kinv_in_range=%d\n",
            kinv != NULL && q != NULL ? BN_is_zero(kinv) == 0 && BN_cmp(kinv, q) < 0 : 0);
        BN_clear_free(kinv);
        BN_free(rr);
        BN_CTX_free(ctx);
    }

    /* ---- sign, then verify, then the two refusals */
    sig = DSA_do_sign(dgst, (int)sizeof(dgst), dsa);
    printf("dsa.sign.sig_nonnull=%d\n", sig != NULL);
    if (sig == NULL) {
        printf("dsa.sign.no_signature=1\n");
        DSA_free(dsa);
        BN_free(one);
        return;
    }
    DSA_SIG_get0(sig, &r, &s);
    printf("dsa.sign.r_nonnull=%d\n", r != NULL);
    printf("dsa.sign.s_nonnull=%d\n", s != NULL);
    printf("dsa.sign.r_in_range=%d\n",
        r != NULL && q != NULL ? BN_is_zero(r) == 0 && BN_is_negative(r) == 0
            && BN_cmp(r, q) < 0 : 0);
    printf("dsa.sign.s_in_range=%d\n",
        s != NULL && q != NULL ? BN_is_zero(s) == 0 && BN_is_negative(s) == 0
            && BN_cmp(s, q) < 0 : 0);

    ERR_clear_error();
    printf("dsa.verify.ret=%d\n",
        DSA_do_verify(dgst, (int)sizeof(dgst), sig, dsa));
    drain("verify");

    /* A tampered signature refuses, and the verdict is the whole observation: no half of it is
     * compared by value. `r + 1` stays below `q` with overwhelming probability, so the refusal is
     * the verification's own rather than the range test's. */
    bad = tamper_r(sig);
    printf("dsa.verify.tampered_built=%d\n", bad != NULL);
    if (bad != NULL) {
        ERR_clear_error();
        printf("dsa.verify.tampered_ret=%d\n",
            DSA_do_verify(dgst, (int)sizeof(dgst), bad, dsa));
        drain("verify_tampered");
    }

    /* A different digest refuses too, and the original still verifies afterwards -- so the two
     * helpers agree about which message the signature is over. */
    {
        unsigned char other[20];
        size_t i;

        for (i = 0; i < sizeof(other); i++)
            other[i] = dgst[i];
        other[0] ^= 0x01;
        ERR_clear_error();
        printf("dsa.verify.other_digest_ret=%d\n",
            DSA_do_verify(other, (int)sizeof(other), sig, dsa));
        drain("verify_other_digest");
        ERR_clear_error();
        printf("dsa.verify.original_again_ret=%d\n",
            DSA_do_verify(dgst, (int)sizeof(dgst), sig, dsa));
        drain("verify_again");
    }

    /* A signature whose `r` is the subgroup order is out of range, and that refusal answers **0**
     * with **no** queue record: an out-of-range signature is a wrong signature, not an error. */
    {
        DSA_SIG *oor = DSA_SIG_new();
        BIGNUM *rq = q != NULL ? BN_dup(q) : NULL;
        BIGNUM *sq = s != NULL ? BN_dup(s) : NULL;

        printf("dsa.verify.oor_built=%d\n",
            oor != NULL && rq != NULL && sq != NULL && DSA_SIG_set0(oor, rq, sq) == 1);
        ERR_clear_error();
        printf("dsa.verify.oor_ret=%d\n", DSA_do_verify(dgst, (int)sizeof(dgst), oor, dsa));
        drain("verify_oor");
        DSA_SIG_free(oor);
    }

    /* ---- `DSA_SIG_new` is two NULL halves, and `DSA_SIG_set0` refuses a NULL pair */
    {
        DSA_SIG *fresh = DSA_SIG_new();
        const BIGNUM *fr = NULL, *fs = NULL;

        DSA_SIG_get0(fresh, &fr, &fs);
        printf("dsa.sig.new_halves_null=%d\n", fr == NULL && fs == NULL);
        printf("dsa.sig.set0_null_pair_ret=%d\n", DSA_SIG_set0(fresh, NULL, NULL));
        printf("dsa.sig.set0_one_null_ret=%d\n",
            DSA_SIG_set0(fresh, BN_dup(s), NULL));
        DSA_SIG_get0(fresh, &fr, &fs);
        printf("dsa.sig.still_null_after_refusals=%d\n", fr == NULL && fs == NULL);
        DSA_SIG_free(fresh);
    }

    /* ---- the DER `DSA-Sig-Value` pair and the size measurement (D342) ----
     *
     * `DSA_size`, `DSA_sign` and `DSA_verify` reach `i2d_DSA_SIG`/`d2i_DSA_SIG`, whose whole body
     * is `crypto/asn1_dsa.c` over `crypto/packet.c`. The signature bytes are random, so the
     * transcript records only the width the group fixes and the verdicts; no byte of any
     * signature is ever printed, only the two comparisons the probe performs itself. */
    {
        /* The generated group fixes a 160-bit `q`, so each INTEGER is 21 content bytes and the
         * sequence is one constant width -- `DSA_size` is a property of `q`, not of the draw. */
        int size = DSA_size(dsa);
        unsigned char der[256];
        unsigned int derlen = 0;

        printf("dsa.der.size.ret=%d\n", size);
        /* A body with no `q` answers **-1**, not 0: the authority's `ret` starts there. */
        {
            DSA *empty = DSA_new();

            printf("dsa.der.size.no_q_ret=%d\n", DSA_size(empty));
            DSA_free(empty);
        }

        /* The sizing call: a NULL buffer answers 1 and sets `*siglen` to `DSA_size`. */
        ERR_clear_error();
        printf("dsa.der.sign.size_ret=%d\n",
            DSA_sign(0, dgst, (int)sizeof(dgst), NULL, &derlen, dsa));
        drain("der_sign_size");
        printf("dsa.der.sign.size_matches=%d\n", (int)derlen == size);

        /* The real signing call, through the method table and the DER encoder. */
        ERR_clear_error();
        derlen = 0;
        printf("dsa.der.sign.ret=%d\n",
            DSA_sign(0, dgst, (int)sizeof(dgst), der, &derlen, dsa));
        drain("der_sign");
        printf("dsa.der.sign.len_within_size=%d\n", derlen > 0 && (int)derlen <= size);
        printf("dsa.der.sign.starts_sequence=%d\n", derlen > 0 && der[0] == 0x30);

        /* The bytes just produced verify. */
        ERR_clear_error();
        printf("dsa.der.verify.ret=%d\n",
            DSA_verify(0, dgst, (int)sizeof(dgst), der, (int)derlen, dsa));
        drain("der_verify");

        /* A truncation refuses in the decoder, and an appended byte refuses through the
         * re-encode strictness check -- two different `err:` paths, neither of which is a value. */
        ERR_clear_error();
        printf("dsa.der.verify.truncated_ret=%d\n",
            DSA_verify(0, dgst, (int)sizeof(dgst), der, (int)derlen - 1, dsa));
        drain("der_verify_truncated");
        {
            unsigned char garbage[257];

            memcpy(garbage, der, derlen);
            garbage[derlen] = 0x00;
            ERR_clear_error();
            printf("dsa.der.verify.trailing_ret=%d\n",
                DSA_verify(0, dgst, (int)sizeof(dgst), garbage, (int)derlen + 1, dsa));
            drain("der_verify_trailing");
        }

        /* A sequence header whose short-form length claims more content than the buffer holds:
         * the decoder refuses it on the bounds check rather than reading past the end. */
        {
            unsigned char lying[64];
            size_t i;

            for (i = 0; i < sizeof(lying); i++)
                lying[i] = 0x00;
            lying[0] = 0x30;
            lying[1] = 0x7f; /* 127 content bytes declared, 62 present */
            ERR_clear_error();
            printf("dsa.der.verify.overlong_ret=%d\n",
                DSA_verify(0, dgst, (int)sizeof(dgst), lying, (int)sizeof(lying), dsa));
            drain("der_verify_overlong");
        }

        /* An empty body: `DSA_sign` answers 0 and zeroes `*siglen` through the sign epilogue. */
        {
            DSA *empty = DSA_new();

            derlen = 0;
            ERR_clear_error();
            printf("dsa.der.sign.empty_ret=%d\n",
                DSA_sign(0, dgst, (int)sizeof(dgst), der, &derlen, empty));
            drain("der_sign_empty");
            printf("dsa.der.sign.empty_siglen_zero=%d\n", derlen == 0);
            DSA_free(empty);
        }

        /* ---- the codec's own entry points, `i2d_DSA_SIG`/`d2i_DSA_SIG`, called
         * directly so the coverage atlas sees them as courted and the round trip is a
         * verdict rather than a byte comparison. */
        {
            unsigned char *pp = NULL;
            const unsigned char *cp;
            DSA_SIG *decoded = NULL;
            DSA_SIG *reused = NULL;
            int n;

            /* The measuring shape: a NULL `ppout` answers the length and allocates nothing. */
            printf("dsa.der.i2d.measure_positive=%d\n", i2d_DSA_SIG(sig, NULL) > 0);

            /* `*ppout == NULL`: the encoder grows a `BUF_MEM` and hands its buffer to the
             * caller, detaching it, so the caller frees it with `OPENSSL_free`. */
            n = i2d_DSA_SIG(sig, &pp);
            printf("dsa.der.i2d.alloc_ret=%d\n", n > 0 && pp != NULL);
            printf("dsa.der.i2d.alloc_starts_sequence=%d\n", pp != NULL && pp[0] == 0x30);

            /* Decode it back and re-verify: the DER round trip is the identity on the two
             * halves as far as the verdict can see, since no half is ever printed. */
            cp = pp;
            printf("dsa.der.d2i.ret_notnull=%d\n",
                d2i_DSA_SIG(&decoded, &cp, (long)n) != NULL);
            printf("dsa.der.d2i.consumed_all=%d\n", (int)(cp - pp) == n);
            printf("dsa.der.d2i.verify_ret=%d\n",
                decoded != NULL ? DSA_do_verify(dgst, (int)sizeof(dgst), decoded, dsa) : -99);

            /* A live `*psig` is reused rather than replaced, so the answer is that object. */
            reused = DSA_SIG_new();
            cp = pp;
            printf("dsa.der.d2i.reuse_returns_the_object=%d\n",
                reused != NULL && d2i_DSA_SIG(&reused, &cp, (long)n) == reused);
            /* A negative length refuses before anything is allocated. */
            printf("dsa.der.d2i.negative_len_refused=%d\n",
                d2i_DSA_SIG(&decoded, &cp, -1) == NULL);

            DSA_SIG_free(reused);
            DSA_SIG_free(decoded);
            OPENSSL_free(pp);
        }
    }

    /* ---- `DSA_dup_DH`: the parameters and the key survive the change of type */
    {
        DH *dh = DSA_dup_DH(dsa);

        printf("dsa.dup_dh.not_null=%d\n", dh != NULL);
        if (dh != NULL) {
            const BIGNUM *dp = NULL, *dq = NULL, *dg = NULL, *dpub = NULL, *dpriv = NULL;

            DH_get0_pqg(dh, &dp, &dq, &dg);
            DH_get0_key(dh, &dpub, &dpriv);
            printf("dsa.dup_dh.p_bits_match=%d\n",
                dp != NULL && p != NULL ? BN_num_bits(dp) == BN_num_bits(p) : 0);
            printf("dsa.dup_dh.q_bits_match=%d\n",
                dq != NULL && q != NULL ? BN_num_bits(dq) == BN_num_bits(q) : 0);
            printf("dsa.dup_dh.g_nonnull=%d\n", dg != NULL);
            printf("dsa.dup_dh.key_present=%d\n", dpub != NULL && dpriv != NULL);
            DH_free(dh);
        }
    }

    /* ---- D345: `crypto/dsa/dsa_asn1.c` -- the three templates and `DSAparams_dup`. Each arm is a
     * verdict on the values the probe re-reads, never a byte of an encoding: no parameter, key,
     * private scalar or signature half is printed. */
    {
        unsigned char *der = NULL;
        const unsigned char *cp;
        int n;

        /* The `DSAparams` template over the generated group. */
        printf("dsa.asn1.params.measure_positive=%d\n", i2d_DSAparams(dsa, NULL) > 0);
        n = i2d_DSAparams(dsa, &der);
        printf("dsa.asn1.params.i2d_ret=%d\n", n > 0 && der != NULL);
        printf("dsa.asn1.params.starts_sequence=%d\n", der != NULL && der[0] == 0x30);
        cp = der;
        {
            DSA *round = d2i_DSAparams(NULL, &cp, (long)n);
            const BIGNUM *rp = NULL, *rq = NULL, *rg = NULL;

            printf("dsa.asn1.params.d2i_notnull=%d\n", round != NULL);
            if (round != NULL) {
                DSA_get0_pqg(round, &rp, &rq, &rg);
                printf("dsa.asn1.params.round_trip=%d\n",
                    rp != NULL && rq != NULL && rg != NULL
                    && BN_cmp(rp, p) == 0 && BN_cmp(rq, q) == 0 && BN_cmp(rg, g) == 0);
                printf("dsa.asn1.params.consumed_all=%d\n", (int)(cp - der) == n);
                DSA_free(round);
            }
        }
        OPENSSL_free(der);
        der = NULL;

        /* The `DSAPublicKey` template: `y`, `p`, `q`, `g` in the authority's order. */
        n = i2d_DSAPublicKey(dsa, &der);
        printf("dsa.asn1.pub.i2d_ret=%d\n", n > 0 && der != NULL);
        cp = der;
        {
            DSA *round = d2i_DSAPublicKey(NULL, &cp, (long)n);
            const BIGNUM *rp = NULL, *rq = NULL, *rg = NULL, *rpub = NULL, *rpriv = NULL;

            printf("dsa.asn1.pub.d2i_notnull=%d\n", round != NULL);
            if (round != NULL) {
                DSA_get0_pqg(round, &rp, &rq, &rg);
                DSA_get0_key(round, &rpub, &rpriv);
                printf("dsa.asn1.pub.round_trip=%d\n",
                    rp != NULL && rq != NULL && rg != NULL && rpub != NULL
                    && BN_cmp(rp, p) == 0 && BN_cmp(rq, q) == 0 && BN_cmp(rg, g) == 0
                    && pub != NULL && BN_cmp(rpub, pub) == 0);
                printf("dsa.asn1.pub.no_private=%d\n", rpriv == NULL);
                DSA_free(round);
            }
        }
        OPENSSL_free(der);
        der = NULL;

        /* The `DSAPrivateKey` template: the version word, the three parameters, `y` and `x`. The
         * private scalar is compared with `BN_cmp` and never printed. */
        n = i2d_DSAPrivateKey(dsa, &der);
        printf("dsa.asn1.priv.i2d_ret=%d\n", n > 0 && der != NULL);
        printf("dsa.asn1.priv.starts_sequence=%d\n", der != NULL && der[0] == 0x30);
        cp = der;
        {
            DSA *round = d2i_DSAPrivateKey(NULL, &cp, (long)n);
            const BIGNUM *rp = NULL, *rq = NULL, *rg = NULL, *rpub = NULL, *rpriv = NULL;

            printf("dsa.asn1.priv.d2i_notnull=%d\n", round != NULL);
            if (round != NULL) {
                DSA_get0_pqg(round, &rp, &rq, &rg);
                DSA_get0_key(round, &rpub, &rpriv);
                printf("dsa.asn1.priv.round_trip=%d\n",
                    rp != NULL && rq != NULL && rg != NULL && rpub != NULL && rpriv != NULL
                    && BN_cmp(rp, p) == 0 && BN_cmp(rq, q) == 0 && BN_cmp(rg, g) == 0
                    && pub != NULL && priv != NULL
                    && BN_cmp(rpub, pub) == 0 && BN_cmp(rpriv, priv) == 0);
                DSA_free(round);
            }
        }
        OPENSSL_free(der);
        der = NULL;

        /* `DSAparams_dup`: an encode-then-decode, so the answer is a fresh `DSA` with the three
         * parameters and no key. */
        {
            DSA *dup = DSAparams_dup(dsa);
            const BIGNUM *rp = NULL, *rq = NULL, *rg = NULL, *dpub = NULL, *dpriv = NULL;

            printf("dsa.asn1.params_dup.notnull=%d\n", dup != NULL);
            if (dup != NULL) {
                DSA_get0_pqg(dup, &rp, &rq, &rg);
                DSA_get0_key(dup, &dpub, &dpriv);
                printf("dsa.asn1.params_dup.match=%d\n",
                    rp != NULL && rq != NULL && rg != NULL
                    && BN_cmp(rp, p) == 0 && BN_cmp(rq, q) == 0 && BN_cmp(rg, g) == 0);
                printf("dsa.asn1.params_dup.no_key=%d\n", dpub == NULL && dpriv == NULL);
                DSA_free(dup);
            }
        }

        /* The refusals: an object with no parameters cannot be encoded, and a negative length is
         * refused before anything is read. */
        {
            DSA *empty = DSA_new();
            unsigned char *none = NULL;

            ERR_clear_error();
            printf("dsa.asn1.params.i2d_empty_ret=%d\n", i2d_DSAparams(empty, &none));
            drain("asn1_i2d_empty");
            OPENSSL_free(none);
            cp = der;
            ERR_clear_error();
            printf("dsa.asn1.params.d2i_negative_is_null=%d\n",
                d2i_DSAparams(NULL, &cp, -1) == NULL);
            drain("asn1_d2i_negative");
            DSA_free(empty);
        }
    }

    /* ---- the refusals, each through its return value and the drained coordinate */

    /* A body with no parameters at all: `DSA_do_sign` answers NULL and raises the *parameter*
     * reason from `ossl_dsa_do_sign_int`'s shared epilogue -- one record, at that function's
     * line. */
    {
        DSA *empty = DSA_new();

        ERR_clear_error();
        printf("dsa.refuse.sign_empty.is_null=%d\n",
            DSA_do_sign(dgst, (int)sizeof(dgst), empty) == NULL);
        drain("sign_empty");
        ERR_clear_error();
        printf("dsa.refuse.verify_empty.ret=%d\n",
            DSA_do_verify(dgst, (int)sizeof(dgst), sig, empty));
        drain("verify_empty");
        ERR_clear_error();
        /* `*rp` must be a live `BIGNUM` even for a refusal: the authority reads it in
         * `dsa_sign_setup`'s declaration block, before the guards. */
        {
            BIGNUM *ekinv = NULL;
            BIGNUM *er = BN_new();

            printf("dsa.refuse.setup_empty.ret=%d\n",
                DSA_sign_setup(empty, NULL, &ekinv, &er));
            drain("setup_empty");
            printf("dsa.refuse.setup_empty.no_output=%d\n", ekinv == NULL && er != NULL);
            BN_clear_free(ekinv);
            BN_free(er);
        }
        DSA_free(empty);
    }

    /* A body with parameters and no private key: the second guard of the sign path, and its own
     * reason code at the same line. */
    {
        DSA *nopriv = DSA_new();
        BIGNUM *p2 = BN_dup(p);
        BIGNUM *q2 = BN_dup(q);
        BIGNUM *g2 = BN_dup(g);

        printf("dsa.refuse.nopriv.built=%d\n",
            p2 != NULL && q2 != NULL && g2 != NULL && DSA_set0_pqg(nopriv, p2, q2, g2) == 1);
        ERR_clear_error();
        printf("dsa.refuse.nopriv.is_null=%d\n",
            DSA_do_sign(dgst, (int)sizeof(dgst), nopriv) == NULL);
        drain("sign_nopriv");
        ERR_clear_error();
        {
            BIGNUM *nkinv = NULL;
            BIGNUM *nr = BN_new();

            printf("dsa.refuse.nopriv_setup.ret=%d\n",
                DSA_sign_setup(nopriv, NULL, &nkinv, &nr));
            drain("setup_nopriv");
            printf("dsa.refuse.nopriv_setup.no_output=%d\n", nkinv == NULL && nr != NULL);
            BN_clear_free(nkinv);
            BN_free(nr);
        }
        DSA_free(nopriv);
    }

    /* The tiny group: every signature arm refuses it, and the `q`-width test is what does it --
     * `dsa_sign_setup` raises ERR_R_BN_LIB at its own `err:` label and then
     * `ossl_dsa_do_sign_int` raises it again, so the sign arm leaves **two** records. */
    {
        DSA *tiny = tiny_group();

        printf("dsa.refuse.tiny.built=%d\n", tiny != NULL);
        if (tiny != NULL) {
            BIGNUM *tkinv = NULL;
            BIGNUM *tr = NULL;

            printf("dsa.refuse.tiny.bits=%d\n", DSA_bits(tiny));
            printf("dsa.refuse.tiny.security_bits=%d\n", DSA_security_bits(tiny));
            ERR_clear_error();
            printf("dsa.refuse.tiny_genkey.ret=%d\n", DSA_generate_key(tiny));
            drain("tiny_genkey");
            ERR_clear_error();
            printf("dsa.refuse.tiny_sign.is_null=%d\n",
                DSA_do_sign(dgst, (int)sizeof(dgst), tiny) == NULL);
            drain("tiny_sign");
            ERR_clear_error();
            printf("dsa.refuse.tiny_setup.ret=%d\n",
                DSA_sign_setup(tiny, NULL, &tkinv, &tr));
            drain("tiny_setup");
            printf("dsa.refuse.tiny_setup.no_output=%d\n", tkinv == NULL && tr == NULL);
            BN_clear_free(tkinv);
            BN_free(tr);
            ERR_clear_error();
            printf("dsa.refuse.tiny_verify.ret=%d\n",
                DSA_do_verify(dgst, (int)sizeof(dgst), sig, tiny));
            drain("tiny_verify");
            DSA_free(tiny);
        }
    }

    /* A group whose three values are all zero and whose private key is present: the
     * "obviously invalid parameters" guard inside `dsa_sign_setup`, which raises
     * `DSA_R_INVALID_PARAMETERS` there and then `ERR_R_BN_LIB` from the sign epilogue. */
    {
        DSA *zeros = DSA_new();
        BIGNUM *z1 = BN_new();
        BIGNUM *z2 = BN_new();
        BIGNUM *z3 = BN_new();

        BN_set_word(z1, 0);
        BN_set_word(z2, 0);
        BN_set_word(z3, 0);
        printf("dsa.refuse.zeros.built=%d\n", DSA_set0_pqg(zeros, z1, z2, z3) == 1);
        printf("dsa.refuse.zeros.key_ret=%d\n", DSA_set0_key(zeros, NULL, BN_dup(priv)));
        ERR_clear_error();
        printf("dsa.refuse.zeros_sign.is_null=%d\n",
            DSA_do_sign(dgst, (int)sizeof(dgst), zeros) == NULL);
        drain("zeros_sign");
        DSA_free(zeros);
    }

    /* ---- `DSA_generate_parameters`'s own arm, and a refusal with the FFC's own coordinate */

    DSA_free(dsa);
    ERR_clear_error();
    dsa = DSA_generate_parameters(1024, seed, (int)sizeof(seed), &counter, &h, NULL, NULL);
    printf("dsa.genparams.depr_nonnull=%d\n", dsa != NULL);
    drain("genparams_depr");
    if (dsa != NULL) {
        printf("dsa.genparams.depr_bits=%d\n", DSA_bits(dsa));
        DSA_free(dsa);
    }

    /* The 512-bit arm: the deprecated wrapper's parameter generation **succeeds** at a size the
     * FFC *validator* refuses, and `DSA_generate_key` on that very object refuses through the
     * validator's own coordinate. That asymmetry is why the object is not released here -- the
     * end of this function does it -- and it is the one place this court observes a generated
     * group no key can be made for. */
    ERR_clear_error();
    dsa = DSA_generate_parameters(512, NULL, 0, NULL, NULL, NULL, NULL);
    printf("dsa.genparams.depr_512_nonnull=%d\n", dsa != NULL);
    drain("genparams_512");
    if (dsa != NULL) {
        printf("dsa.genparams.depr_512_bits=%d\n", DSA_bits(dsa));
        ERR_clear_error();
        printf("dsa.refuse.genkey_512.ret=%d\n", DSA_generate_key(dsa));
        drain("genkey_512");
    }

    DSA_SIG_free(sig);
    DSA_SIG_free(bad);
    DSA_free(dsa);
    BN_free(one);
}

int main(void)
{
    /* The install latches, so it is the first act of the process. `my_malloc` records only while a
     * window is open, so the warm-up below attributes nothing. */
    if (!CRYPTO_set_mem_functions(my_malloc, my_realloc, my_free)) {
        printf("dsa.set_mem_functions=0\n");
        return 1;
    }
    printf("dsa.set_mem_functions=1\n");

    dsa_method_arms();
    dsa_object_arms();
    dsa_primitive_arms();
    dsa_ctl_arms();

    return 0;
}
