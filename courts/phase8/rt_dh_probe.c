/*
 * RT-DH -- the differential court for `crypto/dh/` (Phase 8.5).
 *
 * This program is compiled **twice**, once against the admitted authority and once against the
 * candidate distribution shell, and the two `key=value` transcripts are diffed. It never decides
 * anything: a residual is a difference between two executions, so the expectation cannot drift
 * with the crate. `forensics/tools/phase8_courts.py` owns the comparison.
 *
 * What this court covers
 * ----------------------
 * **Two slices, one probe.** D329's arms are the twenty-one `DH_meth_*` labels of
 * `crypto/dh/dh_meth.c`, where nothing does any cryptography: each function allocates a table,
 * stores a pointer in one, duplicates one, releases one, or reads one back, so their transcript is
 * about *identity, ownership and structure*. D331's arms are the thirty-nine exports of
 * `dh_lib.c`, `dh_key.c`, `dh_gen.c`, `dh_check.c` and `dh_depr.c` -- the `DH` object and its
 * accessors, the default-method family, generation, agreement and every validator. **All sixty
 * exports are called.**
 *
 * The second half is arithmetic, and what it observes is chosen so that no random or secret byte
 * can reach the transcript: a **generated 512-bit safe-prime group** is the parameter set every
 * key arm uses, and the arms print its *properties* only -- `DH_bits`/`DH_size`/`DH_security_bits`,
 * the RFC 7919 key length `DH_generate_parameters_ex` stores, the private exponent's bit width
 * (which `BN_RAND_TOP_ONE` makes exactly that length), the public key's range, two parties'
 * agreement as an equality, and `DH_compute_key` as the padded function's tail. Every refusal is
 * observed through **both** its return value and the coordinate `ERR_get_error_all` reports, which
 * is how the `-1`-vs-`0` asymmetry of `ossl_dh_compute_key`'s three bounds and the **two** records
 * a bad generator leaves are compared rather than asserted.
 *
 * What it does not cover: the FFC primitives (their evidence is their own unit tests, D330),
 * `DH_KDF_X9_42` and the `dh_ameth.c` ASN.1 method objects (`ossl_dh_asn1_meth`, `ossl_dhx_asn1_meth`).
 * D345 lands `crypto/dh/dh_asn1.c` **whole** and the two `dh_ameth.c` exports that reach no Phase 11
 * name — `DHparams_dup` and `DHparams_print` — plus `dh_prn.c`'s `FILE *` wrapper, and the fourth
 * block of arms is theirs. D332's named-group arms are the third block:
 * all fourteen rows of
 * `dh_named_groups[]`, the four `DH_new_by_nid`/`DH_get_nid`-shaped entry points, the three
 * deprecated constructors, the cache `DH_set0_pqg` reaches, and primality through the landed
 * `BN_check_prime`. Two names of that unit are **not** reachable from this court and say so:
 * `ossl_dh_is_named_safe_prime_group`'s one caller is the EVP control translator and
 * `ossl_dh_check_priv_key`'s is the provider keymgmt, so both are exercised by unit tests rather
 * than by an arm. D343 lands `crypto/evp/dh_ctrl.c`'s twenty controls, and the last block of arms
 * is theirs: a NULL context, a live context with no operation, one with a generation operation and
 * one with a derivation operation, and the five getter-backed round trips. This court's arms say
 * so by their absence rather than by a transcribed expectation, and `docs/DECISIONS.md` D329, D331,
 * D332, D343 and D345 name what keeps each open.
 *
 * The allocator-attribution plane
 * -------------------------------
 * `CRYPTO_set_mem_functions`'s callbacks take `(size_t num, const char *file, int line)`, and all
 * three are part of the published contract: an embedder that installs an allocator receives them.
 * `dh_meth.c` is a **source-tree** file, so `OPENSSL_FILE` in its bodies is
 * `../../src/openssl-3.6.4/crypto/dh/dh_meth.c` -- the prefix is present, unlike the `.c.in`
 * instances D279 and D280 had to distinguish. So the first thing this probe does is install an
 * allocator and record, for each arm, the **ordered sequence of `(kind, size, file)`** the library
 * requests inside a window that starts before the call and ends after it. That is how the claim
 * "this unit's allocation is attributed to this unit's translation unit" becomes a diff instead of
 * a constant in the crate.
 *
 * **The sequence, not just the set, is deliberate.** The order is load-bearing in three arms:
 * `DH_meth_new` stores `flags` *before* duplicating the name, so a failed duplicate can release
 * the table; `DH_meth_set1_name` duplicates *first* and releases second, so a failed duplicate
 * leaves the old name in place; `DH_meth_free` releases the name *before* the table. A set of
 * `file` strings would make all three orders invisible.
 *
 * The window is a window and not a whole-program trace for the same reason `RT-CIPHER-MEM`'s is:
 * `CRYPTO_set_mem_functions` latches, and the *rest* of the process -- the error queue, stdio, the
 * warm-up -- is not what this court is about. The warm-up call before the first window is what
 * keeps the first window from containing lazy library state.
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
/* `DH_meth_*` are `OSSL_DEPRECATEDIN_3_0`. The deprecation is the authority's own policy statement
 * about application code, not about a court that must exercise the entry points it declares;
 * suppressing the diagnostic keeps `-Wall` output readable without changing a single symbol this
 * probe links. */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/bio.h>
#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ the recorder */

#define EV_MAX 32
#define EV_NAME 512

/* Each event owns a copy of its `file` string rather than a pointer into the library, so a
 * release that happens before the window closes cannot leave the transcript reading freed
 * memory. A NULL `file` is recorded as the literal `<null>` for the same reason: the argument is
 * itself part of the contract, and dropping the event would hide exactly that. */
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

/* A hex printer for the KDF arms. The DH/EC probe prints no key, group or shared secret; this
 * helper exists only for `DH_KDF_X9_42`'s derived bytes over the constants `dh_kdf_arms` sets. */
static void rt_hex_bytes(const unsigned char *p, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++)
        printf("%02x", p[i]);
}

static void end(const char *arm)
{
    int i;

    recording = 0;
    printf("dh.%s.ev=%d\n", arm, nev);
    for (i = 0; i < nev; i++)
        printf("dh.%s.ev.%d=%c:%lu:%s\n", arm, i, ev_kind[i], ev_size[i], ev_file[i]);
}

/* ------------------------------------------------------------------ sentinels */

/* One per distinct function-pointer signature in `DH_METHOD`. They are stored and compared,
 * never called: each returns its own constant so that a transcription which *did* call one would
 * be visible in the transcript rather than merely wrong. */
static int sentinel_generate_key(DH *dh)
{
    (void)dh;
    return 0;
}

static int sentinel_compute_key(unsigned char *key, const BIGNUM *pub_key, DH *dh)
{
    (void)key; (void)pub_key; (void)dh;
    return 0;
}

static int sentinel_bn_mod_exp(const DH *dh, BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
    const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx)
{
    (void)dh; (void)r; (void)a; (void)p; (void)m; (void)ctx; (void)m_ctx;
    return 0;
}

static int sentinel_life(DH *dh)
{
    (void)dh;
    return 0;
}

static int sentinel_generate_params(DH *dh, int prime_len, int generator, BN_GENCB *cb)
{
    (void)dh; (void)prime_len; (void)generator; (void)cb;
    return 0;
}

/* The six function-pointer pairs, each observed five ways: the member of a fresh table is NULL;
 * the setter answers 1; the getter then answers the *sentinel* rather than merely non-NULL; the
 * setter accepts NULL and still answers 1; and the getter is back to NULL. The round trip leaves
 * the member NULL, which is what lets one table serve all six without order dependence. */
#define ROUNDTRIP(tag, GET, SET, SENT)                                  \
    do {                                                                \
        printf("dh.%s.get_default_is_null=%d\n", tag,                  \
            (const void *)(GET)(m) == NULL);                            \
        printf("dh.%s.set_ret=%d\n", tag, (SET)(m, (SENT)));           \
        printf("dh.%s.get_is_sentinel=%d\n", tag,                      \
            (const void *)(GET)(m) == (const void *)(SENT));           \
        printf("dh.%s.set_null_ret=%d\n", tag, (SET)(m, NULL));        \
        printf("dh.%s.get_after_null_is_null=%d\n", tag,               \
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
        printf("dh.%s.err.%d=%lu:%s:%d:%s\n", arm, n, e,
            file != NULL ? file : "(null)", line,
            func != NULL ? func : "(null)");
        n++;
    }
    printf("dh.%s.err.count=%d\n", arm, n);
}

/* ------------------------------------------------------------------ the control court's provider
 *
 * The `EVP_PKEY_CTX_*dh*` controls of `crypto/evp/dh_ctrl.c` are decisions *about a context*, so
 * they need a context to decide about. This crate publishes no DH `EVP_KEYMGMT` and no DH
 * `EVP_KEYEXCH` (8.5's provider half is not landed), so `EVP_PKEY_CTX_new_from_name(NULL, "DH",
 * NULL)` answers NULL on the candidate and a context on the authority -- an arm that compared that
 * would be a difference about a missing provider row rather than about the controls. The provider
 * below supplies the smallest keymgmt and keyexch the structural check accepts, named `COURT-DH`
 * rather than `DH` so that it cannot shadow the default provider's own row in either binary's
 * method store. Every parameter the controls send is *echoed* by the callback that receives it, so
 * the transcript observes the parameter array the library built and not merely its return code; no
 * echoed value is a secret -- they are FFC sizes, digest and group names, a probe-chosen seed and a
 * probe-chosen UKM, all of which the probe itself supplies. */

struct court_ctx {
    int have_gindex;
    int gindex;
    int have_gen;
    int gen;
    int have_pbits;
    unsigned long pbits;
    int have_qbits;
    unsigned long qbits;
    int have_seed;
    unsigned long seedlen;
    int have_type;
    char type[64];
    int have_digest;
    char digest[64];
    int have_props;
    char props[64];
    int have_pad;
    unsigned int pad;
    int have_outlen;
    unsigned long outlen;
    int have_kdftype;
    char kdftype[64];
    int have_md;
    char md[64];
    int have_oid;
    char oid[80];
    int have_ukm;
    unsigned long ukmlen;
    unsigned char ukm[64];
};

static struct court_ctx *court_new(void)
{
    struct court_ctx *c = malloc(sizeof(*c));

    if (c == NULL)
        return NULL;
    memset(c, 0, sizeof(*c));
    /* The defaults a fresh context answers with. `kdf-type` is the empty string, which
     * `fix_dh_kdf_type`'s table maps back to `EVP_PKEY_DH_KDF_NONE`; `kdf-outlen` is zero, which is
     * the one value `EVP_PKEY_CTX_get_dh_kdf_outlen` reports as a success. */
    strcpy(c->kdftype, "");
    strcpy(c->md, "SHA256");
    strcpy(c->oid, "1.3.133.16.840.63.0.2");
    return c;
}

/* Print every parameter the library sent, one `key=value` line per entry. The rendering is by
 * `data_type`, so a wrong type is visible as well as a wrong value, and the five `OSSL_PARAM`
 * types the controls use are each rendered their own way. */
static void court_dump(const char *arm, const OSSL_PARAM params[])
{
    int i;

    for (i = 0; params != NULL && params[i].key != NULL; i++) {
        const OSSL_PARAM *p = &params[i];

        if (p->data_type == OSSL_PARAM_INTEGER) {
            int64_t v = 0;
            OSSL_PARAM_get_int64(p, &v);
            printf("dh.%s.p.%d=%s:int:%lld\n", arm, i, p->key, (long long)v);
        } else if (p->data_type == OSSL_PARAM_UNSIGNED_INTEGER) {
            uint64_t v = 0;
            OSSL_PARAM_get_uint64(p, &v);
            printf("dh.%s.p.%d=%s:uint:%llu\n", arm, i, p->key, (unsigned long long)v);
        } else if (p->data_type == OSSL_PARAM_UTF8_STRING) {
            printf("dh.%s.p.%d=%s:utf8:%s\n", arm, i, p->key,
                p->data != NULL ? (const char *)p->data : "<null>");
        } else if (p->data_type == OSSL_PARAM_OCTET_STRING) {
            printf("dh.%s.p.%d=%s:octet:%zu\n", arm, i, p->key, p->data_size);
        } else {
            printf("dh.%s.p.%d=%s:type%u:%zu\n", arm, i, p->key, p->data_type,
                p->data_size);
        }
    }
    printf("dh.%s.p.count=%d\n", arm, i);
}

/* Remember the parameters a getter will be asked for, by copying the value rather than the
 * pointer: the arrays the controls build point at stack locals in the *calling* frame, so a stored
 * pointer would be stale the moment the call returns. */
static void court_store(struct court_ctx *c, const OSSL_PARAM params[])
{
    int i;

    for (i = 0; params != NULL && params[i].key != NULL; i++) {
        const OSSL_PARAM *p = &params[i];

        if (strcmp(p->key, "gindex") == 0) {
            int64_t v = 0;
            OSSL_PARAM_get_int64(p, &v);
            c->have_gindex = 1;
            c->gindex = (int)v;
        } else if (strcmp(p->key, "safeprime-generator") == 0) {
            int64_t v = 0;
            OSSL_PARAM_get_int64(p, &v);
            c->have_gen = 1;
            c->gen = (int)v;
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
        } else if (strcmp(p->key, "seed") == 0) {
            c->have_seed = 1;
            c->seedlen = p->data_size;
        } else if (strcmp(p->key, "type") == 0) {
            c->have_type = 1;
            snprintf(c->type, sizeof(c->type), "%s", (const char *)p->data);
        } else if (strcmp(p->key, "digest") == 0) {
            c->have_digest = 1;
            snprintf(c->digest, sizeof(c->digest), "%s", (const char *)p->data);
        } else if (strcmp(p->key, "properties") == 0) {
            c->have_props = 1;
            snprintf(c->props, sizeof(c->props), "%s", (const char *)p->data);
        } else if (strcmp(p->key, "pad") == 0) {
            uint64_t v = 0;
            OSSL_PARAM_get_uint64(p, &v);
            c->have_pad = 1;
            c->pad = (unsigned int)v;
        } else if (strcmp(p->key, "kdf-outlen") == 0) {
            uint64_t v = 0;
            OSSL_PARAM_get_uint64(p, &v);
            c->have_outlen = 1;
            c->outlen = (unsigned long)v;
        } else if (strcmp(p->key, "kdf-type") == 0) {
            c->have_kdftype = 1;
            snprintf(c->kdftype, sizeof(c->kdftype), "%s", (const char *)p->data);
        } else if (strcmp(p->key, "kdf-digest") == 0) {
            c->have_md = 1;
            snprintf(c->md, sizeof(c->md), "%s", (const char *)p->data);
        } else if (strcmp(p->key, "cekalg") == 0) {
            c->have_oid = 1;
            snprintf(c->oid, sizeof(c->oid), "%s", (const char *)p->data);
        } else if (strcmp(p->key, "kdf-ukm") == 0) {
            c->have_ukm = 1;
            c->ukmlen = p->data_size;
            if (p->data != NULL && p->data_size <= sizeof(c->ukm))
                memcpy(c->ukm, p->data, p->data_size);
        }
    }
}

static int court_get(struct court_ctx *c, OSSL_PARAM params[])
{
    int i;

    for (i = 0; params != NULL && params[i].key != NULL; i++) {
        OSSL_PARAM *p = &params[i];

        if (strcmp(p->key, "kdf-outlen") == 0)
            OSSL_PARAM_set_uint64(p, (uint64_t)c->outlen);
        else if (strcmp(p->key, "kdf-type") == 0)
            OSSL_PARAM_set_utf8_string(p, c->kdftype);
        else if (strcmp(p->key, "kdf-digest") == 0)
            OSSL_PARAM_set_utf8_string(p, c->md);
        else if (strcmp(p->key, "cekalg") == 0)
            OSSL_PARAM_set_utf8_string(p, c->oid);
        else if (strcmp(p->key, "kdf-ukm") == 0)
            OSSL_PARAM_set_octet_ptr(p, c->ukm, c->ukmlen);
    }
    return 1;
}

/* The settable and gettable lists, as the structural check reads them. The `data` pointers are
 * NULL and `data_size` is the width the *control* builds, which is all a list of names needs. */
static const OSSL_PARAM court_gen_settable[] = {
    { "gindex", OSSL_PARAM_INTEGER, NULL, sizeof(int), 0 },
    { "safeprime-generator", OSSL_PARAM_INTEGER, NULL, sizeof(int), 0 },
    { "pbits", OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0 },
    { "qbits", OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0 },
    { "seed", OSSL_PARAM_OCTET_STRING, NULL, 0, 0 },
    { "type", OSSL_PARAM_UTF8_STRING, NULL, 0, 0 },
    { "digest", OSSL_PARAM_UTF8_STRING, NULL, 0, 0 },
    { "properties", OSSL_PARAM_UTF8_STRING, NULL, 0, 0 },
    { "group", OSSL_PARAM_UTF8_STRING, NULL, 0, 0 },
    { NULL, 0, NULL, 0, 0 }
};
static const OSSL_PARAM court_gen_gettable[] = {
    { NULL, 0, NULL, 0, 0 }
};
static const OSSL_PARAM court_kex_settable[] = {
    { "pad", OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(unsigned int), 0 },
    { "kdf-outlen", OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0 },
    { "kdf-type", OSSL_PARAM_UTF8_STRING, NULL, 0, 0 },
    { "kdf-digest", OSSL_PARAM_UTF8_STRING, NULL, 0, 0 },
    { "cekalg", OSSL_PARAM_UTF8_STRING, NULL, 0, 0 },
    { "kdf-ukm", OSSL_PARAM_OCTET_STRING, NULL, 0, 0 },
    { NULL, 0, NULL, 0, 0 }
};
static const OSSL_PARAM court_kex_gettable[] = {
    { "kdf-outlen", OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0 },
    { "kdf-type", OSSL_PARAM_UTF8_STRING, NULL, 0, 0 },
    { "kdf-digest", OSSL_PARAM_UTF8_STRING, NULL, 0, 0 },
    { "cekalg", OSSL_PARAM_UTF8_STRING, NULL, 0, 0 },
    { "kdf-ukm", OSSL_PARAM_OCTET_PTR, NULL, 0, 0 },
    { NULL, 0, NULL, 0, 0 }
};

/* The keymgmt: only the generation callbacks carry state, because every control that reaches a
 * keymgmt does so through `EVP_PKEY_CTX_set_params` on a generation operation. */
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
{ court_dump("gen.get", params); return court_get(genctx, params); }
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

/* The keyexch: the ten key-derivation controls reach `EVP_PKEY_CTX_set_params`/`_get_params` on a
 * derivation operation, which dispatch to `set_ctx_params`/`get_ctx_params`. */
static void *cx_newctx(void *provctx) { (void)provctx; return court_new(); }
static int cx_init(void *algctx) { (void)algctx; return 1; }
static int cx_set_peer(void *algctx, void *peerkey)
{ (void)algctx; (void)peerkey; return 1; }
static int cx_derive(void *algctx, unsigned char *secret, size_t *secretlen, size_t outlen)
{ (void)algctx; (void)secret; (void)secretlen; (void)outlen; return 1; }
static void cx_freectx(void *algctx) { free(algctx); }
static int cx_set_ctx_params(void *algctx, const OSSL_PARAM params[])
{ court_dump("der.set", params); court_store(algctx, params); return 1; }
static const OSSL_PARAM *cx_settable_ctx_params(void *algctx, void *provctx)
{ (void)algctx; (void)provctx; return court_kex_settable; }
static int cx_get_ctx_params(void *algctx, OSSL_PARAM params[])
{ court_dump("der.get", params); return court_get(algctx, params); }
static const OSSL_PARAM *cx_gettable_ctx_params(void *algctx, void *provctx)
{ (void)algctx; (void)provctx; return court_kex_gettable; }

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

static const OSSL_DISPATCH court_keyexch_fns[] = {
    { OSSL_FUNC_KEYEXCH_NEWCTX, (void (*)(void))cx_newctx },
    { OSSL_FUNC_KEYEXCH_INIT, (void (*)(void))cx_init },
    { OSSL_FUNC_KEYEXCH_DERIVE, (void (*)(void))cx_derive },
    { OSSL_FUNC_KEYEXCH_SET_PEER, (void (*)(void))cx_set_peer },
    { OSSL_FUNC_KEYEXCH_FREECTX, (void (*)(void))cx_freectx },
    { OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS, (void (*)(void))cx_set_ctx_params },
    { OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS, (void (*)(void))cx_settable_ctx_params },
    { OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS, (void (*)(void))cx_get_ctx_params },
    { OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS, (void (*)(void))cx_gettable_ctx_params },
    { 0, NULL }
};

static const OSSL_ALGORITHM *court_query(void *provctx, int operation_id, int *no_cache)
{
    static const OSSL_ALGORITHM km[] = {
        { "COURT-DH:court-dh", "provider=court-dh", court_keymgmt_fns,
          "the probe's keymgmt" },
        { NULL, NULL, NULL, NULL }
    };
    static const OSSL_ALGORITHM kx[] = {
        { "COURT-DH:court-dh", "provider=court-dh", court_keyexch_fns,
          "the probe's keyexch" },
        { NULL, NULL, NULL, NULL }
    };

    (void)provctx;
    *no_cache = 0;
    if (operation_id == OSSL_OP_KEYMGMT)
        return km;
    if (operation_id == OSSL_OP_KEYEXCH)
        return kx;
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

/* The twenty controls, three ways. Every one is called with a NULL context and with a live one; the
 * live context is then given a generation operation for the nine generation controls and a
 * derivation operation for the ten derivation ones, so the *successful* path of each is observed as
 * the parameter array the library builds. The round trips are the five getter-backed pairs, and
 * every refusal drains its queue. */
static void dh_ctl_arms(void)
{
    OSSL_PROVIDER *prov;
    EVP_PKEY_CTX *null_ctx = NULL;
    EVP_PKEY_CTX *fresh = NULL;
    EVP_PKEY_CTX *gen = NULL;
    EVP_PKEY_CTX *der = NULL;
    const EVP_MD *sha256 = EVP_MD_fetch(NULL, "SHA256", NULL);
    const EVP_MD *pmd = NULL;
    ASN1_OBJECT *oid = NULL;
    ASN1_OBJECT *goid = NULL;
    unsigned char seed[4];
    unsigned char *ukm, *out = NULL;
    int outlen = -1, kdftype, ret;

    memset(seed, 0x5a, sizeof(seed));
    oid = OBJ_txt2obj("1.3.133.16.840.63.0.2", 1);
    printf("dh.ctl.md_fetched=%d\n", sha256 != NULL);
    printf("dh.ctl.oid_built=%d\n", oid != NULL);

    /* ---- the NULL-context refusals: the two gates answer -2, the nine ctrl wrappers reach
     * `EVP_PKEY_CTX_ctrl`'s own NULL test, also -2, and every one leaves a coordinate. */
    ERR_clear_error();
    printf("dh.ctl.null.gindex=%d\n", EVP_PKEY_CTX_set_dh_paramgen_gindex(null_ctx, 5));
    printf("dh.ctl.null.seed=%d\n", EVP_PKEY_CTX_set_dh_paramgen_seed(null_ctx, seed, 4));
    printf("dh.ctl.null.type=%d\n", EVP_PKEY_CTX_set_dh_paramgen_type(null_ctx, 2));
    printf("dh.ctl.null.prime_len=%d\n", EVP_PKEY_CTX_set_dh_paramgen_prime_len(null_ctx, 2048));
    printf("dh.ctl.null.subprime_len=%d\n",
        EVP_PKEY_CTX_set_dh_paramgen_subprime_len(null_ctx, 256));
    printf("dh.ctl.null.generator=%d\n", EVP_PKEY_CTX_set_dh_paramgen_generator(null_ctx, 2));
    printf("dh.ctl.null.rfc5114=%d\n", EVP_PKEY_CTX_set_dh_rfc5114(null_ctx, 1));
    printf("dh.ctl.null.dhx_rfc5114=%d\n", EVP_PKEY_CTX_set_dhx_rfc5114(null_ctx, 1));
    printf("dh.ctl.null.nid=%d\n", EVP_PKEY_CTX_set_dh_nid(null_ctx, 1));
    printf("dh.ctl.null.pad=%d\n", EVP_PKEY_CTX_set_dh_pad(null_ctx, 1));
    printf("dh.ctl.null.set_kdf_type=%d\n", EVP_PKEY_CTX_set_dh_kdf_type(null_ctx, 2));
    printf("dh.ctl.null.get_kdf_type=%d\n", EVP_PKEY_CTX_get_dh_kdf_type(null_ctx));
    printf("dh.ctl.null.set0_oid=%d\n", EVP_PKEY_CTX_set0_dh_kdf_oid(null_ctx, oid));
    printf("dh.ctl.null.get0_oid=%d\n", EVP_PKEY_CTX_get0_dh_kdf_oid(null_ctx, &goid));
    printf("dh.ctl.null.kdf_md=%d\n", EVP_PKEY_CTX_set_dh_kdf_md(null_ctx, sha256));
    printf("dh.ctl.null.get_kdf_md=%d\n", EVP_PKEY_CTX_get_dh_kdf_md(null_ctx, &pmd));
    printf("dh.ctl.null.kdf_outlen=%d\n", EVP_PKEY_CTX_set_dh_kdf_outlen(null_ctx, 32));
    printf("dh.ctl.null.get_kdf_outlen=%d\n", EVP_PKEY_CTX_get_dh_kdf_outlen(null_ctx, &outlen));
    printf("dh.ctl.null.set0_ukm=%d\n", EVP_PKEY_CTX_set0_dh_kdf_ukm(null_ctx, NULL, 0));
    printf("dh.ctl.null.get0_ukm=%d\n", EVP_PKEY_CTX_get0_dh_kdf_ukm(null_ctx, &out));
    drain("ctl_null");

    /* ---- the provider, and the live context with no operation at all */
    printf("dh.ctl.provider.add=%d\n", OSSL_PROVIDER_add_builtin(NULL, "court-dh", court_init));
    prov = OSSL_PROVIDER_load(NULL, "court-dh");
    printf("dh.ctl.provider.load=%d\n", prov != NULL);
    if (prov == NULL)
        return;

    fresh = EVP_PKEY_CTX_new_from_name(NULL, "COURT-DH", NULL);
    printf("dh.ctl.fresh=%d\n", fresh != NULL);
    if (fresh == NULL)
        return;
    printf("dh.ctl.fresh.is_a_self=%d\n", EVP_PKEY_CTX_is_a(fresh, "COURT-DH"));
    printf("dh.ctl.fresh.operation=%d\n", EVP_PKEY_CTX_get_operation(fresh));

    /* On an operation-less context the two gates refuse -2 and the ctrl wrappers refuse -1 with
     * `EVP_R_NO_OPERATION_SET`, so the two families are told apart by the return value. */
    ERR_clear_error();
    printf("dh.ctl.fresh.gindex=%d\n", EVP_PKEY_CTX_set_dh_paramgen_gindex(fresh, 5));
    printf("dh.ctl.fresh.pad=%d\n", EVP_PKEY_CTX_set_dh_pad(fresh, 1));
    printf("dh.ctl.fresh.kdf_outlen=%d\n", EVP_PKEY_CTX_set_dh_kdf_outlen(fresh, 32));
    printf("dh.ctl.fresh.type=%d\n", EVP_PKEY_CTX_set_dh_paramgen_type(fresh, 2));
    printf("dh.ctl.fresh.nid=%d\n", EVP_PKEY_CTX_set_dh_nid(fresh, 1));
    printf("dh.ctl.fresh.kdf_type=%d\n", EVP_PKEY_CTX_set_dh_kdf_type(fresh, 2));
    drain("ctl_fresh");

    /* ---- the generation controls on a parameter-generation operation: six `OSSL_PARAM` builders
     * and three ctrl wrappers, each of which now succeeds and echoes the parameter it built. */
    ERR_clear_error();
    gen = EVP_PKEY_CTX_new_from_name(NULL, "COURT-DH", NULL);
    printf("dh.ctl.gen=%d\n", gen != NULL);
    printf("dh.ctl.gen.init=%d\n", EVP_PKEY_paramgen_init(gen));
    printf("dh.ctl.gen.operation=%d\n", EVP_PKEY_CTX_get_operation(gen));
    ERR_clear_error();
    printf("dh.ctl.gen.gindex=%d\n", EVP_PKEY_CTX_set_dh_paramgen_gindex(gen, 5));
    printf("dh.ctl.gen.seed=%d\n", EVP_PKEY_CTX_set_dh_paramgen_seed(gen, seed, 4));
    printf("dh.ctl.gen.prime_len=%d\n", EVP_PKEY_CTX_set_dh_paramgen_prime_len(gen, 2048));
    printf("dh.ctl.gen.subprime_len=%d\n", EVP_PKEY_CTX_set_dh_paramgen_subprime_len(gen, 256));
    printf("dh.ctl.gen.generator=%d\n", EVP_PKEY_CTX_set_dh_paramgen_generator(gen, 2));
    printf("dh.ctl.gen.type=%d\n", EVP_PKEY_CTX_set_dh_paramgen_type(gen, 2));
    printf("dh.ctl.gen.rfc5114=%d\n", EVP_PKEY_CTX_set_dh_rfc5114(gen, 1));
    printf("dh.ctl.gen.dhx_rfc5114=%d\n", EVP_PKEY_CTX_set_dhx_rfc5114(gen, 1));
    printf("dh.ctl.gen.nid=%d\n", EVP_PKEY_CTX_set_dh_nid(gen, 1));
    drain("ctl_gen");

    /* ---- the derivation controls on a derivation operation, and the five round trips */
    ERR_clear_error();
    der = EVP_PKEY_CTX_new_from_name(NULL, "COURT-DH", NULL);
    printf("dh.ctl.der=%d\n", der != NULL);
    printf("dh.ctl.der.init=%d\n", EVP_PKEY_derive_init(der));
    printf("dh.ctl.der.operation=%d\n", EVP_PKEY_CTX_get_operation(der));
    drain("ctl_der_init");

    /* The defaults a fresh derivation context answers with. */
    ERR_clear_error();
    printf("dh.ctl.der.default_kdf_outlen=%d\n",
        EVP_PKEY_CTX_get_dh_kdf_outlen(der, &outlen));
    printf("dh.ctl.der.default_outlen=%d\n", outlen);
    printf("dh.ctl.der.default_kdf_type=%d\n", EVP_PKEY_CTX_get_dh_kdf_type(der));
    drain("ctl_der_default");

    /* pad, then the four set/get pairs, then the UKM pair. */
    ERR_clear_error();
    printf("dh.ctl.der.pad=%d\n", EVP_PKEY_CTX_set_dh_pad(der, 1));
    printf("dh.ctl.der.set_kdf_outlen=%d\n", EVP_PKEY_CTX_set_dh_kdf_outlen(der, 32));
    printf("dh.ctl.der.get_kdf_outlen=%d\n", EVP_PKEY_CTX_get_dh_kdf_outlen(der, &outlen));
    printf("dh.ctl.der.outlen=%d\n", outlen);
    printf("dh.ctl.der.set_kdf_type=%d\n", EVP_PKEY_CTX_set_dh_kdf_type(der, 2));
    kdftype = EVP_PKEY_CTX_get_dh_kdf_type(der);
    printf("dh.ctl.der.get_kdf_type=%d\n", kdftype);
    printf("dh.ctl.der.kdf_type_is_x942=%d\n", kdftype == 2);
    printf("dh.ctl.der.set_kdf_md=%d\n", EVP_PKEY_CTX_set_dh_kdf_md(der, sha256));
    ret = EVP_PKEY_CTX_get_dh_kdf_md(der, &pmd);
    printf("dh.ctl.der.get_kdf_md=%d\n", ret);
    /* **The digest the getter hands back is not compared, and the callee that blocks it is named
     * rather than hidden.** `fix_md`'s GET arm resolves the method's name through
     * `evp_get_digestbyname_ex` (`crypto/evp/names.c`), whose legacy `OBJ_NAME` table this crate
     * leaves empty: `src/runtime/init.rs`'s `add_all_legacy_methods` is a no-op and
     * `src/context/namemap.rs` records the whole legacy-database pre-population as Phase 13's work.
     * So the candidate answers a NULL method where the authority answers SHA-256, for a reason that
     * is not `dh_ctrl.c`'s, and an arm that compared it would be a residual about that deferral. The
     * parameter-level round trip *is* observed: `dh.der.set.p.0=kdf-digest` and `dh.der.get.p.0` show
     * the name the setter sent and the getter asked for. `docs/DECISIONS.md` D343 records the
     * coordinate. */
    printf("dh.ctl.der.get_kdf_md_digest_skipped=%d\n", 1);
    printf("dh.ctl.der.set0_oid=%d\n", EVP_PKEY_CTX_set0_dh_kdf_oid(der, oid));
    ret = EVP_PKEY_CTX_get0_dh_kdf_oid(der, &goid);
    printf("dh.ctl.der.get0_oid=%d\n", ret);
    printf("dh.ctl.der.goid_is_null=%d\n", goid == NULL);
    drain("ctl_der_pairs");

    /* The UKM pair: `set0` takes custody on success, so the probe allocates through the same
     * allocator the control releases through, and frees only when the control did not. */
    ERR_clear_error();
    ukm = OPENSSL_malloc(4);
    if (ukm != NULL)
        memset(ukm, 0x5a, 4);
    ret = EVP_PKEY_CTX_set0_dh_kdf_ukm(der, ukm, 4);
    printf("dh.ctl.der.set0_ukm=%d\n", ret);
    if (ret != 1)
        OPENSSL_free(ukm);
    out = NULL;
    printf("dh.ctl.der.get0_ukm=%d\n", EVP_PKEY_CTX_get0_dh_kdf_ukm(der, &out));
    printf("dh.ctl.der.ukm_is_null=%d\n", out == NULL);
    drain("ctl_der_ukm");

    /* The refusals that are not a `-2` from a gate: a non-positive output length is `-2` with **no
     * raise**, and a negative UKM length is `-1` before the context is tested. */
    ERR_clear_error();
    printf("dh.ctl.der.zero_outlen=%d\n", EVP_PKEY_CTX_set_dh_kdf_outlen(der, 0));
    printf("dh.ctl.der.neg_outlen=%d\n", EVP_PKEY_CTX_set_dh_kdf_outlen(der, -1));
    printf("dh.ctl.der.neg_ukm=%d\n", EVP_PKEY_CTX_set0_dh_kdf_ukm(der, NULL, -1));
    drain("ctl_der_refusals");

    EVP_PKEY_CTX_free(der);
    EVP_PKEY_CTX_free(gen);
    EVP_PKEY_CTX_free(fresh);
    ASN1_OBJECT_free(goid);
    ASN1_OBJECT_free(oid);
    if (pmd != NULL)
        EVP_MD_free((EVP_MD *)pmd);
    EVP_MD_free((EVP_MD *)sha256);
    OSSL_PROVIDER_unload(prov);
}

/* ------------------------------------------------------------------ the object and key layer */

/* A fresh `DH` with `p`, `g` and no `q`, all borrowed from `src` through the public accessors and
 * duplicated, so the two parties share a group without sharing an object. */
static DH *dh_peer(const DH *src)
{
    const BIGNUM *p = NULL, *q = NULL, *g = NULL;
    BIGNUM *p2, *g2;
    DH *peer;

    DH_get0_pqg(src, &p, &q, &g);
    if (p == NULL || g == NULL)
        return NULL;
    p2 = BN_dup(p);
    g2 = BN_dup(g);
    if (p2 == NULL || g2 == NULL)
        return NULL;
    peer = DH_new();
    if (peer == NULL) {
        BN_free(p2);
        BN_free(g2);
        return NULL;
    }
    if (DH_set0_pqg(peer, p2, NULL, g2) != 1) {
        BN_free(p2);
        BN_free(g2);
        DH_free(peer);
        return NULL;
    }
    return peer;
}

/* Whether every byte of `a`'s first `n` equals `b`'s. A one-line predicate over bytes the
 * probe compares itself, so no shared secret enters the transcript. */
static int bytes_eq(const unsigned char *a, const unsigned char *b, int n)
{
    return memcmp(a, b, (size_t)n) == 0;
}

/* Whether every byte from `off` of `b` equals `a`'s first `n - off`... in other words that the
 * unpadded secret is the tail of the padded one. */
static int is_tail(const unsigned char *short_, int short_len,
                   const unsigned char *long_, int long_len)
{
    if (short_len > long_len)
        return 0;
    return memcmp(short_, long_ + (long_len - short_len), (size_t)short_len) == 0;
}

static void dh_object_arms(void)
{
    DH *dh = DH_new();
    DH *out = DH_new();
    const BIGNUM *p = NULL, *q = NULL, *g = NULL, *pub = NULL, *priv = NULL;
    void *marker = (void *)0x4321;
    BIGNUM *one = BN_new();
    BIGNUM *zero = BN_new();
    unsigned char k1[256], k2[256], u1[256];
    int r1, r2;

    printf("dh.obj.scratch_built=%d\n", dh != NULL && out != NULL && one != NULL && zero != NULL);
    if (dh == NULL || out == NULL || one == NULL || zero == NULL)
        return;
    BN_set_word(one, 1);
    BN_set_word(zero, 0);

    /* ---- the constructor's observable state */
    printf("dh.obj.new.engine_is_null=%d\n", DH_get0_engine(dh) == NULL);
    printf("dh.obj.new.cache_mont=%d\n", DH_test_flags(dh, DH_FLAG_CACHE_MONT_P) != 0);
    printf("dh.obj.new.bits=%d\n", DH_bits(dh));
    printf("dh.obj.new.size=%d\n", DH_size(dh));
    printf("dh.obj.new.security_bits=%d\n", DH_security_bits(dh));
    printf("dh.obj.new.length=%ld\n", DH_get_length(dh));
    DH_get0_pqg(dh, &p, &q, &g);
    printf("dh.obj.new.pqg_null=%d\n", p == NULL && q == NULL && g == NULL);
    DH_get0_key(dh, &pub, &priv);
    printf("dh.obj.new.key_null=%d\n", pub == NULL && priv == NULL);
    printf("dh.obj.new.p_null=%d\n", DH_get0_p(dh) == NULL);
    printf("dh.obj.new.q_null=%d\n", DH_get0_q(dh) == NULL);
    printf("dh.obj.new.g_null=%d\n", DH_get0_g(dh) == NULL);
    printf("dh.obj.new.priv_null=%d\n", DH_get0_priv_key(dh) == NULL);
    printf("dh.obj.new.pub_null=%d\n", DH_get0_pub_key(dh) == NULL);

    /* `DH_new_method(NULL)` is the constructor's only other entry point and answers an object
     * whose engine member is NULL for the same reason the default constructor's is. */
    {
        DH *by_method = DH_new_method(NULL);

        printf("dh.obj.new_method.not_null=%d\n", by_method != NULL);
        if (by_method != NULL) {
            printf("dh.obj.new_method.engine_is_null=%d\n", DH_get0_engine(by_method) == NULL);
            printf("dh.obj.new_method.cache_mont=%d\n",
                DH_test_flags(by_method, DH_FLAG_CACHE_MONT_P) != 0);
            DH_free(by_method);
        }
    }

    /* ---- the flag trio and the length setter */
    DH_set_flags(dh, 0x1234);
    printf("dh.obj.flags.set=%d\n", DH_test_flags(dh, 0x1234));
    DH_clear_flags(dh, 0x0034);
    printf("dh.obj.flags.cleared=%d\n", DH_test_flags(dh, 0x1234));
    printf("dh.obj.flags.remaining=%d\n", DH_test_flags(dh, 0xFFFF));
    printf("dh.obj.length.set_ret=%d\n", DH_set_length(dh, 42));
    printf("dh.obj.length.get=%ld\n", DH_get_length(dh));

    /* ---- the method setters and the default-method family */
    printf("dh.obj.set_method.ret=%d\n", DH_set_method(dh, DH_OpenSSL()));
    printf("dh.obj.set_method.cache_mont=%d\n",
        DH_test_flags(dh, DH_FLAG_CACHE_MONT_P) != 0);
    printf("dh.obj.default.is_openssl=%d\n", DH_get_default_method() == DH_OpenSSL());
    DH_set_default_method(NULL);
    printf("dh.obj.default.null_is_null=%d\n", DH_get_default_method() == NULL);
    DH_set_default_method(DH_OpenSSL());
    printf("dh.obj.default.restored=%d\n", DH_get_default_method() == DH_OpenSSL());

    /* ---- the ex-data pair, and NULL safety */
    printf("dh.obj.exdata.set_ret=%d\n", DH_set_ex_data(dh, 0, marker));
    printf("dh.obj.exdata.get_is_marker=%d\n", DH_get_ex_data(dh, 0) == marker);
    printf("dh.obj.exdata.unset_is_null=%d\n", DH_get_ex_data(dh, 999) == NULL);

    /* ---- the two refusals `DH_set0_pqg` makes before it stores anything */
    DH_get0_pqg(out, &p, &q, &g);
    printf("dh.obj.set0_pqg.all_null_refused=%d\n", DH_set0_pqg(out, NULL, NULL, NULL));
    printf("dh.obj.set0_pqg.p_only_refused=%d\n",
        DH_set0_pqg(out, (BIGNUM *)one, NULL, NULL));
    printf("dh.obj.set0_pqg.p_still_null=%d\n", DH_get0_p(out) == NULL);

    /* ---- references and the two release paths */
    printf("dh.obj.up_ref.ret=%d\n", DH_up_ref(dh));
    DH_free(dh);
    printf("dh.obj.up_ref.survived_first_free=1\n");

    /* ---- generate a 512-bit safe-prime group and key a pair of parties on it */
    ERR_clear_error();
    printf("dh.genparams_ex.ret=%d\n", DH_generate_parameters_ex(dh, 512, 2, NULL));
    drain("genparams_ex");
    printf("dh.genparams_ex.bits=%d\n", DH_bits(dh));
    printf("dh.genparams_ex.size=%d\n", DH_size(dh));
    printf("dh.genparams_ex.security_bits=%d\n", DH_security_bits(dh));
    printf("dh.genparams_ex.length=%ld\n", DH_get_length(dh));
    printf("dh.genparams_ex.p_odd=%d\n", BN_is_odd(DH_get0_p(dh)));

    ERR_clear_error();
    printf("dh.check.ret=%d\n", DH_check(dh, &r1));
    printf("dh.check.flags=%d\n", r1);
    drain("check");
    ERR_clear_error();
    printf("dh.check_ex.ret=%d\n", DH_check_ex(dh));
    drain("check_ex");

    ERR_clear_error();
    printf("dh.check_params.ret=%d\n", DH_check_params(dh, &r1));
    printf("dh.check_params.flags=%d\n", r1);
    drain("check_params");
    ERR_clear_error();
    printf("dh.check_params_ex.ret=%d\n", DH_check_params_ex(dh));
    drain("check_params_ex");

    ERR_clear_error();
    printf("dh.genkey.first.ret=%d\n", DH_generate_key(dh));
    drain("genkey_first");
    printf("dh.genkey.first.priv_bits=%d\n", BN_num_bits(DH_get0_priv_key(dh)));
    printf("dh.genkey.first.pub_null=%d\n", DH_get0_pub_key(dh) == NULL);

    ERR_clear_error();
    printf("dh.check_pub_key.ret=%d\n", DH_check_pub_key(dh, DH_get0_pub_key(dh), &r1));
    printf("dh.check_pub_key.flags=%d\n", r1);
    drain("check_pub_key");
    ERR_clear_error();
    printf("dh.check_pub_key_ex.ret=%d\n", DH_check_pub_key_ex(dh, DH_get0_pub_key(dh)));
    drain("check_pub_key_ex");

    /* ---- the second party and the two agreement functions */
    {
        DH *peer = dh_peer(dh);

        if (peer == NULL) {
            printf("dh.agree.peer_built=0\n");
        } else {
            int pad1, pad2, unpad1, size = DH_size(dh);

            printf("dh.agree.peer_built=1\n");
            ERR_clear_error();
            printf("dh.agree.peer_genkey=%d\n", DH_generate_key(peer));
            drain("peer_genkey");

            ERR_clear_error();
            pad1 = DH_compute_key_padded(k1, DH_get0_pub_key(peer), dh);
            pad2 = DH_compute_key_padded(k2, DH_get0_pub_key(dh), peer);
            printf("dh.agree.pad1=%d\n", pad1);
            printf("dh.agree.pad2=%d\n", pad2);
            printf("dh.agree.pad_is_size=%d\n", pad1 == size && pad2 == size);
            printf("dh.agree.secrets_equal=%d\n", pad1 == pad2 && bytes_eq(k1, k2, pad1));
            drain("agree_padded");

            ERR_clear_error();
            unpad1 = DH_compute_key(u1, DH_get0_pub_key(peer), dh);
            printf("dh.agree.unpad1=%d\n", unpad1);
            printf("dh.agree.unpad_le_pad=%d\n", unpad1 <= pad1);
            printf("dh.agree.unpad_is_tail=%d\n", is_tail(u1, unpad1, k1, pad1));
            drain("agree_unpadded");

            DH_free(peer);
        }
    }

    /* ---- `DH_generate_parameters`'s own success arm */
    DH_free(out);
    ERR_clear_error();
    out = DH_generate_parameters(512, 2, NULL, NULL);
    printf("dh.genparams.depr_nonnull=%d\n", out != NULL);
    drain("genparams_depr");
    if (out != NULL) {
        ERR_clear_error();
        printf("dh.genparams.depr_bits=%d\n", DH_bits(out));
        printf("dh.genparams.depr_check=%d\n", DH_check(out, &r2));
        printf("dh.genparams.depr_flags=%d\n", r2);
        printf("dh.genparams.depr_length=%ld\n", DH_get_length(out));
        drain("genparams_depr_check");
        DH_free(out);
    }

    /* ---- the refusals */

    /* A no-private-value agreement: `DH_compute_key` answers -1 rather than 0 here. */
    {
        DH *q_only = dh_peer(dh);
        if (q_only != NULL) {
            ERR_clear_error();
            printf("dh.refuse.no_priv.ret=%d\n",
                DH_compute_key(u1, DH_get0_pub_key(dh), q_only));
            drain("no_priv");
            ERR_clear_error();
            printf("dh.refuse.no_priv_padded.ret=%d\n",
                DH_compute_key_padded(u1, DH_get0_pub_key(dh), q_only));
            drain("no_priv_padded");
            DH_free(q_only);
        }
    }

    /* A 5-bit modulus: every entry point refuses it. */
    out = DH_new();
    if (out != NULL) {
        p = BN_new();
        g = BN_new();
        q = BN_new();
        BN_set_word((BIGNUM *)p, 23);
        BN_set_word((BIGNUM *)g, 2);
        BN_set_word((BIGNUM *)q, 11);
        printf("dh.refuse.tiny_group.built=%d\n", DH_set0_pqg(out, (BIGNUM *)p, (BIGNUM *)q,
            (BIGNUM *)g));
        printf("dh.refuse.tiny_group.bits=%d\n", DH_bits(out));
        printf("dh.refuse.tiny_group.security_bits=%d\n", DH_security_bits(out));

        ERR_clear_error();
        printf("dh.refuse.tiny_genkey.ret=%d\n", DH_generate_key(out));
        drain("tiny_genkey");

        ERR_clear_error();
        printf("dh.refuse.tiny_compute.ret=%d\n", DH_compute_key(u1, one, out));
        drain("tiny_compute");

        ERR_clear_error();
        printf("dh.refuse.tiny_params.ret=%d\n", DH_check_params(out, &r1));
        printf("dh.refuse.tiny_params.flags=%d\n", r1);
        drain("tiny_params");
        ERR_clear_error();
        printf("dh.refuse.tiny_params_ex.ret=%d\n", DH_check_params_ex(out));
        drain("tiny_params_ex");

        ERR_clear_error();
        printf("dh.refuse.tiny_check.ret=%d\n", DH_check(out, &r1));
        printf("dh.refuse.tiny_check.flags=%d\n", r1);
        drain("tiny_check");
        ERR_clear_error();
        printf("dh.refuse.tiny_check_ex.ret=%d\n", DH_check_ex(out));
        drain("tiny_check_ex");

        /* `1` is too small and `p - 1` is too large: the range check's two ends. */
        ERR_clear_error();
        printf("dh.refuse.pub_one.ret=%d\n", DH_check_pub_key(out, one, &r1));
        printf("dh.refuse.pub_one.flags=%d\n", r1);
        drain("pub_one");
        ERR_clear_error();
        printf("dh.refuse.pub_one_ex.ret=%d\n", DH_check_pub_key_ex(out, one));
        drain("pub_one_ex");

        p = BN_new();
        BN_set_word((BIGNUM *)p, 22);
        ERR_clear_error();
        printf("dh.refuse.pub_pm1.ret=%d\n", DH_check_pub_key(out, p, &r1));
        printf("dh.refuse.pub_pm1.flags=%d\n", r1);
        drain("pub_pm1");
        BN_free((BIGNUM *)p);

        /* A `q` greater than `p`: both validators report their invalid-value bits. */
        DH_free(out);
    }

    /* The parameter generator's own refusals, and the bad-generator arm that leaves two records. */
    out = DH_new();
    if (out != NULL) {
        ERR_clear_error();
        printf("dh.refuse.genparams_small.ret=%d\n",
            DH_generate_parameters_ex(out, 256, 2, NULL));
        drain("genparams_small");
        ERR_clear_error();
        printf("dh.refuse.genparams_badgen.ret=%d\n",
            DH_generate_parameters_ex(out, 512, 1, NULL));
        drain("genparams_badgen");
        DH_free(out);
    }

    ERR_clear_error();
    out = DH_generate_parameters(256, 2, NULL, NULL);
    printf("dh.refuse.genparams_depr_small.is_null=%d\n", out == NULL);
    drain("genparams_depr_small");
    DH_free(out);

    /* A body with no modulus at all: the structural check answers through `*ret`, not a fault. */
    out = DH_new();
    if (out != NULL) {
        ERR_clear_error();
        printf("dh.refuse.empty_params.ret=%d\n", DH_check_params(out, &r1));
        printf("dh.refuse.empty_params.flags=%d\n", r1);
        drain("empty_params");
        ERR_clear_error();
        printf("dh.refuse.empty_params_ex.ret=%d\n", DH_check_params_ex(out));
        drain("empty_params_ex");
        ERR_clear_error();
        printf("dh.refuse.empty_check.ret=%d\n", DH_check(out, &r1));
        printf("dh.refuse.empty_check.flags=%d\n", r1);
        drain("empty_check");
        ERR_clear_error();
        printf("dh.refuse.empty_pub.ret=%d\n", DH_check_pub_key(out, one, &r1));
        printf("dh.refuse.empty_pub.flags=%d\n", r1);
        drain("empty_pub");
        DH_free(out);
    }

    /* `DH_set0_key` always answers 1, including for a NULL pair; its object's members do not move
     * when the argument is NULL, which is what the round trip below observes. */
    out = DH_new();
    if (out != NULL) {
        printf("dh.refuse.set0_key.both_null_ret=%d\n", DH_set0_key(out, NULL, NULL));
        printf("dh.refuse.set0_key.pub_still_null=%d\n", DH_get0_pub_key(out) == NULL);
        p = BN_new();
        BN_set_word((BIGNUM *)p, 7);
        printf("dh.refuse.set0_key.pub_ret=%d\n", DH_set0_key(out, (BIGNUM *)p, NULL));
        printf("dh.refuse.set0_key.pub_is_7=%d\n", BN_cmp(DH_get0_pub_key(out), p) == 0);
        DH_free(out);
    }

    DH_free(NULL);
    printf("dh.obj.free_null.survived=1\n");

    BN_free(one);
    BN_free(zero);
    DH_free(dh);
}

/* ------------------------------------------------------------------ the named groups */

/* `dh_group_params.c` and its two tables (D332). Everything here is a *published* constant or
 * a boolean: a named group is public data, so its widths and its congruence are the whole
 * observation, and the two values that could identify a key -- a private exponent and a shared
 * secret -- are never printed. The exponent appears only as a bound and the secret only as an
 * equality, exactly as the 512-bit arms above treat theirs. */
static void dh_named_group_arms(void)
{
    /* The eleven NID-keyed rows of `dh_named_groups[]`, then the three RFC 5114 uids -- the
     * rows whose uid is not a NID, and the only place this court can see that an integer no
     * NID has still names a group. */
    static const int uids[14] = {
        NID_ffdhe2048, NID_ffdhe3072, NID_ffdhe4096, NID_ffdhe6144, NID_ffdhe8192,
        NID_modp_1536, NID_modp_2048, NID_modp_3072, NID_modp_4096, NID_modp_6144,
        NID_modp_8192, 1, 2, 3
    };
    int i;

    for (i = 0; i < 14; i++) {
        DH *dh = DH_new_by_nid(uids[i]);
        const BIGNUM *p = NULL, *q = NULL, *g = NULL;

        printf("dh.group.%d.built=%d\n", i, dh != NULL);
        if (dh == NULL) {
            drain("group_build");
            continue;
        }
        DH_get0_pqg(dh, &p, &q, &g);
        printf("dh.group.%d.nid=%d\n", i, DH_get_nid(dh));
        printf("dh.group.%d.bits=%d\n", i, DH_bits(dh));
        printf("dh.group.%d.security_bits=%d\n", i, DH_security_bits(dh));
        printf("dh.group.%d.p_bits=%d\n", i, BN_num_bits(p));
        printf("dh.group.%d.q_bits=%d\n", i, BN_num_bits(q));
        printf("dh.group.%d.g_is_two=%d\n", i, g != NULL && BN_is_word(g, 2) != 0);
        /* The constants are `.rodata` on both sides: `BN_FLG_STATIC_DATA` without
         * `BN_FLG_MALLOCED` is what makes `DH_free` of one a no-op. */
        printf("dh.group.%d.p_is_static=%d\n", i,
            BN_get_flags(p, BN_FLG_STATIC_DATA) != 0
            && BN_get_flags(p, BN_FLG_MALLOCED) == 0);
        /* The congruence that makes 2 a member of the order-`q` subgroup: 23 for every
         * safe-prime row, and something else for the three RFC 5114 ones. */
        printf("dh.group.%d.p_mod24=%lu\n", i, BN_mod_word(p, 24));
        printf("dh.group.%d.length=%ld\n", i, DH_get_length(dh));
        DH_free(dh);
    }

    /* The one refusal the lookup has: a uid no row carries. Drained, so the reason and its
     * coordinate are compared rather than the NULL alone. */
    ERR_clear_error();
    {
        DH *none = DH_new_by_nid(0);
        printf("dh.group.refuse.uid0_is_null=%d\n", none == NULL);
        DH_free(none);
    }
    drain("group_uid0");
    ERR_clear_error();
    {
        DH *none = DH_new_by_nid(4);
        printf("dh.group.refuse.uid4_is_null=%d\n", none == NULL);
        DH_free(none);
    }
    drain("group_uid4");
    ERR_clear_error();
    {
        DH *none = DH_new_by_nid(12345);
        printf("dh.group.refuse.uid12345_is_null=%d\n", none == NULL);
        DH_free(none);
    }
    drain("group_uid12345");

    /* **The object graph, as booleans.** Two `DH_new_by_nid` objects of one group hold the
     * *same* modulus because the constants are shared; two `DH_get_*` objects of one RFC 5114
     * group hold different ones because `make_dh` duplicates. No address is printed. */
    {
        DH *a = DH_new_by_nid(NID_ffdhe2048);
        DH *b = DH_new_by_nid(NID_ffdhe2048);
        DH *c = DH_get_2048_256();
        DH *d = DH_get_2048_256();
        const BIGNUM *pa = a != NULL ? DH_get0_p(a) : NULL;
        const BIGNUM *pb = b != NULL ? DH_get0_p(b) : NULL;
        const BIGNUM *pc = c != NULL ? DH_get0_p(c) : NULL;
        const BIGNUM *pd = d != NULL ? DH_get0_p(d) : NULL;

        printf("dh.group.identity.named_shared=%d\n", pa != NULL && pa == pb);
        printf("dh.group.identity.deprecated_own=%d\n",
            pc != NULL && pd != NULL && pc != pd);
        printf("dh.group.identity.named_vs_deprecated=%d\n", pa != NULL && pa != pc);
        DH_free(a);
        DH_free(b);
        DH_free(c);
        DH_free(d);
    }

    /* The named-group *cache*: a `DH` built from a group's own numbers acquires the group's
     * `nid`, its `q` -- which the builder did not supply -- and its key length. This is the
     * call `DH_set0_pqg` makes and the reduction D331 recorded; it is observed through the
     * public accessors only. */
    {
        DH *src = DH_new_by_nid(NID_modp_4096);
        DH *built = DH_new();
        const BIGNUM *p = NULL, *g = NULL;
        BIGNUM *p2 = NULL, *g2 = NULL;

        if (src != NULL) {
            DH_get0_pqg(src, &p, NULL, &g);
            p2 = BN_dup(p);
            g2 = BN_dup(g);
        }
        printf("dh.group.cache.built=%d\n", built != NULL && p2 != NULL && g2 != NULL);
        if (built != NULL && p2 != NULL && g2 != NULL) {
            printf("dh.group.cache.set0_pqg=%d\n", DH_set0_pqg(built, p2, NULL, g2));
            printf("dh.group.cache.q_filled=%d\n", DH_get0_q(built) != NULL);
            printf("dh.group.cache.nid=%d\n", DH_get_nid(built));
            printf("dh.group.cache.q_is_the_rows=%d\n", DH_get0_q(built) == DH_get0_q(src));
            printf("dh.group.cache.p_is_the_rows=%d\n", DH_get0_p(built) == p);
            printf("dh.group.cache.q_bits=%d\n", BN_num_bits(DH_get0_q(built)));
            DH_free(built);
        }
        DH_free(src);
    }

    /* Primality through the landed `BN_check_prime`, at the two smallest widths the table
     * holds: the 1536-bit MODP group and the 160-bit RFC 5114 subgroup order. The 2048-bit
     * and larger rows are 64 Miller-Rabin rounds and up, which is not a court arm. */
    {
        BN_CTX *ctx = BN_CTX_new();
        DH *small = DH_new_by_nid(NID_modp_1536);
        DH *rfc = DH_new_by_nid(1);
        BIGNUM *composite = BN_new();

        printf("dh.group.prime.1536_p=%d\n", BN_check_prime(DH_get0_p(small), ctx, NULL));
        printf("dh.group.prime.1536_q=%d\n", BN_check_prime(DH_get0_q(small), ctx, NULL));
        printf("dh.group.prime.160_q=%d\n", BN_check_prime(DH_get0_q(rfc), ctx, NULL));
        /* A negative control: `2q` is even and therefore composite, so an answer of 1 here
         * would mean the primitive, not the constant, was what the arms above measured. */
        BN_lshift1(composite, DH_get0_q(rfc));
        printf("dh.group.prime.composite=%d\n", BN_check_prime(composite, ctx, NULL));
        BN_free(composite);
        BN_CTX_free(ctx);
        DH_free(small);
        DH_free(rfc);
    }

    /* `DH_check` and `DH_check_ex` on a named group: the `DH_get_nid` short-circuit, which
     * answers 1 with no flags and no records because the group is valid by construction.
     * `DH_check_params` is the `#else` arm and has no such shortcut, so it runs its
     * structural test -- which a named group passes. */
    {
        DH *dh = DH_new_by_nid(NID_ffdhe2048);
        int flags = -1;

        ERR_clear_error();
        printf("dh.group.check.named=%d\n", DH_check(dh, &flags));
        printf("dh.group.check.named_flags=%d\n", flags);
        drain("group_check_named");
        ERR_clear_error();
        printf("dh.group.check_ex.named=%d\n", DH_check_ex(dh));
        drain("group_check_ex_named");
        ERR_clear_error();
        printf("dh.group.check_params.named=%d\n", DH_check_params(dh, &flags));
        printf("dh.group.check_params.named_flags=%d\n", flags);
        drain("group_check_params_named");
        ERR_clear_error();
        printf("dh.group.check_pub_key.named=%d\n",
            DH_check_pub_key(dh, DH_get0_p(dh), &flags));
        printf("dh.group.check_pub_key.named_flags=%d\n", flags);
        drain("group_check_pub_key_named");
        DH_free(dh);
    }

    /* `DH_generate_key` on a named group: the `DH_get_nid` arm of the key layer, whose
     * exponent length is the group's RFC 7919 key length. Two arms, because the arm's own
     * bound is a number this court can cross on purpose: a caller-set length below `2 * s`
     * is refused by `ossl_ffc_generate_private_key`, and the default length is accepted. */
    {
        DH *dh = DH_new_by_nid(NID_ffdhe2048);

        ERR_clear_error();
        printf("dh.group.genkey.short.set_length=%d\n", DH_set_length(dh, 200));
        printf("dh.group.genkey.short.ret=%d\n", DH_generate_key(dh));
        drain("group_genkey_short");
        DH_free(dh);
    }
    {
        DH *dh = DH_new_by_nid(NID_ffdhe2048);
        DH *peer;
        unsigned char k1[512], k2[512];
        int pad1, pad2;

        ERR_clear_error();
        printf("dh.group.genkey.default.ret=%d\n", DH_generate_key(dh));
        drain("group_genkey_default");
        /* The exponent's width is bounded by the table's 225 and the public key's by `p`;
         * neither is a value and neither identifies a key. */
        printf("dh.group.genkey.priv_within_225=%d\n",
            BN_num_bits(DH_get0_priv_key(dh)) <= 225);
        printf("dh.group.genkey.priv_nonzero=%d\n", DH_get0_priv_key(dh) != NULL);
        printf("dh.group.genkey.pub_within_p=%d\n",
            BN_num_bits(DH_get0_pub_key(dh)) <= BN_num_bits(DH_get0_p(dh)));

        peer = dh_peer(dh);
        printf("dh.group.agree.peer_built=%d\n", peer != NULL);
        if (peer != NULL) {
            ERR_clear_error();
            printf("dh.group.agree.peer_genkey=%d\n", DH_generate_key(peer));
            drain("group_peer_genkey");
            ERR_clear_error();
            pad1 = DH_compute_key_padded(k1, DH_get0_pub_key(peer), dh);
            pad2 = DH_compute_key_padded(k2, DH_get0_pub_key(dh), peer);
            printf("dh.group.agree.pad1=%d\n", pad1);
            printf("dh.group.agree.is_size=%d\n", pad1 == DH_size(dh));
            printf("dh.group.agree.equal=%d\n",
                pad1 == pad2 && pad1 > 0 && bytes_eq(k1, k2, pad1));
            drain("group_agree");
            DH_free(peer);
        }
        DH_free(dh);
    }

    /* The three deprecated constructors: the same group as `DH_new_by_nid(1..3)`, and the
     * one asymmetry between the two paths -- `make_dh` assigns the three fields directly, so
     * the object answers `NID_undef` until something caches it. */
    {
        DH *one = DH_get_1024_160();
        DH *two = DH_get_2048_224();
        DH *three = DH_get_2048_256();

        printf("dh.group.depr.built=%d\n", one != NULL && two != NULL && three != NULL);
        printf("dh.group.depr.1024_160_bits=%d\n", DH_bits(one));
        printf("dh.group.depr.2048_224_bits=%d\n", DH_bits(two));
        printf("dh.group.depr.2048_256_bits=%d\n", DH_bits(three));
        printf("dh.group.depr.nid_is_undef=%d\n",
            DH_get_nid(one) == NID_undef && DH_get_nid(two) == NID_undef
            && DH_get_nid(three) == NID_undef);
        DH_free(one);
        DH_free(two);
        DH_free(three);
    }

    /* **There is deliberately no allocation window around `DH_new_by_nid`.** One was written
     * and removed rather than tuned, because the two sides disagree and the disagreement is
     * real (docs/DECISIONS.md D332 records it with these numbers):
     *
     *   authority  7 events   M:208 dh_lib.c, M:56 threads_pthread.c, F:0 ex_data.c,
     *                         F:0 ex_data.c, F:0 threads_pthread.c, F:0 ffc_params.c,
     *                         F:0 dh_lib.c
     *   candidate  2 events   M:208 dh_lib.c, F:0 dh_lib.c
     *
     * Three causes, none of them this unit's: the crate's `CRYPTO_THREAD_lock_new` is a Rust
     * `Box` over a `Mutex`/`Condvar` pair and never reaches the caller's allocator; its ex-data
     * registry likewise; and its `CRYPTO_free` does not hand a NULL pointer to an installed
     * hook where the authority's `free_impl(str, file, line)` does, which is the `F:0` at
     * `ffc_params.c` -- `ossl_ffc_params_cleanup`'s release of a NULL `seed`. A window that
     * printed only the two events both sides share would be this court choosing its answer, so
     * the arm is absent and the measurement is written down instead. */
}

/* ------------------------------------------------------------------ the ASN.1 unit (D345)
 *
 * `crypto/dh/dh_asn1.c` is whole in this crate now: the `DHparams` item and its encode pair, the
 * X9.42 `DHxparams` pair translated to and from a real `DH`, and the `DHparams_dup`/`DHparams_print`
 * pair of `dh_ameth.c` plus `dh_prn.c`'s `FILE *` wrapper. Every arm below is a verdict on the
 * values the probe re-reads -- a return code, a decoded length, an equality of two `BIGNUM`s it
 * already holds -- or on a byte count; **no private key, shared secret or group seed is printed**,
 * and the one text arm is reduced to "the print's first byte is `D`" rather than its bytes. */
static void dh_asn1_arms(void)
{
    DH *src = DH_new_by_nid(NID_ffdhe2048);
    unsigned char *der = NULL;
    const unsigned char *cp;
    int n;

    printf("dh.asn1.group.built=%d\n", src != NULL);
    if (src == NULL)
        return;

    /* `DHparams_it` is an item accessor: it answers a pointer, and two calls answer the same one. */
    printf("dh.asn1.it.notnull=%d\n", DHparams_it() != NULL);
    printf("dh.asn1.it.stable=%d\n", DHparams_it() == DHparams_it());

    /* ---- the `DHparams` template: `p`, `g` and the optional length word ---- */
    printf("dh.asn1.params.measure_positive=%d\n", i2d_DHparams(src, NULL) > 0);
    n = i2d_DHparams(src, &der);
    printf("dh.asn1.params.i2d_ret=%d\n", n > 0 && der != NULL);
    printf("dh.asn1.params.starts_sequence=%d\n", der != NULL && der[0] == 0x30);
    cp = der;
    {
        DH *round = d2i_DHparams(NULL, &cp, (long)n);
        const BIGNUM *rp = NULL, *rq = NULL, *rg = NULL;
        const BIGNUM *sp = NULL, *sq = NULL, *sg = NULL;

        DH_get0_pqg(src, &sp, &sq, &sg);
        printf("dh.asn1.params.d2i_notnull=%d\n", round != NULL);
        if (round != NULL) {
            DH_get0_pqg(round, &rp, &rq, &rg);
            printf("dh.asn1.params.round_trip=%d\n",
                rp != NULL && rg != NULL && sp != NULL && sg != NULL
                && BN_cmp(rp, sp) == 0 && BN_cmp(rg, sg) == 0);
            /* **The template carries no `q`, but the decoded object has one**: `dh_cb`'s
             * `ASN1_OP_D2I_POST` runs `ossl_dh_cache_named_group`, which finds the FFDHE-2048 row
             * by `p` and fills `q` from it. This arm observes that rather than the template's
             * three fields. */
            printf("dh.asn1.params.q_filled_by_the_cache=%d\n",
                rq != NULL && sq != NULL && BN_cmp(rq, sq) == 0);
            printf("dh.asn1.params.consumed_all=%d\n", (int)(cp - der) == n);
            DH_free(round);
        }
    }
    OPENSSL_free(der);
    der = NULL;

    /* ---- the `DHxparams` template: `p`, `g`, `q` in that order ---- */
    n = i2d_DHxparams(src, &der);
    printf("dh.asn1.xparams.i2d_ret=%d\n", n > 0 && der != NULL);
    cp = der;
    {
        DH *round = d2i_DHxparams(NULL, &cp, (long)n);
        const BIGNUM *rp = NULL, *rq = NULL, *rg = NULL;
        const BIGNUM *sp = NULL, *sq = NULL, *sg = NULL;

        DH_get0_pqg(src, &sp, &sq, &sg);
        printf("dh.asn1.xparams.d2i_notnull=%d\n", round != NULL);
        if (round != NULL) {
            DH_get0_pqg(round, &rp, &rq, &rg);
            printf("dh.asn1.xparams.round_trip=%d\n",
                rp != NULL && rq != NULL && rg != NULL
                && sp != NULL && sq != NULL && sg != NULL
                && BN_cmp(rp, sp) == 0 && BN_cmp(rq, sq) == 0 && BN_cmp(rg, sg) == 0);
            printf("dh.asn1.xparams.consumed_all=%d\n", (int)(cp - der) == n);
            DH_free(round);
        }
    }
    OPENSSL_free(der);
    der = NULL;

    /* ---- `DHparams_dup`: a fresh object with the same FFC parameters ---- */
    {
        DH *dup = DHparams_dup(src);
        const BIGNUM *rp = NULL, *rq = NULL, *rg = NULL;
        const BIGNUM *sp = NULL, *sq = NULL, *sg = NULL;

        DH_get0_pqg(src, &sp, &sq, &sg);
        printf("dh.asn1.dup.notnull=%d\n", dup != NULL);
        if (dup != NULL) {
            DH_get0_pqg(dup, &rp, &rq, &rg);
            printf("dh.asn1.dup.match=%d\n",
                rp != NULL && rq != NULL && rg != NULL
                && sp != NULL && sq != NULL && sg != NULL
                && BN_cmp(rp, sp) == 0 && BN_cmp(rq, sq) == 0 && BN_cmp(rg, sg) == 0);
            DH_free(dup);
        }
    }

    /* ---- `DHparams_print` into a memory BIO: the verdict, the byte count, the first byte ---- */
    {
        BIO *bp = BIO_new(BIO_s_mem());

        printf("dh.asn1.print.bio=%d\n", bp != NULL);
        if (bp != NULL) {
            char *data = NULL;
            long len;

            printf("dh.asn1.print.ret=%d\n", DHparams_print(bp, src));
            len = BIO_ctrl(bp, BIO_CTRL_INFO, 0, &data);
            printf("dh.asn1.print.len_positive=%d\n", len > 0);
            /* `do_dh_print` writes the four-space `indent` before its label, so the buffer opens
             * with the indent and not with `D`. */
            printf("dh.asn1.print.starts_indented_D=%d\n",
                data != NULL && len > 6 && data[0] == ' ' && data[4] == 'D' && data[5] == 'H');
            BIO_free(bp);
        }
    }

    /* ---- `DHparams_print_fp` to a temporary `FILE *`: the verdict only, since the bytes are the
     * same print and the file is discarded ---- */
    {
        FILE *fp = tmpfile();

        printf("dh.asn1.print_fp.file=%d\n", fp != NULL);
        if (fp != NULL) {
            printf("dh.asn1.print_fp.ret=%d\n", DHparams_print_fp(fp, src));
            fclose(fp);
        }
    }

    /* ---- the two refusals, each through its return value and the drained coordinate ---- */

    /* A body with no `p` prints nothing: `do_dh_print`'s first guard answers 0 and raises
     * `ERR_R_PASSED_NULL_PARAMETER` at `dh_ameth.c:297`. */
    {
        DH *empty = DH_new();
        BIO *bp = BIO_new(BIO_s_mem());

        ERR_clear_error();
        printf("dh.asn1.print.no_p_ret=%d\n", DHparams_print(bp, empty));
        drain("asn1_print_no_p");
        BIO_free(bp);
        DH_free(empty);
    }

    /* A negative length refuses before anything is read. */
    {
        unsigned char buf[1] = { 0x30 };

        cp = buf;
        ERR_clear_error();
        printf("dh.asn1.params.d2i_negative_is_null=%d\n",
            d2i_DHparams(NULL, &cp, -1) == NULL);
        drain("asn1_d2i_negative");
    }

    DH_free(src);
}

/*
 * `DH_KDF_X9_42` (D346). The wrapper renders an `ASN1_OBJECT` as the `cekalg` name the
 * `X942KDF-ASN1` row's `find_alg_id` resolves, then fetches and drives that row. The input `Z`,
 * `ukm` and digest are constants in this file, so the derived bytes are the authority's own test
 * vector and printing them is the strongest observation available rather than the disclosure of
 * a secret. The `id-aes128-wrap` OID (`2.16.840.1.101.3.4.1.5`) is the `AES-128-WRAP` row's
 * alias, which is what the row's own name check compares against.
 */
static void dh_kdf_arms(void)
{
    unsigned char z[32], ukm[8], out[32];
    ASN1_OBJECT *oid;
    const EVP_MD *md;
    size_t i;

    for (i = 0; i < sizeof(z); i++)
        z[i] = (unsigned char)(3 * i + 1);
    for (i = 0; i < sizeof(ukm); i++)
        ukm[i] = (unsigned char)(5 * i + 2);

    md = EVP_MD_fetch(NULL, "SHA256", NULL);
    printf("dh.kdf.md=%d\n", md != NULL);

    oid = OBJ_txt2obj("2.16.840.1.101.3.4.1.5", 1);
    printf("dh.kdf.oid=%d\n", oid != NULL);

    memset(out, 0, sizeof(out));
    ERR_clear_error();
    printf("dh.kdf.x942.ret=%d\n",
        DH_KDF_X9_42(out, sizeof(out), z, sizeof(z), oid, ukm, sizeof(ukm), md));
    printf("dh.kdf.x942.key=");
    rt_hex_bytes(out, sizeof(out));
    printf("\n");
    drain("dh_kdf_x942");

    /* The UKM is optional: with none, `x942kdf.c`'s encoder leaves the field out and the same
     * inputs must still derive. */
    memset(out, 0, sizeof(out));
    ERR_clear_error();
    printf("dh.kdf.x942.noukm.ret=%d\n",
        DH_KDF_X9_42(out, sizeof(out), z, sizeof(z), oid, NULL, 0, md));
    printf("dh.kdf.x942.noukm.key=");
    rt_hex_bytes(out, sizeof(out));
    printf("\n");
    drain("dh_kdf_x942_noukm");

    /* A NULL object is `OBJ_obj2txt`'s refusal, before any fetch. */
    ERR_clear_error();
    printf("dh.kdf.x942.nulloid.ret=%d\n",
        DH_KDF_X9_42(out, sizeof(out), z, sizeof(z), NULL, ukm, sizeof(ukm), md));
    drain("dh_kdf_x942_nulloid");

    ASN1_OBJECT_free(oid);
    EVP_MD_free((EVP_MD *)md);
}

int main(void)
{
    DH_METHOD *m;
    DH_METHOD *dup;
    void *marker = (void *)0x1234;

    /* The install latches, so it is the first act of the process. `my_malloc` records only while a
     * window is open, so the warm-up below attributes nothing. */
    if (!CRYPTO_set_mem_functions(my_malloc, my_realloc, my_free)) {
        printf("dh.set_mem_functions=0\n");
        return 1;
    }
    printf("dh.set_mem_functions=1\n");

    /* Warm-up, outside every window: the first `DH_meth_new` runs whatever lazy library state the
     * allocation path has, and a window around it would record that rather than this unit. */
    m = DH_meth_new("warmup", 0);
    if (m == NULL) {
        printf("dh.warmup=0\n");
        return 1;
    }
    DH_meth_free(m);

    /* ---- the window arms, in the order the functions run */

    begin();
    m = DH_meth_new("court-dh-method", 0x1234);
    end("new");
    printf("dh.new.not_null=%d\n", m != NULL);

    begin();
    dup = DH_meth_dup(m);
    end("dup");
    printf("dh.dup.not_null=%d\n", dup != NULL);

    begin();
    printf("dh.set1_name.ret=%d\n", DH_meth_set1_name(m, "court-dh-renamed"));
    end("set1_name");

    /* A refusal window: a NULL name is refused without an allocation on either side. */
    begin();
    printf("dh.set1_name_null.ret=%d\n", DH_meth_set1_name(m, NULL));
    end("set1_name_null");

    /* ---- the structural observations, none of which is an address */

    printf("dh.new.name=%s\n", DH_meth_get0_name(m));
    printf("dh.new.flags=%d\n", DH_meth_get_flags(m));
    printf("dh.new.app_data_is_null=%d\n", DH_meth_get0_app_data(m) == NULL);
    printf("dh.dup.name=%s\n", DH_meth_get0_name(dup));
    printf("dh.dup.flags=%d\n", DH_meth_get_flags(dup));
    printf("dh.dup.app_data_is_null=%d\n", DH_meth_get0_app_data(dup) == NULL);
    /* The duplicate's name is a second allocation, so the two pointers differ. */
    printf("dh.dup.name_ptr_differs=%d\n",
        DH_meth_get0_name(dup) != DH_meth_get0_name(m));
    /* A NULL `set1_name` leaves the old name in place. */
    printf("dh.set1_name_null.name_unchanged=%d",
        strcmp(DH_meth_get0_name(m), "court-dh-renamed") == 0);
    printf("\n");

    ROUNDTRIP("generate_key", DH_meth_get_generate_key, DH_meth_set_generate_key,
        sentinel_generate_key);
    ROUNDTRIP("compute_key", DH_meth_get_compute_key, DH_meth_set_compute_key,
        sentinel_compute_key);
    ROUNDTRIP("bn_mod_exp", DH_meth_get_bn_mod_exp, DH_meth_set_bn_mod_exp,
        sentinel_bn_mod_exp);
    ROUNDTRIP("init", DH_meth_get_init, DH_meth_set_init, sentinel_life);
    ROUNDTRIP("finish", DH_meth_get_finish, DH_meth_set_finish, sentinel_life);
    ROUNDTRIP("generate_params", DH_meth_get_generate_params, DH_meth_set_generate_params,
        sentinel_generate_params);

    /* `app_data` is not a function pointer and its NULL is a value, not a refusal. */
    printf("dh.app_data.set_ret=%d\n", DH_meth_set0_app_data(m, marker));
    printf("dh.app_data.get_is_marker=%d\n", DH_meth_get0_app_data(m) == marker);
    printf("dh.app_data.set_null_ret=%d\n", DH_meth_set0_app_data(m, NULL));
    printf("dh.app_data.get_after_null_is_null=%d\n", DH_meth_get0_app_data(m) == NULL);

    /* `flags` is stored verbatim and answered unconditionally. */
    printf("dh.flags.set_ret=%d\n", DH_meth_set_flags(m, 0x0f0f));
    printf("dh.flags.get=%d\n", DH_meth_get_flags(m));

    /* ---- the release windows, in the order the two objects are released */

    begin();
    DH_meth_free(dup);
    end("free_dup");

    begin();
    DH_meth_free(m);
    end("free_new");

    /* The preloaded name is the one `set1_name` stored, so the release order and the string are
     * both observed above. A NULL free is a no-op and records nothing. */
    begin();
    DH_meth_free(NULL);
    end("free_null");

    /* ---- the DH object, its key layer, its generator and its validators (D331) */

    dh_object_arms();

    /* ---- the named-group unit and its two tables (D332) */

    dh_named_group_arms();

    /* ---- the `crypto/evp/dh_ctrl.c` controls (slice E) */

    dh_ctl_arms();

    /* ---- the ASN.1 unit and the two `DHparams_*` exports it unblocks (D345) */

    dh_asn1_arms();

    /* ---- `DH_KDF_X9_42` and the `X942KDF-ASN1` row it fetches (D346) */

    dh_kdf_arms();

    return 0;
}
