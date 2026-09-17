/*
 * RT-EVP-KDF -- the `EVP_KDF` method object and the context it is run through.
 *
 * The mirror of `RT-EVP-MAC`, and it exists separately because the two classes differ in four
 * places a court can see. Three of them are structural and are the reason the provider below
 * publishes four algorithms; the fourth is a **bug in this crate** that this court's sibling found
 * and that this one now pins.
 *
 *   1. **the structural check is `1` and `2`**, where the MAC class's is `3` and `2`. So a KDF with
 *      no `derive` is refused and a KDF with no `freectx` is refused, and there is no fold to make
 *      either acceptable;
 *   2. **`EVP_KDF_CTX_dup` tests its duplicator** -- `src == NULL || src->algctx == NULL ||
 *      src->meth->dupctx == NULL` -- where `EVP_MAC_CTX_dup` calls through it and faults
 *      (`docs/SECURITY_DIVERGENCE_POLICY.md` D-MAC-DUPCTX-NULL-1). `court-kdf` publishes no
 *      `dupctx` and `court-kdf-dup` does, so the same call is observed answering NULL and answering
 *      a context, on two methods that differ in that one entry;
 *   3. **a KDF has a `reset`** and a MAC has none. It is a provider callback, it is optional, and
 *      the context's algorithm context survives it -- which the transcript shows by deriving
 *      before and after one.
 *
 * What the provider counts is the observation, as in `RT-EVP-MAC`: nine counters as one vector, so
 * the transcript says which of the thirteen callbacks ran and how many times. The derived key is a
 * function of what was asked for — the length, the key set on the context and a running fold of the
 * salt — so "the implementation ran" is distinguishable from "some implementation ran".
 *
 * Deliberately not observed
 * -------------------------
 *   * **`EVP_KDF_CTX_set_SKEY` and `EVP_KDF_derive_SKEY`**, which are 7.3f's: both take an
 *     `EVP_SKEY` and both are scaffolds in the candidate, so a probe that called one would abort
 *     the candidate rather than compare anything. The dispatch entries `set_skey` and `derive_skey`
 *     are still *reachable* through the walk -- the tables below publish neither, because a
 *     provider cannot publish a callback whose signature names a type it cannot name.
 *   * **`EVP_KDF_do_all_provided` with a NULL visitor**, which faults the authority
 *     (D-MD-DOALL-NULL-1). The boundary is printed.
 *
 * Addresses are never printed. Every observation is a relation between two pointers this probe
 * holds, a presence answer, a count or a return code.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
/* `EVP_KDF_*` is declared in `kdf.h` and **not** in `evp.h` -- which is the first thing this
 * probe learned: a probe that included only `evp.h` read `EVP_KDF_fetch`'s pointer return as an
 * `int`, which `-Werror=implicit-function-declaration` turned from a silent truncation into a
 * compile failure. The warning was there all along; the flag is what makes it stop a run. */
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/provider.h>

#define COURT_KDF_SIZE 16
#define COURT_KEY_MAX 32

static void sayp(const char *key, const void *p)
{
    printf("%s=%s err=%lu\n", key, p == NULL ? "NULL" : "nonnull", ERR_peek_error());
    ERR_clear_error();
}

static void sayn(const char *key, long long v)
{
    printf("%s=%lld err=%lu\n", key, v, ERR_peek_error());
    ERR_clear_error();
}

/* ---- the provider's own KDF, and the counters that are the observation ---- */

struct court_kdf_st {
    unsigned char key[COURT_KEY_MAX];
    size_t keylen;
    unsigned long salt;
    unsigned long fold;
};

static char kdf_marker;
static int kdf_new_calls, kdf_free_calls, kdf_dup_calls, kdf_reset_calls;
static int kdf_derive_calls, kdf_setp_calls, kdf_getp_calls;

static void *kdf_newctx(void *provctx)
{
    struct court_kdf_st *d;

    (void) provctx;
    kdf_new_calls++;
    d = malloc(sizeof *d);
    if (d == NULL)
        return NULL;
    memset(d, 0, sizeof *d);
    return d;
}

static void kdf_freectx(void *kctx)
{
    kdf_free_calls++;
    free(kctx);
}

static void *kdf_dupctx(void *kctx)
{
    struct court_kdf_st *to;

    kdf_dup_calls++;
    if (kctx == NULL)
        return NULL;
    to = malloc(sizeof *to);
    if (to == NULL)
        return NULL;
    memcpy(to, kctx, sizeof *to);
    return to;
}

/* The reset is the provider's own and it is **not** the context being released and re-made: the
 * caller's pointer is unchanged and the method is not consulted again. */
static void kdf_reset(void *kctx)
{
    struct court_kdf_st *d = kctx;

    kdf_reset_calls++;
    if (d == NULL)
        return;
    d->fold = 0;
}

/* The derived key is a function of everything that was set: the length asked for, the key on the
 * context (if any) and a fold of the salt. That is what makes two derivations from the same
 * context distinguishable in the transcript. */
static int kdf_derive(void *kctx, unsigned char *key, size_t keylen,
                      const OSSL_PARAM *params)
{
    struct court_kdf_st *d = kctx;
    unsigned long fold;
    size_t i;

    kdf_derive_calls++;
    if (d == NULL || key == NULL)
        return 0;
    fold = (unsigned long) (d->salt * 7 + d->keylen + keylen + d->fold);
    for (i = 0; i < keylen; i++)
        key[i] = (unsigned char) ((fold + i * 11) & 0xff);
    return 1;
}

static int kdf_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SIZE);
    size_t size = COURT_KDF_SIZE;

    if (p != NULL && !OSSL_PARAM_set_size_t(p, size))
        return 0;
    return 1;
}

static int kdf_get_ctx_params(void *kctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SIZE);
    size_t size = COURT_KDF_SIZE;

    kdf_getp_calls++;
    (void) kctx;
    if (p != NULL && !OSSL_PARAM_set_size_t(p, size))
        return 0;
    return 1;
}

static int kdf_set_ctx_params(void *kctx, const OSSL_PARAM params[])
{
    struct court_kdf_st *d = kctx;
    const OSSL_PARAM *p;
    const void *data = NULL;
    size_t len = 0;
    unsigned long salt = 0;
    unsigned long v;

    kdf_setp_calls++;
    if (d == NULL)
        return 0;
    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SALT);
    /* The salt is a string parameter in the authority's own KDFs, so it is one here: an octet
     * string whose bytes are folded into a number. */
    if (p != NULL && OSSL_PARAM_get_octet_string_ptr(p, &data, &len)) {
        unsigned long i;

        for (i = 0; i < len; i++)
            salt = salt * 131 + ((const unsigned char *) data)[i];
        d->salt = salt;
        d->fold = salt & 0xffff;
    }
    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_KEY);
    if (p != NULL && OSSL_PARAM_get_octet_string_ptr(p, &data, &len)) {
        d->keylen = len < COURT_KEY_MAX ? len : COURT_KEY_MAX;
        if (data != NULL)
            memcpy(d->key, data, d->keylen);
    }
    v = d->salt;
    (void) v;
    return 1;
}

static const OSSL_PARAM *kdf_gettable_params(void *provctx)
{
    static const OSSL_PARAM gettable[] = {
        OSSL_PARAM_size_t(OSSL_KDF_PARAM_SIZE, NULL),
        OSSL_PARAM_END
    };

    (void) provctx;
    return gettable;
}

static const OSSL_PARAM *kdf_gettable_ctx_params(void *kctx, void *provctx)
{
    static const OSSL_PARAM gettable[] = {
        OSSL_PARAM_size_t(OSSL_KDF_PARAM_SIZE, NULL),
        OSSL_PARAM_END
    };

    (void) kctx;
    (void) provctx;
    return gettable;
}

static const OSSL_PARAM *kdf_settable_ctx_params(void *kctx, void *provctx)
{
    static const OSSL_PARAM settable[] = {
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, NULL, 0),
        OSSL_PARAM_END
    };

    (void) kctx;
    (void) provctx;
    return settable;
}

static void say_kdf_activity(const char *key)
{
    printf("%s=%d,%d,%d,%d,%d,%d,%d err=%lu\n", key,
           kdf_new_calls, kdf_free_calls, kdf_dup_calls, kdf_reset_calls,
           kdf_derive_calls, kdf_setp_calls, kdf_getp_calls, ERR_peek_error());
    ERR_clear_error();
}

/* ---- the four dispatch tables ---- */

static const OSSL_DISPATCH kdf_fns[] = {
    { OSSL_FUNC_KDF_NEWCTX, (void (*)(void)) kdf_newctx },
    { OSSL_FUNC_KDF_FREECTX, (void (*)(void)) kdf_freectx },
    { OSSL_FUNC_KDF_RESET, (void (*)(void)) kdf_reset },
    { OSSL_FUNC_KDF_DERIVE, (void (*)(void)) kdf_derive },
    { OSSL_FUNC_KDF_GET_PARAMS, (void (*)(void)) kdf_get_params },
    { OSSL_FUNC_KDF_GET_CTX_PARAMS, (void (*)(void)) kdf_get_ctx_params },
    { OSSL_FUNC_KDF_SET_CTX_PARAMS, (void (*)(void)) kdf_set_ctx_params },
    { OSSL_FUNC_KDF_GETTABLE_PARAMS, (void (*)(void)) kdf_gettable_params },
    { OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS, (void (*)(void)) kdf_gettable_ctx_params },
    { OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS, (void (*)(void)) kdf_settable_ctx_params },
    { 0, NULL }
};

/* The same, plus a duplicator. `dupctx` is not counted by the structural check, so both this and
 * the table above are fetchable -- and only this one can be duplicated. */
static const OSSL_DISPATCH kdf_dup_fns[] = {
    { OSSL_FUNC_KDF_NEWCTX, (void (*)(void)) kdf_newctx },
    { OSSL_FUNC_KDF_DUPCTX, (void (*)(void)) kdf_dupctx },
    { OSSL_FUNC_KDF_FREECTX, (void (*)(void)) kdf_freectx },
    { OSSL_FUNC_KDF_RESET, (void (*)(void)) kdf_reset },
    { OSSL_FUNC_KDF_DERIVE, (void (*)(void)) kdf_derive },
    { OSSL_FUNC_KDF_GET_PARAMS, (void (*)(void)) kdf_get_params },
    { OSSL_FUNC_KDF_GET_CTX_PARAMS, (void (*)(void)) kdf_get_ctx_params },
    { OSSL_FUNC_KDF_SET_CTX_PARAMS, (void (*)(void)) kdf_set_ctx_params },
    { OSSL_FUNC_KDF_GETTABLE_PARAMS, (void (*)(void)) kdf_gettable_params },
    { OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS, (void (*)(void)) kdf_gettable_ctx_params },
    { OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS, (void (*)(void)) kdf_settable_ctx_params },
    { 0, NULL }
};

/* No `derive`: `fnkdfcnt` is 0 where the check wants exactly 1. */
static const OSSL_DISPATCH kdf_noderive_fns[] = {
    { OSSL_FUNC_KDF_NEWCTX, (void (*)(void)) kdf_newctx },
    { OSSL_FUNC_KDF_FREECTX, (void (*)(void)) kdf_freectx },
    { OSSL_FUNC_KDF_RESET, (void (*)(void)) kdf_reset },
    { 0, NULL }
};

/* No `freectx`: `fnctxcnt` is 1 where the check wants exactly 2. */
static const OSSL_DISPATCH kdf_nofree_fns[] = {
    { OSSL_FUNC_KDF_NEWCTX, (void (*)(void)) kdf_newctx },
    { OSSL_FUNC_KDF_RESET, (void (*)(void)) kdf_reset },
    { OSSL_FUNC_KDF_DERIVE, (void (*)(void)) kdf_derive },
    { 0, NULL }
};

static const OSSL_ALGORITHM court_kdfs[] = {
    { "court-kdf:Court-KDF:courtkdf", "provider=court", kdf_fns, "court kdf" },
    { "court-kdf-dup:Court-KDF-dup:courtkdfdup", "provider=court", kdf_dup_fns,
      "court kdf with a duplicator" },
    { "court-kdf-noderive:Court-KDF-noderive:courtkdfnoderive", "provider=court",
      kdf_noderive_fns, "court kdf that must be refused, for its derivation" },
    { "court-kdf-nofree:Court-KDF-nofree:courtkdfnofree", "provider=court",
      kdf_nofree_fns, "court kdf that must be refused, for its context" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *court_query(void *provctx, int operation_id, int *no_cache)
{
    (void) provctx;
    *no_cache = 0;
    if (operation_id == OSSL_OP_KDF)
        return court_kdfs;
    return NULL;
}

static const OSSL_DISPATCH court_dispatch[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void)) court_query },
    { 0, NULL }
};

static int court_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
                               const OSSL_DISPATCH **out, void **provctx)
{
    (void) handle;
    (void) in;
    *out = court_dispatch;
    *provctx = &kdf_marker;
    return 1;
}

/* ---- the do_all and name visitors ---- */

struct kdf_seen {
    int count;
    int saw_plain;
    int saw_refused;
};

static void kdf_visitor(EVP_KDF *kdf, void *arg)
{
    struct kdf_seen *s = arg;
    const char *name = EVP_KDF_get0_name(kdf);

    s->count++;
    if (name != NULL && strcmp(name, "court-kdf") == 0)
        s->saw_plain = 1;
    if (name != NULL && strcmp(name, "court-kdf-noderive") == 0)
        s->saw_refused = 1;
}

struct kdf_names {
    int count;
    int saw_identity;
    int saw_alias;
};

static void kdf_name_visitor(const char *name, void *arg)
{
    struct kdf_names *s = arg;

    s->count++;
    if (strcmp(name, "court-kdf") == 0)
        s->saw_identity = 1;
    if (strcmp(name, "courtkdf") == 0)
        s->saw_alias = 1;
}

int main(void)
{
    OSSL_LIB_CTX *ctx;
    OSSL_PROVIDER *p;
    EVP_KDF *kdf, *kdfdup, *noderive, *nofree, *again;
    const unsigned char salt[3] = { 's', 'a', 'l' };
    const unsigned char key[4] = { 'p', 'w', '0', '1' };
    unsigned char out[64];
    int i;

    setvbuf(stdout, NULL, _IOLBF, 0);

    ctx = OSSL_LIB_CTX_new();
    if (ctx == NULL) {
        printf("fail.libctx=1\n");
        return 0;
    }
    sayn("add_builtin", OSSL_PROVIDER_add_builtin(ctx, "court-kdf", court_provider_init));
    p = OSSL_PROVIDER_load(ctx, "court-kdf");
    printf("load=%d\n", p != NULL ? 1 : 0);
    if (p == NULL) {
        OSSL_LIB_CTX_free(ctx);
        return 0;
    }
    say_kdf_activity("kdf.activity.pristine");

    /*
     * ---- the structural check, from both sides ----
     *
     * Four fetches. Two must succeed and two must fail, and the two failures are the two counters:
     * a KDF with no `derive` fails `fnkdfcnt`, and one with no `freectx` fails `fnctxcnt`. A
     * transcription that accepted either would be indistinguishable from a correct one until a
     * caller asked the method to derive or to release a context -- which is to say, until it was
     * too late to notice.
     */
    kdf = EVP_KDF_fetch(ctx, "court-kdf", NULL);
    kdfdup = EVP_KDF_fetch(ctx, "court-kdf-dup", NULL);
    noderive = EVP_KDF_fetch(ctx, "court-kdf-noderive", NULL);
    nofree = EVP_KDF_fetch(ctx, "court-kdf-nofree", NULL);
    sayp("fetch.plain", kdf);
    sayp("fetch.with_dupctx", kdfdup);
    sayp("fetch.no_derive", noderive);
    printf("fetch.no_derive.err=%lu\n", ERR_peek_error());
    ERR_clear_error();
    sayp("fetch.no_freectx", nofree);
    printf("fetch.no_freectx.err=%lu\n", ERR_peek_error());
    ERR_clear_error();

    again = EVP_KDF_fetch(ctx, "no-such-kdf", NULL);
    sayp("fetch.unknown", again);
    printf("fetch.unknown.err=%lu\n", ERR_peek_error());
    ERR_clear_error();
    again = EVP_KDF_fetch(ctx, "court-kdf", "provider=other");
    sayp("fetch.rejected", again);
    printf("fetch.rejected.err=%lu\n", ERR_peek_error());
    ERR_clear_error();
    again = EVP_KDF_fetch(ctx, "courtkdf", NULL);
    printf("fetch.alias_same_object=%d\n", again == kdf ? 1 : 0);
    EVP_KDF_free(again);

    if (kdf != NULL) {
        const char *name = EVP_KDF_get0_name(kdf);
        const char *desc = EVP_KDF_get0_description(kdf);

        printf("kdf.name_matches=%d\n", name != NULL && strcmp(name, "court-kdf") == 0 ? 1 : 0);
        printf("kdf.description_matches=%d\n",
               desc != NULL && strcmp(desc, "court kdf") == 0 ? 1 : 0);
        sayp("kdf.provider", (const void *) EVP_KDF_get0_provider(kdf));
        sayn("kdf.is_a.identity", EVP_KDF_is_a(kdf, "court-kdf"));
        sayn("kdf.is_a.alias", EVP_KDF_is_a(kdf, "courtkdf"));
        sayn("kdf.is_a.other", EVP_KDF_is_a(kdf, "hkdf"));
        sayn("kdf.is_a.null_method", EVP_KDF_is_a(NULL, "court-kdf"));
        sayp("kdf.gettable_params", (const void *) EVP_KDF_gettable_params(kdf));
        sayp("kdf.gettable_ctx_params", (const void *) EVP_KDF_gettable_ctx_params(kdf));
        sayp("kdf.settable_ctx_params", (const void *) EVP_KDF_settable_ctx_params(kdf));
        {
            OSSL_PARAM q[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
            size_t sz = 0;

            q[0] = OSSL_PARAM_construct_size_t(OSSL_KDF_PARAM_SIZE, &sz);
            sayn("kdf.get_params.ret", EVP_KDF_get_params(kdf, q));
            sayn("kdf.get_params.size", (long long) sz);
        }
        {
            struct kdf_names s;

            memset(&s, 0, sizeof s);
            sayn("kdf.names_do_all.ret", EVP_KDF_names_do_all(kdf, kdf_name_visitor, &s));
            sayn("kdf.names.count", s.count);
            sayn("kdf.names.saw_identity", s.saw_identity);
            sayn("kdf.names.saw_alias", s.saw_alias);
        }
    }

    /*
     * ---- the context, the reset and the derivation ----
     *
     * The derivation's *value* is the observation that the implementation ran, and the two
     * derivations around the reset are the observation that the reset is the provider's own: the
     * key is the same because the key is still on the context, and the salt's fold is gone.
     */
    if (kdf != NULL) {
        EVP_KDF_CTX *c = EVP_KDF_CTX_new(kdf);

        sayp("ctx.new", c);
        if (c != NULL) {
            printf("ctx.new.kdf_is_method=%d\n", EVP_KDF_CTX_kdf(c) == kdf ? 1 : 0);
            sayn("ctx.new.kdf_size", (long long) EVP_KDF_CTX_get_kdf_size(c));
            sayp("ctx.gettable_params", (const void *) EVP_KDF_CTX_gettable_params(c));
            sayp("ctx.settable_params", (const void *) EVP_KDF_CTX_settable_params(c));
            say_kdf_activity("kdf.activity.after_new");

            /* -- set the salt and the key, then derive -- */
            {
                OSSL_PARAM q[3] = { OSSL_PARAM_END, OSSL_PARAM_END, OSSL_PARAM_END };

                q[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                                         (void *) salt, sizeof salt);
                q[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                                         (void *) key, sizeof key);
                sayn("ctx.set_params", EVP_KDF_CTX_set_params(c, q));
            }
            memset(out, 0xEE, sizeof out);
            sayn("ctx.derive.return", EVP_KDF_derive(c, out, COURT_KDF_SIZE, NULL));
            sayn("ctx.derive.byte0", out[0]);
            sayn("ctx.derive.byte1", out[1]);
            sayn("ctx.derive.byte15", out[15]);
            sayn("ctx.derive.beyond_untouched", out[16] == 0xEE ? 1 : 0);
            say_kdf_activity("kdf.activity.after_derive");

            /* -- the reset -- */
            EVP_KDF_CTX_reset(c);
            say_kdf_activity("kdf.activity.after_reset");
            memset(out, 0xEE, sizeof out);
            sayn("ctx.derive.after_reset", EVP_KDF_derive(c, out, COURT_KDF_SIZE, NULL));
            sayn("ctx.derive.after_reset.byte0", out[0]);
            /* The reset is a *callback*, not a re-initialise: the context is the same object and
             * the method is not consulted again. */
            printf("ctx.after_reset.kdf_is_method=%d\n", EVP_KDF_CTX_kdf(c) == kdf ? 1 : 0);

            /* -- the parameter entry points -- */
            {
                OSSL_PARAM q[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
                size_t sz = 0;

                q[0] = OSSL_PARAM_construct_size_t(OSSL_KDF_PARAM_SIZE, &sz);
                sayn("ctx.get_params.ret", EVP_KDF_CTX_get_params(c, q));
                sayn("ctx.get_params.size", (long long) sz);
                sayn("ctx.set_params.null", EVP_KDF_CTX_set_params(c, NULL));
                say_kdf_activity("kdf.activity.after_params");
            }
            EVP_KDF_CTX_free(c);
            say_kdf_activity("kdf.activity.after_ctx_free");
        }
    }

    /*
     * ---- `EVP_KDF_CTX_dup`, which is the class difference that matters most ----
     *
     * `court-kdf` publishes no `dupctx` and `court-kdf-dup` does, and both were fetchable because
     * the structural check does not count it. The authority's KDF duplicate **tests** the pointer;
     * its MAC duplicate calls through it and faults. So the same call on the same pair of methods
     * is a NULL here and a crash there, and this block is the observation of the difference.
     */
    if (kdf != NULL && kdfdup != NULL) {
        EVP_KDF_CTX *plain = EVP_KDF_CTX_new(kdf);
        EVP_KDF_CTX *withdup = EVP_KDF_CTX_new(kdfdup);
        EVP_KDF_CTX *d;

        d = EVP_KDF_CTX_dup(plain);
        sayp("dup.without_dupctx", d);
        EVP_KDF_CTX_free(d);

        d = EVP_KDF_CTX_dup(withdup);
        sayp("dup.with_dupctx", d);
        printf("dup.distinct=%d\n", d != NULL && d != withdup ? 1 : 0);
        if (d != NULL) {
            printf("dup.kdf_is_source_method=%d\n", EVP_KDF_CTX_kdf(d) == kdfdup ? 1 : 0);
            sayn("dup.kdf_size", (long long) EVP_KDF_CTX_get_kdf_size(d));
            /* The duplicate derives on its own: the algorithm context was copied, not shared. */
            memset(out, 0xEE, sizeof out);
            sayn("dup.derive", EVP_KDF_derive(d, out, COURT_KDF_SIZE, NULL));
            sayn("dup.derive.byte0", out[0]);
            EVP_KDF_CTX_free(d);
        }
        EVP_KDF_CTX_free(plain);
        EVP_KDF_CTX_free(withdup);
        say_kdf_activity("kdf.activity.after_dup");
    }

    /*
     * ---- `do_all`, which counts what was *constructed* rather than what was published ----
     *
     * Four algorithms are published and two cannot be constructed, so the walk counts two. That is
     * `evp_generic_do_all`'s construct-then-enumerate order, and it is the same observation
     * `RT-EVP-MAC` makes with a different arithmetic.
     */
    {
        struct kdf_seen s;

        memset(&s, 0, sizeof s);
        EVP_KDF_do_all_provided(ctx, kdf_visitor, &s);
        sayn("do_all.count", s.count);
        sayn("do_all.saw_court_kdf", s.saw_plain);
        sayn("do_all.saw_a_refused_one", s.saw_refused);
    }
    printf("do_all.null_visitor=NOT_MEASURED_AUTHORITY_FAULTS\n");
    printf("set_SKEY=NOT_MEASURED_CANDIDATE_SCAFFOLD\n");
    printf("derive_SKEY=NOT_MEASURED_CANDIDATE_SCAFFOLD\n");

    (void) i;
    EVP_KDF_free(kdf);
    EVP_KDF_free(kdfdup);
    EVP_KDF_free(noderive);
    EVP_KDF_free(nofree);
    say_kdf_activity("kdf.activity.after_all_free");
    sayn("unload", OSSL_PROVIDER_unload(p));
    OSSL_LIB_CTX_free(ctx);
    return 0;
}
