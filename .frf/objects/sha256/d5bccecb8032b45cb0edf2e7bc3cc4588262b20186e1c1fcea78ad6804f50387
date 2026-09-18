/*
 * RT-EVP-MAC -- the `EVP_MAC` method object and the context it is run through.
 *
 * What this court had to build, and why
 * --------------------------------------
 * `EVP_MAC` is the first class in this stratum with **no legacy half**: there is no
 * `EVP_MAC_meth_new`, no pre-3.0 object underneath, and therefore no way to reach any of
 * `crypto/evp/mac_lib.c` except through a provider. So the provider below is not a convenience --
 * it is the only door, and everything this probe observes is behind it.
 *
 * The provider publishes **five** algorithms, and each is a different arm of
 * `evp_mac_from_algorithm`'s structural check:
 *
 *   * `court-mac` -- `newctx`, `freectx`, `init`, `update`, `final` and the four parameter
 *     callbacks: the acceptance case, and the one every context observation runs on;
 *   * `court-mac5` -- the same with `dupctx` added. `dupctx` is **not counted**, so adding it must
 *     not change whether the fetch succeeds; the pair exists to make that visible rather than
 *     argued (`EVP_MAC_CTX_dup` succeeds on one and answers NULL on the other);
 *   * `court-mac-skey` -- `init_skey` and **no** `init`. The `mac_init_found` fold is what makes
 *     this fetchable at all, and `EVP_MAC_init` on it is a refusal with its own reason;
 *   * `court-mac-bad` -- one mac function too few. The fetch must **fail**
 *     (`EVP_R_INVALID_PROVIDER_FUNCTIONS`), and it is the reason the do_all below counts four
 *     rather than five;
 *   * `court-mac-nosub` -- fetchable, and its settable-parameter list offers neither `digest` nor
 *     `cipher`, which is the only way `EVP_Q_mac`'s sub-algorithm refusal is reachable.
 *
 * The observations are of four kinds, and the same three as `RT-FETCH`'s context block plus one:
 * the **call path** (the provider counts its own callbacks, as one vector), the **value** (the MAC
 * is a function of the key and what was fed), the **refusals** (each with the reason the authority
 * raises), and **`do_all`'s enumeration**, which is the one observation that shows the construct-
 * then-enumerate order from outside: a provider whose constructor refuses leaves its algorithm out
 * of the walk.
 *
 * Deliberately not observed
 * -------------------------
 *   * **`EVP_MAC_init_SKEY`**, which is 7.3f's and is a scaffold in the candidate: calling it would
 *     abort the candidate rather than compare anything. The algorithm that publishes `init_skey` is
 *     here so that the field's *presence* is exercised through the structural check, which needs no
 *     `EVP_SKEY`.
 *   * **`EVP_MAC_do_all_provided` with a NULL visitor**, which faults the authority
 *     (`docs/SECURITY_DIVERGENCE_POLICY.md` D-MD-DOALL-NULL-1). The boundary is printed.
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
#include <openssl/params.h>
#include <openssl/provider.h>

#define COURT_MAC_SIZE 16
#define COURT_MAC_BLOCK 64
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

/* ---- the provider's own MAC, and the counters that are the observation ---- */

struct court_mac_st {
    unsigned long sum;
    size_t len;
    unsigned char key[COURT_KEY_MAX];
    size_t keylen;
    int xof;
    int digest_seen;
};

static char mac_marker;
static int mac_new_calls, mac_free_calls, mac_dup_calls, mac_init_calls;
static int mac_update_calls, mac_final_calls, mac_setp_calls, mac_getp_calls;
static int mac_skey_calls;

static void *mac_newctx(void *provctx)
{
    struct court_mac_st *d;

    (void) provctx;
    mac_new_calls++;
    d = malloc(sizeof *d);
    if (d == NULL)
        return NULL;
    memset(d, 0, sizeof *d);
    return d;
}

static void mac_freectx(void *mctx)
{
    mac_free_calls++;
    free(mctx);
}

static void *mac_dupctx(void *mctx)
{
    struct court_mac_st *to;

    mac_dup_calls++;
    if (mctx == NULL)
        return NULL;
    to = malloc(sizeof *to);
    if (to == NULL)
        return NULL;
    memcpy(to, mctx, sizeof *to);
    return to;
}

static int mac_init(void *mctx, const unsigned char *key, size_t keylen,
                    const OSSL_PARAM *params)
{
    struct court_mac_st *d = mctx;

    (void) params;
    mac_init_calls++;
    d->sum = 0;
    d->len = 0;
    d->keylen = keylen < COURT_KEY_MAX ? keylen : COURT_KEY_MAX;
    if (key != NULL)
        memcpy(d->key, key, d->keylen);
    return 1;
}

static int mac_update(void *mctx, const unsigned char *in, size_t inl)
{
    struct court_mac_st *d = mctx;
    size_t i;

    mac_update_calls++;
    for (i = 0; i < inl; i++)
        d->sum = (d->sum * 131 + in[i]) & 0xffff;
    d->len += inl;
    return 1;
}

/* The value is a function of the key *and* of what was fed, so the transcript distinguishes "the
 * implementation ran" from "some implementation ran" -- and `out[4]` is the `xof` parameter the
 * provider was handed, so the XOF path is visible in the bytes rather than only in a counter. */
static int mac_final(void *mctx, unsigned char *out, size_t *outl, size_t outsize)
{
    struct court_mac_st *d = mctx;
    size_t i;

    mac_final_calls++;
    if (outsize < COURT_MAC_SIZE) {
        *outl = 0;
        return 0;
    }
    out[0] = (unsigned char) (d->len & 0xff);
    out[1] = (unsigned char) (d->sum & 0xff);
    out[2] = (unsigned char) ((d->sum >> 8) & 0xff);
    out[3] = d->keylen > 0 ? d->key[0] : 0;
    out[4] = (unsigned char) (d->xof ? 1 : 0);
    out[5] = (unsigned char) (d->digest_seen ? 1 : 0);
    for (i = 6; i < COURT_MAC_SIZE; i++)
        out[i] = (unsigned char) ((i * 7) & 0xff);
    *outl = COURT_MAC_SIZE;
    return 1;
}

static int mac_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    size_t size = COURT_MAC_SIZE;
    size_t block = COURT_MAC_BLOCK;

    p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, size))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, block))
        return 0;
    return 1;
}

static int mac_get_ctx_params(void *mctx, OSSL_PARAM params[])
{
    struct court_mac_st *d = mctx;
    OSSL_PARAM *p;
    size_t size = COURT_MAC_SIZE;

    mac_getp_calls++;
    if (d == NULL)
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, size))
        return 0;
    return 1;
}

static int mac_set_ctx_params(void *mctx, const OSSL_PARAM params[])
{
    struct court_mac_st *d = mctx;
    const OSSL_PARAM *p;
    int xof = 0;

    mac_setp_calls++;
    if (d == NULL)
        return 0;
    if (params == NULL)
        return 1;
    p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_XOF);
    if (p != NULL && OSSL_PARAM_get_int(p, &xof))
        d->xof = xof;
    p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_DIGEST);
    if (p != NULL)
        d->digest_seen = 1;
    return 1;
}

static int mac_init_skey(void *mctx, void *key, const OSSL_PARAM params[])
{
    (void) mctx;
    (void) key;
    (void) params;
    mac_skey_calls++;
    return 1;
}

static const OSSL_PARAM *mac_gettable_params(void *provctx)
{
    static const OSSL_PARAM gettable[] = {
        OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, NULL),
        OSSL_PARAM_size_t(OSSL_MAC_PARAM_BLOCK_SIZE, NULL),
        OSSL_PARAM_END
    };

    (void) provctx;
    return gettable;
}

static const OSSL_PARAM *mac_gettable_ctx_params(void *mctx, void *provctx)
{
    static const OSSL_PARAM gettable[] = {
        OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, NULL),
        OSSL_PARAM_int(OSSL_MAC_PARAM_XOF, NULL),
        OSSL_PARAM_END
    };

    (void) mctx;
    (void) provctx;
    return gettable;
}

static const OSSL_PARAM *mac_settable_ctx_params(void *mctx, void *provctx)
{
    static const OSSL_PARAM settable[] = {
        OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_CIPHER, NULL, 0),
        OSSL_PARAM_int(OSSL_MAC_PARAM_XOF, NULL),
        OSSL_PARAM_END
    };

    (void) mctx;
    (void) provctx;
    return settable;
}

/* A settable list with neither `digest` nor `cipher`: the only way `EVP_Q_mac`'s sub-algorithm
 * refusal can be reached, because the caller's `subalg` is delivered through one of those two keys
 * and nothing else. */
static const OSSL_PARAM *mac_settable_ctx_params_none(void *mctx, void *provctx)
{
    static const OSSL_PARAM settable[] = {
        OSSL_PARAM_int(OSSL_MAC_PARAM_XOF, NULL),
        OSSL_PARAM_END
    };

    (void) mctx;
    (void) provctx;
    return settable;
}

static void say_mac_activity(const char *key)
{
    printf("%s=%d,%d,%d,%d,%d,%d,%d,%d,%d err=%lu\n", key,
           mac_new_calls, mac_free_calls, mac_dup_calls, mac_init_calls,
           mac_update_calls, mac_final_calls, mac_setp_calls, mac_getp_calls,
           mac_skey_calls, ERR_peek_error());
    ERR_clear_error();
}

/* ---- the five dispatch tables ---- */

static const OSSL_DISPATCH mac_fns[] = {
    { OSSL_FUNC_MAC_NEWCTX, (void (*)(void)) mac_newctx },
    { OSSL_FUNC_MAC_FREECTX, (void (*)(void)) mac_freectx },
    { OSSL_FUNC_MAC_INIT, (void (*)(void)) mac_init },
    { OSSL_FUNC_MAC_UPDATE, (void (*)(void)) mac_update },
    { OSSL_FUNC_MAC_FINAL, (void (*)(void)) mac_final },
    { OSSL_FUNC_MAC_GET_PARAMS, (void (*)(void)) mac_get_params },
    { OSSL_FUNC_MAC_GET_CTX_PARAMS, (void (*)(void)) mac_get_ctx_params },
    { OSSL_FUNC_MAC_SET_CTX_PARAMS, (void (*)(void)) mac_set_ctx_params },
    { OSSL_FUNC_MAC_GETTABLE_PARAMS, (void (*)(void)) mac_gettable_params },
    { OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS, (void (*)(void)) mac_gettable_ctx_params },
    { OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS, (void (*)(void)) mac_settable_ctx_params },
    { 0, NULL }
};

static const OSSL_DISPATCH mac5_fns[] = {
    { OSSL_FUNC_MAC_NEWCTX, (void (*)(void)) mac_newctx },
    { OSSL_FUNC_MAC_DUPCTX, (void (*)(void)) mac_dupctx },
    { OSSL_FUNC_MAC_FREECTX, (void (*)(void)) mac_freectx },
    { OSSL_FUNC_MAC_INIT, (void (*)(void)) mac_init },
    { OSSL_FUNC_MAC_UPDATE, (void (*)(void)) mac_update },
    { OSSL_FUNC_MAC_FINAL, (void (*)(void)) mac_final },
    { OSSL_FUNC_MAC_GET_PARAMS, (void (*)(void)) mac_get_params },
    { OSSL_FUNC_MAC_GET_CTX_PARAMS, (void (*)(void)) mac_get_ctx_params },
    { OSSL_FUNC_MAC_SET_CTX_PARAMS, (void (*)(void)) mac_set_ctx_params },
    { OSSL_FUNC_MAC_GETTABLE_PARAMS, (void (*)(void)) mac_gettable_params },
    { OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS, (void (*)(void)) mac_gettable_ctx_params },
    { OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS, (void (*)(void)) mac_settable_ctx_params },
    { 0, NULL }
};

/* `init_skey` instead of `init`, and nothing else different. */
static const OSSL_DISPATCH mac_skey_fns[] = {
    { OSSL_FUNC_MAC_NEWCTX, (void (*)(void)) mac_newctx },
    { OSSL_FUNC_MAC_FREECTX, (void (*)(void)) mac_freectx },
    { OSSL_FUNC_MAC_INIT_SKEY, (void (*)(void)) mac_init_skey },
    { OSSL_FUNC_MAC_UPDATE, (void (*)(void)) mac_update },
    { OSSL_FUNC_MAC_FINAL, (void (*)(void)) mac_final },
    { OSSL_FUNC_MAC_GET_PARAMS, (void (*)(void)) mac_get_params },
    { OSSL_FUNC_MAC_GETTABLE_PARAMS, (void (*)(void)) mac_gettable_params },
    { 0, NULL }
};

/* One mac function too few: `final` is absent, so `fnmaccnt` is 2 where the check wants 3. */
static const OSSL_DISPATCH mac_bad_fns[] = {
    { OSSL_FUNC_MAC_NEWCTX, (void (*)(void)) mac_newctx },
    { OSSL_FUNC_MAC_FREECTX, (void (*)(void)) mac_freectx },
    { OSSL_FUNC_MAC_INIT, (void (*)(void)) mac_init },
    { OSSL_FUNC_MAC_UPDATE, (void (*)(void)) mac_update },
    { 0, NULL }
};

static const OSSL_DISPATCH mac_nosub_fns[] = {
    { OSSL_FUNC_MAC_NEWCTX, (void (*)(void)) mac_newctx },
    { OSSL_FUNC_MAC_FREECTX, (void (*)(void)) mac_freectx },
    { OSSL_FUNC_MAC_INIT, (void (*)(void)) mac_init },
    { OSSL_FUNC_MAC_UPDATE, (void (*)(void)) mac_update },
    { OSSL_FUNC_MAC_FINAL, (void (*)(void)) mac_final },
    { OSSL_FUNC_MAC_GET_PARAMS, (void (*)(void)) mac_get_params },
    { OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS, (void (*)(void)) mac_settable_ctx_params_none },
    { 0, NULL }
};

static const OSSL_ALGORITHM court_macs[] = {
    { "court-mac:Court-MAC:courtmac", "provider=court", mac_fns, "court mac" },
    { "court-mac5:Court-MAC5:courtmac5", "provider=court", mac5_fns,
      "court mac with a duplicator" },
    { "court-mac-skey:Court-MAC-SKEY:courtmacskey", "provider=court", mac_skey_fns,
      "court mac with only a symmetric-key initialiser" },
    { "court-mac-bad:Court-MAC-BAD:courtmacbad", "provider=court", mac_bad_fns,
      "court mac that must be refused" },
    { "court-mac-nosub:Court-MAC-NOSUB:courtmacnosub", "provider=court", mac_nosub_fns,
      "court mac with no sub-algorithm key" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *court_query(void *provctx, int operation_id, int *no_cache)
{
    (void) provctx;
    *no_cache = 0;
    if (operation_id == OSSL_OP_MAC)
        return court_macs;
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
    *provctx = &mac_marker;
    return 1;
}

/* ---- the do_all visitor ---- */

struct mac_seen {
    int count;
    int saw_court_mac;
    int saw_bad;
};

/* The name visitor `EVP_MAC_names_do_all` is walked with. A **NULL** visitor is the
 * `D-NAMEMAP-DOALL-1` boundary -- `ossl_namemap_doall_names` calls it through -- so this one is
 * real and counts. */
struct mac_names {
    int count;
    int saw_identity;
    int saw_alias;
};

static void mac_name_visitor(const char *name, void *arg)
{
    struct mac_names *s = arg;

    s->count++;
    if (strcmp(name, "court-mac") == 0)
        s->saw_identity = 1;
    if (strcmp(name, "courtmac") == 0)
        s->saw_alias = 1;
}

static void mac_visitor(EVP_MAC *mac, void *arg)
{
    struct mac_seen *s = arg;
    const char *name = EVP_MAC_get0_name(mac);

    s->count++;
    if (name != NULL && strcmp(name, "court-mac") == 0)
        s->saw_court_mac = 1;
    if (name != NULL && strcmp(name, "court-mac-bad") == 0)
        s->saw_bad = 1;
}

int main(void)
{
    OSSL_LIB_CTX *ctx;
    OSSL_PROVIDER *p;
    EVP_MAC *mac, *mac5, *skey, *bad, *nosub, *again;
    const unsigned char key[4] = { 'k', 'e', 'y', '!' };
    const unsigned char data[5] = { 'a', 'b', 'c', 'd', 'e' };
    unsigned char out[64];
    size_t outl;
    int i;

    setvbuf(stdout, NULL, _IOLBF, 0);

    ctx = OSSL_LIB_CTX_new();
    if (ctx == NULL) {
        printf("fail.libctx=1\n");
        return 0;
    }
    sayn("add_builtin", OSSL_PROVIDER_add_builtin(ctx, "court-mac", court_provider_init));
    p = OSSL_PROVIDER_load(ctx, "court-mac");
    printf("load=%d\n", p != NULL ? 1 : 0);
    if (p == NULL) {
        OSSL_LIB_CTX_free(ctx);
        return 0;
    }
    say_mac_activity("mac.activity.pristine");

    /*
     * ---- the structural check, from both sides ----
     *
     * Four fetches that differ only in which callbacks their algorithm publishes. Two must succeed
     * and two must fail, and the failing one's *reason* is the observation: a transcription that
     * counted `dupctx` or that folded `init` and `init_skey` additively would accept `court-mac-bad`
     * and reject `court-mac-skey`, which is the exact pair of mistakes this block exists to catch.
     */
    mac = EVP_MAC_fetch(ctx, "court-mac", NULL);
    mac5 = EVP_MAC_fetch(ctx, "court-mac5", NULL);
    skey = EVP_MAC_fetch(ctx, "court-mac-skey", NULL);
    bad = EVP_MAC_fetch(ctx, "court-mac-bad", NULL);
    nosub = EVP_MAC_fetch(ctx, "court-mac-nosub", NULL);
    sayp("fetch.plain", mac);
    sayp("fetch.with_dupctx", mac5);
    sayp("fetch.init_skey_only", skey);
    sayp("fetch.one_function_short", bad);
    printf("fetch.one_function_short.err=%lu\n", ERR_peek_error());
    ERR_clear_error();
    sayp("fetch.no_subalg_key", nosub);

    /* A name nobody publishes, and a property that contradicts the provider's own. */
    again = EVP_MAC_fetch(ctx, "no-such-mac", NULL);
    sayp("fetch.unknown", again);
    printf("fetch.unknown.err=%lu\n", ERR_peek_error());
    ERR_clear_error();
    again = EVP_MAC_fetch(ctx, "court-mac", "provider=other");
    sayp("fetch.rejected", again);
    printf("fetch.rejected.err=%lu\n", ERR_peek_error());
    ERR_clear_error();
    again = EVP_MAC_fetch(ctx, "courtmac", NULL);
    printf("fetch.alias_same_object=%d\n", again == mac ? 1 : 0);
    EVP_MAC_free(again);

    if (mac != NULL) {
        const char *name = EVP_MAC_get0_name(mac);
        const char *desc = EVP_MAC_get0_description(mac);

        printf("md.name_matches=%d\n",
               name != NULL && strcmp(name, "court-mac") == 0 ? 1 : 0);
        printf("md.description_matches=%d\n",
               desc != NULL && strcmp(desc, "court mac") == 0 ? 1 : 0);
        sayp("md.provider", (const void *) EVP_MAC_get0_provider(mac));
        sayn("md.is_a.identity", EVP_MAC_is_a(mac, "court-mac"));
        sayn("md.is_a.alias", EVP_MAC_is_a(mac, "courtmac"));
        sayn("md.is_a.other", EVP_MAC_is_a(mac, "hmac"));
        sayn("md.is_a.null_mac", EVP_MAC_is_a(NULL, "court-mac"));
        sayp("md.gettable_params", (const void *) EVP_MAC_gettable_params(mac));
        sayp("md.gettable_ctx_params", (const void *) EVP_MAC_gettable_ctx_params(mac));
        sayp("md.settable_ctx_params", (const void *) EVP_MAC_settable_ctx_params(mac));
        {
            OSSL_PARAM q[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
            size_t sz = 0;

            q[0] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &sz);
            sayn("md.get_params.ret", EVP_MAC_get_params(mac, q));
            sayn("md.get_params.size", (long long) sz);
        }
        {
            struct mac_names s;

            memset(&s, 0, sizeof s);
            sayn("md.names_do_all.ret", EVP_MAC_names_do_all(mac, mac_name_visitor, &s));
            sayn("md.names.count", s.count);
            sayn("md.names.saw_identity", s.saw_identity);
            sayn("md.names.saw_alias", s.saw_alias);
        }
    }

    /*
     * ---- the context, and the five calls a MAC is actually made of ----
     *
     * The activity vector is the observation of the *path*: a transcription that took the
     * method-level `get_params` where the authority takes the context-level `get_ctx_params`, or
     * that failed to set the `xof` parameter before an XOF final, cannot produce the same vector.
     */
    if (mac != NULL) {
        EVP_MAC_CTX *c = EVP_MAC_CTX_new(mac);

        sayp("ctx.new", c);
        if (c != NULL) {
            printf("ctx.new.get0_mac_is_method=%d\n",
                   EVP_MAC_CTX_get0_mac(c) == mac ? 1 : 0);
            sayn("ctx.new.mac_size", (long long) EVP_MAC_CTX_get_mac_size(c));
            sayn("ctx.new.block_size", (long long) EVP_MAC_CTX_get_block_size(c));
            sayp("ctx.gettable_params", (const void *) EVP_MAC_CTX_gettable_params(c));
            sayp("ctx.settable_params", (const void *) EVP_MAC_CTX_settable_params(c));
            say_mac_activity("mac.activity.after_new");

            sayn("ctx.init", EVP_MAC_init(c, key, sizeof key, NULL));
            sayn("ctx.update", EVP_MAC_update(c, data, sizeof data));
            sayn("ctx.update.zero", EVP_MAC_update(c, NULL, 0));
            say_mac_activity("mac.activity.after_update");

            memset(out, 0xEE, sizeof out);
            outl = 0;
            sayn("ctx.final.return", EVP_MAC_final(c, out, &outl, sizeof out));
            sayn("ctx.final.outl", (long long) outl);
            sayn("ctx.final.byte0", out[0]);
            sayn("ctx.final.byte1", out[1]);
            sayn("ctx.final.byte2", out[2]);
            sayn("ctx.final.byte3", out[3]);
            sayn("ctx.final.byte4_xof", out[4]);
            sayn("ctx.final.byte5_digest_seen", out[5]);
            sayn("ctx.final.byte15", out[15]);
            sayn("ctx.final.beyond_outl_untouched", out[16] == 0xEE ? 1 : 0);

            /* The size query: a NULL buffer with a length answers 1 and writes the MAC's size. */
            outl = 9999;
            sayn("ctx.final.size_query", EVP_MAC_final(c, NULL, &outl, 0));
            sayn("ctx.final.size_query.outl", (long long) outl);
            /* A buffer smaller than the MAC's size is refused **before** the provider is called. */
            sayn("ctx.final.too_small", EVP_MAC_final(c, out, &outl, 4));
            printf("ctx.final.too_small.err=%lu\n", ERR_peek_error());
            ERR_clear_error();
            /* A size query with no length at all is the other refusal. */
            sayn("ctx.final.size_query_no_length", EVP_MAC_final(c, NULL, NULL, 0));
            printf("ctx.final.size_query_no_length.err=%lu\n", ERR_peek_error());
            ERR_clear_error();

            /* The XOF form sets the parameter first, and the provider records it -- which is why
             * `byte4` above and below differ. */
            memset(out, 0xEE, sizeof out);
            sayn("ctx.finalXOF.return", EVP_MAC_finalXOF(c, out, sizeof out));
            sayn("ctx.finalXOF.byte4_xof", out[4]);
            say_mac_activity("mac.activity.after_final");

            /* -- the parameter entry points, on the context and on the method -- */
            {
                OSSL_PARAM q[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
                size_t sz = 0;

                q[0] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &sz);
                sayn("ctx.get_params.ret", EVP_MAC_CTX_get_params(c, q));
                sayn("ctx.get_params.size", (long long) sz);
                q[0] = OSSL_PARAM_construct_int(OSSL_MAC_PARAM_XOF, &i);
                i = 1;
                sayn("ctx.set_params.ret", EVP_MAC_CTX_set_params(c, q));
                sayn("ctx.set_params.xof", i);
                sayn("ctx.set_params.null", EVP_MAC_CTX_set_params(c, NULL));
                say_mac_activity("mac.activity.after_params");
            }
            EVP_MAC_CTX_free(c);
            say_mac_activity("mac.activity.after_ctx_free");
        }
    }

    /*
     * ---- `EVP_MAC_CTX_dup`, which is the one place `dupctx` is observable ----
     *
     * `court-mac5` publishes `dupctx` and `court-mac` does not, so the same call answers a context
     * and a NULL on two methods that differ only in that entry -- and `dupctx` is deliberately
     * *not* counted by the structural check, so both methods were fetchable.
     */
    if (mac != NULL && mac5 != NULL) {
        EVP_MAC_CTX *a = EVP_MAC_CTX_new(mac);
        EVP_MAC_CTX *b = EVP_MAC_CTX_new(mac5);
        EVP_MAC_CTX *d;

        d = EVP_MAC_CTX_dup(b);
        sayp("dup.with_dupctx", d);
        printf("dup.distinct=%d\n", d != NULL && d != b ? 1 : 0);
        if (d != NULL) {
            printf("dup.method_is_source_method=%d\n",
                   EVP_MAC_CTX_get0_mac(d) == mac5 ? 1 : 0);
            sayn("dup.mac_size", (long long) EVP_MAC_CTX_get_mac_size(d));
            EVP_MAC_CTX_free(d);
        }
        if (a != NULL) {
            /*
             * **Not called.** `EVP_MAC_CTX_dup` on a method with no `dupctx` is one of the
             * authority's unchecked NULL callback calls -- `mac_lib.c` reaches
             * `src->meth->dupctx(src->algctx)` with no test -- and it was measured: a program that
             * fetches a MAC without a duplicator and duplicates a context prints `ctx_new=1` and
             * dies with **exit 139**. The candidate answers NULL, which is what the authority's own
             * next statement does when a duplicator answers NULL, so the boundary is narrow and is
             * recorded rather than reproduced
             * (`docs/SECURITY_DIVERGENCE_POLICY.md` D-MAC-DUPCTX-NULL-1).
             */
            printf("dup.without_dupctx=NOT_MEASURED_AUTHORITY_FAULTS\n");
            EVP_MAC_CTX_free(a);
        }
        EVP_MAC_CTX_free(b);
        say_mac_activity("mac.activity.after_dup");
    }

    /*
     * ---- the method that publishes only `init_skey` ----
     *
     * It is fetchable, which is the whole point of the `mac_init_found` fold, and its byte-string
     * initialise is a refusal with `ERR_R_UNSUPPORTED`. `EVP_MAC_init_SKEY` itself is 7.3f's and is
     * not called: the candidate's is a scaffold that aborts.
     */
    if (skey != NULL) {
        EVP_MAC_CTX *c = EVP_MAC_CTX_new(skey);

        sayp("skey.ctx_new", c);
        if (c != NULL) {
            sayn("skey.init", EVP_MAC_init(c, key, sizeof key, NULL));
            printf("skey.init.err=%lu\n", ERR_peek_error());
            ERR_clear_error();
            sayn("skey.update", EVP_MAC_update(c, data, sizeof data));
            sayn("skey.final", EVP_MAC_final(c, out, &outl, sizeof out));
            EVP_MAC_CTX_free(c);
        }
        sayn("skey.init_SKEY=NOT_MEASURED_CANDIDATE_SCAFFOLD", 0);
    }

    /*
     * ---- `EVP_Q_mac`, in all three of its output shapes ----
     *
     * The caller's buffer, no buffer at all (where the length comes back first and the library
     * allocates), and the sub-algorithm refusal -- which needs `court-mac-nosub`, because the key
     * `subalg` is delivered under is decided by what the method *says* it takes.
     */
    {
        size_t qlen = 7;
        unsigned char *qout;

        memset(out, 0xEE, sizeof out);
        sayp("qmac.into_caller_buffer",
             EVP_Q_mac(ctx, "court-mac", NULL, "SHA256", NULL, key, sizeof key, data,
                       sizeof data, out, sizeof out, &qlen));
        sayn("qmac.caller_buffer.len", (long long) qlen);
        sayn("qmac.caller_buffer.byte5_digest_seen", out[5]);

        qlen = 0;
        qout = EVP_Q_mac(ctx, "court-mac", NULL, NULL, NULL, key, sizeof key, data,
                         sizeof data, NULL, 0, &qlen);
        sayp("qmac.allocated", qout);
        sayn("qmac.allocated.len", (long long) qlen);
        sayn("qmac.allocated.byte0", qout != NULL ? qout[0] : -1);
        OPENSSL_free(qout);

        qlen = 0;
        sayp("qmac.no_subalg_key",
             EVP_Q_mac(ctx, "court-mac-nosub", NULL, "SHA256", NULL, key, sizeof key, data,
                       sizeof data, out, sizeof out, &qlen));
        printf("qmac.no_subalg_key.err=%lu\n", ERR_peek_error());
        ERR_clear_error();
        sayn("qmac.no_subalg_key.len", (long long) qlen);

        /* A name nobody publishes: the fetch fails and the length is still written -- from a
         * zeroed local, which is a fact a caller can see. */
        qlen = 9999;
        sayp("qmac.unknown_algorithm",
             EVP_Q_mac(ctx, "no-such-mac", NULL, NULL, NULL, key, sizeof key, data,
                       sizeof data, out, sizeof out, &qlen));
        sayn("qmac.unknown_algorithm.len", (long long) qlen);
        ERR_clear_error();
    }

    /*
     * ---- `do_all`, which is where the construct-then-enumerate order is visible ----
     *
     * The provider publishes five algorithms and one of them cannot be constructed, so a walk that
     * visited the *published* arrays would count five and this counts four. That is the observation
     * the reference-counting and the constructor's refusal path are for.
     */
    {
        struct mac_seen s;

        memset(&s, 0, sizeof s);
        EVP_MAC_do_all_provided(ctx, mac_visitor, &s);
        sayn("do_all.count", s.count);
        sayn("do_all.saw_court_mac", s.saw_court_mac);
        sayn("do_all.saw_the_refused_one", s.saw_bad);
    }
    printf("do_all.null_visitor=NOT_MEASURED_AUTHORITY_FAULTS\n");

    EVP_MAC_free(mac);
    EVP_MAC_free(mac5);
    EVP_MAC_free(skey);
    EVP_MAC_free(bad);
    EVP_MAC_free(nosub);
    say_mac_activity("mac.activity.after_all_free");
    sayn("unload", OSSL_PROVIDER_unload(p));
    OSSL_LIB_CTX_free(ctx);
    return 0;
}
