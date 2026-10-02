/*
 * RT-X509-VERIFY-ENGINE -- the Phase 11.2 court: the decision procedure itself,
 * driven against the authority and the candidate and compared observation for
 * observation.
 *
 * It calls the five engine exports -- `X509_STORE_CTX_init`, `X509_STORE_CTX_init_rpk`,
 * `X509_verify_cert`, `X509_STORE_CTX_verify` and `X509_build_chain` -- over a fixed
 * three-level PKI whose DER is embedded (`rt_x509_chain_der.h`): a self-signed root,
 * an intermediate signed by it, a valid leaf, an expired leaf and a sibling leaf for a
 * different name. It compares what `docs/PHASE-11-SUBPHASES.md` section 3.2 requires: the
 * *decision* (the return value), the *error code*, the *error depth*, the ordered sequence
 * in which the `verify_cb` callback is invoked, and the constructed chain (its length,
 * each element's subject/issuer link and its serial).
 *
 * The fixtures are **Ed25519**, deliberately. The classical RSA/ECDSA verify path reads
 * `EVP_get_digestbyname`, whose legacy `OBJ_NAME` table the crate records as the Phase-13
 * divergence D333/D343; an Ed25519 signature carries no digest OID, so the engine's
 * decision, error and chain observations here are its own and not that recorded
 * divergence's. Phase 10's `rt_store_probe.c` drives `X509_verify` over Ed25519 for the
 * same reason and names the RSA path `pending`.
 *
 * No wall clock, no addresses
 * ---------------------------
 * Every time-sensitive verification sets the verification time explicitly to
 * 2024-01-01T00:00:00Z through `X509_STORE_CTX_set_time`, which also sets
 * `X509_V_FLAG_USE_CHECK_TIME`. The `NO_CHECK_TIME` arm sets that flag instead. Nothing
 * here prints a pointer value, a resource limit or a hash order; the one nondeterministic
 * input a court could accidentally admit -- the current time -- is never read.
 *
 * Every observation is an integer, a `nonnull`/`null`, a serial number, or an error
 * coordinate (`lib.reason`), so the transcript is stable under -O0/-O1/-O2 (which
 * `forensics/tools/probe_hygiene.py` compiles this file at and requires). The error
 * coordinate is printed only for the refusal arms (a NULL argument or a missing issuer),
 * where the authority raises a specific reason; a verification failure's *decision* and
 * *error code* are the section 3.2 observations and are printed for every arm.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>
#include <time.h>

#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include "rt_x509_chain_der.h"

/* ---------------------------------------------------------------------------------------------
 * Output helpers -- every line is `key=value`, and no address is ever printed.
 * --------------------------------------------------------------------------------------------- */

static void out_int(const char *key, long v)
{
    printf("%s=%ld\n", key, v);
}

static void out_ptr(const char *key, const void *p)
{
    printf("%s=%s\n", key, p != NULL ? "nonnull" : "null");
}

/* The first error on the queue as `lib.reason`, then the queue is cleared. */
static void out_err(const char *key)
{
    unsigned long e = ERR_get_error();

    if (e == 0) {
        printf("%s=none\n", key);
        return;
    }
    printf("%s=%d.%d\n", key, ERR_GET_LIB(e), ERR_GET_REASON(e));
    ERR_clear_error();
}

/* ---------------------------------------------------------------------------------------------
 * The fixtures and the verification-time anchor.
 * --------------------------------------------------------------------------------------------- */

/* 2024-01-01T00:00:00Z: root/int/leaf/other are valid, `expired` is not. */
static const time_t REF = (time_t)1704067200;

static X509 *load(const unsigned char *der, unsigned int len)
{
    const unsigned char *p = der;

    return d2i_X509(NULL, &p, (long)len);
}

static X509_STORE *make_store(X509 *a, X509 *b)
{
    X509_STORE *s = X509_STORE_new();

    if (s == NULL)
        return NULL;
    if (a != NULL)
        X509_STORE_add_cert(s, a);
    if (b != NULL)
        X509_STORE_add_cert(s, b);
    return s;
}

static STACK_OF(X509) *stack_of(X509 *a, X509 *b)
{
    STACK_OF(X509) *sk = sk_X509_new_null();

    if (sk == NULL)
        return NULL;
    if (a != NULL)
        sk_X509_push(sk, a);
    if (b != NULL)
        sk_X509_push(sk, b);
    return sk;
}

/* ---------------------------------------------------------------------------------------------
 * The constructed-chain observation: length, and per element its serial, whether it is
 * self-signed by name, and whether its issuer names the next element's subject.
 * --------------------------------------------------------------------------------------------- */

static void observe_chain(const char *tag, STACK_OF(X509) *sk)
{
    char key[96];
    int n = (sk == NULL) ? -1 : sk_X509_num(sk);
    int i;

    snprintf(key, sizeof key, "%s.len", tag);
    out_int(key, n);
    for (i = 0; i < n; i++) {
        X509 *x = sk_X509_value(sk, i);

        snprintf(key, sizeof key, "%s.%d.serial", tag, i);
        out_int(key, (long)ASN1_INTEGER_get(X509_get_serialNumber(x)));
        snprintf(key, sizeof key, "%s.%d.self_ss", tag, i);
        out_int(key, X509_NAME_cmp(X509_get_subject_name(x),
                                   X509_get_issuer_name(x)) == 0);
        if (i + 1 < n) {
            X509 *up = sk_X509_value(sk, i + 1);

            snprintf(key, sizeof key, "%s.%d.links_up", tag, i);
            out_int(key, X509_NAME_cmp(X509_get_issuer_name(x),
                                       X509_get_subject_name(up)) == 0);
        }
    }
}

/* ---------------------------------------------------------------------------------------------
 * The `verify_cb` recorder. Each invocation prints `(preverify_ok, error, depth)` under a
 * `tag.cb.N` key, so the diff preserves the sequence; the callback forwards `ok`, exactly
 * as the authority's own `null_callback` does, so returning 0 stops verification.
 * --------------------------------------------------------------------------------------------- */

static const char *g_cb_tag = "verify";
static int g_cb_n;

static void cb_begin(const char *tag)
{
    g_cb_tag = tag;
    g_cb_n = 0;
}

static int cb_record(int ok, X509_STORE_CTX *ctx)
{
    printf("%s.cb.%d=%d.%d.%d\n", g_cb_tag, g_cb_n, ok,
           X509_STORE_CTX_get_error(ctx), X509_STORE_CTX_get_error_depth(ctx));
    g_cb_n++;
    return ok;
}

/* Set up a context over `store`, `target` and `untrusted`, install the recorder, and anchor
 * verification at REF. The caller frees the context. */
static X509_STORE_CTX *mkctx(const char *tag, X509_STORE *store, X509 *target,
                             STACK_OF(X509) *untrusted)
{
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();

    if (ctx == NULL)
        return NULL;
    if (!X509_STORE_CTX_init(ctx, store, target, untrusted)) {
        X509_STORE_CTX_free(ctx);
        return NULL;
    }
    X509_STORE_CTX_set_time(ctx, 0, REF);
    X509_STORE_CTX_set_verify_cb(ctx, cb_record);
    cb_begin(tag);
    return ctx;
}

/* Print the section-3.2 observations a decision leaves on the context. */
static void observe_decision(const char *tag, X509_STORE_CTX *ctx, int decision)
{
    char key[96];
    STACK_OF(X509) *c1;

    snprintf(key, sizeof key, "%s.decision", tag);
    out_int(key, decision);
    snprintf(key, sizeof key, "%s.error", tag);
    out_int(key, X509_STORE_CTX_get_error(ctx));
    snprintf(key, sizeof key, "%s.depth", tag);
    out_int(key, X509_STORE_CTX_get_error_depth(ctx));
    snprintf(key, sizeof key, "%s.num_untrusted", tag);
    out_int(key, X509_STORE_CTX_get_num_untrusted(ctx));
    observe_chain(tag, X509_STORE_CTX_get0_chain(ctx));

    c1 = X509_STORE_CTX_get1_chain(ctx);
    snprintf(key, sizeof key, "%s.get1_len", tag);
    out_int(key, c1 != NULL ? sk_X509_num(c1) : -1);
    sk_X509_pop_free(c1, X509_free);
}

/* ---------------------------------------------------------------------------------------------
 * The arms.
 * --------------------------------------------------------------------------------------------- */

static void init_surface(X509 *root, X509 *intermediate, X509 *leaf,
                         STACK_OF(X509) *untrusted)
{
    X509_STORE *store = make_store(root, NULL);
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();

    /* Success on a real chain. */
    out_int("init.ok.ret", X509_STORE_CTX_init(ctx, store, leaf, untrusted));
    out_int("init.ok.cert_same", X509_STORE_CTX_get0_cert(ctx) == leaf);
    out_int("init.ok.untrusted_same", X509_STORE_CTX_get0_untrusted(ctx) == untrusted);
    out_ptr("init.ok.param", X509_STORE_CTX_get0_param(ctx));
    out_ptr("init.ok.verify_cb", (void *)X509_STORE_CTX_get_verify_cb(ctx));
    out_int("init.ok.error", X509_STORE_CTX_get_error(ctx));
    out_int("init.ok.depth", X509_STORE_CTX_get_error_depth(ctx));
    out_ptr("init.ok.chain", X509_STORE_CTX_get0_chain(ctx));
    X509_STORE_CTX_free(ctx);

    /* NULL `ctx` is the one refusal the authority makes. */
    ERR_clear_error();
    out_int("init.ctxnull.ret", X509_STORE_CTX_init(NULL, store, leaf, untrusted));
    out_err("init.ctxnull.err");

    /* NULL `store`: accepted, with the engine's own default callbacks. */
    ctx = X509_STORE_CTX_new();
    ERR_clear_error();
    out_int("init.storenull.ret", X509_STORE_CTX_init(ctx, NULL, leaf, untrusted));
    out_err("init.storenull.err");
    out_int("init.storenull.cert_same", X509_STORE_CTX_get0_cert(ctx) == leaf);
    out_int("init.storenull.cb_set",
            X509_STORE_CTX_get_verify_cb(ctx) != NULL);
    X509_STORE_CTX_free(ctx);

    /* NULL `cert`: accepted. */
    ctx = X509_STORE_CTX_new();
    ERR_clear_error();
    out_int("init.certnull.ret", X509_STORE_CTX_init(ctx, store, NULL, untrusted));
    out_err("init.certnull.err");
    out_ptr("init.certnull.cert", X509_STORE_CTX_get0_cert(ctx));
    X509_STORE_CTX_free(ctx);

    X509_STORE_free(store);
}

static void init_rpk_surface(X509 *root, X509 *leaf)
{
    X509_STORE *store = make_store(root, NULL);
    EVP_PKEY *pk = X509_get0_pubkey(leaf);
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();

    ERR_clear_error();
    out_int("initrpk.ret", X509_STORE_CTX_init_rpk(ctx, store, pk));
    out_err("initrpk.err");
    out_int("initrpk.rpk_same", X509_STORE_CTX_get0_rpk(ctx) == pk);
    out_ptr("initrpk.cert", X509_STORE_CTX_get0_cert(ctx));

    X509_STORE_CTX_set_verify_cb(ctx, cb_record);
    cb_begin("initrpk");
    observe_decision("initrpk", ctx, X509_verify_cert(ctx));
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
}

static void verify_surface(X509 *root, X509 *intermediate, X509 *leaf,
                           X509 *expired, X509 *other)
{
    STACK_OF(X509) *un = stack_of(intermediate, NULL);
    X509_STORE *store = make_store(root, NULL);
    X509_STORE_CTX *ctx;
    X509_VERIFY_PARAM *param;

    /* NULL context refusals for the two entry points, with their error coordinates. */
    ERR_clear_error();
    out_int("verify.null.decision", X509_verify_cert(NULL));
    out_err("verify.null.err");
    ERR_clear_error();
    out_int("ctxverify.null.decision", X509_STORE_CTX_verify(NULL));
    out_err("ctxverify.null.err");

    /* The valid full chain: [leaf, intermediate, root]. */
    ctx = mkctx("verify.ok", store, leaf, un);
    observe_decision("verify.ok", ctx, X509_verify_cert(ctx));
    X509_STORE_CTX_free(ctx);

    /* Missing issuer: the store holds only the root, so the intermediate is unreachable. */
    {
        X509_STORE *bare = make_store(root, NULL);

        ctx = mkctx("verify.miss", bare, leaf, NULL);
        observe_decision("verify.miss", ctx, X509_verify_cert(ctx));
        X509_STORE_CTX_free(ctx);
        X509_STORE_free(bare);
    }

    /* The intermediate is present but untrusted, and the root is absent. */
    {
        X509_STORE *empty = X509_STORE_new();
        STACK_OF(X509) *un2 = stack_of(intermediate, NULL);

        ctx = mkctx("verify.noanchor", empty, leaf, un2);
        observe_decision("verify.noanchor", ctx, X509_verify_cert(ctx));
        X509_STORE_CTX_free(ctx);
        sk_X509_free(un2);
        X509_STORE_free(empty);
    }

    /* Untrusted self-signed: the root is the target and the store is empty. */
    {
        X509_STORE *empty = X509_STORE_new();

        ctx = mkctx("verify.ss", empty, root, NULL);
        observe_decision("verify.ss", ctx, X509_verify_cert(ctx));
        X509_STORE_CTX_free(ctx);
        X509_STORE_free(empty);
    }

    /* Expired leaf at REF. */
    ctx = mkctx("verify.exp", store, expired, un);
    observe_decision("verify.exp", ctx, X509_verify_cert(ctx));
    X509_STORE_CTX_free(ctx);

    /* Wrong host against the leaf's SAN. */
    ctx = mkctx("verify.hostbad", store, leaf, un);
    param = X509_STORE_CTX_get0_param(ctx);
    X509_VERIFY_PARAM_set1_host(param, "wrong.example.net", 0);
    observe_decision("verify.hostbad", ctx, X509_verify_cert(ctx));
    X509_STORE_CTX_free(ctx);

    /* Matching host. */
    ctx = mkctx("verify.hostok", store, leaf, un);
    param = X509_STORE_CTX_get0_param(ctx);
    X509_VERIFY_PARAM_set1_host(param, "good.example.com", 0);
    observe_decision("verify.hostok", ctx, X509_verify_cert(ctx));
    X509_STORE_CTX_free(ctx);

    /* The sibling leaf's SAN does not match the good host. */
    ctx = mkctx("verify.other", store, other, un);
    param = X509_STORE_CTX_get0_param(ctx);
    X509_VERIFY_PARAM_set1_host(param, "good.example.com", 0);
    observe_decision("verify.other", ctx, X509_verify_cert(ctx));
    X509_STORE_CTX_free(ctx);

    /* NO_CHECK_TIME: the expired leaf is accepted once the explicit check time is
     * cleared, so the flag (not the wall clock) decides the time frame. */
    ctx = mkctx("verify.noct", store, expired, un);
    param = X509_STORE_CTX_get0_param(ctx);
    X509_VERIFY_PARAM_clear_flags(param, X509_V_FLAG_USE_CHECK_TIME);
    X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_NO_CHECK_TIME);
    observe_decision("verify.noct", ctx, X509_verify_cert(ctx));
    X509_STORE_CTX_free(ctx);

    /* PARTIAL_CHAIN: a trusted intermediate is an acceptable anchor. */
    {
        X509_STORE *intstore = make_store(intermediate, NULL);

        ctx = mkctx("verify.pc", intstore, leaf, NULL);
        X509_STORE_CTX_set_flags(ctx, X509_V_FLAG_PARTIAL_CHAIN);
        observe_decision("verify.pc", ctx, X509_verify_cert(ctx));
        X509_STORE_CTX_free(ctx);

        /* The same setup without the flag refuses. */
        ctx = mkctx("verify.nopc", intstore, leaf, NULL);
        observe_decision("verify.nopc", ctx, X509_verify_cert(ctx));
        X509_STORE_CTX_free(ctx);
        X509_STORE_free(intstore);
    }

    /* `X509_STORE_CTX_verify` takes the target from the untrusted stack. */
    {
        STACK_OF(X509) *un3 = stack_of(leaf, intermediate);

        ctx = mkctx("ctxverify.ok", store, NULL, un3);
        observe_decision("ctxverify.ok", ctx, X509_STORE_CTX_verify(ctx));
        out_int("ctxverify.ok.cert_same", X509_STORE_CTX_get0_cert(ctx) == leaf);
        X509_STORE_CTX_free(ctx);
        sk_X509_free(un3);
    }

    X509_STORE_free(store);
    sk_X509_free(un);
}

static void build_surface(X509 *root, X509 *intermediate, X509 *leaf)
{
    X509_STORE *both = make_store(root, intermediate);
    X509_STORE *rootonly = make_store(root, NULL);
    STACK_OF(X509) *int_sk = stack_of(intermediate, NULL);
    STACK_OF(X509) *built;

    /* NULL target is the refusal. */
    ERR_clear_error();
    built = X509_build_chain(NULL, NULL, both, 0, NULL, NULL);
    out_ptr("build.null.ret", built);
    out_err("build.null.err");
    sk_X509_pop_free(built, X509_free);

    /* Finish a full chain from the store, dropping the self-signed root. */
    built = X509_build_chain(leaf, NULL, both, 0, NULL, NULL);
    out_ptr("build.store0.ret", built);
    observe_chain("build.store0", built);
    sk_X509_pop_free(built, X509_free);

    /* The same, keeping the self-signed root. */
    built = X509_build_chain(leaf, NULL, both, 1, NULL, NULL);
    out_ptr("build.store1.ret", built);
    observe_chain("build.store1", built);
    sk_X509_pop_free(built, X509_free);

    /* The intermediate supplied as an untrusted cert, the root trusted. */
    built = X509_build_chain(leaf, int_sk, rootonly, 0, NULL, NULL);
    out_ptr("build.untrusted.ret", built);
    observe_chain("build.untrusted", built);
    sk_X509_pop_free(built, X509_free);

    /* No store: the cert stack is the whole basis and the chain is not grown. */
    built = X509_build_chain(leaf, int_sk, NULL, 0, NULL, NULL);
    out_ptr("build.nostore.ret", built);
    observe_chain("build.nostore", built);
    sk_X509_pop_free(built, X509_free);

    /* The root is untrusted and absent, so the chain cannot finish. */
    built = X509_build_chain(leaf, NULL, rootonly, 0, NULL, NULL);
    out_ptr("build.nofinish.ret", built);
    sk_X509_pop_free(built, X509_free);

    sk_X509_free(int_sk);
    X509_STORE_free(rootonly);
    X509_STORE_free(both);
}

int main(void)
{
    X509 *root = load(RT_X509_CHAIN_ROOT_DER, RT_X509_CHAIN_ROOT_DER_LEN);
    X509 *intermediate = load(RT_X509_CHAIN_INT_DER, RT_X509_CHAIN_INT_DER_LEN);
    X509 *leaf = load(RT_X509_CHAIN_LEAF_DER, RT_X509_CHAIN_LEAF_DER_LEN);
    X509 *expired = load(RT_X509_CHAIN_EXPIRED_DER, RT_X509_CHAIN_EXPIRED_DER_LEN);
    X509 *other = load(RT_X509_CHAIN_OTHER_DER, RT_X509_CHAIN_OTHER_DER_LEN);
    STACK_OF(X509) *un;

    out_int("der.root", root != NULL);
    out_int("der.int", intermediate != NULL);
    out_int("der.leaf", leaf != NULL);
    out_int("der.expired", expired != NULL);
    out_int("der.other", other != NULL);
    if (root == NULL || intermediate == NULL || leaf == NULL || expired == NULL
        || other == NULL)
        return 1;

    un = stack_of(intermediate, NULL);

    init_surface(root, intermediate, leaf, un);
    init_rpk_surface(root, leaf);
    verify_surface(root, intermediate, leaf, expired, other);
    build_surface(root, intermediate, leaf);

    sk_X509_free(un);
    X509_free(other);
    X509_free(expired);
    X509_free(leaf);
    X509_free(intermediate);
    X509_free(root);
    return 0;
}
