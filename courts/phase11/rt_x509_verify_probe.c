/*
 * RT-X509-VERIFY -- the Phase 11.2 court: the `X509_VERIFY_PARAM` surface, the
 * `X509_STORE_CTX` object's lifecycle and accessor surface, the free-standing time
 * decision surface and the issuer lookup, driven against the authority and the
 * candidate and compared observation for observation.
 *
 * What this probe can drive, and what it cannot
 * ---------------------------------------------
 * 11.2 landed 104 of the three units' 111 open exports. The three engine entry
 * points -- `X509_verify_cert`, `X509_STORE_CTX_verify` and `X509_build_chain` --
 * and the two that build the context they run on (`X509_STORE_CTX_init`,
 * `X509_STORE_CTX_init_rpk`) are withheld, as is `X509_CRL_diff`; their blocker is
 * recorded in `src/x509/x509_vfy.rs`'s module doc (the chain roll's OCSP arm is
 * Phase 12's, its CRL arm is `x_crl.rs`'s, its DANE arm is the SSL layer's, and
 * `X509v3_{asid,addr}_validate_path` are withheld in their own units). `pcy_tree.c`'s
 * `X509_policy_check` is withheld in the same way. **Two of the chain roll's arms have since
 * landed and are driven below**: the `x_crl.c` CRL method/lookup surface
 * (`X509_CRL_add0_revoked`, `X509_CRL_get0_by_serial`, `X509_CRL_get0_by_cert`, `X509_CRL_verify`,
 * the `X509_CRL_METHOD_*` object and `X509_CRL_set_/get_meth_data`), landed when 11.4 was pulled
 * forward to unblock the engine, and the RFC 3779 path validation
 * `X509v3_{asid,addr}_validate_path` and `..._validate_resource_set` of 11.5's
 * `v3_asid.c`/`v3_addr.c`. The OCSP and DANE arms remain Phase 12's and the SSL layer's. So this
 * probe does NOT run the
 * decision procedure `docs/PHASE-11-SUBPHASES.md` section 3.2 describes; it runs the
 * *time* half of that decision (the boundary instants, the two encodings, the
 * malformed field, `NO_CHECK_TIME`/`USE_CHECK_TIME`), the whole parameter and
 * context surface the decision would read and report, and the two landed arms above.
 *
 * No wall clock
 * -------------
 * Every time comparison is against a time set explicitly through
 * `X509_VERIFY_PARAM_set_time` or passed as an explicit `time_t`. The two
 * `X509_cmp_current_time` arms use instants far enough in the past (1970) and future
 * (2049) that no court run's wall clock can move the answer, and `X509_gmtime_adj` is
 * only asked whether it returned a block, never what that block says. Nothing here
 * prints an address.
 *
 * Every observation is an integer, a byte equality, a nonnull/null or an error
 * coordinate -- never an address, so the transcript is stable under -O0/-O1/-O2
 * (forensics/tools/probe_hygiene.py compiles this file at all three and requires it).
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>
#include <time.h>

#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>

#define PTR(p) ((p) != NULL ? "nonnull" : "null")

/* 2024-01-01T00:00:00Z, the reference instant every comparison below is anchored to. */
static const time_t REF = (time_t)1704067200;

static ASN1_TIME *utc(const char *s)
{
    ASN1_TIME *t = ASN1_UTCTIME_new();
    if (t == NULL)
        return NULL;
    if (!ASN1_UTCTIME_set_string(t, s)) {
        ASN1_TIME_free(t);
        return NULL;
    }
    return t;
}

static ASN1_TIME *gen(const char *s)
{
    ASN1_TIME *t = ASN1_GENERALIZEDTIME_new();
    if (t == NULL)
        return NULL;
    if (!ASN1_GENERALIZEDTIME_set_string(t, s)) {
        ASN1_TIME_free(t);
        return NULL;
    }
    return t;
}

static void time_surface(void)
{
    time_t ref = REF;
    time_t *pref = &ref;

    ASN1_TIME *empty = ASN1_UTCTIME_new();   /* length 0: the malformed-field arm */
    ASN1_TIME *at = utc("240101000000Z");    /* exactly equal to REF */
    ASN1_TIME *after = utc("240101000001Z"); /* one second after REF */
    ASN1_TIME *before = utc("231231235959Z");/* one second before REF */
    ASN1_TIME *g_at = gen("20240101000000Z");
    ASN1_TIME *g_before = gen("20231231235959Z");
    ASN1_TIME *far_past = utc("700101000000Z");
    ASN1_TIME *far_future = utc("491231235959Z");

    /* `X509_cmp_time(NULL, ...)` is a NULL dereference in the authority, so it is not an arm;
     * the malformed-field arm is the zero-length `empty` below. */
    printf("time.cmp.empty=%d\n", X509_cmp_time(empty, pref));
    printf("time.cmp.utc.equal=%d\n", X509_cmp_time(at, pref));
    printf("time.cmp.utc.after=%d\n", X509_cmp_time(after, pref));
    printf("time.cmp.utc.before=%d\n", X509_cmp_time(before, pref));
    printf("time.cmp.gen.equal=%d\n", X509_cmp_time(g_at, pref));
    printf("time.cmp.gen.before=%d\n", X509_cmp_time(g_before, pref));
    /* The two current-time arms are deterministic by construction: 1970 is before any
     * plausible run's clock and 2049 is after it. */
    printf("time.cmp_current.far_past=%d\n", X509_cmp_current_time(far_past));
    printf("time.cmp_current.far_future=%d\n", X509_cmp_current_time(far_future));

    {
        /* USECheckTime boundary frame: [before, after] contains REF. */
        X509_VERIFY_PARAM *vpm = X509_VERIFY_PARAM_new();
        X509_VERIFY_PARAM_set_time(vpm, REF);
        printf("time.frame.use.in_range=%d\n",
               X509_cmp_timeframe(vpm, before, after));
        printf("time.frame.use.end_equal=%d\n",
               X509_cmp_timeframe(vpm, NULL, at));  /* at == REF: past end */
        printf("time.frame.use.start_equal=%d\n",
               X509_cmp_timeframe(vpm, at, NULL));  /* at == REF: not before start */
        printf("time.frame.use.before_start=%d\n",
               X509_cmp_timeframe(vpm, after, NULL)); /* after > REF: before start */
        printf("time.frame.use.both_null=%d\n",
               X509_cmp_timeframe(vpm, NULL, NULL));
        X509_VERIFY_PARAM_clear_flags(vpm, X509_V_FLAG_USE_CHECK_TIME);
        X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_NO_CHECK_TIME);
        printf("time.frame.nocheck=%d\n",
               X509_cmp_timeframe(vpm, after, before));
        X509_VERIFY_PARAM_free(vpm);
    }
    printf("time.frame.null_vpm=%d\n", X509_cmp_timeframe(NULL, NULL, NULL));

    {
        ASN1_TIME *adj = X509_time_adj(NULL, 0, pref);
        ASN1_TIME *adx = X509_time_adj_ex(NULL, 1, 3600, pref);
        ASN1_TIME *gap = X509_gmtime_adj(NULL, 0);
        printf("time.adj.fixed.type=%d\n", adj != NULL ? adj->type : -1);
        printf("time.adj_ex.fixed.type=%d\n", adx != NULL ? adx->type : -1);
        /* `X509_gmtime_adj` has no reference-time parameter, so only its block is observed. */
        printf("time.gmtime_adj.allocated=%s\n", PTR(gap));
        ASN1_TIME_free(adj);
        ASN1_TIME_free(adx);
        ASN1_TIME_free(gap);
    }

    ASN1_TIME_free(empty);
    ASN1_TIME_free(at);
    ASN1_TIME_free(after);
    ASN1_TIME_free(before);
    ASN1_TIME_free(g_at);
    ASN1_TIME_free(g_before);
    ASN1_TIME_free(far_past);
    ASN1_TIME_free(far_future);
}

static void param_surface(void)
{
    X509_VERIFY_PARAM *p = X509_VERIFY_PARAM_new();

    printf("param.new=%s\n", PTR(p));
    printf("param.new.flags=%lu\n", X509_VERIFY_PARAM_get_flags(p));
    printf("param.new.trust=%d\n", X509_VERIFY_PARAM_get_inh_flags(p) == 0 ? 0 : -1);
    printf("param.new.depth=%d\n", X509_VERIFY_PARAM_get_depth(p));
    printf("param.new.auth_level=%d\n", X509_VERIFY_PARAM_get_auth_level(p));
    printf("param.new.name=%s\n", PTR((void *)X509_VERIFY_PARAM_get0_name(p)));

    printf("param.set_flags=%d\n",
           X509_VERIFY_PARAM_set_flags(p, X509_V_FLAG_PARTIAL_CHAIN));
    printf("param.flags.partial=%d\n",
           (X509_VERIFY_PARAM_get_flags(p) & X509_V_FLAG_PARTIAL_CHAIN) != 0);
    /* A policy-mask bit implies X509_V_FLAG_POLICY_CHECK (x509_vpm.c:269-270). */
    X509_VERIFY_PARAM_set_flags(p, X509_V_FLAG_EXPLICIT_POLICY);
    printf("param.flags.policy_implied=%d\n",
           (X509_VERIFY_PARAM_get_flags(p) & X509_V_FLAG_POLICY_CHECK) != 0);
    X509_VERIFY_PARAM_clear_flags(p, X509_V_FLAG_EXPLICIT_POLICY);
    printf("param.flags.cleared=%d\n",
           (X509_VERIFY_PARAM_get_flags(p) & X509_V_FLAG_EXPLICIT_POLICY) == 0);
    printf("param.set_inh_flags=%d\n",
           X509_VERIFY_PARAM_set_inh_flags(p, 0x1u));
    printf("param.inh_flags=%u\n", X509_VERIFY_PARAM_get_inh_flags(p));
    X509_VERIFY_PARAM_set_inh_flags(p, 0u);

    printf("param.set_purpose=%d\n",
           X509_VERIFY_PARAM_set_purpose(p, X509_PURPOSE_SSL_SERVER));
    printf("param.purpose=%d\n", X509_VERIFY_PARAM_get_purpose(p));
    printf("param.set_purpose.bad=%d\n",
           X509_VERIFY_PARAM_set_purpose(p, 9999));
    printf("param.set_trust=%d\n",
           X509_VERIFY_PARAM_set_trust(p, X509_TRUST_SSL_SERVER));
    X509_VERIFY_PARAM_set_depth(p, 7);
    printf("param.depth=%d\n", X509_VERIFY_PARAM_get_depth(p));
    X509_VERIFY_PARAM_set_auth_level(p, 2);
    printf("param.auth_level=%d\n", X509_VERIFY_PARAM_get_auth_level(p));

    X509_VERIFY_PARAM_set_time(p, REF);
    printf("param.time=%ld\n", (long)X509_VERIFY_PARAM_get_time(p));
    printf("param.time.use_check=%d\n",
           (X509_VERIFY_PARAM_get_flags(p) & X509_V_FLAG_USE_CHECK_TIME) != 0);

    printf("param.set1_name=%d\n", X509_VERIFY_PARAM_set1_name(p, "rt-court"));
    printf("param.name=%s\n", X509_VERIFY_PARAM_get0_name(p) != NULL
                                  ? X509_VERIFY_PARAM_get0_name(p) : "(null)");

    /* Hosts. */
    printf("param.set1_host=%d\n", X509_VERIFY_PARAM_set1_host(p, "a.example", 0));
    printf("param.host0=%s\n", X509_VERIFY_PARAM_get0_host(p, 0) != NULL
                                   ? X509_VERIFY_PARAM_get0_host(p, 0) : "(null)");
    printf("param.add1_host=%d\n", X509_VERIFY_PARAM_add1_host(p, "b.example", 0));
    printf("param.set1_host_replace=%d\n",
           X509_VERIFY_PARAM_set1_host(p, "c.example", 0));
    printf("param.host0.after=%s\n", X509_VERIFY_PARAM_get0_host(p, 0) != NULL
                                         ? X509_VERIFY_PARAM_get0_host(p, 0) : "(null)");
    printf("param.host1.after=%s\n", PTR((void *)X509_VERIFY_PARAM_get0_host(p, 1)));
    printf("param.host.embedded_nul=%d\n",
           X509_VERIFY_PARAM_set1_host(p, "bad\0name", 8));
    X509_VERIFY_PARAM_set_hostflags(p, 0x4u);
    printf("param.hostflags=%u\n", X509_VERIFY_PARAM_get_hostflags(p));
    printf("param.peername0=%s\n", PTR((void *)X509_VERIFY_PARAM_get0_peername(p)));

    /* Email. */
    printf("param.set1_email=%d\n", X509_VERIFY_PARAM_set1_email(p, "x@y.z", 0));
    printf("param.email=%s\n", X509_VERIFY_PARAM_get0_email(p) != NULL
                                  ? X509_VERIFY_PARAM_get0_email(p) : "(null)");

    /* IP. */
    printf("param.set1_ip_asc=%d\n", X509_VERIFY_PARAM_set1_ip_asc(p, "127.0.0.1"));
    printf("param.ip_asc=%s\n", X509_VERIFY_PARAM_get1_ip_asc(p) != NULL
                                    ? X509_VERIFY_PARAM_get1_ip_asc(p) : "(null)");
    {
        const unsigned char ip4[4] = { 192, 0, 2, 1 };
        printf("param.set1_ip=%d\n", X509_VERIFY_PARAM_set1_ip(p, ip4, 4));
        printf("param.ip.from_bytes=%s\n", X509_VERIFY_PARAM_get1_ip_asc(p) != NULL
                                               ? X509_VERIFY_PARAM_get1_ip_asc(p) : "(null)");
        printf("param.set1_ip.bad_len=%d\n", X509_VERIFY_PARAM_set1_ip(p, ip4, 5));
    }

    /* Policies. */
    /* `add0` takes ownership, so the probe hands it a private copy rather than the shared
     * `OBJ_nid2obj` object (which `set1_policies(NULL)` below would then free). */
    printf("param.add0_policy=%d\n",
           X509_VERIFY_PARAM_add0_policy(p, OBJ_dup(OBJ_nid2obj(NID_any_policy))));
    printf("param.set1_policies.null=%d\n",
           X509_VERIFY_PARAM_set1_policies(p, NULL));

    /* The peername move: `from` gives its block to `to` and is left NULL. */
    {
        X509_VERIFY_PARAM *to = X509_VERIFY_PARAM_new();
        X509_VERIFY_PARAM_set1_name(to, "to");
        X509_VERIFY_PARAM_move_peername(to, p);
        printf("param.move.to=%s\n", PTR((void *)X509_VERIFY_PARAM_get0_peername(to)));
        printf("param.move.from=%s\n", PTR((void *)X509_VERIFY_PARAM_get0_peername(p)));
        X509_VERIFY_PARAM_free(to);
    }

    X509_VERIFY_PARAM_free(p);
}

static void inherit_surface(void)
{
    X509_VERIFY_PARAM *src = X509_VERIFY_PARAM_new();
    X509_VERIFY_PARAM *dst = X509_VERIFY_PARAM_new();

    X509_VERIFY_PARAM_set_flags(src, X509_V_FLAG_PARTIAL_CHAIN);
    X509_VERIFY_PARAM_set_depth(src, 3);
    X509_VERIFY_PARAM_set_purpose(src, X509_PURPOSE_SSL_SERVER);
    X509_VERIFY_PARAM_set1_host(src, "shared.example", 0);

    /* `X509_VERIFY_PARAM_inherit(NULL, src)` dereferences `dest` in the authority, so only
     * the NULL-`src` arm (which returns immediately) is probed; `X509_VERIFY_PARAM_set1`
     * guards its NULL `to` itself and is probed below. */
    printf("inherit.from.null=%d\n", X509_VERIFY_PARAM_inherit(dst, NULL));
    printf("inherit.ok=%d\n", X509_VERIFY_PARAM_inherit(dst, src));
    printf("inherit.flags=%lu\n", X509_VERIFY_PARAM_get_flags(dst));
    printf("inherit.depth=%d\n", X509_VERIFY_PARAM_get_depth(dst));
    printf("inherit.purpose=%d\n", X509_VERIFY_PARAM_get_purpose(dst));
    printf("inherit.host0=%s\n", X509_VERIFY_PARAM_get0_host(dst, 0) != NULL
                                     ? X509_VERIFY_PARAM_get0_host(dst, 0) : "(null)");

    /* `set1` is `inherit` with X509_VP_FLAG_DEFAULT temporarily set (x509_vpm.c:228). */
    {
        X509_VERIFY_PARAM *d2 = X509_VERIFY_PARAM_new();
        printf("set1.null=%d\n", X509_VERIFY_PARAM_set1(NULL, src));
        printf("set1.ok=%d\n", X509_VERIFY_PARAM_set1(d2, src));
        printf("set1.flags=%lu\n", X509_VERIFY_PARAM_get_flags(d2));
        X509_VERIFY_PARAM_free(d2);
    }

    X509_VERIFY_PARAM_free(src);
    X509_VERIFY_PARAM_free(dst);
}

static void table_surface(void)
{
    int base = X509_VERIFY_PARAM_get_count();
    const X509_VERIFY_PARAM *p0 = X509_VERIFY_PARAM_get0(0);
    const X509_VERIFY_PARAM *pd = X509_VERIFY_PARAM_lookup("default");
    const X509_VERIFY_PARAM *ps = X509_VERIFY_PARAM_lookup("ssl_server");
    const X509_VERIFY_PARAM *pnone = X509_VERIFY_PARAM_lookup("no.such.row");

    printf("table.count.base=%d\n", base);
    printf("table.get0.name=%s\n",
           p0 != NULL && X509_VERIFY_PARAM_get0_name(p0) != NULL
               ? X509_VERIFY_PARAM_get0_name(p0) : "(null)");
    printf("table.lookup.default=%s\n",
           pd != NULL && X509_VERIFY_PARAM_get0_name(pd) != NULL
               ? X509_VERIFY_PARAM_get0_name(pd) : "(null)");
    printf("table.lookup.default.flags=%lu\n",
           pd != NULL ? X509_VERIFY_PARAM_get_flags(pd) : 0UL);
    printf("table.lookup.default.depth=%d\n",
           pd != NULL ? X509_VERIFY_PARAM_get_depth(pd) : -1);
    printf("table.lookup.ssl_server=%s\n",
           ps != NULL && X509_VERIFY_PARAM_get0_name(ps) != NULL
               ? X509_VERIFY_PARAM_get0_name(ps) : "(null)");
    printf("table.lookup.miss=%s\n", PTR((void *)pnone));

    {
        X509_VERIFY_PARAM *add = X509_VERIFY_PARAM_new();
        X509_VERIFY_PARAM_set1_name(add, "rt_added");
        printf("table.add0=%d\n", X509_VERIFY_PARAM_add0_table(add));
        printf("table.count.after=%d\n", X509_VERIFY_PARAM_get_count());
        {
            const X509_VERIFY_PARAM *got = X509_VERIFY_PARAM_lookup("rt_added");
            printf("table.lookup.added=%s\n", PTR((void *)got));
        }
        /* The row is now owned by the table; replacement frees the old one. */
        {
            X509_VERIFY_PARAM *add2 = X509_VERIFY_PARAM_new();
            X509_VERIFY_PARAM_set1_name(add2, "rt_added");
            printf("table.add0.replace=%d\n", X509_VERIFY_PARAM_add0_table(add2));
            printf("table.count.replace=%d\n", X509_VERIFY_PARAM_get_count());
        }
    }
    printf("table.get0.out_of_range=%s\n", PTR((void *)X509_VERIFY_PARAM_get0(1000)));
    X509_VERIFY_PARAM_table_cleanup();
    printf("table.count.cleaned=%d\n", X509_VERIFY_PARAM_get_count());
}

static void ctx_surface(void)
{
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    X509_STORE_CTX *ctx2 = X509_STORE_CTX_new_ex(NULL, "propq");
    X509_VERIFY_PARAM *p = X509_VERIFY_PARAM_new();

    printf("ctx.new=%s\n", PTR(ctx));
    printf("ctx.new_ex=%s\n", PTR(ctx2));
    printf("ctx.new.error=%d\n", ctx != NULL ? X509_STORE_CTX_get_error(ctx) : -1);
    printf("ctx.new.error_depth=%d\n",
           ctx != NULL ? X509_STORE_CTX_get_error_depth(ctx) : -1);
    printf("ctx.new.cert=%s\n", PTR(ctx != NULL ? (void *)X509_STORE_CTX_get0_cert(ctx) : NULL));
    printf("ctx.new.rpk=%s\n", PTR(ctx != NULL ? (void *)X509_STORE_CTX_get0_rpk(ctx) : NULL));
    printf("ctx.new.chain=%s\n", PTR(ctx != NULL ? (void *)X509_STORE_CTX_get0_chain(ctx) : NULL));
    printf("ctx.new.current_issuer=%s\n",
           PTR(ctx != NULL ? (void *)X509_STORE_CTX_get0_current_issuer(ctx) : NULL));
    printf("ctx.new.current_crl=%s\n",
           PTR(ctx != NULL ? (void *)X509_STORE_CTX_get0_current_crl(ctx) : NULL));
    printf("ctx.new.parent=%s\n",
           PTR(ctx != NULL ? (void *)X509_STORE_CTX_get0_parent_ctx(ctx) : NULL));
    printf("ctx.new.untrusted=%s\n",
           PTR(ctx != NULL ? (void *)X509_STORE_CTX_get0_untrusted(ctx) : NULL));
    printf("ctx.new.policy_tree=%s\n",
           PTR(ctx != NULL ? (void *)X509_STORE_CTX_get0_policy_tree(ctx) : NULL));
    printf("ctx.new.num_untrusted=%d\n",
           ctx != NULL ? X509_STORE_CTX_get_num_untrusted(ctx) : -1);
    printf("ctx.new.explicit_policy=%d\n",
           ctx != NULL ? X509_STORE_CTX_get_explicit_policy(ctx) : -1);
    printf("ctx.new.param=%s\n",
           PTR(ctx != NULL ? (void *)X509_STORE_CTX_get0_param(ctx) : NULL));
    printf("ctx.new.get1_chain.null=%s\n",
           PTR(ctx != NULL ? (void *)X509_STORE_CTX_get1_chain(ctx) : NULL));
    printf("ctx.new.ex_data0=%s\n",
           PTR(ctx != NULL ? X509_STORE_CTX_get_ex_data(ctx, 0) : NULL));

    /* The unset callback surface of a freshly allocated context. */
    printf("ctx.cb.verify=%s\n", PTR((void *)X509_STORE_CTX_get_verify(ctx)));
    printf("ctx.cb.verify_cb=%s\n", PTR((void *)X509_STORE_CTX_get_verify_cb(ctx)));
    printf("ctx.cb.get_issuer=%s\n", PTR((void *)X509_STORE_CTX_get_get_issuer(ctx)));
    printf("ctx.cb.check_issued=%s\n", PTR((void *)X509_STORE_CTX_get_check_issued(ctx)));
    printf("ctx.cb.check_revocation=%s\n",
           PTR((void *)X509_STORE_CTX_get_check_revocation(ctx)));
    printf("ctx.cb.get_crl=%s\n", PTR((void *)X509_STORE_CTX_get_get_crl(ctx)));
    printf("ctx.cb.check_crl=%s\n", PTR((void *)X509_STORE_CTX_get_check_crl(ctx)));
    printf("ctx.cb.cert_crl=%s\n", PTR((void *)X509_STORE_CTX_get_cert_crl(ctx)));
    printf("ctx.cb.check_policy=%s\n", PTR((void *)X509_STORE_CTX_get_check_policy(ctx)));
    printf("ctx.cb.lookup_certs=%s\n", PTR((void *)X509_STORE_CTX_get_lookup_certs(ctx)));
    printf("ctx.cb.lookup_crls=%s\n", PTR((void *)X509_STORE_CTX_get_lookup_crls(ctx)));
    printf("ctx.cb.cleanup=%s\n", PTR((void *)X509_STORE_CTX_get_cleanup(ctx)));

    /* Installing callbacks: only the non-NULL-ness round-trips. */
    X509_STORE_CTX_set_verify(ctx, NULL);
    X509_STORE_CTX_set_verify_cb(ctx, NULL);
    X509_STORE_CTX_set_get_crl(ctx, NULL);
    printf("ctx.cb.set.all_null=%d\n",
           X509_STORE_CTX_get_verify(ctx) == NULL && X509_STORE_CTX_get_verify_cb(ctx) == NULL
               && X509_STORE_CTX_get_get_crl(ctx) == NULL);

    /* The parameter block and the flag/depth/time doors it drives. */
    X509_STORE_CTX_set0_param(ctx, p);
    printf("ctx.param.same=%d\n", X509_STORE_CTX_get0_param(ctx) == p);
    X509_STORE_CTX_set_flags(ctx, X509_V_FLAG_TRUSTED_FIRST);
    printf("ctx.flags.trusted_first=%d\n",
           (X509_VERIFY_PARAM_get_flags(p) & X509_V_FLAG_TRUSTED_FIRST) != 0);
    X509_STORE_CTX_set_depth(ctx, 4);
    printf("ctx.depth=%d\n", X509_VERIFY_PARAM_get_depth(p));
    X509_STORE_CTX_set_time(ctx, 0, REF);
    printf("ctx.time=%ld\n", (long)X509_VERIFY_PARAM_get_time(p));
    X509_STORE_CTX_set_purpose(ctx, X509_PURPOSE_SSL_SERVER);
    printf("ctx.purpose=%d\n", X509_VERIFY_PARAM_get_purpose(p));
    X509_STORE_CTX_set_trust(ctx, X509_TRUST_SSL_SERVER);
    printf("ctx.purpose_inherit=%d\n",
           X509_STORE_CTX_purpose_inherit(ctx, 0, X509_PURPOSE_SSL_CLIENT, 0));
    printf("ctx.set_default=%d\n", X509_STORE_CTX_set_default(ctx, "default"));
    printf("ctx.set_default.miss=%d\n", X509_STORE_CTX_set_default(ctx, "no.such.row"));

    /* The error/depth/cert surface. */
    X509_STORE_CTX_set_error(ctx, 7);
    printf("ctx.error=%d\n", X509_STORE_CTX_get_error(ctx));
    X509_STORE_CTX_set_error_depth(ctx, 2);
    printf("ctx.error_depth=%d\n", X509_STORE_CTX_get_error_depth(ctx));
    {
        X509 *c = X509_new();
        X509_STORE_CTX_set_cert(ctx, c);
        printf("ctx.cert.same=%d\n", X509_STORE_CTX_get0_cert(ctx) == c);
        printf("ctx.get_current_cert.null=%s\n",
               PTR((void *)X509_STORE_CTX_get_current_cert(ctx)));
        X509_STORE_CTX_set_current_cert(ctx, c);
        printf("ctx.current_cert.same=%d\n", X509_STORE_CTX_get_current_cert(ctx) == c);
        X509_STORE_CTX_set_current_cert(ctx, NULL);
        printf("ctx.set_ex_data=%d\n", X509_STORE_CTX_set_ex_data(ctx, 3, c));
        printf("ctx.get_ex_data.same=%d\n", X509_STORE_CTX_get_ex_data(ctx, 3) == (void *)c);
        X509_STORE_CTX_set_cert(ctx, NULL);
        X509_STORE_CTX_set_current_cert(ctx, NULL);
        X509_free(c);
    }

    /* The set0 doors. */
    X509_STORE_CTX_set0_crls(ctx, NULL);
    X509_STORE_CTX_set0_rpk(ctx, NULL);
    X509_STORE_CTX_set0_untrusted(ctx, NULL);
    X509_STORE_CTX_set0_dane(ctx, NULL);
    X509_STORE_CTX_set_ocsp_resp(ctx, NULL);
    X509_STORE_CTX_set0_trusted_stack(ctx, NULL);
    X509_STORE_CTX_set0_verified_chain(ctx, NULL);
    X509_STORE_CTX_set_current_reasons(ctx, 0u);
    printf("ctx.set0.doors=0\n");

    /* The issuer lookup with a store-less context: found == 0. */
    {
        X509 *c = X509_new();
        X509 *iss = NULL;
        printf("ctx.get1_issuer.nostore=%d\n",
               X509_STORE_CTX_get1_issuer(&iss, ctx, c));
        printf("ctx.get1_issuer.result=%s\n", PTR((void *)iss));
        X509_free(c);
    }

    /* The parameters helper on a NULL public key and an empty chain. */
    {
        STACK_OF(X509) *sk = sk_X509_new_null();
        printf("pubkey_params.empty=%d\n", X509_get_pubkey_parameters(NULL, sk));
        sk_X509_free(sk);
    }

    /* Cleanup is idempotent; free runs it once more. */
    X509_STORE_CTX_cleanup(ctx);
    X509_STORE_CTX_cleanup(ctx);
    printf("ctx.cleanup.idempotent=1\n");
    X509_STORE_CTX_free(ctx2);
    X509_STORE_CTX_free(ctx);
    X509_policy_tree_free(NULL);
    printf("policy_tree_free.null=1\n");
}

/*
 * The CRL method/lookup surface -- the engine's revocation arm, `x_crl.c`.
 *
 * A fresh `X509_CRL_new` carries the authority's default method, so
 * `X509_CRL_add0_revoked` / `X509_CRL_get0_by_serial` / `X509_CRL_get0_by_cert` run the real
 * `def_crl_lookup` (the sort, the lock, the serial binary search and the issuer match). A
 * second CRL is created after `X509_CRL_set_default_method` installs a probe method, so the
 * vtable dispatch through `X509_CRL_verify` / `..._get0_by_serial` / `..._get0_by_cert` is
 * driven too. `X509_CRL_verify` is called only through the probe method (which returns 9): the
 * default `def_crl_verify` runs `ASN1_item_verify_ex` and is not called with a fabricated
 * keyless signature. Every observation is an integer, a nonnull/null or a pointer equality.
 */
static int rt_crl_init(X509_CRL *crl) { (void)crl; return 1; }
static int rt_crl_free(X509_CRL *crl) { (void)crl; return 1; }

static int rt_crl_lookup(X509_CRL *crl, X509_REVOKED **ret,
                         const ASN1_INTEGER *ser, const X509_NAME *issuer)
{
    (void)crl;
    (void)ret;
    (void)ser;
    (void)issuer;
    return 7; /* a marker no authority default returns, so the dispatch is unambiguous */
}

static int rt_crl_verify(X509_CRL *crl, EVP_PKEY *pk)
{
    (void)crl;
    (void)pk;
    return 9;
}

static void crl_surface(void)
{
    static int marker;
    ASN1_INTEGER *s = ASN1_INTEGER_new();
    X509_CRL *crl = X509_CRL_new();
    X509_REVOKED *r1 = X509_REVOKED_new();
    X509_REVOKED *r2 = X509_REVOKED_new();
    X509 *x = X509_new();

    if (s == NULL || crl == NULL || r1 == NULL || r2 == NULL || x == NULL) {
        printf("crl.alloc=0\n");
        return;
    }
    printf("crl.alloc=1\n");

    /* Two revoked entries with fixed serials, through the real default method. */
    ASN1_INTEGER_set(X509_REVOKED_get0_serialNumber(r1), 0x1234);
    ASN1_INTEGER_set(X509_REVOKED_get0_serialNumber(r2), 0x5678);
    printf("crl.add0_revoked.first=%d\n", X509_CRL_add0_revoked(crl, r1));
    printf("crl.add0_revoked.second=%d\n", X509_CRL_add0_revoked(crl, r2));

    ASN1_INTEGER_set(s, 0x1234);
    {
        X509_REVOKED *got = NULL;
        printf("crl.get0_by_serial.hit=%d\n", X509_CRL_get0_by_serial(crl, &got, s));
        printf("crl.get0_by_serial.hit_identity=%d\n", got == r1);
    }
    ASN1_INTEGER_set(s, 0x9999);
    {
        X509_REVOKED *got = NULL;
        printf("crl.get0_by_serial.miss=%d\n", X509_CRL_get0_by_serial(crl, &got, s));
        printf("crl.get0_by_serial.miss_null=%d\n", got == NULL);
    }

    /* By certificate: a fresh `X509` with the matching serial and the empty issuer both objects
     * carry, so `crl_revoked_issuer_match` takes its no-indirect-issuer path. */
    ASN1_INTEGER_set(s, 0x1234);
    X509_set_serialNumber(x, s);
    {
        X509_REVOKED *got = NULL;
        printf("crl.get0_by_cert.hit=%d\n", X509_CRL_get0_by_cert(crl, &got, x));
        printf("crl.get0_by_cert.hit_identity=%d\n", got == r1);
    }
    ASN1_INTEGER_set(s, 0x9999);
    X509_set_serialNumber(x, s);
    {
        X509_REVOKED *got = NULL;
        printf("crl.get0_by_cert.miss=%d\n", X509_CRL_get0_by_cert(crl, &got, x));
    }

    /* The method object and the vtable dispatch, over a second CRL. */
    {
        X509_CRL_METHOD *m = X509_CRL_METHOD_new(rt_crl_init, rt_crl_free,
                                                 rt_crl_lookup, rt_crl_verify);
        X509_CRL *c3;
        printf("crl.method_new=%s\n", PTR(m));
        X509_CRL_set_default_method(m);
        c3 = X509_CRL_new();
        printf("crl.method.crl=%s\n", PTR(c3));
        printf("crl.verify.custom=%d\n", X509_CRL_verify(c3, NULL));
        {
            X509_REVOKED *got = NULL;
            printf("crl.get0_by_serial.custom=%d\n", X509_CRL_get0_by_serial(c3, &got, s));
            printf("crl.get0_by_cert.custom=%d\n", X509_CRL_get0_by_cert(c3, &got, x));
        }
        /* The CRL frees before the method it points at, so `crl_free` never sees freed storage. */
        X509_CRL_free(c3);
        X509_CRL_METHOD_free(m);
        X509_CRL_set_default_method(NULL);
        printf("crl.method.reset=1\n");
    }

    printf("crl.meth_data.null=%d\n", X509_CRL_get_meth_data(crl) == NULL);
    X509_CRL_set_meth_data(crl, (void *)&marker);
    printf("crl.meth_data.round_trip=%d\n", X509_CRL_get_meth_data(crl) == (void *)&marker);

    X509_free(x);
    X509_CRL_free(crl);
    ASN1_INTEGER_free(s);
}

/*
 * The RFC 3779 path validation doors, `v3_asid.c` and `v3_addr.c`. A context with no chain is
 * the authority's own first test, so each entry returns 0 and leaves `X509_V_ERR_UNSPECIFIED`
 * on the context -- an error coordinate, not a boolean. The `..._validate_resource_set` doors
 * are entered with a NULL extension, their `ext == NULL` arm returning 1.
 */
static void path_surface(void)
{
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();

    printf("path.ctx=%s\n", PTR(ctx));
    printf("asid.validate_path.empty_chain=%d\n", X509v3_asid_validate_path(ctx));
    printf("asid.validate_path.error=%d\n", X509_STORE_CTX_get_error(ctx));
    printf("addr.validate_path.empty_chain=%d\n", X509v3_addr_validate_path(ctx));
    printf("addr.validate_path.error=%d\n", X509_STORE_CTX_get_error(ctx));
    printf("asid.validate_resource_set.null_ext=%d\n",
           X509v3_asid_validate_resource_set(NULL, NULL, 0));
    printf("addr.validate_resource_set.null_ext=%d\n",
           X509v3_addr_validate_resource_set(NULL, NULL, 0));

    X509_STORE_CTX_free(ctx);
}

int main(void)
{
    /* `X509_self_signed` is the one name 11.2 inherits; NULL is its error arm. */
    printf("self_signed.null=%d\n", X509_self_signed(NULL, 0));
    time_surface();
    param_surface();
    inherit_surface();
    table_surface();
    ctx_surface();
    crl_surface();
    path_surface();
    return 0;
}
