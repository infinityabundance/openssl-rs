/*
 * RT-EC -- the differential court for `crypto/ec/` (Phase 8.7).
 *
 * This program is compiled **twice**, once against the admitted authority and once against the
 * candidate distribution shell, and the two `key=value` transcripts are diffed. It never decides
 * anything: a residual is a difference between two executions, so the expectation cannot drift
 * with the crate. `forensics/tools/phase8_courts.py` owns the comparison.
 *
 * What this court covers, and the boundary it is drawn on
 * ------------------------------------------------------
 * D334's slice is `crypto/ec/ec_curve.c`'s built-in curve tables and `crypto/evp/ec_support.c`'s
 * two name tables, which is **four exports**: `EC_get_builtin_curves`, `EC_curve_nid2nist`,
 * `EC_curve_nist2nid` and `OSSL_EC_curve_nid2name`. All four are called, and every one of the
 * eighty-two rows is walked in both directions.
 *
 * **The curve constants are not observable through any export this slice lands.** `p`, `a`, `b`,
 * `gx`, `gy`, `order`, the cofactor and the seed reach a caller only through `EC_GROUP_get_curve`,
 * `EC_POINT_get_affine_coordinates`, `EC_GROUP_get_order`, `EC_GROUP_get0_cofactor` and
 * `EC_GROUP_get0_seed` -- all of which need `EC_GROUP_new_by_curve_name`, which needs `ec_lib.c`'s
 * group object and the field arithmetic it dispatches to. So the constants are **not** courted
 * here and this probe does not call them: their evidence is
 * `forensics/tools/gen_ec_curves.py`, whose own probe links against the authority's
 * `EC_GROUP_new_by_curve_name` and checks every read-back against the `data[]` array the
 * authority's struct declares, member for member and width for width, before
 * `src/ec/curve_data.rs` is written. Their *properties* -- the field widths, the oddness, each
 * comment's field size against its polynomial's degree, and `param_len`'s tightness against `p`
 * and the order -- are asserted by the unit tests in `src/ec/curve.rs`, which is where a value
 * with no public reader has to be checked.
 *
 * That is stated rather than implied because the alternative -- probing the constants through a
 * symbol the candidate has not implemented -- would abort the candidate with a diagnostic, and the
 * runner's own module documentation says a probe stays on the implemented surface so that a
 * failure here means a behavioural divergence rather than a missing symbol.
 *
 * What the four exports *are* diffed on
 * -------------------------------------
 *   * `EC_get_builtin_curves` in all four of its call shapes: a NULL table with a non-zero
 *     `nitems`, a table with `nitems == 0`, a one-entry table, and a full-size one. The answer is
 *     the table's length on every path and only `min(nitems, length)` entries are written, so the
 *     transcript prints the untouched tail of the short buffer beside the entry the call filled.
 *   * The eighty-two rows in order: each one's `nid`, its `OBJ_nid2sn` short name and its
 *     `comment` verbatim. The comment column is what makes this arm load-bearing for the curve
 *     *table* rather than only for the lookup -- a row dropped, added or reordered moves three
 *     lines -- and the three IPSec comments carry newline and tab bytes, printed escaped.
 *   * `EC_curve_nid2nist` and `OSSL_EC_curve_nid2name` over every row's NID and over four
 *     refusals each: `0`, `-1`, a NID no object has, and a curve with no NIST spelling.
 *   * `EC_curve_nist2nid` over the fifteen NIST short names and over the refusals that separate it
 *     from `ossl_ec_curve_name2nid`: a lower-case spelling, a NIST name with a trailing space, a
 *     name of the right shape and the wrong number, a SECG name that is in neither table, the SM2
 *     spelling that is only in the *other* table, and the empty string.
 *
 * No secret is printed and none can be: this slice has no key, no nonce and no shared value. No
 * address is printed either -- every lookup answers a `const char *` into `.rodata`, and the probe
 * prints the *string* or the word `NULL`, never the pointer. stdout is line-buffered, and no
 * NULL-dereferencing entry point is called: `EC_curve_nist2nid(NULL)` faults inside `strcmp` in the
 * authority, so the probe does not call it and records that here instead.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/* `EC_curve_nid2nist`, `EC_curve_nist2nid` and `OSSL_EC_curve_nid2name` are not deprecated, but
 * the field-type constants this probe compares against are reached through `EC_GROUP`-era
 * declarations. The deprecation is the authority's own policy statement about application code,
 * not about a court that must exercise the entry points it declares; suppressing the diagnostic
 * keeps `-Wall` output readable without changing a single symbol this probe links. */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/param_build.h>
#include <openssl/objects.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The comment column, with the two whitespace bytes the three IPSec rows carry written as `|` and
 * `/`, so the transcript is one line per observation. */
static void emit_text(const char *tag, const char *member, const char *s)
{
    const char *p;

    printf("%s.%s=", tag, member);
    if (s == NULL) {
        printf("NULL\n");
        return;
    }
    for (p = s; *p != '\0'; p++)
        putchar(*p == '\n' ? '|' : (*p == '\t' ? '/' : *p));
    putchar('\n');
}

static void emit_nid2nist(int nid)
{
    const char *nist = EC_curve_nid2nist(nid);

    printf("nid2nist.%d=%s\n", nid, nist != NULL ? nist : "NULL");
}

static void emit_nid2name(int nid)
{
    const char *name = OSSL_EC_curve_nid2name(nid);

    printf("nid2name.%d=%s\n", nid, name != NULL ? name : "NULL");
}

static void emit_nist2nid(const char *name)
{
    printf("nist2nid.%s=%d\n", name, EC_curve_nist2nid(name));
}

/* The two refusals every lookup shares. `NID_brainpoolP256r1` is a curve with no NIST short name
 * and `NID_rsaEncryption` is not a curve at all -- the two answers `ec_support.c`'s table
 * distinguishes -- and `OID_undef`-style numbers that no object has are a third. */
static void emit_refusals(void)
{
    emit_nid2nist(0);
    emit_nid2nist(-1);
    emit_nid2nist(999999);
    emit_nid2nist(NID_brainpoolP256r1);
    emit_nid2nist(NID_rsaEncryption);
    emit_nid2name(0);
    emit_nid2name(-1);
    emit_nid2name(999999);
    emit_nid2name(NID_brainpoolP256r1);
    emit_nid2name(NID_rsaEncryption);
}

/* The drained error queue, with each record's library, reason and authority coordinate. The
 * coordinate is the authority's own `__FILE__`/`__LINE__`/`__func__`, which the crate's error
 * sites reproduce by construction, so a transcription that raised from the wrong line is a
 * residual rather than a plausible-looking transcript. */
static void layer_drain(const char *tag)
{
    unsigned long e;
    const char *file = NULL, *func = NULL, *data = NULL;
    int line = 0, flags = 0, k = 0;
    char key[96];

    while ((e = ERR_get_error_all(&file, &line, &func, &data, &flags)) != 0) {
        snprintf(key, sizeof(key), "%s.err%d", tag, k);
        printf("%s.lib=%d\n", key, ERR_GET_LIB(e));
        printf("%s.reason=%d\n", key, ERR_GET_REASON(e));
        emit_text(key, "file", file);
        printf("%s.line=%d\n", key, line);
        emit_text(key, "func", func);
        k++;
    }
    printf("%s.err_count=%d\n", tag, k);
}

/* A group's parameters rebuilt as an explicit one, for the two `EC_GROUP_*_params` exports. */
static void group_params_arms(const EC_GROUP *named, BN_CTX *bctx)
{
    OSSL_PARAM_BLD *bld;
    OSSL_PARAM *params;
    EC_GROUP *round;

    bld = OSSL_PARAM_BLD_new();
    if (bld == NULL) {
        printf("gparams.bld=0\n");
        return;
    }
    printf("gparams.bld=1\n");
    params = EC_GROUP_to_params(named, NULL, NULL, bctx);
    printf("gparams.to_params=%d\n", params != NULL);
    OSSL_PARAM_BLD_free(bld);
    if (params == NULL)
        return;
    round = EC_GROUP_new_from_params(params, NULL, NULL);
    printf("gparams.from_params=%d\n", round != NULL);
    if (round != NULL) {
        printf("gparams.cmp=%d\n", EC_GROUP_cmp(named, round, bctx));
        printf("gparams.field=%d\n", EC_GROUP_get_field_type(round));
        EC_GROUP_free(round);
    }
    OPENSSL_free(params);
}

int main(void)
{
    size_t n, i;
    EC_builtin_curve one[2];

    /* One line per observation, so a crash on either side is located by the last line rather
     * than by a block-sized guess. */
    setvbuf(stdout, NULL, _IOLBF, 0);
    EC_builtin_curve *table;
    char tag[64];

    /* The four call shapes, in the authority's own order of tests: the NULL table and the
     * zero-length one both answer the length without writing; the one-entry one answers the length
     * having written exactly one row, and the second entry is still the sentinel it was. */
    n = EC_get_builtin_curves(NULL, 0);
    printf("count=%zu\n", n);
    printf("count.nitems0=%zu\n", EC_get_builtin_curves(one, 0));
    printf("count.null.nitems1=%zu\n", EC_get_builtin_curves(NULL, 1));
    printf("count.short=%zu\n", EC_get_builtin_curves(one, 1));
    printf("short.nid=%d\n", one[0].nid);
    emit_text("short", "comment", one[0].comment);
    emit_text("short", "sn", OBJ_nid2sn(one[0].nid));
    printf("short.tail=%d,%d\n", one[1].nid, one[1].comment == NULL ? 1 : 0);

    table = malloc(n * sizeof(*table));
    if (table == NULL) {
        printf("alloc=failed\n");
        return 0;
    }
    /* The two unused entries, so that "only `min` are written" is observed rather than assumed. */
    printf("count.full=%zu\n", EC_get_builtin_curves(table, n));

    /* Every row, in the table's own order. */
    for (i = 0; i < n; i++) {
        snprintf(tag, sizeof(tag), "row%.3zu", i);
        printf("%s.nid=%d\n", tag, table[i].nid);
        emit_text(tag, "sn", OBJ_nid2sn(table[i].nid));
        emit_text(tag, "comment", table[i].comment);
        emit_nid2nist(table[i].nid);
        emit_nid2name(table[i].nid);
    }

    emit_refusals();

    /* The fifteen NIST spellings, both directions of the pair. */
    {
        static const char *const nist[] = {
            "B-163", "B-233", "B-283", "B-409", "B-571",
            "K-163", "K-233", "K-283", "K-409", "K-571",
            "P-192", "P-224", "P-256", "P-384", "P-521",
        };
        size_t k;

        for (k = 0; k < sizeof(nist) / sizeof(nist[0]); k++) {
            emit_nist2nid(nist[k]);
            emit_nid2nist(EC_curve_nist2nid(nist[k]));
            emit_nid2name(EC_curve_nist2nid(nist[k]));
        }
    }

    /* The refusals of the case-sensitive walk. */
    emit_nist2nid("p-256");
    emit_nist2nid("b-163");
    emit_nist2nid("P-256 ");
    emit_nist2nid("P-999");
    emit_nist2nid("secp256k1");
    emit_nist2nid("SM2");
    emit_nist2nid("");
    /* One name longer than any row, so the walk's comparison and its fall-through are both crossed
     * on a string that no row's prefix can make equal. */
    emit_nist2nid("P-256-with-a-very-long-suffix-that-matches-no-row-at-all");

    /* The refusals above raise nothing -- neither lookup raises -- so the queue is empty here. It
     * is counted rather than asserted, because a count is a diff and an assertion is not. */
    {
        unsigned long e;
        int records = 0;

        while ((e = ERR_get_error()) != 0) {
            records++;
            (void)e;
        }
        printf("err.queue_records=%d\n", records);
    }


/* ==================== Phase 8.7's remaining layer ==================== */
/* Every export the group object, the field arithmetic, the point encoders, the key layer, the
 * two signature/shared-secret units and the provider backend newly reach. A method table is
 * compared by comparison against the four constructors called below, never by address, and no
 * private key, shared secret, `k` or blinding factor is printed: the ECDH arm prints the two
 * sides' agreement and the length, and the ECDSA arm prints lengths, return codes and the
 * re-encoded round trip's equality. */
{
    const EC_METHOD *t0 = EC_GFp_simple_method();
    const EC_METHOD *t1 = EC_GFp_mont_method();
    const EC_METHOD *t2 = EC_GFp_nist_method();
    const EC_METHOD *t3 = EC_GF2m_simple_method();
    BN_CTX *bctx = BN_CTX_new();
    BIGNUM *bp = NULL, *ba = NULL, *bb = NULL, *bo = NULL, *bc = NULL;
    EC_GROUP *g = NULL, *g2 = NULL, *gexp = NULL;
    EC_POINT *P = NULL, *Q = NULL, *Rs = NULL;
    EC_KEY *key = NULL, *key2 = NULL;
    unsigned char *mem = NULL;
    unsigned int tk = 0, tk1 = 0, tk2 = 0, tk3 = 0;

    printf("layer.ctx=%d\n", bctx != NULL);
    if (bctx == NULL)
        goto layer_done;

    /* ---- the four method tables ---- */
    printf("method.0.field_type=%d\n", EC_METHOD_get_field_type(t0));
    printf("method.1.field_type=%d\n", EC_METHOD_get_field_type(t1));
    printf("method.2.field_type=%d\n", EC_METHOD_get_field_type(t2));
    printf("method.3.field_type=%d\n", EC_METHOD_get_field_type(t3));
    printf("method.distinct=%d%d%d%d%d%d\n",
           t0 != t1, t0 != t2, t0 != t3, t1 != t2, t1 != t3, t2 != t3);

    /* ---- EC_GROUP_new and the group accessors on a bare group ---- */
    g = EC_GROUP_new(t0);
    printf("group_new.0=%d\n", g != NULL);
    if (g != NULL) {
        printf("group_new.0.method_simple=%d\n", EC_GROUP_method_of(g) == t0);
        printf("group_new.0.asn1_flag=%d\n", EC_GROUP_get_asn1_flag(g));
        printf("group_new.0.conv_form=%d\n", EC_GROUP_get_point_conversion_form(g));
        printf("group_new.0.order_bits=%d\n", EC_GROUP_order_bits(g));
        printf("group_new.0.field=%d\n", EC_GROUP_get_field_type(g));
        printf("group_new.0.degree=%d\n", EC_GROUP_get_degree(g));
        printf("group_new.0.basis=%d\n", EC_GROUP_get_basis_type(g));
        printf("group_new.0.check_named=%d\n", EC_GROUP_check_named_curve(g, 0, bctx));
        printf("group_new.0.seed_len=%zu\n", EC_GROUP_get_seed_len(g));
        EC_GROUP_free(g);
    }
    g = EC_GROUP_new(t3);
    printf("group_new.3=%d\n", g != NULL);
    if (g != NULL) {
        printf("group_new.3.method_gf2m=%d\n", EC_GROUP_method_of(g) == t3);
        EC_GROUP_clear_free(g);
    }
    g = NULL;

    /* ---- every built-in curve ---- */
    for (i = 0; i < n; i++) {
        snprintf(tag, sizeof(tag), "cgrp%.3zu", i);
        g = EC_GROUP_new_by_curve_name(table[i].nid);
        printf("%s.ok=%d\n", tag, g != NULL);
        if (g == NULL)
            continue;
        printf("%s.field=%d\n", tag, EC_GROUP_get_field_type(g));
        printf("%s.degree=%d\n", tag, EC_GROUP_get_degree(g));
        printf("%s.order_bits=%d\n", tag, EC_GROUP_order_bits(g));
        bo = BN_new();
        printf("%s.get_order=%d\n", tag, EC_GROUP_get_order(g, bo, bctx));
        printf("%s.order_width=%d\n", tag, bo != NULL ? BN_num_bits(bo) : -1);
        BN_free(bo);
        bo = NULL;
        bc = (BIGNUM *)EC_GROUP_get0_cofactor(g);
        printf("%s.cofactor_word=%lu\n", tag, bc != NULL ? BN_get_word(bc) : 0UL);
        printf("%s.seed_len=%zu\n", tag, EC_GROUP_get_seed_len(g));
        printf("%s.name=%d\n", tag, EC_GROUP_get_curve_name(g));
        printf("%s.gen=%d\n", tag, EC_GROUP_get0_generator(g) != NULL);
        printf("%s.field0=%d\n", tag, EC_GROUP_get0_field(g) != NULL);
        printf("%s.mont=%d\n", tag, EC_GROUP_get_mont_data(g) != NULL);
        printf("%s.basis=%d\n", tag, EC_GROUP_get_basis_type(g));
        tk = tk1 = tk2 = tk3 = 0;
        printf("%s.trinomial=%d,%u\n", tag,
               EC_GROUP_get_trinomial_basis(g, &tk), tk);
        printf("%s.pentanomial=%d,%u,%u,%u\n", tag,
               EC_GROUP_get_pentanomial_basis(g, &tk1, &tk2, &tk3), tk1, tk2, tk3);
        if (table[i].nid != NID_X9_62_prime256v1)
            printf("%s.have_precomp=%d\n", tag, EC_GROUP_have_precompute_mult(g));
        if (table[i].nid != NID_X9_62_prime256v1) {
            const EC_METHOD *m = EC_GROUP_method_of(g);
            printf("%s.method=%d%d%d%d\n", tag, m == t0, m == t1, m == t2, m == t3);
        }
        EC_GROUP_free(g);
        g = NULL;
    }

    /* ---- the group checker and the discriminant, on the two named groups ---- */
    {
        EC_GROUP *gc = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
        EC_GROUP *gb = EC_GROUP_new_by_curve_name(NID_sect163k1);
        printf("check.prime=%d\n", gc != NULL && EC_GROUP_check(gc, bctx));
        printf("check.prime_disc=%d\n",
               gc != NULL && EC_GROUP_check_discriminant(gc, bctx));
        printf("check.binary=%d\n", gb != NULL && EC_GROUP_check(gb, bctx));
        printf("check.binary_disc=%d\n",
               gb != NULL && EC_GROUP_check_discriminant(gb, bctx));
        printf("check.named=%d\n", gc != NULL && EC_GROUP_check_named_curve(gc, 0, bctx));
        printf("check.named_nist_only=%d\n",
               gc != NULL && EC_GROUP_check_named_curve(gc, 1, bctx));
        EC_GROUP_free(gc);
        EC_GROUP_free(gb);
    }

    /* ---- the two curve constructors, over two named curves ---- */
    g2 = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    bp = BN_new();
    ba = BN_new();
    bb = BN_new();
    bo = BN_new();
    bc = BN_new();
    printf("curve.new_by_curve_name_ex=%d\n",
           EC_GROUP_new_by_curve_name_ex(NULL, NULL, NID_X9_62_prime256v1) != NULL);
    printf("curve.get0_order=%d\n", EC_GROUP_get0_order(g2) != NULL);
    printf("curve.get=%d\n", EC_GROUP_get_curve(g2, bp, ba, bb, bctx));
    printf("curve.get_wrapper_gfp=%d\n", EC_GROUP_get_curve_GFp(g2, bp, ba, bb, bctx));
    printf("curve.get_order=%d\n", EC_GROUP_get_order(g2, bo, bctx));
    printf("curve.get_cofactor=%d\n", EC_GROUP_get_cofactor(g2, bc, bctx));
    printf("curve.p_width=%d\n", BN_num_bits(bp));
    printf("curve.order_width=%d\n", BN_num_bits(bo));

    gexp = EC_GROUP_new_curve_GFp(bp, ba, bb, bctx);
    printf("curve.new_gfp=%d\n", gexp != NULL);
    if (gexp != NULL) {
        printf("curve.new_gfp.field=%d\n", EC_GROUP_get_field_type(gexp));
        printf("curve.new_gfp.degree=%d\n", EC_GROUP_get_degree(gexp));
        printf("curve.new_gfp.set_curve=%d\n", EC_GROUP_set_curve(gexp, bp, ba, bb, bctx));
        printf("curve.new_gfp.set_curve_wrapper=%d\n", EC_GROUP_set_curve_GFp(gexp, bp, ba, bb, bctx));
        printf("curve.new_gfp.set_generator=%d\n",
               EC_GROUP_set_generator(gexp, EC_GROUP_get0_generator(g2), bo, bc));
        EC_GROUP_set_curve_name(gexp, NID_X9_62_prime256v1);
        printf("curve.new_gfp.name=%d\n", EC_GROUP_get_curve_name(gexp));
        printf("curve.new_gfp.cmp_named=%d\n", EC_GROUP_cmp(g2, gexp, bctx));
        EC_GROUP_free(gexp);
        gexp = NULL;
    }
    {
        EC_GROUP *gb = EC_GROUP_new_by_curve_name(NID_sect163k1);
        BIGNUM *p2 = BN_new(), *a2 = BN_new(), *b2 = BN_new(), *o2 = BN_new(), *c2 = BN_new();
        if (gb != NULL) {
            printf("gf2m.get_curve=%d\n", EC_GROUP_get_curve(gb, p2, a2, b2, bctx));
            printf("gf2m.get_curve_wrapper=%d\n", EC_GROUP_get_curve_GF2m(gb, p2, a2, b2, bctx));
            printf("gf2m.get_order=%d\n", EC_GROUP_get_order(gb, o2, bctx));
            printf("gf2m.get_cofactor=%d\n", EC_GROUP_get_cofactor(gb, c2, bctx));
            printf("gf2m.set_curve_wrapper=%d\n", EC_GROUP_set_curve_GF2m(gb, p2, a2, b2, bctx));
            gexp = EC_GROUP_new_curve_GF2m(p2, a2, b2, bctx);
            printf("gf2m.new=%d\n", gexp != NULL);
            if (gexp != NULL) {
                printf("gf2m.new.field=%d\n", EC_GROUP_get_field_type(gexp));
                printf("gf2m.new.set_generator=%d\n",
                       EC_GROUP_set_generator(gexp, EC_GROUP_get0_generator(gb), o2, c2));
                EC_GROUP_set_curve_name(gexp, NID_sect163k1);
                printf("gf2m.new.cmp_named=%d\n", EC_GROUP_cmp(gb, gexp, bctx));
                EC_GROUP_free(gexp);
                gexp = NULL;
            }
        }
        BN_free(p2);
        BN_free(a2);
        BN_free(b2);
        BN_free(o2);
        BN_free(c2);
        EC_GROUP_free(gb);
    }

    /* ---- group copying, the seed and the ASN.1 flag ---- */
    {
        static const unsigned char seed[3] = { 1, 2, 3 };
        EC_GROUP *gc = EC_GROUP_dup(g2);
        printf("group.dup=%d\n", gc != NULL);
        if (gc != NULL) {
            printf("group.dup.cmp=%d\n", EC_GROUP_cmp(gc, g2, bctx));
            printf("group.copy=%d\n", EC_GROUP_copy(gc, g2));
            printf("group.set_seed=%zu\n", EC_GROUP_set_seed(gc, seed, sizeof(seed)));
            printf("group.seed_len=%zu\n", EC_GROUP_get_seed_len(gc));
            printf("group.seed0=%d\n", EC_GROUP_get0_seed(gc) != NULL);
            EC_GROUP_set_asn1_flag(gc, OPENSSL_EC_EXPLICIT_CURVE);
            printf("group.asn1_explicit=%d\n", EC_GROUP_get_asn1_flag(gc));
            EC_GROUP_set_asn1_flag(gc, OPENSSL_EC_NAMED_CURVE);
            printf("group.asn1_named=%d\n", EC_GROUP_get_asn1_flag(gc));
            EC_GROUP_set_point_conversion_form(gc, POINT_CONVERSION_COMPRESSED);
            printf("group.conv=%d\n", EC_GROUP_get_point_conversion_form(gc));
            EC_GROUP_set_point_conversion_form(gc, POINT_CONVERSION_UNCOMPRESSED);
            printf("group.precompute=%d\n", EC_GROUP_precompute_mult(gc, bctx));
            printf("group.have_precomp=%d\n", EC_GROUP_have_precompute_mult(gc));
            EC_GROUP_free(gc);
        }
        printf("group.dup_null=%d\n", EC_GROUP_dup(NULL) == NULL);
    }

    /* ---- the point object: accessors, arithmetic, encoders ---- */
    P = EC_POINT_new(g2);
    Q = EC_POINT_new(g2);
    Rs = EC_POINT_new(g2);
    printf("point.new=%d\n", P != NULL && Q != NULL && Rs != NULL);
    printf("point.method=%d\n", EC_POINT_method_of(P) == EC_GROUP_method_of(g2));
    printf("point.copy=%d\n", EC_POINT_copy(P, EC_GROUP_get0_generator(g2)));
    printf("point.is_at_inf=%d\n", EC_POINT_is_at_infinity(g2, P));
    printf("point.is_on_curve=%d\n", EC_POINT_is_on_curve(g2, P, bctx));
    printf("point.set_to_infinity=%d\n", EC_POINT_set_to_infinity(g2, Rs));
    printf("point.inf_is_at_inf=%d\n", EC_POINT_is_at_infinity(g2, Rs));
    printf("point.inf_on_curve=%d\n", EC_POINT_is_on_curve(g2, Rs, bctx));
    printf("point.inf_invert=%d\n", EC_POINT_invert(g2, Rs, bctx));
    printf("point.add=%d\n", EC_POINT_add(g2, Q, P, P, bctx));
    printf("point.dbl=%d\n", EC_POINT_dbl(g2, Rs, P, bctx));
    printf("point.add_matches_dbl=%d\n", EC_POINT_cmp(g2, Q, Rs, bctx) == 0);
    printf("point.cmp_self=%d\n", EC_POINT_cmp(g2, P, P, bctx));
    printf("point.invert=%d\n", EC_POINT_invert(g2, Rs, bctx));
    {
        EC_POINT *pd = EC_POINT_dup(P, g2);
        printf("point.dup=%d\n", pd != NULL);
        printf("point.dup.cmp=%d\n", EC_POINT_cmp(g2, pd, P, bctx));
        printf("point.dup.is_on_curve=%d\n", EC_POINT_is_on_curve(g2, pd, bctx));
        EC_POINT_free(pd);
    }
    {
        BIGNUM *x = BN_new(), *y = BN_new();
        printf("point.get_affine=%d\n", EC_POINT_get_affine_coordinates(g2, P, x, y, bctx));
        printf("point.get_affine_gfp=%d\n",
               EC_POINT_get_affine_coordinates_GFp(g2, P, x, y, bctx));
        printf("point.set_affine=%d\n", EC_POINT_set_affine_coordinates(g2, Q, x, y, bctx));
        printf("point.set_affine_gfp=%d\n",
               EC_POINT_set_affine_coordinates_GFp(g2, Q, x, y, bctx));
        printf("point.affine_round_trip=%d\n", EC_POINT_cmp(g2, P, Q, bctx) == 0);
        printf("point.make_affine=%d\n", EC_POINT_make_affine(g2, Q, bctx));
        BN_free(x);
        BN_free(y);
    }
    {
        BIGNUM *r1 = BN_new();
        EC_POINT *arr[3];
        EC_GROUP *gb = EC_GROUP_new_by_curve_name(NID_sect163k1);
        printf("point.get_affine_gf2m=%d\n",
               gb != NULL && EC_POINT_get_affine_coordinates_GF2m(
                   gb, EC_GROUP_get0_generator(gb), NULL, NULL, bctx));
        printf("point.set_affine_gf2m=%d\n",
               gb != NULL && EC_POINT_set_affine_coordinates_GF2m(
                   gb, EC_POINT_new(gb), NULL, NULL, bctx));
        arr[0] = P;
        arr[1] = Q;
        arr[2] = Rs;
        printf("point.points_make_affine=%d\n", EC_POINTs_make_affine(g2, 3, arr, bctx));
        printf("point.jproj_get=%d\n",
               EC_POINT_get_Jprojective_coordinates_GFp(g2, P, r1, r1, r1, bctx));
        printf("point.jproj_set=%d\n",
               EC_POINT_set_Jprojective_coordinates_GFp(g2, Q, r1, r1, r1, bctx));
        BN_free(r1);
        EC_GROUP_free(gb);
    }
    {
        size_t len = EC_POINT_point2oct(g2, P, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, bctx);
        printf("point.oct_len=%zu\n", len);
        if (len > 0 && len < 512) {
            mem = malloc(len);
            printf("point.point2oct=%zu\n",
                   EC_POINT_point2oct(g2, P, POINT_CONVERSION_UNCOMPRESSED, mem, len, bctx));
            printf("point.oct2point=%d\n", EC_POINT_oct2point(g2, Rs, mem, len, bctx));
            printf("point.oct_round_trip=%d\n", EC_POINT_cmp(g2, P, Rs, bctx) == 0);
            free(mem);
            mem = NULL;
        }
        printf("point.point2buf=%zu\n",
               EC_POINT_point2buf(g2, P, POINT_CONVERSION_UNCOMPRESSED, &mem, bctx));
        if (mem != NULL)
            OPENSSL_free(mem);
        mem = NULL;
        printf("point.compressed_set=%d\n",
               EC_POINT_set_compressed_coordinates(g2, Rs, BN_value_one(), 0, bctx));
        printf("point.compressed_set_gfp=%d\n",
               EC_POINT_set_compressed_coordinates_GFp(g2, Rs, BN_value_one(), 0, bctx));
    }
    {
        EC_GROUP *gb = EC_GROUP_new_by_curve_name(NID_sect163k1);
        EC_POINT *pb = gb != NULL ? EC_POINT_new(gb) : NULL;
        printf("point.compressed_gf2m=%d\n",
               pb != NULL && EC_POINT_set_compressed_coordinates_GF2m(gb, pb, BN_value_one(), 0, bctx));
        EC_POINT_clear_free(pb);
        EC_GROUP_free(gb);
    }
    /* the ladder arms */
    {
        BIGNUM *k = BN_new();
        const EC_POINT *points[1];
        const BIGNUM *scalars[1];
        BN_set_word(k, 7);
        points[0] = P;
        scalars[0] = k;
        printf("point.mul_ladder=%d\n", EC_POINT_mul(g2, Rs, k, NULL, NULL, bctx));
        printf("point.mul_generator_array=%d\n", EC_POINT_mul(g2, Rs, NULL, P, k, bctx));
        printf("point.mul_null_n=%d\n", EC_POINT_mul(g2, Rs, k, P, NULL, bctx));
        printf("point.mul_both_null=%d\n", EC_POINT_mul(g2, Rs, NULL, NULL, NULL, bctx));
        printf("point.mul_both_null_inf=%d\n", EC_POINT_is_at_infinity(g2, Rs));
        printf("point.points_mul=%d\n", EC_POINTs_mul(g2, Rs, k, 1, points, scalars, bctx));
        BN_free(k);
    }

    /* ---- one refusal with its drained coordinate ---- */
    {
        EC_GROUP *other = EC_GROUP_new_by_curve_name(NID_secp384r1);
        if (other != NULL && P != NULL) {
            printf("refusal.incompatible=%d\n", EC_POINT_is_on_curve(other, P, bctx));
            EC_GROUP_free(other);
        }
    }
    layer_drain("refusal.point");

    /* ---- the provider backend's two group-parameter exports ---- */
    group_params_arms(g2, bctx);
    layer_drain("gparams");

    /* ---- the key layer ---- */
    key = EC_KEY_new_by_curve_name_ex(NULL, NULL, NID_X9_62_prime256v1);
    printf("key.new_by_curve_name_ex=%d\n", key != NULL);
    printf("key.new_by_curve_name=%d\n",
           EC_KEY_new_by_curve_name(NID_X9_62_prime256v1) != NULL);
    key2 = EC_KEY_new();
    printf("key.new_meth=%d\n", EC_KEY_new_method(NULL) != NULL);
    printf("key.new_ex=%d\n", EC_KEY_new_ex(NULL, NULL) != NULL);
    printf("key.method_is_default=%d\n", EC_KEY_get_method(key) == EC_KEY_OpenSSL());
    printf("key.default_is_openssl=%d\n", EC_KEY_get_default_method() == EC_KEY_OpenSSL());
    printf("key.can_sign=%d\n", EC_KEY_can_sign(key));
    printf("key.get0_engine_null=%d\n", EC_KEY_get0_engine(key) == NULL);
    printf("key.decoded_from_explicit=%d\n", EC_KEY_decoded_from_explicit_params(key));
    printf("key.set_ex_data=%d\n", EC_KEY_set_ex_data(key, 0, NULL));
    printf("key.get_ex_data=%d\n", EC_KEY_get_ex_data(key, 0) == NULL);
    printf("key.up_ref=%d\n", EC_KEY_up_ref(key));
    printf("key.enc_flags_default=%u\n", EC_KEY_get_enc_flags(key));
    EC_KEY_set_enc_flags(key, EC_PKEY_NO_PUBKEY);
    printf("key.enc_flags_set=%u\n", EC_KEY_get_enc_flags(key) & EC_PKEY_NO_PUBKEY);
    EC_KEY_set_enc_flags(key, 0);
    EC_KEY_set_asn1_flag(key, OPENSSL_EC_NAMED_CURVE);
    printf("key.conv_form=%d\n", EC_KEY_get_conv_form(key));
    EC_KEY_set_conv_form(key, POINT_CONVERSION_COMPRESSED);
    printf("key.conv_form2=%d\n", EC_KEY_get_conv_form(key));
    EC_KEY_set_conv_form(key, POINT_CONVERSION_UNCOMPRESSED);
    printf("key.set_method=%d\n", (EC_KEY_set_method(key2, EC_KEY_OpenSSL()),
                                   EC_KEY_get_method(key2) == EC_KEY_OpenSSL()));
    EC_KEY_set_default_method(EC_KEY_OpenSSL());
    printf("key.set_default=%d\n", EC_KEY_get_default_method() == EC_KEY_OpenSSL());
    printf("key.set_flags=%d\n",
           (EC_KEY_set_flags(key, EC_FLAG_COFACTOR_ECDH), EC_KEY_get_flags(key)));
    EC_KEY_clear_flags(key, EC_FLAG_COFACTOR_ECDH);
    printf("key.clear_flags=%d\n", EC_KEY_get_flags(key));

    printf("key.generate=%d\n", EC_KEY_generate_key(key));
    printf("key.check_key=%d\n", EC_KEY_check_key(key));
    printf("key.pub_on_curve=%d\n",
           EC_POINT_is_on_curve(EC_KEY_get0_group(key), EC_KEY_get0_public_key(key), bctx));
    printf("key.priv_present=%d\n", EC_KEY_get0_private_key(key) != NULL);
    printf("key.set_group=%d\n", EC_KEY_set_group(key2, EC_KEY_get0_group(key)));
    printf("key.set_public=%d\n", EC_KEY_set_public_key(key2, EC_KEY_get0_public_key(key)));
    printf("key.set_private=%d\n",
           EC_KEY_set_private_key(key2, EC_KEY_get0_private_key(key)));
    printf("key2.check_key=%d\n", EC_KEY_check_key(key2));
    printf("key.precompute=%d\n", EC_KEY_precompute_mult(key, bctx));
    {
        BIGNUM *x = BN_new(), *y = BN_new();
        EC_KEY *key3 = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        printf("key.affine=%d\n",
               EC_POINT_get_affine_coordinates(EC_KEY_get0_group(key),
                                               EC_KEY_get0_public_key(key), x, y, bctx)
               && EC_KEY_set_public_key_affine_coordinates(key3, x, y));
        printf("key3.check_key=%d\n", EC_KEY_check_key(key3));
        BN_free(x);
        BN_free(y);
        EC_KEY_free(key3);
    }

    /* the private scalar's and the public key's octet and buffer spellings */
    {
        size_t n1, n2, n3;
        unsigned char *o1 = NULL, *o2 = NULL, *o3 = NULL;
        n1 = EC_KEY_priv2oct(key, NULL, 0);
        printf("key.priv2oct_len=%zu\n", n1);
        if (n1 > 0 && n1 < 512) {
            o1 = malloc(n1);
            printf("key.priv2oct=%zu\n", EC_KEY_priv2oct(key, o1, n1));
            printf("key.oct2priv=%d\n", EC_KEY_oct2priv(key2, o1, n1));
            printf("key.priv_round_trip=%d\n",
                   EC_KEY_get0_private_key(key) != NULL
                   && EC_KEY_get0_private_key(key2) != NULL
                   && BN_cmp(EC_KEY_get0_private_key(key),
                             EC_KEY_get0_private_key(key2)) == 0);
        }
        n2 = EC_KEY_priv2buf(key, &o2);
        printf("key.priv2buf=%zu\n", n2);
        printf("key.priv2buf_matches=%d\n",
               o1 != NULL && o2 != NULL && n1 == n2 && memcmp(o1, o2, n1) == 0);
        n3 = EC_KEY_key2buf(key, POINT_CONVERSION_UNCOMPRESSED, &o3, bctx);
        printf("key.key2buf=%zu\n", n3);
        printf("key.oct2key=%d\n", EC_KEY_oct2key(key2, o3, n3, bctx));
        printf("key.pub_round_trip=%d\n",
               EC_POINT_cmp(EC_KEY_get0_group(key), EC_KEY_get0_public_key(key),
                            EC_KEY_get0_public_key(key2), bctx) == 0);
        free(o1);
        OPENSSL_free(o2);
        OPENSSL_free(o3);
    }
    {
        EC_KEY *kd = EC_KEY_dup(key);
        printf("key.dup=%d\n", kd != NULL);
        if (kd != NULL) {
            printf("key.dup.check=%d\n", EC_KEY_check_key(kd));
            EC_KEY_free(kd);
        }
        key2 = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        printf("key.copy=%d\n", EC_KEY_copy(key2, key) != NULL);
        printf("key.copy.check=%d\n", EC_KEY_check_key(key2));
        EC_KEY_free(key2);
        key2 = NULL;
    }

    /* ---- the EC_KEY_METHOD table, built by the probe itself ---- */
    {
        EC_KEY_METHOD *meth = EC_KEY_METHOD_new(NULL);
        int (*gi)(EC_KEY *);
        void (*gf)(EC_KEY *);
        int (*gc)(EC_KEY *, const EC_KEY *);
        int (*gg)(EC_KEY *, const EC_GROUP *);
        int (*gp)(EC_KEY *, const BIGNUM *);
        int (*gpub)(EC_KEY *, const EC_POINT *);

        EC_KEY_METHOD_set_init(meth, NULL, NULL, NULL, NULL, NULL, NULL);
        EC_KEY_METHOD_set_keygen(meth, NULL);
        EC_KEY_METHOD_set_compute_key(meth, NULL);
        EC_KEY_METHOD_set_sign(meth, NULL, NULL, NULL);
        EC_KEY_METHOD_set_verify(meth, NULL, NULL);
        printf("keymeth.new=%d\n", meth != NULL);
        EC_KEY_METHOD_get_init(meth, &gi, &gf, &gc, &gg, &gp, &gpub);
        printf("keymeth.set_init_all_null=%d\n", gi == NULL && gf == NULL && gc == NULL
               && gg == NULL && gp == NULL && gpub == NULL);
        EC_KEY_METHOD_get_keygen(meth, NULL);
        EC_KEY_METHOD_get_compute_key(meth, NULL);
        EC_KEY_METHOD_get_sign(meth, NULL, NULL, NULL);
        EC_KEY_METHOD_get_verify(meth, NULL, NULL);
        printf("keymeth.get_all=%d\n",
               gi == NULL && gf == NULL && gc == NULL && gg == NULL && gp == NULL
               && gpub == NULL);
        EC_KEY_METHOD_free(meth);
    }

    /* ---- ECDSA ---- */
    {
        static const unsigned char dgst[32] = { 9, 8, 7, 6, 5, 4, 3, 2, 1 };
        unsigned int siglen = 0;

        {
            ECDSA_SIG *fresh = ECDSA_SIG_new();
            BIGNUM *r0 = BN_new(), *s0 = BN_new();
            printf("ecdsa.sig_new=%d\n", fresh != NULL);
            printf("ecdsa.sig_set0=%d\n", ECDSA_SIG_set0(fresh, r0, s0));
            ECDSA_SIG_free(fresh);
        }
        printf("ecdsa.size=%d\n", ECDSA_size(key));
        printf("ecdsa.sign_null_size=%d\n",
               ECDSA_sign(0, dgst, sizeof(dgst), NULL, &siglen, key));
        printf("ecdsa.size_matches=%d\n", (int)siglen == ECDSA_size(key));
        mem = malloc(siglen > 0 ? siglen : 1);
        printf("ecdsa.sign=%d\n", ECDSA_sign(0, dgst, sizeof(dgst), mem, &siglen, key));
        printf("ecdsa.verify=%d\n", ECDSA_verify(0, dgst, sizeof(dgst), mem, (int)siglen, key));
        printf("ecdsa.verify_wrong=%d\n",
               ECDSA_verify(0, dgst + 1, sizeof(dgst) - 1, mem, (int)siglen, key));
        {
            ECDSA_SIG *es = ECDSA_do_sign(dgst, sizeof(dgst), key);
            unsigned char *der = NULL;
            int derlen;
            printf("ecdsa.do_sign=%d\n", es != NULL);
            printf("ecdsa.do_verify=%d\n", ECDSA_do_verify(dgst, sizeof(dgst), es, key));
            {
                const BIGNUM *er = NULL, *es_ = NULL;
                ECDSA_SIG_get0(es, &er, &es_);
                printf("ecdsa.parts=%d\n", er != NULL && es_ != NULL);
            }
            /* The encoded length is *not* printed: a `r` or `s` with its top bit set gains a
             * leading zero byte, so the length of a fresh signature varies run to run. Only the
             * positivity, the decode and the re-encoded round trip are observations. */
            derlen = i2d_ECDSA_SIG(es, NULL);
            printf("ecdsa.i2d_null_pos=%d\n", derlen > 0);
            der = malloc(derlen > 0 ? derlen : 1);
            printf("ecdsa.i2d_pos=%d\n", i2d_ECDSA_SIG(es, &der) > 0);
            {
                const unsigned char *p = der - derlen;
                ECDSA_SIG *es2 = d2i_ECDSA_SIG(NULL, &p, derlen);
                printf("ecdsa.d2i=%d\n", es2 != NULL);
                if (es2 != NULL) {
                    const BIGNUM *r1 = NULL, *s1 = NULL, *r2 = NULL, *s2 = NULL;
                    ECDSA_SIG_get0(es, &r1, &s1);
                    ECDSA_SIG_get0(es2, &r2, &s2);
                    printf("ecdsa.round_trip=%d\n",
                           r1 != NULL && s1 != NULL && r2 != NULL && s2 != NULL
                           && BN_cmp(r1, r2) == 0 && BN_cmp(s1, s2) == 0);
                    ECDSA_SIG_free(es2);
                }
                free(der - derlen);
            }
            ECDSA_SIG_free(es);
        }
        {
            BIGNUM *kinv = NULL, *rp = NULL;
            unsigned int klen;
            unsigned char *kbuf;
            ECDSA_SIG *es;
            printf("ecdsa.sign_setup=%d\n", ECDSA_sign_setup(key, bctx, &kinv, &rp));
            printf("ecdsa.sign_setup_parts=%d\n", kinv != NULL && rp != NULL);
            klen = (unsigned int)ECDSA_size(key);
            kbuf = malloc(klen);
            es = ECDSA_do_sign_ex(dgst, sizeof(dgst), kinv, rp, key);
            printf("ecdsa.do_sign_ex=%d\n", es != NULL);
            ECDSA_SIG_free(es);
            printf("ecdsa.sign_ex=%d\n",
                   ECDSA_sign_ex(0, dgst, sizeof(dgst), kbuf, &klen, kinv, rp, key));
            printf("ecdsa.verify_ex=%d\n",
                   ECDSA_verify(0, dgst, sizeof(dgst), kbuf, (int)klen, key));
            free(kbuf);
            BN_clear_free(kinv);
            BN_clear_free(rp);
        }
    }
    layer_drain("ecdsa");

    /* ---- ECDH: agreement and length only ---- */
    {
        EC_KEY *peer = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        unsigned char *s1 = NULL, *s2 = NULL;
        size_t l1 = 0, l2 = 0, need = 0, q1 = 0, q2 = 0;
        printf("ecdh.peer_gen=%d\n", peer != NULL && EC_KEY_generate_key(peer));
        if (peer != NULL) {
            const EC_POINT *pub1 = EC_KEY_get0_public_key(peer);
            q1 = EC_POINT_point2oct(EC_KEY_get0_group(peer), pub1,
                                    POINT_CONVERSION_UNCOMPRESSED, NULL, 0, bctx);
            need = q1 > 0 ? q1 : 64;
            s1 = malloc(need);
            s2 = malloc(need);
            l1 = ECDH_compute_key(s1, need, pub1, key, NULL);
            l2 = ECDH_compute_key(s2, need, EC_KEY_get0_public_key(key), peer, NULL);
            q2 = EC_POINT_point2oct(EC_KEY_get0_group(key), EC_KEY_get0_public_key(key),
                                    POINT_CONVERSION_UNCOMPRESSED, NULL, 0, bctx);
            printf("ecdh.len=%zu\n", l1);
            printf("ecdh.peer_len=%zu\n", l2);
            printf("ecdh.pub_widths=%zu,%zu\n", q1, q2);
            printf("ecdh.agree=%d\n", l1 != 0 && l1 == l2 && memcmp(s1, s2, l1) == 0);
            /* the secret itself is never printed */
            free(s1);
            free(s2);
            EC_KEY_free(peer);
        }
    }

    layer_drain("layer");

layer_done:
    if (bctx != NULL)
        BN_CTX_free(bctx);
    BN_free(bp);
    BN_free(ba);
    BN_free(bb);
    BN_free(bo);
    BN_free(bc);
    EC_GROUP_free(g);
    EC_GROUP_free(g2);
    EC_GROUP_free(gexp);
    EC_POINT_free(P);
    EC_POINT_free(Q);
    EC_POINT_free(Rs);
    EC_KEY_free(key);
    EC_KEY_free(key2);
    free(mem);
}

    free(table);
    return 0;
}
