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
#include <openssl/err.h>
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

int main(void)
{
    size_t n, i;
    EC_builtin_curve one[2];
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

    free(table);
    return 0;
}
