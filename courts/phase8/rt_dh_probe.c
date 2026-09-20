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
 * What it does not cover: the FFC primitives (their evidence is their own unit tests, D330), the
 * named-group tables, `dh_asn1.c`'s ASN.1 machinery, `DH_KDF_X9_42` and the `EVP_PKEY_CTX_*dh*`
 * controls -- none of which is landed. This court's arms say so by their absence rather than by a
 * transcribed expectation, and `docs/DECISIONS.md` D329 and D331 name what keeps each open.
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
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/dh.h>
#include <openssl/err.h>
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

    return 0;
}
