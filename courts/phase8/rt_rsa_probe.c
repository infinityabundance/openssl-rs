/*
 * RT-RSA -- the differential court for `crypto/rsa/`'s method table (Phase 8.4, slice B).
 *
 * This program is compiled **twice**, once against the admitted authority and once against the
 * candidate distribution shell, and the two `key=value` transcripts are diffed. It never decides
 * anything: a residual is a difference between two executions, so the expectation cannot drift with
 * the crate. `forensics/tools/phase8_courts.py` owns the comparison.
 *
 * What this court is, and what it is not yet
 * ------------------------------------------
 * Slice B is the thirty-three `RSA_meth_*` labels plus `RSA_null_method`, and **every one of the
 * thirty-four is called below**. Nothing here does any cryptography -- each function allocates a
 * table, stores a pointer in it, or returns one -- so the transcript is about *identity and
 * ownership* rather than arithmetic, and that is the whole observable contract of these entry
 * points.
 *
 * **It is deliberately not a court for the default method.** `RSA_PKCS1_OpenSSL`, `RSA_set_method`,
 * `RSA_get_default_method` and `RSA_set_default_method` are slice A's, and until slice A lands they
 * are not symbols the candidate shell publishes, so a probe that called them would fail to link
 * rather than compare. The observations of `rsa_pkcs1_ossl_meth`'s own members -- `rsa_sign` and
 * `rsa_verify` initialised to the integer `0`, both keygen members NULL, `RSA_FLAG_FIPS_METHOD` in
 * `flags` -- therefore arrive with slice A's probe, in the commit that publishes the table. The
 * deferred observation is named here so that "not compared" cannot be read as "compared and equal".
 *
 * The allocator-attribution plane
 * -------------------------------
 * `CRYPTO_set_mem_functions`'s callbacks take `(size_t num, const char *file, int line)`, and all
 * three are part of the published contract: an embedder that installs an allocator receives them.
 * `rsa_meth.c` is a **source-tree** file, so `OPENSSL_FILE` in its bodies is
 * `../../src/openssl-3.6.4/crypto/rsa/rsa_meth.c` -- the prefix is present, unlike the `.c.in`
 * instances D279 and D280 had to distinguish. So the first thing this probe does is install an
 * allocator and record, for each arm, the **ordered sequence of `(kind, size, file)`** the library
 * requests inside a window that starts before the call and ends after it. That is how the claim
 * "this unit's allocation is attributed to this unit's translation unit" becomes a diff instead of
 * a constant in the crate.
 *
 * **The sequence, not just the set, is deliberate.** The order is load-bearing in three of these
 * arms: `RSA_meth_new` stores `flags` *before* duplicating the name, so a failed duplicate can
 * release the table; `RSA_meth_set1_name` duplicates *first* and releases second, so a failed
 * duplicate leaves the old name in place; `RSA_meth_free` releases the name *before* the table. A
 * set of `file` strings would make all three orders invisible.
 *
 * The window is a window and not a whole-program trace for the same reason `RT-CIPHER-MEM`'s is:
 * `CRYPTO_set_mem_functions` latches, and the *rest* of the process -- the error queue, stdio, the
 * warm-up -- is not what this court is about. The warm-up call before the first window is what
 * keeps the first window from containing lazy library state.
 *
 * No address is ever printed: every function pointer is compared for equality with a local
 * sentinel and the *result* is printed. stdout is line-buffered, and no NULL-dereferencing entry
 * point is called -- a probe that aborts the harness compares nothing.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/* `RSA_meth_*` and `RSA_null_method` are `OSSL_DEPRECATEDIN_3_0`. The deprecation is the
 * authority's own policy statement about application code, not about a court that must exercise
 * the entry points it declares; suppressing the diagnostic keeps `-Wall` output readable without
 * changing a single symbol this probe links. */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
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
    printf("rsa.%s.ev=%d\n", arm, nev);
    for (i = 0; i < nev; i++)
        printf("rsa.%s.ev.%d=%c:%lu:%s\n", arm, i, ev_kind[i], ev_size[i], ev_file[i]);
}

/* ------------------------------------------------------------------ sentinels */

/* One per distinct function-pointer signature in `RSA_METHOD`. They are stored and compared,
 * never called: each returns a constant so that a transcription which *did* call one would be
 * visible in the transcript rather than merely wrong. */
static int sentinel_crypt(int flen, const unsigned char *from, unsigned char *to, RSA *rsa,
    int padding)
{
    (void)flen; (void)from; (void)to; (void)rsa; (void)padding;
    return 0;
}

static int sentinel_modexp(BIGNUM *r0, const BIGNUM *i, RSA *rsa, BN_CTX *ctx)
{
    (void)r0; (void)i; (void)rsa; (void)ctx;
    return 0;
}

static int sentinel_bnmodexp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m,
    BN_CTX *ctx, BN_MONT_CTX *m_ctx)
{
    (void)r; (void)a; (void)p; (void)m; (void)ctx; (void)m_ctx;
    return 0;
}

static int sentinel_life(RSA *rsa)
{
    (void)rsa;
    return 0;
}

static int sentinel_sign(int type, const unsigned char *m, unsigned int m_length,
    unsigned char *sigret, unsigned int *siglen, const RSA *rsa)
{
    (void)type; (void)m; (void)m_length; (void)sigret; (void)siglen; (void)rsa;
    return 0;
}

static int sentinel_verify(int dtype, const unsigned char *m, unsigned int m_length,
    const unsigned char *sigbuf, unsigned int siglen, const RSA *rsa)
{
    (void)dtype; (void)m; (void)m_length; (void)sigbuf; (void)siglen; (void)rsa;
    return 0;
}

static int sentinel_keygen(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb)
{
    (void)rsa; (void)bits; (void)e; (void)cb;
    return 0;
}

static int sentinel_mpkeygen(RSA *rsa, int bits, int primes, BIGNUM *e, BN_GENCB *cb)
{
    (void)rsa; (void)bits; (void)primes; (void)e; (void)cb;
    return 0;
}

/* The twelve setter/getter pairs, each observed five ways: the member of a fresh table is NULL;
 * the setter answers 1; the getter then answers the *sentinel* rather than merely non-NULL; the
 * setter accepts NULL and still answers 1; and the getter is back to NULL. The round trip leaves
 * the member NULL, which is what lets one table serve all twelve without order dependence. */
#define ROUNDTRIP(tag, GET, SET, SENT)                                  \
    do {                                                                \
        printf("rsa.%s.get_default_is_null=%d\n", tag,                  \
            (const void *)(GET)(m) == NULL);                            \
        printf("rsa.%s.set_ret=%d\n", tag, (SET)(m, (SENT)));           \
        printf("rsa.%s.get_is_sentinel=%d\n", tag,                      \
            (const void *)(GET)(m) == (const void *)(SENT));            \
        printf("rsa.%s.set_null_ret=%d\n", tag, (SET)(m, NULL));        \
        printf("rsa.%s.get_after_null_is_null=%d\n", tag,               \
            (const void *)(GET)(m) == NULL);                            \
    } while (0)

/* ------------------------------------------------------------------ the padding primitives */

/* Drain the error queue, printing each record's **packed code and coordinate**. The packed code
 * carries the library and the reason; the coordinate is `ERR_get_error_all`'s file/line/func, which
 * is the part of the record `gen_err_raise_sites.py` derives and which a court that compared only
 * the return value could not see at all. */
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
        printf("rsa.%s.err.%d=%lu:%s:%d:%s\n", arm, n, e,
            file != NULL ? file : "(null)", line,
            func != NULL ? func : "(null)");
        n++;
    }
    printf("rsa.%s.err.count=%d\n", arm, n);
}

/* Build a valid PKCS#1 v1.5 OAEP encoding, deterministically. `RSA_padding_add_PKCS1_OAEP_mgf1`
 * itself is a Phase 9 hand-off (it draws its seed with RAND_bytes_ex), so a court that wants a
 * valid encoding to *check* has to build one -- and it can, out of primitives both sides publish:
 * `PKCS1_MGF1` and `EVP_Digest`. The seed is fixed, which is exactly what makes the arm
 * reproducible. The construction is RFC 8017 section 7.1.1: EM = 0x00 || maskedSeed || maskedDB
 * with DB = lHash || PS || 0x01 || M, maskedDB = DB ^ MGF1(seed) and maskedSeed = seed ^
 * MGF1(maskedDB). */
static int oaep_encode(unsigned char *em, int num, const unsigned char *msg, int msglen,
    const unsigned char *seed, int mdlen, const EVP_MD *md, const EVP_MD *mgf1)
{
    unsigned char db[256], dbmask[256], seedmask[64], lhash[EVP_MAX_MD_SIZE];
    int dblen = num - mdlen - 1;
    int i, pslen;

    /* The caller's buffers are sized by the arms below; only the local `db` has a fixed size. */
    if (dblen > (int)sizeof(db) || mdlen > (int)sizeof(seedmask))
        return 0;
    if (dblen < mdlen + msglen + 1)
        return 0;
    if (EVP_Digest(NULL, 0, lhash, NULL, md, NULL) != 1)
        return 0;

    memcpy(db, lhash, mdlen);
    pslen = dblen - mdlen - msglen - 1;
    memset(db + mdlen, 0, (size_t)pslen);
    db[mdlen + pslen] = 0x01;
    memcpy(db + mdlen + pslen + 1, msg, (size_t)msglen);

    if (PKCS1_MGF1(dbmask, dblen, seed, mdlen, mgf1) != 0)
        return 0;
    for (i = 0; i < dblen; i++)
        db[i] ^= dbmask[i];

    em[0] = 0x00;
    memcpy(em + 1 + mdlen, db, (size_t)dblen);

    if (PKCS1_MGF1(seedmask, mdlen, em + 1 + mdlen, dblen, mgf1) != 0)
        return 0;
    for (i = 0; i < mdlen; i++)
        em[1 + i] = (unsigned char)(seed[i] ^ seedmask[i]);
    return 1;
}

static void oaep_arms(void)
{
    /* The two OAEP checks. `RSA_padding_check_PKCS1_OAEP` is the wrapper that passes NULL for both
     * digests, which is what makes it reach `EVP_sha1()` -- the export D291 landed and the reason
     * this unit could not close before it. */
    const EVP_MD *sha1 = EVP_MD_fetch(NULL, "SHA1", NULL);
    unsigned char seed[20];
    unsigned char msg[16];
    unsigned char em[128];
    unsigned char out[128];
    int i, r;

    printf("oaep.md_fetched=%d\n", sha1 != NULL);
    if (sha1 == NULL)
        return;
    for (i = 0; i < 20; i++)
        seed[i] = (unsigned char)(0x30 + i);
    for (i = 0; i < 16; i++)
        msg[i] = (unsigned char)(0xc0 + i);

    ERR_clear_error();
    memset(em, 0, sizeof(em));
    printf("oaep.encode=%d\n", oaep_encode(em, 128, msg, 16, seed, 20, sha1, sha1));

    memset(out, 0x5a, sizeof(out));
    r = RSA_padding_check_PKCS1_OAEP_mgf1(out, 128, em, 128, 128, NULL, 0, sha1, sha1);
    printf("oaep.mgf1.ok=%d\n", r);
    printf("oaep.mgf1.body=%d\n", r == 16 && memcmp(out, msg, 16) == 0);
    drain("oaep_mgf1_ok");

    /* The wrapper: NULL digests mean SHA-1 for both, and the label is empty. */
    memset(out, 0x5a, sizeof(out));
    ERR_clear_error();
    r = RSA_padding_check_PKCS1_OAEP(out, 128, em, 128, 128, NULL, 0);
    printf("oaep.wrapper.ok=%d\n", r);
    printf("oaep.wrapper.body=%d\n", r == 16 && memcmp(out, msg, 16) == 0);
    drain("oaep_wrapper_ok");

    /* A single flipped byte in the data block must be refused through the implicit-rejection
     * path, which is where `RSA_R_OAEP_DECODING_ERROR` and the constant-time flag clearing live. */
    ERR_clear_error();
    em[1 + 20 + 30] ^= 0x01;
    memset(out, 0x5a, sizeof(out));
    printf("oaep.flipped=%d\n", RSA_padding_check_PKCS1_OAEP_mgf1(out, 128, em, 128, 128,
        NULL, 0, sha1, sha1));
    drain("oaep_flipped");

    /* A first byte that is not zero, and the two size refusals. */
    printf("oaep.encode2=%d\n", oaep_encode(em, 128, msg, 16, seed, 20, sha1, sha1));
    ERR_clear_error();
    em[0] = 0x01;
    printf("oaep.first=%d\n", RSA_padding_check_PKCS1_OAEP_mgf1(out, 128, em, 128, 128,
        NULL, 0, sha1, sha1));
    drain("oaep_first");
    printf("oaep.encode3=%d\n", oaep_encode(em, 128, msg, 16, seed, 20, sha1, sha1));
    ERR_clear_error();
    printf("oaep.short_num=%d\n", RSA_padding_check_PKCS1_OAEP_mgf1(out, 128, em, 128, 40,
        NULL, 0, sha1, sha1));
    drain("oaep_short_num");
    printf("oaep.short_flen=%d\n", RSA_padding_check_PKCS1_OAEP_mgf1(out, 128, em, 127, 128,
        NULL, 0, sha1, sha1));
    printf("oaep.zero_tlen=%d\n", RSA_padding_check_PKCS1_OAEP_mgf1(out, 0, em, 128, 128,
        NULL, 0, sha1, sha1));
    EVP_MD_free((EVP_MD *)sha1);
}

int main(void)
{
    RSA_METHOD *m = NULL;
    RSA_METHOD *d = NULL;
    int app = 7;
    int flags;
    unsigned char from[64];
    unsigned char to[64];
    unsigned char blk[64];
    int i;

    setvbuf(stdout, NULL, _IOLBF, 0);

    /* The installation must be the program's first crypto act: the first non-zero allocation
     * through the default path clears `allow_customize` for the life of the process. */
    if (CRYPTO_set_mem_functions(my_malloc, my_realloc, my_free) != 1) {
        printf("rsa.install=0\n");
        return 1;
    }
    printf("rsa.install=1\n");
    ERR_clear_error();

    /* Warm-up. The library lazily builds state on first use -- the error-string table and the
     * `ERR` thread state among it -- and that traffic is not this court's subject. One throwaway
     * table through both the allocate and the release path drains it before the first window. */
    m = RSA_meth_new("warm-up", 0);
    RSA_meth_free(m);
    m = NULL;
    ERR_clear_error();

    /* ---------------------------------------------------------------- RSA_null_method */

    printf("rsa.null_method.is_null=%d\n", (const void *)RSA_null_method() == NULL);

    /* ---------------------------------------------------------------- RSA_meth_new */

    begin();
    m = RSA_meth_new("openssl-rs-probe", 0x2a);
    end("new_named");
    printf("rsa.new_named.is_null=%d\n", (const void *)m == NULL);
    if (m != NULL) {
        printf("rsa.new_named.name=%s\n", RSA_meth_get0_name(m));
        printf("rsa.new_named.flags=%d\n", RSA_meth_get_flags(m));
    }

    /* A NULL name reaches `CRYPTO_strdup(NULL)`, which the authority answers with NULL *before*
     * allocating. So the table is built, `flags` is stored, the duplicate refuses, and the table
     * is released: one M and one F, and a NULL answer. */
    begin();
    d = RSA_meth_new(NULL, 7);
    end("new_unnamed");
    printf("rsa.new_unnamed.is_null=%d\n", (const void *)d == NULL);

    /* ---------------------------------------------------------------- RSA_meth_free */

    begin();
    RSA_meth_free(NULL);
    end("free_null");
    printf("rsa.free_null.survived=1\n");

    /* ---------------------------------------------------------------- RSA_meth_dup */

    if (m != NULL) {
        RSA_meth_set0_app_data(m, &app);
        begin();
        d = RSA_meth_dup(m);
        end("dup");
        printf("rsa.dup.is_null=%d\n", (const void *)d == NULL);
        if (d != NULL) {
            printf("rsa.dup.name_equal=%d\n",
                strcmp(RSA_meth_get0_name(d), RSA_meth_get0_name(m)) == 0);
            printf("rsa.dup.name_distinct_pointer=%d\n",
                (const void *)RSA_meth_get0_name(d) != (const void *)RSA_meth_get0_name(m));
            printf("rsa.dup.flags=%d\n", RSA_meth_get_flags(d));
            printf("rsa.dup.app_data_shared=%d\n",
                RSA_meth_get0_app_data(d) == RSA_meth_get0_app_data(m));
        }
    }

    /* ---------------------------------------------------------------- RSA_meth_set1_name */

    if (m != NULL) {
        begin();
        flags = RSA_meth_set1_name(m, "renamed");
        end("set1_name");
        printf("rsa.set1_name.ret=%d\n", flags);
        printf("rsa.set1_name.name=%s\n", RSA_meth_get0_name(m));

        /* The failure mode, and it is reachable: a NULL argument makes the duplicate refuse
         * before the old name is released, so nothing is allocated and the name is unchanged.
         * This is the arm that distinguishes "duplicate first, release second" from the
         * reverse order, which would free the name and then store a NULL. */
        begin();
        flags = RSA_meth_set1_name(m, NULL);
        end("set1_name_null");
        printf("rsa.set1_name_null.ret=%d\n", flags);
        printf("rsa.set1_name_null.name=%s\n", RSA_meth_get0_name(m));
    }

    /* ---------------------------------------------------------------- flags */

    if (m != NULL) {
        printf("rsa.set_flags.ret=%d\n", RSA_meth_set_flags(m, 0x0001));
        printf("rsa.set_flags.get=%d\n", RSA_meth_get_flags(m));
        printf("rsa.set_flags.ret_zero=%d\n", RSA_meth_set_flags(m, 0));
        printf("rsa.set_flags.get_zero=%d\n", RSA_meth_get_flags(m));
    }

    /* ---------------------------------------------------------------- app_data */

    if (m != NULL) {
        printf("rsa.set0_app_data.ret=%d\n", RSA_meth_set0_app_data(m, &app));
        printf("rsa.get0_app_data.is_app=%d\n",
            RSA_meth_get0_app_data(m) == (void *)&app);
        printf("rsa.set0_app_data.null_ret=%d\n", RSA_meth_set0_app_data(m, NULL));
        printf("rsa.get0_app_data.after_null_is_null=%d\n",
            RSA_meth_get0_app_data(m) == NULL);
    }

    /* ---------------------------------------------------------------- the twelve pairs */

    if (m != NULL) {
        ROUNDTRIP("pub_enc", RSA_meth_get_pub_enc, RSA_meth_set_pub_enc, sentinel_crypt);
        ROUNDTRIP("pub_dec", RSA_meth_get_pub_dec, RSA_meth_set_pub_dec, sentinel_crypt);
        ROUNDTRIP("priv_enc", RSA_meth_get_priv_enc, RSA_meth_set_priv_enc, sentinel_crypt);
        ROUNDTRIP("priv_dec", RSA_meth_get_priv_dec, RSA_meth_set_priv_dec, sentinel_crypt);
        ROUNDTRIP("mod_exp", RSA_meth_get_mod_exp, RSA_meth_set_mod_exp, sentinel_modexp);
        ROUNDTRIP("bn_mod_exp", RSA_meth_get_bn_mod_exp, RSA_meth_set_bn_mod_exp,
            sentinel_bnmodexp);
        ROUNDTRIP("init", RSA_meth_get_init, RSA_meth_set_init, sentinel_life);
        ROUNDTRIP("finish", RSA_meth_get_finish, RSA_meth_set_finish, sentinel_life);
        ROUNDTRIP("sign", RSA_meth_get_sign, RSA_meth_set_sign, sentinel_sign);
        ROUNDTRIP("verify", RSA_meth_get_verify, RSA_meth_set_verify, sentinel_verify);
        ROUNDTRIP("keygen", RSA_meth_get_keygen, RSA_meth_set_keygen, sentinel_keygen);
        ROUNDTRIP("multi_prime_keygen", RSA_meth_get_multi_prime_keygen,
            RSA_meth_set_multi_prime_keygen, sentinel_mpkeygen);
    }

    /* ---------------------------------------------------------------- the padding primitives */

    for (i = 0; i < 64; i++)
        from[i] = (unsigned char)(0xa0 + i);

    /* `none`: the message must be exactly the modulus width, and the two disagreements raise
     * *different* reasons, so both arms are needed to tell the transcription from one that
     * reused a single reason. */
    ERR_clear_error();
    memset(to, 0x5a, sizeof(to));
    printf("rsa.pad_none.exact=%d\n", RSA_padding_add_none(to, 16, from, 16));
    printf("rsa.pad_none.exact.body=%d\n", memcmp(to, from, 16) == 0);
    drain("pad_none_exact");
    printf("rsa.pad_none.long=%d\n", RSA_padding_add_none(to, 16, from, 17));
    drain("pad_none_long");
    printf("rsa.pad_none.short=%d\n", RSA_padding_add_none(to, 16, from, 15));
    drain("pad_none_short");

    /* `check_none` zero-fills to the *left*, so the message ends up right-aligned in `to`. */
    ERR_clear_error();
    memset(to, 0x5a, sizeof(to));
    printf("rsa.chk_none.ok=%d\n", RSA_padding_check_none(to, 16, from, 16, 16));
    printf("rsa.chk_none.body=%d\n", memcmp(to, from, 16) == 0);
    printf("rsa.chk_none.pad=%d\n", RSA_padding_check_none(to, 20, from, 16, 16));
    printf("rsa.chk_none.lead0=%d\n", to[0] == 0 && to[1] == 0 && to[4] == from[0]);
    drain("chk_none_ok");
    ERR_clear_error();
    printf("rsa.chk_none.long=%d\n", RSA_padding_check_none(to, 16, from, 17, 17));
    drain("chk_none_long");

    /* X9.31: the one-octet `0x6A` header when there is no room for padding, and the
     * `0x6B || 0xBB... || 0xBA` run when there is. */
    ERR_clear_error();
    memset(blk, 0, sizeof(blk));
    printf("rsa.pad_x931.tight=%d\n", RSA_padding_add_X931(blk, 16, from, 14));
    printf("rsa.pad_x931.tight.0=%02x\n", blk[0]);
    printf("rsa.pad_x931.tight.body=%d\n", memcmp(blk + 1, from, 14) == 0);
    printf("rsa.pad_x931.tight.last=%02x\n", blk[15]);
    drain("pad_x931_tight");
    memset(blk, 0, sizeof(blk));
    printf("rsa.pad_x931.run=%d\n", RSA_padding_add_X931(blk, 16, from, 6));
    printf("rsa.pad_x931.run.0=%02x\n", blk[0]);
    printf("rsa.pad_x931.run.1=%02x\n", blk[1]);
    printf("rsa.pad_x931.run.8=%02x\n", blk[8]);
    printf("rsa.pad_x931.run.body=%d\n", memcmp(blk + 9, from, 6) == 0);
    printf("rsa.pad_x931.run.last=%02x\n", blk[15]);
    ERR_clear_error();
    printf("rsa.pad_x931.tight_fail=%d\n", RSA_padding_add_X931(blk, 16, from, 15));
    drain("pad_x931_fail");

    /* The check, on the tight form `RSA_padding_add_X931` just produced, then on the run form,
     * then on the three ways it refuses. */
    ERR_clear_error();
    (void)RSA_padding_add_X931(blk, 16, from, 14);
    memset(to, 0x5a, sizeof(to));
    printf("rsa.chk_x931.tight=%d\n", RSA_padding_check_X931(to, 64, blk, 16, 16));
    printf("rsa.chk_x931.tight.body=%d\n", memcmp(to, from, 14) == 0);
    drain("chk_x931_tight");
    (void)RSA_padding_add_X931(blk, 16, from, 6);
    printf("rsa.chk_x931.run=%d\n", RSA_padding_check_X931(to, 64, blk, 16, 16));
    printf("rsa.chk_x931.run.body=%d\n", memcmp(to, from, 6) == 0);
    drain("chk_x931_run");
    ERR_clear_error();
    printf("rsa.chk_x931.short=%d\n", RSA_padding_check_X931(to, 64, blk, 15, 16));
    drain("chk_x931_short");
    (void)RSA_padding_add_X931(blk, 16, from, 6);
    blk[0] = 0x42;
    printf("rsa.chk_x931.header=%d\n", RSA_padding_check_X931(to, 64, blk, 16, 16));
    drain("chk_x931_header");
    /* `0x6B` immediately followed by the terminator: the format requires at least one padding
     * octet, which is the `i == 0` refusal. */
    memset(blk, 0xbb, sizeof(blk));
    blk[0] = 0x6b;
    blk[1] = 0xba;
    blk[15] = 0xcc;
    printf("rsa.chk_x931.nopad=%d\n", RSA_padding_check_X931(to, 64, blk, 16, 16));
    drain("chk_x931_nopad");
    memset(blk, 0xbb, sizeof(blk));
    blk[0] = 0x6b;
    blk[5] = 0x42;
    blk[15] = 0xcc;
    printf("rsa.chk_x931.mid=%d\n", RSA_padding_check_X931(to, 64, blk, 16, 16));
    drain("chk_x931_mid");
    (void)RSA_padding_add_X931(blk, 16, from, 14);
    blk[15] = 0x00;
    printf("rsa.chk_x931.trailer=%d\n", RSA_padding_check_X931(to, 64, blk, 16, 16));
    drain("chk_x931_trailer");

    /* The four ISO/IEC 10118 part numbers, and an unknown NID. */
    printf("rsa.x931_id.sha1=%d\n", RSA_X931_hash_id(64));
    printf("rsa.x931_id.sha256=%d\n", RSA_X931_hash_id(672));
    printf("rsa.x931_id.sha384=%d\n", RSA_X931_hash_id(673));
    printf("rsa.x931_id.sha512=%d\n", RSA_X931_hash_id(674));
    printf("rsa.x931_id.unknown=%d\n", RSA_X931_hash_id(0));

    /* PKCS#1 v1.5 type 1: `00 01 FF... 00 D`, and the check's six refusals. */
    ERR_clear_error();
    memset(blk, 0, sizeof(blk));
    printf("rsa.pad_t1.ok=%d\n", RSA_padding_add_PKCS1_type_1(blk, 16, from, 5));
    printf("rsa.pad_t1.0=%02x\n", blk[0]);
    printf("rsa.pad_t1.1=%02x\n", blk[1]);
    printf("rsa.pad_t1.2=%02x\n", blk[2]);
    printf("rsa.pad_t1.10=%02x\n", blk[10]);
    printf("rsa.pad_t1.body=%d\n", memcmp(blk + 11, from, 5) == 0);
    drain("pad_t1_ok");
    ERR_clear_error();
    printf("rsa.pad_t1.long=%d\n", RSA_padding_add_PKCS1_type_1(blk, 16, from, 6));
    drain("pad_t1_long");

    ERR_clear_error();
    (void)RSA_padding_add_PKCS1_type_1(blk, 16, from, 5);
    memset(to, 0x5a, sizeof(to));
    printf("rsa.chk_t1.ok=%d\n", RSA_padding_check_PKCS1_type_1(to, 64, blk, 16, 16));
    printf("rsa.chk_t1.body=%d\n", memcmp(to, from, 5) == 0);
    drain("chk_t1_ok");
    /* The same block with the leading zero already stripped: `num == flen + 1`. */
    printf("rsa.chk_t1.stripped=%d\n", RSA_padding_check_PKCS1_type_1(to, 64, blk + 1, 15, 16));
    printf("rsa.chk_t1.stripped.body=%d\n", memcmp(to, from, 5) == 0);
    drain("chk_t1_stripped");
    ERR_clear_error();
    printf("rsa.chk_t1.tooshort=%d\n", RSA_padding_check_PKCS1_type_1(to, 64, blk, 8, 8));
    drain("chk_t1_tooshort");
    (void)RSA_padding_add_PKCS1_type_1(blk, 16, from, 5);
    blk[0] = 0x02;
    printf("rsa.chk_t1.lead=%d\n", RSA_padding_check_PKCS1_type_1(to, 64, blk, 16, 16));
    drain("chk_t1_lead");
    blk[0] = 0x00;
    blk[1] = 0x02;
    printf("rsa.chk_t1.type=%d\n", RSA_padding_check_PKCS1_type_1(to, 64, blk, 16, 16));
    drain("chk_t1_type");
    blk[1] = 0x01;
    blk[5] = 0x7f;
    printf("rsa.chk_t1.fixed=%d\n", RSA_padding_check_PKCS1_type_1(to, 64, blk, 16, 16));
    drain("chk_t1_fixed");
    /* No null before the data: fourteen `0xff` with `num == flen + 1` so the walk reaches the
     * end of the padding string without finding the separator. */
    memset(blk, 0xff, sizeof(blk));
    blk[0] = 0x00;
    blk[1] = 0x01;
    printf("rsa.chk_t1.nonull=%d\n", RSA_padding_check_PKCS1_type_1(to, 64, blk, 15, 15));
    drain("chk_t1_nonull");
    /* Seven `0xff` octets, then the separator: below the eight-octet minimum. */
    memset(blk, 0x00, sizeof(blk));
    blk[0] = 0x00;
    blk[1] = 0x01;
    memset(blk + 2, 0xff, 7);
    blk[9] = 0x00;
    printf("rsa.chk_t1.padcount=%d\n", RSA_padding_check_PKCS1_type_1(to, 64, blk, 16, 16));
    drain("chk_t1_padcount");

    /* PKCS1_MGF1: the counter is big-endian and four octets wide, so the arms are a mask that
     * is exactly one digest, one that spans two blocks (the counter's second value), one that is
     * not a multiple of the digest size (the truncating final block), and a zero length. */
    {
        static const unsigned char mgf_seed[20] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
            0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13
        };
        unsigned char mask[80];
        const EVP_MD *md_sha1 = EVP_MD_fetch(NULL, "SHA1", NULL);
        const EVP_MD *md_sha256 = EVP_MD_fetch(NULL, "SHA256", NULL);
        int k;

        /* Fetched rather than `EVP_sha1()`/`EVP_sha256()`: the accessor functions are still a
         * scaffolded ABI in the candidate shell, while the fetched methods are 8.1b's and are
         * what `PKCS1_MGF1` is actually handed by the padding code. The digest is the same
         * function either way, so the mask is the same bytes. */
        printf("rsa.mgf1.fetched=%d\n", md_sha1 != NULL && md_sha256 != NULL);
        if (md_sha1 == NULL || md_sha256 == NULL)
            return 1;

        ERR_clear_error();
        memset(mask, 0, sizeof(mask));
        printf("rsa.mgf1.sha1.one.ret=%d\n", PKCS1_MGF1(mask, 20, mgf_seed, 20, md_sha1));
        for (k = 0; k < 20; k++)
            printf("rsa.mgf1.sha1.one.%02d=%02x\n", k, mask[k]);
        drain("mgf1_sha1_one");
        memset(mask, 0, sizeof(mask));
        printf("rsa.mgf1.sha1.two.ret=%d\n", PKCS1_MGF1(mask, 40, mgf_seed, 20, md_sha1));
        for (k = 20; k < 40; k++)
            printf("rsa.mgf1.sha1.two.%02d=%02x\n", k, mask[k]);
        drain("mgf1_sha1_two");
        memset(mask, 0, sizeof(mask));
        printf("rsa.mgf1.sha256.part.ret=%d\n",
            PKCS1_MGF1(mask, 45, mgf_seed, 20, md_sha256));
        for (k = 32; k < 45; k++)
            printf("rsa.mgf1.sha256.part.%02d=%02x\n", k, mask[k]);
        /* The seed is `seedlen` octets and is not NUL-terminated: a zero length is legal and
         * hashes the counter alone. The mask must be left untouched by a zero-length request. */
        memset(mask, 0xa5, sizeof(mask));
        printf("rsa.mgf1.zero.ret=%d\n", PKCS1_MGF1(mask, 0, mgf_seed, 20, md_sha1));
        printf("rsa.mgf1.zero.untouched=%d\n", mask[0] == 0xa5 && mask[19] == 0xa5);
        printf("rsa.mgf1.noseed.ret=%d\n", PKCS1_MGF1(mask, 20, mgf_seed, 0, md_sha1));
        for (k = 0; k < 4; k++)
            printf("rsa.mgf1.noseed.%02d=%02x\n", k, mask[k]);
        EVP_MD_free((EVP_MD *)md_sha1);
        EVP_MD_free((EVP_MD *)md_sha256);
        printf("rsa.mgf1.released=1\n");
    }

    oaep_arms();

    /* ---------------------------------------------------------------- release */

    /* `RSA_meth_free` releases the name and then the table, both attributed to `rsa_meth.c`. The
     * window is the last thing this probe records, so the order is compared rather than assumed. */
    begin();
    RSA_meth_free(m);
    end("free_named");
    begin();
    RSA_meth_free(d);
    end("free_dup");

    return 0;
}
