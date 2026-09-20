/*
 * RT-RSA -- the differential court for `crypto/rsa`'s method table and object layer (Phase 8.4,
 * slices A and B).
 *
 * This program is compiled **twice**, once against the admitted authority and once against the
 * candidate distribution shell, and the two `key=value` transcripts are diffed. It never decides
 * anything: a residual is a difference between two executions, so the expectation cannot drift with
 * the crate. `forensics/tools/phase8_courts.py` owns the comparison.
 *
 * What this court is, and what it is not yet
 * ------------------------------------------
 * Three slices of `crypto/rsa` share this court. Slice B is the thirty-three `RSA_meth_*` labels
 * plus `RSA_null_method`, and **every one of the thirty-four is called below**. Slice A is
 * `rsa_lib.c`'s object layer plus `rsa_crpt.c`'s three accessors, and **thirty-four of its
 * thirty-six exports are called below as well**. Slice C is the sixteen labelling, checking and
 * digesting entry points of the padding family -- `rsa_none.c`, `rsa_x931.c`, `rsa_pk1.c`,
 * `rsa_oaep.c`'s `PKCS1_MGF1` and both OAEP checks, and now the five randomised *adds* and the
 * type-2 *check* -- and **every one of the sixteen is called below**. Nothing here does any
 * cryptography -- each function allocates a table or an object, stores a pointer in one, or reads
 * one, or pads a buffer -- so the transcript is about *identity, ownership and structure* rather
 * than arithmetic, and that is the whole observable contract of these entry points.
 *
 * **The padding arms observe random output without observing a random byte.** Five of the six
 * padding functions added by D323 fill their output from the DRBG, and both runs of this probe are
 * single-shot, so any byte derived from that draw would be a residual rather than an observation.
 * What is printed instead is: the return code; the *structural* predicates over the block (`00 02`,
 * the non-zero padding run, the terminating zero, the `0xbc` trailer, the zero leading bits a PSS
 * block must have, the leading PSS version octet); a **round trip** through the landed
 * `RSA_padding_check_PKCS1_type_2` / `RSA_padding_check_PKCS1_OAEP_mgf1`, whose answers are a
 * length and a byte comparison and are therefore deterministic functions of the input; a
 * **recomputation** of the PSS `H` from the salt the block itself encodes; and the refusal arms
 * with their error queues drained. `rt_all_nonzero` and `pss_decodes` below are those predicates.
 *
 * **`RSA` is opaque in the installed header on both sides, and no constructor exists on the
 * candidate side yet**, so the object arms build their subject themselves: the fabrication block
 * below owns the shape, transcribed offset by offset from `courts/layout/measure-rsa-ctx.c` (D283's
 * measurement), and hands both binaries the same bytes, the same genuine `BIGNUM`s and the same
 * genuine `RSA_METHOD` from `RSA_meth_new`. The observation is the *library's* answer, and the
 * `get0_*` identity arms tie the probe's offsets to the library's.
 *
 * **Four exports are deliberately not called, and are named here.** `RSA_new` and `RSA_new_method`
 * are **OWED**: the candidate does not link them until the commit that lands
 * `RSA_get_default_method`, so a probe that called them would abort the candidate rather than
 * compare. `RSA_get_default_method` and `RSA_PKCS1_OpenSSL` arrive with that same later commit, as
 * do the observations of `rsa_pkcs1_ossl_meth`'s own members -- `rsa_sign`/`rsa_verify` initialised
 * to the integer `0`, both keygen members NULL, `RSA_FLAG_FIPS_METHOD` in `flags`. Naming these four
 * is what keeps "not compared" from being read as "compared and equal".
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

/* ------------------------------------------------------------------ the fabricated RSA object */

/* `RSA` is opaque in the installed header on both sides, and no constructor exists on the candidate
 * side until commit B: `RSA_new`/`RSA_new_method` are OWED until `RSA_get_default_method` lands. So
 * the probe owns the object's shape, transcribed from `courts/layout/measure-rsa-ctx.c` (D283's
 * measurement) with every offset pinned. 27 pointers is exactly 216 bytes and is eight-aligned.
 * Both binaries are handed the same bytes, the same genuine `BIGNUM`s and the same genuine
 * `RSA_METHOD` from `RSA_meth_new`, and the observation is the *library's* answer. `rt_blank`
 * memsets all 216 bytes because `forensics/tools/probe_hygiene.py` recompiles this probe at several
 * optimisation levels and requires an identical transcript, and a partially-initialised object is
 * exactly the bug class it exists to catch. */
union rt_rsa_object {
    void *p[27];
    unsigned char b[216];
};
_Static_assert(sizeof(union rt_rsa_object) == 216, "RSA is 216 bytes");

/* offsets, from courts/layout/measure-rsa-ctx.c:
   version 16, meth 24, engine 32, n 40, e 48, d 56, p 64, q 72, dmp1 80, dmq1 88, iqmp 96,
   pss 128, prime_infos 136, ex_data 144, references 160, flags 164, lock 200, dirty_cnt 208;
   RSA_METHOD::flags is 72. */
#define RT_OFF(o, n)      ((unsigned char *)(o) + (n))
#define RT_VERSION(o)     (*(int *)RT_OFF(o, 16))
#define RT_METH(o)        (*(RSA_METHOD **)RT_OFF(o, 24))
#define RT_ENGINE(o)      (*(void **)RT_OFF(o, 32))
#define RT_N(o)           (*(BIGNUM **)RT_OFF(o, 40))
#define RT_E(o)           (*(BIGNUM **)RT_OFF(o, 48))
#define RT_D(o)           (*(BIGNUM **)RT_OFF(o, 56))
#define RT_P(o)           (*(BIGNUM **)RT_OFF(o, 64))
#define RT_Q(o)           (*(BIGNUM **)RT_OFF(o, 72))
#define RT_DMP1(o)        (*(BIGNUM **)RT_OFF(o, 80))
#define RT_DMQ1(o)        (*(BIGNUM **)RT_OFF(o, 88))
#define RT_IQMP(o)        (*(BIGNUM **)RT_OFF(o, 96))
#define RT_PSS(o)         (*(void **)RT_OFF(o, 128))
#define RT_PRIME_INFOS(o) (*(void **)RT_OFF(o, 136))
#define RT_REFERENCES(o)  (*(int *)RT_OFF(o, 160))
#define RT_FLAGS(o)       (*(int *)RT_OFF(o, 164))
#define RT_LOCK(o)        (*(void **)RT_OFF(o, 200))
#define RT_DIRTY(o)       (*(int *)RT_OFF(o, 208))
#define RT_METH_FLAGS(m)  (*(int *)((unsigned char *)(m) + 72))

static void *rt_blank(void)
{
    void *o = malloc(sizeof(union rt_rsa_object));

    if (o == NULL)
        return NULL;
    memset(o, 0, sizeof(union rt_rsa_object));
    return o;
}

/* A `BIGNUM` with exactly `bits` significant bits (`0` is the zero value), built through the
 * public API so the observation is `BN_num_bits`'s own answer. */
static BIGNUM *rt_bits(int bits)
{
    BIGNUM *b = BN_new();

    if (b == NULL)
        return NULL;
    if (bits > 0 && BN_set_bit(b, bits - 1) != 1) {
        BN_free(b);
        return NULL;
    }
    return b;
}

/* A `BIGNUM` whose value is `v`. The width arms read the *values* 0/1/255/256 rather than a bit
 * length, because `(bits + 7) / 8` and `bits / 8` only diverge on the value 256. */
static BIGNUM *rt_word(unsigned long v)
{
    BIGNUM *b = BN_new();

    if (b == NULL)
        return NULL;
    if (BN_set_word(b, v) != 1) {
        BN_free(b);
        return NULL;
    }
    return b;
}

/* The ordering sentinels for `RSA_set_method`: each records its turn in a two-slot sequence, so
 * "the outgoing table's `finish` fires before the incoming table's `init`" is the numbers 1 and 2
 * rather than a claim about the source. They are stored in a real table and are never called by the
 * probe itself. */
static int rt_seq;
static int rt_finish_at;
static int rt_init_at;

static int sentinel_mark_finish(RSA *rsa)
{
    (void)rsa;
    rt_finish_at = ++rt_seq;
    return 0;
}

static int sentinel_mark_init(RSA *rsa)
{
    (void)rsa;
    rt_init_at = ++rt_seq;
    return 0;
}

/* Release a probe-fabricated object through the library, giving it the reference count `RSA_free`
 * needs to walk its own order. Only for objects whose `pss` member the probe has not filled: the
 * candidate reduces `RSA_PSS_PARAMS_free(NULL)` away and the authority calls it, which is fine for a
 * NULL member and a fault for the probe's sentinel. */
static void rt_release(void *o)
{
    if (o == NULL)
        return;
    RT_REFERENCES(o) = 1;
    RSA_free(o);
}

/* Whether every octet of `p` is non-zero. The type-2 padding's retry loop exists to make this
 * true whatever the DRBG drew, so it is a *deterministic* predicate over random bytes -- which is
 * what lets a court observe this padding without a byte of it entering the transcript. */
static int rt_all_nonzero(const unsigned char *p, int n)
{
    int i;

    for (i = 0; i < n; i++)
        if (p[i] == 0)
            return 0;
    return 1;
}

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

    /* ------------------------------------------------------------------ the OAEP *adds* */

    /* The adds draw a random seed, so no byte they write can enter the transcript. What can is
     * the round trip: `RSA_padding_check_PKCS1_OAEP_mgf1` is a pure function of the block it is
     * handed, so "the message came back, and it is 16 octets long" is a deterministic fact about a
     * block neither binary can predict. The version octet is not random either. */
    ERR_clear_error();
    memset(em, 0, sizeof(em));
    printf("oaep.add_mgf1.ok=%d\n",
        RSA_padding_add_PKCS1_OAEP_mgf1(em, 128, msg, 16, NULL, 0, sha1, sha1));
    printf("oaep.add_mgf1.0=%02x\n", em[0]);
    memset(out, 0x5a, sizeof(out));
    r = RSA_padding_check_PKCS1_OAEP_mgf1(out, 128, em, 128, 128, NULL, 0, sha1, sha1);
    printf("oaep.add_mgf1.rt=%d\n", r);
    printf("oaep.add_mgf1.rt_body=%d\n", r == 16 && memcmp(out, msg, 16) == 0);
    drain("oaep_add_mgf1_ok");

    /* The wrapper: both digests NULL, which the callee turns into SHA-1, and the empty label. */
    ERR_clear_error();
    memset(em, 0, sizeof(em));
    printf("oaep.add.ok=%d\n", RSA_padding_add_PKCS1_OAEP(em, 128, msg, 16, NULL, 0));
    memset(out, 0x5a, sizeof(out));
    r = RSA_padding_check_PKCS1_OAEP(out, 128, em, 128, 128, NULL, 0);
    printf("oaep.add.rt=%d\n", r);
    printf("oaep.add.rt_body=%d\n", r == 16 && memcmp(out, msg, 16) == 0);
    drain("oaep_add_ok");

    /* A non-empty label, hashed into `DB` by both sides. The same block under the *empty* label
     * must not decode: that is the hash comparison in the check, and it is the arm that says the
     * label reached the add rather than merely the check. */
    {
        static const unsigned char label[5] = { 0x01, 0x02, 0x03, 0x04, 0x05 };

        ERR_clear_error();
        memset(em, 0, sizeof(em));
        printf("oaep.add_label.ok=%d\n",
            RSA_padding_add_PKCS1_OAEP_mgf1(em, 128, msg, 16, label, 5, sha1, sha1));
        memset(out, 0x5a, sizeof(out));
        r = RSA_padding_check_PKCS1_OAEP_mgf1(out, 128, em, 128, 128, label, 5, sha1, sha1);
        printf("oaep.add_label.rt=%d\n", r);
        printf("oaep.add_label.rt_body=%d\n", r == 16 && memcmp(out, msg, 16) == 0);
        drain("oaep_add_label_ok");
        ERR_clear_error();
        r = RSA_padding_check_PKCS1_OAEP_mgf1(out, 128, em, 128, 128, NULL, 0, sha1, sha1);
        printf("oaep.add_label.empty_label=%d\n", r);
        drain("oaep_add_label_empty");
    }

    /* The two length refusals. The first is the ordinary one: 87 > 127 - 2*20 - 1. The second is
     * `emlen < 2*mdlen + 1`, and it is reachable **only** with a negative `flen`: at a modulus too
     * small for the digest the first test fires for every non-negative message length, so `-1` is
     * what puts the `RSA_R_KEY_SIZE_TOO_SMALL` site under the court rather than leaving it to a
     * reader. Neither reaches the copy, which is why `msg`'s 16 octets are enough for both. */
    ERR_clear_error();
    printf("oaep.add_long=%d\n",
        RSA_padding_add_PKCS1_OAEP_mgf1(em, 128, msg, 87, NULL, 0, sha1, sha1));
    drain("oaep_add_long");
    ERR_clear_error();
    printf("oaep.add_small_key=%d\n",
        RSA_padding_add_PKCS1_OAEP_mgf1(em, 41, msg, -1, NULL, 0, sha1, sha1));
    drain("oaep_add_small_key");

    EVP_MD_free((EVP_MD *)sha1);
}

/* ------------------------------------------------------------------ the PSS adds */

/* The recovery `ossl_rsa_verify_PKCS1_PSS_mgf1` performs, written out here because that verifier is
 * `rsa_pss.c`'s other half and is slice D's. It unmasks `DB` with `MGF1(H)`, drops the leading bits
 * `MSBits` forbids, walks to the `0x01`, and rebuilds `H = Hash(00 * 8 || mHash || salt)`.
 *
 * **The salt is the random part and not one byte of it is printed.** The answer is a yes/no about a
 * recomputation, and it is deterministic because the salt the block encodes is the salt the writer
 * drew -- a writer that encoded something else answers 0, which is what makes this an observation
 * rather than a restatement: the only other way to check it would be to print the salt.
 *
 * The caller passes `em` already advanced past the leading zero octet and `emlen` already shrunk,
 * which is what the verifier does when `MSBits == 0`. */
static int pss_decodes(const unsigned char *em, int emlen, int msbits,
    const unsigned char *mhash, int hlen, const EVP_MD *md, const EVP_MD *mgf1, int wantslen)
{
    unsigned char db[256];
    unsigned char buf[8 + EVP_MAX_MD_SIZE + 256];
    unsigned char h2[EVP_MAX_MD_SIZE];
    const unsigned char *H;
    int masked_dblen = emlen - hlen - 1;
    int i, slen;

    if (masked_dblen <= 0 || masked_dblen > (int)sizeof(db))
        return 0;
    H = em + masked_dblen;
    if (PKCS1_MGF1(db, masked_dblen, H, hlen, mgf1) != 0)
        return 0;
    for (i = 0; i < masked_dblen; i++)
        db[i] ^= em[i];
    if (msbits)
        db[0] &= 0xFF >> (8 - msbits);
    /* The authority's own scan, including its "the separator may be the last octet" arm. */
    for (i = 0; db[i] == 0 && i < (masked_dblen - 1); i++)
        ;
    if (db[i++] != 0x1)
        return 0;
    slen = masked_dblen - i;
    if (slen != wantslen)
        return 0;
    memset(buf, 0, 8);
    memcpy(buf + 8, mhash, (size_t)hlen);
    memcpy(buf + 8 + hlen, db + i, (size_t)slen);
    if (EVP_Digest(buf, (size_t)(8 + hlen + slen), h2, NULL, md, NULL) != 1)
        return 0;
    return memcmp(h2, H, (size_t)hlen) == 0;
}

/* One PSS arm: the add -- through the `_mgf1` export when `mgf1` is non-NULL and through the
 * NULL-`mgf1Hash` wrapper when it is not -- then the trailer, the first-octet test the *verifier*
 * applies (`EM[0] & (0xFF << MSBits) == 0`, which for `MSBits == 0` is the leading zero octet
 * itself), and the recovery. `emlen` and `base` describe the effective block: for a modulus whose
 * `BN_num_bits(n) - 1` is a multiple of eight the writer spends one octet on the leading zero and
 * shrinks `emLen` to match, so `base` is 1 and every position below is relative to it. */
static void pss_arm(void *o, unsigned char *em, int emlen, int msbits, int base,
    const unsigned char *mhash, int hlen, const EVP_MD *md, const EVP_MD *mgf1,
    int requested, int want, const char *tag)
{
    int r;

    memset(em, 0, 256);
    ERR_clear_error();
    if (mgf1 == NULL)
        r = RSA_padding_add_PKCS1_PSS(o, em, mhash, md, requested);
    else
        r = RSA_padding_add_PKCS1_PSS_mgf1(o, em, mhash, md, mgf1, requested);
    printf("rsa.pss.%s.ret=%d\n", tag, r);
    printf("rsa.pss.%s.trailer=%d\n", tag, em[base + emlen - 1] == 0xbc);
    printf("rsa.pss.%s.lead=%d\n", tag, (em[0] & (0xFF << msbits)) == 0);
    printf("rsa.pss.%s.decodes=%d\n", tag,
        pss_decodes(em + base, emlen, msbits, mhash, hlen, md, mgf1 == NULL ? md : mgf1, want));
    drain(tag);
}

/* The two PSS adds, over a fabricated object whose `n` is a genuine `BIGNUM` of `bits` bits -- the
 * only thing the add reads (`BN_num_bits(n)` for the leading bits, `RSA_size` for the width).
 * `libctx` is left NULL by `rt_blank`, which is the value the export in `rsa_ossl.c` would pass for
 * an object that has none; the reason the internal reads `rsa->libctx` rather than a parameter is
 * that a caller *can* put something else there, and that is the one thing this court cannot
 * observe without a second library context, which this crate does not have yet. */
static void rsa_pss_arms(void)
{
    const EVP_MD *sha1 = EVP_MD_fetch(NULL, "SHA1", NULL);
    const EVP_MD *sha256 = EVP_MD_fetch(NULL, "SHA256", NULL);
    unsigned char mhash[64];
    unsigned char em[256];
    void *o = rt_blank();
    void *o2 = rt_blank();
    void *small = rt_blank();
    BIGNUM *n = NULL, *n2 = NULL, *n3 = NULL;
    int i, hlen, hlen256, emlen, emlen2, msbits;

    printf("rsa.pss.md_fetched=%d\n", sha1 != NULL && sha256 != NULL);
    if (sha1 == NULL || sha256 == NULL)
        return;
    for (i = 0; i < 64; i++)
        mhash[i] = (unsigned char)(0x10 + i);

    /* 1024 bits: `BN_num_bits(n) - 1` is 1023, so `MSBits` is 7 and the block is the whole
     * `RSA_size`. */
    n = rt_bits(1024);
    RT_N(o) = n;
    printf("rsa.pss.n_1024=%d\n", n != NULL);
    if (n == NULL)
        return;

    hlen = EVP_MD_get_size(sha1);
    hlen256 = EVP_MD_get_size(sha256);
    emlen = RSA_size(o);
    msbits = (BN_num_bits(n) - 1) & 0x7;
    printf("rsa.pss.hlen=%d\n", hlen);
    printf("rsa.pss.emlen=%d\n", emlen);
    printf("rsa.pss.msbits=%d\n", msbits);

    /* The five `sLen` conventions and two explicit lengths. `-1` is the digest length; `-2` and
     * `-3` are the modulus maximum; `-4` is the maximum capped at the digest length, which is the
     * only one that is a `min` of two rules and therefore the only one that a lost `sLenMax`
     * changes. Zero exercises the `sLen > 0` guards around the salt allocation and the digest
     * update. */
    pss_arm(o, em, emlen, msbits, 0, mhash, hlen, sha1, NULL, RSA_PSS_SALTLEN_DIGEST, hlen,
        "slen_digest");
    pss_arm(o, em, emlen, msbits, 0, mhash, hlen, sha1, sha1, RSA_PSS_SALTLEN_MAX,
        emlen - hlen - 2, "slen_max");
    pss_arm(o, em, emlen, msbits, 0, mhash, hlen, sha1, sha1, RSA_PSS_SALTLEN_AUTO,
        emlen - hlen - 2, "slen_auto");
    pss_arm(o, em, emlen, msbits, 0, mhash, hlen, sha1, sha1, RSA_PSS_SALTLEN_MAX_SIGN,
        emlen - hlen - 2, "slen_max_sign");
    pss_arm(o, em, emlen, msbits, 0, mhash, hlen, sha1, sha1, RSA_PSS_SALTLEN_AUTO_DIGEST_MAX,
        hlen, "slen_auto_digest_max");
    pss_arm(o, em, emlen, msbits, 0, mhash, hlen, sha1, NULL, hlen, hlen, "slen_digest_explicit");
    pss_arm(o, em, emlen, msbits, 0, mhash, hlen, sha1, sha1, 0, 0, "slen_zero");
    pss_arm(o, em, emlen, msbits, 0, mhash, hlen, sha1, NULL, emlen - hlen - 2, emlen - hlen - 2,
        "slen_max_explicit");

    /* Two different digests. `Hash` decides `hLen` and therefore the split; `mgf1Hash` decides only
     * the mask, so 128 - 32 - 2 = 94 is the maximum salt under SHA-256 while the mask is SHA-1's. */
    printf("rsa.pss.hlen_sha256=%d\n", hlen256);
    pss_arm(o, em, emlen, msbits, 0, mhash, hlen256, sha256, sha1, emlen - hlen256 - 2,
        emlen - hlen256 - 2, "two_digests");
    pss_arm(o, em, emlen, msbits, 0, mhash, hlen256, sha256, NULL, hlen256, hlen256,
        "sha256_only");

    /* The three refusals. A salt length above what the modulus allows; one below the lowest
     * convention, which is a refusal rather than a clamp; and a modulus too small to hold the hash
     * plus its two mandatory octets. */
    memset(em, 0, sizeof(em));
    ERR_clear_error();
    printf("rsa.pss.slen_over_max.ret=%d\n",
        RSA_padding_add_PKCS1_PSS(o, em, mhash, sha1, emlen - hlen - 1));
    drain("pss_slen_over_max");
    ERR_clear_error();
    printf("rsa.pss.slen_below_min.ret=%d\n",
        RSA_padding_add_PKCS1_PSS_mgf1(o, em, mhash, sha1, sha1, -5));
    drain("pss_slen_below_min");

    /* 1025 bits: `BN_num_bits(n) - 1` is 1024, so `MSBits` is **zero** and the writer spends one
     * octet on the leading zero, shrinking `emLen` from 129 to 128. Every offset downstream -- the
     * trailer included -- is relative to the advanced pointer, which is the arm this object exists
     * for. */
    n2 = rt_bits(1025);
    RT_N(o2) = n2;
    printf("rsa.pss.n_1025=%d\n", n2 != NULL);
    if (n2 != NULL) {
        emlen2 = RSA_size(o2);
        printf("rsa.pss.emlen_1025=%d\n", emlen2);
        printf("rsa.pss.msbits_1025=%d\n", (BN_num_bits(n2) - 1) & 0x7);
        pss_arm(o2, em, emlen2 - 1, 0, 1, mhash, hlen, sha1, sha1, hlen, hlen, "msbits_zero");
    }

    /* A 64-bit modulus is eight octets, which is less than `hLen + 2` for SHA-1. `MSBits` is 7
     * there, so the refusal is reached before a byte of `EM` is touched -- which is why the
     * 256-octet buffer above is more than this arm needs rather than less. */
    n3 = rt_bits(64);
    RT_N(small) = n3;
    printf("rsa.pss.n_64=%d\n", n3 != NULL);
    if (n3 != NULL) {
        printf("rsa.pss.emlen_small=%d\n", RSA_size(small));
        ERR_clear_error();
        printf("rsa.pss.small_key.ret=%d\n",
            RSA_padding_add_PKCS1_PSS_mgf1(small, em, mhash, sha1, sha1, 0));
        drain("pss_small_key");
    }

    if (n != NULL)
        BN_free(n);
    if (n2 != NULL)
        BN_free(n2);
    if (n3 != NULL)
        BN_free(n3);
    free(o);
    free(o2);
    free(small);
    EVP_MD_free((EVP_MD *)sha1);
    EVP_MD_free((EVP_MD *)sha256);
    printf("rsa.pss.released=1\n");
}

/* ------------------------------------------------------------------ the object layer (slice A) */

/* The thirty-four `rsa_lib.c`/`rsa_crpt.c` exports the candidate publishes. Every subject is
 * fabricated by the block above; the observations are the library's own answers. The three
 * `set0_*` refusals and the multi-prime refusals raise nothing, so each of their `drain`
 * transcripts is an *empty* queue -- the emptiness is the observation, and the `err.count` line is
 * what records it. */
static void rsa_object_arms(void)
{
    void *o_get = NULL, *o_setm = NULL, *o_fref = NULL, *o_up1 = NULL, *o_up0 = NULL;
    void *o_exd = NULL, *o_sec = NULL, *o_key = NULL, *o_fac = NULL, *o_crt = NULL;
    void *o_mp = NULL, *o_mp2 = NULL, *o_full = NULL, *o_pss = NULL, *o_flags = NULL;
    void *o_bits = NULL;
    BIGNUM *n, *e, *d, *p, *q, *dmp1, *dmq1, *iqmp;
    BIGNUM *fn, *fe, *fd, *fp, *fq, *fd1, *fd2, *fi;
    BIGNUM *a1, *a2, *a3;
    RSA_METHOD *tbl_get, *tbl_old, *tbl_new, *tbl_flags;
    const BIGNUM *on, *oe, *od, *op, *oq, *odmp1, *odmq1, *oiqmp;
    const BIGNUM *mpf[2], *mpe[2], *mpc[2];
    BIGNUM *mp_primes[1], *mp_exps[1], *mp_coeffs[1];
    int app = 7, app2 = 9;
    int i;
    static const int ladder[7] = { 2048, 3072, 4096, 6144, 7680, 8192, 15360 };

    /* ---------------------------------------------------------------- RSA_get_method */

    tbl_get = RSA_meth_new("rt-obj-get", 0x30);
    o_get = rt_blank();
    printf("rsa.obj_get_method.blank_is_null=%d\n",
        (const void *)RSA_get_method(o_get) == NULL);
    RT_METH(o_get) = tbl_get;
    printf("rsa.obj_get_method.sentinel=%d\n",
        (const void *)RSA_get_method(o_get) == (const void *)tbl_get);

    /* ---------------------------------------------------------------- RSA_set_method */

    /* The outgoing table's `finish` and the incoming table's `init` are distinct sentinels, so the
     * *order* is an observation rather than an assumption. `engine` must be left 0: a non-NULL
     * engine would make the authority call `ENGINE_finish` on it. */
    tbl_old = RSA_meth_new("rt-obj-old", 0x01);
    tbl_new = RSA_meth_new("rt-obj-new", 0x02);
    (void)RSA_meth_set_finish(tbl_old, sentinel_mark_finish);
    (void)RSA_meth_set_init(tbl_new, sentinel_mark_init);
    o_setm = rt_blank();
    RT_METH(o_setm) = tbl_old;
    rt_seq = 0;
    rt_finish_at = 0;
    rt_init_at = 0;
    printf("rsa.obj_set_method.ret=%d\n", RSA_set_method(o_setm, tbl_new));
    printf("rsa.obj_set_method.store=%d\n",
        (const void *)RSA_get_method(o_setm) == (const void *)tbl_new);
    printf("rsa.obj_set_method.finish_fired=%d\n", rt_finish_at == 1);
    printf("rsa.obj_set_method.init_fired=%d\n", rt_init_at == 2);
    printf("rsa.obj_set_method.finish_before_init=%d\n", rt_finish_at < rt_init_at);
    printf("rsa.obj_set_method.engine_is_null=%d\n", RSA_get0_engine(o_setm) == NULL);

    /* ---------------------------------------------------------------- RSA_free */

    begin();
    RSA_free(NULL);
    end("obj_free_null");
    printf("rsa.obj_free_null.survived=1\n");

    /* references == 2: the release order's first rule, so the window is empty and `finish` does
     * not fire. */
    o_fref = rt_blank();
    RT_REFERENCES(o_fref) = 2;
    RT_METH(o_fref) = tbl_old;
    rt_seq = 0;
    rt_finish_at = 0;
    begin();
    RSA_free(o_fref);
    end("obj_free_refs2");
    printf("rsa.obj_free_refs2.ref_after=%d\n", RT_REFERENCES(o_fref));
    printf("rsa.obj_free_refs2.finish_fired=%d\n", rt_finish_at != 0);
    RSA_free(o_fref);

    /* One RSA ex_data index is registered before the last-reference arm so that the authority's
     * `CRYPTO_free_ex_data` finds a non-empty callback table and takes its `storage == stack` path.
     * With an empty table it instead `OPENSSL_free`s a NULL local snapshot, and that `free(NULL)`
     * reaches the caller-installed allocator -- which the candidate's `CRYPTO_free` does not forward
     * (`src/runtime/mem.rs`'s `dealloc` returns early on NULL; the authority's `CRYPTO_free` calls
     * `free_impl` unconditionally). The callback is registered with a NULL `free_func`, so it is a
     * registry entry and nothing else. This keeps the window's subject the object's own release;
     * the NULL-forwarding difference is a separate, out-of-slice divergence and not this arm's claim. */
    (void)RSA_get_ex_new_index(0, NULL, NULL, NULL, NULL);

    /* references == 1 on a fabricated heap object: the whole order, ending in the object's own F,
     * which is attributed to `rsa_lib.c`. */
    {
        void *o_last = rt_blank();

        RT_REFERENCES(o_last) = 1;
        RT_METH(o_last) = tbl_old;
        rt_seq = 0;
        rt_finish_at = 0;
        begin();
        RSA_free(o_last);
        end("obj_free_last");
        printf("rsa.obj_free_last.finish_fired=%d\n", rt_finish_at == 1);
    }

    /* ---------------------------------------------------------------- RSA_up_ref */

    o_up1 = rt_blank();
    RT_REFERENCES(o_up1) = 1;
    printf("rsa.obj_upref.one_ret=%d\n", RSA_up_ref(o_up1));
    printf("rsa.obj_upref.one_ref_after=%d\n", RT_REFERENCES(o_up1));
    o_up0 = rt_blank();
    RT_REFERENCES(o_up0) = 0;
    printf("rsa.obj_upref.zero_ret=%d\n", RSA_up_ref(o_up0));
    printf("rsa.obj_upref.zero_ref_after=%d\n", RT_REFERENCES(o_up0));

    /* ---------------------------------------------------------------- RSA_set_ex_data / RSA_get_ex_data */

    o_exd = rt_blank();
    printf("rsa.obj_ex_data.set0_ret=%d\n", RSA_set_ex_data(o_exd, 0, &app));
    printf("rsa.obj_ex_data.get0_is_app=%d\n", RSA_get_ex_data(o_exd, 0) == (void *)&app);
    printf("rsa.obj_ex_data.set_gap_ret=%d\n", RSA_set_ex_data(o_exd, 3, &app2));
    printf("rsa.obj_ex_data.get_gap_is_app2=%d\n", RSA_get_ex_data(o_exd, 3) == (void *)&app2);
    printf("rsa.obj_ex_data.gap_pad_is_null=%d\n", RSA_get_ex_data(o_exd, 1) == NULL);
    printf("rsa.obj_ex_data.get0_survives_gap=%d\n", RSA_get_ex_data(o_exd, 0) == (void *)&app);
    printf("rsa.obj_ex_data.out_of_range_is_null=%d\n",
        RSA_get_ex_data(o_exd, 100000) == NULL);

    /* ---------------------------------------------------------------- RSA_security_bits */

    o_sec = rt_blank();
    for (i = 0; i < 7; i++) {
        n = rt_bits(ladder[i]);
        RT_N(o_sec) = n;
        printf("rsa.obj_security.%d=%d\n", ladder[i], RSA_security_bits(o_sec));
        RT_N(o_sec) = NULL;
        BN_free(n);
    }
    n = rt_bits(4);
    RT_N(o_sec) = n;
    printf("rsa.obj_security.narrow=%d\n", RSA_security_bits(o_sec));
    RT_N(o_sec) = NULL;
    BN_free(n);
    n = rt_bits(687737);
    RT_N(o_sec) = n;
    printf("rsa.obj_security.wide=%d\n", RSA_security_bits(o_sec));
    RT_N(o_sec) = NULL;
    BN_free(n);

    /* ---------------------------------------------------------------- RSA_set0_key */

    o_key = rt_blank();
    ERR_clear_error();
    printf("rsa.obj_set0_key.all_null_ret=%d\n", RSA_set0_key(o_key, NULL, NULL, NULL));
    drain("obj_set0_key_refuse_all");

    n = BN_new();
    ERR_clear_error();
    printf("rsa.obj_set0_key.empty_e_ret=%d\n", RSA_set0_key(o_key, n, NULL, NULL));
    drain("obj_set0_key_refuse_e");
    BN_free(n);

    e = BN_new();
    ERR_clear_error();
    printf("rsa.obj_set0_key.empty_n_ret=%d\n", RSA_set0_key(o_key, NULL, e, NULL));
    drain("obj_set0_key_refuse_n");
    BN_free(e);

    n = BN_new();
    e = BN_new();
    d = BN_new();
    printf("rsa.obj_set0_key.store_ret=%d\n", RSA_set0_key(o_key, n, e, d));
    printf("rsa.obj_set0_key.d_consttime=%d\n",
        BN_get_flags(RT_D(o_key), BN_FLG_CONSTTIME) != 0);

    /* `dirty_cnt` bumps even when the guard passes and nothing is stored. */
    printf("rsa.obj_set0_key.dirty_before=%d\n", RT_DIRTY(o_key));
    ERR_clear_error();
    printf("rsa.obj_set0_key.nothing_ret=%d\n", RSA_set0_key(o_key, NULL, NULL, NULL));
    printf("rsa.obj_set0_key.dirty_after=%d\n", RT_DIRTY(o_key));
    drain("obj_set0_key_noop");

    /* The replacement. The authority's own transcript for this call is a sequence of `bn_lib.c`
     * F's (the old `n`/`e`/`d` released), but the candidate's `BIGNUM` is a Rust `Box`/`Vec` and its
     * `BN_free` never reaches `CRYPTO_set_mem_functions` (`src/bn/bignum.rs`'s `BN_free` is
     * `Box::from_raw`), so that window can never be equal across the two sides. What *is* comparable
     * is the store: the three fields become the caller's pointers, `d` gains `BN_FLG_CONSTTIME`, and
     * `dirty_cnt` moves. */
    a1 = BN_new();
    a2 = BN_new();
    a3 = BN_new();
    printf("rsa.obj_set0_key.replace_ret=%d\n", RSA_set0_key(o_key, a1, a2, a3));
    printf("rsa.obj_set0_key.replaced_n=%d\n", RSA_get0_n(o_key) == a1);
    printf("rsa.obj_set0_key.replaced_e=%d\n", RSA_get0_e(o_key) == a2);
    printf("rsa.obj_set0_key.replaced_d=%d\n", RSA_get0_d(o_key) == a3);
    printf("rsa.obj_set0_key.replaced_d_consttime=%d\n",
        BN_get_flags(RT_D(o_key), BN_FLG_CONSTTIME) != 0);
    printf("rsa.obj_set0_key.dirty_after_replace=%d\n", RT_DIRTY(o_key));

    /* ---------------------------------------------------------------- RSA_set0_factors */

    o_fac = rt_blank();
    ERR_clear_error();
    printf("rsa.obj_set0_factors.all_null_ret=%d\n", RSA_set0_factors(o_fac, NULL, NULL));
    drain("obj_set0_factors_refuse_all");

    p = BN_new();
    ERR_clear_error();
    printf("rsa.obj_set0_factors.empty_q_ret=%d\n", RSA_set0_factors(o_fac, p, NULL));
    drain("obj_set0_factors_refuse_q");
    BN_free(p);

    q = BN_new();
    ERR_clear_error();
    printf("rsa.obj_set0_factors.empty_p_ret=%d\n", RSA_set0_factors(o_fac, NULL, q));
    drain("obj_set0_factors_refuse_p");
    BN_free(q);

    p = BN_new();
    q = BN_new();
    printf("rsa.obj_set0_factors.store_ret=%d\n", RSA_set0_factors(o_fac, p, q));
    printf("rsa.obj_set0_factors.p_consttime=%d\n",
        BN_get_flags(RT_P(o_fac), BN_FLG_CONSTTIME) != 0);
    printf("rsa.obj_set0_factors.q_consttime=%d\n",
        BN_get_flags(RT_Q(o_fac), BN_FLG_CONSTTIME) != 0);

    /* ---------------------------------------------------------------- RSA_set0_crt_params */

    o_crt = rt_blank();
    ERR_clear_error();
    printf("rsa.obj_set0_crt.all_null_ret=%d\n", RSA_set0_crt_params(o_crt, NULL, NULL, NULL));
    drain("obj_set0_crt_refuse_all");

    dmp1 = BN_new();
    ERR_clear_error();
    printf("rsa.obj_set0_crt.empty_dmq1_ret=%d\n",
        RSA_set0_crt_params(o_crt, dmp1, NULL, NULL));
    drain("obj_set0_crt_refuse_dmq1");
    BN_free(dmp1);

    dmp1 = BN_new();
    dmq1 = BN_new();
    ERR_clear_error();
    printf("rsa.obj_set0_crt.empty_iqmp_ret=%d\n",
        RSA_set0_crt_params(o_crt, dmp1, dmq1, NULL));
    drain("obj_set0_crt_refuse_iqmp");
    BN_free(dmp1);
    BN_free(dmq1);

    dmp1 = BN_new();
    dmq1 = BN_new();
    iqmp = BN_new();
    printf("rsa.obj_set0_crt.store_ret=%d\n", RSA_set0_crt_params(o_crt, dmp1, dmq1, iqmp));
    printf("rsa.obj_set0_crt.dmp1_consttime=%d\n",
        BN_get_flags(RT_DMP1(o_crt), BN_FLG_CONSTTIME) != 0);
    printf("rsa.obj_set0_crt.dmq1_consttime=%d\n",
        BN_get_flags(RT_DMQ1(o_crt), BN_FLG_CONSTTIME) != 0);
    printf("rsa.obj_set0_crt.iqmp_consttime=%d\n",
        BN_get_flags(RT_IQMP(o_crt), BN_FLG_CONSTTIME) != 0);

    /* ---------------------------------------------------------------- RSA_set0_multi_prime_params */

    /* p and q must be set *before* the success call, because `ossl_rsa_multip_calc_product`
     * multiplies them. The refusals raise nothing, so their drains are empty. */
    o_mp = rt_blank();
    (void)RSA_set0_factors(o_mp, rt_word(0x0b), rt_word(0x0d));
    mp_primes[0] = rt_word(0x11);
    mp_exps[0] = rt_word(0x13);
    mp_coeffs[0] = rt_word(0x17);

    ERR_clear_error();
    printf("rsa.obj_set0_mp.primes_null_ret=%d\n",
        RSA_set0_multi_prime_params(o_mp, NULL, mp_exps, mp_coeffs, 1));
    drain("obj_set0_mp_refuse_primes");
    ERR_clear_error();
    printf("rsa.obj_set0_mp.exps_null_ret=%d\n",
        RSA_set0_multi_prime_params(o_mp, mp_primes, NULL, mp_coeffs, 1));
    drain("obj_set0_mp_refuse_exps");
    ERR_clear_error();
    printf("rsa.obj_set0_mp.coeffs_null_ret=%d\n",
        RSA_set0_multi_prime_params(o_mp, mp_primes, mp_exps, NULL, 1));
    drain("obj_set0_mp_refuse_coeffs");
    ERR_clear_error();
    printf("rsa.obj_set0_mp.pnum_zero_ret=%d\n",
        RSA_set0_multi_prime_params(o_mp, mp_primes, mp_exps, mp_coeffs, 0));
    drain("obj_set0_mp_refuse_pnum");

    printf("rsa.obj_set0_mp.dirty_before=%d\n", RT_DIRTY(o_mp));
    RT_N(o_mp) = rt_bits(512);
    printf("rsa.obj_set0_mp.set_ret=%d\n",
        RSA_set0_multi_prime_params(o_mp, mp_primes, mp_exps, mp_coeffs, 1));
    printf("rsa.obj_set0_mp.version=%d\n", RSA_get_version(o_mp));
    printf("rsa.obj_set0_mp.dirty_after=%d\n", RT_DIRTY(o_mp));
    printf("rsa.obj_set0_mp.extra_count=%d\n", RSA_get_multi_prime_extra_count(o_mp));
    mpf[0] = mpe[0] = mpc[0] = NULL;
    printf("rsa.obj_set0_mp.factors_ret=%d\n", RSA_get0_multi_prime_factors(o_mp, mpf));
    printf("rsa.obj_set0_mp.factors_is_stored=%d\n", mpf[0] == mp_primes[0]);
    printf("rsa.obj_set0_mp.crt_ret=%d\n",
        RSA_get0_multi_prime_crt_params(o_mp, mpe, mpc));
    printf("rsa.obj_set0_mp.crt_exps_is_stored=%d\n", mpe[0] == mp_exps[0]);
    printf("rsa.obj_set0_mp.crt_coeffs_is_stored=%d\n", mpc[0] == mp_coeffs[0]);

    /* The multi-prime refusal in `RSA_security_bits`: 512 bits is below 1024, so the cap is 2 and
     * one extra prime plus the two factors is 3. The modulus is real, so the refusal is the cap and
     * not a narrow-modulus answer. */
    printf("rsa.obj_security.mp_refuse_512=%d\n", RSA_security_bits(o_mp));

    /* The same shape at a width the cap permits: 2048 bits, cap 3, one extra prime -> allowed. */
    o_mp2 = rt_blank();
    (void)RSA_set0_factors(o_mp2, rt_word(0x0b), rt_word(0x0d));
    RT_N(o_mp2) = rt_bits(2048);
    mp_primes[0] = rt_word(0x11);
    mp_exps[0] = rt_word(0x13);
    mp_coeffs[0] = rt_word(0x17);
    printf("rsa.obj_security.mp_allow_2048_set=%d\n",
        RSA_set0_multi_prime_params(o_mp2, mp_primes, mp_exps, mp_coeffs, 1));
    printf("rsa.obj_security.mp_allow_2048=%d\n", RSA_security_bits(o_mp2));

    /* ---------------------------------------------------------------- the eleven get0_* readers */

    o_full = rt_blank();
    fn = rt_word(0x11);
    fe = rt_word(0x03);
    fd = rt_word(0x2b);
    fp = rt_word(0x07);
    fq = rt_word(0x0d);
    fd1 = rt_word(0x13);
    fd2 = rt_word(0x17);
    fi = rt_word(0x1d);
    printf("rsa.obj_get0.key_store_ret=%d\n", RSA_set0_key(o_full, fn, fe, fd));
    printf("rsa.obj_get0.factors_store_ret=%d\n", RSA_set0_factors(o_full, fp, fq));
    printf("rsa.obj_get0.crt_store_ret=%d\n", RSA_set0_crt_params(o_full, fd1, fd2, fi));

    on = oe = od = NULL;
    RSA_get0_key(o_full, &on, NULL, &od);
    printf("rsa.obj_get0.key_optional_n=%d\n", on == fn);
    printf("rsa.obj_get0.key_optional_d=%d\n", od == fd);
    oe = NULL;
    RSA_get0_key(o_full, NULL, &oe, NULL);
    printf("rsa.obj_get0.key_optional_e=%d\n", oe == fe);
    RSA_get0_key(o_full, NULL, NULL, NULL);
    printf("rsa.obj_get0.key_all_null_survived=1\n");

    op = oq = NULL;
    RSA_get0_factors(o_full, &op, NULL);
    printf("rsa.obj_get0.factors_optional_p=%d\n", op == fp);
    oq = NULL;
    RSA_get0_factors(o_full, NULL, &oq);
    printf("rsa.obj_get0.factors_optional_q=%d\n", oq == fq);

    odmp1 = odmq1 = oiqmp = NULL;
    RSA_get0_crt_params(o_full, &odmp1, NULL, &oiqmp);
    printf("rsa.obj_get0.crt_optional_dmp1=%d\n", odmp1 == fd1);
    printf("rsa.obj_get0.crt_optional_iqmp=%d\n", oiqmp == fi);
    odmq1 = NULL;
    RSA_get0_crt_params(o_full, NULL, &odmq1, NULL);
    printf("rsa.obj_get0.crt_optional_dmq1=%d\n", odmq1 == fd2);

    /* The identity arms: the pointer the setter stored is the pointer the accessor answers, which
     * is what ties the probe's fabricated offsets to the library's own. */
    printf("rsa.obj_components.n=%d\n", RSA_get0_n(o_full) == fn);
    printf("rsa.obj_components.e=%d\n", RSA_get0_e(o_full) == fe);
    printf("rsa.obj_components.d=%d\n", RSA_get0_d(o_full) == fd);
    printf("rsa.obj_components.p=%d\n", RSA_get0_p(o_full) == fp);
    printf("rsa.obj_components.q=%d\n", RSA_get0_q(o_full) == fq);
    printf("rsa.obj_components.dmp1=%d\n", RSA_get0_dmp1(o_full) == fd1);
    printf("rsa.obj_components.dmq1=%d\n", RSA_get0_dmq1(o_full) == fd2);
    printf("rsa.obj_components.iqmp=%d\n", RSA_get0_iqmp(o_full) == fi);

    /* An object with no extra primes: the count folds -1 to 0, and neither array reader touches its
     * (all-NULL) output slots. */
    {
        void *o_nomp = rt_blank();

        mpf[0] = (const BIGNUM *)&app;
        mpe[0] = mpc[0] = (const BIGNUM *)&app;
        printf("rsa.obj_mp_count.blank=%d\n", RSA_get_multi_prime_extra_count(o_nomp));
        printf("rsa.obj_get0_mp.factors_no_extra_ret=%d\n",
            RSA_get0_multi_prime_factors(o_nomp, mpf));
        printf("rsa.obj_get0_mp.factors_untouched=%d\n", mpf[0] == (const BIGNUM *)&app);
        printf("rsa.obj_get0_mp.crt_no_extra_ret=%d\n",
            RSA_get0_multi_prime_crt_params(o_nomp, mpe, mpc));
        printf("rsa.obj_get0_mp.crt_untouched=%d\n",
            mpe[0] == (const BIGNUM *)&app && mpc[0] == (const BIGNUM *)&app);
        rt_release(o_nomp);
    }

    /* ---------------------------------------------------------------- RSA_get0_pss_params */

    o_pss = rt_blank();
    printf("rsa.obj_pss.blank_is_null=%d\n", RSA_get0_pss_params(o_pss) == NULL);
    RT_PSS(o_pss) = &app;
    printf("rsa.obj_pss.sentinel=%d\n",
        (const void *)RSA_get0_pss_params(o_pss) == (const void *)&app);

    /* ---------------------------------------------------------------- RSA_flag accessors, version, engine */

    o_flags = rt_blank();
    RT_FLAGS(o_flags) = 0;
    RSA_set_flags(o_flags, 0x0008);
    printf("rsa.obj_flags.set_or=%d\n", RT_FLAGS(o_flags));
    printf("rsa.obj_flags.test_exact=%d\n", RSA_test_flags(o_flags, 0x0008));
    /* The masked word, not 0/1: one flag set, two asked for, the answer is the flag itself. */
    printf("rsa.obj_flags.test_masked_word=%d\n", RSA_test_flags(o_flags, 0x000c));
    printf("rsa.obj_flags.test_absent=%d\n", RSA_test_flags(o_flags, 0x0010));
    RSA_clear_flags(o_flags, 0x0008);
    printf("rsa.obj_flags.clear_andnot=%d\n", RT_FLAGS(o_flags));
    RSA_set_flags(o_flags, 0x000f);
    printf("rsa.obj_flags.set_accumulate=%d\n", RT_FLAGS(o_flags));
    RSA_clear_flags(o_flags, 0x0006);
    printf("rsa.obj_flags.clear_partial=%d\n", RT_FLAGS(o_flags));

    printf("rsa.obj_version.blank=%d\n", RSA_get_version(o_flags));
    printf("rsa.obj_version.mp_multi=%d\n", RSA_get_version(o_mp));
    printf("rsa.obj_engine.blank_is_null=%d\n", RSA_get0_engine(o_flags) == NULL);
    printf("rsa.obj_engine.full_is_null=%d\n", RSA_get0_engine(o_full) == NULL);
    printf("rsa.obj_engine.mp_is_null=%d\n", RSA_get0_engine(o_mp) == NULL);

    /* ---------------------------------------------------------------- RSA_bits / RSA_size */

    o_bits = rt_blank();
    RT_N(o_bits) = rt_word(0);
    printf("rsa.obj_bits_size.bits0=%d\n", RSA_bits(o_bits));
    printf("rsa.obj_bits_size.size0=%d\n", RSA_size(o_bits));
    BN_free(RT_N(o_bits));
    RT_N(o_bits) = rt_word(1);
    printf("rsa.obj_bits_size.bits1=%d\n", RSA_bits(o_bits));
    printf("rsa.obj_bits_size.size1=%d\n", RSA_size(o_bits));
    BN_free(RT_N(o_bits));
    RT_N(o_bits) = rt_word(255);
    printf("rsa.obj_bits_size.bits255=%d\n", RSA_bits(o_bits));
    printf("rsa.obj_bits_size.size255=%d\n", RSA_size(o_bits));
    BN_free(RT_N(o_bits));
    RT_N(o_bits) = rt_word(256);
    printf("rsa.obj_bits_size.bits256=%d\n", RSA_bits(o_bits));
    printf("rsa.obj_bits_size.size256=%d\n", RSA_size(o_bits));

    /* ---------------------------------------------------------------- RSA_flags */

    /* The only accessor in the slice with a NULL guard, and the object's `flags` word is not what
     * it answers: `r->meth->flags` is, at offset 72 of the table. */
    printf("rsa.obj_null_flags=%d\n", RSA_flags(NULL));
    tbl_flags = RSA_meth_new("rt-obj-flags", 0x4321);
    RT_METH(o_flags) = tbl_flags;
    printf("rsa.obj_flags_table.ret=%d\n", RSA_flags(o_flags));
    printf("rsa.obj_flags_table.is_meth_flags=%d\n",
        RSA_flags(o_flags) == RSA_meth_get_flags(tbl_flags));
    printf("rsa.obj_flags_table.not_object_flags=%d\n",
        RSA_flags(o_flags) != RT_FLAGS(o_flags));
    printf("rsa.obj_flags_table.probe_offset=%d\n",
        RT_METH_FLAGS(tbl_flags) == RSA_meth_get_flags(tbl_flags));

    /* ---------------------------------------------------------------- release */

    /* Each fabricated object is the probe's own `malloc`, and the installed `my_free` calls the same
     * `free`, so `RSA_free`'s own `CRYPTO_free` releases them. The tables come last: the objects
     * hold pointers into them. */
    free(o_get);
    free(o_setm);
    free(o_up1);
    free(o_up0);
    free(o_flags);
    free(o_pss);
    rt_release(o_exd);
    rt_release(o_sec);
    rt_release(o_key);
    rt_release(o_fac);
    rt_release(o_crt);
    rt_release(o_mp);
    rt_release(o_mp2);
    rt_release(o_full);
    rt_release(o_bits);
    RSA_meth_free(tbl_get);
    RSA_meth_free(tbl_old);
    RSA_meth_free(tbl_new);
    RSA_meth_free(tbl_flags);
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

    /* PKCS#1 v1.5 type 2: `00 02 nonzero... 00 D`, and **not one of the random padding octets is
     * printed**. What is printed instead is the predicate the retry loop exists to make true --
     * every padding octet non-zero -- and then the block is handed to
     * `RSA_padding_check_PKCS1_type_2`, whose answer is a *length* and a byte comparison rather
     * than a byte. So the whole arm is a differential observation of a random block without the
     * transcript ever depending on the randomness. */
    ERR_clear_error();
    memset(blk, 0, sizeof(blk));
    printf("rsa.pad_t2.ok=%d\n", RSA_padding_add_PKCS1_type_2(blk, 16, from, 5));
    printf("rsa.pad_t2.0=%02x\n", blk[0]);
    printf("rsa.pad_t2.1=%02x\n", blk[1]);
    /* `j = 16 - 3 - 5 = 8` padding octets at 2..10. */
    printf("rsa.pad_t2.pad_nonzero=%d\n", rt_all_nonzero(blk + 2, 8));
    printf("rsa.pad_t2.sep=%02x\n", blk[10]);
    printf("rsa.pad_t2.body=%d\n", memcmp(blk + 11, from, 5) == 0);
    drain("pad_t2_ok");

    /* The two refusals, and they raise *different* reasons: too long is
     * `RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE`, negative is `RSA_R_INVALID_LENGTH`. The negative one is
     * reachable from no real caller, which is why the second error site exists at all. */
    ERR_clear_error();
    printf("rsa.pad_t2.long=%d\n", RSA_padding_add_PKCS1_type_2(blk, 16, from, 6));
    drain("pad_t2_long");
    ERR_clear_error();
    printf("rsa.pad_t2.neg=%d\n", RSA_padding_add_PKCS1_type_2(blk, 16, from, -1));
    drain("pad_t2_neg");

    /* The round trip, on the block the arm above produced: the check scans for the *first* zero
     * octet from index 2, so a padding octet that was left zero would move the separator and the
     * length would not be 5. */
    ERR_clear_error();
    memset(to, 0x5a, sizeof(to));
    printf("rsa.chk_t2.ok=%d\n", RSA_padding_check_PKCS1_type_2(to, 64, blk, 16, 16));
    printf("rsa.chk_t2.body=%d\n", memcmp(to, from, 5) == 0);
    drain("chk_t2_ok");

    /* The two silent size refusals: `-1` with an **empty** queue, which is the observation the
     * `err.count` line carries. */
    ERR_clear_error();
    printf("rsa.chk_t2.tlen0=%d\n", RSA_padding_check_PKCS1_type_2(to, 0, blk, 16, 16));
    drain("chk_t2_tlen0");
    ERR_clear_error();
    printf("rsa.chk_t2.flen0=%d\n", RSA_padding_check_PKCS1_type_2(to, 64, blk, 0, 16));
    drain("chk_t2_flen0");

    /* And the two that do raise, both from the same site: an octet count under the eleven-octet
     * minimum, and an encoded message longer than the modulus. */
    ERR_clear_error();
    printf("rsa.chk_t2.pad_short=%d\n", RSA_padding_check_PKCS1_type_2(to, 64, blk, 8, 8));
    drain("chk_t2_pad_short");
    ERR_clear_error();
    printf("rsa.chk_t2.toolong=%d\n", RSA_padding_check_PKCS1_type_2(to, 64, blk, 17, 16));
    drain("chk_t2_toolong");

    /* The constant-time refusal, where the error is left on the queue rather than flagged away.
     * A padding string one octet short of the eight-octet minimum is the `zero_index >= 2 + 8`
     * arm; a block type that is not 2 is the header arm; and a block with no zero octet at all
     * leaves `zero_index` at 0. */
    memset(blk, 0x11, sizeof(blk));
    blk[0] = 0x00;
    blk[1] = 0x02;
    blk[9] = 0x00;
    ERR_clear_error();
    printf("rsa.chk_t2.narrow=%d\n", RSA_padding_check_PKCS1_type_2(to, 64, blk, 16, 16));
    drain("chk_t2_narrow");
    memset(blk, 0x11, sizeof(blk));
    blk[0] = 0x00;
    blk[1] = 0x03;
    blk[10] = 0x00;
    ERR_clear_error();
    printf("rsa.chk_t2.type=%d\n", RSA_padding_check_PKCS1_type_2(to, 64, blk, 16, 16));
    drain("chk_t2_type");
    memset(blk, 0x11, sizeof(blk));
    blk[0] = 0x00;
    blk[1] = 0x02;
    ERR_clear_error();
    printf("rsa.chk_t2.nosep=%d\n", RSA_padding_check_PKCS1_type_2(to, 64, blk, 16, 16));
    drain("chk_t2_nosep");

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

    /* The PSS adds, which need a fabricated object of their own: their `RSA *` argument is read for
     * its modulus, and no constructor exists on the candidate side yet. */
    rsa_pss_arms();

    /* The slice A object layer: every export the candidate publishes that needs no constructor. */
    rsa_object_arms();

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
