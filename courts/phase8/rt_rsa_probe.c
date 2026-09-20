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
 * type-2 *check* -- and **every one of the sixteen is called below**. Slice D is
 * `rsa_ossl.c`'s default method: the table itself, the four-name family around it
 * (`RSA_PKCS1_OpenSSL`, `RSA_get_default_method`, `RSA_set_default_method` and the constructor
 * pair), and the seven `rsa_ossl_*` entry points, which are driven **through the table's own
 * `RSA_meth_get_*` accessors** because they are `static` in the authority and have no name to
 * link. `RSA_setup_blinding` -- `rsa_crpt.c`'s export, and the caller that makes
 * `ossl_rsa_alloc_blinding` reachable -- is called too. Slice E is `crypto/rsa/rsa_x931g.c`'s two
 * key generators plus the four `rsa_crpt.c` crypt wrappers, and **all six are called below**: the
 * derivation arm is deterministic (fixed seeds) and the generation arm drives the wrappers as
 * round trips over a key it generated. That slice's other three names -- `RSA_generate_key_ex`,
 * `RSA_generate_multi_prime_key` and `RSA_generate_key` -- were blocked on a `crypto/bn` unit
 * until D327, and **all three are called below too**, over both generators: the SP800-56B path
 * (2 primes, at least 2048 bits, an exponent wider than 16 bits) and `rsa_multiprime_keygen`
 * (more than two primes, or a small exponent).
 *
 * **Three of the four sections below were added by D328**, and each brings a unit that has no
 * other court in this court's family. `rsa_sig_arms` drives `rsa_sign.c`'s and `rsa_saos.c`'s four
 * entry points, `ossl_rsa_verify`'s recovery arm through the internal, and `rsa_pss.c`'s verifier;
 * `rsa_chk_arms` drives `rsa_chk.c`'s two checkers and `rsa_crpt.c`'s blinding pair; and
 * `rsa_ctl_arms` drives `rsa_lib.c`'s `RSA_pkey_ctx_ctrl` and all twenty-three
 * `EVP_PKEY_CTX_{get,set}_rsa_*` controls. **Every one of the thirty-four is called below.**
 * `rsa_ctl_arms` is the only one that publishes a provider -- a keymgmt named `COURT-RSA`, so a
 * control can be asked what it decides about a context that exists -- and its comment says what
 * that fixture can and cannot reach.
 *
 * The signing arms were the first arms in this court that could compare a *signature* rather than
 * a round trip, and they do it by building the expected block out here: `RSA_X931_derive_ex` over
 * fixed seeds makes the key a function of the probe's constants, RSASSA-PKCS1-v1_5's encoding is
 * deterministic, and the SHA-256 `DigestInfo` prefix the arm compares against is RFC 8017 appendix
 * B.1's own bytes rather than a call into the library. Nothing
 * here does any cryptography
 * beyond small RSA exponentiations -- each function allocates a table or an object, stores a
 * pointer in one, reads one, pads a buffer, raises a 12-bit modulus to the 17th power, or runs
 * one 128-bit CRT private operation -- so the transcript is about *identity, ownership and
 * structure* rather than arithmetic, and that is the whole observable contract of these entry
 * points.
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
 * **`RSA` is opaque in the installed header on both sides**, so the object arms that need a
 * subject of their own build it: the fabrication block below owns the shape, transcribed offset by
 * offset from `courts/layout/measure-rsa-ctx.c` (D283's measurement), and hands both binaries the
 * same bytes, the same genuine `BIGNUM`s and the same genuine `RSA_METHOD` from `RSA_meth_new`.
 * The observation is the *library's* answer, and the `get0_*` identity arms tie the probe's offsets
 * to the library's. **The constructor arms no longer fabricate anything**: `RSA_new`,
 * `RSA_new_method` and `RSA_setup_blinding` are landed (D325), so those arms call them.
 *
 * **Every export of the four slices is called, and the one thing that is not is named here.**
 * `RSA_new_method` is only ever called with NULL: a non-NULL engine is a fault in the authority
 * (there is no engine registered, so `ENGINE_get_RSA` answers NULL and `rsa_new_intern` raises
 * `RSA_LIB_116`) and is ignored by the candidate, which has no `ENGINE` at all -- a difference
 * this probe cannot compare without an `ENGINE_new`, which is Phase 13's. `RSA_bits` and
 * `RSA_size` are **not** called on a freshly constructed object either: the authority's
 * `BN_num_bits` dereferences `b->top` without a NULL test, so `RSA_bits(RSA_new())` is a
 * segmentation fault there where the candidate answers 0. Both omissions are recorded in
 * `docs/DECISIONS.md` D325 rather than left as arms that happened to be missing.
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
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>
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

/* `RSA` is opaque in the installed header on both sides, so the arms that need a subject of their
 * own fabricate one: `rt_blank` owns the shape, transcribed from `courts/layout/measure-rsa-ctx.c`
 * (D283's measurement) with every offset pinned. 27 pointers is exactly 216 bytes and is
 * eight-aligned. Both binaries are handed the same bytes, the same genuine `BIGNUM`s and the same
 * genuine `RSA_METHOD` from `RSA_meth_new`, and the observation is the *library's* answer. The
 * constructor arms added by D325 need none of this: they call `RSA_new` and `RSA_new_method(NULL)`
 * and read the result back through the published accessors. `rt_blank` memsets all 216 bytes
 * because `forensics/tools/probe_hygiene.py` recompiles this probe at several optimisation levels
 * and requires an identical transcript, and a partially-initialised object is exactly the bug class
 * it exists to catch. */
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

/* The 128-bit two-prime key the PKCS#1 private-decrypt arms use, built with the published BN API
 * so that both binaries compute it identically: p = 2^64 - 59 and q = 2^61 - 1 are both prime,
 * n = p*q is 125 bits (16 octets, so a full EME-PKCS1-v1_5 block fits), e = 65537 is coprime with
 * both p-1 and q-1, and d, dmp1, dmq1 and iqmp are the usual CRT parameters.
 *
 * **The key is built rather than typed.** A 38-digit decimal `n` written twice is a constant typed
 * wrong once, and the same `BN_mul`/`BN_mod_inverse` calls run on both sides: the arms below
 * compare the two libraries, not the probe's arithmetic. A failed inversion would answer NULL and
 * the arms would then observe the refusals, which is a comparison too. */
static int rt_key128(BIGNUM **n_out, BIGNUM **e_out, BIGNUM **d_out, BIGNUM **p_out,
    BIGNUM **q_out, BIGNUM **dmp1_out, BIGNUM **dmq1_out, BIGNUM **iqmp_out)
{
    BIGNUM *p = NULL, *q = NULL, *e = NULL, *phi = NULL, *pm1 = NULL, *qm1 = NULL;
    BIGNUM *n = NULL, *d = NULL, *dmp1 = NULL, *dmq1 = NULL, *iqmp = NULL;
    BN_CTX *ctx = NULL;
    int ok = 0;

    p = rt_word(18446744073709551557ULL); /* 2^64 - 59 */
    q = rt_word(2305843009213693951ULL);  /* 2^61 - 1  */
    e = rt_word(65537);
    ctx = BN_CTX_new();
    pm1 = BN_new();
    qm1 = BN_new();
    phi = BN_new();
    n = BN_new();
    dmp1 = BN_new();
    dmq1 = BN_new();
    iqmp = BN_new();
    if (p == NULL || q == NULL || e == NULL || ctx == NULL || pm1 == NULL || qm1 == NULL
        || phi == NULL || n == NULL || dmp1 == NULL || dmq1 == NULL || iqmp == NULL)
        goto err;

    if (BN_copy(pm1, p) == NULL || BN_copy(qm1, q) == NULL)
        goto err;
    if (BN_sub_word(pm1, 1) != 1 || BN_sub_word(qm1, 1) != 1)
        goto err;
    if (BN_mul(phi, pm1, qm1, ctx) != 1)
        goto err;
    d = BN_mod_inverse(NULL, e, phi, ctx);
    if (d == NULL)
        goto err;
    if (BN_mul(n, p, q, ctx) != 1)
        goto err;
    if (BN_mod(dmp1, d, pm1, ctx) != 1 || BN_mod(dmq1, d, qm1, ctx) != 1)
        goto err;
    if (BN_mod_inverse(iqmp, q, p, ctx) == NULL)
        goto err;

    *n_out = n;
    *e_out = e;
    *d_out = d;
    *p_out = p;
    *q_out = q;
    *dmp1_out = dmp1;
    *dmq1_out = dmq1;
    *iqmp_out = iqmp;
    n = e = d = p = q = dmp1 = dmq1 = iqmp = NULL;
    ok = 1;

err:
    BN_free(p);
    BN_free(q);
    BN_free(e);
    BN_free(phi);
    BN_free(pm1);
    BN_free(qm1);
    BN_free(n);
    BN_free(d);
    BN_free(dmp1);
    BN_free(dmq1);
    BN_free(iqmp);
    BN_CTX_free(ctx);
    return ok;
}

/* ------------------------------------------------------------------ the default method (slice D) */

/* `crypto/rsa/rsa_ossl.c`'s table, the four-name family around it and the seven entry points it
 * names.
 *
 * **The entry points are `static` in the authority**, so there is no name to link: each is taken
 * from the table through the `RSA_meth_get_*` accessor that reads that member, and called under the
 * signature `rsa.h` publishes for it. The arm that observes the accessors returning non-NULL is
 * therefore also the arm that makes the call possible, and a member that answered the wrong
 * function would show as a wrong ciphertext rather than as an absent symbol.
 *
 * **The key is the textbook two-prime one, small enough to have no unknown in it**: p = 61,
 * q = 53, n = 3233, e = 17, d = 2753, dmp1 = 2753 mod 60 = 53, dmq1 = 2753 mod 52 = 49,
 * iqmp = 53^-1 mod 61 = 38. Every operation below is therefore a deterministic function of the
 * key and the input, and the bytes are printed because nothing in them came from a generator.
 *
 * **`RSA_FLAG_NO_BLINDING` is set on the private-key object**, because a blinding factor *is* drawn
 * from the DRBG and a probe that printed an unblinded result would differ between two runs. The
 * arm that drives `RSA_setup_blinding` is the one arm on the blinding path, and it observes only
 * the shape of the answer -- non-NULL and its flags -- never a byte of the factor.
 *
 * **No `begin()`/`end()` window wraps these arms, and that is a measured correction.** These are
 * the first arms in this probe to call a *constructor*, and a constructor allocates more than the
 * object: `RSA_new` allocates the object (216 bytes, `rsa_lib.c`), a lock and the blinding array.
 * The lock is the problem -- the authority's `CRYPTO_THREAD_lock_new` is
 * `OPENSSL_zalloc(sizeof(CRYPTO_RWLOCK))`, 56 bytes attributed to `crypto/threads_pthread.c`, and
 * the candidate's is a Rust `Box` that a caller-installed allocator never sees (D325) -- so a
 * window over a constructor is off by exactly one `M` and one `F` on the candidate side, and two
 * transcripts that differ by a known event are still two transcripts this court refuses to call
 * equal. The alternative `RT-CIPHER-MEM` takes for its own unit is not available here either: the
 * object's allocation is the *unit's* and the lock's is not. So the constructor arms observe the
 * structure the accessors publish -- identity, flags, the engine member, the ordinal of the
 * default method -- and D325 records the allocator-plane difference as the residual it is. */
static void rsa_ossl_arms(void)
{
    const RSA_METHOD *ro_meth;
    const RSA_METHOD *bfr;
    RSA_METHOD *tbl;
    RSA *r1 = NULL, *r2 = NULL, *o = NULL, *ob = NULL, *om = NULL;
    BIGNUM *n, *e, *d, *p, *q, *dmp1, *dmq1, *iqmp;
    BIGNUM *bn = NULL, *be = NULL, *bn_out = NULL, *bn_in = NULL;
    BIGNUM *kn = NULL, *ke = NULL, *kd = NULL, *kp = NULL, *kq = NULL;
    BIGNUM *kdmp1 = NULL, *kdmq1 = NULL, *kiqmp = NULL;
    BN_BLINDING *blinding = NULL;
    BN_CTX *ctx = NULL;
    int i, ret, pad, ok;
    /* 0x0b1a is 2842: smaller than 3233, so a `RSA_NO_PADDING` block of exactly the modulus width
     * is a plain number and not a padded message. */
    unsigned char from[4] = { 0x0b, 0x1a, 0x00, 0x00 };
    unsigned char to[4];
    unsigned char back[4];
    unsigned char enc[4];
    /* The 128-bit key's arms work on 16-octet blocks; the buffers are 32 so that a mistake cannot
     * read past them on either side. */
    unsigned char em[32];
    unsigned char ct[32];
    unsigned char out[32];

    int (*pub_enc)(int, const unsigned char *, unsigned char *, RSA *, int);
    int (*pub_dec)(int, const unsigned char *, unsigned char *, RSA *, int);
    int (*priv_enc)(int, const unsigned char *, unsigned char *, RSA *, int);
    int (*priv_dec)(int, const unsigned char *, unsigned char *, RSA *, int);
    int (*mod_exp)(BIGNUM *, const BIGNUM *, RSA *, BN_CTX *);
    int (*init)(RSA *);
    int (*finish)(RSA *);

    /* ---------------------------------------------------------------- the table */

    ro_meth = RSA_PKCS1_OpenSSL();
    printf("rsa.ossl.table.nonnull=%d\n", ro_meth != NULL);
    printf("rsa.ossl.table.is_default=%d\n", RSA_get_default_method() == RSA_PKCS1_OpenSSL());
    printf("rsa.ossl.table.name=%s\n", RSA_meth_get0_name(ro_meth));
    printf("rsa.ossl.table.flags=%d\n", RSA_meth_get_flags(ro_meth));
    printf("rsa.ossl.table.app_data_is_null=%d\n", RSA_meth_get0_app_data(ro_meth) == NULL);
    printf("rsa.ossl.table.pub_enc_set=%d\n", RSA_meth_get_pub_enc(ro_meth) != NULL);
    printf("rsa.ossl.table.pub_dec_set=%d\n", RSA_meth_get_pub_dec(ro_meth) != NULL);
    printf("rsa.ossl.table.priv_enc_set=%d\n", RSA_meth_get_priv_enc(ro_meth) != NULL);
    printf("rsa.ossl.table.priv_dec_set=%d\n", RSA_meth_get_priv_dec(ro_meth) != NULL);
    printf("rsa.ossl.table.mod_exp_set=%d\n", RSA_meth_get_mod_exp(ro_meth) != NULL);
    /* The table's `bn_mod_exp` is the *Montgomery* function by address, which is what makes
     * `rsa_ossl_mod_exp` take its `smooth` path. The accessor returns that signature, so this is
     * the one arm that observes the initialiser's most consequential member. */
    printf("rsa.ossl.table.bn_mod_exp_is_mont=%d\n",
        RSA_meth_get_bn_mod_exp(ro_meth) == BN_mod_exp_mont);
    printf("rsa.ossl.table.init_set=%d\n", RSA_meth_get_init(ro_meth) != NULL);
    printf("rsa.ossl.table.finish_set=%d\n", RSA_meth_get_finish(ro_meth) != NULL);
    /* The four members the authority writes as the integer `0` or NULL. */
    printf("rsa.ossl.table.sign_is_null=%d\n", RSA_meth_get_sign(ro_meth) == NULL);
    printf("rsa.ossl.table.verify_is_null=%d\n", RSA_meth_get_verify(ro_meth) == NULL);
    printf("rsa.ossl.table.keygen_is_null=%d\n", RSA_meth_get_keygen(ro_meth) == NULL);
    printf("rsa.ossl.table.mp_keygen_is_null=%d\n",
        RSA_meth_get_multi_prime_keygen(ro_meth) == NULL);

    pub_enc = RSA_meth_get_pub_enc(ro_meth);
    pub_dec = RSA_meth_get_pub_dec(ro_meth);
    priv_enc = RSA_meth_get_priv_enc(ro_meth);
    priv_dec = RSA_meth_get_priv_dec(ro_meth);
    mod_exp = RSA_meth_get_mod_exp(ro_meth);
    init = RSA_meth_get_init(ro_meth);
    finish = RSA_meth_get_finish(ro_meth);

    /* ---------------------------------------------------------------- RSA_set_default_method */

    /* A table with no members at all, so what the arm observes is the *store* and the fact that a
     * constructor reads it: `RSA_new` under this default has no `init`, so its own `flags` word
     * stays 0 while `RSA_flags` still answers the table's word. */
    tbl = RSA_meth_new("rt-ossl-default", 0x0008);
    bfr = RSA_get_default_method();
    RSA_set_default_method(tbl);
    printf("rsa.ossl.default.is_tbl=%d\n", RSA_get_default_method() == tbl);
    printf("rsa.ossl.default.is_not_open_ssl=%d\n",
        RSA_get_default_method() != RSA_PKCS1_OpenSSL());
    r2 = RSA_new();
    printf("rsa.ossl.default.new_nonnull=%d\n", r2 != NULL);
    printf("rsa.ossl.default.new_uses_tbl=%d\n", RSA_get_method(r2) == tbl);
    printf("rsa.ossl.default.new_meth_flags=%d\n", RSA_flags(r2));
    printf("rsa.ossl.default.new_obj_flags=%d\n", RT_FLAGS(r2));
    RSA_free(r2);
    RSA_set_default_method(bfr);
    printf("rsa.ossl.default.restored=%d\n", RSA_get_default_method() == RSA_PKCS1_OpenSSL());
    RSA_meth_free(tbl);

    /* ---------------------------------------------------------------- the constructors */

    r1 = RSA_new();
    printf("rsa.ossl.obj_new.nonnull=%d\n", r1 != NULL);
    printf("rsa.ossl.obj_new.meth_is_default=%d\n",
        RSA_get_method(r1) == RSA_get_default_method());
    printf("rsa.ossl.obj_new.meth_is_open_ssl=%d\n", RSA_get_method(r1) == RSA_PKCS1_OpenSSL());
    printf("rsa.ossl.obj_new.engine_is_null=%d\n", RSA_get0_engine(r1) == NULL);
    /* The table's word is 0x0400 and the object's is 0x0006: the constructor masks the first out
     * (`~RSA_FLAG_NON_FIPS_ALLOW`) and then the table's own `init` sets the two cache flags. */
    printf("rsa.ossl.obj_new.meth_flags=%d\n", RSA_flags(r1));
    printf("rsa.ossl.obj_new.obj_flags=%d\n", RT_FLAGS(r1));

    r2 = RSA_new_method(NULL);
    printf("rsa.ossl.obj_new_method.nonnull=%d\n", r2 != NULL);
    printf("rsa.ossl.obj_new_method.meth_is_default=%d\n",
        RSA_get_method(r2) == RSA_get_default_method());
    printf("rsa.ossl.obj_new_method.obj_flags=%d\n", RT_FLAGS(r2));

    RSA_free(r1);
    printf("rsa.ossl.obj_free_constructed.survived=1\n");
    RSA_free(r2);
    printf("rsa.ossl.obj_free_constructed_twice.survived=1\n");

    /* ---------------------------------------------------------------- the entry points */

    n = rt_word(3233);
    e = rt_word(17);
    d = rt_word(2753);
    p = rt_word(61);
    q = rt_word(53);
    dmp1 = rt_word(53);
    dmq1 = rt_word(49);
    iqmp = rt_word(38);

    o = rt_blank();
    RT_METH(o) = (RSA_METHOD *)ro_meth;
    RT_N(o) = n;
    RT_E(o) = e;
    RT_D(o) = d;
    RT_P(o) = p;
    RT_Q(o) = q;
    RT_DMP1(o) = dmp1;
    RT_DMQ1(o) = dmq1;
    RT_IQMP(o) = iqmp;
    /* **A real lock, because the cache arms take it.** `init` above sets `RSA_FLAG_CACHE_PUBLIC`,
     * so the first entry point builds a Montgomery context through `BN_MONT_CTX_set_locked` with
     * `rsa->lock` -- and the authority's `BN_MONT_CTX_set_locked` takes that lock unconditionally,
     * so a NULL one is a segmentation fault there. The candidate tolerates NULL, which is exactly
     * the kind of asymmetry this probe exists to keep out of the transcript: both sides get a lock
     * `CRYPTO_THREAD_lock_new` built, and `RSA_free` releases it at the end. */
    RT_LOCK(o) = CRYPTO_THREAD_lock_new();
    printf("rsa.ossl.key.lock_nonnull=%d\n", RT_LOCK(o) != NULL);

    /* `rsa_ossl_init`: the two cache flags, and always 1. */
    printf("rsa.ossl.init.no_cache_flags=%d\n", RT_FLAGS(o));
    printf("rsa.ossl.init.ret=%d\n", init(o));
    printf("rsa.ossl.init.obj_flags=%d\n", RT_FLAGS(o));

    /* `rsa_ossl_finish` on an object whose four contexts were never built, which is the arm that
     * observes the hook's answer rather than its releases. */
    ob = rt_blank();
    RT_METH(ob) = (RSA_METHOD *)ro_meth;
    printf("rsa.ossl.finish.ret=%d\n", finish(ob));
    free(ob);

    /* `rsa_ossl_public_encrypt` with `RSA_NO_PADDING`: the block is the plain number 2842 and the
     * answer is 2842^17 mod 3233. */
    memset(to, 0, sizeof(to));
    printf("rsa.ossl.pub_enc.ret=%d\n", pub_enc(2, from, to, o, RSA_NO_PADDING));
    printf("rsa.ossl.pub_enc.0=%02x\n", to[0]);
    printf("rsa.ossl.pub_enc.1=%02x\n", to[1]);

    /* ... and `rsa_ossl_public_decrypt` undoes it, which is the pair's contract. */
    memset(back, 0, sizeof(back));
    printf("rsa.ossl.pub_dec.ret=%d\n", pub_dec(2, to, back, o, RSA_NO_PADDING));
    printf("rsa.ossl.pub_dec.body=%d\n", memcmp(back, from, 2) == 0);

    /* `rsa_ossl_private_encrypt`: the CRT path, because all five of p, q, dmp1, dmq1 and iqmp are
     * set -- and therefore the arm that drives `rsa_ossl_mod_exp`'s `smooth` path end to end. */
    RT_FLAGS(o) |= RSA_FLAG_NO_BLINDING;
    memset(enc, 0, sizeof(enc));
    printf("rsa.ossl.priv_enc.ret=%d\n", priv_enc(2, from, enc, o, RSA_NO_PADDING));
    printf("rsa.ossl.priv_enc.0=%02x\n", enc[0]);
    printf("rsa.ossl.priv_enc.1=%02x\n", enc[1]);
    memset(back, 0, sizeof(back));
    printf("rsa.ossl.priv_enc.then_pub_dec.ret=%d\n", pub_dec(2, enc, back, o, RSA_NO_PADDING));
    printf("rsa.ossl.priv_enc.then_pub_dec.body=%d\n", memcmp(back, from, 2) == 0);

    /* ... the plain path, with the CRT parameters removed, which is the other half of the same
     * five-way test. `d` is the exponent the plain path uses. */
    RT_P(o) = NULL;
    RT_Q(o) = NULL;
    RT_DMP1(o) = NULL;
    RT_DMQ1(o) = NULL;
    RT_IQMP(o) = NULL;
    memset(back, 0, sizeof(back));
    printf("rsa.ossl.priv_enc.plain.ret=%d\n", priv_enc(2, from, back, o, RSA_NO_PADDING));
    printf("rsa.ossl.priv_enc.plain.body=%d\n", memcmp(back, enc, 2) == 0);
    RT_P(o) = p;
    RT_Q(o) = q;
    RT_DMP1(o) = dmp1;
    RT_DMQ1(o) = dmq1;
    RT_IQMP(o) = iqmp;

    /* `rsa_ossl_private_decrypt` with no padding: the memcpy arm, over the same ciphertext. */
    memset(back, 0, sizeof(back));
    printf("rsa.ossl.priv_dec.none.ret=%d\n", priv_dec(2, to, back, o, RSA_NO_PADDING));
    printf("rsa.ossl.priv_dec.none.body=%d\n", memcmp(back, from, 2) == 0);

    /* ... and with PKCS#1 v1.5 padding. **The two-octet key cannot be used here at all**: with
     * `num <= 10` the check's `max_sep_offset = num - 10` wraps to a near-0xFFFF `uint16_t`, so a
     * candidate length larger than the block is accepted and `msg_index` becomes negative -- the
     * loop then reads *before* both buffers, which is exactly the bug class
     * `forensics/tools/probe_hygiene.py` exists to catch. It caught it: the first version of this
     * arm printed `00 00` at `-O1` and `43 41` at `-O2` on the authority side. So the PKCS#1 arms
     * use the 128-bit key above, where `max_sep_offset` is 6 and every index is in range. */

    /* `rsa_ossl_private_decrypt` with PKCS#1 v1.5 padding over a **valid** encoding:
     * `00 02 || 8 non-zero octets || 00 || "hello"`, encrypted with the public key and then
     * decrypted with the private one. This is the arm that drives the implicit-rejection padding
     * check's success path end to end. */
    ok = rt_key128(&kn, &ke, &kd, &kp, &kq, &kdmp1, &kdmq1, &kiqmp);
    printf("rsa.ossl.key128.built=%d\n", ok);
    if (ok != 0) {
        om = rt_blank();
        RT_METH(om) = (RSA_METHOD *)ro_meth;
        RT_N(om) = kn;
        RT_E(om) = ke;
        RT_D(om) = kd;
        RT_P(om) = kp;
        RT_Q(om) = kq;
        RT_DMP1(om) = kdmp1;
        RT_DMQ1(om) = kdmq1;
        RT_IQMP(om) = kiqmp;
        /* The same real lock the 3233-bit object gets, and for the same reason: an entry point takes
         * `RSA_FLAG_CACHE_PUBLIC`'s branch into `BN_MONT_CTX_set_locked` with `rsa->lock`. */
        RT_LOCK(om) = CRYPTO_THREAD_lock_new();
        printf("rsa.ossl.key128.lock_nonnull=%d\n", RT_LOCK(om) != NULL);
        printf("rsa.ossl.key128.init_ret=%d\n", init(om));
        RT_FLAGS(om) |= RSA_FLAG_NO_BLINDING;
        printf("rsa.ossl.key128.size=%d\n", RSA_size(om));

        memset(em, 0, sizeof(em));
        em[0] = 0x00;
        em[1] = 0x02;
        for (i = 2; i < 10; i++)
            em[i] = (unsigned char)(0x11 + i);
        em[10] = 0x00;
        memcpy(em + 11, "hello", 5);

        memset(ct, 0, sizeof(ct));
        printf("rsa.ossl.padded.enc_ret=%d\n", pub_enc(16, em, ct, om, RSA_NO_PADDING));
        memset(out, 0xa5, sizeof(out));
        ret = priv_dec(16, ct, out, om, RSA_PKCS1_PADDING);
        printf("rsa.ossl.padded.dec_ret=%d\n", ret);
        printf("rsa.ossl.padded.dec_body=%d\n", ret == 5 && memcmp(out, "hello", 5) == 0);

        /* ... and over an **invalid** one, which is the implicit rejection: the message that comes
         * back is `ossl_rsa_prf`'s output under the KDK `derive_kdk` built from `d` and this
         * ciphertext, so it is a function of both and of nothing else. The octets the check wrote
         * are the first `ret` of them. */
        memset(em, 0, sizeof(em));
        em[0] = 0x00;
        em[1] = 0x01;
        for (i = 2; i < 16; i++)
            em[i] = (unsigned char)i;
        memset(ct, 0, sizeof(ct));
        printf("rsa.ossl.reject.enc_ret=%d\n", pub_enc(16, em, ct, om, RSA_NO_PADDING));
        memset(out, 0xa5, sizeof(out));
        ret = priv_dec(16, ct, out, om, RSA_PKCS1_PADDING);
        printf("rsa.ossl.reject.dec_ret=%d\n", ret);
        for (i = 0; i < ret && i < (int)sizeof(out); i++)
            printf("rsa.ossl.reject.%d=%02x\n", i, out[i]);

        rt_release(om);
    }

    /* `rsa_ossl_mod_exp` called directly, so the exponentiation is observed without the entry
     * points' padding and encoding around it. */
    bn_in = rt_word(2842);
    bn_out = BN_new();
    ctx = BN_CTX_new();
    printf("rsa.ossl.mod_exp.ret=%d\n", mod_exp(bn_out, bn_in, o, ctx));
    memset(back, 0, sizeof(back));
    pad = BN_bn2binpad(bn_out, back, 2);
    printf("rsa.ossl.mod_exp.pad=%d\n", pad);
    printf("rsa.ossl.mod_exp.0=%02x\n", back[0]);
    printf("rsa.ossl.mod_exp.1=%02x\n", back[1]);
    BN_free(bn_in);
    BN_free(bn_out);
    BN_CTX_free(ctx);

    /* `RSA_setup_blinding`: the object's public exponent, an odd modulus, and the answer's shape.
     * No byte of the blinding factor enters the transcript -- there is no byte of it that two runs
     * would agree on. */
    bn = rt_word(3233);
    be = rt_word(17);
    ob = rt_blank();
    RT_METH(ob) = (RSA_METHOD *)ro_meth;
    RT_N(ob) = bn;
    RT_E(ob) = be;
    blinding = RSA_setup_blinding(ob, NULL);
    printf("rsa.ossl.setup_blinding.nonnull=%d\n", blinding != NULL);
    printf("rsa.ossl.setup_blinding.flags=%lu\n",
        blinding == NULL ? 0UL : BN_BLINDING_get_flags(blinding));
    BN_BLINDING_free(blinding);
    /* The object is released with plain `free` and its two `BIGNUM`s with `BN_free`, because its
     * method is the default table: `RSA_free` would run `rsa_ossl_finish` and then release the two
     * `BIGNUM`s, which this arm has already done. */
    BN_free(bn);
    BN_free(be);
    free(ob);

    /* Last, the key object: `RSA_free` runs the table's `finish` -- releasing the three Montgomery
     * contexts the arm above built -- and then releases the eight `BIGNUM`s it owns. */
    rt_release(o);
}

/* ------------------------------------------------------------------ the key generators (slice E) */

/* `crypto/rsa/rsa_x931g.c`'s two entry points, and the four `rsa_crpt.c` crypt wrappers over a key
 * one of them generated.
 *
 * **Nothing here prints a random byte, and the two halves observe different things.** The
 * derivation arm is *deterministic*: `RSA_X931_derive_ex` is handed fixed seeds, so its key is a
 * function of this probe's constants alone and the congruences, the modulus width and the
 * exponent relations below are values both binaries must compute identically. The generation arm
 * draws, so it prints the return code, a width predicate and the **round trips** through
 * `RSA_public_encrypt`/`RSA_private_decrypt` and `RSA_private_encrypt`/`RSA_public_decrypt`: a
 * generated key that recovers its own plaintext is one differential observation of all six entry
 * points at once, and no byte of the key or of a ciphertext enters the transcript.
 *
 * **`RSA_FLAG_NO_BLINDING` is set on the generated key** before its private operations. The
 * answer is the same either way, and an arm that needs no DRBG draw cannot fail for a reason this
 * court is not about.
 *
 * **The `RSA_X931_derive_ex` arm's fixed seeds are deliberately not `BN_X931_generate_Xpq`'s.**
 * That function's `|Xp - Xq| > 2^(nbits - 100)` contract is what a *key generator* needs; the
 * derivation itself takes any seed, and a fixed one is what makes the derived `p`, `q` and `n`
 * printable at all. The 101-bit `Xp1`/`Xp2`/`Xq1`/`Xq2` are the widths `BN_X931_generate_prime_ex`
 * draws for its own, so the two arms exercise the same `bn_x931_derive_pi` path. */

/* A `BIGNUM` with `bits` significant bits, the top `top` of them set, plus `addend`. Built through
 * the public API so both binaries compute the same value rather than agreeing about a constant. */
static BIGNUM *rt_bits_top(int bits, int top, unsigned long addend)
{
    BIGNUM *b = BN_new();
    int i;

    if (b == NULL)
        return NULL;
    for (i = 0; i < top; i++) {
        if (BN_set_bit(b, bits - 1 - i) != 1) {
            BN_free(b);
            return NULL;
        }
    }
    if (addend != 0 && BN_add_word(b, addend) != 1) {
        BN_free(b);
        return NULL;
    }
    return b;
}

/* `a mod m == want`, as a boolean. `BN_mod` is the header's `BN_div` macro, written out with the
 * null quotient slot, exactly as the authority spells it. */
static int rt_mod_is(const BIGNUM *a, const BIGNUM *m, unsigned long want, BN_CTX *ctx)
{
    BIGNUM *r = BN_new();
    int ok;

    if (r == NULL)
        return 0;
    ok = BN_div(NULL, r, a, m, ctx) == 1 && BN_is_word(r, want) == 1;
    BN_free(r);
    return ok;
}

/* `a mod m == want`, as a boolean, where `want` is itself a value. */
static int rt_mod_eq(const BIGNUM *a, const BIGNUM *m, const BIGNUM *want, BN_CTX *ctx)
{
    BIGNUM *r = BN_new();
    int ok;

    if (r == NULL)
        return 0;
    ok = BN_div(NULL, r, a, m, ctx) == 1 && BN_cmp(r, want) == 0;
    BN_free(r);
    return ok;
}

/* `(x * y) mod m == want`, so the exponent relations are one line each. */
static int rt_mul_mod_is(const BIGNUM *x, const BIGNUM *y, const BIGNUM *m, unsigned long want,
    BN_CTX *ctx)
{
    BIGNUM *p = BN_new();
    int ok;

    if (p == NULL)
        return 0;
    ok = BN_mul(p, x, y, ctx) == 1 && rt_mod_is(p, m, want, ctx) == 1;
    BN_free(p);
    return ok;
}

static void rsa_keygen_arms(void)
{
    RSA *rd = NULL, *rg = NULL, *rr = NULL, *rn_obj = NULL;
    BIGNUM *p1 = NULL, *p2 = NULL, *q1 = NULL, *q2 = NULL;
    BIGNUM *xp1 = NULL, *xp2 = NULL, *xp = NULL, *xq1 = NULL, *xq2 = NULL, *xq = NULL;
    BIGNUM *e = NULL, *prod = NULL, *pm1 = NULL, *qm1 = NULL, *t = NULL;
    const BIGNUM *kp = NULL, *kq = NULL, *kn = NULL, *ke = NULL, *kd = NULL;
    const BIGNUM *kdmp1 = NULL, *kdmq1 = NULL, *kiqmp = NULL;
    BN_CTX *ctx = NULL;
    int ret, ret2, size;
    unsigned char msg[132], ct[132], out[132];

    ctx = BN_CTX_new();
    e = rt_word(65537);
    xp = rt_bits_top(512, 2, 12345);
    xq = rt_bits_top(512, 2, 987654321);
    /* **The two seeds of a pair are millions apart on purpose.** `bn_x931_derive_pi` answers the
     * first odd prime at or above its seed, and a prime gap near `2^100` is on the order of a
     * hundred: two seeds a few hundred apart can round to the *same* prime, which makes
     * `gcd(p1, p2) != 1` and turns the derivation's `BN_mod_inverse` into `BN_R_NO_INVERSE`. The
     * separation is what keeps the arm on its success path. */
    xp1 = rt_bits_top(101, 1, 12345);
    xp2 = rt_bits_top(101, 1, 5000011);
    xq1 = rt_bits_top(101, 1, 777);
    xq2 = rt_bits_top(101, 1, 9000017);
    printf("rsa.x931d.inputs_built=%d\n",
        ctx != NULL && e != NULL && xp != NULL && xq != NULL && xp1 != NULL && xp2 != NULL
            && xq1 != NULL && xq2 != NULL);

    /* ---------------------------------------------------------------- the deterministic derivation */

    if (ctx != NULL && e != NULL && xp != NULL && xq != NULL && xp1 != NULL && xp2 != NULL
        && xq1 != NULL && xq2 != NULL) {
        rd = RSA_new();
        printf("rsa.x931d.new_nonnull=%d\n", rd != NULL);
        p1 = BN_new();
        p2 = BN_new();
        q1 = BN_new();
        q2 = BN_new();
        t = BN_new();
        prod = BN_new();
        pm1 = BN_new();
        qm1 = BN_new();
        printf("rsa.x931d.scratch_built=%d\n",
            rd != NULL && p1 != NULL && p2 != NULL && q1 != NULL && q2 != NULL && t != NULL
                && prod != NULL && pm1 != NULL && qm1 != NULL);

        if (rd != NULL && p1 != NULL && p2 != NULL && q1 != NULL && q2 != NULL && t != NULL
            && prod != NULL && pm1 != NULL && qm1 != NULL) {
            ERR_clear_error();
            ret = RSA_X931_derive_ex(rd, p1, p2, q1, q2, xp1, xp2, xp, xq1, xq2, xq, e, NULL);
            printf("rsa.x931d.ret=%d\n", ret);
            drain("x931d_derive");

            /* The object's own answers, printed because the inputs are fixed -- **and only when
             * the derivation answered 1**: a refused derivation leaves `n` NULL, and
             * `RSA_bits`/`RSA_size` dereference it (D325 measures that arm as a fault on the
             * authority side), so an unguarded read here would end the transcript. */
            if (ret == 1) {
                printf("rsa.x931d.bits=%d\n", RSA_bits(rd));
                printf("rsa.x931d.size=%d\n", RSA_size(rd));
                printf("rsa.x931d.dirty=%d\n", RT_DIRTY(rd));
            }

            RSA_get0_key(rd, &kn, &ke, &kd);
            RSA_get0_factors(rd, &kp, &kq);
            RSA_get0_crt_params(rd, &kdmp1, &kdmq1, &kiqmp);
            printf("rsa.x931d.parts_null=%d\n",
                kn == NULL || ke == NULL || kd == NULL || kp == NULL || kq == NULL || kdmp1 == NULL
                    || kdmq1 == NULL || kiqmp == NULL);

            if (ret == 1 && kn != NULL && ke != NULL && kd != NULL && kp != NULL && kq != NULL
                && kdmp1 != NULL && kdmq1 != NULL && kiqmp != NULL) {
                /* `bn_x931_derive_pi` finds the first odd prime at or above each seed, so the
                 * returned `p1`/`p2`/`q1`/`q2` are the *seeds' successors* and not the seeds. */
                printf("rsa.x931d.p1_odd=%d\n", BN_is_odd(p1));
                printf("rsa.x931d.p2_odd=%d\n", BN_is_odd(p2));
                printf("rsa.x931d.q1_odd=%d\n", BN_is_odd(q1));
                printf("rsa.x931d.q2_odd=%d\n", BN_is_odd(q2));
                printf("rsa.x931d.p1_prime=%d\n", BN_check_prime(p1, ctx, NULL));
                printf("rsa.x931d.p2_prime=%d\n", BN_check_prime(p2, ctx, NULL));
                printf("rsa.x931d.q1_prime=%d\n", BN_check_prime(q1, ctx, NULL));
                printf("rsa.x931d.q2_prime=%d\n", BN_check_prime(q2, ctx, NULL));
                printf("rsa.x931d.p_prime=%d\n", BN_check_prime(kp, ctx, NULL));
                printf("rsa.x931d.q_prime=%d\n", BN_check_prime(kq, ctx, NULL));

                /* The X9.31 congruence: `p = Rp (mod p1*p2)` with
                 * `Rp = (p2^-1 mod p1)*p2 - (p1^-1 mod p2)*p1`, so `p = 1 (mod p1)` and
                 * `p = -1 (mod p2)` -- and **not** `p = 1 (mod p2)`, which is the arm the first
                 * version of this probe got wrong and the authority answered `0` to. Recomputing
                 * `Rp` and comparing would restate the writer; the two residue classes it factors
                 * into are the independent statement. */
                printf("rsa.x931d.p_mod_p1_is_1=%d\n", rt_mod_is(kp, p1, 1, ctx));
                BN_copy(prod, p2);
                BN_sub_word(prod, 1);
                printf("rsa.x931d.p_mod_p2_is_m1=%d\n", rt_mod_eq(kp, p2, prod, ctx));
                printf("rsa.x931d.q_mod_q1_is_1=%d\n", rt_mod_is(kq, q1, 1, ctx));
                BN_copy(prod, q2);
                BN_sub_word(prod, 1);
                printf("rsa.x931d.q_mod_q2_is_m1=%d\n", rt_mod_eq(kq, q2, prod, ctx));

                /* `n == p*q`, and the two primes are distinct. */
                printf("rsa.x931d.n_is_pq=%d\n",
                    BN_mul(prod, kp, kq, ctx) == 1 && BN_cmp(prod, kn) == 0);
                printf("rsa.x931d.p_ne_q=%d\n", BN_cmp(kp, kq) != 0);

                /* `d` inverts `e` modulo both `p-1` and `q-1`, and the three CRT parameters are
                 * the residues and the inverse they are named for. */
                BN_sub(pm1, kp, BN_value_one());
                BN_sub(qm1, kq, BN_value_one());
                printf("rsa.x931d.ed_mod_pm1_is_1=%d\n", rt_mul_mod_is(ke, kd, pm1, 1, ctx));
                printf("rsa.x931d.ed_mod_qm1_is_1=%d\n", rt_mul_mod_is(ke, kd, qm1, 1, ctx));
                printf("rsa.x931d.dmp1_is_d_mod_pm1=%d\n",
                    BN_div(NULL, t, kd, pm1, ctx) == 1 && BN_cmp(t, kdmp1) == 0);
                printf("rsa.x931d.dmq1_is_d_mod_qm1=%d\n",
                    BN_div(NULL, t, kd, qm1, ctx) == 1 && BN_cmp(t, kdmq1) == 0);
                printf("rsa.x931d.q_iqmp_mod_p_is_1=%d\n", rt_mul_mod_is(kq, kiqmp, kp, 1, ctx));

                /* The object's flags, so the constructor's table is visible under this arm too. */
                printf("rsa.x931d.flags=%d\n", RSA_flags(rd));
            }
        }

        BN_free(p1);
        BN_free(p2);
        BN_free(q1);
        BN_free(q2);
        BN_free(t);
        BN_free(prod);
        BN_free(pm1);
        BN_free(qm1);
        RSA_free(rd);
    }

    /* ---------------------------------------------------------------- the generator and the wrappers */

    if (ctx != NULL && e != NULL) {
        rg = RSA_new();
        printf("rsa.x931g.new_nonnull=%d\n", rg != NULL);
        if (rg != NULL) {
            ERR_clear_error();
            printf("rsa.x931g.ret=%d\n", RSA_X931_generate_key_ex(rg, 1024, e, NULL));
            drain("x931g_gen");
            size = RSA_size(rg);
            printf("rsa.x931g.size_at_least_128=%d\n", size >= 128);
            RSA_set_flags(rg, RSA_FLAG_NO_BLINDING);

            /* The PKCS#1 v1.5 pair: the public operation draws its padding, the private one
             * recovers this probe's five octets, and neither the ciphertext nor a padding octet is
             * printed. */
            memcpy(msg, "hello", 5);
            memset(ct, 0, sizeof(ct));
            ERR_clear_error();
            ret = RSA_public_encrypt(5, msg, ct, rg, RSA_PKCS1_PADDING);
            printf("rsa.x931g.enc_ret=%d\n", ret);
            printf("rsa.x931g.enc_is_size=%d\n", ret == size);
            memset(out, 0xa5, sizeof(out));
            ret2 = RSA_private_decrypt(size, ct, out, rg, RSA_PKCS1_PADDING);
            printf("rsa.x931g.dec_ret=%d\n", ret2);
            printf("rsa.x931g.dec_body=%d\n", ret2 == 5 && memcmp(out, msg, 5) == 0);
            drain("x931g_roundtrip_pkcs1");

            /* The no-padding pair, on a plain number smaller than the modulus. */
            memset(msg, 0, sizeof(msg));
            msg[0] = 0x0b;
            msg[1] = 0x1a;
            memset(ct, 0, sizeof(ct));
            ERR_clear_error();
            ret = RSA_private_encrypt(size, msg, ct, rg, RSA_NO_PADDING);
            printf("rsa.x931g.priv_enc_ret=%d\n", ret);
            memset(out, 0xa5, sizeof(out));
            ret2 = RSA_public_decrypt(size, ct, out, rg, RSA_NO_PADDING);
            printf("rsa.x931g.pub_dec_ret=%d\n", ret2);
            printf("rsa.x931g.pub_dec_body=%d\n", ret2 == size && memcmp(out, msg, size) == 0);
            drain("x931g_roundtrip_none");
        }

        /* The seed generator's two refusals, both with an **empty** queue: the guard is in
         * `BN_X931_generate_Xpq` and this function only forwards its zero. */
        rr = RSA_new();
        printf("rsa.x931g.small_bits_ret=%d\n", RSA_X931_generate_key_ex(rr, 512, e, NULL));
        printf("rsa.x931g.odd_bits_ret=%d\n", RSA_X931_generate_key_ex(rr, 1025, e, NULL));
        drain("x931g_refusals");
        RSA_free(rr);

        /* `RSA_X931_derive_ex`'s two non-arithmetic answers: `2` for an object with an exponent
         * and no primes, and `0` for a NULL object -- the latter reaching the release label with a
         * NULL context. */
        rn_obj = RSA_new();
        printf("rsa.x931d.incomplete_ret=%d\n",
            RSA_X931_derive_ex(rn_obj, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
                e, NULL));
        printf("rsa.x931d.null_ret=%d\n",
            RSA_X931_derive_ex(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, e,
                NULL));
        drain("x931d_incomplete");
        RSA_free(rn_obj);
    }

    BN_free(e);
    BN_free(xp);
    BN_free(xq);
    BN_free(xp1);
    BN_free(xp2);
    BN_free(xq1);
    BN_free(xq2);
    BN_CTX_free(ctx);
}

/* ------------------------------------------------------------------ the RSA_generate_* dispatchers (slice E) */

/* `rsa_gen.c`'s three entry points and `rsa_depr.c`'s deprecated constructor, over the two
 * generators D326 measured: the SP800-56B path (`primes == 2 && bits >= 2048 &&
 * BN_num_bits(e) > 16`) and `rsa_multiprime_keygen` (more than two primes, or a small exponent).
 *
 * Every key here is drawn, so **nothing below prints a byte of it**. What is printed is the
 * library's answer *about* the key: the return code; the width (`RSA_bits`, `RSA_size`); the
 * version word and the extra-prime count, which is the one pair that tells the two generators
 * apart; primality of the factors through the landed `BN_check_prime`; `n = p*q` (and `p*q*r`
 * for the multi-prime arm); the exact exponent the caller asked for; and the round trips through
 * the four `rsa_crpt.c` wrappers. The four refusals are drained, so each one's error coordinate
 * is compared as well as its return value.
 *
 * **`RSA_FLAG_NO_BLINDING` is set before any private operation**, so the private entry points
 * take their no-blinding arm and no DRBG draw can fail for a reason this court is not about.
 *
 * **The multi-prime arm's extra-prime array is the caller's.** `RSA_get0_multi_prime_factors`
 * writes into an array sized by `RSA_get_multi_prime_extra_count`, which is why the count is
 * read first. */

/* `n == a * b`, as a boolean, without printing either. */
static int rt_product_is(const BIGNUM *n, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
{
    BIGNUM *p = BN_new();
    int ok;

    if (p == NULL)
        return 0;
    ok = BN_mul(p, a, b, ctx) == 1 && BN_cmp(p, n) == 0;
    BN_free(p);
    return ok;
}

static void rsa_generate_arms(void)
{
    RSA *rg = NULL, *rm = NULL, *rd = NULL, *rb = NULL;
    BIGNUM *e = NULL, *even = NULL;
    const BIGNUM *kn = NULL, *ke = NULL, *kd = NULL;
    const BIGNUM *kp = NULL, *kq = NULL;
    const BIGNUM *mpf[1] = { NULL };
    BN_CTX *ctx = NULL;
    unsigned char msg[256], ct[256], out[256];
    int ret, ret2, size;

    ctx = BN_CTX_new();
    e = rt_word(65537);
    even = rt_word(65536);
    printf("rsa.gen.scratch_built=%d\n", ctx != NULL && e != NULL && even != NULL);
    if (ctx == NULL || e == NULL || even == NULL)
        goto done;

    /* ------------------------------------------------ the SP800-56B path (2 primes, e > 16 bits) */

    rg = RSA_new();
    printf("rsa.gen.sp800.new_nonnull=%d\n", rg != NULL);
    if (rg != NULL) {
        ERR_clear_error();
        printf("rsa.gen.sp800.ret=%d\n", RSA_generate_key_ex(rg, 2048, e, NULL));
        drain("gen_sp800");
        printf("rsa.gen.sp800.bits=%d\n", RSA_bits(rg));
        printf("rsa.gen.sp800.size=%d\n", RSA_size(rg));
        printf("rsa.gen.sp800.version=%d\n", RSA_get_version(rg));
        printf("rsa.gen.sp800.extra=%d\n", RSA_get_multi_prime_extra_count(rg));
        printf("rsa.gen.sp800.dirty_positive=%d\n", RT_DIRTY(rg) > 0);

        RSA_get0_key(rg, &kn, &ke, &kd);
        RSA_get0_factors(rg, &kp, &kq);
        printf("rsa.gen.sp800.parts_null=%d\n",
            kn == NULL || ke == NULL || kd == NULL || kp == NULL || kq == NULL);
        printf("rsa.gen.sp800.e_is_asked=%d\n", ke != NULL && BN_cmp(ke, e) == 0);
        printf("rsa.gen.sp800.p_prime=%d\n", BN_check_prime(kp, ctx, NULL));
        printf("rsa.gen.sp800.q_prime=%d\n", BN_check_prime(kq, ctx, NULL));
        printf("rsa.gen.sp800.p_ne_q=%d\n", BN_cmp(kp, kq) != 0);
        printf("rsa.gen.sp800.n_is_pq=%d\n", rt_product_is(kn, kp, kq, ctx));

        RSA_set_flags(rg, RSA_FLAG_NO_BLINDING);
        size = RSA_size(rg);

        /* The PKCS#1 v1.5 pair: the public operation draws its padding, the private one recovers
         * this probe's five octets, and neither the ciphertext nor a padding octet is printed. */
        memcpy(msg, "hello", 5);
        memset(ct, 0, sizeof(ct));
        ERR_clear_error();
        ret = RSA_public_encrypt(5, msg, ct, rg, RSA_PKCS1_PADDING);
        printf("rsa.gen.sp800.enc_ret=%d\n", ret);
        printf("rsa.gen.sp800.enc_is_size=%d\n", ret == size);
        memset(out, 0xa5, sizeof(out));
        ret2 = RSA_private_decrypt(size, ct, out, rg, RSA_PKCS1_PADDING);
        printf("rsa.gen.sp800.dec_ret=%d\n", ret2);
        printf("rsa.gen.sp800.dec_body=%d\n", ret2 == 5 && memcmp(out, msg, 5) == 0);
        drain("gen_sp800_roundtrip_pkcs1");

        /* The no-padding pair, on a plain number smaller than the modulus. */
        memset(msg, 0, sizeof(msg));
        msg[0] = 0x0b;
        msg[1] = 0x1a;
        memset(ct, 0, sizeof(ct));
        ERR_clear_error();
        ret = RSA_private_encrypt(size, msg, ct, rg, RSA_NO_PADDING);
        printf("rsa.gen.sp800.priv_enc_ret=%d\n", ret);
        memset(out, 0xa5, sizeof(out));
        ret2 = RSA_public_decrypt(size, ct, out, rg, RSA_NO_PADDING);
        printf("rsa.gen.sp800.pub_dec_ret=%d\n", ret2);
        printf("rsa.gen.sp800.pub_dec_body=%d\n", ret2 == size && memcmp(out, msg, size) == 0);
        drain("gen_sp800_roundtrip_none");
    }

    /* ------------------------------------------------ the multi-prime path (3 primes, 1024 bits) */

    rm = RSA_new();
    printf("rsa.gen.mp.new_nonnull=%d\n", rm != NULL);
    if (rm != NULL) {
        ERR_clear_error();
        printf("rsa.gen.mp.ret=%d\n", RSA_generate_multi_prime_key(rm, 1024, 3, e, NULL));
        drain("gen_mp");
        printf("rsa.gen.mp.bits=%d\n", RSA_bits(rm));
        printf("rsa.gen.mp.size=%d\n", RSA_size(rm));
        printf("rsa.gen.mp.version=%d\n", RSA_get_version(rm));
        printf("rsa.gen.mp.extra=%d\n", RSA_get_multi_prime_extra_count(rm));

        /* The count is one, so a one-element caller array is the exact size. */
        printf("rsa.gen.mp.factors_ret=%d\n", RSA_get0_multi_prime_factors(rm, mpf));
        RSA_get0_key(rm, &kn, &ke, &kd);
        RSA_get0_factors(rm, &kp, &kq);
        printf("rsa.gen.mp.parts_null=%d\n",
            kn == NULL || ke == NULL || kp == NULL || kq == NULL || mpf[0] == NULL);
        printf("rsa.gen.mp.e_is_asked=%d\n", ke != NULL && BN_cmp(ke, e) == 0);
        printf("rsa.gen.mp.p_prime=%d\n", BN_check_prime(kp, ctx, NULL));
        printf("rsa.gen.mp.q_prime=%d\n", BN_check_prime(kq, ctx, NULL));
        printf("rsa.gen.mp.r_prime=%d\n", BN_check_prime(mpf[0], ctx, NULL));
        {
            BIGNUM *pq = BN_new();
            printf("rsa.gen.mp.n_is_pqr=%d\n",
                pq != NULL && BN_mul(pq, kp, kq, ctx) == 1 && rt_product_is(kn, pq, mpf[0], ctx));
            BN_free(pq);
        }

        RSA_set_flags(rm, RSA_FLAG_NO_BLINDING);
        size = RSA_size(rm);
        memcpy(msg, "hello", 5);
        memset(ct, 0, sizeof(ct));
        ERR_clear_error();
        ret = RSA_public_encrypt(5, msg, ct, rm, RSA_PKCS1_PADDING);
        printf("rsa.gen.mp.enc_ret=%d\n", ret);
        printf("rsa.gen.mp.enc_is_size=%d\n", ret == size);
        memset(out, 0xa5, sizeof(out));
        ret2 = RSA_private_decrypt(size, ct, out, rm, RSA_PKCS1_PADDING);
        printf("rsa.gen.mp.dec_ret=%d\n", ret2);
        printf("rsa.gen.mp.dec_body=%d\n", ret2 == 5 && memcmp(out, msg, 5) == 0);
        drain("gen_mp_roundtrip_pkcs1");
    }

    /* ------------------------------------------------ the deprecated constructor */

    ERR_clear_error();
    rd = RSA_generate_key(1024, 65537, NULL, NULL);
    printf("rsa.gen.depr.nonnull=%d\n", rd != NULL);
    drain("gen_depr");
    if (rd != NULL) {
        RSA_get0_key(rd, NULL, &ke, NULL);
        printf("rsa.gen.depr.bits=%d\n", RSA_bits(rd));
        printf("rsa.gen.depr.e_is_asked=%d\n", ke != NULL && BN_cmp(ke, e) == 0);
        printf("rsa.gen.depr.version=%d\n", RSA_get_version(rd));
    }

    /* ------------------------------------------------ the four refusals, drained */

    rb = RSA_new();
    if (rb != NULL) {
        ERR_clear_error();
        printf("rsa.gen.refuse.bits=%d\n", RSA_generate_multi_prime_key(rb, 256, 2, e, NULL));
        printf("rsa.gen.refuse.e_null=%d\n", RSA_generate_multi_prime_key(rb, 1024, 2, NULL, NULL));
        printf("rsa.gen.refuse.e_even=%d\n", RSA_generate_multi_prime_key(rb, 1024, 2, even, NULL));
        printf("rsa.gen.refuse.primes_low=%d\n", RSA_generate_multi_prime_key(rb, 1024, 1, e, NULL));
        printf("rsa.gen.refuse.primes_high=%d\n", RSA_generate_multi_prime_key(rb, 1024, 4, e, NULL));
        /* `RSA_bits` on this object would be the segmentation fault D325 measured, so the
         * "no key was made" observation is the version word and the extra-prime count, both of
         * which read a field and not `n`. */
        printf("rsa.gen.refuse.no_key=%d\n",
            RSA_get_version(rb) == 0 && RSA_get_multi_prime_extra_count(rb) == 0);
        drain("gen_refusals");
    }

done:
    RSA_free(rb);
    RSA_free(rd);
    RSA_free(rm);
    RSA_free(rg);
    BN_free(even);
    BN_free(e);
    BN_CTX_free(ctx);
}

/* ------------------------------------------------------------------ slice D's remainder */

/* The deterministic signing key every arm in this section uses.
 *
 * `RSA_X931_derive_ex` over the same fixed seeds `rsa_keygen_arms` uses makes the whole key a
 * function of the probe's constants, and RSASSA-PKCS1-v1_5's encoding is deterministic -- unlike
 * the randomised paddings -- so a *signature* over a fixed message is a fixed byte string. That is
 * what lets the arms below compare `RSA_sign`'s output octet for octet against an encoding this
 * probe builds from RFC 8017's published DigestInfo prefix, which is the check a table with one
 * wrong byte could not survive. */
static RSA *rt_sign_key(void)
{
    BIGNUM *e = NULL, *xp = NULL, *xq = NULL;
    BIGNUM *xp1 = NULL, *xp2 = NULL, *xq1 = NULL, *xq2 = NULL;
    BIGNUM *p1 = NULL, *p2 = NULL, *q1 = NULL, *q2 = NULL;
    RSA *rsa = NULL;

    e = rt_word(65537);
    xp = rt_bits_top(512, 2, 12345);
    xq = rt_bits_top(512, 2, 987654321);
    xp1 = rt_bits_top(101, 1, 12345);
    xp2 = rt_bits_top(101, 1, 5000011);
    xq1 = rt_bits_top(101, 1, 777);
    xq2 = rt_bits_top(101, 1, 9000017);
    p1 = BN_new();
    p2 = BN_new();
    q1 = BN_new();
    q2 = BN_new();
    if (e == NULL || xp == NULL || xq == NULL || xp1 == NULL || xp2 == NULL || xq1 == NULL
        || xq2 == NULL || p1 == NULL || p2 == NULL || q1 == NULL || q2 == NULL)
        goto done;

    rsa = RSA_new();
    if (rsa == NULL)
        goto done;
    ERR_clear_error();
    if (RSA_X931_derive_ex(rsa, p1, p2, q1, q2, xp1, xp2, xp, xq1, xq2, xq, e, NULL) != 1) {
        RSA_free(rsa);
        rsa = NULL;
    }
    ERR_clear_error();
    /* No private operation below should be able to fail for a reason this court is not about. */
    if (rsa != NULL)
        RSA_set_flags(rsa, RSA_FLAG_NO_BLINDING);

done:
    BN_free(q2);
    BN_free(q1);
    BN_free(p2);
    BN_free(p1);
    BN_free(xq2);
    BN_free(xq1);
    BN_free(xp2);
    BN_free(xp1);
    BN_free(xq);
    BN_free(xp);
    BN_free(e);
    return rsa;
}

/* The SHA-256 `DigestInfo` prefix, without the digest: `SEQUENCE { SEQUENCE { OID, NULL } OCTET
 * STRING }` with `30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20` as its DER. **A
 * literal, and not a call into the library**, on purpose: it is RFC 8017 appendix B.1's published
 * encoding, so a transcription of `rsa_sign.c`'s table that got an octet wrong is a difference this
 * arm sees rather than one it restates. */
static const unsigned char rt_sha256_digestinfo[19] = {
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20
};

/* Build the whole PKCS#1 v1.5 signature block out here, so the arm compares the library's
 * signature against an encoding this probe derived: `00 01 FF... 00 || DigestInfo || digest`. */
static void rt_expect_pkcs1(unsigned char *expect, int size, const unsigned char *prefix,
    int prefixlen, const unsigned char *digest, int digestlen)
{
    int padlen = size - 3 - prefixlen - digestlen;

    memset(expect, 0, (size_t)size);
    expect[0] = 0x00;
    expect[1] = 0x01;
    memset(expect + 2, 0xff, (size_t)padlen);
    expect[2 + padlen] = 0x00;
    memcpy(expect + 3 + padlen, prefix, (size_t)prefixlen);
    memcpy(expect + 3 + padlen + prefixlen, digest, (size_t)digestlen);
}

/* The DER-PSS encoder the verifier arms below build their blocks with; defined after them, and
 * declared here so the two can be read in the order they run. */
static int rt_pss_encode(unsigned char *em, int emlen, int msbits, const unsigned char *mhash,
    int hlen, const unsigned char *salt, int slen, const EVP_MD *md, const EVP_MD *mgf1);

static void rsa_sig_arms(void)
{
    RSA *rsa = rt_sign_key();
    const EVP_MD *sha256 = NULL;
    unsigned char msg[128], sig[256], sig2[256], rec[256], expect[256];
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int siglen = 0, siglen2 = 0;
    int i, size, ret;

    printf("rsa.sig.key_built=%d\n", rsa != NULL);
    if (rsa == NULL)
        return;
    size = RSA_size(rsa);
    printf("rsa.sig.size=%d\n", size);
    sha256 = EVP_MD_fetch(NULL, "SHA256", NULL);
    printf("rsa.sig.md_fetched=%d\n", sha256 != NULL);
    if (sha256 == NULL)
        goto done;

    for (i = 0; i < 128; i++)
        msg[i] = (unsigned char)(i + 1);

    /* The digest the signature must carry, computed through the library's own SHA-256. */
    ERR_clear_error();
    printf("rsa.sig.digest_ret=%d\n", EVP_Digest(msg, 64, hash, NULL, sha256, NULL));
    rt_expect_pkcs1(expect, size, rt_sha256_digestinfo, 19, hash, 32);

    /* ---- RSA_sign / RSA_verify over the fixed key */

    ERR_clear_error();
    ret = RSA_sign(NID_sha256, msg, 64, sig, &siglen, rsa);
    printf("rsa.sig.sign.ret=%d\n", ret);
    printf("rsa.sig.sign.len=%u\n", siglen);
    printf("rsa.sig.sign.len_is_size=%d\n", ret == 1 && siglen == (unsigned int)size);
    drain("sign");

    /* `RSA_NO_PADDING`'s public operation gives the padded block back, so the arm can compare it
     * against the RFC's own encoding rather than against the crate's table. */
    ERR_clear_error();
    memset(rec, 0, sizeof(rec));
    ret = RSA_public_decrypt(size, sig, rec, rsa, RSA_NO_PADDING);
    printf("rsa.sig.recover.ret=%d\n", ret);
    printf("rsa.sig.recover.is_expected=%d\n", ret == size && memcmp(rec, expect, (size_t)size) == 0);
    drain("recover");

    ERR_clear_error();
    printf("rsa.sig.verify.ok=%d\n", RSA_verify(NID_sha256, msg, 64, sig, siglen, rsa));
    drain("verify_ok");

    /* A tampered signature octet. */
    sig[7] ^= 0x01;
    ERR_clear_error();
    printf("rsa.sig.verify.tampered=%d\n", RSA_verify(NID_sha256, msg, 64, sig, siglen, rsa));
    drain("verify_tampered");
    sig[7] ^= 0x01;

    /* A tampered message: the digest the signature encodes is not this message's. */
    msg[0] ^= 0x01;
    ERR_clear_error();
    printf("rsa.sig.verify.msg=%d\n", RSA_verify(NID_sha256, msg, 64, sig, siglen, rsa));
    drain("verify_msg");
    msg[0] ^= 0x01;

    /* A signature one octet short is refused **before anything is allocated**. */
    ERR_clear_error();
    printf("rsa.sig.verify.short=%d\n", RSA_verify(NID_sha256, msg, 64, sig, siglen - 1, rsa));
    drain("verify_short");

    /* ---- the two `encode_pkcs1` refusals, and the size refusal */

    ERR_clear_error();
    printf("rsa.sig.sign.undef=%d\n", RSA_sign(NID_undef, msg, 64, sig2, &siglen2, rsa));
    drain("sign_undef");

    /* `NID_md2 + 0x1000` is a NID with no DigestInfo table at all -- nonzero, so it reaches the
     * table lookup rather than the `NID_undef` test above it. */
    ERR_clear_error();
    printf("rsa.sig.sign.unknown=%d\n", RSA_sign(NID_md2 + 0x1000, msg, 64, sig2, &siglen2, rsa));
    drain("sign_unknown");

    /* 19 + 100 + 11 is 130, one more than this key's width, so the size test refuses it. The
     * digest length is not checked against the digest's own size, which is why 100 works. */
    ERR_clear_error();
    printf("rsa.sig.sign.toobig=%d\n", RSA_sign(NID_sha512, msg, 100, sig2, &siglen2, rsa));
    drain("sign_toobig");

    /* ---- `NID_md5_sha1`, which has no DigestInfo at all */

    memset(msg, 0x11, sizeof(msg));
    ERR_clear_error();
    ret = RSA_sign(NID_md5_sha1, msg, 36, sig, &siglen, rsa);
    printf("rsa.sig.md5sha1.ret=%d\n", ret);
    printf("rsa.sig.md5sha1.len_is_size=%d\n", ret == 1 && siglen == (unsigned int)size);
    drain("md5sha1_sign");

    /* The block is `00 01 FF... 00` followed by the thirty-six octets verbatim. */
    memset(expect, 0, sizeof(expect));
    expect[0] = 0x00;
    expect[1] = 0x01;
    memset(expect + 2, 0xff, (size_t)(size - 3 - 36));
    expect[size - 37] = 0x00;
    memcpy(expect + size - 36, msg, 36);
    memset(rec, 0, sizeof(rec));
    ret = RSA_public_decrypt(size, sig, rec, rsa, RSA_NO_PADDING);
    printf("rsa.sig.md5sha1.block=%d\n", ret == size && memcmp(rec, expect, (size_t)size) == 0);
    drain("md5sha1_block");

    ERR_clear_error();
    printf("rsa.sig.md5sha1.verify=%d\n", RSA_verify(NID_md5_sha1, msg, 36, sig, siglen, rsa));
    drain("md5sha1_verify");

    /* The length is checked before any encoding, and the *verify* side checks it after the
     * decryption, so the two refusals are different functions with different coordinates. */
    ERR_clear_error();
    printf("rsa.sig.md5sha1.short_sign=%d\n", RSA_sign(NID_md5_sha1, msg, 35, sig2, &siglen2, rsa));
    drain("md5sha1_short_sign");
    ERR_clear_error();
    printf("rsa.sig.md5sha1.short_verify=%d\n", RSA_verify(NID_md5_sha1, msg, 35, sig, siglen, rsa));
    drain("md5sha1_short_verify");

    /* ---- `rsa_saos.c`: the ASN.1 OCTET STRING wrap */

    /* The `type` argument is unused by both entry points, and the two different NIDs below are
     * the arm that says so. */
    ERR_clear_error();
    ret = RSA_sign_ASN1_OCTET_STRING(NID_sha256, msg, 36, sig, &siglen, rsa);
    printf("rsa.saos.sign.ret=%d\n", ret);
    printf("rsa.saos.sign.len_is_size=%d\n", ret == 1 && siglen == (unsigned int)size);
    drain("saos_sign");

    /* The recovered block is `00 01 FF... 00 || 04 24 || the thirty-six octets`: `i2d`'s own DER
     * for a 36-octet OCTET STRING. */
    memset(expect, 0, sizeof(expect));
    expect[0] = 0x00;
    expect[1] = 0x01;
    memset(expect + 2, 0xff, (size_t)(size - 3 - 2 - 36));
    expect[size - 2 - 36 - 1] = 0x00;
    expect[size - 2 - 36] = 0x04;
    expect[size - 1 - 36] = 0x24;
    memcpy(expect + size - 36, msg, 36);
    memset(rec, 0, sizeof(rec));
    ret = RSA_public_decrypt(size, sig, rec, rsa, RSA_NO_PADDING);
    printf("rsa.saos.block=%d\n", ret == size && memcmp(rec, expect, (size_t)size) == 0);
    drain("saos_block");

    ERR_clear_error();
    printf("rsa.saos.verify.ok=%d\n", RSA_verify_ASN1_OCTET_STRING(NID_sha256, msg, 36, sig, siglen, rsa));
    drain("saos_verify_ok");
    ERR_clear_error();
    printf("rsa.saos.verify.other_nid=%d\n",
        RSA_verify_ASN1_OCTET_STRING(NID_sha1, msg, 36, sig, siglen, rsa));
    drain("saos_verify_other_nid");
    msg[0] ^= 0x01;
    ERR_clear_error();
    printf("rsa.saos.verify.msg=%d\n", RSA_verify_ASN1_OCTET_STRING(NID_sha256, msg, 36, sig, siglen, rsa));
    drain("saos_verify_msg");
    msg[0] ^= 0x01;
    ERR_clear_error();
    printf("rsa.saos.verify.short=%d\n",
        RSA_verify_ASN1_OCTET_STRING(NID_sha256, msg, 36, sig, siglen - 1, rsa));
    drain("saos_verify_short");

    /* A signature that is **not** a DER octet string: a PKCS#1 v1.5 DigestInfo signature fed to
     * the OCTET STRING verifier, so the `d2i` fails and the answer is the decode's own error. */
    ERR_clear_error();
    ret = RSA_sign(NID_sha256, msg, 64, sig2, &siglen2, rsa);
    printf("rsa.saos.not_der_sign=%d\n", ret);
    drain("saos_not_der_sign");
    ERR_clear_error();
    printf("rsa.saos.not_der=%d\n",
        RSA_verify_ASN1_OCTET_STRING(NID_sha256, msg, 36, sig2, siglen2, rsa));
    drain("saos_not_der");

    /* 2 + 118 is 120, above the 117 the width allows. */
    ERR_clear_error();
    printf("rsa.saos.sign.toobig=%d\n",
        RSA_sign_ASN1_OCTET_STRING(NID_sha256, msg, 118, sig, &siglen, rsa));
    drain("saos_sign_toobig");

    /* ---- `rsa_pss.c`'s verifier, over a block this probe builds with a *fixed* salt */

    {
        unsigned char em[256], em2[256];
        unsigned char salt[20];
        int hlen = EVP_MD_get_size(sha256);

        for (i = 0; i < 20; i++)
            salt[i] = 0x5a;
        ERR_clear_error();
        printf("rsa.pssv.encode=%d\n",
            rt_pss_encode(em, size, 7, hash, hlen, salt, 20, sha256, sha256));

        ERR_clear_error();
        printf("rsa.pssv.ok=%d\n", RSA_verify_PKCS1_PSS(rsa, hash, sha256, em, 20));
        drain("pssv_ok");
        ERR_clear_error();
        printf("rsa.pssv.mgf1=%d\n", RSA_verify_PKCS1_PSS_mgf1(rsa, hash, sha256, NULL, em, 20));
        drain("pssv_mgf1");
        /* `-2` (AUTO) and `-1` (DIGEST) are answered from the block; `-3` (MAX) is resolved to the
         * block's own maximum and this block does not use it. */
        ERR_clear_error();
        printf("rsa.pssv.auto=%d\n",
            RSA_verify_PKCS1_PSS(rsa, hash, sha256, em, RSA_PSS_SALTLEN_AUTO));
        drain("pssv_auto");
        ERR_clear_error();
        printf("rsa.pssv.digest=%d\n",
            RSA_verify_PKCS1_PSS(rsa, hash, sha256, em, RSA_PSS_SALTLEN_DIGEST));
        drain("pssv_digest");
        ERR_clear_error();
        printf("rsa.pssv.max=%d\n",
            RSA_verify_PKCS1_PSS(rsa, hash, sha256, em, RSA_PSS_SALTLEN_MAX));
        drain("pssv_max");
        /* The two ``sLen`` refusals: a length that disagrees with the block (with both numbers in
         * the message) and a length below the smallest convention. */
        ERR_clear_error();
        printf("rsa.pssv.slen_mismatch=%d\n", RSA_verify_PKCS1_PSS(rsa, hash, sha256, em, 19));
        drain("pssv_slen_mismatch");
        ERR_clear_error();
        printf("rsa.pssv.slen_low=%d\n", RSA_verify_PKCS1_PSS(rsa, hash, sha256, em, -5));
        drain("pssv_slen_low");
        /* Above the block's maximum: `emLen - hLen - 2` is 94 for this key, so 95 is refused. */
        ERR_clear_error();
        printf("rsa.pssv.slen_high=%d\n", RSA_verify_PKCS1_PSS(rsa, hash, sha256, em, 95));
        drain("pssv_slen_high");

        /* The four perturbations, each reaching exactly one refusal site. The salt is fixed and
         * every perturbation is a single octet xor, so both runs see the same bytes. */
        memcpy(em2, em, (size_t)size);
        em2[size - 1] = 0x00;
        ERR_clear_error();
        printf("rsa.pssv.trailer=%d\n", RSA_verify_PKCS1_PSS(rsa, hash, sha256, em2, 20));
        drain("pssv_trailer");

        memcpy(em2, em, (size_t)size);
        em2[0] |= 0x80;
        ERR_clear_error();
        printf("rsa.pssv.first=%d\n", RSA_verify_PKCS1_PSS(rsa, hash, sha256, em2, 20));
        drain("pssv_first");

        memcpy(em2, em, (size_t)size);
        em2[size - 40] ^= 0x01;
        ERR_clear_error();
        printf("rsa.pssv.db=%d\n", RSA_verify_PKCS1_PSS(rsa, hash, sha256, em2, 20));
        drain("pssv_db");

        /* The separator octet itself: `PS || 0x01 || salt`, so the 0x01 sits at
         * `emLen - sLen - hLen - 2`. Clearing it leaves a `DB` whose first non-zero octet is the
         * fixed salt `0x5a`, which is not the separator the recovery requires. */
        memcpy(em2, em, (size_t)size);
        em2[size - 20 - 32 - 2] = 0x00;
        ERR_clear_error();
        printf("rsa.pssv.separator=%d\n", RSA_verify_PKCS1_PSS(rsa, hash, sha256, em2, 20));
        drain("pssv_separator");

        /* A block whose mask was generated with a **different** digest: the `_mgf1` form with the
         * mask's digest named agrees, and the `_mgf1`-less wrapper -- which substitutes `Hash` for a
         * NULL `mgf1Hash` -- does not. */
        {
            const EVP_MD *sha1 = EVP_MD_fetch(NULL, "SHA1", NULL);
            printf("rsa.pssv.sha1_fetched=%d\n", sha1 != NULL);
            if (sha1 != NULL) {
                ERR_clear_error();
                printf("rsa.pssv.mgf1_encode=%d\n",
                    rt_pss_encode(em2, size, 7, hash, hlen, salt, 20, sha256, sha1));
                ERR_clear_error();
                printf("rsa.pssv.mgf1_named=%d\n",
                    RSA_verify_PKCS1_PSS_mgf1(rsa, hash, sha256, sha1, em2, 20));
                drain("pssv_mgf1_named");
                ERR_clear_error();
                printf("rsa.pssv.mgf1_null=%d\n",
                    RSA_verify_PKCS1_PSS_mgf1(rsa, hash, sha256, NULL, em2, 20));
                drain("pssv_mgf1_null");
                EVP_MD_free((EVP_MD *)sha1);
            }
        }
    }

done:
    EVP_MD_free((EVP_MD *)sha256);
    RSA_free(rsa);
}

/* RFC 8017 section 9.1.1's EMSA-PSS encoding, built out here with a **fixed** salt so that the
 * verifier arms above compare a block both runs hold identically. `H = Hash(0x00 * 8 || mHash ||
 * salt)`, `DB = PS || 0x01 || salt`, `maskedDB = DB ^ MGF1(H)` and `EM = maskedDB || H || 0xbc`.
 * `msbits` is the verifier's own leading-bits count; a zero one would mean EM starts with a spare
 * octet, and this court's modulus has seven, so the caller passes it and the `base` offset is 0. */
static int rt_pss_encode(unsigned char *em, int emlen, int msbits, const unsigned char *mhash,
    int hlen, const unsigned char *salt, int slen, const EVP_MD *md, const EVP_MD *mgf1)
{
    unsigned char buf[8 + EVP_MAX_MD_SIZE + 256];
    unsigned char db[256];
    int masked_dblen = emlen - hlen - 1;
    int i;

    if (masked_dblen <= 0 || masked_dblen > (int)sizeof(db) || slen < 0
        || slen > masked_dblen - 1)
        return 0;
    if (8 + hlen + slen > (int)sizeof(buf))
        return 0;

    memset(buf, 0, 8);
    memcpy(buf + 8, mhash, (size_t)hlen);
    if (slen > 0)
        memcpy(buf + 8 + hlen, salt, (size_t)slen);
    /* H, written into EM where the verifier will look for it. */
    if (EVP_Digest(buf, (size_t)(8 + hlen + slen), em + masked_dblen, NULL, md, NULL) != 1)
        return 0;

    memset(db, 0, (size_t)masked_dblen);
    db[masked_dblen - slen - 1] = 0x01;
    if (slen > 0)
        memcpy(db + masked_dblen - slen, salt, (size_t)slen);
    if (PKCS1_MGF1(em, masked_dblen, em + masked_dblen, hlen, mgf1) != 0)
        return 0;
    for (i = 0; i < masked_dblen; i++)
        em[i] ^= db[i];
    if (msbits)
        em[0] &= (unsigned char)(0xFF >> (8 - msbits));
    em[emlen - 1] = 0xbc;
    return 1;
}

/* ------------------------------------------------------------------ slice G */

/* `RSA_check_key`/`_ex` and the two blinding flag writers.
 *
 * The checker's arms are **the answers, not the reasons**, and both a good and a broken key are
 * driven: a key whose `n` is not `p*q` is the deliberate breakage the whole function exists to
 * find, and a key with an even exponent is the second, independent one. Every refusal's error
 * coordinate is drained. `RSA_blinding_on`/`_off` are two flag writes, so the observable is
 * `RSA_test_flags`'s masked word -- **the object's flags**, where `RSA_flags` reads the method's. */
static void rsa_chk_arms(void)
{
    RSA *good = rt_sign_key();
    RSA *broken = NULL, *even_e = NULL, *p_only = NULL, *badcrt = NULL;
    BIGNUM *n = NULL, *e = NULL, *d = NULL, *p = NULL, *q = NULL;
    BIGNUM *dmp1 = NULL, *dmq1 = NULL, *iqmp = NULL, *two = NULL, *eodd = NULL;
    const BIGNUM *kp = NULL, *kq = NULL, *kn = NULL;
    const BIGNUM *kdmp1 = NULL, *kdmq1 = NULL, *kiqmp = NULL;
    BN_CTX *ctx = NULL;
    int flags;

    printf("rsa.chk.key_built=%d\n", good != NULL);
    ctx = BN_CTX_new();
    two = rt_word(2);
    eodd = rt_word(65537);
    printf("rsa.chk.scratch=%d\n", ctx != NULL && two != NULL && eodd != NULL);
    if (good == NULL || ctx == NULL || two == NULL || eodd == NULL)
        goto done;

    /* ---- the good key: the one the X9.31 derivation built, unmodified */
    ERR_clear_error();
    printf("rsa.chk.good=%d\n", RSA_check_key(good));
    drain("chk_good");
    ERR_clear_error();
    printf("rsa.chk.good_ex=%d\n", RSA_check_key_ex(good, NULL));
    drain("chk_good_ex");

    /* ---- the blinding pair, on an object whose flags are known */
    flags = RSA_test_flags(good, RSA_FLAG_BLINDING | RSA_FLAG_NO_BLINDING);
    printf("rsa.chk.blinding.before=%d\n", flags);
    RSA_blinding_on(good, NULL);
    flags = RSA_test_flags(good, RSA_FLAG_BLINDING | RSA_FLAG_NO_BLINDING);
    printf("rsa.chk.blinding.on=%d\n", flags);
    RSA_blinding_on(good, ctx);
    flags = RSA_test_flags(good, RSA_FLAG_BLINDING | RSA_FLAG_NO_BLINDING);
    printf("rsa.chk.blinding.on_again=%d\n", flags);
    RSA_blinding_off(good);
    flags = RSA_test_flags(good, RSA_FLAG_BLINDING | RSA_FLAG_NO_BLINDING);
    printf("rsa.chk.blinding.off=%d\n", flags);
    RSA_blinding_off(good);
    flags = RSA_test_flags(good, RSA_FLAG_BLINDING | RSA_FLAG_NO_BLINDING);
    printf("rsa.chk.blinding.off_again=%d\n", flags);
    /* And `RSA_flags` on the same object, which reads the *method's* word and does not move. */
    printf("rsa.chk.blinding.method_flags=%d\n", RSA_flags(good));

    RSA_get0_key(good, &kn, NULL, NULL);
    RSA_get0_factors(good, &kp, &kq);
    RSA_get0_crt_params(good, &kdmp1, &kdmq1, &kiqmp);
    printf("rsa.chk.parts_read=%d\n",
        kn != NULL && kp != NULL && kq != NULL && kdmp1 != NULL && kdmq1 != NULL && kiqmp != NULL);
    if (kn == NULL || kp == NULL || kq == NULL || kdmp1 == NULL || kdmq1 == NULL || kiqmp == NULL)
        goto done;

    /* ---- four broken keys, each one breakage rather than a combination */
    broken = RSA_new();
    even_e = RSA_new();
    p_only = RSA_new();
    badcrt = RSA_new();
    printf("rsa.chk.objects=%d\n",
        broken != NULL && even_e != NULL && p_only != NULL && badcrt != NULL);
    if (broken == NULL || even_e == NULL || p_only == NULL || badcrt == NULL)
        goto done;

    /* `n = p*q + 1`. Every component is a fresh copy, because `RSA_set0_*` takes ownership. */
    n = BN_dup(kn);
    e = BN_dup(eodd);
    d = BN_dup(kdmp1);
    p = BN_dup(kp);
    q = BN_dup(kq);
    dmp1 = BN_dup(kdmp1);
    dmq1 = BN_dup(kdmq1);
    iqmp = BN_dup(kiqmp);
    printf("rsa.chk.copies=%d\n",
        n != NULL && e != NULL && d != NULL && p != NULL && q != NULL && dmp1 != NULL
            && dmq1 != NULL && iqmp != NULL);
    if (n == NULL || e == NULL || d == NULL || p == NULL || q == NULL || dmp1 == NULL
        || dmq1 == NULL || iqmp == NULL)
        goto done;
    BN_add_word(n, 1);

    /* `n != p*q`, with everything else in place: the one check that needs the multiplication.
     * `n` itself is handed over, so the probe's own pointer is cleared and `broken` owns it. */
    ERR_clear_error();
    printf("rsa.chk.broken.set=%d\n",
        RSA_set0_key(broken, n, BN_dup(eodd), BN_dup(d)) == 1
            && RSA_set0_factors(broken, BN_dup(p), BN_dup(q)) == 1
            && RSA_set0_crt_params(broken, BN_dup(dmp1), BN_dup(dmq1), BN_dup(iqmp)) == 1);
    n = NULL;
    ERR_clear_error();
    printf("rsa.chk.broken=%d\n", RSA_check_key(broken));
    drain("chk_broken_n");

    /* An even public exponent, which `RSA_R_BAD_E_VALUE` refuses before the primality work. */
    ERR_clear_error();
    printf("rsa.chk.even_e.set=%d\n",
        RSA_set0_key(even_e, BN_dup(kn), BN_dup(two), BN_dup(d)) == 1  /* the even one */
            && RSA_set0_factors(even_e, BN_dup(p), BN_dup(q)) == 1);
    ERR_clear_error();
    printf("rsa.chk.even_e=%d\n", RSA_check_key(even_e));
    drain("chk_even_e");

    /* No `d` at all: the `VALUE_MISSING` guard, which needs none of the arithmetic. */
    ERR_clear_error();
    printf("rsa.chk.p_only.set=%d\n",
        RSA_set0_key(p_only, BN_dup(kn), BN_dup(eodd), NULL) == 1
            && RSA_set0_factors(p_only, BN_dup(p), BN_dup(q)) == 1);
    ERR_clear_error();
    printf("rsa.chk.p_only=%d\n", RSA_check_key(p_only));
    drain("chk_missing_d");

    /* A CRT parameter that is not `d mod (p-1)`: the congruent test, which is reached only when
     * all three CRT members are present. */
    ERR_clear_error();
    printf("rsa.chk.badcrt.set=%d\n",
        RSA_set0_key(badcrt, BN_dup(kn), BN_dup(eodd), BN_dup(d)) == 1
            && RSA_set0_factors(badcrt, BN_dup(p), BN_dup(q)) == 1
            && RSA_set0_crt_params(badcrt, BN_dup(dmq1), BN_dup(dmq1), BN_dup(iqmp)) == 1);
    ERR_clear_error();
    printf("rsa.chk.badcrt=%d\n", RSA_check_key(badcrt));
    drain("chk_bad_dmp1");

done:
    BN_free(iqmp);
    BN_free(dmq1);
    BN_free(dmp1);
    BN_free(eodd);
    BN_free(two);
    BN_free(q);
    BN_free(p);
    BN_free(d);
    BN_free(e);
    BN_free(n);
    BN_CTX_free(ctx);
    RSA_free(badcrt);
    RSA_free(p_only);
    RSA_free(even_e);
    RSA_free(broken);
    RSA_free(good);
}

/* ------------------------------------------------------------------ slice E */

/* The `EVP_PKEY_CTX` controls: `RSA_pkey_ctx_ctrl` and the twenty-three `EVP_PKEY_CTX_{get,set}_rsa_*`
 * entry points.
 *
 * **This is the one court in `crypto/rsa` that publishes a provider**, and the reason is that a
 * control's body is a *decision about a context*: nineteen of the twenty-three answer differently
 * for a NULL context, a context with no operation, and a context whose key type is not RSA, and
 * three of them cannot be handed a NULL context at all. The keymgmt below is the smallest the
 * structural check accepts -- the same shape `RT-EVP-PKEY-OPS` publishes -- and it is named
 * `COURT-RSA` rather than `RSA` so that it cannot shadow the default provider's own row in either
 * binary's method store.
 *
 * **What no arm here can reach, named rather than implied.** A control's *successful* path is the
 * ctrl-to-parameter translation, which needs a context whose key type is RSA and whose operation is
 * initialised -- and the crate publishes no RSA `EVP_KEYMGMT` at all (8.4's provider half is not
 * landed), so `EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL)` answers NULL on the candidate and a
 * context on the authority. An arm that compared that would be a difference about the missing
 * provider row rather than about this file, so it is not written. What *is* written is every
 * control's refusal structure, driven twice: once against a NULL context and once against a live
 * one, so which of the three refusals each control takes is compared rather than assumed.
 *
 * Three controls dereference `ctx` before any test -- `set_rsa_oaep_md` and `get_rsa_oaep_md`
 * through `EVP_PKEY_CTX_is_a`, and `set1_rsa_keygen_pubexp` through `evp_pkey_ctx_is_legacy` -- so a
 * NULL context is a **fault** on both sides there and only the live arm exists for them. */

static int ct_marker;

static void *ct_new(void *provctx) { (void) provctx; return malloc(1); }
static void ct_free(void *keydata) { free(keydata); }
static int ct_has(const void *keydata, int selection) { (void) keydata; (void) selection; return 1; }
static int ct_get_params(void *keydata, OSSL_PARAM params[]) { (void) keydata; (void) params; return 1; }
static const OSSL_PARAM *ct_gettable_params(void *provctx) { (void) provctx; return NULL; }
static int ct_set_params(void *keydata, const OSSL_PARAM params[]) { (void) keydata; (void) params; return 1; }
static const OSSL_PARAM *ct_settable_params(void *provctx) { (void) provctx; return NULL; }
static void *ct_gen_init(void *provctx, int selection, const OSSL_PARAM params[])
{ (void) provctx; (void) selection; (void) params; return malloc(1); }
static void ct_gen_cleanup(void *genctx) { free(genctx); }
static void *ct_gen(void *genctx, OSSL_CALLBACK *cb, void *cbarg)
{ (void) genctx; (void) cb; (void) cbarg; return malloc(1); }
static int ct_gen_set_template(void *genctx, void *templ) { (void) genctx; (void) templ; return 1; }
static int ct_gen_set_params(void *genctx, const OSSL_PARAM params[]) { (void) genctx; (void) params; return 1; }
static const OSSL_PARAM *ct_gen_settable_params(void *genctx, void *provctx)
{ (void) genctx; (void) provctx; return NULL; }
static int ct_gen_get_params(void *genctx, OSSL_PARAM params[]) { (void) genctx; (void) params; return 1; }
static const OSSL_PARAM *ct_gen_gettable_params(void *genctx, void *provctx)
{ (void) genctx; (void) provctx; return NULL; }
static void *ct_load(const void *reference, size_t reference_sz)
{ (void) reference; (void) reference_sz; return malloc(1); }
static const char *ct_query_operation_name(int operation_id) { (void) operation_id; return NULL; }
static void *ct_import(void *keydata, int selection, const OSSL_PARAM params[])
{ (void) keydata; (void) selection; (void) params; return malloc(1); }
static const OSSL_PARAM *ct_import_types(int selection) { (void) selection; return NULL; }
static int ct_export(void *keydata, int selection, OSSL_CALLBACK *cb, void *cbarg)
{ (void) keydata; (void) selection; (void) cb; (void) cbarg; return 1; }
static const OSSL_PARAM *ct_export_types(int selection) { (void) selection; return NULL; }
static void *ct_dup(const void *keydata, int selection) { (void) keydata; (void) selection; return malloc(1); }
static int ct_validate(const void *keydata, int selection, int checktype)
{ (void) keydata; (void) selection; (void) checktype; return 1; }
static int ct_match(const void *a, const void *b, int selection)
{ (void) a; (void) b; (void) selection; return 1; }

static const OSSL_DISPATCH ct_fns[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void)) ct_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void)) ct_free },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void)) ct_has },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void)) ct_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void)) ct_gettable_params },
    { OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*)(void)) ct_set_params },
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*)(void)) ct_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void)) ct_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE, (void (*)(void)) ct_gen_set_template },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void)) ct_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void)) ct_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN_GET_PARAMS, (void (*)(void)) ct_gen_get_params },
    { OSSL_FUNC_KEYMGMT_GEN_GETTABLE_PARAMS, (void (*)(void)) ct_gen_gettable_params },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void)) ct_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void)) ct_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void)) ct_load },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (void (*)(void)) ct_query_operation_name },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void)) ct_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void)) ct_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void)) ct_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void)) ct_export_types },
    { OSSL_FUNC_KEYMGMT_DUP, (void (*)(void)) ct_dup },
    { OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void)) ct_validate },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void)) ct_match },
    { 0, NULL }
};

static int ct_teardown(void *provctx) { (void) provctx; return 1; }

static const OSSL_ALGORITHM *ct_query(void *provctx, int operation_id, int *no_cache)
{
    static const OSSL_ALGORITHM km[] = {
        { "COURT-RSA:court-rsa", "provider=court-rsa", ct_fns, "the probe's keymgmt" },
        { NULL, NULL, NULL, NULL }
    };

    (void) provctx;
    *no_cache = 0;
    if (operation_id == OSSL_OP_KEYMGMT)
        return km;
    return NULL;
}

static const OSSL_DISPATCH ct_dispatch[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void)) ct_query },
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void)) ct_teardown },
    { 0, NULL }
};

static int ct_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
    const OSSL_DISPATCH **out, void **provctx)
{
    (void) handle;
    (void) in;
    *out = ct_dispatch;
    *provctx = &ct_marker;
    return 1;
}

static void rsa_ctl_arms(void)
{
    OSSL_PROVIDER *prov;
    EVP_PKEY_CTX *null_ctx = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    const EVP_MD *sha256 = EVP_MD_fetch(NULL, "SHA256", NULL);
    BIGNUM *pubexp = NULL;
    unsigned char label[4];
    unsigned char *out = NULL;
    char name[64];
    int pad = 0, saltlen = 0;

    memset(label, 0x5a, sizeof(label));
    memset(name, 0, sizeof(name));

    printf("rsa.ctl.md_fetched=%d\n", sha256 != NULL);

    /* ---- the NULL-context refusals, and the three that would fault are not called */
    ERR_clear_error();
    printf("rsa.ctl.null.padding=%d\n", EVP_PKEY_CTX_set_rsa_padding(null_ctx, 1));
    printf("rsa.ctl.null.get_padding=%d\n", EVP_PKEY_CTX_get_rsa_padding(null_ctx, &pad));
    printf("rsa.ctl.null.pss_kg_md=%d\n", EVP_PKEY_CTX_set_rsa_pss_keygen_md(null_ctx, sha256));
    printf("rsa.ctl.null.pss_kg_md_name=%d\n",
        EVP_PKEY_CTX_set_rsa_pss_keygen_md_name(null_ctx, "SHA256", NULL));
    printf("rsa.ctl.null.oaep_md_name=%d\n",
        EVP_PKEY_CTX_set_rsa_oaep_md_name(null_ctx, "SHA256", NULL));
    printf("rsa.ctl.null.get_oaep_md_name=%d\n",
        EVP_PKEY_CTX_get_rsa_oaep_md_name(null_ctx, name, sizeof(name)));
    printf("rsa.ctl.null.mgf1_md=%d\n", EVP_PKEY_CTX_set_rsa_mgf1_md(null_ctx, sha256));
    printf("rsa.ctl.null.mgf1_md_name=%d\n",
        EVP_PKEY_CTX_set_rsa_mgf1_md_name(null_ctx, "SHA256", NULL));
    printf("rsa.ctl.null.get_mgf1_md_name=%d\n",
        EVP_PKEY_CTX_get_rsa_mgf1_md_name(null_ctx, name, sizeof(name)));
    printf("rsa.ctl.null.pss_kg_mgf1_md=%d\n", EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md(null_ctx, sha256));
    printf("rsa.ctl.null.pss_kg_mgf1_md_name=%d\n",
        EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name(null_ctx, "SHA256"));
    printf("rsa.ctl.null.get_mgf1_md=%d\n", EVP_PKEY_CTX_get_rsa_mgf1_md(null_ctx, NULL));
    printf("rsa.ctl.null.set0_label=%d\n", EVP_PKEY_CTX_set0_rsa_oaep_label(null_ctx, NULL, 0));
    printf("rsa.ctl.null.get0_label=%d\n", EVP_PKEY_CTX_get0_rsa_oaep_label(null_ctx, &out));
    printf("rsa.ctl.null.pss_saltlen=%d\n", EVP_PKEY_CTX_set_rsa_pss_saltlen(null_ctx, 20));
    printf("rsa.ctl.null.get_pss_saltlen=%d\n", EVP_PKEY_CTX_get_rsa_pss_saltlen(null_ctx, &saltlen));
    printf("rsa.ctl.null.pss_kg_saltlen=%d\n", EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(null_ctx, 20));
    printf("rsa.ctl.null.kg_bits=%d\n", EVP_PKEY_CTX_set_rsa_keygen_bits(null_ctx, 2048));
    printf("rsa.ctl.null.kg_pubexp=%d\n", EVP_PKEY_CTX_set_rsa_keygen_pubexp(null_ctx, NULL));
    printf("rsa.ctl.null.kg_primes=%d\n", EVP_PKEY_CTX_set_rsa_keygen_primes(null_ctx, 2));
    printf("rsa.ctl.null.pkey_ctx_ctrl=%d\n",
        RSA_pkey_ctx_ctrl(null_ctx, EVP_PKEY_OP_TYPE_SIG, 1, 0, NULL));
    drain("ctl_null");
    /* **The three NULL calls this probe deliberately does not make** are the ones whose first act is
     * a dereference: `set_rsa_oaep_md` and `get_rsa_oaep_md` through `EVP_PKEY_CTX_is_a`, and
     * `set1_rsa_keygen_pubexp` through `evp_pkey_ctx_is_legacy`. Their live arms are below. */
    printf("rsa.ctl.null.faulting_skipped=%d\n", 3);

    /* ---- the live-context arms, over this probe's own keymgmt */
    printf("rsa.ctl.provider.add=%d\n", OSSL_PROVIDER_add_builtin(NULL, "court-rsa", ct_init));
    prov = OSSL_PROVIDER_load(NULL, "court-rsa");
    printf("rsa.ctl.provider.load=%d\n", prov != NULL);
    if (prov == NULL)
        return;

    ERR_clear_error();
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "COURT-RSA", NULL);
    printf("rsa.ctl.ctx=%d\n", ctx != NULL);
    drain("ctl_ctx_new");
    if (ctx == NULL)
        return;
    printf("rsa.ctl.ctx.is_a_rsa=%d\n", EVP_PKEY_CTX_is_a(ctx, "RSA"));
    printf("rsa.ctl.ctx.is_a_self=%d\n", EVP_PKEY_CTX_is_a(ctx, "COURT-RSA"));
    printf("rsa.ctl.ctx.operation=%d\n", EVP_PKEY_CTX_get_operation(ctx));

    pubexp = rt_word(65537);

    ERR_clear_error();
    printf("rsa.ctl.live.padding=%d\n", EVP_PKEY_CTX_set_rsa_padding(ctx, 1));
    printf("rsa.ctl.live.get_padding=%d\n", EVP_PKEY_CTX_get_rsa_padding(ctx, &pad));
    printf("rsa.ctl.live.pss_kg_md=%d\n", EVP_PKEY_CTX_set_rsa_pss_keygen_md(ctx, sha256));
    printf("rsa.ctl.live.pss_kg_md_name=%d\n", EVP_PKEY_CTX_set_rsa_pss_keygen_md_name(ctx, "SHA256", NULL));
    printf("rsa.ctl.live.oaep_md=%d\n", EVP_PKEY_CTX_set_rsa_oaep_md(ctx, sha256));
    printf("rsa.ctl.live.oaep_md_name=%d\n", EVP_PKEY_CTX_set_rsa_oaep_md_name(ctx, "SHA256", NULL));
    printf("rsa.ctl.live.get_oaep_md_name=%d\n", EVP_PKEY_CTX_get_rsa_oaep_md_name(ctx, name, sizeof(name)));
    printf("rsa.ctl.live.get_oaep_md=%d\n", EVP_PKEY_CTX_get_rsa_oaep_md(ctx, NULL));
    printf("rsa.ctl.live.mgf1_md=%d\n", EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, sha256));
    printf("rsa.ctl.live.mgf1_md_name=%d\n", EVP_PKEY_CTX_set_rsa_mgf1_md_name(ctx, "SHA256", NULL));
    printf("rsa.ctl.live.get_mgf1_md_name=%d\n", EVP_PKEY_CTX_get_rsa_mgf1_md_name(ctx, name, sizeof(name)));
    printf("rsa.ctl.live.pss_kg_mgf1_md=%d\n", EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md(ctx, sha256));
    printf("rsa.ctl.live.pss_kg_mgf1_md_name=%d\n", EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name(ctx, "SHA256"));
    printf("rsa.ctl.live.get_mgf1_md=%d\n", EVP_PKEY_CTX_get_rsa_mgf1_md(ctx, NULL));
    printf("rsa.ctl.live.set0_label=%d\n", EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, label, 4));
    printf("rsa.ctl.live.get0_label=%d\n", EVP_PKEY_CTX_get0_rsa_oaep_label(ctx, &out));
    printf("rsa.ctl.live.pss_saltlen=%d\n", EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, 20));
    printf("rsa.ctl.live.get_pss_saltlen=%d\n", EVP_PKEY_CTX_get_rsa_pss_saltlen(ctx, &saltlen));
    printf("rsa.ctl.live.pss_kg_saltlen=%d\n", EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(ctx, 20));
    printf("rsa.ctl.live.kg_bits=%d\n", EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048));
    printf("rsa.ctl.live.kg_pubexp=%d\n", EVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx, pubexp));
    printf("rsa.ctl.live.set1_kg_pubexp=%d\n", EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx, pubexp));
    printf("rsa.ctl.live.kg_primes=%d\n", EVP_PKEY_CTX_set_rsa_keygen_primes(ctx, 2));
    printf("rsa.ctl.live.pkey_ctx_ctrl=%d\n",
        RSA_pkey_ctx_ctrl(ctx, -1, EVP_PKEY_CTRL_RSA_PADDING, 1, NULL));
    drain("ctl_live");

    /* The context's own state after all of that: a refused control must not have moved it. */
    printf("rsa.ctl.live.operation_after=%d\n", EVP_PKEY_CTX_get_operation(ctx));
    printf("rsa.ctl.live.pkey_null=%d\n", EVP_PKEY_CTX_get0_pkey(ctx) == NULL);

    BN_free(pubexp);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PROVIDER_unload(prov);
    EVP_MD_free((EVP_MD *)sha256);
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

    /* Slice D's default method, its four-name family and the seven `rsa_ossl_*` entry points. It
     * runs after `rsa_object_arms` because it registers no ex_data index of its own: the index that
     * arm registers is what makes the authority's `CRYPTO_free_ex_data` take its non-allocating
     * path inside the constructor windows below. */
    rsa_ossl_arms();

    /* Slice E's X9.31 generator pair and the four `rsa_crpt.c` crypt wrappers, over a key the
     * generator produced. */
    rsa_keygen_arms();

    /* Slice E's other half: `rsa_gen.c`'s dispatchers and `rsa_depr.c`'s constructor, over both
     * generators -- the SP800-56B path and the multi-prime path. */
    rsa_generate_arms();

    /* Slice D's remainder: the two signing entry points, the ASN.1 OCTET STRING pair and the PSS
     * verifier, over a deterministic key both binaries derive from the same seeds. */
    rsa_sig_arms();

    /* Slice G: the two checkers and the blinding flag pair. */
    rsa_chk_arms();

    /* Slice E's controls, over a NULL context and over one this probe's own keymgmt backs. It runs
     * last because it loads a provider, and the arms above are about the library's own tables. */
    rsa_ctl_arms();

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
