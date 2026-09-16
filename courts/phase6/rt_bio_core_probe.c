/*
 * RT-BIO-CORE -- the core BIO, differentially.
 *
 * What this court has to establish
 * --------------------------------
 * `BIO_s_core()` returns a BIO *method* whose every operation is a forward to a
 * function pointer the application supplied in an `OSSL_DISPATCH` table. The method
 * owns nothing: the interesting behaviour is therefore *what it calls, with what
 * argument, and what it answers when there is nothing to call*. Five axes, and none
 * of them is visible from a happy-path test:
 *
 *   1. **The "nothing to call" answer is not uniform.** `bio_core_read_ex` and
 *      `bio_core_write_ex` answer `0` with no callback; `bio_core_ctrl`,
 *      `bio_core_gets` and `bio_core_puts` answer `-1`. A transcription that picked
 *      one value and used it everywhere would pass a test that always supplies a
 *      full table. The probe therefore builds tables that are *deliberately
 *      incomplete* and records the answer for each missing callback separately: a
 *      write-only table (so `ctrl`, `gets`, `puts` and `read` are all absent) and a
 *      read-only one.
 *
 *   2. **The table a BIO uses belongs to the context the BIO was created on.** The
 *      constructor and all seven operations read their callbacks through
 *      `get_globals(bio->libctx)`, so two contexts holding different tables must
 *      drive two different sets of callbacks. The probe gives its two channels
 *      different callback *functions* whose return values are distinguishable
 *      (`3` against `6`), so the transcript names which channel ran without the
 *      probe having to trust a counter.
 *
 *   3. **The stored handle is what the callback receives, verbatim.** Not the BIO,
 *      not the context, not a wrapper. Every callback compares its first argument
 *      against the handle the constructor was handed and against NULL, and the
 *      probe prints the two booleans rather than a pointer (an address would make
 *      the transcript a property of the loader rather than of the library).
 *
 *   4. **`bio->libctx` is stored as given and resolved at use time.** The
 *      authority's `BIO_new_ex` assigns `bio->libctx = libctx` with no
 *      concretisation, and `ossl_lib_ctx_get_concrete(NULL)` answers the *thread*
 *      default. So a BIO created with a NULL context resolves `get_globals` against
 *      whatever this thread's default is *when the operation runs*, not when the BIO
 *      was made. The probe observes that by creating one such BIO before any default
 *      is installed, writing to it (no callbacks -> `0`) and then writing to the
 *      same BIO after installing a context that has them (-> that channel's answer).
 *
 *   5. **The first table entry for an id wins.** The walk arms a slot only while that
 *      slot is still empty, so a table carrying the same id twice reaches the first
 *      entry and never the second. The write-only table below carries two
 *      `BIO_write_ex` entries whose answers differ, which is what makes the rule
 *      observable through the constructor rather than only through the internal
 *      function's unit test.
 *
 * One more obligation is filed here because this is where it becomes observable:
 * `OSSL_LIB_CTX_BIO_CORE_INDEX` (17) is filled **eagerly** by `context_init`, not on
 * first use, so `OSSL_LIB_CTX_get_data` answers non-NULL for a context that has never
 * seen a dispatch table. `RT-LIBCTX` sweeps the slot table and carries the same
 * number; this probe states it as the precondition the constructor's `NULL` answer
 * actually comes from (the absence of `read_ex`/`write_ex`, not the absence of a
 * globals block, which is unreachable through the public API).
 *
 * Fault boundaries
 * ----------------
 * Two paths in the authority call a NULL function pointer and the probe does not
 * take them, because a transcript cannot compare a crash:
 *
 *   * `BIO_new_from_core_bio` with a table that has `write_ex` or `read_ex` but **no**
 *     `BIO_up_ref` — the constructor's guard passes and then calls the NULL pointer;
 *   * `BIO_free` of any core BIO whose context has no `BIO_free` callback — including
 *     every core BIO built on the default context with `BIO_new(BIO_s_core())`.
 *
 * `ossl_bio_init_core` with a NULL table is the same class (the authority's loop
 * condition reads `fns->function_id`). All three are recorded in
 * `docs/SECURITY_DIVERGENCE_POLICY.md` and in `src/context/core_bio.rs`'s module
 * documentation; this probe deliberately stops one step short of each.
 *
 * Every observation is `key=value` on stdout, one line each, with unique keys. The
 * `err=` field is the packed `ERR_peek_error()` read immediately after the call and
 * cleared before the next, so it belongs to its own call.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <openssl/bio.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---------------------------------------------------------------- reporting */

static void sayn(const char *key, long long v)
{
    printf("%s=%lld err=%lu\n", key, v, ERR_peek_error());
    ERR_clear_error();
}

static void sayp(const char *key, const void *p)
{
    printf("%s=%s err=%lu\n", key, p == NULL ? "NULL" : "nonnull",
           ERR_peek_error());
    ERR_clear_error();
}

static void says(const char *key, const char *s)
{
    printf("%s=%s err=%lu\n", key, s == NULL ? "NULL" : s, ERR_peek_error());
    ERR_clear_error();
}

/* ------------------------------------------------------------- the channels */

/* The argument identities every callback compares against. Only equality is ever
 * printed, never the address itself. */
static char io_buf[64];
static const char io_str[] = "probe-core-bio";
static long io_larg = -4242;
static int io_cmd = 9001;
static void *io_ptr;

typedef struct {
    int read_calls, write_calls, gets_calls, puts_calls, ctrl_calls;
    int upref_calls, free_calls;
    int read_handle_ok, write_handle_ok, gets_handle_ok, puts_handle_ok;
    int ctrl_handle_ok, upref_handle_ok, free_handle_ok;
    int read_handle_null, write_handle_null, free_handle_null;
    int read_data_ok, write_data_ok, gets_buf_ok, puts_str_ok, ctrl_ptr_ok;
    size_t read_len, write_len;
    int gets_size, ctrl_cmd;
    long ctrl_num;
} rec_t;

/*
 * One channel: seven callbacks writing into a record of their own, each answering a
 * value derived from `ch` so that a transcript line names the channel that ran.
 * `upret` is the up-ref answer, which is `0` for the one channel that must refuse it.
 *
 * The handle is `h_<tag>`, set by `main` before the table is handed to the
 * constructor. The callbacks are only ever entered through the library, so the
 * handle is always assigned by the time they run.
 */
/*
 * A channel's surface is the same seven callbacks whichever table it sits in, and the
 * tables below deliberately omit some of them: the omission *is* the subject. The
 * unused attribute records that, rather than deleting a function and losing the
 * declaration of what the channel would have done.
 */
#if defined(__GNUC__)
#define MAYBE_UNUSED __attribute__((unused))
#else
#define MAYBE_UNUSED
#endif

#define DEFINE_CHANNEL(tag, ch, upret)                                          \
    static rec_t rec_##tag;                                                     \
    static const void *h_##tag;                                                 \
                                                                                \
    static MAYBE_UNUSED int rd_##tag(OSSL_CORE_BIO *b, void *data,              \
                                     size_t data_len, size_t *bytes_read)       \
    {                                                                           \
        rec_##tag.read_calls++;                                                 \
        rec_##tag.read_handle_ok = ((const void *) b == h_##tag);               \
        rec_##tag.read_handle_null = (b == NULL);                               \
        rec_##tag.read_data_ok = (data == (void *) io_buf);                     \
        rec_##tag.read_len = data_len;                                          \
        *bytes_read = (size_t) (2 * (ch));                                      \
        return 1;                                                               \
    }                                                                           \
                                                                                \
    static MAYBE_UNUSED int wr_##tag(OSSL_CORE_BIO *b, const void *data,        \
                                     size_t data_len, size_t *written)          \
    {                                                                           \
        rec_##tag.write_calls++;                                                \
        rec_##tag.write_handle_ok = ((const void *) b == h_##tag);              \
        rec_##tag.write_handle_null = (b == NULL);                              \
        rec_##tag.write_data_ok = (data == (const void *) io_buf);              \
        rec_##tag.write_len = data_len;                                         \
        *written = (size_t) (3 * (ch));                                         \
        return 1;                                                               \
    }                                                                           \
                                                                                \
    static MAYBE_UNUSED int gt_##tag(OSSL_CORE_BIO *b, char *buf, int size)     \
    {                                                                           \
        rec_##tag.gets_calls++;                                                 \
        rec_##tag.gets_handle_ok = ((const void *) b == h_##tag);               \
        rec_##tag.gets_buf_ok = (buf == io_buf);                                \
        rec_##tag.gets_size = size;                                             \
        return 5 * (ch);                                                        \
    }                                                                           \
                                                                                \
    static MAYBE_UNUSED int pt_##tag(OSSL_CORE_BIO *b, const char *str)         \
    {                                                                           \
        rec_##tag.puts_calls++;                                                 \
        rec_##tag.puts_handle_ok = ((const void *) b == h_##tag);               \
        rec_##tag.puts_str_ok = (str == io_str);                                \
        return 1 * (ch);                                                        \
    }                                                                           \
                                                                                \
    static MAYBE_UNUSED int ct_##tag(OSSL_CORE_BIO *b, int cmd, long num,       \
                                     void *ptr)                                 \
    {                                                                           \
        rec_##tag.ctrl_calls++;                                                 \
        rec_##tag.ctrl_handle_ok = ((const void *) b == h_##tag);               \
        rec_##tag.ctrl_cmd = cmd;                                               \
        rec_##tag.ctrl_num = num;                                               \
        rec_##tag.ctrl_ptr_ok = (ptr == io_ptr);                                \
        return 42 * (ch);                                                       \
    }                                                                           \
                                                                                \
    static MAYBE_UNUSED int ur_##tag(OSSL_CORE_BIO *b)                          \
    {                                                                           \
        rec_##tag.upref_calls++;                                                \
        rec_##tag.upref_handle_ok = ((const void *) b == h_##tag);              \
        return (upret);                                                         \
    }                                                                           \
                                                                                \
    static MAYBE_UNUSED int fr_##tag(OSSL_CORE_BIO *b)                          \
    {                                                                           \
        rec_##tag.free_calls++;                                                 \
        rec_##tag.free_handle_ok = ((const void *) b == h_##tag);               \
        rec_##tag.free_handle_null = (b == NULL);                               \
        return 1;                                                               \
    }

#define CH_ENTRY(id, fn) { (id), (OSSL_FUNC) (fn) }
#define CH_END { 0, NULL }

/*
 * Six channels.
 *
 * `full`   all seven callbacks.
 * `wonly`  `write_ex` + `up_ref` + `free`; no `read_ex`, `ctrl`, `gets` or `puts`.
 * `ronly`  `read_ex` + `up_ref` + `free`; no `write_ex`, `ctrl`, `gets` or `puts`.
 * `noup`   `write_ex` + `free`, and an `up_ref` that answers `0`.
 * `alpha`  all seven, channel 5.
 * `beta`   all seven, channel 6.
 *
 * Every channel that the probe frees supplies `free`, and every one it constructs
 * supplies `up_ref`, because the authority calls both unguarded (see the header).
 */
DEFINE_CHANNEL(full, 1, 1)
DEFINE_CHANNEL(wonly, 2, 1)
DEFINE_CHANNEL(ronly, 3, 1)
DEFINE_CHANNEL(noup, 4, 0)
DEFINE_CHANNEL(alpha, 5, 1)
DEFINE_CHANNEL(beta, 6, 1)

static const OSSL_DISPATCH table_full[] = {
    CH_ENTRY(OSSL_FUNC_BIO_READ_EX, rd_full),
    CH_ENTRY(OSSL_FUNC_BIO_WRITE_EX, wr_full),
    CH_ENTRY(OSSL_FUNC_BIO_GETS, gt_full),
    CH_ENTRY(OSSL_FUNC_BIO_PUTS, pt_full),
    CH_ENTRY(OSSL_FUNC_BIO_CTRL, ct_full),
    CH_ENTRY(OSSL_FUNC_BIO_UP_REF, ur_full),
    CH_ENTRY(OSSL_FUNC_BIO_FREE, fr_full),
    CH_END
};

static const OSSL_DISPATCH table_wonly[] = {
    CH_ENTRY(OSSL_FUNC_BIO_WRITE_EX, wr_wonly),
    /*
     * A second entry carrying the *same* id. `ossl_bio_init_core` stores an entry only
     * while the slot it names is still empty, so the first one wins and the second is
     * never reachable. The two answer different values (3 x 2 against 3 x 4), so a
     * transcription that overwrote the slot, or that sorted the table, would move
     * `wonly.write.rc` and `wonly.second_entry.calls` together.
     */
    CH_ENTRY(OSSL_FUNC_BIO_WRITE_EX, wr_noup),
    CH_ENTRY(OSSL_FUNC_BIO_UP_REF, ur_wonly),
    CH_ENTRY(OSSL_FUNC_BIO_FREE, fr_wonly),
    CH_END
};

static const OSSL_DISPATCH table_ronly[] = {
    CH_ENTRY(OSSL_FUNC_BIO_READ_EX, rd_ronly),
    CH_ENTRY(OSSL_FUNC_BIO_UP_REF, ur_ronly),
    CH_ENTRY(OSSL_FUNC_BIO_FREE, fr_ronly),
    CH_END
};

static const OSSL_DISPATCH table_noup[] = {
    CH_ENTRY(OSSL_FUNC_BIO_WRITE_EX, wr_noup),
    CH_ENTRY(OSSL_FUNC_BIO_UP_REF, ur_noup),
    CH_ENTRY(OSSL_FUNC_BIO_FREE, fr_noup),
    CH_END
};

static const OSSL_DISPATCH table_alpha[] = {
    CH_ENTRY(OSSL_FUNC_BIO_READ_EX, rd_alpha),
    CH_ENTRY(OSSL_FUNC_BIO_WRITE_EX, wr_alpha),
    CH_ENTRY(OSSL_FUNC_BIO_GETS, gt_alpha),
    CH_ENTRY(OSSL_FUNC_BIO_PUTS, pt_alpha),
    CH_ENTRY(OSSL_FUNC_BIO_CTRL, ct_alpha),
    CH_ENTRY(OSSL_FUNC_BIO_UP_REF, ur_alpha),
    CH_ENTRY(OSSL_FUNC_BIO_FREE, fr_alpha),
    CH_END
};

static const OSSL_DISPATCH table_beta[] = {
    CH_ENTRY(OSSL_FUNC_BIO_READ_EX, rd_beta),
    CH_ENTRY(OSSL_FUNC_BIO_WRITE_EX, wr_beta),
    CH_ENTRY(OSSL_FUNC_BIO_GETS, gt_beta),
    CH_ENTRY(OSSL_FUNC_BIO_PUTS, pt_beta),
    CH_ENTRY(OSSL_FUNC_BIO_CTRL, ct_beta),
    CH_ENTRY(OSSL_FUNC_BIO_UP_REF, ur_beta),
    CH_ENTRY(OSSL_FUNC_BIO_FREE, fr_beta),
    CH_END
};

/* The index `RT-LIBCTX` also sweeps. `include/internal/cryptlib.h`. */
#define IDX_BIO_CORE 17

#define CBH(n) ((OSSL_CORE_BIO *) (uintptr_t) (n))

/* --------------------------------------------------------------- the probe */

int main(void)
{
    const BIO_METHOD *m1, *m2;
    OSSL_LIB_CTX *fresh, *ctx_full, *ctx_wonly, *ctx_ronly, *ctx_noup;
    OSSL_LIB_CTX *ctx_a, *ctx_b, *prev;
    BIO *b;
    long ctrl_rc;
    int rc;

    setvbuf(stdout, NULL, _IOLBF, 0);
    io_ptr = (void *) io_buf;

    /* --- 1. the method itself --------------------------------------------- */

    m1 = BIO_s_core();
    sayp("method.nonnull", m1);
    m2 = BIO_s_core();
    sayn("method.stable", m1 == m2);

    /* The slot exists before any table is installed, on a fresh context and on the
     * default one. This is `context_init`, not first use. */
    fresh = OSSL_LIB_CTX_new();
    sayp("slot.fresh17", OSSL_LIB_CTX_get_data(fresh, IDX_BIO_CORE));
    sayp("slot.default17", OSSL_LIB_CTX_get_data(NULL, IDX_BIO_CORE));
    OSSL_LIB_CTX_free(fresh);

    /* --- 2. no table: the constructor refuses ----------------------------- */

    sayp("notable.default_null_handle", BIO_new_from_core_bio(NULL, NULL));
    sayp("notable.default_handle", BIO_new_from_core_bio(NULL, CBH(0x1000)));
    fresh = OSSL_LIB_CTX_new();
    sayp("notable.fresh_handle", BIO_new_from_core_bio(fresh, CBH(0x1000)));
    OSSL_LIB_CTX_free(fresh);

    /* --- 3. a full table --------------------------------------------------- */

    h_full = (const void *) (uintptr_t) 0x2000;
    ctx_full = OSSL_LIB_CTX_new_from_dispatch(NULL, table_full);
    sayp("full.ctx", ctx_full);
    b = BIO_new_from_core_bio(ctx_full, CBH(0x2000));
    sayp("full.bio", b);
    sayn("full.type", BIO_method_type(b));
    sayn("full.type_is_core_to_prov",
         BIO_method_type(b) == BIO_TYPE_CORE_TO_PROV);
    says("full.name", BIO_method_name(b));
    sayn("full.name_is_core_filter",
         memcmp(BIO_method_name(b), "BIO to Core filter", 18) == 0);
    sayn("full.init", BIO_get_init(b));
    sayn("full.data_roundtrip", BIO_get_data(b) == h_full);
    sayn("full.upref.calls", rec_full.upref_calls);
    sayn("full.upref.handle_ok", rec_full.upref_handle_ok);

    rc = BIO_write(b, io_buf, 32);
    sayn("full.write.rc", rc);
    sayn("full.write.calls", rec_full.write_calls);
    sayn("full.write.handle_ok", rec_full.write_handle_ok);
    sayn("full.write.handle_null", rec_full.write_handle_null);
    sayn("full.write.data_ok", rec_full.write_data_ok);
    sayn("full.write.len", (long long) rec_full.write_len);

    rc = BIO_read(b, io_buf, 32);
    sayn("full.read.rc", rc);
    sayn("full.read.calls", rec_full.read_calls);
    sayn("full.read.handle_ok", rec_full.read_handle_ok);
    sayn("full.read.data_ok", rec_full.read_data_ok);
    sayn("full.read.len", (long long) rec_full.read_len);

    rc = BIO_gets(b, io_buf, 64);
    sayn("full.gets.rc", rc);
    sayn("full.gets.calls", rec_full.gets_calls);
    sayn("full.gets.handle_ok", rec_full.gets_handle_ok);
    sayn("full.gets.buf_ok", rec_full.gets_buf_ok);
    sayn("full.gets.size", rec_full.gets_size);

    rc = BIO_puts(b, io_str);
    sayn("full.puts.rc", rc);
    sayn("full.puts.calls", rec_full.puts_calls);
    sayn("full.puts.handle_ok", rec_full.puts_handle_ok);
    sayn("full.puts.str_ok", rec_full.puts_str_ok);

    ctrl_rc = BIO_ctrl(b, io_cmd, io_larg, io_ptr);
    sayn("full.ctrl.rc", ctrl_rc);
    sayn("full.ctrl.calls", rec_full.ctrl_calls);
    sayn("full.ctrl.handle_ok", rec_full.ctrl_handle_ok);
    sayn("full.ctrl.cmd", rec_full.ctrl_cmd);
    sayn("full.ctrl.num", rec_full.ctrl_num);
    sayn("full.ctrl.ptr_ok", rec_full.ctrl_ptr_ok);

    rc = BIO_free(b);
    sayn("full.free.rc", rc);
    sayn("full.free.calls", rec_full.free_calls);
    sayn("full.free.handle_ok", rec_full.free_handle_ok);
    sayn("full.free.handle_null", rec_full.free_handle_null);

    OSSL_LIB_CTX_free(ctx_full);

    /* --- 4. a write-only table: four of the five missing answers are `-1` --- */

    h_wonly = (const void *) (uintptr_t) 0x3000;
    ctx_wonly = OSSL_LIB_CTX_new_from_dispatch(NULL, table_wonly);
    sayp("wonly.ctx", ctx_wonly);
    b = BIO_new_from_core_bio(ctx_wonly, CBH(0x3000));
    sayp("wonly.bio", b);
    sayn("wonly.write.rc", BIO_write(b, io_buf, 32));
    sayn("wonly.read.rc", BIO_read(b, io_buf, 32));
    sayn("wonly.gets.rc", BIO_gets(b, io_buf, 64));
    sayn("wonly.puts.rc", BIO_puts(b, io_str));
    sayn("wonly.ctrl.rc", BIO_ctrl(b, io_cmd, io_larg, io_ptr));
    sayn("wonly.write.calls", rec_wonly.write_calls);
    /* The duplicated id's second entry, which the walk must leave unread. */
    sayn("wonly.second_entry.calls", rec_noup.write_calls);
    sayn("wonly.free.rc", BIO_free(b));
    sayn("wonly.free.calls", rec_wonly.free_calls);
    OSSL_LIB_CTX_free(ctx_wonly);

    /* --- 5. a read-only table: the write answer is `0`, not `-1` ---------- */

    h_ronly = (const void *) (uintptr_t) 0x3800;
    ctx_ronly = OSSL_LIB_CTX_new_from_dispatch(NULL, table_ronly);
    sayp("ronly.ctx", ctx_ronly);
    b = BIO_new_from_core_bio(ctx_ronly, CBH(0x3800));
    sayp("ronly.bio", b);
    sayn("ronly.read.rc", BIO_read(b, io_buf, 32));
    sayn("ronly.write.rc", BIO_write(b, io_buf, 32));
    sayn("ronly.gets.rc", BIO_gets(b, io_buf, 64));
    sayn("ronly.puts.rc", BIO_puts(b, io_str));
    sayn("ronly.ctrl.rc", BIO_ctrl(b, io_cmd, io_larg, io_ptr));
    sayn("ronly.read.calls", rec_ronly.read_calls);
    sayn("ronly.free.rc", BIO_free(b));
    sayn("ronly.free.calls", rec_ronly.free_calls);
    OSSL_LIB_CTX_free(ctx_ronly);

    /* --- 6. the up-ref refuses: the wrapper is released, the handle is not -- */

    h_noup = (const void *) (uintptr_t) 0x4000;
    ctx_noup = OSSL_LIB_CTX_new_from_dispatch(NULL, table_noup);
    sayp("noup.ctx", ctx_noup);
    sayp("noup.bio", BIO_new_from_core_bio(ctx_noup, CBH(0x4000)));
    sayn("noup.upref.calls", rec_noup.upref_calls);
    sayn("noup.upref.handle_ok", rec_noup.upref_handle_ok);
    /* The wrapper's own context is live, so its destroy ran; the BIO had no data
     * set yet, so the handle it forwards is NULL. The caller's handle is untouched
     * (it was never released through this channel). */
    sayn("noup.free.calls", rec_noup.free_calls);
    sayn("noup.free.handle_null", rec_noup.free_handle_null);
    OSSL_LIB_CTX_free(ctx_noup);

    /* --- 7. two contexts, two tables, and a lazily resolved NULL context --- */

    h_alpha = (const void *) (uintptr_t) 0x5000;
    h_beta = (const void *) (uintptr_t) 0x6000;
    ctx_a = OSSL_LIB_CTX_new_from_dispatch(NULL, table_alpha);
    ctx_b = OSSL_LIB_CTX_new_from_dispatch(NULL, table_beta);
    sayp("iso.ctx_a", ctx_a);
    sayp("iso.ctx_b", ctx_b);

    {
        BIO *bio_a = BIO_new_from_core_bio(ctx_a, CBH(0x5000));
        BIO *bio_b = BIO_new_from_core_bio(ctx_b, CBH(0x6000));
        BIO *lazy, *bio_n;
        sayp("iso.bio_a", bio_a);
        sayp("iso.bio_b", bio_b);

        /* The channel that ran is named by the answer: alpha answers 3, beta 6. */
        sayn("iso.write_a.rc", BIO_write(bio_a, io_buf, 32));
        sayn("iso.write_b.rc", BIO_write(bio_b, io_buf, 32));
        sayn("iso.alpha.calls", rec_alpha.write_calls);
        sayn("iso.beta.calls", rec_beta.write_calls);
        sayn("iso.alpha.handle_ok", rec_alpha.write_handle_ok);
        sayn("iso.beta.handle_ok", rec_beta.write_handle_ok);

        /* Created with no context, before any thread default is installed: no
         * callbacks are reachable yet, so the write answers 0. */
        lazy = BIO_new(BIO_s_core());
        sayp("lazy.bio", lazy);
        sayn("lazy.before.rc", BIO_write(lazy, io_buf, 32));
        sayn("lazy.before.alpha.calls", rec_alpha.write_calls);
        sayn("lazy.before.beta.calls", rec_beta.write_calls);

        prev = OSSL_LIB_CTX_set0_default(ctx_b);
        sayn("default.prev_is_global",
             prev == OSSL_LIB_CTX_get0_global_default());

        /* A NULL context now resolves through the thread default. */
        bio_n = BIO_new_from_core_bio(NULL, CBH(0x6000));
        sayp("default.null_bio", bio_n);
        sayn("default.null_write.rc", BIO_write(bio_n, io_buf, 32));
        sayn("default.beta.calls", rec_beta.write_calls);
        sayn("default.alpha.calls", rec_alpha.write_calls);

        /* The BIO made *before* the default was installed resolves it at use time
         * and now reaches beta, so its `libctx` was stored as the NULL it was
         * given rather than concretised at construction. */
        sayn("lazy.after.rc", BIO_write(lazy, io_buf, 32));
        sayn("lazy.after.beta.calls", rec_beta.write_calls);

        sayn("default.free_n.rc", BIO_free(bio_n));
        sayn("default.free_lazy.rc", BIO_free(lazy));
        sayn("default.beta.free.calls", rec_beta.free_calls);

        OSSL_LIB_CTX_set0_default(prev);

        sayn("iso.free_a.rc", BIO_free(bio_a));
        sayn("iso.free_b.rc", BIO_free(bio_b));
        sayn("iso.alpha.free.calls", rec_alpha.free_calls);
        sayn("iso.beta.free.calls", rec_beta.free_calls);
    }

    OSSL_LIB_CTX_free(ctx_a);
    OSSL_LIB_CTX_free(ctx_b);

    /* --- 8. a bare BIO on the method, on the default context --------------- *
     *
     * Last, because a BIO made with `BIO_new(BIO_s_core())` stores a NULL context
     * and therefore answers these through whatever this thread's default is at the
     * moment of the call. It is *not* freed: the default context has no `BIO_FREE`
     * callback and the authority's `bio_core_free` calls it unguarded.
     */
    {
        BIO *plain = BIO_new(BIO_s_core());
        sayp("plain.bio", plain);
        sayn("plain.init", BIO_get_init(plain));
        sayn("plain.write.rc", BIO_write(plain, io_buf, 32));
        sayn("plain.read.rc", BIO_read(plain, io_buf, 32));
        sayn("plain.gets.rc", BIO_gets(plain, io_buf, 64));
        sayn("plain.puts.rc", BIO_puts(plain, io_str));
        sayn("plain.ctrl.rc", BIO_ctrl(plain, io_cmd, io_larg, io_ptr));
    }

    return 0;
}
