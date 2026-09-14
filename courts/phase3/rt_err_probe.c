/*
 * openssl-rs — RT-ERR probe.
 *
 * One program, compiled against the authority and against the candidate and
 * diffed. The `ERR` queue is thread-local state that an application reads
 * directly, so almost nothing here can be reasoned out: the ring depth, which
 * slot is oldest, what a *partially written* slot looks like, which
 * out-parameters an early return leaves untouched, and the exact debug
 * coordinates a raise records all have to be measured.
 *
 * What this probe deliberately does NOT do:
 *   * it never prints a pointer value, because addresses are not contract;
 *   * it never asserts an internal allocation count;
 *   * it does not exercise `ERR_print_errors*` or `ERR_add_error_mem_bio`,
 *     which take a `BIO *` and belong to the BIO phase. They are scaffolded in
 *     the candidate and would abort; leaving them out keeps the court honest
 *     about what it covers.
 *
 * Determinism note: the probe must reach the same state in the same order on
 * both sides. Every section therefore starts with `ERR_clear_error()`.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/stack.h>

#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Exercising the deprecated entry points is deliberate. `OPENSSL_NO_DEPRECATED`
 * is not defined for the admitted profile, so 3.x still declares, exports and
 * honours them; their behaviour is part of the observed contract, and the
 * compile-time deprecation attribute is itself part of source compatibility
 * (checked by the Phase 2 header courts). Warning about the warning adds noise,
 * not evidence. */
#if defined(__clang__)
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif

/* Every (library, reason) pair the authority's tables define, and the generic
 * reasons, generated from the authority's own inputs. */
#include "rt_err_strings_cases.h"

static const char *show(const char *p)
{
    return p == NULL ? "(null)" : p;
}

static void print_error_tuple(const char *tag, unsigned long e)
{
    printf("%s.code=%lX\n", tag, e);
    printf("%s.lib=%s\n", tag, show(ERR_lib_error_string(e)));
    printf("%s.reason=%s\n", tag, show(ERR_reason_error_string(e)));
    printf("%s.func=%s\n", tag, show(ERR_func_error_string(e)));
}

static void drain(void)
{
    ERR_clear_error();
}

/* ------------------------------------------------------------------------- */
/* Thread-local isolation                                                    */
/* ------------------------------------------------------------------------- */

struct thread_result {
    unsigned long first;
    unsigned long second;
    int count;
};

static void *thread_body(void *arg)
{
    struct thread_result *r = arg;

    ERR_clear_error();
    ERR_new();
    ERR_set_debug("thread-file.c", 4242, "thread-func");
    ERR_set_error(15, 5001, NULL);
    ERR_new();
    ERR_set_debug("thread-file.c", 4243, "thread-func");
    ERR_set_error(15, 5002, NULL);

    r->first = ERR_peek_error();
    r->second = ERR_peek_last_error();
    r->count = 0;
    while (ERR_get_error() != 0)
        r->count++;
    return NULL;
}

/* ------------------------------------------------------------------------- */
/* Sections                                                                  */
/* ------------------------------------------------------------------------- */

static void basics(void)
{
    unsigned long e;

    drain();
    printf("empty.peek=%lu\n", ERR_peek_error());
    printf("empty.peek_last=%lu\n", ERR_peek_last_error());
    printf("empty.get=%lu\n", ERR_get_error());

    ERR_new();
    ERR_set_debug("hand-made.c", 7, "basics");
    ERR_set_error(15, 4242, NULL);
    e = ERR_peek_error();
    printf("one.peek=%lu\n", e);
    printf("one.peek_last_eq_peek=%d\n", ERR_peek_last_error() == e);
    print_error_tuple("one", e);
    printf("one.get=%lu\n", ERR_get_error());
    printf("one.after_get=%lu\n", ERR_peek_error());
}

static void ring_capacity(void)
{
    int i;
    int survivors = 0;
    unsigned long first_kept = 0;
    unsigned long last = 0;

    drain();
    for (i = 0; i < 20; i++) {
        ERR_new();
        ERR_set_debug("ring.c", 100 + i, "ring");
        ERR_set_error(15, 1000 + i, NULL);
    }
    first_kept = ERR_peek_error();
    last = ERR_peek_last_error();
    printf("ring.first_kept_reason=%lu\n", first_kept & 0x7FFFFF);
    printf("ring.last_reason=%lu\n", last & 0x7FFFFF);
    while (ERR_get_error() != 0)
        survivors++;
    printf("ring.survivors=%d\n", survivors);
    printf("ring.drained=%lu\n", ERR_peek_error());
}

static void incomplete_slot(void)
{
    unsigned long e;

    drain();
    /* `ERR_new` claims a slot but leaves `err_buffer` zero; until a library and
     * reason arrive the queue must not report it. */
    ERR_new();
    printf("incomplete.peek=%lu\n", ERR_peek_error());
    ERR_set_error(15, 777, NULL);
    e = ERR_peek_error();
    printf("incomplete.after_set=%lu\n", e);
    printf("incomplete.reason=%lu\n", e & 0x7FFFFF);
    /* A second `ERR_new` without a following `set_error` leaves the newest slot
     * incomplete while the older one stays readable as "last". */
    ERR_new();
    printf("incomplete.peek_last_after_new=%lu\n", ERR_peek_last_error());
    printf("incomplete.peek_after_new=%lu\n", ERR_peek_error());
    drain();
}

static void pop_and_marks(void)
{
    unsigned long e;

    drain();
    printf("pop.empty=%d\n", ERR_pop());
    ERR_new();
    ERR_set_error(15, 11, NULL);
    ERR_new();
    ERR_set_error(15, 22, NULL);
    ERR_new();
    ERR_set_error(15, 33, NULL);
    printf("pop.before=%d\n", ERR_count_to_mark());
    printf("pop.ret=%d\n", ERR_pop());
    printf("pop.after_last=%lu\n", ERR_peek_last_error() & 0x7FFFFF);
    printf("pop.count=%d\n", ERR_pop_to_mark());
    printf("pop.emptied=%lu\n", ERR_peek_error());
    printf("pop.pop_empty=%d\n", ERR_pop());

    drain();
    printf("mark.empty=%d\n", ERR_set_mark());
    printf("mark.empty_count=%d\n", ERR_count_to_mark());
    ERR_new();
    ERR_set_error(15, 1, NULL);
    printf("mark.one=%d\n", ERR_set_mark());
    ERR_new();
    ERR_set_error(15, 2, NULL);
    ERR_new();
    ERR_set_error(15, 3, NULL);
    printf("mark.count=%d\n", ERR_count_to_mark());
    printf("mark.pop_to=%d\n", ERR_pop_to_mark());
    e = ERR_peek_last_error();
    printf("mark.kept_reason=%lu\n", e & 0x7FFFFF);
    printf("mark.count_after=%d\n", ERR_count_to_mark());
    printf("mark.pop_to_again=%d\n", ERR_pop_to_mark());
    printf("mark.clear_last=%d\n", ERR_clear_last_mark());
    printf("mark.clear_last_empty=%d\n", ERR_clear_last_mark());
    drain();
}

static void get_and_peek_all(void)
{
    unsigned long e;
    const char *file = NULL, *func = NULL, *data = NULL;
    int line = 0, flags = 0;

    drain();
    ERR_new();
    ERR_set_debug("a-file.c", 11, "a-func");
    ERR_set_error(15, 41, "with data");
    e = ERR_peek_error_all(&file, &line, &func, &data, &flags);
    printf("all.code=%lX\n", e);
    printf("all.file=%s\n", show(file));
    printf("all.line=%d\n", line);
    printf("all.func=%s\n", show(func));
    printf("all.data=%s\n", show(data));
    printf("all.flags=%d\n", flags);

    /* No data: `data` reads as "" and `flags` is forced to 0. */
    file = func = data = NULL;
    line = 0;
    flags = 99;
    ERR_new();
    ERR_set_debug(NULL, 0, NULL);
    ERR_set_error(15, 42, NULL);
    e = ERR_peek_last_error_all(&file, &line, &func, &data, &flags);
    printf("nodata.code=%lX\n", e);
    printf("nodata.file_is_empty=%d\n", file != NULL && file[0] == '\0');
    printf("nodata.line=%d\n", line);
    printf("nodata.func_is_empty=%d\n", func != NULL && func[0] == '\0');
    printf("nodata.data_is_empty=%d\n", data != NULL && data[0] == '\0');
    printf("nodata.flags=%d\n", flags);

    /* `ERR_get_error_line_data` is the reading form of the same record. */
    drain();
    ERR_new();
    ERR_set_debug("b-file.c", 12, "b-func");
    ERR_set_error(15, 43, "payload");
    e = ERR_peek_error_line_data(&file, &line, &data, &flags);
    printf("pld.code=%lX\n", e);
    printf("pld.file=%s\n", show(file));
    printf("pld.line=%d\n", line);
    printf("pld.data=%s\n", show(data));
    printf("pld.flags=%d\n", flags);
    printf("pld.get=%lX\n", ERR_get_error_line_data(NULL, NULL, NULL, NULL));
    printf("pld.get_line=%lu\n", ERR_peek_error_line(&file, &line));

    /* The typed accessors each return the code and fill one out-parameter. */
    drain();
    ERR_new();
    ERR_set_debug("c-file.c", 13, "c-func");
    ERR_set_error(15, 44, "d");
    e = ERR_peek_error_func(&func);
    printf("acc.func_code=%lX\n", e);
    printf("acc.func=%s\n", show(func));
    e = ERR_peek_error_data(&data, &flags);
    printf("acc.data_code=%lX\n", e);
    printf("acc.data=%s\n", show(data));
    printf("acc.data_flags=%d\n", flags);
    e = ERR_peek_error_line(&file, &line);
    printf("acc.line_code=%lX\n", e);
    printf("acc.line=%d\n", line);
    printf("acc.file=%s\n", show(file));

    /* Reusing a slot that once held malloced data: `err_clear_data` with
     * `deall == 0` truncates the buffer and rewrites the flags, so whether a
     * clear leaves allocator state behind is observable. This sequence forces
     * the same slot to be reused by popping back onto it before raising again. */
    drain();
    ERR_new();
    ERR_set_error(15, 46, "first");
    e = ERR_peek_last_error_data(&data, &flags);
    printf("reuse.first_data=%s\n", show(data));
    printf("reuse.first_flags=%d\n", flags);
    printf("reuse.pop=%d\n", ERR_pop());
    ERR_new();
    ERR_set_error(15, 47, NULL);
    e = ERR_peek_last_error_data(&data, &flags);
    printf("reuse.second_code=%lX\n", e);
    printf("reuse.second_data=%s\n", show(data));
    printf("reuse.second_flags=%d\n", flags);

    /* A NULL message on a fresh slot leaves no data at all. */
    drain();
    ERR_new();
    ERR_set_error(15, 45, NULL);
    e = ERR_peek_last_error_data(&data, &flags);
    printf("nullmsg.code=%lX\n", e);
    printf("nullmsg.data=%s\n", show(data));
    printf("nullmsg.flags=%d\n", flags);
    drain();
}

static void codes(void)
{
    drain();
    printf("code.pack_15_1=%lX\n", ERR_PACK(15, 0, 1));
    printf("code.get_lib=%d\n", ERR_GET_LIB(ERR_PACK(15, 0, 1)));
    printf("code.get_reason=%d\n", ERR_GET_REASON(ERR_PACK(15, 0, 1)));
    printf("code.lib_offset_shift=%lX\n", ERR_PACK(1, 0, 0));
    printf("code.reason_mask=%lX\n", ERR_PACK(0, 0, 0xFFFFFF));
    printf("code.sys_flag=%d\n", ERR_SYSTEM_ERROR(ERR_PACK(15, 0, 1)));

    /* A system error keeps only the low bits, and reports as library 2. */
    ERR_new();
    ERR_set_error(ERR_LIB_SYS, 2 /* ENOENT */, NULL);
    {
        unsigned long e = ERR_peek_error();
        printf("code.sys_is_system=%d\n", ERR_SYSTEM_ERROR(e));
        printf("code.sys_lib=%d\n", ERR_GET_LIB(e));
        printf("code.sys_reason=%d\n", ERR_GET_REASON(e));
        printf("code.sys_reason_string=%s\n", show(ERR_reason_error_string(e)));
        /* `ossl_err_string_int` renders system errors through strerror_r
         * instead of the reason table, so the text is platform-dependent but
         * still identical on both sides of this court. */
        printf("code.sys_error_string=%s\n", ERR_error_string(e, NULL));
    }

    /* Reason flags round-trip and are visible through the accessors. */
    drain();
    {
        unsigned long e = ERR_PACK(15, 0, ERR_R_PASSED_NULL_PARAMETER);
        printf("code.flag_fatal=%d\n", ERR_FATAL_ERROR(e) != 0);
        printf("code.flag_common=%d\n", ERR_COMMON_ERROR(e) != 0);
        printf("code.flag_rflags=%X\n", ERR_GET_RFLAGS(e));
        ERR_new();
        ERR_set_error(15, ERR_R_PASSED_NULL_PARAMETER, NULL);
        printf("code.raised=%lX\n", ERR_peek_last_error());
        /* The numeric fallback strips the flag bits. */
        printf("code.fallback=%s\n", ERR_error_string(0x7F800001UL, NULL));
    }
    drain();
}

static void strings_exhaustive(void)
{
    unsigned i;
    int lib_hits = 0, reason_hits = 0, generic_hits = 0;

    printf("strings.per_library_cases=%d\n", ERR_CASE_COUNT);
    for (i = 0; i < (unsigned)ERR_CASE_COUNT; i++) {
        unsigned lib = ERR_CASES[i].lib;
        unsigned reason = ERR_CASES[i].reason;
        unsigned long e = ERR_PACK(lib, 0, reason);
        const char *ls = ERR_lib_error_string(e);
        const char *rs = ERR_reason_error_string(e);

        printf("lib.%u_%u=%s\n", lib, reason, show(ls));
        printf("reason.%u_%u=%s\n", lib, reason, show(rs));
        if (ls != NULL)
            lib_hits++;
        if (rs != NULL)
            reason_hits++;
    }
    printf("strings.lib_hits=%d\n", lib_hits);
    printf("strings.reason_hits=%d\n", reason_hits);

    printf("strings.generic_cases=%d\n", ERR_GENERIC_CASE_COUNT);
    for (i = 0; i < (unsigned)ERR_GENERIC_CASE_COUNT; i++) {
        unsigned reason = ERR_GENERIC_CASES[i].reason;
        unsigned long e = ERR_PACK(0, 0, reason);
        const char *rs = ERR_reason_error_string(e);
        printf("generic.%u=%s\n", reason, show(rs));
        if (rs != NULL)
            generic_hits++;
    }
    printf("strings.generic_hits=%d\n", generic_hits);

    /* Unknown values are NULL, and a system error is refused outright. */
    printf("strings.unknown_lib=%s\n", show(ERR_lib_error_string(ERR_PACK(255, 0, 0))));
    printf("strings.unknown_reason=%s\n", show(ERR_reason_error_string(ERR_PACK(63, 0, 65000))));
    printf("strings.system_reason=%s\n",
           show(ERR_reason_error_string(ERR_SYSTEM_ERROR(1UL) | 2UL)));
}

/* Libraries that ship a compiled reason table but are loaded by neither the
 * crypto step nor the SSL flag. The authority answers NULL for every one of
 * them, always. */
static void strings_unloaded_libraries(void)
{
    unsigned i;
    int nulls = 0;

    printf("unloaded.cases=%d\n", ERR_UNLOADED_CASE_COUNT);
    for (i = 0; i < (unsigned)ERR_UNLOADED_CASE_COUNT; i++) {
        unsigned lib = ERR_UNLOADED_CASES[i].lib;
        unsigned reason = ERR_UNLOADED_CASES[i].reason;
        const char *rs = ERR_reason_error_string(ERR_PACK(lib, 0, reason));
        printf("unloaded.%u_%u=%s\n", lib, reason, show(rs));
        if (rs == NULL)
            nulls++;
    }
    printf("unloaded.null_hits=%d\n", nulls);
}

/* The SSL reasons are the one table `err_all.c` deliberately does not load, so
 * they are observable as NULL until the flag is processed. */
static void strings_ssl_gating(void)
{
    unsigned i;
    int before = 0, after = 0;

    printf("ssl.cases=%d\n", ERR_SSL_CASE_COUNT);
    for (i = 0; i < (unsigned)ERR_SSL_CASE_COUNT; i++) {
        unsigned lib = ERR_SSL_CASES[i].lib;
        unsigned reason = ERR_SSL_CASES[i].reason;
        const char *rs = ERR_reason_error_string(ERR_PACK(lib, 0, reason));
        printf("ssl.before.%u_%u=%s\n", lib, reason, show(rs));
        if (rs != NULL)
            before++;
    }
    printf("ssl.before_hits=%d\n", before);

    /* 0x00200000 is `OPENSSL_INIT_LOAD_SSL_STRINGS` (from `ssl.h`). */
    printf("ssl.load_ret=%d\n", OPENSSL_init_crypto(0x00200000L, NULL));
    for (i = 0; i < (unsigned)ERR_SSL_CASE_COUNT; i++) {
        unsigned lib = ERR_SSL_CASES[i].lib;
        unsigned reason = ERR_SSL_CASES[i].reason;
        const char *rs = ERR_reason_error_string(ERR_PACK(lib, 0, reason));
        printf("ssl.after.%u_%u=%s\n", lib, reason, show(rs));
        if (rs != NULL)
            after++;
    }
    printf("ssl.after_hits=%d\n", after);
}

/* The registry is empty before the first ERR-state creation, so even a library
 * whose table is compiled in answers NULL. This must run BEFORE any call that
 * touches the error state. */
static void pre_state(void)
{
    printf("pre.libname=%s\n", show(ERR_lib_error_string(ERR_PACK(3, 0, 0))));
    printf("pre.reason=%s\n", show(ERR_reason_error_string(ERR_PACK(3, 0, 100))));
    printf("pre.generic=%s\n",
           show(ERR_reason_error_string(ERR_PACK(15, 0, ERR_R_PASSED_NULL_PARAMETER))));
    printf("pre.ssl=%s\n", show(ERR_reason_error_string(ERR_PACK(20, 0, 100))));
    printf("pre.error_string=%s\n",
           ERR_error_string(ERR_PACK(15, 0, ERR_R_PASSED_NULL_PARAMETER), NULL));
    printf("pre.peek=%lu\n", ERR_peek_error());
    printf("pre.libname_after=%s\n", show(ERR_lib_error_string(ERR_PACK(3, 0, 0))));
    printf("pre.error_string_after=%s\n",
           ERR_error_string(ERR_PACK(15, 0, ERR_R_PASSED_NULL_PARAMETER), NULL));
}

static void error_string_rendering(void)
{
    char buf[256];
    char small[16];
    unsigned long e = ERR_PACK(15, 0, ERR_R_PASSED_NULL_PARAMETER);

    memset(buf, 0, sizeof(buf));
    ERR_error_string_n(e, buf, sizeof(buf));
    printf("render.full=%s\n", buf);

    memset(buf, 0, sizeof(buf));
    ERR_error_string_n(e, buf, 0);
    printf("render.len_zero_first_byte=%d\n", buf[0]);

    /* The authority substitutes a compact form when the pretty form exactly
     * fills the buffer, so truncation is observable. */
    memset(small, 'X', sizeof(small));
    ERR_error_string_n(e, small, sizeof(small));
    printf("render.truncated=%s\n", small);

    memset(buf, 0, sizeof(buf));
    ERR_error_string_n(0x7F800001UL, buf, sizeof(buf));
    printf("render.numeric_fallback=%s\n", buf);

    /* A NULL buffer uses the authority's shared static, which is NOT
     * thread-local. Two successive calls with different codes therefore
     * overwrite each other; that is reproduced, not "fixed". */
    {
        const char *p1 = ERR_error_string(e, NULL);
        const char *p2 = ERR_error_string(0x7F800001UL, NULL);
        printf("render.null_buf_same_pointer=%d\n", p1 == p2);
        printf("render.null_buf_last=%s\n", show(p2));
    }
}

static void state_view(void)
{
    ERR_STATE *es;

    drain();
    es = ERR_get_state();
    printf("state.nonnull=%d\n", es != NULL);
    printf("state.top=%d\n", es->top);
    printf("state.bottom=%d\n", es->bottom);
    ERR_new();
    ERR_set_debug("d-file.c", 21, "d-func");
    ERR_set_error(15, 61, "data");
    es = ERR_get_state();
    printf("state.after.top=%d\n", es->top);
    printf("state.after.bottom=%d\n", es->bottom);
    printf("state.after.buffer=%lX\n", es->err_buffer[es->top]);
    printf("state.after.file=%s\n", show(es->err_file[es->top]));
    printf("state.after.line=%d\n", es->err_line[es->top]);
    printf("state.after.func=%s\n", show(es->err_func[es->top]));
    printf("state.after.data=%s\n", show(es->err_data[es->top]));
    printf("state.after.data_flags=%d\n", es->err_data_flags[es->top]);
    printf("state.after.marks=%d\n", es->err_marks[es->top]);
    drain();
    es = ERR_get_state();
    printf("state.cleared.buffer=%lX\n", es->err_buffer[es->top]);
}

static void next_error_library(void)
{
    printf("nextlib.first=%d\n", ERR_get_next_error_library());
    printf("nextlib.second=%d\n", ERR_get_next_error_library());
    printf("nextlib.third=%d\n", ERR_get_next_error_library());
}

static void raise_sites(void)
{
    OPENSSL_STACK *st = OPENSSL_sk_new_null();
    unsigned long e;
    const char *file = NULL, *func = NULL, *data = NULL;
    int line = 0, flags = 0;

    drain();
    /* `OPENSSL_sk_set(NULL, ...)` — ERR_R_PASSED_NULL_PARAMETER. */
    (void)OPENSSL_sk_set(NULL, 0, NULL);
    /* `OPENSSL_sk_set` out of range — ERR_R_PASSED_INVALID_ARGUMENT with the
     * index attached as data. */
    (void)OPENSSL_sk_set(st, 7, NULL);
    /* `OPENSSL_sk_reserve(NULL, ...)` — ERR_R_PASSED_NULL_PARAMETER. */
    (void)OPENSSL_sk_reserve(NULL, 4);
    /* `OPENSSL_sk_insert(NULL, ...)` — ERR_R_PASSED_NULL_PARAMETER. */
    (void)OPENSSL_sk_insert(NULL, (void *)1, 0);
    /* `sk_reserve` refusing an impossible request — CRYPTO_R_TOO_MANY_RECORDS.
     * The stack holds one element, so `INT_MAX > INT_MAX - 1` trips the bound
     * before any allocation is attempted. */
    (void)OPENSSL_sk_push(st, (void *)1);
    printf("raise.huge_reserve=%d\n", OPENSSL_sk_reserve(st, INT_MAX));

    while ((e = ERR_get_error_all(&file, &line, &func, &data, &flags)) != 0) {
        printf("site.%lX.file=%s\n", e, show(file));
        printf("site.%lX.line=%d\n", e, line);
        printf("site.%lX.func=%s\n", e, show(func));
        printf("site.%lX.data=%s\n", e, show(data));
        printf("site.%lX.flags=%d\n", e, flags);
    }
    printf("site.drained=%lu\n", ERR_peek_error());
    OPENSSL_sk_free(st);
}

static void stopped_state(void)
{
    /* Last, because it tears the library down. `OPENSSL_init_crypto` after
     * `OPENSSL_cleanup` is the authority's one reachable `ERR_R_INIT_FAIL`
     * raise, and it carries that raise's source coordinates. */
    OPENSSL_cleanup();
    printf("stopped.init_after_cleanup=%d\n", OPENSSL_init_crypto(0, NULL));
    {
        const char *file = NULL, *func = NULL;
        int line = 0;
        unsigned long e = ERR_peek_error_all(&file, &line, &func, NULL, NULL);
        printf("stopped.code=%lX\n", e);
        printf("stopped.file=%s\n", show(file));
        printf("stopped.line=%d\n", line);
        printf("stopped.func=%s\n", show(func));
        printf("stopped.base_only=%d\n", OPENSSL_init_crypto(0x00040000L /* OPENSSL_INIT_BASE_ONLY */, NULL));
        printf("stopped.err_after_base_only=%lX\n", ERR_peek_error());
    }
}

int main(void)
{
    pthread_t th;
    struct thread_result tr;
    unsigned long main_before, main_after;

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("probe.rt-err=1\n");

    pre_state();
    basics();
    ring_capacity();
    incomplete_slot();
    pop_and_marks();
    get_and_peek_all();
    codes();
    strings_exhaustive();
    strings_unloaded_libraries();
    strings_ssl_gating();
    error_string_rendering();
    state_view();
    next_error_library();
    raise_sites();

    /* Thread isolation: a second thread's queue is its own. */
    drain();
    ERR_new();
    ERR_set_error(15, 9001, NULL);
    main_before = ERR_peek_error();
    memset(&tr, 0, sizeof(tr));
    if (pthread_create(&th, NULL, thread_body, &tr) != 0) {
        printf("thread.spawn=FAILED\n");
    } else {
        pthread_join(th, NULL);
        printf("thread.first_reason=%lu\n", tr.first & 0x7FFFFF);
        printf("thread.second_reason=%lu\n", tr.second & 0x7FFFFF);
        printf("thread.drained_count=%d\n", tr.count);
    }
    main_after = ERR_peek_error();
    printf("thread.main_unchanged=%d\n", main_before == main_after);
    printf("thread.main_reason=%lu\n", main_after & 0x7FFFFF);
    drain();

    stopped_state();

    printf("done=1\n");
    return 0;
}
