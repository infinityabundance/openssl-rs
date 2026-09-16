/*
 * openssl-rs — RT-RUNTIME-EXT: the runtime exports that Phase 6.0's ownership
 * reconciliation found unaccounted for, and which Phase 6.2 implemented.
 *
 * What it compares, and why each one is here
 * -----------------------------------------
 *   * the `OSSL_trace_*` surface. The pinned profile defines `OPENSSL_NO_TRACE`,
 *     so eight of the ten answer a constant — but "answers a constant" is exactly
 *     the kind of claim that is cheap to get wrong in the direction nobody checks,
 *     and the two category interrogators plus `OSSL_trace_string` are fully live.
 *   * the `OSSL_ERR_STATE_*` save/restore round trip, observed through the public
 *     `ERR_*` queue rather than by reading the opaque structure: the only thing a
 *     caller can see is what comes back out.
 *   * `OSSL_sleep`, whose loop must not return early.
 *   * `OSSL_get_thread_support_flags`, a compile-time constant of the build.
 *   * `OPENSSL_isservice` / `OPENSSL_issetugid`, the two privilege predicates.
 *   * the three `OPENSSL_fork_*` hooks, which are empty on this profile.
 *   * `err_free_strings_int`, which is ABI-only — no installed header declares it,
 *     so the prototype below is the authority's own from `err_local.h`.
 *   * `OPENSSL_die`, via a forked child: it does not return, so its exit status and
 *     its stderr bytes are the observation.
 *
 * Every line is `key=value` and every value is a number, a hex string or a
 * bracketed literal, because the court diffs the two transcripts line by line.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <time.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/thread.h>
#include <openssl/trace.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

/* Declared in `crypto/err/err_local.h`, which is not installed: this symbol is in
 * the DSO's ABI but in no public header, which is why the Phase 1 completeness
 * work classified it `ABI_ONLY_EXPORTED`. */
void err_free_strings_int(void);

static void hexdump(const char *key, const unsigned char *p, int n)
{
    int i;
    printf("%s=", key);
    for (i = 0; i < n; i++)
        printf("%02x", p[i]);
    printf(" (len=%d)\n", n);
}

/* Capture whatever a BIO accumulated, without assuming it is a C string: the
 * bytes are the observation, and a NUL inside them must not truncate it. */
static void drain(const char *key, BIO *m)
{
    unsigned char buf[512];
    int n = BIO_read(m, buf, (int)sizeof(buf));
    if (n < 0)
        n = 0;
    hexdump(key, buf, n);
}

static void trace_category_plane(void)
{
    static const int nums[] = { -2, -1, 0, 1, 4, 11, 20, 21, 22 };
    static const char *names[] = {
        "ALL", "TRACE", "TLS_CIPHER", "X509V3_POLICY", "QUERY",
        "all", "tls_cipher", "X509v3_Policy", "query", "NOT_A_CATEGORY", ""
    };
    size_t i;

    for (i = 0; i < sizeof(nums) / sizeof(nums[0]); i++) {
        const char *n = OSSL_trace_get_category_name(nums[i]);
        printf("name[%d]=%s\n", nums[i], n == NULL ? "<NULL>" : n);
    }
    for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        printf("num[%s]=%d\n", names[i], OSSL_trace_get_category_num(names[i]));
    }
    printf("num[NULL]=%d\n", OSSL_trace_get_category_num(NULL));
}

static void trace_channel_plane(void)
{
    static const int cats[] = { -1, 0, 5, 20, 21 };
    size_t i;

    for (i = 0; i < sizeof(cats) / sizeof(cats[0]); i++) {
        int c = cats[i];
        printf("set_channel[%d]=%d\n", c, OSSL_trace_set_channel(c, NULL));
        printf("set_prefix[%d]=%d\n", c, OSSL_trace_set_prefix(c, "P"));
        printf("set_suffix[%d]=%d\n", c, OSSL_trace_set_suffix(c, "S"));
        printf("set_callback[%d]=%d\n", c, OSSL_trace_set_callback(c, NULL, NULL));
        printf("enabled[%d]=%d\n", c, OSSL_trace_enabled(c));
        {
            BIO *b = OSSL_trace_begin(c);
            printf("begin[%d]=%s\n", c, b == NULL ? "<NULL>" : "<BIO>");
            OSSL_trace_end(c, b);
        }
    }
    /* The callback argument's *value* is part of the call, even though the
     * profile's answer does not depend on it. */
    printf("set_callback_data=%d\n", OSSL_trace_set_callback(0, NULL, (void *)1));
}

static void trace_string_plane(void)
{
    static const unsigned char plain[] = "hello";
    static const unsigned char newline_ended[] = "hello\n";
    static const unsigned char controls[] = { 'a', 0x01, 0x7f, '\n', 'b', 0x80 };
    static const unsigned char embedded_nul[] = { 'a', 0x00, 'b' };
    unsigned char wide[96];
    BIO *m;

    memset(wide, 'x', sizeof(wide));

    m = BIO_new(BIO_s_mem());
    if (m == NULL) {
        printf("mem_bio=<NULL>\n");
        return;
    }

    printf("str_plain=%d\n", OSSL_trace_string(m, 1, 1, plain, 5));
    drain("str_plain_bytes", m);

    printf("str_text=%d\n", OSSL_trace_string(m, 1, 1, newline_ended, 6));
    drain("str_text_bytes", m);

    printf("str_mask=%d\n", OSSL_trace_string(m, 0, 1, controls, 6));
    drain("str_mask_bytes", m);

    printf("str_nul=%d\n", OSSL_trace_string(m, 1, 1, embedded_nul, 3));
    drain("str_nul_bytes", m);

    printf("str_zero=%d\n", OSSL_trace_string(m, 0, 1, plain, 0));
    drain("str_zero_bytes", m);

    /* `full == 0` with `size > 80` is the limited form: a prefix, then 80 bytes. */
    printf("str_limited=%d\n", OSSL_trace_string(m, 1, 0, wide, sizeof(wide)));
    drain("str_limited_bytes", m);

    /* `full == 0` with `size == 80` is *not* limited: the limit is `>`. */
    printf("str_exact80=%d\n", OSSL_trace_string(m, 1, 0, wide, 80));
    drain("str_exact80_bytes", m);

    BIO_free(m);
}

static void err_state_plane(void)
{
    ERR_STATE *es;
    unsigned long e;

    ERR_clear_error();
    ERR_raise_data(1, 100, "one");
    ERR_raise_data(1, 101, "two");
    ERR_raise_data(2, 200, "three");
    printf("queued=%d\n", ERR_peek_error() != 0);

    es = OSSL_ERR_STATE_new();
    printf("new_nonnull=%d\n", es != NULL);
    if (es == NULL)
        return;

    OSSL_ERR_STATE_save(es);
    /* The thread's queue is empty afterwards -- the whole point of save. */
    printf("after_save_peek=%lu\n", ERR_peek_error());
    printf("after_save_get=%lu\n", ERR_get_error());

    OSSL_ERR_STATE_restore(es);
    printf("restore1=%lu\n", ERR_get_error());
    printf("restore2=%lu\n", ERR_get_error());
    printf("restore3=%lu\n", ERR_get_error());
    printf("restore4=%lu\n", ERR_get_error());

    /* Restoring twice is legal, because restore copies rather than transfers. */
    OSSL_ERR_STATE_restore(es);
    printf("restore_twice=%lu\n", ERR_get_error());

    /* `save_to_mark` moves only what is above the mark. */
    ERR_clear_error();
    ERR_raise_data(1, 1, "below");
    ERR_set_mark();
    ERR_raise_data(1, 2, "above");
    ERR_raise_data(1, 3, "above2");
    OSSL_ERR_STATE_save_to_mark(es);
    printf("mark_below=%lu\n", ERR_peek_error());
    ERR_pop_to_mark();
    printf("mark_after_pop=%lu\n", ERR_peek_error());
    OSSL_ERR_STATE_restore(es);
    printf("mark_restored1=%lu\n", ERR_get_error());
    printf("mark_restored2=%lu\n", ERR_get_error());
    printf("mark_restored3=%lu\n", ERR_get_error());
    e = ERR_get_error();
    printf("mark_restored_empty=%d\n", e == 0);

    ERR_clear_error();
    OSSL_ERR_STATE_free(es);
    OSSL_ERR_STATE_free(NULL);
    printf("free_null=ok\n");
}

static void process_plane(void)
{
    printf("thread_support_flags=%u\n", OSSL_get_thread_support_flags());
    printf("isservice=%d\n", OPENSSL_isservice());
    printf("issetugid=%d\n", OPENSSL_issetugid());
    OPENSSL_fork_prepare();
    OPENSSL_fork_parent();
    OPENSSL_fork_child();
    printf("fork_hooks=returned\n");
    err_free_strings_int();
    printf("err_free_strings_int=returned\n");
    printf("peek_after_free_strings=%lu\n", ERR_peek_error());
}

static void sleep_plane(void)
{
    unsigned long t0, t1;

    t0 = (unsigned long)time(NULL);
    OSSL_sleep(0);
    t1 = (unsigned long)time(NULL);
    printf("sleep0_under_1s=%d\n", (t1 - t0) <= 1);

    t0 = (unsigned long)time(NULL);
    OSSL_sleep(1200);
    t1 = (unsigned long)time(NULL);
    /* The loop cannot return before the deadline, so this must hold. The upper
     * bound is deliberately loose; the exact overshoot is the scheduler's. */
    printf("sleep1200_ge_1s=%d\n", (t1 - t0) >= 1);
    printf("sleep1200_lt_10s=%d\n", (t1 - t0) < 10);
}

static void die_plane(void)
{
    int fds[2];
    pid_t pid;
    int status = 0;
    char buf[512];
    ssize_t n;

    if (pipe(fds) != 0) {
        printf("die_pipe=failed\n");
        return;
    }
    pid = fork();
    if (pid < 0) {
        printf("die_fork=failed\n");
        close(fds[0]);
        close(fds[1]);
        return;
    }
    if (pid == 0) {
        close(fds[0]);
        dup2(fds[1], 2);
        close(fds[1]);
        OPENSSL_die("the message", "the_file.c", 42);
        _exit(99); /* unreachable: OPENSSL_die does not return */
    }
    close(fds[1]);
    memset(buf, 0, sizeof(buf));
    n = read(fds[0], buf, sizeof(buf) - 1);
    close(fds[0]);
    waitpid(pid, &status, 0);
    if (n < 0)
        n = 0;
    if (WIFSIGNALED(status))
        printf("die_child=signal(%d)\n", WTERMSIG(status));
    else if (WIFEXITED(status))
        printf("die_child=exit(%d)\n", WEXITSTATUS(status));
    else
        printf("die_child=other\n");
    if (n > 0 && buf[n - 1] == '\n')
        buf[n - 1] = '\0';
    printf("die_stderr=%s\n", buf);
}

int main(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    trace_category_plane();
    trace_channel_plane();
    trace_string_plane();
    err_state_plane();
    process_plane();
    sleep_plane();
    die_plane();
    printf("done=1\n");
    return 0;
}
