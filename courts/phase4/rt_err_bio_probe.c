/*
 * openssl-rs — Phase 4 court: the ERR printing surface, differentially.
 *
 * Covers the four exports that were handed from Phase 3 to this stratum because
 * they need a BIO: ERR_print_errors, ERR_print_errors_cb, ERR_print_errors_fp and
 * ERR_add_error_mem_bio.
 *
 * Two deliberate normalisations, both recorded rather than hidden:
 *
 *   * the first field of every printed line is the *thread id*, which is a
 *     per-process value and therefore legitimately differs between the two runs.
 *     `emit_stripped` replaces it with its length and keeps everything after it,
 *     so the error string, file, line and data are still compared exactly.
 *   * an error's `file`/`line`/`func` are supplied explicitly by this probe rather
 *     than inherited from a raise site, so both runs print identical coordinates
 *     and the comparison is about the *printing*, not about which source line the
 *     probe called `ERR_set_debug` from.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/err.h>

/* Emit a multi-line report as one observation. */
static void emit(const char *key, const char *s)
{
    printf("%s=[", key);
    for (; *s != '\0'; s++)
        putchar(*s == '\n' ? '|' : *s);
    printf("]\n");
}

/*
 * As `emit`, but with the leading thread-id field of EVERY line replaced by its
 * length. The id is `pthread_self()` in the authority and a per-process value in
 * both builds, so comparing it would measure the process, not the implementation.
 * A multi-error report has one such field per line, so the substitution is applied
 * per line rather than only to the first.
 */
static void emit_stripped(const char *key, const char *s)
{
    printf("%s=[", key);
    while (*s != '\0') {
        const char *eol = strchr(s, '\n');
        const char *colon = strchr(s, ':');

        if (colon == NULL || (eol != NULL && colon > eol)) {
            /* No thread-id field on this line; print it unchanged. */
            const char *p = s;

            for (; *p != '\0' && *p != '\n'; p++)
                putchar(*p);
            if (*p == '\n') {
                putchar('|');
                s = p + 1;
            } else {
                break;
            }
            continue;
        }
        printf("tid_hex_len=%d", (int)(colon - s));
        /* Skip the id itself: the placeholder replaces it, it does not precede it. */
        s = colon;
        for (; *s != '\0' && *s != '\n'; s++)
            putchar(*s);
        if (*s == '\n') {
            putchar('|');
            s++;
        }
    }
    printf("]\n");
}

static void raise_error(int with_data)
{
    ERR_new();
    ERR_set_debug("/probe/err-bio.c", 42, "probe_raise");
    if (with_data)
        ERR_set_error(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR, "%s", "detail-text");
    else
        ERR_set_error(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR, NULL);
}

static int cb_calls;
static size_t cb_used;
static char cb_buf[8192];

static int collect_cb(const char *str, size_t len, void *u)
{
    (void)u;
    cb_calls++;
    if (cb_used + len < sizeof(cb_buf)) {
        memcpy(cb_buf + cb_used, str, len);
        cb_used += len;
        cb_buf[cb_used] = '\0';
    }
    /* Returning a positive value continues the report. */
    return 1;
}

static int abort_cb(const char *str, size_t len, void *u)
{
    int *n = u;

    (void)str;
    (void)len;
    (*n)++;
    return 0; /* stop, and leave the rest on the queue */
}

int main(void)
{
    BIO *b;
    char *filebuf = NULL;
    size_t filelen = 0;
    FILE *f;

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("probe.rt-err-bio=1\n");

    /* ---- an empty queue prints nothing ------------------------------------- */
    ERR_clear_error();
    b = BIO_new(BIO_s_mem());
    ERR_print_errors(b);
    printf("empty.pending=%d\n", (int)BIO_ctrl_pending(b));

    /* ---- two errors, one with data and one without ------------------------- */
    raise_error(0);
    raise_error(1);
    ERR_print_errors(b);
    {
        char buf[8192];
        int n = BIO_read(b, buf, (int)sizeof(buf) - 1);

        if (n < 0)
            n = 0;
        buf[n] = '\0';
        emit_stripped("print.errors", buf);
    }
    /* The report drains the queue it printed. */
    printf("print.errors.queue_empty=%d\n", ERR_peek_error() == 0);
    BIO_free(b);

    /* ---- ERR_print_errors_cb: collect, then abort -------------------------- */
    b = BIO_new(BIO_s_mem());
    raise_error(1);
    raise_error(1);
    cb_calls = 0;
    cb_used = 0;
    cb_buf[0] = '\0';
    ERR_print_errors_cb(collect_cb, (void *)(intptr_t)0);
    printf("cb.calls=%d\n", cb_calls);
    emit_stripped("cb.output", cb_buf);
    printf("cb.queue_empty=%d\n", ERR_peek_error() == 0);

    /* A callback that aborts leaves the remaining errors queued. */
    raise_error(1);
    raise_error(1);
    cb_calls = 0;
    ERR_print_errors_cb(abort_cb, &cb_calls);
    printf("cb.abort.calls=%d\n", cb_calls);
    printf("cb.abort.still_queued=%d\n", ERR_peek_error() != 0);
    ERR_clear_error();

    /* A NULL callback is accepted and does nothing. */
    ERR_print_errors_cb(NULL, NULL);
    printf("cb.null_survived=1\n");

    /* ---- ERR_print_errors_fp through an in-memory stream ------------------- */
    raise_error(1);
    f = open_memstream(&filebuf, &filelen);
    ERR_print_errors_fp(f);
    ERR_print_errors_fp(NULL);
    fclose(f);
    emit_stripped("print.fp", filebuf == NULL ? "" : filebuf);
    printf("print.fp.queue_empty=%d\n", ERR_peek_error() == 0);
    free(filebuf);
    BIO_free(b);

    /* ---- ERR_add_error_mem_bio -------------------------------------------- */
    {
        static const char *cases[] = {
            "ab",          /* two bytes: appended */
            "x",           /* one byte: treated as empty, so nothing is added */
            "tail-no-nul", /* no terminator: one is written first */
            "",            /* empty */
        };
        size_t c;

        for (c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
            BIO *m = BIO_new(BIO_s_mem());
            const char *sep = (c == 1) ? NULL : " | ";
            char key[64];

            ERR_clear_error();
            raise_error(0);
            BIO_write(m, cases[c], (int)strlen(cases[c]));
            ERR_add_error_mem_bio(sep, m);

            snprintf(key, sizeof(key), "add_mem_bio.case%zu", c);
            {
                const char *data = NULL;
                unsigned long e = ERR_peek_error_all(NULL, NULL, NULL, &data, NULL);

                if (e == 0)
                    printf("%s=<no-error>\n", key);
                else
                    printf("%s=%s\n", key, data == NULL ? "<null>" : data);
            }
            BIO_free(m);
        }

        /* A NULL BIO adds nothing and must not crash. */
        ERR_clear_error();
        raise_error(0);
        ERR_add_error_mem_bio(",", NULL);
        printf("add_mem_bio.null_bio=1\n");
        ERR_clear_error();
    }

    printf("\n# end\n");
    return 0;
}
