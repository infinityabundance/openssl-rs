/*
 * openssl-rs — Phase 25 B67 negative control: the read-buffer BIO's discarded
 * write/puts slots.
 *
 * SCOPE. The B67 proof discharges `readbuffer_write` and `readbuffer_puts`
 * because their bodies ignore every argument, dereference nothing, touch no
 * global/thread state, and return the constant 0. This probe is the external
 * control for that claim: it reaches both slots through the *public* exports
 * (`BIO_new(BIO_f_readbuffer())`, `BIO_write`, `BIO_puts`) against the admitted
 * install, and checks that:
 *
 *   1. BIO_write and BIO_puts both return 0;
 *   2. the read buffer's tell/pending state is unchanged (`pending` is
 *      forwarded to the next BIO while `ibuf_len` is 0, so 4 is the expected
 *      pre/post value here); and
 *   3. the cached bytes are unchanged (a seek back to 0 re-reads the same data).
 *
 * A non-zero return, an advanced cache, or a changed cached byte falsifies the
 * proof. The probe is deliberately outside `src/`: the element-7 evidence is
 * bound to the current DSO, so no crate source is touched.
 *
 * Build (inside the court only):
 *   cc -std=c11 -O1 -Wall -Wextra \
 *      -I artifacts/phase2/install/include \
 *      -o court/tmp/closure-b67-bio/rt_bio_readbuffer_control \
 *      rt_bio_readbuffer_control.c \
 *      -L artifacts/phase2/install/lib -lcrypto \
 *      -Wl,-rpath,/work/artifacts/phase2/install/lib
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <openssl/bio.h>
#include <openssl/err.h>

#include <stdio.h>
#include <string.h>

#define SOURCE_BYTES "ABCDEFGH"

static int fail(const char *what, long got)
{
    fprintf(stderr, "FAIL %s (got %ld)\n", what, got);
    ERR_print_errors_fp(stderr);
    return 1;
}

int main(void)
{
    /* The source that the read buffer will cache. A memory BIO is writable, so
     * its own BIO_write is not the slot under test. */
    BIO *src = BIO_new(BIO_s_mem());
    BIO *rb;
    char buf[8];
    long tell_before, tell_after;
    long pending_before, pending_after;
    int n, w, p;

    if (src == NULL)
        return fail("BIO_new(BIO_s_mem())", -1);

    n = BIO_write(src, SOURCE_BYTES, (int)strlen(SOURCE_BYTES));
    if (n != (int)strlen(SOURCE_BYTES))
        return fail("seed BIO_write on the memory source", n);

    /* BIO_f_readbuffer() is an exported method (OPENSSL_3.0.0); it returns the
     * single static READBUFFER_METHOD whose bwrite_old/bputs slots are the two
     * operations under test. */
    rb = BIO_new(BIO_f_readbuffer());
    if (rb == NULL)
        return fail("BIO_new(BIO_f_readbuffer())", -1);

    /* Push makes `rb` the chain head; the filter creates its context in `create`. */
    if (BIO_push(rb, src) == NULL)
        return fail("BIO_push(readbuffer, mem)", -1);

    /* Read four bytes so the cache holds "ABCD" and the offset is 4. */
    n = BIO_read(rb, buf, 4);
    if (n != 4 || memcmp(buf, "ABCD", 4) != 0) {
        fprintf(stderr, "FAIL initial BIO_read (n=%d)\n", n);
        return 1;
    }

    tell_before = BIO_ctrl(rb, BIO_C_FILE_TELL, 0, NULL);
    pending_before = BIO_ctrl(rb, BIO_CTRL_PENDING, 0, NULL);
    if (tell_before != 4) {
        fprintf(stderr, "FAIL initial state (tell=%ld pending=%ld)\n",
                tell_before, pending_before);
        return 1;
    }

    /* The two slots under test. Both are reached through the exported API:
     * BIO_write -> bwrite_conv -> BioMethod::legacy_write -> readbuffer_write;
     * BIO_puts  -> method->bputs -> readbuffer_puts. */
    w = BIO_write(rb, "ZZ", 2);
    p = BIO_puts(rb, "ZZ");

    if (w != 0)
        return fail("BIO_write(readbuffer) must return 0", w);
    if (p != 0)
        return fail("BIO_puts(readbuffer) must return 0", p);

    tell_after = BIO_ctrl(rb, BIO_C_FILE_TELL, 0, NULL);
    pending_after = BIO_ctrl(rb, BIO_CTRL_PENDING, 0, NULL);
    if (tell_after != tell_before || pending_after != pending_before) {
        fprintf(stderr,
                "FAIL cache state changed (tell %ld->%ld, pending %ld->%ld)\n",
                tell_before, tell_after, pending_before, pending_after);
        return 1;
    }

    /* Seek back inside the cached range and re-read: the bytes must still be
     * the original source, not "ZZ" and not truncated. The readbuffer ctrl
     * refuses an out-of-range seek with 0 and succeeds with its default 1. */
    if (BIO_ctrl(rb, BIO_C_FILE_SEEK, 0, NULL) == 0)
        return fail("BIO_C_FILE_SEEK back to 0 was refused", 0);

    n = BIO_read(rb, buf, 4);
    if (n != 4 || memcmp(buf, "ABCD", 4) != 0) {
        fprintf(stderr, "FAIL cached bytes changed after write/puts (n=%d)\n", n);
        return 1;
    }

    /* The remainder must still come from the source. */
    n = BIO_read(rb, buf, 4);
    if (n != 4 || memcmp(buf, "EFGH", 4) != 0) {
        fprintf(stderr, "FAIL source remainder after write/puts (n=%d)\n", n);
        return 1;
    }

    BIO_free_all(rb);

    printf("PASS readbuffer write/puts: BIO_write=%d BIO_puts=%d "
           "tell_before=%ld tell_after=%ld pending_before=%ld pending_after=%ld "
           "cache_unchanged=1\n",
           w, p, tell_before, tell_after, pending_before, pending_after);
    return 0;
}
