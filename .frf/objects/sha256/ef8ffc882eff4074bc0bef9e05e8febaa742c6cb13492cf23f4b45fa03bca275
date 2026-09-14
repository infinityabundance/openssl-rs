/*
 * openssl-rs — RT-BIO-PAIR: the in-process BIO pair.
 *
 * A BIO pair is two ring buffers wired back to back, and almost all of its
 * contract is the **retry protocol** rather than the bytes. The probe therefore
 * records, after each operation, the return value, the retry flags, the two
 * pending counts, the read request the peer recorded, and the error queue. The
 * explicit small buffers (`BIO_new_bio_pair(&a, 8, &b, 8)`) are what make the
 * full-buffer and wrap cases reachable in a few operations instead of 17 KiB.
 *
 * The wrap case is driven deliberately: write 6, read 4, write 6 again, so the
 * write head passes the end of the ring and the copy has to split. A pair
 * implemented with a flat buffer and a memmove would give the same bytes for the
 * first two steps and differ on the third.
 *
 * Determinism: only lengths, bytes and predicates are printed; no pointers and no
 * descriptor numbers appear, so two processes produce the same transcript.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

static void err_all(const char *key)
{
    char k[96];
    int n = 0;

    for (;;) {
        const char *file = NULL, *data = NULL;
        int line = 0, flags = 0;
        unsigned long e = ERR_get_error_line_data(&file, &line, &data, &flags);

        if (e == 0)
            break;
        snprintf(k, sizeof(k), "%s.%d.code", key, n);
        printf("%s=%lu\n", k, e);
        snprintf(k, sizeof(k), "%s.%d.line", key, n);
        printf("%s=%d\n", k, line);
        snprintf(k, sizeof(k), "%s.%d.data", key, n);
        printf("%s=%s\n", k, data ? data : "<NULL>");
        if (++n > 4)
            break;
    }
    snprintf(k, sizeof(k), "%s.count", key);
    printf("%s=%d\n", k, n);
    ERR_clear_error();
}

/* The state a caller can see, without touching the private structure. */
static void state(const char *key, BIO *a, BIO *b)
{
    char k[96];

    snprintf(k, sizeof(k), "%s.a.pending", key);
    printf("%s=%ld\n", k, BIO_ctrl(a, BIO_CTRL_PENDING, 0, NULL));
    snprintf(k, sizeof(k), "%s.a.wpending", key);
    printf("%s=%ld\n", k, BIO_ctrl(a, BIO_CTRL_WPENDING, 0, NULL));
    snprintf(k, sizeof(k), "%s.a.eof", key);
    printf("%s=%ld\n", k, BIO_ctrl(a, BIO_CTRL_EOF, 0, NULL));
    snprintf(k, sizeof(k), "%s.b.pending", key);
    printf("%s=%ld\n", k, BIO_ctrl(b, BIO_CTRL_PENDING, 0, NULL));
    snprintf(k, sizeof(k), "%s.b.wpending", key);
    printf("%s=%ld\n", k, BIO_ctrl(b, BIO_CTRL_WPENDING, 0, NULL));
    snprintf(k, sizeof(k), "%s.b.eof", key);
    printf("%s=%ld\n", k, BIO_ctrl(b, BIO_CTRL_EOF, 0, NULL));
}

int main(void)
{
    char buf[64];

    setvbuf(stdout, NULL, _IONBF, 0);

    /* --- the method and a default pair ---------------------------------- */
    {
        BIO *a = NULL, *b = NULL;

        printf("s.bio.name=%s\n", BIO_method_name(BIO_new(BIO_s_bio())));
        printf("s.bio.type=%d\n", BIO_method_type(BIO_new(BIO_s_bio())));

        ERR_clear_error();
        printf("pair.make=%d\n", BIO_new_bio_pair(&a, 0, &b, 0));
        printf("pair.a.nonnull=%d\n", a != NULL);
        printf("pair.b.nonnull=%d\n", b != NULL);
        printf("pair.a.init=%d\n", BIO_get_init(a));
        printf("pair.b.init=%d\n", BIO_get_init(b));
        printf("pair.a.bufsize=%ld\n", BIO_ctrl(a, BIO_C_GET_WRITE_BUF_SIZE, 0, NULL));
        printf("pair.b.bufsize=%ld\n", BIO_ctrl(b, BIO_C_GET_WRITE_BUF_SIZE, 0, NULL));
        printf("pair.a.guarantee=%ld\n", BIO_ctrl(a, BIO_C_GET_WRITE_GUARANTEE, 0, NULL));
        printf("pair.a.readrequest=%ld\n", BIO_ctrl(a, BIO_C_GET_READ_REQUEST, 0, NULL));
        state("pair.empty", a, b);

        /* An empty read is retriable, and records the request on the peer. */
        memset(buf, 0, sizeof(buf));
        ERR_clear_error();
        printf("pair.read.empty=%d\n", BIO_read(b, buf, 32));
        printf("pair.read.empty.shouldretry=%d\n", BIO_should_retry(b));
        printf("pair.read.empty.shouldread=%d\n", BIO_should_read(b));
        printf("pair.read.empty.request=%ld\n", BIO_ctrl(a, BIO_C_GET_READ_REQUEST, 0, NULL));
        err_all("pair.read.empty");

        /* The clamp: a read larger than the peer's buffer records the buffer size. */
        memset(buf, 0, sizeof(buf));
        printf("pair.read.huge=%d\n", BIO_read(b, buf, 100000));
        printf("pair.read.huge.request=%ld\n", BIO_ctrl(a, BIO_C_GET_READ_REQUEST, 0, NULL));
        printf("pair.reset.request=%d\n", BIO_ctrl_reset_read_request(a));
        printf("pair.reset.request.after=%ld\n", BIO_ctrl(a, BIO_C_GET_READ_REQUEST, 0, NULL));

        /* Writing then reading moves bytes the other way. */
        printf("pair.write=%d\n", BIO_write(a, "hello", 5));
        printf("pair.write.wpending=%ld\n", BIO_ctrl(a, BIO_CTRL_WPENDING, 0, NULL));
        printf("pair.write.pending=%ld\n", BIO_ctrl(b, BIO_CTRL_PENDING, 0, NULL));
        printf("pair.write.shouldretry=%d\n", BIO_should_retry(a));
        memset(buf, 0, sizeof(buf));
        printf("pair.read=%d\n", BIO_read(b, buf, 5));
        printf("pair.read.data=%s\n", buf);
        printf("pair.read.wpending=%ld\n", BIO_ctrl(a, BIO_CTRL_WPENDING, 0, NULL));

        /* Two ways to tear one down: the control, and just freeing them. */
        printf("pair.destroy=%d\n", BIO_ctrl(a, BIO_C_DESTROY_BIO_PAIR, 0, NULL));
        printf("pair.destroy.a.init=%d\n", BIO_get_init(a));
        printf("pair.destroy.b.init=%d\n", BIO_get_init(b));
        printf("pair.destroy.a.pending=%ld\n", BIO_ctrl(a, BIO_CTRL_PENDING, 0, NULL));
        printf("pair.free.a=%d\n", BIO_free(a));
        printf("pair.free.b=%d\n", BIO_free(b));
    }

    /* --- small buffers: full, and the ring wrap ------------------------- */
    {
        BIO *a = NULL, *b = NULL;
        char out[32];

        printf("small.make=%d\n", BIO_new_bio_pair(&a, 8, &b, 8));
        printf("small.a.bufsize=%ld\n", BIO_ctrl(a, BIO_C_GET_WRITE_BUF_SIZE, 0, NULL));
        printf("small.b.bufsize=%ld\n", BIO_ctrl(b, BIO_C_GET_WRITE_BUF_SIZE, 0, NULL));
        printf("small.a.guarantee=%ld\n", BIO_ctrl(a, BIO_C_GET_WRITE_GUARANTEE, 0, NULL));

        /* Filling the 8-byte buffer exactly, then one more. */
        printf("small.write8=%d\n", BIO_write(a, "abcdefgh", 8));
        printf("small.a.wpending=%ld\n", BIO_ctrl(a, BIO_CTRL_WPENDING, 0, NULL));
        printf("small.a.guarantee.full=%ld\n", BIO_ctrl(a, BIO_C_GET_WRITE_GUARANTEE, 0, NULL));
        ERR_clear_error();
        printf("small.write.overflow=%d\n", BIO_write(a, "i", 1));
        printf("small.overflow.shouldretry=%d\n", BIO_should_retry(a));
        printf("small.overflow.shouldwrite=%d\n", BIO_should_write(a));
        err_all("small.overflow");

        /* Now free 4 bytes and write 6: the write head has to wrap. */
        memset(out, 0, sizeof(out));
        printf("small.read4=%d\n", BIO_read(b, out, 4));
        printf("small.read4.data=%.4s\n", out);
        printf("small.a.wpending.after=%ld\n", BIO_ctrl(a, BIO_CTRL_WPENDING, 0, NULL));
        printf("small.write6=%d\n", BIO_write(a, "ijklmn", 6));
        printf("small.a.wpending.wrapped=%ld\n", BIO_ctrl(a, BIO_CTRL_WPENDING, 0, NULL));
        printf("small.b.pending.wrapped=%ld\n", BIO_ctrl(b, BIO_CTRL_PENDING, 0, NULL));

        /* Read it all back: the order must be efgh + ijklmn. */
        memset(out, 0, sizeof(out));
        printf("small.readall=%d\n", BIO_read(b, out, 10));
        printf("small.readall.data=%.10s\n", out);
        printf("small.a.wpending.end=%ld\n", BIO_ctrl(a, BIO_CTRL_WPENDING, 0, NULL));

        BIO_free(a);
        BIO_free(b);
    }

    /* --- shutdown of the write side ------------------------------------- */
    {
        BIO *a = NULL, *b = NULL;
        char out[32];

        printf("shut.make=%d\n", BIO_new_bio_pair(&a, 16, &b, 16));
        printf("shut.write=%d\n", BIO_write(a, "xy", 2));
        printf("shut.shutdown=%d\n", BIO_ctrl(a, BIO_C_SHUTDOWN_WR, 0, NULL));
        printf("shut.a.eof=%ld\n", BIO_ctrl(a, BIO_CTRL_EOF, 0, NULL));
        printf("shut.b.eof=%ld\n", BIO_ctrl(b, BIO_CTRL_EOF, 0, NULL));

        memset(out, 0, sizeof(out));
        printf("shut.read=%d\n", BIO_read(b, out, 2));
        printf("shut.read.data=%s\n", out);
        printf("shut.b.eof.after=%ld\n", BIO_ctrl(b, BIO_CTRL_EOF, 0, NULL));
        /* A read on a closed and empty peer is 0, not -1 and not an error. */
        ERR_clear_error();
        memset(out, 0, sizeof(out));
        printf("shut.read.closed=%d\n", BIO_read(b, out, 2));
        printf("shut.read.closed.shouldretry=%d\n", BIO_should_retry(b));
        err_all("shut.read.closed");
        /* A write after our peer closed raises. */
        ERR_clear_error();
        printf("shut.write.closed=%d\n", BIO_write(a, "z", 1));
        err_all("shut.write.closed");
        printf("shut.a.guarantee=%ld\n", BIO_ctrl(a, BIO_C_GET_WRITE_GUARANTEE, 0, NULL));

        BIO_free(a);
        BIO_free(b);
    }

    /* --- the non-copying interface -------------------------------------- */
    {
        BIO *a = NULL, *b = NULL;
        char *p = NULL;
        long n;

        printf("nc.make=%d\n", BIO_new_bio_pair(&a, 16, &b, 16));
        printf("nc.nwrite0=%d\n", BIO_nwrite0(a, &p));
        printf("nc.nwrite0.ptr=%d\n", p != NULL);
        if (p != NULL) {
            memcpy(p, "1234567890", 10);
        }
        printf("nc.nwrite=%d\n", BIO_nwrite(a, &p, 10));
        printf("nc.a.wpending=%ld\n", BIO_ctrl(a, BIO_CTRL_WPENDING, 0, NULL));
        printf("nc.nread0=%d\n", BIO_nread0(b, &p));
        printf("nc.nread0.data=%.10s\n", p ? p : "");
        n = BIO_nread(b, &p, 4);
        printf("nc.nread=%ld\n", n);
        printf("nc.b.pending.after=%ld\n", BIO_ctrl(b, BIO_CTRL_PENDING, 0, NULL));
        printf("nc.nread0.rest=%d\n", BIO_nread0(b, &p));
        printf("nc.nread.rest=%ld\n", BIO_nread(b, &p, 6));
        printf("nc.b.pending.end=%ld\n", BIO_ctrl(b, BIO_CTRL_PENDING, 0, NULL));
        printf("nc.nread0.empty=%d\n", BIO_nread0(b, &p));

        BIO_free(a);
        BIO_free(b);
    }

    /* --- the controls that refuse --------------------------------------- */
    {
        BIO *a = NULL, *b = NULL;
        BIO *raw = BIO_new(BIO_s_bio());

        printf("ctl.make=%d\n", BIO_new_bio_pair(&a, 16, &b, 16));
        ERR_clear_error();
        printf("ctl.setbuf.inuse=%ld\n",
               BIO_ctrl(a, BIO_C_SET_WRITE_BUF_SIZE, 32, NULL));
        err_all("ctl.setbuf.inuse");
        ERR_clear_error();
        printf("ctl.setbuf.zero=%ld\n",
               BIO_ctrl(raw, BIO_C_SET_WRITE_BUF_SIZE, 0, NULL));
        err_all("ctl.setbuf.zero");
        printf("ctl.setbuf.ok=%ld\n",
               BIO_ctrl(raw, BIO_C_SET_WRITE_BUF_SIZE, 64, NULL));
        printf("ctl.setbuf.size=%ld\n", BIO_ctrl(raw, BIO_C_GET_WRITE_BUF_SIZE, 0, NULL));

        /* An unpaired BIO is not initialised until it is paired. */
        printf("ctl.raw.init=%d\n", BIO_get_init(raw));
        printf("ctl.raw.read=%d\n", BIO_read(raw, buf, 4));
        printf("ctl.raw.write=%d\n", BIO_write(raw, "x", 1));
        printf("ctl.raw.eof=%ld\n", BIO_ctrl(raw, BIO_CTRL_EOF, 0, NULL));
        printf("ctl.raw.pending=%ld\n", BIO_ctrl(raw, BIO_CTRL_PENDING, 0, NULL));
        printf("ctl.raw.wpending=%ld\n", BIO_ctrl(raw, BIO_CTRL_WPENDING, 0, NULL));
        printf("ctl.raw.flush=%ld\n", BIO_ctrl(raw, BIO_CTRL_FLUSH, 0, NULL));
        printf("ctl.raw.unknown=%ld\n", BIO_ctrl(raw, 999, 0, NULL));

        BIO_free(raw);
        BIO_free(a);
        BIO_free(b);
    }

    ERR_clear_error();
    printf("err.final=%lu\n", ERR_peek_error());
    ERR_clear_error();
    return 0;
}
