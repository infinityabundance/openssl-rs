/*
 * openssl-rs — RT-BIO-DGRAM-PAIR: the in-memory datagram pair and its
 * single-ended sibling `BIO_s_dgram_mem`.
 *
 * Unlike `BIO_s_bio`, this pair preserves **datagram boundaries**: every write
 * lands as one datagram with a header, and every read returns exactly one
 * datagram (or fails). That makes the interesting observations the ones about
 * framing rather than about bytes:
 *
 *   * two writes then one large read returns only the first datagram;
 *   * a read with a smaller buffer than the datagram returns the truncated
 *     prefix, and the rest is discarded — unless `BIO_CTRL_DGRAM_SET_NO_TRUNC`
 *     is set, in which case the read fails and *nothing* is consumed;
 *   * a failed write (ring buffer too small) rolls the buffer back, so the next
 *     read sees the previous datagram and not a half-written one;
 *   * `BIO_CTRL_PENDING` reports the length of the **next datagram**, not the
 *     number of bytes buffered;
 *   * `BIO_CTRL_DGRAM_GET_WRITE_GUARANTEE` reports zero rather than a small
 *     number when the free space cannot hold a worst-case datagram.
 *
 * All numbers printed are lengths, sizes and small integers; no pointers and no
 * addresses appear, so two processes produce the same transcript.
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
        if (++n > 4)
            break;
    }
    snprintf(k, sizeof(k), "%s.count", key);
    printf("%s=%d\n", k, n);
    ERR_clear_error();
}

int main(void)
{
    char buf[256];

    setvbuf(stdout, NULL, _IONBF, 0);

    /* --- the method tables ----------------------------------------------- */
    {
        BIO *a = BIO_new(BIO_s_dgram_pair());
        BIO *b = BIO_new(BIO_s_dgram_mem());

        printf("dgrampair.name=%s\n", BIO_method_name(a));
        printf("dgrampair.type=%d\n", BIO_method_type(a));
        printf("dgrammem.name=%s\n", BIO_method_name(b));
        printf("dgrammem.type=%d\n", BIO_method_type(b));
        printf("dgrampair.init=%d\n", BIO_get_init(a));
        printf("dgrammem.init=%d\n", BIO_get_init(b));
        BIO_free(a);
        BIO_free(b);
    }

    /* --- the default sizes a fresh pair reports --------------------------- */
    {
        BIO *a = BIO_new(BIO_s_dgram_pair());
        BIO *m = BIO_new(BIO_s_dgram_mem());

        printf("fresh.pair.bufsize=%ld\n", BIO_ctrl(a, BIO_C_GET_WRITE_BUF_SIZE, 0, NULL));
        printf("fresh.mem.bufsize=%ld\n", BIO_ctrl(m, BIO_C_GET_WRITE_BUF_SIZE, 0, NULL));
        printf("fresh.pair.mtu=%ld\n", BIO_ctrl(a, BIO_CTRL_DGRAM_GET_MTU, 0, NULL));
        printf("fresh.mem.mtu=%ld\n", BIO_ctrl(m, BIO_CTRL_DGRAM_GET_MTU, 0, NULL));
        printf("fresh.pair.eof=%ld\n", BIO_ctrl(a, BIO_CTRL_EOF, 0, NULL));
        printf("fresh.mem.eof=%ld\n", BIO_ctrl(m, BIO_CTRL_EOF, 0, NULL));
        printf("fresh.pair.pending=%ld\n", BIO_ctrl(a, BIO_CTRL_PENDING, 0, NULL));
        printf("fresh.mem.pending=%ld\n", BIO_ctrl(m, BIO_CTRL_PENDING, 0, NULL));
        printf("fresh.pair.guarantee=%ld\n", BIO_get_write_guarantee(a));
        printf("fresh.mem.guarantee=%ld\n", BIO_get_write_guarantee(m));
        printf("fresh.pair.no_trunc=%ld\n",
               BIO_ctrl(a, BIO_CTRL_DGRAM_GET_NO_TRUNC, 0, NULL));
        printf("fresh.pair.caps=%ld\n", BIO_ctrl(a, BIO_CTRL_DGRAM_GET_CAPS, 0, NULL));
        printf("fresh.pair.locaddr_cap=%ld\n",
               BIO_ctrl(a, BIO_CTRL_DGRAM_GET_LOCAL_ADDR_CAP, 0, NULL));
        {
            /* This one control reports through its pointer, not its return. */
            int enable = -1;
            printf("fresh.pair.locaddr_enable.ret=%ld\n",
                   BIO_ctrl(a, BIO_CTRL_DGRAM_GET_LOCAL_ADDR_ENABLE, 0, &enable));
            printf("fresh.pair.locaddr_enable.value=%d\n", enable);
        }
        ERR_clear_error();
        printf("fresh.err0=%lu\n", ERR_peek_error());
        ERR_clear_error();
        BIO_free(a);
        BIO_free(m);
    }

    /* --- a pair made with explicit buffer sizes --------------------------- */
    {
        BIO *a = NULL, *b = NULL;
        int r;

        ERR_clear_error();
        r = BIO_new_bio_dgram_pair(&a, 0, &b, 0);
        printf("make.default=%d\n", r);
        printf("make.default.a.bufsize=%ld\n", BIO_ctrl(a, BIO_C_GET_WRITE_BUF_SIZE, 0, NULL));
        printf("make.default.a.init=%d\n", BIO_get_init(a));
        printf("make.default.a.eof=%ld\n", BIO_ctrl(a, BIO_CTRL_EOF, 0, NULL));
        BIO_free(a);
        BIO_free(b);

        ERR_clear_error();
        r = BIO_new_bio_dgram_pair(&a, 2048, &b, 4096);
        printf("make.explicit=%d\n", r);
        printf("make.explicit.a.bufsize=%ld\n", BIO_ctrl(a, BIO_C_GET_WRITE_BUF_SIZE, 0, NULL));
        printf("make.explicit.b.bufsize=%ld\n", BIO_ctrl(b, BIO_C_GET_WRITE_BUF_SIZE, 0, NULL));
        printf("make.explicit.a.guarantee=%ld\n", BIO_get_write_guarantee(a));

        /* Datagram boundaries survive a round trip. */
        printf("dg.write1=%d\n", BIO_write(a, "first", 5));
        printf("dg.write2=%d\n", BIO_write(a, "second!", 7));
        printf("dg.b.pending=%ld\n", BIO_ctrl(b, BIO_CTRL_PENDING, 0, NULL));
        printf("dg.b.pending2=%ld\n", BIO_ctrl(b, BIO_CTRL_PENDING, 0, NULL));
        memset(buf, 0, sizeof(buf));
        printf("dg.read.big=%d\n", BIO_read(b, buf, 64));
        printf("dg.read.big.data=%s\n", buf);
        printf("dg.b.pending.after=%ld\n", BIO_ctrl(b, BIO_CTRL_PENDING, 0, NULL));
        memset(buf, 0, sizeof(buf));
        printf("dg.read.second=%d\n", BIO_read(b, buf, 64));
        printf("dg.read.second.data=%s\n", buf);
        printf("dg.b.pending.end=%ld\n", BIO_ctrl(b, BIO_CTRL_PENDING, 0, NULL));

        /* An empty read is retriable. */
        ERR_clear_error();
        memset(buf, 0, sizeof(buf));
        printf("dg.read.empty=%d\n", BIO_read(b, buf, 64));
        printf("dg.read.empty.shouldretry=%d\n", BIO_should_retry(b));
        err_all("dg.read.empty");

        /* Truncation: the remainder of the datagram is discarded. */
        printf("dg.write.trunc=%d\n", BIO_write(a, "0123456789", 10));
        memset(buf, 0, sizeof(buf));
        printf("dg.read.trunc=%d\n", BIO_read(b, buf, 4));
        printf("dg.read.trunc.data=%.4s\n", buf);
        printf("dg.b.pending.trunc=%ld\n", BIO_ctrl(b, BIO_CTRL_PENDING, 0, NULL));

        /* The same read with NO_TRUNC fails and consumes nothing. */
        printf("dg.write.notrunc=%d\n", BIO_write(a, "abcdefghij", 10));
        printf("dg.notrunc.set=%ld\n", BIO_ctrl(b, BIO_CTRL_DGRAM_SET_NO_TRUNC, 1, NULL));
        printf("dg.notrunc.get=%ld\n", BIO_ctrl(b, BIO_CTRL_DGRAM_GET_NO_TRUNC, 0, NULL));
        ERR_clear_error();
        memset(buf, 0, sizeof(buf));
        printf("dg.notrunc.read=%d\n", BIO_read(b, buf, 4));
        printf("dg.notrunc.shouldretry=%d\n", BIO_should_retry(b));
        err_all("dg.notrunc.read");
        printf("dg.b.pending.notrunc=%ld\n", BIO_ctrl(b, BIO_CTRL_PENDING, 0, NULL));
        printf("dg.notrunc.clear=%ld\n", BIO_ctrl(b, BIO_CTRL_DGRAM_SET_NO_TRUNC, 0, NULL));
        memset(buf, 0, sizeof(buf));
        printf("dg.notrunc.read2=%d\n", BIO_read(b, buf, 10));
        printf("dg.notrunc.read2.data=%.10s\n", buf);

        /* A zero-length datagram is still a datagram. */
        printf("dg.write.zero=%d\n", BIO_write(a, "", 0));
        printf("dg.zero.pending=%ld\n", BIO_ctrl(b, BIO_CTRL_PENDING, 0, NULL));
        memset(buf, 0, sizeof(buf));
        printf("dg.zero.read=%d\n", BIO_read(b, buf, 8));

        /* Reset clears this side's buffer. */
        printf("dg.write.reset=%d\n", BIO_write(a, "xyz", 3));
        printf("dg.a.wpending=%ld\n", BIO_ctrl(a, BIO_CTRL_WPENDING, 0, NULL));
        printf("dg.reset=%d\n", BIO_ctrl(a, BIO_CTRL_RESET, 0, NULL));
        printf("dg.a.wpending.after=%ld\n", BIO_ctrl(a, BIO_CTRL_WPENDING, 0, NULL));
        printf("dg.b.pending.afterreset=%ld\n", BIO_ctrl(b, BIO_CTRL_PENDING, 0, NULL));

        /* Filling the buffer: the guarantee drops to zero rather than small. */
        {
            char big[3000];
            memset(big, 'q', sizeof(big));
            printf("dg.write.fill=%d\n", BIO_write(a, big, (int)sizeof(big)));
            printf("dg.a.guarantee.after=%ld\n", BIO_get_write_guarantee(a));
            ERR_clear_error();
            printf("dg.write.overflow=%d\n", BIO_write(a, big, (int)sizeof(big)));
            printf("dg.overflow.shouldretry=%d\n", BIO_should_retry(a));
            err_all("dg.write.overflow");
        }
        BIO_free(a);
        BIO_free(b);
    }

    /* --- mtu, caps and the failing controls ------------------------------- */
    {
        BIO *a = NULL, *b = NULL;

        printf("ctl.make=%d\n", BIO_new_bio_dgram_pair(&a, 0, &b, 0));

        printf("ctl.mtu.set=%ld\n", BIO_ctrl(a, BIO_CTRL_DGRAM_SET_MTU, 512, NULL));
        printf("ctl.mtu.a=%ld\n", BIO_ctrl(a, BIO_CTRL_DGRAM_GET_MTU, 0, NULL));
        printf("ctl.mtu.b=%ld\n", BIO_ctrl(b, BIO_CTRL_DGRAM_GET_MTU, 0, NULL));

        printf("ctl.caps.a=%ld\n", BIO_ctrl(a, BIO_CTRL_DGRAM_GET_CAPS, 0, NULL));
        printf("ctl.caps.set=%ld\n", BIO_ctrl(a, BIO_CTRL_DGRAM_SET_CAPS, 0x3, NULL));
        printf("ctl.caps.a.after=%ld\n", BIO_ctrl(a, BIO_CTRL_DGRAM_GET_CAPS, 0, NULL));
        printf("ctl.caps.effective=%ld\n",
               BIO_ctrl(b, BIO_CTRL_DGRAM_GET_EFFECTIVE_CAPS, 0, NULL));
        printf("ctl.locaddr.cap=%ld\n",
               BIO_ctrl(a, BIO_CTRL_DGRAM_GET_LOCAL_ADDR_CAP, 0, NULL));
        printf("ctl.locaddr.set=%ld\n",
               BIO_ctrl(a, BIO_CTRL_DGRAM_SET_LOCAL_ADDR_ENABLE, 1, NULL));
        {
            int enable = -1;
            printf("ctl.locaddr.get.ret=%ld\n",
                   BIO_ctrl(a, BIO_CTRL_DGRAM_GET_LOCAL_ADDR_ENABLE, 0, &enable));
            printf("ctl.locaddr.get.value=%d\n", enable);
        }

        /* Changing the buffer size while paired is refused. */
        ERR_clear_error();
        printf("ctl.setbuf.inuse=%d\n", BIO_set_write_buf_size(a, 4096));
        err_all("ctl.setbuf.inuse");

        /* The minimum size is enforced, and a smaller request is raised. */
        {
            BIO *m = BIO_new(BIO_s_dgram_mem());
            printf("ctl.mem.bufsize.before=%ld\n", BIO_ctrl(m, BIO_C_GET_WRITE_BUF_SIZE, 0, NULL));
            printf("ctl.mem.setbuf.small=%d\n", BIO_set_write_buf_size(m, 16));
            printf("ctl.mem.bufsize.after=%ld\n", BIO_ctrl(m, BIO_C_GET_WRITE_BUF_SIZE, 0, NULL));
            BIO_free(m);
        }

        /* A negative size is invalid, and the empty datagram is refused. */
        ERR_clear_error();
        printf("ctl.write.negative=%d\n", BIO_write(a, "x", -1));
        err_all("ctl.write.negative");
        ERR_clear_error();
        printf("ctl.read.negative=%d\n", BIO_read(a, buf, -1));
        err_all("ctl.read.negative");

        /* Destroying the pair leaves both halves unusable. */
        printf("ctl.destroy=%d\n", BIO_destroy_bio_pair(a));
        printf("ctl.destroy.a.init=%d\n", BIO_get_init(a));
        printf("ctl.destroy.b.init=%d\n", BIO_get_init(b));
        ERR_clear_error();
        printf("ctl.destroy.read=%d\n", BIO_read(a, buf, 4));
        err_all("ctl.destroy.read");
        printf("ctl.destroy.free=%d\n", BIO_free(a));
        printf("ctl.destroy.free2=%d\n", BIO_free(b));
    }

    /* --- BIO_s_dgram_mem is its own peer -------------------------------- */
    {
        BIO *m = BIO_new(BIO_s_dgram_mem());

        printf("mem.write=%d\n", BIO_write(m, "hello", 5));
        printf("mem.write2=%d\n", BIO_write(m, "world!", 6));
        printf("mem.pending=%ld\n", BIO_ctrl(m, BIO_CTRL_PENDING, 0, NULL));
        printf("mem.wpending=%ld\n", BIO_ctrl(m, BIO_CTRL_WPENDING, 0, NULL));
        printf("mem.eof=%ld\n", BIO_ctrl(m, BIO_CTRL_EOF, 0, NULL));
        memset(buf, 0, sizeof(buf));
        printf("mem.read=%d\n", BIO_read(m, buf, 32));
        printf("mem.read.data=%s\n", buf);
        memset(buf, 0, sizeof(buf));
        printf("mem.read2=%d\n", BIO_read(m, buf, 32));
        printf("mem.read2.data=%s\n", buf);
        printf("mem.pending.end=%ld\n", BIO_ctrl(m, BIO_CTRL_PENDING, 0, NULL));

        /* It grows on write by default, so a big datagram fits. */
        {
            char big[9000];
            memset(big, 'z', sizeof(big));
            printf("mem.grows.write=%d\n", BIO_write(m, big, (int)sizeof(big)));
            printf("mem.grows.bufsize=%ld\n", BIO_ctrl(m, BIO_C_GET_WRITE_BUF_SIZE, 0, NULL));
            printf("mem.grows.pending=%ld\n", BIO_ctrl(m, BIO_CTRL_PENDING, 0, NULL));
            printf("mem.grows.read=%d\n", BIO_read(m, buf, 64));
            memset(buf, 0, sizeof(buf));
            printf("mem.grows.read.full=%d\n", BIO_read(m, big, (int)sizeof(big)));
        }
        BIO_free(m);
    }

    /* --- BIO_sendmmsg / BIO_recvmmsg over the pair ----------------------- */
    {
        BIO *a = NULL, *b = NULL;
        BIO_MSG msgs[3];
        size_t processed = 0;
        size_t i;

        printf("mmsg.make=%d\n", BIO_new_bio_dgram_pair(&a, 0, &b, 0));

        memset(msgs, 0, sizeof(msgs));
        msgs[0].data = (void *)"alpha";
        msgs[0].data_len = 5;
        msgs[1].data = (void *)"beta";
        msgs[1].data_len = 4;
        msgs[2].data = (void *)"gamma";
        msgs[2].data_len = 5;
        ERR_clear_error();
        printf("mmsg.send=%d\n", BIO_sendmmsg(a, msgs, sizeof(msgs[0]), 3, 0, &processed));
        printf("mmsg.send.processed=%zu\n", processed);
        printf("mmsg.send.retry=%d\n", BIO_should_retry(a));
        err_all("mmsg.send");

        memset(msgs, 0, sizeof(msgs));
        msgs[0].data = buf;
        msgs[0].data_len = 8;
        msgs[1].data = buf + 32;
        msgs[1].data_len = 8;
        msgs[2].data = buf + 64;
        msgs[2].data_len = 8;
        ERR_clear_error();
        processed = 0;
        printf("mmsg.recv=%d\n", BIO_recvmmsg(b, msgs, sizeof(msgs[0]), 3, 0, &processed));
        printf("mmsg.recv.processed=%zu\n", processed);
        for (i = 0; i < 3 && i < processed; i++) {
            printf("mmsg.recv.%zu.len=%zu\n", i, msgs[i].data_len);
            printf("mmsg.recv.%zu.data=%.*s\n", i, (int)msgs[i].data_len,
                   (const char *)msgs[i].data);
        }

        /* Zero messages is a success with nothing processed. */
        processed = 99;
        printf("mmsg.send.zero=%d\n", BIO_sendmmsg(a, msgs, sizeof(msgs[0]), 0, 0, &processed));
        printf("mmsg.send.zero.processed=%zu\n", processed);
        processed = 99;
        printf("mmsg.recv.zero=%d\n", BIO_recvmmsg(b, msgs, sizeof(msgs[0]), 0, 0, &processed));
        printf("mmsg.recv.zero.processed=%zu\n", processed);

        /* A partly successful recv reports the count and still succeeds. */
        memset(msgs, 0, sizeof(msgs));
        msgs[0].data = buf;
        msgs[0].data_len = 8;
        msgs[1].data = buf + 32;
        msgs[1].data_len = 8;
        processed = 0;
        printf("mmsg.recv.empty=%d\n", BIO_recvmmsg(b, msgs, sizeof(msgs[0]), 2, 0, &processed));
        printf("mmsg.recv.empty.processed=%zu\n", processed);

        BIO_free(a);
        BIO_free(b);
    }

    /* --- the failure path of the pair constructor ------------------------ */
    {
        BIO *a = (BIO *)1, *b = (BIO *)1;
        int r;

        ERR_clear_error();
        r = BIO_new_bio_dgram_pair(&a, 0, &b, 0);
        printf("pair.ok=%d\n", r);
        printf("pair.outputs.nonnull=%d\n", a != NULL && b != NULL);
        BIO_free(a);
        BIO_free(b);
    }

    ERR_clear_error();
    printf("err.final=%lu\n", ERR_peek_error());
    ERR_clear_error();
    return 0;
}
