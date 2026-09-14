/*
 * openssl-rs — RT-BIO-FILE: the FILE, descriptor and syslog BIOs.
 *
 * Three method families that share one property: their observable surface is the
 * *state machine plus the error queue*, not the bytes. The probe therefore drives
 * the controls (`BIO_tell`, `BIO_seek`, `BIO_eof`, `BIO_flush`, the `.num` and
 * `.ptr` accessors), the close flags, the two-step initialization, and the error
 * shapes, and drains the whole queue for each failure.
 *
 * Determinism rules:
 *
 *   * descriptor numbers and `FILE *` values differ between runs, so they are
 *     reported as predicates (`>= 0`, `matches the pipe end`) never as values;
 *   * the temp file lives at a fixed path under `/tmp` and is removed at the end,
 *     so a re-run starts from the same state;
 *   * the missing-file name is fixed, so the error data string is stable;
 *   * the syslog text leaves the process and is not compared — only the return
 *     values and the method table are.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

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
        snprintf(k, sizeof(k), "%s.%d.flags", key, n);
        printf("%s=%d\n", k, flags);
        if (++n > 8)
            break;
    }
    snprintf(k, sizeof(k), "%s.count", key);
    printf("%s=%d\n", k, n);
    ERR_clear_error();
}

#define TMPFILE "/tmp/openssl-rs-probe-file.txt"

int main(void)
{
    char buf[64];

    setvbuf(stdout, NULL, _IONBF, 0);

    /* --- the method tables, read through a BIO --------------------------- */
    /* `BIO_method_name`/`BIO_method_type` take a `BIO *`, not a method table. */
    {
        BIO *b = BIO_new(BIO_s_file());
        printf("sfile.name=%s\n", BIO_method_name(b));
        printf("sfile.type=%d\n", BIO_method_type(b));
        BIO_free(b);
        b = BIO_new(BIO_s_fd());
        printf("sfd.name=%s\n", BIO_method_name(b));
        printf("sfd.type=%d\n", BIO_method_type(b));
        BIO_free(b);
        b = BIO_new(BIO_s_log());
        printf("slog.name=%s\n", BIO_method_name(b));
        printf("slog.type=%d\n", BIO_method_type(b));
        printf("slog.reused.init=%d\n", BIO_get_init(b));
        printf("slog.reused.free=%d\n", BIO_free(b));
    }

    /* --- BIO_new_file: the failure shapes ------------------------------- */
    ERR_clear_error();
    printf("newfile.missing.null=%d\n", BIO_new_file("/no-such-dir-xyz/f", "r") == NULL);
    err_all("newfile.missing");

    ERR_clear_error();
    printf("newfile.isdir.null=%d\n", BIO_new_file("/tmp", "w") == NULL);
    err_all("newfile.isdir");

    /* --- BIO_new_file: a real round trip -------------------------------- */
    {
        BIO *w = BIO_new_file(TMPFILE, "w");
        char *fp = NULL;
        BIO *r;

        printf("newfile.w.nonnull=%d\n", w != NULL);
        printf("newfile.w.init=%d\n", BIO_get_init(w));
        printf("newfile.w.shutdown=%d\n", BIO_get_shutdown(w));
        printf("newfile.w.getclose=%ld\n", BIO_ctrl(w, BIO_CTRL_GET_CLOSE, 0, NULL));
        printf("newfile.w.getfp.ok=%ld\n", BIO_get_fp(w, &fp));
        printf("newfile.w.fp.nonnull=%d\n", fp != NULL);
        printf("newfile.w.write=%d\n", BIO_write(w, "hello\nworld\n", 12));
        printf("newfile.w.puts=%d\n", BIO_puts(w, "tail"));
        printf("newfile.w.flush=%d\n", BIO_flush(w));
        printf("newfile.w.seek0=%d\n", BIO_seek(w, 0));
        printf("newfile.w.tell=%d\n", BIO_tell(w));
        printf("newfile.w.pending=%ld\n", BIO_ctrl(w, BIO_CTRL_PENDING, 0, NULL));
        printf("newfile.w.free=%d\n", BIO_free(w));

        ERR_clear_error();
        r = BIO_new_file(TMPFILE, "r");
        printf("newfile.r.nonnull=%d\n", r != NULL);
        printf("newfile.r.init=%d\n", BIO_get_init(r));
        printf("newfile.r.shutdown=%d\n", BIO_get_shutdown(r));
        printf("newfile.r.tell=%d\n", BIO_tell(r));
        memset(buf, 0, sizeof(buf));
        printf("newfile.r.read=%d\n", BIO_read(r, buf, 5));
        printf("newfile.r.data=%s\n", buf);
        printf("newfile.r.tell2=%d\n", BIO_tell(r));
        printf("newfile.r.eof=%ld\n", BIO_ctrl(r, BIO_CTRL_EOF, 0, NULL));
        memset(buf, 0, sizeof(buf));
        printf("newfile.r.gets=%d\n", BIO_gets(r, buf, sizeof(buf)));
        printf("newfile.r.gets.data=%s\n", buf);
        memset(buf, 0, sizeof(buf));
        printf("newfile.r.gets2=%d\n", BIO_gets(r, buf, sizeof(buf)));
        printf("newfile.r.gets2.data=%s\n", buf);
        printf("newfile.r.seek=%d\n", BIO_seek(r, 6));
        memset(buf, 0, sizeof(buf));
        printf("newfile.r.read2=%d\n", BIO_read(r, buf, 5));
        printf("newfile.r.data2=%s\n", buf);
        printf("newfile.r.reset=%ld\n", BIO_ctrl(r, BIO_CTRL_RESET, 0, NULL));
        memset(buf, 0, sizeof(buf));
        printf("newfile.r.read3=%d\n", BIO_read(r, buf, 5));
        printf("newfile.r.data3=%s\n", buf);
        printf("newfile.r.dup=%ld\n", BIO_ctrl(r, BIO_CTRL_DUP, 0, NULL));
        printf("newfile.r.setclose=%ld\n", BIO_ctrl(r, BIO_CTRL_SET_CLOSE, BIO_NOCLOSE, NULL));
        printf("newfile.r.getclose=%ld\n", BIO_ctrl(r, BIO_CTRL_GET_CLOSE, 0, NULL));
        printf("newfile.r.free=%d\n", BIO_free(r));

        ERR_clear_error();
        printf("newfile.badmode=%ld\n",
               BIO_ctrl(BIO_new(BIO_s_file()), BIO_C_SET_FILENAME, 0, (void *)TMPFILE));
        err_all("newfile.badmode");
    }

    /* --- BIO_C_SET_FILE_PTR on an already-open BIO ---------------------- */
    {
        FILE *f = fopen(TMPFILE, "r");
        BIO *b = BIO_new(BIO_s_file());

        printf("setfp.file.nonnull=%d\n", f != NULL);
        ERR_clear_error();
        printf("setfp.ret=%ld\n", BIO_set_fp(b, f, BIO_NOCLOSE));
        printf("setfp.init=%d\n", BIO_get_init(b));
        printf("setfp.shutdown=%d\n", BIO_get_shutdown(b));
        memset(buf, 0, sizeof(buf));
        printf("setfp.read=%d\n", BIO_read(b, buf, 4));
        printf("setfp.data=%s\n", buf);
        /* Setting the pointer again runs the destroy hook first; with
         * BIO_NOCLOSE it must not have closed the stream. */
        printf("setfp.ret2=%ld\n", BIO_set_fp(b, f, BIO_CLOSE));
        memset(buf, 0, sizeof(buf));
        printf("setfp.read2=%d\n", BIO_read(b, buf, 4));
        printf("setfp.data2=%s\n", buf);
        printf("setfp.free=%d\n", BIO_free(b));
    }

    /* --- BIO_new_fp on a stream this process owns ----------------------- */
    {
        FILE *f = fopen(TMPFILE, "r");
        BIO *b = BIO_new_fp(f, BIO_NOCLOSE);

        printf("newfp.nonnull=%d\n", b != NULL);
        printf("newfp.init=%d\n", BIO_get_init(b));
        printf("newfp.shutdown=%d\n", BIO_get_shutdown(b));
        printf("newfp.ctl.unused=%ld\n", BIO_ctrl(b, 999, 0, NULL));
        printf("newfp.free=%d\n", BIO_free(b));
        fclose(f);
    }

    /* --- the descriptor BIO --------------------------------------------- */
    {
        int p[2];
        int got = -1;
        BIO *b;

        printf("pipe.ok=%d\n", pipe(p) == 0);
        ERR_clear_error();
        b = BIO_new_fd(p[0], BIO_NOCLOSE);
        printf("newfd.nonnull=%d\n", b != NULL);
        printf("newfd.init=%d\n", BIO_get_init(b));
        printf("newfd.shutdown=%d\n", BIO_get_shutdown(b));
        printf("newfd.getfd=%ld\n", BIO_get_fd(b, &got));
        printf("newfd.fd.matches=%d\n", got == p[0]);
        printf("newfd.pending=%ld\n", BIO_ctrl(b, BIO_CTRL_PENDING, 0, NULL));
        printf("newfd.wpending=%ld\n", BIO_ctrl(b, BIO_CTRL_WPENDING, 0, NULL));
        printf("newfd.flush=%d\n", BIO_flush(b));
        printf("newfd.eof.before=%ld\n", BIO_ctrl(b, BIO_CTRL_EOF, 0, NULL));
        printf("newfd.tell=%d\n", BIO_tell(b));

        printf("pipe.write=%ld\n", (long)write(p[1], "abc\ndef\n", 8));

        memset(buf, 0, sizeof(buf));
        printf("newfd.read=%d\n", BIO_read(b, buf, 4));
        printf("newfd.data=%s\n", buf);
        printf("newfd.eof.mid=%ld\n", BIO_ctrl(b, BIO_CTRL_EOF, 0, NULL));
        memset(buf, 0, sizeof(buf));
        printf("newfd.gets=%d\n", BIO_gets(b, buf, sizeof(buf)));
        printf("newfd.gets.data=%s\n", buf);

        close(p[1]);
        memset(buf, 0, sizeof(buf));
        printf("newfd.read.eof=%d\n", BIO_read(b, buf, 4));
        printf("newfd.eof.after=%ld\n", BIO_ctrl(b, BIO_CTRL_EOF, 0, NULL));
        printf("newfd.gets.eof=%d\n", BIO_gets(b, buf, sizeof(buf)));
        printf("newfd.free=%d\n", BIO_free(b));
        close(p[0]);

        ERR_clear_error();
        {
            /* The authority accepts a negative descriptor here: `BIO_new_fd`
             * only stores it, and the failure comes later. */
            BIO *neg = BIO_new_fd(-1, BIO_NOCLOSE);
            int g = -7;
            printf("newfd.negfd.nonnull=%d\n", neg != NULL);
            printf("newfd.negfd.getfd=%ld\n", BIO_ctrl(neg, BIO_C_GET_FD, 0, &g));
            printf("newfd.negfd.fd=%d\n", g);
            printf("newfd.negfd.free=%d\n", BIO_free(neg));
        }
        err_all("newfd.bad");
    }

    /* --- the descriptor control surface --------------------------------- */
    {
        BIO *b = BIO_new(BIO_s_fd());
        int fd = -1;

        printf("fdctrl.raw.init=%d\n", BIO_get_init(b));
        printf("fdctrl.getfd.before=%ld\n", BIO_ctrl(b, BIO_C_GET_FD, 0, &fd));
        printf("fdctrl.fd.before=%d\n", fd);
        printf("fdctrl.seteof=%ld\n", BIO_ctrl(b, BIO_CTRL_EOF, 0, NULL));
        printf("fdctrl.getclose=%ld\n", BIO_ctrl(b, BIO_CTRL_GET_CLOSE, 0, NULL));
        printf("fdctrl.setclose=%ld\n", BIO_ctrl(b, BIO_CTRL_SET_CLOSE, BIO_NOCLOSE, NULL));
        printf("fdctrl.getclose2=%ld\n", BIO_ctrl(b, BIO_CTRL_GET_CLOSE, 0, NULL));
        printf("fdctrl.dup=%ld\n", BIO_ctrl(b, BIO_CTRL_DUP, 0, NULL));
        printf("fdctrl.info=%ld\n", BIO_ctrl(b, BIO_CTRL_INFO, 0, NULL));
        printf("fdctrl.free=%d\n", BIO_free(b));
    }

    /* --- the syslog BIO ------------------------------------------------- */
    {
        BIO *l = BIO_new(BIO_s_log());

        printf("slog.nonnull=%d\n", l != NULL);
        printf("slog.init=%d\n", BIO_get_init(l));
        printf("slog.shutdown=%d\n", BIO_get_shutdown(l));
        printf("slog.write=%d\n", BIO_write(l, "INFO hello\n", 11));
        printf("slog.write.unmatched=%d\n", BIO_write(l, "plain line\n", 11));
        printf("slog.write.empty=%d\n", BIO_write(l, "", 0));
        printf("slog.write.negative=%d\n", BIO_write(l, "x", -1));
        printf("slog.puts=%d\n", BIO_puts(l, "ERR something"));
        printf("slog.ctrl.set=%ld\n", BIO_ctrl(l, BIO_CTRL_SET, LOG_USER, "myapp"));
        printf("slog.ctrl.flush=%ld\n", BIO_ctrl(l, BIO_CTRL_FLUSH, 0, NULL));
        printf("slog.ctrl.unknown=%ld\n", BIO_ctrl(l, 999, 0, NULL));
        printf("slog.free=%d\n", BIO_free(l));
    }

    printf("cleanup=%d\n", remove(TMPFILE));
    ERR_clear_error();
    printf("err.final=%lu\n", ERR_peek_error());
    ERR_clear_error();
    return 0;
}
