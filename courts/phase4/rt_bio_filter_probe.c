/*
 * openssl-rs — RT-BIO-FILTER: the buffering, line-buffering, read-caching and
 * prefix filters.
 *
 * These four filters are all "a BIO in front of a BIO", and the way to see
 * whether the pipeline is right is to observe what crosses it. The probe
 * therefore builds each filter over a **memory BIO** and records, after every
 * operation, the return value, the number of bytes retained (through
 * `BIO_ctrl(BIO_CTRL_INFO)` and the pending counts, never by reading the private
 * structure), and the exact bytes that reached the sink.
 *
 * The memory BIO is also the oracle for *when* bytes move: `BIO_f_buffer` only
 * flushes when its output buffer fills or `BIO_flush` is called, `BIO_f_linebuffer`
 * only up to the last newline, and `BIO_f_prefix` inserts text at each line
 * start. Reading the mem BIO after each step shows which of those happened.
 *
 * Everything is deterministic: no file system access, no sockets, no clocks.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

/* Show the bytes currently in a memory BIO without consuming them. */
static void show_mem(const char *key, BIO *mem)
{
    char *p = NULL;
    long n = BIO_get_mem_data(mem, &p);
    long i;

    printf("%s.n=%ld\n", key, n);
    printf("%s.v=", key);
    for (i = 0; i < n && i < 256; i++) {
        unsigned char c = (unsigned char)p[i];
        if (c == '\n')
            printf("\\n");
        else if (c < 32 || c > 126)
            printf("\\x%02x", c);
        else
            putchar(c);
    }
    putchar('\n');
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    /* --- BIO_f_buffer ---------------------------------------------------- */
    {
        BIO *mem = BIO_new(BIO_s_mem());
        BIO *b = BIO_new(BIO_f_buffer());

        printf("buff.nonnull=%d\n", b != NULL);
        printf("buff.name=%s\n", b ? BIO_method_name(b) : "-");
        printf("buff.type=%d\n", b ? BIO_method_type(b) : -1);
        printf("buff.init=%d\n", b ? BIO_get_init(b) : -1);
        BIO_push(b, mem);

        printf("buff.info.empty=%ld\n", BIO_ctrl(b, BIO_CTRL_INFO, 0, NULL));
        printf("buff.pending.empty=%ld\n", BIO_ctrl(b, BIO_CTRL_PENDING, 0, NULL));
        printf("buff.wpending.empty=%ld\n", BIO_ctrl(b, BIO_CTRL_WPENDING, 0, NULL));

        /* A small write stays in the filter. */
        printf("buff.write.small=%d\n", BIO_write(b, "abc", 3));
        printf("buff.info.small=%ld\n", BIO_ctrl(b, BIO_CTRL_INFO, 0, NULL));
        printf("buff.wpending.small=%ld\n", BIO_ctrl(b, BIO_CTRL_WPENDING, 0, NULL));
        show_mem("buff.mem.small", mem);

        /* Flushing moves it. */
        printf("buff.flush=%d\n", BIO_flush(b));
        printf("buff.info.flushed=%ld\n", BIO_ctrl(b, BIO_CTRL_INFO, 0, NULL));
        show_mem("buff.mem.flushed", mem);

        /* Writes larger than the buffer go straight through. */
        printf("buff.write.big=%d\n", BIO_write(b, "0123456789", 10));
        printf("buff.wpending.big=%ld\n", BIO_ctrl(b, BIO_CTRL_WPENDING, 0, NULL));
        show_mem("buff.mem.big", mem);

        /* Reading back through the filter uses the memory BIO as the source. */
        {
            char out[64];
            memset(out, 0, sizeof(out));
            printf("buff.read=%d\n", BIO_read(b, out, 5));
            printf("buff.read.data=%s\n", out);
            printf("buff.read.pending=%ld\n", BIO_ctrl(b, BIO_CTRL_PENDING, 0, NULL));
            memset(out, 0, sizeof(out));
            printf("buff.gets=%d\n", BIO_gets(b, out, sizeof(out)));
            printf("buff.gets.data=%s\n", out);
        }

        /* The EOF answer distinguishes buffered input from the next BIO's. */
        printf("buff.eof=%ld\n", BIO_ctrl(b, BIO_CTRL_EOF, 0, NULL));

        /* PEEK forces a read and does not consume. */
        {
            char peek[8];
            memset(peek, 0, sizeof(peek));
            printf("buff.peek=%ld\n", BIO_ctrl(b, BIO_CTRL_PEEK, 4, peek));
            printf("buff.peek.data=%s\n", peek);
            printf("buff.peek.pending=%ld\n", BIO_ctrl(b, BIO_CTRL_PENDING, 0, NULL));
        }

        /* The read-buffer controls. */
        printf("buff.numlines=%ld\n", BIO_ctrl(b, BIO_C_GET_BUFF_NUM_LINES, 0, NULL));
        printf("buff.setrbs=%ld\n", BIO_ctrl(b, BIO_C_SET_BUFF_SIZE, 8192, NULL));
        printf("buff.setrbs.smaller=%ld\n", BIO_ctrl(b, BIO_C_SET_BUFF_SIZE, 64, NULL));
        printf("buff.reset=%ld\n", BIO_ctrl(b, BIO_CTRL_RESET, 0, NULL));

        BIO_free(b);
        BIO_free(mem);
    }

    /* --- the read-buffer path, driven by BIO_set_buffer_read_data --------- */
    {
        BIO *mem = BIO_new(BIO_s_mem());
        BIO *b = BIO_new(BIO_f_buffer());

        BIO_push(b, mem);
        printf("buff.readdata=%ld\n",
               BIO_ctrl(b, BIO_C_SET_BUFF_READ_DATA, 4, (void *)"pre!"));
        printf("buff.readdata.pending=%ld\n", BIO_ctrl(b, BIO_CTRL_PENDING, 0, NULL));
        {
            char out[16];
            memset(out, 0, sizeof(out));
            printf("buff.readdata.read=%d\n", BIO_read(b, out, 4));
            printf("buff.readdata.data=%s\n", out);
        }
        BIO_free(b);
        BIO_free(mem);
    }

    /* --- BIO_f_linebuffer ------------------------------------------------ */
    {
        BIO *mem = BIO_new(BIO_s_mem());
        BIO *b = BIO_new(BIO_f_linebuffer());

        printf("line.nonnull=%d\n", b != NULL);
        printf("line.name=%s\n", b ? BIO_method_name(b) : "-");
        printf("line.type=%d\n", b ? BIO_method_type(b) : -1);
        BIO_push(b, mem);

        /* No newline: retained. */
        printf("line.write.nonl=%d\n", BIO_write(b, "abc", 3));
        printf("line.info.nonl=%ld\n", BIO_ctrl(b, BIO_CTRL_INFO, 0, NULL));
        printf("line.wpending.nonl=%ld\n", BIO_ctrl(b, BIO_CTRL_WPENDING, 0, NULL));
        show_mem("line.mem.nonl", mem);

        /* A newline flushes up to and including it, and the tail is retained. */
        printf("line.write.nl=%d\n", BIO_write(b, "def\nghi", 7));
        printf("line.info.nl=%ld\n", BIO_ctrl(b, BIO_CTRL_INFO, 0, NULL));
        show_mem("line.mem.nl", mem);

        printf("line.flush=%d\n", BIO_flush(b));
        printf("line.info.flushed=%ld\n", BIO_ctrl(b, BIO_CTRL_INFO, 0, NULL));
        show_mem("line.mem.flushed", mem);

        printf("line.puts=%d\n", BIO_puts(b, "!\n"));
        printf("line.flush2=%d\n", BIO_flush(b));
        show_mem("line.mem.puts", mem);

        printf("line.reset=%ld\n", BIO_ctrl(b, BIO_CTRL_RESET, 0, NULL));
        BIO_free(b);
        BIO_free(mem);
    }

    /* --- BIO_f_readbuffer ------------------------------------------------ */
    {
        BIO *mem = BIO_new(BIO_s_mem());
        BIO *b = BIO_new(BIO_f_readbuffer());

        printf("readb.nonnull=%d\n", b != NULL);
        printf("readb.name=%s\n", b ? BIO_method_name(b) : "-");
        printf("readb.type=%d\n", b ? BIO_method_type(b) : -1);
        BIO_push(b, mem);

        /* Long enough that the next BIO can be its own source. */
        BIO_write(mem, "line-one\nline-two\n", 18);

        printf("readb.tell.0=%ld\n", BIO_ctrl(b, BIO_C_FILE_TELL, 0, NULL));
        {
            char out[16];
            memset(out, 0, sizeof(out));
            printf("readb.read=%d\n", BIO_read(b, out, 9));
            printf("readb.read.data=%s\n", out);
        }
        printf("readb.tell.9=%ld\n", BIO_ctrl(b, BIO_C_FILE_TELL, 0, NULL));
        printf("readb.info=%ld\n", BIO_ctrl(b, BIO_CTRL_INFO, 0, NULL));
        printf("readb.pending=%ld\n", BIO_ctrl(b, BIO_CTRL_PENDING, 0, NULL));
        printf("readb.eof=%ld\n", BIO_ctrl(b, BIO_CTRL_EOF, 0, NULL));

        /* Seeking backwards inside the cache is allowed; forwards is not. */
        printf("readb.seek.back=%ld\n", BIO_ctrl(b, BIO_C_FILE_SEEK, 0, NULL));
        printf("readb.tell.after0=%ld\n", BIO_ctrl(b, BIO_C_FILE_TELL, 0, NULL));
        {
            char out[16];
            memset(out, 0, sizeof(out));
            printf("readb.read.again=%d\n", BIO_read(b, out, 9));
            printf("readb.read.again.data=%s\n", out);
        }
        printf("readb.seek.fwd=%ld\n", BIO_ctrl(b, BIO_C_FILE_SEEK, 100, NULL));
        printf("readb.seek.neg=%ld\n", BIO_ctrl(b, BIO_C_FILE_SEEK, -1, NULL));
        printf("readb.reset=%ld\n", BIO_ctrl(b, BIO_CTRL_RESET, 0, NULL));
        printf("readb.tell.afterreset=%ld\n", BIO_ctrl(b, BIO_C_FILE_TELL, 0, NULL));

        /* The read-only filter refuses writes. */
        printf("readb.write=%d\n", BIO_write(b, "x", 1));
        printf("readb.puts=%d\n", BIO_puts(b, "x"));
        printf("readb.flush=%ld\n", BIO_ctrl(b, BIO_CTRL_FLUSH, 0, NULL));
        printf("readb.dup=%ld\n", BIO_ctrl(b, BIO_CTRL_DUP, 0, NULL));
        printf("readb.unknown=%ld\n", BIO_ctrl(b, 999, 0, NULL));

        BIO_free(b);
        BIO_free(mem);
    }

    /* --- BIO_f_readbuffer gets ------------------------------------------ */
    {
        BIO *mem = BIO_new(BIO_s_mem());
        BIO *b = BIO_new(BIO_f_readbuffer());
        char out[16];

        BIO_push(b, mem);
        BIO_write(mem, "aa\nbb\n", 6);
        memset(out, 0, sizeof(out));
        printf("readb.gets=%d\n", BIO_gets(b, out, sizeof(out)));
        printf("readb.gets.data=%s\n", out);
        printf("readb.tell.gets=%ld\n", BIO_ctrl(b, BIO_C_FILE_TELL, 0, NULL));
        memset(out, 0, sizeof(out));
        printf("readb.gets2=%d\n", BIO_gets(b, out, sizeof(out)));
        printf("readb.gets2.data=%s\n", out);

        BIO_free(b);
        BIO_free(mem);
    }

    /* --- BIO_f_prefix ---------------------------------------------------- */
    {
        BIO *mem = BIO_new(BIO_s_mem());
        BIO *b = BIO_new(BIO_f_prefix());

        printf("pref.nonnull=%d\n", b != NULL);
        printf("pref.name=%s\n", b ? BIO_method_name(b) : "-");
        printf("pref.type=%d\n", b ? BIO_method_type(b) : -1);
        BIO_push(b, mem);

        /* Passthrough, but the line-start flag is still tracked. */
        printf("pref.passthru=%d\n", BIO_write(b, "x\ny", 3));
        show_mem("pref.mem.passthru", mem);

        /* Setting a prefix applies from the current line start. */
        printf("pref.setprefix=%ld\n", BIO_ctrl(b, BIO_CTRL_SET_PREFIX, 0, (void *)"> "));
        printf("pref.write=%d\n", BIO_write(b, "one\ntwo\n", 8));
        show_mem("pref.mem.write", mem);
        printf("pref.getindent=%ld\n", BIO_ctrl(b, BIO_CTRL_GET_INDENT, 0, NULL));
        printf("pref.setindent=%ld\n", BIO_ctrl(b, BIO_CTRL_SET_INDENT, 2, NULL));
        printf("pref.getindent2=%ld\n", BIO_ctrl(b, BIO_CTRL_GET_INDENT, 0, NULL));
        printf("pref.setindent.neg=%ld\n", BIO_ctrl(b, BIO_CTRL_SET_INDENT, -1, NULL));
        printf("pref.write2=%d\n", BIO_write(b, "three\n", 6));
        show_mem("pref.mem.write2", mem);

        /* A seek re-arms the line start. */
        printf("pref.seek=%ld\n", BIO_ctrl(b, BIO_C_FILE_SEEK, 0, NULL));
        printf("pref.write3=%d\n", BIO_write(b, "z", 1));
        show_mem("pref.mem.write3", mem);

        /* Clearing the prefix leaves only the indent. */
        printf("pref.clearprefix=%ld\n", BIO_ctrl(b, BIO_CTRL_SET_PREFIX, 0, NULL));
        printf("pref.setindent0=%ld\n", BIO_ctrl(b, BIO_CTRL_SET_INDENT, 0, NULL));
        printf("pref.write4=%d\n", BIO_write(b, "q\n", 2));
        show_mem("pref.mem.write4", mem);

        printf("pref.free=%d\n", BIO_free(b));
        BIO_free(mem);
    }

    ERR_clear_error();
    printf("err.count=%lu\n", ERR_peek_error());
    ERR_clear_error();
    return 0;
}
