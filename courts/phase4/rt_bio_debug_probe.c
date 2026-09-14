/*
 * openssl-rs — RT-BIO-DEBUG: the reference BIO callback's emitted text.
 *
 * `BIO_debug_callback` and `BIO_debug_callback_ex` are the documented way to
 * observe the BIO callback protocol, and their *output* is the contract: a
 * program that installs one and captures the destination BIO sees this text.
 * The probe therefore does exactly that — a memory BIO as the callback argument,
 * the debug callback installed on a subject BIO, one operation at a time — and
 * compares the bytes, the return value, and the error queue.
 *
 * ## One deliberate normalisation, and why it is legitimate
 *
 * Every message begins `BIO[0x…]: ` with the subject's address, which differs
 * between two processes by construction. The probe replaces each `0x`-prefixed
 * hex run with the literal `<addr>` *before* printing, so the comparison is over
 * the message grammar rather than over the allocator. The transformation is
 * applied identically by both sides, it is confined to the address token, and
 * nothing else in any message is a hex run — so it cannot hide a divergence.
 * The raw text remains re-derivable by re-running the staged binaries in
 * `artifacts/phase4/probes/`, which is why scrubbing here is not a loss of
 * evidence.
 *
 * ## The descriptor branch is driven without doing I/O
 *
 * `BIO_debug_callback_ex` formats a different string when the method carries
 * `BIO_TYPE_DESCRIPTOR` (`… fd=%d`). Provoking it through `BIO_read` would mean
 * touching a real descriptor, whose number varies between runs. Instead the
 * probe calls the callback *directly* on a `BIO_s_socket` BIO, which fires the
 * formatting with no syscall at all; `sock_new` leaves `num` at 0 and `init` at
 * 0, so both the address and the number are deterministic and the free path
 * closes nothing.
 *
 * ## Why every operation gets a fresh destination
 *
 * A memory BIO's `BIO_CTRL_RESET` semantics depend on flags
 * (`BIO_FLAGS_NONCLEAR_RST`), and using it to clear between cases would test the
 * reset path *and* the debug text at once. A fresh destination per case observes
 * one thing at a time, which is what the court is for. The subject is freed
 * *before* the destination is read, because `BIO_free` itself invokes the
 * callback with `BIO_CB_FREE` and its line belongs to the case.
 *
 * ## Newlines are escaped
 *
 * Each emitted message ends in `\n`; the probe replaces it with `~` so that one
 * message occupies one `key=value` line and the court's line-wise comparison
 * produces one residual per field rather than shifting every following line.
 *
 * ## The NULL-destination fallback writes to stderr, so the probe captures it
 *
 * `BIO_debug_callback_ex` with a NULL `bio` argument writes to the process's
 * stderr. That is the behaviour under test, but leaving the bytes there made the
 * court's own *capture* irreproducible: the message begins with the subject's
 * address, which is ASLR-dependent, so every run recorded a different stderr and
 * therefore a different evidence identity — while the court's declared axis
 * (`stdout`, `exit`) was stable. Disabling ASLR is not available here (measured:
 * `setarch -R` is refused in both court containers). The probe therefore
 * redirects descriptor 2 to a temporary file for the duration of that one call,
 * restores it, and reports the scrubbed text as an observation. Nothing is
 * discarded — the address is the only token masked, by the same `build_esc` the
 * other cases use — and the raw bytes stay re-derivable from the staged binaries.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <openssl/bio.h>
#include <openssl/err.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* The destination for the debug text, recreated for each case. */
static BIO *dst;
static BIO *subject;

/* Copy `p[0..n)` into `out`, escaping newlines and scrubbing address tokens. */
static void build_esc(const char *p, long n, char *out, long outsz)
{
    long i = 0, j = 0;

    while (i < n && j < outsz - 8) {
        if (p[i] == '\n') {
            out[j++] = '~';
            i++;
            continue;
        }
        if (p[i] == '0' && i + 2 < n && p[i + 1] == 'x'
            && isxdigit((unsigned char)p[i + 2])) {
            const char *m = "<addr>";
            while (*m)
                out[j++] = *m++;
            i += 2;
            while (i < n && isxdigit((unsigned char)p[i]))
                i++;
            continue;
        }
        out[j++] = p[i++];
    }
    out[j] = '\0';
}

static void case_begin(void)
{
    ERR_clear_error();
    dst = BIO_new(BIO_s_mem());
    subject = BIO_new(BIO_s_mem());
    BIO_set_callback_ex(subject, BIO_debug_callback_ex);
    BIO_set_callback_arg(subject, (char *)dst);
}

/*
 * Free the subject (which may append a `BIO_CB_FREE` line to the destination),
 * then read the destination out, then free the destination.
 */
static void case_end(const char *key)
{
    char *p = NULL;
    long n;
    char esc[1024];

    if (subject != NULL) {
        BIO_free(subject);
        subject = NULL;
    }
    n = BIO_get_mem_data(dst, &p);
    esc[0] = '\0';
    if (p != NULL)
        build_esc(p, n, esc, (long)sizeof(esc));

    printf("%s.dstlen=%ld\n", key, n);
    printf("%s.text=%s\n", key, esc);
    printf("%s.err0=%lu\n", key, ERR_peek_error());
    ERR_clear_error();
    BIO_free(dst);
    dst = NULL;
}

int main(void)
{
    char k[64];

    setvbuf(stdout, NULL, _IONBF, 0);

    /* --- a read, including its BIO_CB_RETURN phase ----------------------- */
    case_begin();
    printf("read.ret=%d\n", BIO_read(subject, k, 16));
    case_end("read");

    /* --- a write --------------------------------------------------------- */
    case_begin();
    printf("write.ret=%d\n", BIO_write(subject, "hello", 5));
    case_end("write");

    /* --- a write of zero bytes: no callback fires at all ------------------ */
    case_begin();
    printf("write0.ret=%d\n", BIO_write(subject, "hello", 0));
    case_end("write0");

    /* --- ctrl: the command number is the only argument printed ----------- */
    case_begin();
    printf("ctrl.ret=%ld\n", BIO_ctrl(subject, BIO_CTRL_PENDING, 0, NULL));
    case_end("ctrl");

    /* --- gets ------------------------------------------------------------ */
    case_begin();
    printf("gets.ret=%d\n", BIO_gets(subject, k, 8));
    case_end("gets");

    /* --- puts ------------------------------------------------------------ */
    case_begin();
    printf("puts.ret=%d\n", BIO_puts(subject, "hi"));
    case_end("puts");

    /* --- free: the BIO_CB_FREE arm, which frees the subject on the spot --- */
    case_begin();
    printf("free.ret=%d\n", BIO_free(subject));
    subject = NULL;
    case_end("free");

    /* --- the descriptor branch, formatted directly and without I/O ------- */
    {
        BIO *sock = BIO_new(BIO_s_socket());

        /* `sock_new` leaves init at 0, so the free path closes nothing; set
         * shutdown to 0 anyway so the probe cannot close descriptor 0 on systems
         * whose socket method differs. */
        BIO_set_shutdown(sock, 0);

        case_begin();
        BIO_set_callback_ex(subject, NULL);
        /* Route the socket BIO's text to the same destination: the debug
         * callback writes to *its own* BIO's `cb_arg`, not the caller's. */
        BIO_set_callback_arg(sock, (char *)dst);
        printf("desc.read.ret=%ld\n",
               BIO_debug_callback_ex(sock, BIO_CB_READ, NULL, 16, 0, 0L, 0,
                                     NULL));
        printf("desc.read.type=%d\n", BIO_method_type(sock));
        printf("desc.write.ret=%ld\n",
               BIO_debug_callback_ex(sock, BIO_CB_WRITE, NULL, 5, 0, 0L, 0,
                                     NULL));
        {
            size_t processed = 3;
            printf("desc.readreturn.ret=%ld\n",
                   BIO_debug_callback_ex(sock, BIO_CB_READ | BIO_CB_RETURN,
                                         NULL, 16, 0, 0L, 7, &processed));
        }
        {
            size_t zero = 0;
            printf("desc.writereturn.ret=%ld\n",
                   BIO_debug_callback_ex(sock, BIO_CB_WRITE | BIO_CB_RETURN,
                                         NULL, 5, 0, 0L, -1, &zero));
        }
        BIO_free(sock);
        case_end("desc");
    }

    /* --- the deprecated wrapper, incl. its discarded return -------------- */
    {
        BIO_MMSG_CB_ARGS args;
        long r;

        memset(&args, 0, sizeof(args));
        args.num_msg = 4;

        case_begin();
        BIO_set_callback_ex(subject, NULL);
        r = BIO_debug_callback(subject, BIO_CB_RETURN | BIO_CB_RECVMMSG,
                               (const char *)&args, 4, 9L, 123L);
        printf("wrapper.recvmmsg.ret=%ld\n", r);
        case_end("wrapper.recvmmsg");
    }

    {
        BIO_MMSG_CB_ARGS args;
        size_t processed = 0;
        long r;

        memset(&args, 0, sizeof(args));
        args.num_msg = 4;

        case_begin();
        BIO_set_callback_ex(subject, NULL);
        r = BIO_debug_callback_ex(subject, BIO_CB_RETURN | BIO_CB_RECVMMSG,
                                  (const char *)&args, 4, 7, 9L, 123,
                                  &processed);
        printf("ex.recvmmsg.ret=%ld\n", r);
        case_end("ex.recvmmsg");
    }

    /* --- the pre-call RECVMMSG and SENDMMSG arms ------------------------- */
    {
        BIO_MMSG_CB_ARGS args;
        long r;

        memset(&args, 0, sizeof(args));
        args.num_msg = 4;

        case_begin();
        BIO_set_callback_ex(subject, NULL);
        r = BIO_debug_callback_ex(subject, BIO_CB_RECVMMSG, (const char *)&args,
                                  4, 7, 9L, 123, NULL);
        printf("pre.recvmmsg.ret=%ld\n", r);
        r = BIO_debug_callback_ex(subject, BIO_CB_SENDMMSG, (const char *)&args,
                                  4, 7, 9L, 123, NULL);
        printf("pre.sendmmsg.ret=%ld\n", r);
        case_end("pre");
    }

    /* --- an unknown command word ---------------------------------------- */
    {
        case_begin();
        BIO_set_callback_ex(subject, NULL);
        printf("unknown.ret=%ld\n",
               BIO_debug_callback_ex(subject, 0x3f, NULL, 0, 0, 0L, 5, NULL));
        case_end("unknown");
    }

    /* --- a NULL destination falls back to stderr. Observe the message itself,
     *     with the address masked, rather than letting a live address reach the
     *     capture and make this court's evidence identity irreproducible. ----- */
    {
        long r;
        int saved, capfd;
        FILE *cap;
        char raw[512];
        char esc[sizeof(raw) * 2];
        size_t got = 0;

        ERR_clear_error();
        subject = BIO_new(BIO_s_mem());
        BIO_set_callback_ex(subject, NULL);
        BIO_set_callback_arg(subject, NULL);

        cap = tmpfile();
        saved = dup(STDERR_FILENO);
        capfd = (cap != NULL) ? fileno(cap) : -1;
        if (saved >= 0 && capfd >= 0 && dup2(capfd, STDERR_FILENO) >= 0) {
            r = BIO_debug_callback_ex(subject, BIO_CB_CTRL, NULL, 0, 0, 0L, 7,
                                      NULL);
            fflush(stderr);
            dup2(saved, STDERR_FILENO);
        } else {
            /* No capture available: still drive the call. */
            r = BIO_debug_callback_ex(subject, BIO_CB_CTRL, NULL, 0, 0, 0L, 7,
                                      NULL);
            if (saved >= 0)
                dup2(saved, STDERR_FILENO);
        }
        if (saved >= 0)
            close(saved);
        if (cap != NULL) {
            rewind(cap);
            got = fread(raw, 1, sizeof(raw), cap);
            fclose(cap);
        }
        if (got > 0) {
            build_esc(raw, (long)got, esc, (long)sizeof(esc));
            printf("stderr.ctrl.text=%s\n", esc);
        } else {
            printf("stderr.ctrl.text=\n");
        }
        printf("stderr.ctrl.textlen=%lu\n", (unsigned long)got);
        printf("stderr.ctrl.ret=%ld\n", r);
        printf("stderr.ctrl.err0=%lu\n", ERR_peek_error());
        ERR_clear_error();
        BIO_free(subject);
        subject = NULL;
    }

    return 0;
}
