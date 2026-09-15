/*
 * openssl-rs — RT-ASN1-MIME: `SMIME_crlf_copy` and `i2d_ASN1_bio_stream`,
 * differentially.
 *
 * `asn_mime.c`'s copying half needs nothing but the BIO layer, which is why it is
 * Phase 5's rather than Phase 12's. This probe drives both exports.
 *
 * What this probe establishes:
 *
 *   a.*  the two null-argument refusals, each with `ERR_R_PASSED_NULL_PARAMETER`
 *   b.*  `SMIME_BINARY` copies verbatim, and so does `CMS_BINARY`, which is the
 *        `cms.h` spelling of the same bit and the same branch
 *   c.*  the text policy: a line's terminator is rewritten to `\r\n`, an unterminated
 *        final line gets none, and the `Content-Type: text/plain` block is written
 *        only under `SMIME_TEXT`
 *   d.*  `SMIME_ASCIICRLF` holds blank lines back and re-emits them as a `\r\n` run
 *        *before* the next non-empty line, and drops a trailing space on a line whose
 *        EOL has already been seen
 *   e.*  the copy runs through a `BIO_f_buffer`, so the sink sees the body in the
 *        filter's blocks rather than one line per write, and `SMIME_crlf_copy` pops
 *        that filter again so the caller's sink is left as it was found
 *   f.*  a sink that reports a short write makes the copy answer 0, and the flush is
 *        combined as `flush > 0 && copied`, so a failing flush also answers 0 while a
 *        failing copy cannot be flushed back into a success
 *   g.*  `i2d_ASN1_bio_stream` without `SMIME_STREAM` encodes the whole structure
 *        through `ASN1_item_i2d_bio` and leaves the input BIO untouched
 *   h.*  with `SMIME_STREAM` it frames the structure around a stream: the NDEF
 *        prefix and suffix reach the output, the input BIO is drained, and the
 *        streaming callback runs exactly once at each end
 *
 * Determinism: key=value per line, every payload hexed, and the sink's write log
 * reduced to a count and a length list, so nothing depends on an address or a clock.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/objects.h>

#include <stdio.h>
#include <string.h>

/* `pkcs7.h`'s and `cms.h`'s flags, spelled here so the probe does not depend on
 * which header a build happens to pull in. */
#define P_SMIME_TEXT      0x1
#define P_SMIME_BINARY    0x80
#define P_CMS_BINARY      0x80
#define P_SMIME_CRLFEOL   0x800
#define P_SMIME_STREAM    0x1000
#define P_SMIME_ASCIICRLF 0x80000

/* --------------------------------------------------------------- a logged sink */

static BIO *sink_mem;
static int sink_writes;
static int sink_nsizes;
static int sink_sizes[64];
static int sink_fail_at;      /* fail the write with this index; -1 never */
static long sink_flush;       /* what BIO_CTRL_FLUSH answers */

static int sink_write(BIO *b, const char *data, int len)
{
    (void)b;
    if (sink_fail_at >= 0 && sink_writes >= sink_fail_at)
        return 0;
    sink_writes++;
    if (sink_nsizes < (int)(sizeof(sink_sizes) / sizeof(sink_sizes[0])))
        sink_sizes[sink_nsizes++] = len;
    if (BIO_write(sink_mem, data, len) != len)
        return 0;
    return len;
}

static long sink_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    (void)b;
    (void)num;
    (void)ptr;
    if (cmd == BIO_CTRL_FLUSH)
        return sink_flush;
    return 0;
}

/* --------------------------------------------------------------- the log output */

static void reset_sink(void)
{
    sink_writes = 0;
    sink_nsizes = 0;
    sink_fail_at = -1;
    sink_flush = 1;
}

static void show_log(const char *key)
{
    int i;

    printf("%s.writes=%d\n", key, sink_writes);
    printf("%s.nsizes=%d\n", key, sink_nsizes);
    printf("%s.sizes=", key);
    for (i = 0; i < sink_nsizes; i++)
        printf("%s%d", i ? "," : "", sink_sizes[i]);
    printf("\n");
}

/* Read a memory BIO dry and hex it. */
static void show_bio(const char *key, BIO *b)
{
    unsigned char buf[4096];
    int n, i;

    n = BIO_read(b, buf, (int)sizeof(buf));
    if (n < 0)
        n = 0;
    printf("%s.len=%d\n", key, n);
    printf("%s=", key);
    for (i = 0; i < n; i++)
        printf("%02x", buf[i]);
    printf("\n");
    printf("%s.text=\"", key);
    for (i = 0; i < n; i++)
        printf("%c", (buf[i] >= 0x20 && buf[i] < 0x7f) ? buf[i] : '.');
    printf("\"\n");
}

static BIO *in_from(const char *p)
{
    BIO *b = BIO_new(BIO_s_mem());

    if (b != NULL)
        BIO_write(b, p, (int)strlen(p));
    return b;
}

static void drain(const char *key)
{
    unsigned long e;
    const char *file, *func, *data;
    int line, flags, first = 1;

    printf("%s=", key);
    while ((e = ERR_get_error_all(&file, &line, &func, &data, &flags)) != 0) {
        const char *rsn = ERR_reason_error_string(e);

        if (!first)
            printf(",");
        printf("%s", rsn == NULL ? "<no-string>" : rsn);
        if (data != NULL)
            printf("[%s]", data);
        first = 0;
    }
    if (first)
        printf("<empty>");
    printf("\n");
    ERR_clear_error();
}

/* ------------------------------------------------------- a. the null refusals */

static void part_null(void)
{
    BIO *out = BIO_new(BIO_s_mem());
    BIO *in = in_from("x\n");

    printf("a.null_in=%d\n", SMIME_crlf_copy(NULL, out, 0));
    drain("a.null_in_errors");
    printf("a.null_out=%d\n", SMIME_crlf_copy(in, NULL, 0));
    drain("a.null_out_errors");
    printf("a.both_null=%d\n", SMIME_crlf_copy(NULL, NULL, 0));
    drain("a.both_null_errors");
    BIO_free(in);
    BIO_free(out);
}

/* ---------------------------------------------- b. the two binary modes */

static void part_binary(void)
{
    static const char *bodies[] = {
        "a\r\nb\nc", "x\ny\n", "", "no-newline-at-all", "trailing\r\n",
    };
    size_t i;

    for (i = 0; i < sizeof(bodies) / sizeof(bodies[0]); i++) {
        BIO_METHOD *m = BIO_meth_new(BIO_TYPE_SOURCE_SINK, "probe-sink");
        BIO *sink;
        BIO *in;
        int r;
        char key[64];

        BIO_meth_set_write(m, sink_write);
        BIO_meth_set_ctrl(m, sink_ctrl);
        sink = BIO_new(m);
        sink_mem = BIO_new(BIO_s_mem());
        reset_sink();
        in = in_from(bodies[i]);
        r = SMIME_crlf_copy(in, sink, P_SMIME_BINARY);
        sprintf(key, "b.binary_%d", (int)i);
        printf("%s.ret=%d\n", key, r);
        show_log(key);
        sprintf(key, "b.binary_%d.out", (int)i);
        show_bio(key, sink_mem);
        BIO_free(in);
        BIO_free(sink_mem);
        BIO_free(sink);
        BIO_meth_free(m);

        /* The same body under `cms.h`'s spelling of the flag. */
        m = BIO_meth_new(BIO_TYPE_SOURCE_SINK, "probe-sink");
        BIO_meth_set_write(m, sink_write);
        BIO_meth_set_ctrl(m, sink_ctrl);
        sink = BIO_new(m);
        sink_mem = BIO_new(BIO_s_mem());
        reset_sink();
        in = in_from(bodies[i]);
        r = SMIME_crlf_copy(in, sink, P_CMS_BINARY);
        sprintf(key, "b.cmsbinary_%d", (int)i);
        printf("%s.ret=%d\n", key, r);
        show_log(key);
        BIO_free(in);
        BIO_free(sink_mem);
        BIO_free(sink);
        BIO_meth_free(m);
    }
}

/* ------------------------------------------------------ c.d. the text policy */

struct policy {
    const char *name;
    int flags;
    const char *body;
};

static const struct policy policies[] = {
    { "plain",        0,                              "a\nb\n" },
    { "plain_crlf",   0,                              "a\r\nb\r\n" },
    { "plain_unterm", 0,                              "a\nb" },
    { "plain_empty",  0,                              "\n\n" },
    { "text",         P_SMIME_TEXT,                   "a\nb\n" },
    { "crlfeol",      P_SMIME_CRLFEOL,                "a\nb\n" },
    { "crlfeol_crlf", P_SMIME_CRLFEOL,                "a\r\nb\r\n" },
    { "asciicrlf",    P_SMIME_ASCIICRLF,              "a\n\n\nb\n" },
    { "asciicrlf_trailspace", P_SMIME_ASCIICRLF,      "a \n\n\nb\n" },
    { "asciicrlf_text", P_SMIME_ASCIICRLF | P_SMIME_TEXT, "a\n\nb\n" },
    { "asciicrlf_crlfeol", P_SMIME_ASCIICRLF | P_SMIME_CRLFEOL, "a\n\nb\n" },
    { "binary_or",    P_SMIME_BINARY | P_SMIME_TEXT,   "a\nb\n" },
};

static void part_text(void)
{
    size_t i;

    for (i = 0; i < sizeof(policies) / sizeof(policies[0]); i++) {
        BIO_METHOD *m = BIO_meth_new(BIO_TYPE_SOURCE_SINK, "probe-sink");
        BIO *sink;
        BIO *in;
        int r;
        char key[80];

        BIO_meth_set_write(m, sink_write);
        BIO_meth_set_ctrl(m, sink_ctrl);
        sink = BIO_new(m);
        sink_mem = BIO_new(BIO_s_mem());
        reset_sink();
        in = in_from(policies[i].body);
        r = SMIME_crlf_copy(in, sink, policies[i].flags);
        sprintf(key, "c.%s", policies[i].name);
        printf("%s.ret=%d\n", key, r);
        show_log(key);
        sprintf(key, "c.%s.out", policies[i].name);
        show_bio(key, sink_mem);
        BIO_free(in);
        BIO_free(sink_mem);
        BIO_free(sink);
        BIO_meth_free(m);
    }
}

/* -------------------------------------------- e.f. sinks, blocks and failures */

static void part_sink(void)
{
    /* The body is buffered, so a three-line copy is one write to the sink. */
    {
        BIO_METHOD *m = BIO_meth_new(BIO_TYPE_SOURCE_SINK, "probe-sink");
        BIO *sink = BIO_new(m);
        BIO *in = in_from("aaa\nbbb\nccc\n");

        BIO_meth_set_write(m, sink_write);
        BIO_meth_set_ctrl(m, sink_ctrl);
        sink_mem = BIO_new(BIO_s_mem());
        reset_sink();
        printf("e.blocked_ret=%d\n", SMIME_crlf_copy(in, sink, 0));
        show_log("e.blocked");
        /* The filter is popped again, so the caller's sink is chain-free. */
        printf("e.sink_next=%d\n", BIO_next(sink) == NULL);
        BIO_free(in);
        BIO_free(sink_mem);
        BIO_free(sink);
        BIO_meth_free(m);
    }

    /* A sink that refuses the first write. */
    {
        BIO_METHOD *m = BIO_meth_new(BIO_TYPE_SOURCE_SINK, "probe-sink");
        BIO *sink = BIO_new(m);
        BIO *in = in_from("aaa\nb\n");

        BIO_meth_set_write(m, sink_write);
        BIO_meth_set_ctrl(m, sink_ctrl);
        sink_mem = BIO_new(BIO_s_mem());
        reset_sink();
        sink_fail_at = 0;
        printf("f.fail_write_ret=%d\n", SMIME_crlf_copy(in, sink, 0));
        show_log("f.fail_write");
        drain("f.fail_write_errors");
        BIO_free(in);
        BIO_free(sink_mem);
        BIO_free(sink);
        BIO_meth_free(m);
    }

    /* A sink whose flush fails: the copy succeeded, the answer must not. */
    {
        BIO_METHOD *m = BIO_meth_new(BIO_TYPE_SOURCE_SINK, "probe-sink");
        BIO *sink = BIO_new(m);
        BIO *in = in_from("aaa\nb\n");

        BIO_meth_set_write(m, sink_write);
        BIO_meth_set_ctrl(m, sink_ctrl);
        sink_mem = BIO_new(BIO_s_mem());
        reset_sink();
        sink_flush = 0;
        printf("f.fail_flush_ret=%d\n", SMIME_crlf_copy(in, sink, 0));
        show_log("f.fail_flush");
        show_bio("f.fail_flush.out", sink_mem);
        BIO_free(in);
        BIO_free(sink_mem);
        BIO_free(sink);
        BIO_meth_free(m);
    }

    /* An input BIO that answers nothing at all: the copy succeeds with no output. */
    {
        BIO *sink = BIO_new(BIO_s_mem());
        BIO *in = BIO_new(BIO_s_mem());

        printf("f.empty_ret=%d\n", SMIME_crlf_copy(in, sink, 0));
        show_bio("f.empty.out", sink);
        BIO_free(in);
        BIO_free(sink);
    }
}

/* ---------------------------------------------- g.h. i2d_ASN1_bio_stream */

typedef struct {
    ASN1_OCTET_STRING *oct;
} MIMEST;

static unsigned char *mime_boundary;
static int mime_pre_calls;
static int mime_post_calls;

static int mime_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it, void *exarg)
{
    ASN1_STREAM_ARG *sarg;

    (void)pval;
    (void)it;
    switch (operation) {
    case ASN1_OP_STREAM_PRE:
        mime_pre_calls++;
        sarg = exarg;
        /*
         * The stream is written *through* the ASN.1 filter, which is what
         * `sarg->out` already is at this point: `BIO_new_NDEF` pushed the filter
         * onto the caller's output before calling this. Answering `sarg->out` also
         * keeps the caller's output in the chain, which is what
         * `i2d_ASN1_bio_stream`'s unwind loop walks back to. A BIO that is *not* in
         * that chain makes the authority's loop spin forever; see D-MIME-1.
         */
        sarg->ndef_bio = sarg->out;
        sarg->boundary = &mime_boundary;
        return 1;
    case ASN1_OP_STREAM_POST:
        mime_post_calls++;
        return 1;
    default:
        return 1;
    }
}

ASN1_SEQUENCE_cb(MIMEST, mime_cb) = {
    ASN1_SIMPLE(MIMEST, oct, ASN1_OCTET_STRING)
} static_ASN1_SEQUENCE_END_cb(MIMEST, MIMEST)

IMPLEMENT_ASN1_FUNCTIONS(MIMEST)

static void part_stream(void)
{
    MIMEST *m = MIMEST_new();
    BIO *out;
    BIO *in;
    unsigned char *der = NULL;
    int n;

    if (m == NULL) {
        printf("g.new=0\n");
        return;
    }
    printf("g.new=1\n");
    ASN1_STRING_set(m->oct, "STREAMED", 8);

    /* The whole-structure encoding, for comparison. */
    n = i2d_MIMEST(m, &der);
    printf("g.whole_der_len=%d\n", n);
    {
        int i;

        printf("g.whole_der=");
        for (i = 0; i < n; i++)
            printf("%02x", der[i]);
        printf("\n");
    }
    OPENSSL_free(der);

    /* Without SMIME_STREAM: the structure is encoded whole and `in` is untouched. */
    out = BIO_new(BIO_s_mem());
    in = in_from("BODY");
    printf("g.nostream_ret=%d\n",
        i2d_ASN1_bio_stream(out, (ASN1_VALUE *)m, in, 0, ASN1_ITEM_rptr(MIMEST)));
    show_bio("g.nostream.out", out);
    printf("g.nostream_in_pending=%ld\n", BIO_ctrl(in, BIO_CTRL_PENDING, 0, NULL));
    BIO_free(in);
    BIO_free(out);

    /* With SMIME_STREAM: the structure frames the stream and `in` is drained. */
    out = BIO_new(BIO_s_mem());
    in = in_from("stream-body\n");
    mime_pre_calls = 0;
    mime_post_calls = 0;
    mime_boundary = NULL;
    printf("g.stream_ret=%d\n",
        i2d_ASN1_bio_stream(out, (ASN1_VALUE *)m, in, P_SMIME_STREAM,
            ASN1_ITEM_rptr(MIMEST)));
    printf("g.stream_pre_calls=%d\n", mime_pre_calls);
    printf("g.stream_post_calls=%d\n", mime_post_calls);
    show_bio("g.stream.out", out);
    printf("g.stream_in_pending=%ld\n", BIO_ctrl(in, BIO_CTRL_PENDING, 0, NULL));
    BIO_free(in);
    BIO_free(out);

    /* The same under SMIME_STREAM | SMIME_BINARY, which copies verbatim. */
    out = BIO_new(BIO_s_mem());
    in = in_from("bin\n");
    mime_pre_calls = 0;
    mime_post_calls = 0;
    mime_boundary = NULL;
    printf("g.streambin_ret=%d\n",
        i2d_ASN1_bio_stream(out, (ASN1_VALUE *)m, in, P_SMIME_STREAM | P_SMIME_BINARY,
            ASN1_ITEM_rptr(MIMEST)));
    printf("g.streambin_pre_calls=%d\n", mime_pre_calls);
    printf("g.streambin_post_calls=%d\n", mime_post_calls);
    show_bio("g.streambin.out", out);
    BIO_free(in);
    BIO_free(out);

    MIMEST_free(m);
}

/* --------------------------------------------------------------- the driver */

int main(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);

    part_null();
    part_binary();
    part_text();
    part_sink();
    part_stream();

    printf("done=1\n");
    return 0;
}
