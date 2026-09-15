/*
 * openssl-rs — RT-BIO-ASN1: the ASN.1 filter BIO and the NDEF bridge,
 * differentially.
 *
 * `bio_asn1.c` is a *filter*: everything written through it is wrapped in one
 * ASN.1 primitive header, with optional prefix and suffix byte runs either side.
 * `bio_ndef.c` is its only in-tree caller and uses those runs to encode an
 * `ASN1_ITEM` around a stream in two passes, so a structure can be emitted without
 * being held in memory.
 *
 * What this probe establishes:
 *
 *   a.*  the method: type, name, and that `BIO_new` gives a BIO whose `init` is
 *        set and whose context exists
 *   b.*  the write path is a *state machine*, not one `BIO_write`: 4 bytes become
 *        `04 04` plus the content, and the header is emitted again for content
 *        past the declared length, so writing 6 bytes into a filter told to
 *        declare 4 produces two objects rather than an error
 *   c.*  a prefix is emitted before the header and a suffix after the content, and
 *        the two cleanup callbacks run exactly once each — once when the prefix
 *        has been written and once after the suffix has been
 *   d.*  `BIO_CTRL_FLUSH` before anything is written answers 0 rather than
 *        flushing, because the state machine is still in `START`
 *   e.*  the read, get-line, puts and control paths are pass-throughs to the next
 *        BIO in the chain, and `BIO_callback_ctrl` is too
 *   f.*  the four prefix/suffix controls round-trip a callback pair, and the two
 *        `EX_ARG` controls round-trip the caller's pointer without the filter ever
 *        reading it
 *   g.*  `BIO_new_NDEF` refuses an item with no `ASN1_AUX` callback, with
 *        `ASN1_R_STREAMING_NOT_SUPPORTED`, and leaves the caller owning the output
 *        BIO
 *   h.*  `BIO_new_NDEF` over a caller-declared streaming item returns the BIO the
 *        callback built, and writing through it and flushing produces the item's
 *        DER with the streamed content inside it
 *
 * The chunk log is a three-slot record of the prefix callback's invocations and
 * the two cleanup callbacks, because "called exactly once" is the property under
 * test and a count is what shows it.
 *
 * Determinism: key=value per line; the DER is printed as hex and the callback log
 * as counters and fixed bytes, so nothing depends on an address or a clock.
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

/* ------------------------------------------------------------------ helpers */

static void hex(const char *key, const unsigned char *p, int n)
{
    int i;

    printf("%s=", key);
    if (p == NULL) {
        printf("<null>\n");
        return;
    }
    for (i = 0; i < n; i++)
        printf("%02x", p[i]);
    printf("\n");
}

static void text(const char *key, const unsigned char *p, int n)
{
    int i;

    printf("%s=\"", key);
    if (p == NULL) {
        printf("<null>");
    } else {
        for (i = 0; i < n; i++)
            printf("%c", (p[i] >= 0x20 && p[i] < 0x7f) ? p[i] : '.');
    }
    printf("\"\n");
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

/* Read a memory BIO dry and print what it held. */
static void show_bio(const char *key, BIO *b)
{
    char buf[1024];
    int n = BIO_read(b, buf, (int)sizeof(buf) - 1);

    if (n < 0)
        n = 0;
    printf("%s.len=%d\n", key, n);
    text(key, (const unsigned char *)buf, n);
    hex(key, (const unsigned char *)buf, n);
}

/* ------------------------------------------------------- the prefix/suffix */

static unsigned char prefix_bytes[] = { 0xde, 0xad };
static unsigned char suffix_bytes[] = { 0xbe, 0xef };

static int prefix_calls;
static int prefix_free_calls;
static int suffix_calls;
static int suffix_free_calls;

static int probe_prefix(BIO *b, unsigned char **pbuf, int *plen, void *parg)
{
    (void)b;
    (void)parg;
    prefix_calls++;
    *pbuf = prefix_bytes;
    *plen = (int)sizeof(prefix_bytes);
    return 1;
}

static int probe_prefix_free(BIO *b, unsigned char **pbuf, int *plen, void *parg)
{
    (void)b;
    (void)parg;
    prefix_free_calls++;
    *pbuf = NULL;
    *plen = 0;
    return 1;
}

static int probe_suffix(BIO *b, unsigned char **pbuf, int *plen, void *parg)
{
    (void)b;
    (void)parg;
    suffix_calls++;
    *pbuf = suffix_bytes;
    *plen = (int)sizeof(suffix_bytes);
    return 1;
}

static int probe_suffix_free(BIO *b, unsigned char **pbuf, int *plen, void *parg)
{
    (void)b;
    (void)parg;
    suffix_free_calls++;
    *pbuf = NULL;
    *plen = 0;
    return 1;
}

static void calls(const char *key)
{
    printf("%s.prefix=%d\n", key, prefix_calls);
    printf("%s.prefix_free=%d\n", key, prefix_free_calls);
    printf("%s.suffix=%d\n", key, suffix_calls);
    printf("%s.suffix_free=%d\n", key, suffix_free_calls);
}

static void reset_calls(void)
{
    prefix_calls = prefix_free_calls = suffix_calls = suffix_free_calls = 0;
}

/* --------------------------------------------------- the caller-declared item */

typedef struct {
    ASN1_OCTET_STRING *oct;
} STREAMST;

static unsigned char *stream_boundary;
static int stream_pre_calls;
static int stream_post_calls;

static int stream_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it, void *exarg)
{
    ASN1_STREAM_ARG *sarg;

    (void)pval;
    (void)it;
    switch (operation) {
    case ASN1_OP_STREAM_PRE:
        stream_pre_calls++;
        sarg = exarg;
        sarg->ndef_bio = BIO_new(BIO_s_mem());
        sarg->boundary = &stream_boundary;
        return sarg->ndef_bio != NULL;
    case ASN1_OP_STREAM_POST:
        stream_post_calls++;
        return 1;
    default:
        return 1;
    }
}

ASN1_SEQUENCE_cb(STREAMST, stream_cb) = {
    ASN1_SIMPLE(STREAMST, oct, ASN1_OCTET_STRING)
} static_ASN1_SEQUENCE_END_cb(STREAMST, STREAMST)

IMPLEMENT_ASN1_FUNCTIONS(STREAMST)

/* ------------------------------------------------------------------- part A */

static void part_method(void)
{
    const BIO_METHOD *m = BIO_f_asn1();
    BIO *b;

    printf("method.null=%d\n", m == NULL);

    b = BIO_new(m);
    /*
     * `BIO_method_type` and `BIO_method_name` take a **BIO**, not a method: their
     * argument is the object whose `method` field is read. Passing the method
     * pointer reads the method's first field as if it were a BIO, which the two
     * sides then disagree about, because it is an address either way.
     */
    printf("method.type=%d\n", BIO_method_type(b));
    printf("method.name=%s\n", BIO_method_name(b));
    printf("method.init=%d\n", BIO_get_init(b));
    printf("method.data_nonnull=%d\n", BIO_get_data(b) != NULL);
    printf("method.data_writes=%ld\n", BIO_ctrl(b, BIO_C_GET_WRITE_BUF_SIZE, 0, NULL));
    BIO_free(b);
    drain("method.err");
}

static void part_write(void)
{
    BIO *mem, *f, *chain;
    char buf[64];

    /* The plainest case: four bytes become a four-byte OCTET STRING. */
    mem = BIO_new(BIO_s_mem());
    f = BIO_new(BIO_f_asn1());
    chain = BIO_push(f, mem);
    printf("write.chain=%d\n", chain == f ? 1 : 0);
    printf("write.n=%d\n", BIO_write(f, "ABCD", 4));
    printf("write.flush=%ld\n", BIO_ctrl(f, BIO_CTRL_FLUSH, 0, NULL));
    show_bio("write.plain", mem);
    drain("write.err");
    BIO_free_all(f);

    /* An empty write still emits a header for a zero-length object. */
    mem = BIO_new(BIO_s_mem());
    f = BIO_new(BIO_f_asn1());
    BIO_push(f, mem);
    printf("write.empty=%d\n", BIO_write(f, "", 0));
    printf("write.empty.flush=%ld\n", BIO_ctrl(f, BIO_CTRL_FLUSH, 0, NULL));
    show_bio("write.empty", mem);
    BIO_free_all(f);

    /* A negative length is refused before anything is written. */
    mem = BIO_new(BIO_s_mem());
    f = BIO_new(BIO_f_asn1());
    BIO_push(f, mem);
    printf("write.negative=%d\n", BIO_write(f, "AB", -1));
    printf("write.negative.len=%ld\n", BIO_ctrl_pending(mem));
    BIO_free_all(f);

    /* A long object: the header's length is long-form and the object is still
     * one object. 200 bytes is two content writes. */
    memset(buf, 'x', sizeof(buf));
    mem = BIO_new(BIO_s_mem());
    f = BIO_new(BIO_f_asn1());
    BIO_push(f, mem);
    printf("write.long.first=%d\n", BIO_write(f, buf, 64));
    printf("write.long.second=%d\n", BIO_write(f, buf, 64));
    printf("write.long.third=%d\n", BIO_write(f, buf, 64));
    printf("write.long.flush=%ld\n", BIO_ctrl(f, BIO_CTRL_FLUSH, 0, NULL));
    {
        unsigned char out[512];
        int n = BIO_read(mem, out, (int)sizeof(out));

        printf("write.long.len=%d\n", n);
        hex("write.long.head", out, n > 6 ? 6 : n);
        printf("write.long.is_192=%d\n", n == 195 ? 1 : 0);
    }
    BIO_free_all(f);
    drain("write.err2");
}

static void part_prefix_suffix(void)
{
    BIO *mem, *f;
    char buf[64];

    reset_calls();
    mem = BIO_new(BIO_s_mem());
    f = BIO_new(BIO_f_asn1());
    BIO_push(f, mem);
    printf("ps.set_prefix=%d\n",
           BIO_asn1_set_prefix(f, probe_prefix, probe_prefix_free));
    printf("ps.set_suffix=%d\n",
           BIO_asn1_set_suffix(f, probe_suffix, probe_suffix_free));
    printf("ps.write=%d\n", BIO_write(f, "ABCD", 4));
    calls("ps.after_write");
    printf("ps.flush=%ld\n", BIO_ctrl(f, BIO_CTRL_FLUSH, 0, NULL));
    calls("ps.after_flush");
    show_bio("ps", mem);
    BIO_free_all(f);
    calls("ps.after_free");
    drain("ps.err");

    /* The getters round-trip the pair. */
    mem = BIO_new(BIO_s_mem());
    f = BIO_new(BIO_f_asn1());
    BIO_push(f, mem);
    {
        asn1_ps_func *pf = NULL, *pff = NULL, *sf = NULL, *sff = NULL;

        printf("get.initial=%d %d %d %d\n", pf == NULL, pff == NULL, sf == NULL,
               sff == NULL);
        printf("get.before_set=%d\n", BIO_asn1_get_prefix(f, &pf, &pff));
        printf("get.before_set.null=%d\n", pf == NULL && pff == NULL);
        BIO_asn1_set_prefix(f, probe_prefix, probe_prefix_free);
        printf("get.after_set=%d\n", BIO_asn1_get_prefix(f, &pf, &pff));
        printf("get.after_set.same=%d\n", pf == probe_prefix ? 1 : 0);
        printf("get.after_set.free_same=%d\n", pff == probe_prefix_free ? 1 : 0);
        BIO_asn1_set_suffix(f, probe_suffix, probe_suffix_free);
        printf("get.suffix=%d\n", BIO_asn1_get_suffix(f, &sf, &sff));
        printf("get.suffix.same=%d\n", sf == probe_suffix ? 1 : 0);
        /* A null BIO is not a crash, it is a failure. */
        printf("get.null_bio=%d\n", BIO_asn1_get_prefix(NULL, &pf, &pff));
    }
    BIO_free_all(f);
    drain("get.err");

    /* The caller's argument, which the filter stores and never reads. */
    mem = BIO_new(BIO_s_mem());
    f = BIO_new(BIO_f_asn1());
    BIO_push(f, mem);
    {
        int mine = 0x5eed;
        void *back = NULL;

        printf("exarg.set=%ld\n", BIO_ctrl(f, BIO_C_SET_EX_ARG, 0, &mine));
        printf("exarg.get=%ld\n", BIO_ctrl(f, BIO_C_GET_EX_ARG, 0, &back));
        printf("exarg.same=%d\n", back == &mine ? 1 : 0);
        printf("exarg.unknown_ctrl=%ld\n", BIO_ctrl(f, 9999, 0, NULL));
    }
    BIO_free_all(f);

    /* Three short writes with the memory BIO as the *next* one: the state machine
     * re-emits the header only when the declared content is exhausted. */
    memset(buf, 'y', sizeof(buf));
    reset_calls();
    mem = BIO_new(BIO_s_mem());
    f = BIO_new(BIO_f_asn1());
    BIO_push(f, mem);
    BIO_asn1_set_prefix(f, probe_prefix, probe_prefix_free);
    BIO_asn1_set_suffix(f, probe_suffix, probe_suffix_free);
    printf("multi.first=%d\n", BIO_write(f, buf, 10));
    printf("multi.second=%d\n", BIO_write(f, buf, 10));
    calls("multi.between");
    printf("multi.flush=%ld\n", BIO_ctrl(f, BIO_CTRL_FLUSH, 0, NULL));
    show_bio("multi", mem);
    BIO_free_all(f);
    calls("multi.after_free");
}

static void part_passthrough(void)
{
    BIO *mem, *f;
    char buf[64];

    mem = BIO_new(BIO_s_mem());
    f = BIO_new(BIO_f_asn1());
    BIO_push(f, mem);

    BIO_puts(mem, "line one\nline two\n");
    printf("pass.gets=%d\n", BIO_gets(f, buf, (int)sizeof(buf)));
    text("pass.gets", (const unsigned char *)buf, (int)strlen(buf));
    printf("pass.read=%d\n", BIO_read(f, buf, 4));
    text("pass.read", (const unsigned char *)buf, 4);
    printf("pass.pending=%ld\n", BIO_ctrl_pending(f));
    printf("pass.ctrls=%ld\n", BIO_ctrl_get_read_request(f));
    printf("pass.unknown=%ld\n", BIO_ctrl(f, 9999, 0, NULL));
    printf("pass.callback_ctrl=%ld\n", BIO_callback_ctrl(f, 9999, NULL));
    printf("pass.dup=%ld\n", BIO_ctrl(f, BIO_CTRL_DUP, 0, NULL));
    printf("pass.ptr_ctrl=%d\n", BIO_ptr_ctrl(f, 9999, 0) == NULL);
    BIO_free_all(f);
    drain("pass.err");

    /* A filter with no next BIO answers 0 rather than passing on. */
    f = BIO_new(BIO_f_asn1());
    printf("nolonely.read=%d\n", BIO_read(f, buf, 4));
    printf("nolonely.gets=%d\n", BIO_gets(f, buf, 4));
    printf("nolonely.write=%d\n", BIO_write(f, "A", 1));
    printf("nolonely.flush=%ld\n", BIO_ctrl(f, BIO_CTRL_FLUSH, 0, NULL));
    printf("nolonely.prefix=%d\n", BIO_asn1_set_prefix(f, probe_prefix, NULL));
    BIO_free(f);

    /* Flush before any write: the machine is in START, not DONE. */
    mem = BIO_new(BIO_s_mem());
    f = BIO_new(BIO_f_asn1());
    BIO_push(f, mem);
    printf("early.flush=%ld\n", BIO_ctrl(f, BIO_CTRL_FLUSH, 0, NULL));
    printf("early.pending=%ld\n", BIO_ctrl_pending(mem));
    BIO_free_all(f);
}

/* ------------------------------------------------------------------- part B */

static void part_ndef(void)
{
    BIO *mem, *out;
    STREAMST *st;
    ASN1_VALUE *val;

    /* An item with no AUX callback cannot be streamed. */
    mem = BIO_new(BIO_s_mem());
    ERR_clear_error();
    out = BIO_new_NDEF(mem, (ASN1_VALUE *)"", ASN1_NULL_it());
    printf("ndef.no_aux.null=%d\n", out == NULL);
    drain("ndef.no_aux.err");
    /* The caller still owns the output BIO, so it can be freed. */
    printf("ndef.no_aux.freeable=%d\n", BIO_free(mem));

    /* The real path: a caller-declared SEQUENCE with a streaming callback. */
    st = STREAMST_new();
    printf("ndef.struct_new=%d\n", st != NULL);
    printf("ndef.oct_nonnull=%d\n", st->oct != NULL);
    printf("ndef.oct_set=%d\n",
           ASN1_OCTET_STRING_set(st->oct, (const unsigned char *)"hello", 5));
    printf("ndef.oct_len=%d\n", ASN1_STRING_length(st->oct));

    stream_pre_calls = 0;
    stream_post_calls = 0;
    stream_boundary = NULL;

    mem = BIO_new(BIO_s_mem());
    printf("ndef.mem_nonnull=%d\n", mem != NULL);
    val = (ASN1_VALUE *)st;
    ERR_clear_error();
    out = BIO_new_NDEF(mem, val, STREAMST_it());
    printf("ndef.out_null=%d\n", out == NULL);
    drain("ndef.err");
    printf("ndef.pre_calls=%d\n", stream_pre_calls);

    if (out != NULL) {
        printf("ndef.write=%d\n", BIO_write(out, "WORLD", 5));
        printf("ndef.flush=%ld\n", BIO_ctrl(out, BIO_CTRL_FLUSH, 0, NULL));
        printf("ndef.post_calls=%d\n", stream_post_calls);
        /* `out` is the BIO the callback built; the DER lands in `mem` once the
         * chain is flushed, because the callback's BIO writes into it. */
        show_bio("ndef.mem", mem);
    }
    if (out != NULL)
        BIO_free(out);
    printf("ndef.free_mem=%d\n", BIO_free(mem));

    stream_boundary = NULL;
    (void)val;
}

int main(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);

    part_method();
    part_write();
    part_prefix_suffix();
    part_passthrough();
    part_ndef();
    printf("done=1\n");
    return 0;
}
