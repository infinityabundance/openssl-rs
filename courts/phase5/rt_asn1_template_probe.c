/*
 * openssl-rs — RT-ASN1-TEMPLATE: the template interpreter and the primitive hooks,
 * differentially.
 *
 * This probe exists because nothing before it drove `asn1_item_embed_d2i` and
 * `ASN1_item_ex_i2d` through a **caller-built** descriptor. The items this stratum
 * defines reach the decoder's `PRIMITIVE` arm and little else, so every other arm —
 * `CHOICE`, `SEQUENCE`, the `SEQUENCE OF`/`SET OF` content writer, the `EMBED` field
 * indirection, the `OPTIONAL` absent answer — was implemented without a differential
 * observation. A built-in item cannot exercise them: the shape of the item *is* the
 * thing under test.
 *
 * So the probe declares its own structures, its own `ASN1_SEQUENCE` and `ASN1_CHOICE`
 * templates, and its own instances of the twelve primitive-hook items, and drives them
 * through the public `ASN1_item_*` entry points. The same source is compiled against the
 * authority's headers and the candidate's, and the two transcripts are compared line by
 * line.
 *
 * What it establishes, by observation rather than by argument:
 *
 *   a.*  an `EMBED` field is inline and an `OPTIONAL` field is omitted when absent, and
 *        both survive a round trip
 *   b.*  a truncated encoding, a wrong outer tag and a wrong inner tag each fail with a
 *        specific reason on the queue, and the value is not left half-built
 *   c.*  a `CHOICE` selects by the encoding's tag, and a tag that matches no alternative
 *        fails as such
 *   d.*  a `SET OF` is emitted in canonical order and a `SEQUENCE OF` is not
 *   e.*  a primitive item's value lives where the item says it does — behind the slot for
 *        `INT32`/`BIGNUM`, *in* the slot for `LONG`/`ZLONG` — and `ZERO_DEFAULT` turns a
 *        zero into an absent field
 *   f.*  the two `ASN1_TYPE` octet-string pairs the header declares round-trip, and the
 *        int-pair's encoding is the sequence the template says it is
 *
 * Determinism: nothing here prints an address, a length that depends on the allocator, or
 * a reason code that varies. Every line is `key=value` and the court compares them
 * key-wise.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/stack.h>
#include <openssl/x509.h>

#include <stdint.h>
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

/*
 * Print and clear whatever is on the queue as a comma-separated list of reason codes. The
 * library and file/line are deliberately not printed: the file path embeds the build
 * prefix, which differs between the two sides, and the reasons are what the contract is.
 */
static void drain(const char *key)
{
    unsigned long e;
    int first = 1;

    printf("%s=", key);
    while ((e = ERR_get_error()) != 0) {
        const char *lib = ERR_lib_error_string(e);
        const char *rsn = ERR_reason_error_string(e);

        if (!first)
            printf(",");
        /*
         * The library and the reason string as well as the code. Both are static strings
         * from the library's own tables, so they are deterministic across the two sides,
         * and without them a bare number cannot be told from the same number in another
         * library — which is exactly the ambiguity `ERR_GET_REASON` leaves.
         */
        printf("%d:%s:%s", ERR_GET_LIB(e), lib != NULL ? lib : "?",
               rsn != NULL ? rsn : "?");
        first = 0;
    }
    printf("\n");
}

static void clear_queue(void)
{
    ERR_clear_error();
}

/* ------------------------------------------- a. a SEQUENCE the probe declares */

typedef struct {
    int32_t num;                 /* ASN1_EMBED: inline, at offset 0 */
    ASN1_OCTET_STRING *oct;      /* ASN1_SIMPLE */
    ASN1_IA5STRING *opt;         /* ASN1_OPT: absent when NULL */
} probe_seq;

ASN1_SEQUENCE(probe_seq) = {
    ASN1_EMBED(probe_seq, num, INT32),
    ASN1_SIMPLE(probe_seq, oct, ASN1_OCTET_STRING),
    ASN1_OPT(probe_seq, opt, ASN1_IA5STRING)
} static_ASN1_SEQUENCE_END(probe_seq)

/* --------------------------------------------- c. a CHOICE the probe declares */

typedef struct {
    int type;
    union {
        ASN1_OCTET_STRING *oct;
        ASN1_INTEGER *intg;
    } value;
} probe_choice;

ASN1_CHOICE(probe_choice) = {
    ASN1_SIMPLE(probe_choice, value.oct, ASN1_OCTET_STRING),
    ASN1_SIMPLE(probe_choice, value.intg, ASN1_INTEGER)
} static_ASN1_CHOICE_END(probe_choice)

/* ------------------------------------------------------------ a. SEQUENCE */

static void part_sequence(void)
{
    probe_seq *s = ASN1_item_new(ASN1_ITEM_rptr(probe_seq));
    unsigned char *der = NULL;
    const unsigned char *p;
    probe_seq *t;
    int n;

    printf("a.new_nonnull=%d\n", s != NULL);
    if (s == NULL)
        return;

    /* A magnitude whose top bit is clear, so no padding octet is needed. */
    s->num = 0x1234567;
    printf("a.oct_set=%d\n",
           ASN1_OCTET_STRING_set(s->oct, (const unsigned char *)"\x01\x02\x03", 3));

    /* The OPTIONAL field is absent: it must not appear at all. */
    n = ASN1_item_i2d((const ASN1_VALUE *)s, &der, ASN1_ITEM_rptr(probe_seq));
    printf("a.len_opt_absent=%d\n", n);
    hex("a.der_opt_absent", der, n);

    p = der;
    t = ASN1_item_d2i(NULL, &p, n, ASN1_ITEM_rptr(probe_seq));
    printf("a.rt_opt_absent_nonnull=%d\n", t != NULL);
    if (t != NULL) {
        printf("a.rt_num=%d\n", (int)t->num);
        printf("a.rt_oct_len=%d\n", ASN1_STRING_length(t->oct));
        printf("a.rt_oct_data=");
        {
            const unsigned char *d = ASN1_STRING_get0_data(t->oct);
            int i, l = ASN1_STRING_length(t->oct);

            for (i = 0; i < l; i++)
                printf("%02x", d[i]);
            printf("\n");
        }
        printf("a.rt_opt_is_null=%d\n", t->opt == NULL);
        printf("a.rt_consumed=%d\n", (int)(p - der));
        ASN1_item_free((ASN1_VALUE *)t, ASN1_ITEM_rptr(probe_seq));
    }
    OPENSSL_free(der);
    der = NULL;

    /* The same value with the OPTIONAL field present. */
    s->opt = ASN1_IA5STRING_new();
    printf("a.opt_set=%d\n",
           ASN1_STRING_set((ASN1_STRING *)s->opt, (const void *)"hello", 5));
    n = ASN1_item_i2d((const ASN1_VALUE *)s, &der, ASN1_ITEM_rptr(probe_seq));
    printf("a.len_opt_present=%d\n", n);
    hex("a.der_opt_present", der, n);

    p = der;
    t = ASN1_item_d2i(NULL, &p, n, ASN1_ITEM_rptr(probe_seq));
    printf("a.rt_opt_present_nonnull=%d\n", t != NULL);
    if (t != NULL) {
        printf("a.rt_opt_len=%d\n", ASN1_STRING_length(t->opt));
        ASN1_item_free((ASN1_VALUE *)t, ASN1_ITEM_rptr(probe_seq));
    }
    OPENSSL_free(der);
    der = NULL;

    /* A negative value, which the item encodes as a magnitude with a sign. */
    s->num = -5;
    n = ASN1_item_i2d((const ASN1_VALUE *)s, &der, ASN1_ITEM_rptr(probe_seq));
    printf("a.len_negative=%d\n", n);
    hex("a.der_negative", der, n);
    p = der;
    t = ASN1_item_d2i(NULL, &p, n, ASN1_ITEM_rptr(probe_seq));
    if (t != NULL) {
        printf("a.rt_negative_num=%d\n", (int)t->num);
        ASN1_item_free((ASN1_VALUE *)t, ASN1_ITEM_rptr(probe_seq));
    }
    OPENSSL_free(der);
    der = NULL;

    /* Zero, which INT32 encodes with a zero-length content rather than omitting. */
    s->num = 0;
    n = ASN1_item_i2d((const ASN1_VALUE *)s, &der, ASN1_ITEM_rptr(probe_seq));
    printf("a.len_zero=%d\n", n);
    hex("a.der_zero", der, n);
    p = der;
    t = ASN1_item_d2i(NULL, &p, n, ASN1_ITEM_rptr(probe_seq));
    if (t != NULL) {
        printf("a.rt_zero_num=%d\n", (int)t->num);
        ASN1_item_free((ASN1_VALUE *)t, ASN1_ITEM_rptr(probe_seq));
    }
    OPENSSL_free(der);
    der = NULL;

    /* Re-encode of a decoded value must be byte-identical: the encoding is cached. */
    s->num = 7;
    n = ASN1_item_i2d((const ASN1_VALUE *)s, &der, ASN1_ITEM_rptr(probe_seq));
    p = der;
    t = ASN1_item_d2i(NULL, &p, n, ASN1_ITEM_rptr(probe_seq));
    if (t != NULL) {
        unsigned char *der2 = NULL;

        ASN1_item_i2d((const ASN1_VALUE *)t, &der2, ASN1_ITEM_rptr(probe_seq));
        hex("a.reencode_same", der2, n);
        OPENSSL_free(der2);
        ASN1_item_free((ASN1_VALUE *)t, ASN1_ITEM_rptr(probe_seq));
    }
    OPENSSL_free(der);

    ASN1_item_free((ASN1_VALUE *)s, ASN1_ITEM_rptr(probe_seq));
}

/* ----------------------------------------------------- b. the failure paths */

static void part_failures(void)
{
    probe_seq *s = ASN1_item_new(ASN1_ITEM_rptr(probe_seq));
    unsigned char *der = NULL;
    unsigned char *copy;
    const unsigned char *p;
    probe_seq *t;
    int n;

    s->num = 0x1234567;
    ASN1_OCTET_STRING_set(s->oct, (const unsigned char *)"\x01\x02\x03", 3);
    n = ASN1_item_i2d((const ASN1_VALUE *)s, &der, ASN1_ITEM_rptr(probe_seq));

    clear_queue();

    /* Truncated by one octet: the content of the last field is short. */
    copy = OPENSSL_malloc(n);
    memcpy(copy, der, n);
    p = copy;
    clear_queue();
    t = ASN1_item_d2i(NULL, &p, n - 1, ASN1_ITEM_rptr(probe_seq));
    printf("b.truncated_null=%d\n", t == NULL);
    drain("b.truncated_err");
    if (t != NULL)
        ASN1_item_free((ASN1_VALUE *)t, ASN1_ITEM_rptr(probe_seq));

    /* A wrong outer tag: a SET where the item wants a SEQUENCE. */
    copy[0] = 0x31;
    p = copy;
    clear_queue();
    t = ASN1_item_d2i(NULL, &p, n, ASN1_ITEM_rptr(probe_seq));
    printf("b.wrong_outer_null=%d\n", t == NULL);
    drain("b.wrong_outer_err");
    if (t != NULL)
        ASN1_item_free((ASN1_VALUE *)t, ASN1_ITEM_rptr(probe_seq));
    copy[0] = 0x30;

    /*
     * A wrong inner tag: an INTEGER where the octet string belongs. The octet string's
     * tag is at index 8 — `30 0b | 02 04 xx xx xx xx | 04 03 ...` — and corrupting index
     * 2 instead was this probe's own defect: it rewrote the INTEGER's tag with the value
     * it already had, so the case tested nothing and both sides agreed on a decode that
     * had not been disturbed.
     */
    copy[8] = 0x02;
    p = copy;
    clear_queue();
    t = ASN1_item_d2i(NULL, &p, n, ASN1_ITEM_rptr(probe_seq));
    printf("b.wrong_inner_null=%d\n", t == NULL);
    drain("b.wrong_inner_err");
    if (t != NULL)
        ASN1_item_free((ASN1_VALUE *)t, ASN1_ITEM_rptr(probe_seq));

    /* Trailing garbage after a complete value: the SEQUENCE length does not match. */
    {
        unsigned char *grown = OPENSSL_malloc(n + 1);

        memcpy(grown, der, n);
        grown[n] = 0x00;
        grown[1] = (unsigned char)(n - 2 + 1);   /* claim one more content octet */
        p = grown;
        clear_queue();
        t = ASN1_item_d2i(NULL, &p, n + 1, ASN1_ITEM_rptr(probe_seq));
        printf("b.length_mismatch_null=%d\n", t == NULL);
        drain("b.length_mismatch_err");
        if (t != NULL)
            ASN1_item_free((ASN1_VALUE *)t, ASN1_ITEM_rptr(probe_seq));
        OPENSSL_free(grown);
    }

    OPENSSL_free(copy);
    OPENSSL_free(der);
    ASN1_item_free((ASN1_VALUE *)s, ASN1_ITEM_rptr(probe_seq));
    clear_queue();
}

/* ------------------------------------------------------------- c. the CHOICE */

static void part_choice(void)
{
    probe_choice *c = ASN1_item_new(ASN1_ITEM_rptr(probe_choice));
    unsigned char *der = NULL;
    const unsigned char *p;
    probe_choice *d;
    int n;

    printf("c.new_nonnull=%d\n", c != NULL);
    if (c == NULL)
        return;
    printf("c.initial_selector=%d\n", c->type);
    /* Whether a fresh CHOICE has its first alternative's field allocated is an
     * observable, so it is printed rather than assumed before being dereferenced. */
    printf("c.initial_alt0_null=%d\n", c->value.oct == NULL);

    /* Alternative 0: the octet string. */
    c->type = 0;
    c->value.oct = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(c->value.oct, (const unsigned char *)"\xaa\xbb", 2);
    n = ASN1_item_i2d((const ASN1_VALUE *)c, &der, ASN1_ITEM_rptr(probe_choice));
    printf("c.len_oct=%d\n", n);
    hex("c.der_oct", der, n);
    p = der;
    d = ASN1_item_d2i(NULL, &p, n, ASN1_ITEM_rptr(probe_choice));
    printf("c.oct_nonnull=%d\n", d != NULL);
    if (d != NULL) {
        printf("c.oct_selector=%d\n", d->type);
        printf("c.oct_len=%d\n", ASN1_STRING_length(d->value.oct));
        ASN1_item_free((ASN1_VALUE *)d, ASN1_ITEM_rptr(probe_choice));
    }
    OPENSSL_free(der);
    der = NULL;
    ASN1_item_free((ASN1_VALUE *)c, ASN1_ITEM_rptr(probe_choice));

    /* Alternative 1: the integer. */
    c = ASN1_item_new(ASN1_ITEM_rptr(probe_choice));
    c->type = 1;
    c->value.intg = ASN1_INTEGER_new();
    ASN1_INTEGER_set(c->value.intg, 0x4242);
    n = ASN1_item_i2d((const ASN1_VALUE *)c, &der, ASN1_ITEM_rptr(probe_choice));
    printf("c.len_int=%d\n", n);
    hex("c.der_int", der, n);
    p = der;
    d = ASN1_item_d2i(NULL, &p, n, ASN1_ITEM_rptr(probe_choice));
    printf("c.int_nonnull=%d\n", d != NULL);
    if (d != NULL) {
        printf("c.int_selector=%d\n", d->type);
        printf("c.int_value=%ld\n", ASN1_INTEGER_get(d->value.intg));
        ASN1_item_free((ASN1_VALUE *)d, ASN1_ITEM_rptr(probe_choice));
    }
    OPENSSL_free(der);
    der = NULL;

    /* A tag that matches no alternative: BOOLEAN, which neither one accepts. */
    {
        unsigned char bad[3];

        bad[0] = 0x01;   /* BOOLEAN */
        bad[1] = 0x01;
        bad[2] = 0xff;
        p = bad;
        clear_queue();
        d = ASN1_item_d2i(NULL, &p, (long)sizeof(bad), ASN1_ITEM_rptr(probe_choice));
        printf("c.no_match_null=%d\n", d == NULL);
        drain("c.no_match_err");
        if (d != NULL)
            ASN1_item_free((ASN1_VALUE *)d, ASN1_ITEM_rptr(probe_choice));
    }

    ASN1_item_free((ASN1_VALUE *)c, ASN1_ITEM_rptr(probe_choice));
    clear_queue();
}

/* ----------------------------------------------- d. the *_ANY stack items */

static void part_any(void)
{
    STACK_OF(ASN1_TYPE) *sk = sk_ASN1_TYPE_new_null();
    STACK_OF(ASN1_TYPE) *back = NULL;
    unsigned char *der = NULL;
    const unsigned char *p;
    int n, i;

    /* Three elements in a deliberately non-canonical order, so a SEQUENCE OF keeps
     * them and a SET OF does not. */
    {
        static const unsigned char vals[3][3] = {
            { 0x03, 0x01, 0x77 },   /* a larger first octet */
            { 0x03, 0x01, 0x01 },
            { 0x03, 0x01, 0x02 },
        };

        for (i = 0; i < 3; i++) {
            ASN1_TYPE *t = ASN1_TYPE_new();

            ASN1_TYPE_set_octetstring(t, (unsigned char *)&vals[i][2], 1);
            sk_ASN1_TYPE_push(sk, t);
        }
    }

    n = i2d_ASN1_SEQUENCE_ANY(sk, &der);
    printf("d.seq_len=%d\n", n);
    hex("d.seq_der", der, n);
    p = der;
    back = d2i_ASN1_SEQUENCE_ANY(NULL, &p, n);
    printf("d.seq_rt_nonnull=%d\n", back != NULL);
    if (back != NULL) {
        printf("d.seq_rt_num=%d\n", sk_ASN1_TYPE_num(back));
        for (i = 0; i < sk_ASN1_TYPE_num(back); i++) {
            ASN1_TYPE *t = sk_ASN1_TYPE_value(back, i);
            unsigned char out[8];
            int got = ASN1_TYPE_get_octetstring(t, out, (int)sizeof(out));

            printf("d.seq_rt_%d_type=%d,len=%d,first=%02x\n", i, ASN1_TYPE_get(t), got,
                   got > 0 ? out[0] : 0);
        }
        sk_ASN1_TYPE_pop_free(back, ASN1_TYPE_free);
    }
    OPENSSL_free(der);
    der = NULL;

    n = i2d_ASN1_SET_ANY(sk, &der);
    printf("d.set_len=%d\n", n);
    hex("d.set_der", der, n);
    p = der;
    back = d2i_ASN1_SET_ANY(NULL, &p, n);
    printf("d.set_rt_nonnull=%d\n", back != NULL);
    if (back != NULL) {
        printf("d.set_rt_num=%d\n", sk_ASN1_TYPE_num(back));
        sk_ASN1_TYPE_pop_free(back, ASN1_TYPE_free);
    }
    OPENSSL_free(der);

    sk_ASN1_TYPE_pop_free(sk, ASN1_TYPE_free);
    clear_queue();
}

/* --------------------------------------- e. the primitive-hook numeric items */

static void part_numbers(void)
{
    unsigned char *der = NULL;
    const unsigned char *p;
    int n;
    int32_t i32;
    uint32_t u32;
    int64_t i64;

    clear_queue();

    /* INT32: the value is behind the slot. */
    i32 = 0x1234567;
    n = ASN1_item_i2d((const ASN1_VALUE *)&i32, &der, INT32_it());
    printf("e.int32_len=%d\n", n);
    hex("e.int32_der", der, n);
    p = der;
    {
        int32_t *back = ASN1_item_d2i(NULL, &p, n, INT32_it());

        printf("e.int32_rt=%d\n", back != NULL ? (int)*back : -999999);
        ASN1_item_free((ASN1_VALUE *)back, INT32_it());
    }
    OPENSSL_free(der);
    der = NULL;

    /* INT32 with a negative value. */
    i32 = -3;
    n = ASN1_item_i2d((const ASN1_VALUE *)&i32, &der, INT32_it());
    printf("e.int32_neg_len=%d\n", n);
    hex("e.int32_neg_der", der, n);
    OPENSSL_free(der);
    der = NULL;

    /* UINT32 with the top bit set: the sign flag is absent, so it is a magnitude. */
    u32 = 0xffffffffu;
    n = ASN1_item_i2d((const ASN1_VALUE *)&u32, &der, UINT32_it());
    printf("e.uint32_len=%d\n", n);
    hex("e.uint32_der", der, n);
    p = der;
    {
        uint32_t *back = ASN1_item_d2i(NULL, &p, n, UINT32_it());

        printf("e.uint32_rt=%u\n", back != NULL ? (unsigned)*back : 0u);
        ASN1_item_free((ASN1_VALUE *)back, UINT32_it());
    }
    OPENSSL_free(der);
    der = NULL;

    /* INT64: the eight-byte hooks over a value whose top bit is clear. */
    i64 = 0x123456789abLL;
    n = ASN1_item_i2d((const ASN1_VALUE *)&i64, &der, INT64_it());
    printf("e.int64_len=%d\n", n);
    hex("e.int64_der", der, n);
    p = der;
    {
        int64_t *back = ASN1_item_d2i(NULL, &p, n, INT64_it());

        printf("e.int64_rt=%lld\n", back != NULL ? (long long)*back : -1LL);
        ASN1_item_free((ASN1_VALUE *)back, INT64_it());
    }
    OPENSSL_free(der);
    der = NULL;

    /* ZINT32 with zero: ZERO_DEFAULT, so the field is omitted entirely. */
    i32 = 0;
    der = NULL;
    n = ASN1_item_i2d((const ASN1_VALUE *)&i32, &der, ZINT32_it());
    printf("e.zint32_zero_len=%d\n", n);
    printf("e.zint32_zero_der_null=%d\n", der == NULL);
    OPENSSL_free(der);
    der = NULL;

    /* ZINT32 with a non-zero value encodes normally. */
    i32 = 9;
    n = ASN1_item_i2d((const ASN1_VALUE *)&i32, &der, ZINT32_it());
    printf("e.zint32_nine_len=%d\n", n);
    hex("e.zint32_nine_der", der, n);
    OPENSSL_free(der);
    der = NULL;

    /* LONG: the value is *in* the slot, so the caller passes it as the pointer. */
    n = ASN1_item_i2d((const ASN1_VALUE *)(uintptr_t)(long)5, &der, LONG_it());
    printf("e.long_five_len=%d\n", n);
    hex("e.long_five_der", der, n);
    p = der;
    {
        void *back = ASN1_item_d2i(NULL, &p, n, LONG_it());

        printf("e.long_rt=%ld\n", (long)(uintptr_t)back);
    }
    OPENSSL_free(der);
    der = NULL;

    /* LONG with the reserved sentinel: omitted. */
    n = ASN1_item_i2d((const ASN1_VALUE *)(uintptr_t)(long)0x7fffffff, &der, LONG_it());
    printf("e.long_undef_len=%d\n", n);
    printf("e.long_undef_der_null=%d\n", der == NULL);
    OPENSSL_free(der);
    der = NULL;

    /* ZLONG with zero: the sentinel *is* zero here, so it is omitted too. */
    n = ASN1_item_i2d((const ASN1_VALUE *)(uintptr_t)(long)0, &der, ZLONG_it());
    printf("e.zlong_zero_len=%d\n", n);

    /* BIGNUM: the value is behind the slot as a real BIGNUM. */
    {
        BIGNUM *bn = BN_new();

        BN_set_word(bn, 0x1234);
        n = ASN1_item_i2d((const ASN1_VALUE *)bn, &der, BIGNUM_it());
        printf("e.bignum_len=%d\n", n);
        hex("e.bignum_der", der, n);
        p = der;
        {
            BIGNUM *back = ASN1_item_d2i(NULL, &p, n, BIGNUM_it());
            char *s = back != NULL ? BN_bn2dec(back) : NULL;

            printf("e.bignum_rt=%s\n", s != NULL ? s : "<null>");
            OPENSSL_free(s);
            ASN1_item_free((ASN1_VALUE *)back, BIGNUM_it());
        }
        OPENSSL_free(der);
        BN_free(bn);
    }

    /* A magnitude whose top bit is set needs a padding octet. */
    {
        BIGNUM *bn = BN_new();
        unsigned char raw[2] = { 0x80, 0x01 };

        BN_bin2bn(raw, 2, bn);
        der = NULL;
        n = ASN1_item_i2d((const ASN1_VALUE *)bn, &der, BIGNUM_it());
        printf("e.bignum_pad_len=%d\n", n);
        hex("e.bignum_pad_der", der, n);
        OPENSSL_free(der);
        BN_free(bn);
    }

    clear_queue();
}

/* f. the ASN1_TYPE octet-string pairs */

static void part_type_pairs(void)
{
    ASN1_TYPE *t = ASN1_TYPE_new();
    unsigned char buf[16];
    int n;

    clear_queue();

    /* The plain octet string: copied, so the caller keeps the original. */
    printf("f.set_oct=%d\n", ASN1_TYPE_set_octetstring(t, (unsigned char *)"\xde\xad", 2));
    printf("f.get_oct_type=%d\n", ASN1_TYPE_get(t));
    n = ASN1_TYPE_get_octetstring(t, buf, (int)sizeof(buf));
    printf("f.get_oct_len=%d\n", n);
    hex("f.get_oct_data", buf, n);
    printf("f.get_oct_short=%d\n", ASN1_TYPE_get_octetstring(t, buf, 1));
    hex("f.get_oct_short_data", buf, 1);
    clear_queue();

    /* The int/octet pair, which goes through a private template item. */
    printf("f.set_int_oct=%d\n",
           ASN1_TYPE_set_int_octetstring(t, 0x7f, (unsigned char *)"\x01\x02", 2));
    printf("f.int_oct_type=%d\n", ASN1_TYPE_get(t));
    {
        unsigned char *der = NULL;
        int dn = i2d_ASN1_TYPE(t, &der);

        printf("f.int_oct_der_len=%d\n", dn);
        hex("f.int_oct_der", der, dn);
        OPENSSL_free(der);
    }
    {
        long num = -1;

        n = ASN1_TYPE_get_int_octetstring(t, &num, buf, (int)sizeof(buf));
        printf("f.get_int_oct_len=%d\n", n);
        printf("f.get_int_oct_num=%ld\n", num);
        hex("f.get_int_oct_data", buf, n > 0 ? n : 0);
    }
    printf("f.get_int_oct_short=%ld\n", (long)ASN1_TYPE_get_int_octetstring(t, NULL, buf, 1));
    hex("f.get_int_oct_short_data", buf, 1);

    /* A type that is not the expected one is refused with a reason. */
    ASN1_TYPE_set_int_octetstring(t, 1, (unsigned char *)"\x00", 1);
    clear_queue();
    ASN1_TYPE_set_octetstring(t, (unsigned char *)"\x01", 1);
    printf("f.wrong_type_get_int_oct=%ld\n",
           (long)ASN1_TYPE_get_int_octetstring(t, NULL, buf, (int)sizeof(buf)));
    drain("f.wrong_type_err");

    ASN1_TYPE_free(t);
    clear_queue();
}

/* ------------------------------- g. the installed `X509_ALGOR` family (D348)
 *
 * `crypto/asn1/x_algor.c`'s own item, and the first *installed* descriptor this
 * probe drives: until D348 every template here was the probe's own declaration, which
 * is deliberate -- "the shape of the item is the thing under test". `X509_ALGOR` is the
 * shape an installed header publishes, so driving it checks that the crate's item, its
 * two codecs, its dup and its four hand-written functions answer as the authority's do.
 * `X509_ALGORS` is the `SEQUENCE OF` wrapper over it. Every observation is a return
 * code, a decoded length, an OID comparison the probe computes itself, or the DER of a
 * value the probe built from constants -- no address and no secret. */
static void part_x509_algor(void)
{
    X509_ALGOR *alg = X509_ALGOR_new();
    X509_ALGOR *dup, *dst, *back;
    unsigned char *der = NULL;
    const unsigned char *p;
    int n, ptype;
    const ASN1_OBJECT *o;
    const void *pval;

    printf("g.it.stable=%d\n",
        X509_ALGOR_it() == X509_ALGOR_it()
        && X509_ALGORS_it() == X509_ALGORS_it()
        && X509_ALGOR_it() != X509_ALGORS_it());
    printf("g.new_notnull=%d\n", alg != NULL);

    printf("g.set0=%d\n",
        X509_ALGOR_set0(alg, OBJ_nid2obj(NID_sha256), V_ASN1_NULL, NULL) == 1);

    o = NULL;
    ptype = -99;
    pval = NULL;
    X509_ALGOR_get0(&o, &ptype, &pval, alg);
    printf("g.get0.oid=%d\n", o != NULL && OBJ_obj2nid(o) == NID_sha256);
    printf("g.get0.ptype=%d\n", ptype);
    printf("g.get0.pval=%d\n", pval == NULL);

    n = i2d_X509_ALGOR(alg, NULL);
    printf("g.measure=%d\n", n > 0);
    n = i2d_X509_ALGOR(alg, &der);
    hex("g.der", der, n);
    p = der;
    back = d2i_X509_ALGOR(NULL, &p, n);
    printf("g.d2i=%d\n", back != NULL);
    if (back != NULL) {
        printf("g.cmp=%d\n", X509_ALGOR_cmp(alg, back) == 0);
        printf("g.consumed_all=%d\n", (int)(p - der) == n);
        X509_ALGOR_free(back);
    }
    OPENSSL_free(der);
    der = NULL;

    dst = X509_ALGOR_new();
    printf("g.copy=%d\n",
        X509_ALGOR_copy(dst, alg) == 1 && X509_ALGOR_cmp(dst, alg) == 0);
    dup = X509_ALGOR_dup(alg);
    printf("g.dup=%d\n", dup != NULL && X509_ALGOR_cmp(dup, alg) == 0);
    X509_ALGOR_free(dup);
    X509_ALGOR_free(dst);

    /* An identifier with no parameter reports `V_ASN1_UNDEF`. */
    {
        X509_ALGOR *a2 = X509_ALGOR_new();

        ptype = -99;
        X509_ALGOR_set0(a2, OBJ_nid2obj(NID_sha1), V_ASN1_UNDEF, NULL);
        X509_ALGOR_get0(NULL, &ptype, NULL, a2);
        printf("g.absent_ptype=%d\n", ptype == V_ASN1_UNDEF);
        X509_ALGOR_free(a2);
    }
    X509_ALGOR_free(alg);

    /* `X509_ALGORS`: a `SEQUENCE OF` two identifiers. */
    {
        X509_ALGORS *sk = (X509_ALGORS *)OPENSSL_sk_new_null();
        X509_ALGOR *a0 = X509_ALGOR_new();
        X509_ALGOR *a1 = X509_ALGOR_new();

        X509_ALGOR_set0(a0, OBJ_nid2obj(NID_sha256), V_ASN1_NULL, NULL);
        X509_ALGOR_set0(a1, OBJ_nid2obj(NID_sha1), V_ASN1_UNDEF, NULL);
        OPENSSL_sk_push(sk, a0);
        OPENSSL_sk_push(sk, a1);

        n = i2d_X509_ALGORS(sk, &der);
        printf("g.algors.i2d=%d\n", n > 0 && der != NULL);
        hex("g.algors.der", der, n);
        p = der;
        {
            X509_ALGORS *bsk = d2i_X509_ALGORS(NULL, &p, n);

            printf("g.algors.d2i_notnull=%d\n", bsk != NULL);
            if (bsk != NULL) {
                printf("g.algors.num=%d\n", OPENSSL_sk_num(bsk) == 2);
                printf("g.algors.consumed_all=%d\n", (int)(p - der) == n);
                printf("g.algors.cmp=%d\n",
                    X509_ALGOR_cmp((X509_ALGOR *)OPENSSL_sk_value(bsk, 0), a0) == 0
                    && X509_ALGOR_cmp((X509_ALGOR *)OPENSSL_sk_value(bsk, 1), a1) == 0);
                OPENSSL_sk_pop_free(bsk, (OPENSSL_sk_freefunc)X509_ALGOR_free);
            }
        }
        OPENSSL_free(der);
        OPENSSL_sk_pop_free(sk, (OPENSSL_sk_freefunc)X509_ALGOR_free);
    }
}

int main(void)
{
    part_sequence();
    part_failures();
    part_choice();
    part_any();
    part_numbers();
    part_type_pairs();
    part_x509_algor();
    printf("done=1\n");
    return 0;
}
