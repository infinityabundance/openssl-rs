/*
 * openssl-rs — RT-ASN1-PRINT: `ASN1_item_print`, differentially.
 *
 * `ASN1_item_print` is the derivation counterpart of the template decoder: the
 * same `itype` switch and the same `tt->offset` arithmetic, walking a decoded
 * value instead of bytes. This probe drives every arm of it against two
 * libraries and compares the transcripts.
 *
 * What this probe establishes:
 *
 *   a.*  a null field prints as `<ABSENT>` only under
 *        `ASN1_PCTX_FLAGS_SHOW_ABSENT`, and a `BOOLEAN` primitive is never
 *        "absent" — its value lives in the caller's slot, so a zero-valued
 *        boolean is present
 *   b.*  every primitive type renders as its own text: decimal below 128 bits and
 *        `0x`-prefixed hex above it, three-valued booleans, the bit string's
 *        unused-bit count, the object's long name beside its dotted decimal, the
 *        `NULL` word, the time forms, and the hex dump for octet and bit strings
 *   c.*  a `MSTRING` item reads its type from the value, and an `ANY` item
 *        repoints at its own union — including a `BOOLEAN` inside an `ANY` and the
 *        `NO_ANY_TYPE` suppression
 *   d.*  a `SEQUENCE` prints its declared fields through `tt->offset`, honours
 *        `SHOW_SEQUENCE` around the braces, and an `EMBED` field — whose value is
 *        the field's own storage — is re-addressed before it is printed, which is
 *        checked at three values so that a printer reading the wrong storage
 *        cannot pass by coincidence
 *   e.*  a `CHOICE` prints the alternative its selector names, and an
 *        out-of-range selector prints the `ERROR: selector [%d] invalid` line and
 *        still answers 1
 *   f.*  a `SEQUENCE OF` distinguishes a null stack (`<ABSENT>`) from an empty one
 *        (`<EMPTY>`), separates elements with a blank line, and prints the
 *        `SEQUENCE OF <name> {` header only under `SHOW_SSOF`
 *   g.*  the indentation is written in twenty-space blocks and every `BIO_write`
 *        is checked, so a sink that reports a short count truncates the print; a
 *        *negative* indent is not clamped and fails the whole call
 *   h.*  the `SHOW_TYPE`, `NO_FIELD_NAME` and `SHOW_FIELD_STRUCT_NAME` flags change
 *        the prefix and the field label, and `NO_STRUCT_NAME` drops the structure
 *        name at the top level as well as inside `asn1_print_fsname`
 *   i.*  a `SEQUENCE`/`SET`/`OTHER`-typed value is handed to `ASN1_parse_dump`,
 *        with the blank line before it and no trailing newline after it
 *
 * The templates are the probe's own, declared with the installed `asn1t.h`
 * macros, so the caller-built path is exercised as well as the crate's own items.
 *
 * Determinism: key=value per line, and the printed text is escaped and hexed
 * rather than emitted raw, so a newline or a non-ASCII byte cannot shift a line.
 * Nothing here depends on an address or a clock.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/objects.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>

/*
 * `ASN1_ANY_it` is exported by the authority but declared by none of the
 * installed headers, so a consumer has to declare it itself. It is one of the
 * ABI-only exports the ownership atlas records, and using it here exercises
 * exactly that: an unmodified binary can resolve it.
 */
extern const ASN1_ITEM *ASN1_ANY_it(void);

/* ------------------------------------------------------- a sink to print into */

/* Print `n` bytes escaped and hexed, so the transcript is line-stable. */
static void show(const char *key, BIO *b)
{
    char buf[8192];
    int n, i;

    n = BIO_read(b, buf, (int)sizeof(buf));
    if (n < 0)
        n = 0;
    printf("%s.len=%d\n", key, n);
    printf("%s=", key);
    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char)buf[i];

        if (c == '\n')
            printf("\\n");
        else if (c == '\\')
            printf("\\\\");
        else if (c >= 0x20 && c < 0x7f)
            printf("%c", c);
        else
            printf("\\x%02x", c);
    }
    printf("\n");
}

/* Print one value and record its answer beside its bytes. */
static void emit(const char *key, const ASN1_VALUE *v, int indent,
    const ASN1_ITEM *it, const ASN1_PCTX *pctx)
{
    BIO *b = BIO_new(BIO_s_mem());
    int n;

    if (b == NULL) {
        printf("%s.ret=<no-bio>\n", key);
        return;
    }
    n = ASN1_item_print(b, v, indent, it, pctx);
    printf("%s.ret=%d\n", key, n);
    show(key, b);
    BIO_free(b);
}

/* --------------------------------------- a sink that reports a short count */

static BIO *quota_mem;
static int quota_left;

static int quota_write(BIO *b, const char *data, int len)
{
    int take = len;

    (void)b;
    if (take > quota_left)
        take = quota_left;
    if (take <= 0)
        return 0;
    if (BIO_write(quota_mem, data, take) != take)
        return 0;
    quota_left -= take;
    return take;
}

/* Print one value through a sink that accepts `quota` bytes and then reports 0. */
static void emit_quota(const char *key, const ASN1_VALUE *v, int indent,
    const ASN1_ITEM *it, const ASN1_PCTX *pctx, int quota)
{
    BIO_METHOD *m = BIO_meth_new(BIO_TYPE_SOURCE_SINK, "probe-quota");
    BIO *q;
    int n;

    if (m == NULL) {
        printf("%s.ret=<no-method>\n", key);
        return;
    }
    BIO_meth_set_write(m, quota_write);
    q = BIO_new(m);
    quota_mem = BIO_new(BIO_s_mem());
    quota_left = quota;
    if (q == NULL || quota_mem == NULL) {
        printf("%s.ret=<no-bio>\n", key);
        return;
    }
    n = ASN1_item_print(q, v, indent, it, pctx);
    printf("%s.ret=%d\n", key, n);
    show(key, quota_mem);
    BIO_free(q);
    BIO_free(quota_mem);
    BIO_meth_free(m);
    quota_mem = NULL;
    quota_left = 0;
}

/* ------------------------------------------- the probe's own SEQUENCE template */

typedef struct {
    int32_t num;                 /* ASN1_EMBED: inline, at offset 0 */
    ASN1_OCTET_STRING *oct;      /* ASN1_SIMPLE */
    ASN1_IA5STRING *opt;         /* ASN1_OPT: absent when NULL */
    ASN1_BOOLEAN flag;           /* ASN1_SIMPLE(ASN1_BOOLEAN): in the slot */
} probe_seq;

ASN1_SEQUENCE(probe_seq) = {
    ASN1_EMBED(probe_seq, num, INT32),
    ASN1_SIMPLE(probe_seq, oct, ASN1_OCTET_STRING),
    ASN1_OPT(probe_seq, opt, ASN1_IA5STRING),
    ASN1_SIMPLE(probe_seq, flag, ASN1_BOOLEAN)
} static_ASN1_SEQUENCE_END(probe_seq)

/* --------------------------------------------- the probe's own SET/SEQUENCE OF */

typedef struct {
    STACK_OF(ASN1_INTEGER) *ints;
} probe_of;

ASN1_SEQUENCE(probe_of) = {
    ASN1_SEQUENCE_OF(probe_of, ints, ASN1_INTEGER)
} static_ASN1_SEQUENCE_END(probe_of)

typedef struct {
    STACK_OF(ASN1_INTEGER) *ints;
} probe_set_of;

ASN1_SEQUENCE(probe_set_of) = {
    ASN1_SET_OF(probe_set_of, ints, ASN1_INTEGER)
} static_ASN1_SEQUENCE_END(probe_set_of)

/* A *non-embedded* primitive-hook field, to separate the EMBED normalisation from
 * the hook's own read. `num` is a pointer to a four-byte allocation. */
typedef struct {
    int32_t *num;
} probe_simple_int;

ASN1_SEQUENCE(probe_simple_int) = {
    ASN1_SIMPLE(probe_simple_int, num, INT32)
} static_ASN1_SEQUENCE_END(probe_simple_int)

/* --------------------------------------------- the probe's own CHOICE template */

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

/* ------------------------------------------------------------------ helpers */

static ASN1_OCTET_STRING *octets(const unsigned char *p, int n)
{
    ASN1_OCTET_STRING *s = ASN1_OCTET_STRING_new();

    if (s != NULL && !ASN1_STRING_set(s, p, n)) {
        ASN1_OCTET_STRING_free(s);
        return NULL;
    }
    return s;
}

static ASN1_INTEGER *int_from_u64(uint64_t v)
{
    ASN1_INTEGER *a = ASN1_INTEGER_new();

    if (a != NULL && !ASN1_INTEGER_set_uint64(a, v)) {
        ASN1_INTEGER_free(a);
        return NULL;
    }
    return a;
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

/* ------------------------------------------------------- a. absence and null */

static void part_absent(void)
{
    ASN1_PCTX *no_absent = ASN1_PCTX_new();

    /* Default context: SHOW_ABSENT is set, so a null value prints a line. */
    emit("a.int_null_default", NULL, 0, ASN1_INTEGER_it(), NULL);
    emit("a.seq_null_default", NULL, 0, ASN1_SEQUENCE_it(), NULL);
    emit("a.any_null_default", NULL, 0, ASN1_ANY_it(), NULL);

    /* The same under a context with SHOW_ABSENT cleared: nothing at all. */
    ASN1_PCTX_set_flags(no_absent, 0);
    emit("a.int_null_noshow", NULL, 0, ASN1_INTEGER_it(), no_absent);
    emit("a.seq_null_noshow", NULL, 0, ASN1_SEQUENCE_it(), no_absent);

    /*
     * A boolean's value *is* the `ASN1_VALUE *` the caller passes — the printer
     * reads it back out of its own parameter slot with `*(int *)fld` — so the
     * value is spelled as a pointer-sized integer, exactly as the authority's
     * callers do.
     */
    emit("a.bool_0", (const ASN1_VALUE *)(intptr_t)0, 0, ASN1_BOOLEAN_it(), no_absent);
    emit("a.bool_5", (const ASN1_VALUE *)(intptr_t)5, 0, ASN1_BOOLEAN_it(), no_absent);
    /* -1 is the "absent" sentinel, replaced by the item's own default. */
    emit("a.bool_minus1", (const ASN1_VALUE *)(intptr_t)-1, 0, ASN1_BOOLEAN_it(), no_absent);
    emit("a.bool_t_minus1", (const ASN1_VALUE *)(intptr_t)-1, 0, ASN1_TBOOLEAN_it(), no_absent);
    emit("a.bool_f_minus1", (const ASN1_VALUE *)(intptr_t)-1, 0, ASN1_FBOOLEAN_it(), no_absent);
    emit("a.bool_t_0", (const ASN1_VALUE *)(intptr_t)0, 0, ASN1_TBOOLEAN_it(), no_absent);
    emit("a.bool_f_0", (const ASN1_VALUE *)(intptr_t)0, 0, ASN1_FBOOLEAN_it(), no_absent);

    ASN1_PCTX_free(no_absent);
}

/* ------------------------------------------------------- b. primitive leaves */

static void part_primitives(void)
{
    ASN1_INTEGER *small = int_from_u64(0);
    ASN1_INTEGER *mid = int_from_u64(0x1234567);
    ASN1_INTEGER *neg = ASN1_INTEGER_new();
    ASN1_INTEGER *big = ASN1_INTEGER_new();
    ASN1_ENUMERATED *en = ASN1_ENUMERATED_new();
    ASN1_BIT_STRING *bits = ASN1_BIT_STRING_new();
    unsigned char two_bits[1] = { 0xa5 };
    ASN1_OCTET_STRING *oct = octets((const unsigned char *)"ABCD", 4);
    ASN1_OBJECT *known = OBJ_txt2obj("1.2.840.113549.1.1.1", 0);
    ASN1_OBJECT *unknown = OBJ_txt2obj("1.2.3.4", 0);
    ASN1_UTCTIME *utc = ASN1_UTCTIME_new();
    ASN1_GENERALIZEDTIME *gen = ASN1_GENERALIZEDTIME_new();
    ASN1_PRINTABLESTRING *prn = ASN1_PRINTABLESTRING_new();
    ASN1_UTF8STRING *utf = ASN1_UTF8STRING_new();
    ASN1_PCTX *show_type = ASN1_PCTX_new();
    int i;

    /* Zero, and a value whose top bit is clear. */
    emit("b.int_zero", (const ASN1_VALUE *)small, 0, ASN1_INTEGER_it(), NULL);
    emit("b.int_mid", (const ASN1_VALUE *)mid, 0, ASN1_INTEGER_it(), NULL);

    /* `-1` as a raw content byte, which the integer printer renders as "-1". */
    if (neg != NULL) {
        unsigned char m = 0x01;

        ASN1_STRING_set(neg, &m, 1);
        neg->type = V_ASN1_NEG_INTEGER;
    }
    emit("b.int_neg", (const ASN1_VALUE *)neg, 0, ASN1_INTEGER_it(), NULL);

    /* 16 bytes of 0xff: 128 bits, so `bignum_to_string` switches to hex. */
    if (big != NULL) {
        unsigned char wide[16];

        memset(wide, 0xff, sizeof(wide));
        ASN1_STRING_set(big, wide, (int)sizeof(wide));
        big->type = V_ASN1_INTEGER;
    }
    emit("b.int_128bit", (const ASN1_VALUE *)big, 0, ASN1_INTEGER_it(), NULL);
    /* 15 bytes of 0xff: 120 bits, so it stays decimal. */
    if (big != NULL) {
        unsigned char wide[15];

        memset(wide, 0xff, sizeof(wide));
        ASN1_STRING_set(big, wide, (int)sizeof(wide));
        big->type = V_ASN1_INTEGER;
    }
    emit("b.int_120bit", (const ASN1_VALUE *)big, 0, ASN1_INTEGER_it(), NULL);

    emit("b.enumerated", (const ASN1_VALUE *)en, 0, ASN1_ENUMERATED_it(), NULL);

    /* A bit string with three unused bits, and an empty one. */
    if (bits != NULL) {
        ASN1_BIT_STRING_set(bits, two_bits, 1);
        ASN1_BIT_STRING_set_bit(bits, 12, 1);
    }
    emit("b.bit_string", (const ASN1_VALUE *)bits, 0, ASN1_BIT_STRING_it(), NULL);
    if (bits != NULL) {
        ASN1_BIT_STRING_set(bits, NULL, 0);
        ASN1_STRING_set(bits, NULL, 0);
        bits->length = 0;
        bits->flags = 0;
    }
    emit("b.bit_string_empty", (const ASN1_VALUE *)bits, 0, ASN1_BIT_STRING_it(), NULL);

    emit("b.octet_string", (const ASN1_VALUE *)oct, 0, ASN1_OCTET_STRING_it(), NULL);
    /* `ASN1_NULL_new` answers the sentinel `1`, and that is a *present* null. */
    emit("b.null_present", (const ASN1_VALUE *)ASN1_NULL_new(), 0, ASN1_NULL_it(), NULL);
    emit("b.null_absent", NULL, 0, ASN1_NULL_it(), NULL);
    emit("b.object_known", (const ASN1_VALUE *)known, 0, ASN1_OBJECT_it(), NULL);
    emit("b.object_unknown", (const ASN1_VALUE *)unknown, 0, ASN1_OBJECT_it(), NULL);
    emit("b.utctime_empty", (const ASN1_VALUE *)utc, 0, ASN1_UTCTIME_it(), NULL);
    emit("b.gentime_empty", (const ASN1_VALUE *)gen, 0, ASN1_GENERALIZEDTIME_it(), NULL);

    /* A printable string and a UTF-8 one, both through the `default` arm. */
    if (prn != NULL)
        ASN1_STRING_set(prn, "Print-able!", 11);
    emit("b.printable", (const ASN1_VALUE *)prn, 0, ASN1_PRINTABLESTRING_it(), NULL);
    if (utf != NULL)
        ASN1_STRING_set(utf, "caf\xc3\xa9", 5);
    emit("b.utf8", (const ASN1_VALUE *)utf, 0, ASN1_UTF8STRING_it(), NULL);

    /* SHOW_TYPE prefixes the tag name and a colon. */
    ASN1_PCTX_set_flags(show_type, ASN1_PCTX_FLAGS_SHOW_TYPE);
    emit("b.int_show_type", (const ASN1_VALUE *)mid, 0, ASN1_INTEGER_it(), show_type);
    emit("b.oct_show_type", (const ASN1_VALUE *)oct, 0, ASN1_OCTET_STRING_it(), show_type);
    emit("b.obj_show_type", (const ASN1_VALUE *)known, 0, ASN1_OBJECT_it(), show_type);
    ASN1_PCTX_free(show_type);

    /* The flags word is the unused-bit count for a bit string: `& 0x7` of it. */
    if (bits != NULL) {
        unsigned char one_bit[1] = { 0xff };

        ASN1_STRING_set(bits, one_bit, 1);
        bits->flags = 0x7;
    }
    emit("b.bit_string_7_unused", (const ASN1_VALUE *)bits, 0, ASN1_BIT_STRING_it(), NULL);

    /* Non-printable content goes through the escaped printer with '.' for these. */
    if (oct != NULL)
        ASN1_STRING_set(oct, "\x01\x02\x03", 3);
    emit("b.octet_nonprint", (const ASN1_VALUE *)oct, 0, ASN1_OCTET_STRING_it(), NULL);

    (void)i;
    ASN1_INTEGER_free(small);
    ASN1_INTEGER_free(mid);
    ASN1_INTEGER_free(neg);
    ASN1_INTEGER_free(big);
    ASN1_ENUMERATED_free(en);
    ASN1_BIT_STRING_free(bits);
    ASN1_OCTET_STRING_free(oct);
    ASN1_OBJECT_free(known);
    ASN1_OBJECT_free(unknown);
    ASN1_UTCTIME_free(utc);
    ASN1_GENERALIZEDTIME_free(gen);
    ASN1_PRINTABLESTRING_free(prn);
    ASN1_UTF8STRING_free(utf);
}

/* -------------------------------------------------- b2. the time leaves, set */

static void part_times(void)
{
    ASN1_UTCTIME *utc = ASN1_UTCTIME_new();
    ASN1_GENERALIZEDTIME *gen = ASN1_GENERALIZEDTIME_new();
    ASN1_TIME *t = ASN1_TIME_new();

    if (utc != NULL && ASN1_UTCTIME_set_string(utc, "250101000000Z"))
        emit("b2.utctime", (const ASN1_VALUE *)utc, 0, ASN1_UTCTIME_it(), NULL);
    if (gen != NULL && ASN1_GENERALIZEDTIME_set_string(gen, "20250101000000Z"))
        emit("b2.gentime", (const ASN1_VALUE *)gen, 0, ASN1_GENERALIZEDTIME_it(), NULL);
    if (t != NULL) {
        ASN1_TIME_set_string(t, "250101000000Z");
        emit("b2.time", (const ASN1_VALUE *)t, 0, ASN1_TIME_it(), NULL);
    }
    ASN1_UTCTIME_free(utc);
    ASN1_GENERALIZEDTIME_free(gen);
    ASN1_TIME_free(t);
}

/* ------------------------------------------------------- c. MSTRING and ANY */

static void part_mstring_and_any(void)
{
    ASN1_STRING *prn = ASN1_PRINTABLE_new();
    ASN1_PCTX *no_any = ASN1_PCTX_new();
    ASN1_TYPE *int_any = ASN1_TYPE_new();
    ASN1_TYPE *oct_any = ASN1_TYPE_new();
    ASN1_TYPE *bool_any = ASN1_TYPE_new();
    ASN1_TYPE *bool_true_any = ASN1_TYPE_new();
    ASN1_TYPE *null_any = ASN1_TYPE_new();
    ASN1_TYPE *seq_any = ASN1_TYPE_new();
    ASN1_INTEGER *num = int_from_u64(42);
    ASN1_OCTET_STRING *oct = octets((const unsigned char *)"hi", 2);
    ASN1_OCTET_STRING *der = octets((const unsigned char *)"\x02\x01\x07", 3);

    if (prn != NULL) {
        ASN1_STRING_set(prn, "plain", 5);
        emit("c.mstring_printable", (const ASN1_VALUE *)prn, 0, ASN1_PRINTABLE_it(), NULL);
        /* The real type is read from the value, so an IA5 body renders as one. */
        prn->type = V_ASN1_IA5STRING;
        emit("c.mstring_ia5", (const ASN1_VALUE *)prn, 0, ASN1_PRINTABLE_it(), NULL);
        prn->type = V_ASN1_T61STRING;
        emit("c.mstring_t61", (const ASN1_VALUE *)prn, 0, ASN1_PRINTABLE_it(), NULL);
    }

    if (int_any != NULL)
        ASN1_TYPE_set(int_any, V_ASN1_INTEGER, num);
    if (oct_any != NULL)
        ASN1_TYPE_set(oct_any, V_ASN1_OCTET_STRING, oct);
    if (bool_any != NULL)
        ASN1_TYPE_set(bool_any, V_ASN1_BOOLEAN, NULL);
    if (bool_true_any != NULL)
        ASN1_TYPE_set(bool_true_any, V_ASN1_BOOLEAN, (void *)1);
    if (null_any != NULL)
        ASN1_TYPE_set(null_any, V_ASN1_NULL, NULL);
    if (seq_any != NULL)
        ASN1_TYPE_set(seq_any, V_ASN1_OTHER, der);

    emit("c.any_int", (const ASN1_VALUE *)int_any, 0, ASN1_ANY_it(), NULL);
    emit("c.any_oct", (const ASN1_VALUE *)oct_any, 0, ASN1_ANY_it(), NULL);
    emit("c.any_bool", (const ASN1_VALUE *)bool_any, 0, ASN1_ANY_it(), NULL);
    emit("c.any_bool_true", (const ASN1_VALUE *)bool_true_any, 0, ASN1_ANY_it(), NULL);
    /* The `-1` sentinel inside an `ANY`: the printer substitutes `it->size`. */
    if (bool_any != NULL) {
        ASN1_TYPE_set(bool_any, V_ASN1_BOOLEAN, (void *)1);
        bool_any->value.boolean = -1;
        emit("c.any_bool_minus1", (const ASN1_VALUE *)bool_any, 0, ASN1_ANY_it(), NULL);
    }
    emit("c.any_null", (const ASN1_VALUE *)null_any, 0, ASN1_ANY_it(), NULL);
    emit("c.any_other", (const ASN1_VALUE *)seq_any, 0, ASN1_ANY_it(), NULL);

    /* NO_ANY_TYPE drops the tag prefix that an ANY would otherwise carry. */
    ASN1_PCTX_set_flags(no_any, ASN1_PCTX_FLAGS_NO_ANY_TYPE);
    emit("c.any_int_no_type", (const ASN1_VALUE *)int_any, 0, ASN1_ANY_it(), no_any);
    ASN1_PCTX_free(no_any);

    ASN1_PRINTABLE_free(prn);
    ASN1_TYPE_free(int_any);
    ASN1_TYPE_free(oct_any);
    ASN1_TYPE_free(bool_any);
    ASN1_TYPE_free(bool_true_any);
    ASN1_TYPE_free(null_any);
    ASN1_TYPE_free(seq_any);
    /*
     * `num`, `oct` and `der` are *owned* by the types they were handed to, so
     * `ASN1_TYPE_set` has already transferred them and the `ASN1_TYPE_free` calls
     * above release them. Freeing them here as well would be a double free, which
     * is why they are deliberately absent from this list.
     */
}

/* ----------------------------------------------------- d/i. SEQUENCE and SET */

static void part_sequence_primitives(void)
{
    ASN1_OCTET_STRING *raw = octets((const unsigned char *)"\x02\x01\x07", 3);
    ASN1_OCTET_STRING *set_body = octets((const unsigned char *)"\x02\x01\x07", 3);
    ASN1_OCTET_STRING *other_body = octets((const unsigned char *)"\x02\x01\x07", 3);
    ASN1_TYPE *set_any = ASN1_TYPE_new();
    ASN1_TYPE *other_any = ASN1_TYPE_new();

    /* A primitive SEQUENCE item holds raw DER, which goes to ASN1_parse_dump. */
    emit("d.raw_sequence", (const ASN1_VALUE *)raw, 0, ASN1_SEQUENCE_it(), NULL);
    emit("d.raw_sequence_indent", (const ASN1_VALUE *)raw, 4, ASN1_SEQUENCE_it(), NULL);

    /* The SET and OTHER arms are reachable through an ANY, which carries the tag
     * in the value rather than in the item. Each type gets its own body, because
     * `ASN1_TYPE_set` takes ownership of it. */
    if (set_any != NULL)
        ASN1_TYPE_set(set_any, V_ASN1_SET, set_body);
    if (other_any != NULL)
        ASN1_TYPE_set(other_any, V_ASN1_OTHER, other_body);
    emit("d.raw_set", (const ASN1_VALUE *)set_any, 0, ASN1_ANY_it(), NULL);
    emit("d.raw_other", (const ASN1_VALUE *)other_any, 0, ASN1_ANY_it(), NULL);

    ASN1_TYPE_free(set_any);
    ASN1_TYPE_free(other_any);
    ASN1_OCTET_STRING_free(raw);
}

/* ------------------------------------------------ d. the probe's own SEQUENCE */

static void part_caller_sequence(void)
{
    probe_seq *s = (probe_seq *)ASN1_item_new(ASN1_ITEM_rptr(probe_seq));
    ASN1_PCTX *show_seq = ASN1_PCTX_new();
    ASN1_PCTX *field_struct = ASN1_PCTX_new();
    ASN1_PCTX *no_field = ASN1_PCTX_new();
    ASN1_PCTX *no_struct = ASN1_PCTX_new();

    if (s == NULL) {
        printf("d.caller_new=0\n");
        ASN1_PCTX_free(show_seq);
        ASN1_PCTX_free(field_struct);
        ASN1_PCTX_free(no_field);
        ASN1_PCTX_free(no_struct);
        return;
    }
    printf("d.caller_new=1\n");

    s->num = 0x1234567;
    s->oct = octets((const unsigned char *)"ABCD", 4);
    s->opt = NULL;
    s->flag = 1;

    /* The value in memory, so a divergence in the printer is distinguishable from
     * one in the caller. */
    /*
     * The value the caller wrote, and the same field at two values that cannot be
     * mistaken for an address. Together these separate three cases the transcript
     * would otherwise conflate: a caller that never stored the value, a printer
     * that reads the wrong storage, and a printer that reads *some* storage. An
     * `EMBED` field is the one place the printer reads through a pointer it made
     * itself, so it is the one place this distinction has to be pinned.
     */
    printf("d.caller_num_field=%d\n", s->num);
    s->num = 1;
    emit("d.caller_num1", (const ASN1_VALUE *)s, 0, ASN1_ITEM_rptr(probe_seq), NULL);
    s->num = 0;
    emit("d.caller_num0", (const ASN1_VALUE *)s, 0, ASN1_ITEM_rptr(probe_seq), NULL);
    s->num = 0x1234567;

    /* Default: the optional field is absent, the embedded int and the flag show. */
    emit("d.caller_default", (const ASN1_VALUE *)s, 0, ASN1_ITEM_rptr(probe_seq), NULL);
    emit("d.caller_indent2", (const ASN1_VALUE *)s, 2, ASN1_ITEM_rptr(probe_seq), NULL);

    /* With the optional field present. */
    s->opt = ASN1_IA5STRING_new();
    if (s->opt != NULL)
        ASN1_STRING_set(s->opt, "opt", 3);
    emit("d.caller_with_opt", (const ASN1_VALUE *)s, 0, ASN1_ITEM_rptr(probe_seq), NULL);

    /* A false flag, and then an "absent" flag through the -1 sentinel. */
    s->flag = 0;
    emit("d.caller_flag0", (const ASN1_VALUE *)s, 0, ASN1_ITEM_rptr(probe_seq), NULL);
    s->flag = -1;
    emit("d.caller_flag_minus1", (const ASN1_VALUE *)s, 0, ASN1_ITEM_rptr(probe_seq), NULL);

    /* SHOW_SEQUENCE adds the braces. */
    ASN1_PCTX_set_flags(show_seq, ASN1_PCTX_FLAGS_SHOW_SEQUENCE);
    emit("d.caller_show_seq", (const ASN1_VALUE *)s, 0, ASN1_ITEM_rptr(probe_seq), show_seq);

    /* SHOW_FIELD_STRUCT_NAME labels each field with its type's name. */
    ASN1_PCTX_set_flags(field_struct, ASN1_PCTX_FLAGS_SHOW_FIELD_STRUCT_NAME);
    emit("d.caller_field_struct", (const ASN1_VALUE *)s, 0, ASN1_ITEM_rptr(probe_seq),
        field_struct);

    /* NO_FIELD_NAME drops the labels. */
    ASN1_PCTX_set_flags(no_field, ASN1_PCTX_FLAGS_NO_FIELD_NAME);
    emit("d.caller_no_field", (const ASN1_VALUE *)s, 0, ASN1_ITEM_rptr(probe_seq), no_field);

    /* NO_STRUCT_NAME drops the top-level structure name. */
    ASN1_PCTX_set_flags(no_struct, ASN1_PCTX_FLAGS_NO_STRUCT_NAME);
    emit("d.caller_no_struct", (const ASN1_VALUE *)s, 0, ASN1_ITEM_rptr(probe_seq), no_struct);

    /* The two flags together, which is the branch `asn1_print_fsname` returns on. */
    ASN1_PCTX_set_flags(no_struct,
        ASN1_PCTX_FLAGS_NO_STRUCT_NAME | ASN1_PCTX_FLAGS_NO_FIELD_NAME);
    emit("d.caller_no_names", (const ASN1_VALUE *)s, 0, ASN1_ITEM_rptr(probe_seq), no_struct);

    /* The MSSTRING flag is declared but unused by the printer. */
    ASN1_PCTX_set_flags(no_struct, ASN1_PCTX_FLAGS_NO_MSTRING_TYPE);
    emit("d.caller_mstring_flag", (const ASN1_VALUE *)s, 0, ASN1_ITEM_rptr(probe_seq),
        no_struct);

    ASN1_item_free((ASN1_VALUE *)s, ASN1_ITEM_rptr(probe_seq));
    ASN1_PCTX_free(show_seq);
    ASN1_PCTX_free(field_struct);
    ASN1_PCTX_free(no_field);
    ASN1_PCTX_free(no_struct);
}

/* ------------------------------------------- d2. a non-embedded hook field */

static void part_simple_int(void)
{
    probe_simple_int *s = (probe_simple_int *)ASN1_item_new(ASN1_ITEM_rptr(probe_simple_int));
    int32_t *v = (int32_t *)OPENSSL_zalloc(sizeof(int32_t));

    if (s == NULL || v == NULL) {
        printf("d2.simple_new=0\n");
        ASN1_item_free((ASN1_VALUE *)s, ASN1_ITEM_rptr(probe_simple_int));
        OPENSSL_free(v);
        return;
    }
    printf("d2.simple_new=1\n");
    *v = 0x1234567;
    s->num = v;
    printf("d2.simple_field=%d\n", *s->num);
    emit("d2.simple_int", (const ASN1_VALUE *)s, 0, ASN1_ITEM_rptr(probe_simple_int), NULL);
    /* `ASN1_item_free` releases the allocation the hook made. */
    ASN1_item_free((ASN1_VALUE *)s, ASN1_ITEM_rptr(probe_simple_int));
}

/* -------------------------------------------------- e. the probe's own CHOICE */

static void part_caller_choice(void)
{
    probe_choice *c = (probe_choice *)ASN1_item_new(ASN1_ITEM_rptr(probe_choice));
    ASN1_INTEGER *num = int_from_u64(7);
    ASN1_OCTET_STRING *oct = octets((const unsigned char *)"xy", 2);

    if (c == NULL) {
        printf("e.choice_new=0\n");
        ASN1_INTEGER_free(num);
        ASN1_OCTET_STRING_free(oct);
        return;
    }
    printf("e.choice_new=1\n");

    /* `ASN1_item_new` for a CHOICE sets the selector to a value past the end of
     * the alternative list, which is the invalid-selector path. */
    emit("e.choice_selector_invalid", (const ASN1_VALUE *)c, 0, ASN1_ITEM_rptr(probe_choice),
        NULL);

    /* From here the alternatives are owned by the choice, so `ASN1_item_free`
     * releases whichever one the selector last named — and only that one, which
     * is why the two payloads are never freed by hand. */
    c->type = 0;
    c->value.oct = oct;
    emit("e.choice_0", (const ASN1_VALUE *)c, 0, ASN1_ITEM_rptr(probe_choice), NULL);

    c->type = 1;
    c->value.intg = num;
    emit("e.choice_1", (const ASN1_VALUE *)c, 0, ASN1_ITEM_rptr(probe_choice), NULL);

    /* The `seq_any`/`int_any` payloads are owned by the types, so they are not
     * released here as well. */
    c->type = 9;
    emit("e.choice_9", (const ASN1_VALUE *)c, 0, ASN1_ITEM_rptr(probe_choice), NULL);
    drain("e.choice_9_errors");

    /* `ASN1_item_free` releases whichever alternative the selector names. */
    ASN1_item_free((ASN1_VALUE *)c, ASN1_ITEM_rptr(probe_choice));
}

/* ------------------------------------------------------- f. SEQUENCE OF/SET OF */

static void part_of(void)
{
    probe_of *o = (probe_of *)ASN1_item_new(ASN1_ITEM_rptr(probe_of));
    probe_set_of *so = (probe_set_of *)ASN1_item_new(ASN1_ITEM_rptr(probe_set_of));
    ASN1_PCTX *ssof = ASN1_PCTX_new();
    ASN1_INTEGER *a = int_from_u64(1);
    ASN1_INTEGER *b = int_from_u64(2);
    int pushed = 0;

    if (o == NULL || so == NULL) {
        printf("f.of_new=0\n");
        goto out;
    }
    printf("f.of_new=1\n");

    /* A null stack, which `OPENSSL_sk_num` answers -1 for. */
    emit("f.of_absent", (const ASN1_VALUE *)o, 0, ASN1_ITEM_rptr(probe_of), NULL);

    /* An allocated but empty stack. */
    o->ints = sk_ASN1_INTEGER_new_null();
    emit("f.of_empty", (const ASN1_VALUE *)o, 0, ASN1_ITEM_rptr(probe_of), NULL);

    /* Two elements, which are separated by a blank line. Once pushed they belong
     * to the sequence, so `ASN1_item_free` releases them. */
    sk_ASN1_INTEGER_push(o->ints, a);
    sk_ASN1_INTEGER_push(o->ints, b);
    pushed = 1;
    emit("f.of_two", (const ASN1_VALUE *)o, 0, ASN1_ITEM_rptr(probe_of), NULL);

    /* SHOW_SSOF prints the "SEQUENCE OF <field> {" header instead of "<field>:". */
    ASN1_PCTX_set_flags(ssof, ASN1_PCTX_FLAGS_SHOW_SSOF | ASN1_PCTX_FLAGS_SHOW_SEQUENCE);
    emit("f.of_two_ssof", (const ASN1_VALUE *)o, 0, ASN1_ITEM_rptr(probe_of), ssof);
    emit("f.of_empty_ssof", (const ASN1_VALUE *)so, 0, ASN1_ITEM_rptr(probe_set_of), ssof);

    /* A SET OF whose stack is empty but allocated. */
    so->ints = sk_ASN1_INTEGER_new_null();
    emit("f.set_of_empty", (const ASN1_VALUE *)so, 0, ASN1_ITEM_rptr(probe_set_of), NULL);

out:
    if (o != NULL)
        ASN1_item_free((ASN1_VALUE *)o, ASN1_ITEM_rptr(probe_of));
    if (so != NULL)
        ASN1_item_free((ASN1_VALUE *)so, ASN1_ITEM_rptr(probe_set_of));
    if (!pushed) {
        ASN1_INTEGER_free(a);
        ASN1_INTEGER_free(b);
    }
    ASN1_PCTX_free(ssof);
}

/* ---------------------------------------------------- g. indentation and sinks */

static void part_indent(void)
{
    ASN1_INTEGER *num = int_from_u64(0x1234567);

    /* Negative indents are not clamped, so the indent write fails and so does the
     * print, with no output at all. */
    emit("g.int_indent_neg1", (const ASN1_VALUE *)num, -1, ASN1_INTEGER_it(), NULL);
    emit("g.int_indent_neg5", (const ASN1_VALUE *)num, -5, ASN1_INTEGER_it(), NULL);
    emit("g.int_indent_neg21", (const ASN1_VALUE *)num, -21, ASN1_INTEGER_it(), NULL);

    /* Zero and the two sides of the twenty-space block boundary. */
    emit("g.int_indent_0", (const ASN1_VALUE *)num, 0, ASN1_INTEGER_it(), NULL);
    emit("g.int_indent_1", (const ASN1_VALUE *)num, 1, ASN1_INTEGER_it(), NULL);
    emit("g.int_indent_20", (const ASN1_VALUE *)num, 20, ASN1_INTEGER_it(), NULL);
    emit("g.int_indent_21", (const ASN1_VALUE *)num, 21, ASN1_INTEGER_it(), NULL);
    emit("g.int_indent_40", (const ASN1_VALUE *)num, 40, ASN1_INTEGER_it(), NULL);

    /* A sink that accepts a few bytes and then reports 0: the print fails at the
     * first short write and the bytes written so far are all that arrive. */
    emit_quota("g.quota_0", (const ASN1_VALUE *)num, 0, ASN1_INTEGER_it(), NULL, 0);
    emit_quota("g.quota_1", (const ASN1_VALUE *)num, 1, ASN1_INTEGER_it(), NULL, 1);
    emit_quota("g.quota_3", (const ASN1_VALUE *)num, 0, ASN1_INTEGER_it(), NULL, 3);
    emit_quota("g.quota_5", (const ASN1_VALUE *)num, 0, ASN1_INTEGER_it(), NULL, 5);
    /* A short write *inside* a twenty-space block, which is a different check. */
    emit_quota("g.quota_25", (const ASN1_VALUE *)num, 30, ASN1_INTEGER_it(), NULL, 25);

    ASN1_INTEGER_free(num);
}

/* --------------------------------------------------------------- the driver */

int main(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);

    part_absent();
    part_primitives();
    part_times();
    part_mstring_and_any();
    part_sequence_primitives();
    part_caller_sequence();
    part_simple_int();
    part_caller_choice();
    part_of();
    part_indent();

    printf("done=1\n");
    return 0;
}
