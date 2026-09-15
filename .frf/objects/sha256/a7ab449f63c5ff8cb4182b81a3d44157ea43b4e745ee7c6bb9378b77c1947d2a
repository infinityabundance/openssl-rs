/*
 * openssl-rs — RT-ASN1-STR: the string classification, table and printing surface,
 * differentially.
 *
 * Four translation units and four different kinds of "string" question:
 *
 *   a.*  `a_print.c` — which of PrintableString / IA5String / T61String a buffer
 *        fits in, and the four-byte-per-character narrowing, and the raw printer
 *        whose block size is an observable
 *   b.*  `a_mbstr.c` — the mask-narrowing classifier, its four input encodings and
 *        its four output encodings, the two size limits, and the distinction
 *        between a caller-supplied destination and one the function allocated
 *   c.*  `a_strnid.c` — the per-NID string table: 28 compile-time rows, the
 *        runtime stack that shadows them, the global mask with its `STABLE_NO_MASK`
 *        exemption, and the five spellings of `set_default_mask_asc`
 *   d.*  `t_pkey.c` — the colon-hex buffer printer and the three-shaped BIGNUM
 *        printer
 *
 * The observable that makes (a) worth a custom BIO: `ASN1_STRING_print` writes in
 * blocks of at most 80 bytes, so a 160-octet string is two writes and a 161-octet
 * one is three. The probe installs a method whose write callback records the
 * lengths and nothing else, so the blocking is measured rather than inferred from
 * the bytes.
 *
 * The reason name and the *additional data* of each failure are both printed:
 * `ASN1_mbstring_ncopy` reports its size limits as data (`"minsize=%ld"`), which is
 * a different observable from the reason alone, and `ERR_get_error_all` is the only
 * way to reach it. The file/line/function are deliberately not printed — the file
 * path embeds the build prefix.
 *
 * Determinism: key=value per line; no address, no clock, no build path. The global
 * mask and the runtime string table are process state that the probe mutates, so it
 * restores the mask it started with and cleans the table up before the printer
 * sections, and the order of sections is fixed.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/objects.h>

#include <limits.h>
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

/*
 * One `reason[data]` entry per queue slot, oldest first, and never the file, the
 * line or the function: those embed the build prefix.
 */
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

/* Report a string's observable identity, under `key`. */
static void report_string(const char *key, const ASN1_STRING *s)
{
    char buf[128];

    if (s == NULL) {
        printf("%s=<null>\n", key);
        return;
    }
    snprintf(buf, sizeof(buf), "%s.type", key);
    printf("%s=%d\n", buf, ASN1_STRING_type(s));
    snprintf(buf, sizeof(buf), "%s.len", key);
    printf("%s=%d\n", buf, ASN1_STRING_length(s));
    snprintf(buf, sizeof(buf), "%s.data", key);
    hex(buf, ASN1_STRING_get0_data(s), ASN1_STRING_length(s));
}

/* Read a memory BIO back into a stack buffer and print it. */
static void show_bio(const char *key, BIO *b)
{
    char buf[1024];
    int n = BIO_read(b, buf, (int)sizeof(buf) - 1);

    if (n < 0)
        n = 0;
    buf[n] = '\0';
    printf("%s.len=%d\n", key, n);
    text(key, (const unsigned char *)buf, n);
}

/* --------------------------------------------------- the chunk-recording BIO */

static int chunk_n;
static int chunk_len[64];

static int chunk_write(BIO *b, const char *buf, int len)
{
    (void)b;
    (void)buf;
    if (chunk_n < 64)
        chunk_len[chunk_n++] = len;
    return len;
}

static BIO_METHOD *chunker_method(void)
{
    static BIO_METHOD *m = NULL;

    if (m == NULL) {
        m = BIO_meth_new(250, "chunker");
        BIO_meth_set_write(m, chunk_write);
    }
    return m;
}

static void chunks(const char *key)
{
    int i;

    printf("%s.n=%d\n", key, chunk_n);
    printf("%s=", key);
    for (i = 0; i < chunk_n; i++)
        printf("%s%d", i ? "," : "", chunk_len[i]);
    printf("\n");
}

/* ------------------------------------------------------------ ASN1_PRINTABLE */

static void printable(const char *key, const unsigned char *s, int len)
{
    printf("ptype.%s=%d\n", key, ASN1_PRINTABLE_type(s, len));
}

static void part_printable(void)
{
    static const unsigned char printable_[] = "abc XYZ 0123+-./:=?()'";
    static const unsigned char with_ia5[] = "a;b";
    /* The hex escape would swallow the following digit, so the literal is split. */
    static const unsigned char with_del[] = "a\x7f" "b";
    static const unsigned char with_nl[] = "a\nb";
    static const unsigned char high[] = "a\x80z";
    static const unsigned char all_high[] = "\x80\xff";

    printable("null", NULL, 0);
    printable("null_neg_len", NULL, -1);
    printable("empty", (const unsigned char *)"", -1);
    printable("empty_zero_len", (const unsigned char *)"", 0);
    printable("printable", printable_, -1);
    printable("printable_prefix", printable_, 5);
    printable("printable_zero_len", printable_, 0);
    printable("ia5_semicolon", with_ia5, -1);
    printable("ia5_del", with_del, -1);
    printable("ia5_newline", with_nl, -1);
    printable("t61_high", high, -1);
    printable("t61_all_high", all_high, -1);

    /* Each of the printable alphabet's members and each of its two absences. */
    {
        unsigned char one[2];
        char key[16];
        int c;

        for (c = 0x20; c < 0x7f; c++) {
            one[0] = (unsigned char)c;
            one[1] = 0;
            snprintf(key, sizeof(key), "c%02x", c);
            printf("ptype.one.%s=%d\n", key, ASN1_PRINTABLE_type(one, 1));
        }
    }
}

/* ------------------------------------------- ASN1_UNIVERSALSTRING_to_string */

static void univ(const char *key, const unsigned char *data, int len, int type)
{
    ASN1_STRING *s = ASN1_STRING_type_new(type);

    ERR_clear_error();
    if (len >= 0)
        ASN1_STRING_set(s, data, len);
    printf("univ.%s=%d\n", key, ASN1_UNIVERSALSTRING_to_string(s));
    report_string(key, s);
    ASN1_STRING_free(s);
    drain("univ.err");
}

static void part_universalstring(void)
{
    static const unsigned char ab[] = { 0, 0, 0, 'A', 0, 0, 0, 'B' };
    static const unsigned char nonzero[] = { 0, 0, 1, 'A' };
    static const unsigned char odd[] = { 0, 0, 0, 'A', 0 };
    static const unsigned char mixed[] = { 0, 0, 0, 'A', 0, 0, 0, 0x80 };
    static const unsigned char empty[] = { 0 };

    univ("ab", ab, 8, V_ASN1_UNIVERSALSTRING);
    univ("nonzero_prefix", nonzero, 4, V_ASN1_UNIVERSALSTRING);
    univ("not_multiple_of_4", odd, 5, V_ASN1_UNIVERSALSTRING);
    univ("high_after_compaction", mixed, 8, V_ASN1_UNIVERSALSTRING);
    univ("empty", empty, 0, V_ASN1_UNIVERSALSTRING);
    /* The type guard, not the content, decides the first case. */
    univ("wrong_type", ab, 8, V_ASN1_OCTET_STRING);
    univ("bmp_type", ab, 8, V_ASN1_BMPSTRING);
}

/* ------------------------------------------------------- ASN1_STRING_print */

static BIO *new_chunker(void)
{
    chunk_n = 0;
    return BIO_new(chunker_method());
}

static void string_print(const char *key, const unsigned char *data, int len)
{
    ASN1_STRING *s = ASN1_STRING_new();
    BIO *b;

    if (len >= 0)
        ASN1_STRING_set(s, data, len);
    b = new_chunker();
    printf("sprint.%s=%d\n", key, ASN1_STRING_print(b, s));
    chunks(key);
    BIO_free(b);
    ASN1_STRING_free(s);
}

static void part_string_print(void)
{
    static unsigned char eighty[80];
    static unsigned char eightyone[81];
    static unsigned char one_sixty[160];
    static const unsigned char controls[] = { 'a', 0x00, 'b', 0x09, 'c', 0x0a,
                                             'd', 0x0d, 'e', 0x1f, 'f' };
    static const unsigned char high[] = { 'a', 0x7f, 0x80, 0xff, 'z' };
    int i;

    for (i = 0; i < 80; i++)
        eighty[i] = (unsigned char)('0' + (i % 10));
    memcpy(eightyone, eighty, 80);
    eightyone[80] = 'X';
    for (i = 0; i < 160; i++)
        one_sixty[i] = (unsigned char)('a' + (i % 26));

    printf("sprint.null=%d\n", ASN1_STRING_print(NULL, NULL));

    string_print("empty", (const unsigned char *)"", 0);
    string_print("short", (const unsigned char *)"hello", 5);
    string_print("controls", controls, (int)sizeof(controls));
    string_print("high", high, (int)sizeof(high));
    string_print("exactly_80", eighty, 80);
    string_print("exactly_81", eightyone, 81);
    string_print("exactly_160", one_sixty, 160);

    /* A value whose length is not backed by its data is the caller's error; the
     * printer never reads past `length`, so the probe does not either. */
    {
        ASN1_STRING *s = ASN1_STRING_new();
        BIO *b = new_chunker();

        printf("sprint.fresh=%d\n", ASN1_STRING_print(b, s));
        chunks("sprint.fresh");
        BIO_free(b);
        ASN1_STRING_free(s);
    }
}

/* ---------------------------------------------------------------- mbstring */

static void mb_classify(const char *key, const unsigned char *in, int len,
                        int inform, unsigned long mask)
{
    ERR_clear_error();
    printf("mb.%s.classify=%d\n", key,
           ASN1_mbstring_copy(NULL, in, len, inform, mask));
    drain("mb.err");
}

static void mb_convert(const char *key, const unsigned char *in, int len,
                       int inform, unsigned long mask, int reuse)
{
    ASN1_STRING *s = NULL;
    ASN1_STRING *was = NULL;
    int rv;

    ERR_clear_error();
    if (reuse) {
        s = ASN1_STRING_new();
        ASN1_STRING_set(s, "OLD", 3);
        was = s;
    }
    rv = ASN1_mbstring_copy(&s, in, len, inform, mask);
    printf("mb.%s.rv=%d\n", key, rv);
    printf("mb.%s.reused=%d\n", key, reuse ? (s == was) : 0);
    report_string(key, s);
    ASN1_STRING_free(s);
    drain("mb.err");
}

static void mb_ncopy(const char *key, const unsigned char *in, int len,
                     int inform, unsigned long mask, long mn, long mx)
{
    ASN1_STRING *s = NULL;
    int rv;

    ERR_clear_error();
    rv = ASN1_mbstring_ncopy(&s, in, len, inform, mask, mn, mx);
    printf("mbn.%s.rv=%d\n", key, rv);
    report_string(key, s);
    ASN1_STRING_free(s);
    drain("mbn.err");
}

static void part_mbstring(void)
{
    static const unsigned char latin1[] = "h\xe9llo";
    static const unsigned char utf8_eacute[] = "h\xc3\xa9llo";
    static const unsigned char utf8_euro[] = "h\xe2\x82\xac!";
    static const unsigned char utf8_emoji[] = "h\xf0\x9f\x98\x80";
    static const unsigned char bmp_ascii[] = { 0x00, 'A', 0x00, 'B' };
    static const unsigned char univ_ascii[] = { 0, 0, 0, 'A', 0, 0, 0, 'B' };
    static const unsigned char univ_euro[] = { 0, 0, 0x20, 0xac };
    static const unsigned char bad_utf8_ff[] = { 0xff };
    static const unsigned char bad_utf8_surrogate[] = { 0xed, 0xa0, 0x80 };
    static const unsigned char with_nul[] = { 'a', 0x00, 'b' };

    /* The classifier form: the type the input would be held in. */
    mb_classify("asc_printable", (const unsigned char *)"hello", 5, MBSTRING_ASC,
                DIRSTRING_TYPE);
    mb_classify("asc_default_mask", (const unsigned char *)"hello", 5,
                MBSTRING_ASC, 0);
    mb_classify("asc_latin1", latin1, 6, MBSTRING_ASC, DIRSTRING_TYPE);
    mb_classify("asc_numeric", (const unsigned char *)"12 34", 5, MBSTRING_ASC,
                B_ASN1_NUMERICSTRING | B_ASN1_PRINTABLESTRING);
    mb_classify("asc_semicolon", (const unsigned char *)"a;b", 3, MBSTRING_ASC,
                DIRSTRING_TYPE | B_ASN1_IA5STRING);
    mb_classify("null_len", (const unsigned char *)"hello", -1, MBSTRING_ASC,
                DIRSTRING_TYPE);
    mb_classify("all_seven", (const unsigned char *)"A", 1, MBSTRING_ASC,
                B_ASN1_NUMERICSTRING | B_ASN1_PRINTABLESTRING | B_ASN1_IA5STRING
                    | B_ASN1_T61STRING | B_ASN1_BMPSTRING
                    | B_ASN1_UNIVERSALSTRING | B_ASN1_UTF8STRING);
    /* A mask bit outside the seven is treated as "UTF8 was asked for". */
    mb_classify("only_unknown_bit", (const unsigned char *)"A", 1, MBSTRING_ASC,
                B_ASN1_UNKNOWN);
    mb_classify("unknown_plus_printable", (const unsigned char *)"A", 1,
                MBSTRING_ASC, B_ASN1_UNKNOWN | B_ASN1_PRINTABLESTRING);
    mb_classify("bad_inform", (const unsigned char *)"A", 1, 0x9999,
                DIRSTRING_TYPE);

    /* The converter form, once per input and output encoding. */
    mb_convert("asc_to_dir", (const unsigned char *)"hello", 5, MBSTRING_ASC,
               DIRSTRING_TYPE, 0);
    mb_convert("asc_with_nul", with_nul, 3, MBSTRING_ASC, DIRSTRING_TYPE, 0);
    mb_convert("asc_latin1", latin1, 6, MBSTRING_ASC, DIRSTRING_TYPE, 0);
    mb_convert("utf8_to_asc", utf8_eacute, 6, MBSTRING_UTF8, DIRSTRING_TYPE, 0);
    mb_convert("utf8_to_bmp", utf8_euro, 5, MBSTRING_UTF8, DIRSTRING_TYPE, 0);
    mb_convert("utf8_to_utf8", utf8_emoji, 5, MBSTRING_UTF8, DIRSTRING_TYPE, 0);
    mb_convert("bmp_to_asc", bmp_ascii, 4, MBSTRING_BMP, DIRSTRING_TYPE, 0);
    mb_convert("univ_to_asc", univ_ascii, 8, MBSTRING_UNIV, DIRSTRING_TYPE, 0);
    mb_convert("univ_to_univ", univ_ascii, 8, MBSTRING_UNIV,
               B_ASN1_UNIVERSALSTRING, 0);
    mb_convert("univ_to_bmp", univ_euro, 4, MBSTRING_UNIV, B_ASN1_BMPSTRING, 0);
    mb_convert("asc_to_univ", (const unsigned char *)"AB", 2, MBSTRING_ASC,
               B_ASN1_UNIVERSALSTRING, 0);
    mb_convert("asc_to_bmp", (const unsigned char *)"AB", 2, MBSTRING_ASC,
               B_ASN1_BMPSTRING, 0);
    mb_convert("asc_utf8_only", (const unsigned char *)"AB", 2, MBSTRING_ASC,
               B_ASN1_UTF8STRING, 0);
    mb_convert("reuse", (const unsigned char *)"NEW", 3, MBSTRING_ASC,
               DIRSTRING_TYPE, 1);
    mb_convert("reuse_utf8", (const unsigned char *)"AB", 2, MBSTRING_ASC,
               B_ASN1_UTF8STRING, 1);

    /* Rejection cases, each with its own reason. */
    mb_convert("bad_utf8_ff", bad_utf8_ff, 1, MBSTRING_UTF8, DIRSTRING_TYPE, 0);
    mb_convert("bad_utf8_surrogate", bad_utf8_surrogate, 3, MBSTRING_UTF8,
               DIRSTRING_TYPE, 0);
    mb_convert("odd_bmp", (const unsigned char *)"\x00", 1, MBSTRING_BMP,
               DIRSTRING_TYPE, 0);
    mb_convert("odd_univ", (const unsigned char *)"\x00\x00\x00", 3,
               MBSTRING_UNIV, DIRSTRING_TYPE, 0);
    mb_convert("negative_len", (const unsigned char *)"A", -2, MBSTRING_ASC,
               DIRSTRING_TYPE, 0);
    mb_convert("huge_len", (const unsigned char *)"A", INT_MAX, MBSTRING_ASC,
               DIRSTRING_TYPE, 0);
    mb_convert("bad_inform", (const unsigned char *)"A", 1, 0x9999,
               DIRSTRING_TYPE, 0);
    mb_convert("high_byte_asc", (const unsigned char *)"\x80", 1, MBSTRING_ASC,
               B_ASN1_PRINTABLESTRING, 0);

    /* The two size limits, at and around their bounds. */
    mb_ncopy("min_ok", (const unsigned char *)"abc", 3, MBSTRING_ASC,
             DIRSTRING_TYPE, 3, 0);
    mb_ncopy("min_short", (const unsigned char *)"ab", 2, MBSTRING_ASC,
             DIRSTRING_TYPE, 3, 0);
    mb_ncopy("max_ok", (const unsigned char *)"abc", 3, MBSTRING_ASC,
             DIRSTRING_TYPE, 0, 3);
    mb_ncopy("max_long", (const unsigned char *)"abcd", 4, MBSTRING_ASC,
             DIRSTRING_TYPE, 0, 3);
    mb_ncopy("both_bad_min_first", (const unsigned char *)"abcd", 4,
             MBSTRING_ASC, DIRSTRING_TYPE, 9, 3);
    mb_ncopy("zero_means_unbounded", (const unsigned char *)"abc", 3,
             MBSTRING_ASC, DIRSTRING_TYPE, 0, 0);
}

/* -------------------------------------------------------------- string table */

static void show_row(const char *key, const ASN1_STRING_TABLE *t)
{
    if (t == NULL) {
        printf("row.%s=<null>\n", key);
        return;
    }
    printf("row.%s.nid=%d\n", key, t->nid);
    printf("row.%s.min=%ld\n", key, t->minsize);
    printf("row.%s.max=%ld\n", key, t->maxsize);
    printf("row.%s.mask=%lu\n", key, t->mask);
    printf("row.%s.flags=%lu\n", key, t->flags);
}

static void get_row(const char *key, int nid)
{
    ERR_clear_error();
    show_row(key, ASN1_STRING_TABLE_get(nid));
    drain("row.err");
}

static void part_string_table(void)
{
    int i;

    get_row("commonName", NID_commonName);
    get_row("countryName", NID_countryName);
    get_row("pkcs9_emailAddress", NID_pkcs9_emailAddress);
    get_row("friendlyName", NID_friendlyName);
    get_row("dnQualifier", NID_dnQualifier);
    get_row("dnsName", NID_dnsName);
    get_row("smtputf8", NID_id_on_SmtpUTF8Mailbox);
    get_row("serialNumber", NID_serialNumber);
    get_row("unknown", 99990);
    get_row("zero", 0);
    get_row("negative", -1);

    /* Modify an existing row: the stack shadows the standard table. */
    ERR_clear_error();
    printf("add.commonName=%d\n", ASN1_STRING_TABLE_add(NID_commonName, 3, 10,
                                                       B_ASN1_IA5STRING, 0));
    drain("add.commonName.err");
    get_row("commonName.after", NID_commonName);

    /* A row for a NID the standard table does not have. */
    ERR_clear_error();
    printf("add.unknown_nid=%d\n", ASN1_STRING_TABLE_add(99990, 1, 2,
                                                         B_ASN1_PRINTABLESTRING,
                                                         0));
    drain("add.unknown_nid.err");
    get_row("unknown.after", 99990);

    /* One field at a time: a negative bound means "leave it". */
    ERR_clear_error();
    printf("add.mask_only=%d\n", ASN1_STRING_TABLE_add(NID_commonName, -1, -1,
                                                       B_ASN1_UTF8STRING, 0));
    drain("add.mask_only.err");
    get_row("commonName.mask_only", NID_commonName);

    /* `STABLE_FLAGS_CLEAR` is the way to remove `STABLE_NO_MASK`. */
    ERR_clear_error();
    printf("add.clear_flags=%d\n", ASN1_STRING_TABLE_add(NID_countryName, -1, -1,
                                                         0, STABLE_FLAGS_CLEAR));
    drain("add.clear_flags.err");
    get_row("countryName.cleared", NID_countryName);
    ERR_clear_error();
    printf("add.restore_no_mask=%d\n", ASN1_STRING_TABLE_add(
               NID_countryName, -1, -1, B_ASN1_PRINTABLESTRING, STABLE_NO_MASK));
    drain("add.restore_no_mask.err");
    get_row("countryName.restored", NID_countryName);

    /* The two argument rejections. */
    ERR_clear_error();
    printf("add.min_gt_max=%d\n", ASN1_STRING_TABLE_add(NID_commonName, 5, 1,
                                                        B_ASN1_IA5STRING, 0));
    drain("add.min_gt_max.err");
    ERR_clear_error();
    printf("add.zero_nid=%d\n", ASN1_STRING_TABLE_add(0, 1, 2, B_ASN1_IA5STRING,
                                                      0));
    drain("add.zero_nid.err");
    ERR_clear_error();
    printf("add.negative_nid=%d\n", ASN1_STRING_TABLE_add(-5, 1, 2,
                                                          B_ASN1_IA5STRING, 0));
    drain("add.negative_nid.err");

    /* `set_by_NID` against a modified row, against a standard row and against no
     * row at all. */
    {
        ASN1_STRING *s;
        char key[128];

        ERR_clear_error();
        s = NULL;
        printf("bynid.ia5_ok=%d\n", ASN1_STRING_set_by_NID(&s, (const unsigned char *)"abc",
                                                          3, MBSTRING_ASC,
                                                          NID_commonName) != NULL);
        snprintf(key, sizeof(key), "bynid.ia5_ok");
        report_string(key, s);
        ASN1_STRING_free(s);
        drain("bynid.ia5_ok.err");

        ERR_clear_error();
        s = NULL;
        printf("bynid.ia5_short=%d\n", ASN1_STRING_set_by_NID(&s, (const unsigned char *)"ab",
                                                              2, MBSTRING_ASC,
                                                              NID_commonName) != NULL);
        printf("bynid.ia5_short.null=%d\n", s == NULL);
        ASN1_STRING_free(s);
        drain("bynid.ia5_short.err");

        ERR_clear_error();
        s = NULL;
        printf("bynid.ia5_long=%d\n", ASN1_STRING_set_by_NID(
                   &s, (const unsigned char *)"abcdefghijk", 11, MBSTRING_ASC,
                   NID_commonName) != NULL);
        printf("bynid.ia5_long.null=%d\n", s == NULL);
        ASN1_STRING_free(s);
        drain("bynid.ia5_long.err");

        ERR_clear_error();
        s = NULL;
        printf("bynid.country=%d\n", ASN1_STRING_set_by_NID(&s, (const unsigned char *)"US",
                                                            2, MBSTRING_ASC,
                                                            NID_countryName) != NULL);
        snprintf(key, sizeof(key), "bynid.country");
        report_string(key, s);
        ASN1_STRING_free(s);
        drain("bynid.country.err");

        ERR_clear_error();
        s = NULL;
        printf("bynid.unknown_nid=%d\n", ASN1_STRING_set_by_NID(
                   &s, (const unsigned char *)"hello", 5, MBSTRING_ASC,
                   99991) != NULL);
        snprintf(key, sizeof(key), "bynid.unknown_nid");
        report_string(key, s);
        ASN1_STRING_free(s);
        drain("bynid.unknown_nid.err");
    }

    /* The cleanup drops only the rows it allocated, and the shadowing with them. */
    ASN1_STRING_TABLE_cleanup();
    printf("cleanup.done=1\n");
    get_row("commonName.after_cleanup", NID_commonName);
    get_row("unknown.after_cleanup", 99990);

    /* The global mask, and the `STABLE_NO_MASK` exemption from it. */
    printf("mask.initial=%lu\n", ASN1_STRING_get_default_mask());
    {
        ASN1_STRING *s;
        char key[128];

        ASN1_STRING_set_default_mask(B_ASN1_IA5STRING);
        printf("mask.set=%lu\n", ASN1_STRING_get_default_mask());

        ERR_clear_error();
        s = NULL;
        printf("bynid.masked_country=%d\n", ASN1_STRING_set_by_NID(
                   &s, (const unsigned char *)"US", 2, MBSTRING_ASC,
                   NID_countryName) != NULL);
        snprintf(key, sizeof(key), "bynid.masked_country");
        report_string(key, s);
        ASN1_STRING_free(s);
        drain("bynid.masked_country.err");

        /* commonName's mask is DIRSTRING_TYPE, which has no IA5 bit, so the
         * intersection is empty and `ncopy` falls back to DIRSTRING_TYPE. */
        ERR_clear_error();
        s = NULL;
        printf("bynid.masked_common=%d\n", ASN1_STRING_set_by_NID(
                   &s, (const unsigned char *)"hi", 2, MBSTRING_ASC,
                   NID_commonName) != NULL);
        snprintf(key, sizeof(key), "bynid.masked_common");
        report_string(key, s);
        ASN1_STRING_free(s);
        drain("bynid.masked_common.err");
    }
    ASN1_STRING_set_default_mask(B_ASN1_UTF8STRING);

    /* The five spellings of `set_default_mask_asc`, and the shapes it rejects. */
    {
        static const char *const asc[] = {
            "MASK:0x10", "MASK:16", "MASK:016", "MASK:0", "nombstr", "pkix",
            "utf8only", "default", "MASK:", "MASK:x", "MASK:0x10junk", "",
            "bogus", "Nombstr", "0x10",
        };
        size_t i;

        for (i = 0; i < sizeof(asc) / sizeof(asc[0]); i++) {
            int rv;

            ERR_clear_error();
            rv = ASN1_STRING_set_default_mask_asc(asc[i]);
            printf("ascmask.%zu.rv=%d\n", i, rv);
            printf("ascmask.%zu.now=%lu\n", i, ASN1_STRING_get_default_mask());
            drain("ascmask.err");
            ASN1_STRING_set_default_mask(B_ASN1_UTF8STRING);
        }
    }

    (void)i;
}

/* ------------------------------------------------------------ the printers */

static void buf_print(const char *key, const unsigned char *buf, int n, int indent)
{
    BIO *b = BIO_new(BIO_s_mem());
    char k[128];

    printf("buf.%s=%d\n", key, ASN1_buf_print(b, buf, (size_t)n, indent));
    snprintf(k, sizeof(k), "buf.%s", key);
    show_bio(k, b);
    BIO_free(b);
}

static void bn_print(const char *key, const char *name, const unsigned char *mag,
                     int maglen, int indent)
{
    BIGNUM *bn = NULL;
    BIO *b = BIO_new(BIO_s_mem());
    char k[128];

    if (mag != NULL)
        bn = BN_bin2bn(mag, maglen, NULL);
    printf("bn.%s=%d\n", key, ASN1_bn_print(b, name, bn, NULL, indent));
    snprintf(k, sizeof(k), "bn.%s", key);
    show_bio(k, b);
    BN_free(bn);
    BIO_free(b);
}

static void part_printers(void)
{
    static const unsigned char one[] = { 0x41 };
    static const unsigned char fifteen[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                                             0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                                             0x0d, 0x0e, 0x0f };
    static const unsigned char sixteen[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                                             0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                                             0x0d, 0x0e, 0x0f, 0x10 };
    static const unsigned char thirtyone[31] = { 0xaa };
    static const unsigned char wide_low[] = { 0x01, 0x23, 0x45, 0x67,
                                              0x89, 0xab, 0xcd, 0xef, 0x11 };
    static const unsigned char wide_high[] = { 0x80, 0x23, 0x45, 0x67,
                                               0x89, 0xab, 0xcd, 0xef, 0x11 };
    static const unsigned char word[] = { 0x12, 0x34 };

    buf_print("empty", one, 0, 0);
    buf_print("one", one, 1, 0);
    buf_print("fifteen", fifteen, 15, 0);
    buf_print("sixteen", sixteen, 16, 0);
    buf_print("thirtyone", thirtyone, 31, 0);
    buf_print("indent2", sixteen, 16, 2);
    buf_print("indent80", sixteen, 16, 80);
    buf_print("indent81", sixteen, 16, 81);
    buf_print("indent_negative", sixteen, 16, -1);

    bn_print("null", "N", NULL, 0, 0);
    bn_print("zero", "N", (const unsigned char *)"\x00", 0, 0);
    bn_print("word", "N", word, 2, 0);
    bn_print("one", "N", one, 1, 0);
    bn_print("wide_low", "K", wide_low, 9, 0);
    bn_print("wide_high", "K", wide_high, 9, 0);
    bn_print("wide_indent", "K", wide_high, 9, 2);
    bn_print("wide_indent80", "K", wide_high, 9, 80);
    bn_print("empty_name", "", wide_low, 9, 0);

    /* The negative word case needs a negative BIGNUM, which the magnitude
     * constructor cannot make, so it is built and negated explicitly. */
    {
        BIGNUM *bn = BN_bin2bn(word, 2, NULL);
        BIO *b = BIO_new(BIO_s_mem());

        BN_set_negative(bn, 1);
        printf("bn.neg_word=%d\n", ASN1_bn_print(b, "N", bn, NULL, 0));
        show_bio("bn.neg_word", b);
        BN_free(bn);
        BIO_free(b);
    }
    {
        BIGNUM *bn = BN_bin2bn(wide_high, 9, NULL);
        BIO *b = BIO_new(BIO_s_mem());

        BN_set_negative(bn, 1);
        printf("bn.neg_wide=%d\n", ASN1_bn_print(b, "K", bn, NULL, 0));
        show_bio("bn.neg_wide", b);
        BN_free(bn);
        BIO_free(b);
    }
}


/* ------------------------------------------- ASN1_STRING_print_ex and UTF-8 */

static unsigned long flag_cases[] = {
    0,
    ASN1_STRFLGS_ESC_2253,
    ASN1_STRFLGS_ESC_CTRL,
    ASN1_STRFLGS_ESC_MSB,
    ASN1_STRFLGS_ESC_QUOTE,
    ASN1_STRFLGS_ESC_2254,
    ASN1_STRFLGS_UTF8_CONVERT,
    ASN1_STRFLGS_IGNORE_TYPE,
    ASN1_STRFLGS_SHOW_TYPE,
    ASN1_STRFLGS_DUMP_ALL,
    ASN1_STRFLGS_DUMP_UNKNOWN,
    ASN1_STRFLGS_DUMP_DER,
    ASN1_STRFLGS_DUMP_ALL | ASN1_STRFLGS_DUMP_DER,
    ASN1_STRFLGS_DUMP_UNKNOWN | ASN1_STRFLGS_DUMP_DER,
    ASN1_STRFLGS_ESC_2253 | ASN1_STRFLGS_ESC_CTRL,
    ASN1_STRFLGS_ESC_2253 | ASN1_STRFLGS_ESC_QUOTE,
    ASN1_STRFLGS_ESC_2253 | ASN1_STRFLGS_ESC_CTRL | ASN1_STRFLGS_ESC_QUOTE,
    ASN1_STRFLGS_ESC_CTRL | ASN1_STRFLGS_ESC_MSB,
    ASN1_STRFLGS_ESC_2253 | ASN1_STRFLGS_ESC_MSB,
    ASN1_STRFLGS_ESC_2254 | ASN1_STRFLGS_ESC_CTRL,
    ASN1_STRFLGS_RFC2253,
    ASN1_STRFLGS_RFC2253 | ASN1_STRFLGS_SHOW_TYPE,
    ASN1_STRFLGS_RFC2253 | ASN1_STRFLGS_IGNORE_TYPE,
};

/*
 * `do_dump` builds a stack `ASN1_TYPE` whose `value.ptr` is the `ASN1_STRING`
 * itself, so with `DUMP_DER` the encoder reinterprets that pointer according to
 * the string's `type`. For a character type the union member really is the string
 * and the encoding is the string's own DER. For a type whose content the encoder
 * reads as a scalar — `BOOLEAN` above all — the "content" is the low bits of a
 * heap address, so the output differs between two processes running the same code
 * and cannot be compared. This probe therefore only asks for `DUMP_DER` on the
 * types where the union member is the string.
 */
static int der_comparable(int type)
{
    switch (type) {
    case V_ASN1_UTF8STRING:
    case V_ASN1_NUMERICSTRING:
    case V_ASN1_PRINTABLESTRING:
    case V_ASN1_T61STRING:
    case V_ASN1_IA5STRING:
    case V_ASN1_UTCTIME:
    case V_ASN1_GENERALIZEDTIME:
    case V_ASN1_ISO64STRING:
    case V_ASN1_UNIVERSALSTRING:
    case V_ASN1_BMPSTRING:
    case V_ASN1_OCTET_STRING:
        return 1;
    default:
        return 0;
    }
}

/*
 * Render `data` as a string of `type` under every flag case, once for the length
 * (a null sink) and once for the bytes.
 */
static void strex(const char *key, int type, const unsigned char *data, int len)
{
    size_t i;

    for (i = 0; i < sizeof(flag_cases) / sizeof(flag_cases[0]); i++) {
        ASN1_STRING *s;
        BIO *b = BIO_new(BIO_s_mem());
        char k[160];
        int measured, rv;

        if ((flag_cases[i] & ASN1_STRFLGS_DUMP_DER) && !der_comparable(type))
            continue;
        s = ASN1_STRING_type_new(type);
        if (len >= 0)
            ASN1_STRING_set(s, data, len);
        ERR_clear_error();
        measured = ASN1_STRING_print_ex(NULL, s, flag_cases[i]);
        snprintf(k, sizeof(k), "strex.%s.f%zu", key, i);
        printf("%s.measure=%d\n", k, measured);
        rv = ASN1_STRING_print_ex(b, s, flag_cases[i]);
        printf("%s.rv=%d\n", k, rv);
        printf("%s.same=%d\n", k, rv == measured ? 1 : 0);
        show_bio(k, b);
        drain("strex.err");
        BIO_free(b);
        ASN1_STRING_free(s);
    }
}

static void part_strex(void)
{
    static const unsigned char plain[] = "hello";
    static const unsigned char specials[] = "a b,c+d\"e\\f<g>h;i#j(k)l*m\x00n";
    static const unsigned char leading_space[] = " x";
    static const unsigned char trailing_space[] = "x ";
    static const unsigned char high_bit[] = { 'a', 0x80, 0xe9, 0xff, 'b' };
    static const unsigned char utf8_euro[] = { 'a', 0xe2, 0x82, 0xac, 'b' };
    static const unsigned char four_byte[] = { 0xf0, 0x9f, 0x98, 0x80 };
    static const unsigned char bmp_pair[] = { 0x00, 'A', 0x20, 0xac };
    static const unsigned char univ_pair[] = { 0, 0, 0, 'A', 0, 0, 0x20, 0xac };
    static const unsigned char bad_utf8[] = { 0xff, 0x41 };
    static const unsigned char empty[] = "";

    strex("printable", V_ASN1_PRINTABLESTRING, plain, 5);
    strex("ia5_specials", V_ASN1_IA5STRING, specials, (int)sizeof(specials) - 1);
    strex("ia5_leading_space", V_ASN1_IA5STRING, leading_space, 2);
    strex("ia5_trailing_space", V_ASN1_IA5STRING, trailing_space, 2);
    strex("empty", V_ASN1_IA5STRING, empty, 0);
    strex("high_bit", V_ASN1_IA5STRING, high_bit, (int)sizeof(high_bit));
    strex("numeric", V_ASN1_NUMERICSTRING, (const unsigned char *)"12 34", 5);
    strex("t61", V_ASN1_T61STRING, high_bit, (int)sizeof(high_bit));
    strex("utctime", V_ASN1_UTCTIME, (const unsigned char *)"200101000000Z", 13);
    strex("utf8", V_ASN1_UTF8STRING, utf8_euro, (int)sizeof(utf8_euro));
    strex("utf8_four_byte", V_ASN1_UTF8STRING, four_byte, (int)sizeof(four_byte));
    strex("utf8_bad", V_ASN1_UTF8STRING, bad_utf8, (int)sizeof(bad_utf8));
    strex("utf8_empty", V_ASN1_UTF8STRING, empty, 0);
    strex("bmp", V_ASN1_BMPSTRING, bmp_pair, (int)sizeof(bmp_pair));
    strex("bmp_odd", V_ASN1_BMPSTRING, (const unsigned char *)"\x00", 1);
    strex("univ", V_ASN1_UNIVERSALSTRING, univ_pair, (int)sizeof(univ_pair));
    strex("univ_bad_len", V_ASN1_UNIVERSALSTRING, (const unsigned char *)"\x00\x00\x00", 3);
    /* Types that are not character strings at all, and the boundaries of the
     * table: -1, 0, 1, 4, 21, 25, 27, 29, 30 and 31. */
    strex("octet", V_ASN1_OCTET_STRING, (const unsigned char *)"\x01\x02\x03", 3);
    strex("boolean", V_ASN1_BOOLEAN, (const unsigned char *)"\x01", 1);
    strex("type_minus_one", -1, (const unsigned char *)"ab", 2);
    strex("type_zero", 0, (const unsigned char *)"ab", 2);
    strex("type_one", 1, (const unsigned char *)"ab", 2);
    strex("type_21", 21, (const unsigned char *)"ab", 2);
    strex("type_25", 25, (const unsigned char *)"ab", 2);
    strex("type_27", 27, (const unsigned char *)"ab", 2);
    strex("type_29", 29, (const unsigned char *)"ab", 2);
    strex("type_30", 30, (const unsigned char *)"ab", 2);
    strex("type_31", 31, (const unsigned char *)"ab", 2);

    /* Every byte, as a one-byte IA5String, under RFC2253 and under ESC_MSB
     * alone: this is the observation that pins `char_type[]` and the high-bit
     * branch together. */
    {
        unsigned char one[2];
        char key[32];
        int c;

        for (c = 0; c < 256; c++) {
            ASN1_STRING *s;
            BIO *b = BIO_new(BIO_s_mem());
            char buf[64];
            int rv, n;

            one[0] = (unsigned char)c;
            one[1] = 0;
            s = ASN1_STRING_type_new(V_ASN1_IA5STRING);
            ASN1_STRING_set(s, one, 1);
            ERR_clear_error();
            rv = ASN1_STRING_print_ex(b, s, ASN1_STRFLGS_RFC2253);
            n = BIO_read(b, buf, (int)sizeof(buf) - 1);
            if (n < 0)
                n = 0;
            buf[n] = '\0';
            snprintf(key, sizeof(key), "byte.%02x", c);
            printf("%s.rv=%d\n", key, rv);
            text(key, (const unsigned char *)buf, n);
            BIO_free(b);

            b = BIO_new(BIO_s_mem());
            rv = ASN1_STRING_print_ex(b, s, ASN1_STRFLGS_ESC_MSB);
            printf("%s.msb=%d\n", key, rv);
            n = BIO_read(b, buf, (int)sizeof(buf) - 1);
            if (n < 0)
                n = 0;
            text(key, (const unsigned char *)buf, n);
            BIO_free(b);

            b = BIO_new(BIO_s_mem());
            rv = ASN1_STRING_print_ex(b, s, ASN1_STRFLGS_ESC_QUOTE);
            printf("%s.quote=%d\n", key, rv);
            n = BIO_read(b, buf, (int)sizeof(buf) - 1);
            if (n < 0)
                n = 0;
            text(key, (const unsigned char *)buf, n);
            BIO_free(b);

            ASN1_STRING_free(s);
            ERR_clear_error();
        }
    }

    /* The FILE sink, which is a separate callback over the same core. */
    {
        ASN1_STRING *s = ASN1_STRING_type_new(V_ASN1_IA5STRING);
        FILE *fp = tmpfile();
        char buf[64];
        int n, rv;

        ASN1_STRING_set(s, "a b,c", 5);
        rv = ASN1_STRING_print_ex_fp(fp, s, ASN1_STRFLGS_RFC2253);
        printf("fp.rv=%d\n", rv);
        fflush(fp);
        rewind(fp);
        n = (int)fread(buf, 1, sizeof(buf) - 1, fp);
        if (n < 0)
            n = 0;
        buf[n] = '\0';
        printf("fp.len=%d\n", n);
        text("fp", (const unsigned char *)buf, n);
        fclose(fp);

        /* A null FILE is the counting form, like a null BIO. */
        printf("fp.null=%d\n",
               ASN1_STRING_print_ex_fp(NULL, s, ASN1_STRFLGS_RFC2253));
        ASN1_STRING_free(s);
        ERR_clear_error();
    }
}

static void utf8_of(const char *key, int type, const unsigned char *data, int len)
{
    ASN1_STRING *s = ASN1_STRING_type_new(type);
    unsigned char *out = NULL;
    int rv;

    if (len >= 0)
        ASN1_STRING_set(s, data, len);
    ERR_clear_error();
    rv = ASN1_STRING_to_UTF8(&out, s);
    printf("toutf8.%s.rv=%d\n", key, rv);
    hex(key, out, rv > 0 ? rv : 0);
    drain("toutf8.err");
    OPENSSL_free(out);
    ASN1_STRING_free(s);
}

static void part_to_utf8(void)
{
    static const unsigned char ascii[] = "hello";
    static const unsigned char high_bit[] = { 'a', 0xe9, 'b' };
    static const unsigned char utf8_euro[] = { 'a', 0xe2, 0x82, 0xac, 'b' };
    static const unsigned char utf8_four[] = { 0xf0, 0x9f, 0x98, 0x80 };
    static const unsigned char bmp_pair[] = { 0x00, 'A', 0x20, 0xac };
    static const unsigned char univ_pair[] = { 0, 0, 0, 'A', 0, 0, 0x20, 0xac };
    static const unsigned char bad_utf8[] = { 0xff };

    utf8_of("printable", V_ASN1_PRINTABLESTRING, ascii, 5);
    utf8_of("ia5", V_ASN1_IA5STRING, ascii, 5);
    utf8_of("t61_high", V_ASN1_T61STRING, high_bit, 3);
    utf8_of("numeric", V_ASN1_NUMERICSTRING, (const unsigned char *)"12 34", 5);
    utf8_of("utctime", V_ASN1_UTCTIME, (const unsigned char *)"200101000000Z", 13);
    utf8_of("generic_time", V_ASN1_GENERALIZEDTIME,
            (const unsigned char *)"20200101000000Z", 15);
    utf8_of("utf8_euro", V_ASN1_UTF8STRING, utf8_euro, 5);
    utf8_of("utf8_four", V_ASN1_UTF8STRING, utf8_four, 4);
    utf8_of("utf8_bad", V_ASN1_UTF8STRING, bad_utf8, 1);
    utf8_of("bmp", V_ASN1_BMPSTRING, bmp_pair, 4);
    utf8_of("univ", V_ASN1_UNIVERSALSTRING, univ_pair, 8);
    utf8_of("empty", V_ASN1_IA5STRING, (const unsigned char *)"", 0);
    utf8_of("octet", V_ASN1_OCTET_STRING, (const unsigned char *)"\x01", 1);
    utf8_of("boolean", V_ASN1_BOOLEAN, (const unsigned char *)"\x01", 1);
    utf8_of("null_in", V_ASN1_IA5STRING, NULL, -1);

    /* The null input, and the two type boundaries. */
    {
        unsigned char *out = NULL;
        ASN1_STRING *s = ASN1_STRING_type_new(V_ASN1_IA5STRING);
        char *p = (char *)"x";

        printf("toutf8.null_in=%d\n", ASN1_STRING_to_UTF8(&out, NULL));
        printf("toutf8.null_out_ptr=%d\n", out == NULL ? 1 : 0);
        (void)p;
        ASN1_STRING_free(s);
        ERR_clear_error();
    }
    utf8_of("type_31", 31, (const unsigned char *)"ab", 2);
    utf8_of("type_minus_one", -1, (const unsigned char *)"ab", 2);
}

int main(void)
{
    /*
     * One line per observation and no buffering: a probe that dies part-way
     * through then leaves the observations it *did* make in the transcript, which
     * is what localises the failure. With a block-buffered stdout an abort loses
     * every line printed before it, and the court can only report that nothing
     * matched.
     */
    setvbuf(stdout, NULL, _IOLBF, 0);

    part_printable();
    part_universalstring();
    part_string_print();
    part_mbstring();
    part_string_table();
    part_printers();
    part_strex();
    part_to_utf8();
    printf("done=1\n");
    return 0;
}
