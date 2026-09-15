/*
 * RT-PARAM -- the parameter descriptor, differentially.
 *
 * What this court has to establish
 * --------------------------------
 * An `OSSL_PARAM` is not an operation, it is a *data* type, and its behaviour is a
 * function of three independent axes a caller sets:
 *
 *   * the parameter's own `data_type` -- seven of them (INTEGER, UNSIGNED_INTEGER,
 *     REAL, UTF8_STRING, OCTET_STRING, UTF8_PTR, OCTET_PTR), each of which every getter
 *     and setter answers differently;
 *   * the width and signedness the *caller's* accessor uses, which need not match the
 *     parameter's and which for four of the seven types selects a fast path that is not
 *     the general conversion path;
 *   * whether `data` is NULL, which turns a setter from a write into a size query that
 *     answers **success**.
 *
 * So the probe is a matrix, not a scenario list. For each cell it records the return
 * code, the error queue, and -- where the call succeeded -- the value or the bytes it
 * produced. The reason to do it this way is that the *refusals* are where a plausible
 * implementation and the authority disagree: a negative `UNSIGNED_INTEGER` and a
 * too-large one are two different error reasons, and a caller that exercises only the
 * happy path cannot tell the two implementations apart.
 *
 * A parameter's payload is in **native byte order**, little-endian here, so the sources
 * below are spelled as bytes and the bytes the probe prints are the bytes as laid out.
 * `src/runtime/params/mod.rs` takes the little-endian arm of every one of the
 * authority's byte-order branches, which is the opposite of `ASN1_INTEGER` one stratum
 * below.
 *
 * Fault boundaries
 * ----------------
 * A probe cannot compare a crash, so where the authority faults the probe prints a
 * `NOT_MEASURED_AUTHORITY_FAULTS` marker and the candidate's safer behaviour is recorded
 * in `docs/SECURITY_DIVERGENCE_POLICY.md`. `OSSL_PARAM_print_to_bio` with a NULL array
 * is the one such boundary here (D103).
 *
 * Every observation is `key=value` on stdout, one line each, with unique keys. The
 * `err=` field is the packed `ERR_peek_error()` read immediately after the call and
 * cleared before the next, so it belongs to its own call.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/param_build.h>
#include <openssl/params.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ---------------------------------------------------------------- reporting */

#define SAY(key, expr)                                                        \
    do {                                                                      \
        int rc_ = (expr);                                                     \
        unsigned long e_ = ERR_peek_error();                                  \
        printf("%s=%d err=%lu\n", (key), rc_, e_);                            \
        ERR_clear_error();                                                    \
    } while (0)

static void sayp(const char *key, const void *p)
{
    unsigned long e = ERR_peek_error();

    printf("%s=%s err=%lu\n", key, p == NULL ? "NULL" : "nonnull", e);
    ERR_clear_error();
}

static void sayn(const char *key, long long v)
{
    unsigned long e = ERR_peek_error();

    printf("%s=%lld err=%lu\n", key, v, e);
    ERR_clear_error();
}

static void says(const char *key, const char *s)
{
    unsigned long e = ERR_peek_error();

    printf("%s=%s err=%lu\n", key, s == NULL ? "(null)" : s, e);
    ERR_clear_error();
}

static void sayf(const char *key, double d)
{
    unsigned long e = ERR_peek_error();

    printf("%s=%.17g err=%lu\n", key, d, e);
    ERR_clear_error();
}

static void saysz(const char *key, size_t v)
{
    unsigned long e = ERR_peek_error();

    printf("%s=%zu err=%lu\n", key, v, e);
    ERR_clear_error();
}

/* A byte string as lowercase hex, two digits per byte. */
static void hexcat(char *dst, const unsigned char *b, size_t n)
{
    static const char *D = "0123456789abcdef";
    size_t i;

    for (i = 0; i < n; i++) {
        dst[2 * i] = D[b[i] >> 4];
        dst[2 * i + 1] = D[b[i] & 0xf];
    }
    dst[2 * n] = '\0';
}

/* ------------------------------------------------ the descriptor's own fields */

/*
 * By value: a constructor *returns* a descriptor, so `&OSSL_PARAM_construct_int(...)`
 * would be the address of an rvalue and does not compile. Taking it by value is also
 * what the authority's own prototype does, and it keeps every field observable.
 */
static void describe(const char *key, OSSL_PARAM p)
{
    char buf[192];

    snprintf(buf, sizeof buf, "key=%s type=%u size=%zu ret=%zu",
             p.key == NULL ? "(null)" : p.key, p.data_type, p.data_size, p.return_size);
    printf("%s=%s\n", key, buf);
}

/*
 * A slot for the places that genuinely need a *writable* descriptor, since a function
 * that sets a parameter takes `OSSL_PARAM *`. Each call below materialises exactly one
 * rvalue, so one slot is enough; the probe is single-threaded.
 */
static OSSL_PARAM scratch_param;

static OSSL_PARAM *mk(OSSL_PARAM v)
{
    scratch_param = v;
    return &scratch_param;
}

static void constructors(void)
{
    int i = 0;
    unsigned int u = 0;
    long l = 0;
    unsigned long ul = 0;
    int32_t i32 = 0;
    uint32_t u32 = 0;
    int64_t i64 = 0;
    uint64_t u64 = 0;
    size_t st = 0;
    time_t tt = 0;
    double d = 0.0;
    unsigned char bn[8];
    char s8[8];

    memset(bn, 0, sizeof bn);
    memset(s8, 0, sizeof s8);

    describe("construct.int", OSSL_PARAM_construct_int("k", &i));
    describe("construct.uint", OSSL_PARAM_construct_uint("k", &u));
    describe("construct.long", OSSL_PARAM_construct_long("k", &l));
    describe("construct.ulong", OSSL_PARAM_construct_ulong("k", &ul));
    describe("construct.int32", OSSL_PARAM_construct_int32("k", &i32));
    describe("construct.uint32", OSSL_PARAM_construct_uint32("k", &u32));
    describe("construct.int64", OSSL_PARAM_construct_int64("k", &i64));
    describe("construct.uint64", OSSL_PARAM_construct_uint64("k", &u64));
    describe("construct.size_t", OSSL_PARAM_construct_size_t("k", &st));
    describe("construct.time_t", OSSL_PARAM_construct_time_t("k", &tt));
    describe("construct.double", OSSL_PARAM_construct_double("k", &d));
    describe("construct.BN", OSSL_PARAM_construct_BN("k", bn, sizeof bn));
    /* A zero `bsize` with a non-NULL buffer means "measure it". */
    describe("construct.utf8_string.size0",
             OSSL_PARAM_construct_utf8_string("k", s8, 0));
    describe("construct.octet_string",
             OSSL_PARAM_construct_octet_string("k", s8, 5));
    /* A NULL buffer is allowed and keeps the declared size. */
    describe("construct.utf8_string.null_buffer",
             OSSL_PARAM_construct_utf8_string("k", NULL, 7));
    describe("construct.utf8_ptr", OSSL_PARAM_construct_utf8_ptr("k", (char **) s8, 3));
    describe("construct.octet_ptr", OSSL_PARAM_construct_octet_ptr("k", (void **) s8, 4));
    describe("construct.end", OSSL_PARAM_construct_end());
}

static void locate_and_modified(void)
{
    int a = 0;
    unsigned char b[4];
    char txt[8];
    OSSL_PARAM arr[4];

    memset(b, 0, sizeof b);
    memcpy(txt, "abc", 4);

    arr[0] = OSSL_PARAM_construct_int("one", &a);
    arr[1] = OSSL_PARAM_construct_BN("two", b, sizeof b);
    arr[2] = OSSL_PARAM_construct_utf8_string("three", txt, 3);
    arr[3] = OSSL_PARAM_construct_end();

    sayp("locate.found", OSSL_PARAM_locate(arr, "one"));
    sayp("locate.found.last", OSSL_PARAM_locate(arr, "three"));
    sayp("locate.absent", OSSL_PARAM_locate(arr, "four"));
    sayp("locate.null_array", OSSL_PARAM_locate(NULL, "one"));
    sayp("locate.null_key", OSSL_PARAM_locate(arr, NULL));
    /* A lookup matches the whole key, not a prefix, and is case-sensitive. */
    sayp("locate.prefix_of_key", OSSL_PARAM_locate(arr, "on"));
    sayp("locate.key_extends", OSSL_PARAM_locate(arr, "onex"));
    sayp("locate.case_sensitive", OSSL_PARAM_locate(arr, "ONE"));
    sayp("locate_const.found", OSSL_PARAM_locate_const(arr, "two"));
    sayp("locate_const.absent", OSSL_PARAM_locate_const(arr, "nope"));

    /* `modified` is `return_size != OSSL_PARAM_UNMODIFIED` and nothing more. */
    sayn("modified.fresh", OSSL_PARAM_modified(&arr[0]));
    sayn("modified.null", OSSL_PARAM_modified(NULL));
    SAY("modified.set_int", OSSL_PARAM_set_int(&arr[0], 7));
    sayn("modified.after_set", OSSL_PARAM_modified(&arr[0]));
    sayn("modified.after_set.sibling", OSSL_PARAM_modified(&arr[1]));
    /* A size query marks the parameter modified as well, because it sets
     * `return_size`. */
    SAY("modified.size_query", OSSL_PARAM_set_int(
            mk(OSSL_PARAM_construct_int("q", NULL)), 7));
    sayn("modified.after_size_query", OSSL_PARAM_modified(
            mk(OSSL_PARAM_construct_int("q", NULL))));
    OSSL_PARAM_set_all_unmodified(arr);
    sayn("modified.after_reset.sum",
         OSSL_PARAM_modified(&arr[0]) + OSSL_PARAM_modified(&arr[1])
             + OSSL_PARAM_modified(&arr[2]));
    /* A NULL array is a no-op rather than a fault. */
    OSSL_PARAM_set_all_unmodified(NULL);
    sayn("modified.set_all_unmodified.null", 1);
}

/* ------------------------------------------------------- the integer matrix */

/*
 * The payload is a byte string in native order, so `size` is free-form: the authority's
 * accessors have fast paths for exactly four and eight bytes and fall back to a
 * width-independent conversion for anything else, and the fallback is different code.
 */
struct source {
    const char *name;
    unsigned int type;
    size_t size;
    unsigned char bytes[9];
};

static const struct source SOURCES[] = {
    { "i4.zero", OSSL_PARAM_INTEGER, 4, { 0x00, 0x00, 0x00, 0x00 } },
    { "i4.one", OSSL_PARAM_INTEGER, 4, { 0x01, 0x00, 0x00, 0x00 } },
    { "i4.neg1", OSSL_PARAM_INTEGER, 4, { 0xff, 0xff, 0xff, 0xff } },
    { "i4.min", OSSL_PARAM_INTEGER, 4, { 0x00, 0x00, 0x00, 0x80 } },
    { "i4.max", OSSL_PARAM_INTEGER, 4, { 0xff, 0xff, 0xff, 0x7f } },
    { "i8.zero", OSSL_PARAM_INTEGER, 8, { 0, 0, 0, 0, 0, 0, 0, 0 } },
    { "i8.neg1", OSSL_PARAM_INTEGER, 8, { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } },
    { "i8.min", OSSL_PARAM_INTEGER, 8, { 0, 0, 0, 0, 0, 0, 0, 0x80 } },
    { "i8.max", OSSL_PARAM_INTEGER, 8, { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f } },
    { "i8.int32max_plus1", OSSL_PARAM_INTEGER, 8, { 0x00, 0x00, 0x00, 0x80, 0, 0, 0, 0 } },
    { "u4.zero", OSSL_PARAM_UNSIGNED_INTEGER, 4, { 0, 0, 0, 0 } },
    { "u4.max", OSSL_PARAM_UNSIGNED_INTEGER, 4, { 0xff, 0xff, 0xff, 0xff } },
    { "u4.int32max", OSSL_PARAM_UNSIGNED_INTEGER, 4, { 0xff, 0xff, 0xff, 0x7f } },
    { "u4.int32max_plus1", OSSL_PARAM_UNSIGNED_INTEGER, 4, { 0x00, 0x00, 0x00, 0x80 } },
    { "u8.max", OSSL_PARAM_UNSIGNED_INTEGER, 8, { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } },
    { "u8.int64max", OSSL_PARAM_UNSIGNED_INTEGER, 8, { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f } },
    { "u8.int64max_plus1", OSSL_PARAM_UNSIGNED_INTEGER, 8, { 0, 0, 0, 0, 0, 0, 0, 0x80 } },
    /* Odd widths, which take the width-independent conversion. */
    { "i1.neg1", OSSL_PARAM_INTEGER, 1, { 0xff } },
    { "i1.neg128", OSSL_PARAM_INTEGER, 1, { 0x80 } },
    { "i1.pos127", OSSL_PARAM_INTEGER, 1, { 0x7f } },
    { "u1.255", OSSL_PARAM_UNSIGNED_INTEGER, 1, { 0xff } },
    { "i3.neg8388608", OSSL_PARAM_INTEGER, 3, { 0x00, 0x00, 0x80 } },
    { "u3.16777215", OSSL_PARAM_UNSIGNED_INTEGER, 3, { 0xff, 0xff, 0xff } },
    { "i2.neg2", OSSL_PARAM_INTEGER, 2, { 0xfe, 0xff } },
    { "u5.4294967296", OSSL_PARAM_UNSIGNED_INTEGER, 5, { 0, 0, 0, 0, 0x01 } },
    { "i5.neg1", OSSL_PARAM_INTEGER, 5, { 0xff, 0xff, 0xff, 0xff, 0xff } },
    /* Wider than any native accessor. */
    { "u9.one", OSSL_PARAM_UNSIGNED_INTEGER, 9, { 0x01, 0, 0, 0, 0, 0, 0, 0, 0 } },
};

static void read_matrix(void)
{
    size_t s;
    char key[96];

    for (s = 0; s < sizeof SOURCES / sizeof SOURCES[0]; s++) {
        const struct source *src = &SOURCES[s];
        unsigned char payload[9];
        OSSL_PARAM p = { "k", 0, NULL, 0, OSSL_PARAM_UNMODIFIED };
        int32_t o32 = 0;
        uint32_t ou32 = 0;
        int64_t o64 = 0;
        uint64_t ou64 = 0;
        long ol = 0;
        size_t osz = 0;
        double od = 0.0;
        BIGNUM *bn = NULL;
        int rc;

        memcpy(payload, src->bytes, src->size);
        p.data_type = src->type;
        p.data = payload;
        p.data_size = src->size;

        snprintf(key, sizeof key, "read.%s.get_int32", src->name);
        rc = OSSL_PARAM_get_int32(&p, &o32);
        printf("%s=%d err=%lu v=%d\n", key, rc, ERR_peek_error(), rc ? (int) o32 : 0);
        ERR_clear_error();

        snprintf(key, sizeof key, "read.%s.get_uint32", src->name);
        rc = OSSL_PARAM_get_uint32(&p, &ou32);
        printf("%s=%d err=%lu v=%u\n", key, rc, ERR_peek_error(), rc ? ou32 : 0u);
        ERR_clear_error();

        snprintf(key, sizeof key, "read.%s.get_int64", src->name);
        rc = OSSL_PARAM_get_int64(&p, &o64);
        printf("%s=%d err=%lu v=%lld\n", key, rc, ERR_peek_error(),
               rc ? (long long) o64 : 0LL);
        ERR_clear_error();

        snprintf(key, sizeof key, "read.%s.get_uint64", src->name);
        rc = OSSL_PARAM_get_uint64(&p, &ou64);
        printf("%s=%d err=%lu v=%llu\n", key, rc, ERR_peek_error(),
               rc ? (unsigned long long) ou64 : 0ULL);
        ERR_clear_error();

        snprintf(key, sizeof key, "read.%s.get_long", src->name);
        rc = OSSL_PARAM_get_long(&p, &ol);
        printf("%s=%d err=%lu v=%ld\n", key, rc, ERR_peek_error(), rc ? ol : 0L);
        ERR_clear_error();

        snprintf(key, sizeof key, "read.%s.get_size_t", src->name);
        rc = OSSL_PARAM_get_size_t(&p, &osz);
        printf("%s=%d err=%lu v=%zu\n", key, rc, ERR_peek_error(), rc ? osz : (size_t) 0);
        ERR_clear_error();

        snprintf(key, sizeof key, "read.%s.get_double", src->name);
        rc = OSSL_PARAM_get_double(&p, &od);
        printf("%s=%d err=%lu v=%.17g\n", key, rc, ERR_peek_error(), rc ? od : 0.0);
        ERR_clear_error();

        snprintf(key, sizeof key, "read.%s.get_BN", src->name);
        rc = OSSL_PARAM_get_BN(&p, &bn);
        if (rc == 1 && bn != NULL) {
            char *h = BN_bn2hex(bn);

            printf("%s=%d err=%lu v=%s\n", key, rc, ERR_peek_error(),
                   h == NULL ? "(null)" : h);
            OPENSSL_free(h);
        } else {
            printf("%s=%d err=%lu v=%s\n", key, rc, ERR_peek_error(),
                   bn == NULL ? "NULL" : "nonnull");
        }
        BN_free(bn);
        ERR_clear_error();
    }

    /* A `REAL` source's conversions to an integer have to be *exact*, which is what
     * `real_shift` decides; these are the values either side of each boundary. */
    {
        static const double REAL_VALUES[] = {
            0.0, 1.0, -1.0, 1.5, -1.5, 2.0, 2147483647.0, 2147483648.0,
            4294967295.0, 4294967296.0, 9223372036854775808.0, 1e18, 1e19, 0.25
        };
        size_t i;

        for (i = 0; i < sizeof REAL_VALUES / sizeof REAL_VALUES[0]; i++) {
            double v = REAL_VALUES[i];
            OSSL_PARAM p = { "k", OSSL_PARAM_REAL, NULL, 0, OSSL_PARAM_UNMODIFIED };
            int32_t o32 = 0;
            int64_t o64 = 0;
            uint32_t ou32 = 0;
            uint64_t ou64 = 0;
            int rc;

            p.data = &v;
            p.data_size = sizeof v;

            snprintf(key, sizeof key, "real.%zu.get_int32", i);
            rc = OSSL_PARAM_get_int32(&p, &o32);
            printf("%s=%d err=%lu v=%d\n", key, rc, ERR_peek_error(), rc ? (int) o32 : 0);
            ERR_clear_error();

            snprintf(key, sizeof key, "real.%zu.get_uint32", i);
            rc = OSSL_PARAM_get_uint32(&p, &ou32);
            printf("%s=%d err=%lu v=%u\n", key, rc, ERR_peek_error(), rc ? ou32 : 0u);
            ERR_clear_error();

            snprintf(key, sizeof key, "real.%zu.get_int64", i);
            rc = OSSL_PARAM_get_int64(&p, &o64);
            printf("%s=%d err=%lu v=%lld\n", key, rc, ERR_peek_error(),
                   rc ? (long long) o64 : 0LL);
            ERR_clear_error();

            snprintf(key, sizeof key, "real.%zu.get_uint64", i);
            rc = OSSL_PARAM_get_uint64(&p, &ou64);
            printf("%s=%d err=%lu v=%llu\n", key, rc, ERR_peek_error(),
                   rc ? (unsigned long long) ou64 : 0ULL);
            ERR_clear_error();
        }
    }

    /* The refusals that do not depend on the value at all. */
    {
        int32_t out = 0;
        double dout = 0.0;
        unsigned char buf[8];
        OSSL_PARAM p = { "k", OSSL_PARAM_INTEGER, NULL, 0, OSSL_PARAM_UNMODIFIED };
        BIGNUM *b = NULL;

        SAY("bad.get_int32.null_val", OSSL_PARAM_get_int32(&p, NULL));
        SAY("bad.get_int32.null_param", OSSL_PARAM_get_int32(NULL, &out));
        memset(buf, 0, sizeof buf);
        p.data = buf;
        p.data_size = sizeof buf;
        p.data_type = OSSL_PARAM_OCTET_STRING;
        SAY("bad.get_int32.wrong_type", OSSL_PARAM_get_int32(&p, &out));
        p.data_type = OSSL_PARAM_REAL;
        p.data_size = 4; /* not sizeof(double) */
        SAY("bad.get_int32.real_wrong_width", OSSL_PARAM_get_int32(&p, &out));
        SAY("bad.get_double.null_val", OSSL_PARAM_get_double(&p, NULL));
        p.data_type = OSSL_PARAM_OCTET_STRING;
        SAY("bad.get_double.wrong_type", OSSL_PARAM_get_double(&p, &dout));

        /* A NULL `data` is a refusal for every getter. */
        p.data = NULL;
        p.data_size = 4;
        p.data_type = OSSL_PARAM_INTEGER;
        SAY("bad.get_int32.null_data", OSSL_PARAM_get_int32(&p, &out));
        SAY("bad.get_uint32.null_data", OSSL_PARAM_get_uint32(&p, (uint32_t *) &out));
        SAY("bad.get_int64.null_data", OSSL_PARAM_get_int64(&p, (int64_t *) &out));
        SAY("bad.get_uint64.null_data", OSSL_PARAM_get_uint64(&p, (uint64_t *) &out));
        SAY("bad.get_long.null_data", OSSL_PARAM_get_long(&p, (long *) &out));
        SAY("bad.get_ulong.null_data", OSSL_PARAM_get_ulong(&p, (unsigned long *) &out));
        SAY("bad.get_size_t.null_data", OSSL_PARAM_get_size_t(&p, (size_t *) &out));
        SAY("bad.get_time_t.null_data", OSSL_PARAM_get_time_t(&p, (time_t *) &out));
        SAY("bad.get_double.null_data", OSSL_PARAM_get_double(&p, &dout));
        SAY("bad.get_BN.null_data", OSSL_PARAM_get_BN(&p, &b));
        SAY("bad.get_BN.null_val", OSSL_PARAM_get_BN(NULL, &b));
    }
}

/*
 * Every setter against every destination shape. `return_size` is recorded even when the
 * call wrote nothing, because that is where the NULL-buffer arms report the size the
 * caller would have needed.
 */
struct dest {
    const char *name;
    unsigned int type;
    size_t size; /* 0 means a NULL buffer: the size-query arm */
};

static const struct dest DESTS[] = {
    { "i4", OSSL_PARAM_INTEGER, 4 },
    { "i8", OSSL_PARAM_INTEGER, 8 },
    { "i1", OSSL_PARAM_INTEGER, 1 },
    { "i3", OSSL_PARAM_INTEGER, 3 },
    { "i_null", OSSL_PARAM_INTEGER, 0 },
    { "u4", OSSL_PARAM_UNSIGNED_INTEGER, 4 },
    { "u8", OSSL_PARAM_UNSIGNED_INTEGER, 8 },
    { "u1", OSSL_PARAM_UNSIGNED_INTEGER, 1 },
    { "u3", OSSL_PARAM_UNSIGNED_INTEGER, 3 },
    { "u_null", OSSL_PARAM_UNSIGNED_INTEGER, 0 },
    { "real", OSSL_PARAM_REAL, 8 },
    { "real_null", OSSL_PARAM_REAL, 0 },
    { "utf8", OSSL_PARAM_UTF8_STRING, 8 },
    { "octet", OSSL_PARAM_OCTET_STRING, 8 },
    { "octet_ptr", OSSL_PARAM_OCTET_PTR, 8 },
    { "utf8_ptr", OSSL_PARAM_UTF8_PTR, 8 },
};

static void report_write(const char *key, const OSSL_PARAM *p, int rc, unsigned char *buf,
                         size_t cap)
{
    char hex[64];

    if (p->data == NULL) {
        printf("%s=%d err=%lu ret=%zu\n", key, rc, ERR_peek_error(), p->return_size);
    } else {
        hexcat(hex, buf, cap);
        printf("%s=%d err=%lu ret=%zu bytes=%s\n", key, rc, ERR_peek_error(),
               p->return_size, hex);
    }
    ERR_clear_error();
}

/* A destination descriptor over `buf` with the shape `d` describes. */
static OSSL_PARAM mkdst(const struct dest *d, unsigned char *buf)
{
    OSSL_PARAM p = { "k", d->type, NULL, 0, OSSL_PARAM_UNMODIFIED };

    p.data = d->size == 0 ? NULL : buf;
    p.data_size = d->size;
    return p;
}

static void write_matrix(void)
{
    static const int32_t I32_VALUES[] = { 0, 1, -1, INT32_MIN, INT32_MAX };
    static const uint32_t U32_VALUES[] = { 0, 1, 2147483647u, 2147483648u, UINT32_MAX };
    static const int64_t I64_VALUES[] = { 0, 1, -1, INT64_MIN, INT64_MAX, 2147483648LL };
    static const uint64_t U64_VALUES[] = { 0, 1, 9223372036854775807ULL,
                                           9223372036854775808ULL, UINT64_MAX };
    static const double D_VALUES[] = { 0.0, 1.0, -1.0, 1.5, 2147483647.0, 2147483648.0,
                                       4294967296.0, 9223372036854775808.0, 1e19, 3.5 };
    size_t di;
    char key[128];
    size_t i;

    for (di = 0; di < sizeof DESTS / sizeof DESTS[0]; di++) {
        const struct dest *d = &DESTS[di];
        unsigned char buf[16];

        for (i = 0; i < sizeof I32_VALUES / sizeof I32_VALUES[0]; i++) {
            OSSL_PARAM p;

            memset(buf, 0xaa, sizeof buf);
            p = mkdst(d, buf);
            snprintf(key, sizeof key, "write.%s.set_int32.%zu", d->name, i);
            report_write(key, &p, OSSL_PARAM_set_int32(&p, I32_VALUES[i]), buf,
                         d->size == 0 ? 0 : d->size);
        }
        for (i = 0; i < sizeof U32_VALUES / sizeof U32_VALUES[0]; i++) {
            OSSL_PARAM p;

            memset(buf, 0xaa, sizeof buf);
            p = mkdst(d, buf);
            snprintf(key, sizeof key, "write.%s.set_uint32.%zu", d->name, i);
            report_write(key, &p, OSSL_PARAM_set_uint32(&p, U32_VALUES[i]), buf,
                         d->size == 0 ? 0 : d->size);
        }
        for (i = 0; i < sizeof I64_VALUES / sizeof I64_VALUES[0]; i++) {
            OSSL_PARAM p;

            memset(buf, 0xaa, sizeof buf);
            p = mkdst(d, buf);
            snprintf(key, sizeof key, "write.%s.set_int64.%zu", d->name, i);
            report_write(key, &p, OSSL_PARAM_set_int64(&p, I64_VALUES[i]), buf,
                         d->size == 0 ? 0 : d->size);
        }
        for (i = 0; i < sizeof U64_VALUES / sizeof U64_VALUES[0]; i++) {
            OSSL_PARAM p;

            memset(buf, 0xaa, sizeof buf);
            p = mkdst(d, buf);
            snprintf(key, sizeof key, "write.%s.set_uint64.%zu", d->name, i);
            report_write(key, &p, OSSL_PARAM_set_uint64(&p, U64_VALUES[i]), buf,
                         d->size == 0 ? 0 : d->size);
        }
        for (i = 0; i < sizeof D_VALUES / sizeof D_VALUES[0]; i++) {
            OSSL_PARAM p;

            memset(buf, 0xaa, sizeof buf);
            p = mkdst(d, buf);
            snprintf(key, sizeof key, "write.%s.set_double.%zu", d->name, i);
            report_write(key, &p, OSSL_PARAM_set_double(&p, D_VALUES[i]), buf,
                         d->size == 0 ? 0 : d->size);
        }
        /* The width-preserving spellings, one value each, to show the delegation. */
        {
            OSSL_PARAM p;

            memset(buf, 0xaa, sizeof buf);
            p = mkdst(d, buf);
            snprintf(key, sizeof key, "write.%s.set_int.%d", d->name, -1);
            report_write(key, &p, OSSL_PARAM_set_int(&p, -1), buf,
                         d->size == 0 ? 0 : d->size);

            memset(buf, 0xaa, sizeof buf);
            p = mkdst(d, buf);
            snprintf(key, sizeof key, "write.%s.set_uint.%u", d->name, 7u);
            report_write(key, &p, OSSL_PARAM_set_uint(&p, 7u), buf,
                         d->size == 0 ? 0 : d->size);

            memset(buf, 0xaa, sizeof buf);
            p = mkdst(d, buf);
            snprintf(key, sizeof key, "write.%s.set_long.%ld", d->name, (long) -1);
            report_write(key, &p, OSSL_PARAM_set_long(&p, (long) -1), buf,
                         d->size == 0 ? 0 : d->size);

            memset(buf, 0xaa, sizeof buf);
            p = mkdst(d, buf);
            snprintf(key, sizeof key, "write.%s.set_ulong.max", d->name);
            report_write(key, &p, OSSL_PARAM_set_ulong(&p, ULONG_MAX), buf,
                         d->size == 0 ? 0 : d->size);

            memset(buf, 0xaa, sizeof buf);
            p = mkdst(d, buf);
            snprintf(key, sizeof key, "write.%s.set_size_t.%d", d->name, 1);
            report_write(key, &p, OSSL_PARAM_set_size_t(&p, (size_t) 1), buf,
                         d->size == 0 ? 0 : d->size);

            memset(buf, 0xaa, sizeof buf);
            p = mkdst(d, buf);
            snprintf(key, sizeof key, "write.%s.set_time_t.%ld", d->name, (long) 1000000);
            report_write(key, &p, OSSL_PARAM_set_time_t(&p, (time_t) 1000000), buf,
                         d->size == 0 ? 0 : d->size);
        }
    }

    /* A NULL descriptor is a refusal for every setter. */
    SAY("bad.set_int32.null", OSSL_PARAM_set_int32(NULL, 1));
    SAY("bad.set_uint32.null", OSSL_PARAM_set_uint32(NULL, 1));
    SAY("bad.set_int64.null", OSSL_PARAM_set_int64(NULL, 1));
    SAY("bad.set_uint64.null", OSSL_PARAM_set_uint64(NULL, 1));
    SAY("bad.set_double.null", OSSL_PARAM_set_double(NULL, 1.0));
    SAY("bad.set_int.null", OSSL_PARAM_set_int(NULL, 1));
    SAY("bad.set_uint.null", OSSL_PARAM_set_uint(NULL, 1));
    SAY("bad.set_long.null", OSSL_PARAM_set_long(NULL, 1));
    SAY("bad.set_ulong.null", OSSL_PARAM_set_ulong(NULL, 1));
    SAY("bad.set_size_t.null", OSSL_PARAM_set_size_t(NULL, 1));
    SAY("bad.set_time_t.null", OSSL_PARAM_set_time_t(NULL, 1));
    SAY("bad.set_utf8_string.null_param", OSSL_PARAM_set_utf8_string(NULL, "x"));
    SAY("bad.set_octet_string.null_param", OSSL_PARAM_set_octet_string(NULL, "x", 1));
    SAY("bad.set_utf8_ptr.null_param", OSSL_PARAM_set_utf8_ptr(NULL, "x"));
    SAY("bad.set_octet_ptr.null_param", OSSL_PARAM_set_octet_ptr(NULL, "x", 1));
    SAY("bad.set_octet_string_or_ptr.null", OSSL_PARAM_set_octet_string_or_ptr(NULL, "x", 1));
    SAY("bad.set_BN.null_param", OSSL_PARAM_set_BN(NULL, NULL));
}

/* ------------------------------------------------------- strings and pointers */

static void string_plane(void)
{
    char buf[16];
    char small[4];
    char out[16];
    char *outp = NULL;
    size_t used = 0;
    void *vp = NULL;
    const void *cvp = NULL;
    const char *cp = NULL;
    OSSL_PARAM p;
    char hex[40];

    /* A UTF-8 set with room for a terminator appends one that is not counted. */
    memset(buf, 0xaa, sizeof buf);
    p = OSSL_PARAM_construct_utf8_string("k", buf, 0);
    sayn("str.utf8.size0_construct.is_measured", (long long) p.data_size);
    SAY("str.utf8.set.abc", OSSL_PARAM_set_utf8_string(&p, "abc"));
    sayn("str.utf8.return_size", (long long) p.return_size);
    hexcat(hex, (const unsigned char *) buf, 5);
    printf("str.utf8.bytes=%s\n", hex);
    SAY("str.utf8.get.max16", OSSL_PARAM_get_utf8_string(&p, &outp, sizeof out));
    says("str.utf8.get.value", outp);

    /* An exact fit has no room for the terminator, and that is not an error. */
    memset(small, 0xaa, sizeof small);
    p = OSSL_PARAM_construct_utf8_string("k", small, sizeof small);
    SAY("str.utf8.set.exact_fit", OSSL_PARAM_set_utf8_string(&p, "abcd"));
    sayn("str.utf8.set.exact_fit.return_size", (long long) p.return_size);
    hexcat(hex, (const unsigned char *) small, sizeof small);
    printf("str.utf8.set.exact_fit.bytes=%s\n", hex);

    /* One byte short is a refusal, and `return_size` reports what was needed. */
    memset(small, 0xaa, sizeof small);
    p = OSSL_PARAM_construct_utf8_string("k", small, 3);
    SAY("str.utf8.set.too_small", OSSL_PARAM_set_utf8_string(&p, "abcd"));
    sayn("str.utf8.set.too_small.return_size", (long long) p.return_size);

    /* A NULL buffer is a size query that answers success. */
    p = OSSL_PARAM_construct_utf8_string("k", NULL, 0);
    SAY("str.utf8.set.size_query", OSSL_PARAM_set_utf8_string(&p, "abcdef"));
    sayn("str.utf8.set.size_query.return_size", (long long) p.return_size);

    /* The wrong type, and a NULL value, are refused by the string setters. */
    p = OSSL_PARAM_construct_octet_string("k", buf, sizeof buf);
    SAY("str.utf8.set.wrong_type", OSSL_PARAM_set_utf8_string(&p, "abc"));
    p = OSSL_PARAM_construct_utf8_string("k", buf, sizeof buf);
    SAY("str.utf8.set.null_value", OSSL_PARAM_set_utf8_string(&p, NULL));
    SAY("str.octet.set.wrong_type", OSSL_PARAM_set_octet_string(&p, "abc", 3));
    SAY("str.octet.set.null_value", OSSL_PARAM_set_octet_string(&p, NULL, 3));

    /* Octet strings carry their length and are not terminated. */
    {
        unsigned char ob[8];
        void *got = NULL;

        memset(ob, 0xaa, sizeof ob);
        p = OSSL_PARAM_construct_octet_string("k", ob, sizeof ob);
        SAY("str.octet.set.3", OSSL_PARAM_set_octet_string(&p, "\x00\x01\x02", 3));
        sayn("str.octet.return_size", (long long) p.return_size);
        hexcat(hex, ob, 4);
        printf("str.octet.bytes=%s\n", hex);
        SAY("str.octet.set.empty", OSSL_PARAM_set_octet_string(&p, "", 0));
        sayn("str.octet.set.empty.return_size", (long long) p.return_size);

        p = OSSL_PARAM_construct_octet_string("k", ob, 2);
        SAY("str.octet.set.too_small", OSSL_PARAM_set_octet_string(&p, "\x00\x01\x02", 3));
        sayn("str.octet.set.too_small.return_size", (long long) p.return_size);

        p = OSSL_PARAM_construct_octet_string("k", NULL, 0);
        SAY("str.octet.set.size_query", OSSL_PARAM_set_octet_string(&p, "\x00\x01\x02", 3));
        sayn("str.octet.set.size_query.return_size", (long long) p.return_size);

        /* `get_octet_string` writes `used_len` before it looks at the buffer, so a
         * caller can ask for the length without providing anywhere to put the value. */
        memset(ob, 0, sizeof ob);
        memcpy(ob, "xyz", 3);
        p = OSSL_PARAM_construct_octet_string("k", ob, 3);
        used = 0;
        SAY("str.octet.get.null_val", OSSL_PARAM_get_octet_string(&p, NULL, 0, &used));
        saysz("str.octet.get.null_val.used_len", used);

        /* With a NULL buffer and a non-zero maximum the value is allocated, and the
         * allocation is one byte larger than the data so a terminator fits. */
        used = 0;
        SAY("str.octet.get.allocates", OSSL_PARAM_get_octet_string(&p, &got, 0, &used));
        saysz("str.octet.get.allocated_used_len", used);
        /* An octet string is not NUL-terminated, so it is printed as the bytes the
         * contract declares rather than as a C string. */
        hexcat(hex, (const unsigned char *) got, used);
        printf("str.octet.get.allocated_value=%s\n", hex);
        OPENSSL_free(got);
        got = NULL;

        /* A maximum smaller than the data is a refusal; an exactly-fitting one is not.
         * The out-parameter is the address of a `void *` holding the destination, not
         * the destination's own address: `*val`, not `val`, is what the call writes
         * through. */
        {
            char exact[3];
            void *dst = exact;

            used = 0;
            SAY("str.octet.get.too_small", OSSL_PARAM_get_octet_string(&p, &dst, 2, &used));
            used = 0;
            SAY("str.octet.get.exact", OSSL_PARAM_get_octet_string(&p, &dst, 3, &used));
            saysz("str.octet.get.exact.used_len", used);
            saysz("str.octet.get.exact.dst_moved", dst == exact ? 1 : 0);
            hexcat(hex, (const unsigned char *) exact, 3);
            printf("str.octet.get.exact.bytes=%s\n", hex);
        }

        /* The wrong type and a NULL out-parameter pair are refusals. */
        p = OSSL_PARAM_construct_utf8_string("k", (char *) ob, sizeof ob);
        SAY("str.octet.get.wrong_type", OSSL_PARAM_get_octet_string(&p, &got, 0, &used));
        p = OSSL_PARAM_construct_octet_string("k", ob, 3);
        SAY("str.octet.get.null_val_and_null_used",
            OSSL_PARAM_get_octet_string(&p, NULL, 0, NULL));
    }

    /* The pointer forms store a pointer, not a copy. */
    {
        char *pp = buf;
        char store[8];

        memset(store, 0, sizeof store);
        memcpy(store, "hello", 6);
        pp = store;
        p = OSSL_PARAM_construct_utf8_ptr("k", &pp, 0);
        SAY("ptr.utf8.get", OSSL_PARAM_get_utf8_ptr(
                mk(OSSL_PARAM_construct_utf8_ptr("k", &pp, 5)), &cp));
        says("ptr.utf8.get.value", cp);
        SAY("ptr.utf8.set", OSSL_PARAM_set_utf8_ptr(&p, "world"));
        sayn("ptr.utf8.set.return_size", (long long) p.return_size);
        says("ptr.utf8.set.value", pp);
        /* A NULL value is accepted and records zero, unlike the string form. */
        SAY("ptr.utf8.set.null", OSSL_PARAM_set_utf8_ptr(&p, NULL));
        sayn("ptr.utf8.set.null.return_size", (long long) p.return_size);

        SAY("ptr.octet.set", OSSL_PARAM_set_octet_ptr(
                mk(OSSL_PARAM_construct_octet_ptr("k", &vp, 0)), "abc", 3));
        used = 0;
        SAY("ptr.octet.get", OSSL_PARAM_get_octet_ptr(
                mk(OSSL_PARAM_construct_octet_ptr("k", &vp, 3)), &cvp, &used));
        saysz("ptr.octet.get.used_len", used);
        /* A NULL buffer in the descriptor records the length and writes nothing. */
        SAY("ptr.octet.set.null_buffer", OSSL_PARAM_set_octet_ptr(
                mk(OSSL_PARAM_construct_octet_ptr("k", NULL, 0)), "abc", 3));
        /* The wrong type is refused. */
        SAY("ptr.utf8.get.wrong_type", OSSL_PARAM_get_utf8_ptr(
                mk(OSSL_PARAM_construct_octet_ptr("k", &vp, 0)), &cp));
        SAY("ptr.octet.get.wrong_type", OSSL_PARAM_get_octet_ptr(
                mk(OSSL_PARAM_construct_utf8_ptr("k", &pp, 0)), &cvp, &used));
        SAY("ptr.utf8.get.null_val", OSSL_PARAM_get_utf8_ptr(
                mk(OSSL_PARAM_construct_utf8_ptr("k", &pp, 0)), NULL));
    }

    /* The two `*_string_ptr` readers accept *either* shape, which is the bridge between
     * the descriptor-held and the pointer-held forms. */
    {
        char *pp = buf;
        char shared[8];

        memset(shared, 0, sizeof shared);
        memcpy(shared, "shared", 7);
        pp = shared;
        SAY("strptr.utf8.from_string", OSSL_PARAM_get_utf8_string_ptr(
                mk(OSSL_PARAM_construct_utf8_string("k", shared, 6)), &cp));
        says("strptr.utf8.from_string.value", cp);
        SAY("strptr.utf8.from_ptr", OSSL_PARAM_get_utf8_string_ptr(
                mk(OSSL_PARAM_construct_utf8_ptr("k", &pp, 6)), &cp));
        says("strptr.utf8.from_ptr.value", cp);
        SAY("strptr.utf8.wrong_type", OSSL_PARAM_get_utf8_string_ptr(
                mk(OSSL_PARAM_construct_octet_string("k", shared, 6)), &cp));
        SAY("strptr.utf8.null_val", OSSL_PARAM_get_utf8_string_ptr(
                mk(OSSL_PARAM_construct_utf8_string("k", shared, 6)), NULL));

        used = 0;
        SAY("strptr.octet.from_string", OSSL_PARAM_get_octet_string_ptr(
                mk(OSSL_PARAM_construct_octet_string("k", shared, 6)), &cvp, &used));
        saysz("strptr.octet.from_string.used_len", used);
        used = 0;
        SAY("strptr.octet.from_ptr", OSSL_PARAM_get_octet_string_ptr(
                mk(OSSL_PARAM_construct_octet_ptr("k", &vp, 6)), &cvp, &used));
        saysz("strptr.octet.from_ptr.used_len", used);
        SAY("strptr.octet.null_val", OSSL_PARAM_get_octet_string_ptr(
                mk(OSSL_PARAM_construct_octet_string("k", shared, 6)), NULL, &used));

        /* And the setter that dispatches on the destination's own type. */
        memset(buf, 0xaa, sizeof buf);
        SAY("strptr.set_or_ptr.on_string", OSSL_PARAM_set_octet_string_or_ptr(
                mk(OSSL_PARAM_construct_octet_string("k", buf, 8)), "abc", 3));
        SAY("strptr.set_or_ptr.on_ptr", OSSL_PARAM_set_octet_string_or_ptr(
                mk(OSSL_PARAM_construct_octet_ptr("k", &vp, 0)), "abc", 3));
        SAY("strptr.set_or_ptr.on_int", OSSL_PARAM_set_octet_string_or_ptr(
                mk(OSSL_PARAM_construct_int("k", (int *) buf)), "abc", 3));
    }
}

/* -------------------------------------------------------------------- BIGNUM */

static void bn_plane(void)
{
    BIGNUM *big = NULL;
    BIGNUM *out = NULL;
    unsigned char buf[32];
    OSSL_PARAM p;
    char hex[80];

    sayn("bn.setup.hex2bn", BN_hex2bn(&big, "0102030405060708"));

    p = OSSL_PARAM_construct_BN("k", buf, sizeof buf);
    SAY("bn.set.unsigned", OSSL_PARAM_set_BN(&p, big));
    sayn("bn.set.unsigned.return_size", (long long) p.return_size);
    hexcat(hex, buf, 8);
    printf("bn.set.unsigned.bytes=%s\n", hex);

    /* A signed destination needs `BN_num_bytes + 1` and refuses one byte less. */
    p = OSSL_PARAM_construct_BN("k", buf, sizeof buf);
    p.data_type = OSSL_PARAM_INTEGER;
    SAY("bn.set.signed", OSSL_PARAM_set_BN(&p, big));
    sayn("bn.set.signed.return_size", (long long) p.return_size);
    p = OSSL_PARAM_construct_BN("k", buf, 8);
    p.data_type = OSSL_PARAM_INTEGER;
    SAY("bn.set.signed.one_short", OSSL_PARAM_set_BN(&p, big));
    sayn("bn.set.signed.one_short.return_size", (long long) p.return_size);

    /* A NULL buffer is a size query. */
    p = OSSL_PARAM_construct_BN("k", NULL, 0);
    SAY("bn.set.size_query", OSSL_PARAM_set_BN(&p, big));
    sayn("bn.set.size_query.return_size", (long long) p.return_size);

    /* Zero still occupies a byte, whichever signedness. */
    {
        BIGNUM *zero = NULL;

        BN_hex2bn(&zero, "0");
        p = OSSL_PARAM_construct_BN("k", NULL, 0);
        SAY("bn.set.zero.unsigned_size_query", OSSL_PARAM_set_BN(&p, zero));
        sayn("bn.set.zero.unsigned_size_query.return_size", (long long) p.return_size);
        p = OSSL_PARAM_construct_BN("k", NULL, 0);
        p.data_type = OSSL_PARAM_INTEGER;
        SAY("bn.set.zero.signed_size_query", OSSL_PARAM_set_BN(&p, zero));
        sayn("bn.set.zero.signed_size_query.return_size", (long long) p.return_size);
        BN_free(zero);
    }

    /* A negative value into an UNSIGNED_INTEGER destination is refused; the same value
     * into a signed one is written as two's complement. */
    {
        BIGNUM *neg = NULL;

        BN_hex2bn(&neg, "-deadbeef");
        p = OSSL_PARAM_construct_BN("k", buf, sizeof buf);
        SAY("bn.set.negative_into_unsigned", OSSL_PARAM_set_BN(&p, neg));

        memset(buf, 0xaa, sizeof buf);
        p = OSSL_PARAM_construct_BN("k", buf, sizeof buf);
        p.data_type = OSSL_PARAM_INTEGER;
        SAY("bn.set.negative_into_signed", OSSL_PARAM_set_BN(&p, neg));
        sayn("bn.set.negative_into_signed.return_size", (long long) p.return_size);
        hexcat(hex, buf, p.return_size);
        printf("bn.set.negative_into_signed.bytes=%s\n", hex);

        out = NULL;
        SAY("bn.get.negative_round_trip", OSSL_PARAM_get_BN(&p, &out));
        if (out != NULL) {
            char *h = BN_bn2hex(out);

            says("bn.get.negative_round_trip.value", h);
            OPENSSL_free(h);
            BN_free(out);
            out = NULL;
        }

        /* The all-ones pattern read as signed and as unsigned: two different values,
         * and the unsigned read of a negative `INTEGER` is the negative-value refusal. */
        {
            unsigned char negbuf[8];
            OSSL_PARAM q;

            memset(negbuf, 0xff, sizeof negbuf);
            q = OSSL_PARAM_construct_BN("k", negbuf, sizeof negbuf);
            q.data_type = OSSL_PARAM_INTEGER;
            out = NULL;
            SAY("bn.get.all_ff_signed", OSSL_PARAM_get_BN(&q, &out));
            if (out != NULL) {
                char *h = BN_bn2hex(out);

                says("bn.get.all_ff_signed.value", h);
                OPENSSL_free(h);
                BN_free(out);
                out = NULL;
            }
            q.data_type = OSSL_PARAM_UNSIGNED_INTEGER;
            out = NULL;
            SAY("bn.get.all_ff_unsigned", OSSL_PARAM_get_BN(&q, &out));
            if (out != NULL) {
                char *h = BN_bn2hex(out);

                says("bn.get.all_ff_unsigned.value", h);
                OPENSSL_free(h);
                BN_free(out);
                out = NULL;
            }
        }
        BN_free(neg);
    }

    /* A NULL value, and the wrong type on either side. */
    p = OSSL_PARAM_construct_BN("k", buf, sizeof buf);
    SAY("bn.set.null_value", OSSL_PARAM_set_BN(&p, NULL));
    p = OSSL_PARAM_construct_octet_string("k", buf, sizeof buf);
    SAY("bn.set.wrong_type", OSSL_PARAM_set_BN(&p, big));
    p = OSSL_PARAM_construct_octet_string("k", buf, sizeof buf);
    out = NULL;
    SAY("bn.get.wrong_type", OSSL_PARAM_get_BN(&p, &out));

    BN_free(big);
}

/* -------------------------------------------------------- dup, merge and free */

static void dup_merge_free(void)
{
    int a = 0;
    unsigned char bytes[8];
    char txt[8];
    OSSL_PARAM arr[4];
    OSSL_PARAM *copy;
    OSSL_PARAM *merged;

    memset(bytes, 0, sizeof bytes);
    memcpy(txt, "abc", 4);
    arr[0] = OSSL_PARAM_construct_int("alpha", &a);
    arr[1] = OSSL_PARAM_construct_BN("beta", bytes, sizeof bytes);
    arr[2] = OSSL_PARAM_construct_utf8_string("gamma", txt, 3);
    arr[3] = OSSL_PARAM_construct_end();

    /* A value and a modification state are written first, so the copy has both to
     * carry. */
    OSSL_PARAM_set_int(&arr[0], 0x11223344);
    OSSL_PARAM_set_octet_string(mk(OSSL_PARAM_construct_BN("beta", bytes,
                                                                     sizeof bytes)),
                                "\x01\x02\x03", 3);

    copy = OSSL_PARAM_dup(arr);
    sayp("dup.result", copy);
    if (copy != NULL) {
        sayn("dup.entry0.return_size", (long long) copy[0].return_size);
        sayn("dup.entry0.modified", OSSL_PARAM_modified(&copy[0]));
        says("dup.entry0.key_aliases_source", copy[0].key == arr[0].key ? "same" : "different");
        says("dup.entry0.data_is_own", copy[0].data == arr[0].data ? "same" : "different");
        sayn("dup.entry0.value", *(int *) copy[0].data);
        sayn("dup.entry1.data_size", (long long) copy[1].data_size);
        says("dup.entry1.value_copied", memcmp(copy[1].data, bytes, 3) == 0 ? "equal" : "different");
        says("dup.entry2.value", (const char *) copy[2].data);
        sayn("dup.entry2.data_size", (long long) copy[2].data_size);
        /* The duplicate is self-contained: freeing it frees its values too. */
        OSSL_PARAM_free(copy);
        sayn("dup.freed", 1);
    }

    sayp("dup.null", OSSL_PARAM_dup(NULL));

    /* Merging: the second list wins a case-insensitive collision, and the result is
     * sorted by key while still aliasing the inputs' data. */
    {
        int x = 0;
        int y = 0;
        OSSL_PARAM one[3];
        OSSL_PARAM two[3];

        one[0] = OSSL_PARAM_construct_int("Bravo", &x);
        one[1] = OSSL_PARAM_construct_int("alpha", &x);
        one[2] = OSSL_PARAM_construct_end();
        two[0] = OSSL_PARAM_construct_int("charlie", &y);
        two[1] = OSSL_PARAM_construct_int("ALPHA", &y);
        two[2] = OSSL_PARAM_construct_end();

        merged = OSSL_PARAM_merge(one, two);
        sayp("merge.result", merged);
        if (merged != NULL) {
            int i;
            char buf2[256];
            size_t off = 0;
            const OSSL_PARAM *hit;

            for (i = 0; merged[i].key != NULL && i < 8; i++)
                off += (size_t) snprintf(buf2 + off, sizeof buf2 - off, "%s%s",
                                         i == 0 ? "" : ",", merged[i].key);
            printf("merge.keys=%s\n", buf2);
            hit = OSSL_PARAM_locate(merged, "alpha");
            sayn("merge.collision_takes_second", hit != NULL && hit->data == &y);
            hit = OSSL_PARAM_locate(merged, "Bravo");
            sayn("merge.non_collision_keeps_first", hit != NULL && hit->data == &x);
            OPENSSL_free(merged);
        }

        /* Two NULLs and two empties are two different refusals. */
        sayp("merge.both_null", OSSL_PARAM_merge(NULL, NULL));
        {
            OSSL_PARAM empty[1];

            empty[0] = OSSL_PARAM_construct_end();
            sayp("merge.two_empty", OSSL_PARAM_merge(empty, empty));
        }
        /* A single NULL is accepted, and the other list is copied. */
        merged = OSSL_PARAM_merge(NULL, one);
        sayp("merge.one_null", merged);
        OPENSSL_free(merged);
        merged = OSSL_PARAM_merge(two, NULL);
        sayp("merge.other_null", merged);
        if (merged != NULL)
            sayn("merge.other_null.count",
                 (long long) (merged[0].key != NULL) + (merged[1].key != NULL));
        OPENSSL_free(merged);
    }
}

/* ------------------------------------------------------------------ from_text */

static void from_text(void)
{
    static const OSSL_PARAM DEFS[] = {
        { "int", OSSL_PARAM_INTEGER, NULL, 4, OSSL_PARAM_UNMODIFIED },
        { "int8", OSSL_PARAM_INTEGER, NULL, 8, OSSL_PARAM_UNMODIFIED },
        { "uint", OSSL_PARAM_UNSIGNED_INTEGER, NULL, 4, OSSL_PARAM_UNMODIFIED },
        { "uint8", OSSL_PARAM_UNSIGNED_INTEGER, NULL, 8, OSSL_PARAM_UNMODIFIED },
        { "str", OSSL_PARAM_UTF8_STRING, NULL, 0, OSSL_PARAM_UNMODIFIED },
        { "oct", OSSL_PARAM_OCTET_STRING, NULL, 0, OSSL_PARAM_UNMODIFIED },
        { "freeint", OSSL_PARAM_INTEGER, NULL, 0, OSSL_PARAM_UNMODIFIED },
        { "freeuint", OSSL_PARAM_UNSIGNED_INTEGER, NULL, 0, OSSL_PARAM_UNMODIFIED },
        OSSL_PARAM_END
    };
    static const struct {
        const char *key;
        const char *value;
        size_t value_n;
    } CASES[] = {
        { "int", "42", 2 },
        { "int", "-42", 3 },
        { "int", "2147483647", 10 },
        { "int", "2147483648", 10 },
        { "int8", "-253", 4 },
        { "int8", "-9223372036854775808", 20 },
        { "int8", "9223372036854775807", 19 },
        { "uint", "7", 1 },
        { "uint", "-1", 2 },
        { "uint", "4294967296", 10 },
        { "uint8", "18446744073709551615", 20 },
        { "hexint", "ff", 2 },
        { "hexint", "-ff", 3 },
        { "freeint", "128", 3 },
        { "freeint", "-128", 4 },
        { "freeuint", "255", 3 },
        { "str", "hello", 5 },
        { "str", "", 0 },
        { "hexstr", "41", 2 },
        { "oct", "abc", 3 },
        { "oct", "", 0 },
        { "hexoct", "0102", 4 },
        { "hexoct", "010", 3 },
        { "hexoct", "zz", 2 },
        { "absent", "1", 1 },
    };
    size_t i;
    char key[96];
    char hex[96];

    for (i = 0; i < sizeof CASES / sizeof CASES[0]; i++) {
        OSSL_PARAM out;
        int found = -1;
        int rc;

        memset(&out, 0, sizeof out);
        rc = OSSL_PARAM_allocate_from_text(&out, DEFS, CASES[i].key, CASES[i].value,
                                           CASES[i].value_n, &found);
        snprintf(key, sizeof key, "text.%zu.%s", i, CASES[i].key);
        if (rc == 1 && out.data != NULL) {
            size_t n = out.data_size > 32 ? 32 : out.data_size;

            hexcat(hex, out.data, n);
            printf("%s rc=%d found=%d type=%u size=%zu ret=%zu bytes=%s\n", key, rc,
                   found, out.data_type, out.data_size, out.return_size, hex);
            if (out.data_type == OSSL_PARAM_UTF8_STRING)
                says("text.string_value", (const char *) out.data);
            OPENSSL_free(out.data);
        } else {
            printf("%s rc=%d found=%d err=%lu\n", key, rc, found, ERR_peek_error());
        }
        ERR_clear_error();
    }

    /* The two NULL arguments, and a caller that does not want `found`. */
    {
        OSSL_PARAM out;

        memset(&out, 0, sizeof out);
        SAY("text.null_to", OSSL_PARAM_allocate_from_text(NULL, DEFS, "int", "1", 1, NULL));
        SAY("text.null_defs", OSSL_PARAM_allocate_from_text(&out, NULL, "int", "1", 1, NULL));
        memset(&out, 0, sizeof out);
        sayn("text.found_optional",
             OSSL_PARAM_allocate_from_text(&out, DEFS, "int", "5", 1, NULL));
        sayn("text.found_optional.size", (long long) out.data_size);
        OPENSSL_free(out.data);
    }
}

/* ------------------------------------------------------------------ the builder */

/*
 * `uninitialised_key` names the one parameter whose *value bytes* the authority leaves
 * unwritten, and which therefore cannot be compared.
 *
 * `OSSL_PARAM_BLD_push_BN_pad` with a negative `BIGNUM` records `BN_num_bytes(bn)` bytes
 * -- `sz` is ignored for a negative value, because the encoding must be exactly two's
 * complement -- and `BN_signed_bn2native` refuses that width: it needs
 * `BN_num_bytes + ext` with `ext` 1 for a negative value whose magnitude does not fill its
 * top byte. `param_bld_convert` ignores the refusal, so the destination is left as the
 * allocator returned it. On the authority that read as zeros, which is the kernel's
 * zero-filled first touch of a fresh mapping and not a contract; `RT-BN` measures the
 * refusal itself, and this line records that the bytes are not comparable.
 */
static void dump_params(const char *prefix, const OSSL_PARAM *params,
                        const char *uninitialised_key)
{
    int i;

    for (i = 0; params[i].key != NULL && i < 24; i++) {
        char key[128];
        char hex[64];
        size_t n = params[i].data_size > 16 ? 16 : params[i].data_size;

        snprintf(key, sizeof key, "%s.%s", prefix, params[i].key);
        if (uninitialised_key != NULL && strcmp(params[i].key, uninitialised_key) == 0) {
            printf("%s type=%u size=%zu ret=%zu bytes=NOT_COMPARABLE_AUTHORITY_UNINITIALISED\n",
                   key, params[i].data_type, params[i].data_size, params[i].return_size);
        } else if (params[i].data == NULL) {
            printf("%s type=%u size=%zu ret=%zu bytes=(null)\n", key, params[i].data_type,
                   params[i].data_size, params[i].return_size);
        } else if (params[i].data_type == OSSL_PARAM_UTF8_PTR) {
            /* The block holds a pointer, so printing its bytes would print part of an
             * address -- a value that differs between two runs of the same binary. What
             * is comparable is the string it points at. */
            const char *target = *(const char *const *) params[i].data;

            printf("%s type=%u size=%zu ret=%zu target=%s\n", key, params[i].data_type,
                   params[i].data_size, params[i].return_size,
                   target == NULL ? "(null)" : target);
        } else if (params[i].data_type == OSSL_PARAM_OCTET_PTR) {
            const unsigned char *target = *(const unsigned char *const *) params[i].data;

            if (target == NULL) {
                printf("%s type=%u size=%zu ret=%zu target=(null)\n", key,
                       params[i].data_type, params[i].data_size, params[i].return_size);
            } else {
                hexcat(hex, target, n);
                printf("%s type=%u size=%zu ret=%zu target=%s\n", key, params[i].data_type,
                       params[i].data_size, params[i].return_size, hex);
            }
        } else {
            hexcat(hex, params[i].data, n);
            printf("%s type=%u size=%zu ret=%zu bytes=%s\n", key, params[i].data_type,
                   params[i].data_size, params[i].return_size, hex);
        }
    }
}

static void builder(void)
{
    OSSL_PARAM_BLD *bld;
    OSSL_PARAM *params;
    unsigned char bytes[8];
    char txt[8];
    double d = 1.5;
    time_t tt = 12;

    memset(bytes, 0, sizeof bytes);
    memcpy(bytes, "\x01\x02\x03", 3);
    memcpy(txt, "abc", 4);

    bld = OSSL_PARAM_BLD_new();
    sayp("bld.new", bld);
    if (bld == NULL)
        return;

    SAY("bld.push_int", OSSL_PARAM_BLD_push_int(bld, "i", -7));
    SAY("bld.push_uint", OSSL_PARAM_BLD_push_uint(bld, "u", 7u));
    SAY("bld.push_long", OSSL_PARAM_BLD_push_long(bld, "l", -8L));
    SAY("bld.push_ulong", OSSL_PARAM_BLD_push_ulong(bld, "ul", 8UL));
    SAY("bld.push_int32", OSSL_PARAM_BLD_push_int32(bld, "i32", -9));
    SAY("bld.push_uint32", OSSL_PARAM_BLD_push_uint32(bld, "u32", 9u));
    SAY("bld.push_int64", OSSL_PARAM_BLD_push_int64(bld, "i64", -10LL));
    SAY("bld.push_uint64", OSSL_PARAM_BLD_push_uint64(bld, "u64", 10ULL));
    SAY("bld.push_size_t", OSSL_PARAM_BLD_push_size_t(bld, "sz", (size_t) 11));
    SAY("bld.push_time_t", OSSL_PARAM_BLD_push_time_t(bld, "tt", tt));
    SAY("bld.push_double", OSSL_PARAM_BLD_push_double(bld, "d", d));
    SAY("bld.push_utf8_string", OSSL_PARAM_BLD_push_utf8_string(bld, "s", txt, 0));
    SAY("bld.push_octet_string", OSSL_PARAM_BLD_push_octet_string(bld, "o", bytes, 3));
    SAY("bld.push_utf8_ptr", OSSL_PARAM_BLD_push_utf8_ptr(bld, "sp", txt, 0));
    SAY("bld.push_octet_ptr", OSSL_PARAM_BLD_push_octet_ptr(bld, "op", bytes, 3));

    params = OSSL_PARAM_BLD_to_param(bld);
    sayp("bld.to_param", params);
    if (params != NULL) {
        const OSSL_PARAM *p;
        int v = 0;
        uint64_t uv = 0;
        double dv = 0;
        const char *cp = NULL;

        dump_params("bld.out", params, NULL);
        /* The array reads back through the ordinary accessors, which is the point of
         * the builder: a caller without a buffer now has one. */
        p = OSSL_PARAM_locate_const(params, "i");
        SAY("bld.read.i", p != NULL ? OSSL_PARAM_get_int(p, &v) : 0);
        sayn("bld.read.i.value", v);
        p = OSSL_PARAM_locate_const(params, "u64");
        SAY("bld.read.u64", p != NULL ? OSSL_PARAM_get_uint64(p, &uv) : 0);
        sayn("bld.read.u64.value", (long long) uv);
        p = OSSL_PARAM_locate_const(params, "d");
        SAY("bld.read.d", p != NULL ? OSSL_PARAM_get_double(p, &dv) : 0);
        sayf("bld.read.d.value", dv);
        p = OSSL_PARAM_locate_const(params, "s");
        says("bld.read.s.value", p == NULL ? NULL : (const char *) p->data);
        p = OSSL_PARAM_locate_const(params, "sp");
        SAY("bld.read.sp", p != NULL ? OSSL_PARAM_get_utf8_string_ptr(p, &cp) : 0);
        says("bld.read.sp.value", cp);
        p = OSSL_PARAM_locate_const(params, "op");
        {
            const void *cvp = NULL;
            size_t used = 0;

            SAY("bld.read.op", p != NULL ? OSSL_PARAM_get_octet_string_ptr(p, &cvp, &used) : 0);
            saysz("bld.read.op.used_len", used);
        }
        OSSL_PARAM_free(params);
    }

    /* A successful `to_param` empties the builder, so a second one works. */
    SAY("bld.push_again", OSSL_PARAM_BLD_push_int(bld, "again", 1));
    params = OSSL_PARAM_BLD_to_param(bld);
    sayn("bld.to_param.again.count",
         params == NULL ? -1
                        : (long long) (params[0].key != NULL) + (params[1].key != NULL));
    OSSL_PARAM_free(params);

    /* A builder holding nothing still produces a usable, empty array. */
    params = OSSL_PARAM_BLD_to_param(bld);
    sayp("bld.to_param.empty", params);
    if (params != NULL)
        sayn("bld.to_param.empty.is_terminated", params[0].key == NULL);
    OSSL_PARAM_free(params);

    /* The refusals. */
    SAY("bld.push_int.null_bld", OSSL_PARAM_BLD_push_int(NULL, "k", 1));
    SAY("bld.push_int.null_key", OSSL_PARAM_BLD_push_int(bld, NULL, 1));
    SAY("bld.push_utf8_string.null_buf", OSSL_PARAM_BLD_push_utf8_string(bld, "k", NULL, 0));
    SAY("bld.push_utf8_ptr.null_buf", OSSL_PARAM_BLD_push_utf8_ptr(bld, "k", NULL, 0));
    SAY("bld.push_octet_string.null_buf_zero_len",
        OSSL_PARAM_BLD_push_octet_string(bld, "k", NULL, 0));
    SAY("bld.push_octet_string.null_buf_nonzero_len",
        OSSL_PARAM_BLD_push_octet_string(bld, "k", NULL, 4));
    SAY("bld.push_octet_ptr.null_buf_nonzero_len",
        OSSL_PARAM_BLD_push_octet_ptr(bld, "k", NULL, 4));
    sayp("bld.to_param.null", OSSL_PARAM_BLD_to_param(NULL));
    /* Those refusals left nothing recorded, so the next `to_param` is empty. */
    params = OSSL_PARAM_BLD_to_param(bld);
    sayn("bld.after_refusals.empty", params == NULL ? -1 : (long long) (params[0].key == NULL));
    OSSL_PARAM_free(params);

    OSSL_PARAM_BLD_free(bld);
    /* A NULL builder is a no-op, not a fault. */
    OSSL_PARAM_BLD_free(NULL);
    sayn("bld.free.null", 1);

    /* The BIGNUM forms: a negative value becomes a *signed* parameter one byte wider
     * than its magnitude, and the padding form ignores `sz` for a negative value. */
    {
        BIGNUM *big = NULL;
        BIGNUM *neg = NULL;

        BN_hex2bn(&big, "0102030405");
        BN_hex2bn(&neg, "-0102");

        bld = OSSL_PARAM_BLD_new();
        SAY("bld.push_BN.positive", OSSL_PARAM_BLD_push_BN(bld, "p", big));
        SAY("bld.push_BN.negative", OSSL_PARAM_BLD_push_BN(bld, "n", neg));
        SAY("bld.push_BN.null", OSSL_PARAM_BLD_push_BN(bld, "z", NULL));
        SAY("bld.push_BN_pad.pad_to_16", OSSL_PARAM_BLD_push_BN_pad(bld, "pad", big, 16));
        SAY("bld.push_BN_pad.negative_ignores_sz",
            OSSL_PARAM_BLD_push_BN_pad(bld, "padn", neg, 16));
        SAY("bld.push_BN_pad.too_small", OSSL_PARAM_BLD_push_BN_pad(bld, "small", big, 2));
        params = OSSL_PARAM_BLD_to_param(bld);
        if (params != NULL) {
            dump_params("bld.bn", params, "padn");
            OSSL_PARAM_free(params);
        }
        OSSL_PARAM_BLD_free(bld);
        BN_free(big);
        BN_free(neg);
    }
}

/* --------------------------------------------------------------- print_to_bio */

/*
 * The printed transcript is captured through a memory BIO and printed as the
 * observation, with the characters that would break the one-line format escaped. The
 * bytes are the authority's own formatting, so they are compared rather than hashed.
 */
static void escape(const char *src, char *dst, size_t cap)
{
    size_t i = 0;
    size_t o = 0;

    while (src[i] != '\0' && o + 6 < cap) {
        unsigned char c = (unsigned char) src[i++];

        if (c == '\n') {
            dst[o++] = '\\';
            dst[o++] = 'n';
        } else if (c >= 0x20 && c < 0x7f) {
            dst[o++] = (char) c;
        } else {
            o += (size_t) snprintf(dst + o, cap - o, "\\x%02x", c);
        }
    }
    dst[o] = '\0';
}

static void print_one(const char *prefix, const OSSL_PARAM *arr, int print_values)
{
    BIO *bio = BIO_new(BIO_s_mem());
    char key[64];
    char esc[1024];
    char *mem = NULL;
    char *copy;
    long len;

    if (bio == NULL)
        return;
    snprintf(key, sizeof key, "%s.rc", prefix);
    SAY(key, OSSL_PARAM_print_to_bio(arr, bio, print_values));
    len = BIO_get_mem_data(bio, &mem);
    snprintf(key, sizeof key, "%s.len", prefix);
    printf("%s=%ld\n", key, len);
    if (len > 0) {
        copy = OPENSSL_malloc((size_t) len + 1);
        if (copy != NULL) {
            memcpy(copy, mem, (size_t) len);
            copy[len] = '\0';
            escape(copy, esc, sizeof esc);
            snprintf(key, sizeof key, "%s.text", prefix);
            printf("%s=%s\n", key, esc);
            OPENSSL_free(copy);
        }
    }
    BIO_free(bio);
    ERR_clear_error();
}

static void print_plane(void)
{
    int i = 0x11223344;
    int64_t i64 = 1;
    unsigned char oct[4];
    char txt[8];
    double d = 1.5;
    OSSL_PARAM arr[8];
    OSSL_PARAM empty[1];

    memcpy(oct, "\x01\x02\x03\x04", 4);
    memcpy(txt, "abc", 4);

    arr[0] = OSSL_PARAM_construct_int("i", &i);
    arr[1] = OSSL_PARAM_construct_int64("i64", &i64);
    arr[2] = OSSL_PARAM_construct_octet_string("o", oct, sizeof oct);
    arr[3] = OSSL_PARAM_construct_utf8_string("s", txt, 3);
    arr[4] = OSSL_PARAM_construct_double("d", &d);
    arr[5] = OSSL_PARAM_construct_BN("bn", oct, sizeof oct);
    arr[6] = OSSL_PARAM_construct_octet_ptr("op", (void **) oct, sizeof oct);
    arr[7] = OSSL_PARAM_construct_end();

    print_one("print.keys", arr, 0);
    print_one("print.values", arr, 1);
    print_one("print.values_again", arr, 1);

    empty[0] = OSSL_PARAM_construct_end();
    print_one("print.empty", empty, 1);

    /*
     * A NULL array is a fault in the authority: it dereferences the first entry's key
     * without a test. The candidate answers 0. Recorded rather than reproduced --
     * docs/SECURITY_DIVERGENCE_POLICY.md D103.
     */
    printf("print.null_array=NOT_MEASURED_AUTHORITY_FAULTS\n");
}

int main(void)
{
    /* Line-buffered: a probe that dies part-way must still have produced everything it
     * printed, and a fault in a later section must not hide an earlier one. */
    setvbuf(stdout, NULL, _IOLBF, 0);

    constructors();
    locate_and_modified();
    read_matrix();
    write_matrix();
    string_plane();
    bn_plane();
    dup_merge_free();
    from_text();
    builder();
    print_plane();

    printf("done=1\n");
    return 0;
}
