/*
 * openssl-rs — RT-ASN1-TIME: the time family, differentially.
 *
 * The 29 symbols of `crypto/asn1/a_time.c`, `a_utctm.c` and `a_gentm.c` are one
 * parser and a set of wrappers over it, and this probe drives the parser from both
 * ends: as a validator (`_check`, `_set_string` with a null destination) and as a
 * converter (`_set`, `_adj`, `_to_tm`, `_diff`, `_compare`, `_cmp_time_t`), and it
 * drives the printer over a memory BIO so the rendered bytes are compared rather
 * than the return code alone.
 *
 * The behaviours worth stating, because they are what a plausible reimplementation
 * gets wrong:
 *
 *   a.*  the shortest legal spelling — 13 bytes for UTCTime, 15 for
 *        GeneralizedTime — and the two-digit-field bounds tables, including the
 *        calendar (Feb 29 in 2000 yes, 2021 no, and the `mdays` February
 *        adjustment)
 *   b.*  the *asymmetry* of the offset: `±hhmm` is accepted without the
 *        `X509_TIME` flag, and the offset is applied only when the destination is
 *        non-null, so `ASN1_UTCTIME_set_string(NULL, "+hhmm")` and
 *        `ASN1_UTCTIME_check` validate a value that a fill then normalises — or
 *        rejects, if the day number would go negative
 *   c.*  the RFC 5280 profile: seconds and `Z` mandatory, `±` and fractional
 *        seconds refused, and the `YYYY`→`YY` shortening `ASN1_TIME_set_string_X509`
 *        performs for a year inside the UTCTime window
 *   d.*  which syntax `ASN1_TIME_set_string` picks when a string is legal as
 *        both, and that `ASN1_TIME_set`/`_adj` pick by the year (UTCTime only
 *        inside 1950-2049, so 2050-01-01 is a GeneralizedTime and
 *        `ASN1_UTCTIME_set` refuses it outright)
 *   e.*  `ASN1_TIME_diff`'s `to - from` argument order against
 *        `ASN1_TIME_compare`'s reversed call, and `-2` as the distinct
 *        "could not compare" answer
 *   f.*  the three printer formats and the GeneralizedTime-only fractional field,
 *        which is recognised only when the fraction point is at offset 14 of a
 *        string longer than 15 bytes
 *   g.*  `ASN1_TIME_normalize` and `ASN1_TIME_to_generalizedtime` round trips
 *   h.*  the platform `struct tm` the signatures are written against — size and
 *        every offset, since the candidate declares its own projection of it
 *   i.*  that a parse failure raises nothing on the error queue, which is how a
 *        caller distinguishes a time failure from an allocation failure
 *
 * Deliberately absent: anything whose answer depends on the current clock.
 * `ASN1_TIME_to_tm(NULL, …)` and `ASN1_TIME_diff(NULL, …)` are exercised for their
 * *return* and the sign of their answer only, never for a value.
 *
 * Determinism: every line is `key=value`; no address, no clock reading and no
 * build-path-dependent string is printed.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/objects.h>

#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

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

    printf("%s=", key);
    if (p == NULL) {
        printf("<null>\n");
        return;
    }
    printf("\"");
    for (i = 0; i < n; i++)
        printf("%c", (p[i] >= 0x20 && p[i] < 0x7f) ? p[i] : '.');
    printf("\"\n");
}

static void clear_queue(void)
{
    ERR_clear_error();
}

/*
 * Print and clear the queue as a comma-separated list of reason names. The library
 * and the file/line are deliberately not printed: the file path embeds the build
 * prefix, which differs between the two sides, and the reasons are what the
 * contract is.
 */
static void drain(const char *key)
{
    unsigned long e;
    int first = 1;

    printf("%s=", key);
    while ((e = ERR_get_error()) != 0) {
        const char *rsn = ERR_reason_error_string(e);

        printf("%s%s", first ? "" : ",", rsn == NULL ? "<no-string>" : rsn);
        first = 0;
    }
    if (first)
        printf("<empty>");
    printf("\n");
}

/* Report the string's observable identity, whatever it is. */
static void report_string(const char *key, const ASN1_STRING *s)
{
    char buf[192];

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

/* Report the platform `struct tm` in full. */
static void dump_tm(const char *key, const struct tm *t)
{
    printf("%s.sec=%d\n", key, t->tm_sec);
    printf("%s.min=%d\n", key, t->tm_min);
    printf("%s.hour=%d\n", key, t->tm_hour);
    printf("%s.mday=%d\n", key, t->tm_mday);
    printf("%s.mon=%d\n", key, t->tm_mon);
    printf("%s.year=%d\n", key, t->tm_year);
    printf("%s.wday=%d\n", key, t->tm_wday);
    printf("%s.yday=%d\n", key, t->tm_yday);
    printf("%s.isdst=%d\n", key, t->tm_isdst);
    printf("%s.gmtoff=%ld\n", key, (long)t->tm_gmtoff);
    printf("%s.zone_null=%d\n", key, t->tm_zone == NULL ? 1 : 0);
}

static void try_utc(const char *key, const char *s)
{
    ASN1_UTCTIME *t = ASN1_UTCTIME_new();
    char k[192];
    int via_null = ASN1_UTCTIME_set_string(NULL, s);
    int ok = ASN1_UTCTIME_set_string(t, s);

    clear_queue();
    printf("utc.%s.null=%d\n", key, via_null);
    printf("utc.%s.set=%d\n", key, ok);
    snprintf(k, sizeof(k), "utc.%s", key);
    report_string(k, t);
    /* The checker on the value that was just built, and the type dispatcher. */
    printf("utc.%s.check=%d\n", key, ASN1_UTCTIME_check(t));
    printf("utc.%s.time_check=%d\n", key, ASN1_TIME_check(t));
    printf("utc.%s.gentime_check=%d\n", key, ASN1_GENERALIZEDTIME_check(t));
    ASN1_UTCTIME_free(t);
    clear_queue();
}

static void try_gen(const char *key, const char *s)
{
    ASN1_GENERALIZEDTIME *t = ASN1_GENERALIZEDTIME_new();
    char k[192];
    int via_null = ASN1_GENERALIZEDTIME_set_string(NULL, s);
    int ok = ASN1_GENERALIZEDTIME_set_string(t, s);

    clear_queue();
    printf("gen.%s.null=%d\n", key, via_null);
    printf("gen.%s.set=%d\n", key, ok);
    snprintf(k, sizeof(k), "gen.%s", key);
    report_string(k, t);
    printf("gen.%s.check=%d\n", key, ASN1_GENERALIZEDTIME_check(t));
    printf("gen.%s.time_check=%d\n", key, ASN1_TIME_check(t));
    printf("gen.%s.utctime_check=%d\n", key, ASN1_UTCTIME_check(t));
    ASN1_GENERALIZEDTIME_free(t);
    clear_queue();
}

/* Convert through `ASN1_TIME_to_tm` and dump everything it wrote. */
static void to_tm_of(const char *key, const char *s)
{
    ASN1_TIME *t = ASN1_TIME_new();
    struct tm tm;
    char k[192];
    int ok = ASN1_TIME_set_string(t, s);

    clear_queue();
    if (!ok) {
        printf("%s.set=0\n", key);
        ASN1_TIME_free(t);
        return;
    }
    memset(&tm, 0x5a, sizeof(tm));
    printf("%s.to_tm=%d\n", key, ASN1_TIME_to_tm(t, &tm));
    snprintf(k, sizeof(k), "%s", key);
    dump_tm(k, &tm);
    ASN1_TIME_free(t);
    clear_queue();
}

/* ------------------------------------------------------------------- layout */

static void part_layout(void)
{
    printf("sizeof_tm=%d\n", (int)sizeof(struct tm));
    printf("sizeof_time_t=%d\n", (int)sizeof(time_t));
    printf("off.sec=%d\n", (int)offsetof(struct tm, tm_sec));
    printf("off.min=%d\n", (int)offsetof(struct tm, tm_min));
    printf("off.hour=%d\n", (int)offsetof(struct tm, tm_hour));
    printf("off.mday=%d\n", (int)offsetof(struct tm, tm_mday));
    printf("off.mon=%d\n", (int)offsetof(struct tm, tm_mon));
    printf("off.year=%d\n", (int)offsetof(struct tm, tm_year));
    printf("off.wday=%d\n", (int)offsetof(struct tm, tm_wday));
    printf("off.yday=%d\n", (int)offsetof(struct tm, tm_yday));
    printf("off.isdst=%d\n", (int)offsetof(struct tm, tm_isdst));
    printf("off.gmtoff=%d\n", (int)offsetof(struct tm, tm_gmtoff));
    printf("off.zone=%d\n", (int)offsetof(struct tm, tm_zone));
}

/* ------------------------------------------------------------- UTCTime parse */

static void part_utctime(void)
{
    /* Legal, at the boundaries of the two-digit-year window and the calendar. */
    try_utc("epoch", "700101000000Z");
    try_utc("win_lo", "500101000000Z");
    try_utc("win_hi", "491231235959Z");
    /* February 29 in a leap year, in a common year, and in another leap year.
     * The UTCTime window is 1950-2049, so 1900 and 2100 are not expressible
     * here; the GeneralizedTime part covers those two. */
    try_utc("leap2000", "000229000000Z");
    try_utc("leap2001", "010229000000Z");
    try_utc("leap2004", "040229000000Z");

    /* Each two-digit field against the bounds table, one over the maximum. */
    try_utc("mon_hi", "001231000000Z");
    try_utc("mon_over", "001301000000Z");
    try_utc("mon_zero", "000001000000Z");
    try_utc("day_max", "000131000000Z");
    try_utc("day_over", "000132000000Z");
    try_utc("day_zero", "000100000000Z");
    try_utc("feb30", "000230000000Z");
    try_utc("hour_hi", "000101230000Z");
    try_utc("hour_over", "000101240000Z");
    try_utc("min_over", "000101006000Z");
    try_utc("sec_over", "000101000060Z");
    try_utc("sec_hi", "000101000059Z");

    /* Shortest spelling, and one byte short of it. */
    try_utc("ok_13", "000101000000Z");
    try_utc("short_12", "00010100000Z");
    try_utc("short_11", "0001010000Z");

    /* The terminator and the trailing byte. */
    try_utc("no_z", "000101000000");
    try_utc("lower_z", "000101000000z");
    try_utc("bad_z", "000101000000X");
    try_utc("trailing", "000101000000Z0");
    try_utc("empty", "");
    try_utc("nondigit", "00010100000XZ");
    try_utc("space", "0001010000  Z");
    try_utc("leading_q", "?00101000000Z");

    /* Fractional seconds are GeneralizedTime-only. */
    try_utc("frac", "000101000000.5Z");

    /* The offset form: accepted without the X509 flag, hour bounded by 12. */
    try_utc("off_plus", "0001010000+0100");
    try_utc("off_minus", "0001010000-0100");
    try_utc("off_zero", "0001010000+0000");
    try_utc("off_hour12", "0001010000+1200");
    try_utc("off_hour13", "0001010000+1300");
    try_utc("off_min60", "0001010000+1260");
    try_utc("off_short", "0001010000+010");
    try_utc("off_long", "0001010000+01000");
    try_utc("off_nodigit", "0001010000+01X0");
}

/* -------------------------------------------------------- GeneralizedTime parse */

static void part_gentime(void)
{
    try_gen("basic", "20200101000000Z");
    try_gen("win_lo", "19500101000000Z");
    try_gen("win_hi", "20491231235959Z");
    try_gen("over_window", "20500101000000Z");
    try_gen("under_window", "19491231235959Z");
    try_gen("leap2020", "20200229000000Z");
    try_gen("leap2021", "20210229000000Z");
    try_gen("leap_century", "20000229000000Z");
    try_gen("leap_1900", "19000229000000Z");
    try_gen("leap_2100", "21000229000000Z");
    try_gen("year_zero", "000101000000Z");
    try_gen("year_max", "99991231235959Z");

    /* Fractional seconds: one digit, many digits, none, and no terminator. */
    try_gen("frac1", "20200101000000.5Z");
    try_gen("frac6", "20200101000000.123456Z");
    try_gen("frac_empty", "20200101000000.Z");
    try_gen("frac_last", "20200101000000.");
    try_gen("frac_only", "20200101000000.5");

    /* Length and terminator. */
    try_gen("short_14", "2020010100000Z");
    try_gen("short_15", "20200101000000");
    try_gen("trailing", "20200101000000Z0");
    try_gen("no_z", "2020010100000XX");

    /* The offset form. */
    try_gen("off_plus", "20200101000000+0100");
    try_gen("off_minus", "20200101000000-0100");
    try_gen("off_hour12", "20200101000000+1200");
    try_gen("off_hour13", "20200101000000+1300");
    try_gen("off_min60", "20200101000000+1260");
    try_gen("off_short", "20200101000000+010");

    /* Field bounds, at the GeneralizedTime field indices. */
    try_gen("mon_over", "20201301000000Z");
    try_gen("day_over", "20200132000000Z");
    try_gen("hour_over", "20200101240000Z");
    try_gen("min_over", "20200101006000Z");
    try_gen("sec_over", "20200101000060Z");
}

/* --------------------------------------------------- the type-dispatching entry */

static void part_time_set_string(void)
{
    ASN1_TIME *t = ASN1_TIME_new();
    int ok;

    clear_queue();
    /* Legal as both? The UTCTime reading of the first twelve bytes is not. */
    ok = ASN1_TIME_set_string(t, "20200101000000Z");
    printf("dispatch.gen_str=%d\n", ok);
    report_string("dispatch.gen_str", t);

    /* Legal as both: UTCTime wins, because it is tried first. */
    ASN1_TIME_free(t);
    t = ASN1_TIME_new();
    ok = ASN1_TIME_set_string(t, "200101000000Z");
    printf("dispatch.utc_wins=%d\n", ok);
    report_string("dispatch.utc_wins", t);

    /* A null destination validates without copying. */
    printf("dispatch.null_dest_utc=%d\n", ASN1_TIME_set_string(NULL, "200101000000Z"));
    printf("dispatch.null_dest_gen=%d\n", ASN1_TIME_set_string(NULL, "20200101000000Z"));
    printf("dispatch.null_dest_bad=%d\n", ASN1_TIME_set_string(NULL, "garbage"));

    ASN1_TIME_free(t);
    drain("dispatch.err");
}

/* --------------------------------------------------------- the X509 profile */

static void x509_of(const char *key, const char *s, int with_dest)
{
    ASN1_TIME *t = ASN1_TIME_new();
    char k[192];
    int ok = ASN1_TIME_set_string_X509(with_dest ? t : NULL, s);

    clear_queue();
    printf("x509.%s.ok=%d\n", key, ok);
    if (with_dest) {
        snprintf(k, sizeof(k), "x509.%s", key);
        report_string(k, t);
    }
    ASN1_TIME_free(t);
    clear_queue();
}

static void part_x509_profile(void)
{
    /* Seconds and Z are mandatory, so a UTCTime needs 13 bytes and a Z. */
    x509_of("utc_ok", "200101000000Z", 1);
    x509_of("utc_no_z", "200101000000", 1);
    x509_of("utc_short", "2001010000Z", 1);
    x509_of("utc_offset", "2001010000+0100", 1);
    x509_of("utc_frac", "200101000000.5Z", 1);

    /* The YYYY->YY shortening for a year inside the UTCTime window. */
    x509_of("gen_in_window", "20200101000000Z", 1);
    x509_of("gen_at_2050", "20500101000000Z", 1);
    x509_of("gen_at_1950", "19500101000000Z", 1);
    x509_of("gen_below_1950", "19490101000000Z", 1);
    x509_of("gen_frac", "20200101000000.5Z", 1);
    x509_of("gen_offset", "20200101000000+0100", 1);
    x509_of("gen_short", "202001010000Z", 1);

    /* Without a destination the shortening cannot happen, but the check still does. */
    x509_of("gen_in_window_nodest", "20200101000000Z", 0);
    x509_of("bad_nodest", "garbage", 0);
    x509_of("empty_nodest", "", 0);
}

/* ----------------------------------------------------- set / adj constructors */

static void set_of(const char *key, ASN1_TIME *s, time_t t, int offset_day, long offset_sec)
{
    ASN1_TIME *r;
    char k[192];

    clear_queue();
    r = ASN1_TIME_adj(s, t, offset_day, offset_sec);
    printf("%s.null=%d\n", key, r == NULL);
    snprintf(k, sizeof(k), "%s", key);
    if (r != NULL) {
        report_string(k, r);
        /* Reuse: the same pointer is handed back. */
        printf("%s.reused=%d\n", key, r == s ? 1 : 0);
    }
    if (s != NULL)
        ASN1_TIME_free(s);
    drain(strcat(strcpy(k, key), ".err"));
    clear_queue();
}

static void part_constructors(void)
{
    ASN1_UTCTIME *u;
    ASN1_GENERALIZEDTIME *g;
    char k[192];

    /* Inside the UTCTime window: the syntax follows the year. */
    set_of("set.epoch", ASN1_TIME_new(), (time_t)0, 0, 0);
    set_of("set.2009", ASN1_TIME_new(), (time_t)1234567890, 0, 0);
    set_of("set.neg", ASN1_TIME_new(), (time_t)-1, 0, 0);
    set_of("set.win_lo", ASN1_TIME_new(), (time_t)-631152000, 0, 0); /* 1950-01-01 */
    set_of("set.win_hi", ASN1_TIME_new(), (time_t)2524607999, 0, 0); /* 2049-12-31 */
    set_of("set.at_2050", ASN1_TIME_new(), (time_t)2524608000, 0, 0);

    /* Offsets: a day, a second, the two together, and a negative one. */
    set_of("adj.day", ASN1_TIME_new(), (time_t)1577836800, 1, 0);
    set_of("adj.sec", ASN1_TIME_new(), (time_t)1577836800, 0, 1);
    set_of("adj.neg_sec", ASN1_TIME_new(), (time_t)1577836800, 0, -1);
    set_of("adj.neg_day", ASN1_TIME_new(), (time_t)1577836800, -1, 0);
    set_of("adj.both", ASN1_TIME_new(), (time_t)1577836800, 1, 3600);
    set_of("adj.month_end", ASN1_TIME_new(), (time_t)1583020800, 1, 0); /* 2020-03-01 */
    set_of("adj.null", NULL, (time_t)1577836800, 0, 0);

    /* `ASN1_UTCTIME_set` refuses a year outside its window rather than widening. */
    u = ASN1_UTCTIME_new();
    printf("utc_set.2050_null=%d\n", ASN1_UTCTIME_set(u, (time_t)2524608000) == NULL);
    printf("utc_set.2050_len=%d\n", ASN1_STRING_length(u));
    printf("utc_set.2049_len=%d\n", ASN1_STRING_length(ASN1_UTCTIME_set(u, (time_t)2524607999)));
    ASN1_UTCTIME_free(u);
    drain("utc_set.err");
    clear_queue();

    /* The offset crosses a day boundary. */
    u = ASN1_UTCTIME_new();
    printf("utc_adj.midnight=%s\n",
           ASN1_UTCTIME_adj(u, (time_t)1577836800, 0, 86400) != NULL ? "ok" : "null");
    snprintf(k, sizeof(k), "utc_adj.midnight");
    report_string(k, u);
    ASN1_UTCTIME_free(u);
    clear_queue();

    g = ASN1_GENERALIZEDTIME_new();
    printf("gen_set.epoch_len=%d\n", ASN1_STRING_length(ASN1_GENERALIZEDTIME_set(g, (time_t)0)));
    snprintf(k, sizeof(k), "gen_set.epoch");
    report_string(k, g);
    printf("gen_set.late_len=%d\n",
           ASN1_STRING_length(ASN1_GENERALIZEDTIME_set(g, (time_t)253402300799)));
    snprintf(k, sizeof(k), "gen_set.late");
    report_string(k, g);
    printf("gen_set.adj=%d\n",
           ASN1_GENERALIZEDTIME_adj(g, (time_t)1577836800, 0, -86400) != NULL);
    snprintf(k, sizeof(k), "gen_set.adj");
    report_string(k, g);
    ASN1_GENERALIZEDTIME_free(g);
    clear_queue();
}

/* -------------------------------------------------------------- to_tm and diff */

static void part_to_tm(void)
{
    /* No offset: every field, including the two the parser computes. */
    to_tm_of("tm.utc_epoch", "700101000000Z");
    to_tm_of("tm.utc_2020", "200101010203Z");
    to_tm_of("tm.gen_2020", "20200101010203Z");
    to_tm_of("tm.gen_year_zero", "000101000000Z");
    to_tm_of("tm.leap_day", "20200229000000Z");

    /* With an offset, which is applied only when the destination is non-null. */
    to_tm_of("tm.off_plus", "20200101010203+0100");
    to_tm_of("tm.off_minus", "20200101010203-0100");
    to_tm_of("tm.off_zero", "20200101010203+0000");
    /* An offset that crosses a day boundary in each direction. */
    to_tm_of("tm.off_forward", "20200101003000+0100");
    to_tm_of("tm.off_back", "20200101233000-0100");
    /* The same value checked without a destination: the checker does not normalise. */
    printf("tm.check.off_plus=%d\n", ASN1_TIME_set_string(NULL, "20200101010203+0100"));
    printf("tm.utc_check.off_plus=%d\n", ASN1_UTCTIME_set_string(NULL, "2001010102+0100"));
    printf("tm.utc_check.off_hour13=%d\n", ASN1_UTCTIME_set_string(NULL, "2001010102+1300"));

    /* A null value means now: only the return and the shape of the answer. */
    {
        struct tm tm;
        memset(&tm, 0x5a, sizeof(tm));
        printf("tm.null.ok=%d\n", ASN1_TIME_to_tm(NULL, &tm));
        /* What `gmtime_r` leaves behind is part of the observable answer: UTC has
         * a zero offset and the `GMT` zone name, and `isdst` is zero. */
        printf("tm.null.gmtoff_zero=%d\n", tm.tm_gmtoff == 0 ? 1 : 0);
        printf("tm.null.isdst_zero=%d\n", tm.tm_isdst == 0 ? 1 : 0);
        printf("tm.null.zone_gmt=%d\n",
               tm.tm_zone != NULL && strcmp(tm.tm_zone, "GMT") == 0 ? 1 : 0);
    }
    /* A value the parser refuses. */
    {
        ASN1_TIME *t = ASN1_TIME_new();
        struct tm tm;
        printf("tm.bad.ok=%d\n", ASN1_TIME_to_tm(t, &tm));
        ASN1_TIME_free(t);
    }
    clear_queue();
}

static void diff_of(const char *key, const char *from, const char *to)
{
    ASN1_TIME *f = ASN1_TIME_new();
    ASN1_TIME *t = ASN1_TIME_new();
    int day = 0x5a5a5a5a;
    int sec = 0x5a5a5a5a;
    int ok;

    clear_queue();
    if (!ASN1_TIME_set_string(f, from) || !ASN1_TIME_set_string(t, to)) {
        printf("diff.%s.parse=0\n", key);
        ASN1_TIME_free(f);
        ASN1_TIME_free(t);
        return;
    }
    ok = ASN1_TIME_diff(&day, &sec, f, t);
    printf("diff.%s.ok=%d\n", key, ok);
    printf("diff.%s.day=%d\n", key, day);
    printf("diff.%s.sec=%d\n", key, sec);
    day = 0x5a5a5a5a;
    sec = 0x5a5a5a5a;
    printf("diff.%s.null_day_ok=%d\n", key, ASN1_TIME_diff(NULL, &sec, f, t));
    printf("diff.%s.null_day_sec=%d\n", key, sec);
    printf("diff.%s.null_sec_ok=%d\n", key, ASN1_TIME_diff(&day, NULL, f, t));
    printf("diff.%s.null_sec_day=%d\n", key, day);
    printf("diff.%s.both_null_ok=%d\n", key, ASN1_TIME_diff(NULL, NULL, f, t));
    ASN1_TIME_free(f);
    ASN1_TIME_free(t);
    clear_queue();
}

static void compare_of(const char *key, const char *a, const char *b)
{
    ASN1_TIME *x = ASN1_TIME_new();
    ASN1_TIME *y = ASN1_TIME_new();

    clear_queue();
    if (!ASN1_TIME_set_string(x, a) || !ASN1_TIME_set_string(y, b)) {
        printf("cmp.%s.parse=0\n", key);
        ASN1_TIME_free(x);
        ASN1_TIME_free(y);
        return;
    }
    printf("cmp.%s=%d\n", key, ASN1_TIME_compare(x, y));
    printf("cmp.%s.rev=%d\n", key, ASN1_TIME_compare(y, x));
    ASN1_TIME_free(x);
    ASN1_TIME_free(y);
    clear_queue();
}

static void part_diff_and_compare(void)
{
    diff_of("year", "200101000000Z", "210101000000Z");
    diff_of("year_rev", "210101000000Z", "200101000000Z");
    diff_of("same", "200101000000Z", "200101000000Z");
    diff_of("minute", "20200101000000Z", "20200101000100Z");
    diff_of("cross_midnight", "20200101233000Z", "20200101003000Z");
    diff_of("cross_month", "20200131233000Z", "20200201003000Z");
    diff_of("cross_leap", "20200228233000Z", "20200301003000Z");
    diff_of("negative_span", "20200101233000Z", "20200101000000Z");
    diff_of("big", "19500101000000Z", "20491231235959Z");
    diff_of("bad", "200101000000Z", "garbage");

    compare_of("utc_equal", "200101000000Z", "200101000000Z");
    compare_of("utc_before", "200101000000Z", "200101000001Z");
    compare_of("utc_after", "200101000001Z", "200101000000Z");
    compare_of("cross_syntax", "200101000000Z", "20200101000000Z");

    /* `ASN1_TIME_cmp_time_t` against a fixed instant. */
    {
        ASN1_TIME *t = ASN1_TIME_new();
        char k[192];

        ASN1_TIME_set_string(t, "200101000000Z");
        printf("cmptt.equal=%d\n", ASN1_TIME_cmp_time_t(t, (time_t)1577836800));
        printf("cmptt.before=%d\n", ASN1_TIME_cmp_time_t(t, (time_t)1577836801));
        printf("cmptt.after=%d\n", ASN1_TIME_cmp_time_t(t, (time_t)1577836799));
        printf("cmptt.far=%d\n", ASN1_TIME_cmp_time_t(t, (time_t)0));
        ASN1_TIME_free(t);

        /* A GeneralizedTime through the UTCTime entry point: the type guard. */
        t = ASN1_GENERALIZEDTIME_new();
        ASN1_GENERALIZEDTIME_set_string(t, "20200101000000Z");
        printf("cmptt.gen_via_utc=%d\n", ASN1_UTCTIME_cmp_time_t(t, (time_t)1577836800));
        printf("cmptt.gen_via_time=%d\n", ASN1_TIME_cmp_time_t(t, (time_t)1577836800));
        ASN1_GENERALIZEDTIME_free(t);

        /* Unparseable: the distinct -2. */
        t = ASN1_TIME_new();
        printf("cmptt.unparseable=%d\n", ASN1_TIME_cmp_time_t(t, (time_t)1577836800));
        printf("cmptt.unparseable_utc=%d\n", ASN1_UTCTIME_cmp_time_t(t, (time_t)1577836800));
        ASN1_TIME_free(t);

        /* The UTCTime entry point is type-guarded, so a UTCTime that parses works. */
        t = ASN1_UTCTIME_new();
        ASN1_UTCTIME_set_string(t, "700101000000Z");
        printf("cmptt.utc_epoch=%d\n", ASN1_UTCTIME_cmp_time_t(t, (time_t)0));
        printf("cmptt.utc_epoch_later=%d\n", ASN1_UTCTIME_cmp_time_t(t, (time_t)1));
        ASN1_UTCTIME_free(t);
        snprintf(k, sizeof(k), "cmptt");
        drain("cmptt.err");
        clear_queue();
    }

    /* A null value means now: only the return and the sign, and the sign is
     * stable because `to` is a fixed instant in the past. */
    {
        ASN1_TIME *past = ASN1_TIME_new();
        int day = 0;
        int sec = 0;
        int ok;

        ASN1_TIME_set_string(past, "200101000000Z");
        ok = ASN1_TIME_diff(&day, &sec, past, NULL);
        printf("null_diff.ok=%d\n", ok);
        printf("null_diff.future=%d\n", day > 0 || sec > 0 ? 1 : 0);
        ASN1_TIME_free(past);
        clear_queue();
    }
}

/* ------------------------------------------------------------------ printing */

static void print_of(const char *key, const char *s, unsigned long flags)
{
    ASN1_TIME *t = ASN1_TIME_new();
    BIO *b;
    char buf[256];
    int n;
    int rv;
    char k[192];

    clear_queue();
    if (!ASN1_TIME_set_string(t, s)) {
        printf("print.%s.set=0\n", key);
        ASN1_TIME_free(t);
        return;
    }
    b = BIO_new(BIO_s_mem());
    rv = ASN1_TIME_print_ex(b, t, flags);
    n = BIO_read(b, buf, (int)sizeof(buf) - 1);
    if (n < 0)
        n = 0;
    buf[n] = '\0';
    printf("print.%s.rv=%d\n", key, rv);
    printf("print.%s.len=%d\n", key, n);
    snprintf(k, sizeof(k), "print.%s", key);
    text(k, (const unsigned char *)buf, n);
    BIO_free(b);
    ASN1_TIME_free(t);
    clear_queue();
}

static void part_printing(void)
{
    print_of("rfc822_utc", "200101010203Z", ASN1_DTFLGS_RFC822);
    print_of("iso_utc", "200101010203Z", ASN1_DTFLGS_ISO8601);
    print_of("rfc822_gen", "20200101010203Z", ASN1_DTFLGS_RFC822);
    print_of("iso_gen", "20200101010203Z", ASN1_DTFLGS_ISO8601);
    print_of("rfc822_epoch", "700101000000Z", ASN1_DTFLGS_RFC822);
    print_of("rfc822_zero", "000101000000Z", ASN1_DTFLGS_RFC822);
    print_of("rfc822_double_digit", "20121205010203Z", ASN1_DTFLGS_RFC822);

    /* The fractional field: recognized only at offset 14 of a longer string. */
    print_of("frac1", "20200101000000.5Z", ASN1_DTFLGS_RFC822);
    print_of("frac1_iso", "20200101000000.5Z", ASN1_DTFLGS_ISO8601);
    print_of("frac6", "20200101000000.123456Z", ASN1_DTFLGS_RFC822);
    print_of("frac6_iso", "20200101000000.123456Z", ASN1_DTFLGS_ISO8601);
    print_of("no_frac", "20200101000000Z", ASN1_DTFLGS_RFC822);
    /* A fraction that is there but empty is refused by the parser, so the value
     * never reaches the printer. */
    print_of("frac_empty", "20200101000000.Z", ASN1_DTFLGS_RFC822);

    /* An unparseable value: `Bad time value`, and the collapsed return. */
    {
        ASN1_TIME *t = ASN1_TIME_new();
        BIO *b = BIO_new(BIO_s_mem());
        char buf[256];
        int n;

        clear_queue();
        printf("print.bad.rv=%d\n", ASN1_TIME_print(b, t));
        n = BIO_read(b, buf, (int)sizeof(buf) - 1);
        if (n < 0)
            n = 0;
        buf[n] = '\0';
        printf("print.bad.len=%d\n", n);
        text("print.bad", (const unsigned char *)buf, n);
        BIO_free(b);

        b = BIO_new(BIO_s_mem());
        printf("print.bad_ex.rv=%d\n", ASN1_TIME_print_ex(b, t, ASN1_DTFLGS_ISO8601));
        n = BIO_read(b, buf, (int)sizeof(buf) - 1);
        if (n < 0)
            n = 0;
        buf[n] = '\0';
        text("print.bad_ex", (const unsigned char *)buf, n);
        BIO_free(b);
        ASN1_TIME_free(t);
        drain("print.err");
    }

    /* The two typed printers, including the type guard in each. */
    {
        ASN1_UTCTIME *u = ASN1_UTCTIME_new();
        ASN1_GENERALIZEDTIME *g = ASN1_GENERALIZEDTIME_new();
        BIO *b = BIO_new(BIO_s_mem());
        char buf[256];
        int n;

        ASN1_UTCTIME_set_string(u, "200101010203Z");
        ASN1_GENERALIZEDTIME_set_string(g, "20200101010203Z");

        printf("typed.utc_print_utc=%d\n", ASN1_UTCTIME_print(b, u));
        n = BIO_read(b, buf, (int)sizeof(buf) - 1);
        if (n < 0)
            n = 0;
        buf[n] = '\0';
        text("typed.utc_print_utc", (const unsigned char *)buf, n);
        BIO_free(b);

        b = BIO_new(BIO_s_mem());
        printf("typed.utc_print_gen=%d\n", ASN1_UTCTIME_print(b, g));
        n = BIO_read(b, buf, (int)sizeof(buf) - 1);
        if (n < 0)
            n = 0;
        buf[n] = '\0';
        text("typed.utc_print_gen", (const unsigned char *)buf, n);
        BIO_free(b);

        b = BIO_new(BIO_s_mem());
        printf("typed.gen_print_gen=%d\n", ASN1_GENERALIZEDTIME_print(b, g));
        n = BIO_read(b, buf, (int)sizeof(buf) - 1);
        if (n < 0)
            n = 0;
        buf[n] = '\0';
        text("typed.gen_print_gen", (const unsigned char *)buf, n);
        BIO_free(b);

        b = BIO_new(BIO_s_mem());
        printf("typed.gen_print_utc=%d\n", ASN1_GENERALIZEDTIME_print(b, u));
        n = BIO_read(b, buf, (int)sizeof(buf) - 1);
        if (n < 0)
            n = 0;
        buf[n] = '\0';
        text("typed.gen_print_utc", (const unsigned char *)buf, n);
        BIO_free(b);

        ASN1_UTCTIME_free(u);
        ASN1_GENERALIZEDTIME_free(g);
        clear_queue();
    }
}

/* -------------------------------------------------- converters and duplicates */

static void part_converters(void)
{
    ASN1_TIME *t = ASN1_TIME_new();
    ASN1_GENERALIZEDTIME *out;
    char k[192];

    /* The shortening round trip: a UTCTime becomes a GeneralizedTime. */
    ASN1_TIME_set_string(t, "200101010203Z");
    out = ASN1_TIME_to_generalizedtime(t, NULL);
    printf("togen.from_utc.null=%d\n", out == NULL);
    snprintf(k, sizeof(k), "togen.from_utc");
    report_string(k, out);
    ASN1_GENERALIZEDTIME_free(out);

    /* Reuse through `out`, and the write-back. */
    ASN1_TIME_free(t);
    t = ASN1_TIME_new();
    ASN1_TIME_set_string(t, "20200101010203Z");
    out = NULL;
    {
        ASN1_GENERALIZEDTIME *r = ASN1_TIME_to_generalizedtime(t, &out);
        printf("togen.reuse.same=%d\n", r == out ? 1 : 0);
        printf("togen.reuse.allocated=%d\n", r != NULL ? 1 : 0);
        snprintf(k, sizeof(k), "togen.reuse");
        report_string(k, r);
        ASN1_GENERALIZEDTIME_free(out);
    }

    /* A destination that already holds a value: it is reused in place. */
    out = ASN1_GENERALIZEDTIME_new();
    {
        ASN1_GENERALIZEDTIME *save = out;
        ASN1_GENERALIZEDTIME *r = ASN1_TIME_to_generalizedtime(t, &out);

        printf("togen.inplace.same=%d\n", r == save ? 1 : 0);
        printf("togen.inplace.writeback=%d\n", out == r ? 1 : 0);
        snprintf(k, sizeof(k), "togen.inplace");
        report_string(k, r);
        ASN1_GENERALIZEDTIME_free(out);
    }

    /* A value that does not parse: null, and the caller's pointer untouched. */
    ASN1_TIME_free(t);
    t = ASN1_TIME_new();
    out = NULL;
    printf("togen.bad.null=%d\n", ASN1_TIME_to_generalizedtime(t, &out) == NULL);
    printf("togen.bad.untouched=%d\n", out == NULL ? 1 : 0);
    ASN1_TIME_free(t);
    clear_queue();

    /* normalize: a GeneralizedTime inside the window becomes a UTCTime. */
    t = ASN1_TIME_new();
    ASN1_TIME_set_string(t, "20200101010203Z");
    printf("norm.in_window.ok=%d\n", ASN1_TIME_normalize(t));
    report_string("norm.in_window", t);
    ASN1_TIME_free(t);

    t = ASN1_TIME_new();
    ASN1_TIME_set_string(t, "20500101010203Z");
    printf("norm.out_of_window.ok=%d\n", ASN1_TIME_normalize(t));
    report_string("norm.out_of_window", t);
    ASN1_TIME_free(t);

    t = ASN1_TIME_new();
    ASN1_TIME_set_string(t, "200101010203Z");
    printf("norm.utc.ok=%d\n", ASN1_TIME_normalize(t));
    report_string("norm.utc", t);
    ASN1_TIME_free(t);

    t = ASN1_TIME_new();
    printf("norm.bad.ok=%d\n", ASN1_TIME_normalize(t));
    report_string("norm.bad", t);
    ASN1_TIME_free(t);

    printf("norm.null=%d\n", ASN1_TIME_normalize(NULL));
    clear_queue();

    /* Duplicates: the syntax survives, and the content is equal. */
    {
        ASN1_UTCTIME *u = ASN1_UTCTIME_new();
        ASN1_GENERALIZEDTIME *g = ASN1_GENERALIZEDTIME_new();
        ASN1_UTCTIME *uc;
        ASN1_GENERALIZEDTIME *gc;
        ASN1_TIME *tc;

        ASN1_UTCTIME_set_string(u, "200101010203Z");
        uc = ASN1_UTCTIME_dup(u);
        printf("dup.utc.equal=%d\n", uc != NULL && ASN1_STRING_cmp((ASN1_STRING *)u,
                                                                  (ASN1_STRING *)uc) == 0);
        report_string("dup.utc", uc);
        tc = ASN1_TIME_dup(u);
        report_string("dup.utc_via_time", tc);
        ASN1_UTCTIME_free(uc);
        ASN1_TIME_free(tc);

        ASN1_GENERALIZEDTIME_set_string(g, "20200101010203Z");
        gc = ASN1_GENERALIZEDTIME_dup(g);
        printf("dup.gen.equal=%d\n", gc != NULL && ASN1_STRING_cmp((ASN1_STRING *)g,
                                                                  (ASN1_STRING *)gc) == 0);
        report_string("dup.gen", gc);
        tc = ASN1_TIME_dup(g);
        report_string("dup.gen_via_time", tc);
        ASN1_GENERALIZEDTIME_free(gc);
        ASN1_TIME_free(tc);

        ASN1_UTCTIME_free(u);
        ASN1_GENERALIZEDTIME_free(g);
        clear_queue();
    }

    /* The MSTRING constructor: a type-less, empty value. */
    {
        ASN1_TIME *fresh = ASN1_TIME_new();

        report_string("new.time", fresh);
        printf("new.time.check=%d\n", ASN1_TIME_check(fresh));
        printf("new.time.utc_check=%d\n", ASN1_UTCTIME_check(fresh));
        printf("new.time.gen_check=%d\n", ASN1_GENERALIZEDTIME_check(fresh));
        ASN1_TIME_free(fresh);
        clear_queue();
    }
}

/* --------------------------------------------------------- the error queue */

static void part_error_queue(void)
{
    ASN1_TIME *t = ASN1_TIME_new();

    /* A parse failure raises nothing: the queue is the caller's before and after. */
    clear_queue();
    ASN1_TIME_set_string(t, "garbage");
    ASN1_TIME_set_string(t, "200101000000");
    ASN1_TIME_check(t);
    ASN1_TIME_to_tm(t, NULL);
    ASN1_TIME_to_generalizedtime(t, NULL);
    ASN1_TIME_normalize(t);
    drain("err.after_failures");

    /* A raise on the queue from elsewhere is left alone by a failed parse. The
     * raise is `ASN1_STRING_set`'s own length check, which is reachable from an
     * implemented symbol with no allocation at all. */
    ASN1_STRING_set((ASN1_STRING *)t, "x", INT_MAX);
    ASN1_TIME_set_string(t, "garbage");
    drain("err.with_pending");

    ASN1_TIME_free(t);
    clear_queue();
}

int main(void)
{
    part_layout();
    part_utctime();
    part_gentime();
    part_time_set_string();
    part_x509_profile();
    part_constructors();
    part_to_tm();
    part_diff_and_compare();
    part_printing();
    part_converters();
    part_error_queue();
    printf("done=1\n");
    return 0;
}
