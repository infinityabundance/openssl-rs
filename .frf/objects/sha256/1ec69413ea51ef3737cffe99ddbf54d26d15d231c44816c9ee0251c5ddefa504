/*
 * openssl-rs — RT-ASN1: the DER codec, the string layer, the integer family and
 * the object layer, differentially.
 *
 * One program, compiled twice — against the admitted authority and against the
 * candidate distribution shell — and its transcript compared line by line. Every
 * line is `key=value`, so a divergence produces exactly one residual instead of
 * shifting every following line.
 *
 * What is compared, and why these things
 * --------------------------------------
 * `ASN1_STRING` is *not* opaque: its `length`, `type` and `data` are readable
 * through the installed header, so a caller can see the stored magnitude of an
 * integer, the type word including the `V_ASN1_NEG` bit, and the exact bytes an
 * encoding produced. The probe reads all three.
 *
 * The DER header decoder is the part of this stratum where a plausible-looking
 * implementation is most likely to be wrong, because its answers are packed into
 * one return value and its boundaries are counter-intuitive. So `ASN1_get_object`
 * is driven over a table of headers rather than over one example: short form, long
 * form, the 127/128 and 255/256 length boundaries, indefinite length, constructed
 * forms, the high-tag-number form, a zero-length content, every class, a header
 * whose declared length exceeds the buffer, a truncated long-form length, and the
 * end-of-contents marker. For each, the return value, the tag, the class, the
 * content length, how far the pointer advanced, and the error queue are printed.
 *
 * The integer content codec gets the same treatment, because its padding rules are
 * the least guessable part of the whole stratum: a positive whose top bit is set
 * gains a `00`, and a negative gains an `FF` unless its first octet is exactly
 * `0x80` *and* every later octet is zero. The probe decodes DER by hand for each
 * of those shapes and reads back the magnitude and the sign, so a wrong rule shows
 * up as a wrong `length` or a wrong first octet rather than as a wrong value that
 * happens to still convert.
 *
 * The error queue is part of every failure case. This stratum raises at
 * coordinates the authority's own source names, and the atlas records them: an
 * implementation with the right return value and the wrong reason fails here.
 *
 * Fault boundaries
 * ----------------
 * A probe cannot compare a crash. Where the authority dereferences without a check
 * the probe does not call, and the candidate's safer answer is recorded in
 * `docs/SECURITY_DIVERGENCE_POLICY.md`.
 *
 * A probe also cannot compare a symbol the candidate has not implemented: calling a
 * scaffold aborts the candidate with a diagnostic. The probe therefore stays on the
 * implemented surface, which for this court is the DER codec, `ASN1_STRING`, the
 * integer family, the object layer and the two context objects. The `d2i_*`
 * wrappers for the other primitive types, `i2d_ASN1_*`, `ASN1_BIT_STRING`, the time
 * types and the template machinery are later subphases
 * (`docs/PHASE-5-SUBPHASES.md`).
 *
 * Scope
 * -----
 * This is a differential-compatibility result for the behaviours the probe
 * exercises, on one platform, for one build profile. It is NOT evidence about any
 * symbol the probe does not call (`docs/PARITY_MODEL.md`).
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <stdio.h>
#include <string.h>

/* A header, then what the decoder made of it. `avail` is what the caller claims to
 * have, which is deliberately allowed to disagree with `len` so the over-length
 * paths are reachable. */
static void hdr(const char *key, const unsigned char *p, long len, long avail)
{
    const unsigned char *q = p;
    long plen = 0;
    int tag = 0, xclass = 0;
    int r;

    r = ASN1_get_object(&q, &plen, &tag, &xclass, avail);
    printf("%s.ret=%d\n", key, r);
    printf("%s.tag=%d\n", key, tag);
    printf("%s.class=%d\n", key, xclass);
    printf("%s.len=%ld\n", key, plen);
    printf("%s.adv=%ld\n", key, (long)(q - p));
    printf("%s.err=%lu\n", key, ERR_peek_error());
    ERR_clear_error();
    (void)len;
}

/* Decode one INTEGER or ENUMERATED and report the *stored* magnitude, the type
 * word and the sign bit, so the content codec's padding rules are visible. */
static void decode_int(const char *key, const unsigned char *der, long len)
{
    const unsigned char *p = der;
    ASN1_INTEGER *ai = d2i_ASN1_INTEGER(NULL, &p, len);
    int i;

    printf("%s.present=%d\n", key, ai != NULL);
    printf("%s.adv=%ld\n", key, (long)(p - der));
    printf("%s.err=%lu\n", key, ERR_peek_error());
    ERR_clear_error();
    if (ai == NULL)
        return;
    printf("%s.type=%d\n", key, ASN1_STRING_type(ai));
    printf("%s.length=%d\n", key, ASN1_STRING_length(ai));
    printf("%s.bytes=", key);
    for (i = 0; i < ASN1_STRING_length(ai); i++)
        printf("%02X", ASN1_STRING_get0_data(ai)[i]);
    printf("\n");
    printf("%s.get=%ld\n", key, ASN1_INTEGER_get(ai));
    {
        int64_t v = 0;
        printf("%s.geti64=%d:%lld\n", key, ASN1_INTEGER_get_int64(&v, ai),
               (long long)v);
    }
    ASN1_INTEGER_free(ai);
}

/* The same for an ENUMERATED, whose accessor answers differently on overflow. */
static void decode_enum(const char *key, const unsigned char *der, long len)
{
    const unsigned char *p = der;
    ASN1_ENUMERATED *ae = d2i_ASN1_ENUMERATED(NULL, &p, len);

    printf("%s.present=%d\n", key, ae != NULL);
    printf("%s.adv=%ld\n", key, (long)(p - der));
    printf("%s.err=%lu\n", key, ERR_peek_error());
    ERR_clear_error();
    if (ae == NULL)
        return;
    printf("%s.length=%d\n", key, ASN1_STRING_length(ae));
    printf("%s.get=%ld\n", key, ASN1_ENUMERATED_get(ae));
    ASN1_ENUMERATED_free(ae);
}

/* Decode an OCTET STRING and report the collected content. */
static void decode_oct(const char *key, const unsigned char *der, long len)
{
    const unsigned char *p = der;
    ASN1_OCTET_STRING *os = d2i_ASN1_OCTET_STRING(NULL, &p, len);
    int i;

    printf("%s.present=%d\n", key, os != NULL);
    printf("%s.adv=%ld\n", key, (long)(p - der));
    printf("%s.err=%lu\n", key, ERR_peek_error());
    ERR_clear_error();
    if (os == NULL)
        return;
    printf("%s.length=%d\n", key, ASN1_STRING_length(os));
    printf("%s.bytes=", key);
    for (i = 0; i < ASN1_STRING_length(os); i++)
        printf("%02X", ASN1_STRING_get0_data(os)[i]);
    printf("\n");
    ASN1_OCTET_STRING_free(os);
}

/* Write a BIO's contents, escaping what a line-oriented comparison cannot carry. */
static void drain(const char *key, BIO *b)
{
    char buf[512];
    int n = BIO_read(b, buf, sizeof(buf) - 1);
    int i;

    if (n < 0)
        n = 0;
    buf[n] = '\0';
    printf("%s.len=%d\n", key, n);
    printf("%s.text=", key);
    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char)buf[i];
        if (c >= 0x20 && c < 0x7f && c != '\\')
            putchar(c);
        else
            printf("\\x%02X", c);
    }
    printf("\n");
}

int main(void)
{
    /* Unbuffered: this probe must be able to tell exactly how far it got if a call
     * faults, and a redirected stdout would otherwise lose the tail of its buffer
     * and make the last visible line a lie. A probe whose transcript depends on
     * buffering cannot be compared. */
    setvbuf(stdout, NULL, _IONBF, 0);

    /* ------------------------------------------------------------------ */
    /* The header decoder.                                                */
    /* ------------------------------------------------------------------ */
    {
        static const unsigned char integer5[] = { 0x02, 0x01, 0x05 };
        static const unsigned char octet3[] = { 0x04, 0x03, 0x41, 0x42, 0x43 };
        static const unsigned char seq_empty[] = { 0x30, 0x00 };
        static const unsigned char seq_int[] = { 0x30, 0x03, 0x02, 0x01, 0x01 };
        static const unsigned char indef_oct[] =
            { 0x24, 0x80, 0x04, 0x01, 0x41, 0x00, 0x00 };
        static const unsigned char indef_bit[] =
            { 0x23, 0x80, 0x03, 0x02, 0x00, 0x41 };
        static const unsigned char eoc[] = { 0x00, 0x00 };
        static const unsigned char ctx_prim[] = { 0x80, 0x01, 0x41 };
        static const unsigned char ctx_cons[] = { 0xa0, 0x01, 0x41 };
        static const unsigned char app_prim[] = { 0x41, 0x01, 0x41 };
        static const unsigned char priv_prim[] = { 0xc1, 0x01, 0x41 };
        /* Length 127 and 128: the short-form boundary. */
        static unsigned char len127[2 + 127];
        static unsigned char len128[3 + 128];
        /* Length 255 and 256: the long-form boundary. */
        static unsigned char len255[3 + 255];
        static unsigned char len256[4 + 256];
        /* A declared length past the end of the buffer. */
        static const unsigned char over[] = { 0x04, 0x05, 0x41, 0x42 };
        /* A truncated long-form length: the length-of-length is not all there. */
        static const unsigned char trunclen[] = { 0x04, 0x84, 0x00, 0x00 };
        /* Length-of-length 0x80, which is the indefinite form, and 0x81 with the
         * short form's bit set rather than a minimal encoding. */
        static const unsigned char nonminimal[] = { 0x04, 0x81, 0x01, 0x41 };
        static const unsigned char zerolen[] = { 0x04, 0x00 };

        memset(len127, 0x41, sizeof(len127));
        len127[0] = 0x04;
        len127[1] = 0x7f;
        memset(len128, 0x41, sizeof(len128));
        len128[0] = 0x04;
        len128[1] = 0x81;
        len128[2] = 0x80;
        memset(len255, 0x41, sizeof(len255));
        len255[0] = 0x04;
        len255[1] = 0x81;
        len255[2] = 0xff;
        memset(len256, 0x41, sizeof(len256));
        len256[0] = 0x04;
        len256[1] = 0x82;
        len256[2] = 0x01;
        len256[3] = 0x00;

        hdr("h.int5", integer5, sizeof(integer5), sizeof(integer5));
        hdr("h.oct3", octet3, sizeof(octet3), sizeof(octet3));
        hdr("h.seq_empty", seq_empty, sizeof(seq_empty), sizeof(seq_empty));
        hdr("h.seq_int", seq_int, sizeof(seq_int), sizeof(seq_int));
        hdr("h.indef_oct", indef_oct, sizeof(indef_oct), sizeof(indef_oct));
        hdr("h.indef_bit", indef_bit, sizeof(indef_bit), sizeof(indef_bit));
        hdr("h.eoc", eoc, sizeof(eoc), sizeof(eoc));
        hdr("h.ctx_prim", ctx_prim, sizeof(ctx_prim), sizeof(ctx_prim));
        hdr("h.ctx_cons", ctx_cons, sizeof(ctx_cons), sizeof(ctx_cons));
        hdr("h.app", app_prim, sizeof(app_prim), sizeof(app_prim));
        hdr("h.priv", priv_prim, sizeof(priv_prim), sizeof(priv_prim));
        hdr("h.len127", len127, sizeof(len127), sizeof(len127));
        hdr("h.len128", len128, sizeof(len128), sizeof(len128));
        hdr("h.len255", len255, sizeof(len255), sizeof(len255));
        hdr("h.len256", len256, sizeof(len256), sizeof(len256));
        hdr("h.over", over, sizeof(over), sizeof(over));
        hdr("h.trunclen", trunclen, sizeof(trunclen), sizeof(trunclen));
        hdr("h.nonminimal", nonminimal, sizeof(nonminimal), sizeof(nonminimal));
        hdr("h.zerolen", zerolen, sizeof(zerolen), sizeof(zerolen));
        /* Claiming fewer bytes than the object needs, and none at all. */
        hdr("h.over_short_avail", over, sizeof(over), 3);
        hdr("h.zero_avail", integer5, sizeof(integer5), 0);
        /* The high-tag-number form: tag 31 and above, one and two length octets. */
        {
            static const unsigned char hightag[] =
                { 0x1f, 0x81, 0x00, 0x01, 0x41 };
            hdr("h.hightag", hightag, sizeof(hightag), sizeof(hightag));
        }
        {
            static const unsigned char hightag2[] =
                { 0x1f, 0x82, 0x01, 0x00, 0x01, 0x41 };
            hdr("h.hightag2", hightag2, sizeof(hightag2), sizeof(hightag2));
        }
    }

    /* ------------------------------------------------------------------ */
    /* The infinite-end check, which is what the constructed forms use.    */
    /* ------------------------------------------------------------------ */
    {
        static unsigned char eoc[] = { 0x00, 0x00, 0x41 };
        static unsigned char not_eoc[] = { 0x00, 0x01, 0x00, 0x00 };
        /* `ASN1_check_infinite_end` takes a non-const pointer and
         * `ASN1_const_check_infinite_end` a const one, so the two need different
         * variables -- that asymmetry is the authority's own. */
        unsigned char *p;
        const unsigned char *cp;

        p = eoc;
        printf("eoc.check=%d\n", ASN1_check_infinite_end(&p, (long)sizeof(eoc)));
        printf("eoc.adv=%ld\n", (long)(p - eoc));
        cp = eoc;
        printf("eoc.const_check=%d\n",
               ASN1_const_check_infinite_end(&cp, (long)sizeof(eoc)));
        printf("eoc.const_adv=%ld\n", (long)(cp - eoc));
        p = not_eoc;
        printf("eoc.negative=%d\n", ASN1_check_infinite_end(&p, (long)sizeof(not_eoc)));
        printf("eoc.negative_adv=%ld\n", (long)(p - not_eoc));
        p = eoc;
        printf("eoc.one_byte=%d\n", ASN1_check_infinite_end(&p, 1));
    }

    /* ------------------------------------------------------------------ */
    /* Encoding a header, and the tag helpers.                            */
    /* ------------------------------------------------------------------ */
    {
        unsigned char buf[16];
        unsigned char *p;
        int i;

        for (i = -1; i <= 32; i++)
            printf("tag2bit.%d=%lu\n", i, ASN1_tag2bit(i));
        for (i = -1; i <= 5; i++)
            printf("tag2str.%d=%s\n", i, ASN1_tag2str(i));
        printf("tag2str.16=%s\n", ASN1_tag2str(16));
        printf("tag2str.17=%s\n", ASN1_tag2str(17));
        printf("tag2str.30=%s\n", ASN1_tag2str(30));
        printf("tag2str.31=%s\n", ASN1_tag2str(31));

        /* A primitive universal zero-length, a constructed indefinite, and the
         * high-tag form, written and then read back by the decoder above. */
        p = buf;
        ASN1_put_object(&p, 0, 0, V_ASN1_OCTET_STRING, V_ASN1_UNIVERSAL);
        printf("put.primitive_len=%ld\n", (long)(p - buf));
        printf("put.primitive_size=%d\n",
               ASN1_object_size(0, 0, V_ASN1_OCTET_STRING));

        p = buf;
        ASN1_put_object(&p, 1, 3, V_ASN1_OCTET_STRING, V_ASN1_UNIVERSAL);
        printf("put.constructed_len=%ld\n", (long)(p - buf));
        ASN1_put_eoc(&p);
        printf("put.eoc_total=%ld\n", (long)(p - buf));
        printf("put.constructed_size=%d\n",
               ASN1_object_size(1, 3, V_ASN1_OCTET_STRING));

        p = buf;
        ASN1_put_object(&p, 0, 1, 0x80, V_ASN1_CONTEXT_SPECIFIC);
        printf("put.ctx_len=%ld\n", (long)(p - buf));
        printf("put.ctx_bytes=");
        for (i = 0; i < (int)(p - buf); i++)
            printf("%02X", buf[i]);
        printf("\n");

        p = buf;
        ASN1_put_object(&p, 0, 4, 0x1234, V_ASN1_UNIVERSAL);
        printf("put.hightag_len=%ld\n", (long)(p - buf));
        printf("put.hightag_bytes=");
        for (i = 0; i < (int)(p - buf); i++)
            printf("%02X", buf[i]);
        printf("\n");
    }

    /* ------------------------------------------------------------------ */
    /* The string layer.                                                  */
    /* ------------------------------------------------------------------ */
    {
        ASN1_STRING *a = ASN1_STRING_new();
        ASN1_STRING *b = ASN1_STRING_type_new(V_ASN1_IA5STRING);
        ASN1_STRING *c = ASN1_STRING_new();

        printf("str.new_present=%d\n", a != NULL);
        printf("str.new_type=%d\n", ASN1_STRING_type(a));
        printf("str.new_length=%d\n", ASN1_STRING_length(a));
        printf("str.new_data_null=%d\n", ASN1_STRING_get0_data(a) == NULL);
        printf("str.type_new_type=%d\n", ASN1_STRING_type(b));

        printf("str.set=%d\n", ASN1_STRING_set(a, "hello", 5));
        printf("str.set_length=%d\n", ASN1_STRING_length(a));
        printf("str.set_bytes=%s\n", ASN1_STRING_get0_data(a));
        printf("str.data_matches_get0=%d\n", ASN1_STRING_data(a) == ASN1_STRING_get0_data(a));
        /* `set` writes a NUL one past the content; observable only through a
         * second `set` that shrinks the string, because the authority does not
         * clear the tail. */
        printf("str.set_shorter=%d\n", ASN1_STRING_set(a, "hi", 2));
        printf("str.shorter_length=%d\n", ASN1_STRING_length(a));
        printf("str.shorter_tail=%d\n", ASN1_STRING_get0_data(a)[2]);

        printf("str.set_longer=%d\n", ASN1_STRING_set(a, "hello world", 11));
        printf("str.longer_length=%d\n", ASN1_STRING_length(a));
        printf("str.nul_terminated=%d\n", ASN1_STRING_get0_data(a)[11]);

        /* A negative length means "NUL-terminated". */
        printf("str.set_neg=%d\n", ASN1_STRING_set(a, "abc", -1));
        printf("str.neg_length=%d\n", ASN1_STRING_length(a));

        printf("str.copy=%d\n", ASN1_STRING_copy(c, a));
        printf("str.copy_type=%d\n", ASN1_STRING_type(c));
        printf("str.copy_length=%d\n", ASN1_STRING_length(c));
        printf("str.cmp_equal=%d\n", ASN1_STRING_cmp(a, c));
        printf("str.set_type=%d\n", ASN1_STRING_set(c, "abd", 3));
        printf("str.cmp_differs=%d\n", ASN1_STRING_cmp(a, c) < 0);
        /* The type is part of the comparison, so the same bytes with a different
         * type are not equal. */
        printf("str.copy_type_only=%d\n", ASN1_STRING_copy(c, a));
        ASN1_STRING_set0(c, NULL, 0);
        printf("str.set0_cleared=%d\n", ASN1_STRING_length(c));

        /* `ASN1_STRING_length_set` returns void, so its answer cannot be printed;
         * the length it set is the observation. */
        ASN1_STRING_length_set(a, 1);
        printf("str.length_after_set=%d\n", ASN1_STRING_length(a));

        {
            ASN1_STRING *d = ASN1_STRING_dup(a);
            printf("str.dup_present=%d\n", d != NULL);
            printf("str.dup_length=%d\n", d != NULL ? ASN1_STRING_length(d) : -1);
            printf("str.dup_cmp=%d\n", d != NULL ? ASN1_STRING_cmp(a, d) : -99);
            ASN1_STRING_free(d);
        }

        {
            ASN1_OCTET_STRING *o1 = ASN1_OCTET_STRING_new();
            ASN1_OCTET_STRING *o2 = ASN1_OCTET_STRING_new();
            ASN1_OCTET_STRING *o3;
            printf("oct.set=%d\n", ASN1_OCTET_STRING_set(o1, (unsigned char *)"ab", 2));
            printf("oct.set2=%d\n", ASN1_OCTET_STRING_set(o2, (unsigned char *)"ab", 2));
            printf("oct.cmp_equal=%d\n", ASN1_OCTET_STRING_cmp(o1, o2));
            printf("oct.set3=%d\n", ASN1_OCTET_STRING_set(o2, (unsigned char *)"ac", 2));
            printf("oct.cmp_differs=%d\n", ASN1_OCTET_STRING_cmp(o1, o2));
            o3 = ASN1_OCTET_STRING_dup(o1);
            printf("oct.dup_present=%d\n", o3 != NULL);
            printf("oct.dup_cmp=%d\n", o3 != NULL ? ASN1_OCTET_STRING_cmp(o1, o3) : -99);
            ASN1_OCTET_STRING_free(o3);
            ASN1_OCTET_STRING_free(o1);
            ASN1_OCTET_STRING_free(o2);
        }

        ASN1_STRING_clear_free(a);
        ASN1_STRING_free(b);
        ASN1_STRING_clear_free(c);
    }

    /* ------------------------------------------------------------------ */
    /* The integer content codec: what the stored magnitude looks like for */
    /* each of the padding rules.                                          */
    /* ------------------------------------------------------------------ */
    {
        /* Positive, top bit clear: no pad. */
        static const unsigned char p_7f[] = { 0x02, 0x01, 0x7f };
        /* Positive, top bit set: one 00 pad, which the magnitude drops. */
        static const unsigned char p_80[] = { 0x02, 0x02, 0x00, 0x80 };
        /* Positive 0x80 written without the pad: reads as negative. */
        static const unsigned char p_80_nopad[] = { 0x02, 0x01, 0x80 };
        /* Negative -1, -128, -129. */
        static const unsigned char n_1[] = { 0x02, 0x01, 0xff };
        static const unsigned char n_128[] = { 0x02, 0x01, 0x80 };
        static const unsigned char n_129[] = { 0x02, 0x02, 0xff, 0x7f };
        /* The special case: 0x80 followed by zeros is the minimal negative for
         * its length and gains no pad; 0x80 followed by a non-zero does. */
        static const unsigned char n_min[] =
            { 0x02, 0x03, 0x80, 0x00, 0x00 };
        static const unsigned char n_min_plus[] =
            { 0x02, 0x04, 0xff, 0x80, 0x00, 0x01 };
        /* Zero, and zero written as a padded pair. */
        static const unsigned char zero[] = { 0x02, 0x01, 0x00 };
        static const unsigned char zero_padded[] = { 0x02, 0x02, 0x00, 0x00 };
        /* Illegal: matching sign bits in the first two octets. */
        static const unsigned char bad_pad_pos[] =
            { 0x02, 0x02, 0x00, 0x7f };
        static const unsigned char bad_pad_neg[] =
            { 0x02, 0x02, 0xff, 0x80 };
        /* Zero content: illegal. */
        static const unsigned char zero_content[] = { 0x02, 0x00 };
        /* Never a length that fits a long: nine octets of content. */
        static const unsigned char wide[] =
            { 0x02, 0x09, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        /* 64-bit extremes. */
        static const unsigned char i64max[] =
            { 0x02, 0x08, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
        static const unsigned char i64min[] =
            { 0x02, 0x08, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        static const unsigned char u64max[] =
            { 0x02, 0x09, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
        /* A truncated one: the header claims two, only one is there. */
        static const unsigned char trunc[] = { 0x02, 0x02, 0x01 };
        /* The wrong tag entirely. */
        static const unsigned char wrong_tag[] = { 0x04, 0x01, 0x00 };

        decode_int("i.7f", p_7f, sizeof(p_7f));
        decode_int("i.p80", p_80, sizeof(p_80));
        decode_int("i.p80_nopad", p_80_nopad, sizeof(p_80_nopad));
        decode_int("i.n1", n_1, sizeof(n_1));
        decode_int("i.n128", n_128, sizeof(n_128));
        decode_int("i.n129", n_129, sizeof(n_129));
        decode_int("i.nmin", n_min, sizeof(n_min));
        decode_int("i.nmin_plus", n_min_plus, sizeof(n_min_plus));
        decode_int("i.zero", zero, sizeof(zero));
        decode_int("i.zero_padded", zero_padded, sizeof(zero_padded));
        decode_int("i.bad_pad_pos", bad_pad_pos, sizeof(bad_pad_pos));
        decode_int("i.bad_pad_neg", bad_pad_neg, sizeof(bad_pad_neg));
        decode_int("i.zero_content", zero_content, sizeof(zero_content));
        decode_int("i.wide", wide, sizeof(wide));
        decode_int("i.i64max", i64max, sizeof(i64max));
        decode_int("i.i64min", i64min, sizeof(i64min));
        decode_int("i.u64max", u64max, sizeof(u64max));
        decode_int("i.trunc", trunc, sizeof(trunc));
        decode_int("i.wrong_tag", wrong_tag, sizeof(wrong_tag));

        {
            static const unsigned char e_1[] = { 0x0a, 0x01, 0xff };
            static const unsigned char e_wide[] =
                { 0x0a, 0x09, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            decode_enum("e.n1", e_1, sizeof(e_1));
            decode_enum("e.wide", e_wide, sizeof(e_wide));
        }
    }

    /* ------------------------------------------------------------------ */
    /* The integer accessors, over the values whose ranges are the edges.  */
    /* ------------------------------------------------------------------ */
    {
        static const long long vals[] = {
            0LL, 1LL, -1LL, 127LL, 128LL, -128LL, 255LL, 256LL, -129LL,
            2147483647LL, -2147483648LL,
            9223372036854775807LL, -9223372036854775807LL - 1LL,
        };
        size_t k;

        for (k = 0; k < sizeof(vals) / sizeof(vals[0]); k++) {
            ASN1_INTEGER *ai = ASN1_INTEGER_new();
            int64_t back = 0;
            int ok = ASN1_INTEGER_set_int64(ai, vals[k]);
            printf("iv.%zu.set=%d\n", k, ok);
            printf("iv.%zu.len=%d\n", k, ASN1_STRING_length(ai));
            printf("iv.%zu.type=%d\n", k, ASN1_STRING_type(ai));
            printf("iv.%zu.bytes=", k);
            {
                int i;
                for (i = 0; i < ASN1_STRING_length(ai); i++)
                    printf("%02X", ASN1_STRING_get0_data(ai)[i]);
            }
            printf("\n");
            printf("iv.%zu.geti64=%d:%lld\n", k, ASN1_INTEGER_get_int64(&back, ai),
                   (long long)back);
            printf("iv.%zu.get=%ld\n", k, ASN1_INTEGER_get(ai));
            ASN1_INTEGER_free(ai);
        }

        {
            static const unsigned long long uvals[] = {
                0ULL, 1ULL, 127ULL, 128ULL, 255ULL, 256ULL,
                9223372036854775807ULL, 18446744073709551615ULL,
            };
            size_t k;
            for (k = 0; k < sizeof(uvals) / sizeof(uvals[0]); k++) {
                ASN1_INTEGER *ai = ASN1_INTEGER_new();
                uint64_t back = 0;
                printf("uv.%zu.set=%d\n", k, ASN1_INTEGER_set_uint64(ai, uvals[k]));
                printf("uv.%zu.getu64=%d:%llu\n", k,
                       ASN1_INTEGER_get_uint64(&back, ai),
                       (unsigned long long)back);
                /* The signed accessor on the same value, which is the path that
                 * answers -1 rather than the value. */
                printf("uv.%zu.get=%ld\n", k, ASN1_INTEGER_get(ai));
                {
                    int64_t sv = 0;
                    printf("uv.%zu.geti64=%d:%lld\n", k,
                           ASN1_INTEGER_get_int64(&sv, ai), (long long)sv);
                }
                printf("uv.%zu.err=%lu\n", k, ERR_peek_error());
                ERR_clear_error();
                ASN1_INTEGER_free(ai);
            }
        }

        /* The wrong-type and null cases, which answer differently per accessor. */
        {
            ASN1_ENUMERATED *ae = ASN1_ENUMERATED_new();
            int64_t v = 0;
            printf("m.enum_set=%d\n", ASN1_ENUMERATED_set(ae, 5));
            printf("m.enum_get=%ld\n", ASN1_ENUMERATED_get(ae));
            printf("m.int_accessor_on_enum=%ld\n", ASN1_INTEGER_get(ae));
            printf("m.int_int64_on_enum=%d\n", ASN1_INTEGER_get_int64(&v, ae));
            printf("m.err_after_wrong_type=%lu\n", ERR_peek_error());
            ERR_clear_error();
            printf("m.enum_get_null=%ld\n", ASN1_ENUMERATED_get(NULL));
            printf("m.int_get_null=%ld\n", ASN1_INTEGER_get(NULL));
            ASN1_ENUMERATED_free(ae);
        }

        /* `cmp` is sign-first, so a negative is less than any positive. */
        {
            static const long long pairs[][2] = {
                { 1LL, 2LL }, { 2LL, 1LL }, { -1LL, 1LL }, { 1LL, -1LL },
                { -2LL, -1LL }, { -1LL, -2LL }, { 0LL, -1LL }, { 0LL, 1LL },
                { 0LL, 0LL },
            };
            size_t k;
            for (k = 0; k < sizeof(pairs) / sizeof(pairs[0]); k++) {
                ASN1_INTEGER *x = ASN1_INTEGER_new();
                ASN1_INTEGER *y = ASN1_INTEGER_new();
                int c;
                ASN1_INTEGER_set_int64(x, pairs[k][0]);
                ASN1_INTEGER_set_int64(y, pairs[k][1]);
                c = ASN1_INTEGER_cmp(x, y);
                printf("ic.%zu=%d\n", k, c < 0 ? -1 : (c > 0 ? 1 : 0));
                ASN1_INTEGER_free(x);
                ASN1_INTEGER_free(y);
            }
        }

        /* The `BIGNUM` bridges, including the negative case and the type check. */
        {
            static const char *hexes[] = { "0", "1", "FF", "100", "-1", "-FF",
                                           "7FFFFFFFFFFFFFFF" };
            size_t k;
            for (k = 0; k < sizeof(hexes) / sizeof(hexes[0]); k++) {
                BIGNUM *bn = NULL;
                ASN1_INTEGER *ai;
                BIGNUM *back = NULL;
                if (!BN_hex2bn(&bn, hexes[k])) {
                    printf("bn.%zu.parse=failed\n", k);
                    continue;
                }
                ai = BN_to_ASN1_INTEGER(bn, NULL);
                printf("bn.%zu.present=%d\n", k, ai != NULL);
                if (ai != NULL) {
                    printf("bn.%zu.len=%d\n", k, ASN1_STRING_length(ai));
                    printf("bn.%zu.type=%d\n", k, ASN1_STRING_type(ai));
                    printf("bn.%zu.bytes=", k);
                    {
                        int i;
                        for (i = 0; i < ASN1_STRING_length(ai); i++)
                            printf("%02X", ASN1_STRING_get0_data(ai)[i]);
                    }
                    printf("\n");
                    back = ASN1_INTEGER_to_BN(ai, NULL);
                    printf("bn.%zu.roundtrip=%d\n", k,
                           back != NULL && BN_cmp(bn, back) == 0);
                    printf("bn.%zu.roundtrip_neg=%d\n", k,
                           back != NULL && BN_is_negative(bn) == BN_is_negative(back));
                    BN_free(back);
                    /* The type check inside `ASN1_INTEGER_to_BN`. */
                    printf("bn.%zu.asm_enum=%d\n", k,
                           ASN1_ENUMERATED_to_BN(ai, NULL) == NULL);
                    printf("bn.%zu.enum_err=%lu\n", k, ERR_peek_error());
                    ERR_clear_error();
                    ASN1_INTEGER_free(ai);
                }
                BN_free(bn);
            }
        }
    }

    /* ------------------------------------------------------------------ */
    /* The object layer.                                                  */
    /* ------------------------------------------------------------------ */
    {
        /* A registered OID: the decoder must answer the static table entry. */
        static const unsigned char rsa_oid[] = {
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01
        };
        /* An unregistered one, which becomes dynamic. */
        static const unsigned char dyn_oid[] = { 0x06, 0x03, 0x2a, 0x03, 0x04 };
        /* The last octet's top bit set: invalid. */
        static const unsigned char bad_last[] = { 0x06, 0x02, 0x2a, 0x80 };
        /* A 0x80 octet leading a sub-identifier: the X.690 8.19.2 check. */
        static const unsigned char bad_subid[] = { 0x06, 0x03, 0x2a, 0x80, 0x01 };
        /* Empty content. */
        static const unsigned char empty_oid[] = { 0x06, 0x00 };
        /* The wrong tag. */
        static const unsigned char not_oid[] = { 0x02, 0x01, 0x00 };

        {
            const unsigned char *p = rsa_oid;
            ASN1_OBJECT *o = d2i_ASN1_OBJECT(NULL, &p, sizeof(rsa_oid));
            char txt[128];
            BIO *b;
            printf("o.rsa.present=%d\n", o != NULL);
            printf("o.rsa.adv=%ld\n", (long)(p - rsa_oid));
            printf("o.rsa.length=%d\n", (int)OBJ_length(o));
            printf("o.rsa.nid=%d\n", OBJ_obj2nid(o));
            printf("o.rsa.txt=%d:%s\n", OBJ_obj2txt(txt, sizeof(txt), o, 0), txt);
            /* The encoding round trip; `i2d` with a null slot allocates. */
            {
                unsigned char *der = NULL;
                int n = i2d_ASN1_OBJECT(o, &der);
                printf("o.rsa.i2d=%d\n", n);
                printf("o.rsa.i2d_bytes=");
                {
                    int i;
                    for (i = 0; i < n; i++)
                        printf("%02X", der[i]);
                }
                printf("\n");
                OPENSSL_free(der);
            }
            /* `i2t` and `i2a`. */
            printf("o.rsa.i2t=%d\n", i2t_ASN1_OBJECT(txt, sizeof(txt), o));
            b = BIO_new(BIO_s_mem());
            printf("o.rsa.i2a=%d\n", i2a_ASN1_OBJECT(b, o));
            drain("o.rsa.i2a_text", b);
            BIO_free(b);
            ASN1_OBJECT_free(o);
        }

        {
            const unsigned char *p = dyn_oid;
            ASN1_OBJECT *o = d2i_ASN1_OBJECT(NULL, &p, sizeof(dyn_oid));
            char txt[128];
            printf("o.dyn.present=%d\n", o != NULL);
            printf("o.dyn.length=%d\n", (int)OBJ_length(o));
            printf("o.dyn.nid=%d\n", OBJ_obj2nid(o));
            printf("o.dyn.txt=%d:%s\n", OBJ_obj2txt(txt, sizeof(txt), o, 0), txt);
            ASN1_OBJECT_free(o);
        }

        {
            const unsigned char *p = bad_last;
            ASN1_OBJECT *o = d2i_ASN1_OBJECT(NULL, &p, sizeof(bad_last));
            printf("o.bad_last.present=%d\n", o != NULL);
            printf("o.bad_last.adv=%ld\n", (long)(p - bad_last));
            printf("o.bad_last.err=%lu\n", ERR_peek_error());
            ERR_clear_error();
        }
        {
            const unsigned char *p = bad_subid;
            ASN1_OBJECT *o = d2i_ASN1_OBJECT(NULL, &p, sizeof(bad_subid));
            printf("o.bad_subid.present=%d\n", o != NULL);
            printf("o.bad_subid.err=%lu\n", ERR_peek_error());
            ERR_clear_error();
        }
        {
            const unsigned char *p = empty_oid;
            ASN1_OBJECT *o = d2i_ASN1_OBJECT(NULL, &p, sizeof(empty_oid));
            printf("o.empty.present=%d\n", o != NULL);
            printf("o.empty.err=%lu\n", ERR_peek_error());
            ERR_clear_error();
        }
        {
            const unsigned char *p = not_oid;
            ASN1_OBJECT *o = d2i_ASN1_OBJECT(NULL, &p, sizeof(not_oid));
            printf("o.not_oid.present=%d\n", o != NULL);
            printf("o.not_oid.err=%lu\n", ERR_peek_error());
            ERR_clear_error();
        }

        /* `create` takes ownership of nothing: it copies. The names it was given
         * are dropped by the decoder's own rules, so the text comes from the OID. */
        {
            static unsigned char oid_data[] = { 0x2a, 0x03, 0x04 };
            ASN1_OBJECT *o = ASN1_OBJECT_create(NID_undef,
                                                oid_data, 3, NULL, NULL);
            char txt[128];
            printf("o.create.present=%d\n", o != NULL);
            printf("o.create.length=%d\n", (int)OBJ_length(o));
            printf("o.create.txt=%d:%s\n", OBJ_obj2txt(txt, sizeof(txt), o, 0), txt);
            ASN1_OBJECT_free(o);
        }

        /* A fresh object has no data, which is what makes `i2a_ASN1_OBJECT` write
         * `NULL` rather than an empty string. */
        {
            ASN1_OBJECT *o = ASN1_OBJECT_new();
            BIO *b = BIO_new(BIO_s_mem());
            char txt[16];
            printf("o.new.present=%d\n", o != NULL);
            printf("o.new.length=%d\n", (int)OBJ_length(o));
            printf("o.new.data_null=%d\n", OBJ_get0_data(o) == NULL);
            printf("o.new.i2a=%d\n", i2a_ASN1_OBJECT(b, o));
            drain("o.new.i2a_text", b);
            printf("o.new.i2t=%d\n", i2t_ASN1_OBJECT(txt, sizeof(txt), o));
            BIO_free(b);
            ASN1_OBJECT_free(o);
        }

        /* A null object, which `i2a_ASN1_OBJECT` answers for rather than faulting. */
        {
            BIO *b = BIO_new(BIO_s_mem());
            printf("o.null.i2a=%d\n", i2a_ASN1_OBJECT(b, NULL));
            drain("o.null.i2a_text", b);
            BIO_free(b);
        }

        /* A long OID, which forces `i2a_ASN1_OBJECT` off its stack buffer. */
        {
            static const unsigned char long_oid[] = {
                0x06, 0x0d, 0x2a, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e
            };
            const unsigned char *p = long_oid;
            ASN1_OBJECT *o = d2i_ASN1_OBJECT(NULL, &p, sizeof(long_oid));
            BIO *b = BIO_new(BIO_s_mem());
            char txt[256];
            printf("o.long.present=%d\n", o != NULL);
            printf("o.long.txt=%d:%s\n", OBJ_obj2txt(txt, sizeof(txt), o, 0), txt);
            printf("o.long.i2a=%d\n", i2a_ASN1_OBJECT(b, o));
            drain("o.long.i2a_text", b);
            BIO_free(b);
            ASN1_OBJECT_free(o);
        }
    }

    /* ------------------------------------------------------------------ */
    /* The text writers for the string types.                             */
    /* ------------------------------------------------------------------ */
    {
        ASN1_STRING *s = ASN1_STRING_type_new(V_ASN1_OCTET_STRING);
        BIO *b;
        int i;

        ASN1_STRING_set(s, "\x00\x01\x0f\x10\x7f\x80\xff", 7);
        b = BIO_new(BIO_s_mem());
        printf("t.oct.i2a=%d\n", i2a_ASN1_STRING(b, s, 0));
        drain("t.oct.i2a_text", b);
        BIO_free(b);
        /* Empty content writes a single `0`, not nothing. */
        ASN1_STRING_set(s, "", 0);
        b = BIO_new(BIO_s_mem());
        printf("t.empty.i2a=%d\n", i2a_ASN1_STRING(b, s, 0));
        drain("t.empty.i2a_text", b);
        BIO_free(b);
        ASN1_STRING_free(s);

        /* The 35-octet line break. */
        {
            unsigned char wide[71];
            for (i = 0; i < 71; i++)
                wide[i] = (unsigned char)i;
            s = ASN1_STRING_type_new(V_ASN1_OCTET_STRING);
            ASN1_STRING_set(s, wide, 71);
            b = BIO_new(BIO_s_mem());
            printf("t.wide.i2a=%d\n", i2a_ASN1_STRING(b, s, 0));
            drain("t.wide.i2a_text", b);
            BIO_free(b);
            ASN1_STRING_free(s);
        }

        /* A negative integer prints a `-` then the magnitude, in uppercase hex. */
        {
            ASN1_INTEGER *ai = ASN1_INTEGER_new();
            ASN1_INTEGER_set(ai, -4660);
            b = BIO_new(BIO_s_mem());
            printf("t.neg.i2a=%d\n", i2a_ASN1_INTEGER(b, ai));
            drain("t.neg.i2a_text", b);
            BIO_free(b);
            ASN1_INTEGER_free(ai);

            ai = ASN1_INTEGER_new();
            b = BIO_new(BIO_s_mem());
            printf("t.zero.i2a=%d\n", i2a_ASN1_INTEGER(b, ai));
            drain("t.zero.i2a_text", b);
            /* The same BIO and the same zero-length value through the ENUMERATED
             * writer, which the authority forwards to the INTEGER one. */
            printf("t.zero.enumerated=%d\n", i2a_ASN1_ENUMERATED(b, ai));
            drain("t.zero.enum_text", b);
            BIO_free(b);
            ASN1_INTEGER_free(ai);
        }
    }

    /* ------------------------------------------------------------------ */
    /* The two context objects.                                           */
    /* ------------------------------------------------------------------ */
    {
        ASN1_PCTX *p = ASN1_PCTX_new();
        printf("pctx.present=%d\n", p != NULL);
        printf("pctx.defaults=%lu,%lu,%lu,%lu,%lu\n",
               ASN1_PCTX_get_flags(p), ASN1_PCTX_get_nm_flags(p),
               ASN1_PCTX_get_cert_flags(p), ASN1_PCTX_get_oid_flags(p),
               ASN1_PCTX_get_str_flags(p));
        ASN1_PCTX_set_flags(p, 1);
        ASN1_PCTX_set_nm_flags(p, 2);
        ASN1_PCTX_set_cert_flags(p, 4);
        ASN1_PCTX_set_oid_flags(p, 8);
        ASN1_PCTX_set_str_flags(p, 16);
        printf("pctx.set=%lu,%lu,%lu,%lu,%lu\n",
               ASN1_PCTX_get_flags(p), ASN1_PCTX_get_nm_flags(p),
               ASN1_PCTX_get_cert_flags(p), ASN1_PCTX_get_oid_flags(p),
               ASN1_PCTX_get_str_flags(p));
        ASN1_PCTX_free(p);

        {
            ASN1_SCTX *s = ASN1_SCTX_new(NULL);
            printf("sctx.present=%d\n", s != NULL);
            printf("sctx.item_null=%d\n", ASN1_SCTX_get_item(s) == NULL);
            printf("sctx.template_null=%d\n", ASN1_SCTX_get_template(s) == NULL);
            printf("sctx.flags=%lu\n", ASN1_SCTX_get_flags(s));
            printf("sctx.app_null=%d\n", ASN1_SCTX_get_app_data(s) == NULL);
            ASN1_SCTX_set_app_data(s, (void *)0x5eed);
            printf("sctx.app_set=%d\n", ASN1_SCTX_get_app_data(s) == (void *)0x5eed);
            ASN1_SCTX_free(s);
        }
    }

    /* ------------------------------------------------------------------ */
    /* The parsers, over well-formed and malformed input.                 */
    /* ------------------------------------------------------------------ */
    {
        static const unsigned char blob[] = {
            0x30, 0x10,
            0x02, 0x01, 0x02,
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
            0x04, 0x00
        };
        BIO *b = BIO_new(BIO_s_mem());

        printf("parse.ok=%d\n", ASN1_parse(b, blob, sizeof(blob), 0));
        drain("parse.ok_text", b);
        BIO_free(b);

        b = BIO_new(BIO_s_mem());
        printf("parse.dump=%d\n", ASN1_parse_dump(b, blob, sizeof(blob), 2, 0));
        drain("parse.dump_text", b);
        BIO_free(b);

        b = BIO_new(BIO_s_mem());
        printf("parse.trunc=%d\n", ASN1_parse(b, blob, 5, 0));
        drain("parse.trunc_text", b);
        printf("parse.trunc_err=%lu\n", ERR_peek_error());
        ERR_clear_error();
        BIO_free(b);

        /* A built OCTET STRING inside a SEQUENCE, which the printer decodes and
         * re-reads; and an INTEGER, whose magnitude it hex-dumps. */
        {
            static const unsigned char nested[] = {
                0x30, 0x0c,
                0x04, 0x03, 0x41, 0x42, 0x43,
                0x02, 0x02, 0x01, 0x00,
                0x0a, 0x02, 0x01, 0x00
            };
            b = BIO_new(BIO_s_mem());
            printf("parse.nested=%d\n", ASN1_parse_dump(b, nested, sizeof(nested), 0, 0));
            drain("parse.nested_text", b);
            BIO_free(b);
        }

        /* A malformed OID inside a SEQUENCE: the printer reports `BAD OBJECT`. */
        {
            static const unsigned char badobj[] = {
                0x30, 0x03, 0x06, 0x01, 0x80
            };
            b = BIO_new(BIO_s_mem());
            printf("parse.badobj=%d\n", ASN1_parse_dump(b, badobj, sizeof(badobj), 0, 0));
            drain("parse.badobj_text", b);
            BIO_free(b);
        }

        /* Indefinite length, which the printer must follow to the EOC. */
        {
            static const unsigned char indef[] = {
                0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00
            };
            b = BIO_new(BIO_s_mem());
            printf("parse.indef=%d\n", ASN1_parse_dump(b, indef, sizeof(indef), 0, 0));
            drain("parse.indef_text", b);
            BIO_free(b);
        }

        /* A BOOLEAN, whose content the printer prints as a number. */
        {
            static const unsigned char boolv[] = { 0x01, 0x01, 0xff };
            b = BIO_new(BIO_s_mem());
            printf("parse.bool=%d\n", ASN1_parse_dump(b, boolv, sizeof(boolv), 0, 0));
            drain("parse.bool_text", b);
            BIO_free(b);
        }
    }

    printf("done=1\n");
    return 0;
}
