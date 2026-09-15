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
 * implemented surface. The `ASN1_item_*` template machinery, the time accessors,
 * the `ASN1_TYPE` operations, the NDEF BIO layer and PEM are later subphases
 * (`docs/PHASE-5-SUBPHASES.md`) and are not called here.
 *
 * The `*_it()` descriptors
 * ------------------------
 * The accessors that hand out an `ASN1_ITEM` are compared **field by field**
 * rather than through an encoding. `ASN1_ITEM`'s fields are in `asn1t.h`, so a
 * caller can read every one of them, and a descriptor that answered the right
 * address with a wrong `size`, `utype` or `itype` would still link and still
 * encode — just not to the authority's bytes. The `size` field is the one that
 * looks like a detail and is not: it is `0` for the plain types and the item's
 * *default* for the BOOLEANs, which is what decides whether a value is omitted.
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
#include <openssl/asn1t.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <stdint.h>
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


/* One `ASN1_ITEM` descriptor, field by field.
 *
 * `ASN1_ITEM` is declared with its fields in `asn1t.h`, so a caller can read
 * every one. That matters because a `*_it()` accessor that answered the right
 * address with a wrong `size`, `utype` or `itype` would still link, still be
 * called, and still encode something — just not the authority's bytes. These
 * fields are the item's whole observable content, so they are compared directly
 * rather than inferred from an encoding. */
static void item_desc(const char *key, const ASN1_ITEM *it)
{
    printf("%s.present=%d\n", key, it != NULL);
    if (it == NULL)
        return;
    printf("%s.itype=%d\n", key, (int)it->itype);
    printf("%s.utype=%ld\n", key, (long)it->utype);
    printf("%s.templates=%d\n", key, it->templates != NULL);
    printf("%s.tcount=%ld\n", key, (long)it->tcount);
    printf("%s.funcs=%d\n", key, it->funcs != NULL);
    printf("%s.size=%ld\n", key, (long)it->size);
    printf("%s.sname=%s\n", key, it->sname != NULL ? it->sname : "(null)");
}

/* A bit string's stored state: length, the raw flag word, and the content. */
static void bit_state(const char *key, const ASN1_BIT_STRING *bs)
{
    int i;

    printf("%s.present=%d\n", key, bs != NULL);
    if (bs == NULL)
        return;
    printf("%s.length=%d\n", key, ASN1_STRING_length(bs));
    printf("%s.flags=%ld\n", key, (long)bs->flags);
    printf("%s.data=%s\n", key, bs->data != NULL ? "set" : "null");
    printf("%s.bytes=", key);
    for (i = 0; i < ASN1_STRING_length(bs); i++)
        printf("%02X", ASN1_STRING_get0_data(bs)[i]);
    printf("\n");
}

/* Encode a bit string under all three output conventions and report the result,
 * the consumed pointer, and the bytes. */
static void bit_encode(const char *key, const ASN1_BIT_STRING *bs)
{
    unsigned char buf[64];
    unsigned char *p = NULL;
    int len, i;

    len = i2d_ASN1_BIT_STRING(bs, NULL);
    printf("%s.len=%d\n", key, len);

    i = i2d_ASN1_BIT_STRING(bs, &p);
    printf("%s.alloc=%d\n", key, i);
    printf("%s.alloc_bytes=", key);
    if (p != NULL && i > 0) {
        int k;
        for (k = 0; k < i; k++)
            printf("%02X", p[k]);
    }
    printf("\n");
    /* `OPENSSL_free` is the release for an `i2d_*` allocation. */
    if (p != NULL)
        OPENSSL_free(p);

    memset(buf, 0xCC, sizeof(buf));
    p = buf;
    i = i2d_ASN1_BIT_STRING(bs, &p);
    printf("%s.stack=%d\n", key, i);
    printf("%s.advanced=%ld\n", key, (long)(p - buf));
    printf("%s.stack_bytes=", key);
    if (i > 0) {
        int k;
        for (k = 0; k < i; k++)
            printf("%02X", buf[k]);
    }
    printf("\n");
    printf("%s.err=%lu\n", key, ERR_peek_error());
    ERR_clear_error();
}

/* Decode a bit string and report what came out. */
static void bit_decode(const char *key, const unsigned char *der, long len)
{
    const unsigned char *p = der;
    ASN1_BIT_STRING *bs = d2i_ASN1_BIT_STRING(NULL, &p, len);

    printf("%s.present=%d\n", key, bs != NULL);
    printf("%s.adv=%ld\n", key, (long)(p - der));
    printf("%s.err=%lu\n", key, ERR_peek_error());
    ERR_clear_error();
    bit_state(key, bs);
    if (bs != NULL)
        ASN1_BIT_STRING_free(bs);
}

/* Decode `der` as a named string type, reporting the type word and the content. */
static void str_decode(const char *key, const unsigned char *der, long len,
                       int which)
{
    const unsigned char *p = der;
    ASN1_STRING *s = NULL;
    int i;

    switch (which) {
    case 0: s = d2i_ASN1_UTF8STRING(NULL, &p, len); break;
    case 1: s = d2i_ASN1_IA5STRING(NULL, &p, len); break;
    case 2: s = d2i_ASN1_PRINTABLE(NULL, &p, len); break;
    case 3: s = d2i_ASN1_TIME(NULL, &p, len); break;
    case 4: s = d2i_ASN1_UTCTIME(NULL, &p, len); break;
    case 5: s = d2i_ASN1_GENERALIZEDTIME(NULL, &p, len); break;
    case 6: s = d2i_ASN1_BMPSTRING(NULL, &p, len); break;
    case 7: s = d2i_ASN1_UNIVERSALSTRING(NULL, &p, len); break;
    case 8: s = d2i_ASN1_T61STRING(NULL, &p, len); break;
    case 9: s = d2i_ASN1_VISIBLESTRING(NULL, &p, len); break;
    case 10: s = d2i_DIRECTORYSTRING(NULL, &p, len); break;
    case 11: s = d2i_DISPLAYTEXT(NULL, &p, len); break;
    default: s = d2i_ASN1_PRINTABLESTRING(NULL, &p, len); break;
    }

    printf("%s.present=%d\n", key, s != NULL);
    printf("%s.adv=%ld\n", key, (long)(p - der));
    printf("%s.err=%lu\n", key, ERR_peek_error());
    ERR_clear_error();
    if (s == NULL)
        return;
    printf("%s.type=%d\n", key, ASN1_STRING_type(s));
    printf("%s.length=%d\n", key, ASN1_STRING_length(s));
    printf("%s.bytes=", key);
    for (i = 0; i < ASN1_STRING_length(s); i++)
        printf("%02X", ASN1_STRING_get0_data(s)[i]);
    printf("\n");
    ASN1_STRING_free(s);
}

/* The three output conventions of an `i2d_*` over a string value. */
static void str_encode(const char *key, const ASN1_STRING *s)
{
    unsigned char buf[64];
    unsigned char *p;
    int len, i;

    len = i2d_ASN1_UTF8STRING(s, NULL);
    printf("%s.null_out=%d\n", key, len);

    p = NULL;
    i = i2d_ASN1_UTF8STRING(s, &p);
    printf("%s.alloc=%d\n", key, i);
    if (p != NULL && i > 0) {
        int k;
        for (k = 0; k < i; k++)
            printf("%s.alloc_bytes.%d=%02X\n", key, k, p[k]);
    }
    if (p != NULL)
        OPENSSL_free(p);

    memset(buf, 0xCC, sizeof(buf));
    p = buf;
    i = i2d_ASN1_UTF8STRING(s, &p);
    printf("%s.stack=%d\n", key, i);
    printf("%s.advanced=%ld\n", key, (long)(p - buf));
    if (i > 0) {
        int k;
        for (k = 0; k < i; k++)
            printf("%s.stack_bytes.%d=%02X\n", key, k, buf[k]);
    }
    printf("%s.err=%lu\n", key, ERR_peek_error());
    ERR_clear_error();
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


    /* ------------------------------------------------------------------ */
    /* The item descriptors.                                              */
    /*                                                                    */
    /* Compared field by field, because these *are* the item's observable */
    /* content: a `*_it()` accessor that answered the right address with a */
    /* wrong `size` would still encode, just not to the authority's bytes. */
    /* ------------------------------------------------------------------ */
    {
        item_desc("it.octet", ASN1_OCTET_STRING_it());
        item_desc("it.integer", ASN1_INTEGER_it());
        item_desc("it.enumerated", ASN1_ENUMERATED_it());
        item_desc("it.bitstr", ASN1_BIT_STRING_it());
        item_desc("it.utf8", ASN1_UTF8STRING_it());
        item_desc("it.printable", ASN1_PRINTABLESTRING_it());
        item_desc("it.t61", ASN1_T61STRING_it());
        item_desc("it.ia5", ASN1_IA5STRING_it());
        item_desc("it.general", ASN1_GENERALSTRING_it());
        item_desc("it.utctime", ASN1_UTCTIME_it());
        item_desc("it.gentime", ASN1_GENERALIZEDTIME_it());
        item_desc("it.visible", ASN1_VISIBLESTRING_it());
        item_desc("it.universal", ASN1_UNIVERSALSTRING_it());
        item_desc("it.bmp", ASN1_BMPSTRING_it());
        item_desc("it.null", ASN1_NULL_it());
        item_desc("it.object", ASN1_OBJECT_it());
        item_desc("it.any", ASN1_ANY_it());
        item_desc("it.sequence", ASN1_SEQUENCE_it());
        item_desc("it.boolean", ASN1_BOOLEAN_it());
        item_desc("it.tboolean", ASN1_TBOOLEAN_it());
        item_desc("it.fboolean", ASN1_FBOOLEAN_it());
        item_desc("it.ndef", ASN1_OCTET_STRING_NDEF_it());
        item_desc("it.mstring.printable", ASN1_PRINTABLE_it());
        item_desc("it.mstring.display", DISPLAYTEXT_it());
        item_desc("it.mstring.directory", DIRECTORYSTRING_it());
        item_desc("it.mstring.time", ASN1_TIME_it());

        /* Two calls answer the same address, because the accessor returns a
         * pointer to a function-local static. */
        printf("it.stable=%d\n",
               ASN1_BIT_STRING_it() == ASN1_BIT_STRING_it());
    }

    /* ------------------------------------------------------------------ */
    /* ASN1_BIT_STRING: the bit operations.                               */
    /* ------------------------------------------------------------------ */
    {
        unsigned char two[] = { 0xFF, 0xFF };
        unsigned char trail[] = { 0x01, 0x00 };
        unsigned char one[] = { 0x81 };
        ASN1_BIT_STRING *bs = ASN1_BIT_STRING_new();

        bit_state("bs.fresh", bs);

        printf("bs.setbit0=%d\n", ASN1_BIT_STRING_set_bit(bs, 0, 1));
        bit_state("bs.bit0", bs);
        printf("bs.setbit7=%d\n", ASN1_BIT_STRING_set_bit(bs, 7, 1));
        bit_state("bs.bit7", bs);
        printf("bs.setbit8=%d\n", ASN1_BIT_STRING_set_bit(bs, 8, 1));
        bit_state("bs.bit8", bs);
        printf("bs.setbit9=%d\n", ASN1_BIT_STRING_set_bit(bs, 9, 1));
        bit_state("bs.bit9", bs);
        /* Clearing the top bit truncates: the trailing-zero octet goes. */
        printf("bs.clear9=%d\n", ASN1_BIT_STRING_set_bit(bs, 9, 0));
        bit_state("bs.cleared9", bs);
        printf("bs.clear8=%d\n", ASN1_BIT_STRING_set_bit(bs, 8, 0));
        bit_state("bs.cleared8", bs);
        printf("bs.clear0=%d\n", ASN1_BIT_STRING_set_bit(bs, 0, 0));
        bit_state("bs.cleared0", bs);
        printf("bs.neg=%d\n", ASN1_BIT_STRING_set_bit(bs, -1, 1));
        printf("bs.grow80=%d\n", ASN1_BIT_STRING_set_bit(bs, 80, 1));
        bit_state("bs.bit80", bs);
        ASN1_BIT_STRING_free(bs);

        /* `get_bit` past the end, on a negative index, and on a null string. */
        bs = ASN1_BIT_STRING_new();
        ASN1_BIT_STRING_set(bs, one, 1);
        printf("bs.get0=%d\n", ASN1_BIT_STRING_get_bit(bs, 0));
        printf("bs.get6=%d\n", ASN1_BIT_STRING_get_bit(bs, 6));
        printf("bs.get7=%d\n", ASN1_BIT_STRING_get_bit(bs, 7));
        printf("bs.get8=%d\n", ASN1_BIT_STRING_get_bit(bs, 8));
        printf("bs.getneg=%d\n", ASN1_BIT_STRING_get_bit(bs, -1));
        printf("bs.getnull=%d\n", ASN1_BIT_STRING_get_bit(NULL, 0));
        ASN1_BIT_STRING_free(bs);

        /* `check`: a null string, a null flag vector, and vectors shorter and
         * longer than the content. */
        bs = ASN1_BIT_STRING_new();
        ASN1_BIT_STRING_set(bs, one, 1);
        {
            static const unsigned char allow81[] = { 0x81 };
            static const unsigned char allow80[] = { 0x80 };
            static const unsigned char allow00[] = { 0x00 };
            printf("bs.check.null=%d\n", ASN1_BIT_STRING_check(NULL, NULL, 0));
            printf("bs.check.novlags=%d\n", ASN1_BIT_STRING_check(bs, NULL, 0));
            printf("bs.check.allow81=%d\n", ASN1_BIT_STRING_check(bs, allow81, 1));
            printf("bs.check.allow80=%d\n", ASN1_BIT_STRING_check(bs, allow80, 1));
            printf("bs.check.allow00=%d\n", ASN1_BIT_STRING_check(bs, allow00, 1));
            printf("bs.check.short=%d\n", ASN1_BIT_STRING_check(bs, allow80, 0));
            printf("bs.check.zero=%d\n", ASN1_BIT_STRING_check(bs, allow81, 3));
        }
        ASN1_BIT_STRING_free(bs);

        /* An empty bit string: `check` answers 1 because there is no unneeded
         * bit in nothing. */
        bs = ASN1_BIT_STRING_new();
        printf("bs.check.empty=%d\n", ASN1_BIT_STRING_check(bs, NULL, 0));
        ASN1_BIT_STRING_free(bs);

        /* The explicit unused-bit count, and the mask it applies to the last
         * octet. */
        bs = ASN1_BIT_STRING_new();
        ASN1_BIT_STRING_set(bs, two, 2);
        bit_encode("bs.derived", bs);
        bs->flags |= ASN1_STRING_FLAG_BITS_LEFT | 3;
        bit_state("bs.flagged", bs);
        bit_encode("bs.left3", bs);
        bs->flags &= ~0x07;
        bs->flags |= ASN1_STRING_FLAG_BITS_LEFT | 7;
        bit_encode("bs.left7", bs);
        ASN1_BIT_STRING_free(bs);

        /* The trailing-zero scan: the derived count comes from the last non-zero
         * octet, and the octets after it are dropped. */
        bs = ASN1_BIT_STRING_new();
        ASN1_BIT_STRING_set(bs, trail, 2);
        bit_state("bs.trailing", bs);
        bit_encode("bs.trailing", bs);
        ASN1_BIT_STRING_free(bs);

        /* A zero-length content still encodes as one count octet. */
        bs = ASN1_BIT_STRING_new();
        bit_encode("bs.empty", bs);
        ASN1_BIT_STRING_free(bs);
    }

    /* ------------------------------------------------------------------ */
    /* ASN1_BIT_STRING: the name table.                                   */
    /* ------------------------------------------------------------------ */
    {
        /* Bit 1 carries two names; `name_print` prints the first and skips the
         * repeat, while `num_asc` accepts either spelling. */
        static BIT_STRING_BITNAME tbl[] = {
            { 0, "digitalSignature", "DS" },
            { 1, "nonRepudiation", "NR" },
            { 1, "contentCommitment", "CC" },
            { 2, "keyEncipherment", "KE" },
            { -1, NULL, NULL }
        };
        unsigned char e0[] = { 0xE0 };
        ASN1_BIT_STRING *bs = ASN1_BIT_STRING_new();
        BIO *b;

        printf("asc.long=%d\n", ASN1_BIT_STRING_num_asc("digitalSignature", tbl));
        printf("asc.short=%d\n", ASN1_BIT_STRING_num_asc("DS", tbl));
        printf("asc.alias=%d\n", ASN1_BIT_STRING_num_asc("contentCommitment", tbl));
        printf("asc.nr=%d\n", ASN1_BIT_STRING_num_asc("NR", tbl));
        printf("asc.missing=%d\n", ASN1_BIT_STRING_num_asc("nope", tbl));

        ASN1_BIT_STRING_set(bs, e0, 1);
        b = BIO_new(BIO_s_mem());
        printf("asc.print=%d\n", ASN1_BIT_STRING_name_print(b, bs, tbl, 4));
        drain("asc.text", b);
        BIO_free(b);

        b = BIO_new(BIO_s_mem());
        printf("asc.print0=%d\n", ASN1_BIT_STRING_name_print(b, bs, tbl, 0));
        drain("asc.text0", b);
        BIO_free(b);

        /* A string with no named bit set still produces its indent and newline. */
        ASN1_BIT_STRING_set_bit(bs, 0, 0);
        ASN1_BIT_STRING_set_bit(bs, 1, 0);
        ASN1_BIT_STRING_set_bit(bs, 2, 0);
        b = BIO_new(BIO_s_mem());
        printf("asc.printnone=%d\n", ASN1_BIT_STRING_name_print(b, bs, tbl, 2));
        drain("asc.textnone", b);
        BIO_free(b);

        printf("asc.set1=%d\n", ASN1_BIT_STRING_set_asc(bs, "keyEncipherment", 1, tbl));
        bit_state("asc.after", bs);
        printf("asc.set0=%d\n", ASN1_BIT_STRING_set_asc(bs, "KE", 0, tbl));
        bit_state("asc.cleared", bs);
        printf("asc.setmissing=%d\n", ASN1_BIT_STRING_set_asc(bs, "nope", 1, tbl));
        printf("asc.setnull=%d\n", ASN1_BIT_STRING_set_asc(NULL, "KE", 1, tbl));
        ASN1_BIT_STRING_free(bs);
    }

    /* ------------------------------------------------------------------ */
    /* ASN1_BIT_STRING: decode and encode.                                */
    /* ------------------------------------------------------------------ */
    {
        static const unsigned char ok[] = { 0x03, 0x02, 0x00, 0x41 };
        static const unsigned char bits3[] = { 0x03, 0x03, 0x04, 0xFF, 0xFF };
        static const unsigned char empty[] = { 0x03, 0x01, 0x00 };
        static const unsigned char badcount[] = { 0x03, 0x02, 0x08, 0x41 };
        static const unsigned char eightbits[] = { 0x03, 0x01, 0x08 };
        static const unsigned char zerolen[] = { 0x03, 0x00 };
        static const unsigned char built[] = { 0x23, 0x03, 0x03, 0x02, 0x00, 0x41 };
        static const unsigned char wrongtag[] = { 0x04, 0x02, 0x00, 0x41 };

        bit_decode("bsd.ok", ok, sizeof(ok));
        bit_decode("bsd.bits3", bits3, sizeof(bits3));
        bit_decode("bsd.empty", empty, sizeof(empty));
        bit_decode("bsd.badcount", badcount, sizeof(badcount));
        bit_decode("bsd.eightbits", eightbits, sizeof(eightbits));
        bit_decode("bsd.zerolen", zerolen, sizeof(zerolen));
        bit_decode("bsd.constructed", built, sizeof(built));
        bit_decode("bsd.wrongtag", wrongtag, sizeof(wrongtag));

        /* Reuse: decoding into an existing string keeps the caller's object. */
        {
            const unsigned char *p = ok;
            ASN1_BIT_STRING *slot = ASN1_BIT_STRING_new();
            ASN1_BIT_STRING *got = d2i_ASN1_BIT_STRING(&slot, &p, sizeof(ok));
            printf("bsd.reuse.same=%d\n", got == slot);
            printf("bsd.reuse.err=%lu\n", ERR_peek_error());
            ERR_clear_error();
            bit_state("bsd.reuse", slot);
            ASN1_BIT_STRING_free(slot);
        }

        /* A failure must leave a caller-supplied string where it was. */
        {
            const unsigned char *p = badcount;
            ASN1_BIT_STRING *slot = ASN1_BIT_STRING_new();
            ASN1_BIT_STRING *got = d2i_ASN1_BIT_STRING(&slot, &p, sizeof(badcount));
            printf("bsd.keepnull=%d\n", got == NULL);
            printf("bsd.keepstate=%d\n", slot != NULL);
            printf("bsd.keep.err=%lu\n", ERR_peek_error());
            ERR_clear_error();
            ASN1_BIT_STRING_free(slot);
        }
    }

    /* ------------------------------------------------------------------ */
    /* ASN1_NULL.                                                         */
    /* ------------------------------------------------------------------ */
    {
        static const unsigned char nul[] = { 0x05, 0x00 };
        static const unsigned char nulbad[] = { 0x05, 0x01, 0x00 };
        static const unsigned char trail[] = { 0x05, 0x00, 0x02, 0x01, 0x01 };
        ASN1_NULL *nn = ASN1_NULL_new();
        ASN1_NULL *slot = NULL;
        const unsigned char *p;
        unsigned char buf[8];
        unsigned char *q;
        int i;

        printf("null.new=%ld\n", (long)(intptr_t)(void *)nn);

        p = nul;
        nn = d2i_ASN1_NULL(NULL, &p, sizeof(nul));
        printf("null.present=%d\n", nn != NULL);
        printf("null.adv=%ld\n", (long)(p - nul));
        printf("null.value=%ld\n", (long)(intptr_t)(void *)nn);
        printf("null.err=%lu\n", ERR_peek_error());
        ERR_clear_error();
        ASN1_NULL_free(nn);

        p = nul;
        printf("null.slotret=%d\n", d2i_ASN1_NULL(&slot, &p, sizeof(nul)) != NULL);
        printf("null.slot=%ld\n", (long)(intptr_t)(void *)slot);
        ASN1_NULL_free(slot);
        slot = NULL;

        p = nulbad;
        printf("null.badret=%d\n", d2i_ASN1_NULL(NULL, &p, sizeof(nulbad)) == NULL);
        printf("null.bad.err=%lu\n", ERR_peek_error());
        ERR_clear_error();

        p = trail;
        nn = d2i_ASN1_NULL(NULL, &p, sizeof(trail));
        printf("null.trail.adv=%ld\n", (long)(p - trail));
        printf("null.trail.err=%lu\n", ERR_peek_error());
        ERR_clear_error();
        ASN1_NULL_free(nn);

        nn = ASN1_NULL_new();
        printf("null.i2d.null=%d\n", i2d_ASN1_NULL(nn, NULL));
        memset(buf, 0xCC, sizeof(buf));
        q = buf;
        i = i2d_ASN1_NULL(nn, &q);
        printf("null.i2d.stack=%d\n", i);
        printf("null.i2d.advanced=%ld\n", (long)(q - buf));
        if (i > 0) {
            int k;
            for (k = 0; k < i; k++)
                printf("null.i2d.byte.%d=%02X\n", k, buf[k]);
        }
        printf("null.i2d.err=%lu\n", ERR_peek_error());
        ERR_clear_error();
        q = NULL;
        printf("null.i2d.alloc=%d\n", i2d_ASN1_NULL(nn, &q));
        if (q != NULL)
            OPENSSL_free(q);

        /* A null value is absent, not an empty NULL. */
        printf("null.i2d.absent=%d\n", i2d_ASN1_NULL(NULL, NULL));
        ASN1_NULL_free(nn);
    }

    /* ------------------------------------------------------------------ */
    /* d2i_ASN1_UINTEGER: the reader that ignores the sign bit.           */
    /* ------------------------------------------------------------------ */
    {
        static const unsigned char msb[] = { 0x02, 0x01, 0x80 };
        static const unsigned char padded[] = { 0x02, 0x02, 0x00, 0x80 };
        static const unsigned char zero[] = { 0x02, 0x01, 0x00 };
        static const unsigned char empty[] = { 0x02, 0x00 };
        static const unsigned char seq3[] = { 0x02, 0x03, 0x00, 0x00, 0x01 };
        static const unsigned char wrong[] = { 0x03, 0x02, 0x00, 0x41 };
        const unsigned char *p;
        ASN1_INTEGER *ai;
        int i;

        {
            static const unsigned char *cases[] = { msb, padded, zero, empty,
                                                    seq3, wrong };
            static const long lens[] = { (long)sizeof(msb), (long)sizeof(padded),
                                         (long)sizeof(zero), (long)sizeof(empty),
                                         (long)sizeof(seq3), (long)sizeof(wrong) };
            static const char *keys[] = { "uint.msb", "uint.padded", "uint.zero",
                                          "uint.empty", "uint.seq3", "uint.wrong" };
            for (i = 0; i < 6; i++) {
                p = cases[i];
                ai = d2i_ASN1_UINTEGER(NULL, &p, lens[i]);
                printf("%s.present=%d\n", keys[i], ai != NULL);
                printf("%s.adv=%ld\n", keys[i], (long)(p - cases[i]));
                printf("%s.err=%lu\n", keys[i], ERR_peek_error());
                ERR_clear_error();
                if (ai != NULL) {
                    int k;
                    printf("%s.type=%d\n", keys[i], ASN1_STRING_type(ai));
                    printf("%s.length=%d\n", keys[i], ASN1_STRING_length(ai));
                    printf("%s.bytes=", keys[i]);
                    for (k = 0; k < ASN1_STRING_length(ai); k++)
                        printf("%02X", ASN1_STRING_get0_data(ai)[k]);
                    printf("\n");
                    printf("%s.get=%ld\n", keys[i], ASN1_INTEGER_get(ai));
                    ASN1_INTEGER_free(ai);
                }
            }
        }
    }

    /* ------------------------------------------------------------------ */
    /* The string wrapper family: tags, classes and the per-type lengths. */
    /* ------------------------------------------------------------------ */
    {
        static const unsigned char utf8[] = { 0x0C, 0x03, 0x41, 0x42, 0x43 };
        static const unsigned char utf8_mono[] = { 0x0C, 0x01, 0x41 };
        static const unsigned char printab[] = { 0x13, 0x03, 0x41, 0x42, 0x43 };
        static const unsigned char built_utf8[] = { 0x2C, 0x03, 0x0C, 0x01, 0x41 };
        static const unsigned char indef_utf8[] = { 0x2C, 0x80, 0x0C, 0x01, 0x41,
                                                    0x00, 0x00 };
        static const unsigned char int_tag[] = { 0x02, 0x01, 0x01 };
        static const unsigned char ctx_tag[] = { 0x80, 0x01, 0x41 };
        static const unsigned char utc13[] = { 0x17, 0x0D, '2', '5', '0', '1',
                                               '0', '1', '0', '0', '0', '0',
                                               '0', '0', 'Z' };
        static const unsigned char utc12[] = { 0x17, 0x0C, '2', '5', '0', '1',
                                               '0', '1', '0', '0', '0', '0',
                                               '0', '0' };
        static const unsigned char gen15[] = { 0x18, 0x0F, '2', '0', '2', '5',
                                               '0', '1', '0', '1', '0', '0',
                                               '0', '0', '0', '0', 'Z' };
        static const unsigned char gen14[] = { 0x18, 0x0E, '2', '0', '2', '5',
                                               '0', '1', '0', '1', '0', '0',
                                               '0', '0', '0', '0' };
        static const unsigned char bmp_odd[] = { 0x1E, 0x03, 0x41, 0x42, 0x43 };
        static const unsigned char bmp_ok[] = { 0x1E, 0x02, 0x00, 0x41 };
        static const unsigned char uni_odd[] = { 0x1C, 0x03, 0x00, 0x00, 0x41 };
        static const unsigned char uni_ok[] = { 0x1C, 0x04, 0x00, 0x00, 0x00, 0x41 };
        static const unsigned char t61[] = { 0x14, 0x02, 0x41, 0x42 };
        static const unsigned char vis[] = { 0x1A, 0x02, 0x41, 0x42 };
        static const unsigned char octc[] = { 0x04, 0x02, 0x41, 0x42 };
        static const unsigned char obj[] = { 0x06, 0x03, 0x55, 0x04, 0x03 };

        str_decode("str.utf8", utf8, sizeof(utf8), 0);
        str_decode("str.utf8mono", utf8_mono, sizeof(utf8_mono), 0);
        str_decode("str.utf8.wrongtag", printab, sizeof(printab), 0);
        str_decode("str.utf8.constructed", built_utf8, sizeof(built_utf8), 0);
        str_decode("str.utf8.indef", indef_utf8, sizeof(indef_utf8), 0);
        str_decode("str.utf8.object", obj, sizeof(obj), 0);
        str_decode("str.ia5", utf8, sizeof(utf8), 1);
        str_decode("str.ia5.ok", vis, sizeof(vis), 1);

        /* The multi-string types take the type from the encoding. */
        str_decode("str.printable", printab, sizeof(printab), 2);
        str_decode("str.printable.utf8", utf8, sizeof(utf8), 2);
        str_decode("str.printable.int", int_tag, sizeof(int_tag), 2);
        str_decode("str.printable.ctx", ctx_tag, sizeof(ctx_tag), 2);
        str_decode("str.printable.octet", octc, sizeof(octc), 2);
        str_decode("str.directory", vis, sizeof(vis), 10);
        str_decode("str.directory.bmp", bmp_ok, sizeof(bmp_ok), 10);
        str_decode("str.directory.int", int_tag, sizeof(int_tag), 10);
        str_decode("str.display", t61, sizeof(t61), 11);
        str_decode("str.display.vis", vis, sizeof(vis), 11);
        str_decode("str.display.int", int_tag, sizeof(int_tag), 11);

        /* `ASN1_TIME` is a multi-string over the two time types. */
        str_decode("str.time.utc", utc13, sizeof(utc13), 3);
        str_decode("str.time.general", gen15, sizeof(gen15), 3);
        str_decode("str.time.int", int_tag, sizeof(int_tag), 3);
        str_decode("str.time.ctx", ctx_tag, sizeof(ctx_tag), 3);
        str_decode("str.time.short", utc12, sizeof(utc12), 3);

        str_decode("str.utc.ok", utc13, sizeof(utc13), 4);
        str_decode("str.utc.short", utc12, sizeof(utc12), 4);
        str_decode("str.gen.ok", gen15, sizeof(gen15), 5);
        str_decode("str.gen.short", gen14, sizeof(gen14), 5);

        str_decode("str.bmp.odd", bmp_odd, sizeof(bmp_odd), 6);
        str_decode("str.bmp.ok", bmp_ok, sizeof(bmp_ok), 6);
        str_decode("str.uni.odd", uni_odd, sizeof(uni_odd), 7);
        str_decode("str.uni.ok", uni_ok, sizeof(uni_ok), 7);

        str_decode("str.t61", t61, sizeof(t61), 8);
        str_decode("str.visible", vis, sizeof(vis), 9);
        str_decode("str.printabletag", printab, sizeof(printab), 12);
    }

    /* ------------------------------------------------------------------ */
    /* The zero and negative length boundary, which the item layer checks */
    /* before any header is read.                                         */
    /* ------------------------------------------------------------------ */
    {
        static const unsigned char oct[] = { 0x04, 0x02, 0x41, 0x42 };
        const unsigned char *p = oct;

        printf("len.zero.oct=%d\n", d2i_ASN1_OCTET_STRING(NULL, &p, 0) == NULL);
        printf("len.zero.oct.err=%lu\n", ERR_peek_error());
        ERR_clear_error();
        p = oct;
        printf("len.neg.oct=%d\n", d2i_ASN1_OCTET_STRING(NULL, &p, -1) == NULL);
        printf("len.neg.oct.err=%lu\n", ERR_peek_error());
        ERR_clear_error();
        p = oct;
        printf("len.zero.int=%d\n", d2i_ASN1_INTEGER(NULL, &p, 0) == NULL);
        printf("len.zero.int.err=%lu\n", ERR_peek_error());
        ERR_clear_error();
        p = oct;
        printf("len.zero.utf8=%d\n", d2i_ASN1_UTF8STRING(NULL, &p, 0) == NULL);
        printf("len.zero.utf8.err=%lu\n", ERR_peek_error());
        ERR_clear_error();
        p = oct;
        printf("len.zero.null=%d\n", d2i_ASN1_NULL(NULL, &p, 0) == NULL);
        printf("len.zero.null.err=%lu\n", ERR_peek_error());
        ERR_clear_error();
    }

    /* ------------------------------------------------------------------ */
    /* The encode conventions over the types that gained an `i2d`.        */
    /* ------------------------------------------------------------------ */
    {
        static const unsigned char utf8[] = { 0x0C, 0x03, 0x41, 0x42, 0x43 };
        static const unsigned char oct[] = { 0x04, 0x02, 0x41, 0x42 };
        static const unsigned char intv[] = { 0x02, 0x01, 0x7F };
        const unsigned char *p;
        ASN1_STRING *s;
        unsigned char buf[16];
        unsigned char *q;
        int i;

        p = utf8;
        s = d2i_ASN1_UTF8STRING(NULL, &p, sizeof(utf8));
        str_encode("enc.utf8", s);
        ASN1_STRING_free(s);

        /* A null value is omitted rather than encoded as empty. */
        printf("enc.null.utf8=%d\n", i2d_ASN1_UTF8STRING(NULL, NULL));

        p = oct;
        s = d2i_ASN1_OCTET_STRING(NULL, &p, sizeof(oct));
        printf("enc.oct.len=%d\n", i2d_ASN1_OCTET_STRING(s, NULL));
        memset(buf, 0xCC, sizeof(buf));
        q = buf;
        i = i2d_ASN1_OCTET_STRING(s, &q);
        printf("enc.oct.stack=%d\n", i);
        printf("enc.oct.advanced=%ld\n", (long)(q - buf));
        if (i > 0) {
            int k;
            for (k = 0; k < i; k++)
                printf("enc.oct.byte.%d=%02X\n", k, buf[k]);
        }
        ASN1_STRING_free(s);

        p = intv;
        s = d2i_ASN1_INTEGER(NULL, &p, sizeof(intv));
        printf("enc.int.len=%d\n", i2d_ASN1_INTEGER(s, NULL));
        memset(buf, 0xCC, sizeof(buf));
        q = buf;
        i = i2d_ASN1_INTEGER(s, &q);
        printf("enc.int.stack=%d\n", i);
        if (i > 0) {
            int k;
            for (k = 0; k < i; k++)
                printf("enc.int.byte.%d=%02X\n", k, buf[k]);
        }
        ASN1_STRING_free(s);

        /* An OBJECT with no content is omitted; one with content encodes. */
        p = NULL;
        {
            ASN1_OBJECT *o = OBJ_nid2obj(NID_commonName);
            printf("enc.obj.len=%d\n", i2d_ASN1_OBJECT(o, NULL));
            memset(buf, 0xCC, sizeof(buf));
            q = buf;
            i = i2d_ASN1_OBJECT(o, &q);
            printf("enc.obj.stack=%d\n", i);
            if (i > 0) {
                int k;
                for (k = 0; k < i; k++)
                    printf("enc.obj.byte.%d=%02X\n", k, buf[k]);
            }
        }
    }

    printf("done=1\n");
    return 0;
}
