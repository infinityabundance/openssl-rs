/*
 * openssl-rs -- Phase 10, subphases 10.2 and 10.3's differential court: RT-PKCS12.
 *
 * Compiled twice -- once against the admitted authority, once against the candidate
 * distribution shell -- and run; the two transcripts are compared line for line by
 * `forensics/tools/phase10_courts.py`. Every observation is a `key=value` line, so a missing or
 * extra line costs exactly one residual.
 *
 * What it establishes, and what it does not
 * -----------------------------------------
 * The container's identity is a DER document, not a parsed structure (docs/PHASE-10-SUBPHASES.md
 * section 3.2). This probe drives the three item groups 10.2 lands -- `PKCS12_SAFEBAG`,
 * `PKCS12_BAGS` and `PKCS12_MAC_DATA` -- and prints their **bytes**, built from fixed inputs, and
 * it drives the accessor surface, the refcount/ownership behaviour and the refusal arms with their
 * error coordinates. It does **not** print a parsed structure and call that agreement.
 *
 * Since 10.3 it also drives the four exports of that subphase whose closure is landed:
 * `PKCS12_item_pack_safebag` (a fixed `PKCS8_PRIV_KEY_INFO` packed as a `certBag`, printed as
 * DER), the two `PKCS12_decrypt_skey` spellings (a shrouded key bag with a non-PBE algorithm, so
 * the refusal and its error coordinate are the observation), and `PKCS12_add_secret` (the `add_*`
 * surface, including the stack the call builds and the bag's DER).
 *
 * The `PKCS12` container itself (`PKCS12_it`, `i2d_PKCS12`, the `d2i_PKCS12*`/`i2d_PKCS12*_bio/fp`
 * spellings) and everything in 10.3 that dereferences `PKCS7` or `X509` are **held open**: the
 * `authsafes` column is a `PKCS7` and `PKCS7_it` is Phase 12's, the four `get1_*` certificate
 * readers and the certificate/key builders need Phase 11's `X509_it`, and the MAC setup needs
 * 10.4's `PKCS12_key_gen_utf8_ex`. Those rows are printed as `pending.` with the blocker rather
 * than driven, and the two 10.2 `create_cert`/`create_crl` spellings appear there with their
 * remaining blocker after 10.3 removed the first (docs/PHASE-10-SUBPHASES.md sections 3.2, 3.5).
 *
 * Everything is borrowed or literal: the DER fixtures below are hand-written constants, the
 * strings are literals, and no pointer address is ever printed (two sides allocate differently).
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>

/* ---------------------------------------------------------------------------------------------
 * Output helpers -- every line is `key=value`.
 * --------------------------------------------------------------------------------------------- */

static void out_hex(const char *key, const unsigned char *p, long n)
{
    long i;

    if (p == NULL) {
        printf("%s=null\n", key);
        return;
    }
    printf("%s=", key);
    for (i = 0; i < n; i++)
        printf("%02x", p[i]);
    printf("\n");
}

static void out_int(const char *key, long v)
{
    printf("%s=%ld\n", key, v);
}

static void out_ptr(const char *key, const void *p)
{
    printf("%s=%s\n", key, p != NULL ? "nonnull" : "null");
}

/* The first error on the queue as `lib.reason`, then the queue is cleared. If an arm raises more
 * than one error, only the first is printed: the authority's `ERR_get_error` is LIFO, so the first
 * popped is the last raised, which is the coordinate a caller sees. */
static void out_err(const char *key)
{
    unsigned long e = ERR_get_error();

    if (e == 0) {
        printf("%s=none\n", key);
        return;
    }
    printf("%s=%d.%d\n", key, ERR_GET_LIB(e), ERR_GET_REASON(e));
    ERR_clear_error();
}

/* A whole block of the rows this subphase cannot drive, printed identically on both sides. */
static void out_pending(void)
{
    /* Held open on the `PKCS12` container and its `PKCS7` authsafes (Phase 12). */
    printf("pending.PKCS12_it=phase-12-pkcs7\n");
    printf("pending.PKCS12_new=phase-12-pkcs7\n");
    printf("pending.PKCS12_free=phase-12-pkcs7\n");
    printf("pending.d2i_PKCS12=phase-12-pkcs7\n");
    printf("pending.i2d_PKCS12=phase-12-pkcs7\n");
    printf("pending.PKCS12_AUTHSAFES_it=phase-12-pkcs7\n");
    printf("pending.d2i_PKCS12_bio=phase-12-pkcs7\n");
    printf("pending.d2i_PKCS12_fp=phase-12-pkcs7\n");
    printf("pending.i2d_PKCS12_bio=phase-12-pkcs7\n");
    printf("pending.i2d_PKCS12_fp=phase-12-pkcs7\n");
    /* Held open on `X509_it`/`X509_CRL_it` and `ossl_x509*_set0_libctx` (Phase 11). */
    printf("pending.PKCS12_SAFEBAG_get1_cert=phase-11-x509\n");
    printf("pending.PKCS12_SAFEBAG_get1_cert_ex=phase-11-x509\n");
    printf("pending.PKCS12_SAFEBAG_get1_crl=phase-11-x509\n");
    printf("pending.PKCS12_SAFEBAG_get1_crl_ex=phase-11-x509\n");
    /* 10.2's two `create_cert`/`create_crl` need this subphase's `PKCS12_item_pack_safebag`
     * **and** Phase 11's `X509_it`; 10.3 landed the first, so the blocker that remains is the
     * second, and the row is still `pending` rather than driven. */
    printf("pending.PKCS12_SAFEBAG_create_cert=phase-11-x509\n");
    printf("pending.PKCS12_SAFEBAG_create_crl=phase-11-x509\n");
    /* Held open on `PKCS8_encrypt(_ex)` (p12_p8e.c, 10.4). */
    printf("pending.PKCS12_SAFEBAG_create_pkcs8_encrypt=phase-10.4\n");
    printf("pending.PKCS12_SAFEBAG_create_pkcs8_encrypt_ex=phase-10.4\n");

    /* ----- 10.3: p12_add.c's seven `PKCS#7` container spellings ----- */
    printf("pending.PKCS12_pack_p7data=phase-12-pkcs7\n");
    printf("pending.PKCS12_unpack_p7data=phase-12-pkcs7\n");
    printf("pending.PKCS12_pack_p7encdata=phase-12-pkcs7\n");
    printf("pending.PKCS12_pack_p7encdata_ex=phase-12-pkcs7\n");
    printf("pending.PKCS12_unpack_p7encdata=phase-12-pkcs7\n");
    printf("pending.PKCS12_pack_authsafes=phase-12-pkcs7\n");
    printf("pending.PKCS12_unpack_authsafes=phase-12-pkcs7\n");
    /* ----- 10.3: p12_crt.c's ten container builders (add_secret landed) ----- */
    printf("pending.PKCS12_add_cert=phase-11-x509\n");
    printf("pending.PKCS12_add_key=phase-11-pkey2pkcs8\n");
    printf("pending.PKCS12_add_key_ex=phase-11-pkey2pkcs8\n");
    printf("pending.PKCS12_add_safe=phase-12-pkcs7\n");
    printf("pending.PKCS12_add_safe_ex=phase-12-pkcs7\n");
    printf("pending.PKCS12_add_safes=phase-12-pkcs7\n");
    printf("pending.PKCS12_add_safes_ex=phase-12-pkcs7\n");
    printf("pending.PKCS12_create=phase-12-pkcs7\n");
    printf("pending.PKCS12_create_ex=phase-12-pkcs7\n");
    printf("pending.PKCS12_create_ex2=phase-12-pkcs7\n");
    /* ----- 10.3: p12_mutl.c's MAC setup. `gen_mac`/`verify_mac`/`set_mac`/
     * `set_pbmac1_pbkdf2` need 10.4's `PKCS12_key_gen_utf8_ex`; `setup_mac` reaches the
     * `PKCS7` context through `authsafes`, and `mac_present`/`get0_mac` need the `PKCS12`
     * object itself, which `PKCS12_new`/`PKCS12_it` cannot build without `PKCS7_it`. ----- */
    printf("pending.PKCS12_mac_present=phase-12-pkcs7\n");
    printf("pending.PKCS12_get0_mac=phase-12-pkcs7\n");
    printf("pending.PKCS12_gen_mac=phase-10.4-kdf\n");
    printf("pending.PKCS12_verify_mac=phase-10.4-kdf\n");
    printf("pending.PKCS12_set_mac=phase-10.4-kdf\n");
    printf("pending.PKCS12_setup_mac=phase-12-pkcs7\n");
    printf("pending.PKCS12_set_pbmac1_pbkdf2=phase-10.4-kdf\n");
    /* ----- 10.3: p12_init.c and p12_npas.c ----- */
    printf("pending.PKCS12_init=phase-12-pkcs7\n");
    printf("pending.PKCS12_init_ex=phase-12-pkcs7\n");
    printf("pending.PKCS12_newpass=phase-12-pkcs7\n");
}

/* ---------------------------------------------------------------------------------------------
 * Fixed DER fixtures.
 *
 * All are hand-written constants, so both sides decode the same input rather than one side's
 * output. The digest octets are a walking literal, not a real digest.
 * --------------------------------------------------------------------------------------------- */

/* PKCS8_PRIV_KEY_INFO ::= SEQUENCE { version 0, rsaEncryption+NULL, OCTET STRING {00} }. */
static const unsigned char FIX_PKCS8[] = {
    0x30, 0x15,
      0x02, 0x01, 0x00,
      0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
        0x05, 0x00,
      0x04, 0x01, 0x00
};

/* X509_SIG (EncryptedPrivateKeyInfo) ::= SEQUENCE { rsaEncryption+NULL, OCTET STRING {ab cd} }.
 * The algorithm is deliberately not a PBE one: this probe never decrypts, it only carries the
 * bytes, so a well-formed but inert `AlgorithmIdentifier` keeps the fixture free of a cipher. */
static const unsigned char FIX_X509_SIG[] = {
    0x30, 0x13,
      0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
        0x05, 0x00,
      0x04, 0x02, 0xab, 0xcd
};

/* PKCS12_MAC_DATA ::= SEQUENCE { mac DigestInfo, macSalt OCTET STRING, iterations INTEGER }.
 * DigestInfo = SEQUENCE { sha256+NULL, OCTET STRING of 32 bytes of 0x11 }. */
static const unsigned char FIX_MACDATA[] = {
    0x30, 0x41,
      0x30, 0x31,
        0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
          0x05, 0x00,
        0x04, 0x20,
          0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
          0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
          0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
          0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
      0x04, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
      0x02, 0x02, 0x08, 0x00
};

/* PKCS12_BAGS ::= SEQUENCE { pkcs7-data, [0] EXPLICIT OCTET STRING {01 02 03} }. */
static const unsigned char FIX_BAGS[] = {
    0x30, 0x12,
      0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01,
      0xa0, 0x05, 0x04, 0x03, 0x01, 0x02, 0x03
};

/* A SafeBag whose type is `safeContentsBag` (1.2.840.113549.1.12.10.1.6) and whose value is an
 * empty SEQUENCE OF SafeBag, which is the one ADB arm that is neither a pointer-union member nor
 * a certificate type. */
static const unsigned char FIX_SAFES[] = {
    0x30, 0x11,
      0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x0a, 0x01, 0x06,
      0xa0, 0x02, 0x30, 0x00
};

/* ---------------------------------------------------------------------------------------------
 * Item identity and the four Unicode conversions.
 * --------------------------------------------------------------------------------------------- */

static void court_items(void)
{
    out_ptr("it.macdata", (const void *)PKCS12_MAC_DATA_it());
    out_ptr("it.bags", (const void *)PKCS12_BAGS_it());
    out_ptr("it.safebag", (const void *)PKCS12_SAFEBAG_it());
    out_ptr("it.safebags", (const void *)PKCS12_SAFEBAGS_it());
    out_int("it.safebag_stable", PKCS12_SAFEBAG_it() == PKCS12_SAFEBAG_it());
    out_int("it.macdata_stable", PKCS12_MAC_DATA_it() == PKCS12_MAC_DATA_it());
    out_int("it.bags_stable", PKCS12_BAGS_it() == PKCS12_BAGS_it());
    out_int("it.safebags_stable", PKCS12_SAFEBAGS_it() == PKCS12_SAFEBAGS_it());
}

static void court_unicode(void)
{
    unsigned char *uni = NULL;
    int unilen = 0;
    unsigned char *r;
    const unsigned char astral[] = { 'a', 0xf0, 0x9f, 0x98, 0x80, 'b', 0x00 };
    unsigned char utf16bad[3] = { 0x00, 'a', 0x00 };

    /* The naive pair over a fixed ASCII string. */
    r = OPENSSL_asc2uni("hello", -1, &uni, &unilen);
    out_ptr("uni.asc2uni", r);
    out_hex("uni.asc2uni.hex", r, unilen);
    out_int("uni.asc2uni.len", unilen);
    if (r != NULL) {
        char *back = OPENSSL_uni2asc(r, unilen);
        out_hex("uni.uni2asc.hex", (const unsigned char *)back,
                back != NULL ? (long)strlen(back) : 0);
        OPENSSL_free(back);
    }

    /* The UTF-8 pair, including an astral code point that forces a surrogate pair. */
    r = OPENSSL_utf82uni((const char *)astral, 6, &uni, &unilen);
    out_ptr("uni.utf82uni", r);
    out_hex("uni.utf82uni.hex", r, unilen);
    out_int("uni.utf82uni.len", unilen);
    if (r != NULL) {
        char *back = OPENSSL_uni2utf8(r, unilen);
        out_hex("uni.uni2utf8.hex", (const unsigned char *)back,
                back != NULL ? (long)strlen(back) : 0);
        OPENSSL_free(back);
        OPENSSL_free(r);
    }

    /* The guards: a negative ASCII length and an odd UTF-16 length both answer NULL. */
    out_ptr("uni.asc2uni.neg", OPENSSL_asc2uni("x", -2, &uni, &unilen));
    out_ptr("uni.uni2asc.odd", OPENSSL_uni2asc(utf16bad, 3));
    out_ptr("uni.uni2utf8.odd", OPENSSL_uni2utf8(utf16bad, 3));
}

/* ---------------------------------------------------------------------------------------------
 * The `PKCS12_SAFEBAG` item: DER bytes, the accessor surface and the attribute set.
 * --------------------------------------------------------------------------------------------- */

static void court_safebag(void)
{
    static const unsigned char secret_val[3] = { 0x01, 0x02, 0x03 };
    static unsigned char keyid[4] = { 0x04, 0x05, 0x06, 0x07 };
    PKCS12_SAFEBAG *bag;
    unsigned char *der = NULL, *der2 = NULL, *der3 = NULL;
    long len, len2, len3;
    char *friendly;

    /* The plain allocator, so this name is driven directly rather than only through the
     * constructors that call it. */
    bag = PKCS12_SAFEBAG_new();
    out_ptr("safebag.new", bag);
    PKCS12_SAFEBAG_free(bag);

    bag = PKCS12_SAFEBAG_create_secret(NID_pkcs7_data, V_ASN1_OCTET_STRING, secret_val, 3);
    out_ptr("safebag.secret", bag);
    if (bag == NULL)
        return;
    out_int("safebag.get_nid", PKCS12_SAFEBAG_get_nid(bag));
    out_int("safebag.get_bag_nid", PKCS12_SAFEBAG_get_bag_nid(bag));
    out_int("safebag.type_nid", OBJ_obj2nid(PKCS12_SAFEBAG_get0_type(bag)));
    out_int("safebag.bagtype_nid", OBJ_obj2nid(PKCS12_SAFEBAG_get0_bag_type(bag)));
    out_ptr("safebag.bag_obj", PKCS12_SAFEBAG_get0_bag_obj(bag));
    out_ptr("safebag.p8inf", PKCS12_SAFEBAG_get0_p8inf(bag));
    out_ptr("safebag.pkcs8", PKCS12_SAFEBAG_get0_pkcs8(bag));
    out_ptr("safebag.safes", PKCS12_SAFEBAG_get0_safes(bag));
    out_ptr("safebag.attrs_empty", PKCS12_SAFEBAG_get0_attrs(bag));

    len = i2d_PKCS12_SAFEBAG(bag, &der);
    out_hex("safebag.secret.der", der, len);

    /* The decoder reads the encoder's bytes back, and re-encoding them is the same document. */
    {
        const unsigned char *p = der;
        PKCS12_SAFEBAG *rt = d2i_PKCS12_SAFEBAG(NULL, &p, len);

        out_ptr("safebag.d2i", rt);
        if (rt != NULL) {
            out_int("safebag.d2i.get_nid", PKCS12_SAFEBAG_get_nid(rt));
            out_int("safebag.d2i.get_bag_nid", PKCS12_SAFEBAG_get_bag_nid(rt));
            len2 = i2d_PKCS12_SAFEBAG(rt, &der2);
            out_hex("safebag.d2i.der", der2, len2);
            PKCS12_SAFEBAG_free(rt);
        }
    }

    /* The attribute set: the friendlyname first, then the local key id, so the DER's SET OF
     * ordering is driven rather than assumed. */
    out_int("safebag.friendly_add", PKCS12_add_friendlyname_asc(bag, "probe", -1));
    len3 = i2d_PKCS12_SAFEBAG(bag, &der3);
    out_hex("safebag.friendly.der", der3, len3);
    OPENSSL_free(der3);

    out_int("safebag.keyid_add", PKCS12_add_localkeyid(bag, keyid, 4));
    der3 = NULL;
    len3 = i2d_PKCS12_SAFEBAG(bag, &der3);
    out_hex("safebag.attrs.der", der3, len3);

    out_int("safebag.attrs_count", X509at_get_attr_count(PKCS12_SAFEBAG_get0_attrs(bag)));
    out_ptr("safebag.attr_friendly", PKCS12_SAFEBAG_get0_attr(bag, NID_friendlyName));
    out_ptr("safebag.attr_local", PKCS12_SAFEBAG_get0_attr(bag, NID_localKeyID));
    out_ptr("safebag.get_attr_friendly", PKCS12_get_attr(bag, NID_friendlyName));
    out_ptr("safebag.get_attr_gen_friendly",
            PKCS12_get_attr_gen(PKCS12_SAFEBAG_get0_attrs(bag), NID_friendlyName));

    friendly = PKCS12_get_friendlyname(bag);
    out_hex("safebag.friendlyname", (const unsigned char *)friendly,
            friendly != NULL ? (long)strlen(friendly) : 0);
    OPENSSL_free(friendly);

    /* set0_attrs releases the old stack and adopts the new one; NULL is the observable arm. */
    PKCS12_SAFEBAG_set0_attrs(bag, NULL);
    out_ptr("safebag.attrs_after_set0", PKCS12_SAFEBAG_get0_attrs(bag));

    OPENSSL_free(der);
    OPENSSL_free(der2);
    OPENSSL_free(der3);
    PKCS12_SAFEBAG_free(bag);
}

/* The four remaining attribute writers, each on its own fresh bag so no duplicate guard fires. */
static void court_attr_writers(void)
{
    static const unsigned char secret_val[1] = { 0x2a };
    static unsigned char keyid[2] = { 0xaa, 0xbb };
    static const unsigned char bmp[4] = { 0x00, 'h', 0x00, 'i' };
    PKCS12_SAFEBAG *a, *b, *c, *d;

    a = PKCS12_SAFEBAG_create_secret(NID_pkcs7_data, V_ASN1_OCTET_STRING, secret_val, 1);
    out_int("attr.by_nid", PKCS12_add1_attr_by_NID(a, NID_localKeyID, V_ASN1_OCTET_STRING, keyid, 2));
    PKCS12_SAFEBAG_free(a);

    b = PKCS12_SAFEBAG_create_secret(NID_pkcs7_data, V_ASN1_OCTET_STRING, secret_val, 1);
    out_int("attr.by_txt", PKCS12_add1_attr_by_txt(b, "friendlyName", MBSTRING_ASC,
                                                   (const unsigned char *)"x", 1));
    PKCS12_SAFEBAG_free(b);

    c = PKCS12_SAFEBAG_create_secret(NID_pkcs7_data, V_ASN1_OCTET_STRING, secret_val, 1);
    out_int("attr.friendly_uni", PKCS12_add_friendlyname_uni(c, bmp, 4));
    PKCS12_SAFEBAG_free(c);

    c = PKCS12_SAFEBAG_create_secret(NID_pkcs7_data, V_ASN1_OCTET_STRING, secret_val, 1);
    out_int("attr.friendly_utf8", PKCS12_add_friendlyname_utf8(c, "z", -1));
    PKCS12_SAFEBAG_free(c);

    d = PKCS12_SAFEBAG_create_secret(NID_pkcs7_data, V_ASN1_OCTET_STRING, secret_val, 1);
    out_int("attr.csp", PKCS12_add_CSPName_asc(d, "csp", -1));
    PKCS12_SAFEBAG_free(d);
}

/* ---------------------------------------------------------------------------------------------
 * The key-bag and shrouded-key-bag constructors: ownership by pointer identity, and the PKCS#8
 * attribute writer.
 * --------------------------------------------------------------------------------------------- */

static void court_keybags(void)
{
    const unsigned char *p;
    PKCS8_PRIV_KEY_INFO *p8;
    X509_SIG *sig;
    PKCS12_SAFEBAG *kb, *sb;
    unsigned char *kd = NULL, *kd2 = NULL, *sd = NULL;
    long kl, kl2, sl;

    p = FIX_PKCS8;
    p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, (long)sizeof(FIX_PKCS8));
    out_ptr("p8.d2i", p8);
    if (p8 == NULL)
        return;
    kb = PKCS12_SAFEBAG_create0_p8inf(p8);
    out_ptr("keybag", kb);
    if (kb == NULL)
        return;
    out_int("keybag.get_nid", PKCS12_SAFEBAG_get_nid(kb));
    out_int("keybag.p8inf_eq", PKCS12_SAFEBAG_get0_p8inf(kb) == p8);
    out_ptr("keybag.pkcs8", PKCS12_SAFEBAG_get0_pkcs8(kb));
    kl = i2d_PKCS12_SAFEBAG(kb, &kd);
    out_hex("keybag.der", kd, kl);

    /* The key-usage attribute lands on the PKCS#8 structure and shows up in the bag's bytes. */
    out_int("keybag.keyusage_add", PKCS8_add_keyusage(p8, 0x80));
    out_ptr("keybag.keyusage_get", PKCS8_get_attr(p8, NID_key_usage));
    kl2 = i2d_PKCS12_SAFEBAG(kb, &kd2);
    out_hex("keybag.keyusage.der", kd2, kl2);

    p = FIX_X509_SIG;
    sig = d2i_X509_SIG(NULL, &p, (long)sizeof(FIX_X509_SIG));
    out_ptr("sig.d2i", sig);
    if (sig == NULL)
        return;
    sb = PKCS12_SAFEBAG_create0_pkcs8(sig);
    out_ptr("shrouded", sb);
    if (sb == NULL)
        return;
    out_int("shrouded.get_nid", PKCS12_SAFEBAG_get_nid(sb));
    out_int("shrouded.pkcs8_eq", PKCS12_SAFEBAG_get0_pkcs8(sb) == sig);
    out_ptr("shrouded.p8inf", PKCS12_SAFEBAG_get0_p8inf(sb));
    sl = i2d_PKCS12_SAFEBAG(sb, &sd);
    out_hex("shrouded.der", sd, sl);

    PKCS12_SAFEBAG_free(sb);
    PKCS12_SAFEBAG_free(kb);
    OPENSSL_free(kd);
    OPENSSL_free(kd2);
    OPENSSL_free(sd);
}

/* ---------------------------------------------------------------------------------------------
 * PKCS12_BAGS, PKCS12_MAC_DATA and the safeContentsBag arm.
 * --------------------------------------------------------------------------------------------- */

static void court_items_roundtrip(void)
{
    const unsigned char *p;
    PKCS12_BAGS *b, *bn;
    PKCS12_MAC_DATA *md, *mn;
    PKCS12_SAFEBAG *sc;
    unsigned char *out = NULL;
    long len;

    p = FIX_BAGS;
    b = d2i_PKCS12_BAGS(NULL, &p, (long)sizeof(FIX_BAGS));
    out_ptr("bags.d2i", b);
    if (b != NULL) {
        len = i2d_PKCS12_BAGS(b, &out);
        out_hex("bags.der", out, len);
        OPENSSL_free(out);
    }
    bn = PKCS12_BAGS_new();
    out_ptr("bags.new", bn);
    PKCS12_BAGS_free(bn);
    PKCS12_BAGS_free(b);

    p = FIX_MACDATA;
    md = d2i_PKCS12_MAC_DATA(NULL, &p, (long)sizeof(FIX_MACDATA));
    out_ptr("macdata.d2i", md);
    if (md != NULL) {
        out = NULL;
        len = i2d_PKCS12_MAC_DATA(md, &out);
        out_hex("macdata.der", out, len);
        OPENSSL_free(out);
    }
    mn = PKCS12_MAC_DATA_new();
    out_ptr("macdata.new", mn);
    PKCS12_MAC_DATA_free(mn);
    PKCS12_MAC_DATA_free(NULL);
    PKCS12_MAC_DATA_free(md);

    p = FIX_SAFES;
    sc = d2i_PKCS12_SAFEBAG(NULL, &p, (long)sizeof(FIX_SAFES));
    out_ptr("safes.d2i", sc);
    if (sc != NULL) {
        out_int("safes.get_nid", PKCS12_SAFEBAG_get_nid(sc));
        out_int("safes.get_bag_nid", PKCS12_SAFEBAG_get_bag_nid(sc));
        out_ptr("safes.get0_safes", PKCS12_SAFEBAG_get0_safes(sc));
        out_ptr("safes.get0_bag_type", PKCS12_SAFEBAG_get0_bag_type(sc));
        out_ptr("safes.get0_bag_obj", PKCS12_SAFEBAG_get0_bag_obj(sc));
        out = NULL;
        len = i2d_PKCS12_SAFEBAG(sc, &out);
        out_hex("safes.der", out, len);
        OPENSSL_free(out);
        PKCS12_SAFEBAG_free(sc);
    }
}

/* ---------------------------------------------------------------------------------------------
 * 10.3: the `SafeBag` packer, the shrouded-key reader and the `add_*` surface.
 * --------------------------------------------------------------------------------------------- */

static void court_add3(void)
{
    static const unsigned char secret_val[3] = { 0x01, 0x02, 0x03 };
    const unsigned char *p;
    PKCS8_PRIV_KEY_INFO *p8;
    X509_SIG *sig;
    PKCS12_SAFEBAG *packed, *shrouded, *secret;
    STACK_OF(PKCS12_SAFEBAG) *bags = NULL;
    unsigned char *der = NULL;
    long len;

    /* `PKCS12_item_pack_safebag`: pack a fixed PKCS#8 through `PKCS8_PRIV_KEY_INFO_it` as a
     * `certBag` whose value type is `x509Certificate`. The item is the caller's, so the packed
     * bytes are a function of the fixed input alone and are printed rather than parsed. */
    p = FIX_PKCS8;
    p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, (long)sizeof(FIX_PKCS8));
    out_ptr("pack.p8", p8);
    if (p8 != NULL) {
        packed = PKCS12_item_pack_safebag(p8, ASN1_ITEM_rptr(PKCS8_PRIV_KEY_INFO),
                                          NID_x509Certificate, NID_certBag);
        out_ptr("pack.bag", packed);
        if (packed != NULL) {
            out_int("pack.get_nid", PKCS12_SAFEBAG_get_nid(packed));
            out_int("pack.bag_nid", PKCS12_SAFEBAG_get_bag_nid(packed));
            out_ptr("pack.bag_obj", PKCS12_SAFEBAG_get0_bag_obj(packed));
            len = i2d_PKCS12_SAFEBAG(packed, &der);
            out_hex("pack.der", der, len);
            OPENSSL_free(der);
            der = NULL;
            PKCS12_SAFEBAG_free(packed);
        }
        PKCS8_PRIV_KEY_INFO_free(p8);
    }

    /* `PKCS12_decrypt_skey(_ex)`: a shrouded key bag whose algorithm is not a PBE one. The reader
     * borrows the bag's `X509_SIG` and refuses with the error queue, which is the observable arm
     * this slice can drive without 10.4's `PKCS8_encrypt` to build a real ciphertext. The bag
     * adopts `sig`, so it is not freed here. */
    p = FIX_X509_SIG;
    sig = d2i_X509_SIG(NULL, &p, (long)sizeof(FIX_X509_SIG));
    out_ptr("skey.sig", sig);
    if (sig != NULL) {
        shrouded = PKCS12_SAFEBAG_create0_pkcs8(sig);
        out_ptr("skey.bag", shrouded);
        if (shrouded != NULL) {
            ERR_clear_error();
            out_ptr("skey.decrypt", PKCS12_decrypt_skey(shrouded, "password", -1));
            out_err("skey.decrypt.err");
            ERR_clear_error();
            out_ptr("skey.decrypt_ex",
                    PKCS12_decrypt_skey_ex(shrouded, "password", -1, NULL, NULL));
            out_err("skey.decrypt_ex.err");
            PKCS12_SAFEBAG_free(shrouded);
        }
    }

    /* `PKCS12_add_secret`: the `add_*` surface. A NULL `*pbags` is filled by the call itself,
     * and the appended bag is the returned pointer, so the DER is printed for fixed octets. */
    secret = PKCS12_add_secret(&bags, NID_pkcs7_data, secret_val, 3);
    out_ptr("add_secret.bag", secret);
    out_int("add_secret.num", sk_PKCS12_SAFEBAG_num(bags));
    if (secret != NULL) {
        out_int("add_secret.get_nid", PKCS12_SAFEBAG_get_nid(secret));
        out_int("add_secret.bag_nid", PKCS12_SAFEBAG_get_bag_nid(secret));
        len = i2d_PKCS12_SAFEBAG(secret, &der);
        out_hex("add_secret.der", der, len);
        OPENSSL_free(der);
    }
    sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
}

/* ---------------------------------------------------------------------------------------------
 * The refusals, each with the error queue.
 * --------------------------------------------------------------------------------------------- */

static void court_refusals(void)
{
    static const unsigned char secret_val[3] = { 0x01, 0x02, 0x03 };
    PKCS12_SAFEBAG *bad, *db;

    ERR_clear_error();
    bad = PKCS12_SAFEBAG_create_secret(NID_pkcs7_data, V_ASN1_UTF8STRING, secret_val, 3);
    out_ptr("refuse.secret_bad_vtype", bad);
    out_err("refuse.secret_bad_vtype.err");

    db = PKCS12_SAFEBAG_create_secret(NID_pkcs7_data, V_ASN1_OCTET_STRING, secret_val, 3);
    out_int("refuse.dup_friendly_first", PKCS12_add_friendlyname_asc(db, "x", -1));
    ERR_clear_error();
    out_int("refuse.dup_friendly_second", PKCS12_add_friendlyname_asc(db, "y", -1));
    out_err("refuse.dup_friendly.err");
    PKCS12_SAFEBAG_free(db);
}

int main(void)
{
    court_items();
    court_unicode();
    court_safebag();
    court_attr_writers();
    court_keybags();
    court_items_roundtrip();
    court_add3();
    court_refusals();
    out_pending();
    return 0;
}
