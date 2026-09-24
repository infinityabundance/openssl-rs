/*
 * RT-ECX -- Phase 8.8's X25519/X448/Ed25519/Ed448 method court.
 *
 * `docs/DECISIONS.md` D372 lands `crypto/ec/ecx_meth.c` and the chain it needs
 * (`ecx_key.c`, `ecx_backend.c`, the two curve units, the four `ossl_evp_pkey_get1_*` accessors
 * of `crypto/evp/p_lib.c`), appends its four rows to **both** `standard_methods[]` tables in
 * `src/evp/pkey_asn1.rs` and `src/evp/pkey_ctx.rs`, and retires
 * `docs/SECURITY_DIVERGENCE_POLICY.md`'s `D-PKEY-AMETH-3`. This probe is what observes the
 * result. It is compiled twice -- once against the admitted authority, once against the
 * candidate distribution shell -- and the two `key=value` transcripts are diffed line by line.
 *
 * Every observation is a **return code, a `pkey_id`, a flag word, a bit count, a length, a
 * string the library owns, or the drained `ERR` coordinate**. No method address is printed, no
 * private key is embedded, and no value derived from a random number is printed. The only
 * public keys the probe embeds are RFC 7748 §6.1/§6.2's and RFC 8032 §7.1/§7.4's published
 * values, which are public keys and not secrets.
 *
 * ## What this court observes, arm by arm
 *
 *   1. `EVP_PKEY_asn1_find` over the four ECX NIDs, with `EVP_PKEY_asn1_get0_info`'s five
 *      fields for each -- the `pkey_id`, the `pkey_base_id`, the flags word, the PEM name and
 *      the info string. Before D372 the first two arms answered NULL on the candidate.
 *   2. `EVP_PKEY_asn1_find_str` over the four PEM spellings and their case folds, plus a prefix
 *      and an absent name. Before D372 `"X25519"` answered NULL here.
 *   3. `EVP_PKEY_type` over the four ids, plus `NID_undef`, `EVP_PKEY_NONE` and
 *      `EVP_PKEY_KEYMGMT`. Before D372 the four answered `NID_undef`.
 *   4. `EVP_PKEY_asn1_get_count` and a walk of the whole index space with
 *      `EVP_PKEY_asn1_get0`, printing each row's `pkey_id`. Before D372 the count was 11 and
 *      index 10 was SM2; both sides now answer the authority's fifteen rows in the authority's
 *      order, which is what makes the walk an arm rather than a residual.
 *   5. `EVP_PKEY_meth_find` over the four ids with `EVP_PKEY_meth_get0_info`'s two fields, the
 *      same walk over `EVP_PKEY_meth_get0`, and `EVP_PKEY_meth_get_count`. Before D372 the four
 *      `find` arms answered NULL and the count was 6.
 *   6. **The method columns, through `d2i_PUBKEY`.** Four fixed `SubjectPublicKeyInfo`
 *      structures -- one per type, carrying the RFC public values above -- are decoded, and the
 *      resulting `EVP_PKEY` is asked for `EVP_PKEY_get_id`, `_get_base_id`, `_get_bits`,
 *      `_get_size`, `_get_security_bits` and `EVP_PKEY_get_default_digest_nid`, and then
 *      re-encoded with `i2d_PUBKEY` and compared byte for byte with the input. That arm is the
 *      one that reaches `ecx_pub_decode`, `ecx_pub_encode`, `ecx_bits`, `ecx_size`,
 *      `ecx_security_bits`, `ecd_ctrl` and `ecx_ctrl` -- the seven `EVP_PKEY_ASN1_METHOD`
 *      columns whose values differ per type.
 *
 * ## What this court deliberately does not observe, and why
 *
 * * **The eight `ossl_d2i_*_PUBKEY`/`ossl_i2d_*_PUBKEY` internals of `crypto/x509/x_pubkey.c`
 *   are reached only indirectly.** They are declared in `include/crypto/x509.h`, are not in
 *   `libcrypto.so.3`'s dynamic symbol table, and a probe that named one would fail to link
 *   against **both** sides. They are exercised through `d2i_PUBKEY`/`i2d_PUBKEY`, which is the
 *   path they are on: `d2i_PUBKEY` reaches `ecx_pub_decode`, whose body is the same
 *   `ossl_ecx_key_op` the four `d2i` twins call, and `i2d_PUBKEY` is the function each of the
 *   four `i2d` twins delegates to.
 * * **The private-key arms are not here.** `ecx_priv_encode`/`ecx_priv_decode_ex` and the
 *   `ossl_ecx_key_op(..., KEY_OP_PRIVATE/KEYGEN, ...)` arms would need a PKCS#8 private key or
 *   a keygen, and this court's subject is the public method-table observables. Their evidence is
 *   `src/ec/ecx_backend.rs`'s unit test, which drives `ossl_ecx_key_op` and
 *   `ossl_ecx_compute_key` over RFC 7748 §6.1's **published** key pair and asserts the shared
 *   secret, and `src/ec/ecx_meth.rs`'s two table tests.
 * * **No context-building arm.** `EVP_PKEY_CTX_new_id`'s legacy `pmeth` arm of `int_ctx_new` is
 *   absent in the crate and is not this landing's subject (D355 records it), so an arm that
 *   built a context from one of these four ids would carry a residual about that arm rather
 *   than about the two tables this landing moves. The registry answer is observed directly in
 *   arm 5 instead.
 * * **The `#ifdef S390X_EC_ASM` hardware arms are not compiled on this profile** and raise
 *   nothing a portable run can reach; they are named in `src/ec/ecx_meth.rs`'s module doc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE

/* The `EVP_PKEY_asn1_*` family is `OSSL_DEPRECATEDIN_3_6`. The deprecation is the authority's
 * own statement about application code, not about a court that must exercise the entry points
 * the registry declares; suppressing it changes no symbol this probe links. */
#define OPENSSL_SUPPRESS_DEPRECATED

#include <openssl/asn1.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* The four ECX ids, symbolically, so the probe reads them from the same `obj_mac.h` on both
 * sides. */
static const int IDS[] = {
    NID_X25519,  /* EVP_PKEY_X25519   1034 */
    NID_X448,    /* EVP_PKEY_X448     1035 */
    NID_ED25519, /* EVP_PKEY_ED25519  1087 */
    NID_ED448    /* EVP_PKEY_ED448    1088 */
};
#define NIDS ((int)(sizeof(IDS) / sizeof(IDS[0])))

/* ------------------------------------------------------------------ the error queue */

/* Drain the queue, printing each record's packed code and its coordinate. The coordinate is
 * `ERR_get_error_all`'s file/line/func, which `gen_err_raise_sites.py` derives and which a court
 * that compared only the return value could not see. Nothing here is a secret. */
static void drain(const char *arm)
{
    int n = 0;

    for (;;) {
        const char *file = NULL;
        const char *func = NULL;
        int line = 0;
        unsigned long e = ERR_get_error_all(&file, &line, &func, NULL, NULL);

        if (e == 0)
            break;
        printf("ecx.%s.err.%d=%lu:%s:%d:%s\n", arm, n, e,
            file != NULL ? file : "(null)", line,
            func != NULL ? func : "(null)");
        n++;
    }
    printf("ecx.%s.err.count=%d\n", arm, n);
}

/* `EVP_PKEY_asn1_get0_info`'s five fields for one method. The two strings are the library's own
 * literals, not anything a caller supplied. */
static void info_of(const char *tag, const EVP_PKEY_ASN1_METHOD *m)
{
    int pid = -100000;
    int base = -100000;
    int flags = -100000;
    const char *info = NULL;
    const char *pem = NULL;
    int ok = EVP_PKEY_asn1_get0_info(&pid, &base, &flags, &info, &pem, m);

    printf("ecx.%s.info_ok=%d\n", tag, ok);
    printf("ecx.%s.pkey_id=%d\n", tag, pid);
    printf("ecx.%s.base_id=%d\n", tag, base);
    printf("ecx.%s.flags=%d\n", tag, flags);
    printf("ecx.%s.pem=%s\n", tag, pem != NULL ? pem : "(null)");
    printf("ecx.%s.info=%s\n", tag, info != NULL ? info : "(null)");
}

/* ------------------------------------------------------------------ arm 1: asn1_find */

static void find_arms(void)
{
    char tag[48];
    int i;

    for (i = 0; i < NIDS; i++) {
        int id = IDS[i];
        const EVP_PKEY_ASN1_METHOD *m = EVP_PKEY_asn1_find(NULL, id);

        printf("ecx.find.%d.notnull=%d\n", id, m != NULL);
        if (m != NULL) {
            snprintf(tag, sizeof(tag), "find.%d", id);
            info_of(tag, m);
        }
    }
    printf("ecx.find.none_is_null=%d\n", EVP_PKEY_asn1_find(NULL, 0) == NULL);
}

/* ------------------------------------------------------------------ arm 2: asn1_find_str */

static void find_str_arms(void)
{
    static const struct {
        const char *label;
        const char *s;
        int len;
    } q[] = {
        { "x25519", "X25519", -1 },
        { "x25519_lower", "x25519", -1 },
        { "x25519_explicit", "X25519", 6 },
        { "x25519_prefix", "X2551", 5 },
        { "x448", "X448", -1 },
        { "ed25519", "ED25519", -1 },
        { "ed25519_lower", "ed25519", -1 },
        { "ed448", "ED448", -1 },
        { "absent", "X2551Z", -1 }
    };
    char tag[48];
    int i;

    for (i = 0; i < (int)(sizeof(q) / sizeof(q[0])); i++) {
        const EVP_PKEY_ASN1_METHOD *m = EVP_PKEY_asn1_find_str(NULL, q[i].s, q[i].len);

        printf("ecx.find_str.%s.notnull=%d\n", q[i].label, m != NULL);
        if (m != NULL) {
            snprintf(tag, sizeof(tag), "find_str.%s", q[i].label);
            info_of(tag, m);
        }
    }
}

/* ------------------------------------------------------------------ arm 3: EVP_PKEY_type */

static void type_arms(void)
{
    int i;

    for (i = 0; i < NIDS; i++)
        printf("ecx.type.%d=%d\n", IDS[i], EVP_PKEY_type(IDS[i]));

    printf("ecx.type.undef=%d\n", EVP_PKEY_type(NID_undef));
    printf("ecx.type.none=%d\n", EVP_PKEY_type(EVP_PKEY_NONE));
    printf("ecx.type.keymgmt=%d\n", EVP_PKEY_type(EVP_PKEY_KEYMGMT));

    /* `EVP_PKEY_type` is `EVP_PKEY_asn1_find`'s answer unaliased. The four ECX rows carry
     * `pkey_base_id == pkey_id`, so the two must agree for each -- a boolean. */
    for (i = 0; i < NIDS; i++) {
        const EVP_PKEY_ASN1_METHOD *m = EVP_PKEY_asn1_find(NULL, IDS[i]);
        int pid = -100000;

        if (m != NULL)
            EVP_PKEY_asn1_get0_info(&pid, NULL, NULL, NULL, NULL, m);
        printf("ecx.type.find_agrees.%d=%d\n", IDS[i], pid == EVP_PKEY_type(IDS[i]));
    }
}

/* ------------------------------------------------------------------ arm 4: the ameth table */

static void ameth_table_arms(void)
{
    int i;
    int count = EVP_PKEY_asn1_get_count();

    printf("ecx.ameth.count=%d\n", count);
    printf("ecx.ameth.get0.negative_is_null=%d\n", EVP_PKEY_asn1_get0(-1) == NULL);

    for (i = 0; i < count; i++) {
        const EVP_PKEY_ASN1_METHOD *m = EVP_PKEY_asn1_get0(i);
        int pid = -100000;
        int ok = m != NULL && EVP_PKEY_asn1_get0_info(&pid, NULL, NULL, NULL, NULL, m) == 1;

        printf("ecx.ameth.get0.%d=%d\n", i, ok ? pid : -1);
    }

    /* Each of the four `_find` answers is one of the rows the walk just printed -- a boolean,
     * which is what the two sides must agree on now that the table is whole. */
    for (i = 0; i < NIDS; i++) {
        const EVP_PKEY_ASN1_METHOD *m = EVP_PKEY_asn1_find(NULL, IDS[i]);
        int j, found = 0;

        for (j = 0; j < count; j++)
            if (m != NULL && EVP_PKEY_asn1_get0(j) == m)
                found = 1;
        printf("ecx.ameth.index_of.%d=%d\n", IDS[i], found);
    }
}

/* ------------------------------------------------------------------ arm 5: the pmeth table */

static void pmeth_arms(void)
{
    int i;
    int count = EVP_PKEY_meth_get_count();

    printf("ecx.pmeth.count=%d\n", count);

    for (i = 0; i < NIDS; i++) {
        const EVP_PKEY_METHOD *m = EVP_PKEY_meth_find(IDS[i]);
        int pid = -100000;
        int flags = -100000;

        printf("ecx.pmeth.find.%d.notnull=%d\n", IDS[i], m != NULL);
        if (m != NULL) {
            EVP_PKEY_meth_get0_info(&pid, &flags, m);
            printf("ecx.pmeth.find.%d.pkey_id=%d\n", IDS[i], pid);
            printf("ecx.pmeth.find.%d.flags=%d\n", IDS[i], flags);
        }
    }

    for (i = 0; i < count; i++) {
        const EVP_PKEY_METHOD *m = EVP_PKEY_meth_get0((size_t)i);
        int pid = -100000;

        printf("ecx.pmeth.get0.%d.notnull=%d\n", i, m != NULL);
        if (m != NULL) {
            EVP_PKEY_meth_get0_info(&pid, NULL, m);
            printf("ecx.pmeth.get0.%d.pkey_id=%d\n", i, pid);
        }
    }
}

/* ------------------------------------------------------------------ arm 6: d2i/i2d PUBKEY */

/* Write one `SubjectPublicKeyInfo`: `SEQUENCE { SEQUENCE { OID }, BIT STRING }`. The four OIDs
 * and public values below are the RFC's own; every length here is below 128, so a single length
 * octet is the correct encoding and the function asserts the total fits `cap`. */
static int build_spki(const unsigned char *oid, size_t oidlen,
    const unsigned char *raw, size_t rawlen, unsigned char *out, size_t cap)
{
    size_t algid = 2 + oidlen;          /* SEQUENCE { OID } */
    size_t bitstr = 3 + rawlen;         /* tag, length, unused-bits octet, value */
    size_t body = algid + bitstr;
    size_t total = 2 + body;
    size_t at = 0;

    if (total > cap || body > 127)
        return 0;
    out[at++] = 0x30;
    out[at++] = (unsigned char)body;
    out[at++] = 0x30;
    out[at++] = (unsigned char)oidlen;
    memcpy(out + at, oid, oidlen);
    at += oidlen;
    out[at++] = 0x03;
    out[at++] = (unsigned char)(1 + rawlen);
    out[at++] = 0x00;
    memcpy(out + at, raw, rawlen);
    at += rawlen;
    return (int)at;
}

static void pubkey_arm(const char *label, const unsigned char *oid, size_t oidlen,
    const unsigned char *raw, size_t rawlen, int want_id)
{
    unsigned char der[160];
    const unsigned char *p;
    EVP_PKEY *pk;
    int len = build_spki(oid, oidlen, raw, rawlen, der, sizeof(der));

    printf("ecx.spki.%s.built=%d\n", label, len);
    if (len <= 0)
        return;
    p = der;
    pk = d2i_PUBKEY(NULL, &p, len);
    printf("ecx.d2i.%s.notnull=%d\n", label, pk != NULL);
    if (pk == NULL) {
        drain(label);
        return;
    }

    printf("ecx.d2i.%s.id=%d\n", label, EVP_PKEY_get_id(pk));
    printf("ecx.d2i.%s.id_is_want=%d\n", label, EVP_PKEY_get_id(pk) == want_id);
    printf("ecx.d2i.%s.base_id=%d\n", label, EVP_PKEY_get_base_id(pk));
    printf("ecx.d2i.%s.bits=%d\n", label, EVP_PKEY_get_bits(pk));
    printf("ecx.d2i.%s.size=%d\n", label, EVP_PKEY_get_size(pk));
    printf("ecx.d2i.%s.security_bits=%d\n", label, EVP_PKEY_get_security_bits(pk));
    printf("ecx.d2i.%s.cursor=%d\n", label, (int)(p - der) == len);

    {
        int dnid = -1;
        int rv = EVP_PKEY_get_default_digest_nid(pk, &dnid);

        printf("ecx.d2i.%s.default_md_rv=%d\n", label, rv);
        printf("ecx.d2i.%s.default_md_nid=%d\n", label, dnid);
    }

    {
        unsigned char *out = NULL;
        int n = i2d_PUBKEY(pk, &out);

        printf("ecx.i2d.%s.len=%d\n", label, n);
        printf("ecx.i2d.%s.len_matches=%d\n", label, n == len);
        printf("ecx.i2d.%s.roundtrip=%d\n", label,
            n == len && out != NULL && memcmp(out, der, (size_t)len) == 0);
        OPENSSL_free(out);
    }

    EVP_PKEY_free(pk);
    drain(label);
}

/* `1.3.101.110` .. `1.3.101.113`, and the RFC public values. */
static const unsigned char OID_X25519[] = { 0x2b, 0x65, 0x6e };
static const unsigned char OID_X448[] = { 0x2b, 0x65, 0x6f };
static const unsigned char OID_ED25519[] = { 0x2b, 0x65, 0x70 };
static const unsigned char OID_ED448[] = { 0x2b, 0x65, 0x71 };

/* RFC 7748 §6.1 Alice's public key. */
static const unsigned char PK_X25519[] = {
    0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7,
    0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b,
    0x4e, 0x6a
};
/* RFC 8032 §7.1 TEST 1's public key. */
static const unsigned char PK_ED25519[] = {
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
    0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
    0x51, 0x1a
};
/* RFC 7748 §6.2 Alice's public key. */
static const unsigned char PK_X448[] = {
    0x9b, 0x08, 0xf7, 0xcc, 0x31, 0xb7, 0xe3, 0xe6, 0x7d, 0x22, 0xd5, 0xae, 0xa1, 0x21, 0x07,
    0x4a, 0x27, 0x3b, 0xd2, 0xb8, 0x3d, 0xe0, 0x9c, 0x63, 0xfa, 0xa7, 0x3d, 0x2c, 0x22, 0xc5,
    0xd9, 0xbb, 0xc8, 0x36, 0x64, 0x72, 0x41, 0xd9, 0x53, 0xd4, 0x0c, 0x5b, 0x12, 0xda, 0x88,
    0x12, 0x0d, 0x53, 0x17, 0x7f, 0x80, 0xe5, 0x32, 0xc4, 0x1f, 0xa0
};
/* RFC 8032 §7.4 Sign-Message vector 1's public key. */
static const unsigned char PK_ED448[] = {
    0x5f, 0xd7, 0x44, 0x9b, 0x59, 0xb4, 0x61, 0xfd, 0x2c, 0xe7, 0x87, 0xec, 0x61, 0x6a, 0xd4,
    0x6a, 0x1d, 0xa1, 0x34, 0x24, 0x85, 0xa7, 0x0e, 0x1f, 0x8a, 0x0e, 0xa7, 0x5d, 0x80, 0xe9,
    0x67, 0x78, 0xed, 0xf1, 0x24, 0x76, 0x9b, 0x46, 0xc7, 0x06, 0x1b, 0xd6, 0x78, 0x3d, 0xf1,
    0xe5, 0x0f, 0x6c, 0xd1, 0xfa, 0x1a, 0xbe, 0xaf, 0xe8, 0x25, 0x61, 0x80
};

static void pubkey_arms(void)
{
    pubkey_arm("x25519", OID_X25519, sizeof(OID_X25519), PK_X25519, sizeof(PK_X25519),
        NID_X25519);
    pubkey_arm("x448", OID_X448, sizeof(OID_X448), PK_X448, sizeof(PK_X448), NID_X448);
    pubkey_arm("ed25519", OID_ED25519, sizeof(OID_ED25519), PK_ED25519, sizeof(PK_ED25519),
        NID_ED25519);
    pubkey_arm("ed448", OID_ED448, sizeof(OID_ED448), PK_ED448, sizeof(PK_ED448), NID_ED448);
}

/* ------------------------------------------------------------------ arm 7: refusals */

static void refusal_arms(void)
{
    int count = EVP_PKEY_meth_get_count();

    printf("ecx.refuse.meth_get0_past_end=%d\n",
        EVP_PKEY_meth_get0((size_t)count) == NULL);
    printf("ecx.refuse.meth_find_undef=%d\n", EVP_PKEY_meth_find(NID_undef) == NULL);
    printf("ecx.refuse.asn1_get0_past_end=%d\n",
        EVP_PKEY_asn1_get0(EVP_PKEY_asn1_get_count()) == NULL);
    printf("ecx.refuse.asn1_get0_info_null=%d\n",
        EVP_PKEY_asn1_get0_info(NULL, NULL, NULL, NULL, NULL, NULL));
    printf("ecx.refuse.find_str_absent=%d\n",
        EVP_PKEY_asn1_find_str(NULL, "NOTANECXNAME", -1) == NULL);
    printf("ecx.refuse.find_str_empty=%d\n",
        EVP_PKEY_asn1_find_str(NULL, "", -1) == NULL);
}

int main(void)
{
    find_arms();
    find_str_arms();
    type_arms();
    ameth_table_arms();
    pmeth_arms();
    pubkey_arms();
    refusal_arms();
    return 0;
}
