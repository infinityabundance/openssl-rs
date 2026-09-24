/*
 * RT-PUBKEY -- the differential court for `crypto/x509/x_pubkey.c` and `crypto/pem/pem_pkey.c`'s
 * read half (D369).
 *
 * This program is compiled **twice**, once against the admitted authority and once against the
 * candidate distribution shell, and the two `key=value` transcripts are diffed line by line. It
 * never decides anything: a residual is a difference between two executions, so the expectation
 * cannot drift. `forensics/tools/phase8_courts.py` owns the comparison.
 *
 * What this court covers
 * ----------------------
 *   * **The `X509_PUBKEY` object layer** D369 completed: `X509_PUBKEY_new`, `X509_PUBKEY_set0_param`
 *     and `X509_PUBKEY_get0_param` over a hand-built object whose algorithm and three-byte bit
 *     string are the probe's own constants, `i2d_X509_PUBKEY`/`d2i_X509_PUBKEY` as a round trip,
 *     `X509_PUBKEY_dup` and `X509_PUBKEY_eq`'s three answers.
 *   * **The `EVP_PKEY` codecs**: `X509_PUBKEY_set`/`_get0`/`_get` over a legacy `EVP_PKEY` the
 *     probe assigns an RSA key to, `i2d_PUBKEY` and the type-specific `i2d_`/`d2i_` pairs for RSA,
 *     DSA and EC, each driven as an encode, a decode and a re-encode of the same length.
 *   * **The six `crypto/pem/pem_all.c` private-key readers** and the `PEM_read_bio_PrivateKey`
 *     they wrap, over a traditional `RSA PRIVATE KEY` block the probe writes from its own key.
 *     See the note on the decoder leg below.
 *
 * ## Two arms the court deliberately does not carry, and why
 *
 * **The `OSSL_DECODER` leg is not observed, because it must differ.** The authority's default
 * provider supplies a DER decoder, so `d2i_PUBKEY` on a decodable `SubjectPublicKeyInfo` answers a
 * key there and NULL here -- this crate publishes no provider decoder
 * (`docs/SECURITY_DIVERGENCE_POLICY.md` **D-DECODER-ABSENT-1**, D369). A differential court's
 * residual set must be empty, so the arm that *would* differ is not carried; `d2i_PUBKEY` is
 * observed through the zero-length decode instead, which fails in the ASN.1 layer on both sides
 * with the same coordinate. The legacy entry points -- `ossl_d2i_PUBKEY_legacy` through
 * `d2i_RSA_PUBKEY`/`d2i_DSA_PUBKEY`/`d2i_EC_PUBKEY` -- do not use the decoder and are carried in
 * full.
 *
 * **No traditional private-key block is read through the decoder path.** An unencrypted
 * `-----BEGIN RSA PRIVATE KEY-----` block is a *type-specific* structure the provider's PEM decoder
 * does not map (measured: the authority answers `EVP_PKEY_get0_RSA != NULL` for it, i.e. through
 * the ameth leg), so both sides read it with `ossl_d2i_PrivateKey_legacy` and the arm is exact.
 * A PKCS#8 `PRIVATE KEY` block is not carried for the same reason the decoder leg is not.
 *
 * ## Nothing secret reaches the transcript
 *
 * The RSA, DSA and EC keys are the probe's own; the DSA group is a fixed four-byte constant set and
 * no key generation runs for it. Every observation is a return code, a length, a NID, a bit count,
 * a boolean, or a drained `ERR` coordinate. No DER byte of a private key is ever printed.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

/* Drain the queue, printing each record's packed code and coordinate. Every arm that observes the
 * queue after a call **whose whole path is shared with the authority** uses this. The one exception
 * is the arm that reads through `PEM_read_bio_PrivateKey`'s decoder leg, whose record is the
 * observable `D-DECODER-ABSENT-1` names: it uses `drain_count` instead, so the count is still
 * measured and the differing record is not carried as a residual. Nothing here is a secret. */
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
        printf("pub.%s.err.%d=%lu:%s:%d:%s\n", arm, n, e,
               file != NULL ? file : "(null)", line,
               func != NULL ? func : "(null)");
        n++;
    }
    printf("pub.%s.err.count=%d\n", arm, n);
}

static void drain_count(const char *arm)
{
    int n = 0;

    while (ERR_get_error() != 0)
        n++;
    printf("pub.%s.err.count=%d\n", arm, n);
}

/* `X509_PUBKEY_get0_param`'s whole answer, keyed by a caller-supplied tag. */
static void params_of(const char *tag, X509_PUBKEY *pk)
{
    ASN1_OBJECT *o = NULL;
    const unsigned char *p = NULL;
    int len = -1;
    X509_ALGOR *a = NULL;
    int r = X509_PUBKEY_get0_param(&o, &p, &len, &a, pk);

    printf("pub.%s.get0_param=%d\n", tag, r);
    printf("pub.%s.oid_nid=%d\n", tag, o != NULL ? OBJ_obj2nid(o) : -1);
    printf("pub.%s.bitlen=%d\n", tag, len);
    /* The first octet of the probe's own three-byte constant: not a key byte. */
    printf("pub.%s.bit0=%d\n", tag, len == 3 && p != NULL ? p[0] : -1);
    printf("pub.%s.algor_notnull=%d\n", tag, a != NULL);
}

int main(void)
{
    static const unsigned char BITSTR[3] = { 0x04, 0x11, 0x22 };
    X509_PUBKEY *pk;
    X509_PUBKEY *back = NULL;
    X509_PUBKEY *dup;
    unsigned char *der = NULL;
    int derlen;
    const unsigned char *cur;
    unsigned char *penc;
    RSA *rsa = RSA_new();
    DSA *dsa = DSA_new();
    EC_KEY *ec;
    BIGNUM *e = BN_new();
    EVP_PKEY *pkey;

    /* ---- the X509_PUBKEY object layer ---- */

    pk = X509_PUBKEY_new();
    printf("pub.new=%d\n", pk != NULL);
    penc = (unsigned char *)OPENSSL_malloc(sizeof(BITSTR));
    memcpy(penc, BITSTR, sizeof(BITSTR));
    printf("pub.set0_param=%d\n",
           X509_PUBKEY_set0_param(pk, OBJ_nid2obj(NID_rsaEncryption), V_ASN1_UNDEF, NULL,
                                  penc, (int)sizeof(BITSTR)));
    params_of("built", pk);

    derlen = i2d_X509_PUBKEY(pk, &der);
    printf("pub.i2d.len=%d\n", derlen);
    printf("pub.i2d.tag=%d\n", derlen > 0 ? der[0] : -1);
    cur = der;
    back = d2i_X509_PUBKEY(NULL, &cur, derlen);
    printf("pub.d2i.notnull=%d\n", back != NULL);
    if (back != NULL) {
        params_of("back", back);
        printf("pub.rewrite.equal=%d\n", i2d_X509_PUBKEY(back, NULL) == derlen);
    }
    dup = X509_PUBKEY_dup(pk);
    printf("pub.dup.notnull=%d\n", dup != NULL);
    if (dup != NULL)
        params_of("dup", dup);
    printf("pub.eq.self=%d\n", X509_PUBKEY_eq(pk, pk));
    /* Two algorithm-identical objects with no decoded key: -2, the authority's own answer. */
    printf("pub.eq.pair=%d\n", X509_PUBKEY_eq(pk, back));
    printf("pub.eq.null=%d\n", X509_PUBKEY_eq(pk, NULL));
    drain("object");

    /* ---- X509_PUBKEY_set / get0 / get over a legacy EVP_PKEY ---- */

    BN_set_word(e, RSA_F4);
    printf("pub.rsa.gen=%d\n", RSA_generate_key_ex(rsa, 1024, e, NULL));
    pkey = EVP_PKEY_new();
    printf("pub.assign=%d\n", EVP_PKEY_assign(pkey, EVP_PKEY_RSA, rsa));
    {
        X509_PUBKEY *spk = NULL;

        printf("pub.set=%d\n", X509_PUBKEY_set(&spk, pkey));
        printf("pub.set.get0_is_pkey=%d\n", X509_PUBKEY_get0(spk) == pkey);
        printf("pub.get.notnull=%d\n", X509_PUBKEY_get(spk) != NULL);
        printf("pub.set.i2d.notnull=%d\n", spk != NULL && i2d_X509_PUBKEY(spk, NULL) > 0);
        X509_PUBKEY_free(spk);
    }

    /* ---- i2d_PUBKEY, and d2i_PUBKEY's refusal on a zero-length input ---- */

    {
        unsigned char *pp = NULL;

        derlen = i2d_PUBKEY(pkey, &pp);
        printf("pub.i2d_pubkey.len=%d\n", derlen);
        printf("pub.i2d_pubkey.tag=%d\n", derlen > 0 ? pp[0] : -1);
        ERR_clear_error();
        cur = pp;
        {
            EVP_PKEY *got = d2i_PUBKEY(NULL, &cur, 0);

            printf("pub.d2i_pubkey.zero.notnull=%d\n", got != NULL);
            EVP_PKEY_free(got);
        }
        drain("d2i_pubkey_zero");
        OPENSSL_free(pp);
    }

    /* ---- the type-specific codecs: encode, decode, re-encode ---- */

    {
        unsigned char *rp = NULL;
        int rl = i2d_RSA_PUBKEY(rsa, &rp);
        RSA *rback = NULL;
        const unsigned char *c2 = rp;

        printf("pub.rsa.i2d.len_nonzero=%d\n", rl > 0);
        rback = d2i_RSA_PUBKEY(NULL, &c2, rl);
        printf("pub.rsa.d2i.notnull=%d\n", rback != NULL);
        printf("pub.rsa.bits=%d\n", rback != NULL ? RSA_bits(rback) : -1);
        printf("pub.rsa.rewrite.equal=%d\n",
               rback != NULL ? i2d_RSA_PUBKEY(rback, NULL) == rl : -1);
        RSA_free(rback);
        OPENSSL_free(rp);
    }

    /* The DSA group is a fixed constant set, so no generation and no draw is involved: the arms
     * observe the encoder and decoder, not any arithmetic. */
    {
        BIGNUM *p = BN_new();
        BIGNUM *q = BN_new();
        BIGNUM *g = BN_new();
        BIGNUM *y = BN_new();
        BIGNUM *x = BN_new();
        unsigned char *dp = NULL;
        int dl;
        DSA *dback = NULL;
        const unsigned char *c2;

        BN_set_word(p, 0x00F7);
        BN_set_word(q, 0x0011);
        BN_set_word(g, 0x0002);
        BN_set_word(y, 0x0014);
        BN_set_word(x, 0x0003);
        printf("pub.dsa.set0_pqg=%d\n", DSA_set0_pqg(dsa, p, q, g));
        printf("pub.dsa.set0_key=%d\n", DSA_set0_key(dsa, y, x));
        dl = i2d_DSA_PUBKEY(dsa, &dp);
        printf("pub.dsa.i2d.len_nonzero=%d\n", dl > 0);
        c2 = dp;
        dback = d2i_DSA_PUBKEY(NULL, &c2, dl);
        printf("pub.dsa.d2i.notnull=%d\n", dback != NULL);
        printf("pub.dsa.rewrite.equal=%d\n",
               dback != NULL ? i2d_DSA_PUBKEY(dback, NULL) == dl : -1);
        DSA_free(dback);
        OPENSSL_free(dp);
    }

    {
        unsigned char *ep = NULL;
        int el;
        EC_KEY *eback = NULL;
        const unsigned char *c2;

        ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        printf("pub.ec.keygen=%d\n", EC_KEY_generate_key(ec));
        el = i2d_EC_PUBKEY(ec, &ep);
        printf("pub.ec.i2d.len_nonzero=%d\n", el > 0);
        c2 = ep;
        eback = d2i_EC_PUBKEY(NULL, &c2, el);
        printf("pub.ec.d2i.notnull=%d\n", eback != NULL);
        printf("pub.ec.rewrite.equal=%d\n",
               eback != NULL ? i2d_EC_PUBKEY(eback, NULL) == el : -1);
        EC_KEY_free(eback);
        OPENSSL_free(ep);
    }

    /* ---- the six private-key readers, over a traditional block ----
     *
     * One block per memory BIO: the readers rewind their input, so a BIO holding two blocks would
     * measure the concatenation rather than the block. */

    {
        char *blk = NULL;
        long blk_len;
        RSA *rback;
        DSA *db;
        EC_KEY *eb;
        EVP_PKEY *kv;
        BIO *wb;
        FILE *f;

        /* --- the RSA block, and the four spellings that read it --- */

        wb = BIO_new(BIO_s_mem());
        printf("pub.rsapriv.write=%d\n",
               PEM_write_bio_RSAPrivateKey(wb, rsa, NULL, NULL, 0, NULL, NULL));
        blk_len = BIO_ctrl(wb, BIO_CTRL_PENDING, 0, NULL);
        BIO_ctrl(wb, BIO_CTRL_INFO, 0, (char *)&blk);
        printf("pub.rsapriv.write.len_nonzero=%d\n", blk_len > 0);
        /* The begin line, up to its newline: no `=` can appear, so the parser cannot be confused. */
        printf("pub.rsapriv.begin=%.22s\n", blk);

        ERR_clear_error();
        rback = PEM_read_bio_RSAPrivateKey(BIO_new_mem_buf(blk, (int)blk_len), NULL, NULL, NULL);
        printf("pub.rsapriv.bio.notnull=%d\n", rback != NULL);
        printf("pub.rsapriv.bio.bits=%d\n", rback != NULL ? RSA_bits(rback) : -1);
        {
            BIO *rwb = BIO_new(BIO_s_mem());

            printf("pub.rsapriv.bio.rewrite=%d\n",
                   rback != NULL ? PEM_write_bio_RSAPrivateKey(rwb, rback, NULL, NULL, 0, NULL, NULL)
                                 : -1);
            BIO_free(rwb);
        }
        RSA_free(rback);
        drain("rsapriv_bio");

        ERR_clear_error();
        kv = PEM_read_bio_PrivateKey(BIO_new_mem_buf(blk, (int)blk_len), NULL, NULL, NULL);
        printf("pub.privkey.bio.notnull=%d\n", kv != NULL);
        printf("pub.privkey.bio.type=%d\n", kv != NULL ? EVP_PKEY_get_id(kv) : -1);
        /* A type-specific block is read by the ameth leg on both sides, so the decoded key is a
         * legacy one whose low-level accessor answers without a downgrade. */
        printf("pub.privkey.bio.is_legacy_rsa=%d\n",
               kv != NULL ? EVP_PKEY_get0_RSA(kv) != NULL : -1);
        EVP_PKEY_free(kv);
        /* The decoder leg's record, whose content must differ: D-DECODER-ABSENT-1. */
        drain_count("privkey_bio");

        f = tmpfile();
        printf("pub.rsapriv.file.write=%d\n",
               PEM_write_RSAPrivateKey(f, rsa, NULL, NULL, 0, NULL, NULL));
        rewind(f);
        ERR_clear_error();
        rback = PEM_read_RSAPrivateKey(f, NULL, NULL, NULL);
        printf("pub.rsapriv.file.notnull=%d\n", rback != NULL);
        printf("pub.rsapriv.file.bits=%d\n", rback != NULL ? RSA_bits(rback) : -1);
        RSA_free(rback);
        fclose(f);
        drain("rsapriv_file");

        /* The `_ex` spelling of the same read, in both BIO and FILE flavours. */
        ERR_clear_error();
        kv = PEM_read_bio_PrivateKey_ex(BIO_new_mem_buf(blk, (int)blk_len), NULL, NULL, NULL,
                                        NULL, NULL);
        printf("pub.privkey.bio_ex.notnull=%d\n", kv != NULL);
        printf("pub.privkey.bio_ex.type=%d\n", kv != NULL ? EVP_PKEY_get_id(kv) : -1);
        EVP_PKEY_free(kv);
        drain_count("privkey_bio_ex");

        f = tmpfile();
        PEM_write_RSAPrivateKey(f, rsa, NULL, NULL, 0, NULL, NULL);
        rewind(f);
        kv = PEM_read_PrivateKey_ex(f, NULL, NULL, NULL, NULL, NULL);
        printf("pub.privkey.file_ex.notnull=%d\n", kv != NULL);
        printf("pub.privkey.file_ex.type=%d\n", kv != NULL ? EVP_PKEY_get_id(kv) : -1);
        EVP_PKEY_free(kv);
        fclose(f);

        /* The `FILE *` spelling of the plain reader, over the same block. */
        f = tmpfile();
        PEM_write_RSAPrivateKey(f, rsa, NULL, NULL, 0, NULL, NULL);
        rewind(f);
        kv = PEM_read_PrivateKey(f, NULL, NULL, NULL);
        printf("pub.privkey.file.notnull=%d\n", kv != NULL);
        printf("pub.privkey.file.type=%d\n", kv != NULL ? EVP_PKEY_get_id(kv) : -1);
        EVP_PKEY_free(kv);
        fclose(f);

        BIO_free(wb);

        /* --- the DSA block --- */

        wb = BIO_new(BIO_s_mem());
        printf("pub.dsapriv.write=%d\n",
               PEM_write_bio_DSAPrivateKey(wb, dsa, NULL, NULL, 0, NULL, NULL));
        blk_len = BIO_ctrl(wb, BIO_CTRL_PENDING, 0, NULL);
        BIO_ctrl(wb, BIO_CTRL_INFO, 0, (char *)&blk);
        printf("pub.dsapriv.write.len_nonzero=%d\n", blk_len > 0);
        ERR_clear_error();
        db = PEM_read_bio_DSAPrivateKey(BIO_new_mem_buf(blk, (int)blk_len), NULL, NULL, NULL);
        printf("pub.dsapriv.bio.notnull=%d\n", db != NULL);
        DSA_free(db);
        drain("dsapriv_bio");
        BIO_free(wb);

        f = tmpfile();
        printf("pub.dsapriv.file.write=%d\n",
               PEM_write_DSAPrivateKey(f, dsa, NULL, NULL, 0, NULL, NULL));
        rewind(f);
        db = PEM_read_DSAPrivateKey(f, NULL, NULL, NULL);
        printf("pub.dsapriv.file.notnull=%d\n", db != NULL);
        DSA_free(db);
        fclose(f);

        /* --- the EC block --- */

        wb = BIO_new(BIO_s_mem());
        printf("pub.ecpriv.write=%d\n",
               PEM_write_bio_ECPrivateKey(wb, ec, NULL, NULL, 0, NULL, NULL));
        blk_len = BIO_ctrl(wb, BIO_CTRL_PENDING, 0, NULL);
        BIO_ctrl(wb, BIO_CTRL_INFO, 0, (char *)&blk);
        printf("pub.ecpriv.write.len_nonzero=%d\n", blk_len > 0);
        ERR_clear_error();
        eb = PEM_read_bio_ECPrivateKey(BIO_new_mem_buf(blk, (int)blk_len), NULL, NULL, NULL);
        printf("pub.ecpriv.bio.notnull=%d\n", eb != NULL);
        EC_KEY_free(eb);
        drain("ecpriv_bio");
        BIO_free(wb);

        f = tmpfile();
        printf("pub.ecpriv.file.write=%d\n",
               PEM_write_ECPrivateKey(f, ec, NULL, NULL, 0, NULL, NULL));
        rewind(f);
        eb = PEM_read_ECPrivateKey(f, NULL, NULL, NULL);
        printf("pub.ecpriv.file.notnull=%d\n", eb != NULL);
        EC_KEY_free(eb);
        fclose(f);

        /* ---- the four `PUBKEY` spellings, over a `PUBLIC KEY` block this probe writes ----
         *
         * `PEM_write_bio_PUBKEY` is Phase 11's and a scaffold on the candidate, so the block is
         * written through `PEM_ASN1_write_bio` with `i2d_PUBKEY`, which is the same encode. A
         * `SubjectPublicKeyInfo` is a *public* structure: what is printed is its begin line. */

        wb = BIO_new(BIO_s_mem());
        printf("pub.pubkey.write=%d\n",
               PEM_ASN1_write_bio((i2d_of_void *)i2d_PUBKEY, "PUBLIC KEY", wb, pkey,
                                  NULL, NULL, 0, NULL, NULL));
        blk_len = BIO_ctrl(wb, BIO_CTRL_PENDING, 0, NULL);
        BIO_ctrl(wb, BIO_CTRL_INFO, 0, (char *)&blk);
        printf("pub.pubkey.write.len_nonzero=%d\n", blk_len > 0);
        printf("pub.pubkey.begin=%.22s\n", blk);

        ERR_clear_error();
        kv = PEM_read_bio_PUBKEY(BIO_new_mem_buf(blk, (int)blk_len), NULL, NULL, NULL);
        printf("pub.pubkey.bio.notnull=%d\n", kv != NULL);
        printf("pub.pubkey.bio.type=%d\n", kv != NULL ? EVP_PKEY_get_id(kv) : -1);
        printf("pub.pubkey.bio.is_legacy_rsa=%d\n",
               kv != NULL ? EVP_PKEY_get0_RSA(kv) != NULL : -1);
        EVP_PKEY_free(kv);
        drain_count("pubkey_bio");

        ERR_clear_error();
        kv = PEM_read_bio_PUBKEY_ex(BIO_new_mem_buf(blk, (int)blk_len), NULL, NULL, NULL,
                                    NULL, NULL);
        printf("pub.pubkey.bio_ex.notnull=%d\n", kv != NULL);
        printf("pub.pubkey.bio_ex.type=%d\n", kv != NULL ? EVP_PKEY_get_id(kv) : -1);
        EVP_PKEY_free(kv);
        drain_count("pubkey_bio_ex");

        f = tmpfile();
        fwrite(blk, 1, (size_t)blk_len, f);
        rewind(f);
        kv = PEM_read_PUBKEY(f, NULL, NULL, NULL);
        printf("pub.pubkey.file.notnull=%d\n", kv != NULL);
        printf("pub.pubkey.file.type=%d\n", kv != NULL ? EVP_PKEY_get_id(kv) : -1);
        EVP_PKEY_free(kv);
        fclose(f);

        f = tmpfile();
        fwrite(blk, 1, (size_t)blk_len, f);
        rewind(f);
        kv = PEM_read_PUBKEY_ex(f, NULL, NULL, NULL, NULL, NULL);
        printf("pub.pubkey.file_ex.notnull=%d\n", kv != NULL);
        printf("pub.pubkey.file_ex.type=%d\n", kv != NULL ? EVP_PKEY_get_id(kv) : -1);
        EVP_PKEY_free(kv);
        fclose(f);

        BIO_free(wb);
    }

    OPENSSL_free(der);
    X509_PUBKEY_free(dup);
    X509_PUBKEY_free(back);
    X509_PUBKEY_free(pk);
    EVP_PKEY_free(pkey);
    BN_free(e);
    DSA_free(dsa);
    EC_KEY_free(ec);
    printf("pub.done=1\n");
    return 0;
}
