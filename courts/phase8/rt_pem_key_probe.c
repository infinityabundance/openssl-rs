/*
 * RT-PEM-KEY -- the differential court for `crypto/pem/pem_all.c`, `pem_lib.c`'s plumbing and
 * `pem_oth.c` (Phase 8.9 / Phase 9 staging, D350).
 *
 * This program is compiled **twice**, once against the admitted authority and once against the
 * candidate distribution shell, and the two `key=value` transcripts are diffed. It never decides
 * anything: a residual is a difference between two executions, so the expectation cannot drift.
 * `forensics/tools/phase8_courts.py` owns the comparison.
 *
 * What this court covers
 * ----------------------
 * **Three slices, one probe.**
 *
 *   * The **twenty-four `pem_all.c` rows** Phase 8.9 lands: the `IMPLEMENT_PEM_*` expansions for
 *     `DHparams`, `DHxparams`, `DSAparams`, `DSAPrivateKey`, `ECPKParameters`, `ECPrivateKey`,
 *     `RSAPublicKey` and `RSAPrivateKey`, in both the `BIO *` and the `FILE *` spellings. The six
 *     private-key *readers* are deliberately not here and are named in `src/pem/key_legacy.rs`:
 *     they need `EVP_PKEY_get1_{RSA,DSA,EC_KEY}` and `PEM_read[_bio]_PrivateKey`, neither landed.
 *   * The **PEM plumbing** `pem_lib.c` contributes: `PEM_def_callback`, `PEM_bytes_read_bio`, its
 *     `_secmem` spelling, `PEM_do_header`, `PEM_ASN1_read`/`_read_bio`/`_write`/`_write_bio`/
 *     `_write_bio_ctx`, and `EVP_read_pw_string`/`_min` through the `UI` program.
 *   * `pem_oth.c`'s `PEM_ASN1_read_bio`, driven through `PEM_ASN1_read`'s `FILE *` wrapper.
 *
 * The arms are chosen so that **no random or secret byte reaches the transcript**:
 *
 *   * every `DH`, `DHx` and `EC` block is written from a **public named parameter set**
 *     (`DH_get_1024_160()` and `EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)`), so its bytes
 *     are a constant of the probe's own inputs and printing them is not a leak -- the begin line
 *     and length are printed, and the whole block is compared against a second write of the same
 *     object;
 *   * the `DSA` parameter block comes from `DSA_generate_parameters_ex` over a **fixed seed**, so
 *     it is deterministic, and only its length and round trip are printed;
 *   * the `RSA`, `DSA` and `EC` *private* keys are generated, and **the DER bytes are never
 *     printed**: the arms observe the writer's return code, the presence of the `Proc-Type:
 *     4,ENCRYPTED` and `DEK-Info:` header lines, the decrypted length, and whether the block
 *     decodes back to an object at all. That is D347's rule for a private-key writer.
 *
 * ## Never reaching the prompt
 *
 * `PEM_def_callback`'s `userdata == NULL` arm and `EVP_read_pw_string*` both drive the `UI`
 * program, whose default method reads `/dev/tty`. This probe sets the process default method to
 * `UI_null()` as its first act, so every one of those calls reaches a method with no reader and
 * answers the cancellation code `-2` instead of prompting. The two `PEM_def_callback` arms are
 * therefore both observable without a terminal: the `userdata != NULL` arm returns the string's
 * length, and the `userdata == NULL` arm returns `-1` after the cancelled prompt.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ui.h>

/* The begin line of a written block, up to (not including) its newline. No `=` can appear, so the
 * `key=value` transcript parser cannot mistake it for a value. */
static void print_begin(const char *tag, const char *buf)
{
    size_t n = strcspn(buf, "\n");
    printf("pem.%s.begin=%.*s\n", tag, (int)n, buf);
}

/* Write `dh` to a memory BIO and report the block's length and begin line, then read it back with
 * `reader` and compare a second write of the same object with the first. `name` is the PEM name the
 * reader is told to expect. */
static void dh_roundtrip(const char *tag, DH *dh, int x9,
                         DH *(*reader)(BIO *, DH **, pem_password_cb *, void *))
{
    char *first = NULL;
    long first_len = 0;
    DH *back = NULL;
    char *second = NULL;
    long second_len = 0;
    BIO *wb = BIO_new(BIO_s_mem());
    BIO *rb;
    BIO *wb2 = BIO_new(BIO_s_mem());

    printf("pem.%s.write.ret=%d\n", tag,
           x9 ? PEM_write_bio_DHxparams(wb, dh) : PEM_write_bio_DHparams(wb, dh));
    BIO_ctrl(wb, BIO_CTRL_INFO, 0, (char *)&first);
    first_len = BIO_ctrl(wb, BIO_CTRL_PENDING, 0, NULL);
    printf("pem.%s.write.len_nonzero=%d\n", tag, first_len > 0);
    print_begin(tag, first);

    rb = BIO_new_mem_buf(first, (int)first_len);
    back = reader(rb, NULL, NULL, NULL);
    printf("pem.%s.read.not_null=%d\n", tag, back != NULL);

    printf("pem.%s.rewrite.ret=%d\n", tag,
           x9 ? PEM_write_bio_DHxparams(wb2, back) : PEM_write_bio_DHparams(wb2, back));
    BIO_ctrl(wb2, BIO_CTRL_INFO, 0, (char *)&second);
    second_len = BIO_ctrl(wb2, BIO_CTRL_PENDING, 0, NULL);
    printf("pem.%s.roundtrip.equal=%d\n", tag,
           first_len == second_len && first_len > 0
               && memcmp(first, second, (size_t)first_len) == 0);

    DH_free(back);
    BIO_free(rb);
    BIO_free(wb);
    BIO_free(wb2);
}

/* The `FILE *` spelling: write to a temporary and read it back through the same handle. */
static void dh_file_roundtrip(const char *tag, DH *dh, int x9)
{
    FILE *f = tmpfile();
    DH *back;
    printf("pem.%s.file.write.ret=%d\n", tag,
           x9 ? PEM_write_DHxparams(f, dh) : PEM_write_DHparams(f, dh));
    rewind(f);
    back = PEM_read_DHparams(f, NULL, NULL, NULL);
    printf("pem.%s.file.read.not_null=%d\n", tag, back != NULL);
    DH_free(back);
    fclose(f);
}

/* A private key written with and without a cipher. The **plain** arm is read back through
 * `PEM_bytes_read_bio` (which needs no cipher-name lookup) and decoded; the **encrypted** arm
 * observes only the writer -- the DER bytes are never printed (D347's rule), and the read-back is
 * deliberately absent because `PEM_get_EVP_CIPHER_INFO` resolves the `DEK-Info` name through
 * `EVP_get_cipherbyname`, whose legacy table is Phase 13's and empty in the candidate. */
static void private_write(const char *tag, const char *name,
                          const void *key, int bio_or_fp, int which)
{
    char *blk = NULL;
    long blk_len = 0;
    BIO *wb = BIO_new(BIO_s_mem());
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, "AES-128-CBC", NULL);
    static const unsigned char pw[] = "password";
    int wrote = 0;
    FILE *f;

    if (!bio_or_fp)
        f = tmpfile();

    switch (which) {
    case 0: /* RSA */
        wrote = bio_or_fp
            ? PEM_write_bio_RSAPrivateKey(wb, key, cipher, pw, (int)strlen((const char *)pw),
                                          NULL, NULL)
            : PEM_write_RSAPrivateKey(f, key, cipher, pw, (int)strlen((const char *)pw),
                                      NULL, NULL);
        break;
    case 1: /* DSA */
        wrote = bio_or_fp
            ? PEM_write_bio_DSAPrivateKey(wb, key, cipher, pw, (int)strlen((const char *)pw),
                                          NULL, NULL)
            : PEM_write_DSAPrivateKey(f, key, cipher, pw, (int)strlen((const char *)pw),
                                      NULL, NULL);
        break;
    default: /* EC */
        wrote = bio_or_fp
            ? PEM_write_bio_ECPrivateKey(wb, key, cipher, pw, (int)strlen((const char *)pw),
                                         NULL, NULL)
            : PEM_write_ECPrivateKey(f, key, cipher, pw, (int)strlen((const char *)pw),
                                     NULL, NULL);
        break;
    }
    printf("pem.%s.%s.enc_write.ret_nonzero=%d\n", tag, bio_or_fp ? "bio" : "file", wrote > 0);

    if (bio_or_fp) {
        BIO_ctrl(wb, BIO_CTRL_INFO, 0, (char *)&blk);
        blk_len = BIO_ctrl(wb, BIO_CTRL_PENDING, 0, NULL);
        printf("pem.%s.bio.has_proc_type=%d\n", tag,
               blk != NULL && strstr(blk, "Proc-Type: 4,ENCRYPTED") != NULL);
        printf("pem.%s.bio.has_dek_info=%d\n", tag,
               blk != NULL && strstr(blk, "DEK-Info: AES-128-CBC,") != NULL);
        printf("pem.%s.bio.len_nonzero=%d\n", tag, blk_len > 0);
    } else {
        fclose(f);
    }

    /* The plain arm: write, read back and decode. */
    {
        char *p_blk = NULL;
        long p_len;
        unsigned char *der = NULL;
        long der_len = 0;
        void *obj = NULL;
        BIO *w2 = BIO_new(BIO_s_mem());
        int wret = 0;
        int rret;
        const unsigned char *p;

        switch (which) {
        case 0:
            wret = PEM_write_bio_RSAPrivateKey(w2, key, NULL, NULL, 0, NULL, NULL);
            break;
        case 1:
            wret = PEM_write_bio_DSAPrivateKey(w2, key, NULL, NULL, 0, NULL, NULL);
            break;
        default:
            wret = PEM_write_bio_ECPrivateKey(w2, key, NULL, NULL, 0, NULL, NULL);
            break;
        }
        printf("pem.%s.plain.write.ret=%d\n", tag, wret);
        BIO_ctrl(w2, BIO_CTRL_INFO, 0, (char *)&p_blk);
        p_len = BIO_ctrl(w2, BIO_CTRL_PENDING, 0, NULL);
        printf("pem.%s.plain.len_nonzero=%d\n", tag, p_len > 0);
        rret = PEM_bytes_read_bio(&der, &der_len, NULL, name,
                                  BIO_new_mem_buf(p_blk, (int)p_len), NULL, NULL);
        printf("pem.%s.plain.read.ret=%d\n", tag, rret);
        p = der;
        switch (which) {
        case 0:
            obj = d2i_RSAPrivateKey(NULL, &p, der_len);
            break;
        case 1:
            obj = d2i_DSAPrivateKey(NULL, &p, der_len);
            break;
        default:
            obj = d2i_ECPrivateKey(NULL, &p, der_len);
            break;
        }
        printf("pem.%s.plain.decodes=%d\n", tag, obj != NULL);
        BIO_free(w2);
        OPENSSL_free(der);
    }

    BIO_free(wb);
    EVP_CIPHER_free(cipher);
}

static int my_i2d_ctx(const void *x, unsigned char **pp, void *vctx)
{
    (void)vctx;
    return i2d_DHparams((const DH *)x, pp);
}

int main(void)
{
    unsigned char pwbuf[16];
    EVP_CIPHER_INFO ci;
    unsigned char blob[8] = { 0, 1, 2, 3, 4, 5, 6, 7 };
    long blob_len = (long)sizeof(blob);
    char *data = NULL;
    long len = 0;
    int r;
    DH *dh;
    DH *dh_back;
    DSA *dsa;
    EC_GROUP *grp;
    EC_KEY *eckey;
    RSA *rsa;
    BIGNUM *e;
    BIO *rbio;

    /* Never reach the interactive prompt: the null method has no reader, so `UI_process` answers
     * -2 rather than reading /dev/tty. This is the first act of the process. */
    UI_set_default_method(UI_null());
    printf("pem.default_method_is_null=%d\n", UI_get_default_method() == UI_null());

    /* ---- PEM_def_callback, both arms, neither prompting ---- */

    memset(pwbuf, 0, sizeof(pwbuf));
    printf("pem.def_callback.userdata.ret=%d\n",
           PEM_def_callback((char *)pwbuf, (int)sizeof(pwbuf), 1, (void *)"secret"));
    printf("pem.def_callback.userdata.value=%s\n", (char *)pwbuf);
    /* A clamp: a `num` shorter than the string truncates. */
    memset(pwbuf, 0, sizeof(pwbuf));
    printf("pem.def_callback.clamped.ret=%d\n",
           PEM_def_callback((char *)pwbuf, 3, 1, (void *)"secret"));
    printf("pem.def_callback.clamped.value=%s\n", (char *)pwbuf);
    /* The prompting arm, cancelled by the null method. */
    memset(pwbuf, 0, sizeof(pwbuf));
    printf("pem.def_callback.prompt.ret=%d\n",
           PEM_def_callback((char *)pwbuf, (int)sizeof(pwbuf), 1, NULL));

    /* ---- EVP_read_pw_string / _min, cancelled ---- */

    printf("pem.read_pw_string.ret=%d\n",
           EVP_read_pw_string((char *)pwbuf, (int)sizeof(pwbuf), "prompt:", 0));
    printf("pem.read_pw_string_min.ret=%d\n",
           EVP_read_pw_string_min((char *)pwbuf, 0, (int)sizeof(pwbuf), "prompt:", 0));

    /* ---- PEM_do_header's no-work arm ---- */

    memset(&ci, 0, sizeof(ci));
    printf("pem.do_header.plain.ret=%d\n",
           PEM_do_header(&ci, blob, &blob_len, NULL, NULL));
    printf("pem.do_header.plain.len_unchanged=%d\n", blob_len == (long)sizeof(blob));

    /* ---- the DH parameter writers and readers ---- */

    dh = DH_get_1024_160();
    printf("pem.dh.get_1024_160=%d\n", dh != NULL);
    dh_roundtrip("dhparams", dh, 0, PEM_read_bio_DHparams);
    dh_roundtrip("dhxparams", dh, 1, PEM_read_bio_DHparams);
    dh_file_roundtrip("dhparams", dh, 0);
    dh_file_roundtrip("dhxparams", dh, 1);

    /* ---- PEM_ASN1_* with the same DH object ---- */

    rbio = BIO_new(BIO_s_mem());
    printf("pem.asn1_write_bio.ret=%d\n",
           PEM_ASN1_write_bio((i2d_of_void *)i2d_DHparams, "DH PARAMETERS", rbio, dh,
                              NULL, NULL, 0, NULL, NULL));
    {
        char *blk = NULL;
        long blk_len = BIO_ctrl(rbio, BIO_CTRL_INFO, 0, (char *)&blk);
        BIO *r2;
        dh_back = NULL;
        blk_len = BIO_ctrl(rbio, BIO_CTRL_PENDING, 0, NULL);
        r2 = BIO_new_mem_buf(blk, (int)blk_len);
        dh_back = PEM_ASN1_read_bio((d2i_of_void *)d2i_DHparams, "DH PARAMETERS", r2,
                                    (void **)&dh_back, NULL, NULL);
        printf("pem.asn1_read_bio.not_null=%d\n", dh_back != NULL);
        DH_free(dh_back);
        BIO_free(r2);
    }
    BIO_free(rbio);

    /* The `_ctx` writer and the `FILE *` reader, driven through `PEM_ASN1_read`. */
    rbio = BIO_new(BIO_s_mem());
    printf("pem.asn1_write_bio_ctx.ret=%d\n",
           PEM_ASN1_write_bio_ctx(my_i2d_ctx, NULL, "DH PARAMETERS", rbio, dh,
                                  NULL, NULL, 0, NULL, NULL));
    BIO_free(rbio);
    {
        FILE *f = tmpfile();
        dh_back = NULL;
        printf("pem.asn1_write.file.ret=%d\n",
               PEM_ASN1_write((i2d_of_void *)i2d_DHparams, "DH PARAMETERS", f, dh,
                              NULL, NULL, 0, NULL, NULL));
        rewind(f);
        dh_back = PEM_ASN1_read((d2i_of_void *)d2i_DHparams, "DH PARAMETERS", f,
                                (void **)&dh_back, NULL, NULL);
        printf("pem.asn1_read.file.not_null=%d\n", dh_back != NULL);
        DH_free(dh_back);
        fclose(f);
    }

    /* ---- PEM_bytes_read_bio and its secmem spelling ---- */

    rbio = BIO_new(BIO_s_mem());
    printf("pem.bytes.seed=%d\n",
           PEM_ASN1_write_bio((i2d_of_void *)i2d_DHparams, "DH PARAMETERS", rbio, dh,
                              NULL, NULL, 0, NULL, NULL));
    {
        char *blk = NULL;
        long blk_len = BIO_ctrl(rbio, BIO_CTRL_INFO, 0, (char *)&blk);
        blk_len = BIO_ctrl(rbio, BIO_CTRL_PENDING, 0, NULL);
        r = PEM_bytes_read_bio((unsigned char **)&data, &len, NULL, "DH PARAMETERS",
                               BIO_new_mem_buf(blk, (int)blk_len), NULL, NULL);
        printf("pem.bytes.read.ret=%d\n", r);
        printf("pem.bytes.read.len_is_der=%d\n", r == 1 && len > 0);
        OPENSSL_free(data);
        data = NULL;
        r = PEM_bytes_read_bio_secmem((unsigned char **)&data, &len, NULL, "DH PARAMETERS",
                                      BIO_new_mem_buf(blk, (int)blk_len), NULL, NULL);
        printf("pem.bytes.read_secmem.ret=%d\n", r);
        OPENSSL_free(data);
    }
    BIO_free(rbio);

    /* ---- the DSA parameter writers and readers ----
     *
     * The parameters are the RFC 5114 1024/160 group `DH_get_1024_160` returns, which is a DSA
     * group as well: `DSA_set0_pqg` adopts copies of its `p`, `q` and `g`. That keeps the block a
     * constant of a public parameter set rather than of a random draw, so both sides write the
     * same bytes and the round trip is exact. */

    dsa = DSA_new();
    {
        const BIGNUM *p = NULL;
        const BIGNUM *q = NULL;
        const BIGNUM *g = NULL;
        DH_get0_pqg(dh, &p, &q, &g);
        printf("pem.dsa.set0_pqg=%d",
               DSA_set0_pqg(dsa, BN_dup(p), BN_dup(q), BN_dup(g)));
        printf("\n");
    }
    {
        char *first = NULL;
        long first_len = 0;
        char *second = NULL;
        long second_len = 0;
        BIO *wb = BIO_new(BIO_s_mem());
        BIO *wb2 = BIO_new(BIO_s_mem());
        DSA *back;
        char *blk = NULL;
        printf("pem.dsaparams.write.ret=%d\n", PEM_write_bio_DSAparams(wb, dsa));
        BIO_ctrl(wb, BIO_CTRL_INFO, 0, (char *)&first);
        first_len = BIO_ctrl(wb, BIO_CTRL_PENDING, 0, NULL);
        printf("pem.dsaparams.write.len_nonzero=%d\n", first_len > 0);
        BIO_ctrl(wb, BIO_CTRL_INFO, 0, (char *)&blk);
        back = PEM_read_bio_DSAparams(BIO_new_mem_buf(blk, (int)first_len), NULL, NULL, NULL);
        printf("pem.dsaparams.read.not_null=%d\n", back != NULL);
        printf("pem.dsaparams.rewrite.ret=%d\n", PEM_write_bio_DSAparams(wb2, back));
        BIO_ctrl(wb2, BIO_CTRL_INFO, 0, (char *)&second);
        second_len = BIO_ctrl(wb2, BIO_CTRL_PENDING, 0, NULL);
        printf("pem.dsaparams.roundtrip.equal=%d\n",
               first_len == second_len && first_len > 0
                   && memcmp(first, second, (size_t)first_len) == 0);
        DSA_free(back);
        BIO_free(wb);
        BIO_free(wb2);
    }
    {
        FILE *f = tmpfile();
        DSA *back;
        printf("pem.dsaparams.file.write.ret=%d\n", PEM_write_DSAparams(f, dsa));
        rewind(f);
        back = PEM_read_DSAparams(f, NULL, NULL, NULL);
        printf("pem.dsaparams.file.read.not_null=%d\n", back != NULL);
        DSA_free(back);
        fclose(f);
    }

    /* ---- the EC parameter writers and readers ---- */

    grp = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    printf("pem.ec.group=%d\n", grp != NULL);
    {
        char *first = NULL;
        long first_len = 0;
        char *second = NULL;
        long second_len = 0;
        char *blk = NULL;
        BIO *wb = BIO_new(BIO_s_mem());
        BIO *wb2 = BIO_new(BIO_s_mem());
        EC_GROUP *back;
        printf("pem.ecparams.write.ret=%d\n", PEM_write_bio_ECPKParameters(wb, grp));
        BIO_ctrl(wb, BIO_CTRL_INFO, 0, (char *)&first);
        first_len = BIO_ctrl(wb, BIO_CTRL_PENDING, 0, NULL);
        printf("pem.ecparams.write.len_nonzero=%d\n", first_len > 0);
        print_begin("ecparams", first);
        BIO_ctrl(wb, BIO_CTRL_INFO, 0, (char *)&blk);
        back = PEM_read_bio_ECPKParameters(BIO_new_mem_buf(blk, (int)first_len), NULL, NULL, NULL);
        printf("pem.ecparams.read.not_null=%d\n", back != NULL);
        printf("pem.ecparams.rewrite.ret=%d\n", PEM_write_bio_ECPKParameters(wb2, back));
        BIO_ctrl(wb2, BIO_CTRL_INFO, 0, (char *)&second);
        second_len = BIO_ctrl(wb2, BIO_CTRL_PENDING, 0, NULL);
        printf("pem.ecparams.roundtrip.equal=%d\n",
               first_len == second_len && first_len > 0
                   && memcmp(first, second, (size_t)first_len) == 0);
        EC_GROUP_free(back);
        BIO_free(wb);
        BIO_free(wb2);
    }
    {
        FILE *f = tmpfile();
        EC_GROUP *back;
        printf("pem.ecparams.file.write.ret=%d\n", PEM_write_ECPKParameters(f, grp));
        rewind(f);
        back = PEM_read_ECPKParameters(f, NULL, NULL, NULL);
        printf("pem.ecparams.file.read.not_null=%d\n", back != NULL);
        EC_GROUP_free(back);
        fclose(f);
    }
    EC_GROUP_free(grp);

    /* ---- the RSA public-key writer and reader ---- */

    rsa = RSA_new();
    e = BN_new();
    BN_set_word(e, RSA_F4);
    printf("pem.rsa.gen=%d\n", RSA_generate_key_ex(rsa, 1024, e, NULL));
    {
        char *first = NULL;
        long first_len = 0;
        char *second = NULL;
        long second_len = 0;
        char *blk = NULL;
        BIO *wb = BIO_new(BIO_s_mem());
        BIO *wb2 = BIO_new(BIO_s_mem());
        RSA *back;
        printf("pem.rsapub.write.ret=%d\n", PEM_write_bio_RSAPublicKey(wb, rsa));
        BIO_ctrl(wb, BIO_CTRL_INFO, 0, (char *)&first);
        first_len = BIO_ctrl(wb, BIO_CTRL_PENDING, 0, NULL);
        printf("pem.rsapub.write.len_nonzero=%d\n", first_len > 0);
        BIO_ctrl(wb, BIO_CTRL_INFO, 0, (char *)&blk);
        back = PEM_read_bio_RSAPublicKey(BIO_new_mem_buf(blk, (int)first_len), NULL, NULL, NULL);
        printf("pem.rsapub.read.not_null=%d\n", back != NULL);
        printf("pem.rsapub.rewrite.ret=%d\n", PEM_write_bio_RSAPublicKey(wb2, back));
        BIO_ctrl(wb2, BIO_CTRL_INFO, 0, (char *)&second);
        second_len = BIO_ctrl(wb2, BIO_CTRL_PENDING, 0, NULL);
        printf("pem.rsapub.roundtrip.equal=%d\n",
               first_len == second_len && first_len > 0
                   && memcmp(first, second, (size_t)first_len) == 0);
        RSA_free(back);
        BIO_free(wb);
        BIO_free(wb2);
    }
    {
        FILE *f = tmpfile();
        RSA *back;
        printf("pem.rsapub.file.write.ret=%d\n", PEM_write_RSAPublicKey(f, rsa));
        rewind(f);
        back = PEM_read_RSAPublicKey(f, NULL, NULL, NULL);
        printf("pem.rsapub.file.read.not_null=%d\n", back != NULL);
        RSA_free(back);
        fclose(f);
    }

    /* ---- the private-key writers: width, header and round trip only ---- */

    private_write("rsapriv", "RSA PRIVATE KEY", rsa, 1, 0);
    private_write("rsapriv", "RSA PRIVATE KEY", rsa, 0, 0);

    DSA_generate_key(dsa);
    private_write("dsapriv", "DSA PRIVATE KEY", dsa, 1, 1);
    private_write("dsapriv", "DSA PRIVATE KEY", dsa, 0, 1);

    eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    printf("pem.ec.keygen=%d\n", EC_KEY_generate_key(eckey));
    private_write("ecpriv", "EC PRIVATE KEY", eckey, 1, 2);
    private_write("ecpriv", "EC PRIVATE KEY", eckey, 0, 2);

    /* ---- teardown ---- */

    RSA_free(rsa);
    BN_free(e);
    DSA_free(dsa);
    EC_KEY_free(eckey);
    DH_free(dh);
    printf("pem.done=1\n");
    return 0;
}
