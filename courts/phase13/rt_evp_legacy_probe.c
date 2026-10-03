/*
 * rt_evp_legacy_probe.c -- RT-EVP-LEGACY: the Phase-13.6 legacy EVP method statics, driven.
 *
 * One C program, compiled once against the admitted authority and once against the candidate
 * distribution shell; the two transcripts are diffed line by line, keyed on `key=value`. Every
 * observation is a small integer, a fixed byte string printed as hex, or a fixed word -- never an
 * address, never a clock, never randomness, never the error queue.
 *
 * ## What this probe drives
 *
 * The one hundred and forty-two `EVP_CIPHER` statics 13.6 lands -- the thirty-eight `EVP_aes_*`
 * accessors of `crypto/evp/e_aes.c` and the four `EVP_aes_*_cbc_hmac_sha*` of
 * `crypto/evp/e_aes_cbc_hmac_sha1.c` and `_sha256.c` (13.6a), the twenty-seven `EVP_aria_*` of
 * `crypto/evp/e_aria.c` and the twenty-one `EVP_camellia_*` of `crypto/evp/e_camellia.c` (13.6b),
 * and the fifty-two of 13.6c: the six `EVP_des_*` of `crypto/evp/e_des.c`, the thirteen
 * `EVP_des_ede*` of `crypto/evp/e_des3.c`, the six `EVP_rc2_*` of `crypto/evp/e_rc2.c`, the five
 * `EVP_sm4_*` of `crypto/evp/e_sm4.c`, the four `EVP_bf_*`/`EVP_cast5_*`/`EVP_idea_*`/
 * `EVP_seed_*` of their units, the two `EVP_rc4*` of `crypto/evp/e_rc4.c`, the two
 * `EVP_chacha20*` of `crypto/evp/e_chacha20_poly1305.c`, `EVP_rc4_hmac_md5` and `EVP_desx_cbc`.
 * For each:
 *
 *   * the accessor's answer (`acc=`), and the object's `nid` derived short name (`name=`); the
 *     block size, key length, IV length and `flags` the object publishes (`bs=`, `kl=`, `ivl=`,
 *     `flags=`), read through the exported `EVP_CIPHER_get_*` accessors;
 *   * `EVP_get_cipherbyname(name)` (`pending.<name>.byname=`), which is the fetched-identity arm
 *     the later CPS/CMS/TS and OCSP courts name: the legacy `OBJ_NAME` cipher table is the
 *     authority's at `OPENSSL_init_crypto` and empty in this crate (13.1's recorded divergence),
 *     so the call runs but its answer is named `pending.` with that reason rather than compared.
 *   * a fixed-key, fixed-IV encrypt-then-decrypt round trip (`ct=` the ciphertext as hex,
 *     `rt=` 1 when the decrypted bytes equal the fixed plaintext). The statics are handed to
 *     `EVP_EncryptInit_ex`, which replaces a legacy method with its provider counterpart by short
 *     name, so the bytes are the Phase-8 provider row's on both sides -- exactly the observable
 *     `docs/PHASE-13-SUBPHASES.md` section 3.6 names.
 *
 * Three mode families need their own sequence and are driven accordingly: AEAD (GCM/CCM/OCB) with
 * a set IV length and a 16-byte tag, wrap/wrap-pad with `EVP_CIPHER_CTX_FLAG_WRAP_ALLOW`, and the
 * stitched CBC-HMAC statics as plain CBC (an unset TLS AAD leaves `payload_length` at its sentinel,
 * the authority's own "not TLS mode" arm).
 *
 * Subphase 13.6d adds the four deprecated `EVP_MD` statics -- `EVP_md4` and `EVP_mdc2` of
 * `crypto/evp/legacy_md4.c` and `legacy_mdc2.c`, `EVP_whirlpool` of `crypto/evp/legacy_wp.c` and
 * `EVP_sm3` of `crypto/sm3/legacy_sm3.c` -- and the two `crypto/evp/p_lib.c` names
 * `EVP_PKEY_set1_engine` and `EVP_PKEY_get0_engine`. For each digest it prints the accessor's
 * answer (`acc=`), the `nid`-derived short name (`name=`), the published `md_size`/`block_size`/
 * `type`/`flags` (`size=`, `bs=`, `type=`, `flags=`), and a fixed-input digest over `PT` as the
 * digest bytes and a success flag (`dg=`, `rt=`). `EVP_DigestInit_ex` replaces a legacy method
 * with its provider counterpart by `nid`-derived short name, so `EVP_sm3` -- the default
 * provider's row -- digests for real on both sides. `EVP_md4`, `EVP_mdc2` and `EVP_whirlpool` are
 * the **legacy provider's** rows and only the default provider is activated, so their init is
 * refused identically on both sides and their arm reports `rt=0` with an empty `dg=`; their
 * published fields are still compared. The two `p_lib.c` names are driven over a fresh
 * `EVP_PKEY` with the NULL engine, the only engine this link can hold: the accessor answers NULL,
 * the setter's clearing arm succeeds, and the accessor still answers NULL.
 *
 * ## What this probe does not do
 *
 * It never prints an address, so the fetched-identity divergence cannot leak into a comparison; it
 * never reads the error queue; it does not drive the TLS-record arms of the CBC-HMAC statics (the
 * `EVP_CTRL_AEAD_TLS1_AAD` setup), which `RT-CIPHER`'s `rt_cbchmac_records` arm already drives.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/objects.h>

static void out_int(const char *key, long v)
{
    printf("%s=%ld\n", key, v);
}

static void out_hex(const char *key, const unsigned char *p, int n)
{
    int i;
    printf("%s=", key);
    for (i = 0; i < n; i++)
        printf("%02x", p[i]);
    printf("\n");
}

enum kind { PLAIN, GCM, CCM, OCB, WRAP, WRAP_RANDOM };

typedef const EVP_CIPHER *(*ciph_fn)(void);

struct ent {
    const EVP_CIPHER *(*fn)(void);
    enum kind kind;
};

static const struct ent ENTRIES[] = {
    { EVP_aes_128_cbc, PLAIN }, { EVP_aes_128_ecb, PLAIN },
    { EVP_aes_128_ofb, PLAIN }, { EVP_aes_128_cfb128, PLAIN },
    { EVP_aes_128_cfb1, PLAIN }, { EVP_aes_128_cfb8, PLAIN },
    { EVP_aes_128_ctr, PLAIN }, { EVP_aes_128_gcm, GCM },
    { EVP_aes_128_ccm, CCM }, { EVP_aes_128_xts, PLAIN },
    { EVP_aes_128_ocb, OCB }, { EVP_aes_128_wrap, WRAP },
    { EVP_aes_128_wrap_pad, WRAP },
    { EVP_aes_192_cbc, PLAIN }, { EVP_aes_192_ecb, PLAIN },
    { EVP_aes_192_ofb, PLAIN }, { EVP_aes_192_cfb128, PLAIN },
    { EVP_aes_192_cfb1, PLAIN }, { EVP_aes_192_cfb8, PLAIN },
    { EVP_aes_192_ctr, PLAIN }, { EVP_aes_192_gcm, GCM },
    { EVP_aes_192_ccm, CCM }, { EVP_aes_192_ocb, OCB },
    { EVP_aes_192_wrap, WRAP }, { EVP_aes_192_wrap_pad, WRAP },
    { EVP_aes_256_cbc, PLAIN }, { EVP_aes_256_ecb, PLAIN },
    { EVP_aes_256_ofb, PLAIN }, { EVP_aes_256_cfb128, PLAIN },
    { EVP_aes_256_cfb1, PLAIN }, { EVP_aes_256_cfb8, PLAIN },
    { EVP_aes_256_ctr, PLAIN }, { EVP_aes_256_gcm, GCM },
    { EVP_aes_256_ccm, CCM }, { EVP_aes_256_xts, PLAIN },
    { EVP_aes_256_ocb, OCB }, { EVP_aes_256_wrap, WRAP },
    { EVP_aes_256_wrap_pad, WRAP },
    { EVP_aes_128_cbc_hmac_sha1, PLAIN }, { EVP_aes_256_cbc_hmac_sha1, PLAIN },
    { EVP_aes_128_cbc_hmac_sha256, PLAIN }, { EVP_aes_256_cbc_hmac_sha256, PLAIN },
    /* 13.6b: the ARIA statics of crypto/evp/e_aria.c -- the generic pack per key length, then GCM
     * and CCM. The AEAD statics are driven through the set-IV-length/tag sequence like AES's. */
    { EVP_aria_128_cbc, PLAIN }, { EVP_aria_128_ecb, PLAIN },
    { EVP_aria_128_ofb, PLAIN }, { EVP_aria_128_cfb128, PLAIN },
    { EVP_aria_128_cfb1, PLAIN }, { EVP_aria_128_cfb8, PLAIN },
    { EVP_aria_128_ctr, PLAIN }, { EVP_aria_128_gcm, GCM },
    { EVP_aria_128_ccm, CCM },
    { EVP_aria_192_cbc, PLAIN }, { EVP_aria_192_ecb, PLAIN },
    { EVP_aria_192_ofb, PLAIN }, { EVP_aria_192_cfb128, PLAIN },
    { EVP_aria_192_cfb1, PLAIN }, { EVP_aria_192_cfb8, PLAIN },
    { EVP_aria_192_ctr, PLAIN }, { EVP_aria_192_gcm, GCM },
    { EVP_aria_192_ccm, CCM },
    { EVP_aria_256_cbc, PLAIN }, { EVP_aria_256_ecb, PLAIN },
    { EVP_aria_256_ofb, PLAIN }, { EVP_aria_256_cfb128, PLAIN },
    { EVP_aria_256_cfb1, PLAIN }, { EVP_aria_256_cfb8, PLAIN },
    { EVP_aria_256_ctr, PLAIN }, { EVP_aria_256_gcm, GCM },
    { EVP_aria_256_ccm, CCM },
    /* 13.6b: the Camellia statics of crypto/evp/e_camellia.c -- the seven generic modes per key
     * length, all plain. */
    { EVP_camellia_128_cbc, PLAIN }, { EVP_camellia_128_ecb, PLAIN },
    { EVP_camellia_128_ofb, PLAIN }, { EVP_camellia_128_cfb128, PLAIN },
    { EVP_camellia_128_cfb1, PLAIN }, { EVP_camellia_128_cfb8, PLAIN },
    { EVP_camellia_128_ctr, PLAIN },
    { EVP_camellia_192_cbc, PLAIN }, { EVP_camellia_192_ecb, PLAIN },
    { EVP_camellia_192_ofb, PLAIN }, { EVP_camellia_192_cfb128, PLAIN },
    { EVP_camellia_192_cfb1, PLAIN }, { EVP_camellia_192_cfb8, PLAIN },
    { EVP_camellia_192_ctr, PLAIN },
    { EVP_camellia_256_cbc, PLAIN }, { EVP_camellia_256_ecb, PLAIN },
    { EVP_camellia_256_ofb, PLAIN }, { EVP_camellia_256_cfb128, PLAIN },
    { EVP_camellia_256_cfb1, PLAIN }, { EVP_camellia_256_cfb8, PLAIN },
    { EVP_camellia_256_ctr, PLAIN },
    /* 13.6c: the single-DES, 3DES/DESX, Blowfish, CAST5, IDEA, SEED, RC2, RC4, SM4, ChaCha20 and
     * RC4-HMAC-MD5 statics. The former legacy-provider-only families (single DES, DESX, BF, CAST5,
     * IDEA, SEED, RC2, RC4, RC4-HMAC-MD5) are fetched by short name and refused identically on both
     * sides -- the default provider does not publish them and only it is activated -- so their
     * round-trip arm reports `rt=0` with an empty ciphertext on both transcripts; the statics' own
     * fields are still compared. DES-EDE/EDE3, SM4 and ChaCha20 are the default provider's rows and
     * round-trip for real; DES-EDE3-WRAP and ChaCha20-Poly1305 keep their own sequences. */
    { EVP_des_cbc, PLAIN }, { EVP_des_cfb1, PLAIN }, { EVP_des_cfb64, PLAIN },
    { EVP_des_cfb8, PLAIN }, { EVP_des_ecb, PLAIN }, { EVP_des_ofb, PLAIN },
    { EVP_des_ede, PLAIN }, { EVP_des_ede3, PLAIN },
    { EVP_des_ede_cbc, PLAIN }, { EVP_des_ede_cfb64, PLAIN },
    { EVP_des_ede_ecb, PLAIN }, { EVP_des_ede_ofb, PLAIN },
    { EVP_des_ede3_cbc, PLAIN }, { EVP_des_ede3_cfb1, PLAIN },
    { EVP_des_ede3_cfb64, PLAIN }, { EVP_des_ede3_cfb8, PLAIN },
    { EVP_des_ede3_ecb, PLAIN }, { EVP_des_ede3_ofb, PLAIN },
    { EVP_des_ede3_wrap, WRAP_RANDOM },
    { EVP_desx_cbc, PLAIN },
    { EVP_bf_cbc, PLAIN }, { EVP_bf_cfb64, PLAIN }, { EVP_bf_ecb, PLAIN },
    { EVP_bf_ofb, PLAIN },
    { EVP_cast5_cbc, PLAIN }, { EVP_cast5_cfb64, PLAIN }, { EVP_cast5_ecb, PLAIN },
    { EVP_cast5_ofb, PLAIN },
    { EVP_idea_cbc, PLAIN }, { EVP_idea_cfb64, PLAIN }, { EVP_idea_ecb, PLAIN },
    { EVP_idea_ofb, PLAIN },
    { EVP_seed_cbc, PLAIN }, { EVP_seed_cfb128, PLAIN }, { EVP_seed_ecb, PLAIN },
    { EVP_seed_ofb, PLAIN },
    { EVP_rc2_cbc, PLAIN }, { EVP_rc2_cfb64, PLAIN }, { EVP_rc2_ecb, PLAIN },
    { EVP_rc2_ofb, PLAIN }, { EVP_rc2_40_cbc, PLAIN }, { EVP_rc2_64_cbc, PLAIN },
    { EVP_rc4, PLAIN }, { EVP_rc4_40, PLAIN }, { EVP_rc4_hmac_md5, PLAIN },
    { EVP_sm4_cbc, PLAIN }, { EVP_sm4_ecb, PLAIN }, { EVP_sm4_ofb, PLAIN },
    { EVP_sm4_cfb128, PLAIN }, { EVP_sm4_ctr, PLAIN },
    { EVP_chacha20, PLAIN }, { EVP_chacha20_poly1305, GCM },
};

#define PT_LEN 32

static unsigned char KEY[64];
static unsigned char IV[16];
static unsigned char PT[PT_LEN];

/* The plain and stitched round trip: EVP_Encrypt then EVP_Decrypt, one call each. */
static int rt_plain(const EVP_CIPHER *c, unsigned char *ct, int *ctlen)
{
    EVP_CIPHER_CTX *e = NULL, *d = NULL;
    unsigned char back[PT_LEN + 64];
    int l = 0, l2 = 0, ok = 0;

    e = EVP_CIPHER_CTX_new();
    d = EVP_CIPHER_CTX_new();
    if (e == NULL || d == NULL)
        goto done;
    if (EVP_EncryptInit_ex(e, c, NULL, KEY, IV) != 1)
        goto done;
    if (EVP_EncryptUpdate(e, ct, &l, PT, PT_LEN) != 1)
        goto done;
    if (EVP_EncryptFinal_ex(e, ct + l, &l2) != 1)
        goto done;
    *ctlen = l + l2;

    if (EVP_DecryptInit_ex(d, c, NULL, KEY, IV) != 1)
        goto done;
    if (EVP_DecryptUpdate(d, back, &l, ct, *ctlen) != 1)
        goto done;
    if (EVP_DecryptFinal_ex(d, back + l, &l2) != 1)
        goto done;
    ok = (l + l2 == PT_LEN) && (memcmp(back, PT, PT_LEN) == 0);

done:
    EVP_CIPHER_CTX_free(e);
    EVP_CIPHER_CTX_free(d);
    return ok;
}

/* The AEAD round trip with a twelve-byte IV and a sixteen-byte tag. */
static int rt_aead(const EVP_CIPHER *c, int ccm, unsigned char *ct, int *ctlen)
{
    EVP_CIPHER_CTX *e = NULL, *d = NULL;
    unsigned char tag[16], back[PT_LEN + 64];
    int l = 0, l2 = 0, ok = 0;
    int ivctl = ccm ? EVP_CTRL_CCM_SET_IVLEN : EVP_CTRL_AEAD_SET_IVLEN;
    int tagctl = ccm ? EVP_CTRL_CCM_SET_TAG : EVP_CTRL_AEAD_SET_TAG;

    e = EVP_CIPHER_CTX_new();
    d = EVP_CIPHER_CTX_new();
    if (e == NULL || d == NULL)
        goto done;

    if (EVP_EncryptInit_ex(e, c, NULL, NULL, NULL) != 1)
        goto done;
    if (EVP_CIPHER_CTX_ctrl(e, ivctl, 12, NULL) != 1)
        goto done;
    if (ccm && EVP_CIPHER_CTX_ctrl(e, EVP_CTRL_CCM_SET_TAG, 16, NULL) != 1)
        goto done;
    if (EVP_EncryptInit_ex(e, NULL, NULL, KEY, IV) != 1)
        goto done;
    if (ccm && EVP_EncryptUpdate(e, NULL, &l, NULL, PT_LEN) != 1)
        goto done;
    if (EVP_EncryptUpdate(e, ct, &l, PT, PT_LEN) != 1)
        goto done;
    if (EVP_EncryptFinal_ex(e, ct + l, &l2) != 1)
        goto done;
    *ctlen = l + l2;
    if (EVP_CIPHER_CTX_ctrl(e, tagctl, 16, tag) != 1)
        goto done;

    if (EVP_DecryptInit_ex(d, c, NULL, NULL, NULL) != 1)
        goto done;
    if (EVP_CIPHER_CTX_ctrl(d, ivctl, 12, NULL) != 1)
        goto done;
    if (EVP_CIPHER_CTX_ctrl(d, tagctl, 16, tag) != 1)
        goto done;
    if (EVP_DecryptInit_ex(d, NULL, NULL, KEY, IV) != 1)
        goto done;
    if (ccm && EVP_DecryptUpdate(d, NULL, &l, NULL, *ctlen) != 1)
        goto done;
    if (EVP_DecryptUpdate(d, back, &l, ct, *ctlen) != 1)
        goto done;
    ok = (EVP_DecryptFinal_ex(d, back + l, &l2) == 1)
        && (l + l2 == PT_LEN) && (memcmp(back, PT, PT_LEN) == 0);

done:
    EVP_CIPHER_CTX_free(e);
    EVP_CIPHER_CTX_free(d);
    return ok;
}

static int rt_wrap(const EVP_CIPHER *c, unsigned char *ct, int *ctlen)
{
    EVP_CIPHER_CTX *e = NULL, *d = NULL;
    unsigned char back[PT_LEN + 64];
    int l = 0, l2 = 0, ok = 0;

    e = EVP_CIPHER_CTX_new();
    d = EVP_CIPHER_CTX_new();
    if (e == NULL || d == NULL)
        goto done;
    EVP_CIPHER_CTX_set_flags(e, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
    EVP_CIPHER_CTX_set_flags(d, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
    if (EVP_EncryptInit_ex(e, c, NULL, KEY, IV) != 1)
        goto done;
    if (EVP_EncryptUpdate(e, ct, &l, PT, PT_LEN) != 1)
        goto done;
    l2 = 0;
    if (EVP_EncryptFinal_ex(e, ct + l, &l2) != 1)
        goto done;
    *ctlen = l + l2;

    if (EVP_DecryptInit_ex(d, c, NULL, KEY, IV) != 1)
        goto done;
    if (EVP_DecryptUpdate(d, back, &l, ct, *ctlen) != 1)
        goto done;
    if (EVP_DecryptFinal_ex(d, back + l, &l2) != 1)
        goto done;
    ok = (l + l2 == PT_LEN) && (memcmp(back, PT, PT_LEN) == 0);

done:
    EVP_CIPHER_CTX_free(e);
    EVP_CIPHER_CTX_free(d);
    return ok;
}

/* The fixed-input digest of `PT` under one static. Returns 1 and sets `*outlen` on success, 0 on
 * refusal -- which is what the three legacy-provider-only digests report here. */
static int rt_digest(const EVP_MD *md, unsigned char *out, unsigned int *outlen)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int ok = 0;

    *outlen = 0;
    if (ctx == NULL)
        return 0;
    if (EVP_DigestInit_ex(ctx, md, NULL) != 1)
        goto done;
    if (EVP_DigestUpdate(ctx, PT, PT_LEN) != 1)
        goto done;
    if (EVP_DigestFinal_ex(ctx, out, outlen) != 1)
        goto done;
    ok = 1;

done:
    EVP_MD_CTX_free(ctx);
    return ok;
}

/* 13.6d: the deprecated `EVP_MD` statics. Order is the authority units': legacy_md4, legacy_mdc2,
 * legacy_wp, then sm3. */
typedef const EVP_MD *(*md_fn)(void);

static const md_fn MD_ENTRIES[] = {
    EVP_md4, EVP_mdc2, EVP_whirlpool, EVP_sm3,
};

int main(void)
{
    size_t i;

    for (i = 0; i < sizeof(KEY); i++)
        KEY[i] = (unsigned char)i;
    for (i = 0; i < sizeof(IV); i++)
        IV[i] = (unsigned char)(0xf0 + i);
    for (i = 0; i < PT_LEN; i++)
        PT[i] = (unsigned char)i;

    for (i = 0; i < sizeof(ENTRIES) / sizeof(ENTRIES[0]); i++) {
        const struct ent *e = &ENTRIES[i];
        const EVP_CIPHER *c = e->fn();
        const char *name;
        unsigned char ct[PT_LEN + 64];
        int ctlen = 0, rt = 0, bnum;
        char key[64];

        if (c == NULL) {
            printf("entry%zu.acc=0\n", i);
            continue;
        }
        name = OBJ_nid2sn(EVP_CIPHER_get_nid(c));
        if (name == NULL)
            name = "NULL";

        snprintf(key, sizeof key, "%s.acc", name);
        out_int(key, 1);
        snprintf(key, sizeof key, "%s.bs", name);
        out_int(key, EVP_CIPHER_get_block_size(c));
        snprintf(key, sizeof key, "%s.kl", name);
        out_int(key, EVP_CIPHER_get_key_length(c));
        snprintf(key, sizeof key, "%s.ivl", name);
        out_int(key, EVP_CIPHER_get_iv_length(c));
        snprintf(key, sizeof key, "%s.flags", name);
        printf("%s=%lx\n", key, (unsigned long)EVP_CIPHER_get_flags(c));

        /* The fetched-identity arm. `EVP_get_cipherbyname` first reads the legacy `OBJ_NAME`
         * cipher table, which the authority fills at `OPENSSL_init_crypto` and this crate does
         * not yet populate (13.1's recorded divergence), so the *answer* is not comparable: it
         * is driven and named `pending.` rather than compared, the contract section 3.6 records. */
        bnum = EVP_get_cipherbyname(name) != NULL;
        (void)bnum;
        snprintf(key, sizeof key, "pending.%s.byname", name);
        printf("%s=%s\n", key, "legacy-OBJ_NAME-cipher-table-empty-in-candidate");

        memset(ct, 0, sizeof ct);
        switch (e->kind) {
        case PLAIN:
            rt = rt_plain(c, ct, &ctlen);
            break;
        case GCM:
        case OCB:
            rt = rt_aead(c, 0, ct, &ctlen);
            break;
        case CCM:
            rt = rt_aead(c, 1, ct, &ctlen);
            break;
        case WRAP:
            rt = rt_wrap(c, ct, &ctlen);
            break;
        case WRAP_RANDOM:
            /* The DES-EDE3 key-wrap construction draws its eight-byte IV with `RAND_bytes`
             * (`e_des3.c:375`, and the provider row likewise), so the ciphertext is not
             * deterministic and the round trip cannot be compared byte for byte. The accessor
             * and the object's fields above are still compared; this one value is named
             * `pending.` with the reason. */
            snprintf(key, sizeof key, "pending.%s.roundtrip", name);
            printf("%s=%s\n", key, "tdes-wrap-draws-a-random-iv");
            continue;
        }
        snprintf(key, sizeof key, "%s.ct", name);
        out_hex(key, ct, ctlen);
        snprintf(key, sizeof key, "%s.rt", name);
        out_int(key, rt);
    }

    /* 13.6d: the four deprecated `EVP_MD` statics. `EVP_DigestInit_ex` fetches the provider
     * counterpart by `nid`-derived short name, so `EVP_sm3` digests for real while the three
     * legacy-provider-only digests are refused identically on both sides. */
    for (i = 0; i < sizeof(MD_ENTRIES) / sizeof(MD_ENTRIES[0]); i++) {
        const EVP_MD *md = MD_ENTRIES[i]();
        const char *name;
        unsigned char dg[EVP_MAX_MD_SIZE];
        unsigned int dglen = 0;
        int rt;
        char key[64];

        if (md == NULL) {
            printf("mdentry%zu.acc=0\n", i);
            continue;
        }
        name = OBJ_nid2sn(EVP_MD_get_type(md));
        if (name == NULL)
            name = "NULL";

        snprintf(key, sizeof key, "%s.acc", name);
        out_int(key, 1);
        snprintf(key, sizeof key, "%s.size", name);
        out_int(key, EVP_MD_get_size(md));
        snprintf(key, sizeof key, "%s.bs", name);
        out_int(key, EVP_MD_get_block_size(md));
        snprintf(key, sizeof key, "%s.type", name);
        out_int(key, EVP_MD_get_type(md));
        snprintf(key, sizeof key, "%s.flags", name);
        printf("%s=%lx\n", key, (unsigned long)EVP_MD_get_flags(md));

        memset(dg, 0, sizeof dg);
        rt = rt_digest(md, dg, &dglen);
        snprintf(key, sizeof key, "%s.rt", name);
        out_int(key, rt);
        snprintf(key, sizeof key, "%s.dg", name);
        out_hex(key, dg, (int)dglen);
    }

    /* 13.6d: `crypto/evp/p_lib.c`'s engine remainder, over a fresh key and the NULL engine. The
     * accessor reads `pkey->engine` and the setter writes `pkey->pmeth_engine`, and both are NULL
     * on a key this link built. */
    {
        EVP_PKEY *k = EVP_PKEY_new();

        out_int("pkey.new", k != NULL);
        if (k != NULL) {
            out_int("pkey.get0_engine", EVP_PKEY_get0_engine(k) == NULL);
            out_int("pkey.set1_engine_null", EVP_PKEY_set1_engine(k, NULL));
            out_int("pkey.get0_engine_after", EVP_PKEY_get0_engine(k) == NULL);
            EVP_PKEY_free(k);
        }
    }
    return 0;
}
