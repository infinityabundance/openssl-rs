/*
 * rt_evp_legacy_probe.c -- RT-EVP-LEGACY: the Phase-13.6a legacy EVP AES method statics, driven.
 *
 * One C program, compiled once against the admitted authority and once against the candidate
 * distribution shell; the two transcripts are diffed line by line, keyed on `key=value`. Every
 * observation is a small integer, a fixed byte string printed as hex, or a fixed word -- never an
 * address, never a clock, never randomness, never the error queue.
 *
 * ## What this probe drives
 *
 * The forty-two `EVP_CIPHER` statics 13.6a lands -- the thirty-eight `EVP_aes_*` accessors of
 * `crypto/evp/e_aes.c` and the four `EVP_aes_*_cbc_hmac_sha*` of `crypto/evp/e_aes_cbc_hmac_sha1.c`
 * and `_sha256.c`. For each:
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

enum kind { PLAIN, GCM, CCM, OCB, WRAP };

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
        }
        snprintf(key, sizeof key, "%s.ct", name);
        out_hex(key, ct, ctlen);
        snprintf(key, sizeof key, "%s.rt", name);
        out_int(key, rt);
    }
    return 0;
}
