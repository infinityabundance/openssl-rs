/*
 * RT-EVP-BIO -- `crypto/evp/encode.c`'s four base64 contexts and the four filter BIOs of
 * `crypto/evp/` that 7.5 lands.
 *
 * What this court observes
 * -----------------------
 *   * **the block codec.** `EVP_EncodeBlock` and `EVP_DecodeBlock` over every input length from 0
 *     to 9 and over a 64-byte buffer, as a **round trip against the probe's own bytes**: the
 *     encoded text is decoded again and compared with `memcmp`, so a wrong alphabet, a wrong
 *     padding rule or a wrong tail length is one bit rather than a plausible-looking string. The
 *     encoded text itself is printed for the 64-byte buffer, because that is what a reader needs
 *     when the bit is 0.
 *   * **the streaming codec's line discipline.** `EVP_EncodeUpdate`/`EVP_EncodeFinal` fed in
 *     chunks of 1, 47, 48, 49, 96 and 5000 bytes, with `EVP_ENCODE_CTX_num` read after *every*
 *     call -- the whole observable of "how much is held back" -- and the accumulated text decoded
 *     back and compared with the input. 48 is `EVP_EncodeInit`'s line length, so 47/48/49 is the
 *     boundary the encoder's `ctx->length - ctx->num > inl` test sits on.
 *   * **the decoder's four documented edges.** A 0-, 1-, 2- and 3-byte tail; embedded newlines and
 *     spaces; a buffer that ends exactly on a group boundary; and the **partial group refused**,
 *     which is the retry loop's `EVP_DecodeUpdate` answering `-1` once a `'-'` arrives in the
 *     middle of a group.
 *   * **the two "untouched" answers.** `EVP_EncodeUpdate` with `inl <= 0` answers 0 and leaves
 *     `*outl` exactly as the caller left it, and `EVP_DecodeUpdate` with `inl == 0` answers 0
 *     ("end of input") after decoding nothing. The probe sets a sentinel in `*outl` first, so
 *     "untouched" is observed rather than assumed.
 *   * **`EVP_ENCODE_CTX_copy`** as a real copy: the destination reports the source's `num`.
 *   * **`BIO_f_base64`** with and without `BIO_FLAGS_BASE64_NO_NL`, through a
 *     `BIO_new(BIO_s_mem())` pair: the bytes the filter produced are compared with the *encoded
 *     text the probe computed with the block codec*, and the decoded round trip is compared with
 *     the probe's own input. The line-skipping rule, the `'-'` soft end, `BIO_puts`, the
 *     `BIO_gets` refusal (the method has none), `BIO_CTRL_WPENDING` with a held-back group, and
 *     `BIO_CTRL_RESET` are all driven.
 *   * **`BIO_f_md`** for a two-part write whose digest the probe recomputes itself, over a digest
 *     *this probe's provider publishes*. That is not a convenience: the alternative is to arm the
 *     filter with `EVP_md_null()`, whose `origin` sends `EVP_DigestInit_ex` to
 *     `EVP_MD_fetch(NULL, "NULL", "")`, and the authority resolves that through its **default
 *     provider** while the candidate has none -- a distribution gap Phase 9 owns, not a
 *     behavioural difference this court may report. A fetched method has a provider, so the init
 *     never takes that path. The unarmed refusal is driven too, because `md_new` sets
 *     `BIO_set_init(bi, 1)` with no digest and `EVP_DigestUpdate` then answers 0.
 *   * **`BIO_f_cipher`** for an encrypt/decrypt round trip through `BIO_set_cipher` against the
 *     probe's own cipher: **both of `enc_read`'s arms** (a 300-byte read takes the
 *     `outl > ENC_MIN_CHUNK` arm and writes straight into the caller's buffer; a 16-byte one takes
 *     the buffered arm), the wrong-key case, a **refusal** (the provider refuses an all-zero key
 *     from `encrypt_init`, so `EVP_CipherInit_ex` refuses and `BIO_set_cipher` answers 0),
 *     `BIO_C_GET_CIPHER_STATUS`, `BIO_C_GET_CIPHER_CTX`, `BIO_CTRL_RESET` and `BIO_CTRL_FLUSH`.
 *   * **`BIO_set_cipher`'s callback bracket**: an `_ex` callback set with `BIO_set_callback_ex`
 *     records how many times it was called and with which direction, so the `BIO_CB_CTRL` /
 *     `BIO_CB_CTRL|BIO_CB_RETURN` pair is observed rather than asserted.
 *
 * What it cannot drive, with the coordinate
 * -----------------------------------------
 *   * **`BIO_f_reliable`** (`crypto/evp/bio_ok.c`) is **not built** by this crate. Its `sig_out`
 *     (`bio_ok.c:456`) fills the digest state with `RAND_bytes(md_data, md_size)`, and `RAND_bytes`
 *     is `rand.h`'s and Phase 9's. The line at the end of `main` is the whole observation this
 *     court can make of it, and `docs/DECISIONS.md` D194 names the blocker.
 *   * **`enc_read`'s `blocksize == 0` refusal** (`bio_enc.c:136`) needs a cipher whose
 *     `EVP_CIPHER_CTX_get_block_size` answers 0, which no provider in this profile publishes; it
 *     is named here rather than faked.
 *   * **`BIO_f_md`'s `BIO_C_SET_MD_CTX` arm** replaces the filter's data pointer with the
 *     caller's, so driving it would require the probe to own an `EVP_MD_CTX` afterwards and free
 *     it exactly once; the arm is named here and `BIO_C_GET_MD_CTX` is the half that is driven.
 *   * **`EVP_DecodeUpdate`'s `n >= 64` refusal** (`crypto/evp/encode.c:348-356`) needs a context
 *     whose `num` is already 64, and `EVP_ENCODE_CTX` is opaque in the installed header
 *     (`include/openssl/evp.h:901-914`), so no public call can build one and the arm is
 *     unreachable rather than awkward. The court drives the *reachable* half of the same guard --
 *     sixty-three saved characters take `EVP_ENCODE_CTX_num` to 63 and the sixty-fourth empties
 *     the buffer (`encode.c:361-370`) -- and prints the refusal's coordinate as a line.
 *
 * Addresses are never printed. Every observation is a return code, an integer this lane's own
 * headers define, a byte-for-byte comparison the probe performs itself, or a length.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>

static void sayn(const char *key, long long v)
{
    printf("%s=%lld err=%lu\n", key, v, ERR_peek_error());
    ERR_clear_error();
}

static void says(const char *key, const char *s)
{
    printf("%s=%s err=%lu\n", key, s == NULL ? "(null)" : s, ERR_peek_error());
    ERR_clear_error();
}

/* The value and then the *whole* error chain, reasons, data and raising coordinates. Used for the
 * refusal arms, because a refusal's code is a number this lane's headers define but its reason
 * string is what a reader checks it against. */
static void sayd(const char *key, long long v)
{
    unsigned long e;
    const char *file, *func, *data;
    int line, flags, first = 1;

    printf("%s=%lld chain=", key, v);
    while ((e = ERR_get_error_all(&file, &line, &func, &data, &flags)) != 0) {
        const char *rsn = ERR_reason_error_string(e);

        if (!first)
            printf(",");
        printf("%s", rsn == NULL ? "<no-string>" : rsn);
        if (data != NULL)
            printf("[%s]", data);
        printf("@%s/%d", func == NULL ? "<no-func>" : func, line);
        first = 0;
    }
    if (first)
        printf("<empty>");
    printf("\n");
    ERR_clear_error();
}

/* A deterministic byte pattern, so "the probe's own bytes" are reproducible across compilers. */
static void fill(unsigned char *p, int n)
{
    int i;

    for (i = 0; i < n; i++)
        p[i] = (unsigned char)((i * 7 + 3) & 0xff);
}

static int encoded_len(int n)
{
    return ((n + 2) / 3) * 4;
}

/* ---- the probe's provider: one digest and one cipher ------------------------------------- */

#define CT_MD_SIZE 32
#define CT_MD_BLOCK 64
#define CT_KEY_LEN 16
#define CT_IV_LEN 16
#define CT_BLOCK 16

struct ct_md_ctx {
    unsigned char s[CT_MD_SIZE];
    size_t len;
};

struct ct_ciph_ctx {
    unsigned char key[CT_KEY_LEN];
    unsigned char iv[CT_IV_LEN];
    int enc;
};

static int ct_md_new_calls, ct_md_init_calls, ct_md_update_calls, ct_md_final_calls;
static int ct_ciph_new_calls, ct_ciph_init_calls, ct_ciph_bad_key, ct_ciph_update_calls;
static int ct_ciph_final_calls;

static void *ct_md_newctx(void *provctx)
{
    struct ct_md_ctx *c;

    (void)provctx;
    c = calloc(1, sizeof *c);
    if (c != NULL)
        ct_md_new_calls++;
    return c;
}

static void ct_md_freectx(void *vctx)
{
    free(vctx);
}

static void *ct_md_dupctx(void *vctx)
{
    struct ct_md_ctx *c = vctx, *to;

    if (c == NULL)
        return NULL;
    to = malloc(sizeof *to);
    if (to != NULL)
        *to = *c;
    return to;
}

static int ct_md_init(void *vctx)
{
    struct ct_md_ctx *c = vctx;

    if (c == NULL)
        return 0;
    ct_md_init_calls++;
    memset(c->s, 0, sizeof c->s);
    c->len = 0;
    return 1;
}

/* A fold that is a function of every input byte *and* of its position, so a wrong pointer, a wrong
 * length or a lost part changes the digest rather than cancelling out. */
static int ct_md_update(void *vctx, const unsigned char *in, size_t inl)
{
    struct ct_md_ctx *c = vctx;
    size_t i;

    if (c == NULL || (in == NULL && inl != 0))
        return 0;
    ct_md_update_calls++;
    for (i = 0; i < inl; i++) {
        size_t at = (c->len + i) % CT_MD_SIZE;

        c->s[at] = (unsigned char)(c->s[at] + (unsigned char)(in[i] * 3 + (in[i] >> 1) + i));
    }
    c->len += inl;
    return 1;
}

static int ct_md_final(void *vctx, unsigned char *out, size_t *outl, size_t outsz)
{
    struct ct_md_ctx *c = vctx;
    size_t i;

    if (c == NULL || outl == NULL)
        return 0;
    ct_md_final_calls++;
    if (out == NULL) {
        *outl = CT_MD_SIZE;
        return 1;
    }
    if (outsz < CT_MD_SIZE)
        return 0;
    for (i = 0; i < CT_MD_SIZE; i++)
        out[i] = (unsigned char)(c->s[i] ^ (unsigned char)(c->len + i));
    *outl = CT_MD_SIZE;
    return 1;
}

static int ct_md_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, CT_MD_BLOCK))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, CT_MD_SIZE))
        return 0;
    return 1;
}

static const OSSL_PARAM *ct_md_gettable_params(void *provctx)
{
    static const OSSL_PARAM gettable[] = {
        OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_BLOCK_SIZE, NULL),
        OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, NULL),
        OSSL_PARAM_END
    };

    (void)provctx;
    return gettable;
}

static const OSSL_DISPATCH ct_md_fns[] = {
    { OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))ct_md_newctx },
    { OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))ct_md_freectx },
    { OSSL_FUNC_DIGEST_DUPCTX, (void (*)(void))ct_md_dupctx },
    { OSSL_FUNC_DIGEST_INIT, (void (*)(void))ct_md_init },
    { OSSL_FUNC_DIGEST_UPDATE, (void (*)(void))ct_md_update },
    { OSSL_FUNC_DIGEST_FINAL, (void (*)(void))ct_md_final },
    { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void))ct_md_get_params },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (void (*)(void))ct_md_gettable_params },
    { 0, NULL }
};

static void *ct_ciph_newctx(void *provctx)
{
    struct ct_ciph_ctx *c;

    (void)provctx;
    c = calloc(1, sizeof *c);
    if (c != NULL)
        ct_ciph_new_calls++;
    return c;
}

static void ct_ciph_freectx(void *vctx)
{
    free(vctx);
}

static void *ct_ciph_dupctx(void *vctx)
{
    struct ct_ciph_ctx *c = vctx, *to;

    if (c == NULL)
        return NULL;
    to = malloc(sizeof *to);
    if (to != NULL)
        *to = *c;
    return to;
}

/* The refusal: an all-zero key is refused, which is what makes `BIO_set_cipher` fail through a
 * *provider's* answer rather than through EVP's own argument checks. */
static int ct_ciph_init(void *vctx, const unsigned char *key, size_t keylen,
                        const unsigned char *iv, size_t ivlen, const OSSL_PARAM params[], int enc)
{
    struct ct_ciph_ctx *c = vctx;
    size_t i;
    int zero = 1;

    (void)params;
    if (c == NULL)
        return 0;
    ct_ciph_init_calls++;
    if (key != NULL) {
        for (i = 0; i < keylen && i < CT_KEY_LEN; i++) {
            if (key[i] != 0)
                zero = 0;
        }
        if (keylen != CT_KEY_LEN || zero) {
            ct_ciph_bad_key++;
            return 0;
        }
        memcpy(c->key, key, CT_KEY_LEN);
    }
    if (iv != NULL && ivlen == CT_IV_LEN)
        memcpy(c->iv, iv, CT_IV_LEN);
    c->enc = enc;
    return 1;
}

static int ct_ciph_encrypt_init(void *vctx, const unsigned char *key, size_t keylen,
                                const unsigned char *iv, size_t ivlen, const OSSL_PARAM params[])
{
    return ct_ciph_init(vctx, key, keylen, iv, ivlen, params, 1);
}

static int ct_ciph_decrypt_init(void *vctx, const unsigned char *key, size_t keylen,
                                const unsigned char *iv, size_t ivlen, const OSSL_PARAM params[])
{
    return ct_ciph_init(vctx, key, keylen, iv, ivlen, params, 0);
}

/* A byte-wise keystream, stateless: the same call encrypts and decrypts, so a round trip is the
 * observation and a wrong key is a *different* answer rather than a refusal. */
static int ct_ciph_update(void *vctx, unsigned char *out, size_t *outl, size_t outsz,
                          const unsigned char *in, size_t inl)
{
    struct ct_ciph_ctx *c = vctx;
    size_t i;

    if (c == NULL || outl == NULL)
        return 0;
    ct_ciph_update_calls++;
    if (inl > outsz)
        return 0;
    for (i = 0; i < inl; i++)
        out[i] = (unsigned char)(in[i] ^ c->key[(i + c->iv[0]) % CT_KEY_LEN] ^ c->iv[1]);
    *outl = inl;
    return 1;
}

static int ct_ciph_final(void *vctx, unsigned char *out, size_t *outl, size_t outsz)
{
    (void)vctx;
    (void)out;
    (void)outsz;
    if (outl == NULL)
        return 0;
    ct_ciph_final_calls++;
    *outl = 0;
    return 1;
}

static int ct_ciph_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, CT_BLOCK))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, CT_KEY_LEN))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, CT_IV_LEN))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
    if (p != NULL && !OSSL_PARAM_set_uint(p, EVP_CIPH_CBC_MODE))
        return 0;
    return 1;
}

static const OSSL_PARAM *ct_ciph_gettable_params(void *provctx)
{
    static const OSSL_PARAM gettable[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_MODE, NULL),
        OSSL_PARAM_END
    };

    (void)provctx;
    return gettable;
}

/* The four context-parameter callbacks. `EVP_CipherInit_ex` reads the context's own parameters
 * after `encrypt_init`, and a provider that publishes none makes `geterr` raise
 * `EVP_R_CANNOT_GET_PARAMETERS` -- which is what the first draft of this provider measured. The
 * answers are the values this cipher has: padding on, one block of key and IV, no counter. */
static int ct_ciph_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    unsigned int padding = 1, num = 0;

    (void)vctx;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_PADDING);
    if (p != NULL && !OSSL_PARAM_set_uint(p, padding))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, CT_KEY_LEN))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, CT_IV_LEN))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_NUM);
    if (p != NULL && !OSSL_PARAM_set_uint(p, num))
        return 0;
    return 1;
}

static int ct_ciph_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    struct ct_ciph_ctx *c = vctx;
    const OSSL_PARAM *p;
    unsigned int padding = 0, num = 0;

    (void)c;
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_PADDING);
    if (p != NULL && !OSSL_PARAM_get_uint(p, &padding))
        return 0;
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_NUM);
    if (p != NULL && !OSSL_PARAM_get_uint(p, &num))
        return 0;
    return 1;
}

static const OSSL_PARAM *ct_ciph_gettable_ctx_params(void *vctx, void *provctx)
{
    static const OSSL_PARAM gettable[] = {
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_NUM, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
        OSSL_PARAM_END
    };

    (void)vctx;
    (void)provctx;
    return gettable;
}

static const OSSL_PARAM *ct_ciph_settable_ctx_params(void *vctx, void *provctx)
{
    static const OSSL_PARAM settable[] = {
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, NULL),
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_NUM, NULL),
        OSSL_PARAM_END
    };

    (void)vctx;
    (void)provctx;
    return settable;
}

static const OSSL_DISPATCH ct_ciph_fns[] = {
    { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))ct_ciph_newctx },
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))ct_ciph_freectx },
    { OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void))ct_ciph_dupctx },
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))ct_ciph_encrypt_init },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))ct_ciph_decrypt_init },
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))ct_ciph_update },
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))ct_ciph_final },
    { OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))ct_ciph_get_params },
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (void (*)(void))ct_ciph_gettable_params },
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void))ct_ciph_get_ctx_params },
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (void (*)(void))ct_ciph_set_ctx_params },
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))ct_ciph_gettable_ctx_params },
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))ct_ciph_settable_ctx_params },
    { 0, NULL }
};

static const OSSL_ALGORITHM ct_digests[] = {
    { "COURT-BIO-MD", "provider=court-bio", ct_md_fns, "the two-part fold this probe recomputes" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM ct_ciphers[] = {
    { "COURT-BIO-CIPH", "provider=court-bio", ct_ciph_fns,
      "a stateless keystream that refuses an all-zero key" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *ct_query(void *provctx, int operation_id, int *no_cache)
{
    (void)provctx;
    *no_cache = 0;
    if (operation_id == OSSL_OP_DIGEST)
        return ct_digests;
    if (operation_id == OSSL_OP_CIPHER)
        return ct_ciphers;
    return NULL;
}

static const OSSL_DISPATCH ct_provider_fns[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))ct_query },
    { 0, NULL }
};

static int ct_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
                            const OSSL_DISPATCH **out, void **provctx)
{
    (void)handle;
    (void)in;
    *provctx = &ct_md_new_calls;
    *out = ct_provider_fns;
    return 1;
}

/* ---- the block codec, as a round trip ---- */

static void block_round_trips(void)
{
    unsigned char src[80], enc[128], back[128];
    int n;

    fill(src, (int)sizeof(src));
    for (n = 0; n <= 9; n++) {
        int el = EVP_EncodeBlock(enc, src, n);
        int dl = EVP_DecodeBlock(back, enc, el);
        char key[64];
        int ok;

        /* `EVP_DecodeBlock` passes `eof == 0`, so the padding is *not* removed: a padded group
         * answers three bytes for a one-byte tail and the tail bytes are unspecified. The
         * comparison is therefore on the input's own length. */
        ok = el == encoded_len(n)
             && dl >= 3 * (el / 4) - 3
             && dl <= 3 * (el / 4)
             && (n == 0 || memcmp(back, src, (size_t)n) == 0);
        snprintf(key, sizeof(key), "encode.block.%d", n);
        printf("%s.len=%d dec=%d roundtrip=%d err=%lu\n", key, el, dl, ok, 0UL);
        ERR_clear_error();
    }

    {
        int el = EVP_EncodeBlock(enc, src, 64);
        int dl = EVP_DecodeBlock(back, enc, el);

        sayn("encode.block.64.len", el);
        sayn("encode.block.64.dec", dl);
        sayn("encode.block.64.roundtrip", dl >= 64 && memcmp(back, src, 64) == 0);
        says("encode.block.64.text", (const char *)enc);
    }

    sayn("decode.block.garbage", EVP_DecodeBlock(back, (const unsigned char *)"!!!!", 4));
    sayn("decode.block.partial", EVP_DecodeBlock(back, (const unsigned char *)"YWJ", 3));
    sayn("decode.block.empty", EVP_DecodeBlock(back, (const unsigned char *)"", 0));
    sayn("decode.block.leading_ws", EVP_DecodeBlock(back, (const unsigned char *)" YWJjZA==", 10));
    sayn("decode.block.inner_ws", EVP_DecodeBlock(back, (const unsigned char *)"YW JjZA==", 9));
    sayn("decode.block.high_bit",
         EVP_DecodeBlock(back, (const unsigned char *)"\xff\xff\xff\xff", 4));
    sayn("decode.block.padding_with_data",
         EVP_DecodeBlock(back, (const unsigned char *)"YQ==YQ==", 8));
}

/* ---- the streaming codec's line discipline ---- */

static void streaming_chunks(int chunk)
{
    unsigned char src[6000], enc[9000], back[9000];
    EVP_ENCODE_CTX *c = EVP_ENCODE_CTX_new();
    int total = 0, off = 0, outl = 0, nums[8], nnums = 0, rv = 0;
    char key[64];

    fill(src, (int)sizeof(src));
    EVP_EncodeInit(c);
    nums[nnums++] = EVP_ENCODE_CTX_num(c);
    while (off < 5000) {
        int n = 5000 - off < chunk ? 5000 - off : chunk;

        if (EVP_EncodeUpdate(c, enc + total, &outl, src + off, n) != 1)
            rv = -1;
        total += outl;
        off += n;
        if (nnums < 8)
            nums[nnums++] = EVP_ENCODE_CTX_num(c);
    }
    EVP_EncodeFinal(c, enc + total, &outl);
    total += outl;

    snprintf(key, sizeof(key), "encode.stream.%d", chunk);
    printf("%s.bytes=%d ok=%d num_first=%d num_last=%d err=%lu\n", key, total, rv == 0, nums[0],
           nums[nnums - 1], 0UL);
    ERR_clear_error();

    {
        EVP_ENCODE_CTX *d = EVP_ENCODE_CTX_new();
        int dl = 0, got = 0;

        EVP_DecodeInit(d);
        rv = EVP_DecodeUpdate(d, back, &dl, enc, total);
        got = dl;
        {
            int tl = 0;

            if (EVP_DecodeFinal(d, back + got, &tl) < 0)
                rv = -1;
            got += tl;
        }
        snprintf(key, sizeof(key), "decode.stream.%d", chunk);
        printf("%s.rv=%d bytes=%d roundtrip=%d err=%lu\n", key, rv, got,
               got == 5000 && memcmp(back, src, 5000) == 0, 0UL);
        ERR_clear_error();
        EVP_ENCODE_CTX_free(d);
    }
    {
        EVP_ENCODE_CTX *a = EVP_ENCODE_CTX_new();
        EVP_ENCODE_CTX *b = EVP_ENCODE_CTX_new();
        int al = 0;

        EVP_EncodeInit(a);
        (void)EVP_EncodeUpdate(a, enc, &al, src, 5);
        snprintf(key, sizeof(key), "encode.copy.%d", chunk);
        printf("%s.rv=%d src_num=%d dst_num=%d err=%lu\n", key, EVP_ENCODE_CTX_copy(b, a),
               EVP_ENCODE_CTX_num(a), EVP_ENCODE_CTX_num(b), 0UL);
        ERR_clear_error();
        EVP_ENCODE_CTX_free(a);
        EVP_ENCODE_CTX_free(b);
    }
    EVP_ENCODE_CTX_free(c);
}

/* ---- the decoder's edges ---- */

static void decoder_edges(void)
{
    EVP_ENCODE_CTX *c = EVP_ENCODE_CTX_new();
    unsigned char out[64], back[64];
    int outl = 999, el, rv, i;

    EVP_EncodeInit(c);
    outl = 999;
    sayn("encode.update.neg", EVP_EncodeUpdate(c, out, &outl, (const unsigned char *)"ab", -1));
    sayn("encode.update.neg.outl", outl);
    outl = 999;
    sayn("encode.update.zero", EVP_EncodeUpdate(c, out, &outl, (const unsigned char *)"ab", 0));
    sayn("encode.update.zero.outl", outl);

    outl = 999;
    EVP_EncodeFinal(c, out, &outl);
    sayn("encode.final.empty.outl", outl);

    EVP_DecodeInit(c);
    outl = 999;
    sayn("decode.update.zero", EVP_DecodeUpdate(c, out, &outl, (const unsigned char *)"", 0));
    sayn("decode.update.zero.outl", outl);

    for (i = 0; i <= 3; i++) {
        char key[64];

        EVP_DecodeInit(c);
        el = EVP_EncodeBlock(out, (const unsigned char *)"abcd", 4);
        outl = 0;
        rv = EVP_DecodeUpdate(c, back, &outl, out, el - i);
        snprintf(key, sizeof(key), "decode.tail.%d", i);
        printf("%s.update=%d outl=%d num=%d final=%d err=%lu\n", key, rv, outl,
               EVP_ENCODE_CTX_num(c), EVP_DecodeFinal(c, back + outl, &outl), 0UL);
        ERR_clear_error();
    }

    EVP_DecodeInit(c);
    outl = 0;
    sayn("decode.ws.update",
         EVP_DecodeUpdate(c, back, &outl, (const unsigned char *)"YW\nJj ZA==", 10));
    sayn("decode.ws.outl", outl);

    EVP_DecodeInit(c);
    outl = 0;
    sayn("decode.boundary.update",
         EVP_DecodeUpdate(c, back, &outl, (const unsigned char *)"YWJjZA==", 8));
    sayn("decode.boundary.outl", outl);
    sayn("decode.boundary.num", EVP_ENCODE_CTX_num(c));

    EVP_DecodeInit(c);
    outl = 0;
    sayn("decode.partial.first",
         EVP_DecodeUpdate(c, back, &outl, (const unsigned char *)"YWJ", 3));
    sayn("decode.partial.num", EVP_ENCODE_CTX_num(c));
    outl = 0;
    sayn("decode.partial.then_eof",
         EVP_DecodeUpdate(c, back, &outl, (const unsigned char *)"-", 1));

    EVP_DecodeInit(c);
    outl = 0;
    sayn("decode.after_pad.update",
         EVP_DecodeUpdate(c, back, &outl, (const unsigned char *)"YQ==YQ==", 8));
    sayn("decode.after_pad.outl", outl);

    EVP_DecodeInit(c);
    outl = 0;
    sayn("decode.high_bit.update",
         EVP_DecodeUpdate(c, back, &outl, (const unsigned char *)"\x80\x80\x80\x80", 4));

    /* A `'-'` in the middle of a *complete* group is a soft end: the group is decoded and the
     * answer is 0. */
    EVP_DecodeInit(c);
    outl = 0;
    sayn("decode.seof_after_group.update",
         EVP_DecodeUpdate(c, back, &outl, (const unsigned char *)"YWJjZA==-", 9));
    sayn("decode.seof_after_group.outl", outl);

    /* The reset at exactly sixty-four saved characters is the *reachable* half of the refusal
     * below it (`crypto/evp/encode.c:361-370`): a caller can drive `num` up to 63 through the
     * public API and no further, because the sixty-fourth character empties the buffer. The
     * refusal itself (`crypto/evp/encode.c:348-356`) needs a context whose `num` is already 64,
     * and `EVP_ENCODE_CTX` is opaque in the installed header (`include/openssl/evp.h:901-914`),
     * so no probe can reach it and the line below says so rather than implying coverage. */
    EVP_DecodeInit(c);
    {
        unsigned char raw[48], enc[128], dec[96];
        int n64, k;

        for (k = 0; k < 48; k++)
            raw[k] = (unsigned char)k;
        n64 = EVP_EncodeBlock(enc, raw, 48);
        outl = 0;
        sayn("decode.reset64.first63", EVP_DecodeUpdate(c, dec, &outl, enc, 63));
        sayn("decode.reset64.num", EVP_ENCODE_CTX_num(c));
        outl = 0;
        sayn("decode.reset64.plus1", EVP_DecodeUpdate(c, dec, &outl, enc + 63, 1));
        sayn("decode.reset64.outl", outl);
        sayn("decode.reset64.num_after", EVP_ENCODE_CTX_num(c));
        sayn("decode.reset64.enc_len", n64);
    }
    printf("decode.num_ge_64=NOT_MEASURED_CONTEXT_IS_OPAQUE_encode_c_348\n");

    EVP_ENCODE_CTX_free(c);
}

/* ---- `BIO_f_base64` ---- */

static const unsigned char B64_INPUT[40] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
    0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
    0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
    0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27
};

static void b64_filter(int no_nl)
{
    BIO *mem = BIO_new(BIO_s_mem());
    BIO *b64 = BIO_new(BIO_f_base64());
    unsigned char expected[128], back[128];
    char key[64];
    int el;

    if (no_nl)
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    BIO_push(b64, mem);
    sayn(no_nl ? "b64.nonl.type" : "b64.type", BIO_method_type(b64) == BIO_TYPE_BASE64);

    snprintf(key, sizeof(key), no_nl ? "b64.nonl.write1" : "b64.write1");
    sayn(key, BIO_write(b64, B64_INPUT, 17));
    snprintf(key, sizeof(key), no_nl ? "b64.nonl.write2" : "b64.write2");
    sayn(key, BIO_write(b64, B64_INPUT + 17, 23));

    snprintf(key, sizeof(key), no_nl ? "b64.nonl.wpending" : "b64.wpending");
    sayn(key, BIO_ctrl(b64, BIO_CTRL_WPENDING, 0, NULL));

    snprintf(key, sizeof(key), no_nl ? "b64.nonl.flush" : "b64.flush");
    sayn(key, BIO_ctrl(b64, BIO_CTRL_FLUSH, 0, NULL));

    snprintf(key, sizeof(key), no_nl ? "b64.nonl.gets" : "b64.gets");
    sayn(key, BIO_gets(b64, (char *)back, 4));

    el = EVP_EncodeBlock(expected, B64_INPUT, 40);
    if (!no_nl) {
        /* The streaming encoder wraps at 48 input bytes; forty is one line and the trailing
         * newline is `EVP_EncodeFinal`'s. */
        expected[el++] = '\n';
    }
    {
        char *p = NULL;
        long have = BIO_get_mem_data(mem, &p);
        char cmpkey[64];

        snprintf(cmpkey, sizeof(cmpkey), no_nl ? "b64.nonl.produced" : "b64.produced");
        printf("%s.len=%ld matches_block=%d err=%lu\n", cmpkey, have,
               have == el && p != NULL && memcmp(p, expected, (size_t)el) == 0, 0UL);
        ERR_clear_error();
    }

    {
        BIO *rmem = BIO_new(BIO_s_mem());
        BIO *rb64 = BIO_new(BIO_f_base64());
        int n, n2;

        if (no_nl)
            BIO_set_flags(rb64, BIO_FLAGS_BASE64_NO_NL);
        BIO_write(rmem, expected, el);
        BIO_push(rb64, rmem);
        memset(back, 0, sizeof(back));
        /* Read in two parts, so the filter's own buffered-decoded path is exercised: the first
         * read is shorter than the whole and the second drains what is left. */
        n = BIO_read(rb64, back, 16);
        n2 = BIO_read(rb64, back + n, (int)(sizeof(back) - (size_t)n));
        snprintf(key, sizeof(key), no_nl ? "b64.nonl.parts" : "b64.parts");
        printf("%s.first=%d total=%d roundtrip=%d eof=%ld err=%lu\n", key, n, n + n2,
               n + n2 == 40 && memcmp(back, B64_INPUT, 40) == 0,
               BIO_ctrl(rb64, BIO_CTRL_EOF, 0, NULL), 0UL);
        ERR_clear_error();
        BIO_free_all(rb64);
    }

    snprintf(key, sizeof(key), no_nl ? "b64.nonl.reset" : "b64.reset");
    sayn(key, BIO_ctrl(b64, BIO_CTRL_RESET, 0, NULL));
    snprintf(key, sizeof(key), no_nl ? "b64.nonl.pending_after_reset" : "b64.pending_after_reset");
    sayn(key, BIO_ctrl(b64, BIO_CTRL_PENDING, 0, NULL));
    BIO_free_all(b64);
}

static void b64_leading_lines(void)
{
    BIO *mem = BIO_new(BIO_s_mem());
    BIO *b64 = BIO_new(BIO_f_base64());
    unsigned char back[64];
    int n;

    /* A leading line with a character that is *not* base64 is skipped: `EVP_DecodeUpdate` answers
     * `-1` with nothing decoded, which is the `k <= 0 && num == 0` arm of the start scan. */
    BIO_write(mem, "!!!!\n", 5);
    BIO_write(mem, "YWJjZA==\n", 9);
    BIO_write(mem, "-----END-----\n", 14);
    BIO_push(b64, mem);
    memset(back, 0, sizeof(back));
    n = BIO_read(b64, back, (int)sizeof(back));
    printf("b64.leading_invalid.bytes=%d value=%s err=%lu\n", n,
           n == 4 && memcmp(back, "abcd", 4) == 0 ? "abcd" : "?", 0UL);
    ERR_clear_error();
    BIO_free_all(b64);
}

/* The other half of the same rule, and it is the surprising one: a line whose characters are all
 * base64 *or whitespace* is **accepted** as the start of content -- whitespace is skipped by the
 * decoder, so `"not base64"` decodes to ten characters and `EVP_DecodeUpdate` answers 1. The
 * filter then fails on the content that follows. This is the authority's own behaviour and the
 * arm that makes `sanitize_line`'s three rules distinguishable from the start scan's. */
static void b64_leading_whitespace_line(void)
{
    BIO *mem = BIO_new(BIO_s_mem());
    BIO *b64 = BIO_new(BIO_f_base64());
    unsigned char back[64];
    int n;

    BIO_write(mem, "not base64\n", 11);
    BIO_write(mem, "YWJjZA==\n", 9);
    BIO_write(mem, "-----END-----\n", 14);
    BIO_push(b64, mem);
    memset(back, 0, sizeof(back));
    n = BIO_read(b64, back, (int)sizeof(back));
    printf("b64.leading_mixed.bytes=%d err=%lu\n", n, 0UL);
    ERR_clear_error();
    BIO_free_all(b64);
}

static void b64_no_nl_tail_split(void)
{
    BIO *mem = BIO_new(BIO_s_mem());
    BIO *b64 = BIO_new(BIO_f_base64());
    unsigned char expected[32];
    char *p = NULL;
    long have;
    int el;

    /* With `NO_NL` a one- or two-byte write is held in the filter's `tmp` and encoded by the
     * flush; a write of exactly three goes straight through. */
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, mem);
    sayn("b64.nonl.tail.write1", BIO_write(b64, B64_INPUT, 1));
    sayn("b64.nonl.tail.write2", BIO_write(b64, B64_INPUT + 1, 2));
    sayn("b64.nonl.tail.write3", BIO_write(b64, B64_INPUT + 3, 3));
    sayn("b64.nonl.tail.wpending", BIO_ctrl(b64, BIO_CTRL_WPENDING, 0, NULL));
    sayn("b64.nonl.tail.flush", BIO_ctrl(b64, BIO_CTRL_FLUSH, 0, NULL));
    el = EVP_EncodeBlock(expected, B64_INPUT, 6);
    have = BIO_get_mem_data(mem, &p);
    printf("b64.nonl.tail.produced.len=%ld matches_block=%d err=%lu\n", have,
           have == el && p != NULL && memcmp(p, expected, (size_t)el) == 0, 0UL);
    ERR_clear_error();
    BIO_free_all(b64);
}

/* ---- `BIO_f_md` ---- */

static void md_filter(EVP_MD *md_method)
{
    BIO *mem = BIO_new(BIO_s_mem());
    BIO *md = BIO_new(BIO_f_md());
    unsigned char got[64], own[64];
    unsigned int ownlen = 0;
    EVP_MD_CTX *ref = EVP_MD_CTX_new();

    BIO_push(md, mem);

    /* The method has no `puts` slot, so `BIO_puts` refuses at the BIO layer. */
    sayn("md.puts", BIO_puts(md, "x"));

    /* Unarmed: `md_new` set `init` but no digest, so the fold is refused with 0 while the bytes
     * still reach the memory BIO. */
    sayn("md.unarmed.write", BIO_write(md, B64_INPUT, 10));
    sayn("md.unarmed.gets", BIO_gets(md, (char *)got, (int)sizeof(got)));
    {
        const EVP_MD *m = NULL;

        sayn("md.get_md.unarmed", BIO_ctrl(md, BIO_C_GET_MD, 0, &m));
        sayn("md.get_md.unarmed.null", m == NULL);
    }

    if (md_method != NULL) {
        sayd("md.set_md", BIO_ctrl(md, BIO_C_SET_MD, 0, (void *)md_method));
        sayn("md.write1", BIO_write(md, B64_INPUT, 17));
        sayn("md.write2", BIO_write(md, B64_INPUT + 17, 23));

        /* The two parts in a context of the probe's own: the filter's `BIO_gets` answer and this
         * one must be the same bytes. */
        (void)EVP_DigestInit_ex(ref, md_method, NULL);
        (void)EVP_DigestUpdate(ref, B64_INPUT, 17);
        (void)EVP_DigestUpdate(ref, B64_INPUT + 17, 23);
        memset(own, 0, sizeof(own));
        (void)EVP_DigestFinal_ex(ref, own, &ownlen);

        memset(got, 0, sizeof(got));
        {
            int n = BIO_gets(md, (char *)got, (int)sizeof(got));

            printf("md.gets.n=%d own=%u agree=%d err=%lu\n", n, ownlen,
                   n == (int)ownlen && memcmp(got, own, (size_t)ownlen) == 0, 0UL);
            ERR_clear_error();
        }

        /* A `size` below the digest's length refuses without touching the digest. */
        sayn("md.gets.short", BIO_gets(md, (char *)got, 8));
    }

    {
        EVP_MD_CTX *c = NULL;

        sayn("md.get_md_ctx", BIO_ctrl(md, BIO_C_GET_MD_CTX, 0, &c));
        sayn("md.get_md_ctx.nonnull", c != NULL);
    }

    if (md_method != NULL) {
        /* `BIO_CTRL_RESET` re-arms the digest the filter already holds, so the second digest is
         * of the second write alone. */
        sayn("md.reset", BIO_ctrl(md, BIO_CTRL_RESET, 0, NULL));
        sayn("md.after_reset.write", BIO_write(md, B64_INPUT + 17, 23));
        memset(own, 0, sizeof(own));
        ownlen = 0;
        (void)EVP_DigestInit_ex(ref, md_method, NULL);
        (void)EVP_DigestUpdate(ref, B64_INPUT + 17, 23);
        (void)EVP_DigestFinal_ex(ref, own, &ownlen);
        memset(got, 0, sizeof(got));
        {
            int n = BIO_gets(md, (char *)got, (int)sizeof(got));

            printf("md.after_reset.gets.n=%d own=%u agree=%d err=%lu\n", n, ownlen,
                   n == (int)ownlen && memcmp(got, own, (size_t)ownlen) == 0, 0UL);
            ERR_clear_error();
        }
    }

    /* `BIO_dup_chain` re-creates every BIO through its method's `create` and never issues
     * `BIO_CTRL_DUP`, so the duplicate's filter holds a **fresh, unarmed** context -- which is why
     * the write below refuses exactly as the unarmed arm at the top of this function does. The
     * control itself is driven separately, below. */
    {
        BIO *dup = BIO_dup_chain(md);
        int n = -99;

        printf("md.dup_chain.nonnull=%d\n", dup != NULL);
        ERR_clear_error();
        if (dup != NULL) {
            unsigned char dgot[64];

            memset(dgot, 0, sizeof(dgot));
            sayn("md.dup_chain.write", BIO_write(dup, B64_INPUT, 10));
            n = BIO_gets(dup, (char *)dgot, (int)sizeof(dgot));
            BIO_free_all(dup);
        }
        sayn("md.dup_chain.gets", n);
    }

    /* `BIO_CTRL_DUP` is the control a chain duplicate *used* to issue: it copies the source's
     * context **into the destination's** (`dbio = ptr`, `dctx = BIO_get_data(dbio)`), and it sets
     * `BIO_set_init` on the `b` argument rather than on `dbio` -- the authority's own asymmetry,
     * and the reason the copy is driven with the source as `b`. */
    if (md_method != NULL) {
        BIO *dup = BIO_new(BIO_f_md());
        unsigned char dgot[64];
        int n;

        BIO_push(dup, BIO_new(BIO_s_mem()));
        sayn("md.dup_ctl", BIO_ctrl(md, BIO_CTRL_DUP, 0, dup));
        memset(dgot, 0, sizeof(dgot));
        n = BIO_gets(dup, (char *)dgot, (int)sizeof(dgot));
        /* The source was finalised by the `md.after_reset.gets` arm above, and the copy carries
         * `EVP_MD_CTX_FLAG_FINALISED` with it -- so the *copy* is what the flag refuses, and the
         * two lanes answer the same `-1`. Re-arming the source first would have produced a digest
         * instead; this arm is worth more, because the flag is otherwise invisible. */
        printf("md.dup_ctl.gets.n=%d copies_the_finalised_flag=%d err=%lu\n", n, n == -1, 0UL);
        ERR_clear_error();
        BIO_free_all(dup);
    }

    EVP_MD_CTX_free(ref);
    sayn("md.pending", BIO_ctrl(md, BIO_CTRL_PENDING, 0, NULL));
    BIO_free_all(md);
}

/* ---- `BIO_f_cipher` and `BIO_set_cipher` ---- */

static int cb_calls = 0;
static long cb_last = 0;

static long cipher_cb_ex(BIO *b, int oper, const char *ptr, size_t len, int cmd, long arg1,
                         int arg2, size_t *processed)
{
    (void)b;
    (void)ptr;
    (void)len;
    (void)cmd;
    (void)arg2;
    (void)processed;
    cb_calls++;
    if ((oper & BIO_CB_RETURN) != 0)
        cb_last = arg1;
    return 1;
}

static void cipher_filter(EVP_CIPHER *ciph)
{
    unsigned char key[CT_KEY_LEN], other[CT_KEY_LEN], zero[CT_KEY_LEN], ivb[CT_IV_LEN];
    BIO *mem = BIO_new(BIO_s_mem());
    BIO *enc = BIO_new(BIO_f_cipher());
    char key_name[64];
    int i;

    for (i = 0; i < CT_KEY_LEN; i++) {
        key[i] = (unsigned char)(i + 1);
        other[i] = (unsigned char)(0x40 + i);
        zero[i] = 0;
    }
    for (i = 0; i < CT_IV_LEN; i++)
        ivb[i] = (unsigned char)(0x80 + i);

    BIO_push(enc, mem);

    /* A NULL cipher is refused before any key is looked at. */
    sayd("cipher.set.null_cipher", BIO_set_cipher(enc, NULL, NULL, NULL, 1));

    if (ciph == NULL) {
        BIO_free_all(enc);
        return;
    }

    /* The callback bracket: `BIO_set_cipher` calls the `_ex` callback once with `BIO_CB_CTRL` and
     * once with `BIO_CB_CTRL|BIO_CB_RETURN`, both carrying the direction in `arg1`. */
    BIO_set_callback_ex(enc, cipher_cb_ex);
    sayd("cipher.set.encrypt", BIO_set_cipher(enc, ciph, key, ivb, 1));
    sayn("cipher.cb.calls", cb_calls);
    sayn("cipher.cb.direction", cb_last);
    BIO_set_callback_ex(enc, NULL);

    /* The refusal: the provider refuses an all-zero key from `encrypt_init`, so the init fails
     * and `BIO_set_cipher` answers 0. */
    {
        BIO *zbio = BIO_new(BIO_f_cipher());

        BIO_push(zbio, BIO_new(BIO_s_mem()));
        sayd("cipher.set.zero_key", BIO_set_cipher(zbio, ciph, zero, ivb, 1));
        sayn("cipher.set.zero_key.calls", ct_ciph_bad_key);
        BIO_free_all(zbio);
    }

    /* Encrypt forty bytes: `enc_write` sends the cipher's output to the memory BIO. */
    sayn("cipher.write", BIO_write(enc, B64_INPUT, 40));
    sayn("cipher.wpending", BIO_ctrl(enc, BIO_CTRL_WPENDING, 0, NULL));
    sayn("cipher.flush", BIO_ctrl(enc, BIO_CTRL_FLUSH, 0, NULL));
    sayn("cipher.status_after_encrypt", BIO_ctrl(enc, BIO_C_GET_CIPHER_STATUS, 0, NULL));

    {
        char *p = NULL;
        long have = BIO_get_mem_data(mem, &p);

        printf("cipher.produced.len=%ld err=%lu\n", have, 0UL);
        ERR_clear_error();

        /* Decrypt with the *same* key, reading into a buffer above `ENC_MIN_CHUNK` so the
         * direct-to-caller arm of `enc_read` is the one taken. */
        {
            BIO *rmem = BIO_new(BIO_s_mem());
            BIO *dec = BIO_new(BIO_f_cipher());
            unsigned char back[512];
            int n;

            BIO_write(rmem, p, have);
            BIO_push(dec, rmem);
            sayd("cipher.dec.set", BIO_set_cipher(dec, ciph, key, ivb, 0));
            memset(back, 0, sizeof(back));
            n = BIO_read(dec, back, 300);
            printf("cipher.read_300.bytes=%d roundtrip=%d err=%lu\n", n,
                   n == 40 && memcmp(back, B64_INPUT, 40) == 0, 0UL);
            ERR_clear_error();
            {
                EVP_CIPHER_CTX *c = NULL;

                sayn("cipher.get_ctx", BIO_ctrl(dec, BIO_C_GET_CIPHER_CTX, 0, &c));
                sayn("cipher.get_ctx.nonnull", c != NULL);
            }
            sayn("cipher.status_after_decrypt", BIO_ctrl(dec, BIO_C_GET_CIPHER_STATUS, 0, NULL));
            sayn("cipher.dec.reset", BIO_ctrl(dec, BIO_CTRL_RESET, 0, NULL));
            BIO_free_all(dec);
        }

        /* The wrong key: the keystream differs, so the plaintext does too. This is the "bad key"
         * the authority reaches without a MAC -- an answer of 0 from the *comparison*, not from a
         * refusal, which is why the round trip bit is the observation. */
        {
            BIO *rmem = BIO_new(BIO_s_mem());
            BIO *dec = BIO_new(BIO_f_cipher());
            unsigned char back[512];
            int n;

            BIO_write(rmem, p, have);
            BIO_push(dec, rmem);
            sayd("cipher.dec.wrong_key.set", BIO_set_cipher(dec, ciph, other, ivb, 0));
            memset(back, 0, sizeof(back));
            n = BIO_read(dec, back, 64);
            snprintf(key_name, sizeof(key_name), "cipher.read_wrong_key");
            printf("%s.bytes=%d roundtrip=%d err=%lu\n", key_name, n,
                   n == 40 && memcmp(back, B64_INPUT, 40) == 0, 0UL);
            ERR_clear_error();
            BIO_free_all(dec);
        }
    }

    /* The cipher BIO has neither a `puts` nor a `gets` slot. */
    sayn("cipher.puts", BIO_puts(enc, "x"));
    sayn("cipher.gets", BIO_gets(enc, key_name, 4));

    sayn("cipher.pending", BIO_ctrl(enc, BIO_CTRL_PENDING, 0, NULL));
    BIO_free_all(enc);
}

int main(void)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *prov = NULL;
    EVP_MD *md_method = NULL;
    EVP_CIPHER *ciph = NULL;

    setvbuf(stdout, NULL, _IOLBF, 0);

    if (OSSL_PROVIDER_add_builtin(ctx, "court-bio", ct_provider_init))
        prov = OSSL_PROVIDER_load(ctx, "court-bio");
    sayn("provider.loaded", prov != NULL);
    if (prov != NULL) {
        md_method = EVP_MD_fetch(ctx, "COURT-BIO-MD", NULL);
        ciph = EVP_CIPHER_fetch(ctx, "COURT-BIO-CIPH", NULL);
    }
    says("provider.md", md_method == NULL ? "NULL" : "nonnull");
    says("provider.ciph", ciph == NULL ? "NULL" : "nonnull");

    block_round_trips();
    streaming_chunks(1);
    streaming_chunks(47);
    streaming_chunks(48);
    streaming_chunks(49);
    streaming_chunks(96);
    streaming_chunks(5000);
    decoder_edges();

    b64_filter(0);
    b64_filter(1);
    b64_leading_lines();
    b64_leading_whitespace_line();
    b64_no_nl_tail_split();

    md_filter(md_method);
    sayn("provider.md.new_calls", ct_md_new_calls);
    sayn("provider.md.init_calls", ct_md_init_calls);
    sayn("provider.md.update_calls", ct_md_update_calls);
    sayn("provider.md.final_calls", ct_md_final_calls);

    cipher_filter(ciph);
    sayn("provider.ciph.new_calls", ct_ciph_new_calls);
    sayn("provider.ciph.init_calls", ct_ciph_init_calls);
    sayn("provider.ciph.update_calls", ct_ciph_update_calls);
    sayn("provider.ciph.final_calls", ct_ciph_final_calls);

    EVP_MD_free(md_method);
    EVP_CIPHER_free(ciph);
    OSSL_PROVIDER_unload(prov);
    OSSL_LIB_CTX_free(ctx);

    /* Not built: `crypto/evp/bio_ok.c` needs `RAND_bytes` (`bio_ok.c:456`), which is `rand.h`'s
     * and Phase 9's. Named rather than driven; see `docs/DECISIONS.md` D194. */
    printf("BIO_f_reliable=NOT_MEASURED_RAND_bytes_IS_PHASE_9_bio_ok_c_456\n");
    printf("BIO_f_reliable.table=NOT_MEASURED_RAND_bytes_IS_PHASE_9_bio_ok_c_112\n");

    return 0;
}
