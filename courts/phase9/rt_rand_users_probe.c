/*
 * openssl-rs — the differential probe for the random layer's first two consumers (RT-RAND-USERS).
 *
 * This program is compiled **twice**, once against the admitted authority and once against the
 * candidate distribution shell, and the two `key=value` transcripts are diffed. It decides
 * nothing: a residual is a difference between two executions, so the expectation cannot drift
 * with the crate. `forensics/tools/phase9_courts.py` owns the comparison.
 *
 * Why this court exists
 * ---------------------
 * `EVP_CIPHER_CTX_rand_key` and `EVP_SealInit` are the two smallest names Phase 9 inherited from
 * Phase 7: each was withheld because its body reaches the random layer, and each is now the first
 * thing a key-establishment path calls. They belong to a court of their own rather than to
 * `RT-RAND`, because they are not the `RAND_*` front -- they are *callers* of it, and the thing
 * worth measuring is that they call it the way the authority does (the right `libctx`, the right
 * length, the right refusal).
 *
 * What it observes, and the one arm it cannot
 * -------------------------------------------
 * The draws themselves are unobservable (two different pools), so what is compared is the
 * contract: return codes, the context's key/IV lengths before and after, whether a cipher is
 * installed, and the error queue. The arms are:
 *
 *   - `EVP_CIPHER_CTX_rand_key` on a fetched provider cipher: the key length it reads (16 for
 *     AES-128-CBC) and the success it answers;
 *   - `EVP_SealInit`'s four early-return arms, all of which are deterministic and none of which
 *     needs a public key: `npubk <= 0` answers **1**, `npubk < 0` answers 1, a NULL `type` with
 *     `npubk <= 0` answers 1, and a non-NULL `npubk` with a NULL `pubk` answers 1;
 *   - the context state `EVP_SealInit` leaves behind when it is given a cipher.
 *
 * **The `npubk > 0` path with a real key is not courted**, and that is a measurement rather than
 * an omission: it needs an `EVP_PKEY` with a public part, which the crate can only build once RSA
 * key construction and the ASN.1 public-key decoder land (Phase 8). Both `EVP_PKEY_get_size(NULL)`
 * and `EVP_PKEY_CTX_new_from_pkey(libctx, NULL, NULL)` are on that path, and the first is a null
 * dereference in the authority, so a probe must not reach it with a NULL key either. The arm is
 * recorded as owed, not silently skipped.
 *
 * The `EVP_CIPH_RAND_KEY` branch of `EVP_CIPHER_CTX_rand_key` is likewise unreachable here: only
 * `e_des.c` and `e_des3.c` set that flag, and those statics are Phase 13's, so no cipher this
 * build can fetch routes `rand_key` through `EVP_CIPHER_CTX_ctrl`.
 *
 * What a difference here means
 * ----------------------------
 * Every observation is a return code, a length, a boolean or an `ERR_GET_LIB`/`ERR_GET_REASON`
 * pair drained from the error queue. No address is ever printed and no NULL-dereferencing entry
 * point is called, so a probe that aborts the harness compares nothing rather than noise.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/rand.h>

/*
 * The error queue, normalised to the two fields `docs/PARITY_MODEL.md`'s `ERROR_PASS` names as
 * portable: the library and the reason. The file/line/function coordinates are deliberately not
 * printed -- they are transcription-unit properties the error-site courts cover, and printing
 * them here would turn one behavioural residual into a coordinate diff.
 */
static void errs(const char *key)
{
    unsigned long e;
    int i = 0;

    while ((e = ERR_get_error()) != 0)
        printf("%s.%d=lib=%d,reason=%d\n", key, i++, ERR_GET_LIB(e), ERR_GET_REASON(e));
    printf("%s.count=%d\n", key, i);
}

/*
 * One `EVP_SealInit` call, observed as its arm's contract: the return code, the error queue, and
 * the context state afterwards. `which` only labels the arm; every argument is the caller's.
 */
static void seal(const char *label, EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                 unsigned char **ek, int *ekl, unsigned char *iv,
                 EVP_PKEY **pubk, int npubk)
{
    char k[128];
    int ret;

    ERR_clear_error();
    ret = EVP_SealInit(ctx, type, ek, ekl, iv, pubk, npubk);
    snprintf(k, sizeof(k), "seal.%s.ret", label);
    printf("%s=%d\n", k, ret);
    snprintf(k, sizeof(k), "seal.%s.err", label);
    errs(k);
    if (ctx != NULL) {
        snprintf(k, sizeof(k), "seal.%s.cipher_set", label);
        printf("%s=%d\n", k, EVP_CIPHER_CTX_get0_cipher(ctx) != NULL);
        snprintf(k, sizeof(k), "seal.%s.key_length", label);
        printf("%s=%d\n", k, EVP_CIPHER_CTX_get_key_length(ctx));
        snprintf(k, sizeof(k), "seal.%s.iv_length", label);
        printf("%s=%d\n", k, EVP_CIPHER_CTX_get_iv_length(ctx));
    }
}

int main(void)
{
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher;
    unsigned char key[EVP_MAX_KEY_LENGTH];
    unsigned char iv[EVP_MAX_IV_LENGTH];

    setvbuf(stdout, NULL, _IOLBF, 0);

    (void)OSSL_PROVIDER_load(NULL, "default");

    cipher = EVP_CIPHER_fetch(NULL, "AES-128-CBC", NULL);
    printf("fetch.AES-128-CBC=%d\n", cipher != NULL);
    errs("fetch.AES-128-CBC.err");
    if (cipher == NULL)
        return 1;

    /* ---- 1. `EVP_CIPHER_CTX_rand_key` ---------------------------------------------- */

    ctx = EVP_CIPHER_CTX_new();
    printf("ctx.new=%d\n", ctx != NULL);
    if (ctx == NULL)
        return 1;

    /*
     * Before any `EVP_EncryptInit_ex` the context has no cipher, and `rand_key` reads
     * `ctx->cipher->flags` with no test -- so that state is a null dereference in the authority
     * and is deliberately not called. The length observations below are the pre-image of the one
     * that is.
     */
    printf("rand_key.before_init.key_length=%d\n", EVP_CIPHER_CTX_get_key_length(ctx));

    ERR_clear_error();
    printf("init=%d\n", EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL));
    errs("init.err");
    printf("after_init.key_length=%d\n", EVP_CIPHER_CTX_get_key_length(ctx));
    printf("after_init.iv_length=%d\n", EVP_CIPHER_CTX_get_iv_length(ctx));
    printf("after_init.cipher_set=%d\n", EVP_CIPHER_CTX_get0_cipher(ctx) != NULL);

    memset(key, 0, sizeof(key));
    ERR_clear_error();
    printf("rand_key.ret=%d\n", EVP_CIPHER_CTX_rand_key(ctx, key));
    errs("rand_key.err");
    /*
     * The fill itself is not observable -- it is a draw -- but `EVP_CIPHER_CTX_rand_key`'s
     * contract is that it writes exactly the key length, and the length it reads is observed
     * above. A second call must also succeed, since it re-reads the same length.
     */
    ERR_clear_error();
    printf("rand_key.second_ret=%d\n", EVP_CIPHER_CTX_rand_key(ctx, key));
    errs("rand_key.second_err");

    /*
     * A cipher with a zero key length takes the `kl <= 0` refusal. The default provider publishes
     * `NULL` as a cipher row, so it is fetched rather than assumed, and its own key length is
     * printed first -- a fetch that answered a *non*-zero length would make the arm measure
     * something else.
     */
    {
        EVP_CIPHER_CTX *nctx = EVP_CIPHER_CTX_new();
        const EVP_CIPHER *nullc = EVP_CIPHER_fetch(NULL, "NULL", NULL);

        printf("fetch.NULL=%d\n", nullc != NULL);
        errs("fetch.NULL.err");
        if (nullc != NULL && nctx != NULL) {
            ERR_clear_error();
            printf("null.init=%d\n", EVP_EncryptInit_ex(nctx, nullc, NULL, NULL, NULL));
            errs("null.init.err");
            printf("null.key_length=%d\n", EVP_CIPHER_CTX_get_key_length(nctx));
            memset(key, 0, sizeof(key));
            ERR_clear_error();
            printf("null.rand_key_ret=%d\n", EVP_CIPHER_CTX_rand_key(nctx, key));
            errs("null.rand_key.err");
        }
        EVP_CIPHER_CTX_free(nctx);
        EVP_CIPHER_free(nullc);
    }

    EVP_CIPHER_CTX_free(ctx);

    /* ---- 2. `EVP_SealInit`'s deterministic arms ------------------------------------ */

    memset(iv, 0, sizeof(iv));
    memset(key, 0, sizeof(key));

    /* `npubk == 0` with a cipher: resets, installs the cipher, then answers 1. */
    ctx = EVP_CIPHER_CTX_new();
    seal("npubk0_with_type", ctx, cipher, NULL, NULL, iv, NULL, 0);
    EVP_CIPHER_CTX_free(ctx);

    /* A negative `npubk` takes the same early arm. */
    ctx = EVP_CIPHER_CTX_new();
    seal("npubk_neg_with_type", ctx, cipher, NULL, NULL, iv, NULL, -1);
    EVP_CIPHER_CTX_free(ctx);

    /* A NULL `type` leaves the context alone and still answers 1. */
    ctx = EVP_CIPHER_CTX_new();
    seal("npubk0_no_type", ctx, NULL, NULL, NULL, iv, NULL, 0);
    EVP_CIPHER_CTX_free(ctx);

    /* A positive `npubk` with a NULL `pubk` is the `!pubk` arm, and it answers 1 too. */
    ctx = EVP_CIPHER_CTX_new();
    seal("npubk1_null_pubk", ctx, cipher, NULL, NULL, iv, NULL, 1);
    EVP_CIPHER_CTX_free(ctx);

    EVP_CIPHER_free(cipher);
    printf("done=1\n");
    return 0;
}
