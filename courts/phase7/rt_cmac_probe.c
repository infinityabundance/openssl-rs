/*
 * RT-CMAC -- the legacy CMAC interface `crypto/cmac/cmac.c`.
 *
 * What this court is, and what it deliberately is not
 * ---------------------------------------------------
 * `crypto/cmac/cmac.c` is *not* the CMAC implementation underneath `EVP_MAC`: `EVP_MAC`'s
 * `"CMAC"` is a provider (`providers/implementations/macs/cmac_prov.c`, Phase 13). What this file
 * transcribes is the pre-3.0 construction written directly over `EVP_CIPHER_CTX`, and this probe
 * observes *that*, against a cipher the probe publishes its own provider for.
 *
 * `CMAC_Init` takes an `EVP_CIPHER *`, not an `EVP_MAC *`, so a probe that wants to drive it needs
 * a cipher -- and the court's method is a **known-answer vector**, so the cipher is a real AES-128
 * and the vectors are RFC 4493's. A stub block function that answered a constant would make every
 * arm agree and prove nothing. The probe implements AES-128 itself and checks its own CMAC against
 * the RFC before comparing the crate's answer with it.
 *
 * The arms
 * --------
 *   * `ossl_cmac_init`'s three entry conditions (`cmac.c:119`, `:133`, `:145`): the **restart**
 *     (all four arguments zero/NULL), a **non-NULL `cipher`** with a NULL key (which arms the
 *     cipher and sets `nlast_block = -1` so the context cannot be used yet), and a **non-NULL
 *     `key`** (which completes the initialisation). `CMAC_Init` with `cipher == NULL` and a NULL
 *     key but a non-empty `keylen` falls through both blocks and answers 1 with the context
 *     untouched -- which is the "reuses the previous cipher" arm the plan's row names.
 *   * a known-answer vector for four message lengths (0, 16, 40 and 64 bytes), which is where the
 *     `k1`/`k2` subkeys and the padding branch are all exercised.
 *   * `CMAC_CTX_copy` independence: the copy takes one message and the original another, and each
 *     is compared against the probe's own CMAC of *its* message.
 *   * `CMAC_CTX_get0_cipher_ctx`: the answered pointer *is* the context the CMAC runs on, so a
 *     value read through it agrees with the one `CMAC_Init` set.
 *   * the refusals for a NULL context and a NULL output buffer -- `CMAC_Final`'s `out == NULL` arm
 *     is *not* a refusal but the length query, and the two are distinguished.
 *   * `CMAC_Update` with an empty input, `CMAC_Final`'s length query, `CMAC_resume` after a final,
 *     and `CMAC_CTX_cleanup`'s return to the uninitialised state.
 *
 * Deliberately not observed
 * -------------------------
 *   * `CMAC_CTX_new`'s allocation-failure arm and `CMAC_CTX_reset`'s (there is no `reset`; the
 *     cleanup is the door) -- neither is reachable without fault injection.
 *   * `CMAC_Final`'s `EVP_Cipher` failure arm (`cmac.c:272`), which would need the provider's
 *     `cipher` to answer 0 for a block it accepted at init; the probe's cipher never does, and the
 *     arm is named rather than induced.
 *   * a block length greater than `LOCAL_BUF_SIZE` (`max_burst_blocks == 0`, `cmac.c:215`), which
 *     needs a cipher with a block larger than 2048 bytes; the provider publishes a 16-byte block.
 *
 * Every observation is a return code, a size, a pointer relation or the bytes of a CMAC the probe
 * computed itself. No address is printed.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/cmac.h>
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

/* The error chain, drained and formatted. Nothing here is an address. */
static char *chain(char *buf, size_t n)
{
    unsigned long e;
    const char *file, *func, *data;
    int line, flags, first = 1;
    size_t at = 0;

    buf[0] = '\0';
    while ((e = ERR_get_error_all(&file, &line, &func, &data, &flags)) != 0) {
        const char *rsn = ERR_reason_error_string(e);
        int k = snprintf(buf + at, n - at, "%s%s@%s/%d", first ? "" : ",",
                         rsn == NULL ? "<no-string>" : rsn, func == NULL ? "<no-func>" : func, line);

        if (k < 0 || (size_t)k >= n - at)
            break;
        at += (size_t)k;
        first = 0;
    }
    if (first)
        snprintf(buf, n, "<empty>");
    ERR_clear_error();
    return buf;
}

/* -------------------------------------------------------------------------------------------- */
/* The probe's own AES-128, for RFC 4493's vectors.                                              */
/* -------------------------------------------------------------------------------------------- */

static const unsigned char SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};
static const unsigned char RCON[11] = { 0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36 };

static void aes128_expand(const unsigned char key[16], unsigned char rk[176])
{
    int i;

    memcpy(rk, key, 16);
    for (i = 16; i < 176; i += 4) {
        unsigned char t[4];

        memcpy(t, rk + i - 4, 4);
        if (i % 16 == 0) {
            unsigned char tmp = t[0];

            t[0] = SBOX[t[1]] ^ RCON[i / 16];
            t[1] = SBOX[t[2]];
            t[2] = SBOX[t[3]];
            t[3] = SBOX[tmp];
        }
        rk[i] = rk[i - 16] ^ t[0];
        rk[i + 1] = rk[i - 15] ^ t[1];
        rk[i + 2] = rk[i - 14] ^ t[2];
        rk[i + 3] = rk[i - 13] ^ t[3];
    }
}

static void aes128_encrypt_block(const unsigned char rk[176], const unsigned char in[16],
                                 unsigned char out[16])
{
    unsigned char s[16];
    int round, r, c, i;

    memcpy(s, in, 16);
    for (i = 0; i < 16; i++)
        s[i] ^= rk[i];
    for (round = 1; round <= 10; round++) {
        unsigned char t[16];

        for (i = 0; i < 16; i++)
            t[i] = SBOX[s[i]];
        /* ShiftRows: the state is column-major (byte `r + 4*c` is row `r`, column `c`), so row
         * `r` shifts left by `r`. */
        for (r = 0; r < 4; r++)
            for (c = 0; c < 4; c++)
                s[r + 4 * c] = t[r + 4 * ((c + r) & 3)];
        if (round != 10) {
            for (c = 0; c < 4; c++) {
                unsigned char a0 = s[4 * c], a1 = s[4 * c + 1], a2 = s[4 * c + 2], a3 = s[4 * c + 3];
                unsigned char x0 = (unsigned char)((a0 << 1) ^ ((a0 >> 7) * 0x1b));
                unsigned char x1 = (unsigned char)((a1 << 1) ^ ((a1 >> 7) * 0x1b));
                unsigned char x2 = (unsigned char)((a2 << 1) ^ ((a2 >> 7) * 0x1b));
                unsigned char x3 = (unsigned char)((a3 << 1) ^ ((a3 >> 7) * 0x1b));

                s[4 * c + 0] = (unsigned char)(x0 ^ a1 ^ x1 ^ a2 ^ a3);
                s[4 * c + 1] = (unsigned char)(a0 ^ x1 ^ a2 ^ x2 ^ a3);
                s[4 * c + 2] = (unsigned char)(a0 ^ a1 ^ x2 ^ a3 ^ x3);
                s[4 * c + 3] = (unsigned char)(x0 ^ a0 ^ a1 ^ a2 ^ x3);
            }
        }
        for (i = 0; i < 16; i++)
            s[i] ^= rk[round * 16 + i];
    }
    memcpy(out, s, 16);
}

/* The probe's own CMAC over AES-128, so every arm has an independent expectation. */
static void own_cmac(const unsigned char key[16], const unsigned char *msg, size_t msglen,
                     unsigned char out[16])
{
    unsigned char rk[176];
    unsigned char l[16], k1[16], k2[16];
    unsigned char blk[16];
    unsigned char zero[16];
    int i, nblocks, last_full;
    size_t off;

    aes128_expand(key, rk);
    memset(zero, 0, 16);
    aes128_encrypt_block(rk, zero, l);
    /* make_kn's left shift with the conditional R. */
    {
        unsigned char carry = (unsigned char)(l[0] >> 7);

        for (i = 0; i < 15; i++)
            k1[i] = (unsigned char)((l[i] << 1) | (l[i + 1] >> 7));
        k1[15] = (unsigned char)((l[15] << 1) ^ ((unsigned char)(0 - carry) & 0x87));
    }
    {
        unsigned char carry = (unsigned char)(k1[0] >> 7);

        for (i = 0; i < 15; i++)
            k2[i] = (unsigned char)((k1[i] << 1) | (k1[i + 1] >> 7));
        k2[15] = (unsigned char)((k1[15] << 1) ^ ((unsigned char)(0 - carry) & 0x87));
    }
    nblocks = (int)((msglen + 15) / 16);
    last_full = (msglen != 0 && msglen % 16 == 0);
    if (nblocks == 0)
        nblocks = 1;
    memset(blk, 0, 16);
    for (i = 0; i < nblocks - 1; i++) {
        unsigned char x[16];
        int j;

        for (j = 0; j < 16; j++)
            x[j] = (unsigned char)(blk[j] ^ msg[i * 16 + j]);
        aes128_encrypt_block(rk, x, blk);
    }
    off = (size_t)(nblocks - 1) * 16;
    {
        unsigned char last[16];
        unsigned char x[16];
        int j;

        memset(last, 0, 16);
        memcpy(last, msg + off, msglen - off);
        if (last_full) {
            for (j = 0; j < 16; j++)
                last[j] ^= k1[j];
        } else {
            last[msglen - off] = 0x80;
            for (j = 0; j < 16; j++)
                last[j] ^= k2[j];
        }
        for (j = 0; j < 16; j++)
            x[j] = (unsigned char)(blk[j] ^ last[j]);
        aes128_encrypt_block(rk, x, out);
    }
}

static int hexeq16(const unsigned char *have, const char *hex)
{
    size_t i;

    for (i = 0; i < 16; i++) {
        unsigned int b;

        if (sscanf(hex + i * 2, "%2x", &b) != 1 || (unsigned char)b != have[i])
            return 0;
    }
    return 1;
}

/* -------------------------------------------------------------------------------------------- */
/* The probe's provider: one AES-128-ECB block cipher.                                           */
/* -------------------------------------------------------------------------------------------- */

struct ct_ciph_ctx {
    unsigned char key[16];
    unsigned char iv[16];
    size_t keylen;
    int have_key;
};

static char ct_marker;

static void *ct_newctx(void *provctx)
{
    (void)provctx;
    return calloc(1, sizeof(struct ct_ciph_ctx));
}

static void ct_freectx(void *vctx)
{
    free(vctx);
}

static void *ct_dupctx(void *vctx)
{
    struct ct_ciph_ctx *src = vctx;
    struct ct_ciph_ctx *dst = calloc(1, sizeof *dst);

    if (dst == NULL || src == NULL) {
        free(dst);
        return NULL;
    }
    memcpy(dst, src, sizeof *dst);
    return dst;
}

static int ct_einit(void *vctx, const unsigned char *key, size_t keylen,
                    const unsigned char *iv, size_t ivlen, const OSSL_PARAM params[])
{
    struct ct_ciph_ctx *c = vctx;

    (void)ivlen;
    (void)params;
    if (c == NULL)
        return 0;
    if (key != NULL) {
        if (keylen != 16)
            return 0;
        memcpy(c->key, key, 16);
        c->keylen = keylen;
        c->have_key = 1;
    }
    /* `cmac.c` arms this context as a **CBC** cipher and carries the chaining value in the IV:
     * `CMAC_resume` is `EVP_EncryptInit_ex(cctx, NULL, NULL, NULL, ctx->tbl)` (`cmac.c:290`),
     * `ossl_cmac_init` resets it with the zero IV (`:155`, `:165`), and the whole construction
     * depends on the XOR against it happening inside the cipher call. A NULL `iv` therefore keeps
     * the previous one, as `EVP_CIPHER_CTX` does. */
    if (iv != NULL)
        memcpy(c->iv, iv, 16);
    return 1;
}

static int ct_cipher(void *vctx, unsigned char *out, size_t *outl, size_t outsize,
                     const unsigned char *in, size_t inl)
{
    struct ct_ciph_ctx *c = vctx;
    unsigned char rk[176];
    size_t at = 0;

    if (c == NULL || !c->have_key || in == NULL || inl == 0 || inl % 16 != 0)
        return 0;
    if (outsize < inl)
        return 0;
    /* `EVP_Cipher` reaches a provider's `cipher` with the **whole** span CMAC_Update asked for,
     * which is a multiple of the block size and usually more than one block; the callback chains
     * them in CBC order, updating the IV to each ciphertext. */
    aes128_expand(c->key, rk);
    while (at < inl) {
        unsigned char x[16];
        int j;

        for (j = 0; j < 16; j++)
            x[j] = (unsigned char)(in[at + j] ^ c->iv[j]);
        aes128_encrypt_block(rk, x, out + at);
        memcpy(c->iv, out + at, 16);
        at += 16;
    }
    *outl = inl;
    return 1;
}

static int ct_update(void *vctx, unsigned char *out, size_t *outl, size_t outsize,
                     const unsigned char *in, size_t inl)
{
    size_t at = 0;

    while (at < inl) {
        if (ct_cipher(vctx, out + at, outl, outsize - at, in + at, 16) == 0)
            return 0;
        at += 16;
    }
    *outl = inl;
    return 1;
}

static int ct_final(void *vctx, unsigned char *out, size_t *outl, size_t outsize)
{
    (void)vctx;
    (void)out;
    (void)outsize;
    *outl = 0;
    return 1;
}

static int ct_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 16))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 16))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 16))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
    if (p != NULL && !OSSL_PARAM_set_uint(p, EVP_CIPH_CBC_MODE))
        return 0;
    return 1;
}

static int ct_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    struct ct_ciph_ctx *c = vctx;
    OSSL_PARAM *p;
    size_t keylen = c == NULL ? 16 : (c->have_key ? c->keylen : 16);
    size_t ivlen = 16;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, keylen))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ivlen))
        return 0;
    return 1;
}

static int ct_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    struct ct_ciph_ctx *c = vctx;
    const OSSL_PARAM *p;

    if (c == NULL)
        return 0;
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL) {
        size_t keylen = 0;

        if (!OSSL_PARAM_get_size_t(p, &keylen) || keylen != 16)
            return 0;
        c->keylen = keylen;
    }
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL) {
        size_t ivlen = 0;

        if (!OSSL_PARAM_get_size_t(p, &ivlen) || ivlen != 16)
            return 0;
    }
    return 1;
}

static const OSSL_PARAM *ct_gettable_params(void *provctx)
{
    static const OSSL_PARAM table[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_MODE, NULL),
        OSSL_PARAM_END
    };

    (void)provctx;
    return table;
}

static const OSSL_PARAM *ct_gettable_ctx_params(void *cctx, void *provctx)
{
    static const OSSL_PARAM table[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
        OSSL_PARAM_END
    };

    (void)cctx;
    (void)provctx;
    return table;
}

static const OSSL_PARAM *ct_settable_ctx_params(void *cctx, void *provctx)
{
    (void)cctx;
    (void)provctx;
    return ct_gettable_ctx_params(cctx, provctx);
}

static const OSSL_DISPATCH ct_ciph_fns[] = {
    { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))ct_newctx },
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))ct_freectx },
    { OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void))ct_dupctx },
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))ct_einit },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))ct_einit },
    { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))ct_cipher },
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))ct_update },
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))ct_final },
    { OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))ct_get_params },
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (void (*)(void))ct_gettable_params },
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void))ct_get_ctx_params },
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))ct_gettable_ctx_params },
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (void (*)(void))ct_set_ctx_params },
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))ct_settable_ctx_params },
    { 0, NULL }
};

static const OSSL_ALGORITHM ct_ciphers[] = {
    { "COURT-AES128", "provider=court-cmac", ct_ciph_fns, "the probe's own AES-128-ECB" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *ct_query(void *provctx, int operation_id, int *no_cache)
{
    (void)provctx;
    *no_cache = 0;
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
    *out = ct_provider_fns;
    *provctx = &ct_marker;
    return 1;
}

/* -------------------------------------------------------------------------------------------- */
/* The arms.                                                                                     */
/* -------------------------------------------------------------------------------------------- */

static const unsigned char K4493[16] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

static void hex2bin(const char *hex, unsigned char *out, size_t outlen)
{
    size_t i;

    for (i = 0; i < outlen; i++) {
        unsigned int b = 0;

        sscanf(hex + i * 2, "%2x", &b);
        out[i] = (unsigned char)b;
    }
}

static const struct {
    const char *name;
    size_t len;
    const char *msghex;
    const char *hex;
} VEC[] = {
    { "empty", 0, "",
      "bb1d6929e95937287fa37d129b756746" },
    { "m16", 16, "6bc1bee22e409f96e93d7e117393172a",
      "070a16b46b4d4144f79bdd9dd04a287c" },
    { "m40", 40, "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411",
      "dfa66747de9ae63030ca32611497c827" },
    { "m64", 64, "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
      "51f0bebf7e3b9d92fc49741779363cfe" },
};

static void known_answers(EVP_CIPHER *cipher)
{
    unsigned char msg[64];
    size_t i;

    for (i = 0; i < sizeof VEC / sizeof VEC[0]; i++) {
        unsigned char own[16];
        CMAC_CTX *ctx = CMAC_CTX_new();
        unsigned char got[EVP_MAX_MD_SIZE];
        size_t gotlen = 0;
        int init, upd, fin;

        memset(msg, 0, sizeof msg);
        hex2bin(VEC[i].msghex, msg, VEC[i].len);
        own_cmac(K4493, msg, VEC[i].len, own);
        printf("kat.%s.self=%d", VEC[i].name, hexeq16(own, VEC[i].hex));
        init = CMAC_Init(ctx, K4493, 16, cipher, NULL);
        upd = CMAC_Update(ctx, msg, VEC[i].len);
        fin = CMAC_Final(ctx, got, &gotlen);
        printf(" rv=%d%d%d len=%zu vec=%d own=%d\n", init, upd, fin, gotlen,
               hexeq16(got, VEC[i].hex), (int)(gotlen == 16 && memcmp(got, own, 16) == 0));
        CMAC_CTX_free(ctx);
    }
}

static void init_arms(EVP_CIPHER *cipher)
{
    char errbuf[512];
    CMAC_CTX *ctx = CMAC_CTX_new();
    unsigned char out[16];
    size_t outlen = 0;
    int rv;

    /* A fresh context is uninitialised: the constructor's `nlast_block = -1` gate refuses every
     * operation, and the restart arm refuses it too. */
    printf("fresh.get0_same=%d upd=%d fin=%d resume=%d\n",
           (int)(CMAC_CTX_get0_cipher_ctx(ctx) != NULL),
           CMAC_Update(ctx, out, 0), CMAC_Final(ctx, out, &outlen), CMAC_resume(ctx));

    /* A NULL key with a cipher: arms the cipher and leaves the context unusable until a key. */
    rv = CMAC_Init(ctx, NULL, 0, cipher, NULL);
    sayn("cipher_only.init", rv);
    printf("cipher_only.upd=%d fin=%d err=%s\n", CMAC_Update(ctx, out, 0),
           CMAC_Final(ctx, out, &outlen), chain(errbuf, sizeof errbuf));

    /* A NULL key and a NULL cipher with a non-zero keylen: neither block runs, answer 1, and the
     * context is untouched -- the "reuses the previous cipher" arm. */
    rv = CMAC_Init(ctx, NULL, 7, NULL, NULL);
    sayn("neither_block.init", rv);

    /* The key completes it. */
    rv = CMAC_Init(ctx, K4493, 16, NULL, NULL);
    sayn("complete.init", rv);
    printf("complete.fin_len=%d err=%s\n", CMAC_Final(ctx, NULL, &outlen),
           chain(errbuf, sizeof errbuf));
    printf("complete.outlen=%zu err=%s\n", outlen, chain(errbuf, sizeof errbuf));

    /* A NULL output with a non-NULL length pointer is the length query (answer 1); a NULL context
     * is a refusal. */
    printf("null_cases.fin_out_null=%d fin_len_null=%d err=%s\n",
           CMAC_Final(ctx, NULL, &outlen), CMAC_Final(ctx, out, NULL),
           chain(errbuf, sizeof errbuf));

    /* The restart arm: all four arguments zero/NULL, on an initialised context. */
    rv = CMAC_Init(ctx, NULL, 0, NULL, NULL);
    sayn("restart.init", rv);
    printf("restart.upd=%d err=%s\n", CMAC_Update(ctx, out, 0), chain(errbuf, sizeof errbuf));

    /* The cleanup returns the whole context to the uninitialised state. */
    CMAC_CTX_cleanup(ctx);
    printf("cleanup.upd=%d fin=%d err=%s\n", CMAC_Update(ctx, out, 0), CMAC_Final(ctx, out, &outlen),
           chain(errbuf, sizeof errbuf));

    CMAC_CTX_free(ctx);
}

static void copy_and_resume(EVP_CIPHER *cipher)
{
    static unsigned char ma[32];
    static unsigned char mb[32];
    char errbuf[512];
    CMAC_CTX *src = CMAC_CTX_new();
    CMAC_CTX *cp = CMAC_CTX_new();
    unsigned char da[16], db[16];
    size_t la = 0, lb = 0;
    int rv, i;

    for (i = 0; i < 32; i++) {
        ma[i] = (unsigned char)i;
        mb[i] = (unsigned char)(0xf0 - i);
    }

    /* The copy of an uninitialised source is refused before anything is touched. */
    printf("copy.uninit=%d err=%s\n", CMAC_CTX_copy(cp, src), chain(errbuf, sizeof errbuf));

    rv = CMAC_Init(src, K4493, 16, cipher, NULL);
    sayn("copy.src_init", rv);
    /* 16 bytes fed and not finalised: the copy carries the partial block. */
    CMAC_Update(src, ma, 10);
    rv = CMAC_CTX_copy(cp, src);
    sayn("copy.rv", rv);
    printf("copy.get0_distinct=%d\n",
           (int)(CMAC_CTX_get0_cipher_ctx(cp) != CMAC_CTX_get0_cipher_ctx(src)));

    /* The copy finishes one message, the original another; each against the probe's own CMAC. */
    CMAC_Update(cp, ma + 10, 22);
    CMAC_Final(cp, da, &la);
    CMAC_Update(src, mb + 10, 22);
    CMAC_Final(src, db, &lb);
    {
        unsigned char owna[16], ownb[16], srcexp[32];

        own_cmac(K4493, ma, 32, owna);
        /* The original already holds the shared ten-byte prefix, so its expectation is that
         * prefix followed by `mb`'s remainder -- not `mb` from the start. */
        memcpy(srcexp, ma, 10);
        memcpy(srcexp + 10, mb + 10, 22);
        own_cmac(K4493, srcexp, 32, ownb);
        printf("copy.independent=%d own_a=%d own_b=%d la=%zu lb=%zu err=%s\n",
               (int)(la == 16 && lb == 16 && memcmp(da, db, 16) != 0),
               (int)(la == 16 && memcmp(da, owna, 16) == 0),
               (int)(lb == 16 && memcmp(db, ownb, 16) == 0), la, lb, chain(errbuf, sizeof errbuf));
    }

    /* `CMAC_resume` re-arms from the saved block, so the construction continues after a final. */
    rv = CMAC_resume(src);
    sayn("resume.rv", rv);
    CMAC_Update(src, ma, 4);
    CMAC_Final(src, da, &la);
    printf("resume.fin=%zu err=%s\n", la, chain(errbuf, sizeof errbuf));

    CMAC_CTX_free(cp);
    CMAC_CTX_free(src);
}

int main(void)
{
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *prov = NULL;
    EVP_CIPHER *cipher = NULL;

    setvbuf(stdout, NULL, _IOLBF, 0);

    if (OSSL_PROVIDER_add_builtin(libctx, "court-cmac", ct_provider_init))
        prov = OSSL_PROVIDER_load(libctx, "court-cmac");
    sayn("provider.loaded", prov != NULL);
    if (prov != NULL)
        cipher = EVP_CIPHER_fetch(libctx, "COURT-AES128", NULL);
    sayn("cipher.fetched", cipher != NULL);

    if (cipher != NULL) {
        known_answers(cipher);
        init_arms(cipher);
        copy_and_resume(cipher);
    }

    /* Named in the header comment and not driven. */
    printf("CMAC_Final=NOT_MEASURED_CIPHER_FAILURE_ARM_cmac_c_272\n");
    printf("CMAC_Update=NOT_MEASURED_BLOCK_GT_LOCAL_BUF_cmac_c_215\n");

    EVP_CIPHER_free(cipher);
    if (prov != NULL)
        OSSL_PROVIDER_unload(prov);
    OSSL_LIB_CTX_free(libctx);
    return 0;
}
