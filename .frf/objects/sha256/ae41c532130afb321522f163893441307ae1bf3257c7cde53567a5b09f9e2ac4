/*
 * RT-EVP-PEM -- the `pem.h` surface 7.5 can build, and the twenty-five names it cannot.
 *
 * What lands and is observed
 * -------------------------
 *   * **`PEM_write_bio` then `PEM_read_bio_ex`/`PEM_read_bio`** over one memory BIO, with the
 *     name, the header and the *bytes* compared against the probe's own. The writer's answer is
 *     the encoded body's length and not the whole block's, and the reader's is the decode; both
 *     are printed, and the header's own trailing newline is part of the comparison because the
 *     reader keeps it and drops the blank line that ends it.
 *   * **`PEM_read_bio_ex`'s flag and framing edges**: the `EAY_COMPATIBLE|ONLY_B64` pair, which
 *     is refused before anything is allocated; a body whose `-----END-----` name does not match
 *     its `-----BEGIN-----`; a body with no end line at all; a body with a character the decoder
 *     refuses; an **empty** body, which is a plain zero with no error raised; a blank line *after*
 *     the header's blank line; a BOM on the first line; the **65-byte line length test**, driven
 *     on both sides of the boundary (64 content bytes plus the newline is accepted, 65 is not, and
 *     the refusal raises nothing); `PEM_FLAG_SECURE`; and the three `sanitize_line` rules, which
 *     are *not* interchangeable -- the same body with an internal space, with a control byte, and
 *     with the `ONLY_B64` flag each take a different path through them.
 *   * **`PEM_get_EVP_CIPHER_INFO`** arm by arm, over a **legacy** cipher *this probe* builds and
 *     registers with `EVP_add_cipher`: the absent header, the six malformed-prefix refusals, a
 *     DEK-Info whose name resolves, the IV bytes it parsed, a missing IV, an unexpected IV, one
 *     truncated IV and one non-hex IV. The registration is not decoration: `EVP_get_cipherbyname`
 *     finds a name only in the **legacy** `OBJ_NAME` table (`crypto/evp/names.c:86`, and the
 *     namemap retry behind it ends at the same table at `:114`), so a cipher published by this
 *     probe's own *provider* -- which `EVP_CIPHER_fetch` does return, and the probe prints that --
 *     is deliberately **not** visible to it. That asymmetry is itself an observation and is driven.
 *   * **`PEM_SignInit`/`PEM_SignUpdate`/`PEM_SignFinal`**: the two one-line wrappers driven
 *     through the probe's own digest, with the digest read back and compared against a context the
 *     probe re-ran itself; and `PEM_SignFinal` driven with a key that has no signature method,
 *     which is the one arm of it that does not need an `EVP_PKEY` from a provider.
 *   * **`PEM_write_bio_ASN1_stream`**, one of the three Phase-5 `asn1.h` hand-offs: an
 *     `ASN1_INTEGER` is encoded into a memory BIO through `BIO_f_base64`, and the whole block is
 *     compared with the probe's own `i2d_ASN1_INTEGER` + `EVP_EncodeBlock` of the same value, then
 *     read back through `PEM_read_bio_ex`.
 *   * **the `FILE *` spellings** `PEM_write`/`PEM_read` through a `tmpfile()` and a rewind, which is
 *     the only way to reach `BIO_s_file`/`BIO_set_fp` from this row.
 *
 * What does not land, and the line each one prints
 * -----------------------------------------------
 * Twenty-five of this row's thirty-five `PEM_*` names are **not built**, in four groups, and each
 * prints a `NOT_MEASURED_…` line naming the blocker and its authority coordinate rather than being
 * called. The blockers are:
 *
 *   * **`EVP_md5()`** (`crypto/evp/legacy_md5.c:36`) -- a legacy `EVP_MD` over `MD5_Init`/
 *     `MD5_Update`/`MD5_Final`, which `crypto/md5/` owns and Phase 13 has. It is the single call
 *     `PEM_do_header` makes at `crypto/pem/pem_lib.c:479`, and through `PEM_do_header` it takes
 *     `PEM_bytes_read_bio`, its `_secmem` spelling, `PEM_ASN1_read_bio` and `PEM_ASN1_read` with it.
 *   * **`OSSL_ENCODER_*`/`OSSL_DECODER_*`** (`decoder.h`/`encoder.h`, Phase 10) -- reached first by
 *     every `*_PrivateKey*`, `*_PKCS8PrivateKey*` and `*_Parameters*` spelling.
 *   * **`EVP_read_pw_string_min`** (`crypto/evp/evp_key.c:52`) -- a `UI` program, `ui.h`, Phase 13.
 *     It is the whole of `PEM_def_callback`'s prompting arm, and that arm is the export.
 *   * **`evp_pkey_copy_downgraded`** (`include/crypto/evp.h`, Phase 8) and the legacy `ameth` that
 *     `PEM_write_bio_PrivateKey_traditional` reads (`crypto/pem/pem_pkey.c:354`).
 *
 * Addresses are never printed. Every observation is a return code, a length, a byte comparison the
 * probe performs itself, or a presence answer; every arm prints the error chain it leaves behind,
 * because a refusal that raises nothing and one that raises a reason are different contracts.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* `EVP_CIPHER_meth_new` is deprecated in 3.0 and is still the only public way to build the legacy
 * method `EVP_get_cipherbyname` can find; the deprecation attribute is what is suppressed here, not
 * the API, and the attribute is identical on both lanes. */
#define OPENSSL_SUPPRESS_DEPRECATED

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/provider.h>

static void sayn(const char *key, long long v)
{
    printf("%s=%lld err=%lu\n", key, v, ERR_peek_error());
    ERR_clear_error();
}

/* The error chain, drained and formatted into the caller's buffer. Nothing here is an address. */
static char *chain(char *buf, size_t n)
{
    unsigned long e;
    const char *file, *func, *data;
    int line, flags, first = 1;
    size_t at = 0;

    buf[0] = '\0';
    while ((e = ERR_get_error_all(&file, &line, &func, &data, &flags)) != 0) {
        const char *rsn = ERR_reason_error_string(e);
        int k = snprintf(buf + at, n - at, "%s%s%s@%s/%d", first ? "" : ",",
                         rsn == NULL ? "<no-string>" : rsn, data == NULL ? "" : "[data]",
                         func == NULL ? "<no-func>" : func, line);

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

static void sayd(const char *key, long long v)
{
    char buf[512];

    printf("%s=%lld chain=%s\n", key, v, chain(buf, sizeof buf));
}

/* ---- the probe's provider: one digest and two ciphers, for `EVP_get_cipherbyname` ---------- */

#define CT_MD_SIZE 32
#define CT_MD_BLOCK 64
#define CT_IV16 16

struct ct_md_ctx {
    unsigned char s[CT_MD_SIZE];
    size_t len;
};

static void *ct_md_newctx(void *provctx)
{
    (void)provctx;
    return calloc(1, sizeof(struct ct_md_ctx));
}

static void ct_md_freectx(void *vctx)
{
    free(vctx);
}

static int ct_md_init(void *vctx)
{
    struct ct_md_ctx *c = vctx;

    if (c == NULL)
        return 0;
    memset(c->s, 0, sizeof c->s);
    c->len = 0;
    return 1;
}

static int ct_md_update(void *vctx, const unsigned char *in, size_t inl)
{
    struct ct_md_ctx *c = vctx;
    size_t i;

    if (c == NULL || (in == NULL && inl != 0))
        return 0;
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
    static const OSSL_PARAM table[] = {
        OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_BLOCK_SIZE, NULL),
        OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, NULL),
        OSSL_PARAM_END
    };

    (void)provctx;
    return table;
}

static const OSSL_DISPATCH ct_md_fns[] = {
    { OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))ct_md_newctx },
    { OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))ct_md_freectx },
    { OSSL_FUNC_DIGEST_INIT, (void (*)(void))ct_md_init },
    { OSSL_FUNC_DIGEST_UPDATE, (void (*)(void))ct_md_update },
    { OSSL_FUNC_DIGEST_FINAL, (void (*)(void))ct_md_final },
    { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void))ct_md_get_params },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (void (*)(void))ct_md_gettable_params },
    { 0, NULL }
};

struct ct_ciph_ctx {
    unsigned char key[32];
    size_t keylen;
};

static void *ct_ciph_newctx(void *provctx)
{
    (void)provctx;
    return calloc(1, sizeof(struct ct_ciph_ctx));
}

static void ct_ciph_freectx(void *vctx)
{
    free(vctx);
}

static int ct_ciph_init(void *vctx, const unsigned char *key, size_t keylen,
                        const unsigned char *iv, size_t ivlen, const OSSL_PARAM params[],
                        int enc)
{
    struct ct_ciph_ctx *c = vctx;

    (void)iv;
    (void)ivlen;
    (void)params;
    (void)enc;
    if (c == NULL || key == NULL || keylen == 0 || keylen > sizeof c->key)
        return 0;
    memset(c->key, 0, sizeof c->key);
    memcpy(c->key, key, keylen);
    c->keylen = keylen;
    return 1;
}

static int ct_ciph_update(void *vctx, unsigned char *out, size_t *outl, size_t outsz,
                          const unsigned char *in, size_t inl)
{
    struct ct_ciph_ctx *c = vctx;
    size_t i;

    if (c == NULL || outl == NULL || inl > outsz)
        return 0;
    for (i = 0; i < inl; i++)
        out[i] = (unsigned char)(in[i] ^ c->key[i % c->keylen]);
    *outl = inl;
    return 1;
}

static int ct_ciph_final(void *vctx, unsigned char *out, size_t *outl, size_t outsz)
{
    (void)vctx;
    (void)out;
    (void)outsz;
    *outl = 0;
    return 1;
}

static int ct_ciph_get_params_iv16(OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, CT_IV16))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 16))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 1))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
    if (p != NULL && !OSSL_PARAM_set_uint(p, 1))
        return 0;
    return 1;
}

static int ct_ciph_get_params_iv0(OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 0))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 16))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 1))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
    if (p != NULL && !OSSL_PARAM_set_uint(p, 1))
        return 0;
    return 1;
}

static const OSSL_PARAM *ct_ciph_gettable_params(void *provctx)
{
    static const OSSL_PARAM table[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_MODE, NULL),
        OSSL_PARAM_END
    };

    (void)provctx;
    return table;
}

static int ct_ciph_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    (void)vctx;
    (void)params;
    return 1;
}

static int ct_ciph_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    (void)vctx;
    (void)params;
    return 1;
}

static const OSSL_PARAM *ct_ciph_gettable_ctx_params(void *vctx, void *provctx)
{
    static const OSSL_PARAM table[] = { OSSL_PARAM_END };

    (void)vctx;
    (void)provctx;
    return table;
}

static const OSSL_PARAM *ct_ciph_settable_ctx_params(void *vctx, void *provctx)
{
    static const OSSL_PARAM table[] = { OSSL_PARAM_END };

    (void)vctx;
    (void)provctx;
    return table;
}

#define CT_CIPH_COMMON_FNS                                                    \
    { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))ct_ciph_newctx },              \
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))ct_ciph_freectx },            \
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))ct_ciph_init },          \
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))ct_ciph_init },          \
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))ct_ciph_update },              \
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))ct_ciph_final },                \
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void))ct_ciph_get_ctx_params }, \
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (void (*)(void))ct_ciph_set_ctx_params }, \
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))ct_ciph_gettable_ctx_params }, \
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))ct_ciph_settable_ctx_params }

static const OSSL_DISPATCH ct_ciph16_fns[] = {
    CT_CIPH_COMMON_FNS,
    { OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))ct_ciph_get_params_iv16 },
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (void (*)(void))ct_ciph_gettable_params },
    { 0, NULL }
};

static const OSSL_DISPATCH ct_ciph0_fns[] = {
    CT_CIPH_COMMON_FNS,
    { OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))ct_ciph_get_params_iv0 },
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (void (*)(void))ct_ciph_gettable_params },
    { 0, NULL }
};

static const OSSL_ALGORITHM ct_digests[] = {
    { "COURT-PEM-MD", "provider=court-pem", ct_md_fns, "The probe's own digest" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM ct_ciphers[] = {
    { "COURT-PEM-CIPH", "provider=court-pem", ct_ciph16_fns, "16-byte IV" },
    { "COURT-PEM-NOIV", "provider=court-pem", ct_ciph0_fns, "no IV" },
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

static char ct_marker;

static int ct_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
                            const OSSL_DISPATCH **out, void **provctx)
{
    (void)handle;
    (void)in;
    *out = ct_provider_fns;
    *provctx = &ct_marker;
    return 1;
}

/* ---- the PEM block the probe builds by hand ------------------------------------------------- */

#define BLOCK_NAME "TEST ITEM"
#define BLOCK_HEADER "X-Foo: bar\n"
#define BLOCK_BODY "\x01\x02\x03\x04\x05"

/* `PEM_write_bio` into a memory BIO and hand back the BIO, positioned for reading. */
static BIO *make_block(const char *name, const char *header, const char *body, int bodylen)
{
    BIO *bio = BIO_new(BIO_s_mem());

    if (bio == NULL)
        return NULL;
    if (PEM_write_bio(bio, name, header, (const unsigned char *)body, bodylen) <= 0) {
        BIO_free(bio);
        return NULL;
    }
    return bio;
}

static int expected_body_b64(char *out, size_t outsz)
{
    unsigned char enc[64];
    int n = EVP_EncodeBlock(enc, (const unsigned char *)BLOCK_BODY, 5);

    if ((size_t)n + 2 > outsz)
        return 0;
    memcpy(out, enc, (size_t)n);
    out[n] = '\n';
    out[n + 1] = '\0';
    return n + 1;
}

/*
 * A **legacy** `EVP_CIPHER` the probe owns, registered in the `OBJ_NAME` method table under
 * `NID_undef`'s short and long names (`"UNDEF"`/`"undefined"`). `EVP_get_cipherbyname` finds it
 * there and nowhere else; a provider cipher is invisible to that function even when the namemap
 * knows its name, which is the arm below this one. The method is deliberately never freed: the
 * table holds a borrowed pointer, and freeing it would leave the table dangling.
 */
static EVP_CIPHER *legacy_cipher(int ivlen)
{
    EVP_CIPHER *c = EVP_CIPHER_meth_new(NID_undef, 1, 8);

    if (c == NULL)
        return NULL;
    if (ivlen != 0 && !EVP_CIPHER_meth_set_iv_length(c, ivlen))
        return NULL;
    if (!EVP_add_cipher(c))
        return NULL;
    return c;
}

/* ---- `PEM_write_bio` -> `PEM_read_bio_ex`/`PEM_read_bio` ------------------------------------ */

static void write_then_read(void)
{
    char errbuf[512];
    BIO *bio = make_block(BLOCK_NAME, BLOCK_HEADER, BLOCK_BODY, 5);
    char expect[64];
    int elen = expected_body_b64(expect, sizeof expect);

    sayn("write.block.nonnull", bio != NULL);
    if (bio == NULL)
        return;

    /* The produced text, compared with the probe's own framing of the same three parts. */
    {
        char *p = NULL;
        long have = BIO_get_mem_data(bio, &p);
        char wanted[256];
        int n = snprintf(wanted, sizeof wanted, "-----BEGIN %s-----\n%s\n%s-----END %s-----\n",
                         BLOCK_NAME, BLOCK_HEADER, expect, BLOCK_NAME);

        printf("write.block.len=%ld matches=%d err=%s\n", have,
               (int)(have == n && p != NULL && memcmp(p, wanted, (size_t)n) == 0),
               chain(errbuf, sizeof errbuf));
    }

    /* The `_ex` reader, with the flag word the plain spelling uses. */
    {
        char *name = NULL, *header = NULL;
        unsigned char *data = NULL;
        long len = 0;
        int rv = PEM_read_bio_ex(bio, &name, &header, &data, &len, PEM_FLAG_EAY_COMPATIBLE);

        printf("read.eay.rv=%d name=%s header_len=%d header_ok=%d len=%ld body=%d err=%s\n", rv,
               name == NULL ? "(null)" : name, header == NULL ? -1 : (int)strlen(header),
               (int)(header != NULL && strcmp(header, BLOCK_HEADER) == 0), len,
               (int)(len == 5 && data != NULL && memcmp(data, BLOCK_BODY, 5) == 0),
               chain(errbuf, sizeof errbuf));
        OPENSSL_free(name);
        OPENSSL_free(header);
        OPENSSL_free(data);
    }

    /* The same block through the plain spelling, from a fresh memory BIO. */
    {
        BIO *again = make_block(BLOCK_NAME, BLOCK_HEADER, BLOCK_BODY, 5);
        char *name = NULL, *header = NULL;
        unsigned char *data = NULL;
        long len = 0;
        int rv = again == NULL ? -99
                               : PEM_read_bio(again, &name, &header, &data, &len);

        printf("read.plain.rv=%d name=%s len=%ld body=%d err=%s\n", rv,
               name == NULL ? "(null)" : name, len,
               (int)(len == 5 && data != NULL && memcmp(data, BLOCK_BODY, 5) == 0),
               chain(errbuf, sizeof errbuf));
        OPENSSL_free(name);
        OPENSSL_free(header);
        OPENSSL_free(data);
        BIO_free(again);
    }

    /* A block with no header at all: the reader's two BIOs are *swapped* rather than copied, and
     * the header out-parameter is the empty string. */
    {
        BIO *nohdr = make_block("NO HEADER", "", BLOCK_BODY, 5);

        if (nohdr != NULL) {
            char *name = NULL, *header = NULL;
            unsigned char *data = NULL;
            long len = 0;
            int rv = PEM_read_bio_ex(nohdr, &name, &header, &data, &len, PEM_FLAG_EAY_COMPATIBLE);

            printf("read.no_header.rv=%d name=%s header_len=%d len=%ld body=%d err=%s\n", rv,
                   name == NULL ? "(null)" : name,
                   header == NULL ? -1 : (int)strlen(header), len,
                   (int)(len == 5 && data != NULL && memcmp(data, BLOCK_BODY, 5) == 0),
                   chain(errbuf, sizeof errbuf));
            OPENSSL_free(name);
            OPENSSL_free(header);
            OPENSSL_free(data);
            BIO_free(nohdr);
        }
        (void)elen;
    }

    BIO_free(bio);
}

/* Every `PEM_read_bio_ex` edge the probe can build by hand. */
static void read_edges(void)
{
    char errbuf[512];

    /* The two flags are mutually incompatible: refused before anything is allocated. */
    {
        BIO *bio = make_block(BLOCK_NAME, BLOCK_HEADER, BLOCK_BODY, 5);
        char *name = NULL, *header = NULL;
        unsigned char *data = NULL;
        long len = 7;

        sayd("read.flag_pair",
             PEM_read_bio_ex(bio, &name, &header, &data, &len,
                             PEM_FLAG_EAY_COMPATIBLE | PEM_FLAG_ONLY_B64));
        sayn("read.flag_pair.len", len);
        sayn("read.flag_pair.name_null", name == NULL);
        BIO_free(bio);
    }

    /* A BEGIN line and an END line with different names. */
    {
        BIO *bio = BIO_new(BIO_s_mem());

        BIO_puts(bio, "-----BEGIN TEST ITEM-----\nYWJjZA==\n-----END OTHER-----\n");
        {
            char *name = NULL, *header = NULL;
            unsigned char *data = NULL;
            long len = 0;

            sayd("read.name_mismatch",
                 PEM_read_bio_ex(bio, &name, &header, &data, &len, PEM_FLAG_EAY_COMPATIBLE));
        }
        BIO_free(bio);
    }

    /* A body with no end line at all: the reader runs out of input. */
    {
        BIO *bio = BIO_new(BIO_s_mem());

        BIO_puts(bio, "-----BEGIN TEST ITEM-----\nYWJjZA==\n");
        {
            char *name = NULL, *header = NULL;
            unsigned char *data = NULL;
            long len = 0;

            sayd("read.truncated",
                 PEM_read_bio_ex(bio, &name, &header, &data, &len, PEM_FLAG_EAY_COMPATIBLE));
        }
        BIO_free(bio);
    }

    /* A body with a character the decoder refuses. */
    {
        BIO *bio = BIO_new(BIO_s_mem());

        BIO_puts(bio, "-----BEGIN TEST ITEM-----\n!!!!\n-----END TEST ITEM-----\n");
        {
            char *name = NULL, *header = NULL;
            unsigned char *data = NULL;
            long len = 0;

            sayd("read.bad_base64",
                 PEM_read_bio_ex(bio, &name, &header, &data, &len, PEM_FLAG_EAY_COMPATIBLE));
        }
        BIO_free(bio);
    }

    /* A body that decodes to nothing: a plain zero with **no** error raised, which is the reader's
     * `len == 0` early return and not a refusal. */
    {
        BIO *bio = BIO_new(BIO_s_mem());

        BIO_puts(bio, "-----BEGIN TEST ITEM-----\n\n-----END TEST ITEM-----\n");
        {
            char *name = NULL, *header = NULL;
            unsigned char *data = NULL;
            long len = 99;

            printf("read.empty_body=%d name_null=%d data_null=%d len=%ld chain=%s\n",
                   PEM_read_bio_ex(bio, &name, &header, &data, &len, PEM_FLAG_EAY_COMPATIBLE),
                   (int)(name == NULL), (int)(data == NULL), len, chain(errbuf, sizeof errbuf));
        }
        BIO_free(bio);
    }

    /* A blank line *after* the header's blank line: `POST_HEADER` twice. */
    {
        BIO *bio = BIO_new(BIO_s_mem());

        BIO_puts(bio, "-----BEGIN TEST ITEM-----\nX: y\n\n\nYWJjZA==\n-----END TEST ITEM-----\n");
        {
            char *name = NULL, *header = NULL;
            unsigned char *data = NULL;
            long len = 0;

            sayd("read.double_blank",
                 PEM_read_bio_ex(bio, &name, &header, &data, &len, PEM_FLAG_EAY_COMPATIBLE));
        }
        BIO_free(bio);
    }

    /* The BOM is stripped from the first line, and nothing else is. */
    {
        BIO *bio = BIO_new(BIO_s_mem());

        BIO_write(bio, "\xef\xbb\xbf", 3);
        BIO_puts(bio, "-----BEGIN TEST ITEM-----\nYWJjZA==\n-----END TEST ITEM-----\n");
        {
            char *name = NULL, *header = NULL;
            unsigned char *data = NULL;
            long len = 0;
            int rv = PEM_read_bio_ex(bio, &name, &header, &data, &len, PEM_FLAG_EAY_COMPATIBLE);

            printf("read.bom.rv=%d name=%s len=%ld body=%d err=%s\n", rv,
                   name == NULL ? "(null)" : name, len,
                   (int)(len == 4 && data != NULL && memcmp(data, "abcd", 4) == 0),
                   chain(errbuf, sizeof errbuf));
            OPENSSL_free(name);
            OPENSSL_free(header);
            OPENSSL_free(data);
        }
        BIO_free(bio);
    }

    /* `PEM_FLAG_SECURE`: the same block, allocated from the secure heap. */
    {
        BIO *bio = make_block(BLOCK_NAME, BLOCK_HEADER, BLOCK_BODY, 5);

        if (bio != NULL) {
            char *name = NULL, *header = NULL;
            unsigned char *data = NULL;
            long len = 0;
            int rv = PEM_read_bio_ex(bio, &name, &header, &data, &len,
                                     PEM_FLAG_SECURE | PEM_FLAG_EAY_COMPATIBLE);

            printf("read.secure.rv=%d len=%ld body=%d err=%s\n", rv, len,
                   (int)(len == 5 && data != NULL && memcmp(data, BLOCK_BODY, 5) == 0),
                   chain(errbuf, sizeof errbuf));
            /* `PEM_read_bio_ex`'s `PEM_MALLOC` was the secure one, so the matching free is
             * `OPENSSL_secure_free` -- and it is the flag that decides, which is the observation. */
            OPENSSL_secure_free(name);
            OPENSSL_secure_free(header);
            /* The data block's length is part of the free, which is why the length is kept. */
            CRYPTO_secure_clear_free(data, (size_t)len, NULL, 0);
            BIO_free(bio);
        }
    }
}

/*
 * `get_header_and_data`'s one length test: 65 bytes **including the trailing newline**, and it
 * applies only after the header has ended. A 64-byte content line is therefore the last one
 * accepted, and the refusal at 65 comes from `goto err` with **no** `ERR_raise` after it
 * (`crypto/pem/pem_lib.c:925-928`), which is why the two arms differ in their chains as well as
 * in their return codes.
 */
static void line_length(void)
{
    int content;

    for (content = 64; content <= 65; content++) {
        char line[80];
        char key[64];
        BIO *bio = BIO_new(BIO_s_mem());
        char *name = NULL, *header = NULL;
        unsigned char *data = NULL;
        long len = 0;
        int rv;
        char errbuf[512];

        memset(line, 'A', (size_t)content);
        line[content] = '\0';
        BIO_puts(bio, "-----BEGIN TEST ITEM-----\nX: y\n\n");
        BIO_puts(bio, line);
        BIO_puts(bio, "\n-----END TEST ITEM-----\n");

        rv = PEM_read_bio_ex(bio, &name, &header, &data, &len, PEM_FLAG_EAY_COMPATIBLE);
        snprintf(key, sizeof key, "read.line_%d.rv", content);
        printf("%s=%d name_null=%d len=%ld chain=%s\n", key, rv, (int)(name == NULL), len,
               chain(errbuf, sizeof errbuf));
        BIO_free(bio);
    }
}

/*
 * `sanitize_line` is three rules in one function and they are not interchangeable
 * (`crypto/pem/pem_lib.c:722-765`). The same body, with one internal space and then with one
 * internal control byte, takes a different path under each of `EAY_COMPATIBLE`, `ONLY_B64` and
 * the default (no flag).
 *
 *   * `EAY_COMPATIBLE` strips *trailing* whitespace only, so the space stays and the decoder
 *     skips it -- but the control byte stays too, and `conv_ascii2bin` reads it as `B64_ERROR`;
 *   * `ONLY_B64` truncates the line at the first byte that is not base64, so the space ends the
 *     body's content and the tail of the group is lost with it;
 *   * the default replaces control bytes with spaces and keeps everything else, so the control
 *     byte is decoded as the whitespace the decoder was going to skip anyway.
 */
static void sanitize_rules(void)
{
    struct {
        const char *key;
        const char *body;
        unsigned int flags;
    } arms[] = {
        { "read.sanitize.eay_space", "YWJj ZA==\n", PEM_FLAG_EAY_COMPATIBLE },
        { "read.sanitize.onlyb64_space", "YWJj ZA==\n", PEM_FLAG_ONLY_B64 },
        { "read.sanitize.eay_ctrl", "YW\x01JjZA==\n", PEM_FLAG_EAY_COMPATIBLE },
        { "read.sanitize.default_ctrl", "YW\x01JjZA==\n", 0u },
    };
    size_t i;

    for (i = 0; i < sizeof arms / sizeof arms[0]; i++) {
        BIO *bio = BIO_new(BIO_s_mem());
        char *name = NULL, *header = NULL;
        unsigned char *data = NULL;
        long len = 0;
        int rv;
        char errbuf[512];

        BIO_puts(bio, "-----BEGIN TEST ITEM-----\nX: y\n\n");
        BIO_write(bio, arms[i].body, (int)strlen(arms[i].body));
        BIO_puts(bio, "-----END TEST ITEM-----\n");

        rv = PEM_read_bio_ex(bio, &name, &header, &data, &len, arms[i].flags);
        printf("%s.rv=%d len=%ld bytes=", arms[i].key, rv, len);
        if (rv == 1 && data != NULL) {
            long k;

            for (k = 0; k < len; k++)
                printf("%02x", data[k]);
        } else {
            printf("-");
        }
        printf(" err=%s\n", chain(errbuf, sizeof errbuf));
        OPENSSL_free(name);
        OPENSSL_free(header);
        OPENSSL_free(data);
        BIO_free(bio);
    }
}

/* Every `PEM_get_EVP_CIPHER_INFO` arm this probe's own legacy cipher makes reachable. */
static void cipher_info(void)
{
    EVP_CIPHER_INFO info;
    char errbuf[512];
    int i;

    /* First: what the function does with a name only a *provider* publishes. It answers NULL,
     * because its third step retries the **legacy** table under every alias the namemap knows
     * (`crypto/evp/names.c:114-117`) and a provider's cipher was never inserted there. */
    {
        EVP_CIPHER *prov = EVP_CIPHER_fetch(NULL, "COURT-PEM-CIPH", NULL);
        const EVP_CIPHER *by_name;

        sayn("cipher_info.provider_fetched", prov != NULL);
        if (prov != NULL) {
            by_name = EVP_get_cipherbyname("COURT-PEM-CIPH");
            printf("cipher_info.provider_by_name.null=%d err=%s\n", (int)(by_name == NULL),
                   chain(errbuf, sizeof errbuf));
        }
        EVP_CIPHER_free(prov);
    }

    /* `PEM_get_EVP_CIPHER_INFO` zeroes its out-parameter first, so every refusal is observed as
     * "the cipher is NULL and the IV is zeroed" rather than by the return code alone. */
    memset(&info, 0xa5, sizeof info);
    {
        char empty = '\0';
        int rv = PEM_get_EVP_CIPHER_INFO(&empty, &info);

        printf("cipher_info.empty.rv=%d cipher_null=%d iv_zero=%d err=%s\n", rv,
               (int)(info.cipher == NULL), (int)(info.iv[0] == 0 && info.iv[15] == 0),
               chain(errbuf, sizeof errbuf));
    }

    memset(&info, 0xa5, sizeof info);
    sayd("cipher_info.null_header", PEM_get_EVP_CIPHER_INFO(NULL, &info));

    {
        char buf[160];

        snprintf(buf, sizeof buf, "Not-Proc-Type: 4,ENCRYPTED\n");
        memset(&info, 0xa5, sizeof info);
        sayd("cipher_info.not_proc_type", PEM_get_EVP_CIPHER_INFO(buf, &info));

        snprintf(buf, sizeof buf, "Proc-Type: 5,ENCRYPTED\nDEK-Info: X,00\n");
        memset(&info, 0xa5, sizeof info);
        sayd("cipher_info.bad_version", PEM_get_EVP_CIPHER_INFO(buf, &info));

        snprintf(buf, sizeof buf, "Proc-Type: 4,NOTENCRYPTED\nDEK-Info: X,00\n");
        memset(&info, 0xa5, sizeof info);
        sayd("cipher_info.not_encrypted", PEM_get_EVP_CIPHER_INFO(buf, &info));

        snprintf(buf, sizeof buf, "Proc-Type: 4,ENCRYPTED");
        memset(&info, 0xa5, sizeof info);
        sayd("cipher_info.short_header", PEM_get_EVP_CIPHER_INFO(buf, &info));

        snprintf(buf, sizeof buf, "Proc-Type: 4,ENCRYPTED\n");
        memset(&info, 0xa5, sizeof info);
        sayd("cipher_info.not_dek_info", PEM_get_EVP_CIPHER_INFO(buf, &info));

        snprintf(buf, sizeof buf, "Proc-Type: 4,ENCRYPTED\nDEK-Info: NO-SUCH-CIPHER,00\n");
        memset(&info, 0xa5, sizeof info);
        sayd("cipher_info.unknown_algo", PEM_get_EVP_CIPHER_INFO(buf, &info));
    }

    /* An 8-byte-IV method, registered by the probe, under `NID_undef`'s short name. */
    {
        EVP_CIPHER *c8 = legacy_cipher(8);

        sayn("cipher_info.legacy_cipher.registered", c8 != NULL);
        if (c8 != NULL) {
            char buf[160];
            int rv;

            sayn("cipher_info.by_name.same", EVP_get_cipherbyname("UNDEF") == c8);

            snprintf(buf, sizeof buf,
                     "Proc-Type: 4,ENCRYPTED\nDEK-Info: UNDEF,0001020304050607\n");
            memset(&info, 0xa5, sizeof info);
            rv = PEM_get_EVP_CIPHER_INFO(buf, &info);
            printf("cipher_info.ok.rv=%d cipher_same=%d iv=", rv, (int)(info.cipher == c8));
            for (i = 0; i < (int)sizeof info.iv; i++)
                printf("%02x", info.iv[i]);
            printf(" err=%s\n", chain(errbuf, sizeof errbuf));

            /* Lower-case hex, and a trailing byte the parser does not read past the IV length. */
            snprintf(buf, sizeof buf,
                     "Proc-Type: 4,ENCRYPTED\nDEK-Info: UNDEF,ffffffffffffffffffffffffffffffff\n");
            memset(&info, 0xa5, sizeof info);
            rv = PEM_get_EVP_CIPHER_INFO(buf, &info);
            printf("cipher_info.lower_hex.rv=%d all_ff=%d err=%s\n", rv,
                   (int)(info.iv[0] == 0xff && info.iv[7] == 0xff),
                   chain(errbuf, sizeof errbuf));

            /* A name that resolves but carries no comma: the IV is required. The trailing space is
             * the byte `strcspn` stops on, so the name is the bare one. */
            snprintf(buf, sizeof buf, "Proc-Type: 4,ENCRYPTED\nDEK-Info: UNDEF \n");
            memset(&info, 0xa5, sizeof info);
            sayd("cipher_info.missing_iv", PEM_get_EVP_CIPHER_INFO(buf, &info));

            /* Fifteen hex digits: the walk reaches the terminator, where hexchar2int answers -1. */
            snprintf(buf, sizeof buf,
                     "Proc-Type: 4,ENCRYPTED\nDEK-Info: UNDEF,000102030405060\n");
            memset(&info, 0xa5, sizeof info);
            sayd("cipher_info.truncated_iv", PEM_get_EVP_CIPHER_INFO(buf, &info));

            /* A non-hex character where a hex digit belongs. */
            snprintf(buf, sizeof buf,
                     "Proc-Type: 4,ENCRYPTED\nDEK-Info: UNDEF,00010203040506ZZ\n");
            memset(&info, 0xa5, sizeof info);
            sayd("cipher_info.non_hex_iv", PEM_get_EVP_CIPHER_INFO(buf, &info));
        }
    }

    /* A method with **no** IV, registered over the same name: the comma is then the error. */
    {
        EVP_CIPHER *c0 = legacy_cipher(0);

        sayn("cipher_info.zero_iv_cipher.registered", c0 != NULL);
        if (c0 != NULL) {
            char buf[160];
            int rv;

            sayn("cipher_info.zero_iv.by_name.same", EVP_get_cipherbyname("UNDEF") == c0);

            snprintf(buf, sizeof buf, "Proc-Type: 4,ENCRYPTED\nDEK-Info: UNDEF,00\n");
            memset(&info, 0xa5, sizeof info);
            sayd("cipher_info.unexpected_iv", PEM_get_EVP_CIPHER_INFO(buf, &info));

            snprintf(buf, sizeof buf, "Proc-Type: 4,ENCRYPTED\nDEK-Info: UNDEF\n");
            memset(&info, 0xa5, sizeof info);
            sayd("cipher_info.name_takes_newline", PEM_get_EVP_CIPHER_INFO(buf, &info));

            /* The name ends at `,`, `' '` or `'\t'` and at nothing else (`strcspn(header,
             * " \t,")`), so a name followed directly by the line ending carries the `'\n'` into
             * the lookup and cannot resolve -- and the zero-IV success path is reachable only
             * through a name terminated by one of those three bytes. */
            snprintf(buf, sizeof buf, "Proc-Type: 4,ENCRYPTED\nDEK-Info: UNDEF \n");
            memset(&info, 0xa5, sizeof info);
            rv = PEM_get_EVP_CIPHER_INFO(buf, &info);
            printf("cipher_info.zero_iv_ok.rv=%d cipher_same=%d iv_zero=%d err=%s\n", rv,
                   (int)(info.cipher == c0), (int)(info.iv[0] == 0 && info.iv[7] == 0),
                   chain(errbuf, sizeof errbuf));
        }
    }

    /* A name that resolves only through the **legacy** `OBJ_NAME` table the authority's own
     * `OPENSSL_init_crypto(ADD_ALL_CIPHERS)` fills -- `DES-CBC` -- is deliberately not driven: the
     * authority's table holds it and the candidate's is empty until Phase 13, so the two lanes
     * answer different things for a reason that is a *contents* distribution gap and not this
     * row's behaviour (`docs/DECISIONS.md` D162, D194). */
    printf("cipher_info.legacy_name=NOT_MEASURED_LEGACY_OBJ_NAME_TABLE_IS_PHASE_13_pem_lib_c_571\n");
}

/* ---- `PEM_SignInit`/`PEM_SignUpdate`/`PEM_SignFinal` ---------------------------------------- */

static void sign_wrappers(EVP_MD *md)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_MD_CTX *ref = EVP_MD_CTX_new();
    unsigned char got[64], own[64];
    unsigned int gotlen = 0, ownlen = 0;
    char errbuf[512];
    int i1, i2, i3, f1;

    if (md == NULL) {
        printf("sign.wrappers=NOT_MEASURED_NO_PROVIDER_MD\n");
        EVP_MD_CTX_free(ctx);
        EVP_MD_CTX_free(ref);
        return;
    }

    sayn("sign.init", PEM_SignInit(ctx, md));
    sayn("sign.update.first", PEM_SignUpdate(ctx, (const unsigned char *)BLOCK_BODY, 5));
    sayn("sign.update.second", PEM_SignUpdate(ctx, (const unsigned char *)"abc", 3));
    sayn("sign.final_ex", EVP_DigestFinal_ex(ctx, got, &gotlen));

    /* The same three updates on a second context, so the comparison is against a digest the probe
     * computed itself and not against a constant. */
    i1 = EVP_DigestInit_ex(ref, md, NULL);
    i2 = EVP_DigestUpdate(ref, (const unsigned char *)BLOCK_BODY, 5);
    i3 = EVP_DigestUpdate(ref, (const unsigned char *)"abc", 3);
    f1 = EVP_DigestFinal_ex(ref, own, &ownlen);
    printf("sign.wrappers.agree=%d own=%u got=%u ref_init=%d%d%d%d err=%s\n",
           (int)(ownlen == gotlen && memcmp(own, got, ownlen) == 0), ownlen, gotlen, i1, i2, i3, f1,
           chain(errbuf, sizeof errbuf));

    /*
     * `PEM_SignFinal` with a key that has no signature method. `EVP_PKEY_new()` has no ameth and no
     * cached size, so `EVP_PKEY_get_size` raises `EVP_R_UNKNOWN_MAX_SIZE` and answers 0
     * (`crypto/evp/p_lib.c:1866`), and `OPENSSL_malloc(0)` is NULL -- `CRYPTO_malloc` refuses a
     * zero-length request (`crypto/mem.c:201`) -- so the function takes its `m == NULL` early exit
     * and the signature buffer is untouched. That is the whole of it that is reachable without a
     * provider key; the signing arm is `RT-EVP-PKEY`'s, which has one.
     */
    {
        EVP_PKEY *pkey = EVP_PKEY_new();
        EVP_MD_CTX *one = EVP_MD_CTX_new();
        unsigned char sig[64];
        unsigned int siglen = 0;
        int rv;

        memset(sig, 0x5a, sizeof sig);
        rv = PEM_SignFinal(one, sig, &siglen, pkey);
        printf("sign.final.nosig.rv=%d siglen=%u untouched=%d err=%s\n", rv, siglen,
               (int)(sig[0] == 0x5a && sig[63] == 0x5a), chain(errbuf, sizeof errbuf));
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(one);
    }

    EVP_MD_CTX_free(ctx);
    EVP_MD_CTX_free(ref);
}

/* ---- `PEM_write_bio_ASN1_stream` (the `asn1.h` hand-off that builds) ------------------------- */

static void asn1_stream(void)
{
    ASN1_INTEGER *val = ASN1_INTEGER_new();
    BIO *out = BIO_new(BIO_s_mem());
    unsigned char der[64];
    unsigned char *dp = der;
    int derlen;
    int rv;
    char errbuf[512];

    if (val == NULL || out == NULL) {
        printf("asn1_stream.setup=0 err=%s\n", chain(errbuf, sizeof errbuf));
        ASN1_INTEGER_free(val);
        BIO_free(out);
        return;
    }
    ASN1_INTEGER_set(val, 0x1234);
    derlen = i2d_ASN1_INTEGER(val, &dp);

    /* `flags == 0` is the non-streaming arm, so `in` is never read and a NULL is faithful. */
    rv = PEM_write_bio_ASN1_stream(out, (ASN1_VALUE *)val, NULL, 0, "TEST INT",
                                   ASN1_INTEGER_it());
    printf("asn1_stream.rv=%d derlen=%d err=%s\n", rv, derlen, chain(errbuf, sizeof errbuf));

    /* The whole produced block is compared against the probe's own framing: the header, the
     * `EVP_EncodeBlock` of exactly the DER that was written, and the footer. */
    {
        char *p = NULL;
        long have = BIO_get_mem_data(out, &p);
        char body[128];
        int blen = EVP_EncodeBlock((unsigned char *)body, der, derlen);
        char want[512];
        int n = snprintf(want, sizeof want, "-----BEGIN TEST INT-----\n%s\n-----END TEST INT-----\n",
                         body);

        printf("asn1_stream.produced.len=%ld matches=%d wanted=%d blen=%d err=%s\n", have,
               (int)(p != NULL && have == n && memcmp(p, want, (size_t)n) == 0), n, blen,
               chain(errbuf, sizeof errbuf));

        if (p != NULL && have > 0) {
            BIO *back = BIO_new(BIO_s_mem());
            char *name = NULL, *header = NULL;
            unsigned char *data = NULL;
            long len = 0;

            BIO_write(back, p, have);
            rv = PEM_read_bio_ex(back, &name, &header, &data, &len, PEM_FLAG_EAY_COMPATIBLE);
            printf("asn1_stream.read.rv=%d name=%s len=%ld der_matches=%d err=%s\n", rv,
                   name == NULL ? "(null)" : name, len,
                   (int)(len == derlen && data != NULL && memcmp(data, der, (size_t)derlen) == 0),
                   chain(errbuf, sizeof errbuf));
            OPENSSL_free(name);
            OPENSSL_free(header);
            OPENSSL_free(data);
            BIO_free(back);
        }
    }

    ASN1_INTEGER_free(val);
    BIO_free(out);
}

/* The `FILE *` spellings, which is how `BIO_s_file` is reached from this row. */
static void file_spellings(void)
{
    FILE *fp = tmpfile();
    char *name = NULL, *header = NULL;
    unsigned char *data = NULL;
    long len = 0;
    int w, r;
    char errbuf[512];

    if (fp == NULL) {
        printf("file.tmpfile=0 err=%s\n", chain(errbuf, sizeof errbuf));
        return;
    }

    w = PEM_write(fp, BLOCK_NAME, BLOCK_HEADER, (const unsigned char *)BLOCK_BODY, 5);
    rewind(fp);
    r = PEM_read(fp, &name, &header, &data, &len);
    printf("file.rv.write=%d read=%d name=%s header_len=%d header_ok=%d len=%ld body=%d err=%s\n",
           w, r, name == NULL ? "(null)" : name,
           header == NULL ? -1 : (int)strlen(header),
           (int)(header != NULL && strcmp(header, BLOCK_HEADER) == 0), len,
           (int)(len == 5 && data != NULL && memcmp(data, BLOCK_BODY, 5) == 0),
           chain(errbuf, sizeof errbuf));
    OPENSSL_free(name);
    OPENSSL_free(header);
    OPENSSL_free(data);
    fclose(fp);
}

/* The twenty-five names this row cannot build, one line each: the blocker and its coordinate. */
static void not_measured(void)
{
    printf("PEM_do_header=NOT_MEASURED_EVP_md5_IS_PHASE_13_legacy_md5_c_36_pem_lib_c_479\n");
    printf("PEM_bytes_read_bio=NOT_MEASURED_PEM_do_header_pem_lib_c_266\n");
    printf("PEM_bytes_read_bio_secmem=NOT_MEASURED_PEM_do_header_pem_lib_c_266\n");
    printf("PEM_ASN1_read_bio=NOT_MEASURED_PEM_bytes_read_bio_pem_oth_c_28\n");
    printf("PEM_ASN1_read=NOT_MEASURED_PEM_ASN1_read_bio_pem_lib_c_122\n");
    printf("PEM_ASN1_write_bio=NOT_MEASURED_EVP_md5_IS_PHASE_13_legacy_md5_c_36_pem_lib_c_392\n");
    printf("PEM_ASN1_write_bio_ctx=NOT_MEASURED_EVP_md5_IS_PHASE_13_legacy_md5_c_36_pem_lib_c_392\n");
    printf("PEM_ASN1_write=NOT_MEASURED_PEM_ASN1_write_bio_pem_lib_c_316\n");
    printf("PEM_def_callback=NOT_MEASURED_EVP_read_pw_string_min_IS_PHASE_13_UI_pem_lib_c_62\n");
    printf("PEM_read_bio_PrivateKey_ex=NOT_MEASURED_OSSL_DECODER_CTX_new_for_pkey_PHASE_10_pem_pkey_c_49\n");
    printf("PEM_read_bio_PrivateKey=NOT_MEASURED_OSSL_DECODER_CTX_new_for_pkey_PHASE_10_pem_pkey_c_49\n");
    printf("PEM_read_PrivateKey_ex=NOT_MEASURED_OSSL_DECODER_CTX_new_for_pkey_PHASE_10_pem_pkey_c_49\n");
    printf("PEM_read_PrivateKey=NOT_MEASURED_OSSL_DECODER_CTX_new_for_pkey_PHASE_10_pem_pkey_c_49\n");
    printf("PEM_read_bio_Parameters_ex=NOT_MEASURED_OSSL_DECODER_CTX_new_for_pkey_PHASE_10_pem_pkey_c_49\n");
    printf("PEM_read_bio_Parameters=NOT_MEASURED_OSSL_DECODER_CTX_new_for_pkey_PHASE_10_pem_pkey_c_49\n");
    printf("PEM_write_bio_PrivateKey_ex=NOT_MEASURED_OSSL_ENCODER_CTX_new_for_pkey_PHASE_10_pem_local_h_44\n");
    printf("PEM_write_bio_PrivateKey=NOT_MEASURED_OSSL_ENCODER_CTX_new_for_pkey_PHASE_10_pem_local_h_44\n");
    printf("PEM_write_PrivateKey_ex=NOT_MEASURED_OSSL_ENCODER_CTX_new_for_pkey_PHASE_10_pem_local_h_44\n");
    printf("PEM_write_PrivateKey=NOT_MEASURED_OSSL_ENCODER_CTX_new_for_pkey_PHASE_10_pem_local_h_44\n");
    printf("PEM_write_bio_Parameters=NOT_MEASURED_OSSL_ENCODER_CTX_new_for_pkey_PHASE_10_pem_local_h_44\n");
    printf("PEM_write_bio_PrivateKey_traditional=NOT_MEASURED_evp_pkey_copy_downgraded_IS_PHASE_8_pem_pkey_c_356\n");
    printf("PEM_write_bio_PKCS8PrivateKey=NOT_MEASURED_OSSL_ENCODER_CTX_new_for_pkey_PHASE_10_pem_pk8_c_75\n");
    printf("PEM_write_PKCS8PrivateKey=NOT_MEASURED_OSSL_ENCODER_CTX_new_for_pkey_PHASE_10_pem_pk8_c_75\n");
    printf("PEM_write_bio_PKCS8PrivateKey_nid=NOT_MEASURED_OSSL_ENCODER_CTX_new_for_pkey_PHASE_10_pem_pk8_c_75\n");
    printf("PEM_write_PKCS8PrivateKey_nid=NOT_MEASURED_OSSL_ENCODER_CTX_new_for_pkey_PHASE_10_pem_pk8_c_75\n");
}

int main(void)
{
    OSSL_PROVIDER *prov = NULL;
    EVP_MD *md = NULL;

    setvbuf(stdout, NULL, _IOLBF, 0);

    /* The provider goes into the **default** library context, because `EVP_get_cipherbyname`
     * resolves in that context and `PEM_get_EVP_CIPHER_INFO` is built on it. The authority's own
     * default provider is activated lazily and publishes neither of the probe's names. */
    if (OSSL_PROVIDER_add_builtin(NULL, "court-pem", ct_provider_init))
        prov = OSSL_PROVIDER_load(NULL, "court-pem");
    sayn("provider.loaded", prov != NULL);
    if (prov != NULL)
        md = EVP_MD_fetch(NULL, "COURT-PEM-MD", NULL);

    write_then_read();
    read_edges();
    line_length();
    sanitize_rules();
    cipher_info();
    sign_wrappers(md);
    asn1_stream();
    file_spellings();
    not_measured();

    EVP_MD_free(md);
    if (prov != NULL)
        OSSL_PROVIDER_unload(prov);
    return 0;
}
