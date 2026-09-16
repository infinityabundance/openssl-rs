/*
 * RT-EVP-CIPHER -- the `EVP_CIPHER` method object, from the angle 7.3b can be asked in.
 *
 * What this court can observe
 * --------------------------
 * 7.3b lands the *method object*: `crypto/evp/evp_enc.c`'s fetch half, `evp_lib.c`'s thirteen
 * method-object accessors, `crypto/evp/cmeth_lib.c` whole, and `crypto/evp/e_null.c`'s
 * `EVP_enc_null`. `EVP_CIPHER_CTX` and the `EVP_Encrypt*`/`EVP_Decrypt*`/`EVP_Cipher*` family are
 * 7.3c's, and every `EVP_CIPHER_CTX_*` name is therefore **absent from this probe by design**:
 * a probe that called one would abort the candidate on a scaffold, which is a missing-symbol
 * reading rather than a behavioural one.
 *
 * So the observables are the method object and the two paths that build one:
 *
 *   * **the fetch**, through a provider this probe publishes. Four algorithms, each chosen for
 *     one clause of `evp_cipher_from_algorithm`'s structural check:
 *       - `court-one`, the smallest legal shape: `newctx` + `freectx` + a standalone `cipher`
 *         one-shot. `fnciphcnt` is 0 and `ccipher` carries it -- the arm a transcription that
 *         required three functions would wrongly refuse;
 *       - `court-enc`, `newctx` + `freectx` + `encrypt_init` + `update` + `final` -- `fnciphcnt`
 *         is 3, the other accepted arm;
 *       - `court-pipe`, `newctx` + `freectx` + `pipeline_encrypt_init` + `pipeline_update` +
 *         `pipeline_final` -- `fnpipecnt` is 3, which is legal on its own, and with **no**
 *         `pipeline_decrypt_init` it is also the only shape that separates
 *         `EVP_CIPHER_can_pipeline(c, 1)` from `EVP_CIPHER_can_pipeline(c, 0)`;
 *       - `court-bad`, `newctx` + `freectx` + `update` with no `final` -- `fnciphcnt` is 1, which
 *         no clause accepts. **This one is why the refusal is worth observing**: the name exists
 *         in the namemap only after a constructor has been *entered*, so this fetch takes the
 *         `ERR_R_FETCH_FAILED` arm of `inner_evp_generic_fetch`'s two reasons while a name nobody
 *         publishes takes `ERR_R_UNSUPPORTED`. The two arms share one message and differ only in
 *         the code, and this is the only observation of the second one.
 *   * **the accessors**, on the object the fetch produced: the name, the description, the two
 *     lengths, the block size, the legacy NID and type, `is_a` against three spellings, the
 *     provider's presence, the case-insensitive free, and the reference count.
 *   * **the parameters**, because `evp_cipher_cache_constants` is where the flags come from and
 *     the flags are the one value here that a plausible-but-wrong transcription changes: this
 *     probe's provider answers `mode` GCM, `aead` 1, `custom-iv` 1, `encrypt-then-mac` 1 and
 *     publishes `algorithm-id-params` in its gettable-ctx list, so the authority ORs five
 *     distinct bits onto the mode and the observed mask is the evidence.
 *   * **`cmeth_lib.c`**, which is reachable without a provider at all: a method built by hand,
 *     the append-only setters, the getters that answer what they stored, the duplicate, and the
 *     two destructors that refuse each other's objects.
 *   * **`EVP_enc_null`**, the one `e_*.c` wrapper with no Phase-13 primitive under it: a
 *     read-only global whose address is stable, whose `origin` makes `EVP_CIPHER_free` a no-op,
 *     and whose `do_cipher` is the `memcpy` the legacy ciphers all imitate.
 *
 * What it deliberately does not observe
 * -------------------------------------
 *   * **anything that takes a context.** `EVP_CIPHER_CTX_new`, `EVP_EncryptInit_ex`, the four
 *     `EVP_CIPHER_CTX_*` accessors and the `EVP_CIPHER_param_to_asn1` family are 7.3c's; calling
 *     one aborts the candidate.
 *   * **the `EVP_CIPHER_do_all*` walkers in `names.c`**, which are 7.3g's, and the legacy
 *     wrapper statics besides `EVP_enc_null`, which are Phase 13's — `e_aes.c` calls
 *     `AES_encrypt`, and this probe does not pretend a stub for one would be an observation of
 *     the other.
 *   * **the size of the activated provider set.** `EVP_CIPHER_do_all_provided` is observed with a
 *     visitor that counts only *this* provider's names. The set of providers a context activates
 *     is `crypto/provider_core.c`'s and this stratum's business is what the walk does with what
 *     it finds: an unfiltered count would read a difference in that set as a difference in this
 *     stratum, which is the class of residual a court must not manufacture.
 *
 * Addresses are never printed. Every observation is a relation between two pointers this probe
 * holds (`same` / `different`), a presence answer (`NULL` / `nonnull`), a return code, or an
 * integer the two libraries' own headers define.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/params.h>
#include <openssl/provider.h>

static void sayp(const char *key, const void *p)
{
    printf("%s=%s err=%lu\n", key, p == NULL ? "NULL" : "nonnull", ERR_peek_error());
    ERR_clear_error();
}

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

/* The parameters this provider answers, and the values it answers them with. They are not a
 * cipher: every one of them is chosen so that a distinct branch of `evp_cipher_cache_constants`
 * has something to set, and the digest the one-shot function computes is a byte pattern rather
 * than a security claim. */
#define COURT_BLOCK_SIZE 16
#define COURT_IV_LEN 12
#define COURT_KEY_LEN 32

static int court_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    size_t blksz = COURT_BLOCK_SIZE;
    size_t ivlen = COURT_IV_LEN;
    size_t keylen = COURT_KEY_LEN;
    unsigned int mode = EVP_CIPH_GCM_MODE;
    int aead = 1;
    int custom_iv = 1;
    int cts = 0;
    int multi = 0;
    int randkey = 0;
    int etm = 1;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, blksz))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ivlen))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, keylen))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
    if (p != NULL && !OSSL_PARAM_set_uint(p, mode))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD);
    if (p != NULL && !OSSL_PARAM_set_int(p, aead))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CUSTOM_IV);
    if (p != NULL && !OSSL_PARAM_set_int(p, custom_iv))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CTS);
    if (p != NULL && !OSSL_PARAM_set_int(p, cts))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK);
    if (p != NULL && !OSSL_PARAM_set_int(p, multi))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_HAS_RAND_KEY);
    if (p != NULL && !OSSL_PARAM_set_int(p, randkey))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_ENCRYPT_THEN_MAC);
    if (p != NULL && !OSSL_PARAM_set_int(p, etm))
        return 0;
    return 1;
}

/* `alg_id_param`'s *presence* is what sets `EVP_CIPH_FLAG_CUSTOM_ASN1`, so the list exists for
 * one entry and the entry's value is never read. The name is the one the header spells
 * `OSSL_CIPHER_PARAM_ALGORITHM_ID_PARAMS`: `algorithm-id-params`, not the retired `alg_id_param`
 * alias, which is a different string and would leave the flag clear on both sides while looking
 * correct. */
static const OSSL_PARAM court_ctx_params[] = {
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_ALGORITHM_ID_PARAMS, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *court_gettable_ctx_params(void *cctx, void *provctx)
{
    (void) cctx;
    (void) provctx;
    return court_ctx_params;
}

static char court_marker;

static void *court_newctx(void *provctx)
{
    (void) provctx;
    return &court_marker;
}

static void court_freectx(void *cctx)
{
    (void) cctx;
}

/* The one-shot: a byte pattern, so that a *later* court which runs a real encryption through
 * this provider can prove the implementation it reached is this one. This court does not call
 * it -- `EVP_Cipher` is 7.3c's -- and the function exists because the structural check counts
 * it. */
static int court_cipher(void *cctx, unsigned char *out, size_t *outl, size_t outsize,
                        const unsigned char *in, size_t inl)
{
    size_t i;

    (void) cctx;
    (void) in;
    (void) inl;
    if (outsize < COURT_BLOCK_SIZE)
        return 0;
    for (i = 0; i < COURT_BLOCK_SIZE; i++)
        out[i] = (unsigned char) (i + 1);
    *outl = COURT_BLOCK_SIZE;
    return 1;
}

static int court_encrypt_init(void *cctx, const unsigned char *key, size_t keylen,
                              const unsigned char *iv, size_t ivlen,
                              const OSSL_PARAM params[])
{
    (void) cctx;
    (void) key;
    (void) keylen;
    (void) iv;
    (void) ivlen;
    (void) params;
    /* Nothing to record: no context exists in this subphase, so this callback is never reached.
     * It is published because the structural check counts it. */
    return 1;
}

static int court_update(void *cctx, unsigned char *out, size_t *outl, size_t outsize,
                        const unsigned char *in, size_t inl)
{
    (void) cctx;
    (void) out;
    (void) outsize;
    (void) in;
    *outl = inl;
    return 1;
}

static int court_final(void *cctx, unsigned char *out, size_t *outl, size_t outsize)
{
    (void) cctx;
    (void) out;
    (void) outsize;
    *outl = 0;
    return 1;
}

static int court_pipeline_init(void *cctx, const unsigned char *key, size_t keylen,
                               size_t numpipes, const unsigned char **iv, size_t ivlen,
                               const OSSL_PARAM params[])
{
    (void) cctx;
    (void) key;
    (void) keylen;
    (void) numpipes;
    (void) iv;
    (void) ivlen;
    (void) params;
    return 1;
}

static int court_pipeline_update(void *cctx, size_t numpipes, unsigned char **out, size_t *outl,
                                 const size_t *outsize, const unsigned char **in,
                                 const size_t *inl)
{
    size_t i;

    (void) cctx;
    for (i = 0; i < numpipes; i++) {
        (void) outsize[i];
        outl[i] = inl[i];
    }
    return 1;
}

static int court_pipeline_final(void *cctx, size_t numpipes, unsigned char **out, size_t *outl,
                                const size_t *outsize)
{
    size_t i;

    (void) cctx;
    (void) out;
    for (i = 0; i < numpipes; i++) {
        (void) outsize[i];
        outl[i] = 0;
    }
    return 1;
}

static const OSSL_DISPATCH court_one_shot_fns[] = {
    { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void)) court_newctx },
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void)) court_freectx },
    { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void)) court_cipher },
    { OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void)) court_get_params },
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void)) court_gettable_ctx_params },
    { 0, NULL }
};

static const OSSL_DISPATCH court_enc_fns[] = {
    { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void)) court_newctx },
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void)) court_freectx },
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void)) court_encrypt_init },
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void)) court_update },
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void)) court_final },
    { OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void)) court_get_params },
    { 0, NULL }
};

static const OSSL_DISPATCH court_pipe_fns[] = {
    { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void)) court_newctx },
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void)) court_freectx },
    { OSSL_FUNC_CIPHER_PIPELINE_ENCRYPT_INIT, (void (*)(void)) court_pipeline_init },
    { OSSL_FUNC_CIPHER_PIPELINE_UPDATE, (void (*)(void)) court_pipeline_update },
    { OSSL_FUNC_CIPHER_PIPELINE_FINAL, (void (*)(void)) court_pipeline_final },
    { OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void)) court_get_params },
    { 0, NULL }
};

/* `update` with no `final` and no `encrypt_init`: `fnciphcnt` is 1, which is neither 0, 3 nor 4. */
static const OSSL_DISPATCH court_bad_fns[] = {
    { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void)) court_newctx },
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void)) court_freectx },
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void)) court_update },
    { OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void)) court_get_params },
    { 0, NULL }
};

static const OSSL_ALGORITHM court_ciphers[] = {
    { "court-one:Court-One:courtone", "provider=court", court_one_shot_fns,
      "court one-shot cipher" },
    { "court-enc:Court-Enc:courtenc", "provider=court", court_enc_fns,
      "court streaming cipher" },
    { "court-pipe:Court-Pipe:courtpipe", "provider=court", court_pipe_fns,
      "court pipeline cipher" },
    { "court-bad:Court-Bad:courtbad", "provider=court", court_bad_fns,
      "court refused cipher" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *court_query(void *provctx, int operation_id, int *no_cache)
{
    (void) provctx;
    *no_cache = 0;
    if (operation_id == OSSL_OP_CIPHER)
        return court_ciphers;
    return NULL;
}

static int court_teardown(void *provctx)
{
    (void) provctx;
    return 1;
}

static const OSSL_DISPATCH court_dispatch[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void)) court_query },
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void)) court_teardown },
    { 0, NULL }
};

static int court_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
                               const OSSL_DISPATCH **out, void **provctx)
{
    (void) handle;
    (void) in;
    *out = court_dispatch;
    *provctx = &court_marker;
    return 1;
}

/* ---- the two visitors, which must be real functions rather than expressions ---- */

struct name_seen {
    int saw_one;
    int saw_one_alias;
    int saw_upper;
    int count;
};

static void name_visitor(const char *name, void *data)
{
    struct name_seen *s = data;

    s->count++;
    if (strcmp(name, "court-one") == 0)
        s->saw_one = 1;
    if (strcmp(name, "courtone") == 0)
        s->saw_one_alias = 1;
    if (strcmp(name, "Court-One") == 0)
        s->saw_upper = 1;
}

struct doall_count {
    int ours;
    int others;
};

static void doall_visitor(EVP_CIPHER *cipher, void *arg)
{
    struct doall_count *c = arg;
    const char *nm = EVP_CIPHER_get0_name(cipher);

    /* Only this provider's names are counted: see the header. */
    if (nm != NULL && strncmp(nm, "court-", 6) == 0)
        c->ours++;
    else
        c->others++;
}

/* A `METH` cipher's `do_cipher`, so that the hand-built method has something to store and the
 * getter has something to answer. It is never called by this probe. */
static int meth_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in,
                          size_t inl)
{
    (void) ctx;
    (void) out;
    (void) in;
    (void) inl;
    return 1;
}

int main(void)
{
    OSSL_LIB_CTX *ctx;
    OSSL_PROVIDER *prov;
    EVP_CIPHER *one = NULL, *enc = NULL, *pipe = NULL, *bad = NULL, *rejected = NULL;
    EVP_CIPHER *byhand;
    EVP_CIPHER *global;
    unsigned long one_flags = 0;
    struct name_seen seen;
    struct doall_count counted;
    int ret;

    setvbuf(stdout, NULL, _IOLBF, 0);

    ctx = OSSL_LIB_CTX_new();
    if (ctx == NULL) {
        printf("fail.libctx=1\n");
        return 0;
    }

    ret = OSSL_PROVIDER_add_builtin(ctx, "court-cipher", court_provider_init);
    sayn("add_builtin.ret", ret);
    prov = OSSL_PROVIDER_load(ctx, "court-cipher");
    printf("load.nonnull=%d\n", prov != NULL ? 1 : 0);
    if (prov == NULL) {
        printf("load.failed=1\n");
        OSSL_LIB_CTX_free(ctx);
        return 0;
    }

    /*
     * ---- the four shapes of the structural check ----
     *
     * `court-one` first, because everything below reuses it: the one-shot form is the smallest
     * legal method and the one whose `ccipher` sets `EVP_CIPH_FLAG_CUSTOM_CIPHER` inside
     * `evp_cipher_cache_constants` rather than being read from a parameter.
     */
    one = EVP_CIPHER_fetch(ctx, "court-one", NULL);
    sayp("fetch.one.nonnull", one);
    if (one == NULL) {
        printf("fetch.one.failed=1\n");
        goto done;
    }
    {
        const char *nm = EVP_CIPHER_get0_name(one);
        const char *desc = EVP_CIPHER_get0_description(one);

        printf("fetch.one.name_matches=%d\n", nm != NULL && strcmp(nm, "court-one") == 0 ? 1 : 0);
        printf("fetch.one.description_matches=%d\n",
               desc != NULL && strcmp(desc, "court one-shot cipher") == 0 ? 1 : 0);
    }
    sayn("one.block_size", EVP_CIPHER_get_block_size(one));
    sayn("one.iv_length", EVP_CIPHER_get_iv_length(one));
    sayn("one.key_length", EVP_CIPHER_get_key_length(one));
    /* The legacy NID: a provider method whose names match no legacy entry has none. */
    sayn("one.nid", EVP_CIPHER_get_nid(one));
    sayn("one.type", EVP_CIPHER_get_type(one));
    sayn("one.impl_ctx_size", EVP_CIPHER_impl_ctx_size(one));
    /*
     * The flags are the whole of `evp_cipher_cache_constants` in one integer: `mode` from the
     * provider OR-ed with the five bits its parameters and its dispatch table ask for. A
     * transcription that read the sizes from the provider and the flags from nowhere, or that
     * assigned `mode` with an OR instead of an assignment, changes this number and nothing else.
     */
    printf("one.flags=0x%lx\n", EVP_CIPHER_get_flags(one));
    one_flags = EVP_CIPHER_get_flags(one);
    sayn("one.mode", EVP_CIPHER_get_mode(one));

    sayn("one.is_a.name", EVP_CIPHER_is_a(one, "court-one"));
    sayn("one.is_a.alias", EVP_CIPHER_is_a(one, "courtone"));
    sayn("one.is_a.other", EVP_CIPHER_is_a(one, "court-enc"));
    sayn("one.is_a.unknown", EVP_CIPHER_is_a(one, "no-such-cipher"));

    sayp("one.provider", EVP_CIPHER_get0_provider(one));
    sayp("one.gettable_params", EVP_CIPHER_gettable_params(one));
    sayp("one.settable_ctx_params", EVP_CIPHER_settable_ctx_params(one));
    {
        const OSSL_PARAM *gt = EVP_CIPHER_gettable_ctx_params(one);

        sayp("one.gettable_ctx_params", gt);
        /* The entry that set `EVP_CIPH_FLAG_CUSTOM_ASN1`, located by the caller rather than
         * assumed: the flag's source is a fact this court can check independently. */
        sayp("one.gettable_ctx.alg_id", OSSL_PARAM_locate_const(gt,
              OSSL_CIPHER_PARAM_ALGORITHM_ID_PARAMS));
    }

    /* `EVP_CIPHER_get_params` is the provider's own callback, reached with no context. */
    {
        size_t keylen = 0;
        OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };

        params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_KEYLEN, &keylen);
        sayn("one.get_params.ret", EVP_CIPHER_get_params(one, params));
        sayn("one.get_params.keylen", (long long) keylen);
    }

    /* The namemap's own list, which is the aliases the method was registered under. */
    memset(&seen, 0, sizeof seen);
    sayn("one.names_do_all.ret", EVP_CIPHER_names_do_all(one, name_visitor, &seen));
    sayn("one.names.count", seen.count);
    sayn("one.names.saw_first", seen.saw_one);
    sayn("one.names.saw_alias", seen.saw_one_alias);
    sayn("one.names.saw_upper", seen.saw_upper);

    printf("one.can_pipeline.enc=%d\n", EVP_CIPHER_can_pipeline(one, 1));
    printf("one.can_pipeline.dec=%d\n", EVP_CIPHER_can_pipeline(one, 0));

    /*
     * The reference count: an extra reference survives the first free and the object is still
     * usable -- which is the only observable a refcount has, and the reason the length is read
     * back between the two releases.
     */
    sayn("one.up_ref", EVP_CIPHER_up_ref(one));
    EVP_CIPHER_free(one);
    sayn("one.after_free.key_length", EVP_CIPHER_get_key_length(one));
    EVP_CIPHER_free(one);

    /* ---- the streaming shape, whose flags must equal the one-shot's ---- */
    enc = EVP_CIPHER_fetch(ctx, "court-enc", NULL);
    sayp("fetch.enc.nonnull", enc);
    if (enc != NULL) {
        /* Both shapes ask the same provider for the same parameters, so their flags and their
         * three sizes must agree -- a relation between two objects rather than an absolute. */
        printf("enc.flags_equal_one_shot=%d\n",
               EVP_CIPHER_get_flags(enc) == one_flags ? 1 : 0);
        printf("enc.block_size=%d\n", EVP_CIPHER_get_block_size(enc));
        printf("enc.key_length=%d\n", EVP_CIPHER_get_key_length(enc));
        printf("enc.can_pipeline.enc=%d\n", EVP_CIPHER_can_pipeline(enc, 1));
        printf("enc.can_pipeline.dec=%d\n", EVP_CIPHER_can_pipeline(enc, 0));
    }

    /* ---- the pipeline shape, which is the only one that separates enc from dec ---- */
    pipe = EVP_CIPHER_fetch(ctx, "court-pipe", NULL);
    sayp("fetch.pipe.nonnull", pipe);
    if (pipe != NULL) {
        printf("pipe.can_pipeline.enc=%d\n", EVP_CIPHER_can_pipeline(pipe, 1));
        printf("pipe.can_pipeline.dec=%d\n", EVP_CIPHER_can_pipeline(pipe, 0));
    }

    /*
     * ---- the refusal, and the *reason* it is a refusal ----
     *
     * The name is in the namemap after this fetch's constructor is entered, so this takes the
     * `ERR_R_FETCH_FAILED` arm; the negative selection below takes `ERR_R_UNSUPPORTED`. The two
     * share one message, so the code is the observation.
     */
    bad = EVP_CIPHER_fetch(ctx, "court-bad", NULL);
    printf("fetch.bad_null=%d\n", bad == NULL ? 1 : 0);
    printf("fetch.bad.err=%lu\n", ERR_peek_error());
    ERR_clear_error();
    EVP_CIPHER_free(bad);

    /* ---- the negative selection: the algorithm exists and the query forbids it ---- */
    rejected = EVP_CIPHER_fetch(ctx, "court-one", "provider=other");
    printf("fetch.rejected_null=%d\n", rejected == NULL ? 1 : 0);
    printf("fetch.rejected.err=%lu\n", ERR_peek_error());
    ERR_clear_error();
    EVP_CIPHER_free(rejected);

    /* ---- the walk over what is activated, counted for this provider's names only ---- */
    memset(&counted, 0, sizeof counted);
    EVP_CIPHER_do_all_provided(ctx, doall_visitor, &counted);
    sayn("do_all.ours", counted.ours);

    /*
     * ---- `cmeth_lib.c`, which needs no provider at all ----
     *
     * The append-only setters are the interesting half: each refuses a second write, so the
     * object a caller builds is a fixed record rather than a mutable one.
     */
    byhand = EVP_CIPHER_meth_new(NID_undef, 8, 16);
    sayp("meth.new", byhand);
    if (byhand != NULL) {
        sayn("meth.new.nid", EVP_CIPHER_get_nid(byhand));
        sayn("meth.new.block_size", EVP_CIPHER_get_block_size(byhand));
        sayn("meth.new.key_length", EVP_CIPHER_get_key_length(byhand));
        sayn("meth.new.provider", EVP_CIPHER_get0_provider(byhand) == NULL ? 1 : 0);
        /* A method with no provider and no name answers `is_a` from the name it has, which is
         * NULL -- so every spelling is refused, and the answer is 0 rather than a crash. */
        sayn("meth.new.is_a", EVP_CIPHER_is_a(byhand, "anything"));

        sayn("meth.set_iv_length.first", EVP_CIPHER_meth_set_iv_length(byhand, 8));
        sayn("meth.set_iv_length.second", EVP_CIPHER_meth_set_iv_length(byhand, 16));
        sayn("meth.iv_length", EVP_CIPHER_get_iv_length(byhand));

        sayn("meth.set_flags.first", EVP_CIPHER_meth_set_flags(byhand, EVP_CIPH_CBC_MODE));
        sayn("meth.set_flags.second", EVP_CIPHER_meth_set_flags(byhand, EVP_CIPH_ECB_MODE));
        sayn("meth.mode", EVP_CIPHER_get_mode(byhand));

        sayn("meth.set_impl_ctx_size.first", EVP_CIPHER_meth_set_impl_ctx_size(byhand, 32));
        sayn("meth.set_impl_ctx_size.second", EVP_CIPHER_meth_set_impl_ctx_size(byhand, 64));
        sayn("meth.impl_ctx_size", EVP_CIPHER_impl_ctx_size(byhand));

        sayn("meth.set_do_cipher.first", EVP_CIPHER_meth_set_do_cipher(byhand, meth_do_cipher));
        sayn("meth.set_do_cipher.second", EVP_CIPHER_meth_set_do_cipher(byhand, meth_do_cipher));
        printf("meth.get_do_cipher_matches=%d\n",
               EVP_CIPHER_meth_get_do_cipher(byhand) == meth_do_cipher ? 1 : 0);
        /* The getters that have nothing to answer: NULL, which is not the same as unset. */
        printf("meth.get_init_is_null=%d\n", EVP_CIPHER_meth_get_init(byhand) == NULL ? 1 : 0);
        printf("meth.get_cleanup_is_null=%d\n",
               EVP_CIPHER_meth_get_cleanup(byhand) == NULL ? 1 : 0);
        printf("meth.get_ctrl_is_null=%d\n", EVP_CIPHER_meth_get_ctrl(byhand) == NULL ? 1 : 0);

        /*
         * The two destructors refuse each other's objects. `EVP_CIPHER_free` on a `METH` cipher
         * is a no-op -- the origin is not dynamic -- and `EVP_CIPHER_meth_free` on a *fetched*
         * one is a no-op too, which is the assertion below.
         */
        EVP_CIPHER_free(byhand);
        sayn("meth.still_live_after_public_free", EVP_CIPHER_get_block_size(byhand));

        if (one != NULL) {
            EVP_CIPHER *dup = EVP_CIPHER_fetch(ctx, "court-one", NULL);

            /* A provider method is not duplicable this way: `EVP_CIPHER_up_ref` is the answer. */
            sayp("meth.dup_of_provider", EVP_CIPHER_meth_dup(dup));
            EVP_CIPHER_meth_free(dup);
            sayn("meth.fetched_survives_meth_free",
                 EVP_CIPHER_get_block_size(dup));
            EVP_CIPHER_free(dup);
        }
        EVP_CIPHER_meth_free(byhand);
    }

    /* ---- `EVP_enc_null`, the one legacy global with no primitive under it ---- */
    global = (EVP_CIPHER *) EVP_enc_null();
    sayp("enc_null.nonnull", global);
    if (global != NULL) {
        sayn("enc_null.nid", EVP_CIPHER_get_nid(global));
        sayn("enc_null.block_size", EVP_CIPHER_get_block_size(global));
        sayn("enc_null.key_length", EVP_CIPHER_get_key_length(global));
        sayn("enc_null.iv_length", EVP_CIPHER_get_iv_length(global));
        printf("enc_null.flags=0x%lx\n", EVP_CIPHER_get_flags(global));
        sayn("enc_null.provider_present", EVP_CIPHER_get0_provider(global) == NULL ? 0 : 1);
        /* The same address on every call, which a `const` item cannot provide. */
        printf("enc_null.stable=%d\n", EVP_enc_null() == EVP_enc_null() ? 1 : 0);
        sayn("enc_null.up_ref", EVP_CIPHER_up_ref(global));
        /* A global is not this crate's to release, so the call changes nothing observable. */
        EVP_CIPHER_free(global);
        sayn("enc_null.block_size_after_free", EVP_CIPHER_get_block_size(global));
        sayp("enc_null.gettable_params", EVP_CIPHER_gettable_params(global));
    }

    /* The NULL arms, which every accessor with one has to answer for itself. */
    sayn("null.block_size", EVP_CIPHER_get_block_size(NULL));
    sayn("null.iv_length", EVP_CIPHER_get_iv_length(NULL));
    sayn("null.nid", EVP_CIPHER_get_nid(NULL));
    sayn("null.flags", (long long) EVP_CIPHER_get_flags(NULL));
    sayn("null.is_a", EVP_CIPHER_is_a(NULL, "court-one"));
    sayp("null.gettable_params", EVP_CIPHER_gettable_params(NULL));
    sayp("null.settable_ctx_params", EVP_CIPHER_settable_ctx_params(NULL));
    sayp("null.gettable_ctx_params", EVP_CIPHER_gettable_ctx_params(NULL));
    /* The destructor with nothing to do, which is the arm a caller's error path takes. */
    EVP_CIPHER_free(NULL);
    sayn("null.free_survived", 1);

done:
    OSSL_PROVIDER_unload(prov);
    OSSL_LIB_CTX_free(ctx);
    return 0;
}
