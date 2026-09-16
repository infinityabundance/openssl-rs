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

/* A duplicate of the context: the same marker, because this provider keeps no per-operation
 * state that a copy would have to separate. It exists because `EVP_CIPHER_CTX_copy` refuses a
 * provider shape that does not publish one, and a court that could only observe that refusal
 * would not observe the copy at all. */
static void *court_dupctx(void *cctx)
{
    return cctx;
}

static const OSSL_DISPATCH court_enc_fns[] = {
    { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void)) court_newctx },
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void)) court_freectx },
    { OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void)) court_dupctx },
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void)) court_encrypt_init },
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void)) court_update },
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void)) court_final },
    { OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void)) court_get_params },
    { 0, NULL }
};

/* The one shape that publishes both: `EVP_Cipher` prefers `ccipher` over `cupdate`/`cfinal`
 * when a method has one, and neither the one-shot nor the streaming shape above can show that
 * preference because only one of the two is present in each. */
static const OSSL_DISPATCH court_both_fns[] = {
    { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void)) court_newctx },
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void)) court_freectx },
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void)) court_encrypt_init },
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void)) court_update },
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void)) court_final },
    { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void)) court_cipher },
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
    { "court-both:Court-Both:courtboth", "provider=court", court_both_fns,
      "court one-shot and streaming cipher" },
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

    /*
     * ---- 7.3c-i: the context, its parameters, and initialisation ----
     *
     * Everything above observes the *method object*. This observes the other half: a context
     * armed through `EVP_EncryptInit_ex`, the accessors that read it, and the two refusals a
     * caller meets before it is armed.
     *
     * **Nothing here calls `EVP_EncryptUpdate` or a `Final`.** Those are 7.3c-ii's and calling
     * one would abort the candidate on a scaffold, which reads as a missing symbol rather than
     * as a behavioural difference.
     */
    {
        EVP_CIPHER_CTX *cctx = EVP_CIPHER_CTX_new();
        EVP_CIPHER_CTX *other_ctx = EVP_CIPHER_CTX_new();
        EVP_CIPHER_CTX *dup = NULL;
        EVP_CIPHER *stream = EVP_CIPHER_fetch(ctx, "court-enc", NULL);
        unsigned char key[32], ivb[16], ivout[16];
        int i;

        for (i = 0; i < 32; i++)
            key[i] = (unsigned char) i;
        for (i = 0; i < 16; i++)
            ivb[i] = (unsigned char) (i + 1);

        sayp("ctx.new", cctx);
        sayp("ctx.fetched_for_init", stream);

        /* The empty arms, which are what a caller's error path meets first. */
        sayp("ctx.empty.cipher", EVP_CIPHER_CTX_get0_cipher(cctx));
        sayn("ctx.empty.block_size", EVP_CIPHER_CTX_get_block_size(cctx));
        sayn("ctx.empty.iv_length", EVP_CIPHER_CTX_get_iv_length(cctx));
        sayn("ctx.empty.key_length", EVP_CIPHER_CTX_get_key_length(cctx));
        sayn("ctx.empty.nid", EVP_CIPHER_CTX_get_nid(cctx));
        sayn("ctx.empty.tag_length", EVP_CIPHER_CTX_get_tag_length(cctx));
        sayn("ctx.empty.is_encrypting", EVP_CIPHER_CTX_is_encrypting(cctx));
        sayn("ctx.empty.num", EVP_CIPHER_CTX_get_num(cctx));
        sayn("ctx.empty.app_data_null", EVP_CIPHER_CTX_get_app_data(cctx) == NULL ? 1 : 0);
        sayn("ctx.empty.cipher_data_null", EVP_CIPHER_CTX_get_cipher_data(cctx) == NULL ? 1 : 0);
        /* The control that refuses before it reads the command, and the reason it raises. */
        sayn("ctx.empty.ctrl_init", EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_INIT, 0, NULL));
        sayn("ctx.empty.ctrl_init.err", (long long) ERR_peek_error());
        ERR_clear_error();
        sayn("ctx.empty.set_padding", EVP_CIPHER_CTX_set_padding(cctx, 0));
        /*
         * **`EVP_CIPHER_CTX_gettable_params` and `_settable_params` are NOT called here.** On an
         * unarmed context the authority evaluates `cctx->cipher->gettable_ctx_params` with
         * `cipher` NULL and dies; the crate answers NULL, which is recorded as
         * `D-CIPHERC TX-PARAMS-NULL` in `docs/SECURITY_DIVERGENCE_POLICY.md` rather than
         * reproduced. They are observed below, where a cipher is on the context, which is the
         * only state either library can answer from.
         */
        /* And the copy refusals, which are the first thing a caller meets with no cipher on. */
        sayn("ctx.copy_unarmed", EVP_CIPHER_CTX_copy(other_ctx, cctx));
        sayn("ctx.copy_unarmed.err", (long long) ERR_peek_error());
        ERR_clear_error();
        sayp("ctx.dup_unarmed", EVP_CIPHER_CTX_dup(cctx));

        /* The flags: `test_flags` answers the mask, and the two spellings are masks too. */
        EVP_CIPHER_CTX_set_flags(cctx, EVP_CIPH_NO_PADDING);
        sayn("ctx.flags.after_set", EVP_CIPHER_CTX_test_flags(cctx, EVP_CIPH_NO_PADDING));
        EVP_CIPHER_CTX_clear_flags(cctx, EVP_CIPH_NO_PADDING);
        sayn("ctx.flags.after_clear", EVP_CIPHER_CTX_test_flags(cctx, EVP_CIPH_NO_PADDING));

        if (stream != NULL) {
            /*
             * The arming. The key length the provider is handed comes from the *context's*
             * accessor, which is why the two lengths below are read before the call.
             */
            sayn("ctx.init.encrypt", EVP_EncryptInit_ex(cctx, stream, NULL, key, ivb));
            sayn("ctx.armed.is_encrypting", EVP_CIPHER_CTX_is_encrypting(cctx));
            printf("ctx.armed.cipher_is_the_fetched_one=%d\n",
                   EVP_CIPHER_CTX_get0_cipher(cctx) == stream ? 1 : 0);
            sayn("ctx.armed.block_size", EVP_CIPHER_CTX_get_block_size(cctx));
            sayn("ctx.armed.iv_length", EVP_CIPHER_CTX_get_iv_length(cctx));
            sayn("ctx.armed.key_length", EVP_CIPHER_CTX_get_key_length(cctx));
            sayn("ctx.armed.nid", EVP_CIPHER_CTX_get_nid(cctx));
            sayn("ctx.armed.mode", EVP_CIPHER_get_mode(EVP_CIPHER_CTX_get0_cipher(cctx)));
            /* The two parameters, and the pair of refusals around them: this provider has no
             * ctx-params callbacks, so the asks answer 0 rather than succeeding. */
            sayn("ctx.armed.set_key_length_same", EVP_CIPHER_CTX_set_key_length(cctx, 32));
            sayn("ctx.armed.set_key_length_other", EVP_CIPHER_CTX_set_key_length(cctx, 16));
            sayn("ctx.armed.set_key_length_other.err", (long long) ERR_peek_error());
            ERR_clear_error();
            sayn("ctx.armed.set_padding", EVP_CIPHER_CTX_set_padding(cctx, 0));
            sayn("ctx.armed.get_num", EVP_CIPHER_CTX_get_num(cctx));
            sayn("ctx.armed.set_num", EVP_CIPHER_CTX_set_num(cctx, 5));
            sayn("ctx.armed.get_updated_iv", EVP_CIPHER_CTX_get_updated_iv(cctx, ivout, 16));
            sayn("ctx.armed.get_original_iv", EVP_CIPHER_CTX_get_original_iv(cctx, ivout, 16));
            /* The parameter *setter* on a provider that publishes no settable list. */
            sayn("ctx.armed.set_params_empty", EVP_CIPHER_CTX_set_params(cctx, NULL));
            sayn("ctx.armed.get_params_empty", EVP_CIPHER_CTX_get_params(cctx, NULL));
            /* The two context-parameter lists, now that there is a cipher to ask. */
            sayp("ctx.armed.gettable_ctx_params", EVP_CIPHER_CTX_gettable_params(cctx));
            sayp("ctx.armed.settable_ctx_params", EVP_CIPHER_CTX_settable_params(cctx));
            sayp("ctx.armed.algor_id_in_list",
                 OSSL_PARAM_locate_const(EVP_CIPHER_CTX_gettable_params(cctx),
                                         OSSL_CIPHER_PARAM_ALGORITHM_ID_PARAMS));
            /* The IV as ASN.1, with a NULL type: `court-enc` is GCM, so the AEAD arm is taken
             * and refuses the NULL -- the same refusal both directions make. */
            sayn("ctx.armed.param_to_asn1_null", EVP_CIPHER_param_to_asn1(cctx, NULL));
            sayn("ctx.armed.asn1_to_param_null", EVP_CIPHER_asn1_to_param(cctx, NULL));

            /* Duplication, which the provider now supports. */
            dup = EVP_CIPHER_CTX_dup(cctx);
            sayp("ctx.dup", dup);
            if (dup != NULL) {
                printf("ctx.dup.same_cipher=%d\n",
                       EVP_CIPHER_CTX_get0_cipher(dup) == stream ? 1 : 0);
                sayn("ctx.dup.is_encrypting", EVP_CIPHER_CTX_is_encrypting(dup));
                sayn("ctx.dup.key_length", EVP_CIPHER_CTX_get_key_length(dup));
                EVP_CIPHER_CTX_free(dup);
                /* The original is untouched by the copy having been released. */
                sayn("ctx.after_dup_free.key_length", EVP_CIPHER_CTX_get_key_length(cctx));
                sayn("ctx.after_dup_free.is_encrypting", EVP_CIPHER_CTX_is_encrypting(cctx));
            }
            sayn("ctx.copy_armed", EVP_CIPHER_CTX_copy(other_ctx, cctx));
            sayn("ctx.copy_armed.is_encrypting", EVP_CIPHER_CTX_is_encrypting(other_ctx));
            sayn("ctx.copy_armed.key_length", EVP_CIPHER_CTX_get_key_length(other_ctx));

            /* The other direction, which keeps the context's cipher and changes its flag. */
            sayn("ctx.init.decrypt", EVP_DecryptInit_ex(cctx, NULL, NULL, key, ivb));
            sayn("ctx.after_decrypt_init.is_encrypting", EVP_CIPHER_CTX_is_encrypting(cctx));
            /* And the reset, which leaves the context as fresh as a new one. */
            sayn("ctx.reset", EVP_CIPHER_CTX_reset(cctx));
            sayp("ctx.after_reset.cipher", EVP_CIPHER_CTX_get0_cipher(cctx));
            sayn("ctx.after_reset.key_length", EVP_CIPHER_CTX_get_key_length(cctx));
            sayn("ctx.after_reset.is_encrypting", EVP_CIPHER_CTX_is_encrypting(cctx));

            /* The pipeline initialisers: the pipe bound first, then the shape the provider
             * does not publish -- `court-enc` has no pipeline functions. */
            sayn("ctx.pipeline.too_many",
                 EVP_CipherPipelineEncryptInit(cctx, stream, key, 32, 64, NULL, 16));
            sayn("ctx.pipeline.too_many.err", (long long) ERR_peek_error());
            ERR_clear_error();
            sayn("ctx.pipeline.no_impl",
                 EVP_CipherPipelineEncryptInit(cctx, stream, key, 32, 1, NULL, 16));
            sayn("ctx.pipeline.no_impl.err", (long long) ERR_peek_error());
            ERR_clear_error();
            sayn("ctx.pipeline.decrypt.no_impl",
                 EVP_CipherPipelineDecryptInit(cctx, stream, key, 32, 1, NULL, 16));
            ERR_clear_error();
        }

        /*
         * **`EVP_EncryptInit_ex(ctx, EVP_enc_null(), ...)` is deliberately NOT observed.** A
         * legacy method with no provider is replaced by
         * `EVP_CIPHER_fetch(NULL, cipher->nid == NID_undef ? "NULL" : OBJ_nid2sn(nid), "")` --
         * the literal string `"NULL"` -- and the authority succeeds because its **default
         * provider** publishes a cipher called `NULL`. This crate's default provider does not:
         * it is Phase 13's. So the observation would read a missing stratum as a behavioural
         * divergence, which is the distinction this probe's header draws for slots 10, 11, 15
         * and 20, and it is recorded in `docs/DECISIONS.md` D153 instead.
         */

        EVP_CIPHER_free(stream);
        EVP_CIPHER_CTX_free(other_ctx);
        EVP_CIPHER_CTX_free(cctx);
    }

    /*
     * ---- 7.3c-ii: the data path, which is the only place a provider cipher is *used* ----
     *
     * `court-both` is the fifth algorithm and it exists for one arm of `EVP_Cipher`: its
     * `ccipher` is preferred over `cupdate`/`cfinal` when the method publishes one, so a cipher
     * without a one-shot could never observe that preference. It publishes the three-function
     * encrypt path *and* the one-shot, which is the only shape that has both.
     */
    {
        EVP_CIPHER_CTX *cctx = EVP_CIPHER_CTX_new();
        EVP_CIPHER *stream = EVP_CIPHER_fetch(ctx, "court-enc", NULL);
        EVP_CIPHER *both = EVP_CIPHER_fetch(ctx, "court-both", NULL);
        unsigned char key[32], ivb[16], buf[64];
        int outl = 0;
        int i;

        for (i = 0; i < 32; i++)
            key[i] = (unsigned char) i;
        for (i = 0; i < 16; i++)
            ivb[i] = (unsigned char) (i + 1);
        for (i = 0; i < 64; i++)
            buf[i] = (unsigned char) (i + 1);

        sayp("path.fetched.enc", stream);
        sayp("path.fetched.both", both);

        if (stream != NULL) {
            /* The two direction refusals, which are what stops a caller encrypting through a
             * decrypting context and the other way round. */
            sayn("path.update.before_init",
                 EVP_EncryptUpdate(cctx, buf, &outl, buf, 16));
            sayn("path.update.before_init.err", (long long) ERR_peek_error());
            ERR_clear_error();
            sayn("path.update.null_outl", EVP_EncryptUpdate(cctx, buf, NULL, buf, 16));
            ERR_clear_error();
            sayn("path.update.negative_inl", EVP_EncryptUpdate(cctx, buf, &outl, buf, -1));
            ERR_clear_error();

            sayn("path.init.encrypt", EVP_EncryptInit_ex(cctx, stream, NULL, key, ivb));
            /* The wrong direction: the context is encrypting and `EVP_DecryptUpdate` refuses. */
            sayn("path.decrypt_update.while_encrypting",
                 EVP_DecryptUpdate(cctx, buf, &outl, buf, 16));
            sayn("path.decrypt_update.while_encrypting.err", (long long) ERR_peek_error());
            ERR_clear_error();

            /*
             * The round trip. `court-enc`'s update answers the input length and its final
             * answers zero, so the pair is observable as a *sum* rather than as bytes -- and the
             * bytes are not printed, because a probe compares shapes rather than plaintext.
             */
            sayn("path.encrypt_update", EVP_EncryptUpdate(cctx, buf, &outl, buf, 16));
            sayn("path.encrypt_update.outl", outl);
            sayn("path.encrypt_final", EVP_EncryptFinal_ex(cctx, buf, &outl));
            sayn("path.encrypt_final.outl", outl);
            /* The `_ex`-less spelling is an alias, and it is called on the same armed context. */
            sayn("path.encrypt_final_alias", EVP_EncryptFinal(cctx, buf, &outl));
            sayn("path.cipher_final_ex", EVP_CipherFinal_ex(cctx, buf, &outl));
            sayn("path.cipher_final", EVP_CipherFinal(cctx, buf, &outl));
            sayn("path.cipher_update.while_encrypting",
                 EVP_CipherUpdate(cctx, buf, &outl, buf, 16));

            sayn("path.init.decrypt", EVP_DecryptInit_ex(cctx, NULL, NULL, key, ivb));
            sayn("path.encrypt_update.while_decrypting",
                 EVP_EncryptUpdate(cctx, buf, &outl, buf, 16));
            ERR_clear_error();
            sayn("path.decrypt_update", EVP_DecryptUpdate(cctx, buf, &outl, buf, 16));
            sayn("path.decrypt_update.outl", outl);
            sayn("path.cipher_update.while_decrypting",
                 EVP_CipherUpdate(cctx, buf, &outl, buf, 16));
            sayn("path.decrypt_final", EVP_DecryptFinal_ex(cctx, buf, &outl));
            sayn("path.decrypt_final.outl", outl);
            sayn("path.decrypt_final_alias", EVP_DecryptFinal(cctx, buf, &outl));

            /* The pipeline calls on a context that was not armed for one. */
            sayn("path.pipeline_update.not_a_pipeline",
                 EVP_CipherPipelineUpdate(cctx, NULL, NULL, NULL, NULL, NULL));
            ERR_clear_error();
            sayn("path.pipeline_final.not_a_pipeline",
                 EVP_CipherPipelineFinal(cctx, NULL, NULL, NULL));
            ERR_clear_error();
        }

        if (both != NULL) {
            /* The one-shot, and the mapping of its answer: a non-zero `ccipher` return becomes
             * the *length*, which is why the two observations differ. */
            sayn("path.init.both", EVP_EncryptInit_ex(cctx, both, NULL, key, ivb));
            sayn("path.cipher.oneshot", EVP_Cipher(cctx, buf, buf, 16));
            /* A NULL input is the final call's contract, and it is answered by `cfinal`. */
            sayn("path.cipher.final", EVP_Cipher(cctx, buf, NULL, 0));
        }

        /* `EVP_Cipher` on an unarmed context is a zero rather than a refusal: no cipher. */
        sayn("path.cipher.unarmed", EVP_Cipher(cctx, buf, buf, 16));

        EVP_CIPHER_free(both);
        EVP_CIPHER_free(stream);
        EVP_CIPHER_CTX_free(cctx);
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
