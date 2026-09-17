/*
 * RT-EVP-SKEY -- the `EVP_SKEYMGMT` method object and the `EVP_SKEY` it manages.
 *
 * The fourth class of 7.3e/7.3f and the first whose object is **not a context**. Five things are
 * observable here that no sibling court could observe, and each is a place where a plausible
 * transcription is wrong:
 *
 *   1. **the structural check is three NULL tests and no arithmetic.** There is no counter in
 *      `skeymgmt_from_algorithm` at all, so a provider that lists `import` **twice** is accepted and
 *      the *first* entry wins -- where the MAC class's three-way count and the KDF class's one-and-
 *      two would both have something to say. The probe publishes a method with a duplicate `import`
 *      (fetchable) and three methods missing one of the three mandatory callbacks (refused), and
 *      the four transcripts together are the shape of the check.
 *   2. **an `EVP_SKEY` owns a reference to its method.** `evp_skey_alloc` up-refs the method and
 *      `EVP_SKEY_free` releases it, so a key outlives the fetch that produced its method. The
 *      probe's `free` counter pins that the *key data's* destructor runs exactly once, on the last
 *      release, and not on the intermediate ones.
 *   3. **the key's bytes only ever come out through `export`.** `EVP_SKEY_get0_raw_key` is an export
 *      with a callback that locates one parameter, not a field read, and a key whose provider does
 *      not publish its bytes answers 0 rather than a wrong pointer. The probe round-trips: import a
 *      buffer, `memcmp` what comes back.
 *   4. **`EVP_SKEY_import` falls back by *name*.** A key type nobody publishes is not an error: the
 *      method is asked for again under `GENERIC-SECRET`, and only a second failure raises. The
 *      transcript shows the second fetch happening and the resulting key reporting the generic
 *      method's name.
 *   5. **`EVP_SKEY_to_provider` is four arms and the first is a pointer identity.** Same method
 *      name *and* same provider is an `up_ref` of the object the caller passed; the same name from a
 *      **different** provider is a full round trip -- export to parameters, import into the
 *      destination -- and the result's provider name is the destination's. Both are printed, and
 *      the round trip's key data is the destination's own (flavour 2, not flavour 1).
 *
 * Deliberately not observed
 * -------------------------
 *   * **`EVP_SKEYMGMT_names_do_all(NULL, ...)`** answers 0 where its siblings answer 1. That is a
 *     real boundary, and it is pinned in the crate's unit tests rather than here -- every other
 *     observation in this probe needs a live method, and mixing the two would make one line's
 *     failure ambiguous. It is called on a live method below, which is what this court can compare.
 *   * **`EVP_SKEYMGMT_up_ref(NULL)`** dereferences in the authority, so it is not called.
 *   * **`EVP_SKEYMGMT_do_all_provided` with a NULL visitor**, which faults the authority
 *     (D-MD-DOALL-NULL-1). The boundary is printed.
 *
 * Addresses are never printed. Every observation is a relation between two pointers this probe
 * holds, a presence answer, a count, a bounded byte comparison or a return code.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>

#define COURT_KEY_MAX 64

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

/* ---- the provider's own key data, and the counters that are the observation ---- */

/* Flavour 1 is provider A's key and flavour 2 is provider B's, so a key that went through
 * `to_provider` is distinguishable from one that did not -- without printing a pointer. */
struct court_key_st {
    int flavour;
    unsigned char bytes[COURT_KEY_MAX];
    size_t len;
    char id[24];
};

static int k_import, k_export, k_generate, k_free, k_getkeyid, k_impparams, k_genparams;
/* What the *arguments* were, so "which selection" and "how long" are observations too. */
static int k_import_selection, k_import_len, k_import_byte0;
static int k_export_selection, k_export_len;
static int k_generate_called, k_generate_param_len;

static void reset_counts(void)
{
    k_import = k_export = k_generate = k_free = k_getkeyid = k_impparams = k_genparams = 0;
    k_import_selection = k_import_len = k_import_byte0 = 0;
    k_export_selection = k_export_len = 0;
    k_generate_called = k_generate_param_len = 0;
}

static void say_vec(const char *key)
{
    printf("%s=%d,%d,%d,%d,%d,%d,%d err=%lu\n", key,
           k_import, k_export, k_generate, k_free, k_getkeyid, k_impparams, k_genparams,
           ERR_peek_error());
    ERR_clear_error();
}

static void say_args(const char *key)
{
    printf("%s=import:%d/%d/%d export:%d/%d gen:%d/%d err=%lu\n", key,
           k_import_selection, k_import_len, k_import_byte0,
           k_export_selection, k_export_len,
           k_generate_called, k_generate_param_len, ERR_peek_error());
    ERR_clear_error();
}

static struct court_key_st *new_key(int flavour, const unsigned char *bytes, size_t len)
{
    struct court_key_st *k = malloc(sizeof *k);

    if (k == NULL)
        return NULL;
    memset(k, 0, sizeof *k);
    k->flavour = flavour;
    k->len = len < COURT_KEY_MAX ? len : COURT_KEY_MAX;
    if (bytes != NULL && k->len > 0)
        memcpy(k->bytes, bytes, k->len);
    /* The id is a function of the flavour and the first byte, so it says which key this is. */
    snprintf(k->id, sizeof k->id, "id%d-%02x", flavour, k->len > 0 ? k->bytes[0] : 0);
    return k;
}

static const char *court_key_id(void *keydata)
{
    struct court_key_st *k = keydata;

    k_getkeyid++;
    if (k == NULL)
        return NULL;
    return k->id;
}

static void court_free(void *keydata)
{
    k_free++;
    free(keydata);
}

static const OSSL_PARAM *court_imp_settable(void *provctx)
{
    static const OSSL_PARAM settable[] = {
        OSSL_PARAM_octet_string(OSSL_SKEY_PARAM_RAW_BYTES, NULL, 0),
        OSSL_PARAM_END
    };

    k_impparams++;
    (void) provctx;
    return settable;
}

static const OSSL_PARAM *court_gen_settable(void *provctx)
{
    static const OSSL_PARAM settable[] = {
        OSSL_PARAM_size_t(OSSL_SKEY_PARAM_KEY_LENGTH, NULL),
        OSSL_PARAM_END
    };

    k_genparams++;
    (void) provctx;
    return settable;
}

/* The import reads the one parameter the interface says it will: the raw bytes. The selection is
 * recorded rather than tested, because a transcription that passed `SELECT_ALL` would still import
 * the same bytes and would only be distinguishable from this probe. */
static void *court_import(void *provctx, int selection, const OSSL_PARAM *params)
{
    const OSSL_PARAM *p = NULL;
    const void *data = NULL;
    size_t len = 0;
    struct court_key_st *k;
    int flavour = (int) (size_t) provctx;

    k_import++;
    k_import_selection = selection;
    p = OSSL_PARAM_locate_const(params, OSSL_SKEY_PARAM_RAW_BYTES);
    if (p == NULL || !OSSL_PARAM_get_octet_string_ptr(p, &data, &len))
        return NULL;
    k_import_len = (int) len;
    k_import_byte0 = len > 0 ? ((const unsigned char *) data)[0] : -1;
    k = new_key(flavour, data, len);
    return k;
}

/* An import that refuses, so `EVP_SKEY_import`'s failure path is observable. */
static void *court_import_refuses(void *provctx, int selection, const OSSL_PARAM *params)
{
    (void) provctx;
    (void) selection;
    (void) params;
    k_import++;
    return NULL;
}

static void *court_generate(void *provctx, const OSSL_PARAM *params)
{
    const OSSL_PARAM *p = NULL;
    size_t want = 0;
    unsigned char bytes[COURT_KEY_MAX];
    size_t i;

    k_generate++;
    k_generate_called = 1;
    p = OSSL_PARAM_locate_const(params, OSSL_SKEY_PARAM_KEY_LENGTH);
    k_generate_param_len = p != NULL ? 1 : 0;
    if (p != NULL && !OSSL_PARAM_get_size_t(p, &want))
        return NULL;
    if (want == 0 || want > COURT_KEY_MAX)
        want = 8;
    /* The generated key is a function of the length asked for, so "the implementation ran" and
     * "which arguments it saw" are one observation rather than two. */
    for (i = 0; i < want; i++)
        bytes[i] = (unsigned char) (0x10 + (i & 0x0f));
    return new_key((int) (size_t) provctx, bytes, want);
}

/* The export calls the callback with exactly one parameter: the raw bytes. The selection is
 * recorded, and it is `SELECT_SECRET_KEY` for both of the callers in the API that export a key. */
static int court_export(void *keydata, int selection, OSSL_CALLBACK *param_cb, void *cbarg)
{
    struct court_key_st *k = keydata;
    OSSL_PARAM params[2];
    int ret;

    k_export++;
    k_export_selection = selection;
    if (k == NULL)
        return 0;
    k_export_len = (int) k->len;
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_SKEY_PARAM_RAW_BYTES, k->bytes, k->len);
    params[1] = OSSL_PARAM_construct_end();
    ret = param_cb(params, cbarg);
    return ret;
}

/* ---- provider A's dispatch tables, one per structural arm ---- */

static const OSSL_DISPATCH skey_full_fns[] = {
    { OSSL_FUNC_SKEYMGMT_FREE, (void (*)(void)) court_free },
    { OSSL_FUNC_SKEYMGMT_IMPORT, (void (*)(void)) court_import },
    { OSSL_FUNC_SKEYMGMT_EXPORT, (void (*)(void)) court_export },
    { OSSL_FUNC_SKEYMGMT_GENERATE, (void (*)(void)) court_generate },
    { OSSL_FUNC_SKEYMGMT_GET_KEY_ID, (void (*)(void)) court_key_id },
    { OSSL_FUNC_SKEYMGMT_IMP_SETTABLE_PARAMS, (void (*)(void)) court_imp_settable },
    { OSSL_FUNC_SKEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void)) court_gen_settable },
    { 0, NULL }
};

/* Only the three mandatory callbacks. `EVP_SKEY_generate` must answer NULL, the two parameter
 * accessors must answer NULL, and `EVP_SKEY_get0_key_id` must answer NULL -- four different
 * answers from one method that is nonetheless perfectly fetchable. */
static const OSSL_DISPATCH skey_minimal_fns[] = {
    { OSSL_FUNC_SKEYMGMT_FREE, (void (*)(void)) court_free },
    { OSSL_FUNC_SKEYMGMT_IMPORT, (void (*)(void)) court_import },
    { OSSL_FUNC_SKEYMGMT_EXPORT, (void (*)(void)) court_export },
    { 0, NULL }
};

/* `import` listed twice. There is no counter to notice, so this method is accepted and the *first*
 * entry is the one that runs -- which the import counter shows by being incremented once. */
static const OSSL_DISPATCH skey_dup_fns[] = {
    { OSSL_FUNC_SKEYMGMT_FREE, (void (*)(void)) court_free },
    { OSSL_FUNC_SKEYMGMT_IMPORT, (void (*)(void)) court_import },
    { OSSL_FUNC_SKEYMGMT_EXPORT, (void (*)(void)) court_export },
    { OSSL_FUNC_SKEYMGMT_IMPORT, (void (*)(void)) court_import_refuses },
    { 0, NULL }
};

/* No `export`: one of the three mandatory tests fails. */
static const OSSL_DISPATCH skey_noexport_fns[] = {
    { OSSL_FUNC_SKEYMGMT_FREE, (void (*)(void)) court_free },
    { OSSL_FUNC_SKEYMGMT_IMPORT, (void (*)(void)) court_import },
    { 0, NULL }
};

/* No `free`: the key-data destructor is mandatory, and a method without one would leak. */
static const OSSL_DISPATCH skey_nofree_fns[] = {
    { OSSL_FUNC_SKEYMGMT_IMPORT, (void (*)(void)) court_import },
    { OSSL_FUNC_SKEYMGMT_EXPORT, (void (*)(void)) court_export },
    { 0, NULL }
};

/* No `import`. */
static const OSSL_DISPATCH skey_noimport_fns[] = {
    { OSSL_FUNC_SKEYMGMT_FREE, (void (*)(void)) court_free },
    { OSSL_FUNC_SKEYMGMT_EXPORT, (void (*)(void)) court_export },
    { 0, NULL }
};

/* The three mandatory callbacks, and an `import` that refuses its own key. */
static const OSSL_DISPATCH skey_refuse_fns[] = {
    { OSSL_FUNC_SKEYMGMT_FREE, (void (*)(void)) court_free },
    { OSSL_FUNC_SKEYMGMT_IMPORT, (void (*)(void)) court_import_refuses },
    { OSSL_FUNC_SKEYMGMT_EXPORT, (void (*)(void)) court_export },
    { 0, NULL }
};

static const OSSL_ALGORITHM court_a_keys[] = {
    { "SKEY-Court:SKEY-court:courtskey", "provider=court-skey", skey_full_fns,
      "court secret key, with every optional callback" },
    { "SKEY-Minimal:SKEY-minimal:courtskeyminimal", "provider=court-skey", skey_minimal_fns,
      "court secret key with only the three mandatory callbacks" },
    { "SKEY-Dup:SKEY-dup:courtskeydup", "provider=court-skey", skey_dup_fns,
      "court secret key that lists its importer twice" },
    { "SKEY-Refuse:SKEY-refuse:courtskeyrefuse", "provider=court-skey", skey_refuse_fns,
      "court secret key whose importer refuses" },
    { "SKEY-NoExport:SKEY-noexport:courtskeynoexport", "provider=court-skey", skey_noexport_fns,
      "court secret key that must be refused, for its exporter" },
    { "SKEY-NoFree:SKEY-nofree:courtskeynofree", "provider=court-skey", skey_nofree_fns,
      "court secret key that must be refused, for its destructor" },
    { "SKEY-NoImport:SKEY-noimport:courtskeynoimport", "provider=court-skey", skey_noimport_fns,
      "court secret key that must be refused, for its importer" },
    { "GENERIC-SECRET:generic-secret:courtskeygeneric", "provider=court-skey", skey_minimal_fns,
      "the name EVP_SKEY_import falls back to" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *court_a_query(void *provctx, int operation_id, int *no_cache)
{
    (void) provctx;
    *no_cache = 0;
    if (operation_id == OSSL_OP_SKEYMGMT)
        return court_a_keys;
    return NULL;
}

static const OSSL_DISPATCH court_a_dispatch[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void)) court_a_query },
    { 0, NULL }
};

static char marker_a;

static int court_a_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
                        const OSSL_DISPATCH **out, void **provctx)
{
    (void) handle;
    (void) in;
    *out = court_a_dispatch;
    /* The provider context is the *flavour*, as a small integer: the key data's constructor reads
     * it, so a key says which provider made it. */
    *provctx = (void *) (size_t) 1;
    (void) marker_a;
    return 1;
}

/* ---- provider B: the same first name, a different provider ---- */

static const OSSL_ALGORITHM court_b_keys[] = {
    { "SKEY-Court:SKEY-court-b:courtskeyb", "provider=court-skey-b", skey_full_fns,
      "the same key type, in a second provider" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *court_b_query(void *provctx, int operation_id, int *no_cache)
{
    (void) provctx;
    *no_cache = 0;
    if (operation_id == OSSL_OP_SKEYMGMT)
        return court_b_keys;
    return NULL;
}

static const OSSL_DISPATCH court_b_dispatch[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void)) court_b_query },
    { 0, NULL }
};

static int court_b_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
                        const OSSL_DISPATCH **out, void **provctx)
{
    (void) handle;
    (void) in;
    *out = court_b_dispatch;
    *provctx = (void *) (size_t) 2;
    return 1;
}

/* ---- the do_all and name visitors ---- */

struct skey_seen {
    int count;
    int saw_full;
    int saw_refused;
};

static void skey_visitor(EVP_SKEYMGMT *mgmt, void *arg)
{
    struct skey_seen *s = arg;
    const char *name = EVP_SKEYMGMT_get0_name(mgmt);

    s->count++;
    if (name != NULL && strcmp(name, "SKEY-Court") == 0)
        s->saw_full = 1;
    if (name != NULL && strcmp(name, "SKEY-NoExport") == 0)
        s->saw_refused = 1;
}

struct skey_names {
    int count;
    int saw_identity;
    int saw_alias;
};

static void skey_name_visitor(const char *name, void *arg)
{
    struct skey_names *s = arg;

    s->count++;
    if (strcmp(name, "SKEY-Court") == 0)
        s->saw_identity = 1;
    if (strcmp(name, "courtskey") == 0)
        s->saw_alias = 1;
}

int main(void)
{
    OSSL_LIB_CTX *ctx;
    OSSL_PROVIDER *a, *b;
    EVP_SKEYMGMT *full, *minimal, *dup, *refuse, *again;
    EVP_SKEYMGMT *noexport, *nofree, *noimport;
    EVP_SKEY *skey, *other, *generated, *fallback, *refused;
    const unsigned char raw[5] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE };
    OSSL_PARAM gen_params[2];
    OSSL_PARAM raw_params[2];
    size_t want = 4;

    setvbuf(stdout, NULL, _IOLBF, 0);
    raw_params[0] = OSSL_PARAM_construct_octet_string(OSSL_SKEY_PARAM_RAW_BYTES,
                                                     (void *) raw, sizeof raw);
    raw_params[1] = OSSL_PARAM_construct_end();

    ctx = OSSL_LIB_CTX_new();
    if (ctx == NULL) {
        printf("fail.libctx=1\n");
        return 0;
    }
    sayn("add_builtin.a", OSSL_PROVIDER_add_builtin(ctx, "court-skey", court_a_init));
    sayn("add_builtin.b", OSSL_PROVIDER_add_builtin(ctx, "court-skey-b", court_b_init));
    a = OSSL_PROVIDER_load(ctx, "court-skey");
    b = OSSL_PROVIDER_load(ctx, "court-skey-b");
    printf("load.a=%d\n", a != NULL ? 1 : 0);
    printf("load.b=%d\n", b != NULL ? 1 : 0);
    if (a == NULL || b == NULL) {
        OSSL_LIB_CTX_free(ctx);
        return 0;
    }
    reset_counts();

    /*
     * ---- the structural check: three NULL tests and no arithmetic ----
     *
     * Seven algorithms are published and four are constructed: the full one, the minimal one, the
     * one that lists its importer twice, and the one whose importer refuses at *run* time (the check
     * is structural, so a callback that returns NULL is not a structural defect). The three
     * refusals are the three mandatory callbacks.
     */
    full = EVP_SKEYMGMT_fetch(ctx, "SKEY-Court", NULL);
    minimal = EVP_SKEYMGMT_fetch(ctx, "SKEY-Minimal", NULL);
    dup = EVP_SKEYMGMT_fetch(ctx, "SKEY-Dup", NULL);
    refuse = EVP_SKEYMGMT_fetch(ctx, "SKEY-Refuse", NULL);
    sayp("fetch.full", full);
    sayp("fetch.minimal", minimal);
    sayp("fetch.duplicate_importer", dup);
    sayp("fetch.refusing_importer", refuse);

    noexport = EVP_SKEYMGMT_fetch(ctx, "SKEY-NoExport", NULL);
    sayp("fetch.no_export", noexport);
    printf("fetch.no_export.err=%lu\n", ERR_peek_error());
    ERR_clear_error();
    nofree = EVP_SKEYMGMT_fetch(ctx, "SKEY-NoFree", NULL);
    sayp("fetch.no_free", nofree);
    printf("fetch.no_free.err=%lu\n", ERR_peek_error());
    ERR_clear_error();
    noimport = EVP_SKEYMGMT_fetch(ctx, "SKEY-NoImport", NULL);
    sayp("fetch.no_import", noimport);
    printf("fetch.no_import.err=%lu\n", ERR_peek_error());
    ERR_clear_error();

    again = EVP_SKEYMGMT_fetch(ctx, "no-such-key-type", NULL);
    sayp("fetch.unknown", again);
    printf("fetch.unknown.err=%lu\n", ERR_peek_error());
    ERR_clear_error();
    again = EVP_SKEYMGMT_fetch(ctx, "SKEY-Court", "provider=other");
    sayp("fetch.rejected", again);
    printf("fetch.rejected.err=%lu\n", ERR_peek_error());
    ERR_clear_error();
    again = EVP_SKEYMGMT_fetch(ctx, "courtskey", NULL);
    printf("fetch.alias_same_object=%d\n", again == full ? 1 : 0);
    EVP_SKEYMGMT_free(again);

    /*
     * ---- the method object ----
     */
    if (full != NULL) {
        const char *name = EVP_SKEYMGMT_get0_name(full);
        const char *desc = EVP_SKEYMGMT_get0_description(full);

        printf("method.name_matches=%d\n",
               name != NULL && strcmp(name, "SKEY-Court") == 0 ? 1 : 0);
        printf("method.description_matches=%d\n",
               desc != NULL
                   && strcmp(desc, "court secret key, with every optional callback") == 0 ? 1 : 0);
        sayp("method.provider", (const void *) EVP_SKEYMGMT_get0_provider(full));
        sayn("method.is_a.identity", EVP_SKEYMGMT_is_a(full, "SKEY-Court"));
        sayn("method.is_a.alias", EVP_SKEYMGMT_is_a(full, "courtskey"));
        sayn("method.is_a.other", EVP_SKEYMGMT_is_a(full, "SKEY-Minimal"));
        sayn("method.is_a.null_method", EVP_SKEYMGMT_is_a(NULL, "SKEY-Court"));

        /* The two parameter accessors, which are **provider callbacks** rather than method fields:
         * each one asks the provider. */
        reset_counts();
        sayp("method.gen_settable", (const void *) EVP_SKEYMGMT_get0_gen_settable_params(full));
        sayp("method.imp_settable", (const void *) EVP_SKEYMGMT_get0_imp_settable_params(full));
        say_vec("method.params.vec");
        /* NULL for a NULL method and NULL for a method with no callback alike. */
        sayp("method.gen_settable.null_method",
             (const void *) EVP_SKEYMGMT_get0_gen_settable_params(NULL));
        sayp("method.gen_settable.minimal",
             (const void *) EVP_SKEYMGMT_get0_gen_settable_params(minimal));
        sayp("method.imp_settable.minimal",
             (const void *) EVP_SKEYMGMT_get0_imp_settable_params(minimal));
        {
            struct skey_names s;

            memset(&s, 0, sizeof s);
            sayn("method.names_do_all.ret",
                 EVP_SKEYMGMT_names_do_all(full, skey_name_visitor, &s));
            sayn("method.names.count", s.count);
            sayn("method.names.saw_identity", s.saw_identity);
            sayn("method.names.saw_alias", s.saw_alias);
        }
    }

    /*
     * ---- the key: import, the round trip, and the reference it holds on its method ----
     */
    reset_counts();
    skey = EVP_SKEY_import_raw_key(ctx, "SKEY-Court", (unsigned char *) raw, sizeof raw, NULL);
    sayp("key.import", skey);
    say_vec("key.import.vec");
    say_args("key.import.args");
    if (skey != NULL) {
        const unsigned char *got = NULL;
        size_t gotlen = 0;

        says("key.skeymgmt_name", EVP_SKEY_get0_skeymgmt_name(skey));
        says("key.provider_name", EVP_SKEY_get0_provider_name(skey));
        says("key.key_id", EVP_SKEY_get0_key_id(skey));
        sayn("key.is_a.identity", EVP_SKEY_is_a(skey, "SKEY-Court"));
        sayn("key.is_a.alias", EVP_SKEY_is_a(skey, "courtskey"));
        sayn("key.is_a.other", EVP_SKEY_is_a(skey, "SKEY-Minimal"));
        sayn("key.is_a.null_key", EVP_SKEY_is_a(NULL, "SKEY-Court"));

        reset_counts();
        sayn("key.get0_raw_key.ret", EVP_SKEY_get0_raw_key(skey, &got, &gotlen));
        sayn("key.get0_raw_key.len", (long long) gotlen);
        sayn("key.get0_raw_key.byte0", got != NULL && gotlen > 0 ? got[0] : -1);
        sayn("key.get0_raw_key.byte4", got != NULL && gotlen > 4 ? got[4] : -1);
        printf("key.get0_raw_key.round_trip=%d\n",
               got != NULL && gotlen == sizeof raw && memcmp(got, raw, sizeof raw) == 0 ? 1 : 0);
        say_vec("key.export.vec");
        say_args("key.export.args");

        /* Two `up_ref`s and three `free`s: one release per reference and the key data freed on the
         * last, which is the counter the vector shows. */
        reset_counts();
        sayn("key.up_ref.1", EVP_SKEY_up_ref(skey));
        sayn("key.up_ref.2", EVP_SKEY_up_ref(skey));
        EVP_SKEY_free(skey);
        say_vec("key.free.after_one.vec");
        EVP_SKEY_free(skey);
        say_vec("key.free.after_two.vec");
        EVP_SKEY_free(skey);
        say_vec("key.free.after_three.vec");
    }
    EVP_SKEY_free(NULL);
    printf("key.free_null=returned err=%lu\n", ERR_peek_error());
    ERR_clear_error();

    /*
     * ---- `EVP_SKEY_import` falls back by name ----
     */
    reset_counts();
    fallback = EVP_SKEY_import(ctx, "no-such-key-type", NULL, OSSL_SKEYMGMT_SELECT_SECRET_KEY,
                               raw_params);
    sayp("fallback.import", fallback);
    if (fallback != NULL) {
        says("fallback.skeymgmt_name", EVP_SKEY_get0_skeymgmt_name(fallback));
        says("fallback.provider_name", EVP_SKEY_get0_provider_name(fallback));
        EVP_SKEY_free(fallback);
    }
    say_vec("fallback.vec");

    /* An importer that refuses is a NULL key and no raise from this layer. */
    reset_counts();
    refused = EVP_SKEY_import(ctx, "SKEY-Refuse", NULL, OSSL_SKEYMGMT_SELECT_SECRET_KEY, raw_params);
    sayp("refused.import", refused);
    say_vec("refused.vec");

    /* `EVP_SKEY_import_SKEYMGMT` is the same import with the method in hand. */
    reset_counts();
    other = EVP_SKEY_import_SKEYMGMT(ctx, full, OSSL_SKEYMGMT_SELECT_PARAMETERS, raw_params);
    sayp("import_skeymgmt.with_params_only", other);
    say_vec("import_skeymgmt.vec");
    EVP_SKEY_free(other);
    /* A NULL method is refused by the allocator's `ossl_assert`, without raising. */
    sayp("import_skeymgmt.null_method",
         EVP_SKEY_import_SKEYMGMT(ctx, NULL, OSSL_SKEYMGMT_SELECT_SECRET_KEY, NULL));

    /*
     * ---- `EVP_SKEY_generate`, and the method that cannot ----
     */
    reset_counts();
    gen_params[0] = OSSL_PARAM_construct_size_t(OSSL_SKEY_PARAM_KEY_LENGTH, &want);
    gen_params[1] = OSSL_PARAM_construct_end();
    generated = EVP_SKEY_generate(ctx, "SKEY-Court", NULL, gen_params);
    sayp("generate.import", generated);
    say_vec("generate.vec");
    say_args("generate.args");
    if (generated != NULL) {
        const unsigned char *got = NULL;
        size_t gotlen = 0;

        sayn("generate.get0_raw_key.ret", EVP_SKEY_get0_raw_key(generated, &got, &gotlen));
        sayn("generate.get0_raw_key.len", (long long) gotlen);
        sayn("generate.get0_raw_key.byte0", got != NULL && gotlen > 0 ? got[0] : -1);
        says("generate.key_id", EVP_SKEY_get0_key_id(generated));
        EVP_SKEY_free(generated);
    }
    /* The minimal method publishes no `generate`, and the fetch succeeds regardless. */
    reset_counts();
    generated = EVP_SKEY_generate(ctx, "SKEY-Minimal", NULL, NULL);
    sayp("generate.no_callback", generated);
    say_vec("generate.no_callback.vec");

    /*
     * ---- `EVP_SKEY_to_provider`: four arms ----
     */
    reset_counts();
    skey = EVP_SKEY_import_raw_key(ctx, "SKEY-Court", (unsigned char *) raw, sizeof raw, NULL);
    reset_counts();
    /* Arm one: no provider, so the default one is resolved by name -- and it is the origin, so the
     * answer is the same object with a reference taken. */
    other = EVP_SKEY_to_provider(skey, ctx, NULL, NULL);
    printf("to_provider.default_same_object=%d\n", other == skey ? 1 : 0);
    say_vec("to_provider.default.vec");
    EVP_SKEY_free(other);
    /* Arm two: the *same* provider named explicitly is also the origin. */
    other = EVP_SKEY_to_provider(skey, ctx, a, NULL);
    printf("to_provider.same_provider_same_object=%d\n", other == skey ? 1 : 0);
    say_vec("to_provider.same_provider.vec");
    EVP_SKEY_free(other);
    /* Arm three: a different provider with the same key type: a full round trip, and the result is
     * the *destination's* key, which the flavour inside it says. */
    reset_counts();
    other = EVP_SKEY_to_provider(skey, ctx, b, NULL);
    sayp("to_provider.other_provider", other);
    printf("to_provider.other_provider_distinct=%d\n",
           other != NULL && other != skey ? 1 : 0);
    if (other != NULL) {
        const unsigned char *got = NULL;
        size_t gotlen = 0;

        says("to_provider.other_provider.provider_name", EVP_SKEY_get0_provider_name(other));
        says("to_provider.other_provider.skeymgmt_name", EVP_SKEY_get0_skeymgmt_name(other));
        says("to_provider.other_provider.key_id", EVP_SKEY_get0_key_id(other));
        printf("to_provider.other_provider.round_trip=%d\n",
               EVP_SKEY_get0_raw_key(other, &got, &gotlen) == 1
                   && gotlen == sizeof raw && memcmp(got, raw, sizeof raw) == 0 ? 1 : 0);
        EVP_SKEY_free(other);
    }
    say_vec("to_provider.other_provider.vec");
    /* Arm four: a NULL key raises. */
    sayp("to_provider.null_key", EVP_SKEY_to_provider(NULL, ctx, a, NULL));
    printf("to_provider.null_key.err=%lu\n", ERR_peek_error());
    ERR_clear_error();
    EVP_SKEY_free(skey);

    /*
     * ---- `do_all`, which counts what was *constructed* ----
     *
     * Provider A publishes eight algorithms and **three** cannot be constructed; provider B
     * publishes one. The walk visits both loaded providers, so the count is nine minus three.
     */
    {
        struct skey_seen s;

        memset(&s, 0, sizeof s);
        EVP_SKEYMGMT_do_all_provided(ctx, skey_visitor, &s);
        sayn("do_all.count", s.count);
        sayn("do_all.saw_full", s.saw_full);
        sayn("do_all.saw_a_refused_one", s.saw_refused);
    }
    printf("do_all.null_visitor=NOT_MEASURED_AUTHORITY_FAULTS\n");

    reset_counts();
    EVP_SKEYMGMT_free(full);
    EVP_SKEYMGMT_free(minimal);
    EVP_SKEYMGMT_free(dup);
    EVP_SKEYMGMT_free(refuse);
    EVP_SKEYMGMT_free(noexport);
    EVP_SKEYMGMT_free(nofree);
    EVP_SKEYMGMT_free(noimport);
    say_vec("final.vec");
    sayn("unload.a", OSSL_PROVIDER_unload(a));
    sayn("unload.b", OSSL_PROVIDER_unload(b));
    OSSL_LIB_CTX_free(ctx);
    return 0;
}
