/*
 * openssl-rs — the differential RAND probe (RT-RAND).
 *
 * This program is compiled **twice**, once against the admitted authority and once against the
 * candidate distribution shell, and the two `key=value` transcripts are diffed. It decides
 * nothing: a residual is a difference between two executions, so the expectation cannot drift
 * with the crate. `forensics/tools/phase9_courts.py` owns the comparison.
 *
 * What this probe establishes
 * ---------------------------
 * It is the evidence for the twenty-five exports `rand.h` declares in this stratum: the legacy
 * `RAND_METHOD` table and its identity (`RAND_get_rand_method`, `RAND_set_rand_method`,
 * `RAND_set_rand_engine`, `RAND_OpenSSL`), the byte sources (`RAND_bytes`, `RAND_bytes_ex`,
 * `RAND_priv_bytes`, `RAND_priv_bytes_ex`, `RAND_pseudo_bytes`), the per-`OSSL_LIB_CTX` DRBG
 * handles (`RAND_get0_primary`, `RAND_get0_public`, `RAND_get0_private`, `RAND_set0_public`,
 * `RAND_set0_private`), the configuration setters (`RAND_set_DRBG_type`,
 * `RAND_set_seed_source_type`, `RAND_set1_random_provider`), the mixing entry points
 * (`RAND_seed`, `RAND_add`, `RAND_poll`, `RAND_keep_random_devices_open`, `RAND_status`) and the
 * seed-file helpers (`RAND_file_name`, `RAND_load_file`, `RAND_write_file`).
 *
 * The method table is observed by shape, not by address
 * -----------------------------------------------------
 * `RAND_get_rand_method()` answers a pointer whose identity `RAND_get_rand_method() ==
 * RAND_OpenSSL()` is the first observation, and whose six callback fields are then read as
 * non-NULL booleans through the header's own `struct rand_meth_st`. Printing the address would
 * turn one behavioural residual into an ASLR diff; printing the shape compares the table itself.
 * `ossl_rand_meth` is `{ drbg_seed, drbg_bytes, NULL, drbg_add, drbg_bytes, drbg_status }`, so a
 * candidate that dropped `pseudorand` or `cleanup` is a residual here and nowhere else.
 *
 * The order is load-bearing, and why
 * ----------------------------------
 * Three of these entries refuse once their object exists: `RAND_set_DRBG_type` and
 * `RAND_set_seed_source_type` answer 0 with `RAND_R_ALREADY_INSTANTIATED` after the primary is
 * built, and every `_ex` byte call runs a different body once a randomness provider is nominated.
 * A probe that called them in the wrong order would measure the refusal for all of them and look
 * identical on both sides -- the kind of agreement that proves nothing. So each is called **both
 * before and after** the object it guards, and both answers are observations:
 *
 *   1. the setters, before anything is instantiated    -> success
 *   2. the method table and its identity               -> shape and the `== RAND_OpenSSL()` edge
 *   3. `RAND_status`, which builds the primary         -> the state machine's first transition
 *   4. the byte sources, the getters, the setters again -> the ordinary path and the refusals
 *   5. `RAND_seed`/`RAND_add`/`RAND_poll`               -> the mixing path
 *   6. the seed-file helpers against a temp path       -> open, `stat`, `S_ISREG`, read, refusal
 *
 * What it deliberately does not observe
 * -------------------------------------
 * **The bytes.** The authority and the candidate seed their DRBGs from different pools -- the
 * authority's entropy is this machine's, the candidate's is its own transcription of the same
 * sources -- so their outputs differ by construction. Comparing them would compare two machines,
 * and `docs/PHASE-9-SUBPHASES.md` section 3.3 records output unpredictability as not courted for
 * that reason. `CT-DRBG` compares bytes, against the pinned CAVP vectors, rather than here.
 *
 * **The seed file's contents**, for the same reason: `RAND_write_file`'s *length* and return code
 * are observations, its bytes are not. The temp path is unlinked on both entry and exit so the
 * two sides cannot read each other's file -- each side's `RAND_load_file` reads the bytes that
 * same side wrote.
 *
 * What a difference here means
 * ----------------------------
 * Every observation is a return code, a boolean, a name, a file length, or an
 * `ERR_GET_LIB`/`ERR_GET_REASON` pair drained from the error queue. No address is ever printed
 * and no NULL-dereferencing entry point is called, so a probe that aborts the harness compares
 * nothing rather than comparing noise.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/rand.h>

/*
 * The temp seed file. One fixed path for both sides, because each side unlinks it before it writes
 * and again after it reads: what is compared is the pair of return codes, never the crossing of
 * one side's bytes into the other's run.
 */
static const char RFILE_PATH[] = "/tmp/openssl-rs-rt-rand-probe.rnd";
/* A path that cannot open, for `RAND_load_file`'s `RAND_R_CANNOT_OPEN_FILE` arm. */
static const char MISSING_PATH[] = "/nonexistent/openssl-rs/rt-rand-probe.rnd";
/* A path that opens but is not a regular file, for `RAND_write_file`'s `S_ISREG` arm. */
static const char NOT_REGULAR_PATH[] = "/tmp";

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
 * The six callback fields of a `RAND_METHOD`, as non-NULL booleans, in the header's own order.
 * A NULL table is one observation of its own: `RAND_get_rand_method` can answer NULL and the
 * authority's callers treat that as "no method", which is a different behaviour from a table whose
 * callbacks are absent.
 */
static void method_shape(const char *key, const RAND_METHOD *m)
{
    if (m == NULL) {
        printf("%s=null\n", key);
        return;
    }
    printf("%s.seed=%d\n", key, m->seed != NULL);
    printf("%s.bytes=%d\n", key, m->bytes != NULL);
    printf("%s.cleanup=%d\n", key, m->cleanup != NULL);
    printf("%s.add=%d\n", key, m->add != NULL);
    printf("%s.pseudorand=%d\n", key, m->pseudorand != NULL);
    printf("%s.status=%d\n", key, m->status != NULL);
}

int main(void)
{
    unsigned char buf[1024];
    char namebuf[512];
    const RAND_METHOD *m;
    OSSL_PROVIDER *prov;
    struct stat sb;

    setvbuf(stdout, NULL, _IOLBF, 0);

    /* The probe is given a pristine temp path: nothing a previous run or the other side left is
     * allowed to become an input. */
    (void)unlink(RFILE_PATH);

    prov = OSSL_PROVIDER_load(NULL, "default");
    printf("provider.load.default=%d\n", prov != NULL);
    errs("err.provider.load.default");

    /* ---- 1. The setters, before their object exists -------------------------------- */

    /* NULL arguments clear the stored spellings rather than installing an algorithm, which is why
     * this is the success observation and not a change of behaviour: the fetch that follows falls
     * back to its own defaults on both sides, so the later byte observations stay comparable. */
    printf("set_drbg_type.clear=%d\n",
           RAND_set_DRBG_type(NULL, NULL, NULL, NULL, NULL));
    errs("err.set_drbg_type.clear");
    printf("set_seed_source_type.clear=%d\n",
           RAND_set_seed_source_type(NULL, NULL, NULL));
    errs("err.set_seed_source_type.clear");
    printf("set1_random_provider.clear=%d\n",
           RAND_set1_random_provider(NULL, NULL));
    errs("err.set1_random_provider.clear");

    /* ---- 2. The method table and its identity ------------------------------------- */

    m = RAND_get_rand_method();
    printf("method.nonnull=%d\n", m != NULL);
    printf("method.is_openssl=%d\n", m == RAND_OpenSSL());
    method_shape("method", m);
    printf("openssl_method.nonnull=%d\n", RAND_OpenSSL() != NULL);
    method_shape("openssl_method", RAND_OpenSSL());
    errs("err.method");

    /* `RAND_set_rand_method(NULL)` uninstalls the table; the next `get` must rebuild it to the
     * default, because the authority's `RAND_get_rand_method` fills in `&ossl_rand_meth` when it
     * reads NULL. That self-healing is the observation, not incidental. */
    printf("method.set_null=%d\n", RAND_set_rand_method(NULL));
    errs("err.method.set_null");
    m = RAND_get_rand_method();
    printf("method.after_null.nonnull=%d\n", m != NULL);
    printf("method.after_null.is_openssl=%d\n", m == RAND_OpenSSL());
    method_shape("method.after_null", m);
    errs("err.method.after_null");
    printf("method.set_openssl=%d\n", RAND_set_rand_method(RAND_OpenSSL()));
    errs("err.method.set_openssl");

    /* ---- 3. `RAND_status` builds the primary, and the setters now refuse ------------ */

    printf("status.initial=%d\n", RAND_status());
    errs("err.status.initial");

    printf("set_drbg_type.after_primary=%d\n",
           RAND_set_DRBG_type(NULL, "CTR-DRBG", NULL, "AES-256-CTR", NULL));
    errs("err.set_drbg_type.after_primary");
    printf("set_seed_source_type.after_primary=%d\n",
           RAND_set_seed_source_type(NULL, "SEED-SRC", NULL));
    errs("err.set_seed_source_type.after_primary");

    /* ---- 4. The byte sources and the per-context handles -------------------------- */

    memset(buf, 0, sizeof(buf));

    printf("bytes_ex.16=%d\n", RAND_bytes_ex(NULL, buf, 16, 0));
    errs("err.bytes_ex.16");
    printf("priv_bytes_ex.16=%d\n", RAND_priv_bytes_ex(NULL, buf, 16, 0));
    errs("err.priv_bytes_ex.16");
    /* A strength the public DRBG's cipher can satisfy, to prove the parameter is read rather than
     * ignored. */
    printf("bytes_ex.16_s128=%d\n", RAND_bytes_ex(NULL, buf, 16, 128));
    errs("err.bytes_ex.16_s128");
    /* A strength no 256-bit DRBG can satisfy: the refusal arm. */
    printf("bytes_ex.16_s512=%d\n", RAND_bytes_ex(NULL, buf, 16, 512));
    errs("err.bytes_ex.16_s512");
    /* The zero-length boundary. */
    printf("bytes_ex.0=%d\n", RAND_bytes_ex(NULL, buf, 0, 0));
    errs("err.bytes_ex.0");

    printf("bytes.16=%d\n", RAND_bytes(buf, 16));
    errs("err.bytes.16");
    printf("priv_bytes.16=%d\n", RAND_priv_bytes(buf, 16));
    errs("err.priv_bytes.16");
    /* The negative-length wrapper: the authority answers 0 without reaching the DRBG. */
    printf("bytes.neg=%d\n", RAND_bytes(buf, -1));
    errs("err.bytes.neg");
    printf("priv_bytes.neg=%d\n", RAND_priv_bytes(buf, -1));
    errs("err.priv_bytes.neg");
    /* The deprecated wrapper, which the default table routes to `drbg_bytes`. */
    printf("pseudo_bytes.16=%d\n", RAND_pseudo_bytes(buf, 16));
    errs("err.pseudo_bytes.16");

    printf("get0_primary.nonnull=%d\n", RAND_get0_primary(NULL) != NULL);
    printf("get0_public.nonnull=%d\n", RAND_get0_public(NULL) != NULL);
    printf("get0_private.nonnull=%d\n", RAND_get0_private(NULL) != NULL);
    errs("err.get0");

    /* `_set0_*` frees the old handle and installs NULL; the following getter must then rebuild.
     * Passing the live handle back in would free what it just installed, so NULL is both the safe
     * argument and the one that reaches the free path. */
    printf("set0_public.null=%d\n", RAND_set0_public(NULL, NULL));
    errs("err.set0_public.null");
    printf("set0_private.null=%d\n", RAND_set0_private(NULL, NULL));
    errs("err.set0_private.null");
    printf("get0_public.after_set0=%d\n", RAND_get0_public(NULL) != NULL);
    printf("get0_private.after_set0=%d\n", RAND_get0_private(NULL) != NULL);
    errs("err.get0.after_set0");

    /* ---- 5. The mixing path and the randomness-provider dispatch ------------------- */

    /* `RAND_seed`, `RAND_add` and `RAND_keep_random_devices_open` return void: their only
     * observable is what they put on (or leave off) the error queue, which is what is drained
     * here. A printed constant would add a line to the transcript without adding an observation. */
    RAND_seed(buf, 16);
    errs("err.seed");
    RAND_add(buf, 16, 0.5);
    errs("err.add");
    RAND_keep_random_devices_open(1);
    errs("err.keep_open");
    printf("poll=%d\n", RAND_poll());
    errs("err.poll");

    /*
     * The dispatch arm. The default provider publishes no `OSSL_FUNC_provider_random_bytes`
     * (`providers/defltprov.c` carries none; only the FIPS module does), so `ossl_provider_random_bytes`
     * answers 0 for it on the authority. That is the observation: the candidate must answer 0 too,
     * and must answer it *through* the nominated provider rather than silently falling back to its
     * own DRBG. Only a provider that does publish the callback can return 1, which is what the
     * refusal is here to pin.
     */
    printf("set1_random_provider.default=%d\n", RAND_set1_random_provider(NULL, prov));
    errs("err.set1_random_provider.default");
    printf("bytes_ex.via_provider=%d\n", RAND_bytes_ex(NULL, buf, 16, 0));
    errs("err.bytes_ex.via_provider");
    printf("priv_bytes_ex.via_provider=%d\n", RAND_priv_bytes_ex(NULL, buf, 16, 0));
    errs("err.priv_bytes_ex.via_provider");
    printf("set1_random_provider.clear2=%d\n", RAND_set1_random_provider(NULL, NULL));
    errs("err.set1_random_provider.clear2");
    /* The DRBG path must be reachable again once the nomination is cleared. */
    printf("bytes_ex.after_clear=%d\n", RAND_bytes_ex(NULL, buf, 16, 0));
    errs("err.bytes_ex.after_clear");

    /* ---- 6. The seed-file helpers -------------------------------------------------- */

    printf("file_name.ok=%d\n", RAND_file_name(namebuf, sizeof(namebuf)) != NULL);
    printf("file_name.value=%s\n",
           RAND_file_name(namebuf, sizeof(namebuf)) != NULL ? namebuf : "(null)");
    /* A buffer too small for `$RANDFILE` or `$HOME/.rnd` is a NULL answer, not a truncation. */
    printf("file_name.tiny=%d\n", RAND_file_name(namebuf, 1) != NULL);
    errs("err.file_name");

    printf("write_file.tmp=%d\n", RAND_write_file(RFILE_PATH));
    errs("err.write_file.tmp");
    printf("write_file.size_matches=%d\n",
           stat(RFILE_PATH, &sb) == 0 && S_ISREG(sb.st_mode)
           && sb.st_size == 1024);
    errs("err.write_file.stat");

    printf("load_file.all=%d\n", RAND_load_file(RFILE_PATH, -1));
    errs("err.load_file.all");
    printf("load_file.100=%d\n", RAND_load_file(RFILE_PATH, 100));
    errs("err.load_file.100");
    printf("load_file.zero=%d\n", RAND_load_file(RFILE_PATH, 0));
    errs("err.load_file.zero");
    printf("load_file.missing=%d\n", RAND_load_file(MISSING_PATH, -1));
    errs("err.load_file.missing");
    /* A directory opens but is not a regular file: `RAND_write_file` refuses before writing. */
    printf("write_file.not_regular=%d\n", RAND_write_file(NOT_REGULAR_PATH));
    errs("err.write_file.not_regular");

    (void)unlink(RFILE_PATH);

    /* ---- The engine setter, whose only reachable argument is NULL ------------------ */

    printf("set_rand_engine.null=%d\n", RAND_set_rand_engine(NULL));
    errs("err.set_rand_engine.null");
    m = RAND_get_rand_method();
    printf("method.after_engine.nonnull=%d\n", m != NULL);
    printf("method.after_engine.is_openssl=%d\n", m == RAND_OpenSSL());
    method_shape("method.after_engine", m);
    errs("err.method.after_engine");

    printf("status.final=%d\n", RAND_status());
    errs("err.status.final");

    printf("provider.unload.default=%d\n", OSSL_PROVIDER_unload(prov));
    printf("provider.available=%d\n", OSSL_PROVIDER_available(NULL, "default"));
    errs("err.provider.unload.default");
    return 0;
}
