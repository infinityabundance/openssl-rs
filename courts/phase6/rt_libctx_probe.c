/*
 * RT-LIBCTX -- the library context, differentially.
 *
 * What this court has to establish
 * --------------------------------
 * `OSSL_LIB_CTX` is the object the whole of OpenSSL 3 is parameterised by, and almost
 * none of its contract is in its documentation. What a caller can actually observe is:
 *
 *   * **identity and lifetime.** `OSSL_LIB_CTX_new` hands back a distinct object each
 *     time; `OSSL_LIB_CTX_get0_global_default` hands back *the same* object in every
 *     thread and never a new one; and two of the three values `OSSL_LIB_CTX_free`
 *     accepts -- NULL, and a context that is currently the default for this thread --
 *     are **no-ops**, because `ossl_lib_ctx_is_default` answers 1 for both. A caller
 *     who frees the thread-local default and then uses it is not using freed memory.
 *   * **the default chain.** A NULL context resolves to this thread's default if one
 *     was set and to the global default otherwise, and `OSSL_LIB_CTX_set0_default`
 *     *returns the previous default while setting a new one*, except that passing the
 *     global default as the new one **clears** the thread's slot rather than pointing
 *     it back at the global object.
 *   * **the index registry.** `OSSL_LIB_CTX_get_data(ctx, index)` is a plain switch
 *     with no bounds check, so the *shape* of the table is observable: which index
 *     numbers answer a pointer, which answer NULL, and which answer a pointer into the
 *     context itself. A caller cannot name the indices -- they are declared in
 *     `include/internal/cryptlib.h`, which is not installed -- but it can pass
 *     integers, and this probe does, so the numbers below are written out with the
 *     header they came from. That is also why the probe is written against the
 *     *installed* headers only.
 *   * **`conf_diagnostics` is per-context state**, read and written through a NULL
 *     context as well, so a caller can set it on the default context without naming it.
 *
 * Addresses are never printed. Every observation is a *relation* between two pointers
 * this probe holds (`==`, `!=`) or a presence answer (`NULL` / `nonnull`), because the
 * authority's addresses and the candidate's cannot be equal and printing one would
 * compare the probe's own heap layout rather than the library's behaviour. Relations
 * are the entire observable content of an identity API.
 *
 * The scope of the index table
 * ---------------------------
 * The authority answers a pointer for **every live index** -- eighteen of them -- and
 * each holds a sub-object that a different stratum owns. This stratum owns one: index
 * 21, whose answer is the *address of a field* rather than an allocation, and which is
 * therefore exact as soon as the field exists. The other seventeen are named in
 * `docs/PHASE-6-SUBPHASES.md` with the subphase that fills each, and this probe does
 * not call them: calling one would compare a *missing subsystem* rather than a
 * behavioural divergence, which is the obligation ledger's business, not a court's.
 *
 * So the table below observes two things and prints its own scope:
 *
 *   * the **dead** indices -- -1, 7, 8, 9, 13 and everything from 23 up -- which answer
 *     NULL in the authority because its `switch` has no arm for them, and must answer
 *     NULL in the candidate for the same reason. This is a real test of the boundary,
 *     and it is the one place where a candidate that guessed instead of reading would
 *     differ.
 *   * the **filled** slots, which the candidate claims to have built.
 *
 * `libctx.slots.live`, `.filled` and `.deferred` state the arithmetic, so a reader of
 * the transcript can see the gap without reading this file. When a later subphase fills
 * a slot it adds it to `filled_slots` and the counts move with it.
 *
 * Fault boundaries
 * ----------------
 * A divergence this probe deliberately does not observe
 * ----------------------------------------------------
 * `OSSL_LIB_CTX_load_config` with a NULL file name and `OPENSSL_CONF` unset reaches
 * `CONF_get1_default_config_file`, whose fallback is the authority's own `OPENSSLDIR` and
 * this crate's empty string -- a recorded divergence, because claiming a path inside the
 * authority's build tree would be a false statement about this build. The observation is
 * left out for the same reason `RT-CONF-MOD` leaves out the
 * `OPENSSL_load_builtin_modules` fan-out: it would fail the court for a reason the court
 * is not about. The half that *is* in scope -- a default file that exists -- is observed,
 * with `OPENSSL_CONF` set to a file the probe wrote.
 *
 * One observation deliberately reads a context *after* `OSSL_LIB_CTX_free` returned,
 * to distinguish "the no-op the authority performs" from "a free". That read is only
 * well-defined because the authority keeps the object alive; an implementation that
 * really freed it is reading released memory, which glibc does not fault on for a
 * heap chunk of this size, so the defect surfaces as a differing value rather than as a
 * crash. The hazard is recorded here rather than avoided, because avoiding it would
 * remove the only observation that can see this behaviour at all.
 *
 * Every observation is `key=value` on stdout, one line each, with unique keys. The
 * `err=` field is the packed `ERR_peek_error()` read immediately after the call and
 * cleared before the next, so it belongs to its own call.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * `OPENSSL_load_builtin_modules` and `CONF_modules_load_file` are installed; the
 * `CONF_*` flag word is not needed here because `OSSL_LIB_CTX_load_config` passes a
 * literal zero.
 */
extern void OPENSSL_load_builtin_modules(void);
extern int CONF_modules_load_file(const char *filename, const char *appname,
                                  unsigned long flags);

/* ---------------------------------------------------------------- reporting */

#define SAYN(key, expr)                                                       \
    do {                                                                      \
        printf("%s=%d err=%lu\n", (key), (int) (expr), ERR_peek_error());      \
        ERR_clear_error();                                                    \
    } while (0)

static void sayp(const char *key, const void *p)
{
    printf("%s=%s err=%lu\n", key, p == NULL ? "NULL" : "nonnull",
           ERR_peek_error());
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

/*
 * The index numbers, from `include/internal/cryptlib.h` of the admitted authority
 * (`OSSL_LIB_CTX_*_INDEX`). They are not in any installed header, so a consumer that
 * passes one is passing a bare integer -- which is exactly what this probe does.
 *
 *  0 EVP_METHOD_STORE   1 PROVIDER_STORE     2 PROPERTY_DEFN    3 PROPERTY_STRING
 *  4 NAMEMAP            5 DRBG               6 DRBG_NONCE       7 (was CRNG test data)
 *  8 (was THREAD_EVENT) 9 FIPS_PROV         10 ENCODER_STORE   11 DECODER_STORE
 * 12 SELF_TEST_CB      13 BIO_PROV          14 GLOBAL_PROPERTIES
 * 15 STORE_LOADER      16 PROVIDER_CONF     17 BIO_CORE        18 CHILD_PROVIDER
 * 19 THREAD            20 DECODER_CACHE     21 COMP_METHODS    22 INDICATOR_CB
 *
 * `OSSL_LIB_CTX_MAX_INDEXES` is 22 and the function does not consult it; 22 is a live
 * index and 23 is the first one the `default:` arm answers.
 */
#define IDX_COMP_METHODS 21
#define IDX_NAMEMAP 4
#define IDX_SELF_TEST_CB 12
#define IDX_THREAD 19
#define IDX_INDICATOR_CB 22
#define IDX_BIO_CORE 17
#define IDX_PROPERTY_DEFNS 2
#define IDX_PROPERTY_STRING 3
#define IDX_GLOBAL_PROPERTIES 14
#define IDX_PROVIDER_STORE 1

/* The eighteen indices the authority answers a pointer for. */
#define LIVE_SLOTS 18

/* The slots this stratum fills. 21 answers `&ctx->comp_methods`, so it is exact as
 * soon as the field exists; 4 is the namemap (6.6b), 19 the thread slot (6.6e),
 * 17 the core BIO globals (6.6c, filled eagerly by `context_init`), 12 and 22
 * the two callback holders (6.11), and 2, 3 and 14 the property engine (6.7a).
 * 1 is the provider store, filled by `context_init` in 6.8b-slot -- and it is the
 * first slot object the authority builds, not the last, which is what made filling
 * it worth reading `context_init` rather than appending an arm.
 * Each later subphase appends its slot here when it lands. */
static const int filled_slots[] = { IDX_PROVIDER_STORE, IDX_COMP_METHODS, IDX_NAMEMAP,
                                    IDX_THREAD, IDX_BIO_CORE, IDX_SELF_TEST_CB,
                                    IDX_INDICATOR_CB, IDX_PROPERTY_DEFNS,
                                    IDX_PROPERTY_STRING, IDX_GLOBAL_PROPERTIES };
#define FILLED_COUNT ((int) (sizeof filled_slots / sizeof filled_slots[0]))

/* The indices the authority answers NULL for, and why: 7 and 8 are slots it reuses
 * or leaves unassigned, 9 is FIPS-only in a profile that is not a FIPS build, 13 was
 * `BIO_PROV` and has no arm, and everything from 23 up is past the end of the switch.
 * -1 is the negative case, which the `default:` arm answers too. */
static const int dead_slots[] = { -1, 7, 8, 9, 13, 23, 24, 31, 255 };
#define DEAD_COUNT ((int) (sizeof dead_slots / sizeof dead_slots[0]))

/* One line per filled slot, for whichever context the caller resolves. */
static void filled_table(const char *prefix, OSSL_LIB_CTX *ctx)
{
    char key[64];
    int i;

    for (i = 0; i < FILLED_COUNT; i++) {
        snprintf(key, sizeof key, "%s.%d", prefix, filled_slots[i]);
        sayp(key, OSSL_LIB_CTX_get_data(ctx, filled_slots[i]));
    }
}

/* One line per dead slot. `idx.<n>` is printed for the NULL context, which resolves
 * through the thread default, and for a fresh non-default context, because a
 * candidate could plausibly get one right and the other wrong. */
static void dead_table(const char *prefix, OSSL_LIB_CTX *ctx)
{
    char key[64];
    int i;

    for (i = 0; i < DEAD_COUNT; i++) {
        snprintf(key, sizeof key, "%s.%d", prefix, dead_slots[i]);
        sayp(key, OSSL_LIB_CTX_get_data(ctx, dead_slots[i]));
    }
}

int main(void)
{
    OSSL_LIB_CTX *gd, *a, *b, *prev;
    void *cm_gd, *cm_a, *cm_b;

    setvbuf(stdout, NULL, _IOLBF, 0);

    sayn("libctx.slots.live", LIVE_SLOTS);
    sayn("libctx.slots.filled", FILLED_COUNT);
    sayn("libctx.slots.deferred", LIVE_SLOTS - FILLED_COUNT);

    /* ------------------------------------------------------- the global default */

    gd = OSSL_LIB_CTX_get0_global_default();
    sayp("gd.nonnull", gd);
    sayn("gd.stable", gd == OSSL_LIB_CTX_get0_global_default());

    /* A NULL context is the default for this thread, and no thread-local default has
     * been set, so the NULL-context answers are the global default's answers. */
    cm_gd = OSSL_LIB_CTX_get_data(gd, IDX_COMP_METHODS);
    sayn("gd.comp_methods.stable",
         OSSL_LIB_CTX_get_data(gd, IDX_COMP_METHODS) == cm_gd);
    sayn("null.comp_methods.eq.gd",
         OSSL_LIB_CTX_get_data(NULL, IDX_COMP_METHODS) == cm_gd);
    /* `COMP_METHODS` answers `&ctx->comp_methods`, the address of a field inside the
     * object, so it is never equal to the object's own address. */
    sayn("null.comp_methods.ne.gd",
         OSSL_LIB_CTX_get_data(NULL, IDX_COMP_METHODS) != (void *) gd);

    filled_table("gslot", gd);
    dead_table("gdead", gd);
    dead_table("ndead", NULL);

    /* ------------------------------------------------------------ a fresh context */

    a = OSSL_LIB_CTX_new();
    b = OSSL_LIB_CTX_new();
    sayp("new.a", a);
    sayp("new.b", b);
    sayn("new.distinct", a != b);

    filled_table("aslot", a);
    dead_table("adead", a);

    cm_a = OSSL_LIB_CTX_get_data(a, IDX_COMP_METHODS);
    cm_b = OSSL_LIB_CTX_get_data(b, IDX_COMP_METHODS);
    sayn("new.comp_methods.stable", cm_a == OSSL_LIB_CTX_get_data(a, IDX_COMP_METHODS));
    /* Each context's field has its own address, so two contexts differ ... */
    sayn("new.comp_methods.distinct", cm_a != cm_b);
    /* ... and a non-default context differs from the default one. */
    sayn("new.comp_methods.ne.gd", cm_a != cm_gd);

    /* --------------------------------------------------- conf_diagnostics is state */

    sayn("cd.new.zero", OSSL_LIB_CTX_get_conf_diagnostics(a));
    OSSL_LIB_CTX_set_conf_diagnostics(a, 7);
    sayn("cd.set7.get", OSSL_LIB_CTX_get_conf_diagnostics(a));
    sayn("cd.other.unaffected", OSSL_LIB_CTX_get_conf_diagnostics(b));
    sayn("cd.null.reads.default", OSSL_LIB_CTX_get_conf_diagnostics(NULL));
    OSSL_LIB_CTX_set_conf_diagnostics(NULL, 9);
    sayn("cd.null.set.null.get", OSSL_LIB_CTX_get_conf_diagnostics(NULL));
    /* Setting it through NULL touched the default, not `a`. */
    sayn("cd.a.unaffected", OSSL_LIB_CTX_get_conf_diagnostics(a));
    OSSL_LIB_CTX_set_conf_diagnostics(NULL, 0);
    sayn("cd.null.reset", OSSL_LIB_CTX_get_conf_diagnostics(NULL));
    /* Any `int` is stored, including a negative one. */
    OSSL_LIB_CTX_set_conf_diagnostics(a, -3);
    sayn("cd.negative", OSSL_LIB_CTX_get_conf_diagnostics(a));
    OSSL_LIB_CTX_set_conf_diagnostics(a, 0);

    /* ------------------------------------------------------ set0_default semantics */

    /* With no thread-local default set, a query returns the global default and, since
     * the argument is NULL, leaves it alone. */
    sayn("sd.query.returns.gd", OSSL_LIB_CTX_set0_default(NULL) == gd);
    sayn("sd.query.leaves.default",
         OSSL_LIB_CTX_get_data(NULL, IDX_COMP_METHODS) == cm_gd);

    prev = OSSL_LIB_CTX_set0_default(a);
    sayn("sd.set.returns.previous", prev == gd);
    /* The NULL context now resolves to `a`, so both the data table and the diagnostics
     * follow the thread's slot rather than the global object. */
    sayn("sd.set.null.resolves.a",
         OSSL_LIB_CTX_get_data(NULL, IDX_COMP_METHODS) == cm_a);
    sayn("sd.set.null.data.ne.gd",
         OSSL_LIB_CTX_get_data(NULL, IDX_COMP_METHODS) != cm_gd);
    OSSL_LIB_CTX_set_conf_diagnostics(a, 5);
    sayn("sd.set.null.cd.reads.a", OSSL_LIB_CTX_get_conf_diagnostics(NULL));
    sayn("sd.query.now.returns.a", OSSL_LIB_CTX_set0_default(NULL) == a);

    /* Passing the *global* default as the new default clears the thread's slot instead
     * of storing the global object in it -- `set_default_context` rewrites it to NULL.
     * The observable consequence is that a query answers the global default again. */
    prev = OSSL_LIB_CTX_set0_default(gd);
    sayn("sd.clear.returns.previous", prev == a);
    sayn("sd.clear.null.resolves.gd",
         OSSL_LIB_CTX_get_data(NULL, IDX_COMP_METHODS) == cm_gd);
    sayn("sd.clear.query.returns.gd", OSSL_LIB_CTX_set0_default(NULL) == gd);

    /* ---------------------------------------------------------------- free is not */

    /* NULL is a no-op ... */
    OSSL_LIB_CTX_free(NULL);
    sayn("free.null.noop",
         OSSL_LIB_CTX_get_data(NULL, IDX_COMP_METHODS) == cm_gd);

    /* ... and so is the global default, which `get0_global_default` must keep handing
     * back afterwards, still usable. */
    OSSL_LIB_CTX_free(gd);
    sayp("free.gd.alive.comp_methods", OSSL_LIB_CTX_get_data(gd, IDX_COMP_METHODS));
    sayn("free.gd.same.object", OSSL_LIB_CTX_get0_global_default() == gd);
    sayn("free.gd.cd", OSSL_LIB_CTX_get_conf_diagnostics(gd));

    /* A context that is not the default really is released; the observable statement is
     * that the library is still consistent afterwards. */
    OSSL_LIB_CTX_free(a);
    sayn("free.a.gd.ok",
         OSSL_LIB_CTX_get_data(NULL, IDX_COMP_METHODS) == cm_gd);

    /* The thread-local default is a no-op too. `b` is read afterwards, which is
     * well-defined only because the authority kept it alive -- see the header. */
    sayn("free.threaddefault.installed", OSSL_LIB_CTX_set0_default(b) == gd);
    OSSL_LIB_CTX_free(b);
    sayn("free.threaddefault.cd", OSSL_LIB_CTX_get_conf_diagnostics(b));
    sayn("free.threaddefault.data.nonnull",
         OSSL_LIB_CTX_get_data(b, IDX_COMP_METHODS) != NULL);
    sayn("free.threaddefault.still.default", OSSL_LIB_CTX_set0_default(NULL) == b);
    sayn("free.threaddefault.restore", OSSL_LIB_CTX_set0_default(gd) == b);

    /* ------------------------------------------------- OSSL_LIB_CTX_load_config */

    /*
     * The tenth export of this stratum, and the one that waited for the CONF module
     * registry to exist (6.10). Its body is one line and its *contract* is three
     * details, each observed below:
     *
     *   * it passes an explicit **zero** flag word, not `DEFAULT_CONF_MFLAGS`, so a
     *     missing file and a failing module are both errors here where the automatic
     *     loader tolerates them;
     *   * it answers `> 0`, and the inner call can answer **-1**, so the result is a
     *     boolean rather than a pass-through -- which one observation below pins by
     *     comparing the same file through both entry points;
     *   * `config_diagnostics` in the file is set on **the context it was loaded into**,
     *     which is why this section can use a fresh context and leave the default alone.
     *
     * A configuration file has to be written by the probe, because the alternative -- the
     * installation directory -- differs between the two sides by construction.
     */
    {
        static const char *DIR = "/tmp/rt-libctx";
        char p_ok[128], p_plain[128], p_missing[128], p_badsec[128], p_diag[128], p_unknown[128];
        static const char *OK =
            "openssl_conf = lc_init\n"
            "\n"
            "[lc_init]\n"
            "oid_section = lc_oids\n"
            "\n"
            "[lc_oids]\n"
            "rt-libctx-oid = 1.2.3.4.5.6.7.8.123\n";
        /*
         * A second good file, and it exists because the first one is **only loadable
         * once**: `oid_section`'s initialiser calls `OBJ_create`, which refuses a short
         * name that already exists, so a second load of `ok.cnf` fails with
         * `OBJ_R_OID_EXISTS` rather than succeeding. That is a real behaviour and is
         * observed below -- but it cannot be the file the *repeatability* observations
         * use. This one names `ssl_conf` instead, whose reader frees its store before it
         * rebuilds it and is therefore idempotent.
         */
        static const char *PLAIN =
            "openssl_conf = lc_init\n"
            "\n"
            "[lc_init]\n"
            "ssl_conf = lc_ssl\n"
            "\n"
            "[lc_ssl]\n"
            "system_default = lc_sds\n"
            "\n"
            "[lc_sds]\n"
            "MinProtocol = TLSv1.2\n";
        static const char *BADSEC = "openssl_conf = no_such_section\n";
        static const char *DIAG =
            "config_diagnostics = 1\n"
            "openssl_conf = lc_init\n"
            "\n"
            "[lc_init]\n"
            "ssl_conf = lc_ssl\n"
            "\n"
            "[lc_ssl]\n"
            "system_default = lc_sds\n"
            "\n"
            "[lc_sds]\n"
            "MinProtocol = TLSv1.2\n";
        static const char *UNKNOWN =
            "openssl_conf = lc_init\n"
            "\n"
            "[lc_init]\n"
            "nosuchmodule = x\n";
        FILE *f;
        int r;
        OSSL_LIB_CTX *lc;

        mkdir(DIR, 0755);
        snprintf(p_ok, sizeof p_ok, "%s/ok.cnf", DIR);
        snprintf(p_plain, sizeof p_plain, "%s/plain.cnf", DIR);
        snprintf(p_missing, sizeof p_missing, "%s/not-here.cnf", DIR);
        snprintf(p_badsec, sizeof p_badsec, "%s/badsec.cnf", DIR);
        snprintf(p_diag, sizeof p_diag, "%s/diag.cnf", DIR);
        snprintf(p_unknown, sizeof p_unknown, "%s/unknown.cnf", DIR);
#define WRITE(p, t)                                                            \
    do {                                                                       \
        f = fopen((p), "wb");                                                  \
        if (f != NULL) {                                                       \
            fputs((t), f);                                                     \
            fclose(f);                                                         \
        }                                                                      \
    } while (0)
        WRITE(p_ok, OK);
        WRITE(p_plain, PLAIN);
        WRITE(p_badsec, BADSEC);
        WRITE(p_diag, DIAG);
        WRITE(p_unknown, UNKNOWN);
        unlink(p_missing);
#undef WRITE

        /* The built-ins must be registered before any of this can resolve a module
         * name, and `module_run`'s own run-once is what does it -- called explicitly so
         * that the observation is about the loader rather than about that once. */
        OPENSSL_load_builtin_modules();
        ERR_clear_error();

        lc = OSSL_LIB_CTX_new();
        sayp("ldcfg.newctx", lc);

        /* A fresh context's diagnostics flag is zero, which is what the `diag.cnf`
         * observation below needs as its starting point. */
        sayn("ldcfg.diag.before", OSSL_LIB_CTX_get_conf_diagnostics(lc));

        r = OSSL_LIB_CTX_load_config(lc, p_ok);
        printf("ldcfg.ok=%d err=%lu\n", r, ERR_peek_last_error());
        ERR_clear_error();
        /* The module ran: the OID its section named exists. */
        sayn("ldcfg.ok.oid.known", OBJ_txt2nid("rt-libctx-oid") != NID_undef);

        /* The *same* file a second time, into the global default: the OID module's
         * initialiser refuses a short name it already has, so the load fails and the
         * `> 0` collapses the inner -1. This is the pair that shows the wrapper is not a
         * pass-through, and it is also why every repeatable observation below uses
         * `plain.cnf` instead. */
        r = OSSL_LIB_CTX_load_config(NULL, p_ok);
        printf("ldcfg.duplicate.oid=%d err=%lu\n", r, ERR_peek_last_error());
        printf("ldcfg.duplicate.oid.reason=%d\n",
               ERR_GET_REASON(ERR_peek_last_error()));
        ERR_clear_error();

        /* `ssl_conf`'s reader frees its store before rebuilding it, so the same file
         * loads cleanly twice -- and it does so into the global default, which shows the
         * load is not tied to the context that made the call. */
        r = OSSL_LIB_CTX_load_config(NULL, p_plain);
        printf("ldcfg.plain=%d err=%lu\n", r, ERR_peek_last_error());
        ERR_clear_error();
        r = OSSL_LIB_CTX_load_config(NULL, p_plain);
        printf("ldcfg.plain.again=%d err=%lu\n", r, ERR_peek_last_error());
        ERR_clear_error();

        /* A missing file is an error here, where the automatic loader's flag word
         * tolerates it. */
        r = OSSL_LIB_CTX_load_config(lc, p_missing);
        printf("ldcfg.missing=%d err=%lu\n", r, ERR_peek_last_error());
        printf("ldcfg.missing.reason=%d\n",
               ERR_GET_REASON(ERR_peek_last_error()));
        ERR_clear_error();

        /* A section the file names but does not define. */
        r = OSSL_LIB_CTX_load_config(lc, p_badsec);
        printf("ldcfg.badsec=%d err=%lu\n", r, ERR_peek_last_error());
        ERR_clear_error();

        /* The same file through the two entry points, which is what pins the `> 0`:
         * the raw call answers -1 and the wrapper answers 0. */
        r = CONF_modules_load_file(p_unknown, NULL, 0);
        printf("ldcfg.raw.unknown=%d\n", r);
        ERR_clear_error();
        r = OSSL_LIB_CTX_load_config(lc, p_unknown);
        printf("ldcfg.wrapped.unknown=%d\n", r);
        ERR_clear_error();

        /* A file that turns diagnostics on sets it on **this** context and not on the
         * process default. */
        sayn("ldcfg.diag.default.before", OSSL_LIB_CTX_get_conf_diagnostics(NULL));
        r = OSSL_LIB_CTX_load_config(lc, p_diag);
        printf("ldcfg.diag.ok=%d err=%lu\n", r, ERR_peek_last_error());
        ERR_clear_error();
        sayn("ldcfg.diag.thisctx.after", OSSL_LIB_CTX_get_conf_diagnostics(lc));
        sayn("ldcfg.diag.default.after", OSSL_LIB_CTX_get_conf_diagnostics(NULL));

        /* A NULL context resolves through the thread's default, so this load lands on
         * the global default object -- and diagnostics on `lc` is what makes the two
         * distinguishable, since the default's flag stays zero. */
        sayn("ldcfg.default.after.diag.file",
             OSSL_LIB_CTX_get_conf_diagnostics(NULL));

        /* A NULL `config_file` asks for the default file, which is `$OPENSSL_CONF`
         * when it is set -- the probe sets it so that both sides read the same bytes
         * rather than their own installation directory. */
        setenv("OPENSSL_CONF", p_plain, 1);
        r = OSSL_LIB_CTX_load_config(lc, NULL);
        printf("ldcfg.null.file=%d err=%lu\n", r, ERR_peek_last_error());
        ERR_clear_error();

        /* And a NULL file name with the environment variable cleared is **not**
         * observed. `CONF_get1_default_config_file` falls back to
         * `X509_get_default_cert_area()` when `OPENSSL_CONF` is unset, which answers the
         * authority's own `OPENSSLDIR` string and this crate's empty string -- a recorded
         * divergence, because claiming a path inside the authority's build tree would be
         * a false statement about this build. Observing it here would fail the court for a
         * reason the court is not about, exactly as the `OPENSSL_load_builtin_modules`
         * fan-out would in `RT-CONF-MOD`. What the pair above establishes is the half
         * that is in scope: with a default file that *exists*, both sides read it and
         * answer 1. */

        OSSL_LIB_CTX_free(lc);
    }

    /* --------------------------------------------------------------- nothing raised */

    sayn("err.empty", ERR_peek_error() == 0);
    says("done", "rt-libctx");
    return 0;
}
