/*
 * RT-CONF-MOD -- the CONF module registry and the automatic configuration loader,
 * differentially.
 *
 * What this court has to establish
 * --------------------------------
 * `crypto/conf/conf_mod.c` is a registry of *named initialisers* and
 * `crypto/conf/conf_sap.c` is what the library calls itself the first time it is
 * asked to configure. Neither is an I/O surface, and almost nothing about them is a
 * return value: the observable is **which callback ran, with which strings, and in
 * which order**, plus the error record the call left behind. So the probe *is* the
 * module: it registers its own initialisers with `CONF_module_add` and reports what
 * the library handed them.
 *
 * Eight behaviours are the ones a plausible transcription gets wrong, and each has
 * an observation below:
 *
 *   * **`module_add` pushes, and never deduplicates.** Registering the same name
 *     twice puts two entries in the list, and `module_find` returns the *first*
 *     match — so the second registration is unreachable for as long as the first is
 *     live. Observed by giving the two registrations separate counters.
 *
 *   * **`module_find` truncates the name at its *last* dot** and compares that many
 *     bytes, so `rt-cm-a.alpha` finds `rt-cm-a`. The truncation is `strrchr`-based,
 *     which has an edge: a name whose last dot is its *first* character truncates to
 *     zero bytes, and `strncmp(x, y, 0)` is 0 for every `y` — so such a name matches
 *     the **first registered module in the whole registry**, whatever it is called.
 *     Observed both ways.
 *
 *   * **`module_init` answers -1 on failure, not the initialiser's own code.** That
 *     value is what `module_run` returns, what `CONF_modules_load` returns, and what
 *     goes into the `retcode=%-8d` field of the error record's data. A transcription
 *     that propagated the initialiser's `0` would differ in all three. The
 *     `%-8d` is *left*-justified padding, which `format!` cannot express, so the
 *     data string is observed byte for byte.
 *
 *   * **the finish callback runs before the link count drops, and only when the
 *     initialiser ran.** Observed with a module that counts both.
 *
 *   * **`CONF_modules_load` returns 1 when there is no section to load.** A
 *     `CONF` with no `openssl_conf` key is not an error, and neither is a NULL
 *     `CONF`.
 *
 *   * **the error record's file/line/function come from the authority's own
 *     source.** Every raise in these two files is at a generated site, so a
 *     decomposition of one error is a direct read of that generator: the file
 *     string, the line, the function name and the data. Observed for four
 *     different reasons.
 *
 *   * **`config_diagnostics` is a per-*context* setting that a configuration file
 *     can turn on, and turning it on clears four ignore flags.** It is sticky, so
 *     it is observed last, and it changes the answer of a call the probe already
 *     made — which is the point.
 *
 *   * **`ossl_config_int` loads a configuration at most once per process.** The
 *     flag it sets is set unconditionally, even when the load failed, and the
 *     re-entrancy thread-local the loader sets is **never cleared**. The three
 *     consequences that are distinguishable are each their own child process
 *     below, because a process can only observe its first configuration load
 *     once.
 *
 * The re-execution trick
 * ----------------------
 * Six of the behaviours above need a **fresh process**: the configuration once, the
 * `openssl_configured` flag and the never-cleared thread-local are all process-wide
 * and permanent, so a single process can only see its own first call. The probe
 * therefore re-executes itself with a mode argument and reports the child's exit
 * code, so that each scenario is a real first call. `/proc/self/exe` is used rather
 * than `argv[0]`, which is not a path. The children's own output is interleaved in
 * order because the parent waits.
 *
 * Divergences this court deliberately does not observe
 * ---------------------------------------------------
 * * **The fan-out of `OPENSSL_load_builtin_modules`.** Six of its seven registrations
 *   belong to later strata, so a configuration naming `ssl_conf`, `alg_section`,
 *   `provider_section`, `engine_id` or `random` resolves on the authority and not
 *   here. That is a recorded divergence (D121) and an observation of it would fail
 *   the court for a reason the court is not about. Only `oid_section`, which both
 *   sides register, is named in a configuration below.
 * * **`CONF_imodule_get_flags` before the module's own initialiser runs.** The
 *   authority allocates `CONF_IMODULE` with `OPENSSL_malloc` and never initialises
 *   `flags`, so a read there is a read of indeterminate memory; the crate patches
 *   the field to 0. Reading it would make the court depend on the allocator's
 *   leftovers, so the probe reads it only *after* it has set it. The divergence is
 *   recorded in `docs/SECURITY_DIVERGENCE_POLICY.md`.
 * * **`module_load_dso` against a module name that is not a path.** The last
 *   observation in the DSO section does call it, and reports only the return value
 *   and the packed error word, because the *data* on that path is `dlerror`'s text.
 *
 * Every observation is `key=value` on stdout, one line each, with unique keys. Where
 * a call can leave an error on the queue, the key's value carries
 * `ERR_peek_last_error()` read immediately afterwards, and the queue is cleared
 * before the next call, so the field belongs to its own call.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/* `OPENSSL_config` is deprecated and is exactly what mode 5 has to call. */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* ------------------------------------------------------------------ reporting */

static void sayn(const char *key, long long v)
{
    printf("%s=%lld err=%lu\n", key, v, ERR_peek_last_error());
    ERR_clear_error();
}

static void says(const char *key, const char *s)
{
    printf("%s=%s err=%lu\n", key, s == NULL ? "(null)" : s,
           ERR_peek_last_error());
    ERR_clear_error();
}

/* The four coordinates of the *last* error, without popping it. */
static void saye(const char *key)
{
    const char *file = NULL, *func = NULL, *data = NULL;
    int line = 0, flags = 0;
    unsigned long e = ERR_peek_last_error_all(&file, &line, &func, &data, &flags);

    printf("%s_lib=%d\n", key, ERR_GET_LIB(e));
    printf("%s_reason=%d\n", key, ERR_GET_REASON(e));
    printf("%s_line=%d\n", key, line);
    printf("%s_file=%s\n", key, file == NULL ? "(null)" : file);
    printf("%s_func=%s\n", key, func == NULL ? "(null)" : func);
    printf("%s_data=%s\n", key, data == NULL ? "(null)" : data);
    printf("%s_flags=%d\n", key, flags);
    printf("%s_reasonstr=%s\n", key,
           ERR_reason_error_string(e) == NULL ? "(null)"
                                              : ERR_reason_error_string(e));
    ERR_clear_error();
}

/*
 * A call's return value **and** the error it left behind, in one observation.
 *
 * The two are one function and not two calls on purpose. `ERR_clear_error` is what a
 * following `saye` would need to happen first, so a probe written as
 * `sayn(key, call()); saye(key);` reads an empty queue and prints zeros -- which is exactly
 * what the first version of this probe did, and why "the error coordinates are all zero"
 * looked like agreement rather than like a probe that had already cleared the evidence.
 * Reading the queue *before* clearing it is the whole of the fix.
 */
static void sayne(const char *key, long long v)
{
    printf("%s=%lld\n", key, v);
    saye(key);
}

/*
 * The three `conf_ssl.c` accessors are **internal**: they are declared in
 * `include/internal/sslconf.h`, which is not installed, so a probe compiled against
 * installed headers has to declare them the way that header does. `SSL_CONF_CMD` is
 * opaque here on purpose -- every observation below goes through `conf_ssl_get_cmd`,
 * which is what libssl uses too, so the struct's layout is never needed.
 */
typedef struct ssl_conf_cmd_st SSL_CONF_CMD;
extern const SSL_CONF_CMD *conf_ssl_get(size_t idx, const char **name, size_t *cnt);
extern void conf_ssl_get_cmd(const SSL_CONF_CMD *cmd, size_t idx, char **cmdstr,
                             char **arg);
extern int conf_ssl_name_find(const char *name, size_t *idx);

/* ------------------------------------------------------------------- fixtures */

/*
 * `OPENSSL_INIT_BASE_ONLY` is **internal**: the authority defines it in
 * `include/internal/crypto.h` rather than in `crypto.h`, so a probe compiled against
 * installed headers cannot name it. The value is the authority's, and it is spelled
 * out here the way `src/runtime/init.rs` does rather than guessed.
 */
#define OPENSSL_INIT_BASE_ONLY_INTERNAL 0x00040000

static const char *DIR = "/tmp/rt-conf-mod";

static char path_main[256], path_noinit[256], path_badsec[256], path_unknown[256],
    path_diag[256], path_empty[256], path_oids[256], path_missing[256],
    path_sslconf[256], path_sslconf_nosect[256], path_sslconf_nocmds[256];

static int write_file(const char *path, const char *text)
{
    FILE *f = fopen(path, "wb");
    if (f == NULL)
        return 0;
    fputs(text, f);
    fclose(f);
    return 1;
}

/*
 * The four configuration files. Every one is written by the probe, so no side's
 * installation directory is involved and the bytes are identical on both sides.
 *
 * `main.cnf` deliberately carries an `oid_section` entry: it is the only built-in
 * module both sides register, and the OID it creates is what proves the initialiser
 * actually ran rather than merely being found.
 */
static const char *TEXT_MAIN =
    "openssl_conf = init_sect\n"
    "myapp = appname_sect\n"
    "\n"
    "[init_sect]\n"
    "rt-cm-a = from-init-sect\n"
    "\n"
    "[appname_sect]\n"
    "rt-cm-a3 = from-appname-sect\n";

/*
 * The OID module gets a file of its own, and is loaded exactly once.
 *
 * `oid_module_init` creates every OID the section names, and `OBJ_create` refuses a
 * short name that already exists -- raising `OBJ_R_OID_EXISTS` and returning 0, which
 * the initialiser turns into a failed module. So a file carrying an `oid_section` is
 * only loadable **once per process**, and putting one in the file the later sections
 * load repeatedly would fail from the second load on for a reason this court is not
 * about. Hence the separate file and the single load.
 */
static const char *TEXT_OIDS =
    "openssl_conf = oid_sect\n"
    "\n"
    "[oid_sect]\n"
    "oid_section = oid_defs\n"
    "\n"
    "[oid_defs]\n"
    "rt-cm-oid = 1.2.3.4.5.6.7.8.99\n";

static const char *TEXT_NOINIT =
    "# a configuration file with no openssl_conf key at all\n"
    "unrelated = 1\n";

static const char *TEXT_BADSEC =
    "openssl_conf = no_such_section\n";

static const char *TEXT_UNKNOWN =
    "openssl_conf = unk_sect\n"
    "\n"
    "[unk_sect]\n"
    "nosuchmodule = x\n";

/*
 * `config_diagnostics = 1` is a *top-level* key, which is where
 * `NCONF_get_number_e(cnf, NULL, "config_diagnostics", ...)` looks for it.
 */
static const char *TEXT_DIAG =
    "config_diagnostics = 1\n"
    "openssl_conf = diag_sect\n"
    "\n"
    "[diag_sect]\n"
    "nosuchmodule = x\n";

/*
 * The `ssl_conf` module's two sections, and the three shapes its reader distinguishes.
 *
 * `ssl_conf` is the second of the seven `OPENSSL_load_builtin_modules` registrations this
 * crate can make (6.10e), and it is the one whose *store* is observable: the accessors in
 * `conf_ssl.c` answer what the module's reader put there. So this file is the only way to
 * see the reader at all through the installed headers.
 */
static const char *TEXT_SSLCONF =
    "openssl_conf = ssl_init_sect\n"
    "\n"
    "[ssl_init_sect]\n"
    "ssl_conf = ssl_sect\n"
    "\n"
    "[ssl_sect]\n"
    "system_default = sds\n"
    "\n"
    "[sds]\n"
    ".CipherString = DEFAULT:@SECLEVEL=2\n"
    "MinProtocol = TLSv1.2\n";

/* `ssl_conf` naming a section the file does not define: `CONF_R_SSL_SECTION_NOT_FOUND`. */
static const char *TEXT_SSLCONF_NOSECT =
    "openssl_conf = ssl_init_sect\n"
    "\n"
    "[ssl_init_sect]\n"
    "ssl_conf = no_such_section\n";

/* A command set whose own section is absent: `CONF_R_SSL_COMMAND_SECTION_NOT_FOUND`. */
static const char *TEXT_SSLCONF_NOCMDS =
    "openssl_conf = ssl_init_sect\n"
    "\n"
    "[ssl_init_sect]\n"
    "ssl_conf = ssl_sect\n"
    "\n"
    "[ssl_sect]\n"
    "system_default = no_such_command_section\n";

static void fixtures(void)
{
    mkdir(DIR, 0755);
    snprintf(path_main, sizeof path_main, "%s/main.cnf", DIR);
    snprintf(path_noinit, sizeof path_noinit, "%s/noinit.cnf", DIR);
    snprintf(path_badsec, sizeof path_badsec, "%s/badsec.cnf", DIR);
    snprintf(path_unknown, sizeof path_unknown, "%s/unknown.cnf", DIR);
    snprintf(path_diag, sizeof path_diag, "%s/diag.cnf", DIR);
    snprintf(path_empty, sizeof path_empty, "%s/empty.cnf", DIR);
    snprintf(path_oids, sizeof path_oids, "%s/oids.cnf", DIR);
    snprintf(path_missing, sizeof path_missing, "%s/not-here.cnf", DIR);
    snprintf(path_sslconf, sizeof path_sslconf, "%s/sslconf.cnf", DIR);
    snprintf(path_sslconf_nosect, sizeof path_sslconf_nosect, "%s/sslconf-nosect.cnf", DIR);
    snprintf(path_sslconf_nocmds, sizeof path_sslconf_nocmds, "%s/sslconf-nocmds.cnf", DIR);

    /* A path that has never existed, so the "missing file" observations cannot be
     * satisfied by a leftover from an earlier run. Its own directory is removed
     * first, which also clears any fixture a previous run wrote. */
    (void)write_file(path_main, TEXT_MAIN);
    write_file(path_noinit, TEXT_NOINIT);
    write_file(path_badsec, TEXT_BADSEC);
    write_file(path_unknown, TEXT_UNKNOWN);
    write_file(path_diag, TEXT_DIAG);
    write_file(path_empty, "");
    write_file(path_oids, TEXT_OIDS);
    write_file(path_sslconf, TEXT_SSLCONF);
    write_file(path_sslconf_nosect, TEXT_SSLCONF_NOSECT);
    write_file(path_sslconf_nocmds, TEXT_SSLCONF_NOCMDS);
    unlink(path_missing);

    /* `CONF_get1_default_config_file` answers `$OPENSSL_CONF` when it is set, which
     * is what makes the `filename == NULL` path deterministic on both sides rather
     * than a read of the installation directory. */
    setenv("OPENSSL_CONF", path_main, 1);
}

/* -------------------------------------------------------- the conf module types */

/*
 * Six records, so a module that must be distinguished from another has its own
 * counters rather than a shared one.
 */
#define N_MODS 5

enum {
    M_A = 0,
    M_A2,
    M_B,
    M_A3,
    M_FAIL
};

struct modrec {
    int inits;
    int finishes;
    int ret;
    int pmod_seen;
    int pmod_usr_roundtrip;
    int usr_roundtrip;
    int flags_roundtrip;
    char name[96];
    char value[96];
};

static struct modrec MR[N_MODS];

static int rec_init(CONF_IMODULE *md, int idx)
{
    struct modrec *r = &MR[idx];
    CONF_MODULE *pmod;
    const char *nm = CONF_imodule_get_name(md);
    const char *vl = CONF_imodule_get_value(md);
    void *want = (void *)(long)(0x1000 + idx);

    r->inits++;
    snprintf(r->name, sizeof r->name, "%s", nm == NULL ? "(null)" : nm);
    snprintf(r->value, sizeof r->value, "%s", vl == NULL ? "(null)" : vl);

    /* Set, then read back: the read is of what this callback wrote, so it is
     * defined on both sides even though the authority's field starts
     * indeterminate. See the header note. */
    CONF_imodule_set_flags(md, 0x1234u + (unsigned)idx);
    r->flags_roundtrip =
        CONF_imodule_get_flags(md) == (unsigned long)(0x1234u + (unsigned)idx);

    CONF_imodule_set_usr_data(md, want);
    r->usr_roundtrip = CONF_imodule_get_usr_data(md) == want;

    pmod = CONF_imodule_get_module(md);
    r->pmod_seen = pmod != NULL;
    if (pmod != NULL) {
        CONF_module_set_usr_data(pmod, (void *)(long)(0x2000 + idx));
        r->pmod_usr_roundtrip =
            CONF_module_get_usr_data(pmod) == (void *)(long)(0x2000 + idx);
    }
    return r->ret;
}

static void rec_finish(int idx)
{
    MR[idx].finishes++;
}

static int init_a(CONF_IMODULE *md, const CONF *cnf)
{
    (void)cnf;
    return rec_init(md, M_A);
}
static void fin_a(CONF_IMODULE *md)
{
    (void)md;
    rec_finish(M_A);
}
static int init_a2(CONF_IMODULE *md, const CONF *cnf)
{
    (void)cnf;
    return rec_init(md, M_A2);
}
static void fin_a2(CONF_IMODULE *md)
{
    (void)md;
    rec_finish(M_A2);
}
static int init_b(CONF_IMODULE *md, const CONF *cnf)
{
    (void)cnf;
    return rec_init(md, M_B);
}
static void fin_b(CONF_IMODULE *md)
{
    (void)md;
    rec_finish(M_B);
}
static int init_a3(CONF_IMODULE *md, const CONF *cnf)
{
    (void)cnf;
    return rec_init(md, M_A3);
}
static void fin_a3(CONF_IMODULE *md)
{
    (void)md;
    rec_finish(M_A3);
}
static int init_fail(CONF_IMODULE *md, const CONF *cnf)
{
    (void)cnf;
    return rec_init(md, M_FAIL);
}
static void fin_fail(CONF_IMODULE *md)
{
    (void)md;
    rec_finish(M_FAIL);
}
/* ------------------------------------------------------------------ helpers */

static void clear_records(void)
{
    int i;
    for (i = 0; i < N_MODS; i++) {
        memset(&MR[i], 0, sizeof MR[i]);
        MR[i].ret = 1;
    }
}

static CONF *load_conf(const char *file)
{
    CONF *c = NCONF_new(NULL);
    if (c == NULL)
        return NULL;
    if (NCONF_load(c, file, NULL) <= 0) {
        NCONF_free(c);
        return NULL;
    }
    return c;
}

/* One `CONF_modules_load` against a file, reporting the return value. */
static int load_via(const char *file, const char *appname, unsigned long flags,
                    const char *key)
{
    CONF *c = load_conf(file);
    int r;
    if (c == NULL) {
        printf("%s_conf=NULL err=%lu\n", key, ERR_peek_last_error());
        ERR_clear_error();
        return -2;
    }
    ERR_clear_error();
    r = CONF_modules_load(c, appname, flags);
    sayn(key, r);
    NCONF_free(c);
    return r;
}

/* Whether a module by that name is registered, observed by loading one that names
 * it. `NO_DSO` stops the "not found" path turning into a loader attempt. */

/* ------------------------------------------------------------------ sections */

static void section_a(void)
{
    printf("-- A: the registry and the implicit run-once\n");

    /* A NULL CONF is not an error and loads nothing. */
    sayn("A_null_conf_load", CONF_modules_load(NULL, NULL, 0));

    /* A file with no `openssl_conf` key is not an error either: `vsection` stays
     * NULL and the function answers 1 without running anything. */
    load_via(path_noinit, NULL, 0, "A_no_openssl_conf_load");

    /* The built-ins are registered by the **first `CONF_modules_load` in the
     * process**, through `module_run`'s own run-once -- nothing had to call
     * `OPENSSL_load_builtin_modules` first. That is what makes `oid_section`
     * resolvable here, and the OID its initialiser creates is what proves the
     * initialiser ran rather than merely being found. */
    load_via(path_oids, NULL, 0, "A_oids_load");
    sayn("A_oids_nid_known", OBJ_txt2nid("rt-cm-oid") != NID_undef);
    says("A_oids_shortname", OBJ_nid2sn(OBJ_txt2nid("rt-cm-oid")));
    ERR_clear_error();

    /* `OPENSSL_load_builtin_modules` is idempotent in **effect** but not in the
     * registry: `module_add` pushes unconditionally and never deduplicates, so a
     * second call appends another entry for every module it names -- including
     * `oid_section`. Those extra entries are unreachable, because `module_find`
     * returns the *first* match, so a load that follows behaves identically. That
     * is what is observable here, and it is all that is: the registry's length is
     * not reachable through any exported function, so this court does not claim to
     * have counted the duplicate. */
    OPENSSL_load_builtin_modules();
    OPENSSL_load_builtin_modules();
    ERR_clear_error();
}

/* The `oid_section` module is only loadable once per process -- see `TEXT_OIDS`.
 * This is where that single load's *result* is re-observed after the duplicate
 * built-in registrations, by asking whether the first registry entry is still the
 * one that answers: a `.x`-shaped name matches the first entry and no other. */
static void section_a2(void)
{
    printf("-- A2: the zero-length prefix match, and which entry is first\n");

    CONF *c = NCONF_new(NULL);
    static const char *TEXT =
        "openssl_conf = weird_sect\n"
        "\n"
        "[weird_sect]\n"
        ".weird = no_such_oid_section\n";
    char p[256];
    snprintf(p, sizeof p, "%s/weird.cnf", DIR);
    write_file(p, TEXT);
    if (NCONF_load(c, p, NULL) > 0) {
        /* `strrchr(".weird", '.')` is the string's own first byte, so `nchar` is
         * 0 and `strncmp(tmod->name, ".weird", 0)` is 0 for the **first entry in
         * the registry** -- which is the built-in `oid_section`, because it was
         * pushed before anything else was registered. So the OID module's
         * initialiser is called with `.weird`'s value, and its
         * `NCONF_get_section` fails. */
        sayne("A2_weird_load", CONF_modules_load(c, NULL, CONF_MFLAGS_NO_DSO));
    } else {
        says("A2_weird_conf", "(unloadable)");
        ERR_clear_error();
    }
    NCONF_free(c);
}

static void section_b(void)
{
    printf("-- B: CONF_module_add, the two registrations, and the name grammar\n");

    clear_records();
    sayn("B_add_first", CONF_module_add("rt-cm-a", init_a, fin_a));
    /* The same name again: accepted, pushed, and shadowed by the first. */
    sayn("B_add_duplicate", CONF_module_add("rt-cm-a", init_b, fin_b));
    sayn("B_add_a2", CONF_module_add("rt-cm-a2", init_a2, fin_a2));
    sayn("B_add_a3", CONF_module_add("rt-cm-a3", init_a3, fin_a3));
    sayn("B_add_fail", CONF_module_add("rt-cm-fail", init_fail, fin_fail));

    /* The duplicate is live but unreachable: the first wins. */
    clear_records();
    load_via(path_main, NULL, 0, "B_load_main");
    sayn("B_load_main_first_inits", MR[M_A].inits);
    sayn("B_load_main_duplicate_inits", MR[M_B].inits);
    says("B_load_main_name", MR[M_A].name);
    says("B_load_main_value", MR[M_A].value);
    sayn("B_load_main_flags_roundtrip", MR[M_A].flags_roundtrip);
    sayn("B_load_main_usr_roundtrip", MR[M_A].usr_roundtrip);
    sayn("B_load_main_pmod_seen", MR[M_A].pmod_seen);
    sayn("B_load_main_pmod_usr_roundtrip", MR[M_A].pmod_usr_roundtrip);

    /* A dotted name: the module is found by the part before the *last* dot, and
     * the `CONF_IMODULE` keeps the name the configuration used, not the module's.
     * That is what lets one module be initialised several times. */
    clear_records();
    {
        CONF *c = NCONF_new(NULL);
        static const char *TEXT =
            "openssl_conf = dot_sect\n"
            "\n"
            "[dot_sect]\n"
            "rt-cm-a.alpha = one\n"
            "rt-cm-a.beta = two\n"
            "rt-cm-a.gamma.delta = three\n";
        char p[256];
        snprintf(p, sizeof p, "%s/dot.cnf", DIR);
        write_file(p, TEXT);
        if (NCONF_load(c, p, NULL) > 0) {
            int r = CONF_modules_load(c, NULL, CONF_MFLAGS_NO_DSO);
            sayn("B_dotted_load", r);
            sayn("B_dotted_inits", MR[M_A].inits);
            says("B_dotted_last_name", MR[M_A].name);
            says("B_dotted_last_value", MR[M_A].value);
        } else {
            says("B_dotted_conf", "(unloadable)");
            ERR_clear_error();
        }
        NCONF_free(c);
    }

    /* A module whose initialiser fails. Three things are observable together:
     * the return value `CONF_modules_load` passes through, the finish callback
     * having run, and the `retcode=` field of the error record's data. */
    clear_records();
    MR[M_FAIL].ret = 0;
    {
        CONF *c = NCONF_new(NULL);
        static const char *TEXT =
            "openssl_conf = fail_sect\n"
            "\n"
            "[fail_sect]\n"
            "rt-cm-fail = fv\n";
        char p[256];
        snprintf(p, sizeof p, "%s/fail.cnf", DIR);
        write_file(p, TEXT);
        if (NCONF_load(c, p, NULL) > 0) {
            sayne("B_fail_load", CONF_modules_load(c, NULL, CONF_MFLAGS_NO_DSO));
            sayn("B_fail_inits", MR[M_FAIL].inits);
            sayn("B_fail_finishes", MR[M_FAIL].finishes);
            sayn("B_fail_finish_after_init", MR[M_FAIL].finishes == 1);
        } else {
            says("B_fail_conf", "(unloadable)");
            ERR_clear_error();
        }
        NCONF_free(c);
    }

    /* `IGNORE_ERRORS` keeps walking, so the entry after the failing one runs and
     * the call answers 1. */
    clear_records();
    MR[M_FAIL].ret = 0;
    {
        CONF *c = NCONF_new(NULL);
        static const char *TEXT =
            "openssl_conf = mixed_sect\n"
            "\n"
            "[mixed_sect]\n"
            "rt-cm-fail = fv\n"
            "rt-cm-a = av\n";
        char p[256];
        snprintf(p, sizeof p, "%s/mixed.cnf", DIR);
        write_file(p, TEXT);
        if (NCONF_load(c, p, NULL) > 0) {
            int r = CONF_modules_load(c, NULL,
                                      CONF_MFLAGS_NO_DSO |
                                          CONF_MFLAGS_IGNORE_ERRORS);
            sayn("B_mixed_load", r);
            sayn("B_mixed_fail_inits", MR[M_FAIL].inits);
            sayn("B_mixed_a_inits", MR[M_A].inits);
        } else {
            says("B_mixed_conf", "(unloadable)");
            ERR_clear_error();
        }
        NCONF_free(c);
    }
    MR[M_FAIL].ret = 1;
}

static void section_c(void)
{
    printf("-- C: the file-shaped entry point and its flag word\n");

    clear_records();
    sayn("C_missing_file_flags0", CONF_modules_load_file(path_missing, NULL, 0));
    ERR_clear_error();
    sayn("C_missing_file_ignore_missing",
         CONF_modules_load_file(path_missing, NULL,
                                CONF_MFLAGS_IGNORE_MISSING_FILE));
    ERR_clear_error();
    sayn("C_missing_file_ignore_rc",
         CONF_modules_load_file(path_missing, NULL,
                                CONF_MFLAGS_IGNORE_RETURN_CODES));
    ERR_clear_error();
    sayn("C_empty_file_flags0", CONF_modules_load_file(path_empty, NULL, 0));
    sayn("C_empty_file_ran_a", MR[M_A].inits);

    /* A section the file names but does not define. */
    clear_records();
    sayne("C_badsec_flags0", CONF_modules_load_file(path_badsec, NULL, 0));
    sayn("C_badsec_silent",
         CONF_modules_load_file(path_badsec, NULL, CONF_MFLAGS_SILENT));
    sayn("C_badsec_silent_err", ERR_peek_last_error());
    ERR_clear_error();

    /* An unknown module name. `NO_DSO` keeps the loader out of the way so the
     * reason is the registry's own. */
    clear_records();
    sayne("C_unknown_flags0",
          CONF_modules_load_file(path_unknown, NULL, CONF_MFLAGS_NO_DSO));
    sayn("C_unknown_silent",
         CONF_modules_load_file(path_unknown, NULL,
                                CONF_MFLAGS_NO_DSO | CONF_MFLAGS_SILENT));
    sayn("C_unknown_silent_err", ERR_peek_last_error());
    ERR_clear_error();
    /* `IGNORE_RETURN_CODES` forces 1 without removing the error record. */
    sayne("C_unknown_ignore_rc",
          CONF_modules_load_file(path_unknown, NULL,
                                 CONF_MFLAGS_NO_DSO |
                                     CONF_MFLAGS_IGNORE_RETURN_CODES));
    /* The default file, reached by a NULL filename: `$OPENSSL_CONF`. */
    clear_records();
    sayn("C_default_file", CONF_modules_load_file(NULL, NULL, 0));
    sayn("C_default_file_ran_a", MR[M_A].inits);
    /* The loader path, without `NO_DSO`: the registry miss becomes a `DSO_load`
     * attempt on the module name. Only the return value and the packed word are
     * reported -- the record's data on this path is `dlerror`'s text. */
    clear_records();
    sayne("C_unknown_with_dso", CONF_modules_load_file(path_unknown, NULL, 0));
}

static void section_d(void)
{
    printf("-- D: unload, finish, and the two return-early paths\n");

    /* `unload(0)` removes only dynamic modules with no live links. Everything
     * registered here is static, so the registry is unchanged and the next load
     * still runs the module. */
    clear_records();
    CONF_modules_unload(0);
    ERR_clear_error();
    load_via(path_main, NULL, 0, "D_after_unload0");
    sayn("D_after_unload0_ran_a", MR[M_A].inits);

    /* `CONF_modules_finish` finishes the live initialisations and leaves the
     * registry alone, so the module runs again. */
    clear_records();
    CONF_modules_finish();
    ERR_clear_error();
    load_via(path_main, NULL, 0, "D_after_finish");
    sayn("D_after_finish_ran_a", MR[M_A].inits);

    /* `unload(1)` removes static modules too, and publishes NULL for an emptied
     * list -- which is what makes the *second* call return early rather than walk
     * a freed list. */
    CONF_modules_unload(1);
    ERR_clear_error();
    CONF_modules_unload(1);
    ERR_clear_error();
    clear_records();
    sayne("D_after_unload1_unknown",
          CONF_modules_load_file(path_main, NULL, CONF_MFLAGS_NO_DSO));
}

static void section_e(void)
{
    printf("-- E: config_diagnostics, which is sticky and is observed last\n");

    /* Unset first, so the observation is of the transition rather than of a value
     * some earlier section left behind. */
    sayn("E_diagnostics_before", OSSL_LIB_CTX_get_conf_diagnostics(NULL) != 0);
    /* A file with no `config_diagnostics` key leaves the context's setting alone. */
    sayn("E_diag_absent_load", CONF_modules_load_file(path_main, NULL,
                                                     CONF_MFLAGS_NO_DSO));
    sayn("E_diagnostics_after_absent",
         OSSL_LIB_CTX_get_conf_diagnostics(NULL) != 0);

    /* The file that turns it on. It names an unknown module, so the load fails --
     * and the context's setting is now on. */
    sayn("E_diag_on_load", CONF_modules_load_file(path_diag, NULL, 0));
    ERR_clear_error();
    sayn("E_diagnostics_after_on", OSSL_LIB_CTX_get_conf_diagnostics(NULL) != 0);

    /* With diagnostics on, `CONF_modules_load` clears `IGNORE_RETURN_CODES`, so
     * the tail of `CONF_modules_load_file_ex` no longer forces 1: the same call
     * that answered 1 in section C answers -1 here. */
    sayne("E_unknown_ignore_rc_with_diag",
          CONF_modules_load_file(path_unknown, NULL,
                                 CONF_MFLAGS_NO_DSO |
                                     CONF_MFLAGS_IGNORE_RETURN_CODES));
    /* And a NULL `CONF` still answers 1, because the diagnostics read happens
     * before the NULL test. */
    sayn("E_diag_null_conf", CONF_modules_load(NULL, NULL, 0));
}

/* ------------------------------------------------------------------ section G */

/*
 * Pop the whole error queue, reporting each record's lib, reason, line and function.
 *
 * `ERR_peek_last_error` shows only the **outermost** record, and the `ssl_conf` reader's own
 * two raise sites are inner ones: `module_run` raises `CONF_R_MODULE_INITIALIZATION_ERROR`
 * after the initialiser has already raised `CONF_SSL_75` or `CONF_SSL_94`. So the inner
 * coordinates are unreachable through the peek and have to be drained. The order is the
 * authority's: `ERR_get_error` takes the **oldest** record, so index 0 is the initialiser's
 * and index 1 is `module_run`'s.
 */
static void drain_errors(const char *key)
{
    int i;
    for (i = 0; i < 4; i++) {
        const char *file = NULL, *func = NULL, *data = NULL;
        int line = 0, flags = 0;
        unsigned long e = ERR_get_error_all(&file, &line, &func, &data, &flags);
        printf("%s_%d_lib=%d\n", key, i, ERR_GET_LIB(e));
        printf("%s_%d_reason=%d\n", key, i, ERR_GET_REASON(e));
        printf("%s_%d_line=%d\n", key, i, line);
        printf("%s_%d_func=%s\n", key, i, func == NULL ? "(null)" : func);
        printf("%s_%d_data=%s\n", key, i, data == NULL ? "(null)" : data);
        if (e == 0) {
            break;
        }
    }
    ERR_clear_error();
}

/* One command set's worth of store, read back through the three accessors. */
static void report_store(const char *key)
{
    const char *name = NULL;
    size_t cnt = 0;
    size_t idx = (size_t)-1;
    const SSL_CONF_CMD *set;
    char cmdkey[32];

    snprintf(cmdkey, sizeof cmdkey, "%s_find_system_default", key);
    sayn(cmdkey, conf_ssl_name_find("system_default", &idx));
    snprintf(cmdkey, sizeof cmdkey, "%s_idx", key);
    sayn(cmdkey, (long long)idx);
    snprintf(cmdkey, sizeof cmdkey, "%s_find_absent", key);
    sayn(cmdkey, conf_ssl_name_find("not_a_set", &idx));
    /* A NULL name is answered 0 rather than dereferenced -- the authority's first check,
     * and the one Phase 4's `RT-COMP` already observed. Repeated here because the store is
     * now non-empty, which is the case that could have changed it. */
    snprintf(cmdkey, sizeof cmdkey, "%s_find_null", key);
    sayn(cmdkey, conf_ssl_name_find(NULL, &idx));
    /* An empty name is a prefix of nothing and a match for nothing. */
    snprintf(cmdkey, sizeof cmdkey, "%s_find_empty", key);
    sayn(cmdkey, conf_ssl_name_find("", &idx));

    if (conf_ssl_name_find("system_default", &idx) != 1) {
        return;
    }
    set = conf_ssl_get(idx, &name, &cnt);
    snprintf(cmdkey, sizeof cmdkey, "%s_set_name", key);
    says(cmdkey, name);
    snprintf(cmdkey, sizeof cmdkey, "%s_set_count", key);
    sayn(cmdkey, (long long)cnt);
    if (cnt < 2) {
        return;
    }
    {
        char *cs = NULL, *arg = NULL;
        conf_ssl_get_cmd(set, 0, &cs, &arg);
        snprintf(cmdkey, sizeof cmdkey, "%s_cmd0_name", key);
        says(cmdkey, cs);
        snprintf(cmdkey, sizeof cmdkey, "%s_cmd0_arg", key);
        says(cmdkey, arg);
        conf_ssl_get_cmd(set, 1, &cs, &arg);
        snprintf(cmdkey, sizeof cmdkey, "%s_cmd1_name", key);
        says(cmdkey, cs);
        snprintf(cmdkey, sizeof cmdkey, "%s_cmd1_arg", key);
        says(cmdkey, arg);
    }
}

/*
 * The `ssl_conf` module (6.10e).
 *
 * Three things here are the module's own contract rather than the accessors':
 *
 *   * the store is filled by loading a configuration, and the command set's name is the
 *     section entry's *key*, not its value;
 *   * a command's name has one leading dot stripped -- `.CipherString` becomes
 *     `CipherString`, and `conf_def.c` passes the dot through deliberately;
 *   * both of the reader's failure modes leave the store **empty**, because its `err:` label
 *     calls the free, and the reason distinguishes a missing section from a missing command
 *     section.
 *
 * That last one is checkable from outside: after a failed load, `conf_ssl_name_find` answers
 * 0 for a name that a previous successful load had put there.
 */
static void section_g(void)
{
    printf("-- G: the ssl_conf module, and the store its reader fills\n");

    /*
     * The registry was **emptied** by section D's `CONF_modules_unload(1)`, and
     * `module_run`'s own run-once has already fired, so nothing will repopulate it on its
     * own. The re-registration is explicit, and it is also an observation: it is what proves
     * `CONF_modules_unload(1)` really removed the built-in modules and that
     * `OPENSSL_load_builtin_modules` can put them back.
     */
    OPENSSL_load_builtin_modules();
    ERR_clear_error();

    /* Nothing is loaded yet, so the store is empty and every name is absent. */
    {
        size_t idx = (size_t)-1;
        says("G_before_any_load", "empty");
        sayn("G_before_find", conf_ssl_name_find("system_default", &idx));
    }

    /* A successful load. */
    sayne("G_load", CONF_modules_load_file(path_sslconf, NULL, CONF_MFLAGS_NO_DSO));
    report_store("G");

    /* A second load of the same file: the reader calls its free before replacing the store,
     * so the result is the same store, not a doubled one and not a leak. */
    sayne("G_reload",
          CONF_modules_load_file(path_sslconf, NULL, CONF_MFLAGS_NO_DSO));
    report_store("G_reload");

    /* `ssl_conf` naming a section the file does not define. The reader raises its own
     * `CONF_SSL_75` before `module_run` raises `CONF_MOD_286`, so the queue is drained to
     * observe the inner coordinate. */
    {
        int r = CONF_modules_load_file(path_sslconf_nosect, NULL, CONF_MFLAGS_NO_DSO);
        printf("G_nosect_load=%d\n", r);
        drain_errors("G_nosect");
    }
    /* The store was released by the reader's `err:` label. */
    {
        size_t idx = (size_t)-1;
        sayn("G_after_nosect_find", conf_ssl_name_find("system_default", &idx));
    }

    /* A command set whose own section is missing. */
    {
        int r = CONF_modules_load_file(path_sslconf_nocmds, NULL, CONF_MFLAGS_NO_DSO);
        printf("G_nocmds_load=%d\n", r);
        drain_errors("G_nocmds");
    }
    {
        size_t idx = (size_t)-1;
        sayn("G_after_nocmds_find", conf_ssl_name_find("system_default", &idx));
    }

    /* And a successful load after two failures restores the store, which is what proves the
     * failures did not leave the module's own registration broken. */
    sayne("G_reload_after_failure",
          CONF_modules_load_file(path_sslconf, NULL, CONF_MFLAGS_NO_DSO));
    {
        size_t idx = (size_t)-1;
        sayn("G_recovered_find", conf_ssl_name_find("system_default", &idx));
    }
}

/* ------------------------------------------------- the fresh-process scenarios */

/*
 * Each of these is the *first* `OPENSSL_init_crypto(LOAD_CONFIG, ...)` in its own
 * process, which is the only way to observe `ossl_config_int`'s flag and the
 * never-cleared re-entrancy slot.
 */
static void child_scenario(int mode)
{
    OPENSSL_INIT_SETTINGS *s;

    /* Every mode registers the same modules the parent did, because a child is a
     * fresh process. */
    clear_records();
    CONF_module_add("rt-cm-a", init_a, fin_a);
    CONF_module_add("rt-cm-a2", init_a2, fin_a2);
    CONF_module_add("rt-cm-a3", init_a3, fin_a3);

    switch (mode) {
    case 1:
        /* Settings that name a file directly: the `ossl_init_config_settings`
         * body, which is the one that reads the three settings fields. */
        s = OPENSSL_INIT_new();
        OPENSSL_INIT_set_config_filename(s, path_main);
        OPENSSL_INIT_set_config_file_flags(s, 0);
        ERR_clear_error();
        sayn("m1_first_load", OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, s));
        sayn("m1_first_load_ran_a", MR[M_A].inits);
        ERR_clear_error();
        sayn("m1_oid_known", OBJ_txt2nid("rt-cm-oid") != NID_undef);
        ERR_clear_error();
        /* A second call, with a settings object naming a file that would fail.
         * The option bit is recorded, so this is the fast path: 1, and the file is
         * never opened. */
        OPENSSL_INIT_set_config_filename(s, path_badsec);
        ERR_clear_error();
        sayn("m1_second_load", OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, s));
        sayn("m1_second_load_err", ERR_peek_last_error());
        ERR_clear_error();
        sayn("m1_second_load_ran_a_again", MR[M_A].inits);
        /* And the deprecated wrapper, which routes through the same once. */
        clear_records();
        OPENSSL_config(NULL);
        ERR_clear_error();
        sayn("m1_config_after_load_ran_a", MR[M_A].inits);
        OPENSSL_INIT_free(s);
        ERR_clear_error();
        break;

    case 2:
        /* `settings == NULL`: the `ossl_init_config` body, which falls back to
         * `CONF_get1_default_config_file()` and therefore to `$OPENSSL_CONF`. */
        ERR_clear_error();
        sayn("m2_first_load",
             OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL));
        sayn("m2_first_load_ran_a", MR[M_A].inits);
        ERR_clear_error();
        sayn("m2_oid_known", OBJ_txt2nid("rt-cm-oid") != NID_undef);
        ERR_clear_error();
        sayn("m2_base_only",
             OPENSSL_init_crypto(OPENSSL_INIT_BASE_ONLY_INTERNAL, NULL));
        ERR_clear_error();
        break;

    case 3:
        /* A settings object naming a file that does not exist, with a flag word
         * that does not tolerate it. The load fails, `openssl_configured` is set
         * anyway, and the re-entrancy slot stays set -- so a *second* call, this
         * time naming a good file, takes the skip branch and answers 1 without
         * loading anything. That pair is the whole reason the slot is modelled. */
        s = OPENSSL_INIT_new();
        OPENSSL_INIT_set_config_filename(s, path_missing);
        OPENSSL_INIT_set_config_file_flags(s, 0);
        ERR_clear_error();
        sayne("m3_first_load", OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, s));
        OPENSSL_INIT_set_config_filename(s, path_main);
        ERR_clear_error();
        sayn("m3_second_load", OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, s));
        sayn("m3_second_load_err", ERR_peek_last_error());
        ERR_clear_error();
        sayn("m3_second_load_ran_a", MR[M_A].inits);
        sayn("m3_oid_known", OBJ_txt2nid("rt-cm-oid") != NID_undef);
        ERR_clear_error();
        OPENSSL_INIT_free(s);
        break;

    case 4:
        /* Both config bits. `NO_LOAD_CONFIG` claims the shared once and records 1;
         * the `LOAD_CONFIG` block that follows finds it done and loads nothing.
         * The settings name a perfectly good file, and it is not read. */
        s = OPENSSL_INIT_new();
        OPENSSL_INIT_set_config_filename(s, path_main);
        OPENSSL_INIT_set_config_file_flags(s, 0);
        ERR_clear_error();
        sayn("m4_both_bits_load",
             OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG |
                                     OPENSSL_INIT_LOAD_CONFIG,
                                 s));
        sayn("m4_both_bits_ran_a", MR[M_A].inits);
        ERR_clear_error();
        sayn("m4_both_bits_oid_known", OBJ_txt2nid("rt-cm-oid") != NID_undef);
        ERR_clear_error();
        OPENSSL_INIT_free(s);
        break;

    case 5:
        /* `OPENSSL_config(appname)` builds its own settings on the stack with
         * `filename == NULL` and `appname` duplicated. The appname names a
         * *top-level key* whose value is the section to use, which is how an
         * application keeps its own section in the system file. */
        ERR_clear_error();
        OPENSSL_config("myapp");
        ERR_clear_error();
        sayn("m5_ran_a3", MR[M_A3].inits);
        sayn("m5_ran_a", MR[M_A].inits);
        says("m5_a3_name", MR[M_A3].name);
        says("m5_a3_value", MR[M_A3].value);
        break;

    case 6:
        /* An appname the file does not define. `CONF_modules_load` falls back to
         * `openssl_conf`, because `DEFAULT_CONF_MFLAGS` carries
         * `CONF_MFLAGS_DEFAULT_SECTION`. */
        OPENSSL_config("an_appname_that_is_absent");
        ERR_clear_error();
        sayn("m6_ran_a3", MR[M_A3].inits);
        sayn("m6_ran_a", MR[M_A].inits);
        break;

    default:
        sayn("m_bad_mode", mode);
        break;
    }
}

/* Re-executes this binary with a mode argument and reports the child's status. */
static void spawn_mode(int mode)
{
    pid_t pid = fork();
    if (pid == 0) {
        char buf[16];
        char *args[3];
        snprintf(buf, sizeof buf, "%d", mode);
        args[0] = (char *)"rt-conf-mod";
        args[1] = buf;
        args[2] = NULL;
        execv("/proc/self/exe", args);
        _exit(127);
    }
    if (pid < 0) {
        sayn("spawn_failed", mode);
        return;
    }
    {
        int status = 0;
        char key[32];
        if (waitpid(pid, &status, 0) < 0) {
            sayn("spawn_wait_failed", mode);
            return;
        }
        snprintf(key, sizeof key, "m%d_exit_code", mode);
        sayn(key, WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    }
}

int main(int argc, char **argv)
{
    /* Line-buffered: a probe's stdout is a pipe here, and a crash mid-section must
     * not swallow what was already observed. */
    setvbuf(stdout, NULL, _IOLBF, 0);

    fixtures();

    if (argc > 1) {
        child_scenario(atoi(argv[1]));
        return 0;
    }

    /* The reason strings, so `ERR_reason_error_string` answers rather than
     * returning NULL. The authority's `err_all.c` loads the CONF table as part of
     * the crypto set. */
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
    ERR_clear_error();

    section_a();
    section_a2();
    section_b();
    section_c();
    section_d();

    printf("-- F: the automatic loader, one fresh process per first call\n");
    spawn_mode(1);
    spawn_mode(2);
    spawn_mode(3);
    spawn_mode(4);
    spawn_mode(5);
    spawn_mode(6);

    /* Last, because it is sticky on the default context. */
    section_g();
    section_e();

    printf("-- done\n");
    return 0;
}
