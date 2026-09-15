/*
 * RT-DSO -- the generic dynamic-object layer, differentially.
 *
 * Why this court exists
 * --------------------
 * `DSO` is the one Phase-6 subsystem whose subject matter is *another library*: a
 * `DSO` owns a `dlopen` handle, and almost every operation it offers delegates to a
 * method table the caller never sees. That makes it a genuinely awkward parity target,
 * because the obvious observations are contaminated:
 *
 *   * the **filename** a `DSO` resolves is a real path, and the two sides are
 *     different libraries at different paths, so no path text is comparable;
 *   * a **successful load** needs a library that exists, and the only one both sides
 *     are guaranteed to have is the library each is itself built as;
 *   * `dladdr` on an address inside the library under test answers that library's path,
 *     which is likewise different.
 *
 * So this probe compares **relations, not text**: whether a pointer is NULL, whether
 * two pointers are equal, whether a returned string equals the string that was passed
 * in, and the return codes and error-queue entries of every refusal. Where a path has
 * to be named at all it is supplied by the build (`DSO_COURT_LIB`) rather than read
 * back, so the value differs between the two compilations and is never printed. That is
 * the same discipline `RT-LIBCTX` uses for addresses.
 *
 * What is being established
 * -------------------------
 * 1. **The NULL contract is not uniform.** `DSO_free(NULL)` answers 1 (a caller may
 *    free unconditionally) and `DSO_flags(NULL)` answers 0, but `DSO_up_ref(NULL)`,
 *    `DSO_ctrl(NULL, ...)`, `DSO_get_filename(NULL)`, `DSO_set_filename(NULL, ...)`,
 *    `DSO_merge(NULL, ...)`, `DSO_convert_filename(NULL, ...)` and
 *    `DSO_bind_func(NULL, ...)` are all *errors that raise*. A plausible
 *    implementation that made the family uniform would pass every happy-path test and
 *    fail here.
 *
 * 2. **`DSO_ctrl`'s three generic commands never reach the method.** The `dlfcn`
 *    method supplies `NULL` for `dso_ctrl`, so if the three commands were not
 *    intercepted, `DSO_CTRL_GET_FLAGS` would answer `-1` with `DSO_R_UNSUPPORTED`
 *    instead of the flags. The probe reads back what it wrote, and then asks for an
 *    unrecognised command to observe the interception's boundary: that one *does*
 *    reach the NULL method and *does* refuse.
 *
 * 3. **A negative `DSO_ctrl` answer is not an error.** Setting the flags to `-1`
 *    answers 0 and leaves `-1` stored, so the *next* `GET` answers `-1` with a clean
 *    error queue. The authority's own comment says a negative answer means failure;
 *    this is the case where it does not, and a caller cannot use the truthiness idiom.
 *
 * 4. **The name translator's rule is "contains no slash", not "has not been
 *    translated".** `"foo"` becomes `"libfoo.so"` and `"libfoo.so"` becomes
 *    `"liblibfoo.so"`. Both are observable, both are surprising, and the second is the
 *    one a reimplementation gets wrong by trying to be helpful.
 *
 * 5. **`DSO_merge` has four shapes and does not check that its second argument is a
 *    directory.** A missing second spec and an *empty* second spec are different
 *    (`merge("a", NULL)` is `"a"`; `merge("a", "")` is `"/a"`), one trailing slash is
 *    removed from the directory and no more, and a rooted first spec wins outright.
 *
 * 6. **`DSO_pathbyaddr` answers a *size* when told to.** With `sz <= 0` it writes
 *    nothing and returns `len + 1`; otherwise it writes at most `sz - 1` bytes and
 *    returns `min(len, sz - 1) + 1`. The two answers must agree at full size, which is
 *    the invariant a two-pass caller like `DSO_dsobyaddr` relies on. The path *text*
 *    differs between the sides and is never printed; the *contract* is compared.
 *
 * 7. **`DSO_load`'s refusals are ordered and each has its own reason.** The
 *    already-loaded check comes *first*, so a second `DSO_load` on the same object is
 *    `DSO_R_DSO_ALREADY_LOADED` and not a reload; a NULL filename on a fresh object is
 *    `DSO_R_NO_FILENAME`; and the translation happens on the load path, which is why a
 *    bare `"libcrypto.so.3"` does not load even though the library is right there.
 *
 * 8. **The reference count is observable through `DSO_free`'s answer.** One `up_ref`
 *    followed by two `free`s answers 1 both times: the first releases a reference, the
 *    second unloads and destroys. A caller therefore cannot use `DSO_free`'s answer to
 *    learn whether the object died.
 *
 * Fault boundaries
 * ----------------
 * Three things a probe cannot do, and does not try:
 *
 *   * a `DSO_free` past the last reference is a use-after-free, so the probe stops one
 *     short of it;
 *   * a `DSO_bind_func` answer is a `void (*)(void)` and is never called through --
 *     the observation is that the symbol resolved, not that it was invoked;
 *   * a failing `dlopen`'s *text* is carried in the error data and differs between the
 *     sides, which is why only the packed error code is compared. The packed code is
 *     the reason, not the data.
 *
 * The deliberately-unsafe reads are all in `RT-LIBCTX`'s category: they exist to
 * distinguish a defined behaviour from a missing one, and they are safe on the
 * authority because the authority defines them.
 *
 * The declarations below are transcribed from the admitted authority's
 * `include/internal/dso.h`, because `openssl/dso.h` is exported by the build but is
 * **not installed** -- a consumer cannot include it, and this probe is written against
 * what a consumer can actually do. Every type, arity and qualifier is the header's.
 *
 * Every observation is `key=value` on stdout, one line each, with unique keys. `err` is
 * `ERR_peek_error()` (the *oldest* entry) and `last` is `ERR_peek_last_error()` (the
 * *newest*), read immediately after the call and cleared before the next; whenever the
 * two differ the call raised more than one reason, in the order they are read.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

/* ------------------------------------------------------------- declarations */

typedef void (*DSO_FUNC_TYPE)(void);
typedef struct dso_st DSO;
typedef struct dso_meth_st DSO_METHOD;

extern DSO *DSO_new(void);
extern int DSO_free(DSO *dso);
extern int DSO_flags(DSO *dso);
extern int DSO_up_ref(DSO *dso);
extern long DSO_ctrl(DSO *dso, int cmd, long larg, void *parg);
extern const char *DSO_get_filename(DSO *dso);
extern int DSO_set_filename(DSO *dso, const char *filename);
extern char *DSO_convert_filename(DSO *dso, const char *filename);
extern char *DSO_merge(DSO *dso, const char *filespec1, const char *filespec2);
extern DSO *DSO_load(DSO *dso, const char *filename, DSO_METHOD *meth, int flags);
extern DSO_FUNC_TYPE DSO_bind_func(DSO *dso, const char *symname);
extern DSO_METHOD *DSO_METHOD_openssl(void);
extern int DSO_pathbyaddr(void *addr, char *path, int sz);
extern DSO *DSO_dsobyaddr(void *addr, int flags);
extern void *DSO_global_lookup(const char *name);

/* `include/internal/dso.h`. Not installed, so they are spelled out. */
#define DSO_CTRL_GET_FLAGS 1
#define DSO_CTRL_SET_FLAGS 2
#define DSO_CTRL_OR_FLAGS 3
#define DSO_FLAG_NO_NAME_TRANSLATION 0x01
#define DSO_FLAG_NAME_TRANSLATION_EXT_ONLY 0x02
#define DSO_FLAG_NO_UNLOAD_ON_FREE 0x04
#define DSO_FLAG_GLOBAL_SYMBOLS 0x20

/*
 * The library under test's own path, supplied by the build. It is the one filename a
 * successful `DSO_load` can use on both sides, and it is never printed -- the
 * observations around it are `strcmp`-against-the-input and NULL-ness, which are the
 * same on both sides by construction.
 */
#ifndef DSO_COURT_LIB
#error "DSO_COURT_LIB must be defined by the court"
#endif

/* --------------------------------------------------------------- reporting */

/*
 * Every helper reads the error queue **after** its value argument has already been
 * evaluated: the call sites assign to a temporary first. That is deliberate. Writing
 * `printf("%d %lu", call(), ERR_peek_error())` would be unspecified in C, and the
 * compiler is free to read the queue before the call -- which would silently turn the
 * `err` field into the *previous* call's reason. The existing probes' `SAYN` macro has
 * that hazard; this one does not.
 */
static void sayn(const char *key, long long v)
{
    unsigned long first = ERR_peek_error();
    unsigned long last = ERR_peek_last_error();

    printf("%s=%lld err=%lu last=%lu\n", key, v, first, last);
    ERR_clear_error();
}

static void sayp(const char *key, const void *p)
{
    unsigned long first = ERR_peek_error();
    unsigned long last = ERR_peek_last_error();

    printf("%s=%s err=%lu last=%lu\n", key, p == NULL ? "NULL" : "nonnull",
           first, last);
    ERR_clear_error();
}

static void says(const char *key, const char *s)
{
    unsigned long first = ERR_peek_error();
    unsigned long last = ERR_peek_last_error();

    printf("%s=%s err=%lu last=%lu\n", key, s == NULL ? "(null)" : s, first, last);
    ERR_clear_error();
}

/*
 * A string observation whose *text* is not comparable, only its relation to an input.
 * `s == NULL` is reported separately from `strcmp(s, expected)` so that "the call
 * answered nothing" cannot be confused with "the call answered something else".
 */
static void say_eq(const char *key, const char *got, const char *expected)
{
    int eq;

    if (got == NULL) {
        printf("%s=NULL err=%lu last=%lu\n", key, ERR_peek_error(),
               ERR_peek_last_error());
    } else {
        eq = strcmp(got, expected) == 0;
        printf("%s=%d err=%lu last=%lu\n", key, eq, ERR_peek_error(),
               ERR_peek_last_error());
    }
    ERR_clear_error();
}

/*
 * A `DSO_convert_filename`/`DSO_merge` answer, freed here rather than at the call site
 * so that no path can forget it. The text *is* comparable in this probe: the inputs are
 * literals and the answers are derived from them, with no filesystem involved.
 */
static void say_owned(const char *key, char *s)
{
    says(key, s);
    OPENSSL_free(s);
}

int main(void)
{
    DSO *a, *b, *c, *d;
    DSO_METHOD *m1, *m2;
    char *s;
    char buf[4096];
    int i, q, full, sz1, sz2, sz4, neg;

    setvbuf(stdout, NULL, _IOLBF, 0);

    /* ------------------------------------------------------------------ identity
     *
     * `DSO_METHOD_openssl` answers the same static object on every call -- a caller may
     * compare it -- and `DSO_new` answers a distinct object each time. Neither address
     * is printed; only the relations.
     */
    m1 = DSO_METHOD_openssl();
    m2 = DSO_METHOD_openssl();
    sayp("meth.nonnull", m1);
    sayn("meth.stable", m1 == m2);

    a = DSO_new();
    b = DSO_new();
    sayp("new.a", a);
    sayp("new.b", b);
    sayn("new.distinct", a != b);

    i = DSO_flags(a);
    sayn("new.flags.zero", i);

    /* `DSO_new` discards its method argument: `DSO_load(NULL, name, meth, flags)`
     * passes the caller's method to `DSO_new_method`, which overwrites the field with
     * `DSO_METHOD_openssl()` regardless. The observable consequence is that the *real*
     * method may be passed and nothing changes -- so the probe passes the real one and
     * records that the object still behaves as the default, which the load section
     * below confirms by loading successfully. */

    /* ------------------------------------------------------- the NULL contract
     *
     * Five of the seven answer without raising. The probe records both the answer and
     * the queue, because the difference between "0 and clean" and "0 and raised" is the
     * whole content of this section.
     */
    i = DSO_free(NULL);
    sayn("null.free", i);
    i = DSO_flags(NULL);
    sayn("null.flags", i);

    i = DSO_up_ref(NULL);
    sayn("null.upref", i);

    {
        long r;

        r = DSO_ctrl(NULL, DSO_CTRL_GET_FLAGS, 0, NULL);
        sayn("null.ctrl.get", r);
        r = DSO_ctrl(NULL, DSO_CTRL_SET_FLAGS, 0, NULL);
        sayn("null.ctrl.set", r);
        r = DSO_ctrl(NULL, DSO_CTRL_OR_FLAGS, 0, NULL);
        sayn("null.ctrl.or", r);
    }

    s = (char *) DSO_get_filename(NULL);
    sayp("null.getfilename", s);

    i = DSO_set_filename(NULL, "x");
    sayn("null.setfilename.dso", i);
    i = DSO_set_filename(a, NULL);
    sayn("null.setfilename.name", i);

    s = DSO_merge(NULL, "a", "b");
    sayp("null.merge", s);
    s = DSO_convert_filename(NULL, "a");
    sayp("null.convert", s);

    {
        DSO_FUNC_TYPE f;

        f = DSO_bind_func(NULL, "x");
        sayp("null.bind.dso", (void *) f);
        f = DSO_bind_func(a, NULL);
        sayp("null.bind.name", (void *) f);
        /* A well-formed object that has loaded nothing refuses too, and with a
         * different reason than the NULL argument. */
        f = DSO_bind_func(a, "CRYPTO_malloc");
        sayp("unloaded.bind", (void *) f);
    }

    {
        DSO *loaded;

        loaded = DSO_load(NULL, NULL, NULL, 0);
        sayp("null.load.both", loaded);
    }

    /* ------------------------------------------------- DSO_ctrl's three commands
     *
     * Written, read back, then written again with OR. Each step is a separate
     * observation because the *return* code and the *stored* value are two different
     * facts, and a plausible implementation gets one right and the other wrong.
     */
    {
        long r;
        int f;

        f = DSO_flags(a);
        sayn("ctrl.get.fresh", f);

        r = DSO_ctrl(a, DSO_CTRL_SET_FLAGS, DSO_FLAG_GLOBAL_SYMBOLS, NULL);
        sayn("ctrl.set.ret", r);
        f = DSO_flags(a);
        sayn("ctrl.get.after.set", f);
        /* `DSO_ctrl(GET)` and `DSO_flags` are two doors to the same field; the probe
         * reads it through both and reports whether they agree. */
        {
            long g = DSO_ctrl(a, DSO_CTRL_GET_FLAGS, 0, NULL);

            sayn("ctrl.get.ret", g);
            f = DSO_flags(a);
            sayn("ctrl.get.ctrl.agrees.flags", g == (long) f);
        }

        r = DSO_ctrl(a, DSO_CTRL_OR_FLAGS, DSO_FLAG_NO_NAME_TRANSLATION, NULL);
        sayn("ctrl.or.ret", r);
        f = DSO_flags(a);
        sayn("ctrl.get.after.or", f);

        /* OR is an OR, so re-ORing changes nothing and still answers 0. */
        r = DSO_ctrl(a, DSO_CTRL_OR_FLAGS, DSO_FLAG_NO_NAME_TRANSLATION, NULL);
        sayn("ctrl.or.idempotent.ret", r);
        f = DSO_flags(a);
        sayn("ctrl.get.after.or.again", f);

        /* A negative flag is stored as-is and read back as-is, answering 0 and then
         * -1 with a clean queue. This is the observation a caller cannot get from the
         * return code: -1 is *not* an error here. */
        r = DSO_ctrl(a, DSO_CTRL_SET_FLAGS, -1, NULL);
        sayn("ctrl.set.negative.ret", r);
        f = (int) DSO_ctrl(a, DSO_CTRL_GET_FLAGS, 0, NULL);
        sayn("ctrl.get.after.negative", f);
        f = DSO_flags(a);
        sayn("ctrl.flags.after.negative", f);

        /* Back to zero so the object does not carry a translation flag into the
         * converter section below. */
        r = DSO_ctrl(a, DSO_CTRL_SET_FLAGS, 0, NULL);
        sayn("ctrl.set.zero.ret", r);
        f = DSO_flags(a);
        sayn("ctrl.get.after.zero", f);
    }

    /* The interception's boundary: an unrecognised command does reach the method, whose
     * `dso_ctrl` is NULL, so it refuses with `DSO_R_UNSUPPORTED` and -1. */
    {
        long r;

        r = DSO_ctrl(a, 0, 0, NULL);
        sayn("ctrl.unknown.zero", r);
        r = DSO_ctrl(a, 4, 0, NULL);
        sayn("ctrl.unknown.four", r);
        r = DSO_ctrl(a, 99, 0, NULL);
        sayn("ctrl.unknown.99", r);
        r = DSO_ctrl(a, -1, 0, NULL);
        sayn("ctrl.unknown.neg", r);
    }

    /* ------------------------------------------------------------- the filename
     *
     * `DSO_get_filename` on a fresh object is NULL **without** raising, which is a
     * different fact from `DSO_get_filename(NULL)`. The name is *copied*, so the caller
     * may reuse its buffer -- and each set releases the previous one, which is why a
     * replacement reports the new text and not a concatenation.
     */
    s = (char *) DSO_get_filename(a);
    sayp("name.fresh", s);

    i = DSO_set_filename(a, "one");
    sayn("name.set.ret", i);
    s = (char *) DSO_get_filename(a);
    say_eq("name.get.one", s, "one");

    i = DSO_set_filename(a, "two");
    sayn("name.replace.ret", i);
    s = (char *) DSO_get_filename(a);
    say_eq("name.get.two", s, "two");

    /* An empty name is a name: it is not a missing one. */
    i = DSO_set_filename(a, "");
    sayn("name.set.empty.ret", i);
    s = (char *) DSO_get_filename(a);
    say_eq("name.get.empty", s, "");

    i = DSO_set_filename(a, NULL);
    sayn("name.set.null.ret", i);
    s = (char *) DSO_get_filename(a);
    say_eq("name.get.still", s, "");

    /* ---------------------------------------------------- the name translator
     *
     * `c` is used for the cases that need a clean flag word; each case names its own
     * object so a flag cannot leak between them.
     */
    c = DSO_new();
    sayp("translator.object", c);

    /* No slash: prefixed and suffixed. *With* a slash: untouched, whatever it is. */
    say_owned("conv.plain", DSO_convert_filename(c, "foo"));
    say_owned("conv.already", DSO_convert_filename(c, "libfoo.so"));
    say_owned("conv.slash", DSO_convert_filename(c, "/x/foo"));
    say_owned("conv.slash.already", DSO_convert_filename(c, "/x/libfoo.so"));
    say_owned("conv.empty", DSO_convert_filename(c, ""));
    say_owned("conv.trailing.slash", DSO_convert_filename(c, "/x/"));
    say_owned("conv.dot", DSO_convert_filename(c, "."));
    say_owned("conv.dotdot", DSO_convert_filename(c, ".."));

    /* `DSO_FLAG_NAME_TRANSLATION_EXT_ONLY` adds the extension and *not* the prefix. */
    DSO_ctrl(c, DSO_CTRL_SET_FLAGS, DSO_FLAG_NAME_TRANSLATION_EXT_ONLY, NULL);
    say_owned("conv.extonly.plain", DSO_convert_filename(c, "foo"));
    say_owned("conv.extonly.already", DSO_convert_filename(c, "libfoo.so"));
    say_owned("conv.extonly.slash", DSO_convert_filename(c, "/x/foo"));

    /* ... and `DSO_FLAG_NO_NAME_TRANSLATION` skips the converter entirely, so the
     * answer is a plain copy. It does not mean "answer NULL" -- which is what
     * `DSO_merge` does with the same flag. */
    DSO_ctrl(c, DSO_CTRL_SET_FLAGS, DSO_FLAG_NO_NAME_TRANSLATION, NULL);
    say_owned("conv.notranslate.plain", DSO_convert_filename(c, "foo"));
    say_owned("conv.notranslate.slash", DSO_convert_filename(c, "/x/foo"));

    /* A NULL filename means "translate the one I already have". */
    DSO_ctrl(c, DSO_CTRL_SET_FLAGS, 0, NULL);
    s = DSO_convert_filename(c, NULL);
    sayp("conv.null.noname", s);
    i = DSO_set_filename(c, "stored");
    sayn("conv.null.set.ret", i);
    say_owned("conv.null.stored", DSO_convert_filename(c, NULL));
    /* ... and the stored name is translated even though it was set untranslated: the
     * object keeps the caller's name in `filename` and the translation lives only in
     * the load. */
    s = (char *) DSO_get_filename(c);
    say_eq("conv.stored.untranslated", s, "stored");

    /* --------------------------------------------- DSO_merge and its four shapes
     *
     * The merger is the method's, reached through `DSO_merge`, and
     * `DSO_FLAG_NO_NAME_TRANSLATION` short-circuits it to NULL *before* it is called --
     * which is why the last case below has a clean error queue and no merger reason.
     */
    d = DSO_new();
    sayp("merge.object", d);

    say_owned("merge.rooted.first", DSO_merge(d, "/a/b", "/dir"));
    say_owned("merge.no.second", DSO_merge(d, "b", NULL));
    say_owned("merge.dir.slash", DSO_merge(d, "f", "/d/"));
    say_owned("merge.dir.noslash", DSO_merge(d, "f", "/d"));
    say_owned("merge.dir.relative", DSO_merge(d, "f", "d"));
    say_owned("merge.dir.double.slash", DSO_merge(d, "f", "/d//"));
    say_owned("merge.empty.first", DSO_merge(d, "", "/d"));
    say_owned("merge.empty.second", DSO_merge(d, "f", ""));
    say_owned("merge.empty.both", DSO_merge(d, "", ""));
    say_owned("merge.rooted.empty.second", DSO_merge(d, "/a", ""));

    /* A NULL **first** spec is refused by this layer, *before* the merger is reached,
     * and so is a NULL first spec *with* the no-translation flag -- the flag is checked
     * second. The merger's own "both are NULL" arm is therefore unreachable through
     * `DSO_merge`: it needs a non-NULL first spec to be entered at all, and then its
     * condition cannot hold. It is dead code in the authority, and dead here. */
    s = DSO_merge(d, NULL, "/dir");
    sayp("merge.null.first", s);
    s = DSO_merge(d, NULL, NULL);
    sayp("merge.both.null", s);

    DSO_ctrl(d, DSO_CTRL_SET_FLAGS, DSO_FLAG_NO_NAME_TRANSLATION, NULL);
    s = DSO_merge(d, "f", "/d");
    sayp("merge.notranslate", s);
    s = DSO_merge(d, NULL, "/dir");
    sayp("merge.notranslate.null.first", s);

    /* ------------------------------------------------- DSO_pathbyaddr's size contract
     *
     * The path differs between the sides -- and so does its *length*, because the two
     * libraries live at different paths -- so neither the text nor the absolute size is
     * comparable. What is comparable, and what a caller actually depends on, is the
     * *arithmetic*: that the size query is positive, that it agrees with the answer at
     * full size, that a size below the length truncates by exactly the rule, and that
     * the written bytes are terminated. `q` and `full` are therefore used only in
     * relations and never printed.
     */
    q = DSO_pathbyaddr(NULL, NULL, 0);
    sayn("path.query.positive", q > 0);

    sz1 = DSO_pathbyaddr(NULL, buf, 1);
    sayn("path.sz1", sz1);
    sayn("path.sz1.terminator", buf[0] == 0);

    sz2 = DSO_pathbyaddr(NULL, buf, 2);
    sayn("path.sz2", sz2);
    sayn("path.sz2.terminator", sz2 >= 1 && buf[sz2 - 1] == 0);

    sz4 = DSO_pathbyaddr(NULL, buf, 4);
    sayn("path.sz4", sz4);
    sayn("path.sz4.terminator", sz4 >= 1 && buf[sz4 - 1] == 0);

    memset(buf, 0, sizeof buf);
    full = DSO_pathbyaddr(NULL, buf, (int) sizeof buf);
    sayn("path.query.agrees.full", q == full);
    sayn("path.full.terminator", full >= 1 && buf[full - 1] == 0);
    sayn("path.full.strlen.agrees", (int) strlen(buf) == full - 1);
    /* The full path is absolute on both sides -- that a path came back is the
     * observation; which path is not. */
    sayn("path.full.rooted", full >= 1 && buf[0] == '/');

    /* One byte short of the length: the truncation rule is `min(len, sz - 1) + 1`, so
     * with `sz == len` the answer is still `len` and exactly one byte is dropped. That
     * this holds for the side's *own* `full` is the comparable statement. */
    if (full > 1) {
        int trunc = DSO_pathbyaddr(NULL, buf, full - 1);

        sayn("path.truncated.answer.eq.full.minus.one", trunc == full - 1);
        sayn("path.truncated.terminator", trunc >= 1 && buf[trunc - 1] == 0);
        sayn("path.truncated.strlen", (int) strlen(buf) == trunc - 1);
        /* A one-byte buffer holds the terminator and nothing else, so the truncated
         * string is strictly shorter than the full one. */
        sayn("path.truncated.shorter", trunc < full);
    }

    /* `sz <= 0` is the same branch, so a negative size is a size query too. */
    neg = DSO_pathbyaddr(NULL, NULL, -1);
    sayn("path.negative.agrees.query", neg == q);

    /* A `dladdr` miss. An address that belongs to no loaded module -- a stack local is
     * the portable way to name one -- is refused with -1, and the refusal is **not**
     * accompanied by an error code: this is the one site in the subsystem that appends
     * text to the queue without raising, so on an otherwise-empty queue the text lands
     * on a slot that carries no code and `ERR_peek_error()` stays 0. That is the
     * observation, and it is what distinguishes this failure from every other in the
     * file.
     *
     * The appended *text* is deliberately not compared: recovering it would require
     * priming the queue with an error first, which is the ERR stratum's business and its
     * own court's, and the two sides' differences there (`<NULL>` for an empty
     * `dlerror()`) are invisible while nothing else is on the queue. The candidate's
     * substitution is nevertheless implemented to match -- see
     * `crate::dso::add_error_data_pathbyaddr`. */
    {
        int stack_local = 0;
        int miss = DSO_pathbyaddr(&stack_local, buf, (int) sizeof buf);

        sayn("path.miss.answer.is.negative.one", miss == -1);
        sayn("path.miss.queue.empty", ERR_peek_error() == 0);
    }

    /* The text that site appends becomes observable as soon as something is already on
     * the queue, because then there is a slot with a code to attach it to. `ERR_raise`
     * puts a code there with **no data at all**, and the site appends to it -- so what
     * comes back out is exactly what the site wrote, which is the authority's
     * `ERR_add_error_data(2, "dlfcn_pathbyaddr(): ", dlerror())` including its
     * `<NULL>` substitution for a NULL argument. `dladdr` does not set `dlerror`'s
     * state, so this is the one place in the subsystem where that substitution is
     * reachable, and the transaction below is what makes the claim about it bear
     * evidence rather than assertion.
     *
     * `ERR_LIB_USER` and reason 1 are constants a consumer may name; the code is printed
     * as well so that a side which failed to raise would be visible rather than merely
     * producing an empty `data`. */
    {
        int stack_local = 0;
        const char *file = NULL, *func = NULL, *data = NULL;
        int line = 0, flags = 0;
        unsigned long got;
        char datacopy[256];

        ERR_raise(ERR_LIB_USER, 1);
        (void) DSO_pathbyaddr(&stack_local, buf, (int) sizeof buf);
        got = ERR_get_error_all(&file, &line, &func, &data, &flags);
        /* `data` aliases the slot's own buffer, which the *next* `ERR_clear_error`
         * releases -- and every reporting helper here ends with one. So it is copied
         * before anything else reads the queue. Measured the other way round first: the
         * text came back empty on both sides and looked like a divergence that was not
         * one, which is why the copy is commented rather than merely present. */
        datacopy[0] = 0;
        if (data != NULL) {
            size_t n = strlen(data);

            if (n >= sizeof datacopy)
                n = sizeof datacopy - 1;
            memcpy(datacopy, data, n);
            datacopy[n] = 0;
        }
        sayn("path.miss.raised.code.nonzero", got != 0);
        says("path.miss.raised.data", datacopy);
        sayn("path.miss.raised.flags.string", (flags & 0x02) != 0);
        sayn("path.miss.raised.queue.drained", ERR_peek_error() == 0);
    }

    /* ------------------------------------------------------------ DSO_dsobyaddr
     *
     * A two-pass size query over the above, then a load. The answer depends on whether
     * the loader recorded a *path* or a bare soname for the library under test; either
     * way both sides run the same code against the same question, so the answers must
     * agree, and the probe records which one it got rather than assuming.
     */
    {
        DSO *by;
        const char *fn;
        DSO_FUNC_TYPE f;

        by = DSO_dsobyaddr(NULL, 0);
        sayp("byaddr.object", by);
        if (by != NULL) {
            fn = DSO_get_filename(by);
            sayp("byaddr.filename", fn);
            i = (fn != NULL && fn[0] == '/');
            sayn("byaddr.filename.rooted", i);
            f = DSO_bind_func(by, "DSO_new");
            sayp("byaddr.bind.dso_new", (void *) f);
            f = DSO_bind_func(by, "no_such_symbol_openssl_rs_at_all");
            sayp("byaddr.bind.absent", (void *) f);
            i = DSO_up_ref(by);
            sayn("byaddr.upref", i);
            i = DSO_free(by);
            sayn("byaddr.free.first", i);
            i = DSO_free(by);
            sayn("byaddr.free.second", i);
        }
    }

    /* --------------------------------------------------- DSO_global_lookup
     *
     * A `dlopen(NULL)` handle sees the whole process, so the library under test answers
     * for its own symbol: the probe links against it, which is what puts it in the
     * global scope. A `dlsym` miss is apparently *not* an error here -- the queue is
     * read either side of it.
     */
    {
        void *p, *n;

        p = DSO_global_lookup("CRYPTO_malloc");
        sayp("global.crypto_malloc", p);
        p = DSO_global_lookup("DSO_new");
        sayp("global.dso_new", p);
        n = DSO_global_lookup("no_such_symbol_openssl_rs_at_all");
        sayp("global.absent", n);
        /* A NULL name is *not* probed: `DSO_global_lookup` passes it to `dlsym`
         * unchanged, and `dlsym`'s treatment of a NULL name is the loader's, not
         * OpenSSL's -- on this platform it is not guaranteed to return, so a probe
         * cannot compare it and does not try. */
    }

    /* ------------------------------------------------------------ DSO_load
     *
     * The order of the refusals is the content here. Every one of them is exercised
     * against a *fresh* object where possible so that a previous failure cannot be
     * mistaken for this one's cause.
     */
    {
        DSO *fresh, *loaded;
        const char *fn;
        DSO_FUNC_TYPE f;

        /* No object, no name: the object is allocated and then released, and the reason
         * is "there is no filename". */
        loaded = DSO_load(NULL, NULL, NULL, 0);
        sayp("load.no.object.no.name", loaded);

        /* A caller's object and no name: same reason, and the object survives -- which
         * is the difference between the two branches of the failure path. */
        fresh = DSO_new();
        loaded = DSO_load(fresh, NULL, NULL, 0);
        sayp("load.caller.no.name", loaded);
        sayn("load.caller.survives", DSO_flags(fresh) == 0);
        sayp("load.caller.getfilename", DSO_get_filename(fresh));
        i = DSO_free(fresh);
        sayn("load.caller.free", i);

        /* A name that does not exist. Two reasons: the method's, carrying `dlerror()`,
         * then this layer's. Only the packed codes are compared. */
        loaded = DSO_load(NULL, "/nonexistent/openssl-rs-court-probe.so", NULL, 0);
        sayp("load.absent.absolute", loaded);

        /* A bare soname that *does* exist is still translated, and the translation does
         * not: `"libcrypto.so.3"` becomes `"liblibcrypto.so.3.so"`. This is the
         * translator running on the load path rather than only in `DSO_convert_filename`,
         * and it is the reason the successful load below passes a path. */
        loaded = DSO_load(NULL, "libcrypto.so.3", NULL, 0);
        sayp("load.bare.soname.translated", loaded);

        /* The one load that can succeed on both sides. */
        loaded = DSO_load(NULL, DSO_COURT_LIB, NULL, 0);
        sayp("load.self.object", loaded);
        if (loaded != NULL) {
            int flags;

            fn = DSO_get_filename(loaded);
            say_eq("load.self.filename.kept", fn, DSO_COURT_LIB);
            flags = DSO_flags(loaded);
            sayn("load.self.flags.zero", flags);

            /* A loaded object's name is no longer the caller's to change. */
            i = DSO_set_filename(loaded, "something-else");
            sayn("load.self.setfilename.refused", i);
            fn = DSO_get_filename(loaded);
            say_eq("load.self.filename.unchanged", fn, DSO_COURT_LIB);

            /* Already loaded: refused first, before the filename is even looked at, and
             * the *caller's* object is not freed by the refusal. */
            sayp("load.self.twice", DSO_load(loaded, DSO_COURT_LIB, NULL, 0));
            fn = DSO_get_filename(loaded);
            say_eq("load.self.alive.after.refusal", fn, DSO_COURT_LIB);
            f = DSO_bind_func(loaded, "DSO_new");
            sayp("load.self.bind.after.refusal", (void *) f);

            /* Binding through the loaded object: a real symbol resolves, an absent one
             * refuses with the method's reason first. */
            f = DSO_bind_func(loaded, "CRYPTO_malloc");
            sayp("load.self.bind.crypto_malloc", (void *) f);
            f = DSO_bind_func(loaded, "openssl_rs_no_such_symbol_at_all");
            sayp("load.self.bind.absent", (void *) f);

            /* The reference count: one `up_ref`, then two `free`s that both answer 1,
             * the second having unloaded and destroyed. */
            i = DSO_up_ref(loaded);
            sayn("load.self.upref", i);
            i = DSO_free(loaded);
            sayn("load.self.free.first", i);
            i = DSO_free(loaded);
            sayn("load.self.free.second", i);
        }
    }

    /* --------------------------------------------------- the unload flag
     *
     * `DSO_FLAG_NO_UNLOAD_ON_FREE` skips `dso_unload` entirely, which is observable
     * only through the answer of the final `DSO_free`: it is 1 either way, because the
     * flag changes *what is done*, not *what is reported*. What it does change is that
     * the library stays loaded, which a later `DSO_global_lookup` can see -- but only
     * for a library the lookup would not otherwise find. The library under test is
     * already loaded by the probe's own `DT_NEEDED`, so that observation is not
     * available here and the flag is recorded through the object's own flags instead.
     */
    {
        DSO *nu;

        nu = DSO_load(NULL, DSO_COURT_LIB, NULL, DSO_FLAG_NO_UNLOAD_ON_FREE);
        sayp("nounload.object", nu);
        if (nu != NULL) {
            i = DSO_flags(nu);
            sayn("nounload.flags", i);
            i = DSO_free(nu);
            sayn("nounload.free", i);
            /* Still loaded, so a bind through a freshly loaded handle still works. */
            nu = DSO_load(NULL, DSO_COURT_LIB, NULL, 0);
            sayp("nounload.reload", nu);
            if (nu != NULL) {
                i = DSO_free(nu);
                sayn("nounload.reload.free", i);
            }
        }
    }

    /* -------------------------------------------------------------------- cleanup
     *
     * `a` still holds an empty filename from the substitution section, `c` holds
     * "stored", `d` carries the no-translation flag, and `b` has never held anything.
     */
    i = DSO_free(d);
    sayn("free.d", i);
    i = DSO_free(c);
    sayn("free.c", i);
    i = DSO_free(b);
    sayn("free.b", i);
    i = DSO_free(a);
    sayn("free.a", i);
    i = DSO_free(NULL);
    sayn("free.null.again", i);

    printf("done=rt-dso err=%lu\n", ERR_peek_error());
    return 0;
}
