/*
 * openssl-rs — Phase 4 court: the CONF reader, differentially.
 *
 * Compiled twice (authority headers + authority libcrypto, candidate headers +
 * candidate libcrypto) and run; the two transcripts are compared line by line,
 * keyed on `key=value`. Every line is an observation of the authority, not an
 * expectation written down by hand, so this probe cannot drift away from what the
 * authority does without the court noticing.
 *
 * The configuration grammar is input that *people write*, so almost every rule in
 * `conf_def.c` has a plausible-but-wrong implementation: whether `;` is a comment
 * (it is not, in the default method), whether a doubled quote escapes (it does not,
 * outside the WIN32 table), whether a long line and a continued line are the same
 * thing, and what the error queue holds — including which authority source file and
 * line raised. All of those are observed here rather than assumed.
 *
 * Sections:
 *   methods      the two method tables and their identity
 *   fresh        a new configuration: every getter and control against no data
 *   parse        the grammar, one fixture per rule, through an in-memory BIO
 *   errors       the same fixtures where they fail: return, line, and the queue
 *   pragma       .pragma and .include
 *   win32        the WIN32 method's different classes, on the same text
 *   number       NCONF_get_number_e, including its overflow
 *   names        NCONF_get_section_names, which is sorted
 *   parselist    CONF_parse_list, including its empty elements
 *   classic      the caller-owned hash API (CONF_set_nconf and friends)
 *   defaultcfg   CONF_get1_default_config_file
 *
 * Everything runs from an in-memory BIO except `.include`, which needs real
 * files; those live under a fixed scratch directory so both runs see byte
 * identical inputs. No pointer value and no allocation count is printed: they
 * differ between two builds and would be residual noise.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/conf_api.h>
#include <openssl/err.h>
#include <openssl/lhash.h>

/* ------------------------------------------------------------------------- */
/* Transcript helpers.                                                        */
/* ------------------------------------------------------------------------- */

static char cur[96];

/* Line buffered, so if a probe hits an authority fault the last completed
 * observation is still in the transcript and names the call. */
#define CASE(name)                                                            \
    do {                                                                      \
        snprintf(cur, sizeof cur, "%s", (name));                              \
    } while (0)

static void oi(const char *k, long v)
{
    printf("%s.%s=%ld\n", cur, k, v);
}

/* Escapes a string so that it can live on one transcript line: newline becomes
 * `|`, carriage return `^`, and anything unprintable becomes `\xNN`. */
static const char *show(const char *s)
{
    static char buf[65536];
    size_t o = 0;

    if (s == NULL)
        return "<NULL>";
    for (; *s != '\0' && o + 5 < sizeof buf; s++) {
        unsigned char c = (unsigned char)*s;

        if (c == '\n')
            buf[o++] = '|';
        else if (c == '\r')
            buf[o++] = '^';
        else if (c >= 0x20 && c < 0x7f)
            buf[o++] = (char)c;
        else
            o += (size_t)sprintf(buf + o, "\\x%02x", c);
    }
    buf[o] = '\0';
    return buf;
}

static void os(const char *k, const char *v)
{
    printf("%s.%s=[%s]\n", cur, k, show(v));
}

/*
 * Drains the error queue and prints every entry as
 * `code|file|line|func|data|flags`, which is the whole of what
 * `ERR_get_error_all` exposes. The file and line are the authority's own raise
 * coordinates, so this is also an observation of the generated error-site table.
 */
static void errdump(const char *k)
{
    unsigned long e;
    const char *file = NULL, *func = NULL, *data = NULL;
    int line = 0, flags = 0;
    char text[2048];
    int n = 0;

    /*
     * The queue is drained, NOT cleared first: the entries are what this
     * observation is for, and `ERR_clear_error` would destroy them before they
     * could be read. The trailing `drained` line is what verifies emptiness.
     */
    while ((e = ERR_get_error_all(&file, &line, &func, &data, &flags)) != 0) {
        snprintf(text, sizeof text, "%lX|%s|%d|%s|%s|%d", e, file ? file : "",
                 line, func ? func : "", data ? data : "", flags);
        printf("%s.%s.%d=[%s]\n", cur, k, n, show(text));
        n++;
    }
    printf("%s.%s.count=%d\n", cur, k, n);
    /* After the drain the queue must be empty, which is itself observed. */
    printf("%s.%s.drained=%d\n", cur, k, ERR_peek_error() == 0);
}

/* A memory BIO holding `text`, positioned at the start. */
static BIO *mem(const char *text)
{
    return BIO_new_mem_buf(text, -1);
}

/* A fresh default configuration with the text loaded through a memory BIO.
 * Returns NULL if the load failed; `eline` is whatever the load reported. */
static CONF *load_mem(const char *text, long *eline, int *ret)
{
    CONF *c = NCONF_new(NULL);
    BIO *b = mem(text);

    if (c == NULL || b == NULL) {
        BIO_free(b);
        NCONF_free(c);
        if (ret)
            *ret = -1;
        return NULL;
    }
    if (eline)
        *eline = -1;
    *ret = NCONF_load_bio(c, b, eline);
    BIO_free(b);
    return c;
}

/* The whole model, as the dumper writes it. */
static void dump_conf(CONF *c)
{
    BIO *b = BIO_new(BIO_s_mem());
    char buf[8192];
    int n;

    BIO_reset(b);
    oi("dump.ret", NCONF_dump_bio(c, b));
    n = BIO_read(b, buf, (int)sizeof buf - 1);
    if (n < 0)
        n = 0;
    buf[n] = '\0';
    os("dump.text", buf);
    BIO_free(b);
}

/* ------------------------------------------------------------------------- */
/* The scratch directory `.include` needs.                                    */
/* ------------------------------------------------------------------------- */

#define SCRATCH "/tmp/openssl-rs-rtconf"

static void rm_rf(const char *path)
{
    /* One level is enough for this probe's layout. */
    char cmd[512];

    snprintf(cmd, sizeof cmd, "rm -rf '%s'", path);
    if (system(cmd) != 0) {
        fprintf(stderr, "probe: rm -rf %s failed\n", path);
    }
}

static void write_file(const char *path, const char *text)
{
    FILE *f = fopen(path, "wb");

    if (f == NULL) {
        fprintf(stderr, "probe: cannot write %s\n", path);
        exit(2);
    }
    fwrite(text, 1, strlen(text), f);
    fclose(f);
}

static void make_fixtures(void)
{
    char path[512];

    rm_rf(SCRATCH);
    if (mkdir(SCRATCH, 0700) != 0 && errno != EEXIST) {
        fprintf(stderr, "probe: cannot create %s\n", SCRATCH);
        exit(2);
    }

    snprintf(path, sizeof path, SCRATCH "/plain.cnf");
    write_file(path, "[inc]\nfrom_include = yes\n.include " SCRATCH "/nested.cnf\n");
    snprintf(path, sizeof path, SCRATCH "/nested.cnf");
    write_file(path, "[nested]\ndeep = 1\n");

    /* A directory include reads `.conf`/`.cnf` names only, case-insensitively. */
    snprintf(path, sizeof path, SCRATCH "/d");
    mkdir(path, 0700);
    snprintf(path, sizeof path, SCRATCH "/d/aa.cnf");
    write_file(path, "[d]\naa = 1\n");
    snprintf(path, sizeof path, SCRATCH "/d/bb.conf");
    write_file(path, "[d]\nbb = 2\n");
    snprintf(path, sizeof path, SCRATCH "/d/cc.txt");
    write_file(path, "[d]\ncc = 3\n");
    /* A name that ends in the suffix but is shorter than it: `namelen > 5` guard. */
    snprintf(path, sizeof path, SCRATCH "/d/.cnf");
    write_file(path, "[d]\ndotcnf = 4\n");

    /* A directory whose member includes that same directory again. */
    snprintf(path, sizeof path, SCRATCH "/rec");
    mkdir(path, 0700);
    snprintf(path, sizeof path, SCRATCH "/rec/one.cnf");
    write_file(path, "[rec]\n.include " SCRATCH "/rec\n");

    /* An absolute include target used by the abspath pragma test. */
    snprintf(path, sizeof path, SCRATCH "/abs.cnf");
    write_file(path, "[abs]\nabsolute = 1\n");
}

/* ------------------------------------------------------------------------- */
/* Sections.                                                                  */
/* ------------------------------------------------------------------------- */

static void s_methods(void)
{
    CONF_METHOD *d = NCONF_default();
    CONF_METHOD *w = NCONF_WIN32();

    CASE("methods");
    oi("default.nonnull", d != NULL);
    oi("win32.nonnull", w != NULL);
    oi("distinct", d != w);
    oi("default.stable", NCONF_default() == d);
    os("default.name", d ? d->name : NULL);
    os("win32.name", w ? w->name : NULL);
    oi("default.hooks", d != NULL && d->create && d->init && d->destroy
        && d->destroy_data && d->load_bio && d->dump && d->is_number
        && d->to_int && d->load);
    oi("win32.hooks", w != NULL && w->create && w->init && w->destroy
        && w->destroy_data && w->load_bio && w->dump && w->is_number
        && w->to_int && w->load);
    /* The two tables share everything but `init`. */
    oi("same.create", d->create == w->create);
    oi("same.load", d->load == w->load);
    oi("same.dump", d->dump == w->dump);
    oi("same.is_number", d->is_number == w->is_number);
    oi("same.to_int", d->to_int == w->to_int);
    oi("same.init", d->init == w->init);
}

static void s_fresh(void)
{
    CONF *c = NCONF_new(NULL);
    long eline = -1;
    long out = -12345;

    CASE("fresh");
    oi("new.nonnull", c != NULL);
    oi("libctx.null", NCONF_get0_libctx(c) == NULL);
    oi("libctx.from_new_ex", NCONF_get0_libctx(NCONF_new_ex(NULL, NULL)) == NULL);

    /* No data yet: every lookup is a defined NULL, and the section list is an
     * empty stack rather than a failure. */
    oi("section.null", NCONF_get_section(c, "nope") == NULL);
    oi("get_string.null", NCONF_get_string(c, "nope", "nope") == NULL);
    oi("get_string.null_group", NCONF_get_string(c, NULL, "nope") == NULL);
    oi("get_string.null_name", NCONF_get_string(c, "g", NULL) == NULL);
    eline = -1;
    oi("get_number_e.absent", NCONF_get_number_e(c, NULL, "nope", (long *)&eline));
    oi("get_number_e.absent_out", eline);
    eline = -1;
    oi("get_number_e.null_result", NCONF_get_number_e(c, NULL, "nope", NULL));
    {
        STACK_OF(OPENSSL_CSTRING) *names = NCONF_get_section_names(c);

        oi("names.nonnull", names != NULL);
        oi("names.count", names ? OPENSSL_sk_num((const OPENSSL_STACK *)names) : -1);
        OPENSSL_sk_free((OPENSSL_STACK *)names);
    }

    /* A NULL configuration is a defined failure for the data-taking calls. */
    oi("null.load_bio", NCONF_load_bio(NULL, NULL, NULL));
    oi("null.load", NCONF_load(NULL, "/nonexistent", NULL));
    oi("null.get_section", NCONF_get_section(NULL, "s") == NULL);
    oi("null.dump_bio", NCONF_dump_bio(NULL, NULL));
    oi("null.get_number_e", NCONF_get_number_e(NULL, "g", "n", &out));

    /* A NULL BIO is not an error: the parser treats it as immediate EOF and
     * installs the default section. */
    eline = -1;
    oi("empty.load_bio", NCONF_load_bio(c, NULL, &eline));
    oi("empty.line", eline);
    oi("empty.section_exists", NCONF_get_section(c, "default") != NULL);
    {
        STACK_OF(OPENSSL_CSTRING) *names = NCONF_get_section_names(c);

        oi("empty.names.count", names ? OPENSSL_sk_num((const OPENSSL_STACK *)names) : -1);
        OPENSSL_sk_free((OPENSSL_STACK *)names);
    }
    dump_conf(c);

    errdump("err");
    /*
     * `NCONF_free_data` releases the model but leaves `conf->data` dangling, so
     * this configuration must NOT then be passed to `NCONF_free`: that would walk
     * the freed hash again and the authority faults on it. The contract is
     * therefore observed on a configuration of its own, and the empty shell is
     * deliberately leaked rather than freed.
     */
    {
        CONF *d = NCONF_new(NULL);
        BIO *b = mem("k = v\n");

        oi("free_data.load", NCONF_load_bio(d, b, NULL));
        BIO_free(b);
        oi("free_data.lookup_before", NCONF_get_string(d, "default", "k") != NULL);
        NCONF_free_data(d);
        printf("%s.free_data.survived=1\n", cur);
    }

    NCONF_free(c);
    NCONF_free(NULL);
    NCONF_free_data(NULL);
    oi("free.null_is_safe", 1);
}

/* One text fixture: load, report the return and the line, dump, then look up a
 * listed key in a listed group. */
static void fixture(const char *name, const char *text,
                    const char *group, const char *key)
{
    long eline = -1;
    int ret = 2;
    CONF *c;

    CASE(name);
    c = load_mem(text, &eline, &ret);
    oi("ret", ret);
    oi("eline", eline);
    if (c != NULL) {
        os("lookup", NCONF_get_string(c, group, key));
        dump_conf(c);
        errdump("err");
    }
    NCONF_free(c);
}

static void s_parse(void)
{
    fixture("basic", "[default]\nname = value\n", "default", "name");
    fixture("comments",
            "# full line\n"
            "key = val # trailing\n"
            "; semicolon line\n"
            "k2 = v2 ; semicolon here\n"
            "hash = a#b\n"
            "semi = a;b\n",
            "default", "key");
    fixture("comments.semicolon_hash",
            "; semicolon line\n"
            "k = v\n",
            "default", "; semicolon line");
    fixture("quotes",
            "q1 = 'a b'\n"
            "q2 = \"c d\"\n"
            "q3 = 'e\\'f'\n"
            "q4 = \"g\"\"h\"\n"
            "q5 = 'i\"j'\n"
            "q6 = \"k'l\"\n"
            "q7 = pre'mid'post\n"
            "q8 = 'a#b'\n",
            "default", "q4");
    fixture("escapes",
            "e1 = a\\rb\n"
            "e2 = a\\nb\n"
            "e3 = a\\bb\n"
            "e4 = a\\tb\n"
            "e5 = a\\\\b\n"
            "e6 = a\\qb\n"
            "e7 = 'x\\qy'\n",
            "default", "e1");
    fixture("continuation",
            "c1 = one \\\n"
            " two\n"
            "c2 = x\\\\\n"
            "c3 = a\\\n"
            "     b\n",
            "default", "c1");
    fixture("bom", "\xEF\xBB\xBF[default]\nkey = bom\n", "default", "key");
    fixture("bom.key", "\xEF\xBB\xBFk = v\n", "default", "k");
    fixture("sections",
            "[s1]\n"
            "a = 1\n"
            "[s2]\n"
            "b = 2\n"
            "[s1]\n"
            "c = 3\n",
            "s1", "c");
    fixture("badsection", "[broken\nkey = v\n", "default", "key");
    fixture("spacesection", "[  name with space  ]\nk = v\n",
            "name with space", "k");
    fixture("qualified", "sec::key = val\n[s]\nother::k2 = v2\n", "sec", "key");
    fixture("qualified.in_section", "sec::key = val\n[s]\nother::k2 = v2\n",
            "other", "k2");
    fixture("emptyvalue", "k =\nk2  =  \nk3 =   x   \n", "default", "k2");
    fixture("nokey", "= value\n", "default", "value");
    fixture("duplicate", "k = 1\nk = 2\n", "default", "k");
    fixture("nonascii", "k\xC3\xA9 = v\nok = 1\n", "default", "ok");
    fixture("blanklines", "\n\n   \n\t\nk = v\n", "default", "k");
    fixture("crlf", "k = v\r\nk2 = v2\r\n", "default", "k");
    fixture("noeol", "k = v", "default", "k");
    fixture("tabkey", "k\t=\tv\n", "default", "k");
    fixture("colonname", "a:b = v\n", "default", "a:b");
    fixture("quotedkey", "'k' = v\n", "default", "k");
    fixture("dotkey", ".key = v\n", "default", ".key");
    fixture("bracketkey", "[a] = v\n", "a", "a");
    /* A value longer than the 511-byte read buffer exercises the long-line path;
     * 600 'x' plus the surrounding syntax. */
    fixture("longline",
            "k = "
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n"
            "after = 1\n",
            "default", "after");
}

static void s_errors(void)
{
    static const struct {
        const char *name;
        const char *text;
    } bad[] = {
        { "err.missing_equals", "[default]\nthis line has no equals\n" },
        { "err.missing_equals.late", "a = 1\nb = 2\nbroken here\n" },
        { "err.open_bracket", "[unclosed\nk = v\n" },
        { "err.open_bracket.tight", "[a b\n" },
        { "err.bad_pragma", ".pragma dollarid:maybe\nk = v\n" },
        { "err.pragma_no_colon", ".pragma dollarid\n" },
        { "err.pragma_empty_value", ".pragma dollarid:\n" },
        { "err.pragma_empty_name", ".pragma :on\n" },
        { "err.var_missing", "k = $nosuchvariable\n" },
        { "err.var_missing.braced", "k = ${nosuchvariable}\n" },
        { "err.var_unclosed", "k = ${nosuchvariable\n" },
        { "err.var_unclosed.paren", "k = $(nosuchvariable\n" },
        { "err.include_missing", ".include " SCRATCH "/nosuchfile.cnf\nk = v\n" },
        { "err.include_recursive",
          ".include " SCRATCH "/rec\n[after]\nreached = 1\n" },
        { "err.relative_abspath",
          ".pragma abspath:on\n.include relative-not-absolute.cnf\n" },
    };
    size_t i;

    for (i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        long eline = -1;
        int ret = 2;
        CONF *c;

        CASE(bad[i].name);
        c = load_mem(bad[i].text, &eline, &ret);
        oi("ret", ret);
        oi("eline", eline);
        errdump("err");
        if (c != NULL) {
            /* The error path frees a table it created itself, so the
             * configuration must not still hold the failed data. */
            oi("section.after_failure", NCONF_get_section(c, "default") != NULL);
            NCONF_free(c);
        }
    }
}

static void s_pragma(void)
{
    char text[1024];

    fixture("pragma.unknown", ".pragma nosuchpragma:value\nk = v\n",
            "default", "k");
    fixture("pragma.dollarid_off", "$foo = bar\nk = $foo\n", "default", "$foo");
    fixture("pragma.dollarid_on",
            ".pragma dollarid:on\n$foo = bar\nk = $foo\n", "default", "$foo");
    fixture("pragma.dollarid_on.expand",
            ".pragma dollarid:on\n$foo = bar\nk = ${foo}\n", "default", "k");
    fixture("pragma.dollarid_eq_form",
            ".pragma = dollarid:on\n$foo = bar\nk = ${foo}\n", "default", "k");
    fixture("pragma.dollarid_off_again",
            ".pragma dollarid:on\n.pragma dollarid:off\n$foo = bar\nk = $foo\n",
            "default", "$foo");
    fixture("pragma.abspath_absolute",
            ".pragma abspath:on\n.include " SCRATCH "/abs.cnf\nk = v\n",
            "abs", "absolute");
    fixture("pragma.includedir",
            ".pragma includedir:" SCRATCH "\n.include d\n[z]\nz = 1\n",
            "d", "aa");
    fixture("pragma.includedir_abs_include",
            ".pragma includedir:" SCRATCH "\n.include abs.cnf\n",
            "abs", "absolute");

    /* The real-file include path, both forms. */
    fixture("include.absolute",
            ".include " SCRATCH "/plain.cnf\n[top]\ntop = 1\n",
            "nested", "deep");
    fixture("include.absolute.inc",
            ".include " SCRATCH "/plain.cnf\n[top]\ntop = 1\n",
            "inc", "from_include");
    fixture("include.directory",
            ".include " SCRATCH "/d\n[top]\ntop = 1\n",
            "d", "aa");
    fixture("include.directory.bb",
            ".include " SCRATCH "/d\n[top]\ntop = 1\n",
            "d", "bb");
    fixture("include.directory.txt",
            ".include " SCRATCH "/d\n[top]\ntop = 1\n",
            "d", "cc");
    fixture("include.directory.dotcnf",
            ".include " SCRATCH "/d\n[top]\ntop = 1\n",
            "d", "dotcnf");

    /* Expansion across sections and from the environment. */
    fixture("expand.same_section", "a = one\nb = $a\n", "default", "b");
    fixture("expand.braced", "a = one\nb = ${a}\n", "default", "b");
    fixture("expand.paren", "a = one\nb = $(a)\n", "default", "b");
    fixture("expand.qualified",
            "[s]\nk = v\n[default]\nb = $s::k\n", "default", "b");
    fixture("expand.default_section",
            "[s]\nk = v\n[default]\nm = w\nb = $::k\n", "default", "b");
    fixture("expand.env",
            "[default]\nb = $ENV::HOME\n", "default", "b");
    fixture("expand.literal_dollar", "b = a\\$b\n", "default", "b");
    fixture("expand.double_dollar", "a = one\nb = $$a\n", "default", "b");
    fixture("expand.recursive",
            "a = $b\nb = $a\nc = $a\n", "default", "c");
    fixture("expand.in_quotes", "a = one\nb = '$a'\n", "default", "b");
    fixture("expand.in_dquotes", "a = one\nb = \"$a\"\n", "default", "b");
    fixture("expand.after_quote", "a = one\nb = '$a'$a\n", "default", "b");

    /* The expansion cap: a value that expands past MAX_CONF_VALUE_LENGTH. */
    {
        /* 700 * 100 = 70000 > 65536, reached through repeated self-reference is
         * not possible (the source is bounded), so the cap is exercised by
         * expanding a 700-byte value into a 70000-byte context: 100
         * concatenations, each of which is a 700-byte expansion. */
        size_t o = 0;
        int i;

        text[o++] = 'a';
        text[o++] = ' ';
        text[o++] = '=';
        text[o++] = ' ';
        for (i = 0; i < 700 && o < sizeof text - 8; i++)
            text[o++] = 'v';
        text[o++] = '\n';
        text[o++] = 'b';
        text[o++] = ' ';
        text[o++] = '=';
        text[o++] = ' ';
        for (i = 0; i < 100 && o < sizeof text - 8; i++) {
            text[o++] = '$';
            text[o++] = 'a';
        }
        text[o++] = '\n';
        text[o] = '\0';
        fixture("expand.too_long", text, "default", "b");
    }
}

static void s_win32(void)
{
    const char *comments =
        "# full line\n"
        "key = val # trailing\n"
        "; semicolon line\n"
        "k2 = v2 ; semicolon here\n"
        "hash = a#b\n";
    const char *quotes =
        "q4 = \"g\"\"h\"\n"
        "q5 = 'i\"j'\n"
        "q6 = \"k'l\"\n";
    const struct {
        const char *name;
        const char *text;
        const char *group;
        const char *key;
    } cases[] = {
        { "win.comments", comments, "default", "key" },
        { "win.comment_hash_is_key", comments, "default", "hash" },
        { "win.comment_semicolon_line", comments, "default", "# full line" },
        { "win.quotes", quotes, "default", "q4" },
        { "win.quotes.single", quotes, "default", "q5" },
        { "win.quotes.both", quotes, "default", "q6" },
    };
    size_t i;

    for (i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        long eline = -1;
        int ret = 2;
        CONF *c = NCONF_new(NCONF_WIN32());
        BIO *b = mem(cases[i].text);

        CASE(cases[i].name);
        ret = NCONF_load_bio(c, b, &eline);
        BIO_free(b);
        oi("ret", ret);
        oi("eline", eline);
        os("lookup", NCONF_get_string(c, cases[i].group, cases[i].key));
        dump_conf(c);
        errdump("err");
        NCONF_free(c);
    }
}

static void s_number(void)
{
    const char *text =
        "[default]\n"
        "n1 = 42\n"
        "n2 = 42abc\n"
        "n3 = abc\n"
        "n4 =\n"
        "n5 = -1\n"
        "n6 = 0\n"
        "n7 = 007\n"
        "n8 = 9223372036854775807\n"
        "n9 = 9223372036854775808\n"
        "n10 = '99'\n"
        "n11 = 1 2\n";
    static const char *keys[] = {
        "n1", "n2", "n3", "n4", "n5", "n6", "n7", "n8", "n9", "n10", "n11"
    };
    long eline = -1;
    int ret = 2;
    CONF *c = load_mem(text, &eline, &ret);
    size_t i;
    char k[16];

    CASE("number");
    oi("load", ret);
    for (i = 0; i < sizeof keys / sizeof keys[0]; i++) {
        long out = -12345;
        int r = NCONF_get_number_e(c, "default", keys[i], &out);

        snprintf(k, sizeof k, "%s.ret", keys[i]);
        oi(k, r);
        snprintf(k, sizeof k, "%s.out", keys[i]);
        oi(k, out);
        snprintf(k, sizeof k, "%s.err", keys[i]);
        errdump(k);
    }
    /* The mark/pop wrapper hides both the failure and the reason. */
    oi("classic.get_number.missing", CONF_get_number(NULL, "default", "nope"));
    oi("classic.get_number.present", CONF_get_number(NULL, "default", "n1"));
    errdump("classic.err");
    {
        LHASH_OF(CONF_VALUE) *h = NULL;

        /* `CONF_get_number` needs a hash, not a CONF; the probe's own hash is
         * built below in `s_classic`, so this only checks the NULL-hash path. */
        oi("classic.get_number.null_hash", CONF_get_number(h, "default", "n1"));
        errdump("classic.err.null_hash");
    }
    NCONF_free(c);
}

static void s_names(void)
{
    const char *text =
        "[zeta]\nz = 1\n"
        "[alpha]\na = 1\n"
        "[ENV]\ne = 1\n"
        "[middle]\nm = 1\n";
    long eline = -1;
    int ret = 2;
    CONF *c = load_mem(text, &eline, &ret);
    STACK_OF(OPENSSL_CSTRING) *names;
    int n, i;

    CASE("names");
    oi("load", ret);
    names = NCONF_get_section_names(c);
    n = names ? OPENSSL_sk_num((const OPENSSL_STACK *)names) : -1;
    oi("count", n);
    for (i = 0; i < n; i++) {
        char k[24];

        snprintf(k, sizeof k, "%02d", i);
        os(k, (const char *)OPENSSL_sk_value((const OPENSSL_STACK *)names, i));
    }
    /* The stack is sorted, and the sort flag says so rather than recomputing. */
    oi("is_sorted", names ? OPENSSL_sk_is_sorted((const OPENSSL_STACK *)names) : -1);
    OPENSSL_sk_free((OPENSSL_STACK *)names);
    NCONF_free(c);
}

static int list_count;
static char list_log[1024];

static int list_cb(const char *elem, int len, void *usr)
{
    char piece[128];

    (void)usr;
    if (elem == NULL) {
        snprintf(piece, sizeof piece, "<NULL>:%d", len);
    } else if (len < 0 || len > (int)sizeof piece - 1) {
        snprintf(piece, sizeof piece, "<len %d>", len);
    } else {
        int i;

        for (i = 0; i < len; i++)
            piece[i] = elem[i];
        piece[len] = '\0';
    }
    if (list_count < 40) {
        size_t o = strlen(list_log);

        snprintf(list_log + o, sizeof list_log - o, "%s;", piece);
    }
    list_count++;
    return 1;
}

static int list_cb_stop(const char *elem, int len, void *usr)
{
    (void)elem;
    (void)len;
    (void)usr;
    return -3;
}

static void s_parselist(void)
{
    static const struct {
        const char *name;
        const char *list;
        int sep;
        int nospc;
    } cases[] = {
        { "plain", "a,b,c", ',', 0 },
        { "trailing", "a,", ',', 0 },
        { "leading", ",a", ',', 0 },
        { "double", "a,,b", ',', 0 },
        { "empty", "", ',', 0 },
        { "spaces", "  a , b  ,c", ',', 1 },
        { "spaces.off", "  a , b  ,c", ',', 0 },
        { "allspace", "   ", ',', 1 },
        { "colon", "a:b", ':', 0 },
        { "nosep", "abc", ',', 0 },
        { "onlysep", ",", ',', 0 },
    };
    size_t i;

    for (i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        CASE(cases[i].name);
        list_count = 0;
        list_log[0] = '\0';
        oi("ret", CONF_parse_list(cases[i].list, cases[i].sep, cases[i].nospc,
                                  list_cb, NULL));
        oi("count", list_count);
        os("log", list_log);
    }
    CASE("parselist.null");
    oi("ret", CONF_parse_list(NULL, ',', 0, list_cb, NULL));
    errdump("err");
    CASE("parselist.stop");
    oi("ret", CONF_parse_list("a,b", ',', 0, list_cb_stop, NULL));
    /*
     * NOT MEASURED: `CONF_parse_list("a,b", ',', 0, NULL, NULL)`. The authority
     * calls the NULL callback on the first element and faults; the candidate
     * treats a NULL callback as "nothing to deliver to" and returns 0, which is
     * the same recorded divergence class as a NULL `doall` thunk in `RT-LHASH`.
     */
    CASE("parselist.nocb");
    printf("%s.value=NOT_MEASURED_AUTHORITY_FAULTS\n", cur);
}

/* ------------------------------------------------------------------------- */
/* The caller-owned hash API.                                                 */
/* ------------------------------------------------------------------------- */

/*
 * `CONF_load` takes an `LHASH_OF(CONF_VALUE) *` the caller created, and the
 * parser inserts through *that* hash's registered functions. The classic API is
 * therefore only reproducible if the probe's own hash and comparison functions
 * match the authority's internal ones — which they can, because
 * `OPENSSL_LH_strhash` is public and the ordering rule is documented by
 * observation. Reproducing them here is what makes the dump comparison in this
 * section meaningful.
 */
static unsigned long probe_conf_hash(const CONF_VALUE *v)
{
    return (OPENSSL_LH_strhash(v->section) << 2) ^ OPENSSL_LH_strhash(v->name);
}

static int probe_conf_cmp(const CONF_VALUE *a, const CONF_VALUE *b)
{
    int i;

    if (a->section != b->section) {
        i = strcmp(a->section, b->section);
        if (i != 0)
            return i;
    }
    if (a->name != NULL && b->name != NULL)
        return strcmp(a->name, b->name);
    if (a->name == b->name)
        return 0;
    return (a->name == NULL) ? -1 : 1;
}

static void s_classic(void)
{
    LHASH_OF(CONF_VALUE) *h;
    LHASH_OF(CONF_VALUE) *loaded;
    CONF_VALUE probe;

    CASE("classic");
    h = lh_CONF_VALUE_new(probe_conf_hash, probe_conf_cmp);
    oi("new.nonnull", h != NULL);

    /* An empty hash answers nothing, and `CONF_get_string` on a NULL hash reads
     * the environment instead of the model. */
    oi("empty.get_section.null", CONF_get_section(h, "default") == NULL);
    oi("empty.get_string.null", CONF_get_string(h, "default", "k") == NULL);
    setenv("OPENSSL_RS_CONF_PROBE", "from-env", 1);
    os("null_hash.get_string.env", CONF_get_string(NULL, "default",
                                                   "OPENSSL_RS_CONF_PROBE"));
    os("null_hash.get_string.other", CONF_get_string(NULL, "default", "nope"));
    errdump("null_hash.err");

    loaded = CONF_load(h, SCRATCH "/plain.cnf", NULL);
    oi("load.returns_input_hash", loaded == h);
    h = loaded != NULL ? loaded : h;

    os("get_string.inc", CONF_get_string(h, "inc", "from_include"));
    os("get_string.nested", CONF_get_string(h, "nested", "deep"));
    oi("get_string.missing", CONF_get_string(h, "inc", "nope") == NULL);

    /* Look up through the hash directly, which is what the caller owns. */
    probe.section = (char *)"inc";
    probe.name = (char *)"from_include";
    probe.value = NULL;
    oi("retrieve.direct", lh_CONF_VALUE_retrieve(h, &probe) != NULL);
    oi("num_items", OPENSSL_LH_num_items((OPENSSL_LHASH *)h) != 0);

    {
        BIO *b = BIO_new(BIO_s_mem());
        char buf[4096];
        int n;

        oi("dump.ret", CONF_dump_bio(h, b));
        n = BIO_read(b, buf, (int)sizeof buf - 1);
        if (n < 0)
            n = 0;
        buf[n] = '\0';
        os("dump.text", buf);
        BIO_free(b);
    }
    oi("get_number.present", CONF_get_number(h, "inc", "from_include"));
    errdump("get_number.err");
    CONF_free(h);
    /* A NULL hash is accepted by `CONF_free`. */
    CONF_free(NULL);
    oi("free.null_is_safe", 1);

    /* A missing file is the documented failure, and the hash is untouched. */
    CASE("classic.missing");
    h = lh_CONF_VALUE_new(probe_conf_hash, probe_conf_cmp);
    oi("load", CONF_load(h, SCRATCH "/nosuchfile.cnf", NULL) == NULL);
    errdump("err");
    CONF_free(h);
}

static void s_defaultcfg(void)
{
    char *p;

    CASE("defaultcfg");
    setenv("OPENSSL_CONF", "/tmp/openssl-rs-probe.cnf", 1);
    p = CONF_get1_default_config_file();
    os("env", p);
    oi("env.nonnull", p != NULL);
    OPENSSL_free(p);

    setenv("OPENSSL_CONF", "", 1);
    p = CONF_get1_default_config_file();
    os("env_empty", p);
    oi("env_empty.nonnull", p != NULL);
    OPENSSL_free(p);

    unsetenv("OPENSSL_CONF");
    /*
     * With no `OPENSSL_CONF`, the authority answers with its own build's
     * `OPENSSLDIR`, which is a forensic-build path this candidate deliberately
     * does not claim (`OBL-CONF-DEFAULT-CONFIG-FILE`, Phase 16; the same decision
     * `init.rs` records for `OpenSSL_version(OPENSSL_DIR)`). The value is
     * therefore *not* printed: both sides print this label instead, which is the
     * same idiom `RT-LHASH` uses for the boundary it cannot compare.
     */
    p = CONF_get1_default_config_file();
    oi("unset.nonnull", p != NULL);
    printf("%s.unset=RECORDED_DIVERGENCE_OBL_CONF_DEFAULT_CONFIG_FILE\n", cur);
    OPENSSL_free(p);
}

int main(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    make_fixtures();

    s_methods();
    s_fresh();
    s_parse();
    s_errors();
    s_pragma();
    s_win32();
    s_number();
    s_names();
    s_parselist();
    s_classic();
    s_defaultcfg();

    printf("probe.done=1\n");
    return 0;
}
