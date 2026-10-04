/*
 * RT-CONFIG — the config loader, over a fixed in-memory configuration, as 16.4
 * lands the CLI's config-loading surface.
 *
 * Compiled twice (authority and candidate), run, and the two transcripts
 * compared line by line, keyed on `key=value`. The probe drives the loader the
 * `openssl` CLI stands on — `NCONF_new`/`NCONF_load_bio` over a memory BIO,
 * `NCONF_get_string`/`NCONF_get_number`, `NCONF_get_section` — and the CLI's
 * default configuration file (`CONF_get1_default_config_file`), which Phase
 * 16.3's `ossl_get_openssldir` answers.
 *
 * Everything runs from an in-memory BIO except the default-file arm, which is
 * controlled by `OPENSSL_CONF` so both runs see the same value. The unset-
 * `OPENSSL_CONF` arm answers the build's own `OPENSSLDIR` prefix, a distribution
 * fact this candidate does not claim (docs/PHASE-16-SUBPHASES.md §3.2), so the
 * probe records the boundary (`RECORDED_DIVERGENCE_OBL_CONF_DEFAULT_CONFIG_FILE`)
 * rather than printing the raw path.
 *
 * No wall clock, no network, no address, no allocation count, and no error-queue
 * read (the queue's file/line coordinates are a different observation and are
 * RT-CONF's).
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/bio.h>
#include <openssl/conf.h>

static void oi(const char *k, long v)
{
    printf("%s=%ld\n", k, v);
}

static void os(const char *k, const char *v)
{
    printf("%s=[%s]\n", k, v != NULL ? v : "<NULL>");
}

/* A fixed in-memory configuration exercising the grammar the loader reads. */
static const char CONFIG_TEXT[] =
    "# a leading comment\n"
    "[one]\n"
    "alpha = first\n"
    "beta  = 42\n"
    "quoted = \"two words\"\n"
    "empty =\n"
    "\n"
    "[two]\n"
    "gamma = x=y\n"
    "continued = a\\\n"
    "b\n";

static CONF *load_mem(const char *text, int *ret)
{
    CONF *c = NCONF_new(NULL);
    BIO *b = BIO_new_mem_buf(text, -1);
    long eline = -1;

    if (c == NULL || b == NULL) {
        BIO_free(b);
        NCONF_free(c);
        *ret = -1;
        return NULL;
    }
    *ret = NCONF_load_bio(c, b, &eline);
    oi("load.eline_zero", eline == 0);
    BIO_free(b);
    return c;
}

static void dump_section(CONF *c, const char *name)
{
    STACK_OF(CONF_VALUE) *sk = NCONF_get_section(c, name);
    int i, n = sk != NULL ? sk_CONF_VALUE_num(sk) : -1;

    oi("section.present", sk != NULL);
    if (sk == NULL)
        return;
    oi("section.count", n);
    for (i = 0; i < n; i++) {
        const CONF_VALUE *v = sk_CONF_VALUE_value(sk, i);
        printf("section.row.%d=[%s|%s]\n", i, v->name, v->value);
    }
}

int main(void)
{
    CONF *c;
    int ret = 0;
    long num = 0;
    char *p;

    setvbuf(stdout, NULL, _IOLBF, 0);

    /* --- fresh configuration: getters against no data --- */
    c = NCONF_new(NULL);
    oi("fresh.nonnull", c != NULL);
    if (c != NULL) {
        os("fresh.string", NCONF_get_string(c, "nope", "nope"));
        oi("fresh.number_ok", NCONF_get_number(c, "nope", "nope", &num));
    }
    NCONF_free(c);

    /* --- parse the fixed in-memory configuration --- */
    c = load_mem(CONFIG_TEXT, &ret);
    oi("parse.ret_ok", ret == 1);
    if (c != NULL) {
        os("one.alpha", NCONF_get_string(c, "one", "alpha"));
        os("one.beta", NCONF_get_string(c, "one", "beta"));
        os("one.quoted", NCONF_get_string(c, "one", "quoted"));
        os("one.empty", NCONF_get_string(c, "one", "empty"));
        os("one.missing", NCONF_get_string(c, "one", "missing"));
        os("two.gamma", NCONF_get_string(c, "two", "gamma"));
        os("two.continued", NCONF_get_string(c, "two", "continued"));
        oi("two.number_ok", NCONF_get_number(c, "two", "gamma", &num));
        oi("one.number_ok", NCONF_get_number(c, "one", "beta", &num));
        oi("one.number_value", num);
        dump_section(c, "one");
        dump_section(c, "two");
        dump_section(c, "absent");
    }
    NCONF_free(c);

    /* --- the CLI's default configuration file, controlled by OPENSSL_CONF --- */
    setenv("OPENSSL_CONF", "/tmp/openssl-rs-phase16.cnf", 1);
    p = CONF_get1_default_config_file();
    os("default.env", p);
    oi("default.env_nonnull", p != NULL);
    OPENSSL_free(p);

    unsetenv("OPENSSL_CONF");
    p = CONF_get1_default_config_file();
    oi("default.unset_nonnull", p != NULL);
    printf("default.unset=RECORDED_DIVERGENCE_OBL_CONF_DEFAULT_CONFIG_FILE\n");
    OPENSSL_free(p);

    printf("probe.done=1\n");
    return 0;
}
