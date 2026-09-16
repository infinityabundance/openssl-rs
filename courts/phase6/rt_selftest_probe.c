/*
 * RT-SELFTEST -- the self-test and indicator callback surfaces, differentially.
 *
 * What this court has to establish
 * --------------------------------
 * The probe *is* the callback. Both surfaces are callback plumbing, so the only
 * way to observe them is to register a callback and record what the library passes
 * it, when, and with what return value flowing back. That makes four things
 * observable, and all four are places a plausible transcription differs:
 *
 *   * **the array's entries alias the object's own fields.** `st-phase`, `st-type`
 *     and `st-desc` are built with `OSSL_PARAM_construct_utf8_string(key,
 *     st->field, 0)`, which stores the *address* of the field, not a copy of the
 *     string. `OSSL_SELF_TEST_onend` reassigns all three fields to the string
 *     `"None"` after invoking the callback and does **not** rebuild the array, so
 *     the same array read inside the callback reports `Pass` and read afterwards
 *     reports `None`. The probe stashes the array pointer inside the callback and
 *     reads through it again after the call, which is the only way a C caller can
 *     see the aliasing at all.
 *   * **`onend` treats anything other than 1 as a failure.** 0 and -1 both report
 *     `Fail`.
 *   * **`oncorrupt_byte`'s answer is the callback's, inverted.** The callback
 *     returning 0 makes the first byte be flipped and the call report 1; returning
 *     1 leaves the byte alone and reports 0.
 *   * **both callback pairs are per context**, and both getters skip a NULL output
 *     pointer rather than writing through it. The self-test *object*'s callback is
 *     the one passed to `OSSL_SELF_TEST_new`, **not** the context's — the
 *     context's is what other code invokes, and conflating the two would be a
 *     transcription error the probe can see.
 *
 * Addresses are never printed. Every callback observation is a relation or a
 * string, and every callback *identity* observation is an equality against the
 * pointer the probe passed in.
 *
 * Fault boundaries
 * ----------------
 * `OSSL_SELF_TEST_oncorrupt_byte` with a NULL `bytes` and a refusing callback
 * dereferences NULL in the authority. The probe does not call it, and the
 * candidate's safer answer is recorded in `docs/SECURITY_DIVERGENCE_POLICY.md`.
 *
 * Every observation is `key=value` on stdout, one line each, with unique keys. The
 * `err=` field is the packed `ERR_peek_error()` read immediately after the call and
 * cleared before the next, so it belongs to its own call.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/indicator.h>
#include <openssl/params.h>
#include <openssl/self_test.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ reporting */

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

static void sayp(const char *key, const void *p)
{
    printf("%s=%s err=%lu\n", key, p == NULL ? "NULL" : "nonnull",
           ERR_peek_error());
    ERR_clear_error();
}

/* --------------------------------------------------------------- the callbacks */

static int calls;            /* how many times the self-test callback ran */
static int refuse;           /* what the callback answers for oncorrupt_byte */
static const OSSL_PARAM *stashed; /* the array the callback was last given */

/* Reads one UTF-8 entry of the array the callback was handed, or "-" when the key
 * is absent. Used from the callback and again after the call, which is what makes
 * the aliasing visible. */
static void entry(const OSSL_PARAM *params, const char *key, const char *tag)
{
    char buf[64];
    const OSSL_PARAM *p = OSSL_PARAM_locate(params, key);

    if (p == NULL) {
        printf("%s=%s err=%lu\n", tag, "(absent)", ERR_peek_error());
        ERR_clear_error();
        return;
    }
    if (p->data == NULL) {
        printf("%s=%s err=%lu\n", tag, "(nulldata)", ERR_peek_error());
        ERR_clear_error();
        return;
    }
    /* A UTF8_STRING entry's `data` is a NUL-terminated string and `data_size`
     * counts it; the copy is bounded by the destination so a wrong `data_size` is
     * a difference in the value rather than a read past either buffer. */
    {
        size_t n = p->data_size;

        if (n > sizeof buf - 1)
            n = sizeof buf - 1;
        if (n > 0)
            memcpy(buf, p->data, n);
        buf[n] = '\0';
    }
    printf("%s=%s err=%lu\n", tag, buf, ERR_peek_error());
    ERR_clear_error();
}

static int self_test_cb(const OSSL_PARAM params[], void *arg)
{
    char tag[64];

    calls++;
    snprintf(tag, sizeof tag, "cb%d.calls", calls);
    printf("%s=%d err=0\n", tag, calls);
    snprintf(tag, sizeof tag, "cb%d.phase", calls);
    entry(params, OSSL_PROV_PARAM_SELF_TEST_PHASE, tag);
    snprintf(tag, sizeof tag, "cb%d.type", calls);
    entry(params, OSSL_PROV_PARAM_SELF_TEST_TYPE, tag);
    snprintf(tag, sizeof tag, "cb%d.desc", calls);
    entry(params, OSSL_PROV_PARAM_SELF_TEST_DESC, tag);
    snprintf(tag, sizeof tag, "cb%d.arg", calls);
    /* The argument the object was created with, round-tripped. */
    printf("%s=%d err=0\n", tag, arg == (void *)&calls ? 1 : 0);
    stashed = params;
    return refuse ? 0 : 1;
}

static int indicator_cb(const char *type, const char *desc,
    const OSSL_PARAM params[])
{
    printf("indicator.called=%d err=0\n", 1);
    (void)type;
    (void)desc;
    (void)params;
    return 1;
}

int main(void)
{
    OSSL_LIB_CTX *gd, *a, *b;
    OSSL_SELF_TEST *st;
    OSSL_CALLBACK *got_cb;
    void *got_arg;

    setvbuf(stdout, NULL, _IOLBF, 0);

    gd = OSSL_LIB_CTX_get0_global_default();
    a = OSSL_LIB_CTX_new();
    b = OSSL_LIB_CTX_new();
    sayp("gd.nonnull", gd);
    sayp("a.nonnull", a);
    sayp("b.nonnull", b);

    /* ------------------------------------------------- the per-context self-test pair */

    got_cb = (OSSL_CALLBACK *) &calls;
    got_arg = &refuse;
    OSSL_SELF_TEST_get_callback(a, &got_cb, &got_arg);
    sayn("st.fresh.cb.null", got_cb == NULL);
    sayn("st.fresh.arg.null", got_arg == NULL);

    OSSL_SELF_TEST_set_callback(a, self_test_cb, &calls);
    got_cb = NULL;
    got_arg = NULL;
    OSSL_SELF_TEST_get_callback(a, &got_cb, &got_arg);
    sayn("st.set.cb.back", got_cb == self_test_cb);
    sayn("st.set.arg.back", got_arg == (void *)&calls);

    /* Per context: `b` did not move, and neither did the default. */
    got_cb = (OSSL_CALLBACK *) &calls;
    got_arg = &refuse;
    OSSL_SELF_TEST_get_callback(b, &got_cb, &got_arg);
    sayn("st.other.cb.null", got_cb == NULL);
    sayn("st.other.arg.null", got_arg == NULL);
    got_cb = (OSSL_CALLBACK *) &calls;
    got_arg = &refuse;
    OSSL_SELF_TEST_get_callback(NULL, &got_cb, &got_arg);
    sayn("st.default.cb.null", got_cb == NULL);
    sayn("st.default.arg.null", got_arg == NULL);

    /* Each output pointer is optional. */
    got_cb = NULL;
    OSSL_SELF_TEST_get_callback(a, &got_cb, NULL);
    sayn("st.cb.only", got_cb == self_test_cb);
    got_arg = NULL;
    OSSL_SELF_TEST_get_callback(a, NULL, &got_arg);
    sayn("st.arg.only", got_arg == (void *)&calls);

    /* A NULL context is whatever this thread defaults to. */
    sayn("st.dflt.install", OSSL_LIB_CTX_set0_default(a) == gd);
    got_cb = NULL;
    got_arg = NULL;
    OSSL_SELF_TEST_get_callback(NULL, &got_cb, &got_arg);
    sayn("st.dflt.after.set.cb", got_cb == self_test_cb);
    sayn("st.dflt.restore", OSSL_LIB_CTX_set0_default(gd) == a);

    /* Setting NULL removes it. */
    OSSL_SELF_TEST_set_callback(a, NULL, NULL);
    got_cb = (OSSL_CALLBACK *) &calls;
    got_arg = &refuse;
    OSSL_SELF_TEST_get_callback(a, &got_cb, &got_arg);
    sayn("st.cleared.cb.null", got_cb == NULL);
    sayn("st.cleared.arg.null", got_arg == NULL);
    /* Put it back for the object tests below. */
    OSSL_SELF_TEST_set_callback(a, self_test_cb, &calls);

    /* ---------------------------------------------------------- the self-test object */

    /* An object with no callback: every entry point is a no-op and none of them
     * calls the context's callback either. */
    calls = 0;
    st = OSSL_SELF_TEST_new(NULL, NULL);
    sayp("st.null_cb.object", st);
    OSSL_SELF_TEST_onbegin(st, OSSL_SELF_TEST_TYPE_KAT_DIGEST,
                           OSSL_SELF_TEST_DESC_MD_SHA2);
    OSSL_SELF_TEST_onend(st, 1);
    {
        unsigned char byte = 0x01;
        sayn("st.null_cb.oncorrupt", OSSL_SELF_TEST_oncorrupt_byte(st, &byte));
        sayn("st.null_cb.byte", byte);
    }
    sayn("st.null_cb.calls", calls);
    OSSL_SELF_TEST_free(st);
    /* Freeing NULL is a no-op. */
    OSSL_SELF_TEST_free(NULL);
    sayn("st.free.null.ok", 1);

    /* An object with the callback: the phases, the alias, and the corruption. */
    calls = 0;
    refuse = 1;
    stashed = NULL;
    st = OSSL_SELF_TEST_new(self_test_cb, &calls);
    sayp("st.object", st);

    OSSL_SELF_TEST_onbegin(st, OSSL_SELF_TEST_TYPE_KAT_DIGEST,
                           OSSL_SELF_TEST_DESC_MD_SHA2);
    OSSL_SELF_TEST_onend(st, 1);
    /* Read the *same array* again, now that `onend` has reset the fields without
     * rebuilding it. This is the aliasing observation. */
    sayp("st.stash.present", stashed);
    entry(stashed, OSSL_PROV_PARAM_SELF_TEST_PHASE, "st.after.phase");
    entry(stashed, OSSL_PROV_PARAM_SELF_TEST_TYPE, "st.after.type");
    entry(stashed, OSSL_PROV_PARAM_SELF_TEST_DESC, "st.after.desc");

    /* `onend` with anything other than 1 is a failure. */
    OSSL_SELF_TEST_onend(st, 0);
    OSSL_SELF_TEST_onend(st, -1);
    sayn("st.calls.after.onend", calls);

    /* `oncorrupt_byte` with a refusing callback flips the first byte and answers 1. */
    {
        unsigned char byte = 0xa5;

        refuse = 1;
        sayn("st.oncorrupt.refused", OSSL_SELF_TEST_oncorrupt_byte(st, &byte));
        sayn("st.oncorrupt.byte", byte);
        /* And with a callback that accepts, nothing is flipped and the answer is 0. */
        refuse = 0;
        byte = 0xa5;
        sayn("st.oncorrupt.accepted", OSSL_SELF_TEST_oncorrupt_byte(st, &byte));
        sayn("st.oncorrupt.byte.kept", byte);
    }
    /* `oncorrupt_byte` does not touch type or desc, so the callback still sees the
     * empty strings the object was created with. */
    sayn("st.calls.total", calls);
    OSSL_SELF_TEST_free(st);

    /* ------------------------------------------------------------ the indicator pair */

    {
        OSSL_INDICATOR_CALLBACK *igot = (OSSL_INDICATOR_CALLBACK *) &calls;

        OSSL_INDICATOR_get_callback(a, &igot);
        sayn("ind.fresh.null", igot == NULL);
        OSSL_INDICATOR_set_callback(a, indicator_cb);
        igot = NULL;
        OSSL_INDICATOR_get_callback(a, &igot);
        sayn("ind.set.back", igot == indicator_cb);
        /* Per context. */
        igot = (OSSL_INDICATOR_CALLBACK *) &calls;
        OSSL_INDICATOR_get_callback(b, &igot);
        sayn("ind.other.null", igot == NULL);
        /* A NULL out-pointer is skipped. */
        OSSL_INDICATOR_get_callback(a, NULL);
        sayn("ind.null.out.ok", 1);
        /* NULL removes it. */
        OSSL_INDICATOR_set_callback(a, NULL);
        igot = (OSSL_INDICATOR_CALLBACK *) &calls;
        OSSL_INDICATOR_get_callback(a, &igot);
        sayn("ind.cleared.null", igot == NULL);
    }

    /* -------------------------------------------------------------------- cleanup */

    OSSL_LIB_CTX_free(b);
    OSSL_LIB_CTX_free(a);
    sayn("err.empty", ERR_peek_error() == 0);
    printf("done=rt-selftest err=%lu\n", ERR_peek_error());
    return 0;
}
