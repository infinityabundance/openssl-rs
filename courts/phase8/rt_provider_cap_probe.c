/*
 * RT-PROVIDER-CAP -- the default provider's third dispatch-table face: `GETTABLE_PARAMS`,
 * `GET_PARAMS` and `GET_CAPABILITIES`.
 *
 * This program is compiled **twice**, once against the admitted authority and once against the
 * candidate distribution shell, and the two `key=value` transcripts are diffed line by line. It
 * never decides anything: a residual is a difference between two executions, so the expectation
 * cannot drift. `forensics/tools/phase8_courts.py` owns the comparison.
 *
 * ## Why this court exists
 *
 * The default provider's dispatch table in the authority publishes five entries
 * (`forensics/authorities/src/openssl-3.6.4/providers/defltprov.c:742-750`):
 *
 *     OSSL_FUNC_PROVIDER_TEARDOWN
 *     OSSL_FUNC_PROVIDER_GETTABLE_PARAMS   -> deflt_gettable_params (defltprov.c:46)
 *     OSSL_FUNC_PROVIDER_GET_PARAMS        -> deflt_get_params      (defltprov.c:51)
 *     OSSL_FUNC_PROVIDER_QUERY_OPERATION
 *     OSSL_FUNC_PROVIDER_GET_CAPABILITIES  -> ossl_prov_get_capabilities
 *                                            (providers/common/capabilities.c:334)
 *
 * The candidate's default dispatch **published** `QUERY_OPERATION` and `TEARDOWN` only
 * (`src/provider/digest.rs`, whose own note named the three missing arms as the D117 residual)
 * until D411 landed them, so the arms in the first three lines above were absent and the public
 * entry points that reach them are the ones this court drives. Those entry points all exist on the
 * candidate --
 * `OSSL_PROVIDER_gettable_params`, `OSSL_PROVIDER_get_params` and
 * `OSSL_PROVIDER_get_capabilities` (`src/provider/mod.rs:2386/2400/2498`) -- and are already
 * wired to the provider vtable, so **before D411 each answered the "no such
 * function" path** of the core (`crypto/provider_core.c:1767/1810/1903`):
 *
 *   * `gettable_params` answers **NULL** (`prov->gettable_params == NULL`);
 *   * `get_params` answers **0** (`prov->get_params == NULL`);
 *   * `get_capabilities` answers **1** and never invites the callback
 *     (`prov->get_capabilities == NULL` returns 1, capabilities.c's `0` for an unclaimed name is
 *     therefore unreachable).
 *
 * **D411 landed those three arms** -- `deflt_get_params`/`deflt_gettable_params` in
 * `src/provider/digest.rs` and `ossl_prov_get_capabilities` in `src/provider/capabilities.rs`, all
 * three published by `DEFLT_DISPATCH`. **This court is the arm that drives them**, and its
 * pre-landing answers are exactly the three above: it is not enough for the symbols to be
 * present, they must dispatch to a provider that answers the authority's values. Every "before the
 * arm landed" sentence below is that record, kept rather than rewritten: it is what makes each
 * arm load-bearing, because an observation that would have been the same either way discriminates
 * nothing.
 *
 * ## What each arm observes, and what it would have shown before the arms landed
 *
 *   1. **The load.** `OSSL_PROVIDER_load(NULL, "default")`; observed as non-NULL. The whole court
 *      is skipped, with `cap.load.notnull=0`, if the default provider will not load, so a missing
 *      provider is a residual rather than a crash.
 *   2. **`TLS-GROUP`.** `OSSL_PROVIDER_get_capabilities(prov, "TLS-GROUP", cb, &state)`. The
 *      authority's `tls_group_capability` (`capabilities.c:260`) walks `param_group_list[][11]`
 *      (`capabilities.c:153`) and hands the callback **one `OSSL_PARAM[]` per group entry**. For
 *      each entry the probe prints the entry index, the number of parameters in the entry, and
 *      then one `cap.group.<i>.p.<j>` line per parameter carrying `name|data_type|data_size|value`.
 *      The array is `[11]` because it holds ten parameters plus the `OSSL_PARAM_END` terminator
 *      (`capabilities.c:96-122`); the probe prints the count it actually walks (`10`) rather than
 *      assuming it. Values are the three UTF-8 name strings and the seven integers (`id`,
 *      `sec-bits`, the four TLS/DTLS version bounds, `is-kem`); integers print as decimal and
 *      strings print with their length, because a group alias repeats every field but the first
 *      (`capabilities.c:124-135`) and the length is what distinguishes e.g. `secp256r1` from
 *      `P-256`. Before the arm landed this answered `cap.group.ret=1` with `cap.group.count=0`
 *      and no entry lines at all.
 *   3. **`TLS-SIGALG`.** The same treatment over `tls_sigalg_capability` (`capabilities.c:322`)
 *      and `param_sigalg_list[][10]` (`capabilities.c:315`): nine parameters plus the terminator,
 *      and **three entries** (ML-DSA-44/65/87). Before the arm landed, `cap.sigalg.count=0`.
 *   4. **The callback refusal.** `TLS-GROUP` again with a callback that returns 0 on the first
 *      entry. The walk's own contract is `if (!cb(...)) return 0;` (`capabilities.c:265-267`), so
 *      `OSSL_PROVIDER_get_capabilities` must answer **0** and the callback must have been invited
 *      **once**. This is what distinguishes a real walk over a producer's array from a table dump
 *      the core fabricated: a dump would have to return the whole table regardless of the
 *      callback's verdict. Before the arm landed this answered `ret=1` and `calls=0`.
 *   5. **An unsupported capability.** `"NOT-A-CAPABILITY"` is claimed by no arm, so
 *      `ossl_prov_get_capabilities` falls through to `return 0` (`capabilities.c:342-343`) and the
 *      callback is never invited. Before the arm landed the missing `get_capabilities` made the
 *      core answer **1**, which is the one arm whose pre-landing answer is *wrong on its face*
 *      rather than merely empty.
 *   6. **`gettable_params` and `get_params`.** `OSSL_PROVIDER_gettable_params(prov)` is the
 *      authority's `deflt_param_types` (`defltprov.c:38-44`): name, version, buildinfo and status,
 *      each declared as a definition (`data_size == 0`, `data == NULL`). The probe prints each
 *      name, `data_type` and `data_size`, then builds its own request array with the public
 *      `OSSL_PARAM_construct_*` constructors -- `OSSL_PROV_PARAM_NAME`, `OSSL_PROV_PARAM_VERSION`,
 *      `OSSL_PROV_PARAM_BUILDINFO`, `OSSL_PROV_PARAM_STATUS`, and one key no arm sets -- calls
 *      `OSSL_PROVIDER_get_params`, and prints the return, and for each request whether it was
 *      filled (`return_size` moved off `OSSL_PARAM_UNMODIFIED`), its `data_type` and its value.
 *      `deflt_get_params` (`defltprov.c:51`) answers the four known keys and leaves the unknown
 *      one untouched, so the fifth line is the contract's own "not filled" answer rather than a
 *      missing arm. Finally it calls `get_params` with an array whose index 0 is `OSSL_PARAM_END`,
 *      which `OSSL_PARAM_locate` walks as the empty array: the authority answers **1**. Before the
 *      arm landed `gettable_params` answered NULL and both `get_params` calls answered 0.
 *
 * ## Nothing non-deterministic reaches the transcript
 *
 * No pointer, address, time or environment value is ever printed. Every observation is a return
 * code, a count, a `data_type` constant, a `data_size`, a boolean (`return_size` moved) or a value
 * the provider itself published: `name = "OpenSSL Default Provider"`, `version = "3.6.4"`,
 * `buildinfo = "3.6.4"` and `status = 1`, all of which are compile-time constants of the
 * authority (`defltprov.c:56-65`). Two runs of one side agree byte for byte; the comparison is a
 * line-wise `key=value` diff over exactly that property.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/provider.h>

/* The state a capability walk carries through its callback. The tag names the arm (`group` or
 * `sigalg`), `index` counts entries the callback has been shown, and `calls` counts invocations
 * even for an arm that prints nothing. The struct is the probe's own; no pointer is printed. */
struct cap_walk {
    const char *tag;
    int index;
    int calls;
};

/* One parameter's whole observable surface, on one line, keyed by the arm, the entry index and
 * the parameter position: `name|data_type|data_size|value`. A string prints as
 * `s<strlen>:<bytes>` and an integer as `u<decimal>`/`i<decimal>`, so the length a store alias
 * depends on is carried explicitly. The value therefore contains no `=`, and the line
 * partitions at the key's single `=`. */
static void print_param(const char *tag, int i, int j, const OSSL_PARAM *p)
{
    if (p->data_type == OSSL_PARAM_UTF8_STRING) {
        const char *s = (const char *)p->data;
        printf("cap.%s.%d.p.%d=%s|%u|%zu|s%zu:%s\n", tag, i, j, p->key,
               (unsigned int)p->data_type, p->data_size,
               s != NULL ? strlen(s) : (size_t)0, s != NULL ? s : "(null)");
    } else if (p->data_type == OSSL_PARAM_UTF8_PTR) {
        const char *s = NULL;

        OSSL_PARAM_get_utf8_ptr(p, &s);
        printf("cap.%s.%d.p.%d=%s|%u|%zu|s%zu:%s\n", tag, i, j, p->key,
               (unsigned int)p->data_type, p->data_size,
               s != NULL ? strlen(s) : (size_t)0, s != NULL ? s : "(null)");
    } else if (p->data_type == OSSL_PARAM_UNSIGNED_INTEGER) {
        unsigned int u = 0;

        OSSL_PARAM_get_uint(p, &u);
        printf("cap.%s.%d.p.%d=%s|%u|%zu|u%u\n", tag, i, j, p->key,
               (unsigned int)p->data_type, p->data_size, u);
    } else if (p->data_type == OSSL_PARAM_INTEGER) {
        int v = 0;

        OSSL_PARAM_get_int(p, &v);
        printf("cap.%s.%d.p.%d=%s|%u|%zu|i%d\n", tag, i, j, p->key,
               (unsigned int)p->data_type, p->data_size, v);
    } else {
        printf("cap.%s.%d.p.%d=%s|%u|%zu|type%u\n", tag, i, j, p->key,
               (unsigned int)p->data_type, p->data_size, (unsigned int)p->data_type);
    }
}

/* The recording callback: print one entry, accept every one. The array is terminated by
 * `OSSL_PARAM_END` (`key == NULL`), the same terminator the producer's own `TLS_GROUP_ENTRY`
 * macro appends. */
static int cap_print_cb(const OSSL_PARAM params[], void *arg)
{
    struct cap_walk *w = arg;
    int i = w->index;
    int j;
    int n = 0;

    w->calls++;
    while (params[n].key != NULL)
        n++;
    printf("cap.%s.%d.count=%d\n", w->tag, i, n);
    for (j = 0; j < n; j++)
        print_param(w->tag, i, j, &params[j]);
    w->index++;
    return 1;
}

/* The refusing callback: count the entry then return 0, which ends the walk. */
static int cap_refuse_cb(const OSSL_PARAM params[], void *arg)
{
    struct cap_walk *w = arg;

    (void)params;
    w->calls++;
    return 0;
}

/* One entry of the probe's own request array: whether the provider moved `return_size` off
 * `OSSL_PARAM_UNMODIFIED`, the declared `data_type`, and the value only when it did. Reading the
 * value only after the filled check is what keeps the unfilled key from dereferencing a pointer
 * the provider never wrote. */
static void print_request(const char *key, const OSSL_PARAM *p)
{
    printf("%s.filled=%d\n", key, p->return_size != OSSL_PARAM_UNMODIFIED);
    printf("%s.type=%u\n", key, (unsigned int)p->data_type);
    if (p->return_size == OSSL_PARAM_UNMODIFIED) {
        printf("%s.value=(unset)\n", key);
    } else if (p->data_type == OSSL_PARAM_UTF8_PTR) {
        const char *s = NULL;

        OSSL_PARAM_get_utf8_ptr(p, &s);
        printf("%s.value=s%zu:%s\n", key, s != NULL ? strlen(s) : (size_t)0,
               s != NULL ? s : "(null)");
    } else if (p->data_type == OSSL_PARAM_INTEGER) {
        int v = 0;

        OSSL_PARAM_get_int(p, &v);
        printf("%s.value=i%d\n", key, v);
    } else {
        printf("%s.value=type%u\n", key, (unsigned int)p->data_type);
    }
}

int main(void)
{
    OSSL_PROVIDER *prov;
    struct cap_walk group = { "group", 0, 0 };
    struct cap_walk sigalg = { "sigalg", 0, 0 };
    struct cap_walk refuse = { "group.refuse", 0, 0 };
    struct cap_walk unsupported = { "unsupported", 0, 0 };
    const OSSL_PARAM *gt;
    char *v_name = NULL;
    char *v_version = NULL;
    char *v_buildinfo = NULL;
    int v_status = -1;
    int v_unknown = -1;
    OSSL_PARAM req[6];
    OSSL_PARAM empty[1] = { OSSL_PARAM_END };
    int r;
    int j;
    int n;

    /* ---- 1. the load ---- */

    prov = OSSL_PROVIDER_load(NULL, "default");
    printf("cap.load.notnull=%d\n", prov != NULL);
    if (prov == NULL) {
        printf("cap.done=0\n");
        return 0;
    }

    /* ---- 2. the TLS-GROUP capability, recorded in full ---- */

    r = OSSL_PROVIDER_get_capabilities(prov, "TLS-GROUP", cap_print_cb, &group);
    printf("cap.group.ret=%d\n", r);
    printf("cap.group.count=%d\n", group.index);
    printf("cap.group.calls=%d\n", group.calls);

    /* ---- 3. the TLS-SIGALG capability, recorded in full ---- */

    r = OSSL_PROVIDER_get_capabilities(prov, "TLS-SIGALG", cap_print_cb, &sigalg);
    printf("cap.sigalg.ret=%d\n", r);
    printf("cap.sigalg.count=%d\n", sigalg.index);
    printf("cap.sigalg.calls=%d\n", sigalg.calls);

    /* ---- 4. the walk's refusal contract ---- */

    r = OSSL_PROVIDER_get_capabilities(prov, "TLS-GROUP", cap_refuse_cb, &refuse);
    printf("cap.group.refuse.ret=%d\n", r);
    printf("cap.group.refuse.calls=%d\n", refuse.calls);

    /* ---- 5. a capability no arm claims ---- */

    r = OSSL_PROVIDER_get_capabilities(prov, "NOT-A-CAPABILITY", cap_print_cb, &unsupported);
    printf("cap.unsupported.ret=%d\n", r);
    printf("cap.unsupported.calls=%d\n", unsupported.calls);

    /* ---- 6a. gettable_params: the provider's own definitions ---- */

    gt = OSSL_PROVIDER_gettable_params(prov);
    printf("cap.gt.notnull=%d\n", gt != NULL);
    n = 0;
    if (gt != NULL)
        while (gt[n].key != NULL)
            n++;
    printf("cap.gt.count=%d\n", n);
    for (j = 0; j < n; j++) {
        printf("cap.gt.%d.name=%s\n", j, gt[j].key);
        printf("cap.gt.%d.type=%u\n", j, (unsigned int)gt[j].data_type);
        printf("cap.gt.%d.size=%zu\n", j, gt[j].data_size);
    }

    /* ---- 6b. get_params: four keys an arm answers and one it does not ---- */

    req[0] = OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_NAME, &v_name, 0);
    req[1] = OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_VERSION, &v_version, 0);
    req[2] = OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_BUILDINFO, &v_buildinfo, 0);
    req[3] = OSSL_PARAM_construct_int(OSSL_PROV_PARAM_STATUS, &v_status);
    req[4] = OSSL_PARAM_construct_int("openssl-rs-no-such-provider-param", &v_unknown);
    req[5] = OSSL_PARAM_construct_end();

    r = OSSL_PROVIDER_get_params(prov, req);
    printf("cap.gp.ret=%d\n", r);
    for (j = 0; j < 5; j++) {
        char key[16];

        snprintf(key, sizeof(key), "cap.gp.%d", j);
        print_request(key, &req[j]);
    }

    /* ---- 6c. get_params with an array that is END at index 0 ---- */

    r = OSSL_PROVIDER_get_params(prov, empty);
    printf("cap.gp.empty.ret=%d\n", r);

    printf("cap.done=1\n");
    OSSL_PROVIDER_unload(prov);
    return 0;
}
