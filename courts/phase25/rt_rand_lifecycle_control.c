/*
 * openssl-rs — Phase 25 B69 negative control: the per-libctx RAND slot lifecycle
 * (`ossl_rand_ctx_new` / `ossl_rand_ctx_free`) and the default method's
 * `drbg_status` slot.
 *
 * SCOPE. B69 discharges three site-scoped `UNSAFE_FN_DEF` obligations in
 * `src/rand/rand_lib.rs`. This probe is the external control, run against the
 * admitted install and touching no crate source:
 *
 *   1. `OSSL_LIB_CTX_new()` succeeds and `OSSL_LIB_CTX_free()` releases it,
 *      1000 times (each iteration exercises `context_init`'s
 *      `ossl_rand_ctx_new` and `context_deinit_objs`'s `ossl_rand_ctx_free`
 *      through the public context API);
 *   2. `OSSL_LIB_CTX_free(NULL)` is a no-op;
 *   3. `RAND_status()` equals
 *      `EVP_RAND_get_state(RAND_get0_primary(NULL)) == EVP_RAND_STATE_READY`;
 *   4. `RAND_get_rand_method()` returns the default method table
 *      (`RAND_OpenSSL()`), whose `status` slot is non-NULL and, when invoked,
 *      equals `RAND_status()`. The private Rust symbol `drbg_status` has no
 *      dynamic export, so the probe cannot name it; the slot identity is the
 *      observable, and the source construction
 *      (`OSSL_RAND_METH.status = Some(drbg_status)`) is the name binding.
 *
 * A NULL context, a crash, a double-release/no-op failure, a status
 * disagreement, or a missing/replaced `status` slot fails the probe.
 *
 * Build (inside the court only):
 *   cc -std=c11 -O1 -Wall -Wextra -Wno-deprecated-declarations \
 *      -I artifacts/phase2/install/include \
 *      -o court/tmp/closure-b69-rand/rt_rand_lifecycle_control \
 *      courts/phase25/rt_rand_lifecycle_control.c \
 *      -L artifacts/phase2/install/lib -lcrypto \
 *      -Wl,-rpath,/work/artifacts/phase2/install/lib
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <stdio.h>

#define LIFECYCLE_ITERATIONS 1000

static int fail(const char *what, long got)
{
    fprintf(stderr, "FAIL %s (got %ld)\n", what, got);
    ERR_print_errors_fp(stderr);
    return 1;
}

int main(void)
{
    const RAND_METHOD *meth;
    RAND_METHOD *own;
    EVP_RAND_CTX *primary;
    int status, primary_state, expected, method_status;
    int i;

    /* (2) The authority's `ossl_rand_ctx_free` starts with `if (dgbl == NULL)
     * return;`; the public release of a NULL context must likewise be a no-op. */
    OSSL_LIB_CTX_free(NULL);

    /* (1) Each iteration builds and tears down every slot, including slot 5. */
    for (i = 0; i < LIFECYCLE_ITERATIONS; i++) {
        OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();

        if (ctx == NULL) {
            fprintf(stderr, "FAIL OSSL_LIB_CTX_new iteration %d\n", i);
            ERR_print_errors_fp(stderr);
            return 1;
        }
        OSSL_LIB_CTX_free(ctx);
    }

    /* (3) RAND_status is the default method's drbg_status body: it asks the
     * primary DRBG, created on demand, whether it is READY. */
    status = RAND_status();
    primary = RAND_get0_primary(NULL);
    if (primary == NULL)
        return fail("RAND_get0_primary(NULL) returned NULL", -1);
    primary_state = EVP_RAND_get_state(primary);
    expected = (primary_state == EVP_RAND_STATE_READY) ? 1 : 0;
    if ((status != 0) != (expected != 0)) {
        fprintf(stderr,
                "FAIL RAND_status=%d but EVP_RAND_get_state(primary)=%d "
                "(ready=%d)\n",
                status, primary_state, expected);
        return 1;
    }

    /* (4) The default table and its status slot. */
    meth = RAND_get_rand_method();
    own = RAND_OpenSSL();
    if (meth == NULL)
        return fail("RAND_get_rand_method() returned NULL", -1);
    if (own == NULL)
        return fail("RAND_OpenSSL() returned NULL", -1);
    if (meth != own) {
        fprintf(stderr, "FAIL RAND_get_rand_method()=%p != RAND_OpenSSL()=%p\n",
                (const void *)meth, (const void *)own);
        return 1;
    }
    if (meth->status == NULL)
        return fail("default RAND_METHOD.status is NULL", -1);
    if (meth->status != own->status) {
        fprintf(stderr, "FAIL default RAND_METHOD.status slots differ\n");
        return 1;
    }
    method_status = meth->status();
    if (method_status != RAND_status()) {
        fprintf(stderr, "FAIL method->status()=%d != RAND_status()=%d\n",
                method_status, RAND_status());
        return 1;
    }

    printf("PASS rand lifecycle: libctx_new_free=%d free_null_noop=1 "
           "rand_status=%d primary_state=%d primary_ready=%d "
           "method_is_default=1 status_slot_present=1 "
           "method_status=%d method_status_eq_rand_status=1\n",
           LIFECYCLE_ITERATIONS, status, primary_state, expected,
           method_status);
    return 0;
}
