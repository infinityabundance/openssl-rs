/*
 * RT-CROSS-DSO-STATE — the cross-DSO shared-state contract, measured in both directions.
 *
 * Compiled twice (authority and candidate), run, and the two transcripts compared line
 * by line, keyed on `key=value`. The subject is the *link shape*: the admitted authority
 * links `libssl.so.3` against one shared `libcrypto.so.3` through `DT_NEEDED`, so the
 * crate's internal globals -- the `ERR` queue and the `ssl_conf` configuration store --
 * have one instance. The candidate distribution shell links the crate's whole archive
 * into *both* `libssl.so.3` and `libcrypto.so.3`, so each DSO carries its own copy and
 * the two views need not agree. The court measures that, rather than asserting it.
 *
 * The probe drives the boundary in both directions:
 *
 *   1. **ERR: raise through libssl, read through libcrypto.** `SSL_CTX_new(NULL)` is a
 *      deterministic libssl entry point that raises `ERR_LIB_SSL` (the `SSL_CTX_new_ex`
 *      NULL-method arm). The probe then reads the queue with `ERR_peek_error`/
 *      `ERR_get_error`, both of which resolve to *libcrypto* on either side (neither
 *      libssl exports them). On the authority the libssl-raised error is a member of the
 *      shared queue and is observed; on the candidate it was written to libssl's own
 *      copy and the libcrypto queue is empty. A libcrypto-raised error (`ERR_raise`) read
 *      through libcrypto is the control: it must be observed on both sides.
 *
 *   2. **CONF: store through libcrypto, read through libssl.** `CONF_modules_load_file`
 *      loads `courts/phase17/fixtures/cross_dso.cnf`, whose `ssl_conf` section stores a
 *      `system_default` command set (`MinProtocol = TLSv1.2`) in the library's `ssl_conf`
 *      store. `SSL_CTX_config(ctx, "system_default")` is a libssl entry point that reads
 *      that store. On the authority the store is libcrypto's and libssl reads it, applies
 *      the command and returns 1, so `SSL_CTX_get_min_proto_version` answers TLS1.2; on
 *      the candidate libssl reads its own empty store, refuses with
 *      `SSL_R_INVALID_CONFIGURATION_NAME` and leaves the protocol unset.
 *
 * Every observation printed is a deterministic function of the build: a return value, a
 * packed error code (and its library/reason fields), or an applied protocol version.
 * Nothing reads the clock, the network, an address or a random. The candidate's own
 * answers are the receipt the plan (docs/PHASE-17-SUBPHASES.md section 3.3) requires: the
 * court records the divergence rather than failing on the architecture.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

/* The fixed fixture `CONF_modules_load_file` reads, self-contained under the /work mount. */
#define FIXTURE "/work/courts/phase17/fixtures/cross_dso.cnf"

static void out_int(const char *key, int value)
{
    printf("%s=%d\n", key, value);
}

static void out_hex(const char *key, unsigned long value)
{
    printf("%s=0x%lx\n", key, value);
}

int main(void)
{
    SSL_CTX *ctx, *bad;
    unsigned long e;
    long r;

    setvbuf(stdout, NULL, _IOLBF, 0);

    /* --- 1. ERR: the libcrypto control, then the libssl raise read through libcrypto --- */

    ERR_clear_error();
    ERR_raise(ERR_LIB_USER, 100);
    e = ERR_peek_error();
    out_hex("err.crypto.peek", e);
    out_int("err.crypto.lib", ERR_GET_LIB(e));
    out_int("err.crypto.reason", ERR_GET_REASON(e));
    ERR_clear_error();

    ctx = SSL_CTX_new(TLS_method());
    out_int("ctx.nonnull", ctx != NULL);
    if (ctx == NULL) {
        printf("probe.done=0\n");
        return 0;
    }

    bad = SSL_CTX_new(NULL);
    out_int("err.ssl.null_ret", bad == NULL);
    e = ERR_peek_error();
    out_hex("err.ssl.peek", e);
    out_int("err.ssl.lib", ERR_GET_LIB(e));
    out_int("err.ssl.reason", ERR_GET_REASON(e));
    out_hex("err.ssl.get", ERR_get_error());
    out_hex("err.ssl.after_get", ERR_peek_error());
    ERR_clear_error();

    /* --- 2. CONF: store through libcrypto, read through libssl --- */

    r = CONF_modules_load_file(FIXTURE, NULL, 0);
    out_int("conf.load.ret", (int)r);
    e = ERR_peek_error();
    out_hex("conf.load.peek", e);
    ERR_clear_error();

    out_int("conf.ctx_config.ret", SSL_CTX_config(ctx, "system_default"));
    e = ERR_peek_error();
    out_hex("conf.ctx_config.peek", e);
    out_int("conf.ctx_config.lib", ERR_GET_LIB(e));
    out_int("conf.ctx_config.reason", ERR_GET_REASON(e));
    ERR_clear_error();

    out_int("conf.ctx.min_proto", SSL_CTX_get_min_proto_version(ctx));

    SSL_CTX_free(ctx);
    printf("probe.done=1\n");
    return 0;
}
