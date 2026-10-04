/*
 * RT-DEFAULTS — the directory and install-context plane, as subphase 16.3 lands it.
 *
 * Compiled twice (authority and candidate), run, and the two transcripts compared
 * line by line. The probe drives the two `crypto/defaults.c` functions 16.3 lands
 * through the public surfaces that stand on them — `OPENSSL_info` and the four
 * `X509_get_default_*` paths:
 *
 *   * `OPENSSL_info(OPENSSL_INFO_CONFIG_DIR)` is `ossl_get_openssldir()`
 *     (`crypto/defaults.c:151-160`, `crypto/info.c:254`). Its answer is a `'static`
 *     C string and is equal to `X509_get_default_cert_area()` on both sides, because
 *     both are the same build-time `OPENSSLDIR`;
 *   * the four `X509_get_default_{cert_area,cert_dir,cert_file,private_dir}` paths
 *     are that area and its `/certs`, `/cert.pem` and `/private` children
 *     (`include/internal/common.h:83-86`), so the *relationship* between each child
 *     and the area holds on both sides;
 *   * `OPENSSL_info(OPENSSL_INFO_WINDOWS_CONTEXT)` is `ossl_get_wininstallcontext()`
 *     (`crypto/defaults.c:199-206`, `crypto/info.c:285`), the one name that is equal
 *     on both sides: the non-Windows arm is the literal `"Undefined"`;
 *   * the refusal arm that is comparable: an unrecognised code is `NULL` on both
 *     sides. `OPENSSL_INFO_SEED_SOURCE` (1007) and `OPENSSL_INFO_CPU_SETTINGS`
 *     (1008) are *not* refusal arms — the authority answers `"os-specific"` and its
 *     CPU string, while the candidate answers NULL because those subsystems are
 *     Phase 9's and Phase 19's — so they are a recorded divergence and are not
 *     observed here.
 *
 * ## What is deliberately not printed, and why
 *
 * The authority's `OPENSSLDIR` is its own forensic-build path
 * (`…/prefix/openssl-3.6.4-production/ssl`), which this substitute distribution is
 * not installed at; the candidate answers its build's `OPENSSL_RS_OPENSSLDIR` (the
 * empty C string when unset). Printing either raw string would fail the court for a
 * *value* the stratum deliberately does not claim, so the probe prints the
 * relationship to `X509_get_default_cert_area()` instead — the idiom `RT-CONF`,
 * `RT-LHASH` and `RT-COMP` already use for a boundary they cannot compare. For the
 * same reason the engines and modules dirs are not observed: the candidate answers
 * NULL when the build configured no prefix where the authority answers its own
 * `ENGINESDIR`/`MODULESDIR`. The empty-string arm is the candidate's own (a build
 * that configured no `OPENSSL_RS_OPENSSLDIR`), so what is compared there is that the
 * answer is a non-NULL C string and stable across calls.
 *
 * No wall clock, no network, no address, and no error-queue read.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/x509.h>

static void out_int(const char *key, int value)
{
    printf("%s=%d\n", key, value);
}

static void out_str(const char *key, const char *value)
{
    printf("%s=%s\n", key, value != NULL ? value : "(null)");
}

/* Is `child` exactly `base` with `suffix` appended? */
static int has_suffix(const char *base, const char *child, const char *suffix)
{
    size_t lb = strlen(base);
    size_t lc = strlen(child);
    size_t ls = strlen(suffix);

    return lc == lb + ls && strncmp(child, base, lb) == 0 && strcmp(child + lb, suffix) == 0;
}

/*
 * A path is either the empty C string an unset `OPENSSL_RS_OPENSSLDIR` degrades to
 * (`src/x509/x509_def.rs`) or the area with `suffix` appended. The disjunction is what
 * makes the arm comparable: the authority is in the second case, the candidate is in the
 * first, and printing the raw string would compare the two builds' prefixes.
 */
static int path_ok(const char *base, const char *child, const char *suffix)
{
    return strlen(child) == 0 || has_suffix(base, child, suffix);
}

int main(void)
{
    const char *config_dir = OPENSSL_info(OPENSSL_INFO_CONFIG_DIR);
    const char *wc = OPENSSL_info(OPENSSL_INFO_WINDOWS_CONTEXT);
    const char *cert_area = X509_get_default_cert_area();

    setvbuf(stdout, NULL, _IOLBF, 0);

    /* --- ossl_get_openssldir, through OPENSSL_info(OPENSSL_INFO_CONFIG_DIR) --- */
    out_int("info.config_dir_nonnull", config_dir != NULL);
    out_int("info.config_dir_stable", config_dir != NULL && config_dir == OPENSSL_info(OPENSSL_INFO_CONFIG_DIR));
    out_int("info.config_dir_eq_cert_area", config_dir != NULL && strcmp(config_dir, cert_area) == 0);

    /* --- ossl_get_wininstallcontext, through OPENSSL_info(OPENSSL_INFO_WINDOWS_CONTEXT) --- */
    out_str("info.windows_context", wc);
    out_int("info.windows_context_stable", wc != NULL && wc == OPENSSL_info(OPENSSL_INFO_WINDOWS_CONTEXT));

    /* --- the x509 default paths' relationship to the area OPENSSLDIR names --- */
    out_int("x509.cert_dir_suffix",
            path_ok(cert_area, X509_get_default_cert_dir(), "/certs"));
    out_int("x509.cert_file_suffix",
            path_ok(cert_area, X509_get_default_cert_file(), "/cert.pem"));
    out_int("x509.private_dir_suffix",
            path_ok(cert_area, X509_get_default_private_dir(), "/private"));

    /* --- the refusal arm that is comparable: an unrecognised code --- */
    out_int("info.unknown_null", OPENSSL_info(0) == NULL);

    printf("done=1\n");
    return 0;
}
