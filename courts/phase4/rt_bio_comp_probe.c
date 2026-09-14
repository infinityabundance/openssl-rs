/*
 * openssl-rs — RT-BIO-COMP: the compressed-filter methods and the retry classifiers.
 *
 * Two small but genuinely observable surfaces that share a property: their
 * *value set* is what matters, not their concept.
 *
 * The three compression methods are exercised because the admitted authority is
 * built with `OPENSSL_NO_ZLIB`, `OPENSSL_NO_ZSTD` and `OPENSSL_NO_BROTLI`, so
 * each must return `NULL`. A build with any of them enabled would return a real
 * method here, which is why the probe also prints whether the error queue stayed
 * empty — the authority's compiled-out body raises nothing.
 *
 * The retry classifiers are exercised over a fixed list of `errno` values rather
 * than representative ones, because the difference between
 * `BIO_fd_non_fatal_error` and `BIO_dgram_non_fatal_error` is exactly one
 * membership (`ENOTCONN`), and a representative probe would step straight over
 * it. The list is Linux's, so it is stable across runs.
 *
 * `BIO_fd_should_retry` is driven with values other than 0 and -1 too, because
 * the authority only consults `errno` for those two: every other input answers 0
 * without reading it. The probe sets a *retryable* `errno` first, so an
 * implementation that consulted `errno` unconditionally would answer 1 and be
 * caught.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <openssl/bio.h>
#include <openssl/comp.h>
#include <openssl/err.h>
#include <errno.h>
#include <stdio.h>

static void show_errqueue(const char *key)
{
    unsigned long e = ERR_peek_error();

    printf("%s.err0=%lu\n", key, e);
    printf("%s.count=%d\n", key, ERR_peek_error() == 0 ? 0 : 1);
    ERR_clear_error();
}

int main(void)
{
    static const int errs[] = {
        0, EINTR, EAGAIN, EWOULDBLOCK, EINPROGRESS, EALREADY, ENOTCONN,
        EPROTO, ECONNREFUSED, ECONNRESET, EBADF, 999
    };
    char k[64];
    unsigned i;

    setvbuf(stdout, NULL, _IONBF, 0);

    /* --- the three compression method factories -------------------------- */

    ERR_clear_error();
    printf("zlib.isnull=%d\n", BIO_f_zlib() == NULL);
    show_errqueue("zlib");
    ERR_clear_error();
    printf("zstd.isnull=%d\n", BIO_f_zstd() == NULL);
    show_errqueue("zstd");
    ERR_clear_error();
    printf("brotli.isnull=%d\n", BIO_f_brotli() == NULL);
    show_errqueue("brotli");

    /* --- the two non-fatal-error classifiers, over the whole list -------- */

    for (i = 0; i < sizeof(errs) / sizeof(errs[0]); i++) {
        snprintf(k, sizeof(k), "fd_nonfatal.e%d", errs[i]);
        printf("%s=%d\n", k, BIO_fd_non_fatal_error(errs[i]));
        snprintf(k, sizeof(k), "dgram_nonfatal.e%d", errs[i]);
        printf("%s=%d\n", k, BIO_dgram_non_fatal_error(errs[i]));
    }

    /* --- BIO_fd_should_retry only reads errno for 0 and -1 ---------------- */

    errno = EAGAIN;
    printf("fd_retry.eagain.0=%d\n", BIO_fd_should_retry(0));
    printf("fd_retry.eagain.m1=%d\n", BIO_fd_should_retry(-1));
    printf("fd_retry.eagain.1=%d\n", BIO_fd_should_retry(1));
    printf("fd_retry.eagain.2=%d\n", BIO_fd_should_retry(2));
    printf("fd_retry.eagain.m2=%d\n", BIO_fd_should_retry(-2));
    printf("fd_retry.eagain.5=%d\n", BIO_fd_should_retry(5));
    printf("fd_retry.eagain.m5=%d\n", BIO_fd_should_retry(-5));

    errno = EBADF;
    printf("fd_retry.ebadf.0=%d\n", BIO_fd_should_retry(0));
    printf("fd_retry.ebadf.m1=%d\n", BIO_fd_should_retry(-1));

    errno = ENOTCONN;
    printf("fd_retry.enotconn.0=%d\n", BIO_fd_should_retry(0));

    errno = EPROTO;
    printf("fd_retry.eproto.0=%d\n", BIO_fd_should_retry(0));

    /* The classifiers raise nothing, whatever they are asked. */
    ERR_clear_error();
    printf("classifiers.err0=%lu\n", ERR_peek_error());
    ERR_clear_error();

    return 0;
}
