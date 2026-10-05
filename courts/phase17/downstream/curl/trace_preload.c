/*
 * LD_PRELOAD tracer for the Phase 17 downstream/curl diagnostics.
 *
 * Interposes the libssl entry points curl's OpenSSL backend calls during connection setup and
 * logs each call's return value, so the exact call on which a candidate-linked curl fails is
 * named. Build with `cc -shared -fPIC -o trace_preload.so trace_preload.c -ldl` and run curl
 * with `LD_PRELOAD=.../trace_preload.so`. Diagnostic only; not part of the court.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>

#include <openssl/ssl.h>

#define NEXT(name) dlsym(RTLD_NEXT, name)

const SSL_METHOD *TLS_client_method(void)
{
    static const SSL_METHOD *(*f)(void);
    const SSL_METHOD *m;
    if(!f) f = NEXT("TLS_client_method");
    m = f();
    fprintf(stderr, "[trace] TLS_client_method -> %p\n", (void *)m);
    return m;
}

SSL_CTX *SSL_CTX_new(const SSL_METHOD *method)
{
    static SSL_CTX *(*f)(const SSL_METHOD *);
    SSL_CTX *c;
    if(!f) f = NEXT("SSL_CTX_new");
    c = f(method);
    fprintf(stderr, "[trace] SSL_CTX_new -> %p\n", (void *)c);
    return c;
}

long SSL_CTX_ctrl(SSL_CTX *ctx, int cmd, long larg, void *parg)
{
    static long (*f)(SSL_CTX *, int, long, void *);
    long r;
    if(!f) f = NEXT("SSL_CTX_ctrl");
    r = f(ctx, cmd, larg, parg);
    fprintf(stderr, "[trace] SSL_CTX_ctrl cmd=%d larg=%ld -> %ld\n", cmd, larg, r);
    return r;
}

long SSL_CTX_callback_ctrl(SSL_CTX *ctx, int cmd, void (*cb)(void))
{
    static long (*f)(SSL_CTX *, int, void (*)(void));
    long r;
    if(!f) f = NEXT("SSL_CTX_callback_ctrl");
    r = f(ctx, cmd, cb);
    fprintf(stderr, "[trace] SSL_CTX_callback_ctrl cmd=%d -> %ld\n", cmd, r);
    return r;
}

void SSL_CTX_set_verify(SSL_CTX *ctx, int mode, int (*cb)(int, X509_STORE_CTX *))
{
    static void (*f)(SSL_CTX *, int, int (*)(int, X509_STORE_CTX *));
    if(!f) f = NEXT("SSL_CTX_set_verify");
    fprintf(stderr, "[trace] SSL_CTX_set_verify mode=%d\n", mode);
    f(ctx, mode, cb);
}

SSL *SSL_new(SSL_CTX *ctx)
{
    static SSL *(*f)(SSL_CTX *);
    SSL *s;
    if(!f) f = NEXT("SSL_new");
    s = f(ctx);
    fprintf(stderr, "[trace] SSL_new -> %p\n", (void *)s);
    return s;
}

void SSL_set_connect_state(SSL *s)
{
    static void (*f)(SSL *);
    if(!f) f = NEXT("SSL_set_connect_state");
    fprintf(stderr, "[trace] SSL_set_connect_state\n");
    f(s);
}

long SSL_ctrl(SSL *ssl, int cmd, long larg, void *parg)
{
    static long (*f)(SSL *, int, long, void *);
    long r;
    if(!f) f = NEXT("SSL_ctrl");
    r = f(ssl, cmd, larg, parg);
    fprintf(stderr, "[trace] SSL_ctrl cmd=%d larg=%ld -> %ld\n", cmd, larg, r);
    return r;
}

int SSL_set_alpn_protos(SSL *ssl, const unsigned char *protos, unsigned int len)
{
    static int (*f)(SSL *, const unsigned char *, unsigned int);
    int r;
    if(!f) f = NEXT("SSL_set_alpn_protos");
    r = f(ssl, protos, len);
    fprintf(stderr, "[trace] SSL_set_alpn_protos len=%u -> %d\n", len, r);
    return r;
}

int SSL_connect(SSL *ssl)
{
    static int (*f)(SSL *);
    int r;
    if(!f) f = NEXT("SSL_connect");
    fprintf(stderr, "[trace] SSL_connect ...\n");
    r = f(ssl);
    fprintf(stderr, "[trace] SSL_connect -> %d\n", r);
    return r;
}

int SSL_get_error(const SSL *ssl, int ret)
{
    static int (*f)(const SSL *, int);
    int r;
    if(!f) f = NEXT("SSL_get_error");
    r = f(ssl, ret);
    fprintf(stderr, "[trace] SSL_get_error(%d) -> %d\n", ret, r);
    return r;
}
