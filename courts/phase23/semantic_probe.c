/*
 * openssl-rs — the Phase 23.8 semantic oracle-to-oracle probe.
 *
 * This probe is the shared instrument of `RT-SEMANTIC-COURTS`
 * (`docs/PHASE-23-MULTITRACK-SUBPHASES.md` section 2, row 23.8). It is compiled
 * twice — once against each authority's own prefix — and each run prints one
 * `OBS <key>=<value>` line per observation. The two sides therefore emit the
 * **same normalized observation vocabulary**, so comparing them is a comparison
 * rather than a translation, and the raw transcript is preserved beside the
 * normalized rows.
 *
 * Two rules the probe obeys, and why
 * ----------------------------------
 *  1. **An identical API uses the identical probe.** A constant, a digest and a
 *     deterministic parse are read the same text on both sides; the two runs are
 *     byte-comparable without an adapter.
 *  2. **A declaration that differs across the pair uses a side-specific
 *     adapter that still emits the same vocabulary.** `SSL_VALUE_QUIC_MAX_PENDING_CONNS`
 *     and `X509_R_CRL_SIGNATURE_ALGORITHM_MISMATCH` are public in 3.6.4 and absent
 *     from 3.6.3, so a struct/field access would not compile on the older side.
 *     The adapter below emits the key on **both** sides — the value on the side
 *     that declares it, the literal `<absent>` on the side that does not — so the
 *     difference is *preserved* in the vocabulary rather than erased by it. The
 *     adapter is exactly what the difference is under investigation, and it never
 *     maps the two sides to the same observation when the declarations differ.
 *
 * The transcript is deterministic by construction: it prints no address, no
 * clock, no PID and no DSO path, so the same authority binary yields the same
 * bytes on every run and the artefact that carries it is reproducible.
 *
 * Compiled with `-DSEMANTIC_AUTHORITY_ID=...` and `-DSEMANTIC_RELEASE_ID=...`,
 * which the probe echoes as `side.authority` / `side.release` so the reader of a
 * raw transcript can never mis-attribute it to the wrong authority.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>
#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/ssl.h>
#include <openssl/bn.h>
#include <openssl/http.h>
#include <openssl/pkcs12.h>

#ifndef SEMANTIC_AUTHORITY_ID
#define SEMANTIC_AUTHORITY_ID "(unset)"
#endif
#ifndef SEMANTIC_RELEASE_ID
#define SEMANTIC_RELEASE_ID "(unset)"
#endif

#define SEM_STR_(x) #x
#define SEM_STR(x) SEM_STR_(x)

/* One normalized observation line. The vocabulary is `OBS <key>=<value>` on every
 * side; a value that cannot be observed is the literal `<absent>` or `<error>`,
 * never an omitted line, so a missing observation is impossible to confuse with
 * an equal one. */
static void obs(const char *key, const char *value)
{
    printf("OBS %s=%s\n", key, value);
}

static void obs_int(const char *key, long long value)
{
    char buf[64];
    snprintf(buf, sizeof(buf), "%lld", value);
    obs(key, buf);
}

static void obs_hex(const char *key, const unsigned char *md, unsigned int len)
{
    static const char hexd[] = "0123456789abcdef";
    char buf[2 * EVP_MAX_MD_SIZE + 1];
    unsigned int i;
    if (len > EVP_MAX_MD_SIZE) {
        obs(key, "<error>");
        return;
    }
    for (i = 0; i < len; i++) {
        buf[2 * i] = hexd[(md[i] >> 4) & 0xf];
        buf[2 * i + 1] = hexd[md[i] & 0xf];
    }
    buf[2 * len] = '\0';
    obs(key, buf);
}

/* -- version reporting: the release identity the trajectory is about --------- */

static void version_reporting(void)
{
    obs("version.text.macro", OPENSSL_VERSION_TEXT);
    obs("version.str", OPENSSL_VERSION_STR);
    obs("version.full", OPENSSL_FULL_VERSION_STR);
    obs("version.release_date", OPENSSL_RELEASE_DATE);
    obs_int("version.patch", OPENSSL_VERSION_PATCH);
    obs_int("version.number", (long long)OpenSSL_version_num());
    obs("version.text.runtime", OpenSSL_version(OPENSSL_VERSION));
}

/* -- presence adapters: a declaration that differs across the pair ----------- */

static void presence_adapters(void)
{
#ifdef SSL_VALUE_QUIC_MAX_PENDING_CONNS
    obs("presence.SSL_VALUE_QUIC_MAX_PENDING_CONNS",
        SEM_STR(SSL_VALUE_QUIC_MAX_PENDING_CONNS));
#else
    obs("presence.SSL_VALUE_QUIC_MAX_PENDING_CONNS", "<absent>");
#endif

#ifdef X509_R_CRL_SIGNATURE_ALGORITHM_MISMATCH
    obs("presence.X509_R_CRL_SIGNATURE_ALGORITHM_MISMATCH",
        SEM_STR(X509_R_CRL_SIGNATURE_ALGORITHM_MISMATCH));
#else
    obs("presence.X509_R_CRL_SIGNATURE_ALGORITHM_MISMATCH", "<absent>");
#endif
}

/* -- error behaviour --------------------------------------------------------- */

static void error_behaviour(void)
{
#ifdef X509_R_CRL_SIGNATURE_ALGORITHM_MISMATCH
    {
        const char *s = ERR_reason_error_string(X509_R_CRL_SIGNATURE_ALGORITHM_MISMATCH);
        obs("error.reason.CRL_SIGNATURE_ALGORITHM_MISMATCH", s ? s : "<null>");
    }
#else
    obs("error.reason.CRL_SIGNATURE_ALGORITHM_MISMATCH", "<absent>");
#endif
    {
        const char *s = ERR_reason_error_string(ERR_R_MALLOC_FAILURE);
        obs("error.reason.MALLOC_FAILURE", s ? s : "<null>");
    }
}

/* -- identical APIs: the same probe on both sides ---------------------------- */

static void constants(void)
{
    obs_int("const.EVP_MAX_MD_SIZE", (long long)EVP_MAX_MD_SIZE);
    obs_int("const.SHA256_DIGEST_LENGTH", (long long)SHA256_DIGEST_LENGTH);
    obs_int("const.TLS1_3_VERSION", (long long)TLS1_3_VERSION);
    obs_int("const.X509_V_OK", (long long)X509_V_OK);
}

static void behaviour_digest(void)
{
    static const char msg[] = "openssl-rs semantic probe\n";
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx != NULL
        && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1
        && EVP_DigestUpdate(ctx, msg, sizeof(msg) - 1) == 1
        && EVP_DigestFinal_ex(ctx, md, &len) == 1) {
        obs_hex("behaviour.EVP_sha256", md, len);
    } else {
        obs("behaviour.EVP_sha256", "<error>");
    }
    EVP_MD_CTX_free(ctx);
}

static void behaviour_parse_url(void)
{
    char *scheme = NULL, *user = NULL, *host = NULL, *port = NULL;
    char *path = NULL, *query = NULL, *fragment = NULL;
    int portnum = -1;
    char buf[512];
    int r = OSSL_parse_url("https://user@example.com:8443/a/b?q=1#frag",
                           &scheme, &user, &host, &port, &portnum,
                           &path, &query, &fragment);
    if (r == 1) {
        snprintf(buf, sizeof(buf),
                 "r=1 scheme=%s host=%s port=%s portnum=%d path=%s query=%s frag=%s",
                 scheme ? scheme : "-", host ? host : "-", port ? port : "-",
                 portnum, path ? path : "-", query ? query : "-",
                 fragment ? fragment : "-");
    } else {
        snprintf(buf, sizeof(buf), "r=%d", r);
    }
    obs("behaviour.OSSL_parse_url", buf);
    OPENSSL_free(scheme);
    OPENSSL_free(user);
    OPENSSL_free(host);
    OPENSSL_free(port);
    OPENSSL_free(path);
    OPENSSL_free(query);
    OPENSSL_free(fragment);
}

static void behaviour_bn(void)
{
    BIGNUM *a = BN_new(), *b = BN_new(), *c = BN_new();
    char *h = NULL;
    if (a == NULL || b == NULL || c == NULL
        || BN_hex2bn(&a, "0f0f0f0f0f0f0f0f") == 0
        || BN_hex2bn(&b, "00000000000000ff") == 0
        || BN_uadd(c, a, b) != 1) {
        obs("behaviour.BN_uadd", "<error>");
        obs("behaviour.BN_ucmp", "<error>");
        BN_free(a);
        BN_free(b);
        BN_free(c);
        return;
    }
    h = BN_bn2hex(c);
    obs("behaviour.BN_uadd", h ? h : "<null>");
    obs_int("behaviour.BN_ucmp", (long long)BN_ucmp(a, b));
    OPENSSL_free(h);
    BN_free(a);
    BN_free(b);
    BN_free(c);
}

static void behaviour_uni2utf8(void)
{
    /* UTF-16BE for U+0041 U+00E9 U+0042; a deterministic BMPString. */
    static const unsigned char uni[] = {0x00, 0x41, 0x00, 0xe9, 0x00, 0x42};
    char *u = OPENSSL_uni2utf8(uni, (int)sizeof(uni));
    obs("behaviour.OPENSSL_uni2utf8", u ? u : "<null>");
    OPENSSL_free(u);
}

int main(void)
{
    obs("side.authority", SEMANTIC_AUTHORITY_ID);
    obs("side.release", SEMANTIC_RELEASE_ID);
    version_reporting();
    presence_adapters();
    error_behaviour();
    constants();
    behaviour_digest();
    behaviour_parse_url();
    behaviour_bn();
    behaviour_uni2utf8();
    return 0;
}
